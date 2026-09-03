//! HTTP worker for hosted bux sandboxes.
//!
//! `bux serve start` opens one [`bux::Runtime`] (exclusive flock on `BUX_HOME`),
//! binds TCP (loopback unless `--public`), sweeps idle VMs every 30s, and
//! serves `/v1/health` (public) plus Bearer-protected `/v1/me`, `/v1/metrics`,
//! sandbox get-or-create, collect exec, files, images, and logs. At least one
//! API key is required to start. Identifiers use the alphabet `[A-Za-z0-9._]`;
//! `-` is only a separator in formatted sandbox and volume names.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "internal fields are named for their role"
)]

mod auth;
mod error;
mod exec;
mod files;
mod ids;
mod images;
mod logs;
mod openapi;
mod router;
mod sandboxes;
mod state;

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use error::{Error, Result};
pub use ids::{
    IdError, sandbox_name, validate_agent_id, validate_tenant_id, workspace_volume_name,
};
pub use state::Limits;

use state::AppState;

/// Bearer credential. `id` is the tenant id.
#[derive(Clone)]
pub struct ApiKey {
    id: String,
    secret: String,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ApiKey {
    /// Construct a key. `id` uses the tenant alphabet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidId`] when `id` fails tenant validation, or
    /// [`Error::EmptyApiKeySecret`] when `secret` is empty.
    pub fn new(id: impl AsRef<str>, secret: impl Into<String>) -> Result<Self> {
        let id = id.as_ref();
        validate_tenant_id(id)?;
        let secret = secret.into();
        if secret.is_empty() {
            return Err(Error::EmptyApiKeySecret(id.to_owned()));
        }
        Ok(Self {
            id: id.to_owned(),
            secret,
        })
    }

    /// Tenant id for this key.
    #[must_use]
    pub const fn id(&self) -> &str {
        self.id.as_str()
    }

    pub(crate) const fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

/// How often the worker calls [`bux::Runtime::sweep`].
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// TCP bind address, API keys, data dir, and admission limits.
#[derive(Debug)]
pub struct ServeConfig {
    listen: SocketAddr,
    keys: Vec<ApiKey>,
    data_dir: PathBuf,
    limits: Limits,
    allow_unrestricted_net: bool,
}

impl ServeConfig {
    /// Loopback `IP:PORT` and at least one API key.
    ///
    /// Data dir defaults to [`bux::default_data_dir`]; limits to [`Limits::default`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoApiKeys`], [`Error::InvalidListen`], or
    /// [`Error::NonLoopback`].
    pub fn new(listen: &str, keys: Vec<ApiKey>) -> Result<Self> {
        Self::bind(listen, keys, false)
    }

    /// TCP bind with at least one API key.
    ///
    /// `public` is required for a non-loopback address (`--public`). Zero keys
    /// is always [`Error::NoApiKeys`], including with `public`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoApiKeys`], [`Error::InvalidListen`], or
    /// [`Error::NonLoopback`].
    pub fn bind(listen: &str, keys: Vec<ApiKey>, public: bool) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoApiKeys);
        }
        let listen: SocketAddr = listen
            .parse()
            .map_err(|_| Error::InvalidListen(listen.to_owned()))?;
        if !listen.ip().is_loopback() && !public {
            return Err(Error::NonLoopback(listen));
        }
        Ok(Self {
            listen,
            keys,
            data_dir: bux::default_data_dir(),
            limits: Limits::default(),
            allow_unrestricted_net: false,
        })
    }

    /// Permit `"unrestricted": true` on create (`NetworkSpec::Enabled` with an
    /// empty allow-list).
    #[must_use]
    pub const fn allow_unrestricted_net(mut self, allow: bool) -> Self {
        self.allow_unrestricted_net = allow;
        self
    }

    /// Runtime data directory (`bux.lock` / `bux.db`). Second process → [`bux::Error::Busy`].
    #[must_use]
    pub fn data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = data_dir.into();
        self
    }

    /// Admission caps applied before `Runtime::create`.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// Load keys from CLI `id:secret` specs, an `id=secret` file, and comma-separated env specs.
///
/// # Errors
///
/// Returns [`Error`] if a spec is malformed, an id is invalid, ids collide, or
/// the file cannot be read.
pub fn load_api_keys(
    cli_keys: &[String],
    key_file: Option<&Path>,
    env_keys: Option<&str>,
) -> Result<Vec<ApiKey>> {
    let mut keys = Vec::new();
    if let Some(path) = key_file {
        load_key_file(path, &mut keys)?;
    }
    if let Some(env_keys) = env_keys {
        for spec in env_keys.split(',') {
            if spec.is_empty() {
                continue;
            }
            push_colon_spec(&mut keys, spec)?;
        }
    }
    for spec in cli_keys {
        push_colon_spec(&mut keys, spec)?;
    }
    Ok(keys)
}

fn push_colon_spec(keys: &mut Vec<ApiKey>, spec: &str) -> Result<()> {
    let Some((id, secret)) = spec.split_once(':') else {
        return Err(Error::ApiKeyMissingSeparator);
    };
    push_key(keys, id, secret)
}

fn push_key(keys: &mut Vec<ApiKey>, id: &str, secret: &str) -> Result<()> {
    let key = ApiKey::new(id, secret)?;
    if keys.iter().any(|existing| existing.id == key.id) {
        return Err(Error::DuplicateApiKeyId(key.id));
    }
    keys.push(key);
    Ok(())
}

fn load_key_file(path: &Path, keys: &mut Vec<ApiKey>) -> Result<()> {
    #[cfg(unix)]
    warn_if_world_readable(path);
    let text = std::fs::read_to_string(path)?;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id, secret)) = line.split_once('=') else {
            return Err(Error::ApiKeyFileSyntax {
                path: path.display().to_string(),
                line: i + 1,
            });
        };
        push_key(keys, id.trim(), secret)?;
    }
    Ok(())
}

#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                "API key file is readable by group or others"
            );
        }
    }
}

/// Bind `config.listen` and serve until SIGINT / SIGTERM.
///
/// Opens [`bux::Runtime`] on `config.data_dir` (exclusive flock) before bind.
/// Builds a multi-thread tokio runtime. Must not be called from an existing runtime.
///
/// # Errors
///
/// Returns [`Error::Runtime`] with [`bux::Error::Busy`] if another process holds
/// the data-dir lock. Returns [`Error::Io`] if the address cannot be bound.
pub fn run(config: ServeConfig) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

fn open_runtime(data_dir: &Path) -> Result<bux::Runtime> {
    bux::Runtime::open(data_dir).map_err(Error::from)
}

async fn serve(config: ServeConfig) -> Result<()> {
    let shutdown = install_shutdown()?;
    let runtime = open_runtime(&config.data_dir)?;
    let listen = config.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(
        %listen,
        api_keys = config.keys.len(),
        data_dir = %config.data_dir.display(),
        allow_unrestricted_net = config.allow_unrestricted_net,
        "listening"
    );
    let state = AppState::new(config.keys, runtime, config.limits)
        .with_unrestricted_net(config.allow_unrestricted_net);
    let sweep = tokio::spawn(sweep_loop(state.clone()));
    let app = router::router(state);
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    sweep.abort();
    result?;
    Ok(())
}

async fn sweep_loop(state: AppState) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    #[allow(
        clippy::infinite_loop,
        reason = "aborted when the HTTP server shuts down"
    )]
    loop {
        interval.tick().await;
        match state.runtime.sweep() {
            Ok(report) => {
                if report.stopped > 0 || report.deleted > 0 {
                    tracing::info!(stopped = report.stopped, deleted = report.deleted, "sweep");
                }
            }
            Err(err) => tracing::warn!(error = %err, "sweep failed"),
        }
    }
}

/// Install SIGINT/SIGTERM first. A failed install is I/O, not shutdown.
#[cfg(unix)]
fn install_shutdown() -> std::io::Result<impl Future<Output = ()> + Send> {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            () = recv_signal(&mut interrupt) => {}
            () = recv_signal(&mut terminate) => {}
        }
    })
}

/// `None` from `recv` means the stream closed, not that a signal arrived.
#[cfg(unix)]
async fn recv_signal(signal: &mut tokio::signal::unix::Signal) {
    if signal.recv().await.is_none() {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
fn install_shutdown() -> std::io::Result<impl Future<Output = ()> + Send> {
    Ok(async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    })
}

/// OpenAPI 3.1 document for routes this worker currently serves.
pub use openapi::openapi_json;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::shadow_unrelated, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn refuses_zero_keys() {
        let err = ServeConfig::new("127.0.0.1:8080", vec![]).unwrap_err();
        assert!(matches!(err, Error::NoApiKeys), "{err}");
        assert_eq!(err.exit_code(), 2, "exit");
    }

    #[test]
    fn refuses_non_loopback() {
        let err =
            ServeConfig::new("0.0.0.0:8080", vec![ApiKey::new("t", "s").unwrap()]).unwrap_err();
        assert!(matches!(err, Error::NonLoopback(_)), "{err}");
        let err = ServeConfig::bind("0.0.0.0:8080", vec![ApiKey::new("t", "s").unwrap()], false)
            .unwrap_err();
        assert!(matches!(err, Error::NonLoopback(_)), "{err}");
    }

    #[test]
    fn public_bind_allows_non_loopback() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::bind("0.0.0.0:8080", vec![key], true).unwrap();
    }

    #[test]
    fn public_bind_without_keys_is_hard_error() {
        let err = ServeConfig::bind("0.0.0.0:8080", vec![], true).unwrap_err();
        assert!(matches!(err, Error::NoApiKeys), "{err}");
        assert_eq!(err.exit_code(), 2, "exit");
    }

    #[test]
    fn accepts_loopback() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::new("127.0.0.1:8080", vec![key]).unwrap();
    }

    #[test]
    fn sweep_interval_is_30s() {
        assert_eq!(SWEEP_INTERVAL, Duration::from_secs(30), "30s");
        let prod = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(prod.contains("sweep_loop"), "sweep task");
        assert!(prod.contains("runtime.sweep"), "Runtime::sweep");
    }

    #[test]
    fn api_key_requires_colon() {
        let err = load_api_keys(&["noseparator".into()], None, None).unwrap_err();
        assert!(matches!(err, Error::ApiKeyMissingSeparator), "{err}");
    }

    #[test]
    fn api_key_id_rejects_hyphen() {
        let err = load_api_keys(&["foo-bar:secret".into()], None, None).unwrap_err();
        assert!(matches!(err, Error::InvalidId(_)), "{err}");
    }

    #[test]
    fn duplicate_ids() {
        let err = load_api_keys(&["t:a".into(), "t:b".into()], None, None).unwrap_err();
        assert!(matches!(err, Error::DuplicateApiKeyId(_)), "{err}");
    }

    #[test]
    fn env_keys_comma_separated() {
        let keys = load_api_keys(&[], None, Some("a:one,b:two")).unwrap();
        assert_eq!(keys.len(), 2, "count");
        assert_eq!(keys.first().map(ApiKey::id), Some("a"), "first");
        assert_eq!(keys.get(1).map(ApiKey::id), Some("b"), "second");
    }

    #[test]
    fn key_file_parses_comments_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        std::fs::write(&path, "# c\n\nt1=sec1\nt2=sec2\n").unwrap();
        let keys = load_api_keys(&[], Some(&path), None).unwrap();
        assert_eq!(keys.len(), 2, "count");
        assert_eq!(keys.first().map(ApiKey::id), Some("t1"), "t1");
        assert_eq!(keys.get(1).map(ApiKey::id), Some("t2"), "t2");
    }

    #[test]
    fn openapi_is_json_object() {
        let v: serde_json::Value = serde_json::from_str(&openapi_json()).unwrap();
        assert!(v.get("openapi").is_some(), "openapi field");
        let paths = v.get("paths").expect("paths");
        for path in [
            "/v1/health",
            "/v1/config",
            "/v1/me",
            "/v1/metrics",
            "/v1/sandboxes",
            "/v1/sandboxes/{id}",
            "/v1/sandboxes/{id}/start",
            "/v1/sandboxes/{id}/logs",
            "/v1/sandboxes/{id}/exec",
            "/v1/sandboxes/{id}/files",
            "/v1/images",
            "/v1/images/pull",
        ] {
            assert!(paths.get(path).is_some(), "{path}");
        }
        assert!(
            paths.get("/v1/sandboxes/{id}/snapshots").is_none(),
            "snapshots are a later PR"
        );
        assert!(
            v.pointer("/components/schemas/MetricsBody").is_some(),
            "utoipa schema"
        );
        assert_eq!(
            v.pointer("/components/securitySchemes/bearer/scheme")
                .and_then(serde_json::Value::as_str),
            Some("bearer"),
            "bearer scheme"
        );
        assert_eq!(
            v.pointer("/paths/~1v1~1health/get/security"),
            Some(&serde_json::json!([{}])),
            "health overrides global bearer"
        );
        assert_eq!(
            v.get("security"),
            Some(&serde_json::json!([{"bearer": []}])),
            "global bearer"
        );
    }

    #[test]
    fn second_runtime_open_on_same_dir_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let _held = bux::Runtime::open(dir.path()).unwrap();
        let err = open_runtime(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::Runtime(bux::Error::Busy(_))),
            "exclusive flock: {err}"
        );
        assert_eq!(err.exit_code(), 1, "engine Busy is exit 1");
    }
}
