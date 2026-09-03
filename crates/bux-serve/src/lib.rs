//! HTTP worker for hosted bux sandboxes.
//!
//! `bux serve start` opens one [`bux::Runtime`] (exclusive flock on `BUX_HOME`),
//! binds TCP (loopback unless `--public`) and a Unix socket, sweeps idle VMs
//! every 30s, and serves `/v1/health` (public) plus Bearer-protected `/v1/me`,
//! `/v1/metrics`, sandbox get-or-create, collect exec, files, images, and logs.
//! At least one API key is required to start, including on the Unix socket.
//! Identifiers use the alphabet `[A-Za-z0-9._]`; `-` is only a separator in
//! formatted sandbox and volume names.

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
mod listen;
mod logs;
mod openapi;
mod router;
mod sandboxes;
mod state;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use error::{Error, Result};
pub use ids::{
    IdError, sandbox_name, validate_agent_id, validate_tenant_id, workspace_volume_name,
};
pub use listen::listen_specs;
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

/// Listen addresses, API keys, data dir, and admission limits.
#[derive(Debug)]
pub struct ServeConfig {
    listen: Vec<listen::ListenAddr>,
    keys: Vec<ApiKey>,
    data_dir: PathBuf,
    limits: Limits,
    allow_unrestricted_net: bool,
}

impl ServeConfig {
    /// Bind specs and at least one API key. Empty `listen` uses the defaults
    /// (`127.0.0.1:8080` and `unix://$XDG_RUNTIME_DIR/bux.sock`, fallback
    /// `/tmp/bux-$UID.sock`).
    ///
    /// Data dir defaults to [`bux::default_data_dir`]; limits to [`Limits::default`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoApiKeys`], [`Error::InvalidListen`],
    /// [`Error::NonLoopback`], or [`Error::PublicRequiresTcp`].
    pub fn new<I, S>(listen: I, keys: Vec<ApiKey>) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::bind(listen, keys, false)
    }

    /// Bind with at least one API key.
    ///
    /// Each spec is `HOST:PORT`, `unix://ABS_PATH`, or an absolute `/path`.
    /// Empty `listen` uses TCP loopback plus the default Unix socket.
    /// `public` is required for a non-loopback **TCP** address (`--public`).
    /// `--public` with only Unix listeners is [`Error::PublicRequiresTcp`].
    /// Zero keys is always [`Error::NoApiKeys`], including Unix-only and
    /// `public`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoApiKeys`], [`Error::InvalidListen`],
    /// [`Error::NonLoopback`], or [`Error::PublicRequiresTcp`].
    pub fn bind<I, S>(listen: I, keys: Vec<ApiKey>, public: bool) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if keys.is_empty() {
            return Err(Error::NoApiKeys);
        }
        Ok(Self {
            listen: listen::resolve_listen(listen, public)?,
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

/// Bind every `config.listen` address (same router / [`AppState`]) until SIGINT / SIGTERM.
///
/// Opens [`bux::Runtime`] on `config.data_dir` (exclusive flock) before bind.
/// Builds a multi-thread tokio runtime. Must not be called from an existing runtime.
/// Unix socket files are unlinked on shutdown.
///
/// # Errors
///
/// Returns [`Error::Runtime`] with [`bux::Error::Busy`] if another process holds
/// the data-dir lock. Returns [`Error::Io`] if an address cannot be bound.
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
    serve_until(config, shutdown).await
}

async fn serve_until(
    config: ServeConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let runtime = open_runtime(&config.data_dir)?;
    tracing::info!(
        api_keys = config.keys.len(),
        data_dir = %config.data_dir.display(),
        allow_unrestricted_net = config.allow_unrestricted_net,
        "starting worker"
    );
    let state = AppState::new(config.keys, runtime, config.limits)
        .with_unrestricted_net(config.allow_unrestricted_net);
    let sweep = tokio::spawn(sweep_loop(state.clone()));
    let app = router::router(state);
    let result = listen::serve_listeners(&config.listen, app, shutdown).await;
    sweep.abort();
    result
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
fn install_shutdown() -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
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
fn install_shutdown() -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
    Ok(async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    })
}

/// OpenAPI 3.1 document for routes this worker currently serves.
pub use openapi::openapi_json;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::shadow_unrelated,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn refuses_zero_keys() {
        let err = ServeConfig::new(["127.0.0.1:8080"], vec![]).unwrap_err();
        assert!(matches!(err, Error::NoApiKeys), "{err}");
        assert_eq!(err.exit_code(), 2, "exit");
    }

    #[test]
    fn refuses_non_loopback() {
        let new_err =
            ServeConfig::new(["0.0.0.0:8080"], vec![ApiKey::new("t", "s").unwrap()]).unwrap_err();
        assert!(matches!(new_err, Error::NonLoopback(_)), "{new_err}");
        let bind_err = ServeConfig::bind(
            ["0.0.0.0:8080"],
            vec![ApiKey::new("t", "s").unwrap()],
            false,
        )
        .unwrap_err();
        assert!(matches!(bind_err, Error::NonLoopback(_)), "{bind_err}");
    }

    #[test]
    fn public_bind_allows_non_loopback() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::bind(["0.0.0.0:8080"], vec![key], true).unwrap();
    }

    #[test]
    fn public_bind_without_keys_is_hard_error() {
        let err = ServeConfig::bind(["0.0.0.0:8080"], vec![], true).unwrap_err();
        assert!(matches!(err, Error::NoApiKeys), "{err}");
        assert_eq!(err.exit_code(), 2, "exit");
    }

    #[cfg(unix)]
    #[test]
    fn public_unix_only_is_hard_error() {
        let key = ApiKey::new("t", "s").unwrap();
        let err = ServeConfig::bind(["unix:///tmp/bux.sock"], vec![key], true).unwrap_err();
        assert!(matches!(err, Error::PublicRequiresTcp), "{err}");
        assert_eq!(err.exit_code(), 2, "exit");
    }

    #[test]
    fn accepts_loopback() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::new(["127.0.0.1:8080"], vec![key]).unwrap();
    }

    #[test]
    fn omitted_listen_defaults_tcp_and_unix() {
        let key = ApiKey::new("t", "s").unwrap();
        let cfg = ServeConfig::new(Vec::<&str>::new(), vec![key]).unwrap();
        assert!(
            cfg.listen
                .iter()
                .any(|addr| matches!(addr, listen::ListenAddr::Tcp(_))),
            "tcp: {:?}",
            cfg.listen
        );
        #[cfg(unix)]
        assert!(
            cfg.listen
                .iter()
                .any(|addr| matches!(addr, listen::ListenAddr::Unix(_))),
            "unix: {:?}",
            cfg.listen
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_only_listen_without_public_is_ok() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::bind(["unix:///tmp/bux.sock"], vec![key], false).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listen_health_and_unauth_mutate() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bux.sock");
        std::fs::write(&sock, b"stale").unwrap();
        let spec = format!("unix://{}", sock.display());
        let config = ServeConfig::bind(
            [spec.as_str()],
            vec![ApiKey::new("t", "secret").unwrap()],
            false,
        )
        .unwrap()
        .data_dir(dir.path());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_until(config, async move {
            drop(stop_rx.await);
        }));

        let health = unix_http(
            &sock,
            "GET /v1/health HTTP/1.1\r\nHost: bux\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            health.starts_with("HTTP/1.1 200 ") || health.contains("HTTP/1.1 200 "),
            "{health}"
        );

        let mutate = unix_http(
            &sock,
            "POST /v1/sandboxes HTTP/1.1\r\nHost: bux\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        assert!(mutate.contains("401"), "{mutate}");
        assert!(mutate.contains("unauthorized"), "{mutate}");

        assert!(stop_tx.send(()).is_ok(), "server still running");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server shutdown")
            .expect("join")
            .expect("serve");
        assert!(!sock.exists(), "unlinked on shutdown");
    }

    #[cfg(unix)]
    async fn unix_http(path: &Path, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = connect_unix(path).await;
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[cfg(unix)]
    async fn connect_unix(path: &Path) -> tokio::net::UnixStream {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::UnixStream::connect(path).await {
                Ok(stream) => return stream,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(err) => panic!("connect {}: {err}", path.display()),
            }
        }
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
