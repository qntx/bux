//! HTTP worker for hosted bux sandboxes.
//!
//! `bux serve start` binds a TCP loopback address and serves `/v1/health`
//! (public) plus Bearer-protected routes. At least one API key is required
//! to start. Identifiers use the alphabet `[A-Za-z0-9._]`; `-` is only a
//! separator in formatted sandbox and volume names.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "internal fields are named for their role"
)]

mod error;
mod ids;
mod router;

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

pub use error::{Error, Result};
pub use ids::{
    IdError, sandbox_name, validate_agent_id, validate_tenant_id, workspace_volume_name,
};

use router::AppState;

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

    const fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

/// TCP bind address and loaded API keys.
#[derive(Debug)]
pub struct ServeConfig {
    listen: SocketAddr,
    keys: Vec<ApiKey>,
}

impl ServeConfig {
    /// Loopback `IP:PORT` and at least one API key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoApiKeys`], [`Error::InvalidListen`], or
    /// [`Error::NonLoopback`].
    pub fn new(listen: &str, keys: Vec<ApiKey>) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoApiKeys);
        }
        let listen: SocketAddr = listen
            .parse()
            .map_err(|_| Error::InvalidListen(listen.to_owned()))?;
        if !listen.ip().is_loopback() {
            return Err(Error::NonLoopback(listen));
        }
        Ok(Self { listen, keys })
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
/// Builds a multi-thread tokio runtime. Must not be called from an existing runtime.
///
/// # Errors
///
/// Returns [`Error::Io`] if the address cannot be bound or the server fails.
pub fn run(config: ServeConfig) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

async fn serve(config: ServeConfig) -> Result<()> {
    let shutdown = install_shutdown()?;
    let listen = config.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, api_keys = config.keys.len(), "listening");
    let app = router::router(AppState::new(config.keys));
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
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
#[must_use]
pub const fn openapi_json() -> &'static str {
    OPENAPI_JSON
}

const OPENAPI_JSON: &str = concat!(
    "{\n",
    "  \"openapi\": \"3.1.0\",\n",
    "  \"info\": {\n",
    "    \"title\": \"bux\",\n",
    "    \"version\": \"",
    env!("CARGO_PKG_VERSION"),
    "\"\n",
    "  },\n",
    "  \"paths\": {\n",
    "    \"/v1/health\": {\n",
    "      \"get\": {\n",
    "        \"operationId\": \"health\",\n",
    "        \"responses\": {\n",
    "          \"200\": { \"description\": \"Worker is up\" }\n",
    "        }\n",
    "      }\n",
    "    },\n",
    "    \"/v1/config\": {\n",
    "      \"get\": {\n",
    "        \"operationId\": \"config\",\n",
    "        \"security\": [{ \"bearer\": [] }],\n",
    "        \"responses\": {\n",
    "          \"200\": { \"description\": \"Worker config\" },\n",
    "          \"401\": { \"description\": \"Missing or invalid Bearer token\" }\n",
    "        }\n",
    "      }\n",
    "    }\n",
    "  },\n",
    "  \"components\": {\n",
    "    \"securitySchemes\": {\n",
    "      \"bearer\": { \"type\": \"http\", \"scheme\": \"bearer\" }\n",
    "    }\n",
    "  }\n",
    "}"
);

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
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
        let key = ApiKey::new("t", "s").unwrap();
        let err = ServeConfig::new("0.0.0.0:8080", vec![key]).unwrap_err();
        assert!(matches!(err, Error::NonLoopback(_)), "{err}");
    }

    #[test]
    fn accepts_loopback() {
        let key = ApiKey::new("t", "s").unwrap();
        ServeConfig::new("127.0.0.1:8080", vec![key]).unwrap();
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
        let v: serde_json::Value = serde_json::from_str(openapi_json()).unwrap();
        assert!(v.get("openapi").is_some(), "openapi field");
        assert!(
            v.get("paths").and_then(|p| p.get("/v1/health")).is_some(),
            "health path"
        );
        assert!(
            v.get("paths").and_then(|p| p.get("/v1/config")).is_some(),
            "config path"
        );
    }
}
