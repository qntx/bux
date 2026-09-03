//! `GET /v1/sandboxes/{id}/logs` — shim stderr at [`bux::Vm::log_path`].

use std::io;

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use bux::Vm;

use crate::auth::Tenant;
use crate::error::ApiError;
use crate::sandboxes::load_owned;
use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/sandboxes/{id}/logs", get(logs_one))
}

#[utoipa::path(
    get,
    path = "/v1/sandboxes/{id}/logs",
    operation_id = "getSandboxLogs",
    tag = "Sandboxes",
    params(("id" = String, Path, description = "Exact 12-char hex sandbox id")),
    responses(
        (status = 200, description = "Shim stderr ({socks}/{id}.stderr)", content_type = "text/plain", body = String),
        (status = 401, description = "Missing or invalid Bearer token"),
        (status = 404, description = "Missing or other tenant")
    )
)]
pub(crate) async fn logs_one(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
) -> Result<String, ApiError> {
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    read_stderr(&vm)
}

fn read_stderr(vm: &Vm) -> Result<String, ApiError> {
    match std::fs::read(vm.log_path()) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(ApiError::from_engine(err.into())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Request, StatusCode};
    use rusqlite::params;
    use tower::ServiceExt;

    use crate::ApiKey;
    use crate::router::router;
    use crate::state::Limits;

    struct Harness {
        dir: tempfile::TempDir,
        runtime: Arc<bux::Runtime>,
        app: Router,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let opened = bux::Runtime::open(dir.path()).unwrap();
        let state = AppState::new(
            vec![
                ApiKey::new("tenant1", "secret1").unwrap(),
                ApiKey::new("tenant2", "secret2").unwrap(),
            ],
            opened,
            Limits::default(),
        );
        let runtime = Arc::clone(&state.runtime);
        let app = router(state);
        Harness { dir, runtime, app }
    }

    async fn json_body(res: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    async fn text_body(res: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf-8")
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn plant_vm(data_dir: &Path, id: &str, tenant: &str, agent: &str) {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        drop(child.wait());
        let socket = data_dir.join("socks").join(format!("{id}.sock"));
        let conn = rusqlite::Connection::open(data_dir.join("bux.db")).unwrap();
        conn.busy_timeout(Duration::from_secs(5)).unwrap();
        let config = serde_json::json!({
            "vcpus": 1,
            "ram_mib": 512,
            "tenant_id": tenant,
            "agent_id": agent,
        });
        conn.execute(
            "INSERT INTO vms (id, name, pid, image, socket, status, config, created_at)
             VALUES (?1, ?2, ?3, NULL, ?4, 'stopped', ?5, 0)",
            params![
                id,
                format!("a-{tenant}-{agent}"),
                pid,
                socket.to_str().expect("utf-8"),
                config.to_string(),
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn logs_without_bearer_is_401() {
        let h = harness();
        let res = send(h.app, "GET", "/v1/sandboxes/0123456789ab/logs", None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("unauthorized"),
            "code"
        );
    }

    #[tokio::test]
    async fn logs_missing_is_404() {
        let h = harness();
        let res = send(
            h.app,
            "GET",
            "/v1/sandboxes/0123456789ab/logs",
            Some("secret1"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("not_found"),
            "code"
        );
    }

    #[tokio::test]
    async fn logs_other_tenant_is_404_same_as_missing() {
        const ID: &str = "abc123aaa020";
        let h = harness();
        plant_vm(h.dir.path(), ID, "tenant1", "a1");
        let missing = send(
            h.app.clone(),
            "GET",
            "/v1/sandboxes/ffffffffffff/logs",
            Some("secret2"),
        )
        .await;
        let other = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{ID}/logs"),
            Some("secret2"),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "missing");
        assert_eq!(other.status(), StatusCode::NOT_FOUND, "other tenant");
        assert_eq!(json_body(missing).await, json_body(other).await, "envelope");
    }

    #[tokio::test]
    async fn logs_returns_engine_stderr_file() {
        const ID: &str = "abc123aaa021";
        let h = harness();
        plant_vm(h.dir.path(), ID, "tenant1", "a1");
        let vm = h.runtime.get_exact(ID).unwrap();
        std::fs::write(vm.log_path(), "shim says hi\n").unwrap();
        let res = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{ID}/logs"),
            Some("secret1"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "owner");
        assert_eq!(text_body(res).await, "shim says hi\n", "stderr");
    }

    #[tokio::test]
    async fn logs_missing_file_is_empty_200() {
        const ID: &str = "abc123aaa022";
        let h = harness();
        plant_vm(h.dir.path(), ID, "tenant1", "a1");
        let res = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{ID}/logs"),
            Some("secret1"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "no file yet");
        assert_eq!(text_body(res).await, "", "empty");
    }

    #[test]
    fn production_uses_engine_log_path() {
        let prod = include_str!("logs.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(prod.contains("log_path"), "Vm::log_path");
        assert!(prod.contains("from_utf8_lossy"), "lossy utf-8");
        assert!(prod.contains("ErrorKind::NotFound"), "missing file");
    }
}
