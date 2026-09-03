//! Collect-only `POST /v1/sandboxes/{id}/exec`. Guest `ExecStart::timeout` is required.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::post;
use bux::{ExecHandle, ExecStart};
use bux_proto::ExecOut;
use serde::{Deserialize, Serialize};

use crate::auth::Tenant;
use crate::error::{ApiError, JsonBody};
use crate::sandboxes::load_owned;
use crate::state::AppState;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 300_000;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/sandboxes/{id}/exec", post(exec_one))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequest {
    cmd: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ExecResponse {
    stdout: String,
    stderr: String,
    code: i32,
    timed_out: bool,
    duration_ms: u64,
    truncated: bool,
}

async fn exec_one(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<ExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    if req.cmd.is_empty() {
        return Err(ApiError::invalid_config("cmd is required").with_field("cmd"));
    }
    let timeout_ms = parse_timeout_ms(req.timeout_ms)?;
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    if vm.info().secrets_required {
        return Err(ApiError::from_engine(bux::Error::SecretsRequired));
    }

    let mut start = ExecStart::new(req.cmd)
        .args(req.args)
        .env(req.env)
        .timeout(timeout_ms);
    if let Some(cwd) = req.cwd {
        start = start.cwd(cwd);
    }

    let handle = vm.exec(start).await.map_err(ApiError::from_engine)?;
    let cap = usize::try_from(state.limits.max_exec_output_bytes).unwrap_or(usize::MAX);
    Ok(Json(collect_capped(handle, cap).await?))
}

fn parse_timeout_ms(timeout_ms: Option<u64>) -> Result<u64, ApiError> {
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(
            ApiError::invalid_config("timeout_ms must be between 1 and 300000")
                .with_field("timeout_ms"),
        );
    }
    Ok(timeout_ms)
}

async fn collect_capped(mut handle: ExecHandle, cap: usize) -> Result<ExecResponse, ApiError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut truncated = false;
    let mut signaled = false;
    loop {
        match handle.next_output().await {
            Ok(ExecOut::Stdout(chunk)) => {
                if !append_capped(&mut stdout, &chunk, cap) {
                    truncated = true;
                    kill_once(&mut handle, &mut signaled).await;
                }
            }
            Ok(ExecOut::Stderr(chunk)) => {
                if !append_capped(&mut stderr, &chunk, cap) {
                    truncated = true;
                    kill_once(&mut handle, &mut signaled).await;
                }
            }
            Ok(ExecOut::Exit {
                code,
                timed_out,
                duration_ms,
                ..
            }) => {
                return Ok(ExecResponse {
                    stdout: String::from_utf8_lossy(&stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr).into_owned(),
                    code,
                    timed_out,
                    duration_ms,
                    truncated,
                });
            }
            Ok(ExecOut::Error(info)) => {
                return Err(ApiError::from_engine(bux::Error::Io(
                    std::io::Error::other(info.message),
                )));
            }
            Err(err) => return Err(ApiError::from_engine(err.into())),
            Ok(_) => {}
        }
    }
}

fn append_capped(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) -> bool {
    let room = cap.saturating_sub(buf.len());
    if chunk.len() <= room {
        buf.extend_from_slice(chunk);
        return true;
    }
    if let Some(head) = chunk.get(..room) {
        buf.extend_from_slice(head);
    }
    false
}

async fn kill_once(handle: &mut ExecHandle, signaled: &mut bool) {
    if *signaled {
        return;
    }
    *signaled = true;
    drop(handle.signal(9).await);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
    use axum::http::{Request, StatusCode};
    use rusqlite::params;
    use tower::ServiceExt;

    use crate::ApiKey;
    use crate::router::router;
    use crate::state::Limits;

    fn test_app() -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let app = router(AppState::new(
            vec![
                ApiKey::new("tenant1", "secret1").unwrap(),
                ApiKey::new("tenant2", "secret2").unwrap(),
            ],
            runtime,
            Limits::default(),
        ));
        (dir, app)
    }

    async fn json_body(res: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Body,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if method == "POST" {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        app.oneshot(builder.body(body).unwrap()).await.unwrap()
    }

    fn plant_vm(data_dir: &Path, id: &str, config: &serde_json::Value) {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        drop(child.wait());
        let socket = data_dir.join("socks").join(format!("{id}.sock"));
        let conn = rusqlite::Connection::open(data_dir.join("bux.db")).unwrap();
        conn.busy_timeout(Duration::from_secs(5)).unwrap();
        conn.execute(
            "INSERT INTO vms (id, name, pid, image, socket, status, config, created_at)
             VALUES (?1, ?2, ?3, NULL, ?4, 'stopped', ?5, 0)",
            params![
                id,
                "a-tenant1-a1",
                pid,
                socket.to_str().expect("utf-8"),
                config.to_string(),
            ],
        )
        .unwrap();
    }

    fn error_code(v: &serde_json::Value) -> Option<&str> {
        v.pointer("/error/code").and_then(serde_json::Value::as_str)
    }

    #[tokio::test]
    async fn exec_without_bearer_is_401() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            None,
            Body::from(r#"{"cmd":"echo"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
    }

    #[tokio::test]
    async fn exec_missing_sandbox_is_404() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"echo"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "status");
        assert_eq!(error_code(&json_body(res).await), Some("not_found"), "code");
    }

    #[tokio::test]
    async fn exec_other_tenant_is_404() {
        let (dir, app) = test_app();
        plant_vm(
            dir.path(),
            "abc123aaa001",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "a1",
            }),
        );
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/abc123aaa001/exec",
            Some("secret2"),
            Body::from(r#"{"cmd":"echo"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "other tenant");
    }

    #[tokio::test]
    async fn exec_timeout_ms_zero_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"sleep","timeout_ms":0}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "zero");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("invalid_config"), "code");
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("timeout_ms"),
            "field"
        );
    }

    #[tokio::test]
    async fn exec_timeout_ms_over_max_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"sleep","timeout_ms":300001}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "max");
    }

    #[tokio::test]
    async fn exec_timeout_ms_one_is_not_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"echo","timeout_ms":1}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "1 is valid");
    }

    #[tokio::test]
    async fn exec_empty_cmd_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":""}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "empty cmd");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("cmd"),
            "field"
        );
    }

    #[tokio::test]
    async fn exec_missing_cmd_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"args":["x"]}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "missing cmd");
    }

    #[tokio::test]
    async fn exec_unknown_field_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"echo","tty":true}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "tty");
    }

    #[tokio::test]
    async fn exec_json_over_1mib_is_413() {
        let (_dir, app) = test_app();
        let len = crate::router::MAX_JSON_BODY_BYTES.saturating_add(1);
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sandboxes/0123456789ab/exec")
                    .header(AUTHORIZATION, "Bearer secret1")
                    .header(CONTENT_TYPE, "application/json")
                    .header("content-length", len.to_string())
                    .body(Body::from(vec![0_u8; len]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE, "json cap");
    }

    #[tokio::test]
    async fn exec_get_is_405() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/exec",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "no get");
    }

    #[tokio::test]
    async fn exec_id_route_is_404() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/exec/abc",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "no exec_id");
    }

    #[tokio::test]
    async fn exec_secrets_required_is_409() {
        let (dir, app) = test_app();
        plant_vm(
            dir.path(),
            "abc123aaa002",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "a1",
                "secrets_required": true,
            }),
        );
        let res = send(
            app,
            "POST",
            "/v1/sandboxes/abc123aaa002/exec",
            Some("secret1"),
            Body::from(r#"{"cmd":"echo"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "secrets");
        assert_eq!(
            error_code(&json_body(res).await),
            Some("secrets_required"),
            "code"
        );
    }

    #[test]
    fn timeout_ms_never_zero() {
        assert!(parse_timeout_ms(Some(0)).is_err(), "0");
        assert_eq!(
            parse_timeout_ms(None).unwrap(),
            DEFAULT_TIMEOUT_MS,
            "default"
        );
        assert_eq!(parse_timeout_ms(Some(1)).unwrap(), 1, "min");
        assert_eq!(
            parse_timeout_ms(Some(MAX_TIMEOUT_MS)).unwrap(),
            MAX_TIMEOUT_MS,
            "max"
        );
        assert!(parse_timeout_ms(Some(MAX_TIMEOUT_MS + 1)).is_err(), "over");
    }

    #[test]
    fn append_capped_truncates_over_cap() {
        let mut buf = Vec::new();
        assert!(append_capped(&mut buf, b"abc", 4), "under");
        assert!(!append_capped(&mut buf, b"xyz", 4), "over");
        assert_eq!(buf, b"abcx", "kept cap");
    }

    #[test]
    fn production_sets_guest_timeout_and_collects() {
        let prod = include_str!("exec.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(
            prod.contains(".timeout(timeout_ms)"),
            "must set ExecStart::timeout"
        );
        assert!(prod.contains("next_output"), "collect via next_output");
        assert!(prod.contains("signal(9)"), "cap sends SIGKILL");
        assert!(
            !prod.contains("tokio::time::timeout"),
            "must not wrap the host future"
        );
        assert!(
            !prod.contains("time::timeout"),
            "must not wrap the host future via time::timeout"
        );
        assert!(
            !prod.contains("tokio::time"),
            "exec must not import tokio::time"
        );
        assert!(!prod.contains("/exec/{"), "no exec_id routes");
        assert!(prod.contains("ExecStart::new"), "build ExecStart");
    }
}
