//! `PUT`/`GET /v1/sandboxes/{id}/files?path=` — single file, absolute guest path.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use serde::Deserialize;

use crate::auth::Tenant;
use crate::error::{ApiError, QueryBody};
use crate::sandboxes::load_owned;
use crate::state::AppState;

const DEFAULT_FILE_MODE: u32 = 0o644;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/sandboxes/{id}/files", get(get_file).put(put_file))
}

#[derive(Debug, Deserialize)]
struct FileQuery {
    path: String,
    #[serde(default)]
    mode: Option<u32>,
}

async fn put_file(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
    QueryBody(query): QueryBody<FileQuery>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validate_guest_path(&query.path)?;
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let mode = query.mode.unwrap_or(DEFAULT_FILE_MODE);
    vm.write_file(&query.path, &body, mode)
        .await
        .map_err(ApiError::from_engine)?;
    vm.touch_activity().map_err(ApiError::from_engine)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_file(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
    QueryBody(query): QueryBody<FileQuery>,
) -> Result<Vec<u8>, ApiError> {
    validate_guest_path(&query.path)?;
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let data = vm
        .read_file(&query.path)
        .await
        .map_err(ApiError::from_engine)?;
    vm.touch_activity().map_err(ApiError::from_engine)?;
    Ok(data)
}

fn validate_guest_path(path: &str) -> Result<(), ApiError> {
    if path.starts_with('/') && !path.contains("..") {
        Ok(())
    } else {
        Err(
            ApiError::invalid_config("path must be an absolute guest path without ..")
                .with_field("path"),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::ApiKey;
    use crate::router::{MAX_FILE_BODY_BYTES, MAX_JSON_BODY_BYTES, router};
    use crate::state::Limits;

    fn test_app() -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let app = router(AppState::new(
            vec![ApiKey::new("tenant1", "secret1").unwrap()],
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
        app.oneshot(builder.body(body).unwrap()).await.unwrap()
    }

    fn error_code(v: &serde_json::Value) -> Option<&str> {
        v.pointer("/error/code").and_then(serde_json::Value::as_str)
    }

    #[test]
    fn guest_path_must_be_absolute_without_dotdot() {
        assert!(validate_guest_path("/workspace/x").is_ok(), "ok");
        assert!(validate_guest_path("/").is_ok(), "root");
        assert!(validate_guest_path("relative").is_err(), "relative");
        assert!(validate_guest_path("").is_err(), "empty");
        assert!(validate_guest_path("/foo/../bar").is_err(), "dotdot");
        assert!(validate_guest_path("/foo/..").is_err(), "trailing");
        assert!(validate_guest_path("..").is_err(), "only dotdot");
    }

    #[tokio::test]
    async fn files_without_bearer_is_401() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/files?path=/x",
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
    }

    #[tokio::test]
    async fn files_missing_path_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/files",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "missing path");
    }

    #[tokio::test]
    async fn files_relative_path_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=tmp/x",
            Some("secret1"),
            Body::from("hi"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "relative");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("invalid_config"), "code");
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("path"),
            "field"
        );
    }

    #[tokio::test]
    async fn files_dotdot_path_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/files?path=/foo/../bar",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "dotdot");
    }

    #[tokio::test]
    async fn files_missing_sandbox_is_404() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab/files?path=/workspace/x",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing");
    }

    #[tokio::test]
    async fn files_put_missing_sandbox_is_404() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=/workspace/x&mode=420",
            Some("secret1"),
            Body::from("hello"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "put missing");
    }

    #[tokio::test]
    async fn files_invalid_mode_is_400() {
        let (_dir, app) = test_app();
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=/x&mode=abc",
            Some("secret1"),
            Body::from("x"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "mode");
    }

    #[tokio::test]
    async fn files_over_json_limit_is_not_413() {
        let (_dir, app) = test_app();
        let len = MAX_JSON_BODY_BYTES.saturating_add(1);
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=/x",
            Some("secret1"),
            Body::from(vec![0_u8; len]),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "files allow >1MiB");
    }

    #[tokio::test]
    async fn files_over_axum_default_2mib_is_not_413() {
        let (_dir, app) = test_app();
        let len = (2_usize * 1024 * 1024).saturating_add(1);
        assert!(len < MAX_FILE_BODY_BYTES, "under files cap");
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=/x",
            Some("secret1"),
            Body::from(vec![0_u8; len]),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "files allow >2MiB");
    }

    #[tokio::test]
    async fn files_over_32mib_is_413() {
        let (_dir, app) = test_app();
        let len = MAX_FILE_BODY_BYTES.saturating_add(1);
        let res = send(
            app,
            "PUT",
            "/v1/sandboxes/0123456789ab/files?path=/x",
            Some("secret1"),
            Body::from(vec![0_u8; len]),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE, "32MiB");
        assert_eq!(
            error_code(&json_body(res).await),
            Some("payload_too_large"),
            "code"
        );
    }

    #[test]
    fn production_touches_activity_and_rejects_dotdot() {
        let prod = include_str!("files.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(prod.contains("touch_activity"), "idle clock");
        assert!(prod.contains("write_file"), "PUT");
        assert!(prod.contains("read_file"), "GET");
        assert!(prod.contains("validate_guest_path"), "path check");
        assert!(prod.contains("0o644"), "default mode");
        assert!(prod.contains("contains(\"..\")"), "reject ..");
    }
}
