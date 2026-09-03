//! HTTP router: public health, Bearer-protected config, sandboxes, exec, files, images.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::require_bearer;
use crate::error::ApiError;
use crate::state::{AppState, Limits};
use crate::{exec, files, images, sandboxes};

/// JSON request body cap.
pub(crate) const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
/// Files PUT body cap.
pub(crate) const MAX_FILE_BODY_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn router(state: AppState) -> Router {
    let json = Router::new()
        .route("/v1/config", get(config))
        .merge(sandboxes::routes())
        .merge(exec::routes())
        .merge(images::routes())
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_JSON_BODY_BYTES));

    let files = files::routes()
        .layer(DefaultBodyLimit::max(MAX_FILE_BODY_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_FILE_BODY_BYTES));

    let protected = json
        .merge(files)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

    Router::new()
        .route("/v1/health", get(health))
        .merge(protected)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
        .layer(middleware::map_response(map_payload_too_large))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn config(State(state): State<AppState>) -> Json<Limits> {
    Json(state.limits)
}

async fn map_payload_too_large(response: Response) -> Response {
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large().into_response()
    } else {
        response
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::header::AUTHORIZATION;
    use tower::ServiceExt;

    use crate::ApiKey;

    fn sample_app() -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let state = AppState::new(
            vec![ApiKey::new("tenant1", "secret1").unwrap()],
            runtime,
            Limits::default(),
        );
        (dir, router(state))
    }

    async fn json_body(res: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn health_is_public() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "health");
    }

    #[tokio::test]
    async fn config_without_bearer_is_401_envelope() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("unauthorized"),
            "code"
        );
        assert!(
            v.pointer("/error/message")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "message"
        );
    }

    #[tokio::test]
    async fn config_with_bearer_is_200_limits() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .header(AUTHORIZATION, "Bearer secret1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "config");
        let v = json_body(res).await;
        assert_eq!(
            v.get("max_sandboxes").and_then(serde_json::Value::as_u64),
            Some(32),
            "max_sandboxes"
        );
        assert_eq!(
            v.get("max_ram_mib").and_then(serde_json::Value::as_u64),
            Some(2048),
            "max_ram_mib"
        );
        assert_eq!(
            v.get("max_exec_output_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(1024 * 1024),
            "max_exec_output_bytes"
        );
        assert_eq!(
            v.get("max_pull_bytes").and_then(serde_json::Value::as_u64),
            Some(4_u64 * 1024 * 1024 * 1024),
            "max_pull_bytes"
        );
    }

    #[tokio::test]
    async fn config_wrong_secret_is_401() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .header(AUTHORIZATION, "Bearer nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "wrong secret");
    }

    #[tokio::test]
    async fn bearer_matches_any_key() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let app = router(AppState::new(
            vec![
                ApiKey::new("a", "one").unwrap(),
                ApiKey::new("b", "two").unwrap(),
            ],
            runtime,
            Limits::default(),
        ));
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .header(AUTHORIZATION, "Bearer two")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "second key");
    }

    #[tokio::test]
    async fn body_over_1mib_is_413_envelope() {
        let (_dir, app) = sample_app();
        let len = MAX_JSON_BODY_BYTES.saturating_add(1);
        let body = vec![0_u8; len];
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/config")
                    .header(AUTHORIZATION, "Bearer secret1")
                    .header("content-length", len.to_string())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE, "limit");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("payload_too_large"),
            "code"
        );
    }

    #[test]
    fn files_limit_is_32mib_and_json_is_1mib() {
        assert_eq!(MAX_JSON_BODY_BYTES, 1024 * 1024, "json");
        assert_eq!(MAX_FILE_BODY_BYTES, 32 * 1024 * 1024, "files");
        let prod = include_str!("router.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(prod.contains("files::routes"), "files routes");
        assert!(prod.contains("exec::routes"), "exec routes");
        assert!(prod.contains("images::routes"), "images routes");
        assert!(prod.contains("MAX_FILE_BODY_BYTES"), "files body limit");
    }
}
