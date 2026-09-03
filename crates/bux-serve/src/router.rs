//! HTTP router: public health, Bearer-protected stubs.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::ApiKey;
use crate::error::ApiError;

/// JSON and default request body cap.
pub(crate) const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    keys: Arc<[ApiKey]>,
}

impl AppState {
    pub(crate) fn new(keys: Vec<ApiKey>) -> Self {
        Self { keys: keys.into() }
    }

    fn tenant_for_bearer(&self, token: &str) -> Option<&str> {
        let token = token.as_bytes();
        let mut found = None;
        for key in self.keys.iter() {
            if constant_time_eq(key.secret_bytes(), token) {
                found = Some(key.id());
            }
        }
        found
    }
}

/// Pad to at least this many bytes so unequal lengths are not a `zip` min-len oracle.
const CT_EQ_MIN_ITERS: usize = 256;

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut acc = u8::from(left.len() != right.len());
    let n = left.len().max(right.len()).max(CT_EQ_MIN_ITERS);
    for i in 0..n {
        acc |= left.get(i).copied().unwrap_or(0) ^ right.get(i).copied().unwrap_or(0);
    }
    acc == 0
}

pub(crate) fn router(state: AppState) -> Router {
    let protected =
        Router::new()
            .route("/v1/config", get(config))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer,
            ));

    Router::new()
        .route("/v1/health", get(health))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(RequestBodyLimitLayer::new(MAX_JSON_BODY_BYTES)),
        )
        .layer(middleware::map_response(map_payload_too_large))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn config() -> Json<serde_json::Value> {
    Json(serde_json::json!({}))
}

async fn require_bearer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers()).ok_or_else(ApiError::unauthorized)?;
    if state.tenant_for_bearer(token).is_none() {
        return Err(ApiError::unauthorized());
    }
    Ok(next.run(req).await)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty() {
        Some(rest)
    } else {
        None
    }
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
    use tower::ServiceExt;

    fn sample_state() -> AppState {
        AppState::new(vec![ApiKey::new("tenant1", "secret1").unwrap()])
    }

    async fn json_body(res: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn health_is_public() {
        let app = router(sample_state());
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
        let app = router(sample_state());
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
    async fn config_with_bearer_is_200() {
        let app = router(sample_state());
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
    }

    #[tokio::test]
    async fn config_wrong_secret_is_401() {
        let app = router(sample_state());
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

    #[test]
    fn tenant_for_bearer_last_match_wins() {
        let state = AppState::new(vec![
            ApiKey::new("first", "shared").unwrap(),
            ApiKey::new("second", "shared").unwrap(),
        ]);
        assert_eq!(
            state.tenant_for_bearer("shared"),
            Some("second"),
            "must walk every key"
        );
    }

    #[tokio::test]
    async fn bearer_matches_any_key() {
        let app = router(AppState::new(vec![
            ApiKey::new("a", "one").unwrap(),
            ApiKey::new("b", "two").unwrap(),
        ]));
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
        let app = router(sample_state());
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
    fn constant_time_eq_cases() {
        assert!(constant_time_eq(b"abc", b"abc"), "eq");
        assert!(!constant_time_eq(b"abc", b"abd"), "neq");
        assert!(!constant_time_eq(b"abc", b"ab"), "len");
        assert!(constant_time_eq(b"", b""), "empty");
    }
}
