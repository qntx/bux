//! HTTP router: public health, Bearer-protected me/config/metrics, sandboxes, exec, files, images.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use utoipa::ToSchema;

use crate::auth::{Tenant, require_bearer};
use crate::error::ApiError;
use crate::state::{AppState, Limits};
use crate::{exec, files, images, logs, sandboxes};

/// JSON request body cap.
pub(crate) const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
pub(crate) use crate::files::MAX_FILE_BODY_BYTES;

pub(crate) fn router(state: AppState) -> Router {
    let json = Router::new()
        .route("/v1/config", get(config))
        .route("/v1/me", get(me))
        .route("/v1/metrics", get(metrics))
        .merge(sandboxes::routes())
        .merge(exec::routes())
        .merge(logs::routes())
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

#[utoipa::path(
    get,
    path = "/v1/health",
    operation_id = "health",
    tag = "Worker",
    responses((status = 200, description = "Worker is up")),
    security(())
)]
pub(crate) async fn health() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/v1/config",
    operation_id = "config",
    tag = "Worker",
    responses(
        (status = 200, description = "Worker config", body = Limits),
        (status = 401, description = "Missing or invalid Bearer token")
    )
)]
pub(crate) async fn config(State(state): State<AppState>) -> Json<Limits> {
    Json(state.limits)
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MeBody {
    tenant_id: String,
    max_sandboxes: u32,
}

#[utoipa::path(
    get,
    path = "/v1/me",
    operation_id = "me",
    tag = "Worker",
    responses(
        (status = 200, description = "Bearer tenant_id and max_sandboxes", body = MeBody),
        (status = 401, description = "Missing or invalid Bearer token")
    )
)]
pub(crate) async fn me(State(state): State<AppState>, tenant: Tenant) -> Json<MeBody> {
    Json(MeBody {
        tenant_id: tenant.id,
        max_sandboxes: state.limits.max_sandboxes,
    })
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MetricsBody {
    vms_created_total: u64,
    num_running_vms: i64,
    vms_failed_total: u64,
    total_uptime_ms: u64,
    disk_bytes_used: u64,
    data_dir_bytes: u64,
}

#[utoipa::path(
    get,
    path = "/v1/metrics",
    operation_id = "metrics",
    tag = "Worker",
    responses(
        (status = 200, description = "RuntimeMetrics getters plus data_dir_bytes", body = MetricsBody),
        (status = 401, description = "Missing or invalid Bearer token")
    )
)]
pub(crate) async fn metrics(State(state): State<AppState>) -> Result<Json<MetricsBody>, ApiError> {
    let m = state.runtime.metrics();
    let data_dir_bytes = state
        .runtime
        .data_dir_usage()
        .map_err(|e| ApiError::from_engine(e.into()))?;
    Ok(Json(MetricsBody {
        vms_created_total: m.vms_created_total(),
        num_running_vms: m.num_running_vms(),
        vms_failed_total: m.vms_failed_total(),
        total_uptime_ms: m.total_uptime_ms(),
        disk_bytes_used: m.disk_bytes_used(),
        data_dir_bytes,
    }))
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
    async fn me_without_bearer_is_401() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/me")
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
    }

    #[tokio::test]
    async fn me_returns_tenant_and_max_sandboxes() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/me")
                    .header(AUTHORIZATION, "Bearer secret1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "me");
        let v = json_body(res).await;
        assert_eq!(
            v.get("tenant_id").and_then(serde_json::Value::as_str),
            Some("tenant1"),
            "tenant_id"
        );
        assert_eq!(
            v.get("max_sandboxes").and_then(serde_json::Value::as_u64),
            Some(32),
            "max_sandboxes"
        );
    }

    #[tokio::test]
    async fn me_two_keys_are_distinct_tenants() {
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
                    .uri("/v1/me")
                    .header(AUTHORIZATION, "Bearer two")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "second key");
        let v = json_body(res).await;
        assert_eq!(
            v.get("tenant_id").and_then(serde_json::Value::as_str),
            Some("b"),
            "tenant_id"
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
        assert!(prod.contains("logs::routes"), "logs routes");
        assert!(prod.contains("/v1/metrics"), "metrics");
        assert!(prod.contains("MAX_FILE_BODY_BYTES"), "files body limit");
    }

    #[tokio::test]
    async fn metrics_without_bearer_is_401() {
        let (_dir, app) = sample_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
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
    }

    #[tokio::test]
    async fn metrics_is_worker_global_with_data_dir_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let data_dir_bytes = runtime.data_dir_usage().unwrap();
        let disk_bytes_used = runtime.metrics().disk_bytes_used();
        let overlays = runtime.disk_usage().unwrap();
        assert!(
            data_dir_bytes > overlays,
            "data_dir_usage={data_dir_bytes} must exceed disk_usage={overlays}"
        );
        let app = router(AppState::new(
            vec![
                ApiKey::new("a", "one").unwrap(),
                ApiKey::new("b", "two").unwrap(),
            ],
            runtime,
            Limits::default(),
        ));
        let a = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .header(AUTHORIZATION, "Bearer one")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = app
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .header(AUTHORIZATION, "Bearer two")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(a.status(), StatusCode::OK, "first key");
        assert_eq!(b.status(), StatusCode::OK, "second key");
        let va = json_body(a).await;
        let vb = json_body(b).await;
        assert_eq!(va, vb, "worker-global");
        assert_eq!(va.as_object().map(serde_json::Map::len), Some(6), "keys");
        assert_eq!(
            va.get("data_dir_bytes").and_then(serde_json::Value::as_u64),
            Some(data_dir_bytes),
            "admission gauge"
        );
        assert_eq!(
            va.get("disk_bytes_used")
                .and_then(serde_json::Value::as_u64),
            Some(disk_bytes_used),
            "overlays+bases gauge"
        );
        assert_ne!(
            data_dir_bytes, disk_bytes_used,
            "data_dir_bytes is not disk_bytes_used"
        );
        assert_eq!(
            va.get("vms_created_total")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "vms_created_total"
        );
        assert_eq!(
            va.get("num_running_vms")
                .and_then(serde_json::Value::as_i64),
            Some(0),
            "num_running_vms"
        );
        assert_eq!(
            va.get("vms_failed_total")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "vms_failed_total"
        );
        assert_eq!(
            va.get("total_uptime_ms")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "total_uptime_ms"
        );
    }
}
