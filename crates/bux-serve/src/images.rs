//! Worker-global image pull / list / delete. Serve uses [`bux::Runtime`], not `bux-oci`.

use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use bux::ImageInfo;
use serde::Deserialize;

use crate::error::{ApiError, JsonBody, QueryBody};
use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/images", get(list_images).delete(delete_image))
        .route("/v1/images/pull", post(pull_image))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequest {
    reference: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceQuery {
    reference: String,
}

async fn list_images(State(state): State<AppState>) -> Result<Json<Vec<ImageInfo>>, ApiError> {
    let images = state.runtime.images().map_err(ApiError::from_engine)?;
    Ok(Json(images))
}

async fn pull_image(
    State(state): State<AppState>,
    JsonBody(req): JsonBody<PullRequest>,
) -> Result<Json<ImageInfo>, ApiError> {
    let reference = bux::canonical_reference(&req.reference)
        .map_err(|e| ApiError::invalid_config(e.to_string()))?;
    admit_disk(&state)?;
    let compressed = state
        .runtime
        .manifest_compressed_bytes(&reference)
        .await
        .map_err(ApiError::from_engine)?;
    if compressed > state.limits.max_pull_bytes {
        return Err(ApiError::payload_too_large_msg(
            "image exceeds max-pull-bytes",
        ));
    }
    let pull = state.runtime.pull(&reference, |_| {});
    match tokio::time::timeout(Duration::from_secs(state.limits.pull_timeout_secs), pull).await {
        Ok(Ok(info)) => Ok(Json(info)),
        Ok(Err(err)) => Err(ApiError::from_engine(err)),
        Err(_) => Err(ApiError::oci("pull timed out")),
    }
}

async fn delete_image(
    State(state): State<AppState>,
    QueryBody(query): QueryBody<ReferenceQuery>,
) -> Result<StatusCode, ApiError> {
    let reference = bux::canonical_reference(&query.reference)
        .map_err(|e| ApiError::invalid_config(e.to_string()))?;
    if image_in_use(&state, &reference)? {
        return Err(ApiError::image_in_use());
    }
    state
        .runtime
        .remove_image(&reference)
        .map_err(ApiError::from_engine)?;
    Ok(StatusCode::NO_CONTENT)
}

fn admit_disk(state: &AppState) -> Result<(), ApiError> {
    let usage = state
        .runtime
        .data_dir_usage()
        .map_err(|e| ApiError::from_engine(e.into()))?;
    if usage >= state.limits.max_disk_bytes {
        return Err(ApiError::resource_exhausted("disk limit reached"));
    }
    Ok(())
}

fn image_in_use(state: &AppState, canonical: &str) -> Result<bool, ApiError> {
    let infos = state.runtime.list().map_err(ApiError::from_engine)?;
    for info in infos {
        let Some(label) = info.image.as_deref() else {
            continue;
        };
        if bux::canonical_reference(label).ok().as_deref() == Some(canonical) {
            return Ok(true);
        }
    }
    Ok(false)
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

    struct Harness {
        dir: tempfile::TempDir,
        app: Router,
    }

    fn harness(limits: Limits) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let opened = bux::Runtime::open(dir.path()).unwrap();
        let state = AppState::new(
            vec![
                ApiKey::new("tenant1", "secret1").unwrap(),
                ApiKey::new("tenant2", "secret2").unwrap(),
            ],
            opened,
            limits,
        );
        let app = router(state);
        Harness { dir, app }
    }

    async fn json_body(res: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .expect("body");
        if bytes.is_empty() {
            return serde_json::Value::Null;
        }
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

    fn error_code(v: &serde_json::Value) -> Option<&str> {
        v.pointer("/error/code").and_then(serde_json::Value::as_str)
    }

    fn plant_vm(data_dir: &Path, id: &str, image: Option<&str>, tenant: &str) {
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
            "agent_id": "a1",
        });
        conn.execute(
            "INSERT INTO vms (id, name, pid, image, socket, status, config, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'stopped', ?6, 0)",
            params![
                id,
                format!("a-{tenant}-a1"),
                pid,
                image,
                socket.to_str().expect("utf-8"),
                config.to_string(),
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn images_without_bearer_is_401() {
        let h = harness(Limits::default());
        let res = send(h.app, "GET", "/v1/images", None, Body::empty()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
    }

    #[tokio::test]
    async fn list_images_is_worker_global_empty() {
        let h = harness(Limits::default());
        let a = send(
            h.app.clone(),
            "GET",
            "/v1/images",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        let b = send(h.app, "GET", "/v1/images", Some("secret2"), Body::empty()).await;
        assert_eq!(a.status(), StatusCode::OK, "t1");
        assert_eq!(b.status(), StatusCode::OK, "t2");
        assert_eq!(json_body(a).await, serde_json::json!([]), "t1 list");
        assert_eq!(json_body(b).await, serde_json::json!([]), "t2 list");
    }

    #[tokio::test]
    async fn pull_invalid_reference_is_400() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "POST",
            "/v1/images/pull",
            Some("secret1"),
            Body::from(r#"{"reference":"not a ref"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "invalid");
    }

    #[tokio::test]
    async fn pull_missing_reference_is_400() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "POST",
            "/v1/images/pull",
            Some("secret1"),
            Body::from("{}"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "missing");
    }

    #[tokio::test]
    async fn pull_unknown_field_is_400() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "POST",
            "/v1/images/pull",
            Some("secret1"),
            Body::from(r#"{"reference":"alpine","extra":1}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown");
    }

    #[tokio::test]
    async fn pull_disk_cap_is_429() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = bux::Runtime::open(dir.path()).unwrap();
        let disk = runtime.disk_usage().unwrap();
        let data = runtime.data_dir_usage().unwrap();
        assert!(data > disk, "data_dir_usage exceeds disk_usage");
        let cap = disk.saturating_add(1);
        assert!(cap <= data, "cap in (disk_usage, data_dir_usage]");
        let app = router(AppState::new(
            vec![ApiKey::new("tenant1", "secret1").unwrap()],
            runtime,
            Limits {
                max_disk_bytes: cap,
                ..Limits::default()
            },
        ));
        let res = send(
            app,
            "POST",
            "/v1/images/pull",
            Some("secret1"),
            Body::from(r#"{"reference":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "disk");
        assert_eq!(
            error_code(&json_body(res).await),
            Some("resource_exhausted"),
            "code"
        );
    }

    #[tokio::test]
    async fn delete_missing_reference_query_is_400() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "DELETE",
            "/v1/images",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "no query");
    }

    #[tokio::test]
    async fn delete_invalid_reference_is_400() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "DELETE",
            "/v1/images?reference=not%20a%20ref",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "invalid");
    }

    #[tokio::test]
    async fn delete_missing_image_is_404() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "DELETE",
            "/v1/images?reference=alpine",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing");
        assert_eq!(error_code(&json_body(res).await), Some("not_found"), "code");
    }

    #[tokio::test]
    async fn delete_in_use_is_409() {
        let h = harness(Limits::default());
        plant_vm(h.dir.path(), "abc123aaa010", Some("python:slim"), "tenant2");
        let res = send(
            h.app,
            "DELETE",
            "/v1/images?reference=docker.io/library/python:slim",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "in use");
        assert_eq!(error_code(&json_body(res).await), Some("busy"), "code");
    }

    #[tokio::test]
    async fn delete_unparsable_vm_label_is_not_in_use() {
        let h = harness(Limits::default());
        plant_vm(h.dir.path(), "abc123aaa011", Some("not a ref"), "tenant1");
        let res = send(
            h.app,
            "DELETE",
            "/v1/images?reference=alpine",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "skip unparsable");
    }

    #[test]
    fn production_uses_runtime_preflight_not_second_oci() {
        let prod = include_str!("images.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(prod.contains("canonical_reference"), "parse");
        assert!(prod.contains("manifest_compressed_bytes"), "pull byte cap");
        assert!(prod.contains("data_dir_usage"), "disk cap");
        assert!(prod.contains("remove_image"), "delete");
        assert!(prod.contains(".pull("), "Runtime::pull");
        let pull_fn = prod
            .split("async fn pull_image(")
            .nth(1)
            .and_then(|rest| rest.split("\nasync fn ").next())
            .expect("pull_image");
        let disk = pull_fn.find("admit_disk").expect("disk");
        let manifest = pull_fn.find("manifest_compressed_bytes").expect("manifest");
        let pull = pull_fn.find(".pull(").expect("pull");
        assert!(disk < manifest, "disk cap before manifest");
        assert!(manifest < pull, "manifest cap before pull");
        assert!(!prod.contains("Oci::open"), "no second OCI handle");
        assert!(!prod.contains("open_at"), "no Oci::open_at");
        assert!(
            !prod.contains("bux_oci"),
            "serve depends on bux only, not bux-oci"
        );
    }
}
