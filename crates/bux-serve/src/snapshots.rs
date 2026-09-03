//! Snapshot, clone, and restore HTTP. Wraps engine snapshot/clone/restore.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use bux::{Runtime, SnapshotInfo, Vm, VolumeMount};
use serde::{Deserialize, Serialize};

use crate::auth::Tenant;
use crate::error::{ApiError, JsonBody};
use crate::ids::{sandbox_name, validate_agent_id, workspace_volume_name};
use crate::sandboxes::{SandboxBody, WORKSPACE_GUEST_PATH, admit, load_owned};
use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/sandboxes/{id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route(
            "/v1/sandboxes/{id}/snapshots/{sid}",
            delete(delete_snapshot),
        )
        .route(
            "/v1/sandboxes/{id}/snapshots/{sid}/restore",
            post(restore_snapshot),
        )
        .route("/v1/sandboxes/{id}/clone", post(clone_one))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSnapshotRequest {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRequest {
    agent_id: String,
}

#[derive(Debug, Serialize)]
struct SnapshotBody {
    id: String,
    vm_id: String,
    name: Option<String>,
    disk_bytes: u64,
    created_at: u64,
}

impl SnapshotBody {
    fn from_info(info: &SnapshotInfo) -> Self {
        Self {
            id: info.id.clone(),
            vm_id: info.vm_id.clone(),
            name: info.name.clone(),
            disk_bytes: info.disk_bytes,
            created_at: unix_secs(info.created_at),
        }
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

async fn list_snapshots(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
) -> Result<Json<Vec<SnapshotBody>>, ApiError> {
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let snaps = vm.list_snapshots().map_err(ApiError::from_engine)?;
    Ok(Json(snaps.iter().map(SnapshotBody::from_info).collect()))
}

async fn create_snapshot(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<CreateSnapshotRequest>,
) -> Result<(StatusCode, Json<SnapshotBody>), ApiError> {
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let name = req.name.as_deref().filter(|n| !n.is_empty());
    let info = vm
        .create_snapshot(name)
        .await
        .map_err(ApiError::from_engine)?;
    tracing::info!(
        tenant_id = %tenant.id,
        vm_id = %id,
        snapshot_id = %info.id,
        "snapshot created"
    );
    Ok((StatusCode::CREATED, Json(SnapshotBody::from_info(&info))))
}

async fn delete_snapshot(
    State(state): State<AppState>,
    tenant: Tenant,
    Path((id, sid)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let _snap = owned_snapshot(&vm, &id, &sid)?;
    vm.delete_snapshot(&sid).map_err(ApiError::from_engine)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn restore_snapshot(
    State(state): State<AppState>,
    tenant: Tenant,
    Path((id, sid)): Path<(String, String)>,
    JsonBody(req): JsonBody<AgentRequest>,
) -> Result<(StatusCode, Json<SandboxBody>), ApiError> {
    validate_agent_id(&req.agent_id)?;
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let snap = owned_snapshot(&vm, &id, &sid)?;
    let info = vm.info();
    let name = prepare_spawn(&state, &tenant.id, &req.agent_id, info.ram_mib, info.vcpus)?;
    let restored = state
        .runtime
        .restore(&snap.id, Some(name))
        .await
        .map_err(ApiError::from_engine)?;
    finish_spawn(&state.runtime, &tenant, &req.agent_id, &restored)
}

async fn clone_one(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<AgentRequest>,
) -> Result<(StatusCode, Json<SandboxBody>), ApiError> {
    validate_agent_id(&req.agent_id)?;
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let info = vm.info();
    let name = prepare_spawn(&state, &tenant.id, &req.agent_id, info.ram_mib, info.vcpus)?;
    let cloned = Runtime::clone(&state.runtime, &info.id, Some(name))
        .await
        .map_err(ApiError::from_engine)?;
    finish_spawn(&state.runtime, &tenant, &req.agent_id, &cloned)
}

fn prepare_spawn(
    state: &AppState,
    tenant_id: &str,
    agent_id: &str,
    ram_mib: u32,
    vcpus: u8,
) -> Result<String, ApiError> {
    let name = sandbox_name(tenant_id, agent_id)?;
    reject_occupied(&state.runtime, &name)?;
    admit(state, tenant_id, ram_mib, vcpus)?;
    Ok(name)
}

fn finish_spawn(
    runtime: &Runtime,
    tenant: &Tenant,
    agent_id: &str,
    vm: &Vm,
) -> Result<(StatusCode, Json<SandboxBody>), ApiError> {
    let info = vm.info();
    attach_workspace(runtime, &tenant.id, agent_id, &info.id)?;
    tracing::info!(
        tenant_id = %tenant.id,
        agent_id,
        id = %info.id,
        "sandbox cloned or restored"
    );
    Ok((StatusCode::CREATED, Json(SandboxBody::from_info(&info))))
}

fn owned_snapshot(vm: &Vm, vm_id: &str, sid: &str) -> Result<SnapshotInfo, ApiError> {
    let snaps = vm.list_snapshots().map_err(ApiError::from_engine)?;
    let snap = snaps
        .into_iter()
        .find(|s| s.id == sid)
        .ok_or_else(ApiError::not_found)?;
    if snap.vm_id != vm_id {
        return Err(ApiError::not_found());
    }
    Ok(snap)
}

fn reject_occupied(runtime: &Runtime, name: &str) -> Result<(), ApiError> {
    if let Some(vm) = runtime.get_named(name).map_err(ApiError::from_engine)? {
        return Err(ApiError::name_occupied(vm.info().id));
    }
    Ok(())
}

/// Engine clone/restore do not copy source volumes. HTTP clones always have a
/// unique agent, so attach `ws-{tenant}-{agent}` after create if create did not.
fn attach_workspace(
    runtime: &Runtime,
    tenant_id: &str,
    agent_id: &str,
    vm_id: &str,
) -> Result<(), ApiError> {
    let name = workspace_volume_name(tenant_id, agent_id)?;
    let resolved = runtime
        .volumes()
        .resolve_mounts(&[VolumeMount::named(name, WORKSPACE_GUEST_PATH)])
        .map_err(ApiError::from_engine)?;
    runtime
        .volumes()
        .link_vm(vm_id, &resolved)
        .map_err(ApiError::from_engine)
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
    use axum::http::{Request, header};
    use rusqlite::params;
    use tower::ServiceExt;

    use crate::ApiKey;
    use crate::router::router;
    use crate::state::Limits;

    struct Harness {
        dir: tempfile::TempDir,
        runtime: Arc<Runtime>,
        app: Router,
    }

    fn harness(limits: Limits) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let opened = Runtime::open(dir.path()).unwrap();
        let state = AppState::new(
            vec![
                ApiKey::new("tenant1", "secret1").unwrap(),
                ApiKey::new("tenant2", "secret2").unwrap(),
            ],
            opened,
            limits,
        );
        let runtime = Arc::clone(&state.runtime);
        let app = router(state);
        Harness { dir, runtime, app }
    }

    fn open_db(data_dir: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(data_dir.join("bux.db")).unwrap();
        conn.busy_timeout(Duration::from_secs(5)).unwrap();
        conn
    }

    fn plant_vm(
        data_dir: &Path,
        id: &str,
        name: &str,
        pid: i32,
        status: &str,
        config: &serde_json::Value,
    ) {
        let socket = data_dir.join("socks").join(format!("{id}.sock"));
        open_db(data_dir)
            .execute(
                "INSERT INTO vms (id, name, pid, image, socket, status, config, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![
                    id,
                    name,
                    pid,
                    Option::<String>::None,
                    socket.to_str().expect("socket utf-8"),
                    status,
                    config.to_string(),
                ],
            )
            .unwrap();
    }

    fn plant_snapshot(
        data_dir: &Path,
        id: &str,
        vm_id: &str,
        name: Option<&str>,
        disk_path: &str,
        disk_bytes: i64,
    ) {
        open_db(data_dir)
            .execute(
                "INSERT INTO snapshots (id, vm_id, name, disk_path, disk_bytes, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![id, vm_id, name, disk_path, disk_bytes],
            )
            .unwrap();
    }

    fn owned_config(tenant: &str, agent: &str) -> serde_json::Value {
        serde_json::json!({
            "vcpus": 1,
            "ram_mib": 512,
            "tenant_id": tenant,
            "agent_id": agent,
        })
    }

    fn dead_pid() -> i32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        drop(child.wait());
        pid
    }

    fn error_code(v: &serde_json::Value) -> Option<&str> {
        v.pointer("/error/code").and_then(serde_json::Value::as_str)
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
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        app.oneshot(builder.body(body).unwrap()).await.unwrap()
    }

    const SRC: &str = "abc123aaa001";
    const OTHER: &str = "abc123aaa002";
    const SNAP: &str = "snap00000001";

    fn plant_owned_stopped(h: &Harness, id: &str, agent: &str) {
        plant_vm(
            h.dir.path(),
            id,
            &format!("a-tenant1-{agent}"),
            dead_pid(),
            "stopped",
            &owned_config("tenant1", agent),
        );
    }

    #[tokio::test]
    async fn snapshots_without_bearer_is_401() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
        assert_eq!(error_code(&json_body(res).await), Some("unauthorized"));
    }

    #[tokio::test]
    async fn snapshots_missing_sandbox_is_404() {
        let h = harness(Limits::default());
        let res = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing");
        assert_eq!(error_code(&json_body(res).await), Some("not_found"));
    }

    #[tokio::test]
    async fn snapshots_other_tenant_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        let missing = send(
            h.app.clone(),
            "GET",
            "/v1/sandboxes/ffffffffffff",
            Some("secret2"),
            Body::empty(),
        )
        .await;
        let other = send(
            h.app.clone(),
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret2"),
            Body::empty(),
        )
        .await;
        let other_post = send(
            h.app.clone(),
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret2"),
            Body::from("{}"),
        )
        .await;
        let other_clone = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret2"),
            Body::from(r#"{"agent_id":"c1"}"#),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "missing");
        assert_eq!(other.status(), StatusCode::NOT_FOUND, "other list");
        assert_eq!(other_post.status(), StatusCode::NOT_FOUND, "other create");
        assert_eq!(other_clone.status(), StatusCode::NOT_FOUND, "other clone");
        let envelope = json_body(missing).await;
        assert_eq!(json_body(other).await, envelope, "list envelope");
        assert_eq!(json_body(other_post).await, envelope, "create envelope");
        assert_eq!(json_body(other_clone).await, envelope, "clone envelope");
    }

    #[tokio::test]
    async fn list_planted_snapshot_omits_disk_path() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(
            h.dir.path(),
            SNAP,
            SRC,
            Some("s1"),
            "/secret/host/snap.qcow2",
            42,
        );
        let res = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "list");
        let v = json_body(res).await;
        let row = v.as_array().and_then(|a| a.first()).expect("one snap");
        assert_eq!(
            row.get("id").and_then(serde_json::Value::as_str),
            Some(SNAP)
        );
        assert_eq!(
            row.get("vm_id").and_then(serde_json::Value::as_str),
            Some(SRC)
        );
        assert_eq!(
            row.get("name").and_then(serde_json::Value::as_str),
            Some("s1")
        );
        assert_eq!(
            row.get("disk_bytes").and_then(serde_json::Value::as_u64),
            Some(42)
        );
        assert!(row.get("disk_path").is_none(), "host path must not leak");
        assert!(
            row.get("created_at")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
    }

    #[tokio::test]
    async fn create_snapshot_without_overlay_is_409() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::from("{}"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "no overlay");
        assert_eq!(error_code(&json_body(res).await), Some("invalid_state"));
    }

    #[tokio::test]
    async fn create_snapshot_copies_overlay_without_hypervisor() {
        let h = harness(Limits::default());
        let overlay = h.dir.path().join("overlay.qcow2");
        std::fs::write(&overlay, b"qcow-bytes").unwrap();
        plant_vm(
            h.dir.path(),
            SRC,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "a1",
                "root_disk": overlay.to_str().expect("utf-8"),
            }),
        );
        let res = send(
            h.app.clone(),
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::from(r#"{"name":"marker"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED, "created");
        let v = json_body(res).await;
        assert!(v.get("disk_path").is_none(), "omit host path");
        assert_eq!(
            v.get("name").and_then(serde_json::Value::as_str),
            Some("marker")
        );
        assert_eq!(
            v.get("disk_bytes").and_then(serde_json::Value::as_u64),
            Some(10)
        );
        assert_eq!(
            v.get("vm_id").and_then(serde_json::Value::as_str),
            Some(SRC)
        );
        let sid = v.get("id").and_then(serde_json::Value::as_str).expect("id");
        assert!(!sid.is_empty(), "snapshot id");

        let after_create = send(
            h.app.clone(),
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        let rows = json_body(after_create).await;
        assert_eq!(rows.as_array().map(Vec::len), Some(1), "listed");

        let del = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{SRC}/snapshots/{sid}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::NO_CONTENT, "deleted");
        let after_delete = send(
            h.app,
            "GET",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            json_body(after_delete).await,
            serde_json::json!([]),
            "empty"
        );
    }

    #[tokio::test]
    async fn delete_snapshot_wrong_vm_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_owned_stopped(&h, OTHER, "a2");
        plant_snapshot(h.dir.path(), SNAP, OTHER, Some("x"), "/tmp/x.qcow2", 1);
        let res = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "foreign snap");
        assert_eq!(error_code(&json_body(res).await), Some("not_found"));
        assert!(
            h.runtime
                .get_exact(OTHER)
                .unwrap()
                .list_snapshots()
                .unwrap()
                .iter()
                .any(|s| s.id == SNAP),
            "must not delete the other VM's snapshot"
        );
    }

    #[tokio::test]
    async fn delete_snapshot_other_tenant_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(h.dir.path(), SNAP, SRC, Some("s"), "/tmp/s.qcow2", 1);
        let res = send(
            h.app,
            "DELETE",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}"),
            Some("secret2"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "other tenant");
    }

    #[tokio::test]
    async fn restore_missing_snapshot_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"r1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing snap");
    }

    #[tokio::test]
    async fn restore_wrong_vm_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_owned_stopped(&h, OTHER, "a2");
        plant_snapshot(h.dir.path(), SNAP, OTHER, Some("x"), "/tmp/x.qcow2", 1);
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"r1"}"#),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "snap belongs elsewhere"
        );
    }

    #[tokio::test]
    async fn restore_after_source_delete_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(h.dir.path(), SNAP, SRC, Some("s"), "/tmp/s.qcow2", 1);
        let del = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{SRC}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::NO_CONTENT, "source gone");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"r1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "CASCADE");
        assert_eq!(error_code(&json_body(res).await), Some("not_found"));
    }

    #[tokio::test]
    async fn restore_and_clone_require_agent_id() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(h.dir.path(), SNAP, SRC, Some("s"), "/tmp/s.qcow2", 1);
        let restore = send(
            h.app.clone(),
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret1"),
            Body::from("{}"),
        )
        .await;
        let clone = send(
            h.app.clone(),
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from("{}"),
        )
        .await;
        let hyphen = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"a-b"}"#),
        )
        .await;
        assert_eq!(restore.status(), StatusCode::BAD_REQUEST, "restore body");
        assert_eq!(clone.status(), StatusCode::BAD_REQUEST, "clone body");
        assert_eq!(hyphen.status(), StatusCode::BAD_REQUEST, "hyphen agent");
        assert_eq!(error_code(&json_body(hyphen).await), Some("invalid_config"));
    }

    #[tokio::test]
    async fn clone_unknown_field_is_400() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"c1","bind":"/tmp"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown field");
    }

    #[tokio::test]
    async fn clone_name_occupied_is_409() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_owned_stopped(&h, OTHER, "dst");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"dst"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "occupied");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("name_occupied"));
        assert_eq!(
            v.pointer("/error/existing_id")
                .and_then(serde_json::Value::as_str),
            Some(OTHER)
        );
    }

    #[tokio::test]
    async fn clone_admission_count_is_429() {
        let h = harness(Limits {
            max_sandboxes: 1,
            ..Limits::default()
        });
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"c1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "count");
        assert_eq!(
            error_code(&json_body(res).await),
            Some("resource_exhausted")
        );
    }

    #[tokio::test]
    async fn clone_admission_running_ram_is_429() {
        let h = harness(Limits {
            max_running_ram_mib: 100,
            ..Limits::default()
        });
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/clone"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"c1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "ram");
        assert_eq!(
            error_code(&json_body(res).await),
            Some("resource_exhausted")
        );
    }

    #[tokio::test]
    async fn restore_admission_is_429() {
        let h = harness(Limits {
            max_sandboxes: 1,
            ..Limits::default()
        });
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(h.dir.path(), SNAP, SRC, Some("s"), "/tmp/s.qcow2", 1);
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret1"),
            Body::from(r#"{"agent_id":"r1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "count");
    }

    #[tokio::test]
    async fn restore_other_tenant_is_404() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        plant_snapshot(h.dir.path(), SNAP, SRC, Some("s"), "/tmp/s.qcow2", 1);
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots/{SNAP}/restore"),
            Some("secret2"),
            Body::from(r#"{"agent_id":"r1"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "other tenant");
    }

    #[tokio::test]
    async fn create_snapshot_unknown_field_is_400() {
        let h = harness(Limits::default());
        plant_owned_stopped(&h, SRC, "a1");
        let res = send(
            h.app,
            "POST",
            &format!("/v1/sandboxes/{SRC}/snapshots"),
            Some("secret1"),
            Body::from(r#"{"name":"s","disk_path":"/tmp"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown field");
    }

    #[test]
    fn handlers_never_call_runtime_get() {
        let prod = include_str!("snapshots.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        let forbidden = concat!("runtime.get", "(");
        for (i, line) in prod.lines().enumerate() {
            assert!(
                !line.contains(forbidden),
                "HTTP must use get_exact via load_owned, line {}: {line}",
                i + 1
            );
        }
        assert!(prod.contains("load_owned"), "ownership via load_owned");
        assert!(
            prod.contains("Runtime::clone"),
            "Arc::clone would drop source id"
        );
    }

    #[test]
    fn snapshot_json_type_has_no_disk_path_field() {
        let body = SnapshotBody {
            id: "s".into(),
            vm_id: "v".into(),
            name: None,
            disk_bytes: 0,
            created_at: 0,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v.get("disk_path").is_none(), "serde omit");
        assert!(v.get("id").is_some());
        assert!(v.get("disk_bytes").is_some());
    }
}
