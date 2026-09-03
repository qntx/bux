//! Sandbox HTTP: list, create, exact-id get, DELETE (stop + remove + workspace volume).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use bux::{
    EgressClass, NetworkSpec, Runtime, SecurityOptions, Status, Vm, VmInfo, VmOptions, VolumeMount,
};
use serde::{Deserialize, Serialize};

use crate::auth::Tenant;
use crate::error::{ApiError, JsonBody};
use crate::ids::{sandbox_name, validate_agent_id, workspace_volume_name};
use crate::state::AppState;

const WORKSPACE_GUEST_PATH: &str = "/workspace";
const DEFAULT_AUTO_STOP_SECS: u64 = 1800;
const STOP_WAIT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sandboxes", get(list).post(create))
        .route("/v1/sandboxes/{id}", get(get_one).delete(delete_one))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    agent_id: String,
    image: String,
    #[serde(default)]
    vcpus: Option<u8>,
    #[serde(default)]
    ram_mib: Option<u32>,
    #[serde(default)]
    allow_net: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    auto_stop_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SandboxBody {
    id: String,
    name: Option<String>,
    agent_id: Option<String>,
    tenant_id: Option<String>,
    image: Option<String>,
    status: &'static str,
    ram_mib: u32,
    vcpus: u8,
    network: NetworkSpec,
    egress: EgressClass,
    isolation_note: &'static str,
    secrets_required: bool,
    workload_env: Vec<String>,
    workload_workdir: Option<String>,
    created_at: u64,
}

impl SandboxBody {
    fn from_info(info: &VmInfo) -> Self {
        Self {
            id: info.id.clone(),
            name: info.name.clone(),
            agent_id: info.agent_id.clone(),
            tenant_id: info.tenant_id.clone(),
            image: info.image.clone(),
            status: status_str(info.status),
            ram_mib: info.ram_mib,
            vcpus: info.vcpus,
            network: info.network.clone(),
            egress: info.egress.clone(),
            isolation_note: info.isolation_note,
            secrets_required: info.secrets_required,
            workload_env: info.workload_env.clone(),
            workload_workdir: info.workload_workdir.clone(),
            created_at: unix_secs(info.created_at),
        }
    }
}

const fn status_str(status: Status) -> &'static str {
    match status {
        Status::Running => "running",
        Status::Stopping => "stopping",
        Status::Stopped | _ => "stopped",
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn is_vm_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

async fn list(
    State(state): State<AppState>,
    tenant: Tenant,
) -> Result<Json<Vec<SandboxBody>>, ApiError> {
    let infos = state.runtime.list().map_err(ApiError::from_engine)?;
    let body = infos
        .iter()
        .filter(|vm| vm.tenant_id.as_deref() == Some(tenant.id.as_str()))
        .map(SandboxBody::from_info)
        .collect();
    Ok(Json(body))
}

async fn get_one(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
) -> Result<Json<SandboxBody>, ApiError> {
    let vm = load_owned(&state.runtime, &tenant.id, &id)?;
    Ok(Json(SandboxBody::from_info(&vm.info())))
}

async fn create(
    State(state): State<AppState>,
    tenant: Tenant,
    JsonBody(req): JsonBody<CreateRequest>,
) -> Result<(StatusCode, Json<SandboxBody>), ApiError> {
    validate_agent_id(&req.agent_id)?;
    if !req.allow_net.is_empty() {
        return Err(ApiError::invalid_config("allow_net is not accepted").with_field("allow_net"));
    }
    let image = parse_image(&req.image)?;
    let name = sandbox_name(&tenant.id, &req.agent_id)?;
    let volume = workspace_volume_name(&tenant.id, &req.agent_id)?;

    if let Some(vm) = state
        .runtime
        .get_named(&name)
        .map_err(ApiError::from_engine)?
    {
        return existing_or_occupied(&tenant.id, &vm);
    }

    let ram_mib = req.ram_mib.unwrap_or(state.limits.default_ram_mib);
    let vcpus = req.vcpus.unwrap_or(state.limits.default_vcpus);
    admit(&state, &tenant.id, ram_mib, vcpus)?;

    let mut opts = VmOptions::from_image(image)
        .name(name.clone())
        .agent_id(req.agent_id.clone())
        .tenant_id(tenant.id.clone())
        .detach(true)
        .network(NetworkSpec::Disabled)
        .volume(VolumeMount::named(volume, WORKSPACE_GUEST_PATH))
        .auto_stop_secs(Some(req.auto_stop_secs.unwrap_or(DEFAULT_AUTO_STOP_SECS)))
        .env(req.env)
        .vcpus(vcpus)
        .ram_mib(ram_mib)
        .security(SecurityOptions::default())
        .ready_timeout(READY_TIMEOUT);
    if let Some(workdir) = req.workdir {
        opts = opts.workdir(workdir);
    }

    match state.runtime.create(opts).await {
        Ok(vm) => {
            let info = vm.info();
            tracing::info!(
                tenant_id = %tenant.id,
                agent_id = %req.agent_id,
                id = %info.id,
                "sandbox created"
            );
            Ok((StatusCode::CREATED, Json(SandboxBody::from_info(&info))))
        }
        Err(err) => match state.runtime.get_named(&name) {
            Ok(Some(vm)) => existing_or_occupied(&tenant.id, &vm),
            Ok(None) => Err(create_miss_error(err)),
            Err(lookup) => Err(ApiError::from_engine(lookup)),
        },
    }
}

async fn delete_one(
    State(state): State<AppState>,
    tenant: Tenant,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut vm = load_owned(&state.runtime, &tenant.id, &id)?;
    let info = vm.info();
    let volume = match (info.tenant_id.as_deref(), info.agent_id.as_deref()) {
        (Some(t), Some(a)) => {
            Some(workspace_volume_name(t, a).map_err(|err| ApiError::internal(err.to_string()))?)
        }
        _ => None,
    };
    stop_for_delete(&mut vm).await?;
    if vm.info().status.is_active() {
        vm.kill().map_err(ApiError::from_engine)?;
    }
    state
        .runtime
        .remove(&info.id)
        .map_err(ApiError::from_engine)?;
    if let Some(name) = volume {
        remove_workspace_volume(&state.runtime, &name)?;
    }
    tracing::info!(
        tenant_id = %tenant.id,
        id = %info.id,
        "sandbox deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

fn parse_image(image: &str) -> Result<String, ApiError> {
    if image.is_empty() {
        return Err(ApiError::invalid_config("image is required").with_field("image"));
    }
    bux::canonical_reference(image).map_err(|e| ApiError::invalid_config(e.to_string()))
}

fn existing_or_occupied(
    tenant: &str,
    vm: &Vm,
) -> Result<(StatusCode, Json<SandboxBody>), ApiError> {
    let info = vm.info();
    match info.tenant_id.as_deref() {
        Some(id) if id == tenant => Ok((StatusCode::OK, Json(SandboxBody::from_info(&info)))),
        _ => Err(ApiError::name_occupied(info.id)),
    }
}

fn create_miss_error(err: bux::Error) -> ApiError {
    match err {
        bux::Error::Ambiguous(_) => ApiError::name_occupied_unknown(),
        other => ApiError::from_engine(other),
    }
}

pub(crate) fn load_owned(runtime: &Runtime, tenant: &str, id: &str) -> Result<Vm, ApiError> {
    if !is_vm_id(id) {
        return Err(ApiError::not_found());
    }
    let vm = match runtime.get_exact(id) {
        Ok(vm) => vm,
        Err(bux::Error::NotFound(_)) => return Err(ApiError::not_found()),
        Err(err) => return Err(ApiError::from_engine(err)),
    };
    if vm.info().tenant_id.as_deref() != Some(tenant) {
        return Err(ApiError::not_found());
    }
    Ok(vm)
}

fn admit(state: &AppState, tenant: &str, ram_mib: u32, vcpus: u8) -> Result<(), ApiError> {
    if ram_mib == 0 {
        return Err(ApiError::invalid_config("ram_mib must be >= 1").with_field("ram_mib"));
    }
    if vcpus == 0 {
        return Err(ApiError::invalid_config("vcpus must be >= 1").with_field("vcpus"));
    }
    if ram_mib > state.limits.max_ram_mib {
        return Err(
            ApiError::invalid_config("ram_mib exceeds the per-sandbox maximum")
                .with_field("ram_mib"),
        );
    }
    if vcpus > state.limits.max_vcpus {
        return Err(
            ApiError::invalid_config("vcpus exceeds the per-sandbox maximum").with_field("vcpus"),
        );
    }
    let infos = state.runtime.list().map_err(ApiError::from_engine)?;
    let tenant_n = infos
        .iter()
        .filter(|vm| vm.tenant_id.as_deref() == Some(tenant))
        .count();
    if tenant_n >= usize_cap(state.limits.max_sandboxes) {
        return Err(ApiError::resource_exhausted("tenant sandbox limit reached"));
    }
    if infos.len() >= usize_cap(state.limits.max_sandboxes_global) {
        return Err(ApiError::resource_exhausted("global sandbox limit reached"));
    }
    let running: u64 = infos
        .iter()
        .filter(|vm| vm.status.is_active())
        .map(|vm| u64::from(vm.ram_mib))
        .sum();
    if running.saturating_add(u64::from(ram_mib)) > u64::from(state.limits.max_running_ram_mib) {
        return Err(ApiError::resource_exhausted("running RAM limit reached"));
    }
    let usage = state
        .runtime
        .data_dir_usage()
        .map_err(|e| ApiError::from_engine(e.into()))?;
    if usage >= state.limits.max_disk_bytes {
        return Err(ApiError::resource_exhausted("disk limit reached"));
    }
    Ok(())
}

fn usize_cap(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

async fn stop_for_delete(vm: &mut Vm) -> Result<(), ApiError> {
    match vm.info().status {
        Status::Running => {
            if vm.stop_timeout(STOP_WAIT).await.is_err() {
                vm.kill().map_err(ApiError::from_engine)?;
            }
        }
        Status::Stopping => match tokio::time::timeout(STOP_WAIT, vm.wait()).await {
            Ok(Ok(())) => {}
            _ => vm.kill().map_err(ApiError::from_engine)?,
        },
        _ => {}
    }
    Ok(())
}

fn remove_workspace_volume(runtime: &Runtime, name: &str) -> Result<(), ApiError> {
    match runtime.volumes().remove(name) {
        Ok(()) | Err(bux::Error::NotFound(_)) => Ok(()),
        Err(bux::Error::Busy(message)) => Err(ApiError::internal(message)),
        Err(err) => Err(ApiError::from_engine(err)),
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

    fn test_app(limits: Limits) -> (tempfile::TempDir, Router) {
        let h = harness(limits);
        (h.dir, h.app)
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
                 VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, 0)",
                params![
                    id,
                    name,
                    pid,
                    socket.to_str().expect("socket utf-8"),
                    status,
                    config.to_string(),
                ],
            )
            .unwrap();
    }

    fn dead_pid() -> i32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        drop(child.wait());
        pid
    }

    fn attach_volume(data_dir: &Path, vm_id: &str, volume_id: &str) {
        open_db(data_dir)
            .execute(
                "INSERT INTO vm_volumes (vm_id, volume_id, guest_path) VALUES (?1, ?2, ?3)",
                params![vm_id, volume_id, WORKSPACE_GUEST_PATH],
            )
            .unwrap();
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

    #[tokio::test]
    async fn list_without_bearer_is_401() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(app, "GET", "/v1/sandboxes", None, Body::empty()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("unauthorized"),
            "code"
        );
    }

    #[tokio::test]
    async fn list_empty_for_tenant() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(app, "GET", "/v1/sandboxes", Some("secret1"), Body::empty()).await;
        assert_eq!(res.status(), StatusCode::OK, "status");
        let v = json_body(res).await;
        assert_eq!(v, serde_json::json!([]), "empty list");
    }

    #[tokio::test]
    async fn get_missing_is_404_envelope() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789ab",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("not_found"),
            "code"
        );
        assert!(
            v.pointer("/error/existing_id").is_none(),
            "no existing_id on 404"
        );
    }

    #[tokio::test]
    async fn get_non_hex_id_is_404() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/abcd",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "short id");
    }

    #[tokio::test]
    async fn get_uppercase_hex_id_is_404() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "GET",
            "/v1/sandboxes/0123456789AB",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "uppercase");
    }

    #[tokio::test]
    async fn delete_missing_is_404() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "DELETE",
            "/v1/sandboxes/0123456789ab",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("not_found"),
            "code"
        );
    }

    #[tokio::test]
    async fn post_without_bearer_is_401() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            None,
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "status");
    }

    #[tokio::test]
    async fn post_hyphen_agent_id_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a-b","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("invalid_config"),
            "code"
        );
    }

    #[tokio::test]
    async fn post_missing_agent_id_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("invalid_config"),
            "code"
        );
    }

    #[tokio::test]
    async fn post_unknown_field_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","bind":"/tmp"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
    }

    #[tokio::test]
    async fn post_allow_net_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","allow_net":["example.com"]}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("allow_net"),
            "field"
        );
    }

    #[tokio::test]
    async fn post_invalid_image_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"not a ref"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
    }

    #[tokio::test]
    async fn admission_ram_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","ram_mib":4096}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("invalid_config"),
            "code"
        );
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("ram_mib"),
            "field"
        );
    }

    #[tokio::test]
    async fn admission_vcpus_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","vcpus":8}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/field")
                .and_then(serde_json::Value::as_str),
            Some("vcpus"),
            "field"
        );
    }

    #[tokio::test]
    async fn admission_zero_ram_is_400() {
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","ram_mib":0}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "zero ram");
    }

    #[tokio::test]
    async fn admission_tenant_count_is_429() {
        let limits = Limits {
            max_sandboxes: 0,
            ..Limits::default()
        };
        let (_dir, app) = test_app(limits);
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("resource_exhausted"),
            "code"
        );
    }

    #[tokio::test]
    async fn admission_running_ram_counts_live_vm_info() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let h = harness(Limits {
            max_running_ram_mib: 1000,
            ..Limits::default()
        });
        plant_vm(
            h.dir.path(),
            "cafebabe0001",
            "a-tenant1-live",
            pid,
            "running",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 700,
                "tenant_id": "tenant1",
                "agent_id": "live",
            }),
        );
        let res = send(
            h.app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","ram_mib":512}"#),
        )
        .await;
        drop(child.kill());
        drop(child.wait());
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "live ram sum");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("resource_exhausted"), "code");
    }

    #[tokio::test]
    async fn admission_running_ram_ignores_dead_pid() {
        let h = harness(Limits {
            max_running_ram_mib: 1000,
            ..Limits::default()
        });
        plant_vm(
            h.dir.path(),
            "cafebabe0002",
            "a-tenant1-dead",
            dead_pid(),
            "running",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 700,
                "tenant_id": "tenant1",
                "agent_id": "dead",
            }),
        );
        if bux::HostInfo::probe().virtualization {
            return;
        }
        let res = send(
            h.app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","ram_mib":512}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED, "no create");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("security_unavailable"), "code");
    }

    #[tokio::test]
    async fn admission_disk_is_429() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(dir.path()).unwrap();
        let disk = runtime.disk_usage().unwrap();
        let data = runtime.data_dir_usage().unwrap();
        assert!(
            data > disk,
            "data_dir_usage={data} must exceed disk_usage={disk}"
        );
        let cap = disk.saturating_add(1);
        assert!(
            cap <= data,
            "cap {cap} must be in (disk_usage, data_dir_usage]"
        );
        let state = AppState::new(
            vec![ApiKey::new("tenant1", "secret1").unwrap()],
            runtime,
            Limits {
                max_disk_bytes: cap,
                ..Limits::default()
            },
        );
        let app = router(state);
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "status");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("resource_exhausted"), "code");
    }

    #[tokio::test]
    async fn same_tenant_post_returns_existing_without_create() {
        const ID: &str = "abc123aaa001";
        let h = harness(Limits::default());
        plant_vm(
            h.dir.path(),
            ID,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "a1",
            }),
        );
        let created = send(
            h.app.clone(),
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine","ram_mib":2048}"#),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK, "same tenant");
        let body = json_body(created).await;
        assert_eq!(body.get("id").and_then(serde_json::Value::as_str), Some(ID));
        assert_eq!(
            body.get("ram_mib").and_then(serde_json::Value::as_u64),
            Some(512),
            "must not compare or overwrite ram"
        );

        let got = send(
            h.app.clone(),
            "GET",
            &format!("/v1/sandboxes/{ID}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(got.status(), StatusCode::OK, "owner get");

        let missing = send(
            h.app.clone(),
            "GET",
            "/v1/sandboxes/ffffffffffff",
            Some("secret2"),
            Body::empty(),
        )
        .await;
        let other_get = send(
            h.app.clone(),
            "GET",
            &format!("/v1/sandboxes/{ID}"),
            Some("secret2"),
            Body::empty(),
        )
        .await;
        let other_del = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{ID}"),
            Some("secret2"),
            Body::empty(),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "missing");
        assert_eq!(other_get.status(), StatusCode::NOT_FOUND, "other get");
        assert_eq!(other_del.status(), StatusCode::NOT_FOUND, "other delete");
        let missing_json = json_body(missing).await;
        assert_eq!(json_body(other_get).await, missing_json, "get envelope");
        assert_eq!(json_body(other_del).await, missing_json, "delete envelope");

        let list2 = send(
            h.app.clone(),
            "GET",
            "/v1/sandboxes",
            Some("secret2"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            json_body(list2).await,
            serde_json::json!([]),
            "tenant2 list"
        );
        let list1 = send(
            h.app,
            "GET",
            "/v1/sandboxes",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        let listed = json_body(list1).await;
        let row = listed.as_array().and_then(|a| a.first());
        assert_eq!(
            row.and_then(|item| item.get("id"))
                .and_then(serde_json::Value::as_str),
            Some(ID),
            "tenant1 list"
        );
    }

    #[tokio::test]
    async fn none_tenant_name_is_occupied() {
        const ID: &str = "abc123aaa002";
        let h = harness(Limits::default());
        plant_vm(
            h.dir.path(),
            ID,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": null,
                "agent_id": "a1",
            }),
        );
        let res = send(
            h.app.clone(),
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "occupied");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("name_occupied"), "code");
        assert_eq!(
            v.pointer("/error/existing_id")
                .and_then(serde_json::Value::as_str),
            Some(ID),
            "existing_id"
        );
        let list = send(
            h.app,
            "GET",
            "/v1/sandboxes",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            json_body(list).await,
            serde_json::json!([]),
            "cli vm omitted"
        );
    }

    #[tokio::test]
    async fn other_tenant_name_is_occupied() {
        const ID: &str = "abc123aaa003";
        let h = harness(Limits::default());
        plant_vm(
            h.dir.path(),
            ID,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant2",
                "agent_id": "a1",
            }),
        );
        let res = send(
            h.app.clone(),
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT, "occupied");
        let v = json_body(res).await;
        assert_eq!(error_code(&v), Some("name_occupied"), "code");
        assert_eq!(
            v.pointer("/error/existing_id")
                .and_then(serde_json::Value::as_str),
            Some(ID),
            "existing_id"
        );
        let list1 = send(
            h.app.clone(),
            "GET",
            "/v1/sandboxes",
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            json_body(list1).await,
            serde_json::json!([]),
            "owner is tenant2"
        );
        let list2 = send(
            h.app,
            "GET",
            "/v1/sandboxes",
            Some("secret2"),
            Body::empty(),
        )
        .await;
        let listed = json_body(list2).await;
        let row = listed.as_array().and_then(|a| a.first());
        assert_eq!(
            row.and_then(|item| item.get("id"))
                .and_then(serde_json::Value::as_str),
            Some(ID),
            "tenant2 list"
        );
    }

    #[tokio::test]
    async fn delete_owned_removes_workspace_volume() {
        const ID: &str = "abc123aaa004";
        const VOL: &str = "ws-tenant1-a1";
        let h = harness(Limits::default());
        plant_vm(
            h.dir.path(),
            ID,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "a1",
            }),
        );
        let info = h.runtime.volumes().create(VOL).unwrap();
        attach_volume(h.dir.path(), ID, &info.id);
        let vol_dir = h.dir.path().join("volumes").join(VOL);
        assert!(vol_dir.is_dir(), "volume dir planted");

        let res = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{ID}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "delete");
        assert!(
            matches!(h.runtime.get_exact(ID), Err(bux::Error::NotFound(_))),
            "row gone"
        );
        assert!(
            matches!(h.runtime.volumes().get(VOL), Err(bux::Error::NotFound(_))),
            "volume row gone"
        );
        assert!(!vol_dir.exists(), "volume directory gone");
    }

    #[tokio::test]
    async fn delete_invalid_stored_ids_is_500() {
        const ID: &str = "abc123aaa005";
        let h = harness(Limits::default());
        plant_vm(
            h.dir.path(),
            ID,
            "a-tenant1-a1",
            dead_pid(),
            "stopped",
            &serde_json::json!({
                "vcpus": 1,
                "ram_mib": 512,
                "tenant_id": "tenant1",
                "agent_id": "bad-id",
            }),
        );
        let res = send(
            h.app.clone(),
            "DELETE",
            &format!("/v1/sandboxes/{ID}"),
            Some("secret1"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid ids"
        );
        assert!(h.runtime.get_exact(ID).is_ok(), "must not remove the VM");
    }

    #[tokio::test]
    async fn create_without_virtualization_is_412() {
        if bux::HostInfo::probe().virtualization {
            return;
        }
        let (_dir, app) = test_app(Limits::default());
        let res = send(
            app,
            "POST",
            "/v1/sandboxes",
            Some("secret1"),
            Body::from(r#"{"agent_id":"a1","image":"alpine"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED, "status");
        let v = json_body(res).await;
        assert_eq!(
            v.pointer("/error/code").and_then(serde_json::Value::as_str),
            Some("security_unavailable"),
            "code"
        );
    }

    #[test]
    fn vm_id_is_lowercase_12_hex() {
        assert!(is_vm_id("0123456789ab"), "ok");
        assert!(!is_vm_id("0123456789AB"), "upper");
        assert!(!is_vm_id("0123456789abc"), "13");
        assert!(!is_vm_id("xyzxyzxyzxyz"), "not hex");
    }

    #[test]
    fn handlers_never_call_runtime_get() {
        let src = include_str!("sandboxes.rs");
        let prod = src.split("#[cfg(test)]").next().expect("prod");
        let forbidden = concat!("runtime.get", "(");
        for (i, line) in prod.lines().enumerate() {
            assert!(
                !line.contains(forbidden),
                "HTTP must use get_exact/get_named, line {}: {line}",
                i + 1
            );
        }
        assert!(prod.contains("get_named"), "occupancy uses get_named");
        assert!(prod.contains("get_exact"), "HTTP id uses get_exact");
    }

    #[test]
    fn delete_removes_vm_before_volume() {
        let src = include_str!("sandboxes.rs");
        let prod = src.split("#[cfg(test)]").next().expect("prod");
        let vm = prod.find("remove(&info.id)").expect("Runtime::remove");
        let vol = prod.find("remove_workspace_volume").expect("volume remove");
        assert!(
            vm < vol,
            "VM row must be removed before the workspace volume"
        );
    }

    #[test]
    fn admit_uses_data_dir_usage_not_disk_usage() {
        let src = include_str!("sandboxes.rs");
        let admit = src
            .split("fn admit(")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .expect("admit");
        assert!(admit.contains("data_dir_usage"), "disk cap");
        assert!(
            !admit.contains("disk_usage"),
            "disk cap is data_dir_usage, not disk_usage"
        );
    }
}
