//! Handle to a single managed VM.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bux_proto::ExecStart;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::Serialize;
use tracing::info;

use super::HealthStatus;
use super::boot::{
    clean_vm_files, inject_guest_boot_env, is_pid_alive, prepare_restart_config,
    shim_death_message, spawn_shim, wait_for_exit,
};
use crate::Result;
use crate::client::{Client, ExecHandle, ExecOutput, PongInfo};
use crate::disk::DiskManager;
use crate::events::{AuditEvent, AuditEventKind, EventDispatcher};
use crate::metrics::{RuntimeMetrics, VmMetrics};
use crate::net_manager::NetworkManager;
use crate::options::NetworkSpec;
use crate::ports::{PublishedPort, format_port_pairs, parse_publish_spec, resolve_ports};
use crate::process::{PHASE_A_LIMITS, apply_workload_defaults};
use crate::secrets::{LiveSecrets, StartOptions};
use crate::security::{SecurityOptions, SecurityStatus};
use crate::snapshot::SnapshotManager;
use crate::state::{StateDb, Status, VmState};
use crate::volumes::VolumeManager;
use crate::watchdog::Keepalive;

/// Read-only product view of a managed VM (no persist/engine internals).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct VmInfo {
    /// Short hex identifier.
    pub id: String,
    /// Optional unique name.
    pub name: Option<String>,
    /// Shim process PID.
    pub pid: i32,
    /// Image label (OCI ref or path).
    pub image: Option<String>,
    /// Lifecycle status.
    pub status: Status,
    /// Live snapshot: Dead if the process is gone; Starting otherwise (no ping).
    pub health: HealthStatus,
    /// Concrete published TCP ports.
    pub published_ports: Vec<PublishedPort>,
    /// Guest network mode.
    pub network: NetworkSpec,
    /// Actual isolation posture from last spawn.
    pub security: SecurityStatus,
    /// Requested isolation policy.
    pub security_options: SecurityOptions,
    /// Phase A isolation note.
    pub isolation_note: &'static str,
    /// Last recorded error, if any.
    pub last_error: Option<String>,
    /// Creation timestamp.
    pub created_at: SystemTime,
    /// Optional first command (OCI ENTRYPOINT+CMD or CLI override).
    pub workload_cmd: Vec<String>,
}

impl VmInfo {
    /// Project stored state into a product view (no guest ping).
    pub(crate) fn from_stored(state: &VmState) -> Self {
        let health = if state.status == Status::Stopped || !is_pid_alive(state.pid) {
            HealthStatus::Dead
        } else {
            HealthStatus::Starting
        };
        let network = state.config.network.clone();
        Self {
            id: state.id.clone(),
            name: state.name.clone(),
            pid: state.pid,
            image: state.image.clone(),
            status: state.status,
            health,
            published_ports: state.config.published_ports.clone(),
            network,
            security: state.config.security_status.clone(),
            security_options: state.config.security,
            isolation_note: PHASE_A_LIMITS,
            last_error: state.config.last_error.clone(),
            created_at: state.created_at,
            workload_cmd: state.config.workload_cmd.clone(),
        }
    }
}

/// Handle to a single managed VM.
#[derive(Debug)]
pub struct Vm {
    /// Cached state snapshot.
    state: VmState,
    /// Shared database reference for status updates.
    db: Arc<StateDb>,
    /// Disk image manager for auto-remove cleanup.
    disk: DiskManager,
    /// Stateless client (opens a new connection per operation).
    client: Client,
    /// Watchdog keepalive — dropping this signals the shim to shut down.
    /// `None` when reconnecting to a VM spawned in a previous session.
    #[allow(dead_code, reason = "held for RAII; drop signals shim shutdown")]
    keepalive: Option<Keepalive>,
    /// Runtime-level metrics (shared with Runtime).
    runtime_metrics: Arc<RuntimeMetrics>,
    /// Per-VM metrics.
    metrics: VmMetrics,
    /// Event dispatcher (shared with Runtime).
    events: Arc<EventDispatcher>,
    /// Snapshot manager (shared with Runtime).
    snapshots: SnapshotManager,
    /// Network manager (shared with Runtime).
    net: Arc<NetworkManager>,
    /// Memory-only secrets map (shared with Runtime).
    secrets: Arc<Mutex<HashMap<String, LiveSecrets>>>,
    /// Named volumes (shared with Runtime); used by abort cleanup.
    volumes: VolumeManager,
    /// When this VM was spawned (for uptime tracking).
    spawned_at: std::time::Instant,
}

impl Vm {
    /// Creates a new handle from a state snapshot.
    #[allow(
        clippy::too_many_arguments,
        reason = "handle wires shared Runtime resources"
    )]
    pub(super) fn new(
        state: VmState,
        db: Arc<StateDb>,
        disk: DiskManager,
        keepalive: Option<Keepalive>,
        runtime_metrics: Arc<RuntimeMetrics>,
        events: Arc<EventDispatcher>,
        snapshots: SnapshotManager,
        net: Arc<NetworkManager>,
        secrets: Arc<Mutex<HashMap<String, LiveSecrets>>>,
        volumes: VolumeManager,
    ) -> Self {
        let client = Client::new(&state.socket);
        Self {
            state,
            db,
            disk,
            client,
            keepalive,
            runtime_metrics,
            metrics: VmMetrics::new(),
            events,
            snapshots,
            net,
            secrets,
            volumes,
            spawned_at: std::time::Instant::now(),
        }
    }

    /// Product view of this VM (no persist JSON, no guest ping).
    #[must_use]
    pub fn info(&self) -> VmInfo {
        VmInfo::from_stored(&self.state)
    }

    /// Stored row (crate-internal).
    pub(crate) const fn stored(&self) -> &VmState {
        &self.state
    }

    /// Shim stderr log path (`{id}.stderr` next to the vsock socket).
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.state.socket.with_extension("stderr")
    }

    /// Tear down a VM that never became ready (create failure).
    pub(super) fn abort_unready(&mut self) {
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGKILL).ok();
        self.net.stop(&self.state.id);
        self.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.state.id);
        clean_vm_files(&self.state.socket);
        drop(self.volumes.unlink_vm(&self.state.id));
        drop(self.disk.remove_vm_disk(&self.state.id));
        drop(self.db.delete(&self.state.id));
        self.state.status = Status::Stopped;
    }

    /// Published TCP ports (concrete host ports after ephemeral resolution).
    ///
    /// Empty when networking is disabled or no ports were requested.
    #[must_use]
    pub fn published_ports(&self) -> &[PublishedPort] {
        &self.state.config.published_ports
    }

    /// Egress allow-list (empty = unrestricted).
    #[must_use]
    pub fn allow_net(&self) -> &[String] {
        self.state.config.network.allow_net()
    }

    /// Workload env defaults for Phase A exec (`KEY=VALUE`).
    #[must_use]
    pub fn workload_env(&self) -> &[String] {
        &self.state.config.workload_env
    }

    /// Workload working directory default for Phase A exec.
    #[must_use]
    pub fn workload_workdir(&self) -> Option<&str> {
        self.state.config.workload_workdir.as_deref()
    }

    /// Workload user string for Phase A (`uid[:gid]` or `name[:group]`).
    #[must_use]
    pub fn workload_user(&self) -> Option<&str> {
        self.state.config.workload_user.as_deref()
    }

    /// Optional first command (OCI ENTRYPOINT+CMD or CLI override).
    #[must_use]
    pub fn workload_cmd(&self) -> &[String] {
        &self.state.config.workload_cmd
    }

    /// Phase A isolation note (workload shares the guest with the agent).
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "instance accessor for inspect-shaped API"
    )]
    pub const fn phase_a_limits(&self) -> &'static str {
        PHASE_A_LIMITS
    }

    /// Actual host-side isolation posture from the last spawn (K22).
    #[must_use]
    pub const fn security_status(&self) -> &SecurityStatus {
        &self.state.config.security_status
    }

    /// Requested security policy for this VM.
    #[must_use]
    pub const fn security_options(&self) -> &SecurityOptions {
        &self.state.config.security
    }

    /// Last error recorded on this VM (e.g. secrets re-supply after recovery).
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.state.config.last_error.as_deref()
    }

    /// Persist activity timestamp for idle auto-stop / auto-delete.
    fn touch_activity_local(&self) -> Result<()> {
        let mut cfg = self.state.config.clone();
        cfg.last_activity_at = Some(SystemTime::now());
        cfg.last_error = None;
        self.db.update_config(&self.state.id, &cfg)
    }

    /// Apply stored workload defaults to an exec request (caller overrides win).
    #[must_use]
    pub fn with_workload_defaults(&self, req: ExecStart) -> ExecStart {
        apply_workload_defaults(
            req,
            &self.state.config.workload_env,
            self.state.config.workload_workdir.as_deref(),
            self.state.config.workload_user.as_deref(),
        )
    }

    /// Per-VM metrics.
    pub const fn metrics(&self) -> &VmMetrics {
        &self.metrics
    }

    /// Creates a point-in-time snapshot of this VM's disk.
    ///
    /// If the VM is running, guest filesystems are quiesced first.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM has no overlay disk or the snapshot fails.
    pub async fn create_snapshot(
        &self,
        name: Option<&str>,
    ) -> Result<crate::snapshot::SnapshotInfo> {
        let overlay = self.state.config.root_disk.as_deref().ok_or_else(|| {
            crate::Error::InvalidState("VM has no overlay disk to snapshot".to_owned())
        })?;

        let info = self
            .snapshots
            .create(
                &self.state.id,
                self.state.status,
                Path::new(overlay),
                &self.client,
                name,
            )
            .await?;

        self.events
            .emit(AuditEvent::now(AuditEventKind::SnapshotCreated {
                vm_id: self.state.id.clone(),
                snapshot_id: info.id.clone(),
            }));

        Ok(info)
    }

    /// Lists all snapshots for this VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list_snapshots(&self) -> Result<Vec<crate::snapshot::SnapshotInfo>> {
        self.snapshots.list(&self.state.id)
    }

    /// Deletes a snapshot by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot is not found or deletion fails.
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.snapshots.delete(snapshot_id)
    }

    /// Exports this VM's disk as a standalone QCOW2 image.
    ///
    /// # Errors
    ///
    /// Returns an error if the disk flattening fails.
    pub fn export(&self, dest: &Path) -> Result<()> {
        let vm_id = &self.state.id;
        self.disk.flatten_vm_disk(vm_id, dest)?;
        info!(vm_id = %vm_id, dest = %dest.display(), "VM disk exported");
        Ok(())
    }

    /// Starts a background health check task for this VM.
    #[allow(
        dead_code,
        reason = "opt-in background health; not on the product inspect path"
    )]
    pub(crate) fn enable_health_check(
        &self,
        config: crate::health::HealthCheckConfig,
    ) -> crate::health::HealthCheckHandle {
        crate::health::start(
            self.state.id.clone(),
            self.client.clone(),
            Arc::clone(&self.db),
            config,
        )
    }

    /// Probes the guest agent and returns the current health status.
    pub async fn health(&self) -> HealthStatus {
        if !self.is_alive() {
            return HealthStatus::Dead;
        }
        match tokio::time::timeout(Duration::from_secs(2), self.client.ping()).await {
            Ok(Ok(_)) => HealthStatus::Healthy,
            Ok(Err(_)) => HealthStatus::Unhealthy,
            Err(_) => HealthStatus::Starting,
        }
    }

    /// Pings the guest agent and returns agent metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent is unreachable.
    pub async fn ping(&self) -> Result<PongInfo> {
        Ok(self.client.ping().await?)
    }

    /// Starts a command on a dedicated exec connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or command start fails.
    pub async fn exec(&self, req: ExecStart) -> Result<ExecHandle> {
        let req = self.with_workload_defaults(req);
        let cmd = req.cmd.clone();
        let handle = self.client.exec(req).await?;
        drop(self.touch_activity_local());
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecStarted {
                vm_id: self.state.id.clone(),
                command: cmd,
                exec_id: handle.exec_id().to_owned(),
            }));
        Ok(handle)
    }

    /// Executes a command and collects all output.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or command execution fails.
    pub async fn exec_output(&self, req: ExecStart) -> Result<ExecOutput> {
        let req = self.with_workload_defaults(req);
        let cmd = req.cmd.clone();
        let output = self.client.exec_output(req).await?;
        drop(self.touch_activity_local());
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecStarted {
                vm_id: self.state.id.clone(),
                command: cmd,
                exec_id: output.exec_id.clone(),
            }));
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecCompleted {
                vm_id: self.state.id.clone(),
                exec_id: output.exec_id.clone(),
                exit_code: output.code,
                duration_ms: output.duration_ms,
            }));
        self.metrics.on_exec_completed(output.duration_ms);
        Ok(output)
    }

    /// Restarts a stopped VM (uses memory-held secrets if still present).
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not stopped, secrets are missing, or spawn fails.
    pub async fn start(&mut self, ready_timeout: Duration) -> Result<()> {
        self.start_with(StartOptions {
            ready_timeout: Some(ready_timeout),
            secrets: Vec::new(),
        })
        .await
    }

    /// Restart with explicit options (secret re-supply after process restart).
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not stopped, secrets cannot be resolved,
    /// or the spawn fails.
    #[allow(
        clippy::cognitive_complexity,
        reason = "restart: secrets, net, shim, ready; split would hide fail-closed order"
    )]
    pub async fn start_with(&mut self, opts: StartOptions) -> Result<()> {
        if self.state.status != Status::Stopped {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be started (status: {:?}); only stopped VMs can restart",
                self.state.id, self.state.status
            )));
        }

        prepare_restart_config(&mut self.state.config)?;

        let live = if opts.secrets.is_empty() {
            let held = {
                let guard = self
                    .secrets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.get(&self.state.id).cloned()
            };
            match held {
                Some(live) => Some(live),
                None if self.state.config.secrets_required => {
                    return Err(crate::Error::SecretsRequired);
                }
                None => None,
            }
        } else {
            if !self.state.config.network.is_enabled() {
                return Err(crate::Error::SecretsNeedVirtioNet);
            }
            let live = LiveSecrets::mint(opts.secrets)?;
            self.secrets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.state.id.clone(), live.clone());
            self.state.config.secrets_required = true;
            Some(live)
        };

        let mitm_ca = live.as_ref().map(|l| l.ca_cert_pem.clone());
        inject_guest_boot_env(&mut self.state.config, &self.state.id, mitm_ca)?;

        let network = if self.state.config.network.is_enabled() {
            let mut specs = Vec::with_capacity(self.state.config.ports.len());
            for s in &self.state.config.ports {
                specs.push(parse_publish_spec(s)?);
            }
            let (pairs, published) = resolve_ports(&specs)?;
            self.state.config.ports = format_port_pairs(&pairs);
            self.state.config.published_ports = published;
            let net = self.net.start(
                &self.state.id,
                pairs,
                self.state.config.network.allow_net().to_vec(),
                live.as_ref(),
            )?;
            Some(net.shim_network)
        } else {
            self.state.config.published_ports.clear();
            None
        };

        let config_path = self
            .state
            .socket
            .with_file_name(format!("{}.json", self.state.id));
        let socks_dir = self.state.socket.parent().unwrap_or_else(|| Path::new("."));
        let shim = match spawn_shim(
            &self.state.config,
            &config_path,
            socks_dir,
            &self.state.id,
            true,
            network,
        ) {
            Ok(s) => s,
            Err(e) => {
                self.net.stop(&self.state.id);
                return Err(e);
            }
        };

        self.state.config.security_status = shim.security.clone();
        if let Err(e) = self
            .db
            .update_pid_status(&self.state.id, shim.pid, Status::Running)
            .and_then(|()| self.db.update_config(&self.state.id, &self.state.config))
        {
            self.revert_failed_start(shim.pid);
            return Err(e);
        }
        self.state.pid = shim.pid;
        self.state.status = Status::Running;
        self.client = Client::new(&self.state.socket);
        self.keepalive = shim.keepalive;

        info!(
            vm_id = %self.state.id,
            pid = shim.pid,
            network_enabled = self.state.config.network.is_enabled(),
            secrets = self.state.config.secrets_required,
            "VM restarted"
        );
        self.spawned_at = std::time::Instant::now();
        self.events.emit(AuditEvent::now(AuditEventKind::VmStarted {
            id: self.state.id.clone(),
        }));
        let ready_timeout = opts
            .ready_timeout
            .unwrap_or_else(|| Duration::from_secs(30));
        if !ready_timeout.is_zero()
            && let Err(e) = self.wait_ready(ready_timeout).await
        {
            if let Err(kill_err) = self.kill() {
                tracing::warn!(error = %kill_err, "failed to stop VM after ready failure");
            }
            return Err(e);
        }
        Ok(())
    }

    /// Graceful shutdown with default 10 s timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped.
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_timeout(Duration::from_secs(10)).await
    }

    /// Graceful shutdown: sends `Shutdown` request, waits up to `timeout`,
    /// then falls back to `SIGKILL`.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped or the status update fails.
    pub async fn stop_timeout(&mut self, timeout: Duration) -> Result<()> {
        if !self.state.status.can_stop() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be stopped (status: {:?})",
                self.state.id, self.state.status
            )));
        }

        self.state.status = Status::Stopping;
        self.db.update_status(&self.state.id, Status::Stopping)?;

        drop(self.client.shutdown().await);

        let pid = self.state.pid;
        let result = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || wait_for_exit(pid)),
        )
        .await;

        if result.is_ok() {
            return self.mark_stopped();
        }
        self.kill()
    }

    /// Sends `SIGKILL` to the VM process.
    ///
    /// # Errors
    ///
    /// Returns an error if the status update fails.
    pub fn kill(&mut self) -> Result<()> {
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGKILL).ok();
        self.mark_stopped()
    }

    /// Returns `true` if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        is_pid_alive(self.state.pid)
    }

    /// Pauses the VM by quiescing its filesystems and sending `SIGSTOP`.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be paused or the signal fails.
    pub async fn pause(&mut self) -> Result<()> {
        if !self.state.status.can_pause() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be paused (status: {:?})",
                self.state.id, self.state.status
            )));
        }
        drop(self.client.quiesce().await);
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGSTOP)?;
        self.state.status = Status::Paused;
        self.db.update_status(&self.state.id, Status::Paused)?;
        Ok(())
    }

    /// Resumes a paused VM by sending `SIGCONT` and thawing its filesystems.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be resumed or the signal fails.
    pub async fn resume(&mut self) -> Result<()> {
        if !self.state.status.can_resume() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be resumed (status: {:?})",
                self.state.id, self.state.status
            )));
        }
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGCONT)?;
        drop(self.client.thaw().await);
        self.state.status = Status::Running;
        self.db.update_status(&self.state.id, Status::Running)?;
        Ok(())
    }

    /// Sends a POSIX signal to the VM process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal number is invalid or delivery fails.
    pub fn signal(&self, sig: i32) -> Result<()> {
        let signal =
            Signal::try_from(sig).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        signal::kill(Pid::from_raw(self.state.pid), signal)?;
        Ok(())
    }

    /// Waits for the VM process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the status update fails.
    pub async fn wait(&mut self) -> Result<()> {
        let pid = self.state.pid;
        drop(tokio::task::spawn_blocking(move || wait_for_exit(pid)).await);
        self.mark_stopped()
    }

    /// Waits for the guest agent to become reachable.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent does not become ready within `timeout`
    /// or the VM process dies.
    #[allow(
        clippy::excessive_nesting,
        reason = "inherent in async select! + timeout pattern"
    )]
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let pid = self.state.pid;
        let exit_file = self.state.socket.with_extension("exit");

        let handshake_loop = async {
            loop {
                if self.client.handshake().await.is_ok() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        let process_monitor = async {
            loop {
                if !is_pid_alive(pid) {
                    return Err(crate::Error::GuestUnavailable(shim_death_message(
                        pid, &exit_file,
                    )));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };

        let result = tokio::time::timeout(timeout, async {
            tokio::select! {
                result = handshake_loop => result,
                result = process_monitor => result,
            }
        })
        .await
        .map_err(|_| crate::Error::GuestUnavailable("guest agent did not become ready".into()))?;

        if result.is_ok() {
            let boot_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.metrics.set_boot_duration_ms(boot_ms);
        }
        result
    }

    /// Reads a file from the guest filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client.read_file(path).await?)
    }

    /// Writes a file to the guest filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        Ok(self.client.write_file(path, data, mode).await?)
    }

    /// Copies a tar archive into the guest, unpacking at `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the copy operation fails.
    pub async fn copy_in(&self, dest: &str, tar_data: &[u8]) -> Result<()> {
        Ok(self.client.copy_in(dest, tar_data).await?)
    }

    /// Streams a tar archive from `reader` into the guest, unpacking at `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the streaming copy fails.
    pub async fn copy_in_from_reader(
        &self,
        dest: &str,
        reader: &mut (impl tokio::io::AsyncRead + Unpin + Send),
    ) -> Result<()> {
        Ok(self.client.copy_in_from_reader(dest, reader).await?)
    }

    /// Copies a path from the guest as a tar archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the copy operation fails.
    pub async fn copy_out(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client.copy_out(path).await?)
    }

    /// Streams a path from the guest as a tar archive directly to `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error if the streaming copy fails.
    pub async fn copy_out_to_writer(
        &self,
        path: &str,
        follow_symlinks: bool,
        writer: &mut (impl tokio::io::AsyncWrite + Unpin + Send),
    ) -> Result<u64> {
        Ok(self
            .client
            .copy_out_to_writer(path, follow_symlinks, writer)
            .await?)
    }

    /// Performs a version handshake with the guest agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.client.handshake().await?)
    }

    /// Kill a shim that started but was not committed as Running.
    ///
    /// Leaves the handle Stopped so `start_with` can be retried. Best-effort
    /// `update_status(Stopped)` covers a pid row that already landed.
    fn revert_failed_start(&mut self, pid: i32) {
        signal::kill(Pid::from_raw(pid), Signal::SIGKILL).ok();
        self.net.stop(&self.state.id);
        self.state.status = Status::Stopped;
        drop(self.db.update_status(&self.state.id, Status::Stopped));
    }

    /// Updates status to Stopped and persists. If `auto_remove` is set,
    /// deletes the VM record, socket, and disk image.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;
        self.net.stop(&self.state.id);

        let uptime_ms = u64::try_from(self.spawned_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.runtime_metrics.on_vm_stopped(uptime_ms);
        self.events.emit(AuditEvent::now(AuditEventKind::VmStopped {
            id: self.state.id.clone(),
            exit_code: None,
        }));

        if self.state.config.auto_remove {
            clean_vm_files(&self.state.socket);
            self.secrets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.state.id);
            drop(self.disk.remove_vm_disk(&self.state.id));
            self.db.delete(&self.state.id)?;
        } else {
            self.db.update_status(&self.state.id, Status::Stopped)?;
        }
        Ok(())
    }
}
