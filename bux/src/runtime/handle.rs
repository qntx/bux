use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bux_proto::ExecStart;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::info;

use super::{
    HealthStatus, clean_vm_files, is_pid_alive, prepare_managed_config, shim_death_message,
    spawn_shim, wait_for_exit,
};
use crate::Result;
use crate::client::{Client, ExecHandle, ExecOutput, PongInfo};
use crate::disk::DiskManager;
use crate::events::{AuditEvent, AuditEventKind, EventDispatcher};
use crate::metrics::{BoxMetrics, RuntimeMetrics};
use crate::snapshot::SnapshotManager;
use crate::state::{StateDb, Status, VmState};
use crate::watchdog::Keepalive;

/// Handle to a single managed VM.
#[derive(Debug)]
pub struct VmHandle {
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
    keepalive: Option<Keepalive>,
    /// Runtime-level metrics (shared with Runtime).
    runtime_metrics: Arc<RuntimeMetrics>,
    /// Per-box metrics for this VM.
    box_metrics: BoxMetrics,
    /// Event dispatcher (shared with Runtime).
    events: Arc<EventDispatcher>,
    /// Snapshot manager (shared with Runtime).
    snapshots: SnapshotManager,
    /// When this VM was spawned (for uptime tracking).
    spawned_at: std::time::Instant,
}

impl VmHandle {
    /// Creates a new handle from a state snapshot.
    pub(super) fn new(
        state: VmState,
        db: Arc<StateDb>,
        disk: DiskManager,
        keepalive: Option<Keepalive>,
        runtime_metrics: Arc<RuntimeMetrics>,
        events: Arc<EventDispatcher>,
        snapshots: SnapshotManager,
    ) -> Self {
        let client = Client::new(&state.socket);
        Self {
            state,
            db,
            disk,
            client,
            keepalive,
            runtime_metrics,
            box_metrics: BoxMetrics::new(),
            events,
            snapshots,
            spawned_at: std::time::Instant::now(),
        }
    }

    /// Returns the current state snapshot.
    pub const fn state(&self) -> &VmState {
        &self.state
    }

    /// Returns a reference to the stateless client.
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Returns per-box metrics for this VM.
    pub const fn box_metrics(&self) -> &BoxMetrics {
        &self.box_metrics
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
                box_id: self.state.id.clone(),
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
    /// Flattens the QCOW2 overlay chain (overlay + backing base) into a
    /// single self-contained file at `dest`. The source VM is unaffected.
    /// If the VM is running, consider creating a snapshot first.
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
    ///
    /// The task periodically pings the guest agent and updates the VM's
    /// health state in the database. Dropping the returned handle cancels
    /// the background task.
    pub fn enable_health_check(
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
    /// Emits an [`ExecStarted`](AuditEventKind::ExecStarted) audit event.
    /// The caller is responsible for collecting output and calling
    /// [`exec_output`](Self::exec_output) if they want
    /// [`ExecCompleted`](AuditEventKind::ExecCompleted) to be emitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or command start fails.
    pub async fn exec(&self, req: ExecStart) -> Result<ExecHandle> {
        let cmd = req.cmd.clone();
        let handle = self.client.exec(req).await?;
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecStarted {
                box_id: self.state.id.clone(),
                command: cmd,
                exec_id: handle.exec_id().to_owned(),
            }));
        Ok(handle)
    }

    /// Executes a command and collects all output.
    ///
    /// Emits both [`ExecStarted`](AuditEventKind::ExecStarted) and
    /// [`ExecCompleted`](AuditEventKind::ExecCompleted) audit events,
    /// and updates [`BoxMetrics::exec_count`](crate::BoxMetrics).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or command execution fails.
    pub async fn exec_output(&self, req: ExecStart) -> Result<ExecOutput> {
        let cmd = req.cmd.clone();
        let output = self.client.exec_output(req).await?;
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecStarted {
                box_id: self.state.id.clone(),
                command: cmd,
                exec_id: output.exec_id.clone(),
            }));
        self.events
            .emit(AuditEvent::now(AuditEventKind::ExecCompleted {
                box_id: self.state.id.clone(),
                exec_id: output.exec_id.clone(),
                exit_code: output.code,
                duration_ms: output.duration_ms,
            }));
        self.box_metrics.on_exec_completed(output.duration_ms);
        Ok(output)
    }

    /// Restarts a stopped VM from its preserved QCOW2 overlay disk.
    ///
    /// Only works when `auto_remove` is `false` (the default for [`crate::Runtime::run`]).
    /// All previous state (installed packages, files) is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not stopped or the spawn fails.
    pub async fn start(&mut self, ready_timeout: Duration) -> Result<()> {
        if self.state.status != Status::Stopped {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be started (status: {:?}); only stopped VMs can restart",
                self.state.id, self.state.status
            )));
        }

        prepare_managed_config(&mut self.state.config)?;

        let config_path = self
            .state
            .socket
            .with_file_name(format!("{}.json", self.state.id));
        let socks_dir = self.state.socket.parent().unwrap_or_else(|| Path::new("."));
        let shim = spawn_shim(
            &self.state.config,
            &config_path,
            socks_dir,
            &self.state.id,
            true,
        )?;

        self.state.pid = shim.pid;
        self.state.status = Status::Running;
        self.db.update_status(&self.state.id, Status::Running)?;
        self.client = Client::new(&self.state.socket);
        self.keepalive = shim.keepalive;

        info!(vm_id = %self.state.id, pid = shim.pid, "VM restarted");
        self.spawned_at = std::time::Instant::now();
        self.events
            .emit(AuditEvent::now(AuditEventKind::BoxStarted {
                id: self.state.id.clone(),
            }));
        if !ready_timeout.is_zero() {
            drop(self.wait_ready(ready_timeout).await);
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
    /// Races handshake probes against shim process death detection.
    /// On failure, reads the shim's exit file for structured diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent does not become ready within `timeout`
    /// or the VM process dies.
    #[allow(
        clippy::excessive_nesting,
        reason = "inherent in async select! + timeout pattern"
    )]
    pub async fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
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
                    let msg = shim_death_message(pid, &exit_file);
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, msg));
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
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest agent did not become ready"))?;

        // Record boot duration on success.
        if result.is_ok() {
            let boot_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.box_metrics.set_boot_duration_ms(boot_ms);
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

    /// Updates status to Stopped and persists. If `auto_remove` is set,
    /// deletes the VM record, socket, and disk image.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;

        let uptime_ms = u64::try_from(self.spawned_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.runtime_metrics.on_box_stopped(uptime_ms);
        self.events
            .emit(AuditEvent::now(AuditEventKind::BoxStopped {
                id: self.state.id.clone(),
                exit_code: None,
            }));

        if self.state.config.auto_remove {
            clean_vm_files(&self.state.socket);
            drop(self.disk.remove_vm_disk(&self.state.id));
            self.db.delete(&self.state.id)?;
        } else {
            self.db.update_status(&self.state.id, Status::Stopped)?;
        }
        Ok(())
    }
}
