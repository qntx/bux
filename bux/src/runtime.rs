//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages VM state in a SQLite database and spawns VMs
//! as child processes via the `bux-shim` binary, which calls
//! `krun_start_enter` to take over the child process.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{fs, io};

use bux_proto::{AGENT_PORT, ExecStart};

use crate::Result;
use crate::client::{Client, ExecHandle, ExecOutput};
use crate::disk::DiskManager;
use crate::jail::{self, JailConfig};
use crate::state::{self, StateDb, Status, VmState, VsockPort};
use crate::vm::VmBuilder;
use crate::watchdog::{self, Keepalive};

/// Manages the lifecycle of bux micro-VMs.
///
/// State is stored in `{data_dir}/bux.db` (SQLite).
#[derive(Debug)]
pub struct Runtime {
    /// SQLite state database.
    db: Arc<StateDb>,
    /// Directory for Unix sockets (`{data_dir}/socks/`).
    socks_dir: PathBuf,
    /// Disk image manager.
    disk: DiskManager,
}

impl Runtime {
    /// Opens (or creates) the runtime data directory and database.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let base = data_dir.as_ref();
        fs::create_dir_all(base)?;

        let socks_dir = base.join("socks");
        fs::create_dir_all(&socks_dir)?;

        let db_path = base.join("bux.db");
        let db = StateDb::open(db_path)?;
        let disk = DiskManager::open(base)?;

        #[allow(clippy::arc_with_non_send_sync)]
        // StateDb uses rusqlite::Connection (not Sync), but Arc is needed for VmHandle sharing within a single-threaded tokio runtime.
        Ok(Self {
            db: Arc::new(db),
            socks_dir,
            disk,
        })
    }

    /// Returns a reference to the disk image manager.
    pub const fn disk(&self) -> &DiskManager {
        &self.disk
    }

    /// Spawns a VM in a child process via `bux-shim` and returns a handle.
    ///
    /// The VM configuration is serialized to a temp JSON file, then
    /// `bux-shim` is spawned as a subprocess that reads the config and
    /// calls `krun_start_enter()` to become the VM.
    pub async fn spawn(
        &self,
        builder: VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        // Validate name uniqueness via DB index.
        if let Some(ref n) = name
            && self.db.get_by_name(n)?.is_some()
        {
            return Err(crate::Error::Ambiguous(format!(
                "a VM named '{n}' already exists"
            )));
        }

        let id = state::gen_id();
        let socket = self.socks_dir.join(format!("{id}.sock"));
        let socket_str = socket.to_string_lossy().into_owned();

        // Build the full config including the internal agent vsock port.
        let mut config = builder.to_config();
        config.auto_remove = auto_remove;
        config.vsock_ports.push(VsockPort {
            port: AGENT_PORT,
            path: socket_str,
            listen: true,
        });

        // If a base disk is specified, create a per-VM QCOW2 overlay.
        if let Some(ref base) = config.base_disk {
            let overlay = self.disk.create_overlay(Path::new(base), &id)?;
            config.root_disk = Some(overlay.to_string_lossy().into_owned());
            config.disk_format = "qcow2".to_owned();
            config.base_disk = None; // consumed — shim doesn't need this
        }

        // Write config to a temp file for the shim to read.
        let config_path = self.socks_dir.join(format!("{id}.json"));
        let json = serde_json::to_string(&config)?;
        fs::write(&config_path, &json)?;

        // Create watchdog pipe — parent holds write end (Keepalive),
        // shim gets read end for parent-death detection.
        let (shim_wd_fd, keepalive) = watchdog::create()?;

        // Spawn bux-shim inside a sandbox (bwrap on Linux, seatbelt on macOS).
        let shim = find_shim()?;
        let jail_config = JailConfig {
            rootfs: config.rootfs.as_deref().map(PathBuf::from),
            root_disk: config.root_disk.as_deref().map(PathBuf::from),
            socks_dir: self.socks_dir.clone(),
            virtiofs_paths: config
                .virtiofs
                .iter()
                .map(|v| PathBuf::from(&v.path))
                .collect(),
            watchdog_fd: Some(std::os::unix::io::AsRawFd::as_raw_fd(&shim_wd_fd)),
        };
        let child = jail::spawn(&shim, &config_path, &jail_config).map_err(|e| {
            let _ = fs::remove_file(&config_path);
            io::Error::new(e.kind(), format!("failed to spawn {}: {e}", shim.display()))
        })?;

        #[allow(clippy::cast_possible_wrap)]
        let child_pid = child.id() as i32;

        let vm_state = VmState {
            id,
            name,
            pid: child_pid,
            image,
            socket,
            status: Status::Running,
            config,
            created_at: SystemTime::now(),
        };
        self.db.insert(&vm_state)?;

        // Drop the shim's read end in the parent — the child already
        // inherited it before exec.
        drop(shim_wd_fd);

        let handle = VmHandle::new(
            vm_state,
            Arc::clone(&self.db),
            self.disk.clone(),
            Some(keepalive),
        );

        // Best-effort readiness wait.
        let _ = handle.wait_ready(Duration::from_secs(5)).await;

        Ok(handle)
    }

    /// Lists all known VMs, reconciling liveness and auto-removing stopped VMs.
    pub fn list(&self) -> Result<Vec<VmState>> {
        let vms = self.db.list()?;
        let mut keep = Vec::with_capacity(vms.len());

        for mut vm in vms {
            // Reconcile: mark dead processes as stopped.
            if matches!(vm.status, Status::Running | Status::Paused) && !is_pid_alive(vm.pid) {
                vm.status = Status::Stopped;
                let _ = self.db.update_status(&vm.id, Status::Stopped);
            }

            // Auto-remove stopped VMs with auto_remove flag.
            if vm.status == Status::Stopped && vm.config.auto_remove {
                let _ = fs::remove_file(&vm.socket);
                let _ = self.db.delete(&vm.id);
                continue;
            }

            keep.push(vm);
        }
        Ok(keep)
    }

    /// Retrieves a handle by name or ID prefix.
    pub fn get(&self, id_or_name: &str) -> Result<VmHandle> {
        // Try name lookup first (O(1) via UNIQUE index).
        let mut state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };

        // Reconcile liveness.
        if matches!(state.status, Status::Running | Status::Paused) && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            let _ = self.db.update_status(&state.id, Status::Stopped);
        }

        Ok(VmHandle::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
            None, // no keepalive — reconnecting to an existing VM
        ))
    }

    /// Renames a VM.
    pub fn rename(&self, id_or_name: &str, new_name: &str) -> Result<()> {
        let handle = self.get(id_or_name)?;
        if let Some(existing) = self.db.get_by_name(new_name)?
            && existing.id != handle.state().id
        {
            return Err(crate::Error::Ambiguous(format!(
                "a VM named '{new_name}' already exists"
            )));
        }
        self.db.update_name(&handle.state().id, Some(new_name))?;
        Ok(())
    }

    /// Removes a stopped VM's state and socket.
    pub fn remove(&self, id_or_name: &str) -> Result<()> {
        let handle = self.get(id_or_name)?;
        let state = handle.state();

        if state.status == Status::Running && is_pid_alive(state.pid) {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VM {} is still running; stop it first", state.id),
            )));
        }

        let _ = fs::remove_file(&state.socket);
        let _ = self.disk.remove_vm_disk(&state.id);
        self.db.delete(&state.id)?;
        Ok(())
    }
}

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
    _keepalive: Option<Keepalive>,
}

impl VmHandle {
    /// Creates a new handle from a state snapshot, shared database, and disk manager.
    fn new(
        state: VmState,
        db: Arc<StateDb>,
        disk: DiskManager,
        keepalive: Option<Keepalive>,
    ) -> Self {
        let client = Client::new(&state.socket);
        Self {
            state,
            db,
            disk,
            client,
            _keepalive: keepalive,
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

    /// Starts a command on a dedicated exec connection.
    pub async fn exec(&self, req: ExecStart) -> Result<ExecHandle> {
        Ok(self.client.exec(req).await?)
    }

    /// Executes a command and collects all output.
    pub async fn exec_output(&self, req: ExecStart) -> Result<ExecOutput> {
        Ok(self.client.exec_output(req).await?)
    }

    /// Graceful shutdown with default 10 s timeout.
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_timeout(Duration::from_secs(10)).await
    }

    /// Graceful shutdown: sends `Shutdown` request, waits up to `timeout`,
    /// then falls back to `SIGKILL`.
    pub async fn stop_timeout(&mut self, timeout: Duration) -> Result<()> {
        let _ = self.client.shutdown().await;

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
    pub fn kill(&mut self) -> Result<()> {
        unsafe {
            libc::kill(self.state.pid, libc::SIGKILL);
        }
        self.mark_stopped()
    }

    /// Returns `true` if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        is_pid_alive(self.state.pid)
    }

    /// Pauses the VM by quiescing its filesystems and sending `SIGSTOP`.
    ///
    /// The guest's filesystems are frozen (FIFREEZE) for point-in-time
    /// consistency before the VM process is stopped.
    pub async fn pause(&mut self) -> Result<()> {
        if self.state.status != Status::Running {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VM {} is not running", self.state.id),
            )));
        }
        // Quiesce guest filesystems before freezing the process.
        let _ = self.client.quiesce().await;
        unsafe { libc::kill(self.state.pid, libc::SIGSTOP) };
        self.state.status = Status::Paused;
        self.db.update_status(&self.state.id, Status::Paused)?;
        Ok(())
    }

    /// Resumes a paused VM by sending `SIGCONT` and thawing its filesystems.
    pub async fn resume(&mut self) -> Result<()> {
        if self.state.status != Status::Paused {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VM {} is not paused", self.state.id),
            )));
        }
        unsafe { libc::kill(self.state.pid, libc::SIGCONT) };
        // Thaw guest filesystems after resuming the process.
        let _ = self.client.thaw().await;
        self.state.status = Status::Running;
        self.db.update_status(&self.state.id, Status::Running)?;
        Ok(())
    }

    /// Sends a POSIX signal to the VM process.
    pub fn signal(&self, sig: i32) -> Result<()> {
        let ret = unsafe { libc::kill(self.state.pid, sig) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    /// Waits for the VM process to exit.
    ///
    /// Uses `waitpid` for child processes (zero CPU, zero latency).
    /// Falls back to `kill(pid, 0)` polling for non-child processes.
    pub async fn wait(&mut self) -> Result<()> {
        let pid = self.state.pid;
        let _ = tokio::task::spawn_blocking(move || wait_for_exit(pid)).await;
        self.mark_stopped()
    }

    /// Reads a file from the guest filesystem.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client.read_file(path).await?)
    }

    /// Writes a file to the guest filesystem.
    pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        Ok(self.client.write_file(path, data, mode).await?)
    }

    /// Copies a tar archive into the guest, unpacking at `dest`.
    pub async fn copy_in(&self, dest: &str, tar_data: &[u8]) -> Result<()> {
        Ok(self.client.copy_in(dest, tar_data).await?)
    }

    /// Streams a tar archive from `reader` into the guest, unpacking at `dest`.
    ///
    /// O(chunk_size) memory regardless of total archive size.
    pub async fn copy_in_from_reader(
        &self,
        dest: &str,
        reader: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> Result<()> {
        Ok(self.client.copy_in_from_reader(dest, reader).await?)
    }

    /// Copies a path from the guest as a tar archive.
    pub async fn copy_out(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client.copy_out(path).await?)
    }

    /// Streams a path from the guest as a tar archive directly to `writer`.
    ///
    /// O(chunk_size) memory regardless of total archive size.
    pub async fn copy_out_to_writer(
        &self,
        path: &str,
        follow_symlinks: bool,
        writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<u64> {
        Ok(self
            .client
            .copy_out_to_writer(path, follow_symlinks, writer)
            .await?)
    }

    /// Performs a version handshake with the guest agent.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.client.handshake().await?)
    }

    /// Waits for the guest agent to become reachable, racing handshake probes
    /// against shim process death detection.
    ///
    /// If the shim exits before the agent is ready, returns immediately with
    /// a diagnostic error instead of waiting for the full timeout.
    async fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
        let pid = self.state.pid;
        let console_output = self.state.config.console_output.clone();

        // Race: handshake loop vs. process death vs. timeout.
        tokio::time::timeout(timeout, async {
            let handshake_loop = async {
                loop {
                    if self.client.handshake().await.is_ok() {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };

            let process_monitor = async {
                // Poll for process death (cannot use waitpid here — it would
                // consume the zombie before wait()/stop() can reap it).
                loop {
                    if !is_pid_alive(pid) {
                        let console_hint = console_output
                            .as_deref()
                            .map(|p| format!("\n  console log: {p}"))
                            .unwrap_or_default();
                        let msg = format!(
                            "VM process (pid {pid}) exited before guest agent became ready{console_hint}"
                        );
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, msg));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };

            tokio::select! {
                result = handshake_loop => result,
                result = process_monitor => result,
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest agent did not become ready"))?
    }

    /// Updates status to Stopped and persists. If `auto_remove` is set,
    /// deletes the VM record, socket, and disk image.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;

        if self.state.config.auto_remove {
            let _ = fs::remove_file(&self.state.socket);
            let _ = self.disk.remove_vm_disk(&self.state.id);
            self.db.delete(&self.state.id)?;
        } else {
            self.db.update_status(&self.state.id, Status::Stopped)?;
        }
        Ok(())
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
fn is_pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Blocks until a process exits.
///
/// Tries `waitpid` first (works for child processes — zero CPU, zero delay).
/// Falls back to `kill(pid, 0)` polling if the process is not a direct child
/// (e.g. `ECHILD` from attached mode).
fn wait_for_exit(pid: i32) {
    // Try waitpid — only succeeds for our own child processes.
    let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    if ret == pid {
        return;
    }
    // Not our child (ECHILD) or other error — fall back to polling.
    while is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Locates the `bux-shim` binary.
///
/// Search order:
/// 1. Next to the current executable (e.g. `/usr/bin/bux-shim`).
/// 2. In `$PATH` via `which`.
fn find_shim() -> io::Result<PathBuf> {
    const NAME: &str = "bux-shim";

    // 1. Sibling of the current executable.
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(NAME);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    // 2. Search $PATH.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("'{NAME}' not found; install it next to the bux binary or in $PATH"),
    ))
}
