//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages VM state in a SQLite database, OCI images, and
//! spawns VMs as child processes via the `bux-shim` binary.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use std::{fs, io};

use bux_proto::{AGENT_PORT, ExecStart};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use tracing::{info, warn};

use crate::Result;
use crate::client::{Client, ExecHandle, ExecOutput, PongInfo};
use crate::disk::DiskManager;
use crate::guest::ManagedGuestBinary;
use crate::jail::{self, JailConfig};
use crate::state::{self, StateDb, Status, VmState, VsockPort};
use crate::vm::{Vm, VmBuilder};
use crate::watchdog::{self, Keepalive};

/// VM health status returned by [`VmHandle::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthStatus {
    /// VM process is alive but guest agent has not responded yet.
    Starting,
    /// Guest agent responded to ping successfully.
    Healthy,
    /// Guest agent did not respond within the probe timeout.
    Unhealthy,
    /// VM process has exited.
    Dead,
}

/// Options for [`Runtime::run_opts`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunOptions {
    /// Remove VM state automatically when it stops (default: `false`).
    ///
    /// When `false`, the QCOW2 overlay disk is preserved after stop,
    /// allowing the VM to be restarted with [`VmHandle::start`].
    pub auto_remove: bool,
    /// Maximum time to wait for the guest agent to become reachable
    /// (default: 30 s). Set to `Duration::ZERO` to skip the readiness check.
    pub ready_timeout: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            auto_remove: false,
            ready_timeout: Duration::from_secs(30),
        }
    }
}

/// Global default runtime singleton.
static DEFAULT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Ensures atexit handler is registered only once.
static ATEXIT_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Atexit handler: stops non-detached VMs on normal process exit.
extern "C" fn shutdown_on_exit() {
    if let Some(rt) = DEFAULT_RUNTIME.get() {
        rt.shutdown_sync();
    }
}

/// Returns the platform-default data directory for bux.
///
/// Checks `$BUX_HOME` first, then falls back to platform conventions:
/// - Linux: `$XDG_DATA_HOME/bux` or `~/.local/share/bux`
/// - macOS: `~/Library/Application Support/bux`
pub fn default_data_dir() -> PathBuf {
    if let Ok(home) = std::env::var("BUX_HOME") {
        return PathBuf::from(home);
    }
    dirs::data_dir().map_or_else(|| PathBuf::from("bux"), |d| d.join("bux"))
}

/// Manages the lifecycle of bux micro-VMs.
///
/// Integrates OCI image management, disk management, and VM state
/// persistence in a single entry point. A file lock prevents multiple
/// `Runtime` instances from operating on the same data directory.
#[derive(Debug)]
pub struct Runtime {
    /// SQLite state database.
    db: Arc<StateDb>,
    /// Directory for Unix sockets (`{data_dir}/socks/`).
    socks_dir: PathBuf,
    /// Disk image manager.
    disk: DiskManager,
    /// OCI image manager.
    oci: bux_oci::Oci,
    /// Advisory lock — held for the lifetime of this `Runtime`.
    _lock: Flock<fs::File>,
}

// SAFETY: Runtime is protected by an exclusive file lock — only one instance
// per data directory. The OnceLock<Runtime> static requires Send + Sync, but
// rusqlite::Connection and oci_client::Client are !Sync. This is safe because:
// 1. The file lock guarantees single-process access.
// 2. Runtime::global() returns &'static Self — no ownership transfer.
// 3. All public methods take &self and execute sequentially (no interior mut races).
#[allow(unsafe_code)]
unsafe impl Send for Runtime {}
#[allow(unsafe_code)]
unsafe impl Sync for Runtime {}

impl Runtime {
    /// Opens (or creates) the runtime data directory and database.
    ///
    /// Runs crash recovery to reconcile stale state from previous runs.
    /// Acquires an exclusive file lock to prevent concurrent access.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let base = data_dir.as_ref();
        fs::create_dir_all(base)?;

        let lock_file = fs::File::create(base.join("bux.lock"))?;
        let lock =
            Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("another bux runtime is using {}: {errno}", base.display()),
                )
            })?;

        let socks_dir = base.join("socks");
        fs::create_dir_all(&socks_dir)?;

        let db = StateDb::open(base.join("bux.db"))?;
        let disk = DiskManager::open(base)?;
        let oci = bux_oci::Oci::open_at(base)?;

        #[allow(clippy::arc_with_non_send_sync)]
        let rt = Self {
            db: Arc::new(db),
            socks_dir,
            disk,
            oci,
            _lock: lock,
        };

        rt.recover();
        info!(data_dir = %base.display(), "runtime opened");
        Ok(rt)
    }

    /// Returns the global default runtime, creating it on first call.
    ///
    /// Uses [`default_data_dir()`] for the data directory. Installs an
    /// atexit handler and signal handler for graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime initialization fails (filesystem,
    /// lock, database).
    pub fn global() -> Result<&'static Self> {
        if let Some(rt) = DEFAULT_RUNTIME.get() {
            return Ok(rt);
        }

        let _ = DEFAULT_RUNTIME.set(Self::open(default_data_dir())?);

        // Register atexit handler (once).
        if ATEXIT_INSTALLED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            #[allow(unsafe_code)]
            unsafe {
                libc::atexit(shutdown_on_exit);
            }
        }

        // SAFETY: we just called .set() above; if another thread raced us,
        // .get() still returns their value — either way it's Some.
        Ok(DEFAULT_RUNTIME.get().unwrap_or_else(|| unreachable!()))
    }

    /// Returns a reference to the disk image manager.
    pub const fn disk(&self) -> &DiskManager {
        &self.disk
    }

    /// Returns a reference to the OCI image manager.
    pub const fn oci(&self) -> &bux_oci::Oci {
        &self.oci
    }

    /// One-shot: pull image → create base disk → spawn VM with writable overlay.
    ///
    /// Flow: OCI pull → ext4 base image (cached by digest) → per-VM QCOW2
    /// overlay → block-device boot. Each VM gets its own copy-on-write layer,
    /// so `pip install`, `apt install`, etc. work out of the box.
    pub async fn run(
        &self,
        image: &str,
        configure: impl FnOnce(VmBuilder) -> VmBuilder,
        name: Option<String>,
    ) -> Result<VmHandle> {
        self.run_opts(image, configure, name, &RunOptions::default(), |_| {})
            .await
    }

    /// Like [`run`](Self::run) but with explicit options and progress callback.
    pub async fn run_opts(
        &self,
        image: &str,
        configure: impl FnOnce(VmBuilder) -> VmBuilder,
        name: Option<String>,
        opts: &RunOptions,
        on_progress: impl Fn(&str),
    ) -> Result<VmHandle> {
        let pull = self.oci.ensure(image, &on_progress).await?;

        // Convert rootfs directory → ext4 base image (idempotent, cached by digest).
        // Runs in spawn_blocking because ext4 creation is CPU-bound.
        let base_path = {
            let disk = self.disk.clone();
            let rootfs = pull.rootfs.clone();
            let digest = pull.digest.replace(':', "-");
            let reference = pull.reference.clone();
            tokio::task::spawn_blocking(move || -> Result<PathBuf> {
                info!(image = %reference, "creating ext4 base image from rootfs");
                disk.create_managed_base(&rootfs, &digest)
            })
            .await
            .map_err(io::Error::other)??
        };

        let mut builder = Vm::builder().base_disk(base_path.to_string_lossy());

        builder = configure(builder);
        let handle = self.spawn(&builder, Some(image.to_owned()), name, opts.auto_remove)?;

        if !opts.ready_timeout.is_zero() {
            let _ = handle.wait_ready(opts.ready_timeout).await;
        }
        Ok(handle)
    }

    /// Spawns a VM in a child process via `bux-shim` and returns a handle.
    pub fn spawn(
        &self,
        builder: &VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        self.spawn_impl(builder, image, name, auto_remove, true)
    }

    #[allow(missing_docs)]
    pub fn spawn_detached(
        &self,
        builder: &VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        self.spawn_impl(builder, image, name, auto_remove, false)
    }

    #[allow(clippy::missing_docs_in_private_items)]
    fn spawn_impl(
        &self,
        builder: &VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
        watch_parent: bool,
    ) -> Result<VmHandle> {
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

        let mut config = builder.to_config();
        let guest = ManagedGuestBinary::resolve()?;
        if config.exec_path.is_some() {
            return Err(crate::Error::InvalidConfig(
                "managed runtime no longer supports boot-time exec; start the VM, then run commands through bux exec".to_owned(),
            ));
        }
        if config.workdir.is_some()
            || config.uid.is_some()
            || config.gid.is_some()
            || config.env.as_ref().is_some_and(|env| !env.is_empty())
        {
            return Err(crate::Error::InvalidConfig(
                "managed runtime options env/workdir/user now apply only to guest exec requests, not VM boot".to_owned(),
            ));
        }
        if config.root_disk.is_some() && config.rootfs.is_none() && config.base_disk.is_none() {
            return Err(crate::Error::InvalidConfig(
                "managed runtime does not yet support direct root_disk boot without a managed guest-rootfs preparation step".to_owned(),
            ));
        }
        if let Some(rootfs) = config.rootfs.as_deref() {
            guest.inject_into_rootfs(Path::new(rootfs))?;
        }
        config.exec_path = Some(ManagedGuestBinary::exec_path().to_owned());
        config.exec_args.clear();
        config.env = None;
        config.workdir = None;
        config.uid = None;
        config.gid = None;
        config.auto_remove = auto_remove;
        config.vsock_ports.push(VsockPort {
            port: AGENT_PORT,
            path: socket_str,
            listen: true,
        });

        if let Some(ref base) = config.base_disk {
            let overlay = self
                .disk
                .create_overlay(Path::new(base), config.disk_format, &id)?;
            config.root_disk = Some(overlay.to_string_lossy().into_owned());
            config.disk_format = crate::disk::DiskFormat::Qcow2;
            config.base_disk = None;
        }

        let config_path = self.socks_dir.join(format!("{id}.json"));
        let shim = spawn_shim(&config, &config_path, &self.socks_dir, &id, watch_parent)?;

        let vm_state = VmState {
            id: id.clone(),
            name,
            pid: shim.pid,
            image,
            socket,
            status: Status::Running,
            config,
            created_at: SystemTime::now(),
        };
        self.db.insert(&vm_state)?;

        info!(vm_id = %id, pid = shim.pid, "VM spawned");

        Ok(VmHandle::new(
            vm_state,
            Arc::clone(&self.db),
            self.disk.clone(),
            shim.keepalive,
        ))
    }

    /// Lists all known VMs, reconciling liveness and auto-removing stopped VMs.
    pub fn list(&self) -> Result<Vec<VmState>> {
        let vms = self.db.list()?;
        let mut keep = Vec::with_capacity(vms.len());

        for mut vm in vms {
            if vm.status.is_active() && !is_pid_alive(vm.pid) {
                vm.status = Status::Stopped;
                let _ = self.db.update_status(&vm.id, Status::Stopped);
            }

            if vm.status == Status::Stopped && vm.config.auto_remove {
                let _ = fs::remove_file(&vm.socket);
                let _ = self.disk.remove_vm_disk(&vm.id);
                let _ = self.db.delete(&vm.id);
                continue;
            }

            keep.push(vm);
        }
        Ok(keep)
    }

    /// Retrieves a handle by name or ID prefix.
    pub fn get(&self, id_or_name: &str) -> Result<VmHandle> {
        let mut state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };

        if state.status.is_active() && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            let _ = self.db.update_status(&state.id, Status::Stopped);
        }

        Ok(VmHandle::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
            None,
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

    /// Removes a stopped VM's state, socket, and disk overlay.
    pub fn remove(&self, id_or_name: &str) -> Result<()> {
        let handle = self.get(id_or_name)?;
        let state = handle.state();

        if !state.status.can_remove() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be removed (status: {:?}); stop it first",
                state.id, state.status
            )));
        }

        clean_vm_files(&state.socket);
        let _ = self.disk.remove_vm_disk(&state.id);
        self.db.delete(&state.id)?;
        info!(vm_id = %state.id, "VM removed");
        Ok(())
    }

    /// Gracefully stops all active VMs.
    ///
    /// Sends `SIGTERM` to each shim process, waits briefly, then
    /// `SIGKILL` any survivors. Called by the atexit handler and
    /// can be called manually for coordinated shutdown.
    pub fn shutdown_sync(&self) {
        let Ok(vms) = self.db.list() else { return };

        for vm in vms {
            if !vm.status.is_active() || !is_pid_alive(vm.pid) {
                continue;
            }

            info!(vm_id = %vm.id, pid = vm.pid, "stopping VM on shutdown");
            let _ = signal::kill(Pid::from_raw(vm.pid), Signal::SIGTERM);

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            while is_pid_alive(vm.pid) && start.elapsed() < timeout {
                std::thread::sleep(Duration::from_millis(50));
            }

            if is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "SIGKILL after timeout");
                let _ = signal::kill(Pid::from_raw(vm.pid), Signal::SIGKILL);
            }

            let _ = self.db.update_status(&vm.id, Status::Stopped);
        }
    }

    /// Recovers stale state from a previous run.
    ///
    /// Three phases:
    /// 1. Auto-remove stopped VMs flagged with `auto_remove`.
    /// 2. Mark dead-but-active processes as Stopped.
    /// 3. Clean up orphaned socket files.
    fn recover(&self) {
        let vms = match self.db.list() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recovery: failed to list VMs");
                return;
            }
        };

        let mut cleaned = 0u32;
        for vm in &vms {
            // Phase 1: auto-remove stopped VMs.
            if vm.status == Status::Stopped && vm.config.auto_remove {
                clean_vm_files(&vm.socket);
                let _ = self.disk.remove_vm_disk(&vm.id);
                let _ = self.db.delete(&vm.id);
                cleaned += 1;
                continue;
            }

            // Phase 2: reconcile active VMs whose process died.
            if vm.status.is_active() && !is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "recovery: marking dead VM as stopped");
                let _ = self.db.update_status(&vm.id, Status::Stopped);

                if vm.config.auto_remove {
                    clean_vm_files(&vm.socket);
                    let _ = self.disk.remove_vm_disk(&vm.id);
                    let _ = self.db.delete(&vm.id);
                    cleaned += 1;
                }
            }
        }

        // Phase 3: clean orphaned files (.sock, .exit, .json, .stderr).
        let known_ids: HashSet<&str> = vms.iter().map(|v| v.id.as_str()).collect();
        let orphan_exts = [".sock", ".exit", ".json", ".stderr"];
        if let Ok(entries) = fs::read_dir(&self.socks_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                let is_orphan = orphan_exts.iter().any(|ext| {
                    name_str
                        .strip_suffix(ext)
                        .is_some_and(|id| !known_ids.contains(id))
                });
                if is_orphan {
                    let _ = fs::remove_file(entry.path());
                    cleaned += 1;
                }
            }
        }

        if cleaned > 0 {
            info!(cleaned, "recovery complete");
        }
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
    keepalive: Option<Keepalive>,
}

impl VmHandle {
    /// Creates a new handle from a state snapshot.
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
            keepalive,
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
    pub async fn ping(&self) -> Result<PongInfo> {
        Ok(self.client.ping().await?)
    }

    /// Starts a command on a dedicated exec connection.
    pub async fn exec(&self, req: ExecStart) -> Result<ExecHandle> {
        Ok(self.client.exec(req).await?)
    }

    /// Executes a command and collects all output.
    pub async fn exec_output(&self, req: ExecStart) -> Result<ExecOutput> {
        Ok(self.client.exec_output(req).await?)
    }

    /// Restarts a stopped VM from its preserved QCOW2 overlay disk.
    ///
    /// Only works when `auto_remove` is `false` (the default for [`Runtime::run`]).
    /// All previous state (installed packages, files) is preserved.
    pub async fn start(&mut self, ready_timeout: Duration) -> Result<()> {
        if self.state.status != Status::Stopped {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be started (status: {:?}); only stopped VMs can restart",
                self.state.id, self.state.status
            )));
        }

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
        if !ready_timeout.is_zero() {
            let _ = self.wait_ready(ready_timeout).await;
        }
        Ok(())
    }

    /// Graceful shutdown with default 10 s timeout.
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_timeout(Duration::from_secs(10)).await
    }

    /// Graceful shutdown: sends `Shutdown` request, waits up to `timeout`,
    /// then falls back to `SIGKILL`.
    pub async fn stop_timeout(&mut self, timeout: Duration) -> Result<()> {
        if !self.state.status.can_stop() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be stopped (status: {:?})",
                self.state.id, self.state.status
            )));
        }

        self.state.status = Status::Stopping;
        self.db.update_status(&self.state.id, Status::Stopping)?;

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
        let _ = signal::kill(Pid::from_raw(self.state.pid), Signal::SIGKILL);
        self.mark_stopped()
    }

    /// Returns `true` if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        is_pid_alive(self.state.pid)
    }

    /// Pauses the VM by quiescing its filesystems and sending `SIGSTOP`.
    pub async fn pause(&mut self) -> Result<()> {
        if !self.state.status.can_pause() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be paused (status: {:?})",
                self.state.id, self.state.status
            )));
        }
        let _ = self.client.quiesce().await;
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGSTOP)?;
        self.state.status = Status::Paused;
        self.db.update_status(&self.state.id, Status::Paused)?;
        Ok(())
    }

    /// Resumes a paused VM by sending `SIGCONT` and thawing its filesystems.
    pub async fn resume(&mut self) -> Result<()> {
        if !self.state.status.can_resume() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be resumed (status: {:?})",
                self.state.id, self.state.status
            )));
        }
        signal::kill(Pid::from_raw(self.state.pid), Signal::SIGCONT)?;
        let _ = self.client.thaw().await;
        self.state.status = Status::Running;
        self.db.update_status(&self.state.id, Status::Running)?;
        Ok(())
    }

    /// Sends a POSIX signal to the VM process.
    pub fn signal(&self, sig: i32) -> Result<()> {
        let signal =
            Signal::try_from(sig).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        signal::kill(Pid::from_raw(self.state.pid), signal)?;
        Ok(())
    }

    /// Waits for the VM process to exit.
    pub async fn wait(&mut self) -> Result<()> {
        let pid = self.state.pid;
        let _ = tokio::task::spawn_blocking(move || wait_for_exit(pid)).await;
        self.mark_stopped()
    }

    /// Waits for the guest agent to become reachable.
    ///
    /// Races handshake probes against shim process death detection.
    /// On failure, reads the shim's exit file for structured diagnostics.
    pub async fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
        let pid = self.state.pid;
        let exit_file = self.state.socket.with_extension("exit");

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
                loop {
                    if !is_pid_alive(pid) {
                        let msg = shim_death_message(pid, &exit_file);
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

    /// Updates status to Stopped and persists. If `auto_remove` is set,
    /// deletes the VM record, socket, and disk image.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;

        if self.state.config.auto_remove {
            clean_vm_files(&self.state.socket);
            let _ = self.disk.remove_vm_disk(&self.state.id);
            self.db.delete(&self.state.id)?;
        } else {
            self.db.update_status(&self.state.id, Status::Stopped)?;
        }
        Ok(())
    }
}

/// Builds a diagnostic message when the shim process dies before the guest agent is ready.
///
/// Combines structured [`ExitInfo`] JSON and the last few lines of the shim's
/// stderr file into a single actionable error message.
fn shim_death_message(pid: i32, exit_file: &Path) -> String {
    let detail = crate::ExitInfo::from_file(exit_file)
        .map_or_else(|| "unknown reason".into(), |info| info.summary());

    let stderr_path = exit_file.with_extension("stderr");
    let stderr_hint = fs::read_to_string(&stderr_path)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let total = s.lines().count();
            let skip = total.saturating_sub(5);
            let tail: String = s.lines().skip(skip).collect::<Vec<_>>().join("\n");
            format!("\n  stderr:\n    {}", tail.replace('\n', "\n    "))
        })
        .unwrap_or_default();

    format!("VM process (pid {pid}) died before ready: {detail}{stderr_hint}")
}

/// Removes all transient files associated with a VM socket path.
///
/// Cleans `.sock`, `.exit`, `.json`, and `.stderr` files that share the
/// same stem as the socket.
fn clean_vm_files(socket: &Path) {
    let _ = fs::remove_file(socket);
    for ext in ["exit", "json", "stderr"] {
        let _ = fs::remove_file(socket.with_extension(ext));
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
fn is_pid_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Blocks until a process exits.
///
/// Tries `waitpid` first (works for child processes — zero CPU, zero delay).
/// Falls back to `kill(pid, 0)` polling if the process is not a direct child.
fn wait_for_exit(pid: i32) {
    let nix_pid = Pid::from_raw(pid);
    if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(nix_pid, None) {
        return;
    }
    while is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Result of spawning a shim subprocess.
struct ShimSpawnResult {
    /// Child PID (as i32 for nix compatibility).
    pid: i32,
    /// Parent-side watchdog keepalive.
    keepalive: Option<Keepalive>,
}

/// Writes config JSON, creates watchdog pipe, and spawns `bux-shim` inside a sandbox.
///
/// Shared by [`Runtime::spawn()`] and [`VmHandle::start()`].
fn spawn_shim(
    config: &state::VmConfig,
    config_path: &Path,
    socks_dir: &Path,
    vm_id: &str,
    watch_parent: bool,
) -> io::Result<ShimSpawnResult> {
    let json =
        serde_json::to_string(config).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(config_path, &json)?;

    // Capture shim stderr to a file for post-mortem diagnostics.
    let stderr_path = config_path.with_extension("stderr");
    let stderr_file = fs::File::create(&stderr_path)?;

    let (shim_wd_fd, keepalive) = if watch_parent {
        let (fd, keepalive) = watchdog::create()?;
        (Some(fd), Some(keepalive))
    } else {
        (None, None)
    };
    let shim = find_shim()?;
    #[cfg(target_os = "macos")]
    ensure_shim_dylib_aliases(&shim)?;

    let jail_config = JailConfig {
        rootfs: config.rootfs.as_deref().map(PathBuf::from),
        root_disk: config.root_disk.as_deref().map(PathBuf::from),
        socks_dir: socks_dir.to_path_buf(),
        virtiofs_paths: config
            .virtiofs
            .iter()
            .map(|v| PathBuf::from(&v.path))
            .collect(),
        watchdog_fd: shim_wd_fd
            .as_ref()
            .map(std::os::unix::io::AsRawFd::as_raw_fd),
        sandbox: None,
        resource_limits: None,
        stderr_file: Some(stderr_file),
    };

    let result = jail::spawn(&shim, config_path, jail_config, vm_id).map_err(|e| {
        let _ = fs::remove_file(config_path);
        io::Error::new(e.kind(), format!("failed to spawn {}: {e}", shim.display()))
    })?;

    #[allow(clippy::cast_possible_wrap)]
    let pid = result.child.id() as i32;
    drop(shim_wd_fd);

    Ok(ShimSpawnResult { pid, keepalive })
}

/// Locates the `bux-shim` binary.
///
/// Search order:
/// 1. `$BUX_SHIM_PATH` environment variable (development override).
/// 2. Next to the current executable.
/// 3. In `$PATH`.
fn find_shim() -> io::Result<PathBuf> {
    const NAME: &str = "bux-shim";

    if let Ok(p) = std::env::var("BUX_SHIM_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(NAME);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

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

#[cfg(target_os = "macos")]
#[allow(clippy::missing_docs_in_private_items)]
fn ensure_shim_dylib_aliases(shim: &Path) -> io::Result<()> {
    let Some(shim_dir) = shim.parent() else {
        return Ok(());
    };

    for (src, alias) in [
        ("libkrun.dylib", "libkrun.1.dylib"),
        ("libkrunfw.dylib", "libkrunfw.5.dylib"),
    ] {
        let src_path = shim_dir.join(src);
        let alias_path = shim_dir.join(alias);
        if alias_path.exists() {
            continue;
        }
        if !src_path.exists() {
            continue;
        }
        match std::os::unix::fs::symlink(src, &alias_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                fs::copy(&src_path, &alias_path)?;
            }
        }
    }

    Ok(())
}
