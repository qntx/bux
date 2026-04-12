//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages VM state in a `SQLite` database, OCI images, and
//! spawns VMs as child processes via the `bux-shim` binary.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

/// Per-VM runtime handles and async event processing.
mod handle;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use std::{fs, io};

use bux_proto::AGENT_PORT;
pub use handle::VmHandle;
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use tracing::{info, warn};

use crate::Result;
use crate::disk::DiskManager;
use crate::events::{AuditEvent, AuditEventKind, EventDispatcher};
use crate::guest::ManagedGuestBinary;
use crate::jail::{self, JailConfig};
use crate::metrics::RuntimeMetrics;
use crate::snapshot::SnapshotManager;
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
///
/// **Deprecated**: prefer creating `Runtime` instances explicitly with
/// [`Runtime::open()`] and managing their lifetime via `Arc<Runtime>`.
/// This global will be removed in a future release.
static DEFAULT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Returns the platform-default data directory for bux.
///
/// Checks `$BUX_HOME` first, then falls back to platform conventions:
/// - Linux: `$XDG_DATA_HOME/bux` or `~/.local/share/bux`
/// - macOS: `~/Library/Application Support/bux`
#[must_use]
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
    /// `SQLite` state database.
    db: Arc<StateDb>,
    /// Directory for Unix sockets (`{data_dir}/socks/`).
    socks_dir: PathBuf,
    /// Disk image manager.
    disk: DiskManager,
    /// OCI image manager.
    oci: bux_oci::Oci,
    /// Advisory lock — held for the lifetime of this `Runtime`.
    _lock: Flock<fs::File>,
    /// Snapshot manager.
    snapshots: SnapshotManager,
    /// Runtime-level metrics (atomic counters).
    metrics: Arc<RuntimeMetrics>,
    /// Audit event dispatcher.
    events: Arc<EventDispatcher>,
}

// Runtime is Send + Sync because:
// - StateDb wraps Connection in Mutex<Connection>
// - Oci (bux_oci::Oci) wraps its Connection in Mutex<Connection>
// - All other fields are naturally Send + Sync

impl Runtime {
    /// Opens (or creates) the runtime data directory and database.
    ///
    /// Runs crash recovery to reconcile stale state from previous runs.
    /// Acquires an exclusive file lock to prevent concurrent access.
    ///
    /// # Errors
    ///
    /// Returns an error if the data directory cannot be created, the lock
    /// is already held, or the database fails to open.
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

        let db = Arc::new(StateDb::open(base.join("bux.db"))?);
        let disk = DiskManager::open(base)?;
        let oci = bux_oci::Oci::open_at(base)?;
        let snapshots = SnapshotManager::new(Arc::clone(&db), base)?;

        let rt = Self {
            db,
            socks_dir,
            disk,
            oci,
            _lock: lock,
            snapshots,
            metrics: Arc::new(RuntimeMetrics::new()),
            events: Arc::new(EventDispatcher::new()),
        };

        rt.recover();
        info!(data_dir = %base.display(), "runtime opened");
        Ok(rt)
    }

    /// Returns the global default runtime, creating it on first call.
    ///
    /// Uses [`default_data_dir()`] for the data directory.
    ///
    /// # Deprecation
    ///
    /// **Prefer [`Runtime::open()`]** and manage the runtime lifetime
    /// explicitly (e.g. via `Arc<Runtime>`). The global singleton prevents
    /// multiple data directories and makes shutdown ordering implicit.
    /// This method will be removed in a future release.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime initialization fails (filesystem,
    /// lock, database).
    #[deprecated(since = "0.8.0", note = "use Runtime::open() instead")]
    pub fn global() -> Result<&'static Self> {
        if let Some(rt) = DEFAULT_RUNTIME.get() {
            return Ok(rt);
        }

        drop(DEFAULT_RUNTIME.set(Self::open(default_data_dir())?));

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

    /// Returns a reference to the snapshot manager.
    pub const fn snapshots(&self) -> &SnapshotManager {
        &self.snapshots
    }

    /// Returns a reference to the runtime-level metrics.
    pub fn metrics(&self) -> &RuntimeMetrics {
        &self.metrics
    }

    /// Returns a reference to the event dispatcher.
    ///
    /// Use this to register [`EventListener`](crate::EventListener)
    /// implementations that will receive audit events.
    pub fn events(&self) -> &EventDispatcher {
        &self.events
    }

    /// Sets resource quota limits for a tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn set_quota(&self, tenant: &str, quota: &state::QuotaRow) -> Result<()> {
        self.db.set_quota(quota)?;
        info!(tenant, "quota updated");
        Ok(())
    }

    /// Returns the resource quota for a tenant, if configured.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_quota(&self, tenant: &str) -> Result<Option<state::QuotaRow>> {
        self.db.get_quota(tenant)
    }

    /// Returns the current total disk usage of all bases and overlays in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if filesystem stat operations fail.
    pub fn disk_usage(&self) -> io::Result<u64> {
        self.disk.disk_usage()
    }

    /// Garbage-collects orphaned base disk images (`ref_count` <= 0).
    ///
    /// Returns the number of base images removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query or a deletion fails.
    pub fn gc(&self) -> Result<u32> {
        let orphans = self.db.orphaned_base_disks()?;
        let mut removed = 0_u32;
        for orphan in &orphans {
            drop(self.disk.remove_base(&orphan.digest));
            self.db.delete_base_disk(&orphan.id)?;
            removed += 1;
        }
        if removed > 0 {
            info!(removed, "garbage collection complete");
        }
        // Update disk usage gauge after cleanup.
        if let Ok(usage) = self.disk.disk_usage() {
            self.metrics.set_disk_bytes_used(usage);
        }
        Ok(removed)
    }

    /// Checks that the tenant's quota allows creating another VM.
    fn check_quota(&self, tenant: &str) -> Result<()> {
        if let Some(quota) = self.db.get_quota(tenant)?
            && let Some(max) = quota.max_boxes
        {
            let current = self.db.count_boxes_by_tenant(tenant)?;
            if current >= max {
                return Err(crate::Error::QuotaExceeded(format!(
                    "tenant '{tenant}' already has {current}/{max} VMs"
                )));
            }
        }
        Ok(())
    }

    /// Creates a new VM by cloning an existing VM's disk state.
    ///
    /// Flattens the source VM's QCOW2 overlay into a new standalone base
    /// image, then creates a fresh overlay on top. The new VM has all the
    /// same installed packages and files as the source, but is independent.
    ///
    /// The source VM can be running or stopped.
    /// # Errors
    ///
    /// Returns an error if the source VM is not found, quota is exceeded,
    /// disk flattening fails, or the spawn fails.
    pub fn clone_box(
        &self,
        source_id: &str,
        name: Option<String>,
        configure: impl FnOnce(VmBuilder) -> VmBuilder,
        opts: &RunOptions,
    ) -> Result<VmHandle> {
        self.check_quota("default")?;

        let source = self.get(source_id)?;
        let source_state = source.state();

        // Flatten source overlay → new base disk.
        let clone_id = state::gen_id();
        let clone_base = self.disk.bases_dir().join(format!("clone-{clone_id}.raw"));
        self.disk.flatten_vm_disk(&source_state.id, &clone_base)?;

        // Build the new VM using the cloned base.
        let mut builder = Vm::builder().base_disk(clone_base.to_string_lossy());
        builder = builder
            .vcpus(source_state.config.vcpus)
            .ram_mib(source_state.config.ram_mib);
        builder = configure(builder);

        let handle = self.spawn(&builder, source_state.image.clone(), name, opts.auto_remove)?;

        info!(
            source_id = %source_state.id,
            clone_id = %handle.state().id,
            "VM cloned"
        );

        Ok(handle)
    }

    /// One-shot: pull image → create base disk → spawn VM with writable overlay.
    ///
    /// Flow: OCI pull → ext4 base image (cached by digest) → per-VM QCOW2
    /// overlay → block-device boot. Each VM gets its own copy-on-write layer,
    /// so `pip install`, `apt install`, etc. work out of the box.
    /// # Errors
    ///
    /// Returns an error if the image pull, disk creation, or spawn fails.
    pub async fn run(
        &self,
        image: &str,
        configure: impl FnOnce(VmBuilder) -> VmBuilder + Send,
        name: Option<String>,
    ) -> Result<VmHandle> {
        self.run_opts(image, configure, name, &RunOptions::default(), |_| {})
            .await
    }

    /// Like [`run`](Self::run) but with explicit options and progress callback.
    ///
    /// Checks tenant quota limits before creating the VM. Pass `tenant`
    /// via [`RunOptions`] (defaults to `"default"`).
    /// # Errors
    ///
    /// Returns an error if quota is exceeded, pull fails, disk creation
    /// fails, or the spawn fails.
    pub async fn run_opts(
        &self,
        image: &str,
        configure: impl FnOnce(VmBuilder) -> VmBuilder + Send,
        name: Option<String>,
        opts: &RunOptions,
        on_progress: impl Fn(&str) + Send + Sync,
    ) -> Result<VmHandle> {
        // Quota check: enforce max_boxes limit for the tenant.
        self.check_quota("default")?;

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
            drop(handle.wait_ready(opts.ready_timeout).await);
        }
        Ok(handle)
    }

    /// Spawns a VM in a child process via `bux-shim` and returns a handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the shim binary is not found, config serialization
    /// fails, or the child process cannot be created.
    pub fn spawn(
        &self,
        builder: &VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        self.spawn_impl(builder, image, name, auto_remove, true)
    }

    #[allow(
        missing_docs,
        reason = "mirrors spawn() but skips parent-watch; pending docs"
    )]
    /// # Errors
    ///
    /// Returns an error if the shim binary is not found or spawn fails.
    pub fn spawn_detached(
        &self,
        builder: &VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        self.spawn_impl(builder, image, name, auto_remove, false)
    }

    #[allow(
        clippy::missing_docs_in_private_items,
        reason = "private implementation detail"
    )]
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
        prepare_managed_config(&mut config)?;
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

        self.metrics.on_box_created();
        self.events
            .emit(AuditEvent::now(AuditEventKind::BoxCreated {
                id,
                image: vm_state.image.clone(),
                tenant: "default".to_owned(),
            }));

        Ok(VmHandle::new(
            vm_state,
            Arc::clone(&self.db),
            self.disk.clone(),
            shim.keepalive,
            Arc::clone(&self.metrics),
            Arc::clone(&self.events),
            self.snapshots.clone(),
        ))
    }

    /// Lists all known VMs, reconciling liveness and auto-removing stopped VMs.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list(&self) -> Result<Vec<VmState>> {
        let vms = self.db.list()?;
        let mut keep = Vec::with_capacity(vms.len());

        for mut vm in vms {
            if vm.status.is_active() && !is_pid_alive(vm.pid) {
                vm.status = Status::Stopped;
                drop(self.db.update_status(&vm.id, Status::Stopped));
            }

            if vm.status == Status::Stopped && vm.config.auto_remove {
                drop(fs::remove_file(&vm.socket));
                drop(self.disk.remove_vm_disk(&vm.id));
                drop(self.db.delete(&vm.id));
                continue;
            }

            keep.push(vm);
        }
        Ok(keep)
    }

    /// Retrieves a handle by name or ID prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not found or the database query fails.
    pub fn get(&self, id_or_name: &str) -> Result<VmHandle> {
        let mut state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };

        if state.status.is_active() && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            drop(self.db.update_status(&state.id, Status::Stopped));
        }

        Ok(VmHandle::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
            None,
            Arc::clone(&self.metrics),
            Arc::clone(&self.events),
            self.snapshots.clone(),
        ))
    }

    /// Renames a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not found, the new name conflicts,
    /// or the database update fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not found, is still running,
    /// or the database deletion fails.
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
        drop(self.disk.remove_vm_disk(&state.id));
        self.db.delete(&state.id)?;
        info!(vm_id = %state.id, "VM removed");
        self.events
            .emit(AuditEvent::now(AuditEventKind::BoxRemoved {
                id: state.id.clone(),
            }));
        Ok(())
    }

    /// Gracefully stops all active VMs.
    ///
    /// Sends `SIGTERM` to each shim process, waits briefly, then
    /// `SIGKILL` any survivors. Called automatically when the
    /// `Runtime` is dropped, or can be called manually for
    /// coordinated shutdown.
    #[allow(
        clippy::disallowed_methods,
        reason = "sync shutdown cannot use tokio::time::sleep"
    )]
    pub fn shutdown_sync(&self) {
        let Ok(vms) = self.db.list() else { return };

        for vm in vms {
            if !vm.status.is_active() || !is_pid_alive(vm.pid) {
                continue;
            }

            info!(vm_id = %vm.id, pid = vm.pid, "stopping VM on shutdown");
            signal::kill(Pid::from_raw(vm.pid), Signal::SIGTERM).ok();

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            while is_pid_alive(vm.pid) && start.elapsed() < timeout {
                std::thread::sleep(Duration::from_millis(50));
            }

            if is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "SIGKILL after timeout");
                signal::kill(Pid::from_raw(vm.pid), Signal::SIGKILL).ok();
            }

            drop(self.db.update_status(&vm.id, Status::Stopped));
        }
    }

    /// Recovers stale state from a previous run.
    ///
    /// Three phases:
    /// 1. Auto-remove stopped VMs flagged with `auto_remove`.
    /// 2. Mark dead-but-active processes as Stopped.
    /// 3. Clean up orphaned socket files.
    #[allow(
        clippy::cognitive_complexity,
        clippy::excessive_nesting,
        reason = "three-phase recovery logic with inherent branching"
    )]
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
                drop(self.disk.remove_vm_disk(&vm.id));
                drop(self.db.delete(&vm.id));
                cleaned += 1;
                continue;
            }

            // Phase 2: reconcile active VMs whose process died.
            if vm.status.is_active() && !is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "recovery: marking dead VM as stopped");
                drop(self.db.update_status(&vm.id, Status::Stopped));

                if vm.config.auto_remove {
                    clean_vm_files(&vm.socket);
                    drop(self.disk.remove_vm_disk(&vm.id));
                    drop(self.db.delete(&vm.id));
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
                    drop(fs::remove_file(entry.path()));
                    cleaned += 1;
                }
            }
        }

        if cleaned > 0 {
            info!(cleaned, "recovery complete");
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown_sync();
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
    drop(fs::remove_file(socket));
    for ext in ["exit", "json", "stderr"] {
        drop(fs::remove_file(socket.with_extension(ext)));
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
#[allow(
    clippy::disallowed_methods,
    reason = "sync fallback poll cannot use tokio::time::sleep"
)]
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

/// Resolves the managed guest binary and validates the VM configuration for managed mode.
fn prepare_managed_config(config: &mut state::VmConfig) -> Result<()> {
    let guest = ManagedGuestBinary::resolve()?;

    if let Some(exec_path) = config.exec_path.as_deref()
        && exec_path != ManagedGuestBinary::exec_path()
    {
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
    Ok(())
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
        drop(fs::remove_file(config_path));
        io::Error::new(e.kind(), format!("failed to spawn {}: {e}", shim.display()))
    })?;

    #[allow(
        clippy::cast_possible_wrap,
        reason = "PID fits in i32 on all supported platforms"
    )]
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
#[allow(
    clippy::missing_docs_in_private_items,
    reason = "macOS-only helper with self-explanatory name"
)]
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
