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
/// Crash recovery and graceful shutdown.
mod recover;
/// Shim process spawning and lifecycle utilities.
mod spawn;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use std::{fs, io};

use bux_proto::AGENT_PORT;
pub use handle::VmHandle;
use nix::fcntl::{Flock, FlockArg};
use spawn::{clean_vm_files, is_pid_alive, prepare_managed_config, spawn_shim};
use tracing::info;

use crate::Result;
use crate::disk::DiskManager;
use crate::events::{AuditEvent, AuditEventKind, EventDispatcher};
use crate::metrics::RuntimeMetrics;
use crate::snapshot::SnapshotManager;
use crate::state::{self, StateDb, Status, VmState, VsockPort};
use crate::vm::{Vm, VmBuilder};

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
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown_sync();
    }
}
