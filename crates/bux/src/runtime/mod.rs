//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages VM state in a `SQLite` database, OCI images, and
//! spawns VMs as child processes via the `bux-shim` binary.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

/// Managed boot path: options → running VM.
mod boot;
/// Crash recovery and graceful shutdown.
mod recover;
/// Per-VM handle.
mod vm;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{fs, io};

use nix::fcntl::{Flock, FlockArg};
use tracing::info;

use crate::Result;
use crate::disk::DiskManager;
use crate::events::{AuditEvent, AuditEventKind, EventDispatcher};
use crate::metrics::RuntimeMetrics;
use crate::options::{ImageRef, VmOptions};
use crate::secrets::LiveSecrets;
use crate::snapshot::SnapshotManager;
use crate::state::{StateDb, Status, VmConfig, VmState};
use crate::volumes::VolumeManager;
use boot::{clean_vm_files, is_pid_alive};
use bux_oci::RegistryAuth;

pub use vm::{EgressClass, Vm, VmInfo};

/// How to open a [`Runtime`]. [`Runtime::open`] is this with defaults.
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Data dir (`bux.lock`, `bux.db`, disks, volumes, socks). Required.
    pub data_dir: PathBuf,
    /// If `Some`, must be a regular file at first use or [`crate::Error::NotFound`] (no search fallthrough).
    /// If `None` → canonical sibling of the running executable → `bux-pkg` → fetch.
    pub shim_path: Option<PathBuf>,
    /// Same contract as `shim_path` for the static Linux `bux-guest` ELF.
    pub guest_path: Option<PathBuf>,
    /// Registry credentials for this Runtime's OCI handle (pull and [`crate::ImageRef::Oci`]).
    pub registry_auth: RegistryAuth,
}

/// Cached OCI image metadata (product view).
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct ImageInfo {
    /// Image reference string.
    pub reference: String,
    /// Manifest digest.
    pub digest: String,
    /// Total compressed layer size in bytes.
    pub size: u64,
}

/// VM health status returned by [`Vm::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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
/// Integrates OCI image management, disk management, networking, and VM
/// state persistence in a single entry point. A file lock prevents multiple
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
    /// Memory-only secrets per VM (never `SQLite`).
    secrets: Arc<Mutex<HashMap<String, LiveSecrets>>>,
    /// Named volumes under `{data_dir}/volumes/`.
    volumes: VolumeManager,
    /// Runtime-level metrics (atomic counters).
    metrics: Arc<RuntimeMetrics>,
    /// Audit event dispatcher.
    events: Arc<EventDispatcher>,
    /// Unresolved shim binary override from [`RuntimeOptions`].
    pub(crate) shim_path: Option<PathBuf>,
    /// Unresolved guest ELF override from [`RuntimeOptions`].
    pub(crate) guest_path: Option<PathBuf>,
    /// Cached payload paths from the last [`crate::payload::ensure_blocking`].
    payload: Mutex<Option<crate::payload::ResolvedPayload>>,
}

// Runtime is Send + Sync because:
// - StateDb wraps Connection in Mutex<Connection>
// - Oci (bux_oci::Oci) wraps its Connection in Mutex<Connection>
// - All other fields are naturally Send + Sync

impl Runtime {
    /// Opens (or creates) the runtime data directory and database.
    ///
    /// Equivalent to [`Self::open_with`] with no sidecar paths and anonymous
    /// registry auth. Runs crash recovery to reconcile stale state from
    /// previous runs. Acquires an exclusive file lock to prevent concurrent
    /// access.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Busy`] if another Runtime holds the lock.
    /// Returns an error if the data directory cannot be created or the
    /// database fails to open.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(RuntimeOptions {
            data_dir: data_dir.as_ref().to_path_buf(),
            shim_path: None,
            guest_path: None,
            registry_auth: RegistryAuth::Anonymous,
        })
    }

    /// Opens a runtime with explicit sidecar paths and registry auth.
    ///
    /// Sidecar paths are stored unresolved and copied onto each [`Vm`]. They
    /// are resolved at first shim spawn / guest inject, not at open, and are
    /// not stored in `SQLite`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Busy`] if another Runtime holds the lock.
    /// Returns an error if the data directory cannot be created or the
    /// database fails to open.
    pub fn open_with(opts: RuntimeOptions) -> Result<Self> {
        let base = opts.data_dir.as_path();
        fs::create_dir_all(base)?;

        let lock_file = fs::File::create(base.join("bux.lock"))?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|_| {
            crate::Error::Busy(format!("another bux runtime is using {}", base.display()))
        })?;

        let socks_dir = base.join("socks");
        fs::create_dir_all(&socks_dir)?;

        let db = Arc::new(StateDb::open(base.join("bux.db"))?);
        let disk = DiskManager::open(base)?;
        let oci = bux_oci::Oci::open_at(base, opts.registry_auth)?;
        let snapshots = SnapshotManager::new(Arc::clone(&db), base)?;
        let secrets = Arc::new(Mutex::new(HashMap::new()));
        let volumes = VolumeManager::open(base, Arc::clone(&db))?;

        let rt = Self {
            db,
            socks_dir,
            disk,
            oci,
            _lock: lock,
            snapshots,
            secrets,
            volumes,
            metrics: Arc::new(RuntimeMetrics::new()),
            events: Arc::new(EventDispatcher::new()),
            shim_path: opts.shim_path,
            guest_path: opts.guest_path,
            payload: Mutex::new(None),
        };

        rt.recover();
        info!(data_dir = %base.display(), "runtime opened");
        Ok(rt)
    }

    /// Returns a reference to the disk image manager.
    pub(crate) const fn disk(&self) -> &DiskManager {
        &self.disk
    }

    /// Returns a reference to the OCI image manager.
    pub(crate) const fn oci(&self) -> &bux_oci::Oci {
        &self.oci
    }

    /// Pull/ensure an OCI image into this runtime's store.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry pull or local extract fails.
    pub async fn pull(
        &self,
        reference: &str,
        on_progress: impl Fn(&str) + Send + Sync,
    ) -> Result<ImageInfo> {
        let pulled = self.oci.pull(reference, on_progress).await?;
        let size = self
            .oci
            .images()?
            .into_iter()
            .find(|m| m.digest == pulled.digest)
            .map_or(0, |m| m.size);
        Ok(ImageInfo {
            reference: pulled.reference,
            digest: pulled.digest,
            size,
        })
    }

    /// List cached OCI images.
    ///
    /// # Errors
    ///
    /// Returns an error if the image index cannot be read.
    pub fn images(&self) -> Result<Vec<ImageInfo>> {
        Ok(self
            .oci
            .images()?
            .into_iter()
            .map(|m| ImageInfo {
                reference: m.reference,
                digest: m.digest,
                size: m.size,
            })
            .collect())
    }

    /// Remove a cached OCI image reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be removed.
    pub fn remove_image(&self, reference: &str) -> Result<()> {
        self.oci.remove(reference)?;
        Ok(())
    }

    /// List base disk digests.
    ///
    /// # Errors
    ///
    /// Returns an error if the bases directory cannot be read.
    pub fn list_bases(&self) -> io::Result<Vec<String>> {
        self.disk.list_bases()
    }

    /// Absolute path of a base disk by digest.
    #[must_use]
    pub fn base_path(&self, digest: &str) -> PathBuf {
        self.disk.base_path(digest)
    }

    /// Create a base ext4 image from a rootfs directory.
    ///
    /// # Errors
    ///
    /// Returns an error if image creation fails.
    pub fn create_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
        self.disk.create_base(rootfs, digest)
    }

    /// Remove a base disk by digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub fn remove_base(&self, digest: &str) -> io::Result<()> {
        self.disk.remove_base(digest)
    }

    /// Delete the runtime data directory after taking the exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Busy`] if another Runtime holds the lock.
    pub fn reset(data_dir: impl AsRef<Path>) -> Result<()> {
        let base = data_dir.as_ref();
        if !base.exists() {
            return Ok(());
        }
        fs::create_dir_all(base)?;
        let lock_file = fs::File::create(base.join("bux.lock"))?;
        let _lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|_| {
            crate::Error::Busy(format!("another bux runtime is using {}", base.display()))
        })?;
        fs::remove_dir_all(base)?;
        Ok(())
    }

    /// Delete a snapshot by ID (any VM).
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot is missing or deletion fails.
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.snapshots.delete(snapshot_id)
    }

    /// Probe host isolation capabilities (KVM/HVF, bwrap, landlock, …).
    #[must_use]
    #[allow(clippy::unused_self, reason = "instance API for Runtime symmetry")]
    pub fn host_info(&self) -> crate::security::HostInfo {
        crate::security::HostInfo::probe()
    }

    /// Cache sidecar paths so later spawn / ext4 inject do not fetch again.
    pub(crate) fn store_payload(&self, payload: crate::payload::ResolvedPayload) {
        *self
            .payload
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(payload);
    }

    /// Last successful payload resolution, if `create` already ran `ensure`.
    pub(crate) fn cached_payload(&self) -> Option<crate::payload::ResolvedPayload> {
        self.payload
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Named volume manager (`{data_dir}/volumes/`).
    #[must_use]
    pub const fn volumes(&self) -> &VolumeManager {
        &self.volumes
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

    /// Returns the current total disk usage of all bases and overlays in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if filesystem stat operations fail.
    pub fn disk_usage(&self) -> io::Result<u64> {
        self.disk.disk_usage()
    }

    /// Recursive sum of regular file sizes under the runtime data directory.
    ///
    /// Distinct from [`Self::disk_usage`], which is non-recursive bases+overlays only.
    ///
    /// # Errors
    ///
    /// Returns an error if a directory cannot be read or a file cannot be stat'd.
    pub fn data_dir_usage(&self) -> io::Result<u64> {
        dir_tree_size(self.data_dir())
    }

    /// Data directory this runtime was opened on (parent of `socks/`).
    fn data_dir(&self) -> &Path {
        self.socks_dir.parent().unwrap_or(&self.socks_dir)
    }

    /// Compressed layer bytes from the image manifest, before layer blob download.
    ///
    /// Uses this runtime's OCI handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or the registry request fails.
    pub async fn manifest_compressed_bytes(&self, image: &str) -> Result<u64> {
        Ok(self.oci.manifest_compressed_bytes(image).await?)
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

    /// Disk-clone a VM: flatten its QCOW2 overlay into a new base, then boot a
    /// detached VM.
    ///
    /// Copied from the source: overlay contents, `vcpus`, `ram_mib`, `network`,
    /// `auto_remove`, and `tenant_id`. Always `detach: true` so CLI/`Runtime`
    /// Drop does not SIGTERM the clone (same process model as `bux create`).
    ///
    /// `source_id` is the exact primary key (not name, not prefix). CLI
    /// resolves name/prefix with [`Self::get`] first.
    ///
    /// `agent_id` is set from `name` when that name is the serve unique form
    /// `a-{tenant_id}-{agent}`. If `name` is `None` (CLI), `agent_id` stays
    /// `None`. Source volumes are not copied; a new `ws-{tenant}-{agent}`
    /// volume is attached when both ids are known.
    ///
    /// Not copied: ports, volumes, secrets, security, command, env, workdir,
    /// user, auto-stop/delete, ready timeout, or name (unless `name` is passed).
    ///
    /// # Errors
    ///
    /// Returns an error if the source is missing, flatten fails, or create fails.
    pub async fn clone(&self, source_id: &str, name: Option<String>) -> Result<Vm> {
        let opts = self.clone_prepare(source_id, name)?;
        let handle = self.create(opts).await?;
        info!(source_id, clone_id = %handle.stored().id, "VM cloned");
        Ok(handle)
    }

    /// Exact-id lookup + flatten overlay into `bases/clone-{id}.qcow2` + clone-shaped options.
    fn clone_prepare(&self, source_id: &str, name: Option<String>) -> Result<VmOptions> {
        let source = self.get_exact(source_id)?;
        let source_state = source.stored();
        let clone_id = crate::state::gen_id();
        let clone_base = self
            .disk
            .bases_dir()
            .join(format!("clone-{clone_id}.qcow2"));
        self.disk.flatten_vm_disk(&source_state.id, &clone_base)?;
        Ok(clone_vm_options(&source_state.config, name, clone_base))
    }

    /// Restore a VM from a snapshot: flatten the snapshot overlay into a new
    /// base, then boot a detached VM (same disk recipe as [`Self::clone`]).
    ///
    /// Copied from the source VM: overlay contents (via the snapshot file),
    /// `vcpus`, `ram_mib`, `network`, `auto_remove`, and `tenant_id`. Always
    /// `detach: true`. `agent_id` follows the same name rule as [`Self::clone`].
    ///
    /// Not copied: ports, volumes, secrets, security, command, env, workdir,
    /// user, auto-stop/delete, ready timeout, or name (unless `name` is passed).
    ///
    /// Requires the source VM row, loaded by exact `snapshots.vm_id` (not
    /// name/prefix). After [`Self::remove`] of the source, snapshot rows are
    /// dropped (`ON DELETE CASCADE`) and this returns [`crate::Error::NotFound`].
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot or source VM is missing, the snapshot
    /// disk file is gone, flatten fails, or create fails.
    pub async fn restore(&self, snapshot_id: &str, name: Option<String>) -> Result<Vm> {
        let opts = self.restore_prepare(snapshot_id, name)?;
        let handle = self.create(opts).await?;
        let vm_id = handle.stored().id.clone();
        info!(snapshot_id, restore_id = %vm_id, "VM restored from snapshot");
        self.events
            .emit(AuditEvent::now(AuditEventKind::SnapshotRestored {
                vm_id,
                snapshot_id: snapshot_id.to_owned(),
            }));
        Ok(handle)
    }

    /// Lookup + flatten snapshot overlay into `bases/restore-{id}.qcow2` + clone-shaped options.
    fn restore_prepare(&self, snapshot_id: &str, name: Option<String>) -> Result<VmOptions> {
        let snap = self.db.get_snapshot(snapshot_id)?;
        let snap_disk = Path::new(&snap.disk_path);
        if !snap_disk.is_file() {
            return Err(crate::Error::NotFound(format!(
                "snapshot disk missing: {snapshot_id}"
            )));
        }
        let source = self.get_exact(&snap.vm_id)?;
        restore_vm_options(&self.disk, snap_disk, &source.stored().config, name)
    }

    /// Create and start a managed VM from product [`VmOptions`].
    ///
    /// Pipeline: validate → resolve image → base disk → network → shim → wait ready.
    ///
    /// # Errors
    ///
    /// Returns an error if image resolution, disk, network, or spawn fails.
    pub async fn create(&self, opts: VmOptions) -> Result<Vm> {
        boot::create(self, opts, |_| {}).await
    }

    /// Like [`create`](Self::create) with a progress callback.
    ///
    /// # Errors
    ///
    /// Same as [`create`](Self::create).
    pub async fn create_with(
        &self,
        opts: VmOptions,
        on_progress: impl Fn(&str) + Send + Sync,
    ) -> Result<Vm> {
        boot::create(self, opts, on_progress).await
    }

    /// Alias for [`create`](Self::create) (ready wait is already part of create).
    ///
    /// # Errors
    ///
    /// Same as [`create`](Self::create).
    pub async fn run(&self, opts: VmOptions) -> Result<Vm> {
        self.create(opts).await
    }

    /// Lists all known VMs, reconciling liveness and auto-removing stopped VMs.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list(&self) -> Result<Vec<VmInfo>> {
        let vms = self.db.list()?;
        let mut keep = Vec::with_capacity(vms.len());

        for mut vm in vms {
            self.reconcile_dead_pid(&mut vm);

            if vm.status == Status::Stopped && vm.config.auto_remove {
                drop(self.remove_stored(&vm));
                continue;
            }

            keep.push(VmInfo::from_stored(&vm));
        }
        Ok(keep)
    }

    /// Retrieves a handle by name or ID prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not found or the database query fails.
    pub fn get(&self, id_or_name: &str) -> Result<Vm> {
        let state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };
        Ok(self.handle(state))
    }

    /// Exact primary-key lookup (`WHERE id = ?1`). Never prefix, never name.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotFound`] if no row has this id. Never
    /// [`crate::Error::Ambiguous`].
    pub fn get_exact(&self, id: &str) -> Result<Vm> {
        Ok(self.handle(self.db.get_by_id(id)?))
    }

    /// Exact unique-name lookup (`WHERE name = ?1`). Never prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails. Missing name is `Ok(None)`.
    pub fn get_named(&self, name: &str) -> Result<Option<Vm>> {
        Ok(self.db.get_by_name(name)?.map(|state| self.handle(state)))
    }

    /// Reconcile liveness and wrap a stored row as a handle.
    fn handle(&self, mut state: VmState) -> Vm {
        self.reconcile_dead_pid(&mut state);
        Vm::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
            None,
            Arc::clone(&self.metrics),
            Arc::clone(&self.events),
            self.snapshots.clone(),
            Arc::clone(&self.secrets),
            self.volumes.clone(),
            self.shim_path.clone(),
            self.guest_path.clone(),
        )
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
            && existing.id != handle.stored().id
        {
            return Err(crate::Error::Ambiguous(format!(
                "a VM named '{new_name}' already exists"
            )));
        }
        self.db.update_name(&handle.stored().id, Some(new_name))?;
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
        let state = handle.stored();

        if !state.status.can_remove() {
            return Err(crate::Error::InvalidState(format!(
                "VM {} cannot be removed (status: {:?}); stop it first",
                state.id, state.status
            )));
        }

        self.remove_stored(state)
    }

    /// Tear down a known row by primary key (no name/prefix lookup).
    fn remove_stored(&self, vm: &VmState) -> Result<()> {
        clean_vm_files(&vm.socket);
        self.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&vm.id);
        drop(self.volumes.unlink_vm(&vm.id));
        drop(self.disk.remove_vm_disk(&vm.id));
        self.db.delete(&vm.id)?;
        info!(vm_id = %vm.id, "VM removed");
        self.events.emit(AuditEvent::now(AuditEventKind::VmRemoved {
            id: vm.id.clone(),
        }));
        Ok(())
    }

    /// Mark a stored active row Stopped when the shim PID is gone.
    fn reconcile_dead_pid(&self, vm: &mut VmState) {
        if vm.status.is_active() && !is_pid_alive(vm.pid) {
            vm.status = Status::Stopped;
            drop(self.db.update_status(&vm.id, Status::Stopped));
            clean_vm_files(&vm.socket);
        }
    }
}

/// Flatten a snapshot overlay into `bases/restore-{id}.qcow2` and build clone-shaped create options.
fn restore_vm_options(
    disk: &DiskManager,
    snap_disk: &Path,
    config: &VmConfig,
    name: Option<String>,
) -> Result<VmOptions> {
    let restore_id = crate::state::gen_id();
    let dest = disk.bases_dir().join(format!("restore-{restore_id}.qcow2"));
    bux_qcow2::flatten(snap_disk, &dest)?;
    Ok(clone_vm_options(config, name, dest))
}

/// Create-options for a disk-clone or snapshot-restore: copy
/// `vcpus`/`ram_mib`/`network`/`auto_remove`/`tenant_id`; always detach.
///
/// Serve always passes `a-{tenant}-{agent}`. That form is injective (`-` is
/// not in the id alphabet), so `agent_id` can be recovered from `name`.
/// CLI names are optional and unconstrained; missing/`None` leaves `agent_id`
/// unset. Source volumes are not copied; a new workspace volume is attached
/// only when tenant and agent are both known so HTTP clones stay isolated.
#[must_use]
fn clone_vm_options(config: &VmConfig, name: Option<String>, clone_base: PathBuf) -> VmOptions {
    let mut opts = VmOptions::from_image(ImageRef::BaseDisk(clone_base))
        .vcpus(config.vcpus)
        .ram_mib(config.ram_mib)
        .auto_remove(config.auto_remove)
        .detach(true) // durable disk-clone; CLI drop must not SIGTERM
        .network(config.network.clone());
    if let Some(tenant) = config.tenant_id.as_deref() {
        opts = opts.tenant_id(tenant.to_owned());
        if let Some(agent) = name
            .as_deref()
            .and_then(|n| agent_id_from_sandbox_name(tenant, n))
        {
            opts = opts
                .agent_id(agent.to_owned())
                .named_volume(format!("ws-{tenant}-{agent}"), "/workspace");
        }
    }
    if let Some(n) = name {
        opts = opts.name(n);
    }
    opts
}

/// Parse `agent` from serve unique name `a-{tenant}-{agent}`.
fn agent_id_from_sandbox_name<'a>(tenant_id: &str, name: &'a str) -> Option<&'a str> {
    name.strip_prefix("a-")?
        .strip_prefix(tenant_id)?
        .strip_prefix('-')
        .filter(|agent| !agent.is_empty())
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown_sync();
    }
}

/// Recursive sum of regular file sizes under `dir`.
fn dir_tree_size(dir: &Path) -> io::Result<u64> {
    let mut total = 0_u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                total += meta.len();
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::events::{AuditEventKind, RingBufferListener};
    use crate::options::NetworkSpec;
    use crate::secrets::{LiveSecrets, StartOptions};
    use crate::state::VmConfig;
    use crate::volumes::{VolumeMount, VolumeSource};
    use bux_oci::RegistryAuth;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    fn insert_running(rt: &Runtime, id: &str, pid: i32) {
        insert_running_cfg(rt, id, pid, VmConfig::default());
    }

    fn insert_running_cfg(rt: &Runtime, id: &str, pid: i32, config: VmConfig) {
        insert_cfg(rt, id, pid, Status::Running, config);
    }

    fn insert_cfg(rt: &Runtime, id: &str, pid: i32, status: Status, config: VmConfig) {
        rt.db
            .insert(&VmState {
                id: id.to_owned(),
                name: None,
                pid,
                image: None,
                socket: rt.socks_dir.join(format!("{id}.sock")),
                status,
                config,
                created_at: SystemTime::now(),
            })
            .unwrap();
    }

    fn wait_dead_pid() -> i32 {
        // Sidecar tests empty PATH under a mutex.
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child_pid(&child);
        drop(child.wait());
        pid
    }

    fn shim_json(rt: &Runtime, id: &str) -> PathBuf {
        rt.socks_dir.join(format!("{id}.json"))
    }

    fn plant_shim_json(rt: &Runtime, id: &str) -> PathBuf {
        let path = shim_json(rt, id);
        fs::write(&path, "{\"secret\":\"s3cret\"}").unwrap();
        path
    }

    fn spawn_sleep() -> std::process::Child {
        std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap()
    }

    fn child_pid(child: &std::process::Child) -> i32 {
        i32::try_from(child.id()).unwrap()
    }

    fn dummy_offline_runtime() -> (tempfile::TempDir, Runtime, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("dummy-shim");
        fs::write(&shim, b"#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        let overlay = dir.path().join("overlay.raw");
        fs::write(&overlay, b"not-qcow").unwrap();
        let rt = Runtime::open_with(RuntimeOptions {
            data_dir: dir.path().join("rt"),
            shim_path: Some(shim),
            guest_path: None,
            registry_auth: RegistryAuth::Anonymous,
        })
        .unwrap();
        (dir, rt, overlay)
    }

    fn insert_idle_stopped(rt: &Runtime, overlay: &Path, id: &str) {
        insert_cfg(
            rt,
            id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_stop_secs: Some(1),
                last_activity_at: Some(SystemTime::UNIX_EPOCH),
                detach: true,
                network: NetworkSpec::Disabled,
                root_disk: Some(overlay.to_string_lossy().into_owned()),
                security: crate::security::SecurityOptions::default()
                    .jailer(false)
                    .landlock(false),
                ..VmConfig::default()
            },
        );
    }

    #[test]
    fn list_preserves_live_pid() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let mut child = spawn_sleep();
        let pid = child_pid(&child);
        insert_running(&rt, "aabbccddeeff", pid);
        let list = rt.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, pid);
        assert_eq!(list[0].status, Status::Running);
        drop(rt);
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn list_marks_dead_pid_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let dead = wait_dead_pid();
        insert_running(&rt, "deadpid000001", dead);
        let json = plant_shim_json(&rt, "deadpid000001");
        let list = rt.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, Status::Stopped);
        assert_eq!(list[0].pid, dead);
        assert!(
            !json.exists(),
            "reconcile_dead_pid must unlink leftover shim JSON"
        );
    }

    #[test]
    fn update_pid_then_list_sees_new_pid() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let mut dead_child = std::process::Command::new("true").spawn().unwrap();
        let dead = child_pid(&dead_child);
        drop(dead_child.wait());
        insert_running(&rt, "aabbccddeeff", dead);
        let mut live_child = spawn_sleep();
        let live = child_pid(&live_child);
        rt.db
            .update_pid_status("aabbccddeeff", live, Status::Running)
            .unwrap();
        let list = rt.list().unwrap();
        assert_eq!(list[0].pid, live);
        assert_eq!(list[0].status, Status::Running);
        drop(rt);
        drop(live_child.kill());
        drop(live_child.wait());
    }

    #[test]
    fn drop_skips_detached_live_pid() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = spawn_sleep();
        let pid = child_pid(&child);
        {
            let rt = Runtime::open(dir.path()).unwrap();
            insert_running_cfg(
                &rt,
                "detachdead0001",
                pid,
                VmConfig {
                    detach: true,
                    ..VmConfig::default()
                },
            );
            drop(rt);
        }
        assert!(
            is_pid_alive(pid),
            "Runtime Drop must not SIGTERM detach=true"
        );
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn clone_boots_detached() {
        let source = VmConfig {
            detach: false,
            vcpus: 2,
            ram_mib: 1024,
            auto_remove: true,
            network: NetworkSpec::Disabled,
            ..VmConfig::default()
        };
        let opts = clone_vm_options(&source, Some("n".into()), PathBuf::from("/tmp/clone.qcow2"));
        assert!(
            opts.detach,
            "disk-clone must boot detached even if source is attached"
        );
        assert_eq!(opts.vcpus, 2);
        assert_eq!(opts.ram_mib, 1024);
        assert!(opts.auto_remove);
        assert_eq!(opts.name.as_deref(), Some("n"));
        assert_eq!(opts.network, NetworkSpec::Disabled);
        assert!(opts.tenant_id.is_none(), "CLI source has no tenant");
        assert!(opts.agent_id.is_none(), "non-serve name leaves agent unset");
        assert!(opts.volumes.is_empty(), "source volumes are not copied");
        assert!(
            opts.auto_stop_secs.is_none(),
            "engine clone leaves idle policy off"
        );
        assert!(
            matches!(&opts.image, ImageRef::BaseDisk(p) if p == Path::new("/tmp/clone.qcow2")),
            "clone image must be the flattened base"
        );
    }

    #[test]
    fn clone_vm_options_copies_tenant_and_agent_from_serve_name() {
        let source = VmConfig {
            tenant_id: Some("ten1".into()),
            agent_id: Some("old".into()),
            vcpus: 2,
            ram_mib: 1024,
            network: NetworkSpec::Disabled,
            ..VmConfig::default()
        };
        let opts = clone_vm_options(
            &source,
            Some("a-ten1-newagt".into()),
            PathBuf::from("/tmp/clone.qcow2"),
        );
        assert_eq!(opts.tenant_id.as_deref(), Some("ten1"));
        assert_eq!(opts.agent_id.as_deref(), Some("newagt"));
        assert_eq!(opts.name.as_deref(), Some("a-ten1-newagt"));
        assert_eq!(
            opts.volumes,
            vec![VolumeMount::named("ws-ten1-newagt", "/workspace")],
            "new workspace, not the source volume"
        );
        assert!(
            matches!(
                opts.volumes.first().map(|m| &m.source),
                Some(VolumeSource::Named { name }) if name == "ws-ten1-newagt"
            ),
            "named volume"
        );
    }

    #[test]
    fn clone_vm_options_none_name_leaves_agent_none() {
        let source = VmConfig {
            tenant_id: Some("ten1".into()),
            agent_id: Some("old".into()),
            ..VmConfig::default()
        };
        let opts = clone_vm_options(&source, None, PathBuf::from("/tmp/clone.qcow2"));
        assert_eq!(opts.tenant_id.as_deref(), Some("ten1"), "tenant is copied");
        assert!(opts.agent_id.is_none(), "CLI name None keeps agent unset");
        assert!(opts.name.is_none());
        assert!(opts.volumes.is_empty(), "no agent → no workspace volume");
    }

    #[test]
    fn clone_vm_options_custom_name_does_not_invent_agent() {
        let source = VmConfig {
            tenant_id: Some("ten1".into()),
            agent_id: Some("old".into()),
            ..VmConfig::default()
        };
        let opts = clone_vm_options(
            &source,
            Some("custom".into()),
            PathBuf::from("/tmp/c.qcow2"),
        );
        assert_eq!(opts.tenant_id.as_deref(), Some("ten1"));
        assert!(opts.agent_id.is_none(), "unparseable name");
        assert_eq!(opts.name.as_deref(), Some("custom"));
        assert!(opts.volumes.is_empty());
    }

    #[test]
    fn restore_after_rm_source_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let vm_id = "srcsnap000001";
        insert_cfg(
            &rt,
            vm_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        let snap_path = dir.path().join("snapshots").join("snap1.qcow2");
        fs::write(&snap_path, b"overlay").unwrap();
        rt.db
            .insert_snapshot(&crate::state::SnapshotRow {
                id: "snap1".into(),
                vm_id: vm_id.into(),
                name: Some("s".into()),
                disk_path: snap_path.to_string_lossy().into_owned(),
                disk_bytes: 1,
                created_at: SystemTime::now(),
            })
            .unwrap();
        rt.remove(vm_id).unwrap();
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(rt.restore("snap1", None))
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::NotFound(_)),
            "CASCADE drops snapshot rows: {err}"
        );
    }

    #[test]
    fn restore_flatten_uses_snapshot_overlay_not_live_vm_disk() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let vm_id = "srcsnap000002";

        let live_raw = rt.disk.bases_dir().join("live.raw");
        fs::write(&live_raw, vec![0xAA; 8192]).unwrap();
        rt.disk
            .create_overlay(&live_raw, crate::disk::DiskFormat::Raw, vm_id)
            .unwrap();

        let snap_raw = rt.disk.bases_dir().join("snap.raw");
        fs::write(&snap_raw, vec![0xBB; 4096]).unwrap();
        let snap_ovl = rt
            .disk
            .create_overlay(&snap_raw, crate::disk::DiskFormat::Raw, "snap-src")
            .unwrap();
        let snap_path = dir.path().join("snapshots").join("snap1.qcow2");
        fs::copy(&snap_ovl, &snap_path).unwrap();

        insert_cfg(
            &rt,
            vm_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                vcpus: 2,
                ram_mib: 512,
                auto_remove: true,
                network: NetworkSpec::Disabled,
                ..VmConfig::default()
            },
        );
        rt.db
            .insert_snapshot(&crate::state::SnapshotRow {
                id: "snap1".into(),
                vm_id: vm_id.into(),
                name: Some("s".into()),
                disk_path: snap_path.to_string_lossy().into_owned(),
                disk_bytes: 4096,
                created_at: SystemTime::now(),
            })
            .unwrap();

        let opts = rt.restore_prepare("snap1", Some("n".into())).unwrap();
        assert!(opts.detach);
        assert_eq!(opts.vcpus, 2);
        assert_eq!(opts.ram_mib, 512);
        assert!(opts.auto_remove);
        assert_eq!(opts.name.as_deref(), Some("n"));
        assert_eq!(opts.network, NetworkSpec::Disabled);
        assert!(
            matches!(&opts.image, ImageRef::BaseDisk(p) if {
                p.starts_with(rt.disk.bases_dir())
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("restore-"))
                    && p.extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("qcow2"))
            }),
            "restore image must be ImageRef::BaseDisk of bases/restore-{{id}}.qcow2"
        );
        if let ImageRef::BaseDisk(dest) = &opts.image {
            let hdr = bux_qcow2::read_header(dest).unwrap();
            assert_eq!(
                hdr.virtual_size, 4096,
                "flatten source must be the snapshot overlay (4096), not the live VM disk (8192)"
            );
            assert!(
                hdr.backing_file.is_none(),
                "flattened restore base must be standalone"
            );
        }
    }

    #[test]
    fn restore_prepare_uses_exact_source_id_not_name() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let src_id = "srcsnap000003";
        let decoy_id = "decoy00000001";
        let snap_raw = rt.disk.bases_dir().join("snap.raw");
        fs::write(&snap_raw, vec![0xBB; 4096]).unwrap();
        let snap_ovl = rt
            .disk
            .create_overlay(&snap_raw, crate::disk::DiskFormat::Raw, "snap-src")
            .unwrap();
        let snap_path = dir.path().join("snapshots").join("snap1.qcow2");
        fs::copy(&snap_ovl, &snap_path).unwrap();
        insert_cfg(
            &rt,
            src_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                ram_mib: 512,
                ..VmConfig::default()
            },
        );
        rt.db
            .insert(&VmState {
                id: decoy_id.to_owned(),
                name: Some(src_id.to_owned()),
                pid: wait_dead_pid(),
                image: None,
                socket: rt.socks_dir.join(format!("{decoy_id}.sock")),
                status: Status::Stopped,
                config: VmConfig {
                    ram_mib: 2048,
                    ..VmConfig::default()
                },
                created_at: SystemTime::now(),
            })
            .unwrap();
        rt.db
            .insert_snapshot(&crate::state::SnapshotRow {
                id: "snap1".into(),
                vm_id: src_id.into(),
                name: Some("s".into()),
                disk_path: snap_path.to_string_lossy().into_owned(),
                disk_bytes: 4096,
                created_at: SystemTime::now(),
            })
            .unwrap();
        let by_name = rt.get(src_id).unwrap();
        assert_eq!(by_name.stored().id, decoy_id, "get prefers name");
        let opts = rt.restore_prepare("snap1", None).unwrap();
        assert_eq!(
            opts.ram_mib, 512,
            "restore source is snapshot vm_id, not a VM named that id"
        );
    }

    #[test]
    fn clone_prepare_uses_exact_source_id_not_name() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let src_id = "srcclone00001";
        let decoy_id = "decoy00000002";
        let live_raw = rt.disk.bases_dir().join("live.raw");
        fs::write(&live_raw, vec![0xAA; 8192]).unwrap();
        rt.disk
            .create_overlay(&live_raw, crate::disk::DiskFormat::Raw, src_id)
            .unwrap();
        insert_cfg(
            &rt,
            src_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                ram_mib: 512,
                ..VmConfig::default()
            },
        );
        rt.db
            .insert(&VmState {
                id: decoy_id.to_owned(),
                name: Some(src_id.to_owned()),
                pid: wait_dead_pid(),
                image: None,
                socket: rt.socks_dir.join(format!("{decoy_id}.sock")),
                status: Status::Stopped,
                config: VmConfig {
                    ram_mib: 2048,
                    ..VmConfig::default()
                },
                created_at: SystemTime::now(),
            })
            .unwrap();
        let by_name = rt.get(src_id).unwrap();
        assert_eq!(by_name.stored().id, decoy_id, "get prefers name");
        let opts = rt.clone_prepare(src_id, None).unwrap();
        assert_eq!(
            opts.ram_mib, 512,
            "clone source is exact id, not a VM named that id"
        );
        assert!(
            opts.auto_stop_secs.is_none(),
            "engine clone leaves idle policy off"
        );
    }

    #[test]
    fn clone_and_restore_prepare_call_get_exact() {
        let prod = include_str!("mod.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod");
        assert!(
            prod.contains("self.get_exact(source_id)"),
            "clone_prepare must use get_exact"
        );
        assert!(
            prod.contains("self.get_exact(&snap.vm_id)"),
            "restore_prepare must use get_exact"
        );
    }

    #[test]
    fn recover_live_secrets_shim_is_vsock_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = spawn_sleep();
        let pid = child_pid(&child);
        let rt = Runtime::open(dir.path()).unwrap();
        insert_running_cfg(
            &rt,
            "secretlive0001",
            pid,
            VmConfig {
                detach: true,
                secrets_required: true,
                ..VmConfig::default()
            },
        );
        let json = plant_shim_json(&rt, "secretlive0001");
        rt.recover();
        assert!(
            is_pid_alive(pid),
            "live secrets + live shim must not be SIGTERM'd"
        );
        assert!(
            json.exists(),
            "live shim JSON must not be unlinked (ReattachVsockOnly)"
        );
        let row = rt.db.get_by_id_prefix("secretlive0001").unwrap();
        assert_eq!(row.status, Status::Running);
        drop(rt);
        assert!(is_pid_alive(pid));
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn recover_dead_unlinks_shim_json() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let dead = wait_dead_pid();
        insert_running(&rt, "deadjson000001", dead);
        let json = plant_shim_json(&rt, "deadjson000001");
        rt.recover();
        assert!(
            !json.exists(),
            "recover_dead must unlink leftover shim JSON"
        );
        let row = rt.db.get_by_id_prefix("deadjson000001").unwrap();
        assert_eq!(row.status, Status::Stopped);
    }

    #[test]
    fn recover_dead_auto_remove_purges_shim_json_once() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let dead = wait_dead_pid();
        insert_running_cfg(
            &rt,
            "deadauto000001",
            dead,
            VmConfig {
                auto_remove: true,
                ..VmConfig::default()
            },
        );
        let json = plant_shim_json(&rt, "deadauto000001");
        rt.recover();
        assert!(
            !json.exists(),
            "auto_remove recover_dead must purge shim JSON"
        );
        assert!(rt.db.get_by_id_prefix("deadauto000001").is_err());
    }

    #[test]
    fn sweep_auto_stop_unlinks_shim_json() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let dead = wait_dead_pid();
        insert_running_cfg(
            &rt,
            "sweepjson00001",
            dead,
            VmConfig {
                auto_stop_secs: Some(1),
                last_activity_at: Some(SystemTime::UNIX_EPOCH),
                ..VmConfig::default()
            },
        );
        let json = plant_shim_json(&rt, "sweepjson00001");
        let report = rt.sweep().unwrap();
        assert_eq!(report.stopped, 1);
        assert_eq!(report.deleted, 0);
        assert!(
            !json.exists(),
            "sweep auto-stop must unlink leftover shim JSON"
        );
        let row = rt.db.get_by_id_prefix("sweepjson00001").unwrap();
        assert_eq!(row.status, Status::Stopped);
    }

    #[test]
    fn list_auto_remove_matches_remove() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let id = "listauto000001";
        insert_cfg(
            &rt,
            id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_remove: true,
                ..VmConfig::default()
            },
        );
        let json = plant_shim_json(&rt, id);
        rt.secrets.lock().unwrap().insert(
            id.to_owned(),
            LiveSecrets {
                secrets: Vec::new(),
                ca_cert_pem: String::new(),
                ca_key_pem: String::new(),
            },
        );
        let vol = rt.volumes().create("vol1").unwrap();
        rt.db.insert_vm_volume(id, &vol.id, "/data").unwrap();
        let ring = Arc::new(RingBufferListener::new(8));
        let listener = Arc::clone(&ring);
        rt.events().add_listener(listener);

        let list = rt.list().unwrap();
        assert!(list.is_empty());
        assert!(!json.exists(), "list auto_remove must clean_vm_files");
        assert!(rt.secrets.lock().unwrap().get(id).is_none());
        assert_eq!(rt.db.count_volume_attachments(&vol.id).unwrap(), 0);
        assert!(rt.db.get_by_id_prefix(id).is_err());
        assert!(
            ring.recent(8).iter().any(|e| matches!(
                &e.kind,
                AuditEventKind::VmRemoved { id: removed } if removed == id
            )),
            "list auto_remove must emit VmRemoved"
        );
    }

    #[test]
    fn abort_unready_keeps_stderr_drops_json_and_row() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let id = "abortunready001";
        insert_cfg(
            &rt,
            id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_remove: false,
                ..VmConfig::default()
            },
        );
        let sock = rt.socks_dir.join(format!("{id}.sock"));
        let stderr = sock.with_extension("stderr");
        let json = sock.with_extension("json");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        fs::write(&stderr, b"shim-and-guest-log").unwrap();
        fs::write(&json, b"{\"secrets\":true}").unwrap();

        rt.get(id).unwrap().abort_unready();

        assert!(stderr.exists(), "create_or_dump needs socks/*.stderr");
        assert_eq!(fs::read(&stderr).unwrap(), b"shim-and-guest-log");
        assert!(!json.exists(), "secrets JSON must not linger on abort");
        assert!(!sock.exists());
        assert!(rt.db.get_by_id_prefix(id).is_err());
    }

    #[test]
    fn mark_stopped_non_auto_remove_unlinks_vsock_sock_keeps_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let id = "stopvsock000001";
        insert_cfg(
            &rt,
            id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_remove: false,
                ..VmConfig::default()
            },
        );
        let sock = rt.socks_dir.join(format!("{id}.sock"));
        let stderr = sock.with_extension("stderr");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        fs::write(&stderr, b"shim-log").unwrap();

        rt.get(id).unwrap().kill().unwrap();

        assert!(
            !sock.exists(),
            "#109: non-auto_remove stop must unlink {id}.sock"
        );
        assert!(stderr.exists(), "bux logs after stop");
        let row = rt.db.get_by_id_prefix(id).unwrap();
        assert_eq!(row.status, Status::Stopped);
    }

    #[test]
    fn list_auto_remove_does_not_delete_name_colliding_with_id() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let auto_id = "aaaaaaaaaaaa";
        let named_id = "bbbbbbbbbbbb";
        insert_cfg(
            &rt,
            auto_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_remove: true,
                ..VmConfig::default()
            },
        );
        insert_cfg(
            &rt,
            named_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        rt.db.update_name(named_id, Some(auto_id)).unwrap();
        let auto_json = plant_shim_json(&rt, auto_id);
        let named_json = plant_shim_json(&rt, named_id);

        let list = rt.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, named_id);
        assert!(!auto_json.exists());
        assert!(
            named_json.exists(),
            "name-collision victim must keep shim JSON"
        );
        assert!(rt.db.get_by_id_prefix(auto_id).is_err());
        assert_eq!(rt.db.get_by_id_prefix(named_id).unwrap().id, named_id);
    }

    #[test]
    fn sweep_auto_delete_does_not_delete_name_colliding_with_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = spawn_sleep();
        let live = child_pid(&child);
        let rt = Runtime::open(dir.path()).unwrap();
        let delete_id = "aaaaaaaaaaaa";
        let named_id = "bbbbbbbbbbbb";
        insert_cfg(
            &rt,
            delete_id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                auto_delete_secs: Some(1),
                last_activity_at: Some(SystemTime::UNIX_EPOCH),
                ..VmConfig::default()
            },
        );
        insert_running_cfg(
            &rt,
            named_id,
            live,
            VmConfig {
                detach: true,
                ..VmConfig::default()
            },
        );
        rt.db.update_name(named_id, Some(delete_id)).unwrap();

        let report = rt.sweep().unwrap();
        assert_eq!(report.deleted, 1);
        assert!(rt.db.get_by_id_prefix(delete_id).is_err());
        let named = rt.db.get_by_id_prefix(named_id).unwrap();
        assert_eq!(named.id, named_id);
        assert_eq!(named.status, Status::Running);
        assert!(is_pid_alive(live));
        drop(rt);
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn open_flock_contention_is_busy_not_io() {
        let dir = tempfile::tempdir().unwrap();
        let _rt = Runtime::open(dir.path()).unwrap();
        let open_err = Runtime::open(dir.path()).unwrap_err();
        assert!(
            matches!(open_err, crate::Error::Busy(_)),
            "open contention must be Busy: {open_err}"
        );
        let with_err = Runtime::open_with(RuntimeOptions {
            data_dir: dir.path().to_path_buf(),
            shim_path: None,
            guest_path: None,
            registry_auth: RegistryAuth::Anonymous,
        })
        .unwrap_err();
        assert!(
            matches!(with_err, crate::Error::Busy(_)),
            "open_with contention must be Busy: {with_err}"
        );
    }

    #[test]
    fn open_with_anonymous_matches_open_db_layout() {
        let dir = tempfile::tempdir().unwrap();
        let open_dir = dir.path().join("open");
        let with_dir = dir.path().join("with");
        drop(Runtime::open(&open_dir).unwrap());
        drop(
            Runtime::open_with(RuntimeOptions {
                data_dir: with_dir.clone(),
                shim_path: None,
                guest_path: None,
                registry_auth: RegistryAuth::Anonymous,
            })
            .unwrap(),
        );

        let names = |base: &Path| -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(base)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(&open_dir), names(&with_dir));
        assert!(open_dir.join("bux.db").is_file());
        assert!(with_dir.join("bux.db").is_file());
    }

    #[test]
    fn runtime_options_debug_redacts_registry_auth() {
        let opts = RuntimeOptions {
            data_dir: PathBuf::from("/tmp/bux-data"),
            shim_path: None,
            guest_path: None,
            registry_auth: RegistryAuth::Bearer {
                token: "tokensecret".into(),
            },
        };
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("***"), "{dbg}");
        assert!(!dbg.contains("tokensecret"), "{dbg}");
    }

    #[test]
    fn get_copies_unresolved_shim_path_from_open_with() {
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join("planted-shim");
        fs::write(&planted, b"shim").unwrap();
        let rt = Runtime::open_with(RuntimeOptions {
            data_dir: dir.path().join("rt"),
            shim_path: Some(planted.clone()),
            guest_path: None,
            registry_auth: RegistryAuth::Anonymous,
        })
        .unwrap();
        insert_cfg(
            &rt,
            "getshim000001",
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        let vm = rt.get("getshim000001").unwrap();
        assert_eq!(vm.shim_path.as_deref(), Some(planted.as_path()));
        assert!(vm.guest_path.is_none());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock then ext4 lock must outlive create_managed_base and namei"
    )]
    fn create_managed_base_uses_runtime_guest_path_not_path_decoy() {
        let mut env = crate::guest::sidecar_env::lock();
        let _ext4 = crate::guest::EXT4_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let planted_bytes = crate::guest::test_static_guest_elf(b"PLANT-GUEST-ELF!");
        let decoy_bytes = crate::guest::test_static_guest_elf(b"DECOY-GUEST-ELF!");

        let files = tempfile::tempdir().unwrap();
        let planted = files.path().join("planted-guest");
        let decoy = files.path().join("decoy-guest");
        fs::write(&planted, &planted_bytes).unwrap();
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&decoy, &decoy_bytes).unwrap();

        let decoy_bin = tempfile::tempdir().unwrap();
        fs::write(decoy_bin.path().join("bux-guest"), &decoy_bytes).unwrap();
        env.prepend_path(decoy_bin.path());
        env.set("BUX_GUEST_PATH", &decoy);

        let data = tempfile::tempdir().unwrap();
        let rt = Runtime::open_with(RuntimeOptions {
            data_dir: data.path().to_path_buf(),
            shim_path: None,
            guest_path: Some(planted),
            registry_auth: RegistryAuth::Anonymous,
        })
        .unwrap();

        let rootfs = tempfile::tempdir().unwrap();
        fs::write(rootfs.path().join("placeholder"), b"root").unwrap();
        let image = rt
            .disk()
            .create_managed_base(rootfs.path(), "testdigest", rt.guest_path.as_deref())
            .unwrap();
        let image_bytes = fs::read(&image).unwrap();
        assert!(
            image_bytes
                .windows(planted_bytes.len())
                .any(|w| w == planted_bytes.as_slice()),
            "ext4 image must contain the planted guest ELF"
        );
        assert!(
            image_bytes
                .windows(decoy_bytes.len())
                .all(|w| w != decoy_bytes.as_slice()),
            "ext4 image must not contain the PATH decoy guest ELF"
        );
        let ext4 = bux_e2fs::Filesystem::open(&image).unwrap();
        let ino = ext4
            .namei(crate::guest::ManagedGuestBinary::relative_path())
            .unwrap();
        let inode = ext4.read_inode(ino).unwrap();
        assert_eq!(
            u32::from(inode.i_mode) & 0o777,
            0o555,
            "managed-base guest inode must be 0555"
        );
    }

    #[test]
    fn canonical_reference_reexport_library_alias() {
        let short = crate::canonical_reference("python:slim").unwrap();
        let long = crate::canonical_reference("docker.io/library/python:slim").unwrap();
        assert_eq!(
            short, long,
            "python:slim and docker.io/library/python:slim must canonicalize equally"
        );
        assert_eq!(
            short, "docker.io/library/python:slim",
            "canonical form must be the docker.io library reference"
        );
    }

    #[test]
    fn get_exact_does_not_prefix_match() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        insert_cfg(
            &rt,
            "abc123def456",
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        insert_cfg(
            &rt,
            "abc999000111",
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        rt.db.update_name("abc123def456", Some("alpha")).unwrap();

        let hit = rt.get_exact("abc123def456").unwrap();
        assert_eq!(hit.info().id, "abc123def456", "full id must resolve");

        let prefix = rt.get_exact("abc").unwrap_err();
        assert!(
            matches!(prefix, crate::Error::NotFound(_)),
            "get_exact must not prefix-match, got {prefix}"
        );
        assert!(
            !matches!(prefix, crate::Error::Ambiguous(_)),
            "get_exact must never be Ambiguous, got {prefix}"
        );

        let unique_prefix = rt.get_exact("abc123def").unwrap_err();
        assert!(
            matches!(unique_prefix, crate::Error::NotFound(_)),
            "get_exact must not accept a unique prefix, got {unique_prefix}"
        );
        assert!(
            !matches!(unique_prefix, crate::Error::Ambiguous(_)),
            "unique prefix must be NotFound, not Ambiguous, got {unique_prefix}"
        );
        let via_prefix = rt.get("abc123def").unwrap();
        assert_eq!(
            via_prefix.info().id,
            "abc123def456",
            "Runtime::get still prefix-matches unique ids"
        );

        let by_name = rt.get_exact("alpha").unwrap_err();
        assert!(
            matches!(by_name, crate::Error::NotFound(_)),
            "get_exact must not look up vms.name, got {by_name}"
        );
        assert_eq!(
            rt.get("alpha").unwrap().info().id,
            "abc123def456",
            "Runtime::get still resolves exact names"
        );
    }

    #[test]
    fn get_named_is_exact_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        insert_cfg(
            &rt,
            "namedvm000001",
            wait_dead_pid(),
            Status::Stopped,
            VmConfig::default(),
        );
        rt.db.update_name("namedvm000001", Some("alpha")).unwrap();

        let hit = rt.get_named("alpha").unwrap();
        assert!(hit.is_some(), "exact name must resolve");
        assert_eq!(hit.unwrap().info().id, "namedvm000001");
        assert!(
            rt.get_named("alp").unwrap().is_none(),
            "get_named must not prefix-match"
        );
        assert!(
            rt.get_named("namedvm000001").unwrap().is_none(),
            "get_named must not look up by id"
        );
    }

    #[test]
    fn data_dir_usage_counts_volumes_file_disk_usage_misses() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let disk_before = rt.disk_usage().unwrap();
        let usage_before = rt.data_dir_usage().unwrap();

        let payload = vec![0_u8; 65_536];
        let vol_dir = dir.path().join("volumes").join("ws-t-a");
        fs::create_dir_all(&vol_dir).unwrap();
        fs::write(vol_dir.join("blob"), &payload).unwrap();

        let disk_after = rt.disk_usage().unwrap();
        let usage_after = rt.data_dir_usage().unwrap();
        assert_eq!(
            disk_after, disk_before,
            "disk_usage must not count volumes/ files"
        );
        assert!(
            usage_after >= usage_before + payload.len() as u64,
            "data_dir_usage delta must include the volumes/ blob: before={usage_before} after={usage_after}"
        );
    }

    #[test]
    fn start_with_stamps_activity_so_sweep_skips_idle_stop() {
        let (_dir, rt, overlay) = dummy_offline_runtime();
        let id = "idleclock0001";
        insert_idle_stopped(&rt, &overlay, id);

        let mut vm = rt.get_exact(id).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(vm.start_with(StartOptions {
                ready_timeout: Some(Duration::ZERO),
                secrets: Vec::new(),
            }))
            .unwrap();

        let report = rt.sweep().unwrap();
        assert_eq!(
            report.stopped, 0,
            "start_with must persist last_activity_at so sweep does not auto-stop"
        );
        assert_eq!(report.deleted, 0, "sweep must not delete the restarted VM");
        drop(vm.kill());
    }

    #[test]
    fn start_with_failed_ready_does_not_stamp_activity() {
        let (_dir, rt, overlay) = dummy_offline_runtime();
        let id = "idlefail00001";
        insert_idle_stopped(&rt, &overlay, id);

        let mut vm = rt.get_exact(id).unwrap();
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(vm.start_with(StartOptions {
                ready_timeout: Some(Duration::from_millis(50)),
                secrets: Vec::new(),
            }))
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::GuestUnavailable(_)),
            "dummy shim cannot handshake, got {err}"
        );
        let last = rt
            .db
            .get_by_id(id)
            .unwrap()
            .config
            .last_activity_at
            .unwrap();
        assert_eq!(
            last,
            SystemTime::UNIX_EPOCH,
            "failed ready must not persist last_activity_at"
        );
    }

    #[test]
    fn touch_activity_persists_last_activity_at() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::open(dir.path()).unwrap();
        let id = "touchact000001";
        insert_cfg(
            &rt,
            id,
            wait_dead_pid(),
            Status::Stopped,
            VmConfig {
                last_activity_at: Some(SystemTime::UNIX_EPOCH),
                ..VmConfig::default()
            },
        );
        rt.get_exact(id).unwrap().touch_activity().unwrap();
        let last = rt
            .db
            .get_by_id(id)
            .unwrap()
            .config
            .last_activity_at
            .unwrap();
        assert!(
            last > SystemTime::UNIX_EPOCH,
            "touch_activity must persist last_activity_at"
        );
    }
}
