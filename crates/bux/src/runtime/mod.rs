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
    /// If `None` → `BUX_SHIM_PATH` (fall through if not a file) → sibling of the running executable → `$PATH`.
    pub shim_path: Option<PathBuf>,
    /// Same contract as `shim_path` for the static Linux `bux-guest` ELF (`BUX_GUEST_PATH`).
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
    /// and `auto_remove`. Always `detach: true` so CLI/`Runtime` Drop does not
    /// SIGTERM the clone (same process model as `bux create`).
    ///
    /// Not copied: ports, volumes, secrets, security, command, env, workdir,
    /// user, auto-stop/delete, ready timeout, or name (unless `name` is passed).
    ///
    /// # Errors
    ///
    /// Returns an error if the source is missing, flatten fails, or create fails.
    pub async fn clone(&self, source_id: &str, name: Option<String>) -> Result<Vm> {
        let source = self.get(source_id)?;
        let source_state = source.stored();

        let clone_id = crate::state::gen_id();
        let clone_base = self
            .disk
            .bases_dir()
            .join(format!("clone-{clone_id}.qcow2"));
        self.disk.flatten_vm_disk(&source_state.id, &clone_base)?;

        let opts = clone_vm_options(&source_state.config, name, clone_base);
        let handle = self.create(opts).await?;
        info!(
            source_id = %source_state.id,
            clone_id = %handle.stored().id,
            "VM cloned"
        );
        Ok(handle)
    }

    /// Restore a VM from a snapshot: flatten the snapshot overlay into a new
    /// base, then boot a detached VM (same disk recipe as [`Self::clone`]).
    ///
    /// Copied from the source VM: overlay contents (via the snapshot file),
    /// `vcpus`, `ram_mib`, `network`, and `auto_remove`. Always `detach: true`.
    ///
    /// Not copied: ports, volumes, secrets, security, command, env, workdir,
    /// user, auto-stop/delete, ready timeout, or name (unless `name` is passed).
    ///
    /// Requires the source VM row. After [`Self::remove`] of the source,
    /// snapshot rows are dropped (`ON DELETE CASCADE`) and this returns
    /// [`crate::Error::NotFound`].
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
        let source = self.get(&snap.vm_id)?;
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
        let mut state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };

        self.reconcile_dead_pid(&mut state);

        Ok(Vm::new(
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
/// `vcpus`/`ram_mib`/`network`/`auto_remove`; always detach.
#[must_use]
fn clone_vm_options(config: &VmConfig, name: Option<String>, clone_base: PathBuf) -> VmOptions {
    let mut opts = VmOptions::from_image(ImageRef::BaseDisk(clone_base))
        .vcpus(config.vcpus)
        .ram_mib(config.ram_mib)
        .auto_remove(config.auto_remove)
        .detach(true) // durable disk-clone; CLI drop must not SIGTERM
        .network(config.network.clone());
    if let Some(n) = name {
        opts = opts.name(n);
    }
    opts
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown_sync();
    }
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
    use crate::secrets::LiveSecrets;
    use crate::state::VmConfig;
    use bux_oci::RegistryAuth;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;

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
        let mut child = std::process::Command::new("true").spawn().unwrap();
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
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap()
    }

    fn child_pid(child: &std::process::Child) -> i32 {
        i32::try_from(child.id()).unwrap()
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
        assert!(
            matches!(&opts.image, ImageRef::BaseDisk(p) if p == Path::new("/tmp/clone.qcow2")),
            "clone image must be the flattened base"
        );
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
}
