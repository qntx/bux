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
use crate::net_manager::NetworkManager;
use crate::options::VmOptions;
use crate::secrets::LiveSecrets;
use crate::snapshot::SnapshotManager;
use crate::state::{StateDb, Status};
use crate::volumes::VolumeManager;
use boot::{clean_vm_files, is_pid_alive};

pub use vm::{Vm, VmInfo};

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
    /// Per-VM gvproxy backends (`virtio_net` VMs).
    net: Arc<NetworkManager>,
    /// Memory-only secrets per VM (never `SQLite`).
    secrets: Arc<Mutex<HashMap<String, LiveSecrets>>>,
    /// Named volumes under `{data_dir}/volumes/`.
    volumes: VolumeManager,
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
        let net = Arc::new(NetworkManager::new(socks_dir.clone()));
        let secrets = Arc::new(Mutex::new(HashMap::new()));
        let volumes = VolumeManager::open(base, Arc::clone(&db))?;

        let rt = Self {
            db,
            socks_dir,
            disk,
            oci,
            _lock: lock,
            snapshots,
            net,
            secrets,
            volumes,
            metrics: Arc::new(RuntimeMetrics::new()),
            events: Arc::new(EventDispatcher::new()),
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

    /// Clone a VM by flattening its overlay into a new base disk, then boot.
    ///
    /// # Errors
    ///
    /// Returns an error if the source is missing, flatten fails, or create fails.
    pub async fn clone(&self, source_id: &str, name: Option<String>) -> Result<Vm> {
        let source = self.get(source_id)?;
        let source_state = source.stored();

        let clone_id = crate::state::gen_id();
        let clone_base = self.disk.bases_dir().join(format!("clone-{clone_id}.raw"));
        self.disk.flatten_vm_disk(&source_state.id, &clone_base)?;

        let mut opts = VmOptions::from_image(crate::options::ImageRef::BaseDisk(clone_base))
            .vcpus(source_state.config.vcpus)
            .ram_mib(source_state.config.ram_mib)
            .auto_remove(source_state.config.auto_remove);
        if let Some(n) = name {
            opts = opts.name(n);
        }
        opts = opts.network(source_state.config.network.clone());

        let handle = self.create(opts).await?;
        info!(
            source_id = %source_state.id,
            clone_id = %handle.stored().id,
            "VM cloned"
        );
        Ok(handle)
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

        if state.status.is_active() && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            drop(self.db.update_status(&state.id, Status::Stopped));
        }

        Ok(Vm::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
            None,
            Arc::clone(&self.metrics),
            Arc::clone(&self.events),
            self.snapshots.clone(),
            Arc::clone(&self.net),
            Arc::clone(&self.secrets),
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

        clean_vm_files(&state.socket);
        self.net.stop(&state.id);
        self.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&state.id);
        drop(self.volumes.unlink_vm(&state.id));
        drop(self.disk.remove_vm_disk(&state.id));
        self.db.delete(&state.id)?;
        info!(vm_id = %state.id, "VM removed");
        self.events.emit(AuditEvent::now(AuditEventKind::VmRemoved {
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
