//! Snapshot management for point-in-time VM disk captures.
//!
//! A snapshot copies the current QCOW2 overlay disk, optionally quiescing
//! guest filesystems first (via `FIFREEZE`) for consistency. Snapshots can
//! be listed or deleted. Restore is [`crate::Runtime::restore`]: flatten the
//! snapshot overlay into a new base, then create like clone. Snapshot rows
//! are `ON DELETE CASCADE` on the source VM.
//!
//! The snapshot workflow:
//! 1. Quiesce guest filesystems (if VM is running).
//! 2. Copy the QCOW2 overlay to `{data_dir}/snapshots/{snapshot_id}.qcow2`.
//! 3. Thaw guest filesystems.
//! 4. Record metadata in `SQLite`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, io};

use tracing::{info, warn};

use crate::client::Client;
use crate::error::Result;
use crate::state::{SnapshotRow, StateDb, Status};

/// Information about a created snapshot.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SnapshotInfo {
    /// Unique snapshot identifier.
    pub id: String,
    /// ID of the VM this snapshot belongs to.
    pub vm_id: String,
    /// Optional human-friendly name.
    pub name: Option<String>,
    /// Absolute path to the snapshot disk image.
    pub disk_path: PathBuf,
    /// Size of the snapshot disk in bytes.
    pub disk_bytes: u64,
    /// When the snapshot was created.
    pub created_at: SystemTime,
}

impl From<SnapshotRow> for SnapshotInfo {
    fn from(row: SnapshotRow) -> Self {
        Self {
            id: row.id,
            vm_id: row.vm_id,
            name: row.name,
            disk_path: PathBuf::from(&row.disk_path),
            disk_bytes: row.disk_bytes,
            created_at: row.created_at,
        }
    }
}

/// Manages snapshot lifecycle: create, list, delete.
#[derive(Debug, Clone)]
pub(crate) struct SnapshotManager {
    /// Shared state database.
    db: Arc<StateDb>,
    /// Directory for snapshot disk images.
    snapshots_dir: PathBuf,
}

impl SnapshotManager {
    /// Creates a new snapshot manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshots directory cannot be created.
    pub(crate) fn new(db: Arc<StateDb>, data_dir: &Path) -> io::Result<Self> {
        let snapshots_dir = data_dir.join("snapshots");
        fs::create_dir_all(&snapshots_dir)?;
        Ok(Self { db, snapshots_dir })
    }

    /// Creates a snapshot of a VM's disk.
    ///
    /// If the VM is running, quiesces guest filesystems first for
    /// point-in-time consistency, then thaws after the copy.
    ///
    /// # Errors
    ///
    /// Returns an error if the disk copy or database insert fails.
    pub(crate) async fn create(
        &self,
        vm_id: &str,
        vm_status: Status,
        overlay_path: &Path,
        client: &Client,
        name: Option<&str>,
    ) -> Result<SnapshotInfo> {
        let snapshot_id = crate::state::gen_id();
        let dest = self.snapshots_dir.join(format!("{snapshot_id}.qcow2"));

        let quiesced = try_quiesce(vm_id, vm_status, client).await;

        // Copy the overlay disk.
        let src = overlay_path.to_path_buf();
        let dst = dest.clone();
        let disk_bytes =
            tokio::task::spawn_blocking(move || -> io::Result<u64> { fs::copy(&src, &dst) })
                .await
                .map_err(io::Error::other)??;

        // Thaw if we quiesced.
        if quiesced {
            client.thaw().await.ok();
        }

        let row = SnapshotRow {
            id: snapshot_id.clone(),
            vm_id: vm_id.to_owned(),
            name: name.map(ToOwned::to_owned),
            disk_path: dest.to_string_lossy().into_owned(),
            disk_bytes,
            created_at: SystemTime::now(),
        };
        self.db.insert_snapshot(&row)?;

        info!(vm_id, snapshot_id = %snapshot_id, bytes = disk_bytes, "snapshot created");
        Ok(SnapshotInfo::from(row))
    }

    /// Lists all snapshots for a given VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub(crate) fn list(&self, vm_id: &str) -> Result<Vec<SnapshotInfo>> {
        Ok(self
            .db
            .list_snapshots(vm_id)?
            .into_iter()
            .map(SnapshotInfo::from)
            .collect())
    }

    /// Deletes a snapshot (both the DB record and the disk file).
    ///
    /// # Errors
    ///
    /// Returns an error if the database record cannot be removed.
    pub(crate) fn delete(&self, snapshot_id: &str) -> Result<()> {
        let snap = self.db.get_snapshot(snapshot_id)?;
        fs::remove_file(&snap.disk_path).ok();
        self.db.delete_snapshot(snapshot_id)?;
        info!(snapshot_id, "snapshot deleted");
        Ok(())
    }
}

/// Attempts to quiesce guest filesystems. Returns `true` if frozen successfully.
async fn try_quiesce(vm_id: &str, status: Status, client: &Client) -> bool {
    if status != Status::Running {
        return false;
    }
    match client.quiesce().await {
        Ok(n) => {
            info!(vm_id, frozen = n, "filesystems quiesced for snapshot");
            true
        }
        Err(e) => {
            warn!(vm_id, error = %e, "quiesce failed, snapshot may be inconsistent");
            false
        }
    }
}
