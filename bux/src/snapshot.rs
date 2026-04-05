//! Snapshot management for point-in-time VM disk captures.
//!
//! A snapshot copies the current QCOW2 overlay disk, optionally quiescing
//! guest filesystems first (via `FIFREEZE`) for consistency. Snapshots can
//! be listed, restored (creating a new VM from the snapshot), or deleted.
//!
//! The snapshot workflow:
//! 1. Quiesce guest filesystems (if VM is running).
//! 2. Copy the QCOW2 overlay to `{data_dir}/snapshots/{snapshot_id}.qcow2`.
//! 3. Thaw guest filesystems.
//! 4. Record metadata in SQLite.

#[cfg(unix)]
/// Unix-specific snapshot implementation using QCOW2 disk copies and SQLite metadata.
mod inner {
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
        pub box_id: String,
        /// Optional human-friendly name.
        pub name: Option<String>,
        /// Absolute path to the snapshot disk image.
        pub disk_path: PathBuf,
        /// Size of the snapshot disk in bytes.
        pub disk_bytes: u64,
        /// Whether this snapshot includes memory state.
        pub memory: bool,
        /// When the snapshot was created.
        pub created_at: SystemTime,
    }

    impl From<SnapshotRow> for SnapshotInfo {
        fn from(row: SnapshotRow) -> Self {
            Self {
                id: row.id,
                box_id: row.box_id,
                name: row.name,
                disk_path: PathBuf::from(&row.disk_path),
                disk_bytes: row.disk_bytes,
                memory: row.memory,
                created_at: row.created_at,
            }
        }
    }

    /// Manages snapshot lifecycle: create, list, restore, delete.
    #[derive(Debug, Clone)]
    pub struct SnapshotManager {
        /// Shared state database.
        db: Arc<StateDb>,
        /// Directory for snapshot disk images.
        snapshots_dir: PathBuf,
    }

    impl SnapshotManager {
        /// Creates a new snapshot manager.
        pub fn new(db: Arc<StateDb>, data_dir: &Path) -> io::Result<Self> {
            let snapshots_dir = data_dir.join("snapshots");
            fs::create_dir_all(&snapshots_dir)?;
            Ok(Self { db, snapshots_dir })
        }

        /// Creates a snapshot of a VM's disk.
        ///
        /// If the VM is running, quiesces guest filesystems first for
        /// point-in-time consistency, then thaws after the copy.
        pub async fn create(
            &self,
            vm_id: &str,
            vm_status: Status,
            overlay_path: &Path,
            client: &Client,
            name: Option<&str>,
        ) -> Result<SnapshotInfo> {
            let snapshot_id = crate::state::gen_id();
            let dest = self
                .snapshots_dir
                .join(format!("{snapshot_id}.qcow2"));

            // Quiesce if running.
            let quiesced = if vm_status == Status::Running {
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
            } else {
                false
            };

            // Copy the overlay disk.
            let src = overlay_path.to_path_buf();
            let dst = dest.clone();
            let disk_bytes = tokio::task::spawn_blocking(move || -> io::Result<u64> {
                fs::copy(&src, &dst)
            })
            .await
            .map_err(io::Error::other)??;

            // Thaw if we quiesced.
            if quiesced {
                let _ = client.thaw().await;
            }

            let row = SnapshotRow {
                id: snapshot_id.clone(),
                box_id: vm_id.to_owned(),
                name: name.map(ToOwned::to_owned),
                disk_path: dest.to_string_lossy().into_owned(),
                disk_bytes,
                memory: false,
                created_at: SystemTime::now(),
            };
            self.db.insert_snapshot(&row)?;

            info!(vm_id, snapshot_id = %snapshot_id, bytes = disk_bytes, "snapshot created");
            Ok(SnapshotInfo::from(row))
        }

        /// Lists all snapshots for a given VM.
        pub fn list(&self, box_id: &str) -> Result<Vec<SnapshotInfo>> {
            Ok(self
                .db
                .list_snapshots(box_id)?
                .into_iter()
                .map(SnapshotInfo::from)
                .collect())
        }

        /// Gets a snapshot by ID.
        pub fn get(&self, snapshot_id: &str) -> Result<SnapshotInfo> {
            Ok(SnapshotInfo::from(self.db.get_snapshot(snapshot_id)?))
        }

        /// Deletes a snapshot (both the DB record and the disk file).
        pub fn delete(&self, snapshot_id: &str) -> Result<()> {
            let snap = self.db.get_snapshot(snapshot_id)?;
            let _ = fs::remove_file(&snap.disk_path);
            self.db.delete_snapshot(snapshot_id)?;
            info!(snapshot_id, "snapshot deleted");
            Ok(())
        }
    }
}

#[cfg(unix)]
pub use inner::{SnapshotInfo, SnapshotManager};
