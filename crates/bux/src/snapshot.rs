//! Snapshot management for point-in-time VM disk captures.
//!
//! A snapshot copies the current QCOW2 overlay disk. Running VMs must
//! `FIFREEZE` first; freeze failure aborts and does not create the
//! destination overlay. Stopped VMs copy without quiesce. Snapshots can
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

use tracing::info;

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
    /// Running VMs are frozen (`FIFREEZE`) before the copy; freeze failure
    /// skips the destination overlay. Stopped VMs copy without quiesce.
    ///
    /// # Errors
    ///
    /// Returns an error if a running VM cannot be quiesced, or if the disk
    /// copy or database insert fails.
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

        let quiesced = try_quiesce(vm_id, vm_status, client).await?;

        let src = overlay_path.to_path_buf();
        let dst = dest.clone();
        let copied = tokio::task::spawn_blocking(move || fs::copy(&src, &dst))
            .await
            .map_err(io::Error::other);

        if quiesced {
            // FIFREEZE holds until FITHAW; copy failure must not leave the guest frozen.
            client.thaw().await.ok();
        }

        let disk_bytes = copied??;

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

/// Running snapshots without freeze can be torn; fail closed instead of copying dirty.
async fn try_quiesce(vm_id: &str, status: Status, client: &Client) -> Result<bool> {
    if status != Status::Running {
        return Ok(false);
    }
    let n = client.quiesce().await?;
    info!(vm_id, frozen = n, "filesystems quiesced for snapshot");
    Ok(true)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::state::{VmConfig, VmState};
    use bux_proto::{ControlReq, ControlResp, ErrorInfo, Hello, HelloAck, PROTOCOL_VERSION};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::SystemTime;
    use tokio::net::UnixListener;

    async fn stub_guest_quiesce_error(listener: UnixListener, saw_quiesce: Arc<AtomicBool>) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello: Hello = bux_proto::recv(&mut stream).await.unwrap();
        assert!(
            matches!(hello, Hello::Control { version } if version == PROTOCOL_VERSION),
            "Client::quiesce must send Hello::Control v10, got {hello:?}"
        );
        bux_proto::send(
            &mut stream,
            &HelloAck::Control {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let req: ControlReq = bux_proto::recv(&mut stream).await.unwrap();
        assert!(
            matches!(req, ControlReq::Quiesce),
            "create must send ControlReq::Quiesce, got {req:?}"
        );
        saw_quiesce.store(true, Ordering::SeqCst);
        bux_proto::send(
            &mut stream,
            &ControlResp::Error(ErrorInfo::internal("FIFREEZE failed")),
        )
        .await
        .unwrap();
    }

    #[test]
    fn try_quiesce_running_error_skips_copy() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("overlay.qcow2");
        fs::write(&overlay, b"overlay-bytes").unwrap();
        let sock = dir.path().join("guest.sock");
        let db = Arc::new(StateDb::open(dir.path().join("bux.db")).unwrap());
        db.insert(&VmState {
            id: "vm1".into(),
            name: None,
            pid: 1,
            image: None,
            socket: sock.clone(),
            status: Status::Running,
            config: VmConfig::default(),
            created_at: SystemTime::UNIX_EPOCH,
        })
        .unwrap();
        let mgr = SnapshotManager::new(Arc::clone(&db), dir.path()).unwrap();
        let snapshots_dir = dir.path().join("snapshots");
        let saw_quiesce = Arc::new(AtomicBool::new(false));

        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = UnixListener::bind(&sock).unwrap();
                let saw = Arc::clone(&saw_quiesce);
                let server = tokio::spawn(stub_guest_quiesce_error(listener, saw));
                let client = Client::new(&sock);
                let create = mgr
                    .create("vm1", Status::Running, &overlay, &client, None)
                    .await;
                server.abort();
                create
            });

        assert!(
            result.is_err(),
            "running snapshot must fail when FIFREEZE fails, got {result:?}"
        );
        assert!(
            saw_quiesce.load(Ordering::SeqCst),
            "create must call Client::quiesce"
        );
        let copied = fs::read_dir(&snapshots_dir).unwrap().any(|entry| {
            entry
                .ok()
                .is_some_and(|e| e.path().extension().is_some_and(|ext| ext == "qcow2"))
        });
        assert!(
            !copied,
            "quiesce failure must not create the destination overlay"
        );
        assert!(
            mgr.list("vm1").unwrap().is_empty(),
            "failed snapshot must not insert a row"
        );
    }
}
