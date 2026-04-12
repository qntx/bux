//! VM state types and `SQLite` persistence.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::disk::DiskFormat;

/// VM lifecycle status.
///
/// ```text
/// Creating ──► Running ──► Stopping ──► Stopped
///                │  ▲                      ▲
///                ▼  │                      │
///              Paused ────────────────────►┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Status {
    /// VM is being prepared (disk creation, etc.).
    Creating,
    /// VM process is running.
    Running,
    /// VM is frozen via SIGSTOP (vCPUs and virtio backends paused).
    ///
    /// Filesystem may also be quiesced (FIFREEZE) for point-in-time consistency.
    /// Resume with [`VmHandle::resume()`](crate::runtime::VmHandle::resume).
    Paused,
    /// A graceful shutdown has been requested; waiting for the process to exit.
    Stopping,
    /// VM has been stopped or exited.
    Stopped,
}

impl Status {
    /// Returns `true` if the VM process may still be alive.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Stopping)
    }

    /// Returns `true` if `exec()` can be called.
    #[must_use]
    pub const fn can_exec(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `stop()` can be called.
    #[must_use]
    pub const fn can_stop(self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }

    /// Returns `true` if `pause()` can be called.
    #[must_use]
    pub const fn can_pause(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `resume()` can be called.
    #[must_use]
    pub const fn can_resume(self) -> bool {
        matches!(self, Self::Paused)
    }

    /// Returns `true` if `remove()` can be called.
    #[must_use]
    pub const fn can_remove(self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Returns `true` if transitioning from `self` to `target` is valid.
    ///
    /// ```text
    /// Creating ──► Running ──► Stopping ──► Stopped
    ///                │  ▲                      ▲
    ///                ▼  │                      │
    ///              Paused ────────────────────►┘
    /// ```
    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Creating | Self::Paused | Self::Stopped, Self::Running)
                | (
                    Self::Creating | Self::Running | Self::Paused | Self::Stopping,
                    Self::Stopped
                )
                | (Self::Running, Self::Paused | Self::Stopping)
                | (Self::Paused, Self::Stopping)
        )
    }
}

/// VM health state, tracked independently of lifecycle [`Status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HealthState {
    /// Health has not been checked yet.
    Unknown,
    /// Guest agent responded successfully.
    Healthy,
    /// Guest agent failed to respond within the configured threshold.
    Unhealthy,
}

/// A virtio-fs shared directory.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioFs {
    /// Mount tag visible inside the guest.
    pub tag: String,
    /// Absolute host directory path.
    pub path: String,
}

/// A vsock port mapping.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockPort {
    /// Guest-side vsock port number.
    pub port: u32,
    /// Host-side Unix socket path.
    pub path: String,
    /// `true` = guest listens, host connects (agent pattern).
    pub listen: bool,
}

/// Complete VM configuration — sufficient to reconstruct a [`crate::VmBuilder`].
///
/// Serialized as JSON inside the `SQLite` `config` column and passed to
/// `bux-shim` as a temp file so the child process can rebuild the VM.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub vcpus: u8,
    /// RAM size in MiB.
    pub ram_mib: u32,

    /// Root filesystem directory path (virtiofs-based).
    #[serde(default)]
    pub rootfs: Option<String>,
    /// Root filesystem disk image path (block device-based).
    #[serde(default)]
    pub root_disk: Option<String>,
    /// Disk image format for `root_disk`.
    #[serde(default)]
    pub disk_format: DiskFormat,
    /// Shared base image path for QCOW2 overlay creation.
    ///
    /// When set, [`crate::Runtime::spawn()`] creates a per-VM QCOW2 overlay backed
    /// by this image, then replaces `root_disk` with the overlay path and
    /// sets `disk_format` to [`DiskFormat::Qcow2`]. Consumed during spawn.
    #[serde(default)]
    pub base_disk: Option<String>,

    /// Executable path inside the VM.
    #[serde(default)]
    pub exec_path: Option<String>,
    /// Arguments passed to the executable.
    #[serde(default)]
    pub exec_args: Vec<String>,
    /// Environment variables (`KEY=VALUE`). `None` = inherit host env.
    #[serde(default)]
    pub env: Option<Vec<String>>,
    /// Working directory inside the VM.
    #[serde(default)]
    pub workdir: Option<String>,

    /// TCP port mappings (`"host:guest"`).
    #[serde(default)]
    pub ports: Vec<String>,

    /// virtio-fs shared directories.
    #[serde(default)]
    pub virtiofs: Vec<VirtioFs>,
    /// vsock port mappings (includes internal agent port).
    #[serde(default)]
    pub vsock_ports: Vec<VsockPort>,

    /// Global log level.
    #[serde(default)]
    pub log_level: Option<crate::vm::LogLevel>,
    /// UID to set before starting the VM.
    #[serde(default)]
    pub uid: Option<u32>,
    /// GID to set before starting the VM.
    #[serde(default)]
    pub gid: Option<u32>,
    /// Resource limits (`"RESOURCE=RLIM_CUR:RLIM_MAX"`).
    #[serde(default)]
    pub rlimits: Vec<String>,
    /// Enable nested virtualization (macOS only).
    #[serde(default)]
    pub nested_virt: Option<bool>,
    /// Enable/disable virtio-snd.
    #[serde(default)]
    pub snd_device: Option<bool>,
    /// Redirect console output to a file.
    #[serde(default)]
    pub console_output: Option<String>,

    /// Remove VM state automatically when it stops.
    #[serde(default)]
    pub auto_remove: bool,
}

/// Persisted state of a managed VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VmState {
    /// Short hex identifier.
    pub id: String,
    /// Optional human-friendly name (unique across the runtime).
    pub name: Option<String>,
    /// Host PID of the VM process (matches `libc::pid_t`).
    pub pid: i32,
    /// OCI image reference (if pulled from a registry).
    pub image: Option<String>,
    /// Unix socket path for host↔guest communication.
    pub socket: PathBuf,
    /// Current lifecycle status.
    pub status: Status,
    /// VM configuration snapshot.
    pub config: VmConfig,
    /// Timestamp when the VM was created.
    pub created_at: SystemTime,
}

/// Generates a 12-character hex VM identifier.
#[cfg(unix)]
pub(crate) fn gen_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::UNIX_EPOCH;

    let mut h = RandomState::new().build_hasher();
    h.write_u64(u64::from(std::process::id()));
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    format!("{:012x}", h.finish())
}

#[cfg(unix)]
mod db;

#[cfg(unix)]
pub use db::{BaseDiskRow, QuotaRow, SnapshotRow, StateDb};

#[cfg(test)]
#[cfg(unix)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::shadow_unrelated,
    clippy::indexing_slicing,
    reason = "test assertions use unwrap/indexing for clarity"
)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    /// Creates a test `VmState` with the given ID and name.
    fn test_vm(id: &str, name: Option<&str>) -> VmState {
        VmState {
            id: id.to_owned(),
            name: name.map(ToOwned::to_owned),
            pid: 1234,
            image: Some("alpine:latest".to_owned()),
            socket: format!("/tmp/{id}.sock").into(),
            status: Status::Running,
            config: VmConfig {
                vcpus: 2,
                ram_mib: 512,
                rootfs: None,
                root_disk: None,
                disk_format: DiskFormat::default(),
                base_disk: None,
                exec_path: Some("/bin/sh".to_owned()),
                exec_args: vec![],
                env: None,
                workdir: None,
                ports: vec![],
                virtiofs: vec![],
                vsock_ports: vec![],
                log_level: None,
                uid: None,
                gid: None,
                rlimits: vec![],
                nested_virt: None,
                snd_device: None,
                console_output: None,
                auto_remove: false,
            },
            created_at: SystemTime::now(),
        }
    }

    /// Opens an in-memory `StateDb` for testing.
    fn open_test_db() -> StateDb {
        StateDb::open(":memory:").expect("open in-memory db")
    }

    #[test]
    fn insert_and_list() {
        let db = open_test_db();
        let vm = test_vm("aaa111bbb222", Some("myvm"));
        db.insert(&vm).unwrap();

        let all = db.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "aaa111bbb222");
        assert_eq!(all[0].name.as_deref(), Some("myvm"));
        assert_eq!(all[0].pid, 1234);
        assert_eq!(all[0].status, Status::Running);
    }

    #[test]
    fn get_by_name() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", Some("alpha"))).unwrap();
        db.insert(&test_vm("bbb222", Some("beta"))).unwrap();

        let found = db.get_by_name("alpha").unwrap().unwrap();
        assert_eq!(found.id, "aaa111");

        assert!(db.get_by_name("nonexistent").unwrap().is_none());
    }

    #[test]
    fn get_by_id_prefix() {
        let db = open_test_db();
        db.insert(&test_vm("abc123def456", None)).unwrap();
        db.insert(&test_vm("xyz789000111", None)).unwrap();

        // Exact match.
        let found = db.get_by_id_prefix("abc123def456").unwrap();
        assert_eq!(found.id, "abc123def456");

        // Unique prefix.
        let found = db.get_by_id_prefix("abc").unwrap();
        assert_eq!(found.id, "abc123def456");

        // No match → NotFound.
        assert!(db.get_by_id_prefix("zzz").is_err());
    }

    #[test]
    fn ambiguous_prefix() {
        let db = open_test_db();
        db.insert(&test_vm("abc111", None)).unwrap();
        db.insert(&test_vm("abc222", None)).unwrap();

        let err = db.get_by_id_prefix("abc").unwrap_err();
        assert!(
            matches!(err, crate::Error::Ambiguous(_)),
            "expected Ambiguous, got {err:?}"
        );
    }

    #[test]
    fn update_status() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", None)).unwrap();

        db.update_status("aaa111", Status::Stopped).unwrap();
        let vm = db.get_by_id_prefix("aaa111").unwrap();
        assert_eq!(vm.status, Status::Stopped);
    }

    #[test]
    fn update_name() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", Some("old"))).unwrap();

        db.update_name("aaa111", Some("new")).unwrap();
        assert!(db.get_by_name("old").unwrap().is_none());
        assert!(db.get_by_name("new").unwrap().is_some());
    }

    #[test]
    fn delete() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", None)).unwrap();
        assert_eq!(db.list().unwrap().len(), 1);

        db.delete("aaa111").unwrap();
        assert_eq!(db.list().unwrap().len(), 0);
    }

    #[test]
    fn duplicate_name_rejected() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", Some("dup"))).unwrap();

        let result = db.insert(&test_vm("bbb222", Some("dup")));
        assert!(result.is_err(), "duplicate name should be rejected");
    }

    #[test]
    fn pid_stored_as_i32() {
        let db = open_test_db();
        let mut vm = test_vm("aaa111", None);
        vm.pid = -1; // Negative PID should survive round-trip.
        db.insert(&vm).unwrap();

        let loaded = db.get_by_id_prefix("aaa111").unwrap();
        assert_eq!(loaded.pid, -1);
    }

    #[test]
    fn status_transitions() {
        assert!(Status::Creating.can_transition_to(Status::Running));
        assert!(Status::Running.can_transition_to(Status::Paused));
        assert!(Status::Running.can_transition_to(Status::Stopping));
        assert!(Status::Paused.can_transition_to(Status::Running));
        assert!(Status::Stopping.can_transition_to(Status::Stopped));
        assert!(Status::Stopped.can_transition_to(Status::Running));

        // Invalid transitions.
        assert!(!Status::Stopped.can_transition_to(Status::Paused));
        assert!(!Status::Creating.can_transition_to(Status::Paused));
        assert!(!Status::Running.can_transition_to(Status::Creating));
    }

    #[test]
    fn snapshot_crud() {
        let db = open_test_db();
        db.insert(&test_vm("vm1", Some("myvm"))).unwrap();

        let snap = SnapshotRow {
            id: "snap1".to_owned(),
            box_id: "vm1".to_owned(),
            name: Some("backup1".to_owned()),
            disk_path: "/tmp/snap1.qcow2".to_owned(),
            disk_bytes: 1024 * 1024,
            memory: false,
            created_at: SystemTime::now(),
        };
        db.insert_snapshot(&snap).unwrap();

        let snaps = db.list_snapshots("vm1").unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, "snap1");
        assert_eq!(snaps[0].name.as_deref(), Some("backup1"));
        assert_eq!(snaps[0].disk_bytes, 1024 * 1024);

        let loaded = db.get_snapshot("snap1").unwrap();
        assert_eq!(loaded.box_id, "vm1");

        db.delete_snapshot("snap1").unwrap();
        assert_eq!(db.list_snapshots("vm1").unwrap().len(), 0);
    }

    #[test]
    fn base_disk_ref_counting() {
        let db = open_test_db();

        db.upsert_base_disk("bd1", "sha256:abc", "/tmp/base.raw")
            .unwrap();

        let bd = db.get_base_disk_by_digest("sha256:abc").unwrap().unwrap();
        assert_eq!(bd.ref_count, 0);

        db.incr_base_disk_ref("sha256:abc").unwrap();
        db.incr_base_disk_ref("sha256:abc").unwrap();
        let bd = db.get_base_disk_by_digest("sha256:abc").unwrap().unwrap();
        assert_eq!(bd.ref_count, 2);

        db.decr_base_disk_ref("sha256:abc").unwrap();
        db.decr_base_disk_ref("sha256:abc").unwrap();

        let orphans = db.orphaned_base_disks().unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].digest, "sha256:abc");

        db.delete_base_disk("bd1").unwrap();
        assert!(db.get_base_disk_by_digest("sha256:abc").unwrap().is_none());
    }

    #[test]
    fn quota_crud() {
        let db = open_test_db();

        assert!(db.get_quota("team-a").unwrap().is_none());

        db.set_quota(&QuotaRow {
            tenant: "team-a".to_owned(),
            max_boxes: Some(10),
            max_disk_bytes: Some(100 * 1024 * 1024 * 1024),
            max_vcpus: Some(32),
            max_ram_mib: Some(64 * 1024),
        })
        .unwrap();

        let q = db.get_quota("team-a").unwrap().unwrap();
        assert_eq!(q.max_boxes, Some(10));
        assert_eq!(q.max_vcpus, Some(32));

        // Upsert updates existing.
        db.set_quota(&QuotaRow {
            tenant: "team-a".to_owned(),
            max_boxes: Some(20),
            max_disk_bytes: None,
            max_vcpus: None,
            max_ram_mib: None,
        })
        .unwrap();
        let q = db.get_quota("team-a").unwrap().unwrap();
        assert_eq!(q.max_boxes, Some(20));
        assert!(q.max_disk_bytes.is_none());
    }

    #[test]
    fn health_update() {
        let db = open_test_db();
        db.insert(&test_vm("vm1", None)).unwrap();

        db.update_health("vm1", HealthState::Healthy).unwrap();
        // Verify health is stored (read back via list).
        let vms = db.list().unwrap();
        assert_eq!(vms.len(), 1);
        // Health is not yet in VmState struct, but the SQL succeeded.
    }

    #[test]
    fn tenant_filtering() {
        let db = open_test_db();
        db.insert(&test_vm("vm1", Some("a"))).unwrap();
        db.insert(&test_vm("vm2", Some("b"))).unwrap();

        // Both VMs default to 'default' tenant.
        let all = db.list_by_tenant("default").unwrap();
        assert_eq!(all.len(), 2);

        assert_eq!(db.count_boxes_by_tenant("default").unwrap(), 2);
        assert_eq!(db.count_boxes_by_tenant("other").unwrap(), 0);
    }
}
