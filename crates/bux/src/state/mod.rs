//! VM state types and `SQLite` persistence.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::disk::DiskFormat;

/// VM lifecycle status.
///
/// ```text
/// Stopped ──► Running ──► Stopping ──► Stopped
///                │                        ▲
///                └────────────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Status {
    /// VM process is running.
    Running,
    /// A graceful shutdown has been requested; waiting for the process to exit.
    Stopping,
    /// VM has been stopped or exited.
    Stopped,
}

impl Status {
    /// Returns `true` if the VM process may still be alive.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Stopping)
    }

    /// Returns `true` if `exec()` can be called.
    #[must_use]
    pub const fn can_exec(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `stop()` can be called.
    #[must_use]
    pub const fn can_stop(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `remove()` can be called.
    #[must_use]
    pub const fn can_remove(self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Returns `true` if transitioning from `self` to `target` is valid.
    ///
    /// ```text
    /// Stopped ──► Running ──► Stopping ──► Stopped
    ///                │                        ▲
    ///                └────────────────────────┘
    /// ```
    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Stopped, Self::Running)
                | (Self::Running | Self::Stopping, Self::Stopped)
                | (Self::Running, Self::Stopping)
        )
    }
}

/// A virtio-fs shared directory.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VirtioFs {
    /// Mount tag visible inside the guest.
    pub tag: String,
    /// Absolute host directory path.
    pub path: String,
    /// Guest mount point; the agent mounts this at PID 1 from `GuestBootConfig.volumes`.
    #[serde(default)]
    pub guest_path: String,
    /// Read-only virtio-fs (`krun_add_virtiofs3`).
    #[serde(default)]
    pub read_only: bool,
}

/// A vsock port mapping.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VsockPort {
    /// Guest-side vsock port number.
    pub port: u32,
    /// Host-side Unix socket path.
    pub path: String,
    /// `true` = guest listens, host connects (agent pattern).
    pub listen: bool,
}

/// Complete VM configuration persisted in `SQLite`.
///
/// Serialized as JSON inside the `SQLite` `config` column. The shim receives
/// a derived [`bux_shim::ShimConfig`], not this type directly.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VmConfig {
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
    /// When set, create builds a per-VM QCOW2 overlay backed by this image,
    /// then replaces `root_disk` with the overlay path and sets `disk_format`
    /// to [`DiskFormat::Qcow2`]. Consumed during spawn.
    #[serde(default)]
    pub base_disk: Option<String>,

    /// Executable path inside the VM.
    #[serde(default)]
    pub exec_path: Option<String>,
    /// Arguments passed to the executable.
    #[serde(default)]
    pub exec_args: Vec<String>,
    /// Environment variables (`KEY=VALUE`). Managed boot writes only `BUX_GUEST_CONFIG`.
    #[serde(default)]
    pub env: Option<Vec<String>>,

    /// TCP port mappings as concrete `"host:guest"` after resolution.
    #[serde(default)]
    pub ports: Vec<String>,

    /// Resolved published ports (set by Runtime after ephemeral probe).
    #[serde(default)]
    pub published_ports: Vec<crate::ports::PublishedPort>,

    /// virtio-fs shared directories.
    #[serde(default)]
    pub virtiofs: Vec<VirtioFs>,
    /// vsock port mappings (includes internal agent port).
    #[serde(default)]
    pub vsock_ports: Vec<VsockPort>,

    /// Guest network (gvproxy or offline).
    #[serde(default)]
    pub network: crate::options::NetworkSpec,

    /// When true, restart requires secret re-supply (`StartOptions.secrets`)
    /// if the Runtime process does not still hold memory-only secrets.
    ///
    /// Secret **values** are never stored in `SQLite`.
    #[serde(default)]
    pub secrets_required: bool,

    /// Workload env defaults for Phase A exec (`KEY=VALUE`). Not VM boot env.
    #[serde(default)]
    pub workload_env: Vec<String>,

    /// Workload working directory for Phase A exec. Not VM boot cwd.
    #[serde(default)]
    pub workload_workdir: Option<String>,

    /// Workload user for Phase A (`uid[:gid]` or `name[:group]`).
    ///
    /// Applied at exec time; not libkrun boot credentials.
    #[serde(default)]
    pub workload_user: Option<String>,

    /// Optional command the CLI may exec after the agent is ready.
    #[serde(default)]
    pub workload_cmd: Vec<String>,

    /// Requested security policy (persisted; applied at each spawn/start).
    #[serde(default)]
    pub security: crate::security::SecurityOptions,

    /// Actual security posture from the last successful spawn.
    #[serde(default)]
    pub security_status: crate::security::SecurityStatus,

    /// Remove VM state automatically when it stops.
    #[serde(default)]
    pub auto_remove: bool,

    /// Stop the VM after this many seconds of inactivity (`None` = never). Default off.
    #[serde(default)]
    pub auto_stop_secs: Option<u64>,

    /// Delete a stopped VM after this many seconds of inactivity (`None` = never). Default off.
    #[serde(default)]
    pub auto_delete_secs: Option<u64>,

    /// Last activity timestamp (exec, start, create). Used by the idle sweeper.
    #[serde(default, with = "crate::state::opt_system_time")]
    pub last_activity_at: Option<SystemTime>,

    /// Last fatal/recoverable error message (e.g. secrets re-supply required).
    #[serde(default)]
    pub last_error: Option<String>,

    /// Detached VM: no watchdog, no parent-death, Runtime Drop does not SIGTERM.
    #[serde(default)]
    pub detach: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpus: 1,
            ram_mib: 512,
            rootfs: None,
            root_disk: None,
            disk_format: DiskFormat::default(),
            base_disk: None,
            exec_path: None,
            exec_args: Vec::new(),
            env: None,
            ports: Vec::new(),
            published_ports: Vec::new(),
            virtiofs: Vec::new(),
            vsock_ports: Vec::new(),
            network: crate::options::NetworkSpec::default(),
            secrets_required: false,
            workload_env: Vec::new(),
            workload_workdir: None,
            workload_user: None,
            workload_cmd: Vec::new(),
            security: crate::security::SecurityOptions::default(),
            security_status: crate::security::SecurityStatus::default(),
            auto_remove: false,
            auto_stop_secs: None,
            auto_delete_secs: None,
            last_activity_at: None,
            last_error: None,
            detach: false,
        }
    }
}

/// Serde helpers for `Option<SystemTime>` as optional f64 unix seconds.
pub(crate) mod opt_system_time {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize optional activity timestamp as unix seconds.
    #[allow(clippy::ref_option, reason = "serde with signature")]
    pub(crate) fn serialize<S>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match t {
            Some(st) => {
                let secs = st
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                Some(secs).serialize(s)
            }
            None => None::<f64>.serialize(s),
        }
    }

    /// Deserialize optional activity timestamp from unix seconds.
    pub(crate) fn deserialize<'de, D>(d: D) -> Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Option<f64> = Option::deserialize(d)?;
        Ok(v.map(|secs| UNIX_EPOCH + Duration::from_secs_f64(secs.max(0.0))))
    }
}

/// Persisted state of a managed VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) struct VmState {
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
pub(crate) use db::{SnapshotRow, StateDb};

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
                exec_path: Some("/bin/sh".to_owned()),
                ..VmConfig::default()
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
    fn update_pid_status_persists_new_pid() {
        let db = open_test_db();
        db.insert(&test_vm("aaa111", None)).unwrap();

        db.update_pid_status("aaa111", 5678, Status::Running)
            .unwrap();
        let vm = db.get_by_id_prefix("aaa111").unwrap();
        assert_eq!(vm.pid, 5678);
        assert_eq!(vm.status, Status::Running);
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
        assert!(Status::Stopped.can_transition_to(Status::Running));
        assert!(Status::Running.can_transition_to(Status::Stopping));
        assert!(Status::Running.can_transition_to(Status::Stopped));
        assert!(Status::Stopping.can_transition_to(Status::Stopped));

        assert!(!Status::Stopped.can_transition_to(Status::Stopping));
        assert!(!Status::Stopping.can_transition_to(Status::Running));
        assert!(!Status::Stopping.can_transition_to(Status::Stopping));

        assert!(Status::Running.can_stop());
        assert!(!Status::Stopping.can_stop());
        assert!(!Status::Stopped.can_stop());

        assert!(Status::Running.is_active());
        assert!(Status::Stopping.is_active());
        assert!(!Status::Stopped.is_active());
    }

    #[test]
    fn snapshot_crud() {
        let db = open_test_db();
        db.insert(&test_vm("vm1", Some("myvm"))).unwrap();

        let snap = SnapshotRow {
            id: "snap1".to_owned(),
            vm_id: "vm1".to_owned(),
            name: Some("backup1".to_owned()),
            disk_path: "/tmp/snap1.qcow2".to_owned(),
            disk_bytes: 1024 * 1024,
            created_at: SystemTime::now(),
        };
        db.insert_snapshot(&snap).unwrap();

        let snaps = db.list_snapshots("vm1").unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, "snap1");
        assert_eq!(snaps[0].name.as_deref(), Some("backup1"));
        assert_eq!(snaps[0].disk_bytes, 1024 * 1024);

        let loaded = db.get_snapshot("snap1").unwrap();
        assert_eq!(loaded.vm_id, "vm1");

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
}
