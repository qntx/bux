//! VM state types and SQLite persistence.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// VM lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Status {
    /// VM is being prepared (disk creation, etc.).
    Creating,
    /// VM process is running.
    Running,
    /// VM has been stopped or exited.
    Stopped,
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

/// Complete VM configuration — sufficient to reconstruct a [`VmBuilder`].
///
/// Serialized as JSON inside the SQLite `config` column and passed to
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
pub fn gen_id() -> String {
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
/// SQLite persistence layer for VM state.
mod db {
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rusqlite::{Connection, params};

    use super::{Status, VmState};
    use crate::error::{Error, Result};

    /// Schema migration step.
    struct Migration {
        /// Sequential version number.
        version: u32,
        /// SQL to apply for this migration.
        sql: &'static str,
    }

    /// Ordered list of schema migrations. New migrations are appended here.
    const MIGRATIONS: &[Migration] = &[Migration {
        version: 1,
        sql: "
            CREATE TABLE IF NOT EXISTS vms (
                id          TEXT PRIMARY KEY NOT NULL,
                name        TEXT UNIQUE,
                pid         INTEGER NOT NULL,
                image       TEXT,
                socket      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'running',
                config      TEXT NOT NULL,
                created_at  REAL NOT NULL
            );
        ",
    }];

    /// SQLite-backed VM state database.
    #[derive(Debug)]
    pub struct StateDb {
        /// Underlying SQLite connection.
        conn: Connection,
    }

    impl StateDb {
        /// Opens (or creates) the database at `path`, running pending migrations.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            let conn = Connection::open(path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
            migrate(&conn)?;
            Ok(Self { conn })
        }

        /// Inserts a new VM state record.
        pub fn insert(&self, s: &VmState) -> Result<()> {
            let config_json = serde_json::to_string(&s.config)?;
            let ts = system_time_to_f64(s.created_at);
            self.conn.execute(
                "INSERT INTO vms (id, name, pid, image, socket, status, config, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    s.id,
                    s.name,
                    s.pid,
                    s.image,
                    s.socket.to_string_lossy(),
                    status_str(s.status),
                    config_json,
                    ts,
                ],
            )?;
            Ok(())
        }

        /// Updates the status of a VM.
        pub fn update_status(&self, id: &str, status: Status) -> Result<()> {
            self.conn.execute(
                "UPDATE vms SET status = ?1 WHERE id = ?2",
                params![status_str(status), id],
            )?;
            Ok(())
        }

        /// Finds a VM by exact name.
        pub fn get_by_name(&self, name: &str) -> Result<Option<VmState>> {
            let mut stmt = self.conn.prepare("SELECT * FROM vms WHERE name = ?1")?;
            let mut rows = stmt.query_map(params![name], row_to_state)?;
            rows.next().transpose().map_err(Into::into)
        }

        /// Finds a VM by exact ID or unique ID prefix.
        pub fn get_by_id_prefix(&self, prefix: &str) -> Result<VmState> {
            // Try exact match first.
            let mut stmt = self.conn.prepare("SELECT * FROM vms WHERE id = ?1")?;
            let mut rows = stmt.query_map(params![prefix], row_to_state)?;
            if let Some(row) = rows.next() {
                return Ok(row?);
            }
            drop(rows);
            drop(stmt);

            // Prefix search (id LIKE 'prefix%').
            let pattern = format!("{prefix}%");
            let mut prefix_stmt = self.conn.prepare("SELECT * FROM vms WHERE id LIKE ?1")?;
            let matches: Vec<VmState> = prefix_stmt
                .query_map(params![pattern], row_to_state)?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            match matches.len() {
                0 => Err(Error::NotFound(format!("no VM matching '{prefix}'"))),
                #[allow(clippy::expect_used)]
                1 => Ok(matches.into_iter().next().expect("len==1")),
                n => Err(Error::Ambiguous(format!(
                    "prefix '{prefix}' matches {n} VMs"
                ))),
            }
        }

        /// Lists all VMs, optionally filtering auto-removed stopped VMs.
        pub fn list(&self) -> Result<Vec<VmState>> {
            let mut stmt = self
                .conn
                .prepare("SELECT * FROM vms ORDER BY created_at DESC")?;
            let rows = stmt.query_map([], row_to_state)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }

        /// Updates the name of a VM.
        pub fn update_name(&self, id: &str, name: Option<&str>) -> Result<()> {
            self.conn
                .execute("UPDATE vms SET name = ?1 WHERE id = ?2", params![name, id])?;
            Ok(())
        }

        /// Deletes a VM record by ID.
        pub fn delete(&self, id: &str) -> Result<()> {
            self.conn
                .execute("DELETE FROM vms WHERE id = ?1", params![id])?;
            Ok(())
        }
    }

    /// Runs all pending schema migrations inside a transaction.
    fn migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);",
        )?;

        let current: u32 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )?;

        for m in MIGRATIONS.iter().filter(|m| m.version > current) {
            conn.execute_batch(m.sql)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![m.version],
            )?;
        }
        Ok(())
    }

    /// Maps a row to a [`VmState`].
    fn row_to_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<VmState> {
        let status_text: String = row.get("status")?;
        let config_json: String = row.get("config")?;
        let ts: f64 = row.get("created_at")?;
        let socket_str: String = row.get("socket")?;

        Ok(VmState {
            id: row.get("id")?,
            name: row.get("name")?,
            pid: row.get("pid")?,
            image: row.get("image")?,
            socket: socket_str.into(),
            status: parse_status(&status_text),
            config: serde_json::from_str(&config_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
            created_at: f64_to_system_time(ts),
        })
    }

    /// Converts a [`Status`] to its database string representation.
    const fn status_str(s: Status) -> &'static str {
        match s {
            Status::Creating => "creating",
            Status::Running => "running",
            Status::Stopped => "stopped",
        }
    }

    /// Parses a database string into a [`Status`].
    fn parse_status(s: &str) -> Status {
        match s {
            "creating" => Status::Creating,
            "running" => Status::Running,
            _ => Status::Stopped,
        }
    }

    /// Converts a [`SystemTime`] to seconds since UNIX epoch as `f64`.
    fn system_time_to_f64(t: SystemTime) -> f64 {
        t.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }

    /// Converts seconds since UNIX epoch (`f64`) back to a [`SystemTime`].
    fn f64_to_system_time(secs: f64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs_f64(secs)
    }
}

#[cfg(unix)]
pub use db::StateDb;

#[cfg(all(test, unix))]
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

    /// Opens an in-memory StateDb for testing.
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
}
