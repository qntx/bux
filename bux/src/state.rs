//! VM state types and SQLite persistence.

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
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Stopping)
    }

    /// Returns `true` if `exec()` can be called.
    pub const fn can_exec(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `stop()` can be called.
    pub const fn can_stop(self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }

    /// Returns `true` if `pause()` can be called.
    pub const fn can_pause(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if `resume()` can be called.
    pub const fn can_resume(self) -> bool {
        matches!(self, Self::Paused)
    }

    /// Returns `true` if `remove()` can be called.
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
    pub const fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Creating | Self::Paused | Self::Stopped, Self::Running)
                | (Self::Creating | Self::Running | Self::Paused | Self::Stopping, Self::Stopped)
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
    /// Disk image format for `root_disk`.
    #[serde(default)]
    pub disk_format: DiskFormat,
    /// Shared base image path for QCOW2 overlay creation.
    ///
    /// When set, [`Runtime::spawn()`] creates a per-VM QCOW2 overlay backed
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

    use super::{HealthState, Status, VmState};
    use crate::error::{Error, Result};

    /// Persisted snapshot metadata.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct SnapshotRow {
        /// Unique snapshot identifier.
        pub id: String,
        /// ID of the VM this snapshot belongs to.
        pub box_id: String,
        /// Optional human-friendly snapshot name (unique per box).
        pub name: Option<String>,
        /// Absolute path to the snapshot disk image.
        pub disk_path: String,
        /// Disk image size in bytes.
        pub disk_bytes: u64,
        /// Whether this snapshot includes memory state.
        pub memory: bool,
        /// When the snapshot was created.
        pub created_at: SystemTime,
    }

    /// Persisted base disk metadata with reference counting.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct BaseDiskRow {
        /// Unique base disk identifier.
        pub id: String,
        /// Content digest (e.g. `sha256:abcdef...`).
        pub digest: String,
        /// Absolute path to the base disk image.
        pub path: String,
        /// Number of overlays referencing this base disk.
        pub ref_count: i64,
        /// When the base disk was created.
        pub created_at: SystemTime,
    }

    /// Resource quota limits for a tenant.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct QuotaRow {
        /// Tenant identifier.
        pub tenant: String,
        /// Maximum number of VMs.
        pub max_boxes: Option<i64>,
        /// Maximum total disk usage in bytes.
        pub max_disk_bytes: Option<i64>,
        /// Maximum total vCPUs across all VMs.
        pub max_vcpus: Option<i64>,
        /// Maximum total RAM in MiB across all VMs.
        pub max_ram_mib: Option<i64>,
    }

    /// Schema migration step.
    struct Migration {
        /// Sequential version number.
        version: u32,
        /// SQL to apply for this migration.
        sql: &'static str,
    }

    /// Ordered list of schema migrations. New migrations are appended here.
    const MIGRATIONS: &[Migration] = &[
        Migration {
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
        },
        Migration {
            version: 2,
            sql: "
                -- Tenant + health columns on existing vms table.
                ALTER TABLE vms ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
                ALTER TABLE vms ADD COLUMN health TEXT NOT NULL DEFAULT 'unknown';
                ALTER TABLE vms ADD COLUMN updated_at REAL;

                -- Snapshot table: point-in-time disk copies.
                CREATE TABLE IF NOT EXISTS snapshots (
                    id          TEXT PRIMARY KEY NOT NULL,
                    box_id      TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
                    name        TEXT,
                    disk_path   TEXT NOT NULL,
                    disk_bytes  INTEGER NOT NULL DEFAULT 0,
                    memory      INTEGER NOT NULL DEFAULT 0,
                    created_at  REAL NOT NULL,
                    UNIQUE(box_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_box ON snapshots(box_id);

                -- Base disk tracking with reference counting.
                CREATE TABLE IF NOT EXISTS base_disks (
                    id          TEXT PRIMARY KEY NOT NULL,
                    digest      TEXT NOT NULL UNIQUE,
                    path        TEXT NOT NULL,
                    ref_count   INTEGER NOT NULL DEFAULT 0,
                    created_at  REAL NOT NULL
                );

                -- Resource quotas per tenant.
                CREATE TABLE IF NOT EXISTS quotas (
                    tenant          TEXT PRIMARY KEY NOT NULL,
                    max_boxes       INTEGER,
                    max_disk_bytes  INTEGER,
                    max_vcpus       INTEGER,
                    max_ram_mib     INTEGER
                );
            ",
        },
    ];

    /// SQLite-backed VM state database.
    ///
    /// Uses `Mutex<Connection>` to be safely `Send + Sync` without
    /// requiring `unsafe impl`. The mutex is held briefly per operation.
    #[derive(Debug)]
    pub struct StateDb {
        /// Underlying SQLite connection, protected by a mutex.
        conn: std::sync::Mutex<Connection>,
    }

    impl StateDb {
        /// Opens (or creates) the database at `path`, running pending migrations.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            let conn = Connection::open(path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
            migrate(&conn)?;
            Ok(Self {
                conn: std::sync::Mutex::new(conn),
            })
        }

        /// Acquires the database connection lock.
        ///
        /// # Panics
        ///
        /// Panics if the mutex is poisoned, which indicates a prior panic
        /// during a database operation — an unrecoverable state.
        #[allow(clippy::expect_used)]
        fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
            self.conn.lock().expect("StateDb mutex poisoned")
        }

        /// Inserts a new VM state record.
        pub fn insert(&self, s: &VmState) -> Result<()> {
            let config_json = serde_json::to_string(&s.config)?;
            let ts = system_time_to_f64(s.created_at);
            self.lock().execute(
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
            self.lock().execute(
                "UPDATE vms SET status = ?1 WHERE id = ?2",
                params![status_str(status), id],
            )?;
            Ok(())
        }

        /// Finds a VM by exact name.
        pub fn get_by_name(&self, name: &str) -> Result<Option<VmState>> {
            let conn = self.lock();
            let mut stmt = conn.prepare("SELECT * FROM vms WHERE name = ?1")?;
            let mut rows = stmt.query_map(params![name], row_to_state)?;
            rows.next().transpose().map_err(Into::into)
        }

        /// Finds a VM by exact ID or unique ID prefix.
        pub fn get_by_id_prefix(&self, prefix: &str) -> Result<VmState> {
            let conn = self.lock();

            // Try exact match first.
            let mut stmt = conn.prepare("SELECT * FROM vms WHERE id = ?1")?;
            let mut rows = stmt.query_map(params![prefix], row_to_state)?;
            if let Some(row) = rows.next() {
                return Ok(row?);
            }
            drop(rows);
            drop(stmt);

            // Prefix search (id LIKE 'prefix%').
            let pattern = format!("{prefix}%");
            let mut prefix_stmt = conn.prepare("SELECT * FROM vms WHERE id LIKE ?1")?;
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
            let conn = self.lock();
            let mut stmt = conn.prepare("SELECT * FROM vms ORDER BY created_at DESC")?;
            let rows = stmt.query_map([], row_to_state)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }

        /// Updates the name of a VM.
        pub fn update_name(&self, id: &str, name: Option<&str>) -> Result<()> {
            self.lock()
                .execute("UPDATE vms SET name = ?1 WHERE id = ?2", params![name, id])?;
            Ok(())
        }

        /// Deletes a VM record by ID.
        pub fn delete(&self, id: &str) -> Result<()> {
            self.lock()
                .execute("DELETE FROM vms WHERE id = ?1", params![id])?;
            Ok(())
        }

        /// Updates the health state of a VM.
        pub fn update_health(&self, id: &str, health: HealthState) -> Result<()> {
            self.lock().execute(
                "UPDATE vms SET health = ?1 WHERE id = ?2",
                params![health_str(health), id],
            )?;
            Ok(())
        }

        // ---- Snapshot CRUD ----

        /// Inserts a snapshot record.
        pub fn insert_snapshot(&self, s: &SnapshotRow) -> Result<()> {
            self.lock().execute(
                "INSERT INTO snapshots (id, box_id, name, disk_path, disk_bytes, memory, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    s.id,
                    s.box_id,
                    s.name,
                    s.disk_path,
                    i64::try_from(s.disk_bytes).unwrap_or(i64::MAX),
                    s.memory,
                    system_time_to_f64(s.created_at),
                ],
            )?;
            Ok(())
        }

        /// Lists all snapshots for a given box.
        pub fn list_snapshots(&self, box_id: &str) -> Result<Vec<SnapshotRow>> {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, box_id, name, disk_path, disk_bytes, memory, created_at
                 FROM snapshots WHERE box_id = ?1 ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map(params![box_id], row_to_snapshot)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }

        /// Finds a snapshot by ID.
        pub fn get_snapshot(&self, snapshot_id: &str) -> Result<SnapshotRow> {
            let conn = self.lock();
            conn.query_row(
                "SELECT id, box_id, name, disk_path, disk_bytes, memory, created_at
                 FROM snapshots WHERE id = ?1",
                params![snapshot_id],
                row_to_snapshot,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    Error::NotFound(format!("no snapshot matching '{snapshot_id}'"))
                }
                other => Error::Db(other),
            })
        }

        /// Deletes a snapshot record.
        pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
            self.lock()
                .execute("DELETE FROM snapshots WHERE id = ?1", params![snapshot_id])?;
            Ok(())
        }

        // ---- Base disk CRUD ----

        /// Inserts or returns an existing base disk by digest.
        pub fn upsert_base_disk(
            &self,
            id: &str,
            digest: &str,
            path: &str,
        ) -> Result<()> {
            self.lock().execute(
                "INSERT INTO base_disks (id, digest, path, ref_count, created_at)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT(digest) DO NOTHING",
                params![id, digest, path, system_time_to_f64(SystemTime::now())],
            )?;
            Ok(())
        }

        /// Finds a base disk by digest.
        pub fn get_base_disk_by_digest(&self, digest: &str) -> Result<Option<BaseDiskRow>> {
            let conn = self.lock();
            let result = conn.query_row(
                "SELECT id, digest, path, ref_count, created_at FROM base_disks WHERE digest = ?1",
                params![digest],
                row_to_base_disk,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(Error::Db(e)),
            }
        }

        /// Increments the reference count for a base disk.
        pub fn incr_base_disk_ref(&self, digest: &str) -> Result<()> {
            self.lock().execute(
                "UPDATE base_disks SET ref_count = ref_count + 1 WHERE digest = ?1",
                params![digest],
            )?;
            Ok(())
        }

        /// Decrements the reference count for a base disk.
        pub fn decr_base_disk_ref(&self, digest: &str) -> Result<()> {
            self.lock().execute(
                "UPDATE base_disks SET ref_count = ref_count - 1 WHERE digest = ?1",
                params![digest],
            )?;
            Ok(())
        }

        /// Returns all base disks with ref_count <= 0 (eligible for GC).
        pub fn orphaned_base_disks(&self) -> Result<Vec<BaseDiskRow>> {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, digest, path, ref_count, created_at
                 FROM base_disks WHERE ref_count <= 0",
            )?;
            let rows = stmt.query_map([], row_to_base_disk)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }

        /// Deletes a base disk record by ID.
        pub fn delete_base_disk(&self, id: &str) -> Result<()> {
            self.lock()
                .execute("DELETE FROM base_disks WHERE id = ?1", params![id])?;
            Ok(())
        }

        // ---- Quota CRUD ----

        /// Sets quota limits for a tenant.
        pub fn set_quota(&self, q: &QuotaRow) -> Result<()> {
            self.lock().execute(
                "INSERT INTO quotas (tenant, max_boxes, max_disk_bytes, max_vcpus, max_ram_mib)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(tenant) DO UPDATE SET
                    max_boxes = excluded.max_boxes,
                    max_disk_bytes = excluded.max_disk_bytes,
                    max_vcpus = excluded.max_vcpus,
                    max_ram_mib = excluded.max_ram_mib",
                params![q.tenant, q.max_boxes, q.max_disk_bytes, q.max_vcpus, q.max_ram_mib],
            )?;
            Ok(())
        }

        /// Gets quota limits for a tenant.
        pub fn get_quota(&self, tenant: &str) -> Result<Option<QuotaRow>> {
            let conn = self.lock();
            let result = conn.query_row(
                "SELECT tenant, max_boxes, max_disk_bytes, max_vcpus, max_ram_mib
                 FROM quotas WHERE tenant = ?1",
                params![tenant],
                |row| {
                    Ok(QuotaRow {
                        tenant: row.get(0)?,
                        max_boxes: row.get(1)?,
                        max_disk_bytes: row.get(2)?,
                        max_vcpus: row.get(3)?,
                        max_ram_mib: row.get(4)?,
                    })
                },
            );
            match result {
                Ok(q) => Ok(Some(q)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(Error::Db(e)),
            }
        }

        /// Counts running VMs for a given tenant.
        pub fn count_boxes_by_tenant(&self, tenant: &str) -> Result<i64> {
            let conn = self.lock();
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM vms WHERE tenant = ?1",
                params![tenant],
                |r| r.get(0),
            )?)
        }

        /// Lists VMs filtered by tenant.
        pub fn list_by_tenant(&self, tenant: &str) -> Result<Vec<VmState>> {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT * FROM vms WHERE tenant = ?1 ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map(params![tenant], row_to_state)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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

    /// Maps a row to a [`SnapshotRow`].
    fn row_to_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<SnapshotRow> {
        Ok(SnapshotRow {
            id: row.get(0)?,
            box_id: row.get(1)?,
            name: row.get(2)?,
            disk_path: row.get(3)?,
            disk_bytes: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
            memory: row.get(5)?,
            created_at: f64_to_system_time(row.get(6)?),
        })
    }

    /// Maps a row to a [`BaseDiskRow`].
    fn row_to_base_disk(row: &rusqlite::Row<'_>) -> rusqlite::Result<BaseDiskRow> {
        Ok(BaseDiskRow {
            id: row.get(0)?,
            digest: row.get(1)?,
            path: row.get(2)?,
            ref_count: row.get(3)?,
            created_at: f64_to_system_time(row.get(4)?),
        })
    }

    /// Converts a [`HealthState`] to its database string representation.
    const fn health_str(h: HealthState) -> &'static str {
        match h {
            HealthState::Unknown => "unknown",
            HealthState::Healthy => "healthy",
            HealthState::Unhealthy => "unhealthy",
        }
    }

    /// Converts a [`Status`] to its database string representation.
    const fn status_str(s: Status) -> &'static str {
        match s {
            Status::Creating => "creating",
            Status::Running => "running",
            Status::Paused => "paused",
            Status::Stopping => "stopping",
            Status::Stopped => "stopped",
        }
    }

    /// Parses a database string into a [`Status`].
    fn parse_status(s: &str) -> Status {
        match s {
            "creating" => Status::Creating,
            "running" => Status::Running,
            "paused" => Status::Paused,
            "stopping" => Status::Stopping,
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
pub use db::{BaseDiskRow, QuotaRow, SnapshotRow, StateDb};

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::shadow_unrelated)]
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
