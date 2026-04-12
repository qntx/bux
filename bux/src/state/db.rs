//! `SQLite` persistence layer for VM state.

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
    /// Underlying `SQLite` connection, protected by a mutex.
    conn: std::sync::Mutex<Connection>,
}

impl StateDb {
    /// Opens (or creates) the database at `path`, running pending migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrations fail.
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
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("StateDb mutex poisoned")
    }

    /// Inserts a new VM state record.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or the database insert fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn update_status(&self, id: &str, status: Status) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET status = ?1 WHERE id = ?2",
            params![status_str(status), id],
        )?;
        Ok(())
    }

    /// Finds a VM by exact name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_by_name(&self, name: &str) -> Result<Option<VmState>> {
        let conn = self.lock();
        Ok(conn
            .prepare("SELECT * FROM vms WHERE name = ?1")?
            .query_map(params![name], row_to_state)?
            .next()
            .transpose()?)
    }

    /// Finds a VM by exact ID or unique ID prefix.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VM matches, or
    /// [`Error::Ambiguous`] if the prefix matches multiple VMs.
    ///
    /// # Panics
    ///
    /// Should not panic in practice; the internal `expect` is guarded
    /// by a length check.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "MutexGuard must live across two queries"
    )]
    pub fn get_by_id_prefix(&self, prefix: &str) -> Result<VmState> {
        let conn = self.lock();

        // Try exact match first.
        if let Some(row) = conn
            .prepare("SELECT * FROM vms WHERE id = ?1")?
            .query_map(params![prefix], row_to_state)?
            .next()
        {
            return Ok(row?);
        }

        // Prefix search (id LIKE 'prefix%').
        let pattern = format!("{prefix}%");
        let matches: Vec<VmState> = conn
            .prepare("SELECT * FROM vms WHERE id LIKE ?1")?
            .query_map(params![pattern], row_to_state)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(conn);

        match matches.len() {
            0 => Err(Error::NotFound(format!("no VM matching '{prefix}'"))),
            #[allow(clippy::expect_used, reason = "length checked on previous line")]
            1 => Ok(matches.into_iter().next().expect("len==1")),
            n => Err(Error::Ambiguous(format!(
                "prefix '{prefix}' matches {n} VMs"
            ))),
        }
    }

    /// Lists all VMs, optionally filtering auto-removed stopped VMs.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list(&self) -> Result<Vec<VmState>> {
        let conn = self.lock();
        Ok(conn
            .prepare("SELECT * FROM vms ORDER BY created_at DESC")?
            .query_map([], row_to_state)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Updates the name of a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn update_name(&self, id: &str, name: Option<&str>) -> Result<()> {
        self.lock()
            .execute("UPDATE vms SET name = ?1 WHERE id = ?2", params![name, id])?;
        Ok(())
    }

    /// Deletes a VM record by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database deletion fails.
    pub fn delete(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM vms WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Updates the health state of a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn update_health(&self, id: &str, health: HealthState) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET health = ?1 WHERE id = ?2",
            params![health_str(health), id],
        )?;
        Ok(())
    }

    // ---- Snapshot CRUD ----

    /// Inserts a snapshot record.
    ///
    /// # Errors
    ///
    /// Returns an error if the database insert fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list_snapshots(&self, box_id: &str) -> Result<Vec<SnapshotRow>> {
        let conn = self.lock();
        Ok(conn
            .prepare(
                "SELECT id, box_id, name, disk_path, disk_bytes, memory, created_at
                 FROM snapshots WHERE box_id = ?1 ORDER BY created_at DESC",
            )?
            .query_map(params![box_id], row_to_snapshot)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Finds a snapshot by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no snapshot matches.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the database deletion fails.
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM snapshots WHERE id = ?1", params![snapshot_id])?;
        Ok(())
    }

    // ---- Base disk CRUD ----

    /// Inserts or returns an existing base disk by digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the database upsert fails.
    pub fn upsert_base_disk(&self, id: &str, digest: &str, path: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO base_disks (id, digest, path, ref_count, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(digest) DO NOTHING",
            params![id, digest, path, system_time_to_f64(SystemTime::now())],
        )?;
        Ok(())
    }

    /// Finds a base disk by digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_base_disk_by_digest(&self, digest: &str) -> Result<Option<BaseDiskRow>> {
        let result = {
            let conn = self.lock();
            conn.query_row(
                "SELECT id, digest, path, ref_count, created_at FROM base_disks WHERE digest = ?1",
                params![digest],
                row_to_base_disk,
            )
        };
        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Db(e)),
        }
    }

    /// Increments the reference count for a base disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn incr_base_disk_ref(&self, digest: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE base_disks SET ref_count = ref_count + 1 WHERE digest = ?1",
            params![digest],
        )?;
        Ok(())
    }

    /// Decrements the reference count for a base disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn decr_base_disk_ref(&self, digest: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE base_disks SET ref_count = ref_count - 1 WHERE digest = ?1",
            params![digest],
        )?;
        Ok(())
    }

    /// Returns all base disks with `ref_count` <= 0 (eligible for GC).
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn orphaned_base_disks(&self) -> Result<Vec<BaseDiskRow>> {
        let conn = self.lock();
        Ok(conn
            .prepare(
                "SELECT id, digest, path, ref_count, created_at
                 FROM base_disks WHERE ref_count <= 0",
            )?
            .query_map([], row_to_base_disk)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Deletes a base disk record by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database deletion fails.
    pub fn delete_base_disk(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM base_disks WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- Quota CRUD ----

    /// Sets quota limits for a tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if the database upsert fails.
    pub fn set_quota(&self, q: &QuotaRow) -> Result<()> {
        self.lock().execute(
            "INSERT INTO quotas (tenant, max_boxes, max_disk_bytes, max_vcpus, max_ram_mib)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(tenant) DO UPDATE SET
                max_boxes = excluded.max_boxes,
                max_disk_bytes = excluded.max_disk_bytes,
                max_vcpus = excluded.max_vcpus,
                max_ram_mib = excluded.max_ram_mib",
            params![
                q.tenant,
                q.max_boxes,
                q.max_disk_bytes,
                q.max_vcpus,
                q.max_ram_mib
            ],
        )?;
        Ok(())
    }

    /// Gets quota limits for a tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_quota(&self, tenant: &str) -> Result<Option<QuotaRow>> {
        let result = {
            let conn = self.lock();
            conn.query_row(
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
            )
        };
        match result {
            Ok(q) => Ok(Some(q)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Db(e)),
        }
    }

    /// Counts running VMs for a given tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn count_boxes_by_tenant(&self, tenant: &str) -> Result<i64> {
        let conn = self.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM vms WHERE tenant = ?1",
            params![tenant],
            |r| r.get(0),
        )?)
    }

    /// Lists VMs filtered by tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list_by_tenant(&self, tenant: &str) -> Result<Vec<VmState>> {
        let conn = self.lock();
        Ok(conn
            .prepare("SELECT * FROM vms WHERE tenant = ?1 ORDER BY created_at DESC")?
            .query_map(params![tenant], row_to_state)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

/// Runs all pending schema migrations inside a transaction.
fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")?;

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
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
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
