//! `SQLite` persistence layer for VM state.
//!
//! **Product schema only** — no migrations from pre-1.0 layouts.
//! On version mismatch the open fails; delete the data directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use super::{Status, VmState};
use crate::error::{Error, Result};

/// Product state-schema version (PRAGMA `user_version`).
///
/// Bump only on incompatible schema changes. There is **no** migration
/// path — callers must wipe the data directory.
///
/// v5: drop `vms.health`.
pub(crate) const PRODUCT_SCHEMA_VERSION: u32 = 5;

/// DDL for a fresh product database.
const PRODUCT_SCHEMA_SQL: &str = "
CREATE TABLE vms (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT UNIQUE,
    pid         INTEGER NOT NULL,
    image       TEXT,
    socket      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    config      TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL
);

CREATE TABLE snapshots (
    id          TEXT PRIMARY KEY NOT NULL,
    vm_id       TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name        TEXT,
    disk_path   TEXT NOT NULL,
    disk_bytes  INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    UNIQUE(vm_id, name)
);
CREATE INDEX idx_snapshots_vm ON snapshots(vm_id);

CREATE TABLE base_disks (
    id          TEXT PRIMARY KEY NOT NULL,
    digest      TEXT NOT NULL UNIQUE,
    path        TEXT NOT NULL,
    ref_count   INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);

CREATE TABLE volumes (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL UNIQUE,
    path        TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE vm_volumes (
    vm_id       TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    volume_id   TEXT NOT NULL REFERENCES volumes(id),
    guest_path  TEXT NOT NULL,
    PRIMARY KEY (vm_id, volume_id)
);
CREATE INDEX idx_vm_volumes_volume ON vm_volumes(volume_id);
";

/// Persisted snapshot metadata (disk-only; no memory snapshots).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct SnapshotRow {
    /// Unique snapshot identifier.
    pub id: String,
    /// ID of the VM this snapshot belongs to.
    pub vm_id: String,
    /// Optional human-friendly snapshot name (unique per VM).
    pub name: Option<String>,
    /// Absolute path to the snapshot disk image.
    pub disk_path: String,
    /// Disk image size in bytes.
    pub disk_bytes: u64,
    /// When the snapshot was created.
    pub created_at: SystemTime,
}

/// Persisted base disk metadata with reference counting.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(dead_code, reason = "row mapped from SQLite; fields used in tests")]
pub(crate) struct BaseDiskRow {
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

/// SQLite-backed VM state database.
///
/// Uses `Mutex<Connection>` to be safely `Send + Sync` without
/// requiring `unsafe impl`. The mutex is held briefly per operation.
#[derive(Debug)]
pub(crate) struct StateDb {
    /// Underlying `SQLite` connection, protected by a mutex.
    conn: std::sync::Mutex<Connection>,
}

#[allow(
    dead_code,
    reason = "base-disk refcount helpers used by DiskManager/tests"
)]
impl StateDb {
    /// Opens (or creates) the product-schema database at `path`.
    ///
    /// Empty / new files get schema version [`PRODUCT_SCHEMA_VERSION`].
    /// Existing files with any other `user_version` are **rejected**.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, schema init fails,
    /// or the on-disk schema version is unsupported.
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        ensure_product_schema(&conn)?;
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
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("StateDb mutex poisoned")
    }

    /// Inserts a new VM state record.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or the database insert fails.
    pub(crate) fn insert(&self, s: &VmState) -> Result<()> {
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
    pub(crate) fn update_status(&self, id: &str, status: Status) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET status = ?1 WHERE id = ?2",
            params![status_str(status), id],
        )?;
        Ok(())
    }

    /// Persist shim PID and status together (restart must not leave the old PID).
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub(crate) fn update_pid_status(&self, id: &str, pid: i32, status: Status) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET pid = ?1, status = ?2 WHERE id = ?3",
            params![pid, status_str(status), id],
        )?;
        Ok(())
    }

    /// Rewrites the serialized config JSON for a VM (e.g. after restart security status).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or the database update fails.
    pub(crate) fn update_config(&self, id: &str, config: &crate::state::VmConfig) -> Result<()> {
        let config_json = serde_json::to_string(config)?;
        self.lock().execute(
            "UPDATE vms SET config = ?1 WHERE id = ?2",
            params![config_json, id],
        )?;
        Ok(())
    }

    /// Finds a VM by exact name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub(crate) fn get_by_name(&self, name: &str) -> Result<Option<VmState>> {
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
    pub(crate) fn get_by_id_prefix(&self, prefix: &str) -> Result<VmState> {
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
    pub(crate) fn list(&self) -> Result<Vec<VmState>> {
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
    pub(crate) fn update_name(&self, id: &str, name: Option<&str>) -> Result<()> {
        self.lock()
            .execute("UPDATE vms SET name = ?1 WHERE id = ?2", params![name, id])?;
        Ok(())
    }

    /// Deletes a VM record by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database deletion fails.
    pub(crate) fn delete(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM vms WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Inserts a snapshot record.
    ///
    /// # Errors
    ///
    /// Returns an error if the database insert fails.
    pub(crate) fn insert_snapshot(&self, s: &SnapshotRow) -> Result<()> {
        self.lock().execute(
            "INSERT INTO snapshots (id, vm_id, name, disk_path, disk_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                s.id,
                s.vm_id,
                s.name,
                s.disk_path,
                i64::try_from(s.disk_bytes).unwrap_or(i64::MAX),
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
    pub(crate) fn list_snapshots(&self, vm_id: &str) -> Result<Vec<SnapshotRow>> {
        let conn = self.lock();
        Ok(conn
            .prepare(
                "SELECT id, vm_id, name, disk_path, disk_bytes, created_at
                 FROM snapshots WHERE vm_id = ?1 ORDER BY created_at DESC",
            )?
            .query_map(params![vm_id], row_to_snapshot)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Finds a snapshot by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no snapshot matches.
    pub(crate) fn get_snapshot(&self, snapshot_id: &str) -> Result<SnapshotRow> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, vm_id, name, disk_path, disk_bytes, created_at
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
    pub(crate) fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM snapshots WHERE id = ?1", params![snapshot_id])?;
        Ok(())
    }

    /// Inserts or returns an existing base disk by digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the database upsert fails.
    pub(crate) fn upsert_base_disk(&self, id: &str, digest: &str, path: &str) -> Result<()> {
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
    pub(crate) fn get_base_disk_by_digest(&self, digest: &str) -> Result<Option<BaseDiskRow>> {
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
    pub(crate) fn incr_base_disk_ref(&self, digest: &str) -> Result<()> {
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
    pub(crate) fn decr_base_disk_ref(&self, digest: &str) -> Result<()> {
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
    pub(crate) fn orphaned_base_disks(&self) -> Result<Vec<BaseDiskRow>> {
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
    pub(crate) fn delete_base_disk(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM base_disks WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ── volumes ──────────────────────────────────────────────────────────

    /// Insert a named volume row.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails (e.g. duplicate name).
    pub(crate) fn insert_volume(&self, v: &crate::volumes::VolumeInfo) -> Result<()> {
        self.lock().execute(
            "INSERT INTO volumes (id, name, path, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                v.id,
                v.name,
                v.path.to_string_lossy(),
                system_time_to_f64(v.created_at),
            ],
        )?;
        Ok(())
    }

    /// Look up a volume by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub(crate) fn get_volume_by_name(
        &self,
        name: &str,
    ) -> Result<Option<crate::volumes::VolumeInfo>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, name, path, created_at FROM volumes WHERE name = ?1",
            params![name],
            row_to_volume,
        )
        .optional()
        .map_err(Into::into)
    }

    /// List all named volumes.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "stmt borrows conn; collect before drop"
    )]
    pub(crate) fn list_volumes(&self) -> Result<Vec<crate::volumes::VolumeInfo>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id, name, path, created_at FROM volumes ORDER BY name")?;
        let out = stmt
            .query_map([], row_to_volume)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(out)
    }

    /// Delete a volume by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub(crate) fn delete_volume(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM volumes WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Count VMs attached to a volume.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub(crate) fn count_volume_attachments(&self, volume_id: &str) -> Result<i64> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM vm_volumes WHERE volume_id = ?1",
            params![volume_id],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// Record a VM↔volume attachment.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub(crate) fn insert_vm_volume(
        &self,
        vm_id: &str,
        volume_id: &str,
        guest_path: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO vm_volumes (vm_id, volume_id, guest_path)
             VALUES (?1, ?2, ?3)",
            params![vm_id, volume_id, guest_path],
        )?;
        Ok(())
    }

    /// Remove all volume attachments for a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub(crate) fn delete_vm_volumes(&self, vm_id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM vm_volumes WHERE vm_id = ?1", params![vm_id])?;
        Ok(())
    }
}

/// Map a `volumes` table row into [`crate::volumes::VolumeInfo`].
fn row_to_volume(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::volumes::VolumeInfo> {
    Ok(crate::volumes::VolumeInfo {
        id: row.get(0)?,
        name: row.get(1)?,
        path: PathBuf::from(row.get::<_, String>(2)?),
        created_at: f64_to_system_time(row.get(3)?),
    })
}

/// Ensure product schema: init empty DB, or refuse foreign versions.
fn ensure_product_schema(conn: &Connection) -> Result<()> {
    let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if version == 0 {
        // Distinguish brand-new DB vs legacy unversioned/migrated DB.
        let has_vms: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='vms'",
            [],
            |r| r.get(0),
        )?;
        if has_vms {
            return Err(Error::InvalidConfig(format!(
                "state database uses a legacy schema (user_version=0 with existing tables); \
                 delete the bux data directory and recreate (product schema v{PRODUCT_SCHEMA_VERSION})"
            )));
        }
        conn.execute_batch(PRODUCT_SCHEMA_SQL)?;
        conn.pragma_update(None, "user_version", PRODUCT_SCHEMA_VERSION)?;
        return Ok(());
    }

    if version != PRODUCT_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(format!(
            "state database schema version {version} is unsupported \
             (need {PRODUCT_SCHEMA_VERSION}); delete the bux data directory and recreate"
        )));
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
        vm_id: row.get(1)?,
        name: row.get(2)?,
        disk_path: row.get(3)?,
        disk_bytes: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        created_at: f64_to_system_time(row.get(5)?),
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
