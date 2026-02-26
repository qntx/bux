//! VM state types and SQLite persistence.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// VM lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Status {
    /// VM process is running.
    Running,
    /// VM has been stopped or exited.
    Stopped,
}

/// Serializable snapshot of a VM's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub vcpus: u8,
    /// RAM size in MiB.
    pub ram_mib: u32,
    /// Root filesystem path on the host.
    pub rootfs: Option<String>,
    /// Executable path inside the VM.
    pub exec_path: Option<String>,
    /// Arguments passed to the executable.
    pub exec_args: Vec<String>,
    /// Environment variables (`KEY=VALUE`).
    pub env: Option<Vec<String>>,
    /// Working directory inside the VM.
    pub workdir: Option<String>,
    /// TCP port mappings (`"host:guest"`).
    pub ports: Vec<String>,
}

/// Persisted state of a managed VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VmState {
    /// Short hex identifier.
    pub id: String,
    /// Optional human-friendly name (unique across the runtime).
    pub name: Option<String>,
    /// Host PID of the VM process.
    pub pid: u32,
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

    /// SQL schema for the `vms` table.
    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS vms (
            id         TEXT PRIMARY KEY NOT NULL,
            name       TEXT UNIQUE,
            pid        INTEGER NOT NULL,
            image      TEXT,
            socket     TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'running',
            config     TEXT NOT NULL,
            created_at REAL NOT NULL
        );
    ";

    /// SQLite-backed VM state database.
    #[derive(Debug)]
    pub struct StateDb {
        /// Underlying SQLite connection.
        conn: Connection,
    }

    impl StateDb {
        /// Opens (or creates) the database at `path`.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            let conn = Connection::open(path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
            conn.execute_batch(SCHEMA)?;
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
                // SAFETY: len() == 1 guarantees next() returns Some.
                #[allow(clippy::expect_used)]
                1 => Ok(matches.into_iter().next().expect("len==1 guarantees Some")),
                n => Err(Error::Ambiguous(format!(
                    "prefix '{prefix}' matches {n} VMs"
                ))),
            }
        }

        /// Lists all VMs.
        pub fn list(&self) -> Result<Vec<VmState>> {
            let mut stmt = self
                .conn
                .prepare("SELECT * FROM vms ORDER BY created_at DESC")?;
            let rows = stmt.query_map([], row_to_state)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        }

        /// Deletes a VM record by ID.
        pub fn delete(&self, id: &str) -> Result<()> {
            self.conn
                .execute("DELETE FROM vms WHERE id = ?1", params![id])?;
            Ok(())
        }
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
            Status::Running => "running",
            Status::Stopped => "stopped",
        }
    }

    /// Parses a database string into a [`Status`].
    fn parse_status(s: &str) -> Status {
        match s {
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
