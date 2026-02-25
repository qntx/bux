//! VM state types and JSON persistence.

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs, io};

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

impl VmState {
    /// Loads state from a JSON file.
    pub fn load(path: &Path) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Persists state to a JSON file.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let file = fs::File::create(path)?;
        serde_json::to_writer_pretty(file, self).map_err(io::Error::other)
    }
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
