//! cgroup v2 resource limits for VM processes (Linux only).
//!
//! Creates a per-VM cgroup under the user's cgroup subtree and writes
//! CPU/memory limits before spawning the shim. The cgroup is cleaned up
//! when the [`CgroupGuard`] is dropped.
//!
//! Requires cgroup v2 (unified hierarchy) mounted at `/sys/fs/cgroup`.

use std::path::{Path, PathBuf};
use std::{fs, io};

/// Base path for the unified cgroup v2 hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Resource limits applied to a VM's cgroup.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Maximum CPU bandwidth as a fraction (e.g. 2.0 = 2 cores).
    /// Implemented via `cpu.max` as `quota period`.
    pub cpu_cores: Option<f64>,
    /// Memory limit in bytes. Written to `memory.max`.
    pub memory_bytes: Option<u64>,
    /// Memory+swap limit in bytes. Written to `memory.swap.max`.
    /// Set equal to `memory_bytes` to disable swap.
    pub memory_swap_bytes: Option<u64>,
}

/// RAII guard that removes the cgroup directory on drop.
#[derive(Debug)]
pub struct CgroupGuard {
    /// Full path to the cgroup directory (e.g. `/sys/fs/cgroup/bux/vm-abc123`).
    path: PathBuf,
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Best-effort removal — the cgroup must be empty (no processes).
        let _ = fs::remove_dir(&self.path);
    }
}

/// Creates a per-VM cgroup with the given resource limits.
///
/// Returns a [`CgroupGuard`] that removes the cgroup on drop, and the
/// cgroup path for adding the shim PID via `cgroup.procs`.
///
/// The cgroup is created at `/sys/fs/cgroup/bux/{vm_id}`.
pub fn create(vm_id: &str, limits: &ResourceLimits) -> io::Result<CgroupGuard> {
    let cgroup_dir = Path::new(CGROUP_ROOT).join("bux").join(vm_id);
    fs::create_dir_all(&cgroup_dir)?;

    // Enable controllers in the parent if needed.
    let parent = Path::new(CGROUP_ROOT).join("bux");
    enable_controllers(&parent)?;

    // Apply CPU limit via cpu.max: "$QUOTA $PERIOD"
    if let Some(cores) = limits.cpu_cores {
        let period: u64 = 100_000; // 100ms in microseconds
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let quota = (cores * period as f64) as u64;
        let value = format!("{quota} {period}");
        write_cgroup_file(&cgroup_dir, "cpu.max", &value)?;
    }

    // Apply memory limit.
    if let Some(mem) = limits.memory_bytes {
        write_cgroup_file(&cgroup_dir, "memory.max", &mem.to_string())?;
    }

    // Apply memory+swap limit.
    if let Some(swap) = limits.memory_swap_bytes {
        write_cgroup_file(&cgroup_dir, "memory.swap.max", &swap.to_string())?;
    }

    Ok(CgroupGuard { path: cgroup_dir })
}

/// Adds a process to the cgroup.
pub fn add_pid(guard: &CgroupGuard, pid: i32) -> io::Result<()> {
    write_cgroup_file(&guard.path, "cgroup.procs", &pid.to_string())
}

/// Returns the cgroup directory path.
pub fn path(guard: &CgroupGuard) -> &Path {
    &guard.path
}

/// Enable cpu and memory controllers in the parent cgroup.
fn enable_controllers(parent: &Path) -> io::Result<()> {
    let subtree_control = parent.join("cgroup.subtree_control");
    if subtree_control.exists() {
        // Best-effort — may fail if controllers are already enabled or
        // if the user lacks permission.
        let _ = fs::write(&subtree_control, "+cpu +memory");
    }
    Ok(())
}

/// Write a value to a cgroup control file.
fn write_cgroup_file(cgroup_dir: &Path, filename: &str, value: &str) -> io::Result<()> {
    let path = cgroup_dir.join(filename);
    fs::write(&path, value)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to write {}: {e}", path.display())))
}
