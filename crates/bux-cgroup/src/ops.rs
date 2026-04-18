//! cgroup v2 operations: create, add PID, write control files.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::guard::CgroupGuard;
use crate::limits::ResourceLimits;

/// Base path for the unified cgroup v2 hierarchy on every supported distro.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Parent cgroup directory created under the root hierarchy.
const PARENT_GROUP: &str = "bux";

/// CPU bandwidth accounting period, in microseconds (100 ms — kernel default).
const CPU_PERIOD_US: u64 = 100_000;

/// Create a per-VM cgroup under `/sys/fs/cgroup/bux/{name}` and apply limits.
///
/// The parent cgroup `/sys/fs/cgroup/bux` is created on demand, and the
/// `cpu` / `memory` controllers are enabled there (best-effort). Returns
/// a [`CgroupGuard`] that removes the cgroup on drop.
///
/// # Errors
///
/// - [`Error::CreateDir`] if the cgroup directory cannot be created.
/// - [`Error::WriteFile`] if any control file write fails.
pub fn create(name: &str, limits: &ResourceLimits) -> Result<CgroupGuard> {
    let parent = Path::new(CGROUP_ROOT).join(PARENT_GROUP);
    let cgroup_dir = parent.join(name);

    fs::create_dir_all(&cgroup_dir).map_err(|source| Error::CreateDir {
        path: cgroup_dir.clone(),
        source,
    })?;

    enable_controllers(&parent);

    if let Some(cores) = limits.cpu_cores {
        write_control(&cgroup_dir, "cpu.max", &format_cpu_max(cores))?;
    }

    if let Some(mem) = limits.memory_bytes {
        write_control(&cgroup_dir, "memory.max", &mem.to_string())?;
    }

    if let Some(swap) = limits.memory_swap_bytes {
        write_control(&cgroup_dir, "memory.swap.max", &swap.to_string())?;
    }

    Ok(CgroupGuard::new(cgroup_dir))
}

/// Add a process (by PID) to the cgroup.
///
/// Writes the PID to `cgroup.procs`. The kernel atomically moves the
/// target process into the cgroup.
///
/// # Errors
///
/// Returns [`Error::WriteFile`] if the PID cannot be added (e.g. the
/// process has already exited).
pub fn add_pid(guard: &CgroupGuard, pid: i32) -> Result<()> {
    write_control(guard.path(), "cgroup.procs", &pid.to_string())
}

/// Format a CPU quota as `"{quota_us} {period_us}"` for `cpu.max`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "cores*period fits in u64 for any sane core count; negative values become 0 quota"
)]
fn format_cpu_max(cores: f64) -> String {
    let quota = (cores * CPU_PERIOD_US as f64) as u64;
    format!("{quota} {CPU_PERIOD_US}")
}

/// Enable `cpu` and `memory` controllers in the parent cgroup.
///
/// This is best-effort because the write fails if the controllers are
/// already enabled or if the caller lacks `CAP_SYS_ADMIN`. Failure is
/// non-fatal — the actual limit writes will fail later with a clear
/// error if the controllers truly are not available.
fn enable_controllers(parent: &Path) {
    let subtree_control = parent.join("cgroup.subtree_control");
    if subtree_control.exists() {
        drop(fs::write(&subtree_control, "+cpu +memory"));
    }
}

/// Write `value` to `{cgroup_dir}/{filename}`, wrapping any I/O error
/// with the full file path for diagnostics.
fn write_control(cgroup_dir: &Path, filename: &str, value: &str) -> Result<()> {
    let path: PathBuf = cgroup_dir.join(filename);
    fs::write(&path, value).map_err(|source| Error::WriteFile {
        path: path.clone(),
        source,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn format_cpu_max_one_core() {
        assert_eq!(format_cpu_max(1.0), "100000 100000");
    }

    #[test]
    fn format_cpu_max_two_cores() {
        assert_eq!(format_cpu_max(2.0), "200000 100000");
    }

    #[test]
    fn format_cpu_max_half_core() {
        assert_eq!(format_cpu_max(0.5), "50000 100000");
    }

    #[test]
    fn format_cpu_max_fractional() {
        assert_eq!(format_cpu_max(1.5), "150000 100000");
    }

    #[test]
    fn format_cpu_max_clamps_negative() {
        // Negative cores produce quota 0 (wrap via `as u64`) — kernel
        // rejects this at write time; we don't defend against it here.
        let s = format_cpu_max(-1.0);
        assert!(s.ends_with(" 100000"));
    }
}
