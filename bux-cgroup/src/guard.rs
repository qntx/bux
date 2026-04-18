//! RAII guard for a created cgroup directory.

use std::fs;
use std::path::{Path, PathBuf};

/// RAII guard that removes the cgroup directory on drop.
///
/// Removal is best-effort: if processes remain in the cgroup when the
/// guard is dropped, the directory will stay behind and must be cleaned
/// up manually. The kernel refuses `rmdir` on non-empty cgroups.
#[derive(Debug)]
pub struct CgroupGuard {
    /// Absolute path to the cgroup directory, e.g. `/sys/fs/cgroup/bux/vm-abc`.
    path: PathBuf,
}

impl CgroupGuard {
    /// Creates a new guard for an already-existing cgroup directory.
    ///
    /// This is an internal constructor — public API goes through
    /// [`crate::create`].
    pub(crate) const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the cgroup directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        drop(fs::remove_dir(&self.path));
    }
}
