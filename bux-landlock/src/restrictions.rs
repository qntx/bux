//! Fluent builder for a Landlock path/network restriction ruleset.
//!
//! The builder is platform-agnostic — it compiles on any OS, so callers
//! can thread configuration through without `cfg` gates. The companion
//! `PathRestrictions::build` method (Linux-only) consumes the builder
//! and returns `Ok(None)` when the kernel lacks Landlock support, which
//! callers treat as a benign skip.

use std::path::{Path, PathBuf};

/// Fluent builder for Landlock filesystem (and optional network)
/// restrictions.
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # fn main() -> Result<(), bux_landlock::Error> {
/// let ruleset = bux_landlock::PathRestrictions::new()
///     .allow_read("/usr")
///     .allow_read("/etc")
///     .allow_read_write("/tmp")
///     .deny_network()
///     .build()?;
///
/// if let Some(fd) = ruleset {
///     // Pass `fd` to a forked child and call `restrict_self(fd)` there.
///     drop(fd);
/// }
/// # Ok(()) }
/// # #[cfg(not(target_os = "linux"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "PathRestrictions does nothing until you call `.build()`"]
pub struct PathRestrictions {
    /// Paths granted read-only access (recursive under the given path).
    read_paths: Vec<PathBuf>,
    /// Paths granted read-write access (recursive under the given path).
    read_write_paths: Vec<PathBuf>,
    /// Whether to deny all TCP bind/connect (Landlock ABI v4+).
    deny_network: bool,
}

impl PathRestrictions {
    /// Create an empty restrictions set.
    pub const fn new() -> Self {
        Self {
            read_paths: Vec::new(),
            read_write_paths: Vec::new(),
            deny_network: false,
        }
    }

    /// Grant recursive **read-only** access to `path` and everything
    /// beneath it (inode-based; follows mount points).
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.read_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Grant recursive **read-write** access to `path` and everything
    /// beneath it.
    pub fn allow_read_write(mut self, path: impl AsRef<Path>) -> Self {
        self.read_write_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Add several read-only paths at once.
    pub fn allow_read_many<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for p in paths {
            self.read_paths.push(p.as_ref().to_path_buf());
        }
        self
    }

    /// Add several read-write paths at once.
    pub fn allow_read_write_many<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for p in paths {
            self.read_write_paths.push(p.as_ref().to_path_buf());
        }
        self
    }

    /// Deny all TCP bind/connect (Landlock ABI v4+; silently no-op on
    /// older kernels).
    pub const fn deny_network(mut self) -> Self {
        self.deny_network = true;
        self
    }

    /// Read-only paths registered so far.
    #[must_use]
    pub fn read_paths(&self) -> &[PathBuf] {
        &self.read_paths
    }

    /// Read-write paths registered so far.
    #[must_use]
    pub fn read_write_paths(&self) -> &[PathBuf] {
        &self.read_write_paths
    }

    /// Whether network will be denied by the resulting ruleset.
    #[must_use]
    pub const fn network_denied(&self) -> bool {
        self.deny_network
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to panic on indexing and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let r = PathRestrictions::new();
        assert!(r.read_paths().is_empty());
        assert!(r.read_write_paths().is_empty());
        assert!(!r.network_denied());
    }

    #[test]
    fn allow_read_appends() {
        let r = PathRestrictions::new()
            .allow_read("/usr")
            .allow_read("/etc");
        assert_eq!(r.read_paths().len(), 2);
        assert_eq!(r.read_paths()[0], Path::new("/usr"));
        assert_eq!(r.read_paths()[1], Path::new("/etc"));
    }

    #[test]
    fn allow_read_write_appends() {
        let r = PathRestrictions::new().allow_read_write("/tmp");
        assert_eq!(r.read_write_paths().len(), 1);
        assert_eq!(r.read_write_paths()[0], Path::new("/tmp"));
    }

    #[test]
    fn allow_many_preserves_order() {
        let r = PathRestrictions::new().allow_read_many(["/a", "/b", "/c"]);
        assert_eq!(
            r.read_paths()
                .iter()
                .map(|p| p.as_os_str())
                .collect::<Vec<_>>(),
            vec!["/a", "/b", "/c"],
        );
    }

    #[test]
    fn deny_network_toggles_flag() {
        let r = PathRestrictions::new().deny_network();
        assert!(r.network_denied());
    }

    #[test]
    fn builder_is_fluent() {
        let r = PathRestrictions::new()
            .allow_read("/usr")
            .allow_read_write("/tmp")
            .deny_network();
        assert_eq!(r.read_paths().len(), 1);
        assert_eq!(r.read_write_paths().len(), 1);
        assert!(r.network_denied());
    }
}
