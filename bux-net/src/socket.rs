//! Unix socket path shortening via symlinks.
//!
//! Unix domain sockets have a `sun_path` limit of 104 bytes (macOS) or
//! 108 bytes (Linux).  When `$BUX_HOME` is deeply nested, socket paths
//! like `~/.local/share/bux/socks/{vm_id}.sock` can exceed this limit.
//!
//! **Solution**: create a short symlink `/tmp/bx_{short_id}` → real
//! sockets directory.  The kernel resolves symlinks during VFS path
//! lookup *after* the `sun_path` length check, so the short path
//! satisfies the buffer constraint while the socket physically lives
//! at the real (long) path.
//!
//! This is the same pattern used by Open vSwitch
//! (`shorten_name_via_symlink()` in `lib/socket-util-unix.c`).

use std::path::{Path, PathBuf};

use crate::error::{NetError, Result};

/// Maximum allowed `sun_path` length.
///
/// macOS = 104, Linux = 108.  We use the smaller value for
/// cross-platform safety.
const MAX_SUN_PATH: usize = 104;

/// Prefix for shortener symlinks in the temp directory.
const SYMLINK_PREFIX: &str = "bx_";

/// Manages a short symlink in `/tmp` that aliases a sockets directory.
///
/// When the real socket path exceeds [`MAX_SUN_PATH`], this creates:
///
/// ```text
/// /tmp/bx_{short_id}  →  {data_dir}/socks/
/// ```
///
/// Use [`short_path()`](Self::short_path) to obtain a short path for
/// `bind()` / `connect()`.  The symlink is removed on [`Drop`].
///
/// Returns `None` from [`new()`](Self::new) if paths already fit —
/// no symlink is created.
#[derive(Debug)]
pub struct SocketShortener {
    /// The short symlink path: `/tmp/bx_{short_id}`.
    symlink_path: PathBuf,
    /// The real sockets directory this symlink points to.
    #[allow(dead_code)]
    real_dir: PathBuf,
}

impl SocketShortener {
    /// Creates a shortener if the socket paths exceed the `sun_path` limit.
    ///
    /// Returns `Ok(None)` if all paths already fit.
    pub fn new(short_id: &str, sockets_dir: &Path) -> Result<Option<Self>> {
        // Use a representative long socket name for the length check.
        let longest_real = sockets_dir.join("net.sock");
        if longest_real.as_os_str().len() < MAX_SUN_PATH {
            return Ok(None);
        }

        let symlink_path = std::env::temp_dir().join(format!("{SYMLINK_PREFIX}{short_id}"));

        // Verify the shortened path actually fits.
        let longest_short = symlink_path.join("net.sock");
        if longest_short.as_os_str().len() >= MAX_SUN_PATH {
            return Err(NetError::SocketPath(format!(
                "'{}' ({} bytes) exceeds sun_path limit ({} bytes) even with symlink shortening; \
                 use a shorter temp directory",
                longest_short.display(),
                longest_short.as_os_str().len(),
                MAX_SUN_PATH,
            )));
        }

        // Handle stale symlinks from a previous run.
        match std::fs::symlink_metadata(&symlink_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let _ = std::fs::remove_file(&symlink_path);
            }
            Ok(_) => {
                return Err(NetError::SocketPath(format!(
                    "'{}' already exists and is not a symlink",
                    symlink_path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(NetError::Io(e)),
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(sockets_dir, &symlink_path)?;

        tracing::debug!(
            symlink = %symlink_path.display(),
            target = %sockets_dir.display(),
            "created socket shortener symlink"
        );

        Ok(Some(Self {
            symlink_path,
            real_dir: sockets_dir.to_path_buf(),
        }))
    }

    /// Returns a short path for a socket file name.
    ///
    /// E.g. `short_path("net.sock")` → `/tmp/bx_abc123/net.sock`.
    #[must_use]
    pub fn short_path(&self, socket_name: &str) -> PathBuf {
        self.symlink_path.join(socket_name)
    }
}

impl Drop for SocketShortener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.symlink_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_not_needed() {
        let dir = std::env::temp_dir().join("bux_test_short");
        let _ = std::fs::create_dir_all(&dir);
        let result = SocketShortener::new("test1", &dir).unwrap();
        assert!(result.is_none(), "short paths should not need a shortener");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
