//! Process isolation for the `bux-shim` child process.
//!
//! Wraps the shim binary in a platform-specific sandbox:
//! - **Linux**: [bubblewrap] namespace isolation (via [`bux-bwrap`]).
//! - **macOS**: [seatbelt] `sandbox-exec` with a deny-default SBPL profile.
//! - **Fallback**: bare `Command` with pre-exec hardening only.
//!
//! [bubblewrap]: https://github.com/containers/bubblewrap
//! [seatbelt]: https://developer.apple.com/documentation/sandbox

#![allow(unsafe_code)]

mod pre_exec;

#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(target_os = "macos")]
mod seatbelt;

use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Sandbox configuration for a single VM spawn.
#[derive(Debug)]
pub struct JailConfig {
    /// Path to the rootfs directory (if using directory-based root).
    pub rootfs: Option<PathBuf>,
    /// Path to the root disk image (if using disk-based root).
    pub root_disk: Option<PathBuf>,
    /// Directory containing Unix sockets for vsock.
    pub socks_dir: PathBuf,
    /// Host paths for virtiofs mounts.
    pub virtiofs_paths: Vec<PathBuf>,
    /// Watchdog pipe read-end FD to preserve across exec.
    pub watchdog_fd: Option<RawFd>,
}

/// Spawn `bux-shim` inside a sandbox.
///
/// Applies platform-specific isolation, then falls back to a bare process
/// with pre-exec hardening (FD cleanup, die-with-parent) if no sandbox
/// is available.
pub fn spawn(shim: &Path, config_path: &Path, config: &JailConfig) -> io::Result<Child> {
    let mut cmd = build_command(shim, config_path, config);
    cmd.stdin(Stdio::null());

    // Pass watchdog FD number to the shim via environment variable.
    if let Some(fd) = config.watchdog_fd {
        cmd.env(crate::watchdog::ENV_WATCHDOG_FD, fd.to_string());
    }

    pre_exec::apply(&mut cmd, config.watchdog_fd);
    cmd.spawn()
}

/// Build the sandboxed `Command`, or fall back to a bare command.
fn build_command(shim: &Path, config_path: &Path, config: &JailConfig) -> Command {
    #[cfg(target_os = "linux")]
    if let Some(cmd) = bwrap::wrap(shim, config_path, config) {
        return cmd;
    }

    #[cfg(target_os = "macos")]
    if let Some(cmd) = seatbelt::wrap(shim, config_path, config) {
        return cmd;
    }

    // Fallback: no sandbox, just run the shim directly.
    let mut cmd = Command::new(shim);
    cmd.arg(config_path);
    cmd
}
