//! Watchdog pipe for parent↔shim liveness detection.
//!
//! When the parent process dies (or drops its [`Keepalive`] handle), the
//! write end of the pipe closes. The shim detects this via `POLLHUP` on
//! the read end and initiates a graceful shutdown.
//!
//! This mechanism works on **all** Unix platforms, unlike
//! `PR_SET_PDEATHSIG` which is Linux-only.

use std::io;
use std::os::fd::{AsFd, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::unistd::pipe;

/// Parent-side handle that keeps the watchdog pipe alive.
///
/// When this value is dropped, the write end of the pipe closes,
/// causing `POLLHUP` on the shim's read end — signaling it to shut down.
#[derive(Debug)]
pub(crate) struct Keepalive(#[allow(dead_code, reason = "dropped to trigger pipe close")] OwnedFd);

/// Creates a watchdog pipe pair.
///
/// Returns `(shim_fd, keepalive)`:
/// - `shim_fd`: read end — passed to the shim process. Created **without**
///   `O_CLOEXEC` so it survives `exec`.
/// - `keepalive`: write end — held by the parent. Has `O_CLOEXEC` set so
///   it does not leak into the child.
///
/// # Errors
///
/// Returns an error if `pipe()` or `fcntl()` fails.
pub(crate) fn create() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;

    // Set CLOEXEC on the write end (parent keeps it; must not leak to child).
    fcntl(write_fd.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    // read end intentionally lacks CLOEXEC — it must survive exec into shim.

    Ok((read_fd, Keepalive(write_fd)))
}
