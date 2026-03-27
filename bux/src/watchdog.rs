//! Watchdog pipe for parent↔shim liveness detection.
//!
//! When the parent process dies (or drops its [`Keepalive`] handle), the
//! write end of the pipe closes. The shim detects this via `POLLHUP` on
//! the read end and initiates a graceful shutdown.
//!
//! This mechanism works on **all** Unix platforms, unlike
//! `PR_SET_PDEATHSIG` which is Linux-only.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::unistd::pipe;

/// Parent-side handle that keeps the watchdog pipe alive.
///
/// When this value is dropped, the write end of the pipe closes,
/// causing `POLLHUP` on the shim's read end — signaling it to shut down.
#[derive(Debug)]
pub struct Keepalive(#[allow(dead_code)] OwnedFd);

/// Creates a watchdog pipe pair.
///
/// Returns `(shim_fd, keepalive)`:
/// - `shim_fd`: read end — passed to the shim process. Created **without**
///   `O_CLOEXEC` so it survives `exec`.
/// - `keepalive`: write end — held by the parent. Has `O_CLOEXEC` set so
///   it does not leak into the child.
pub fn create() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;

    // Set CLOEXEC on the write end (parent keeps it; must not leak to child).
    fcntl(write_fd.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    // read end intentionally lacks CLOEXEC — it must survive exec into shim.

    Ok((read_fd, Keepalive(write_fd)))
}

/// Name of the environment variable used to pass the watchdog FD to the shim.
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

/// Blocks the calling thread until `POLLHUP` is detected on the given FD.
///
/// This is intended for use inside the shim process. When the parent dies,
/// the write end of the watchdog pipe closes, producing `POLLHUP`.
pub fn wait_for_parent_death(fd: BorrowedFd<'_>) {
    let mut pfd = [PollFd::new(fd, PollFlags::empty())];
    loop {
        match poll(&mut pfd, PollTimeout::NONE) {
            Ok(n) if n > 0 => {
                if let Some(revents) = pfd[0].revents()
                    && revents.contains(PollFlags::POLLHUP)
                {
                    return;
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => return, // fatal poll error — treat as parent death
            _ => {}
        }
    }
}
