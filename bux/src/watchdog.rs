//! Watchdog pipe for parent↔shim liveness detection.
//!
//! When the parent process dies (or drops its [`Keepalive`] handle), the
//! write end of the pipe closes. The shim detects this via `POLLHUP` on
//! the read end and initiates a graceful shutdown.
//!
//! This mechanism works on **all** Unix platforms, unlike
//! `PR_SET_PDEATHSIG` which is Linux-only.

#![allow(unsafe_code)]

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Parent-side handle that keeps the watchdog pipe alive.
///
/// When this value is dropped, the write end of the pipe closes,
/// causing `POLLHUP` on the shim's read end — signaling it to shut down.
#[derive(Debug)]
pub struct Keepalive(OwnedFd);

/// Creates a watchdog pipe pair.
///
/// Returns `(shim_fd, keepalive)`:
/// - `shim_fd`: read end — passed to the shim process. Created **without**
///   `O_CLOEXEC` so it survives `exec`.
/// - `keepalive`: write end — held by the parent. Has `O_CLOEXEC` set so
///   it does not leak into the child.
pub fn create() -> io::Result<(OwnedFd, Keepalive)> {
    let mut fds: [RawFd; 2] = [0; 2];

    // SAFETY: pipe() is a standard POSIX call; fds is a valid 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: both FDs are valid after a successful pipe() call.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // Set CLOEXEC on the write end (parent keeps it; must not leak to child).
    set_cloexec(&write_fd)?;
    // read end intentionally lacks CLOEXEC — it must survive exec into shim.

    Ok((read_fd, Keepalive(write_fd)))
}

/// Name of the environment variable used to pass the watchdog FD to the shim.
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

/// Sets `FD_CLOEXEC` on a file descriptor.
fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl(F_SETFD) is async-signal-safe and the FD is valid.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Blocks the calling thread until `POLLHUP` is detected on the given FD.
///
/// This is intended for use inside the shim process. When the parent dies,
/// the write end of the watchdog pipe closes, producing `POLLHUP`.
///
/// # Safety
///
/// `fd` must be a valid, open file descriptor (the watchdog read end).
pub unsafe fn wait_for_parent_death(fd: RawFd) {
    let mut pfd = libc::pollfd {
        fd,
        events: 0, // only interested in POLLHUP (always delivered)
        revents: 0,
    };
    loop {
        // SAFETY: pfd is a valid pollfd struct; blocking indefinitely is intentional.
        let ret = unsafe { libc::poll(&raw mut pfd, 1, -1) };
        if ret > 0 && (pfd.revents & libc::POLLHUP) != 0 {
            return;
        }
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return; // fatal poll error — treat as parent death
            }
            // EINTR — retry
        }
    }
}
