//! Pre-exec hardening for child processes.
//!
//! Applied after `fork()` but before `exec()`:
//! 1. **Die with parent** — `PR_SET_PDEATHSIG(SIGKILL)` prevents orphaned VMs
//!    (Linux only; on macOS the watchdog pipe provides equivalent detection).
//! 2. **FD cleanup** — close all inherited file descriptors ≥ 3, except for
//!    an optionally preserved FD (used by the watchdog pipe).

use std::process::Command;

/// Install pre-exec hooks on the command.
///
/// `preserve_fd` — an FD that must survive into the exec'd process (e.g.
/// the watchdog pipe read end). Pass `None` to close everything.
///
/// On non-Unix platforms this is a no-op.
#[cfg(not(unix))]
pub fn apply(_cmd: &mut Command, _preserve_fd: Option<i32>) {}

/// Install pre-exec hooks on the command.
#[cfg(unix)]
pub fn apply(cmd: &mut Command, preserve_fd: Option<i32>) {
    use std::os::unix::process::CommandExt;

    // SAFETY: all operations inside are async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            // 1. Die when parent exits — prevents orphaned VM processes.
            //    (Belt-and-suspenders with the watchdog pipe on Linux.)
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);

            // 2. Close all inherited file descriptors >= 3, except preserve_fd.
            close_inherited_fds(preserve_fd);

            Ok(())
        });
    }
}

/// Close all file descriptors >= 3, optionally preserving one.
#[cfg(unix)]
fn close_inherited_fds(preserve: Option<i32>) {
    match preserve {
        Some(keep) => close_fds_preserving(keep),
        None => close_all_fds(),
    }
}

/// Close all FDs >= 3 unconditionally.
#[cfg(unix)]
fn close_all_fds() {
    // Try close_range(3, u32::MAX, 0) — available on Linux 5.9+.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range is an async-signal-safe syscall.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
        if ret == 0 {
            return;
        }
    }
    close_fd_range(3, max_fd());
}

/// Close all FDs >= 3 except `keep`.
///
/// On Linux 5.9+ uses two `close_range` calls to skip the preserved FD.
/// Falls back to an iterative loop otherwise.
#[cfg(unix)]
fn close_fds_preserving(keep: i32) {
    #[cfg(target_os = "linux")]
    {
        #[allow(clippy::cast_sign_loss)]
        let keep_u = keep as u32;
        // SAFETY: close_range is async-signal-safe.
        unsafe {
            // Close [3, keep-1] and [keep+1, MAX].
            if keep > 3 {
                libc::syscall(libc::SYS_close_range, 3_u32, keep_u - 1, 0_u32);
            }
            libc::syscall(libc::SYS_close_range, keep_u + 1, u32::MAX, 0_u32);
        }
        return;
    }

    #[allow(unreachable_code)]
    {
        let end = max_fd();
        for fd in 3..end {
            if fd != keep {
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// Upper bound on FD numbers from `sysconf(_SC_OPEN_MAX)`.
#[cfg(unix)]
fn max_fd() -> i32 {
    // SAFETY: sysconf is async-signal-safe.
    let n = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    #[allow(clippy::cast_possible_truncation)]
    if n > 0 { n as i32 } else { 1024 }
}

/// Close FDs in `[start, end)` via iterative `close()`.
#[cfg(unix)]
fn close_fd_range(start: i32, end: i32) {
    for fd in start..end {
        unsafe { libc::close(fd) };
    }
}
