//! Pre-exec hardening for child processes.
//!
//! Applied after `fork()` but before `exec()`:
//! 1. **Landlock** (Linux, optional) — apply ruleset then close its fd.
//! 2. **Die with parent** — `PR_SET_PDEATHSIG(SIGKILL)` (Linux), when requested.
//! 3. **FD cleanup** — close inherited FDs ≥ 3 except preserved ones.

#![allow(
    unsafe_code,
    clippy::multiple_unsafe_ops_per_block,
    reason = "pre_exec runs between fork and exec where allocation / external calls are prohibited; clippy's 'one unsafe op per block' rule fights async-signal-safety here"
)]

use std::process::Command;

/// FDs that must survive into the child until we explicitly handle them.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PreserveFds {
    /// Watchdog pipe read end (optional).
    pub watchdog: Option<i32>,
    /// Landlock ruleset fd — applied then closed inside `pre_exec` (optional).
    pub landlock: Option<i32>,
}

/// Install pre-exec hooks on the command.
#[cfg(not(unix))]
pub fn apply(_cmd: &mut Command, _preserve: PreserveFds, _die_with_parent: bool) {}

/// Install pre-exec hooks on the command.
#[cfg(unix)]
pub(crate) fn apply(cmd: &mut Command, preserve: PreserveFds, die_with_parent: bool) {
    use std::os::unix::process::CommandExt;

    // SAFETY: all operations inside are async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            // 1. Landlock first (closes its own fd). Linux only.
            #[cfg(target_os = "linux")]
            if let Some(fd) = preserve.landlock {
                // SAFETY: fd is a ruleset from PathRestrictions::build.
                let errno = bux_landlock::restrict_self(fd);
                if errno != 0 {
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = preserve.landlock;

            // 2. Die when parent exits — omitted for detached VMs.
            #[cfg(target_os = "linux")]
            if die_with_parent {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = die_with_parent;

            // 3. Close inherited FDs except watchdog (landlock already closed).
            close_inherited_fds(preserve.watchdog);

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
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range is a valid syscall on Linux 5.9+; arguments are well-formed.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
        if ret == 0 {
            return;
        }
    }
    close_fd_range(3, max_fd());
}

/// Close all FDs >= 3 except `keep`.
#[cfg(unix)]
fn close_fds_preserving(keep: i32) {
    #[cfg(target_os = "linux")]
    {
        #[allow(clippy::cast_sign_loss, reason = "keep FD is always non-negative")]
        let keep_u = keep as u32;
        // SAFETY: close_range is a valid syscall; arguments specify FD ranges that
        // exclude the preserved FD.
        unsafe {
            if keep > 3 {
                libc::syscall(libc::SYS_close_range, 3_u32, keep_u - 1, 0_u32);
            }
            libc::syscall(libc::SYS_close_range, keep_u + 1, u32::MAX, 0_u32);
        }
        return;
    }

    #[allow(
        unreachable_code,
        reason = "fallback path after platform-specific early return"
    )]
    {
        let end = max_fd();
        for fd in 3..end {
            if fd != keep {
                // SAFETY: fd is a valid file descriptor number in range.
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// Upper bound on FD numbers from `sysconf(_SC_OPEN_MAX)`.
#[cfg(unix)]
fn max_fd() -> i32 {
    // SAFETY: sysconf with _SC_OPEN_MAX is always safe and returns a valid long.
    let n = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    #[allow(
        clippy::cast_possible_truncation,
        reason = "sysconf result fits in i32"
    )]
    if n > 0 { n as i32 } else { 1024 }
}

/// Close FDs in `[start, end)` via iterative `close()`.
#[cfg(unix)]
fn close_fd_range(start: i32, end: i32) {
    for fd in start..end {
        // SAFETY: fd is a valid file descriptor number in [start, end).
        unsafe { libc::close(fd) };
    }
}
