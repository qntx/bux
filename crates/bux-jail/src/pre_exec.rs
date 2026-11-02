//! Pre-exec hardening for child processes.
//!
//! Applied after `fork()` but before `exec()`:
//! 1. **Die with parent** — `PR_SET_PDEATHSIG(SIGKILL)` (Linux), when requested.
//! 2. **FD cleanup** — inherited FDs ≥ 3 become close-on-exec, except preserved ones.
//!
//! Marking instead of closing keeps open the close-on-exec pipe through which
//! std's `Command::spawn` reports an `exec` failure.

#![allow(
    unsafe_code,
    clippy::multiple_unsafe_ops_per_block,
    reason = "pre_exec runs between fork and exec where allocation / external calls are prohibited; clippy's 'one unsafe op per block' rule fights async-signal-safety here"
)]

use std::process::Command;

/// FDs that must survive `exec` into the child.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PreserveFds {
    /// Watchdog pipe read end (optional).
    pub watchdog: Option<i32>,
    /// Landlock ruleset the shim applies to itself (optional).
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
            // 1. Die when parent exits — omitted for detached VMs.
            #[cfg(target_os = "linux")]
            if die_with_parent {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = die_with_parent;

            // 2. Nothing but the preserved FDs survives `exec`.
            mark_inherited_fds_cloexec();
            for fd in [preserve.watchdog, preserve.landlock].into_iter().flatten() {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }
}

/// Mark all FDs >= 3 close-on-exec.
#[cfg(unix)]
fn mark_inherited_fds_cloexec() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range takes only integers; the flag needs Linux 5.11+.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if ret == 0 {
            return;
        }
    }
    for fd in 3..max_fd() {
        // SAFETY: fcntl on a number that is not an open FD only returns EBADF.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
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
