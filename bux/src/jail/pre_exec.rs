//! Pre-exec hardening for child processes.
//!
//! Applied after `fork()` but before `exec()`:
//! 1. **Die with parent** — `PR_SET_PDEATHSIG(SIGKILL)` prevents orphaned VMs.
//! 2. **FD cleanup** — close all inherited file descriptors ≥ 3.

use std::process::Command;

/// Install pre-exec hooks on the command.
///
/// On non-Unix platforms this is a no-op.
#[cfg(not(unix))]
pub fn apply(_cmd: &mut Command) {}

/// Install pre-exec hooks on the command.
#[cfg(unix)]
pub fn apply(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: all operations inside are async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(|| {
            // 1. Die when parent exits — prevents orphaned VM processes.
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);

            // 2. Close all inherited file descriptors >= 3.
            close_inherited_fds();

            Ok(())
        });
    }
}

/// Close all file descriptors >= 3.
///
/// FDs 0 (stdin), 1 (stdout), 2 (stderr) are preserved.
#[cfg(unix)]
fn close_inherited_fds() {
    // Try close_range(3, u32::MAX, 0) — available on Linux 5.9+.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range is an async-signal-safe syscall.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
        if ret == 0 {
            return;
        }
    }

    // Fallback: close up to sysconf(_SC_OPEN_MAX).
    // SAFETY: sysconf and close are async-signal-safe.
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let limit = if max_fd > 0 { max_fd } else { 1024 };
    #[allow(clippy::cast_possible_truncation)]
    let end = limit as i32; // _SC_OPEN_MAX fits in i32 on all real systems.
    for fd in 3..end {
        unsafe { libc::close(fd) };
    }
}
