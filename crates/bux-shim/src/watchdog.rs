//! Shim-side watchdog: exit when the parent Runtime dies.
//!
//! Env: `BUX_WATCHDOG_FD` = decimal read-end FD of a pipe whose write end
//! is held by the parent (`bux_jail::ENV_WATCHDOG_FD` contract).

#![allow(
    clippy::print_stderr,
    clippy::exit,
    clippy::disallowed_methods,
    reason = "shim process: stderr + process::exit on parent death"
)]

use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};

/// Environment variable name (must match `bux_jail::ENV_WATCHDOG_FD`).
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

/// Block until parent death: the write end of the watchdog pipe closes.
///
/// Polls for `POLLIN` as well: macOS never wakes a poll with an empty event
/// mask for a pipe whose writer closed (Linux always reports `POLLHUP`), and
/// reports the close as `POLLIN | POLLHUP`. The parent never writes, so a
/// readable EOF also means it is gone.
#[cfg(unix)]
pub fn wait_for_parent_death(fd: BorrowedFd<'_>) {
    use nix::errno::Errno;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    let mut pfd = [PollFd::new(fd, PollFlags::POLLIN)];
    let mut buf = [0_u8; 64];
    loop {
        match poll(&mut pfd, PollTimeout::NONE) {
            Ok(n) if n > 0 => {
                if pfd[0]
                    .revents()
                    .is_some_and(|revents| parent_gone(fd, revents, &mut buf))
                {
                    return;
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return,
            _ => {}
        }
    }
}

/// Whether the poll events on the watchdog pipe mean the parent is gone.
#[cfg(unix)]
fn parent_gone(fd: BorrowedFd<'_>, revents: nix::poll::PollFlags, buf: &mut [u8]) -> bool {
    use nix::errno::Errno;
    use nix::poll::PollFlags;

    if revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return true;
    }
    if !revents.contains(PollFlags::POLLIN) {
        return false;
    }
    match nix::unistd::read(fd, buf) {
        Ok(0) => true,
        Ok(_) | Err(Errno::EINTR) => false,
        Err(_) => true,
    }
}

/// Spawn a background thread that exits the process when the parent dies.
///
/// No-op when `BUX_WATCHDOG_FD` is unset (detach mode).
#[cfg(unix)]
pub fn start_watchdog_thread() {
    let Ok(fd_str) = std::env::var(ENV_WATCHDOG_FD) else {
        return;
    };
    let Ok(fd_num) = fd_str.parse::<i32>() else {
        eprintln!("[bux-shim] invalid {ENV_WATCHDOG_FD}: {fd_str}");
        return;
    };

    #[allow(
        unsafe_code,
        reason = "fd created by parent via pipe and preserved across exec"
    )]
    // SAFETY: fd_num is the read end created by the parent without CLOEXEC.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd_num) };

    if let Err(e) = std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            #[allow(unsafe_code, reason = "borrow raw fd for poll lifetime")]
            // SAFETY: owned_fd keeps the fd open for this thread.
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd_num) };
            wait_for_parent_death(borrowed);
            drop(owned_fd);
            eprintln!("[bux-shim] parent process died, shutting down");
            std::process::exit(0);
        })
    {
        eprintln!("[bux-shim] failed to spawn watchdog thread: {e}");
    }
}

/// Die with bwrap's outer process when this shim is PID 1 of a jail. Call first
/// thing in `main`: the setting survives `exec`.
///
/// The outer process is the one recorded for the VM, and the VM must not outlive
/// it. bwrap's `--die-with-parent` would also tie it to the caller, which a
/// detached VM outlives.
///
/// # Errors
///
/// Returns the OS error if the kernel refuses. The shim must not continue: it
/// could outlive the jail.
#[cfg(target_os = "linux")]
pub fn die_with_jail() -> crate::Result<()> {
    if std::process::id() != 1 {
        return Ok(());
    }
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
        .map_err(|e| std::io::Error::from(e).into())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::os::fd::AsFd;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Run `wait_for_parent_death` on the read end in a thread; the receiver
    /// gets a message once it returns.
    fn watch(read_end: OwnedFd) -> mpsc::Receiver<()> {
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            wait_for_parent_death(read_end.as_fd());
            done_tx.send(()).ok();
        });
        done_rx
    }

    #[test]
    fn returns_when_write_end_closes() {
        let (read_end, write_end) = nix::unistd::pipe().unwrap();
        let done = watch(read_end);
        drop(write_end);
        assert!(
            done.recv_timeout(Duration::from_secs(5)).is_ok(),
            "watchdog must notice the closed write end"
        );
    }

    #[test]
    fn ignores_data_until_write_end_closes() {
        let (read_end, write_end) = nix::unistd::pipe().unwrap();
        let done = watch(read_end);
        nix::unistd::write(&write_end, b"x").unwrap();
        assert!(
            done.recv_timeout(Duration::from_millis(300)).is_err(),
            "data on the pipe is not parent death"
        );
        drop(write_end);
        assert!(
            done.recv_timeout(Duration::from_secs(5)).is_ok(),
            "watchdog must notice the closed write end"
        );
    }
}
