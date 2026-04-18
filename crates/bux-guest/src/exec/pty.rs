//! PTY-based process spawning and window resize.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use bux_proto::{ExecStart, TtyConfig};
use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::unistd::dup;

/// Handle to a process spawned with a PTY.
pub struct PtyHandle {
    /// Child PID.
    pub pid: i32,
    /// Async reader for the PTY master (child's stdout+stderr merged).
    pub master_read: tokio::fs::File,
    /// Async writer for the PTY master (child's stdin).
    pub master_write: tokio::fs::File,
    /// Raw fd of the PTY master, kept alive for `TIOCSWINSZ`.
    master_fd: OwnedFd,
}

impl PtyHandle {
    /// Resize the PTY window via `TIOCSWINSZ` ioctl.
    pub fn resize(&self, config: &TtyConfig) {
        let winsize = Winsize {
            ws_row: config.rows,
            ws_col: config.cols,
            ws_xpixel: config.x_pixels,
            ws_ypixel: config.y_pixels,
        };
        unsafe {
            libc::ioctl(
                self.master_fd.as_raw_fd(),
                libc::TIOCSWINSZ,
                std::ptr::from_ref(&winsize),
            );
        }
    }
}

/// Spawns a process with a PTY.
///
/// The child gets a new session (`setsid`) and the PTY slave becomes its
/// controlling terminal (`TIOCSCTTY`). In PTY mode, stdout and stderr are
/// merged into a single stream through the PTY master.
pub fn spawn(req: &ExecStart) -> io::Result<PtyHandle> {
    let Some(tty) = req.tty.as_ref() else {
        return Err(io::Error::other("tty config required for PTY spawn"));
    };

    let winsize = Winsize {
        ws_row: tty.rows,
        ws_col: tty.cols,
        ws_xpixel: tty.x_pixels,
        ws_ypixel: tty.y_pixels,
    };

    let OpenptyResult { master, slave } =
        openpty(Some(&winsize), None).map_err(|e| io::Error::other(format!("openpty: {e}")))?;

    let slave_raw_fd = slave.as_raw_fd();

    // Duplicate slave fd for each stdio handle (Stdio::from_raw_fd takes ownership).
    let slave_stdin = dup_fd(&slave, "stdin")?;
    let slave_stdout = dup_fd(&slave, "stdout")?;
    let slave_stderr = dup_fd(&slave, "stderr")?;

    let mut cmd = Command::new(&req.cmd);
    cmd.args(&req.args);
    super::apply_exec_options!(&mut cmd, req);

    unsafe {
        cmd.stdin(Stdio::from_raw_fd(slave_stdin.into_raw_fd()));
        cmd.stdout(Stdio::from_raw_fd(slave_stdout.into_raw_fd()));
        cmd.stderr(Stdio::from_raw_fd(slave_stderr.into_raw_fd()));
    }

    // Create new session and set controlling terminal in the child.
    unsafe {
        cmd.pre_exec(move || {
            nix::unistd::setsid().map_err(io::Error::other)?;
            if libc::ioctl(slave_raw_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;

    #[allow(clippy::cast_possible_wrap)]
    let pid = child.id() as i32;

    // Close slave in parent — child has its own copies after fork.
    drop(slave);

    // Create separate read/write handles from the master fd.
    let read_fd = dup_fd(&master, "master_read")?;
    let write_fd = dup_fd(&master, "master_write")?;

    let master_read =
        tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(read_fd.into_raw_fd()) });
    let master_write =
        tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(write_fd.into_raw_fd()) });

    Ok(PtyHandle {
        pid,
        master_read,
        master_write,
        master_fd: master,
    })
}

/// Duplicates an `OwnedFd` with a descriptive error context.
fn dup_fd(fd: &OwnedFd, label: &str) -> io::Result<OwnedFd> {
    dup(fd).map_err(|e| io::Error::other(format!("dup {label}: {e}")))
}
