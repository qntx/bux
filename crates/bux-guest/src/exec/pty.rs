//! PTY-based process spawning and window resize.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use bux_proto::{ExecStart, TtyConfig};
use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::unistd::dup;
use tokio::sync::oneshot;

use crate::reaper::{Exit, Reaper};

/// Handle to a process spawned with a PTY.
pub struct PtyHandle {
    /// Child PID.
    pub pid: i32,
    /// Async reader for the PTY master (child's stdout+stderr merged).
    pub master_read: tokio::fs::File,
    /// Async writer for the PTY master (child's stdin).
    pub master_write: tokio::fs::File,
    /// Completes when the reaper observes this child's exit.
    pub exit: oneshot::Receiver<Exit>,
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
///
/// # Errors
///
/// Returns an error if the PTY cannot be opened, credentials cannot be
/// resolved, or the child fails to spawn.
pub fn spawn(req: &ExecStart, reaper: &Reaper) -> io::Result<PtyHandle> {
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

    let credentials = super::resolve_credentials(req)?;

    let mut cmd = Command::new(&req.cmd);
    cmd.args(&req.args);
    // cwd/env only — credentials share one pre_exec with setsid below.
    if let Some(ref cwd) = req.cwd {
        cmd.current_dir(cwd);
    }
    for pair in &req.env {
        if let Some((k, v)) = pair.split_once('=') {
            cmd.env(k, v);
        }
    }

    unsafe {
        cmd.stdin(Stdio::from_raw_fd(slave_stdin.into_raw_fd()));
        cmd.stdout(Stdio::from_raw_fd(slave_stdout.into_raw_fd()));
        cmd.stderr(Stdio::from_raw_fd(slave_stderr.into_raw_fd()));
    }

    // Single pre_exec: session + controlling TTY + optional credentials.
    // (Command keeps only the last pre_exec hook.)
    unsafe {
        cmd.pre_exec(move || {
            nix::unistd::setsid().map_err(io::Error::other)?;
            if libc::ioctl(slave_raw_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if let Some((uid, gid)) = credentials {
                if libc::setgid(gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let spawned = reaper.spawn(&mut cmd)?;

    #[allow(clippy::cast_possible_wrap)]
    let pid = spawned.child.id() as i32;
    drop(spawned.child);

    // Close slave in parent — child has its own copies after fork.
    drop(slave);

    // Create separate read/write handles from the master fd.
    let read_fd = dup_fd(&master, "master_read")?;
    let write_fd = dup_fd(&master, "master_write")?;

    Ok(PtyHandle {
        pid,
        master_read: super::file_from_stdio(read_fd),
        master_write: super::file_from_stdio(write_fd),
        exit: spawned.exit,
        master_fd: master,
    })
}

/// Duplicates an `OwnedFd` with a descriptive error context.
fn dup_fd(fd: &OwnedFd, label: &str) -> io::Result<OwnedFd> {
    dup(fd).map_err(|e| io::Error::other(format!("dup {label}: {e}")))
}
