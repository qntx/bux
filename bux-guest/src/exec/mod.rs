//! Command execution with PTY support and timeout management.

mod pty;

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use bux_proto::{ErrorCode, ErrorInfo, ExecIn, ExecOut, ExecStart, HelloAck};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Monotonic counter for generating unique execution IDs.
static EXEC_SEQ: AtomicU64 = AtomicU64::new(1);

/// Handles an exec connection: spawns a child, multiplexes I/O until exit.
pub async fn handle(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    req: ExecStart,
) -> io::Result<()> {
    let exec_id = format!("exec-{}", EXEC_SEQ.fetch_add(1, Ordering::Relaxed));
    let spawn_t0 = Instant::now();

    if req.tty.is_some() {
        handle_pty(r, w, req, &exec_id, spawn_t0).await
    } else {
        handle_pipe(r, w, req, &exec_id, spawn_t0).await
    }
}

/// Pipe-mode execution: stdout and stderr are separate streams.
async fn handle_pipe(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    req: ExecStart,
    exec_id: &str,
    spawn_t0: Instant,
) -> io::Result<()> {
    use std::process::Stdio;

    use tokio::process::Command;

    let mut cmd = Command::new(&req.cmd);
    cmd.args(&req.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if req.stdin {
        cmd.stdin(Stdio::piped());
    }

    apply_exec_options!(&mut cmd, &req);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = ErrorInfo::new(ErrorCode::Internal, e.to_string());
            bux_proto::send(w, &HelloAck::Error(err)).await?;
            return w.flush().await;
        }
    };

    #[allow(clippy::cast_possible_wrap)]
    let pid = child.id().unwrap_or(0) as i32;
    bux_proto::send(
        w,
        &HelloAck::ExecStarted {
            exec_id: exec_id.to_owned(),
            pid,
        },
    )
    .await?;
    w.flush().await?;

    // Set up timeout watcher.
    let timed_out = Arc::new(AtomicBool::new(false));
    if req.timeout_ms > 0 {
        let flag = Arc::clone(&timed_out);
        let timeout = std::time::Duration::from_millis(req.timeout_ms);
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            flag.store(true, Ordering::SeqCst);
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
    }

    let mut child_stdin = child.stdin.take();
    // SAFETY: stdout/stderr were set to Stdio::piped() above.
    let Some(mut stdout) = child.stdout.take() else {
        unreachable!()
    };
    let Some(mut stderr) = child.stderr.take() else {
        unreachable!()
    };
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stdout_buf = [0u8; 4096];
    let mut stderr_buf = [0u8; 4096];

    loop {
        // Exit the I/O loop once both output streams are done.
        if stdout_done && stderr_done {
            break;
        }

        tokio::select! {
            host_msg = bux_proto::recv::<ExecIn>(r) => {
                match host_msg {
                    Ok(ExecIn::Stdin(data)) => {
                        if let Some(ref mut stdin) = child_stdin {
                            let _ = stdin.write_all(&data).await;
                        }
                    }
                    Ok(ExecIn::StdinClose) => {
                        child_stdin = None;
                    }
                    Ok(ExecIn::Signal(sig)) => {
                        let _ = unsafe { libc::kill(pid, sig) };
                    }
                    Ok(ExecIn::ResizeTty(_)) => {}
                    Err(_) => {
                        // Host disconnected — kill child and collect exit status.
                        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                        break;
                    }
                }
            }
            n = stdout.read(&mut stdout_buf), if !stdout_done => {
                match n {
                    Ok(0) | Err(_) => stdout_done = true,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stdout(stdout_buf[..len].to_vec())).await?;
                    }
                }
            }
            n = stderr.read(&mut stderr_buf), if !stderr_done => {
                match n {
                    Ok(0) | Err(_) => stderr_done = true,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stderr(stderr_buf[..len].to_vec())).await?;
                    }
                }
            }
        }
    }

    drop(child_stdin);
    send_exit(w, &mut child, spawn_t0, &timed_out).await
}

/// PTY-mode execution: stdout and stderr are merged into a single PTY stream.
async fn handle_pty(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    req: ExecStart,
    exec_id: &str,
    spawn_t0: Instant,
) -> io::Result<()> {
    let spawn_result = pty::spawn(&req);
    let mut pty_handle = match spawn_result {
        Ok(h) => h,
        Err(e) => {
            let err = ErrorInfo::new(ErrorCode::Internal, e.to_string());
            bux_proto::send(w, &HelloAck::Error(err)).await?;
            return w.flush().await;
        }
    };

    let pid = pty_handle.pid;
    bux_proto::send(
        w,
        &HelloAck::ExecStarted {
            exec_id: exec_id.to_owned(),
            pid,
        },
    )
    .await?;
    w.flush().await?;

    // Set up timeout watcher.
    let timed_out = Arc::new(AtomicBool::new(false));
    if req.timeout_ms > 0 {
        let flag = Arc::clone(&timed_out);
        let timeout = std::time::Duration::from_millis(req.timeout_ms);
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            flag.store(true, Ordering::SeqCst);
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
    }

    let mut pty_buf = [0u8; 4096];

    loop {
        tokio::select! {
            host_msg = bux_proto::recv::<ExecIn>(r) => {
                match host_msg {
                    Ok(ExecIn::Stdin(data)) => {
                        let _ = pty_handle.master_write.write_all(&data).await;
                    }
                    Ok(ExecIn::StdinClose) => {
                        // PTY doesn't have a separate stdin EOF concept.
                    }
                    Ok(ExecIn::Signal(sig)) => {
                        let _ = unsafe { libc::kill(pid, sig) };
                    }
                    Ok(ExecIn::ResizeTty(config)) => {
                        pty_handle.resize(&config);
                    }
                    Err(_) => {
                        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                        break;
                    }
                }
            }
            n = pty_handle.master_read.read(&mut pty_buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stdout(pty_buf[..len].to_vec())).await?;
                    }
                }
            }
        }
    }

    send_exit_by_pid(w, pid, spawn_t0, &timed_out).await
}

/// Waits for a `tokio::process::Child` and sends `ExecOut::Exit`.
async fn send_exit(
    w: &mut (impl AsyncWrite + Unpin),
    child: &mut tokio::process::Child,
    spawn_t0: Instant,
    timed_out: &AtomicBool,
) -> io::Result<()> {
    let status = child.wait().await?;
    let code = status.code().unwrap_or(-1);
    let signal = status.signal();

    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = spawn_t0.elapsed().as_millis() as u64;

    bux_proto::send(
        w,
        &ExecOut::Exit {
            code,
            signal,
            timed_out: timed_out.load(Ordering::SeqCst),
            duration_ms,
            error_message: String::new(),
        },
    )
    .await
}

/// Waits for a process by PID (PTY mode) and sends `ExecOut::Exit`.
async fn send_exit_by_pid(
    w: &mut (impl AsyncWrite + Unpin),
    pid: i32,
    spawn_t0: Instant,
    timed_out: &AtomicBool,
) -> io::Result<()> {
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;

    let wait_result = tokio::task::spawn_blocking(move || waitpid(Pid::from_raw(pid), None))
        .await
        .map_err(io::Error::other)?;

    let (code, signal) = match wait_result {
        Ok(WaitStatus::Exited(_, c)) => (c, None),
        Ok(WaitStatus::Signaled(_, sig, _)) => (0, Some(sig as i32)),
        // ECHILD: already reaped (SIG_IGN on SIGCHLD).
        Err(nix::errno::Errno::ECHILD) => (0, None),
        Ok(_) | Err(_) => (-1, None),
    };

    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = spawn_t0.elapsed().as_millis() as u64;

    bux_proto::send(
        w,
        &ExecOut::Exit {
            code,
            signal,
            timed_out: timed_out.load(Ordering::SeqCst),
            duration_ms,
            error_message: String::new(),
        },
    )
    .await
}

/// Applies common exec options (cwd, env, uid, gid) to a command.
///
/// Works with both `std::process::Command` and `tokio::process::Command`
/// since they share the same method signatures for env/cwd/pre_exec.
macro_rules! apply_exec_options {
    ($cmd:expr, $req:expr) => {{
        if let Some(ref cwd) = $req.cwd {
            $cmd.current_dir(cwd);
        }
        for pair in &$req.env {
            if let Some((k, v)) = pair.split_once('=') {
                $cmd.env(k, v);
            }
        }
        // Apply gid before uid — setuid would drop privilege to change gid.
        if let Some(gid) = $req.gid {
            unsafe {
                $cmd.pre_exec(move || {
                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        if let Some(uid) = $req.uid {
            unsafe {
                $cmd.pre_exec(move || {
                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }};
}
pub(crate) use apply_exec_options;
