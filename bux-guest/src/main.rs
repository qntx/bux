//! bux guest agent — runs inside a micro-VM, typically as PID 1.
//!
//! Listens on a vsock port and handles host requests via [`bux_proto`].
#![allow(unsafe_code, clippy::print_stderr)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bux-guest only runs inside a Linux micro-VM");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = agent::run().await {
        eprintln!("[bux-guest] fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod agent {
    use std::io;
    use std::path::Path;
    use std::process::Stdio;

    use bux_proto::{AGENT_PORT, ExecReq, Request, Response};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
    use tokio::process::Command;
    use tokio_vsock::VsockListener;

    /// Entry point for the guest agent.
    pub(crate) async fn run() -> io::Result<()> {
        // PID 1 duty: auto-reap zombie children.
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }

        let listener = VsockListener::bind(libc::VMADDR_CID_ANY as u32, AGENT_PORT)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;
        eprintln!("[bux-guest] listening on vsock port {AGENT_PORT}");

        loop {
            let (stream, _addr) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = session(stream).await {
                    eprintln!("[bux-guest] session error: {e}");
                }
            });
        }
    }

    /// Handles a single host connection: read requests, dispatch, respond.
    async fn session(stream: tokio_vsock::VsockStream) -> io::Result<()> {
        let (reader, writer) = tokio::io::split(stream);
        let mut r = BufReader::new(reader);
        let mut w = BufWriter::new(writer);

        loop {
            let req: Request = match bux_proto::recv(&mut r).await {
                Ok(req) => req,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };

            match req {
                Request::Exec(exec) => exec_cmd(&mut r, &mut w, exec).await?,
                Request::Signal { pid, signal } => {
                    unsafe { libc::kill(pid as i32, signal) };
                    bux_proto::send(&mut w, &Response::Ok).await?;
                }
                Request::ReadFile { path } => read_file(&mut w, &path).await?,
                Request::WriteFile { path, data, mode } => {
                    write_file(&mut w, &path, &data, mode).await?;
                }
                Request::CopyIn { dest, tar } => copy_in(&mut w, &dest, &tar).await?,
                Request::CopyOut { path } => copy_out(&mut w, &path).await?,
                Request::Ping => bux_proto::send(&mut w, &Response::Pong).await?,
                Request::Shutdown => {
                    bux_proto::send(&mut w, &Response::Ok).await?;
                    w.flush().await?;
                    std::process::exit(0);
                }
                // Stdin/StdinClose outside of an exec session are no-ops.
                Request::Stdin { .. } | Request::StdinClose { .. } => {
                    bux_proto::send(&mut w, &Response::Ok).await?;
                }
            }
        }
    }

    /// Spawns a child process with optional stdin piping and uid/gid switching.
    ///
    /// Protocol flow:
    /// 1. Guest sends `Started { pid }`.
    /// 2. Guest streams `Stdout`/`Stderr` chunks while reading `Stdin`/`StdinClose`
    ///    from the host concurrently.
    /// 3. Guest sends `Exit(code)` when the process terminates.
    async fn exec_cmd(
        r: &mut (impl AsyncRead + Unpin),
        w: &mut (impl AsyncWrite + Unpin),
        req: ExecReq,
    ) -> io::Result<()> {
        let mut cmd = Command::new(&req.cmd);
        cmd.args(&req.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if req.stdin {
            cmd.stdin(Stdio::piped());
        }

        if let Some(ref cwd) = req.cwd {
            cmd.current_dir(cwd);
        }
        for pair in &req.env {
            if let Some((k, v)) = pair.split_once('=') {
                cmd.env(k, v);
            }
        }

        // Apply uid/gid before exec.
        if let Some(gid) = req.gid {
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setgid(gid) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        if let Some(uid) = req.uid {
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setuid(uid) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return bux_proto::send(w, &Response::Error(e.to_string())).await,
        };

        let pid = child.id().unwrap_or(0);
        bux_proto::send(w, &Response::Started { pid }).await?;

        // Take ownership of child stdio handles.
        let mut child_stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap_or_else(|| unreachable!());
        let mut stderr = child.stderr.take().unwrap_or_else(|| unreachable!());
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut stdout_buf = [0u8; 4096];
        let mut stderr_buf = [0u8; 4096];

        // Multiplex: read host stdin requests + stream stdout/stderr.
        loop {
            if stdout_done && stderr_done {
                break;
            }

            tokio::select! {
                // Read host requests (stdin data / stdin close / signals).
                host_req = bux_proto::recv::<Request>(r), if child_stdin.is_some() => {
                    match host_req {
                        Ok(Request::Stdin { data, .. }) => {
                            if let Some(ref mut stdin) = child_stdin {
                                let _ = stdin.write_all(&data).await;
                            }
                        }
                        Ok(Request::StdinClose { .. }) => {
                            child_stdin = None; // drop closes pipe
                        }
                        Ok(Request::Signal { pid: p, signal }) => {
                            unsafe { libc::kill(p as i32, signal) };
                        }
                        _ => {} // ignore other requests during exec
                    }
                }
                n = stdout.read(&mut stdout_buf), if !stdout_done => {
                    match n {
                        Ok(0) | Err(_) => stdout_done = true,
                        Ok(n) => {
                            bux_proto::send(w, &Response::Stdout(stdout_buf[..n].to_vec())).await?;
                        }
                    }
                }
                n = stderr.read(&mut stderr_buf), if !stderr_done => {
                    match n {
                        Ok(0) | Err(_) => stderr_done = true,
                        Ok(n) => {
                            bux_proto::send(w, &Response::Stderr(stderr_buf[..n].to_vec())).await?;
                        }
                    }
                }
            }
        }

        // Drop stdin to unblock child if still open.
        drop(child_stdin);

        let status = child.wait().await?;
        bux_proto::send(w, &Response::Exit(status.code().unwrap_or(-1))).await
    }

    /// Reads a file and sends its contents back to the host.
    async fn read_file(w: &mut (impl AsyncWrite + Unpin), path: &str) -> io::Result<()> {
        match tokio::fs::read(path).await {
            Ok(data) => bux_proto::send(w, &Response::FileData(data)).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }

    /// Writes data to a file with the specified permission mode.
    async fn write_file(
        w: &mut (impl AsyncWrite + Unpin),
        path: &str,
        data: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let result = async {
            if let Some(parent) = Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(path, data).await?;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
            io::Result::Ok(())
        }
        .await;

        match result {
            Ok(()) => bux_proto::send(w, &Response::Ok).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }

    /// Unpacks a tar archive into `dest` directory.
    async fn copy_in(
        w: &mut (impl AsyncWrite + Unpin),
        dest: &str,
        tar_data: &[u8],
    ) -> io::Result<()> {
        let dest = dest.to_owned();
        let data = tar_data.to_vec();

        // tar::Archive is sync; run in blocking task.
        let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
            std::fs::create_dir_all(&dest)?;
            let cursor = io::Cursor::new(data);
            let mut archive = tar::Archive::new(cursor);
            archive.set_preserve_permissions(true);
            archive.unpack(&dest)?;
            Ok(())
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        match result {
            Ok(()) => bux_proto::send(w, &Response::Ok).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }

    /// Packs a path (file or directory) into a tar archive and sends it.
    async fn copy_out(w: &mut (impl AsyncWrite + Unpin), path: &str) -> io::Result<()> {
        let path = path.to_owned();

        let result = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            {
                let mut ar = tar::Builder::new(&mut buf);
                let meta = std::fs::metadata(&path)?;
                if meta.is_dir() {
                    ar.append_dir_all(".", &path)?;
                } else {
                    let name = Path::new(&path)
                        .file_name()
                        .unwrap_or_else(|| std::ffi::OsStr::new("file"));
                    ar.append_path_with_name(&path, name)?;
                }
                ar.finish()?;
            }
            Ok(buf)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        match result {
            Ok(data) => bux_proto::send(w, &Response::TarData(data)).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }
}
