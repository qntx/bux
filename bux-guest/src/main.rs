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
                Request::Exec(exec) => exec_cmd(&mut w, exec).await?,
                Request::Ping => bux_proto::send(&mut w, &Response::Pong).await?,
                Request::Signal { pid, signal } => {
                    unsafe {
                        libc::kill(pid as i32, signal);
                    }
                    bux_proto::send(&mut w, &Response::Ok).await?;
                }
                Request::ReadFile { path } => read_file(&mut w, &path).await?,
                Request::WriteFile { path, data, mode } => {
                    write_file(&mut w, &path, &data, mode).await?;
                }
                Request::Shutdown => {
                    bux_proto::send(&mut w, &Response::Ok).await?;
                    w.flush().await?;
                    std::process::exit(0);
                }
            }
        }
    }

    /// Spawns a child process and streams stdout/stderr via `tokio::select!`.
    async fn exec_cmd(
        w: &mut (impl AsyncWrite + Unpin),
        req: ExecReq,
    ) -> io::Result<()> {
        let mut cmd = Command::new(&req.cmd);
        cmd.args(&req.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref cwd) = req.cwd {
            cmd.current_dir(cwd);
        }
        for pair in &req.env {
            if let Some((k, v)) = pair.split_once('=') {
                cmd.env(k, v);
            }
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return bux_proto::send(w, &Response::Error(e.to_string())).await,
        };

        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut stdout_buf = [0u8; 4096];
        let mut stderr_buf = [0u8; 4096];

        // Concurrently read stdout/stderr and forward chunks to the host.
        loop {
            if stdout_done && stderr_done {
                break;
            }

            let chunk = tokio::select! {
                r = stdout.read(&mut stdout_buf), if !stdout_done => match r {
                    Ok(0) | Err(_) => { stdout_done = true; None }
                    Ok(n) => Some(Response::Stdout(stdout_buf[..n].to_vec())),
                },
                r = stderr.read(&mut stderr_buf), if !stderr_done => match r {
                    Ok(0) | Err(_) => { stderr_done = true; None }
                    Ok(n) => Some(Response::Stderr(stderr_buf[..n].to_vec())),
                },
            };

            if let Some(resp) = chunk {
                bux_proto::send(w, &resp).await?;
            }
        }

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
            if let Some(parent) = std::path::Path::new(path).parent() {
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
}
