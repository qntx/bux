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
    agent::install_panic_hook();

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
    use std::sync::OnceLock;
    use std::time::Instant;

    use bux_proto::{
        AGENT_PORT, ExecReq, MAX_UPLOAD_BYTES, PROTOCOL_VERSION, Request, Response,
        STREAM_CHUNK_SIZE,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
    use tokio::process::Command;
    use tokio_vsock::VsockListener;

    /// Boot timestamp, set once at agent startup.
    static BOOT_T0: OnceLock<Instant> = OnceLock::new();

    /// Milliseconds elapsed since agent startup.
    fn elapsed_ms() -> u128 {
        BOOT_T0.get().map_or(0, |t| t.elapsed().as_millis())
    }

    /// Ensures panics are visible and trigger a clean exit.
    pub fn install_panic_hook() {
        std::panic::set_hook(Box::new(|info| {
            eprintln!("[bux-guest] PANIC: {info}");
            std::process::exit(1);
        }));
    }

    /// Entry point for the guest agent.
    pub async fn run() -> io::Result<()> {
        BOOT_T0.set(Instant::now()).ok();
        eprintln!("[bux-guest] T+0ms: starting");

        // PID 1 duty: auto-reap zombie children.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

        mount_essential_tmpfs();
        eprintln!("[bux-guest] T+{}ms: tmpfs mounted", elapsed_ms());

        let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, AGENT_PORT);
        let listener =
            VsockListener::bind(addr).map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;
        eprintln!(
            "[bux-guest] T+{}ms: listening on vsock port {AGENT_PORT}",
            elapsed_ms()
        );

        loop {
            let (stream, _addr) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = session(stream).await {
                    eprintln!("[bux-guest] session error: {e}");
                }
            });
        }
    }

    /// Mounts essential tmpfs directories needed by programs inside the VM.
    ///
    /// virtio-fs does not support the open-unlink-fstat pattern that many
    /// programs rely on, so `/tmp` and `/run` must be real tmpfs.
    fn mount_essential_tmpfs() {
        for path in ["/tmp", "/run"] {
            let _ = std::fs::create_dir_all(path);
            let target = std::ffi::CString::new(path).unwrap();
            let fstype = std::ffi::CString::new("tmpfs").unwrap();
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    target.as_ptr(),
                    fstype.as_ptr(),
                    0,
                    std::ptr::null(),
                );
            }
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
                Request::Handshake { .. } => {
                    bux_proto::send(
                        &mut w,
                        &Response::Handshake {
                            version: PROTOCOL_VERSION,
                        },
                    )
                    .await?;
                }
                Request::Exec(exec) => exec_cmd(&mut r, &mut w, exec).await?,
                Request::Signal { pid, signal } => {
                    unsafe { libc::kill(pid, signal) };
                    bux_proto::send(&mut w, &Response::Ok).await?;
                }
                Request::ReadFile { path } => read_file(&mut w, &path).await?,
                Request::WriteFile { path, mode } => {
                    write_file(&mut r, &mut w, &path, mode).await?;
                }
                Request::CopyIn { dest } => copy_in(&mut r, &mut w, &dest).await?,
                Request::CopyOut { path } => copy_out(&mut w, &path).await?,
                // Chunk/EndOfStream outside an active upload are protocol errors.
                Request::Chunk(_) | Request::EndOfStream => {
                    bux_proto::send(&mut w, &Response::Error("unexpected chunk".into())).await?;
                }
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

        // Apply uid/gid before exec (gid first — setuid would drop privileges).
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

        #[allow(clippy::cast_possible_wrap)]
        let pid = child.id().unwrap_or(0) as i32;
        bux_proto::send(w, &Response::Started { pid }).await?;

        let mut child_stdin = child.stdin.take();
        // SAFETY: stdout/stderr were set to Stdio::piped() above, so take() always succeeds.
        let Some(mut stdout) = child.stdout.take() else { unreachable!() };
        let Some(mut stderr) = child.stderr.take() else { unreachable!() };
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut stdout_buf = [0u8; 4096];
        let mut stderr_buf = [0u8; 4096];

        // Multiplex: read host stdin/signal requests + stream stdout/stderr.
        loop {
            if stdout_done && stderr_done && child_stdin.is_none() {
                break;
            }

            tokio::select! {
                // Always accept host messages during exec (not just when stdin is open).
                // This ensures Signal messages are delivered even after stdin is closed.
                host_req = bux_proto::recv::<Request>(r) => {
                    match host_req {
                        Ok(Request::Stdin { data, .. }) => {
                            if let Some(ref mut stdin) = child_stdin {
                                let _ = stdin.write_all(&data).await;
                            }
                        }
                        Ok(Request::StdinClose { .. }) => {
                            child_stdin = None;
                        }
                        Ok(Request::Signal { pid: p, signal }) => {
                            unsafe { libc::kill(p, signal) };
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                bytes_read = stdout.read(&mut stdout_buf), if !stdout_done => {
                    match bytes_read {
                        Ok(0) => stdout_done = true,
                        Ok(len) => {
                            bux_proto::send(w, &Response::Stdout(stdout_buf[..len].to_vec())).await?;
                        }
                        Err(e) => {
                            eprintln!("[bux-guest] stdout read error: {e}");
                            stdout_done = true;
                        }
                    }
                }
                bytes_read = stderr.read(&mut stderr_buf), if !stderr_done => {
                    match bytes_read {
                        Ok(0) => stderr_done = true,
                        Ok(len) => {
                            bux_proto::send(w, &Response::Stderr(stderr_buf[..len].to_vec())).await?;
                        }
                        Err(e) => {
                            eprintln!("[bux-guest] stderr read error: {e}");
                            stderr_done = true;
                        }
                    }
                }
            }
        }

        drop(child_stdin);

        let status = child.wait().await?;
        bux_proto::send(w, &Response::Exit(status.code().unwrap_or(-1))).await
    }

    /// Reads a file and streams its contents back to the host in chunks.
    ///
    /// Streams directly from the file handle — memory usage is O(STREAM_CHUNK_SIZE).
    async fn read_file(w: &mut (impl AsyncWrite + Unpin), path: &str) -> io::Result<()> {
        let mut file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) => return bux_proto::send(w, &Response::Error(e.to_string())).await,
        };
        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            bux_proto::send(w, &Response::Chunk(buf[..n].to_vec())).await?;
        }
        bux_proto::send(w, &Response::EndOfStream).await
    }

    /// Receives upload chunks from the host into a temp file.
    ///
    /// Returns the temp file path. Enforces [`MAX_UPLOAD_BYTES`] safety cap.
    /// Memory usage is O(STREAM_CHUNK_SIZE) regardless of total transfer size.
    async fn recv_upload_to_file(
        r: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<std::path::PathBuf> {
        let temp_path = Path::new("/tmp").join(format!("bux-upload-{}", std::process::id()));
        let mut file = tokio::fs::File::create(&temp_path).await?;
        let mut total: u64 = 0;
        loop {
            match bux_proto::recv::<Request>(r).await? {
                Request::Chunk(data) => {
                    total += data.len() as u64;
                    if total > MAX_UPLOAD_BYTES {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        return Err(io::Error::other(
                            format!("upload exceeds {MAX_UPLOAD_BYTES} byte limit"),
                        ));
                    }
                    file.write_all(&data).await?;
                }
                Request::EndOfStream => {
                    file.flush().await?;
                    return Ok(temp_path);
                }
                _ => {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected Chunk or EndOfStream",
                    ));
                }
            }
        }
    }

    /// Receives chunked data from the host and writes it to a file.
    ///
    /// Uses a temp file as intermediate buffer — memory usage is O(STREAM_CHUNK_SIZE).
    async fn write_file(
        r: &mut (impl AsyncRead + Unpin),
        w: &mut (impl AsyncWrite + Unpin),
        path: &str,
        mode: u32,
    ) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_path = match recv_upload_to_file(r).await {
            Ok(p) => p,
            Err(e) => return bux_proto::send(w, &Response::Error(e.to_string())).await,
        };

        let result = async {
            if let Some(parent) = Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::copy(&temp_path, path).await?;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
            tokio::fs::remove_file(&temp_path).await?;
            io::Result::Ok(())
        }
        .await;

        // Clean up temp file on error path too.
        let _ = tokio::fs::remove_file(&temp_path).await;

        match result {
            Ok(()) => bux_proto::send(w, &Response::Ok).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }

    /// Receives a chunked tar archive from the host and unpacks it into `dest`,
    /// rejecting path traversal attacks.
    ///
    /// Streams to a temp file first — memory usage is O(STREAM_CHUNK_SIZE).
    async fn copy_in(
        r: &mut (impl AsyncRead + Unpin),
        w: &mut (impl AsyncWrite + Unpin),
        dest: &str,
    ) -> io::Result<()> {
        let temp_path = match recv_upload_to_file(r).await {
            Ok(p) => p,
            Err(e) => return bux_proto::send(w, &Response::Error(e.to_string())).await,
        };
        let dest_owned = dest.to_owned();
        let tp = temp_path.clone();

        let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let dest_path = Path::new(&dest_owned);
            std::fs::create_dir_all(dest_path)?;
            let canonical_dest = dest_path.canonicalize()?;
            let file = std::fs::File::open(&tp)?;
            let mut archive = tar::Archive::new(file);
            archive.set_preserve_permissions(true);
            // Validate each entry to prevent path traversal (e.g. ../../etc/passwd).
            for raw_entry in archive.entries()? {
                let mut entry = raw_entry?;
                let path = entry.path()?.into_owned();
                let target = canonical_dest.join(&path);
                // Resolve symlinks in prefix only, not the final component.
                if let Ok(resolved) = target.parent().unwrap_or(&canonical_dest).canonicalize()
                    && !resolved.starts_with(&canonical_dest) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("path traversal blocked: {}", path.display()),
                        ));
                    }
                entry.unpack_in(&canonical_dest)?;
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)?;

        let _ = tokio::fs::remove_file(&temp_path).await;

        match result {
            Ok(()) => bux_proto::send(w, &Response::Ok).await,
            Err(e) => bux_proto::send(w, &Response::Error(e.to_string())).await,
        }
    }

    /// Packs a path (file or directory) into a tar archive and streams it.
    ///
    /// Packs to a temp file first, then streams from the file in chunks.
    /// Memory usage is O(STREAM_CHUNK_SIZE) regardless of archive size.
    async fn copy_out(w: &mut (impl AsyncWrite + Unpin), path: &str) -> io::Result<()> {
        let owned_path = path.to_owned();
        let temp_path = Path::new("/tmp").join(format!("bux-download-{}", std::process::id()));
        let tp = temp_path.clone();

        let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let file = std::fs::File::create(&tp)?;
            let mut ar = tar::Builder::new(file);
            let meta = std::fs::metadata(&owned_path)?;
            if meta.is_dir() {
                ar.append_dir_all(".", &owned_path)?;
            } else {
                let name = Path::new(&owned_path)
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("file"));
                ar.append_path_with_name(&owned_path, name)?;
            }
            ar.finish()?;
            Ok(())
        })
        .await
        .map_err(io::Error::other)?;

        match result {
            Ok(()) => {
                // Stream the temp file in chunks.
                let mut file = tokio::fs::File::open(&temp_path).await?;
                let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    bux_proto::send(w, &Response::Chunk(buf[..n].to_vec())).await?;
                }
                let _ = tokio::fs::remove_file(&temp_path).await;
                bux_proto::send(w, &Response::EndOfStream).await
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                bux_proto::send(w, &Response::Error(e.to_string())).await
            }
        }
    }
}
