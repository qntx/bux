//! Async host-side client for communicating with a bux guest agent.
//!
//! Each operation opens a **dedicated connection** to the guest agent.
//! This eliminates contention — multiple execs, file transfers, and control
//! operations can proceed concurrently without any locking.

#[cfg(unix)]
/// Platform-specific implementation (Unix only).
mod inner {
    use std::io;
    use std::path::{Path, PathBuf};

    use bux_proto::{
        ControlReq, ControlResp, ExecIn, ExecOut, ExecStart, Hello, HelloAck, PROTOCOL_VERSION,
        STREAM_CHUNK_SIZE, UploadResult,
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::UnixStream;
    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

    /// Output captured from a completed exec.
    #[derive(Debug)]
    pub struct ExecOutput {
        pub exec_id: String,
        pub pid: i32,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
        pub code: i32,
        pub signal: Option<i32>,
        pub timed_out: bool,
        pub duration_ms: u64,
        pub error_message: String,
    }

    /// Information returned by a successful ping.
    #[derive(Debug)]
    pub struct PongInfo {
        pub version: String,
        pub uptime_ms: u64,
    }

    /// Handle to a running exec with a dedicated connection.
    ///
    /// The connection is split into read/write halves so stdin writes and
    /// stdout/stderr reads proceed concurrently without deadlock.
    pub struct ExecHandle {
        /// Unique execution identifier assigned by the guest.
        exec_id: String,
        /// Child process ID inside the guest.
        pid: i32,
        /// Read half — receives [`ExecOut`] messages from the guest.
        reader: OwnedReadHalf,
        /// Write half — sends [`ExecIn`] messages to the guest.
        writer: OwnedWriteHalf,
    }

    impl ExecHandle {
        /// Unique execution identifier.
        pub fn exec_id(&self) -> &str {
            &self.exec_id
        }

        /// Process ID inside the guest.
        pub const fn pid(&self) -> i32 {
            self.pid
        }

        /// Writes data to the process's stdin.
        pub async fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
            bux_proto::send(&mut self.writer, &ExecIn::Stdin(data.to_vec())).await
        }

        /// Closes the process's stdin (sends EOF).
        pub async fn close_stdin(&mut self) -> io::Result<()> {
            bux_proto::send(&mut self.writer, &ExecIn::StdinClose).await
        }

        /// Sends a POSIX signal to the process.
        pub async fn signal(&mut self, sig: i32) -> io::Result<()> {
            bux_proto::send(&mut self.writer, &ExecIn::Signal(sig)).await
        }

        /// Resizes the PTY window (only for TTY sessions).
        pub async fn resize_tty(
            &mut self,
            rows: u16,
            cols: u16,
            x_pixels: u16,
            y_pixels: u16,
        ) -> io::Result<()> {
            bux_proto::send(
                &mut self.writer,
                &ExecIn::ResizeTty(bux_proto::TtyConfig {
                    rows,
                    cols,
                    x_pixels,
                    y_pixels,
                }),
            )
            .await
        }

        /// Reads the next output event from the guest.
        ///
        /// Returns `None` when the connection closes unexpectedly.
        pub async fn next_output(&mut self) -> io::Result<ExecOut> {
            bux_proto::recv(&mut self.reader).await
        }

        /// Waits for the process to exit, collecting all output.
        pub async fn wait_with_output(mut self) -> io::Result<ExecOutput> {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                match self.next_output().await? {
                    ExecOut::Stdout(d) => stdout.extend(d),
                    ExecOut::Stderr(d) => stderr.extend(d),
                    ExecOut::Exit {
                        code,
                        signal,
                        timed_out,
                        duration_ms,
                        error_message,
                    } => {
                        return Ok(ExecOutput {
                            exec_id: self.exec_id,
                            pid: self.pid,
                            stdout,
                            stderr,
                            code,
                            signal,
                            timed_out,
                            duration_ms,
                            error_message,
                        });
                    }
                    ExecOut::Error(e) => return Err(io::Error::other(e)),
                }
            }
        }

        /// Streams output via callback, returns collected output.
        pub async fn stream(mut self, mut on: impl FnMut(&ExecOut)) -> io::Result<ExecOutput> {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                let msg = self.next_output().await?;
                on(&msg);
                match msg {
                    ExecOut::Stdout(d) => stdout.extend(d),
                    ExecOut::Stderr(d) => stderr.extend(d),
                    ExecOut::Exit {
                        code,
                        signal,
                        timed_out,
                        duration_ms,
                        error_message,
                    } => {
                        return Ok(ExecOutput {
                            exec_id: self.exec_id,
                            pid: self.pid,
                            stdout,
                            stderr,
                            code,
                            signal,
                            timed_out,
                            duration_ms,
                            error_message,
                        });
                    }
                    ExecOut::Error(e) => return Err(io::Error::other(e)),
                }
            }
        }
    }

    /// Stateless connection factory to a running guest agent.
    ///
    /// Each method opens a **dedicated connection**, sends a [`Hello`] message
    /// to identify the operation, and processes the response on that connection.
    /// Multiple operations can run concurrently without contention.
    #[derive(Debug, Clone)]
    pub struct Client {
        /// Socket path (Unix socket mapped from vsock by libkrun).
        socket_path: PathBuf,
    }

    impl Client {
        /// Creates a new client targeting the given Unix socket path.
        ///
        /// Does **not** connect immediately — connections are opened per-operation.
        pub fn new(path: impl Into<PathBuf>) -> Self {
            Self {
                socket_path: path.into(),
            }
        }

        /// Verifies connectivity and protocol version by opening a control
        /// connection and performing a handshake.
        pub async fn handshake(&self) -> io::Result<()> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::Control {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            match bux_proto::recv::<HelloAck>(&mut stream).await? {
                HelloAck::Control { version } if version == PROTOCOL_VERSION => Ok(()),
                HelloAck::Control { version } => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("protocol version mismatch: host={PROTOCOL_VERSION}, guest={version}"),
                )),
                HelloAck::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected Control ack",
                )),
            }
        }

        /// Requests graceful shutdown of the guest agent.
        pub async fn shutdown(&self) -> io::Result<()> {
            let mut stream = self.open_control().await?;
            bux_proto::send(&mut stream, &ControlReq::Shutdown).await?;
            match bux_proto::recv::<ControlResp>(&mut stream).await? {
                ControlResp::ShutdownOk => Ok(()),
                ControlResp::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected ShutdownOk",
                )),
            }
        }

        /// Pings the guest agent and returns agent metadata.
        pub async fn ping(&self) -> io::Result<PongInfo> {
            let mut stream = self.open_control().await?;
            bux_proto::send(&mut stream, &ControlReq::Ping).await?;
            match bux_proto::recv::<ControlResp>(&mut stream).await? {
                ControlResp::Pong { version, uptime_ms } => Ok(PongInfo { version, uptime_ms }),
                ControlResp::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected Pong")),
            }
        }

        /// Freezes all writable guest filesystems (FIFREEZE).
        pub async fn quiesce(&self) -> io::Result<u32> {
            let mut stream = self.open_control().await?;
            bux_proto::send(&mut stream, &ControlReq::Quiesce).await?;
            match bux_proto::recv::<ControlResp>(&mut stream).await? {
                ControlResp::QuiesceOk { frozen_count } => Ok(frozen_count),
                ControlResp::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected QuiesceOk",
                )),
            }
        }

        /// Thaws previously frozen guest filesystems (FITHAW).
        pub async fn thaw(&self) -> io::Result<u32> {
            let mut stream = self.open_control().await?;
            bux_proto::send(&mut stream, &ControlReq::Thaw).await?;
            match bux_proto::recv::<ControlResp>(&mut stream).await? {
                ControlResp::ThawOk { thawed_count } => Ok(thawed_count),
                ControlResp::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected ThawOk",
                )),
            }
        }

        /// Starts a command on a dedicated exec connection.
        ///
        /// Returns an [`ExecHandle`] for reading output and writing stdin.
        pub async fn exec(&self, req: ExecStart) -> io::Result<ExecHandle> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(&mut stream, &Hello::Exec(req)).await?;
            match bux_proto::recv::<HelloAck>(&mut stream).await? {
                HelloAck::ExecStarted { exec_id, pid } => {
                    let (reader, writer) = stream.into_split();
                    Ok(ExecHandle {
                        exec_id,
                        pid,
                        reader,
                        writer,
                    })
                }
                HelloAck::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected ExecStarted",
                )),
            }
        }

        /// Executes a command and collects all output.
        pub async fn exec_output(&self, req: ExecStart) -> io::Result<ExecOutput> {
            self.exec(req).await?.wait_with_output().await
        }

        /// Reads a file from the guest filesystem.
        pub async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::FileRead {
                    path: path.to_owned(),
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::recv_download(&mut stream).await
        }

        /// Writes a file to the guest filesystem.
        pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> io::Result<()> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::FileWrite {
                    path: path.to_owned(),
                    mode,
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::send_upload(&mut stream, data, STREAM_CHUNK_SIZE).await?;
            Self::expect_upload_ok(&mut stream).await
        }

        /// Copies a tar archive into the guest, unpacking at `dest`.
        pub async fn copy_in(&self, dest: &str, tar_data: &[u8]) -> io::Result<()> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::CopyIn {
                    dest: dest.to_owned(),
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::send_upload(&mut stream, tar_data, STREAM_CHUNK_SIZE).await?;
            Self::expect_upload_ok(&mut stream).await
        }

        /// Streams a tar archive from `reader` into the guest, unpacking at `dest`.
        ///
        /// Unlike [`copy_in`](Self::copy_in), this never loads the entire archive
        /// into memory — O(chunk_size) regardless of total size.
        pub async fn copy_in_from_reader(
            &self,
            dest: &str,
            reader: &mut (impl AsyncRead + Unpin),
        ) -> io::Result<()> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::CopyIn {
                    dest: dest.to_owned(),
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::send_upload_from_reader(&mut stream, reader, STREAM_CHUNK_SIZE).await?;
            Self::expect_upload_ok(&mut stream).await
        }

        /// Copies a path from the guest as a tar archive.
        pub async fn copy_out(&self, path: &str) -> io::Result<Vec<u8>> {
            self.copy_out_opts(path, false).await
        }

        /// Copies a path from the guest as a tar archive with options.
        pub async fn copy_out_opts(
            &self,
            path: &str,
            follow_symlinks: bool,
        ) -> io::Result<Vec<u8>> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::CopyOut {
                    path: path.to_owned(),
                    follow_symlinks,
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::recv_download(&mut stream).await
        }

        /// Streams a path from the guest as a tar archive directly to `writer`.
        ///
        /// Unlike [`copy_out`](Self::copy_out), this never loads the entire archive
        /// into memory — O(chunk_size) regardless of total size.
        pub async fn copy_out_to_writer(
            &self,
            path: &str,
            follow_symlinks: bool,
            writer: &mut (impl AsyncWrite + Unpin),
        ) -> io::Result<u64> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::CopyOut {
                    path: path.to_owned(),
                    follow_symlinks,
                },
            )
            .await?;
            Self::expect_ready(&mut stream).await?;
            bux_proto::recv_download_to_writer(&mut stream, writer).await
        }

        /// Returns the socket path this client targets.
        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        /// Opens a raw Unix socket connection to the guest agent.
        async fn connect_raw(&self) -> io::Result<UnixStream> {
            UnixStream::connect(&self.socket_path).await
        }

        /// Opens a control connection (Hello::Control + HelloAck::Control).
        async fn open_control(&self) -> io::Result<UnixStream> {
            let mut stream = self.connect_raw().await?;
            bux_proto::send(
                &mut stream,
                &Hello::Control {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            match bux_proto::recv::<HelloAck>(&mut stream).await? {
                HelloAck::Control { version } if version == PROTOCOL_VERSION => Ok(stream),
                HelloAck::Control { version } => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("protocol version mismatch: host={PROTOCOL_VERSION}, guest={version}"),
                )),
                HelloAck::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected Control ack",
                )),
            }
        }

        /// Expects a HelloAck::Ready response.
        async fn expect_ready(
            stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        ) -> io::Result<()> {
            match bux_proto::recv::<HelloAck>(stream).await? {
                HelloAck::Ready => Ok(()),
                HelloAck::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected Ready ack",
                )),
            }
        }

        /// Expects an UploadResult::Ok response.
        async fn expect_upload_ok(
            stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        ) -> io::Result<()> {
            match bux_proto::recv::<UploadResult>(stream).await? {
                UploadResult::Ok => Ok(()),
                UploadResult::Error(e) => Err(io::Error::other(e)),
            }
        }
    }
}

#[cfg(unix)]
pub use inner::{Client, ExecHandle, ExecOutput, PongInfo};
