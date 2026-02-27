//! Async host-side client for communicating with a bux guest agent.
//!
//! Connects via the Unix socket that libkrun maps from a vsock port.
//! Uses a persistent connection with interior mutability (`tokio::sync::Mutex`)
//! so all methods take `&self`.

#[cfg(unix)]
/// Platform-specific implementation (Unix only).
mod inner {
    use std::io;
    use std::path::Path;

    use bux_proto::{ExecReq, PROTOCOL_VERSION, Request, Response, STREAM_CHUNK_SIZE};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    /// Event emitted during streaming command execution.
    #[non_exhaustive]
    #[derive(Debug)]
    pub enum ExecEvent {
        /// Process spawned with the given PID.
        Started {
            /// Child process ID inside the guest.
            pid: i32,
        },
        /// A chunk of stdout data.
        Stdout(Vec<u8>),
        /// A chunk of stderr data.
        Stderr(Vec<u8>),
    }

    /// Output captured from a command executed inside the guest.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct ExecOutput {
        /// Child process ID inside the guest.
        pub pid: i32,
        /// Stdout bytes.
        pub stdout: Vec<u8>,
        /// Stderr bytes.
        pub stderr: Vec<u8>,
        /// Process exit code (`-1` if killed by signal).
        pub code: i32,
    }

    /// Async client connection to a running guest agent.
    ///
    /// Holds a persistent Unix socket connection. All methods take `&self`
    /// thanks to an internal `Mutex`.
    #[derive(Debug)]
    pub struct Client {
        /// Persistent connection to the guest agent.
        stream: Mutex<UnixStream>,
    }

    impl Client {
        /// Connects to a guest agent via its Unix socket path.
        pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
            let stream = UnixStream::connect(path).await?;
            Ok(Self {
                stream: Mutex::new(stream),
            })
        }

        /// Performs a version handshake with the guest agent.
        ///
        /// Verifies that the guest speaks the same major protocol version.
        pub async fn handshake(&self) -> io::Result<()> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::Handshake {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            match bux_proto::recv::<Response>(&mut *stream).await? {
                Response::Handshake { version } if version == PROTOCOL_VERSION => Ok(()),
                Response::Handshake { version } => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("protocol version mismatch: host={PROTOCOL_VERSION}, guest={version}"),
                )),
                Response::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected Handshake",
                )),
            }
        }

        /// Requests graceful shutdown of the guest agent.
        pub async fn shutdown(&self) -> io::Result<()> {
            self.send_expect(&Request::Shutdown, |r| matches!(r, Response::Ok))
                .await
        }

        /// Sends a signal to a process inside the guest.
        pub async fn signal(&self, pid: i32, signal: i32) -> io::Result<()> {
            self.send_expect(&Request::Signal { pid, signal }, |r| {
                matches!(r, Response::Ok)
            })
            .await
        }

        /// Executes a command, streaming output via callback. Returns exit code.
        ///
        /// The callback receives [`ExecEvent::Started`] first with the child PID,
        /// then zero or more [`ExecEvent::Stdout`]/[`ExecEvent::Stderr`] chunks.
        pub async fn exec_stream(
            &self,
            req: ExecReq,
            mut on: impl FnMut(ExecEvent),
        ) -> io::Result<i32> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(&mut *stream, &Request::Exec(req)).await?;
            loop {
                match bux_proto::recv::<Response>(&mut *stream).await? {
                    Response::Started { pid } => on(ExecEvent::Started { pid }),
                    Response::Stdout(d) => on(ExecEvent::Stdout(d)),
                    Response::Stderr(d) => on(ExecEvent::Stderr(d)),
                    Response::Exit(code) => return Ok(code),
                    Response::Error(e) => return Err(io::Error::other(e)),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected response",
                        ));
                    }
                }
            }
        }

        /// Executes a command and collects all output.
        pub async fn exec(&self, req: ExecReq) -> io::Result<ExecOutput> {
            let mut pid = 0i32;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = self
                .exec_stream(req, |event| match event {
                    ExecEvent::Started { pid: p } => pid = p,
                    ExecEvent::Stdout(d) => stdout.extend(d),
                    ExecEvent::Stderr(d) => stderr.extend(d),
                })
                .await?;
            Ok(ExecOutput {
                pid,
                stdout,
                stderr,
                code,
            })
        }

        /// Executes a command with stdin data piped to the process.
        ///
        /// Splits the stream internally so stdin writes and stdout/stderr
        /// reads proceed concurrently (avoids deadlock on large payloads).
        pub async fn exec_with_stdin(
            &self,
            mut req: ExecReq,
            stdin_data: &[u8],
            mut on: impl FnMut(ExecEvent),
        ) -> io::Result<i32> {
            req.stdin = true;
            let mut guard = self.stream.lock().await;
            bux_proto::send(&mut *guard, &Request::Exec(req)).await?;

            // Split for concurrent read/write to prevent deadlock.
            let (mut r, mut w) = tokio::io::split(&mut *guard);

            // First response must be Started.
            let pid: i32 = match bux_proto::recv::<Response>(&mut r).await? {
                Response::Started { pid } => {
                    on(ExecEvent::Started { pid });
                    pid
                }
                Response::Error(e) => return Err(io::Error::other(e)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected Started",
                    ));
                }
            };

            // Send stdin and read output concurrently.
            let stdin_buf = stdin_data.to_vec();
            let write_stdin = async {
                let _ = bux_proto::send(
                    &mut w,
                    &Request::Stdin {
                        pid,
                        data: stdin_buf,
                    },
                )
                .await;
                let _ = bux_proto::send(&mut w, &Request::StdinClose { pid }).await;
                let _ = w.flush().await;
            };

            let read_output = async {
                loop {
                    match bux_proto::recv::<Response>(&mut r).await? {
                        Response::Stdout(d) => on(ExecEvent::Stdout(d)),
                        Response::Stderr(d) => on(ExecEvent::Stderr(d)),
                        Response::Exit(code) => return io::Result::Ok(code),
                        Response::Error(e) => return Err(io::Error::other(e)),
                        _ => {}
                    }
                }
            };

            let ((), code) = tokio::join!(write_stdin, read_output);
            code
        }

        /// Reads a file from the guest filesystem (streamed in chunks).
        pub async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::ReadFile {
                    path: path.to_owned(),
                },
            )
            .await?;
            Self::recv_download_chunks(&mut *stream).await
        }

        /// Writes a file to the guest filesystem (streamed in chunks).
        pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> io::Result<()> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::WriteFile {
                    path: path.to_owned(),
                    mode,
                },
            )
            .await?;
            bux_proto::send_request_chunks(&mut *stream, data, STREAM_CHUNK_SIZE).await?;
            match bux_proto::recv::<Response>(&mut *stream).await? {
                Response::Ok => Ok(()),
                Response::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected response",
                )),
            }
        }

        /// Copies a tar archive into the guest, unpacking at `dest` (streamed in chunks).
        pub async fn copy_in(&self, dest: &str, tar_data: &[u8]) -> io::Result<()> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::CopyIn {
                    dest: dest.to_owned(),
                },
            )
            .await?;
            bux_proto::send_request_chunks(&mut *stream, tar_data, STREAM_CHUNK_SIZE).await?;
            match bux_proto::recv::<Response>(&mut *stream).await? {
                Response::Ok => Ok(()),
                Response::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected response",
                )),
            }
        }

        /// Copies a path from the guest as a tar archive (streamed in chunks).
        pub async fn copy_out(&self, path: &str) -> io::Result<Vec<u8>> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::CopyOut {
                    path: path.to_owned(),
                },
            )
            .await?;
            Self::recv_download_chunks(&mut *stream).await
        }

        /// Receives chunked download data (Chunk + EndOfStream) from the guest.
        async fn recv_download_chunks(
            stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        ) -> io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            loop {
                match bux_proto::recv::<Response>(stream).await? {
                    Response::Chunk(data) => buf.extend(data),
                    Response::EndOfStream => return Ok(buf),
                    Response::Error(e) => return Err(io::Error::other(e)),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expected Chunk or EndOfStream",
                        ));
                    }
                }
            }
        }

        /// Sends a request and expects a specific response variant.
        async fn send_expect(
            &self,
            req: &Request,
            ok: impl FnOnce(&Response) -> bool,
        ) -> io::Result<()> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(&mut *stream, req).await?;
            let resp: Response = bux_proto::recv(&mut *stream).await?;
            if ok(&resp) {
                Ok(())
            } else if let Response::Error(e) = resp {
                Err(io::Error::other(e))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected response",
                ))
            }
        }
    }
}

#[cfg(unix)]
pub use inner::{Client, ExecEvent, ExecOutput};
