//! Async host-side client for communicating with a bux guest agent.
//!
//! Connects via the Unix socket that libkrun maps from a vsock port.
//! Uses a persistent connection with interior mutability (`tokio::sync::Mutex`)
//! so all methods take `&self`.

#[cfg(unix)]
mod inner {
    use std::io;
    use std::path::Path;

    use bux_proto::{ExecReq, Request, Response};
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    /// Event emitted during streaming command execution.
    #[derive(Debug)]
    pub enum ExecEvent {
        /// A chunk of stdout data.
        Stdout(Vec<u8>),
        /// A chunk of stderr data.
        Stderr(Vec<u8>),
    }

    /// Output captured from a command executed inside the guest.
    #[derive(Debug)]
    pub struct ExecOutput {
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

        /// Sends a ping and waits for a pong.
        pub async fn ping(&self) -> io::Result<()> {
            self.send_expect(&Request::Ping, |r| matches!(r, Response::Pong))
                .await
        }

        /// Requests graceful shutdown of the guest agent.
        pub async fn shutdown(&self) -> io::Result<()> {
            self.send_expect(&Request::Shutdown, |r| matches!(r, Response::Ok))
                .await
        }

        /// Sends a signal to a process inside the guest.
        pub async fn signal(&self, pid: u32, signal: i32) -> io::Result<()> {
            self.send_expect(&Request::Signal { pid, signal }, |r| {
                matches!(r, Response::Ok)
            })
            .await
        }

        /// Executes a command, streaming output via callback. Returns exit code.
        pub async fn exec_stream(
            &self,
            req: ExecReq,
            mut on: impl FnMut(ExecEvent),
        ) -> io::Result<i32> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(&mut *stream, &Request::Exec(req)).await?;
            loop {
                match bux_proto::recv::<Response>(&mut *stream).await? {
                    Response::Stdout(d) => on(ExecEvent::Stdout(d)),
                    Response::Stderr(d) => on(ExecEvent::Stderr(d)),
                    Response::Exit(code) => return Ok(code),
                    Response::Error(e) => {
                        return Err(io::Error::other(e));
                    }
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
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = self
                .exec_stream(req, |event| match event {
                    ExecEvent::Stdout(d) => stdout.extend(d),
                    ExecEvent::Stderr(d) => stderr.extend(d),
                })
                .await?;
            Ok(ExecOutput {
                stdout,
                stderr,
                code,
            })
        }

        /// Reads a file from the guest filesystem.
        pub async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
            let mut stream = self.stream.lock().await;
            bux_proto::send(
                &mut *stream,
                &Request::ReadFile {
                    path: path.to_owned(),
                },
            )
            .await?;
            match bux_proto::recv::<Response>(&mut *stream).await? {
                Response::FileData(data) => Ok(data),
                Response::Error(e) => Err(io::Error::other(e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected response",
                )),
            }
        }

        /// Writes a file to the guest filesystem.
        pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> io::Result<()> {
            self.send_expect(
                &Request::WriteFile {
                    path: path.to_owned(),
                    data: data.to_vec(),
                    mode,
                },
                |r| matches!(r, Response::Ok),
            )
            .await
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
