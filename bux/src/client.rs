//! Host-side client for communicating with a bux guest agent.
//!
//! Connects to the guest agent via the Unix socket that libkrun maps
//! from a vsock port (see [`krun_add_vsock_port2`]).

#[cfg(unix)]
mod inner {
    use std::io;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use bux_proto::{ExecReq, Request, Response};

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

    /// A client connection to a running guest agent.
    #[derive(Debug)]
    pub struct Client {
        /// The underlying Unix socket stream.
        stream: UnixStream,
    }

    impl Client {
        /// Connects to a guest agent via its Unix socket path.
        pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
            let stream = UnixStream::connect(path)?;
            Ok(Self { stream })
        }

        /// Sends a ping and waits for a pong.
        pub fn ping(&mut self) -> io::Result<()> {
            self.send_expect(&Request::Ping, |r| matches!(r, Response::Pong))
        }

        /// Requests graceful shutdown of the guest agent.
        pub fn shutdown(&mut self) -> io::Result<()> {
            self.send_expect(&Request::Shutdown, |r| matches!(r, Response::Ok))
        }

        /// Sends a signal to a process inside the guest.
        pub fn signal(&mut self, pid: u32, signal: i32) -> io::Result<()> {
            self.send_expect(&Request::Signal { pid, signal }, |r| {
                matches!(r, Response::Ok)
            })
        }

        /// Executes a command and collects all output.
        ///
        /// Blocks until the command exits. Stdout and stderr chunks are
        /// accumulated into [`ExecOutput`].
        pub fn exec(&mut self, req: ExecReq) -> io::Result<ExecOutput> {
            bux_proto::encode(&mut self.stream, &Request::Exec(req))?;

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            loop {
                match bux_proto::decode::<Response>(&mut self.stream)? {
                    Response::Stdout(d) => stdout.extend(d),
                    Response::Stderr(d) => stderr.extend(d),
                    Response::Exit(code) => {
                        return Ok(ExecOutput {
                            stdout,
                            stderr,
                            code,
                        });
                    }
                    Response::Error(e) => {
                        return Err(io::Error::new(io::ErrorKind::Other, e));
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

        /// Reads a file from the guest filesystem.
        pub fn read_file(&mut self, path: &str) -> io::Result<Vec<u8>> {
            bux_proto::encode(
                &mut self.stream,
                &Request::ReadFile {
                    path: path.to_owned(),
                },
            )?;
            match bux_proto::decode::<Response>(&mut self.stream)? {
                Response::FileData(data) => Ok(data),
                Response::Error(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected response",
                )),
            }
        }

        /// Writes a file to the guest filesystem.
        pub fn write_file(&mut self, path: &str, data: &[u8], mode: u32) -> io::Result<()> {
            self.send_expect(
                &Request::WriteFile {
                    path: path.to_owned(),
                    data: data.to_vec(),
                    mode,
                },
                |r| matches!(r, Response::Ok),
            )
        }

        /// Sends a request and expects a specific response variant.
        fn send_expect(
            &mut self,
            req: &Request,
            ok: impl FnOnce(&Response) -> bool,
        ) -> io::Result<()> {
            bux_proto::encode(&mut self.stream, req)?;
            let resp: Response = bux_proto::decode(&mut self.stream)?;
            if ok(&resp) {
                Ok(())
            } else if let Response::Error(e) = resp {
                Err(io::Error::new(io::ErrorKind::Other, e))
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
pub use inner::{Client, ExecOutput};
