//! bux guest agent — runs inside a micro-VM, typically as PID 1.
//!
//! Listens on a vsock port and executes commands received from the host
//! via the [`bux_proto`] wire protocol.
#![allow(unsafe_code, clippy::print_stderr)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bux-guest only runs inside a Linux micro-VM");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    agent::run()
}

#[cfg(target_os = "linux")]
mod agent {
    use std::fs::File;
    use std::io::{self, BufReader, BufWriter};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;

    use bux_proto::{AGENT_PORT, ExecReq, Request, Response};

    /// Entry point for the guest agent.
    pub(crate) fn run() -> io::Result<()> {
        // PID 1 duty: auto-reap zombie children.
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }

        let listener = vsock_bind(AGENT_PORT)?;
        eprintln!("[bux-guest] listening on vsock port {AGENT_PORT}");

        loop {
            let stream = vsock_accept(&listener)?;
            std::thread::spawn(move || {
                if let Err(e) = session(stream) {
                    eprintln!("[bux-guest] session error: {e}");
                }
            });
        }
    }

    /// Handles a single host connection: read requests, dispatch, respond.
    fn session(fd: OwnedFd) -> io::Result<()> {
        // Clone the fd so reader and writer operate independently.
        let read_file = unsafe { File::from_raw_fd(libc::dup(fd.as_raw_fd())) };
        let write_file = File::from(fd);
        let mut r = BufReader::new(read_file);
        let mut w = BufWriter::new(write_file);

        loop {
            let req: Request = match bux_proto::decode(&mut r) {
                Ok(req) => req,
                // Clean disconnect.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };

            match req {
                Request::Exec(exec) => exec_cmd(&mut w, exec)?,
                Request::Ping => bux_proto::encode(&mut w, &Response::Pong)?,
                Request::Signal { pid, signal } => {
                    unsafe {
                        libc::kill(pid as i32, signal);
                    }
                    bux_proto::encode(&mut w, &Response::Ok)?;
                }
                Request::ReadFile { path } => read_file(&mut w, &path)?,
                Request::WriteFile { path, data, mode } => {
                    write_file(&mut w, &path, &data, mode)?;
                }
                Request::Shutdown => {
                    bux_proto::encode(&mut w, &Response::Ok)?;
                    std::process::exit(0);
                }
            }
        }
    }

    /// Spawns a child process, captures its output, and streams it back.
    fn exec_cmd(w: &mut impl io::Write, req: ExecReq) -> io::Result<()> {
        let mut cmd = Command::new(&req.cmd);
        cmd.args(&req.args);

        if let Some(ref cwd) = req.cwd {
            cmd.current_dir(cwd);
        }
        for pair in &req.env {
            if let Some((k, v)) = pair.split_once('=') {
                cmd.env(k, v);
            }
        }

        match cmd.output() {
            Ok(out) => {
                if !out.stdout.is_empty() {
                    bux_proto::encode(w, &Response::Stdout(out.stdout))?;
                }
                if !out.stderr.is_empty() {
                    bux_proto::encode(w, &Response::Stderr(out.stderr))?;
                }
                bux_proto::encode(w, &Response::Exit(out.status.code().unwrap_or(-1)))
            }
            Err(e) => bux_proto::encode(w, &Response::Error(e.to_string())),
        }
    }

    /// Reads a file and sends its contents back to the host.
    fn read_file(w: &mut impl io::Write, path: &str) -> io::Result<()> {
        match std::fs::read(path) {
            Ok(data) => bux_proto::encode(w, &Response::FileData(data)),
            Err(e) => bux_proto::encode(w, &Response::Error(e.to_string())),
        }
    }

    /// Writes data to a file with the specified permission mode.
    fn write_file(w: &mut impl io::Write, path: &str, data: &[u8], mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let result = (|| -> io::Result<()> {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, data)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
            Ok(())
        })();

        match result {
            Ok(()) => bux_proto::encode(w, &Response::Ok),
            Err(e) => bux_proto::encode(w, &Response::Error(e.to_string())),
        }
    }

    /// Creates a vsock listener bound to `port`.
    fn vsock_bind(port: u32) -> io::Result<OwnedFd> {
        unsafe {
            let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let sock = OwnedFd::from_raw_fd(fd);

            let mut addr: libc::sockaddr_vm = std::mem::zeroed();
            addr.svm_family = libc::AF_VSOCK as u16;
            addr.svm_cid = libc::VMADDR_CID_ANY;
            addr.svm_port = port;

            if libc::bind(
                sock.as_raw_fd(),
                std::ptr::from_ref(&addr).cast(),
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }

            if libc::listen(sock.as_raw_fd(), 8) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(sock)
        }
    }

    /// Accepts one connection from a vsock listener.
    fn vsock_accept(listener: &OwnedFd) -> io::Result<OwnedFd> {
        unsafe {
            let fd = libc::accept(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }
}
