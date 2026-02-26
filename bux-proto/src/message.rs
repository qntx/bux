//! Protocol message types for host↔guest communication.

use serde::{Deserialize, Serialize};

/// Default vsock port for the bux guest agent.
pub const AGENT_PORT: u32 = 1024;

/// Request sent from host to guest.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Execute a command inside the guest.
    Exec(ExecReq),
    /// Write data to a running process's stdin.
    Stdin {
        /// Target process ID.
        pid: u32,
        /// Raw bytes to write.
        data: Vec<u8>,
    },
    /// Close a running process's stdin (sends EOF).
    StdinClose {
        /// Target process ID.
        pid: u32,
    },
    /// Send a POSIX signal to a running process.
    Signal {
        /// Target process ID.
        pid: u32,
        /// Signal number (e.g. `libc::SIGTERM`).
        signal: i32,
    },
    /// Read a single file from the guest filesystem.
    ReadFile {
        /// Absolute path inside the guest.
        path: String,
    },
    /// Write a single file to the guest filesystem.
    WriteFile {
        /// Absolute path inside the guest.
        path: String,
        /// File contents.
        data: Vec<u8>,
        /// Unix permission mode (e.g. `0o644`).
        mode: u32,
    },
    /// Copy a tar archive into the guest, unpacking at `dest`.
    CopyIn {
        /// Destination directory inside the guest.
        dest: String,
        /// Tar archive bytes.
        tar: Vec<u8>,
    },
    /// Copy a path from the guest as a tar archive.
    CopyOut {
        /// Path inside the guest to archive.
        path: String,
    },
    /// Health-check ping.
    Ping,
    /// Request graceful shutdown of the guest agent.
    Shutdown,
}

/// Command execution request.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecReq {
    /// Executable path or name.
    pub cmd: String,
    /// Command-line arguments (excluding argv\[0\]).
    pub args: Vec<String>,
    /// Environment variables in `KEY=VALUE` format.
    pub env: Vec<String>,
    /// Working directory inside the guest.
    pub cwd: Option<String>,
    /// Override UID for this execution.
    pub uid: Option<u32>,
    /// Override GID for this execution.
    pub gid: Option<u32>,
    /// Whether the host will send stdin data.
    pub stdin: bool,
}

impl ExecReq {
    /// Creates a new exec request for the given command.
    #[must_use]
    pub fn new(cmd: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            uid: None,
            gid: None,
            stdin: false,
        }
    }

    /// Sets the command-line arguments.
    #[must_use]
    pub fn args(mut self, args: impl Into<Vec<String>>) -> Self {
        self.args = args.into();
        self
    }

    /// Sets the environment variables.
    #[must_use]
    pub fn env(mut self, env: impl Into<Vec<String>>) -> Self {
        self.env = env.into();
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the UID and GID for execution.
    #[must_use]
    pub fn user(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    /// Enables stdin piping from the host.
    #[must_use]
    pub fn with_stdin(mut self) -> Self {
        self.stdin = true;
        self
    }
}

/// Response sent from guest to host.
///
/// For [`Request::Exec`], the guest first sends [`Response::Started`] with
/// the child PID, then streams [`Response::Stdout`] / [`Response::Stderr`]
/// chunks, and finally sends exactly one [`Response::Exit`].
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Process started with the given PID (for subsequent `Stdin`/`Signal`).
    Started {
        /// Child process ID inside the guest.
        pid: u32,
    },
    /// A chunk of stdout data.
    Stdout(Vec<u8>),
    /// A chunk of stderr data.
    Stderr(Vec<u8>),
    /// Process exited with the given code (`-1` if killed by signal).
    Exit(i32),
    /// An error occurred while handling the request.
    Error(String),
    /// Reply to [`Request::Ping`].
    Pong,
    /// File contents returned for [`Request::ReadFile`].
    FileData(Vec<u8>),
    /// Tar archive returned for [`Request::CopyOut`].
    TarData(Vec<u8>),
    /// Generic success acknowledgment.
    Ok,
}
