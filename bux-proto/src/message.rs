//! Protocol message types for host↔guest communication.

use serde::{Deserialize, Serialize};

/// Default vsock port for the bux guest agent.
pub const AGENT_PORT: u32 = 1024;

/// Request sent from host to guest.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Request {
    /// Execute a command inside the guest.
    Exec(ExecReq),
    /// Send a POSIX signal to a running process.
    Signal {
        /// Target process ID.
        pid: u32,
        /// Signal number (e.g. `libc::SIGTERM`).
        signal: i32,
    },
    /// Health-check ping.
    Ping,
    /// Request graceful shutdown of the guest agent.
    Shutdown,
}

/// Command execution request.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecReq {
    /// Executable path or name.
    pub cmd: String,
    /// Command-line arguments (excluding argv\[0\]).
    pub args: Vec<String>,
    /// Environment variables in `KEY=VALUE` format.
    pub env: Vec<String>,
    /// Working directory inside the guest.
    pub cwd: Option<String>,
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
}

/// Response sent from guest to host.
///
/// For [`Request::Exec`], the guest streams zero or more [`Response::Stdout`]
/// / [`Response::Stderr`] chunks followed by exactly one [`Response::Exit`].
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Response {
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
    /// Acknowledgment for [`Request::Signal`] / [`Request::Shutdown`].
    Ok,
}
