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
