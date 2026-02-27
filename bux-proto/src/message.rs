//! Protocol message types for bux host↔guest communication.
//!
//! Each operation uses a **dedicated connection** (per-operation model):
//!
//! 1. Host opens a new vsock/Unix socket connection.
//! 2. Host sends a [`Hello`] identifying the operation type.
//! 3. Guest replies with [`HelloAck`].
//! 4. Both sides exchange operation-specific messages until completion.
//! 5. Connection closes when the operation completes.
//!
//! This eliminates multiplexing and allows concurrent operations without
//! contention.

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on every incompatible change.
pub const PROTOCOL_VERSION: u32 = 5;

/// Default chunk size for streaming transfers (1 MiB).
pub const STREAM_CHUNK_SIZE: usize = 1 << 20;

/// Maximum total upload size accepted by the guest agent (512 MiB).
pub const MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Default vsock port for the bux guest agent.
pub const AGENT_PORT: u32 = 1024;

/// First message on every new connection — identifies the operation type.
#[derive(Debug, Serialize, Deserialize)]
pub enum Hello {
    /// Open a control channel (ping, shutdown, quiesce, thaw).
    Control {
        /// Protocol version offered by the host.
        version: u32,
    },
    /// Execute a command on this connection.
    Exec(ExecStart),
    /// Read a single file from the guest (guest streams [`Download`] back).
    FileRead {
        /// Absolute path inside the guest.
        path: String,
    },
    /// Write a single file to the guest (host streams [`Upload`] in).
    FileWrite {
        /// Absolute path inside the guest.
        path: String,
        /// Unix permission mode (e.g. `0o644`).
        mode: u32,
    },
    /// Upload a tar archive and extract it at `dest`.
    CopyIn {
        /// Destination directory inside the guest.
        dest: String,
    },
    /// Download a path from the guest as a tar archive.
    CopyOut {
        /// Path inside the guest to archive.
        path: String,
        /// Follow symlinks when archiving (default: `false`).
        follow_symlinks: bool,
    },
}

/// Guest's acknowledgment after receiving [`Hello`].
#[derive(Debug, Serialize, Deserialize)]
pub enum HelloAck {
    /// Control channel accepted.
    Control {
        /// Protocol version supported by the guest agent.
        version: u32,
    },
    /// Exec process spawned successfully.
    ExecStarted {
        /// Unique execution identifier assigned by the guest.
        exec_id: String,
        /// Child process ID inside the guest.
        pid: i32,
    },
    /// File/copy operation ready to proceed.
    Ready,
    /// Operation rejected.
    Error(ErrorInfo),
}

/// Host → guest on a control connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ControlReq {
    /// Health check.
    Ping,
    /// Graceful shutdown of the guest agent.
    Shutdown,
    /// Freeze all writable filesystems (`FIFREEZE`).
    Quiesce,
    /// Thaw previously frozen filesystems (`FITHAW`).
    Thaw,
}

/// Guest → host on a control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlResp {
    /// Reply to [`ControlReq::Ping`].
    Pong {
        /// Guest agent version string.
        version: String,
        /// Milliseconds since the agent started.
        uptime_ms: u64,
    },
    /// Shutdown acknowledged — agent will exit imminently.
    ShutdownOk,
    /// Reply to [`ControlReq::Quiesce`]: number of filesystems frozen.
    QuiesceOk {
        /// Number of filesystems frozen.
        frozen_count: u32,
    },
    /// Reply to [`ControlReq::Thaw`]: number of filesystems thawed.
    ThawOk {
        /// Number of filesystems thawed.
        thawed_count: u32,
    },
    /// Control request failed.
    Error(ErrorInfo),
}

/// Command execution parameters, sent inside [`Hello::Exec`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStart {
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
    /// PTY configuration for interactive sessions.
    pub tty: Option<TtyConfig>,
    /// Kill the process after this many milliseconds (`0` = no timeout).
    pub timeout_ms: u64,
}

impl ExecStart {
    /// Creates a minimal exec request for the given command.
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
            tty: None,
            timeout_ms: 0,
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
    pub const fn user(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    /// Enables stdin piping from the host.
    #[must_use]
    pub const fn with_stdin(mut self) -> Self {
        self.stdin = true;
        self
    }

    /// Configures a PTY for interactive sessions.
    #[must_use]
    pub const fn tty(mut self, rows: u16, cols: u16) -> Self {
        self.tty = Some(TtyConfig {
            rows,
            cols,
            x_pixels: 0,
            y_pixels: 0,
        });
        self
    }

    /// Sets execution timeout in milliseconds.
    #[must_use]
    pub const fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

/// PTY dimensions for interactive terminal sessions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TtyConfig {
    /// Terminal height in rows.
    pub rows: u16,
    /// Terminal width in columns.
    pub cols: u16,
    /// Pixel width (optional, `0` if unknown).
    pub x_pixels: u16,
    /// Pixel height (optional, `0` if unknown).
    pub y_pixels: u16,
}

/// Host → guest messages on an exec connection (after [`HelloAck::ExecStarted`]).
#[derive(Debug, Serialize, Deserialize)]
pub enum ExecIn {
    /// Raw stdin data for the child process.
    Stdin(Vec<u8>),
    /// Close stdin (sends EOF to the child).
    StdinClose,
    /// Deliver a POSIX signal to the child.
    Signal(i32),
    /// Resize the PTY window.
    ResizeTty(TtyConfig),
}

/// Guest → host messages on an exec connection (after [`HelloAck::ExecStarted`]).
#[derive(Debug, Serialize, Deserialize)]
pub enum ExecOut {
    /// A chunk of stdout data.
    Stdout(Vec<u8>),
    /// A chunk of stderr data (empty in TTY mode — merged into stdout).
    Stderr(Vec<u8>),
    /// Process exited. Terminal message on the connection.
    Exit {
        /// Exit code (`0` = success).
        code: i32,
        /// Signal that killed the process, if any (e.g. `SIGKILL = 9`).
        signal: Option<i32>,
        /// `true` if `timeout_ms` fired and the agent killed the process.
        timed_out: bool,
        /// Wall-clock milliseconds from spawn to exit.
        duration_ms: u64,
        /// Diagnostic message when the process died unexpectedly.
        error_message: String,
    },
    /// Fatal error during execution (e.g. I/O failure on pipes).
    Error(ErrorInfo),
}

/// Host → guest data chunk for upload streams ([`Hello::FileWrite`], [`Hello::CopyIn`]).
#[derive(Debug, Serialize, Deserialize)]
pub enum Upload {
    /// A data chunk.
    Chunk(Vec<u8>),
    /// End of the upload stream.
    Done,
}

/// Guest → host reply after an upload completes.
#[derive(Debug, Serialize, Deserialize)]
pub enum UploadResult {
    /// Upload succeeded.
    Ok,
    /// Upload failed.
    Error(ErrorInfo),
}

/// Guest → host data chunk for download streams ([`Hello::FileRead`], [`Hello::CopyOut`]).
#[derive(Debug, Serialize, Deserialize)]
pub enum Download {
    /// A data chunk.
    Chunk(Vec<u8>),
    /// End of the download stream.
    Done,
    /// Error reading the requested path.
    Error(ErrorInfo),
}

/// Structured error with machine-readable code and human-readable message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Machine-readable error classification.
    pub code: ErrorCode,
    /// Human-readable error description.
    pub message: String,
}

impl ErrorInfo {
    /// Creates a new error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// Creates a not-found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// Creates an invalid-request error.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    /// Creates a permission-denied error.
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, message)
    }

    /// Creates a version-mismatch error.
    pub fn version_mismatch(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::VersionMismatch, message)
    }
}

impl std::fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorInfo {}

/// Machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Protocol version mismatch.
    VersionMismatch,
    /// Invalid request or argument.
    InvalidRequest,
    /// Resource not found.
    NotFound,
    /// Permission denied.
    PermissionDenied,
    /// Operation timed out.
    Timeout,
    /// Upload size limit exceeded.
    LimitExceeded,
    /// Internal guest agent error.
    Internal,
}
