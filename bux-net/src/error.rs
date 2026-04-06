//! Network-specific error types.

/// Errors from network backend operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// FFI call returned an error or NULL pointer.
    #[error("gvproxy FFI error: {0}")]
    Ffi(String),

    /// JSON serialization / deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration is invalid.
    #[error("invalid network config: {0}")]
    Config(String),

    /// Socket path exceeds the `sun_path` limit.
    #[error("socket path too long: {0}")]
    SocketPath(String),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for unexpected failures.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, NetError>;
