//! Network-specific error types.

/// Errors from network backend operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// A gvproxy FFI or config-serialisation error bubbled up from the
    /// [`bux_gvproxy`] crate.
    #[error(transparent)]
    Gvproxy(#[from] bux_gvproxy::Error),

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
