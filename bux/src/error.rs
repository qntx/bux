//! Error types for bux operations.

use std::ffi::NulError;

/// Alias for `Result<T, bux::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by bux VM operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// libkrun returned a negative error code.
    #[error("{op}: libkrun error code {code}")]
    Krun {
        /// The FFI operation that failed.
        op: &'static str,
        /// The negative error code returned by libkrun.
        code: i32,
    },

    /// A string argument contained an interior NUL byte.
    #[error("interior NUL byte in string argument")]
    Nul(#[from] NulError),

    /// An I/O error from runtime, client, or state operations.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A VM or resource was not found.
    #[error("{0}")]
    NotFound(String),

    /// An ambiguous identifier matched multiple VMs.
    #[error("{0}")]
    Ambiguous(String),

    /// SQLite database error.
    #[cfg(unix)]
    #[error(transparent)]
    Db(#[from] rusqlite::Error),

    /// JSON serialization error (for config stored in SQLite).
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
