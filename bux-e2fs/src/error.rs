//! Error types for ext4 filesystem operations.

use std::ffi::NulError;

/// Errors returned by ext4 operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A libext2fs function returned a non-zero error code.
    #[error("libext2fs {op} failed (errcode {code})")]
    Ext2fs {
        /// Name of the libext2fs operation that failed.
        op: &'static str,
        /// The raw `errcode_t` value.
        code: i64,
    },

    /// A path contained an interior NUL byte.
    #[error("path contains interior NUL byte: {0}")]
    Nul(#[from] NulError),

    /// A path was not valid UTF-8.
    #[error("path is not valid UTF-8")]
    InvalidPath,

    /// An I/O error occurred outside of libext2fs.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
