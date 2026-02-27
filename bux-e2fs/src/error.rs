//! Error types for ext4 filesystem operations.

/// Errors returned by ext4 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A libext2fs function returned a non-zero error code.
    #[error("{op}: libext2fs error {code:#x}")]
    Ext2fs {
        /// Name of the libext2fs operation that failed.
        op: &'static str,
        /// The raw `errcode_t` value.
        code: i64,
    },

    /// A path could not be converted to a C string.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// An I/O error occurred outside of libext2fs.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
