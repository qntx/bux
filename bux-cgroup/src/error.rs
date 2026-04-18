//! Error types for cgroup v2 operations.

use std::io;
use std::path::PathBuf;

/// Alias for `Result<T, bux_cgroup::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by cgroup v2 operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_cgroup::Error`"
)]
pub enum Error {
    /// Failed to create the cgroup directory.
    #[error("failed to create cgroup directory {path}: {source}")]
    CreateDir {
        /// The directory path that failed to be created.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Failed to write a cgroup control file.
    #[error("failed to write cgroup control file {path}: {source}")]
    WriteFile {
        /// The control file path (e.g. `cpu.max`, `memory.max`).
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Generic I/O error in cgroup plumbing.
    #[error(transparent)]
    Io(#[from] io::Error),
}
