//! Error types for seccomp filter operations.

use std::io;

/// Alias for `Result<T, bux_seccomp::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by seccomp filter construction and installation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_seccomp::Error`"
)]
pub enum Error {
    /// The filter exceeds the kernel's `BPF_MAXINSNS` limit (4096).
    #[error("seccomp filter too large ({0} instructions, max 4096)")]
    FilterTooLarge(usize),

    /// `prctl(PR_SET_NO_NEW_PRIVS)` failed. Without this flag set to 1,
    /// the unprivileged `seccomp` syscall returns `EACCES`.
    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivs(#[source] io::Error),

    /// The kernel rejected the filter during
    /// `seccomp(SECCOMP_SET_MODE_FILTER, …)`.
    #[error("seccomp filter installation failed: {0}")]
    Install(#[source] io::Error),

    /// Thread synchronisation via `SECCOMP_FILTER_FLAG_TSYNC` failed.
    /// The value is the TID of the thread that could not be synced.
    #[error("seccomp TSYNC failed for thread {0}")]
    TsyncFailed(i64),
}
