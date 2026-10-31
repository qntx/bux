//! Errors from shim config apply and boot.

/// Alias for `Result<T, bux_shim::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Engine / shim errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate Error; disambiguated via bux_shim::Error"
)]
pub enum Error {
    /// Invalid or incomplete configuration.
    #[error("{0}")]
    InvalidConfig(String),

    /// libkrun FFI failure.
    #[cfg(feature = "krun")]
    #[error(transparent)]
    Krun(#[from] bux_krun::Error),

    /// `BUX_LANDLOCK_FD` does not hold a file descriptor number.
    #[error("landlock: invalid BUX_LANDLOCK_FD: {0}")]
    InvalidLandlockFd(String),

    /// Landlock domain could not be entered (Linux fail-closed).
    #[error("landlock: cannot {action}: {source}")]
    Landlock {
        /// The step that failed.
        action: &'static str,
        /// Why it failed.
        source: std::io::Error,
    },

    /// Seccomp filter could not be installed (Linux fail-closed).
    #[error("seccomp: {0}")]
    Seccomp(String),

    /// I/O (config file, crash dump, …).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON (de)serialisation.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
