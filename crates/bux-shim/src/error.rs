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
    #[error(transparent)]
    Krun(#[from] bux_krun::Error),

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
