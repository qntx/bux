//! Error types for the gvproxy FFI layer.

/// Alias for `Result<T, bux_gvproxy::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the FFI wrappers and safe helpers in this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_gvproxy::Error`"
)]
pub enum Error {
    /// A call into the Go c-archive returned an error status or NULL
    /// pointer. The embedded message is taken from the Go side or
    /// constructed from the negative return code.
    #[error("gvproxy FFI error: {0}")]
    Ffi(String),

    /// Serialising or deserialising a config/stats JSON payload failed.
    #[error("gvproxy JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
