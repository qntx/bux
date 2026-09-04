//! Error types for `bux-jail`.

/// Alias for `Result<T, bux_jail::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from sandbox spawn and isolation setup.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate Error name; disambiguated via bux_jail::Error"
)]
pub enum Error {
    /// Process spawn or related I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Landlock was requested but the kernel cannot enforce it (K22 fail-closed).
    ///
    /// Set [`crate::JailConfig::allow_degraded_security`] to proceed without Landlock.
    #[error(
        "landlock required but unavailable on this kernel (set allow_degraded_security to proceed)"
    )]
    LandlockUnavailable,

    /// Linux jailer is on but `bwrap` was not provided / could not wrap.
    #[error("bwrap required (jailer); install with: curl -fsSL https://sh.qntx.org/bux | sh")]
    BwrapUnavailable,

    /// Landlock ruleset construction failed (kernel error, not mere unavailability).
    #[error("landlock ruleset failed: {0}")]
    Landlock(String),
}
