//! Error types for bubblewrap command construction.

/// Alias for `Result<T, bux_bwrap::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the [`crate::BwrapCommand`] builder.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_bwrap::Error`"
)]
pub enum Error {
    /// The `bwrap` binary could not be located via any of the search
    /// strategies used by [`crate::path`].
    #[error("bwrap binary not found (bubblewrap may not be installed on this system)")]
    NotFound,
}
