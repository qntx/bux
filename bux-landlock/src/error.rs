//! Error types for Landlock ruleset construction.

use std::path::PathBuf;

/// Alias for `Result<T, bux_landlock::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the Linux-only `PathRestrictions::build` call
/// and related APIs.
///
/// Note that **absence of kernel support is not an error** — it is signalled
/// by `PathRestrictions::build` returning `Ok(None)`. This matches the
/// graceful-degradation pattern recommended by the kernel docs: Landlock
/// is a best-effort defence-in-depth layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_landlock::Error`"
)]
pub enum Error {
    /// The underlying `landlock` crate returned a ruleset error while
    /// constructing or finalising the filter.
    #[error("landlock ruleset failed during {context}: {message}")]
    Ruleset {
        /// Short human description of the step that failed, e.g.
        /// `"handle filesystem access"` or `"add rule for /foo"`.
        context: String,
        /// The underlying error rendered via `Display`.
        message: String,
    },

    /// A caller-supplied path could not be opened for rule insertion.
    /// The path is retained for diagnostics but never leaks file descriptors.
    #[error("landlock: cannot open path {path}: {source}")]
    PathOpen {
        /// The path that could not be resolved to a file descriptor.
        path: PathBuf,
        /// Underlying I/O error from `open(2)`.
        #[source]
        source: std::io::Error,
    },
}
