//! Error types for the safe `libkrun` wrapper layer.

/// Alias for `Result<T, bux_krun::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the safe [`libkrun`] wrapper.
///
/// [`libkrun`]: https://github.com/containers/libkrun
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; disambiguated via `bux_krun::Error`"
)]
pub enum Error {
    /// A `krun_*` FFI call returned a negative error code.
    ///
    /// `op` identifies the operation (e.g. `"set_vm_config"`) and
    /// `code` is the raw `errno`-style value returned by libkrun.
    #[error("krun call `{op}` failed with code {code}")]
    Krun {
        /// Short identifier of the failed `krun_*` call.
        op: &'static str,
        /// Raw negative status code from libkrun (typically an `-errno`).
        code: i32,
    },

    /// A Rust string handed to the FFI layer contained an interior NUL byte.
    #[error("argument contains an interior NUL byte: {0}")]
    InteriorNul(#[from] std::ffi::NulError),
}
