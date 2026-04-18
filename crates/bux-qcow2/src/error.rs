//! Error types for QCOW2 operations.

use std::io;

/// Errors returned by QCOW2 operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate `Error` name; callers disambiguate with `bux_qcow2::Error`"
)]
pub enum Error {
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// File does not start with the QCOW2 magic bytes `QFI\xfb`.
    #[error("not a QCOW2 image (magic={magic:#010x}, expected={expected:#010x})")]
    InvalidMagic {
        /// The magic value actually read from the file.
        magic: u32,
        /// The expected QCOW2 magic value.
        expected: u32,
    },

    /// QCOW2 version is outside the supported range (v2, v3).
    #[error("unsupported QCOW2 version {0}")]
    UnsupportedVersion(u32),

    /// `cluster_bits` is outside the sane range `9..=30`.
    #[error("invalid cluster_bits {0} (must be 9..=30)")]
    InvalidClusterBits(u32),

    /// File is too small to contain a valid QCOW2 header.
    #[error("file too small for QCOW2 header")]
    TooSmall,

    /// Encountered a compressed cluster during `flatten`.
    /// Compression is not implemented.
    #[error("compressed QCOW2 clusters are not supported")]
    CompressedUnsupported,

    /// `flatten` was called on a non-QCOW2 file.
    #[error("source file is not a QCOW2 image")]
    NotQcow2,

    /// A string inside the QCOW2 file is not valid UTF-8.
    #[error("invalid UTF-8 in QCOW2 data")]
    InvalidUtf8,

    /// `qemu-img` binary was not found in `PATH`.
    #[error("qemu-img not found — install qemu-utils to enable this operation")]
    QemuImgNotFound,

    /// `qemu-img` exited with a non-zero status.
    #[error("qemu-img failed: {0}")]
    QemuImgFailed(String),
}

/// Result alias for QCOW2 operations.
pub type Result<T> = std::result::Result<T, Error>;
