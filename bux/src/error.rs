//! Error types for bux operations.
//!
//! Errors are classified into categories for programmatic handling:
//!
//! - **User errors**: invalid configuration, missing resources, ambiguous
//!   identifiers — the caller can fix these.
//! - **Retryable errors**: resource busy, guest agent unavailable — transient
//!   conditions that may resolve on retry.
//! - **System errors**: I/O failures, database errors, libkrun errors —
//!   infrastructure issues requiring operator attention.
//! - **Fatal errors**: the runtime has been shut down.

use std::ffi::NulError;

/// Alias for `Result<T, bux::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by bux VM operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ---- User errors (caller can fix) ----
    /// Invalid VM, runtime, or managed-guest configuration.
    #[error("{0}")]
    InvalidConfig(String),

    /// A VM or resource was not found.
    #[error("{0}")]
    NotFound(String),

    /// An ambiguous identifier matched multiple VMs.
    #[error("{0}")]
    Ambiguous(String),

    /// An operation was attempted in an invalid VM state.
    #[error("{0}")]
    InvalidState(String),

    // ---- Retryable errors (transient) ----
    /// A resource is currently busy (e.g. locked by another operation).
    #[error("{0}")]
    Busy(String),

    /// The guest agent is not yet reachable.
    #[error("guest agent unavailable")]
    GuestUnavailable,

    /// A quota limit would be exceeded.
    #[error("{0}")]
    QuotaExceeded(String),

    // ---- System errors (infrastructure) ----
    /// libkrun returned a negative error code.
    #[error("{op}: libkrun error code {code}")]
    Krun {
        /// The FFI operation that failed.
        op: &'static str,
        /// The negative error code returned by libkrun.
        code: i32,
    },

    /// A string argument contained an interior NUL byte.
    #[error("interior NUL byte in string argument")]
    Nul(#[from] NulError),

    /// An I/O error from runtime, client, or state operations.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Unix syscall error (via nix).
    #[cfg(unix)]
    #[error(transparent)]
    Nix(#[from] nix::errno::Errno),

    /// Ext4 filesystem image creation error.
    #[cfg(unix)]
    #[error(transparent)]
    E2fs(#[from] bux_e2fs::Error),

    /// OCI image operation error.
    #[cfg(unix)]
    #[error(transparent)]
    Oci(#[from] bux_oci::Error),

    /// SQLite database error.
    #[cfg(unix)]
    #[error(transparent)]
    Db(#[from] rusqlite::Error),

    /// JSON serialization error (for config stored in SQLite).
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    // ---- Fatal errors ----
    /// The runtime has been shut down; no new operations are accepted.
    #[error("runtime has been shut down")]
    Shutdown,
}

impl Error {
    /// Returns `true` if this is a user error that the caller can fix
    /// (invalid config, missing resource, wrong state).
    pub const fn is_user_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidConfig(_) | Self::NotFound(_) | Self::Ambiguous(_) | Self::InvalidState(_)
        )
    }

    /// Returns `true` if this is a transient error that may succeed on retry.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Busy(_) | Self::GuestUnavailable | Self::QuotaExceeded(_)
        )
    }

    /// Returns `true` if this is a fatal error (runtime shut down).
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Shutdown)
    }
}
