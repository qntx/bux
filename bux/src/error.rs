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
#[allow(
    clippy::error_impl_error,
    reason = "Error is the crate's public error type"
)]
pub enum Error {
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

    /// A resource is currently busy (e.g. locked by another operation).
    #[error("{0}")]
    Busy(String),

    /// The guest agent is not yet reachable.
    #[error("guest agent unavailable")]
    GuestUnavailable,

    /// A quota limit would be exceeded.
    #[error("{0}")]
    QuotaExceeded(String),

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

    /// QCOW2 image operation error.
    #[cfg(unix)]
    #[error(transparent)]
    Qcow2(#[from] bux_qcow2::Error),

    /// cgroup v2 resource-limit error (Linux-only operations).
    #[cfg(unix)]
    #[error(transparent)]
    Cgroup(#[from] bux_cgroup::Error),

    /// Seccomp BPF filter error (Linux-only).
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Seccomp(#[from] bux_seccomp::Error),

    /// OCI image operation error.
    #[cfg(unix)]
    #[error(transparent)]
    Oci(#[from] bux_oci::OciError),

    /// `SQLite` database error.
    #[cfg(unix)]
    #[error(transparent)]
    Db(#[from] rusqlite::Error),

    /// JSON serialization error (for config stored in `SQLite`).
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The runtime has been shut down; no new operations are accepted.
    #[error("runtime has been shut down")]
    Shutdown,
}

impl Error {
    /// Returns `true` if this is a user error that the caller can fix
    /// (invalid config, missing resource, wrong state).
    #[must_use]
    pub const fn is_user_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidConfig(_) | Self::NotFound(_) | Self::Ambiguous(_) | Self::InvalidState(_)
        )
    }

    /// Returns `true` if this is a transient error that may succeed on retry.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Busy(_) | Self::GuestUnavailable | Self::QuotaExceeded(_)
        )
    }

    /// Returns `true` if this is a fatal error (runtime shut down).
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_errors() {
        assert!(Error::InvalidConfig("bad".into()).is_user_error());
        assert!(Error::NotFound("gone".into()).is_user_error());
        assert!(Error::Ambiguous("many".into()).is_user_error());
        assert!(Error::InvalidState("wrong".into()).is_user_error());

        assert!(!Error::InvalidConfig("bad".into()).is_retryable());
        assert!(!Error::InvalidConfig("bad".into()).is_fatal());
    }

    #[test]
    fn retryable_errors() {
        assert!(Error::Busy("locked".into()).is_retryable());
        assert!(Error::GuestUnavailable.is_retryable());
        assert!(Error::QuotaExceeded("disk".into()).is_retryable());

        assert!(!Error::GuestUnavailable.is_user_error());
        assert!(!Error::GuestUnavailable.is_fatal());
    }

    #[test]
    fn fatal_error() {
        assert!(Error::Shutdown.is_fatal());
        assert!(!Error::Shutdown.is_user_error());
        assert!(!Error::Shutdown.is_retryable());
    }

    #[test]
    fn system_errors_not_categorized() {
        let krun = Error::Krun {
            op: "create_ctx",
            code: -1,
        };
        assert!(!krun.is_user_error());
        assert!(!krun.is_retryable());
        assert!(!krun.is_fatal());
    }
}
