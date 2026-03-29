//! Structured crash diagnostics for the `bux-shim` process.
//!
//! When a shim crashes (signal, panic, or error), it writes an [`ExitInfo`]
//! JSON file that the host runtime reads to produce actionable error messages
//! instead of opaque timeouts.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Structured exit information written by the shim on crash.
///
/// Three variants cover the distinct failure modes:
/// - **Signal**: Process killed by OS signal (SIGABRT, SIGSEGV, …).
/// - **Panic**: Rust panic in the shim or libkrun.
/// - **Error**: Normal error returned from `Vm::start()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ExitInfo {
    /// Process killed by a signal.
    Signal {
        /// Unix convention: 128 + signal number.
        exit_code: i32,
        /// Signal name (e.g. `"SIGABRT"`).
        signal: String,
    },
    /// Rust panic occurred.
    Panic {
        /// Always 101 (Rust default panic exit code).
        exit_code: i32,
        /// Panic message payload.
        message: String,
        /// Source location (`file:line:col`).
        location: String,
    },
    /// Normal error from `Vm::start()` or config parsing.
    Error {
        /// Process exit code.
        exit_code: i32,
        /// Error description.
        message: String,
    },
}

impl ExitInfo {
    /// Reads exit info from a JSON file. Returns `None` if missing or invalid.
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Exit code regardless of variant.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Signal { exit_code, .. }
            | Self::Panic { exit_code, .. }
            | Self::Error { exit_code, .. } => *exit_code,
        }
    }

    /// Human-readable summary for error messages.
    pub fn summary(&self) -> String {
        match self {
            Self::Signal { signal, .. } => format!("killed by {signal}"),
            Self::Panic {
                message, location, ..
            } => format!("panic at {location}: {message}"),
            Self::Error { message, .. } => message.clone(),
        }
    }
}

/// Unix convention: exit code = 128 + signal number.
pub const SIGNAL_EXIT_BASE: i32 = 128;

/// Rust default panic exit code.
pub const PANIC_EXIT_CODE: i32 = 101;
