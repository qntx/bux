//! Safe Rust wrapper over [gvisor-tap-vsock] (gvproxy), packaged as the
//! L1 platform primitive `bux-gvproxy`.
//!
//! This crate owns the Go toolchain integration (via `build.rs`),
//! `libgvproxy.a` static linkage, and the raw `extern "C"` FFI. On top
//! of that it exposes a small, safe surface:
//!
//! - [`GvproxyConfig`] — the JSON payload the Go side consumes (topology,
//!   `allow_net`, secrets, CA PEMs).
//! - [`ca`] — ephemeral MITM CA minting (`rcgen`).
//! - [`GvproxyInstance`] — RAII handle owning the Go-side resources.
//! - [`NetworkStats`] / [`TcpStats`] — live counters decoded from JSON.
//! - [`init_logging`] — Go `slog` → Rust `tracing` bridge (idempotent).
//!
//! `bux-shim-bin` constructs [`GvproxyInstance`] in-process. This crate
//! does not depend on any bux trait so it remains independently usable.
//!
//! [gvisor-tap-vsock]: https://github.com/containers/gvisor-tap-vsock
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::PathBuf;
//! use bux_gvproxy::{GvproxyConfig, GvproxyInstance};
//!
//! let config = GvproxyConfig::new(
//!     PathBuf::from("/tmp/my-vm/net.sock"),
//!     vec![(8080, 80), (8443, 443)],
//! );
//! let instance = GvproxyInstance::new(&config)?;
//! let stats = instance.get_stats()?;
//! eprintln!("bytes sent: {}", stats.bytes_sent);
//! # Ok::<(), bux_gvproxy::Error>(())
//! ```

pub mod ca;
pub mod config;
pub mod constants;
mod error;
mod ffi;
mod instance;
mod logging;
pub mod stats;

pub use ca::{MitmCa, generate as generate_mitm_ca};
pub use config::{DnsZone, GvproxyConfig, PortMapping, SecretConfig};
pub use error::{Error, Result};
pub use instance::{GvproxyInstance, start_stats_logging};
pub use logging::init as init_logging;
pub use stats::{NetworkStats, TcpStats};

/// Returns the `libgvproxy` c-archive version string.
///
/// # Errors
///
/// Returns [`Error::Ffi`] if the Go side returns a NULL pointer or the
/// version string is not valid UTF-8.
pub fn version() -> Result<String> {
    ffi::get_version()
}
