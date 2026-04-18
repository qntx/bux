//! Network backend abstraction for bux micro-VMs.
//!
//! This crate layers the backend-neutral [`NetworkBackend`] trait on
//! top of platform primitives such as [`bux_gvproxy`]. Concrete
//! backends live under their own module:
//!
//! - [`GvproxyBackend`] — userspace `gvisor-tap-vsock` via the
//!   `bux-gvproxy` crate.
//!
//! Shared utilities:
//!
//! - [`SocketShortener`](socket::SocketShortener) — Unix socket
//!   `sun_path` length workaround via `/tmp` symlinks.
//!
//! Network-topology defaults (subnet, gateway/guest IP & MAC, MTU,
//! DNS search domains) live in [`bux_gvproxy::constants`] to keep a
//! single source of truth.
//!
//! # Quick start
//!
//! ```no_run
//! use bux_net::{GvproxyBackend, NetworkBackend, NetworkConfig};
//! use std::path::PathBuf;
//!
//! let config = NetworkConfig::new(
//!     vec![(8080, 80), (8443, 443)],
//!     PathBuf::from("/tmp/my-vm/net.sock"),
//! );
//!
//! let backend = GvproxyBackend::new(config)?;
//! let endpoint = backend.endpoint()?;
//! # Ok::<(), bux_net::NetError>(())
//! ```

pub mod backend;
pub mod error;
mod gvproxy_backend;
pub mod socket;

pub use backend::{ConnectionType, NetworkBackend, NetworkConfig, NetworkEndpoint, NetworkMetrics};
pub use error::{NetError, Result};
pub use gvproxy_backend::GvproxyBackend;
