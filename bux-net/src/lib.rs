//! Network backend abstraction and gvproxy integration for bux micro-VMs.
//!
//! This crate provides:
//!
//! - A [`NetworkBackend`] trait that engine code programs against.
//! - A concrete [`gvproxy::GvproxyBackend`] implementation using
//!   [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock)
//!   via a Go c-archive (CGO bridge).
//! - Shared network constants ([`constants`]) and a Unix socket path
//!   shortener ([`socket::SocketShortener`]).
//!
//! # Quick start
//!
//! ```no_run
//! use bux_net::{NetworkBackend, NetworkConfig, gvproxy::GvproxyBackend};
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
pub mod constants;
pub mod error;
pub mod gvproxy;
pub mod socket;

pub use backend::{
    ConnectionType, NetworkBackend, NetworkConfig, NetworkEndpoint, NetworkMetrics,
};
pub use error::{NetError, Result};
