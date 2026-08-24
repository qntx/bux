//! gvproxy virtio-net for bux micro-VMs.
//!
//! [`GvproxyBackend`] wraps [`bux_gvproxy`]. Shared utilities:
//!
//! - [`SocketShortener`](socket::SocketShortener) — Unix socket
//!   `sun_path` length workaround via `/tmp` symlinks.
//!
//! Network-topology defaults (subnet, gateway/guest IP & MAC, MTU,
//! DNS search domains) live in [`bux_gvproxy::constants`].
//!
//! # Quick start
//!
//! ```no_run
//! use bux_net::{GvproxyBackend, NetworkConfig};
//! use std::path::PathBuf;
//!
//! let config = NetworkConfig::new(
//!     vec![(8080, 80), (8443, 443)],
//!     PathBuf::from("/tmp/my-vm/net.sock"),
//! )
//! .with_allow_net(vec!["example.com".into()]);
//!
//! let backend = GvproxyBackend::new(config)?;
//! let endpoint = backend.endpoint();
//! # Ok::<(), bux_net::NetError>(())
//! ```

pub mod backend;
pub mod error;
mod gvproxy_backend;
pub mod socket;

pub use backend::{ConnectionType, NetworkConfig, NetworkEndpoint, NetworkMetrics};
pub use error::{NetError, Result};
pub use gvproxy_backend::GvproxyBackend;
// Re-export secret/CA types so callers need not depend on bux-gvproxy directly.
pub use bux_gvproxy::{MitmCa, SecretConfig, generate_mitm_ca};
