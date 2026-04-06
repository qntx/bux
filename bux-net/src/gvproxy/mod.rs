//! gvisor-tap-vsock network backend.
//!
//! This module provides a userspace network backend using
//! [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock)
//! (from the Podman project), integrated via a Go c-archive (CGO bridge).
//!
//! # Module structure
//!
//! - [`config`] — [`GvproxyConfig`] serialised to JSON and sent to Go.
//! - [`ffi`] — Raw `extern "C"` declarations + safe wrappers.
//! - [`instance`] — [`GvproxyInstance`] with RAII resource management.
//! - [`logging`] — Go logrus → Rust tracing bridge.
//! - [`stats`] — [`NetworkStats`] / [`TcpStats`] deserialised from JSON.
//! - [`GvproxyBackend`] — [`NetworkBackend`](crate::NetworkBackend) implementation (this file).
//!
//! # Platform-specific behaviour
//!
//! - **macOS**: VFKit protocol with `UnixDgram` sockets (`SOCK_DGRAM`).
//! - **Linux**: Qemu protocol with `UnixStream` sockets (`SOCK_STREAM`).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ Rust                                                         │
//! │  ┌─────────────────┐    ┌────────────────┐                   │
//! │  │ GvproxyBackend   │──▶│ GvproxyInstance │                  │
//! │  └─────────────────┘    └───────┬────────┘                   │
//! │                                 │                            │
//! │  ┌──────────┐       ┌──────────▼──────────┐                  │
//! │  │ tracing  │◀──────│ logging::log_callback│                 │
//! │  └──────────┘       └─────────────────────┘                  │
//! │                              ▲                               │
//! ├──────────────────────────────┼───────────────────────────────┤
//! │ FFI (CGO)                    │                               │
//! ├──────────────────────────────┼───────────────────────────────┤
//! │ Go                           │                               │
//! │  ┌───────────────────┐  ┌────┴────────────────┐              │
//! │  │ gvisor-tap-vsock  │  │ RustTracingLogrusHook│             │
//! │  └───────────────────┘  └─────────────────────┘              │
//! └──────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub(crate) mod ffi;
pub mod instance;
pub mod logging;
pub mod stats;

use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::{
    ConnectionType, NetworkBackend, NetworkConfig, NetworkEndpoint, NetworkMetrics,
};
use crate::constants::GUEST_MAC;
use crate::error::Result;

pub use config::{DnsZone, GvproxyConfig, PortMapping};
pub use instance::GvproxyInstance;
pub use stats::{NetworkStats, TcpStats};

/// gvisor-tap-vsock network backend with integrated Go→Rust logging.
///
/// Holds an `Arc<GvproxyInstance>` — cheap to clone and share across
/// threads.  The Go-side instance is automatically cleaned up when
/// the last reference is dropped.
#[derive(Debug, Clone)]
pub struct GvproxyBackend {
    /// The gvproxy instance.
    instance: Arc<GvproxyInstance>,
    /// Socket path for cross-process communication.
    socket_path: PathBuf,
}

impl GvproxyBackend {
    /// Creates a new gvproxy backend from a [`NetworkConfig`].
    ///
    /// Initialises the Go c-archive, creates the virtual network, and
    /// starts background stats logging.
    pub fn new(config: NetworkConfig) -> Result<Self> {
        tracing::debug!(
            socket_path = ?config.socket_path,
            port_mappings = ?config.port_mappings,
            "creating gvisor-tap-vsock backend",
        );

        let instance = Arc::new(GvproxyInstance::new(
            config.socket_path.clone(),
            &config.port_mappings,
        )?);

        // Background stats logging (holds only a Weak ref).
        instance::start_stats_logging(Arc::downgrade(&instance));

        let socket_path = config.socket_path;

        tracing::info!(
            ?socket_path,
            version = ?ffi::get_version().ok(),
            "created gvisor-tap-vsock backend"
        );

        Ok(Self {
            instance,
            socket_path,
        })
    }

    /// Returns live network statistics.
    pub fn get_stats(&self) -> Result<NetworkStats> {
        self.instance.get_stats()
    }
}

impl NetworkBackend for GvproxyBackend {
    fn endpoint(&self) -> Result<NetworkEndpoint> {
        let connection_type = if cfg!(target_os = "macos") {
            ConnectionType::UnixDgram
        } else {
            ConnectionType::UnixStream
        };

        Ok(NetworkEndpoint::UnixSocket {
            path: self.socket_path.clone(),
            connection_type,
            mac_address: GUEST_MAC,
        })
    }

    fn name(&self) -> &'static str {
        "gvisor-tap-vsock"
    }

    fn metrics(&self) -> Result<Option<NetworkMetrics>> {
        let stats = self.get_stats()?;
        Ok(Some(NetworkMetrics {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            tcp_connections: Some(stats.tcp.current_established),
            tcp_connection_errors: Some(stats.tcp.failed_connection_attempts),
        }))
    }
}

impl Drop for GvproxyBackend {
    fn drop(&mut self) {
        tracing::debug!(socket_path = ?self.socket_path, "dropping gvproxy backend");
    }
}
