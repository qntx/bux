//! `NetworkBackend` implementation backed by [`bux_gvproxy`].
//!
//! The raw FFI / Go toolchain lives in the `bux-gvproxy` crate. This
//! module just wires a [`GvproxyInstance`] to the backend-neutral
//! [`NetworkBackend`] trait.

use std::path::PathBuf;
use std::sync::Arc;

use bux_gvproxy::{GvproxyConfig, GvproxyInstance, NetworkStats, constants::GUEST_MAC, version};

use crate::backend::{
    ConnectionType, NetworkBackend, NetworkConfig, NetworkEndpoint, NetworkMetrics,
};
use crate::error::Result;

/// `gvisor-tap-vsock` network backend.
///
/// Holds an `Arc<GvproxyInstance>`, cheap to clone and share across
/// threads. The underlying Go resources are released once the last
/// reference is dropped.
#[derive(Debug, Clone)]
pub struct GvproxyBackend {
    /// RAII handle over the Go-side instance.
    instance: Arc<GvproxyInstance>,
    /// Unix socket path exposed to the VM engine.
    socket_path: PathBuf,
}

impl GvproxyBackend {
    /// Create a new gvproxy backend from a [`NetworkConfig`].
    ///
    /// Spawns a background stats-logging task that holds only a `Weak`
    /// reference, so it exits cleanly when the backend is dropped.
    ///
    /// # Errors
    ///
    /// Forwards any [`bux_gvproxy::Error`] from instance construction.
    pub fn new(config: NetworkConfig) -> Result<Self> {
        tracing::debug!(
            socket_path = ?config.socket_path,
            port_mappings = ?config.port_mappings,
            "creating gvisor-tap-vsock backend",
        );

        let gv_config = GvproxyConfig::new(config.socket_path.clone(), config.port_mappings);
        let instance = Arc::new(GvproxyInstance::new(&gv_config)?);

        bux_gvproxy::start_stats_logging(Arc::downgrade(&instance));

        let socket_path = config.socket_path;
        tracing::info!(
            ?socket_path,
            version = ?version().ok(),
            "created gvisor-tap-vsock backend"
        );

        Ok(Self {
            instance,
            socket_path,
        })
    }

    /// Live network statistics (wraps [`GvproxyInstance::get_stats`]).
    ///
    /// # Errors
    ///
    /// Forwards any FFI or JSON-decoding error from the Go side.
    pub fn get_stats(&self) -> Result<NetworkStats> {
        Ok(self.instance.get_stats()?)
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
