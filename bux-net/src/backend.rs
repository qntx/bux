//! Network backend trait and associated types.
//!
//! The [`NetworkBackend`] trait defines the interface that all network
//! implementations (gvproxy, libslirp, passt, …) must satisfy.  Engine
//! code programs against this trait so that the concrete backend can be
//! swapped without touching VM lifecycle logic.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Result;

// ============================================================================
// NetworkBackend trait
// ============================================================================

/// Trait that every pluggable network backend must implement.
///
/// Implementations must be `Send + Sync` because the backend may be shared
/// across the runtime's async tasks and the shim child process.
pub trait NetworkBackend: Send + Sync + fmt::Debug {
    /// Returns the connection information the VM engine needs to wire
    /// the guest's virtio-net device to this backend.
    fn endpoint(&self) -> Result<NetworkEndpoint>;

    /// Human-readable backend name (e.g. `"gvisor-tap-vsock"`).
    fn name(&self) -> &'static str;

    /// Optional live network counters.
    ///
    /// Backends that don't support metrics return `Ok(None)`.
    fn metrics(&self) -> Result<Option<NetworkMetrics>> {
        Ok(None)
    }
}

// ============================================================================
// Endpoint
// ============================================================================

/// How the VM engine should connect the guest to the network backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkEndpoint {
    /// Connect via a Unix domain socket.
    ///
    /// Used by gvproxy, passt, libslirp, and socket_vmnet.
    UnixSocket {
        /// Path to the Unix socket.
        path: PathBuf,
        /// Socket type expected by the backend.
        connection_type: ConnectionType,
        /// MAC address for the guest NIC — must match the DHCP static
        /// lease configured inside the backend.
        mac_address: [u8; 6],
    },
}

/// Socket protocol flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConnectionType {
    /// `SOCK_STREAM` — passt, socket_vmnet, libslirp, gvproxy on Linux.
    UnixStream,
    /// `SOCK_DGRAM` — gvproxy on macOS (VFKit protocol).
    UnixDgram,
}

// ============================================================================
// Configuration
// ============================================================================

/// Minimal, backend-agnostic network configuration.
///
/// Callers fill this in and pass it to a concrete backend constructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port mappings: `(host_port, guest_port)`.
    pub port_mappings: Vec<(u16, u16)>,
    /// Unix socket path — must be unique per VM to avoid collisions.
    pub socket_path: PathBuf,
}

impl NetworkConfig {
    /// Creates a new configuration.
    pub fn new(port_mappings: Vec<(u16, u16)>, socket_path: PathBuf) -> Self {
        Self {
            port_mappings,
            socket_path,
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Snapshot of live network counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkMetrics {
    /// Total bytes sent from host to guest.
    pub bytes_sent: u64,
    /// Total bytes received from guest to host.
    pub bytes_received: u64,
    /// Current TCP connections in `ESTABLISHED` state.
    pub tcp_connections: Option<u64>,
    /// Total failed TCP connection attempts.
    pub tcp_connection_errors: Option<u64>,
}
