//! Network types used by [`crate::GvproxyBackend`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ============================================================================
// Endpoint
// ============================================================================

/// How the VM engine should connect the guest to the network backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkEndpoint {
    /// Connect via a Unix domain socket.
    ///
    /// Used by gvproxy (`UnixStream` on Linux, `UnixDgram` on macOS).
    UnixSocket {
        /// Path to the Unix socket.
        path: PathBuf,
        /// Socket type expected by the backend.
        connection_type: ConnectionType,
        /// MAC address for the guest NIC — must match the static lease
        /// configured inside the backend (`GUEST_MAC`).
        mac_address: [u8; 6],
    },
}

/// Socket protocol flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConnectionType {
    /// `SOCK_STREAM` — gvproxy on Linux.
    UnixStream,
    /// `SOCK_DGRAM` — gvproxy on macOS (`VFKit` protocol).
    UnixDgram,
}

// ============================================================================
// Configuration
// ============================================================================

/// Network configuration passed to a concrete backend constructor.
///
/// Port mappings are always concrete `(host, guest)` pairs — ephemeral
/// host ports must be resolved by the Runtime before construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port mappings: `(host_port, guest_port)`. Always concrete values.
    pub port_mappings: Vec<(u16, u16)>,
    /// Unix socket path — must be unique per VM to avoid collisions.
    pub socket_path: PathBuf,
    /// Egress allow-list (hostnames / CIDRs). Empty = unrestricted egress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_net: Vec<String>,
    /// MITM secrets (placeholder → value). Empty = no MITM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<bux_gvproxy::SecretConfig>,
    /// PEM CA certificate when secrets non-empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_cert_pem: String,
    /// PEM CA private key when secrets non-empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_key_pem: String,
    /// When true, spawn background stats logging (opt-in; off by default).
    #[serde(default)]
    pub stats_logging: bool,
}

impl NetworkConfig {
    /// Creates a topology-only configuration (no `allow_net` / secrets).
    #[must_use]
    pub const fn new(port_mappings: Vec<(u16, u16)>, socket_path: PathBuf) -> Self {
        Self {
            port_mappings,
            socket_path,
            allow_net: Vec::new(),
            secrets: Vec::new(),
            ca_cert_pem: String::new(),
            ca_key_pem: String::new(),
            stats_logging: false,
        }
    }

    /// Sets egress allow-list rules.
    #[must_use]
    pub fn with_allow_net(mut self, allow_net: Vec<String>) -> Self {
        self.allow_net = allow_net;
        self
    }

    /// Attaches MITM secrets and CA PEMs.
    #[must_use]
    pub fn with_secrets(
        mut self,
        secrets: Vec<bux_gvproxy::SecretConfig>,
        ca_cert_pem: String,
        ca_key_pem: String,
    ) -> Self {
        self.secrets = secrets;
        self.ca_cert_pem = ca_cert_pem;
        self.ca_key_pem = ca_key_pem;
        self
    }

    /// Opt into background stats logging on the backend.
    #[must_use]
    pub const fn with_stats_logging(mut self, enabled: bool) -> Self {
        self.stats_logging = enabled;
        self
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "unit tests"
)]
mod tests {
    use super::*;

    #[test]
    fn network_config_defaults() {
        let c = NetworkConfig::new(vec![(8080, 80)], PathBuf::from("/tmp/n.sock"));
        assert!(c.allow_net.is_empty());
        assert!(c.secrets.is_empty());
        assert!(!c.stats_logging);
    }

    #[test]
    fn network_config_builder() {
        let c = NetworkConfig::new(vec![], PathBuf::from("/tmp/n.sock"))
            .with_allow_net(vec!["a.com".into()])
            .with_stats_logging(true);
        assert_eq!(c.allow_net, vec!["a.com".to_owned()]);
        assert!(c.stats_logging);
    }
}
