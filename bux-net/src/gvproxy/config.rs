//! Gvproxy configuration structures.
//!
//! [`GvproxyConfig`] is serialized to JSON and passed across the FFI
//! boundary to the Go `gvproxy_create()` function.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::constants;

/// Local DNS zone served by the gateway's embedded DNS server.
///
/// Queries that don't match any zone are forwarded to the host's
/// system DNS resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    /// Zone name (e.g. `"myapp.local."`, `"."` for root).
    pub name: String,
    /// Default IP for unmatched queries in this zone.
    pub default_ip: String,
}

/// A single port mapping entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortMapping {
    /// Host port to bind.
    pub host_port: u16,
    /// Guest port to forward to.
    pub guest_port: u16,
}

/// Complete configuration for a gvproxy virtual-network instance.
///
/// All values are sent as JSON to the Go c-archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GvproxyConfig {
    /// Unix socket path for the network tap interface.
    pub socket_path: PathBuf,

    /// Virtual network subnet (e.g. `"192.168.127.0/24"`).
    pub subnet: String,

    /// Gateway IP address.
    pub gateway_ip: String,
    /// Gateway MAC address.
    pub gateway_mac: String,

    /// Guest IP address.
    pub guest_ip: String,
    /// Guest MAC address.
    pub guest_mac: String,

    /// MTU for the virtual network.
    pub mtu: u16,

    /// Port mappings.
    pub port_mappings: Vec<PortMapping>,

    /// Local DNS zones for the gateway's embedded DNS server.
    pub dns_zones: Vec<DnsZone>,

    /// DNS search domains.
    pub dns_search_domains: Vec<String>,

    /// Enable verbose logging in gvproxy.
    pub debug: bool,

    /// Optional pcap file for packet capture (debugging with Wireshark).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_file: Option<String>,
}

impl GvproxyConfig {
    /// Creates a new configuration with the given socket path and port
    /// mappings, using network defaults from [`constants`].
    pub fn new(socket_path: PathBuf, port_mappings: Vec<(u16, u16)>) -> Self {
        let mut config = Self {
            socket_path,
            subnet: constants::SUBNET.to_owned(),
            gateway_ip: constants::GATEWAY_IP.to_owned(),
            gateway_mac: constants::GATEWAY_MAC_STRING.to_owned(),
            guest_ip: constants::GUEST_IP.to_owned(),
            guest_mac: constants::GUEST_MAC_STRING.to_owned(),
            mtu: constants::DEFAULT_MTU,
            port_mappings: port_mappings
                .into_iter()
                .map(|(host_port, guest_port)| PortMapping {
                    host_port,
                    guest_port,
                })
                .collect(),
            dns_zones: Vec::new(),
            dns_search_domains: constants::DNS_SEARCH_DOMAINS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            debug: false,
            capture_file: None,
        };

        // Allow packet capture via environment variable.
        if let Ok(path) = std::env::var("BUX_NET_CAPTURE_FILE") {
            if !path.is_empty() {
                tracing::info!(path, "enabling packet capture from BUX_NET_CAPTURE_FILE");
                config.capture_file = Some(path);
                config.debug = true;
            }
        }

        config
    }

    /// Enable verbose debug logging.
    #[must_use]
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set custom DNS zones.
    #[must_use]
    pub fn with_dns_zones(mut self, zones: Vec<DnsZone>) -> Self {
        self.dns_zones = zones;
        self
    }

    /// Set custom MTU.
    #[must_use]
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enable packet capture to a pcap file.
    #[must_use]
    pub fn with_capture_file(mut self, path: String) -> Self {
        self.capture_file = Some(path);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_socket() -> PathBuf {
        PathBuf::from("/tmp/test-gvproxy.sock")
    }

    #[test]
    fn defaults() {
        let cfg = GvproxyConfig::new(test_socket(), vec![]);
        assert_eq!(cfg.subnet, "192.168.127.0/24");
        assert_eq!(cfg.gateway_ip, "192.168.127.1");
        assert_eq!(cfg.guest_ip, "192.168.127.2");
        assert_eq!(cfg.mtu, 1500);
        assert!(!cfg.debug);
    }

    #[test]
    fn port_mappings() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80), (8443, 443)]);
        assert_eq!(cfg.port_mappings.len(), 2);
        assert_eq!(cfg.port_mappings[0].host_port, 8080);
        assert_eq!(cfg.port_mappings[0].guest_port, 80);
    }

    #[test]
    fn builder_pattern() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80)])
            .with_debug(true)
            .with_mtu(9000);
        assert!(cfg.debug);
        assert_eq!(cfg.mtu, 9000);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80)]);
        let json = serde_json::to_string(&cfg).unwrap();
        let de: GvproxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.subnet, de.subnet);
        assert_eq!(cfg.socket_path, de.socket_path);
    }

    #[test]
    fn socket_path_in_json() {
        let cfg = GvproxyConfig::new(
            PathBuf::from("/data/bux/socks/vm-abc.sock"),
            vec![(8080, 80)],
        );
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("socket_path"));
        assert!(json.contains("/data/bux/socks/vm-abc.sock"));
    }

    #[test]
    fn different_sockets_produce_different_json() {
        let a = GvproxyConfig::new(PathBuf::from("/a/net.sock"), vec![(8080, 80)]);
        let b = GvproxyConfig::new(PathBuf::from("/b/net.sock"), vec![(8080, 80)]);
        assert_ne!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
