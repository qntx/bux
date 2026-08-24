//! Shared virtio-net topology (host gvproxy, guest static eth0, shim MAC).
//!
//! Single source of truth. Do not duplicate these values in guest or gvproxy.

use std::net::Ipv4Addr;

/// Virtual network subnet.
pub const SUBNET: &str = "192.168.127.0/24";

/// Gateway IPv4 (gvproxy). Also the guest DNS resolver.
pub const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);

/// Guest IPv4 (static on eth0).
pub const GUEST_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

/// Prefix length for [`GUEST_IPV4`].
pub const PREFIX_LEN: u8 = 24;

/// Gateway IP as a dotted string (JSON / resolv.conf).
pub const GATEWAY_IP: &str = "192.168.127.1";

/// Guest IP as a dotted string.
pub const GUEST_IP: &str = "192.168.127.2";

/// Guest address with CIDR prefix.
pub const GUEST_CIDR: &str = "192.168.127.2/24";

/// Guest virtio-net interface name.
pub const GUEST_INTERFACE: &str = "eth0";

/// Guest NIC MAC (must match libkrun `add_net_*` and gvproxy static lease).
pub const GUEST_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

/// Gateway MAC.
pub const GATEWAY_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd];

/// [`GUEST_MAC`] as a colon-separated hex string.
pub const GUEST_MAC_STRING: &str = "5a:94:ef:e4:0c:ee";

/// [`GATEWAY_MAC`] as a colon-separated hex string.
pub const GATEWAY_MAC_STRING: &str = "5a:94:ef:e4:0c:dd";

/// Default MTU.
pub const DEFAULT_MTU: u16 = 1500;

/// DNS server IP (gateway).
pub const DNS_SERVER_IP: &str = GATEWAY_IP;

/// Default DNS search domains.
pub const DNS_SEARCH_DOMAINS: &[&str] = &["local"];

/// Format a 6-byte MAC as colon-separated hex.
#[must_use]
pub fn mac_to_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn mac_strings_match_bytes() {
        assert_eq!(mac_to_string(GUEST_MAC), GUEST_MAC_STRING);
        assert_eq!(mac_to_string(GATEWAY_MAC), GATEWAY_MAC_STRING);
    }

    #[test]
    fn guest_and_gateway_differ_by_last_octet() {
        assert_eq!(&GUEST_MAC[..5], &GATEWAY_MAC[..5]);
        assert_eq!(GUEST_MAC[5], 0xee);
        assert_eq!(GATEWAY_MAC[5], 0xdd);
    }
}
