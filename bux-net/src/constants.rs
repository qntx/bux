//! Virtual network topology constants.
//!
//! These values define the default subnet, gateway, and guest addresses.
//! They must remain consistent across the host runtime, network backend,
//! and the guest agent's network configuration.

/// Virtual network subnet.
pub const SUBNET: &str = "192.168.127.0/24";

/// Gateway IP address (the gvproxy side).
///
/// Also serves as the DNS server for guest containers.
pub const GATEWAY_IP: &str = "192.168.127.1";

/// Guest IP address (assigned via DHCP static lease).
pub const GUEST_IP: &str = "192.168.127.2";

/// Guest IP with CIDR prefix (for static assignment inside the guest).
pub const GUEST_CIDR: &str = "192.168.127.2/24";

/// Guest network interface name created by virtio-net.
pub const GUEST_INTERFACE: &str = "eth0";

/// Gateway MAC address.
///
/// Uses the locally-administered address space (bit 2 of the first octet is set).
pub const GATEWAY_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd];

/// Guest MAC address.
///
/// Must match the MAC configured by the engine for the guest NIC.
/// Used for the DHCP static lease so the guest always receives [`GUEST_IP`].
pub const GUEST_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

/// Guest MAC as a colon-separated string (for DHCP / config serialization).
pub const GUEST_MAC_STRING: &str = "5a:94:ef:e4:0c:ee";

/// Gateway MAC as a colon-separated string.
pub const GATEWAY_MAC_STRING: &str = "5a:94:ef:e4:0c:dd";

/// Default MTU for the virtual network.
pub const DEFAULT_MTU: u16 = 1500;

/// DNS server IP (same as gateway).
pub const DNS_SERVER_IP: &str = GATEWAY_IP;

/// Default DNS search domains.
pub const DNS_SEARCH_DOMAINS: &[&str] = &["local"];

/// Format a 6-byte MAC address as a colon-separated hex string.
#[must_use]
pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_to_string_matches_constants() {
        assert_eq!(mac_to_string(&GUEST_MAC), GUEST_MAC_STRING);
        assert_eq!(mac_to_string(&GATEWAY_MAC), GATEWAY_MAC_STRING);
    }

    #[test]
    fn mac_addresses_differ_by_last_byte() {
        for i in 0..5 {
            assert_eq!(GUEST_MAC[i], GATEWAY_MAC[i]);
        }
        assert_eq!(GUEST_MAC[5], 0xee);
        assert_eq!(GATEWAY_MAC[5], 0xdd);
    }
}
