//! Network statistics from gvisor-tap-vsock.
//!
//! Deserialized from the JSON returned by `gvproxy_get_stats()`.
//! Field names use `#[serde(rename)]` to map Go's PascalCase to
//! Rust's snake_case.

use serde::{Deserialize, Serialize};

/// Aggregate network statistics from a gvproxy instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Total bytes transmitted to the VM.
    #[serde(rename = "BytesSent")]
    pub bytes_sent: u64,

    /// Total bytes received from the VM.
    #[serde(rename = "BytesReceived")]
    pub bytes_received: u64,

    /// TCP-layer statistics.
    #[serde(rename = "TCP")]
    pub tcp: TcpStats,
}

/// TCP-specific counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpStats {
    /// SYN packets dropped because the TCP forwarder's `maxInFlight`
    /// limit was exceeded.  A non-zero value indicates connection
    /// throttling.
    #[serde(rename = "ForwardMaxInFlightDrop")]
    pub forward_max_inflight_drop: u64,

    /// Current connections in `ESTABLISHED` state.
    #[serde(rename = "CurrentEstablished")]
    pub current_established: u64,

    /// Total failed connection attempts.
    #[serde(rename = "FailedConnectionAttempts")]
    pub failed_connection_attempts: u64,

    /// Total TCP segments retransmitted (performance indicator).
    #[serde(rename = "Retransmits")]
    pub retransmits: u64,

    /// Number of RTO (retransmission timeout) events.
    #[serde(rename = "Timeouts")]
    pub timeouts: u64,
}

impl NetworkStats {
    /// Parse from a JSON string returned by the Go FFI layer.
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize() {
        let json = r#"{
            "BytesSent": 1024,
            "BytesReceived": 2048,
            "TCP": {
                "ForwardMaxInFlightDrop": 100,
                "CurrentEstablished": 5,
                "FailedConnectionAttempts": 2,
                "Retransmits": 10,
                "Timeouts": 1
            }
        }"#;

        let stats = NetworkStats::from_json_str(json).unwrap();
        assert_eq!(stats.bytes_sent, 1024);
        assert_eq!(stats.bytes_received, 2048);
        assert_eq!(stats.tcp.forward_max_inflight_drop, 100);
        assert_eq!(stats.tcp.current_established, 5);
    }

    #[test]
    fn invalid_json() {
        assert!(NetworkStats::from_json_str("invalid").is_err());
    }

    #[test]
    fn clone_eq() {
        let stats = NetworkStats {
            bytes_sent: 1024,
            bytes_received: 2048,
            tcp: TcpStats {
                forward_max_inflight_drop: 0,
                current_established: 1,
                failed_connection_attempts: 0,
                retransmits: 0,
                timeouts: 0,
            },
        };
        assert_eq!(stats, stats.clone());
    }
}
