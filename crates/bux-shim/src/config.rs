//! Serializable engine configuration: Runtime → `bux-shim` process.
//!
//! This is the **only** wire format the shim binary understands. Runtime
//! converts product `VmConfig` into [`ShimConfig`] in the `bux` crate —
//! the shim never depends on `bux`.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Disk image format for root block devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ShimDiskFormat {
    /// Raw image.
    #[default]
    Raw,
    /// QCOW2 copy-on-write image.
    Qcow2,
}

/// virtio-fs share: host directory → guest tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimVirtioFs {
    /// Mount tag inside the guest.
    pub tag: String,
    /// Absolute host path.
    pub path: String,
    /// Read-only virtio-fs (`krun_add_virtiofs3`).
    #[serde(default)]
    pub read_only: bool,
}

/// vsock port mapping (guest port ↔ host Unix socket).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimVsockPort {
    /// Guest vsock port.
    pub port: u32,
    /// Host Unix socket path.
    pub path: String,
    /// When `true`, guest listens and host connects.
    #[serde(default = "default_true")]
    pub listen: bool,
}

/// Serde default for [`ShimVsockPort::listen`].
const fn default_true() -> bool {
    true
}

/// Virtio-net attachment to a userspace network proxy (gvproxy).
///
/// When `Some`, the engine calls `add_net_*`. When `None`, no virtio-net
/// is added and implicit TSI is disabled (`disable_implicit_vsock` + `add_vsock(0)`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimNetwork {
    /// Unix socket path of the network backend.
    pub socket_path: PathBuf,
    /// Stream (Linux) vs datagram (macOS `VFKit`).
    pub connection: ShimNetConn,
    /// Guest NIC MAC — must match gvproxy static lease (`GUEST_MAC`).
    pub mac: [u8; 6],
}

/// Socket type for [`ShimNetwork`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ShimNetConn {
    /// `SOCK_STREAM` — gvproxy on Linux.
    UnixStream,
    /// `SOCK_DGRAM` — gvproxy on macOS.
    UnixDgram,
}

/// Data for the `bux-shim` binary (`bux-shim-bin`) to start gvproxy.
/// Ignored by libkrun apply.
///
/// Types live here so the `bux-shim` library does not depend on `bux-gvproxy`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimGvproxy {
    /// Concrete `(host, guest)` TCP publish pairs.
    #[serde(default)]
    pub port_mappings: Vec<(u16, u16)>,
    /// Egress allow-list. Empty = unrestricted.
    #[serde(default)]
    pub allow_net: Vec<String>,
    /// MITM secrets. Empty = no MITM.
    #[serde(default)]
    pub secrets: Vec<ShimSecret>,
    /// PEM-encoded MITM CA certificate. Empty when secrets unused.
    #[serde(default)]
    pub ca_cert_pem: String,
    /// PEM-encoded MITM CA private key. Empty when secrets unused.
    #[serde(default)]
    pub ca_key_pem: String,
}

impl fmt::Debug for ShimGvproxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShimGvproxy")
            .field("port_mappings", &self.port_mappings)
            .field("allow_net", &self.allow_net)
            .field("secrets", &self.secrets)
            .field(
                "ca_cert_pem",
                &format!("<{} bytes>", self.ca_cert_pem.len()),
            )
            .field("ca_key_pem", &"[REDACTED]")
            .finish()
    }
}

/// Secret placeholder substitution for gvproxy MITM (host-side only).
///
/// Mapped to `bux_gvproxy::SecretConfig` in the `bux-shim` binary crate.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimSecret {
    /// Logical secret name.
    pub name: String,
    /// Hostnames (SNI / Host) this secret applies to.
    pub hosts: Vec<String>,
    /// Placeholder string that appears in guest traffic.
    pub placeholder: String,
    /// Real secret value — never logged.
    pub value: String,
}

impl fmt::Debug for ShimSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShimSecret")
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .field("placeholder", &self.placeholder)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Complete configuration applied by the shim to libkrun.
///
/// Written as JSON by Runtime; consumed only by `bux-shim`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimConfig {
    /// Virtual CPUs.
    pub vcpus: u8,
    /// RAM in MiB.
    pub ram_mib: u32,

    /// Directory root (virtiofs). Mutually exclusive with `root_disk` in practice.
    #[serde(default)]
    pub rootfs: Option<String>,
    /// Block root disk path.
    #[serde(default)]
    pub root_disk: Option<String>,
    /// Format of `root_disk`.
    #[serde(default)]
    pub disk_format: ShimDiskFormat,

    /// virtio-fs mounts.
    #[serde(default)]
    pub virtiofs: Vec<ShimVirtioFs>,

    /// vsock ports (agent socket lives here).
    #[serde(default)]
    pub vsock_ports: Vec<ShimVsockPort>,

    /// Optional virtio-net (gvproxy). `None` = offline (no NIC).
    #[serde(default)]
    pub network: Option<ShimNetwork>,

    /// Optional gvproxy start data for the binary. Must be `Some` iff [`Self::network`] is `Some`.
    #[serde(default)]
    pub gvproxy: Option<ShimGvproxy>,

    /// Guest PID 1 / agent executable path inside the guest root.
    #[serde(default)]
    pub exec_path: Option<String>,
    /// Args after argv0.
    #[serde(default)]
    pub exec_args: Vec<String>,
    /// Environment `KEY=VALUE`. `None` = inherit host env in libkrun.
    #[serde(default)]
    pub env: Option<Vec<String>>,
}

impl ShimConfig {
    /// Parse from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Json`] on invalid JSON.
    pub fn from_json(bytes: &[u8]) -> crate::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Json`] on serialisation failure.
    pub fn to_json(&self) -> crate::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Serialize to pretty JSON string (tests / debugging).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Json`] on serialisation failure.
    pub fn to_json_string_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
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
    fn roundtrip_minimal() {
        let cfg = ShimConfig {
            vcpus: 2,
            ram_mib: 512,
            rootfs: Some("/rootfs".into()),
            root_disk: None,
            disk_format: ShimDiskFormat::Raw,
            virtiofs: vec![],
            vsock_ports: vec![ShimVsockPort {
                port: 1024,
                path: "/tmp/a.sock".into(),
                listen: true,
            }],
            network: None,
            gvproxy: None,
            exec_path: Some("/bux/bin/bux-guest".into()),
            exec_args: vec![],
            env: Some(vec!["BUX_GUEST_CONFIG={}".into()]),
        };
        let json = cfg.to_json().unwrap();
        let de = ShimConfig::from_json(&json).unwrap();
        assert_eq!(de.vcpus, 2);
        assert!(de.network.is_none());
        assert_eq!(de.vsock_ports.first().map(|v| v.port), Some(1024));
    }

    #[test]
    fn network_variant_roundtrip() {
        let cfg = ShimConfig {
            vcpus: 1,
            ram_mib: 256,
            rootfs: None,
            root_disk: Some("/disk.qcow2".into()),
            disk_format: ShimDiskFormat::Qcow2,
            virtiofs: vec![],
            vsock_ports: vec![],
            network: Some(ShimNetwork {
                socket_path: PathBuf::from("/tmp/net.sock"),
                connection: ShimNetConn::UnixStream,
                mac: [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee],
            }),
            gvproxy: Some(ShimGvproxy {
                port_mappings: vec![(8080, 80)],
                allow_net: vec!["example.com".into()],
                secrets: vec![ShimSecret {
                    name: "TOKEN".into(),
                    hosts: vec!["api.example.com".into()],
                    placeholder: "<BUX_SECRET:TOKEN>".into(),
                    value: "must-not-appear".into(),
                }],
                ca_cert_pem: "CERT".into(),
                ca_key_pem: "KEY".into(),
            }),
            exec_path: None,
            exec_args: vec![],
            env: None,
        };
        let de = ShimConfig::from_json(&cfg.to_json().unwrap()).unwrap();
        let net = de.network.unwrap();
        assert_eq!(net.connection, ShimNetConn::UnixStream);
        assert_eq!(net.mac[5], 0xee);
        let gvp = de.gvproxy.unwrap();
        assert_eq!(gvp.port_mappings, vec![(8080, 80)]);
        assert_eq!(
            gvp.secrets.first().map(|s| s.value.as_str()),
            Some("must-not-appear")
        );
        let dbg = format!("{gvp:?}");
        assert!(dbg.contains("REDACTED"), "{dbg}");
        assert!(!dbg.contains("must-not-appear"), "{dbg}");
        assert!(!dbg.contains("KEY"), "{dbg}");
    }

    #[test]
    fn gvproxy_absent_in_json_is_none() {
        let json = br#"{"vcpus":1,"ram_mib":256,"rootfs":"/r"}"#;
        let cfg = ShimConfig::from_json(json).unwrap();
        assert!(cfg.gvproxy.is_none());
        assert!(cfg.network.is_none());
    }

    #[test]
    fn virtiofs_read_only_roundtrip() {
        let cfg = ShimConfig {
            vcpus: 1,
            ram_mib: 256,
            rootfs: Some("/r".into()),
            root_disk: None,
            disk_format: ShimDiskFormat::Raw,
            virtiofs: vec![ShimVirtioFs {
                tag: "vol0".into(),
                path: "/host/data".into(),
                read_only: true,
            }],
            vsock_ports: vec![],
            network: None,
            gvproxy: None,
            exec_path: None,
            exec_args: vec![],
            env: None,
        };
        let de = ShimConfig::from_json(&cfg.to_json().unwrap()).unwrap();
        let share = de.virtiofs.first().expect("one share");
        assert_eq!(share.tag, "vol0");
        assert_eq!(share.path, "/host/data");
        assert!(share.read_only);
    }

    #[test]
    fn virtiofs_read_only_defaults_false() {
        let json =
            br#"{"vcpus":1,"ram_mib":256,"rootfs":"/r","virtiofs":[{"tag":"vol0","path":"/h"}]}"#;
        let cfg = ShimConfig::from_json(json).unwrap();
        let share = cfg.virtiofs.first().expect("one share");
        assert_eq!(share.tag, "vol0");
        assert!(!share.read_only);
    }
}
