//! Guest boot configuration channel (host → guest via environment).
//!
//! Runtime serialises [`GuestBootConfig`] into
//! `BUX_GUEST_CONFIG=<json>` and passes it through libkrun `set_exec` env.
//! The guest agent parses it before configuring network, MITM trust, and
//! virtio-fs volume mounts.

use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

/// Environment variable name carrying compact JSON of [`GuestBootConfig`].
pub const GUEST_BOOT_CONFIG_ENV: &str = "BUX_GUEST_CONFIG";

/// How the guest should treat the primary NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuestNetworkMode {
    /// Configure static eth0 (gvproxy virtio-net). Fatal if eth0 is missing.
    Enabled,
    /// Skip eth0; loopback / identity only (no virtio-net / offline).
    Disabled,
}

/// virtio-fs share the guest agent must mount before vsock listen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestVolume {
    /// libkrun virtio-fs tag from `krun_add_virtiofs`.
    pub tag: String,
    /// Absolute guest mount point (no `..`; not filesystem root).
    pub guest_path: String,
    /// Read-only preference recorded by the host.
    ///
    /// Best-effort metadata: libkrun does not pass a RO flag today, so the
    /// kernel mount is RW even when this is `true`. Not a guest mount option.
    #[serde(default)]
    pub read_only: bool,
}

impl GuestVolume {
    /// Reject empty `tag`, non-absolute `guest_path`, `..`, or filesystem root.
    ///
    /// # Errors
    ///
    /// Returns a message if the tag is empty or the path is not a safe mount point.
    pub fn validate(&self) -> Result<(), String> {
        if self.tag.is_empty() {
            return Err("virtiofs tag must not be empty".into());
        }
        validate_guest_mount_path(&self.guest_path)
    }
}

/// Absolute POSIX guest mount point with a normal component and no `..`.
///
/// # Errors
///
/// Returns a message if the path is empty, relative, contains `..`, or is only
/// root / `.` (`/` or `/./`).
pub fn validate_guest_mount_path(guest_path: &str) -> Result<(), String> {
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(format!("guest_path must be absolute: {guest_path:?}"));
    }
    let mut saw_name = false;
    for c in Path::new(guest_path).components() {
        match c {
            Component::ParentDir => {
                return Err(format!("guest_path must not contain '..': {guest_path:?}"));
            }
            Component::Normal(_) => saw_name = true,
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => {
                return Err(format!("guest_path must be absolute: {guest_path:?}"));
            }
        }
    }
    if !saw_name {
        return Err(format!(
            "guest_path must not be filesystem root: {guest_path:?}"
        ));
    }
    Ok(())
}

/// Public boot material for the guest agent (no secret values).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestBootConfig {
    /// Network intent for this boot.
    pub network: GuestNetworkMode,
    /// Optional MITM CA certificate PEM (installed into guest trust store later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitm_ca_pem: Option<String>,
    /// VM id for logs / diagnostics.
    #[serde(default)]
    pub vm_id: String,
    /// virtio-fs volumes to mount at PID 1 (tag → `guest_path`).
    ///
    /// `GuestVolume::read_only` is metadata only; see that field.
    #[serde(default)]
    pub volumes: Vec<GuestVolume>,
}

impl GuestBootConfig {
    /// Build a config for the common managed paths.
    #[must_use]
    pub fn new(vm_id: impl Into<String>, network: GuestNetworkMode) -> Self {
        Self {
            network,
            mitm_ca_pem: None,
            vm_id: vm_id.into(),
            volumes: Vec::new(),
        }
    }

    /// Serialise to a single `KEY=VALUE` env entry for libkrun.
    ///
    /// # Errors
    ///
    /// Returns a string error if JSON serialisation fails (should not happen
    /// for this type).
    pub fn to_env_assignment(&self) -> Result<String, String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        Ok(format!("{GUEST_BOOT_CONFIG_ENV}={json}"))
    }

    /// Parse from process environment (`BUX_GUEST_CONFIG`).
    ///
    /// # Errors
    ///
    /// Missing var or invalid JSON.
    pub fn from_env() -> Result<Self, String> {
        let raw = std::env::var(GUEST_BOOT_CONFIG_ENV)
            .map_err(|_| format!("missing env {GUEST_BOOT_CONFIG_ENV}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("invalid {GUEST_BOOT_CONFIG_ENV}: {e}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn env_roundtrip() {
        let cfg = GuestBootConfig::new("vm1", GuestNetworkMode::Enabled);
        let assignment = cfg.to_env_assignment().unwrap();
        assert!(assignment.starts_with("BUX_GUEST_CONFIG="));
        let json = assignment.strip_prefix("BUX_GUEST_CONFIG=").unwrap();
        let de: GuestBootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(de, cfg);
        assert!(de.volumes.is_empty());
    }

    #[test]
    fn missing_volumes_defaults_empty() {
        let cfg: GuestBootConfig =
            serde_json::from_str(r#"{"network":"enabled","vm_id":"x"}"#).unwrap();
        assert!(cfg.volumes.is_empty());
        assert_eq!(cfg.network, GuestNetworkMode::Enabled);
        assert_eq!(cfg.vm_id, "x");
        assert!(cfg.mitm_ca_pem.is_none());
    }

    #[test]
    fn volumes_json_roundtrip() {
        let mut cfg = GuestBootConfig::new("vm1", GuestNetworkMode::Disabled);
        cfg.volumes.push(GuestVolume {
            tag: "vol0".into(),
            guest_path: "/data".into(),
            read_only: true,
        });
        let json = serde_json::to_string(&cfg).unwrap();
        let de: GuestBootConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(de, cfg);
        let vol = de.volumes.first().expect("one volume");
        assert_eq!(vol.tag, "vol0");
        assert_eq!(vol.guest_path, "/data");
        assert!(vol.read_only);
    }

    fn vol(path: &str) -> GuestVolume {
        GuestVolume {
            tag: "vol0".into(),
            guest_path: path.into(),
            read_only: false,
        }
    }

    #[test]
    fn guest_path_rejects_relative() {
        for path in ["data", "tmp/foo", "../etc", "", "foo/../bar"] {
            let err = vol(path).validate().unwrap_err();
            assert!(
                err.contains("absolute"),
                "expected absolute rejection for {path:?}, got {err}"
            );
            assert!(validate_guest_mount_path(path).is_err());
        }
    }

    #[test]
    fn guest_path_rejects_parent_dir() {
        for path in ["/app/../etc", "/..", "/data/foo/../../etc", "/tmp/../"] {
            let err = vol(path).validate().unwrap_err();
            assert!(
                err.contains(".."),
                "expected parent-dir rejection for {path:?}, got {err}"
            );
            assert!(validate_guest_mount_path(path).is_err());
        }
    }

    #[test]
    fn guest_path_accepts_absolute_without_parent() {
        for path in ["/data", "/var/cache", "/mnt/vol-1", "/data/."] {
            vol(path).validate().unwrap();
            validate_guest_mount_path(path).unwrap();
        }
    }

    #[test]
    fn guest_path_rejects_filesystem_root() {
        for path in ["/", "/./", "/././"] {
            let err = vol(path).validate().unwrap_err();
            assert!(
                err.contains("root"),
                "expected root rejection for {path:?}, got {err}"
            );
            assert!(validate_guest_mount_path(path).is_err());
        }
    }

    #[test]
    fn rejects_empty_tag() {
        let v = GuestVolume {
            tag: String::new(),
            guest_path: "/data".into(),
            read_only: false,
        };
        let err = v.validate().unwrap_err();
        assert!(err.contains("tag"), "{err}");
    }
}
