//! Guest boot configuration channel (host → guest via environment).
//!
//! Runtime serialises [`GuestBootConfig`] into
//! `BUX_GUEST_CONFIG=<json>` and passes it through libkrun `set_exec` env.
//! The guest agent parses it before configuring network / MITM trust.

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
}

impl GuestBootConfig {
    /// Build a config for the common managed paths.
    #[must_use]
    pub fn new(vm_id: impl Into<String>, network: GuestNetworkMode) -> Self {
        Self {
            network,
            mitm_ca_pem: None,
            vm_id: vm_id.into(),
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
    }
}
