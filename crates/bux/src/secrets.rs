//! Host-side secret injection via gvproxy MITM placeholders.
//!
//! Real secret values never enter the guest. Guests send placeholder strings
//! (default `<BUX_SECRET:name>`); gvproxy substitutes the real value on egress.
//!
//! Secrets are **memory-only** on the `Runtime`. `SQLite` only stores
//! [`VmConfig::secrets_required`]. After `Runtime` process death, callers must
//! re-supply secrets via [`crate::StartOptions`].

#![cfg(unix)]

use std::fmt;

use serde::{Deserialize, Serialize};

/// Default placeholder brand prefix inside the angle-bracket form.
pub(crate) const SECRET_PLACEHOLDER_PREFIX: &str = "BUX_SECRET";

/// A secret available for MITM substitution on matching hostnames.
#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Logical name (also used in the default placeholder).
    pub name: String,
    /// Hostnames (SNI / Host) this secret applies to.
    pub hosts: Vec<String>,
    /// Real secret value — never logged, never written to guest or `SQLite`.
    pub value: String,
    /// Optional override for the placeholder string.
    ///
    /// When `None`, uses [`default_placeholder`] for `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) placeholder: Option<String>,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .field("placeholder", &self.placeholder_str())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Secret {
    /// Create a secret with the default placeholder form.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        hosts: impl IntoIterator<Item = impl Into<String>>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            hosts: hosts.into_iter().map(Into::into).collect(),
            value: value.into(),
            placeholder: None,
        }
    }

    /// Placeholder string used in guest traffic.
    #[must_use]
    pub fn placeholder_str(&self) -> String {
        self.placeholder
            .clone()
            .unwrap_or_else(|| default_placeholder(&self.name))
    }

    /// Convert to shim JSON for the binary to map onto gvproxy.
    #[must_use]
    pub(crate) fn to_shim_secret(&self) -> bux_shim::ShimSecret {
        bux_shim::ShimSecret {
            name: self.name.clone(),
            hosts: self.hosts.clone(),
            placeholder: self.placeholder_str(),
            value: self.value.clone(),
        }
    }
}

/// Default placeholder: `<BUX_SECRET:name>`.
#[must_use]
pub(crate) fn default_placeholder(name: &str) -> String {
    format!("<{SECRET_PLACEHOLDER_PREFIX}:{name}>")
}

/// Live secret material held only in `Runtime` memory (never `SQLite`).
#[derive(Clone)]
pub(crate) struct LiveSecrets {
    /// Secrets for MITM.
    pub(crate) secrets: Vec<Secret>,
    /// MITM CA certificate PEM paired with this secret set.
    pub(crate) ca_cert_pem: String,
    /// MITM CA private key PEM (host-only).
    pub(crate) ca_key_pem: String,
}

impl fmt::Debug for LiveSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveSecrets")
            .field("secrets", &self.secrets)
            .field(
                "ca_cert_pem",
                &format!("<{} bytes>", self.ca_cert_pem.len()),
            )
            .field("ca_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl LiveSecrets {
    /// Mint a CA and package secrets for gvproxy JSON.
    ///
    /// # Errors
    ///
    /// Returns CA generation errors.
    pub(crate) fn mint(secrets: Vec<Secret>) -> crate::Result<Self> {
        let (ca_cert_pem, ca_key_pem) = mint_mitm_ca()?;
        Ok(Self {
            secrets,
            ca_cert_pem,
            ca_key_pem,
        })
    }

    /// Shim JSON secrets for the binary to start gvproxy.
    #[must_use]
    pub(crate) fn to_shim_secrets(&self) -> Vec<bux_shim::ShimSecret> {
        self.secrets.iter().map(Secret::to_shim_secret).collect()
    }
}

/// Ephemeral ECDSA P-256 MITM CA. Lives in `bux` so embedders do not link `libgvproxy.a`.
fn mint_mitm_ca() -> crate::Result<(String, String)> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use time::OffsetDateTime;

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| crate::Error::InvalidConfig(format!("MITM CA key generation failed: {e}")))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "bux MITM CA");
        dn
    };

    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(24);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];

    let cert = params.self_signed(&key_pair).map_err(|e| {
        crate::Error::InvalidConfig(format!("MITM CA self-signed cert failed: {e}"))
    })?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Options for restarting a VM that may require secret re-supply.
#[derive(Debug, Clone, Default)]
pub struct StartOptions {
    /// How long to wait for the guest agent after start (`Duration::ZERO` = skip).
    pub ready_timeout: Option<std::time::Duration>,
    /// Secrets to install for this start (required when `secrets_required`).
    pub secrets: Vec<Secret>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn placeholder_default() {
        let s = Secret::new("TOKEN", ["api.example.com"], "s3cr3t");
        assert_eq!(s.placeholder_str(), "<BUX_SECRET:TOKEN>");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn mint_produces_pem() {
        let live = LiveSecrets::mint(vec![Secret::new("A", ["h"], "v")]).unwrap();
        assert!(live.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
