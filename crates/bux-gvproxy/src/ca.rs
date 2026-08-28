//! Ephemeral MITM CA generation for secret placeholder substitution.
//!
//! The Go bridge expects `ca_cert_pem` / `ca_key_pem` when `secrets` is
//! non-empty (`gvproxy-bridge/main.go`). Generation lives on the Rust side
//! so the private key never needs a separate Go crypto path.
//!
//! Persistence (load-or-generate to disk) is a Runtime concern; this module
//! only mints PEMs.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::error::{Error, Result};

/// PEM-encoded MITM CA certificate and private key.
#[derive(Clone)]
pub struct MitmCa {
    /// Public certificate PEM (`-----BEGIN CERTIFICATE-----` …).
    pub cert_pem: String,
    /// Private key PEM.
    pub key_pem: String,
}

impl std::fmt::Debug for MitmCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmCa")
            .field("cert_pem", &format!("<{} bytes>", self.cert_pem.len()))
            .field("key_pem", &"[REDACTED]")
            .finish()
    }
}

/// Generate a fresh ECDSA P-256 CA certificate suitable for MITM.
///
/// Validity: now−1m … now+10y (`not_before` skew).
///
/// # Errors
///
/// Returns [`Error::Ca`] if key or certificate generation fails.
pub fn generate() -> Result<MitmCa> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Ca(format!("key generation failed: {e}")))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "bux MITM CA");
        dn
    };

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(1);
    params.not_after = now + Duration::days(365 * 10);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Ca(format!("self-signed cert failed: {e}")))?;

    Ok(MitmCa {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
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
    fn generate_produces_pem() {
        let ca = generate().unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(
            ca.key_pem.contains("BEGIN PRIVATE KEY") || ca.key_pem.contains("BEGIN EC PRIVATE KEY")
        );
        let dbg = format!("{ca:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("BEGIN EC") && !dbg.contains("BEGIN PRIVATE"));
    }

    fn ca_not_after(pem: &str) -> OffsetDateTime {
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        block
            .parse_x509()
            .unwrap()
            .validity()
            .not_after
            .to_datetime()
    }

    #[test]
    fn generate_ca_not_after_is_ten_years() {
        let ca = generate().unwrap();
        let span = ca_not_after(&ca.cert_pem) - OffsetDateTime::now_utc();
        assert!(
            span >= Duration::days(365 * 10 - 1) && span <= Duration::days(365 * 10 + 1),
            "not_after delta {span:?}"
        );
    }
}
