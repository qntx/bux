//! Port publish specs and ephemeral host-port resolution.
//!
//! v1: TCP only; host bind address is always `0.0.0.0` (matches gvproxy).

use std::net::TcpListener;

use serde::{Deserialize, Serialize};

use crate::Result;

/// Host bind address used for all published ports (gvproxy forward key).
pub(crate) const BIND_ADDR: &str = "0.0.0.0";

/// Requested port publish mapping (before ephemeral resolution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSpec {
    /// Host port. `None` or `Some(0)` → probe an ephemeral free port.
    pub host: Option<u16>,
    /// Guest TCP port.
    pub guest: u16,
}

impl PortSpec {
    /// Fixed host and guest ports.
    #[must_use]
    pub const fn new(host: u16, guest: u16) -> Self {
        Self {
            host: Some(host),
            guest,
        }
    }

    /// Ephemeral host port → fixed guest port.
    #[must_use]
    pub const fn ephemeral(guest: u16) -> Self {
        Self { host: None, guest }
    }
}

/// Concrete published port after resolution (what gvproxy actually binds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPort {
    /// Host TCP port (always concrete, never 0).
    pub host: u16,
    /// Guest TCP port.
    pub guest: u16,
    /// Always [`BIND_ADDR`] in v1.
    pub bind_addr: String,
}

impl PublishedPort {
    /// Construct with the v1 bind address.
    #[must_use]
    pub fn new(host: u16, guest: u16) -> Self {
        Self {
            host,
            guest,
            bind_addr: BIND_ADDR.to_owned(),
        }
    }
}

/// Parse CLI / Docker-style publish strings.
///
/// Accepted:
/// - `8080:80` — host 8080 → guest 80
/// - `80` — ephemeral host → guest 80
/// - `0:80` / `:80` — ephemeral host → guest 80
/// - optional `/tcp` suffix (default); `/udp` is rejected in v1
///
/// # Errors
///
/// Returns [`crate::Error::InvalidConfig`] on malformed input or UDP.
pub fn parse_publish_spec(spec: &str) -> Result<PortSpec> {
    let (map, proto) = match spec.rsplit_once('/') {
        Some((m, p)) => (m, Some(p)),
        None => (spec, None),
    };
    if let Some(p) = proto {
        let p = p.to_ascii_lowercase();
        if p != "tcp" {
            return Err(crate::Error::InvalidConfig(format!(
                "unsupported port protocol /{p} in {spec:?}; v1 is TCP only"
            )));
        }
    }

    // ":80" or "0:80" or "8080:80" or "80"
    if let Some((host_s, guest_s)) = map.split_once(':') {
        let guest: u16 = guest_s
            .parse()
            .map_err(|_| crate::Error::InvalidConfig(format!("invalid guest port in {spec:?}")))?;
        if host_s.is_empty() || host_s == "0" {
            return Ok(PortSpec::ephemeral(guest));
        }
        let host: u16 = host_s
            .parse()
            .map_err(|_| crate::Error::InvalidConfig(format!("invalid host port in {spec:?}")))?;
        if host == 0 {
            return Ok(PortSpec::ephemeral(guest));
        }
        return Ok(PortSpec::new(host, guest));
    }

    // bare guest port → ephemeral host
    let guest: u16 = map
        .parse()
        .map_err(|_| crate::Error::InvalidConfig(format!("invalid port spec {spec:?}")))?;
    Ok(PortSpec::ephemeral(guest))
}

/// Concrete host→guest port pairs after ephemeral resolution.
pub(crate) type PortPairs = Vec<(u16, u16)>;

/// Resolve specs to concrete `(host, guest)` pairs and [`PublishedPort`] list.
///
/// Ephemeral ports are chosen by binding `0.0.0.0:0` then releasing the
/// socket so gvproxy can re-bind (small race window; acceptable for v1).
///
/// # Errors
///
/// Returns config or I/O errors from probe-bind.
pub(crate) fn resolve_ports(specs: &[PortSpec]) -> Result<(PortPairs, Vec<PublishedPort>)> {
    let mut pairs = Vec::with_capacity(specs.len());
    let mut published = Vec::with_capacity(specs.len());
    for spec in specs {
        let host = match spec.host {
            None | Some(0) => probe_ephemeral_port()?,
            Some(h) => h,
        };
        pairs.push((host, spec.guest));
        published.push(PublishedPort::new(host, spec.guest));
    }
    Ok((pairs, published))
}

/// Bind `0.0.0.0:0` and return the kernel-assigned port.
fn probe_ephemeral_port() -> Result<u16> {
    let listener = TcpListener::bind((BIND_ADDR, 0)).map_err(|e| {
        crate::Error::Io(std::io::Error::new(
            e.kind(),
            format!("ephemeral port probe failed: {e}"),
        ))
    })?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Format concrete pairs as legacy `"host:guest"` strings (TSI / storage).
#[must_use]
pub(crate) fn format_port_pairs(pairs: &[(u16, u16)]) -> Vec<String> {
    pairs.iter().map(|(h, g)| format!("{h}:{g}")).collect()
}

/// Parse stored `"host:guest"` list into concrete pairs (no ephemeral).
///
/// # Errors
///
/// Malformed entries or host port 0.
pub(crate) fn parse_concrete_port_strings(ports: &[String]) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::with_capacity(ports.len());
    for spec in ports {
        let Some((host_s, guest_s)) = spec.split_once(':') else {
            return Err(crate::Error::InvalidConfig(format!(
                "invalid port mapping {spec:?}; expected host:guest"
            )));
        };
        let host: u16 = host_s
            .parse()
            .map_err(|_| crate::Error::InvalidConfig(format!("invalid host port in {spec:?}")))?;
        let guest: u16 = guest_s
            .parse()
            .map_err(|_| crate::Error::InvalidConfig(format!("invalid guest port in {spec:?}")))?;
        if host == 0 {
            return Err(crate::Error::InvalidConfig(format!(
                "unresolved ephemeral port in stored mapping {spec:?}"
            )));
        }
        out.push((host, guest));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_publish_variants() {
        assert_eq!(
            parse_publish_spec("8080:80").unwrap(),
            PortSpec::new(8080, 80)
        );
        assert_eq!(parse_publish_spec("80").unwrap(), PortSpec::ephemeral(80));
        assert_eq!(parse_publish_spec("0:80").unwrap(), PortSpec::ephemeral(80));
        assert_eq!(parse_publish_spec(":80").unwrap(), PortSpec::ephemeral(80));
        assert_eq!(
            parse_publish_spec("8080:80/tcp").unwrap(),
            PortSpec::new(8080, 80)
        );
        assert!(parse_publish_spec("8080:80/udp").is_err());
    }

    #[test]
    fn resolve_fixed() {
        let (pairs, pubd) = resolve_ports(&[PortSpec::new(18080, 80)]).unwrap();
        assert_eq!(pairs, vec![(18080, 80)]);
        let p = pubd.first().expect("one published port");
        assert_eq!(p.bind_addr, BIND_ADDR);
        assert_eq!(p.host, 18080);
    }

    #[test]
    fn resolve_ephemeral_nonzero() {
        let (pairs, _) = resolve_ports(&[PortSpec::ephemeral(443)]).unwrap();
        assert_eq!(pairs.len(), 1);
        let (host, guest) = pairs.first().copied().expect("one pair");
        assert_ne!(host, 0);
        assert_eq!(guest, 443);
    }
}
