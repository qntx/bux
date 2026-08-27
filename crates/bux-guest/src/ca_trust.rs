//! Install MITM CA certificate into guest trust stores (overlay-writable paths).

use std::fs;
use std::io;
use std::path::Path;

/// Write the CA PEM to well-known trust paths.
pub fn install_mitm_ca(pem: &str) -> io::Result<()> {
    write_ca_pem(Path::new("/"), pem)?;
    eprintln!("[bux-guest] installed MITM CA into guest trust paths");
    Ok(())
}

/// Write PEM to well-known trust paths. Missing parents: create. IO errors return.
///
/// After `Reaper::start`, PID 1 must never `waitpid` except via `Reaper`;
/// this function stays before Reaper and must not grow a `Command`.
fn write_ca_pem(root: &Path, pem: &str) -> io::Result<()> {
    let debian = root.join("usr/local/share/ca-certificates/bux-mitm-ca.crt");
    if let Some(parent) = debian.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&debian, pem.as_bytes())?;

    let openssl = root.join("etc/ssl/certs/bux-mitm-ca.pem");
    if let Some(parent) = openssl.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&openssl, pem.as_bytes())?;

    let anchor = root.join("etc/pki/ca-trust/source/anchors/bux-mitm-ca.pem");
    if let Some(parent) = anchor.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&anchor, pem.as_bytes());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn write_ca_pem_writes_primary_paths() {
        let dir = tempfile::tempdir().unwrap();
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
        write_ca_pem(dir.path(), pem).unwrap();
        assert_eq!(
            fs::read(
                dir.path()
                    .join("usr/local/share/ca-certificates/bux-mitm-ca.crt")
            )
            .unwrap(),
            pem.as_bytes()
        );
        assert_eq!(
            fs::read(dir.path().join("etc/ssl/certs/bux-mitm-ca.pem")).unwrap(),
            pem.as_bytes()
        );
    }
}
