//! Install MITM CA certificate into guest trust stores (overlay-writable paths).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// alpine wget reads this env as `CAfile` (replaces the default bundle; `CApath` is unchanged).
const SSL_CERT_FILE: &str = "/etc/ssl/certs/bux-ca-bundle.pem";

/// Write the CA PEM to well-known trust paths and activate `SSL_CERT_FILE`.
pub fn install_mitm_ca(pem: &str) -> io::Result<()> {
    write_ca_pem(Path::new("/"), pem)?;
    activate_ssl_cert_file();
    eprintln!("[bux-guest] installed MITM CA into guest trust paths");
    Ok(())
}

/// Exec children inherit this; alpine wget does not load sibling PEM paths.
fn activate_ssl_cert_file() {
    #[allow(
        clippy::disallowed_methods,
        reason = "PID 1, single-threaded before listen; exec children inherit SSL_CERT_FILE"
    )]
    {
        // SAFETY: guest agent is PID 1 and still single-threaded (no vsock tasks yet).
        unsafe {
            std::env::set_var("SSL_CERT_FILE", SSL_CERT_FILE);
        }
    }
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

    let bundle = root.join("etc/ssl/certs/ca-certificates.crt");
    // Read before append: composing from the mutated bundle duplicates MITM.
    let system_copy = match fs::read(&bundle) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if system_copy.is_some() {
        let mut f = fs::OpenOptions::new().append(true).open(&bundle)?;
        f.write_all(b"\n")?;
        f.write_all(pem.as_bytes())?;
        if !pem.ends_with('\n') {
            f.write_all(b"\n")?;
        }
    }

    let mut body = system_copy.unwrap_or_default();
    if !body.is_empty() && !body.ends_with(b"\n") {
        body.push(b'\n');
    }
    body.extend_from_slice(pem.as_bytes());
    let combined = root.join("etc/ssl/certs/bux-ca-bundle.pem");
    fs::write(&combined, body)?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests"
)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";

    #[test]
    fn write_ca_pem_writes_primary_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_ca_pem(dir.path(), PEM).unwrap();
        assert_eq!(
            fs::read(
                dir.path()
                    .join("usr/local/share/ca-certificates/bux-mitm-ca.crt")
            )
            .unwrap(),
            PEM.as_bytes()
        );
        assert_eq!(
            fs::read(dir.path().join("etc/ssl/certs/bux-mitm-ca.pem")).unwrap(),
            PEM.as_bytes()
        );
        assert!(
            !dir.path()
                .join("etc/ssl/certs/ca-certificates.crt")
                .exists()
        );
        assert_eq!(
            fs::read(dir.path().join("etc/ssl/certs/bux-ca-bundle.pem")).unwrap(),
            PEM.as_bytes()
        );
    }

    #[test]
    fn write_ca_pem_appends_existing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("etc/ssl/certs/ca-certificates.crt");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        fs::write(
            &bundle,
            "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        write_ca_pem(dir.path(), PEM).unwrap();
        let got = fs::read_to_string(&bundle).unwrap();
        assert!(got.contains("old"), "{got}");
        assert!(got.contains("test"), "{got}");
        assert!(
            got.find("old").unwrap() < got.find("test").unwrap(),
            "{got}"
        );
        let combined =
            fs::read_to_string(dir.path().join("etc/ssl/certs/bux-ca-bundle.pem")).unwrap();
        assert!(combined.contains("old"), "{combined}");
        assert!(combined.contains("test"), "{combined}");
        assert!(
            combined.find("old").unwrap() < combined.find("test").unwrap(),
            "{combined}"
        );
        assert_eq!(
            combined.matches("BEGIN CERTIFICATE").count(),
            2,
            "{combined}"
        );
        assert_eq!(
            fs::read(dir.path().join("etc/ssl/certs/bux-mitm-ca.pem")).unwrap(),
            PEM.as_bytes()
        );
    }

    #[test]
    fn write_ca_pem_fails_when_primary_write_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("usr/local/share");
        fs::create_dir_all(&share).unwrap();
        fs::write(share.join("ca-certificates"), b"not-a-dir").unwrap();
        assert!(write_ca_pem(dir.path(), PEM).is_err());
    }

    #[test]
    fn write_ca_pem_fails_when_bundle_append_blocked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/ssl/certs/ca-certificates.crt")).unwrap();
        assert!(write_ca_pem(dir.path(), PEM).is_err());
    }

    #[test]
    fn write_ca_pem_fails_when_combined_write_blocked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/ssl/certs/bux-ca-bundle.pem")).unwrap();
        assert!(write_ca_pem(dir.path(), PEM).is_err());
    }

    #[test]
    fn ssl_cert_file_is_combined_bundle() {
        assert_eq!(SSL_CERT_FILE, "/etc/ssl/certs/bux-ca-bundle.pem");
    }
}
