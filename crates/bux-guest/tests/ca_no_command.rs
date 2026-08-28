//! Guest CA install must not spawn helpers; write/append errors abort `run`.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    reason = "linux-only source scan of production files"
)]
#![cfg(target_os = "linux")]

#[test]
fn ca_trust_has_no_command_and_run_fail_closes_on_ca() {
    let ca = include_str!("../src/ca_trust.rs");
    assert!(!ca.contains("Command::"), "ca_trust must not spawn helpers");
    assert!(
        !ca.contains("std::process::Command"),
        "ca_trust must not import process::Command"
    );
    assert!(
        ca.contains("SSL_CERT_FILE"),
        "ca_trust must set SSL_CERT_FILE"
    );
    let server = include_str!("../src/server.rs");
    assert!(
        server.contains("install_mitm_ca(pem)?"),
        "run must fail-closed on CA"
    );
}
