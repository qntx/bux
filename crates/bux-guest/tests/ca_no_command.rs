//! Production guest sources must not spawn CA helpers or fail-closed on writes.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    reason = "linux-only source scan of production files"
)]
#![cfg(target_os = "linux")]

#[test]
fn ca_trust_has_no_command_and_server_does_not_fail_closed_on_ca() {
    let ca = include_str!("../src/ca_trust.rs");
    assert!(!ca.contains("Command::"), "ca_trust must not spawn helpers");
    assert!(
        !ca.contains("std::process::Command"),
        "ca_trust must not import process::Command"
    );
    let server = include_str!("../src/server.rs");
    assert!(
        !server.contains("install_mitm_ca(pem)?"),
        "run must not fail-closed on CA"
    );
}
