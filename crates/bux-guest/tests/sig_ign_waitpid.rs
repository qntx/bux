//! Kernel contract: `SIG_IGN` on `SIGCHLD` makes `waitpid` return `ECHILD`.
//!
//! Isolated process so it cannot poison tokio's SIGCHLD handler or steal
//! `waitpid(-1)` from the reaper test binary.

#![allow(
    unused_crate_dependencies,
    unsafe_code,
    clippy::tests_outside_test_module,
    clippy::panic,
    reason = "linux-only kernel-contract test; SIG_IGN via libc::signal"
)]
#![cfg(target_os = "linux")]

use std::io;
use std::process::{Command, Stdio};

use nix::sys::wait::waitpid;
use nix::unistd::Pid;

/// `waitpid(pid)` returns `ECHILD` after `SIG_IGN` on `SIGCHLD`.
#[test]
fn sig_ign_waitpid_returns_echild() {
    // SAFETY: dedicated test process; POSIX `signal(SIGCHLD, SIG_IGN)`.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    let child = match Command::new("sh")
        .args(["-c", "exit 42"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("skipping: sh not found");
            return;
        }
        Err(e) => panic!("spawn sh: {e}"),
    };

    let pid = Pid::from_raw(child.id().cast_signed());
    let result = waitpid(pid, None);
    assert!(
        matches!(result, Err(nix::errno::Errno::ECHILD)),
        "expected ECHILD under SIG_IGN, got {result:?}"
    );
}
