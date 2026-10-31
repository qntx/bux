//! The shim enters the Landlock domain its parent prepared, with every thread.

#![allow(
    unused_crate_dependencies,
    unsafe_code,
    clippy::multiple_unsafe_ops_per_block,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "linux-only integration test binary"
)]
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const SHIM: &str = env!("CARGO_BIN_EXE_bux-shim");

/// Ruleset that lets the shim load and run, and use `dir`.
fn ruleset(dir: &Path) -> OwnedFd {
    let fd = bux_landlock::PathRestrictions::new()
        .allow_read_many(["/usr", "/lib", "/lib64", "/etc", "/proc"])
        .allow_read(Path::new(SHIM).parent().unwrap())
        .allow_read_write(dir)
        .build()
        .unwrap()
        .unwrap();
    // SAFETY: `build` returns an fd that nothing else owns.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// The shim on `config`, with `ruleset` open across `exec` and named in its env.
fn shim_with_ruleset(ruleset: &OwnedFd, config: &Path) -> Command {
    let fd = ruleset.as_raw_fd();
    let mut cmd = Command::new(SHIM);
    cmd.arg(config).env("BUX_LANDLOCK_FD", fd.to_string());
    // SAFETY: fcntl is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_domain_applies_before_the_config_is_read() {
    if !bux_landlock::is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("cfg.json");

    // The shim removes a config it has read.
    fs::write(&config, b"not json").unwrap();
    let unconfined = Command::new(SHIM).arg(&config).output().unwrap();
    assert!(
        stderr(&unconfined).contains("invalid config JSON"),
        "{}",
        stderr(&unconfined)
    );

    fs::write(&config, b"not json").unwrap();
    let other = tempfile::tempdir().unwrap();
    let confined = shim_with_ruleset(&ruleset(other.path()), &config)
        .output()
        .unwrap();
    assert_eq!(confined.status.code(), Some(1));
    assert!(
        stderr(&confined).contains("failed to read config")
            && stderr(&confined).contains("Permission denied"),
        "the config is outside the ruleset: {}",
        stderr(&confined)
    );
}

/// The thread count and how many threads have `NoNewPrivs` set, which
/// `landlock_restrict_self` requires and a new thread inherits.
fn threads_and_confined(pid: u32) -> (usize, usize) {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return (0, 0);
    };
    let states: Vec<bool> = tasks
        .flatten()
        .filter_map(|task| fs::read_to_string(task.path().join("status")).ok())
        .map(|status| {
            status
                .lines()
                .any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1'))
        })
        .collect();
    (states.len(), states.iter().filter(|c| **c).count())
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

#[test]
fn every_thread_runs_inside_the_domain() {
    if !bux_landlock::is_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // Reading a FIFO without a writer blocks, so the shim stays up.
    let config = dir.path().join("cfg.json");
    let path = CString::new(config.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is a valid C string.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

    let shim = KillOnDrop(
        shim_with_ruleset(&ruleset(dir.path()), &config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // The Go runtime's thread is there before `main`. The first image has it
    // outside the domain; only the re-executed image has it inside.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (threads, confined) = threads_and_confined(shim.0.id());
        if threads >= 2 && confined == threads {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{confined} of {threads} threads confined"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_ruleset_that_cannot_be_applied_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("cfg.json");
    for (value, expected) in [
        ("not-a-number", "invalid BUX_LANDLOCK_FD"),
        ("987", "cannot apply ruleset"),
    ] {
        let out = Command::new(SHIM)
            .arg(&config)
            .env("BUX_LANDLOCK_FD", value)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(stderr(&out).contains(expected), "{}", stderr(&out));
    }
}
