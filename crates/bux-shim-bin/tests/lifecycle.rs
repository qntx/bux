//! How the shim process ends: on a fatal signal, and with bwrap's outer process.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "integration test binary"
)]
#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const SHIM: &str = env!("CARGO_BIN_EXE_bux-shim");

/// A FIFO to use as the shim's config, in a new directory: reading one that has
/// a writer keeps the shim up.
fn fifo_config(name: &str) -> (PathBuf, PathBuf) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("cfg.json");
    drop(fs::remove_file(&config));
    let mkfifo = Command::new("mkfifo").arg(&config).status().unwrap();
    assert!(mkfifo.success(), "{mkfifo}");
    (dir, config)
}

/// Open `fifo` for writing. That returns once the shim opens it for reading,
/// which it does after installing its signal handlers.
fn open_for_writing(fifo: &Path) -> File {
    let path = fifo.to_path_buf();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || sender.send(OpenOptions::new().write(true).open(path)));
    let Ok(opened) = receiver.recv_timeout(Duration::from_secs(10)) else {
        panic!("the shim did not open its config");
    };
    opened.unwrap()
}

fn send_abort(pid: &str) {
    let kill = Command::new("kill").args(["-ABRT", pid]).status().unwrap();
    assert!(kill.success(), "{kill}");
}

#[test]
fn a_crash_ends_the_shim_with_the_signal() {
    let (dir, config) = fifo_config("crash");
    let mut shim = Command::new(SHIM)
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _writer = open_for_writing(&config);

    send_abort(&shim.id().to_string());

    let status = shim.wait().unwrap();
    assert!(status.signal().is_some(), "{status}");
    let record = fs::read_to_string(config.with_extension("exit")).unwrap();
    assert!(record.contains("SIGABRT"), "{record}");
    drop(fs::remove_dir_all(&dir));
}

#[cfg(target_os = "linux")]
mod jail {
    use std::io::{ErrorKind, Write};
    use std::time::Instant;

    use super::*;

    /// bwrap with the arguments that matter here, around `program`.
    fn bwrap(program: &str) -> Command {
        let mut cmd = Command::new("bwrap");
        cmd.args(["--unshare-pid", "--as-pid-1", "--ro-bind", "/", "/", "--"])
            .arg(program)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    fn bwrap_works() -> bool {
        bwrap("/bin/true").status().is_ok_and(|s| s.success())
    }

    #[test]
    fn a_jailed_shim_dies_with_the_outer_process() {
        if !bwrap_works() {
            return;
        }
        let (dir, config) = fifo_config("jail");

        let mut outer = bwrap(SHIM).arg(&config).spawn().unwrap();
        let mut fifo = open_for_writing(&config);

        outer.kill().unwrap();
        outer.wait().unwrap();

        // The shim was the FIFO's only reader.
        let gone_by = Instant::now() + Duration::from_secs(10);
        loop {
            match fifo.write(b" ") {
                Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
                _ => {
                    assert!(
                        Instant::now() < gone_by,
                        "the shim outlived bwrap's outer process"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_crash_in_a_jail_exits_with_the_signal_code() {
        if !bwrap_works() {
            return;
        }
        let (dir, config) = fifo_config("jail-crash");

        let mut outer = bwrap(SHIM).arg(&config).spawn().unwrap();
        let _writer = open_for_writing(&config);
        let shim = Command::new("pgrep")
            .args(["-P", &outer.id().to_string()])
            .output()
            .unwrap();
        send_abort(String::from_utf8(shim.stdout).unwrap().trim());

        assert_eq!(outer.wait().unwrap().code(), Some(128 + 6));
        drop(fs::remove_dir_all(&dir));
    }
}
