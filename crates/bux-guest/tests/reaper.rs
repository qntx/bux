//! Reaper integration: exclusive waitpid demux, signaled encoding, orphan reap.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::panic,
    reason = "linux-only integration test binary"
)]
#![cfg(target_os = "linux")]

use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use bux_guest::reaper::{Exit, Reaper, Spawned};
use tokio::sync::oneshot;

/// `sh -c` with stdio discarded.
fn sh(script: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// Await a reaper oneshot with a 2s timeout.
async fn wait_exit(rx: oneshot::Receiver<Exit>) -> Exit {
    tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .expect("timeout waiting for child exit")
        .expect("reaper dropped waiter")
}

/// Drop the child and return its waiter.
fn take_exit(spawned: Spawned) -> oneshot::Receiver<Exit> {
    spawned.exit
}

/// True when the unwatched child is gone (`/proc` or `kill(pid, 0)`).
fn orphan_gone(pid: u32) -> bool {
    if std::path::Path::new("/proc").is_dir() {
        return !std::path::Path::new(&format!("/proc/{pid}")).exists();
    }
    let raw = nix::unistd::Pid::from_raw(pid.cast_signed());
    nix::sys::signal::kill(raw, None) == Err(nix::errno::Errno::ESRCH)
}

/// Poll until `pid` is reaped. Must `.await` so the current-thread reaper runs.
async fn wait_orphan_gone(pid: u32) {
    loop {
        if orphan_gone(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Sequential cases: exit codes, demux, signaled encoding, orphan reap.
#[tokio::test(flavor = "current_thread")]
async fn reaper_reports_exit_codes_and_reaps_orphans() {
    let reaper = Reaper::start().expect("Reaper::start");

    // 1. exit 42
    let mut cmd_42 = sh("exit 42");
    let spawned_42 = match reaper.spawn(&mut cmd_42) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("skipping: sh not found");
            return;
        }
        Err(e) => panic!("spawn sh: {e}"),
    };
    let exit_42 = wait_exit(take_exit(spawned_42)).await;
    assert_eq!(exit_42.code, 42);
    assert_eq!(exit_42.signal, None);

    // 2. true / exit 0
    let mut cmd_true = sh("exit 0");
    let spawned_true = reaper.spawn(&mut cmd_true).expect("spawn exit 0");
    let exit_true = wait_exit(take_exit(spawned_true)).await;
    assert_eq!(exit_true.code, 0);
    assert_eq!(exit_true.signal, None);

    // 3. concurrent demux
    let mut cmd3 = sh("exit 3");
    let spawned_3 = reaper.spawn(&mut cmd3).expect("spawn exit 3");
    let mut cmd5 = sh("exit 5");
    let spawned_5 = reaper.spawn(&mut cmd5).expect("spawn exit 5");
    let pid3 = spawned_3.child.id();
    let pid5 = spawned_5.child.id();
    let exit_3 = wait_exit(take_exit(spawned_3)).await;
    let exit_5 = wait_exit(take_exit(spawned_5)).await;
    assert_eq!(exit_3.pid, pid3);
    assert_eq!(exit_3.code, 3);
    assert_eq!(exit_5.pid, pid5);
    assert_eq!(exit_5.code, 5);

    // 4. SIGKILL → 128+9
    let mut cmd_kill = sh("kill -s KILL $$");
    let spawned_kill = reaper.spawn(&mut cmd_kill).expect("spawn kill");
    let exit_kill = wait_exit(take_exit(spawned_kill)).await;
    assert_eq!(exit_kill.signal, Some(9));
    assert_eq!(exit_kill.code, 137);

    // 5. unwatched orphan is reaped (poll must .await so the reaper task runs)
    let mut cmd_orphan = sh("exit 0");
    let orphan_pid = reaper
        .spawn_unwatched(&mut cmd_orphan)
        .expect("spawn_unwatched");
    tokio::time::timeout(Duration::from_secs(2), wait_orphan_gone(orphan_pid))
        .await
        .expect("orphan still present; reaper not polled or not reaping");
}
