//! Exclusive `waitpid(-1, WNOHANG)` child reaper for PID 1.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;

/// PID 1 child reaper. Clone is cheap (`Arc`).
#[derive(Clone, Debug)]
pub struct Reaper {
    /// Shared waiter table and reap lock.
    inner: Arc<Mutex<Inner>>,
}

/// Map of watched pids to oneshot senders.
#[derive(Debug)]
struct Inner {
    /// Registered waiters; unknown pids are orphans.
    waiters: HashMap<u32, oneshot::Sender<Exit>>,
}

/// Wait status for one child. `code` is `0..=255` or `128+sig`.
#[derive(Clone, Copy, Debug)]
pub struct Exit {
    /// Child pid as returned by spawn.
    pub pid: u32,
    /// Exit code, or `128 + signal` if killed by a signal.
    pub code: i32,
    /// Terminating signal number, if any.
    pub signal: Option<i32>,
}

/// Result of [`Reaper::spawn`]: pipes still on `child`; status on `exit`.
#[derive(Debug)]
pub struct Spawned {
    /// Child process; drop after taking stdio. Drop does not `waitpid`.
    pub child: std::process::Child,
    /// Completes when the reaper observes this child's exit.
    pub exit: oneshot::Receiver<Exit>,
}

impl Reaper {
    /// Install the SIGCHLD handler and spawn the drain task. Once per process.
    ///
    /// # Errors
    ///
    /// Returns an error if the SIGCHLD handler cannot be registered.
    pub fn start() -> io::Result<Self> {
        let inner = Arc::new(Mutex::new(Inner {
            waiters: HashMap::new(),
        }));
        let sig = signal(SignalKind::child())?;
        tokio::spawn(drain_sigchld(sig, Arc::clone(&inner)));
        Ok(Self { inner })
    }

    /// Fork/exec with the reap lock held so a concurrent SIGCHLD drain cannot
    /// discard this pid as an orphan before it is in `waiters`.
    ///
    /// # Errors
    ///
    /// Returns an error if `cmd` fails to spawn.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "mutex must be held across spawn, insert, and drain"
    )]
    pub fn spawn(&self, cmd: &mut std::process::Command) -> io::Result<Spawned> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        reap(&mut g);
        let child = cmd.spawn()?;
        let pid = child.id();
        let (tx, rx) = oneshot::channel();
        g.waiters.insert(pid, tx);
        reap(&mut g); // child already a zombie between fork and insert
        Ok(Spawned { child, exit: rx })
    }

    /// Spawn a child with no waiter. The reaper treats it as an orphan.
    ///
    /// Tests use this; production exec does not. Do not `waitpid` in the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if `cmd` fails to spawn.
    #[allow(
        clippy::unused_self,
        reason = "method form matches spawn; unwatched children still belong to this reaper"
    )]
    pub fn spawn_unwatched(&self, cmd: &mut std::process::Command) -> io::Result<u32> {
        let child = cmd.spawn()?;
        Ok(child.id())
        // std::process::Child drop does not waitpid.
    }
}

/// SIGCHLD task: drain zombies until the signal stream ends.
async fn drain_sigchld(mut sig: Signal, inner: Arc<Mutex<Inner>>) {
    loop {
        let Some(()) = sig.recv().await else {
            break;
        };
        reap_locked(&inner);
    }
}

/// Drain `waitpid` while holding `inner`.
fn reap_locked(inner: &Arc<Mutex<Inner>>) {
    let mut g = inner.lock().unwrap_or_else(PoisonError::into_inner);
    reap(&mut g);
}

/// Non-blocking `waitpid(-1)` until `ECHILD` or `StillAlive`.
fn reap(inner: &mut Inner) {
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
            Err(nix::errno::Errno::EINTR) => {} // do not stop the PID 1 reaper
            Ok(st) => {
                let Some((pid, exit)) = decode(st) else {
                    continue;
                };
                let Some(tx) = inner.waiters.remove(&pid) else {
                    continue;
                };
                let _ = tx.send(exit);
            }
            Err(e) => {
                eprintln!("[bux-guest] reaper waitpid: {e}");
                break;
            }
        }
    }
}

/// Map an exit/signal wait status to [`Exit`]. Job-control statuses are ignored.
const fn decode(st: WaitStatus) -> Option<(u32, Exit)> {
    match st {
        WaitStatus::Exited(pid, code) => {
            let pid = pid.as_raw().cast_unsigned();
            Some((
                pid,
                Exit {
                    pid,
                    code,
                    signal: None,
                },
            ))
        }
        WaitStatus::Signaled(pid, sig, _) => {
            let pid = pid.as_raw().cast_unsigned();
            let s = sig as i32;
            Some((
                pid,
                Exit {
                    pid,
                    code: 128 + s,
                    signal: Some(s),
                },
            ))
        }
        // Stopped / Continued / PtraceEvent / PtraceSyscall: not an exit.
        _ => None,
    }
}
