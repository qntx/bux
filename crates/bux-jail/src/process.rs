//! Shim process identity, liveness, and the parent keepalive.
//!
//! A pid alone cannot name a process across a host restart: once the shim
//! exits, the OS may hand its pid to an unrelated process. [`ShimProcess`]
//! pairs the pid with the process start time and treats a pid whose start
//! time differs as a process that is gone.
//!
//! With a jail, the recorded process is bwrap's outer process and the shim is
//! PID 1 of the new namespace. Both are in the process group that
//! [`spawn`](crate::spawn) creates, and signals go to that group.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, pipe};

/// How long [`ShimProcess::kill`] waits for the killed processes to be gone.
const KILL_WAIT: Duration = Duration::from_secs(10);

/// Whether [`ShimProcess::kill`] sent `SIGKILL` to the group, which it does only
/// while the pid still names this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signalled {
    /// The group was sent `SIGKILL`.
    Group,
    /// The pid no longer named this process, so nothing was sent.
    Nothing,
}

/// A `bux-shim` process, identified by pid and start time.
///
/// Plain identity: safe to persist and to rebuild with [`Self::open`]
/// after a host restart. Every operation first checks that the pid still
/// belongs to the same process, so a reused pid is never signalled.
///
/// The process must lead its own process group, as [`crate::spawn`] arranges:
/// signals go to the group, which is the whole jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimProcess {
    /// OS process id.
    pid: u32,
    /// Opaque start time read when the process was identified.
    start_time: u64,
}

impl ShimProcess {
    /// Rebuild a handle from a stored pid and start time.
    #[must_use]
    pub const fn open(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }

    /// Identify the process that currently holds `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::NotFound`] if no process has this pid.
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        let start_time = start_time(pid).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no process with pid {pid}"),
            )
        })?;
        Ok(Self { pid, start_time })
    }

    /// OS process id.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Start time as an opaque token: clock ticks since boot on Linux,
    /// microseconds since the Unix epoch on macOS. Only compare it.
    #[must_use]
    pub const fn start_time(self) -> u64 {
        self.start_time
    }

    /// `true` while the pid still belongs to this process and it has not
    /// exited. An exited child that is not reaped yet (a zombie) is not alive.
    #[must_use]
    pub fn is_alive(self) -> bool {
        start_time(self.pid) == Some(self.start_time)
    }

    /// Reap the process if it is an exited child of this process, and return
    /// how it ended.
    ///
    /// `None` if it is still running, is not a child of this process, or was
    /// already reaped. Linux only: there the exited process can still be told
    /// apart from a reused pid. Elsewhere this always returns `None`.
    #[must_use]
    #[allow(
        clippy::unused_self,
        clippy::missing_const_for_fn,
        reason = "only Linux can reap safely; elsewhere this returns None"
    )]
    pub fn try_reap(self) -> Option<ExitStatus> {
        #[cfg(target_os = "linux")]
        {
            let stat = stat(self.pid)?;
            if stat.state != 'Z' || stat.start_time != self.start_time {
                return None;
            }
            match waitpid(self.nix_pid(), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => Some(ExitStatus::from_raw((code & 0xff) << 8)),
                Ok(WaitStatus::Signaled(_, signal, core)) => Some(ExitStatus::from_raw(
                    signal as i32 | if core { 0x80 } else { 0 },
                )),
                _ => None,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Ask the process group to exit (`SIGTERM`). A process that is gone is not an error.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the signal cannot be delivered.
    pub fn terminate(self) -> io::Result<()> {
        if self.is_alive() {
            self.deliver(Signal::SIGTERM)?;
        }
        Ok(())
    }

    /// Kill the process group (`SIGKILL`) and wait until none of it is left,
    /// up to 10 s. A process that is gone is not an error.
    ///
    /// This blocks the calling thread, so async code runs it on a blocking one.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the signal cannot be delivered or the group cannot be
    /// checked, and [`io::ErrorKind::TimedOut`] if a process of the group is still
    /// alive.
    pub fn kill(self) -> io::Result<()> {
        let signalled = if self.is_alive() {
            self.deliver(Signal::SIGKILL)?;
            Signalled::Group
        } else {
            Signalled::Nothing
        };
        self.wait_group_gone(signalled, KILL_WAIT)
    }

    /// Send the POSIX signal number `sig` to the process group.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an unknown signal, and
    /// `ESRCH` if the process is gone.
    pub fn signal(self, sig: i32) -> io::Result<()> {
        let sig = Signal::try_from(sig).map_err(io::Error::from)?;
        if !self.is_alive() {
            return Err(Errno::ESRCH.into());
        }
        self.killpg(sig).map_err(io::Error::from)
    }

    /// Block until the process exits.
    ///
    /// Reaps the process when it is a child of this process; otherwise polls.
    #[allow(
        clippy::disallowed_methods,
        reason = "blocking wait runs on a blocking thread, not in async code"
    )]
    pub fn wait(self) {
        if self.try_reap().is_some() {
            return;
        }
        if !self.is_alive() {
            // macOS cannot look up a zombie, so an exited child may still need reaping.
            #[cfg(not(target_os = "linux"))]
            let _reaped = waitpid(self.nix_pid(), Some(WaitPidFlag::WNOHANG));
            return;
        }
        if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(self.nix_pid(), None)
        {
            return;
        }
        while self.is_alive() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Deliver `sig` to the group. A group that is gone is not an error.
    fn deliver(self, sig: Signal) -> io::Result<()> {
        match self.killpg(sig) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// `killpg`, with the `EPERM` macOS returns for a group of only zombies
    /// reported as `ESRCH`.
    fn killpg(self, sig: Signal) -> nix::Result<()> {
        match signal::killpg(self.nix_pid(), sig) {
            #[cfg(not(target_os = "linux"))]
            Err(Errno::EPERM) if !self.is_alive() => Err(Errno::ESRCH),
            result => result,
        }
    }

    /// Poll until no process of the group is alive. A check that fails counts as
    /// not gone.
    #[allow(
        clippy::disallowed_methods,
        reason = "blocks its thread; `Vm` runs it on a blocking one, and the error-path teardowns accept the wait"
    )]
    fn wait_group_gone(self, signalled: Signalled, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.group_gone(signalled) {
                Ok(true) => return Ok(()),
                last if Instant::now() >= deadline => {
                    return Err(self.not_gone_error(last.err(), timeout));
                }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// The error for a group not seen gone within `timeout`. `failure` is why the
    /// last check could not tell, if it could not.
    fn not_gone_error(self, failure: Option<io::Error>, timeout: Duration) -> io::Error {
        let Some(e) = failure else {
            return io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "process group {0} is still alive after {1} s; stop it with: kill -9 -- -{0}",
                    self.pid,
                    timeout.as_secs()
                ),
            );
        };
        io::Error::new(
            e.kind(),
            format!(
                "cannot tell whether process group {} is gone: {e}",
                self.pid
            ),
        )
    }

    /// `true` once no process of the group is alive, reaping this process if it
    /// is an exited child of this process. Zombies do not count.
    ///
    /// A group keeps its id reserved as a pid until its last process is gone. So
    /// another process with this pid means the group is gone, and a pid that
    /// no process holds can still name a group whose leader was killed alone.
    ///
    /// # Errors
    ///
    /// Returns the error from [`live_group_members`].
    #[cfg(target_os = "linux")]
    fn group_gone(self, _signalled: Signalled) -> io::Result<bool> {
        match stat(self.pid) {
            Some(stat) if stat.start_time != self.start_time => Ok(true),
            Some(stat) if !matches!(stat.state, 'Z' | 'X') => Ok(false),
            _ => {
                let _reaped = self.try_reap();
                Ok(live_group_members(self.pid)? == 0)
            }
        }
    }

    /// `true` once the process is gone, reaping it if it is a child of this
    /// process. On macOS the group is the shim alone: `sandbox-exec` execs it in
    /// place.
    ///
    /// macOS cannot look up a zombie, so a child that `waitpid` finds running is
    /// known to be this process only if `kill` signalled it: `kill` checks the pid
    /// right before the signal.
    ///
    /// # Errors
    ///
    /// Returns the error from `waitpid`, other than `ECHILD` for a process that is
    /// not a child of this process.
    #[cfg(not(target_os = "linux"))]
    fn group_gone(self, signalled: Signalled) -> io::Result<bool> {
        match waitpid(self.nix_pid(), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(signalled == Signalled::Nothing),
            Ok(_) => Ok(true),
            Err(Errno::ECHILD) => Ok(!self.is_alive()),
            Err(e) => Err(e.into()),
        }
    }

    /// pid as a `nix` [`Pid`].
    #[allow(
        clippy::cast_possible_wrap,
        reason = "pids are positive and below i32::MAX on Unix"
    )]
    const fn nix_pid(self) -> Pid {
        Pid::from_raw(self.pid as i32)
    }
}

/// Parent end of the watchdog pipe.
///
/// While it is held, the shim's read end stays open. Dropping it (or the
/// parent exiting) closes the pipe; the shim sees `POLLHUP` and shuts down.
/// This works on every Unix platform, unlike `PR_SET_PDEATHSIG`.
#[derive(Debug)]
pub struct Keepalive(#[allow(dead_code, reason = "dropped to close the pipe")] OwnedFd);

/// Create the watchdog pipe: `(shim read end, parent keepalive)`.
///
/// The read end has no `O_CLOEXEC` so it survives `exec` into the shim.
/// The write end has `O_CLOEXEC` so it does not leak into the child.
pub(crate) fn watchdog_pipe() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;
    fcntl(write_fd.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok((read_fd, Keepalive(write_fd)))
}

/// Start time of `pid`, or `None` if no such process exists or it has exited.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    stat(pid)
        .filter(|stat| !matches!(stat.state, 'Z' | 'X'))
        .map(|stat| stat.start_time)
}

/// Processes in group `pgid` that have not exited.
///
/// # Errors
///
/// Returns the error from listing `/proc` or from [`read_stat`]: a process left
/// out could be a live member.
#[cfg(target_os = "linux")]
pub(crate) fn live_group_members(pgid: u32) -> io::Result<usize> {
    let mut live = 0;
    for entry in std::fs::read_dir("/proc")? {
        let name = entry?.file_name();
        // Only the numeric entries are processes.
        let Some(pid) = name.to_str().and_then(|text| text.parse().ok()) else {
            continue;
        };
        let live_member = read_stat(pid)?
            .is_some_and(|stat| stat.pgrp == pgid && !matches!(stat.state, 'Z' | 'X'));
        if live_member {
            live += 1;
        }
    }
    Ok(live)
}

/// Fields of `/proc/<pid>/stat` that identify a process.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct Stat {
    /// Field 3: `R`, `S`, `D`, ..., `Z` for a zombie, `X` for dead.
    state: char,
    /// Field 5: process group id.
    pgrp: u32,
    /// Field 22: clock ticks since boot.
    start_time: u64,
}

/// `/proc/<pid>/stat` of `pid`, or `None` if no such process exists or it cannot
/// be read.
#[cfg(target_os = "linux")]
fn stat(pid: u32) -> Option<Stat> {
    read_stat(pid).ok().flatten()
}

/// `/proc/<pid>/stat` of `pid`, or `None` if no such process exists or it belongs
/// to another user: a group this process started holds only this user's
/// processes, which `/proc` shows to their owner.
///
/// # Errors
///
/// Returns the error from reading it otherwise, such as `EMFILE`, and
/// [`io::ErrorKind::InvalidData`] if it does not parse.
#[cfg(target_os = "linux")]
fn read_stat(pid: u32) -> io::Result<Option<Stat>> {
    let path = format!("/proc/{pid}/stat");
    match std::fs::read(&path) {
        Ok(bytes) => parse_stat(&bytes).map(Some).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("cannot parse {path}"))
        }),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) || e.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Fields 3 (`state`), 5 (`pgrp`) and 22 (`starttime`) of `/proc/<pid>/stat`.
///
/// `comm` (field 2) is the process name as raw bytes. It may contain spaces and
/// parentheses, and need not be UTF-8: the kernel cuts it to 15 bytes, which can
/// split a character, and a process can set it to any bytes. So fields are
/// counted from the last `)`, which closes it, and only the fields after it are
/// read as text.
#[cfg(any(target_os = "linux", test))]
fn parse_stat(stat: &[u8]) -> Option<Stat> {
    let comm_end = stat.iter().rposition(|&byte| byte == b')')?;
    // `rest` starts at field 3 (state).
    let rest = std::str::from_utf8(stat.get(comm_end + 1..)?).ok()?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let pgrp = fields.nth(1)?.parse().ok()?;
    let start_time = fields.nth(16)?.parse().ok()?;
    Some(Stat {
        state,
        pgrp,
        start_time,
    })
}

/// Start time of `pid`, or `None` if no such process exists.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "proc_pidinfo fills a caller-owned proc_bsdinfo")]
fn start_time(pid: u32) -> Option<u64> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is a writable buffer of exactly `size` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole struct (written == size).
    let info = unsafe { info.assume_init() };
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    use super::*;

    fn sleep_child() -> (Child, ShimProcess) {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let process = ShimProcess::from_pid(child.id()).unwrap();
        (child, process)
    }

    /// A `/bin/sh -c` group leader that runs `script` once its stdin closes,
    /// identified while it is still running.
    fn exiting_child(script: &str) -> (Child, ShimProcess) {
        let child = Command::new("/bin/sh")
            .args(["-c", &format!("read _; {script}")])
            .stdin(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let process = ShimProcess::from_pid(child.id()).unwrap();
        (child, process)
    }

    /// Check that `process`, a child of this process, leaves no zombie: `waitpid`
    /// only fails for a child that has been reaped.
    fn assert_reaped(process: ShimProcess) {
        assert_eq!(
            waitpid(process.nix_pid(), Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD),
            "a zombie is left"
        );
    }

    #[test]
    fn kill_reaps_a_child() {
        let (_child, process) = sleep_child();
        process.kill().unwrap();
        assert_reaped(process);
    }

    /// macOS: a zombie cannot be looked up, `killpg` on it returns `EPERM`, and
    /// only `waitpid` removes it. The sleep lets the exit finish.
    #[cfg(not(target_os = "linux"))]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "no way to observe a macOS zombie"
    )]
    fn a_zombie_counts_as_gone_and_wait_reaps_it() {
        let (mut child, process) = exiting_child("exit 0");
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while process.is_alive() {
            assert!(Instant::now() < deadline, "the child did not exit");
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(500));

        assert_eq!(process.killpg(Signal::SIGTERM), Err(Errno::ESRCH));
        process.terminate().unwrap();
        process.kill().unwrap();
        assert_reaped(process);
    }

    /// Block until `pid` has exited and is a zombie.
    #[cfg(target_os = "linux")]
    fn wait_for_zombie(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while stat(pid).is_some_and(|stat| stat.state != 'Z') {
            assert!(Instant::now() < deadline, "pid {pid} did not exit");
            std::thread::yield_now();
        }
    }

    #[test]
    fn parses_state_and_start_time_after_last_paren() {
        let stat = b"42 (a) b (c)) S 1 43 44 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1 2";
        let expected = Stat {
            state: 'S',
            pgrp: 43,
            start_time: 98_765,
        };
        assert_eq!(parse_stat(stat), Some(expected));
        let zombie = b"7 (sh) Z 1 7 7 0 -1 4227084 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0";
        assert_eq!(parse_stat(zombie).map(|parsed| parsed.state), Some('Z'));
        assert_eq!(parse_stat(b"42 (x) S 1"), None);
        assert_eq!(parse_stat(b"no paren"), None);
    }

    #[test]
    fn parses_a_name_that_is_not_utf8() {
        // The name ends in the first two bytes of a three-byte character.
        let stat = b"42 (a\xe5\x90) S 1 43 44 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1 2";
        let expected = Stat {
            state: 'S',
            pgrp: 43,
            start_time: 98_765,
        };
        assert_eq!(parse_stat(stat), Some(expected));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exited_child_is_not_alive_and_is_reaped_once() {
        let (mut child, process) = exiting_child("exit 3");
        assert!(
            process.try_reap().is_none(),
            "a running child is not reaped"
        );
        drop(child.stdin.take());
        wait_for_zombie(process.pid());
        assert!(!process.is_alive(), "a zombie is not alive");
        assert_eq!(process.try_reap().unwrap().code(), Some(3));
        assert!(process.try_reap().is_none(), "already reaped");
        assert!(stat(process.pid()).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn try_reap_reports_the_killing_signal() {
        let (mut child, process) = exiting_child("kill -KILL $$");
        drop(child.stdin.take());
        wait_for_zombie(process.pid());
        assert_eq!(process.try_reap().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wait_reaps_an_exited_child() {
        let (mut child, process) = exiting_child("exit 0");
        drop(child.stdin.take());
        wait_for_zombie(process.pid());
        process.wait();
        assert!(stat(process.pid()).is_none(), "wait must reap the zombie");
    }

    #[test]
    fn own_process_is_alive() {
        let me = ShimProcess::from_pid(std::process::id()).unwrap();
        assert!(me.is_alive());
        assert_eq!(me, ShimProcess::open(me.pid(), me.start_time()));
    }

    #[test]
    fn different_start_time_is_gone() {
        let (mut child, process) = sleep_child();
        let reused = ShimProcess::open(process.pid(), process.start_time() + 1);
        assert!(!reused.is_alive());
        reused.kill().unwrap();
        assert!(
            process.is_alive(),
            "kill on a mismatched start time must not signal the live process"
        );
        assert_eq!(
            reused.signal(libc::SIGTERM).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn kill_then_wait_reaps_child() {
        let (_child, process) = sleep_child();
        assert!(process.is_alive());
        process.kill().unwrap();
        process.wait();
        assert!(!process.is_alive());
        process.kill().unwrap();
    }

    /// A second process in `leader`'s group, which the leader does not wait for.
    #[cfg(target_os = "linux")]
    fn group_member(leader: ShimProcess) -> Child {
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(leader.pid().try_into().unwrap())
            .spawn()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kill_takes_the_whole_group_and_waits() {
        let (_child, process) = exiting_child("");
        let mut member = group_member(process);
        assert_eq!(live_group_members(process.pid()).unwrap(), 2);

        process.kill().unwrap();

        assert_eq!(live_group_members(process.pid()).unwrap(), 0);
        assert!(!process.is_alive());
        assert_eq!(member.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    /// A second process in `leader`'s group, named with the byte `0xff`, which is
    /// not UTF-8. It runs until its stdin closes and is returned once named.
    #[cfg(target_os = "linux")]
    fn group_member_not_named_in_utf8(leader: ShimProcess) -> Child {
        use std::io::Read;

        let mut member = Command::new("/bin/sh")
            .args(["-c", r"printf '\377' > /proc/self/comm && echo && read _"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .process_group(leader.pid().try_into().unwrap())
            .spawn()
            .unwrap();
        // The shell writes a line once it is named.
        let mut stdout = member.stdout.take().unwrap();
        stdout.read_exact(&mut [0_u8]).unwrap();
        let comm = std::fs::read(format!("/proc/{}/comm", member.id())).unwrap();
        assert_eq!(comm, b"\xff\n");
        member
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_member_not_named_in_utf8_is_counted_and_killed() {
        let (_child, process) = exiting_child("");
        let mut member = group_member_not_named_in_utf8(process);
        assert_eq!(live_group_members(process.pid()).unwrap(), 2);

        process.kill().unwrap();

        assert_eq!(live_group_members(process.pid()).unwrap(), 0);
        assert_eq!(member.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_member_outliving_the_leader_is_reported() {
        let (mut leader, process) = exiting_child("exit 0");
        let mut member = group_member(process);
        drop(leader.stdin.take());
        drop(leader.wait());

        let err = process
            .wait_group_gone(Signalled::Nothing, Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        drop(member.kill());
        drop(member.wait());
        process
            .wait_group_gone(Signalled::Nothing, KILL_WAIT)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reused_pid_means_the_group_is_gone() {
        let (_child, live) = exiting_child("");
        let reused = ShimProcess::open(live.pid(), live.start_time() + 1);
        reused
            .wait_group_gone(Signalled::Nothing, Duration::ZERO)
            .unwrap();
        assert!(live.is_alive());
        live.kill().unwrap();
    }

    /// Opens `/dev/null` until this process has no file descriptor left, under a
    /// limit lowered so that this takes few files.
    #[cfg(target_os = "linux")]
    fn use_up_fds() -> Vec<std::fs::File> {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};

        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, 64, hard).unwrap();
        let mut held = Vec::new();
        let err = loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(e) => break e,
            }
        };
        assert_eq!(err.raw_os_error(), Some(libc::EMFILE), "{err}");
        held
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_group_that_cannot_be_read_is_not_taken_for_gone() {
        const NAME: &str = "process::tests::a_group_that_cannot_be_read_is_not_taken_for_gone";
        const IN_CHILD: &str = "BUX_JAIL_TEST_IN_CHILD";
        // Using up the file descriptors would fail the tests running next to this
        // one, so the body runs alone in a child of this test binary.
        if std::env::var_os(IN_CHILD).is_none() {
            let child = Command::new(std::env::current_exe().unwrap())
                .args([NAME, "--exact", "--test-threads=1"])
                .env(IN_CHILD, "1")
                .output()
                .unwrap();
            let report = String::from_utf8_lossy(&child.stdout);
            // A `NAME` that no longer matches would run no test and still succeed.
            assert!(
                child.status.success() && report.contains("1 passed"),
                "{report}"
            );
            return;
        }

        let (mut leader, process) = exiting_child("exit 0");
        let mut member = group_member(process);
        drop(leader.stdin.take());
        wait_for_zombie(process.pid());

        let mut held = use_up_fds();
        let unlisted = process.wait_group_gone(Signalled::Nothing, Duration::ZERO);
        // One descriptor: enough to list `/proc`, not to read the processes in it.
        drop(held.pop().unwrap());
        let unread = process.wait_group_gone(Signalled::Nothing, Duration::ZERO);
        drop(held);
        // The member holds the output that the parent reads to the end, so it is
        // stopped before a check can fail.
        drop(member.kill());
        drop(member.wait());
        drop(leader.wait());

        for result in [unlisted, unread] {
            let err = result.unwrap_err();
            assert_ne!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        }
        process
            .wait_group_gone(Signalled::Nothing, KILL_WAIT)
            .unwrap();
    }

    #[test]
    fn terminate_stops_child() {
        let (_child, process) = sleep_child();
        process.terminate().unwrap();
        process.wait();
        assert!(!process.is_alive());
    }

    #[test]
    fn unknown_signal_is_invalid_input() {
        let me = ShimProcess::from_pid(std::process::id()).unwrap();
        assert_eq!(
            me.signal(9999).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dropping_keepalive_hangs_up_reader() {
        let (read_end, keepalive) = watchdog_pipe().unwrap();
        drop(keepalive);
        let mut buf = [0_u8; 1];
        let n = nix::unistd::read(&read_end, &mut buf).unwrap();
        assert_eq!(n, 0, "reader must see EOF once the keepalive is dropped");
    }
}
