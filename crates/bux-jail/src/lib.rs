//! Process isolation for the `bux-shim` child process.
//!
//! The [`Sandbox`] trait abstracts platform-specific sandboxing:
//! - **Linux**: bubblewrap namespace isolation (via [`bux-bwrap`]) + Landlock (K22).
//!   Auto-detect without `bwrap` is [`Error::BwrapUnavailable`], not a no-op.
//! - **macOS**: `sandbox-exec` with a deny-default SBPL profile.
//! - **Explicit [`NoopSandbox`]**: bare `Command` with pre-exec hardening only.
//!
//! The default sandbox is auto-detected at runtime. Override via
//! [`JailConfig::sandbox`].
//!
//! [`spawn`] returns the shim as a [`ShimProcess`] (pid plus start time,
//! safe against pid reuse) and, unless the VM is detached, a [`Keepalive`]
//! that ties the shim's lifetime to this process.

/// Host capability probes.
pub mod checks;
mod error;
mod pre_exec;
mod process;
/// Security layer status types.
pub mod security;

#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(target_os = "linux")]
mod landlock_setup;
#[cfg(target_os = "macos")]
mod seatbelt;

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub use error::{Error, Result};
pub use process::{Keepalive, ShimProcess};
pub use security::{LayerStatus, SandboxKind, SecurityReport};

#[cfg(target_os = "linux")]
use bwrap::BwrapSandbox;
#[cfg(target_os = "macos")]
use seatbelt::SeatbeltSandbox;

/// Environment variable set on the shim child when it gets a watchdog pipe.
///
/// Value is the decimal file descriptor number. Must match
/// `bux_shim::ENV_WATCHDOG_FD` / the shim binary.
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

/// Environment variable set on the shim child when it gets a Landlock ruleset.
///
/// Value is the decimal file descriptor number. Must match
/// `bux_shim::ENV_LANDLOCK_FD` / the shim binary.
pub const ENV_LANDLOCK_FD: &str = "BUX_LANDLOCK_FD";

/// Describes the isolation features provided by a [`Sandbox`] implementation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools, reason = "capability flags struct")]
pub struct SandboxCapabilities {
    /// Whether the sandbox provides namespace isolation (mount, PID, net, etc.).
    pub namespaces: bool,
    /// Whether the sandbox applies seccomp BPF syscall filtering.
    pub seccomp: bool,
    /// Whether mandatory access control is enforced (AppArmor/SELinux/Seatbelt).
    pub mandatory_access_control: bool,
}

/// Trait for platform-specific process sandboxing.
///
/// Implementations wrap a `Command` with isolation primitives (namespaces,
/// seatbelt profiles, seccomp, etc.) before the shim process is spawned.
pub trait Sandbox: std::fmt::Debug + Send + Sync {
    /// Wraps the shim invocation with sandbox-specific isolation.
    ///
    /// Returns a pre-configured [`Command`] that will execute the shim
    /// inside the sandbox, or `None` if the sandbox is not available on
    /// this system (e.g. bwrap binary not installed).
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command>;

    /// Returns the isolation capabilities this sandbox provides.
    ///
    /// Used for security auditing and reporting.
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::default()
    }

    /// Stable kind label for security reports.
    fn kind(&self) -> SandboxKind {
        SandboxKind::Noop
    }
}

/// No-op sandbox: runs the shim directly with no additional isolation.
///
/// Pre-exec hardening (FD cleanup, die-with-parent) is still applied, and the
/// shim still applies Landlock to itself.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, _jail: &JailConfig) -> Option<Command> {
        let mut cmd = Command::new(shim);
        cmd.arg(config_path);
        Some(cmd)
    }

    fn kind(&self) -> SandboxKind {
        SandboxKind::Noop
    }
}

/// Sandbox configuration for a single VM spawn.
///
/// Constructed by the Runtime (or tests). Not `non_exhaustive` so
/// in-workspace callers can fill all fields explicitly without a builder.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "isolation flags are independent booleans, not a state machine"
)]
pub struct JailConfig {
    /// Path to the rootfs directory (if using directory-based root).
    pub rootfs: Option<PathBuf>,
    /// Path to the root disk image (if using disk-based root).
    pub root_disk: Option<PathBuf>,
    /// Extra read-only paths (e.g. QCOW2 backing chain). Filled by Runtime.
    pub readonly_paths: Vec<PathBuf>,
    /// Directory containing Unix sockets for vsock.
    pub socks_dir: PathBuf,
    /// Host paths for virtiofs mounts.
    pub virtiofs_paths: Vec<PathBuf>,
    /// Override the default platform sandbox.
    ///
    /// When `None`, auto-detects: bwrap on Linux (fail-closed without
    /// [`Self::bwrap_path`]), seatbelt on macOS, noop on other Unix.
    /// Explicit [`NoopSandbox`] is the only way to skip the Linux jailer.
    pub sandbox: Option<Box<dyn Sandbox>>,
    /// Log file for the child's stdout and stderr. When `None`, stdout goes
    /// to `/dev/null` and stderr is inherited.
    pub log_file: Option<std::fs::File>,
    /// Request Landlock LSM on Linux (default product: true on Linux).
    ///
    /// When true and the kernel cannot enforce Landlock, spawn fails unless
    /// [`Self::allow_degraded_security`] is set (K22).
    pub landlock: bool,
    /// If true, missing Landlock (when requested) degrades instead of failing.
    pub allow_degraded_security: bool,
    /// Tie the shim's lifetime to this process: a watchdog pipe whose
    /// [`Keepalive`] end is returned in [`SpawnResult::keepalive`],
    /// `PR_SET_PDEATHSIG`, and bwrap `--die-with-parent`.
    ///
    /// Default true. False when the VM is detached.
    pub die_with_parent: bool,
    /// Allow host networking inside the jail (gvproxy bind, DNS, resolver files).
    ///
    /// True when the VM uses virtio-net.
    pub network_host: bool,
    /// Absolute `bwrap` binary. Required on Linux when the jailer is on.
    pub bwrap_path: Option<PathBuf>,
}

/// Result of spawning a shim process inside a sandbox.
#[derive(Debug)]
pub struct SpawnResult {
    /// The spawned process (the jail parent when a sandbox wraps the shim).
    pub process: ShimProcess,
    /// Parent end of the watchdog pipe. `Some` iff [`JailConfig::die_with_parent`].
    pub keepalive: Option<Keepalive>,
    /// Actual security posture for this spawn.
    pub security: SecurityReport,
}

/// Spawn `bux-shim` inside a sandbox.
///
/// Applies platform-specific isolation, then pre-exec hardening (FD cleanup,
/// die-with-parent). With [`JailConfig::die_with_parent`], also creates the
/// watchdog pipe and passes its read end to the shim via [`ENV_WATCHDOG_FD`].
///
/// When Landlock is requested, builds the ruleset and passes it to the shim via
/// [`ENV_LANDLOCK_FD`]. The shim must apply it itself: bwrap, which runs first,
/// cannot build its sandbox inside a Landlock domain.
///
/// # Errors
///
/// Returns [`Error::Io`] if the process cannot be spawned,
/// [`Error::LandlockUnavailable`] when Landlock is required but missing (K22),
/// [`Error::BwrapUnavailable`] when Linux auto-detect cannot wrap with `bwrap`,
/// or [`Error::Landlock`] on ruleset construction failure.
#[allow(
    unsafe_code,
    reason = "own the landlock ruleset fd so Drop closes it on every error path"
)]
pub fn spawn(shim: &Path, config_path: &Path, config: JailConfig) -> Result<SpawnResult> {
    let (mut cmd, sandbox_kind) = build_command(shim, config_path, &config)?;
    let (landlock_raw, landlock_status) = prepare_landlock(&config, shim, config_path)?;
    let landlock_owned = landlock_raw.map(|fd| {
        // SAFETY: `prepare_landlock` yields an exclusively owned ruleset fd.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    cmd.stdin(Stdio::null());

    let die_with_parent = config.die_with_parent;
    // A detached shim outlives the caller, so it must not keep the caller's
    // stdout open: `ID=$(bux create ...)` would wait until the VM stops.
    if let Some(file) = config.log_file {
        cmd.stdout(Stdio::from(file.try_clone()?));
        cmd.stderr(Stdio::from(file));
    } else {
        cmd.stdout(Stdio::null());
    }

    let (watchdog_read, keepalive) = if die_with_parent {
        let (read_end, keepalive) = process::watchdog_pipe()?;
        (Some(read_end), Some(keepalive))
    } else {
        (None, None)
    };
    let watchdog_fd = watchdog_read.as_ref().map(AsRawFd::as_raw_fd);
    if let Some(fd) = watchdog_fd {
        cmd.env(ENV_WATCHDOG_FD, fd.to_string());
    }
    let landlock_fd = landlock_owned.as_ref().map(AsRawFd::as_raw_fd);
    set_landlock_env(&mut cmd, landlock_fd);

    pre_exec::apply(
        &mut cmd,
        pre_exec::PreserveFds {
            watchdog: watchdog_fd,
            landlock: landlock_fd,
        },
        die_with_parent,
    );
    let child = cmd.spawn()?;
    drop(landlock_owned);
    drop(watchdog_read);
    let process = identify(child)?;

    let mac = match sandbox_kind {
        SandboxKind::Seatbelt => LayerStatus::Enforced,
        SandboxKind::Bwrap | SandboxKind::Noop => {
            if cfg!(target_os = "macos") {
                LayerStatus::Disabled
            } else {
                LayerStatus::NotApplicable
            }
        }
    };

    Ok(SpawnResult {
        process,
        keepalive,
        security: SecurityReport {
            sandbox: sandbox_kind,
            landlock: landlock_status,
            mac,
        },
    })
}

/// Record the child's start time; reap it if it cannot be identified.
fn identify(mut child: Child) -> Result<ShimProcess> {
    match ShimProcess::from_pid(child.id()) {
        Ok(process) => Ok(process),
        Err(e) => {
            drop(child.kill());
            drop(child.wait());
            Err(e.into())
        }
    }
}

/// Name the ruleset in the shim's environment, or clear the variable without one.
fn set_landlock_env(cmd: &mut Command, ruleset: Option<RawFd>) {
    match ruleset {
        Some(fd) => cmd.env(ENV_LANDLOCK_FD, fd.to_string()),
        // The shim would try to apply a value inherited from this process.
        None => cmd.env_remove(ENV_LANDLOCK_FD),
    };
}

/// Resolve Landlock fd + status (K22).
///
/// Returns [`Error::LandlockUnavailable`] / [`Error::Landlock`] on Linux when
/// Landlock is requested and cannot be enforced (unless degraded is allowed).
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "Result/errors only arise on Linux Landlock path; macOS always succeeds"
)]
fn prepare_landlock(
    config: &JailConfig,
    shim: &Path,
    config_path: &Path,
) -> Result<(Option<RawFd>, LayerStatus)> {
    if !config.landlock {
        return Ok((
            None,
            if cfg!(target_os = "linux") {
                LayerStatus::Disabled
            } else {
                LayerStatus::NotApplicable
            },
        ));
    }

    #[cfg(target_os = "linux")]
    {
        match landlock_setup::build_fd(config, shim, config_path) {
            Ok(Some(fd)) => Ok((Some(fd), LayerStatus::Enforced)),
            Ok(None) => {
                if config.allow_degraded_security {
                    Ok((None, LayerStatus::Degraded))
                } else {
                    Err(Error::LandlockUnavailable)
                }
            }
            Err(msg) => Err(Error::Landlock(msg)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (shim, config_path);
        // Requested on non-Linux: treat as not applicable (no fail).
        Ok((None, LayerStatus::NotApplicable))
    }
}

/// Build the sandboxed `Command` using the configured (or auto-detected) sandbox.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Linux returns BwrapUnavailable; other platforms always succeed"
)]
fn build_command(
    shim: &Path,
    config_path: &Path,
    config: &JailConfig,
) -> Result<(Command, SandboxKind)> {
    if let Some(ref sandbox) = config.sandbox
        && let Some(cmd) = sandbox.wrap(shim, config_path, config)
    {
        return Ok((cmd, sandbox.kind()));
    }

    if let Some((cmd, kind)) = platform_sandbox(shim, config_path, config) {
        return Ok((cmd, kind));
    }

    #[cfg(target_os = "linux")]
    {
        Err(Error::BwrapUnavailable)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut cmd = Command::new(shim);
        cmd.arg(config_path);
        Ok((cmd, SandboxKind::Noop))
    }
}

/// Try the platform-native sandbox.
fn platform_sandbox(
    shim: &Path,
    config_path: &Path,
    config: &JailConfig,
) -> Option<(Command, SandboxKind)> {
    #[cfg(target_os = "linux")]
    {
        let sandbox = BwrapSandbox;
        if let Some(cmd) = sandbox.wrap(shim, config_path, config) {
            return Some((cmd, SandboxKind::Bwrap));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let sandbox = SeatbeltSandbox;
        if let Some(cmd) = sandbox.wrap(shim, config_path, config) {
            return Some((cmd, SandboxKind::Seatbelt));
        }
    }

    let _ = (shim, config_path, config);
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::*;

    fn jail(bwrap_path: Option<PathBuf>) -> JailConfig {
        JailConfig {
            rootfs: None,
            root_disk: None,
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![],
            sandbox: None,
            log_file: None,
            landlock: false,
            allow_degraded_security: false,
            die_with_parent: true,
            network_host: false,
            bwrap_path,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_auto_detect_without_bwrap_is_unavailable() {
        let err = build_command(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(None),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::BwrapUnavailable),
            "missing bwrap must not fall through to Noop: {err}"
        );
        assert!(
            err.to_string().contains("sh.qntx.org/bux"),
            "error must name the install URL: {err}"
        );
    }

    /// Serializes the tests that open rulesets: [`landlock_fd_count`] counts the
    /// whole process.
    #[cfg(target_os = "linux")]
    static RULESETS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Open landlock ruleset fds in this process. Only rulesets: other tests
    /// open and close fds concurrently, so a count of all fds is racy.
    #[cfg(target_os = "linux")]
    fn landlock_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").map_or(0, |fds| {
            fds.flatten()
                .filter(|fd| {
                    std::fs::read_link(fd.path())
                        .is_ok_and(|target| target.as_os_str() == "anon_inode:[landlock-ruleset]")
                })
                .count()
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_without_bwrap_does_not_leak_landlock_fd() {
        let _rulesets = RULESETS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cfg = JailConfig {
            landlock: true,
            ..jail(None)
        };
        let before = landlock_fd_count();
        let err = spawn(Path::new("/usr/bin/true"), Path::new("/tmp/cfg.json"), cfg).unwrap_err();
        assert!(
            matches!(err, Error::BwrapUnavailable),
            "auto-detect without bwrap must fail closed: {err}"
        );
        let after = landlock_fd_count();
        assert_eq!(
            after, before,
            "BwrapUnavailable must not leak the landlock ruleset fd"
        );
    }

    #[test]
    fn spawn_sends_shim_stdout_to_the_log_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("shim");
        // Stay alive: a child that exits at once may be gone before spawn
        // reads its start time.
        std::fs::write(
            &shim,
            "#!/bin/sh\necho to-stdout\necho to-stderr >&2\nexec /bin/sleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let log = dir.path().join("shim.log");
        let cfg = JailConfig {
            sandbox: Some(Box::new(NoopSandbox)),
            log_file: Some(std::fs::File::create(&log).unwrap()),
            die_with_parent: false,
            ..jail(None)
        };

        let spawned = spawn(&shim, &dir.path().join("cfg.json"), cfg).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !std::fs::read_to_string(&log).unwrap().contains("to-stderr")
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        spawned.process.kill().unwrap();
        spawned.process.wait();

        let out = std::fs::read_to_string(&log).unwrap();
        assert!(
            out.contains("to-stdout") && out.contains("to-stderr"),
            "shim stdout and stderr must both go to the log file, got {out:?}"
        );
    }

    #[test]
    fn spawn_returns_the_exec_error() {
        let cfg = JailConfig {
            sandbox: Some(Box::new(NoopSandbox)),
            die_with_parent: false,
            ..jail(None)
        };
        let err = spawn(
            Path::new("/nonexistent/bux-shim"),
            Path::new("/tmp/cfg.json"),
            cfg,
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound),
            "a failed exec must come back as the spawn error: {err}"
        );
    }

    /// Script that lists its FDs (bwrap's `/proc` is the host's, so
    /// `/proc/self`, not `$$`), then stays alive long enough for `spawn` to
    /// read its start time.
    #[cfg(target_os = "linux")]
    fn fd_listing_script(dir: &Path) -> PathBuf {
        let script = dir.join("cfg.sh");
        std::fs::write(
            &script,
            "ls -l /proc/self/fd\necho listed\nexec /bin/sleep 3\n",
        )
        .unwrap();
        script
    }

    /// Spawn `sh` as the shim, wait for the FD listing of `script`, and return the log.
    ///
    /// `sh` reads the config path as its script. A file this process just wrote can
    /// fail to `exec` with `ETXTBSY`: a test forking in parallel inherits the
    /// descriptor.
    #[cfg(target_os = "linux")]
    fn fd_listing(script: &Path, log: &Path, cfg: JailConfig) -> String {
        let spawned = {
            let _rulesets = RULESETS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            spawn(Path::new("/bin/sh"), script, cfg).unwrap()
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !std::fs::read_to_string(log).unwrap().contains("listed")
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        spawned.process.kill().unwrap();
        spawned.process.wait();
        std::fs::read_to_string(log).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_passes_the_ruleset_and_no_other_fd() {
        if !bux_landlock::is_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let script = fd_listing_script(dir.path());
        let log = dir.path().join("shim.log");
        let _inheritable = nix::unistd::pipe().unwrap();
        let cfg = JailConfig {
            sandbox: Some(Box::new(NoopSandbox)),
            log_file: Some(std::fs::File::create(&log).unwrap()),
            landlock: true,
            die_with_parent: false,
            ..jail(None)
        };

        let out = fd_listing(&script, &log, cfg);

        assert!(
            out.contains("anon_inode:[landlock-ruleset]"),
            "the ruleset must reach the shim: {out}"
        );
        assert!(
            !out.contains("pipe:"),
            "an inherited fd must not reach the shim: {out}"
        );
    }

    #[test]
    fn an_inherited_ruleset_fd_does_not_reach_the_shim() {
        let mut cmd = Command::new("/bin/true");
        cmd.env(ENV_LANDLOCK_FD, "9");
        set_landlock_env(&mut cmd, None);
        assert!(
            cmd.get_envs()
                .any(|(key, value)| key == ENV_LANDLOCK_FD && value.is_none()),
            "{cmd:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bwrap_runs_outside_the_domain_and_passes_on_the_ruleset() {
        if !bux_landlock::is_available() {
            return;
        }
        let Some(bwrap) = bwrap::usable_bwrap() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let script = fd_listing_script(dir.path());
        let log = dir.path().join("shim.log");
        let cfg = JailConfig {
            socks_dir: dir.path().to_path_buf(),
            log_file: Some(std::fs::File::create(&log).unwrap()),
            landlock: true,
            die_with_parent: false,
            ..jail(Some(bwrap))
        };

        let out = fd_listing(&script, &log, cfg);

        assert!(
            out.contains("anon_inode:[landlock-ruleset]"),
            "bwrap must start and pass on the ruleset: {out}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_explicit_noop_still_wraps() {
        let mut cfg = jail(None);
        cfg.sandbox = Some(Box::new(NoopSandbox));
        let (cmd, kind) =
            build_command(Path::new("/usr/bin/true"), Path::new("/tmp/cfg.json"), &cfg).unwrap();
        assert_eq!(kind, SandboxKind::Noop);
        assert_eq!(cmd.get_program(), "/usr/bin/true");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_auto_detect_with_bwrap_path_is_bwrap() {
        let (cmd, kind) = build_command(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(Some(PathBuf::from("/bin/true"))),
        )
        .unwrap();
        assert_eq!(kind, SandboxKind::Bwrap);
        assert_eq!(cmd.get_program(), "/bin/true");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_auto_detect_without_bwrap_is_noop_or_seatbelt() {
        let (cmd, kind) = build_command(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(None),
        )
        .unwrap();
        assert!(
            matches!(kind, SandboxKind::Noop | SandboxKind::Seatbelt),
            "non-Linux must not require bwrap: {kind:?}"
        );
        let program = cmd.get_program();
        assert!(
            program == "/usr/bin/true"
                || program == "sandbox-exec"
                || program == "/usr/bin/sandbox-exec",
            "program must be shim or sandbox-exec: {program:?}"
        );
    }
}
