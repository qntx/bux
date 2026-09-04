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

/// Host capability probes.
pub mod checks;
mod error;
mod pre_exec;
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
pub use security::{LayerStatus, SandboxKind, SecurityReport};

#[cfg(target_os = "linux")]
use bwrap::BwrapSandbox;
#[cfg(target_os = "macos")]
use seatbelt::SeatbeltSandbox;

/// Environment variable set on the shim child when a watchdog FD is preserved.
///
/// Value is the decimal file descriptor number. Must match
/// `bux_shim::ENV_WATCHDOG_FD` / the shim binary.
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

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
/// Pre-exec hardening (FD cleanup, die-with-parent, Landlock) is still applied.
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
    /// Watchdog pipe read-end FD to preserve across exec.
    pub watchdog_fd: Option<RawFd>,
    /// Override the default platform sandbox.
    ///
    /// When `None`, auto-detects: bwrap on Linux (fail-closed without
    /// [`Self::bwrap_path`]), seatbelt on macOS, noop on other Unix.
    /// Explicit [`NoopSandbox`] is the only way to skip the Linux jailer.
    pub sandbox: Option<Box<dyn Sandbox>>,
    /// File to redirect child stderr to. When `None`, stderr is inherited.
    pub stderr_file: Option<std::fs::File>,
    /// Request Landlock LSM on Linux (default product: true on Linux).
    ///
    /// When true and the kernel cannot enforce Landlock, spawn fails unless
    /// [`Self::allow_degraded_security`] is set (K22).
    pub landlock: bool,
    /// If true, missing Landlock (when requested) degrades instead of failing.
    pub allow_degraded_security: bool,
    /// Kill the child when the parent dies (`PR_SET_PDEATHSIG` and bwrap `--die-with-parent`).
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
    /// The spawned child process.
    pub child: Child,
    /// Actual security posture for this spawn.
    pub security: SecurityReport,
}

/// Spawn `bux-shim` inside a sandbox.
///
/// Applies platform-specific isolation, Landlock (when requested), then
/// pre-exec hardening (FD cleanup, die-with-parent).
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

    let watchdog_fd = config.watchdog_fd;
    let die_with_parent = config.die_with_parent;
    if let Some(file) = config.stderr_file {
        cmd.stderr(Stdio::from(file));
    }

    if let Some(fd) = watchdog_fd {
        cmd.env(ENV_WATCHDOG_FD, fd.to_string());
    }

    pre_exec::apply(
        &mut cmd,
        pre_exec::PreserveFds {
            watchdog: watchdog_fd,
            landlock: landlock_owned.as_ref().map(AsRawFd::as_raw_fd),
        },
        die_with_parent,
    );
    let child = cmd.spawn()?;
    drop(landlock_owned);

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
        child,
        security: SecurityReport {
            sandbox: sandbox_kind,
            landlock: landlock_status,
            mac,
        },
    })
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
        return Err(Error::BwrapUnavailable);
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
            watchdog_fd: None,
            sandbox: None,
            stderr_file: None,
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

    #[cfg(target_os = "linux")]
    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count())
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_without_bwrap_does_not_leak_landlock_fd() {
        let cfg = JailConfig {
            landlock: true,
            ..jail(None)
        };
        let before = fd_count();
        let err = spawn(Path::new("/usr/bin/true"), Path::new("/tmp/cfg.json"), cfg).unwrap_err();
        assert!(
            matches!(err, Error::BwrapUnavailable),
            "auto-detect without bwrap must fail closed: {err}"
        );
        let after = fd_count();
        assert_eq!(
            after, before,
            "BwrapUnavailable must not leak the landlock ruleset fd"
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
