//! Process isolation for the `bux-shim` child process.
//!
//! The [`Sandbox`] trait abstracts platform-specific sandboxing:
//! - **Linux**: [`BwrapSandbox`] — bubblewrap namespace isolation (via [`bux-bwrap`]).
//! - **macOS**: [`SeatbeltSandbox`] — `sandbox-exec` with a deny-default SBPL profile.
//! - **Fallback**: [`NoopSandbox`] — bare `Command` with pre-exec hardening only.
//!
//! The default sandbox is auto-detected at runtime. Users can override it
//! via [`JailConfig::sandbox`] to supply a custom [`Sandbox`] implementation.
//!
//! [bubblewrap]: https://github.com/containers/bubblewrap
//! [seatbelt]: https://developer.apple.com/documentation/sandbox

pub mod checks;
#[cfg(target_os = "linux")]
pub mod credentials;
mod pre_exec;
#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "macos")]
mod seatbelt;

use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

// Re-export platform-specific sandbox implementations.
#[cfg(target_os = "linux")]
pub use bwrap::BwrapSandbox;
#[cfg(target_os = "macos")]
pub use seatbelt::SeatbeltSandbox;

/// Describes the isolation features provided by a [`Sandbox`] implementation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SandboxCapabilities {
    /// Whether the sandbox provides namespace isolation (mount, PID, net, etc.).
    pub namespaces: bool,
    /// Whether the sandbox applies seccomp BPF syscall filtering.
    pub seccomp: bool,
    /// Whether mandatory access control is enforced (AppArmor/SELinux/Seatbelt).
    pub mandatory_access_control: bool,
    /// Whether cgroup-based resource limits are enforced.
    pub cgroups: bool,
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
}

/// No-op sandbox: runs the shim directly with no additional isolation.
///
/// Pre-exec hardening (FD cleanup, die-with-parent) is always applied
/// regardless of sandbox choice.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, _jail: &JailConfig) -> Option<Command> {
        let mut cmd = Command::new(shim);
        cmd.arg(config_path);
        Some(cmd)
    }
}

/// cgroup v2 resource limits for VM processes.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Maximum CPU bandwidth as a fraction (e.g. 2.0 = 2 cores).
    pub cpu_cores: Option<f64>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// Memory+swap limit in bytes. Set equal to `memory_bytes` to disable swap.
    pub memory_swap_bytes: Option<u64>,
}

/// Sandbox configuration for a single VM spawn.
#[non_exhaustive]
#[derive(Debug)]
pub struct JailConfig {
    /// Path to the rootfs directory (if using directory-based root).
    pub rootfs: Option<PathBuf>,
    /// Path to the root disk image (if using disk-based root).
    pub root_disk: Option<PathBuf>,
    /// Directory containing Unix sockets for vsock.
    pub socks_dir: PathBuf,
    /// Host paths for virtiofs mounts.
    pub virtiofs_paths: Vec<PathBuf>,
    /// Watchdog pipe read-end FD to preserve across exec.
    pub watchdog_fd: Option<RawFd>,
    /// Override the default platform sandbox.
    ///
    /// When `None`, auto-detects: bwrap on Linux, seatbelt on macOS,
    /// noop otherwise.
    pub sandbox: Option<Box<dyn Sandbox>>,
    /// cgroup v2 resource limits (Linux only; ignored on other platforms).
    pub resource_limits: Option<ResourceLimits>,
    /// File to redirect child stderr to. When `None`, stderr is inherited.
    pub stderr_file: Option<std::fs::File>,
}

/// Result of spawning a shim process inside a sandbox.
#[derive(Debug)]
pub struct SpawnResult {
    /// The spawned child process.
    pub child: Child,
    /// cgroup guard — holds the cgroup alive; cleaned up on drop.
    /// `None` on non-Linux platforms or when no resource limits are set.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub cgroup: Option<cgroup::CgroupGuard>,
}

/// Spawn `bux-shim` inside a sandbox.
///
/// Applies platform-specific isolation, then falls back to a bare process
/// with pre-exec hardening (FD cleanup, die-with-parent) if no sandbox
/// is available.
pub fn spawn(
    shim: &Path,
    config_path: &Path,
    config: JailConfig,
    vm_id: &str,
) -> io::Result<SpawnResult> {
    let mut cmd = build_command(shim, config_path, &config);
    cmd.stdin(Stdio::null());
    if let Some(file) = config.stderr_file {
        cmd.stderr(Stdio::from(file));
    }

    // Pass watchdog FD number to the shim via environment variable.
    if let Some(fd) = config.watchdog_fd {
        cmd.env(crate::watchdog::ENV_WATCHDOG_FD, fd.to_string());
    }

    pre_exec::apply(&mut cmd, config.watchdog_fd);
    let child = cmd.spawn()?;

    // vm_id is only used on Linux (cgroup setup).
    let _ = vm_id;

    // Apply cgroup v2 resource limits (Linux only).
    #[cfg(target_os = "linux")]
    let cgroup_guard = if let Some(ref limits) = config.resource_limits {
        let guard = cgroup::create(
            vm_id,
            &cgroup::ResourceLimits {
                cpu_cores: limits.cpu_cores,
                memory_bytes: limits.memory_bytes,
                memory_swap_bytes: limits.memory_swap_bytes,
            },
        )
        .map_err(|e| io::Error::new(e.kind(), format!("cgroup setup failed: {e}")))?;
        #[allow(clippy::cast_possible_wrap)]
        cgroup::add_pid(&guard, child.id() as i32)?;
        Some(guard)
    } else {
        None
    };

    Ok(SpawnResult {
        child,
        #[cfg(target_os = "linux")]
        cgroup: cgroup_guard,
    })
}

/// Build the sandboxed `Command` using the configured (or auto-detected) sandbox.
fn build_command(shim: &Path, config_path: &Path, config: &JailConfig) -> Command {
    // Use explicit sandbox override if provided.
    if let Some(ref sandbox) = config.sandbox
        && let Some(cmd) = sandbox.wrap(shim, config_path, config)
    {
        return cmd;
    }

    // Auto-detect platform sandbox.
    if let Some(cmd) = platform_sandbox(shim, config_path, config) {
        return cmd;
    }

    // Ultimate fallback: noop.
    let mut cmd = Command::new(shim);
    cmd.arg(config_path);
    cmd
}

/// Try the platform-native sandbox.
fn platform_sandbox(shim: &Path, config_path: &Path, config: &JailConfig) -> Option<Command> {
    #[cfg(target_os = "linux")]
    {
        let sandbox = BwrapSandbox;
        if let Some(cmd) = sandbox.wrap(shim, config_path, config) {
            return Some(cmd);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let sandbox = SeatbeltSandbox;
        if let Some(cmd) = sandbox.wrap(shim, config_path, config) {
            return Some(cmd);
        }
    }

    let _ = (shim, config_path, config);
    None
}
