//! Shim process spawning and lifecycle utilities.
//!
//! Free functions shared by [`super::Runtime`] spawn paths and
//! [`super::VmHandle`] restart logic.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use nix::sys::signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::Result;
use crate::guest::ManagedGuestBinary;
use crate::jail::{self, JailConfig};
use crate::state;
use crate::watchdog::{self, Keepalive};

/// Result of spawning a shim subprocess.
pub(super) struct ShimSpawnResult {
    /// Child PID (as i32 for nix compatibility).
    pub pid: i32,
    /// Parent-side watchdog keepalive.
    pub keepalive: Option<Keepalive>,
}

/// Builds a diagnostic message when the shim process dies before the guest agent is ready.
///
/// Combines structured [`ExitInfo`] JSON and the last few lines of the shim's
/// stderr file into a single actionable error message.
pub(super) fn shim_death_message(pid: i32, exit_file: &Path) -> String {
    let detail = crate::ExitInfo::from_file(exit_file)
        .map_or_else(|| "unknown reason".into(), |info| info.summary());

    let stderr_path = exit_file.with_extension("stderr");
    let stderr_hint = fs::read_to_string(&stderr_path)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let total = s.lines().count();
            let skip = total.saturating_sub(5);
            let tail: String = s.lines().skip(skip).collect::<Vec<_>>().join("\n");
            format!("\n  stderr:\n    {}", tail.replace('\n', "\n    "))
        })
        .unwrap_or_default();

    format!("VM process (pid {pid}) died before ready: {detail}{stderr_hint}")
}

/// Removes all transient files associated with a VM socket path.
///
/// Cleans `.sock`, `.exit`, `.json`, and `.stderr` files that share the
/// same stem as the socket.
pub(super) fn clean_vm_files(socket: &Path) {
    drop(fs::remove_file(socket));
    for ext in ["exit", "json", "stderr"] {
        drop(fs::remove_file(socket.with_extension(ext)));
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
pub(super) fn is_pid_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Blocks until a process exits.
///
/// Tries `waitpid` first (works for child processes — zero CPU, zero delay).
/// Falls back to `kill(pid, 0)` polling if the process is not a direct child.
#[allow(
    clippy::disallowed_methods,
    reason = "sync fallback poll cannot use tokio::time::sleep"
)]
pub(super) fn wait_for_exit(pid: i32) {
    let nix_pid = Pid::from_raw(pid);
    if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(nix_pid, None) {
        return;
    }
    while is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Resolves the managed guest binary and validates the VM configuration for managed mode.
pub(super) fn prepare_managed_config(config: &mut state::VmConfig) -> Result<()> {
    let guest = ManagedGuestBinary::resolve()?;

    if let Some(exec_path) = config.exec_path.as_deref()
        && exec_path != ManagedGuestBinary::exec_path()
    {
        return Err(crate::Error::InvalidConfig(
            "managed runtime no longer supports boot-time exec; start the VM, then run commands through bux exec".to_owned(),
        ));
    }
    if config.workdir.is_some()
        || config.uid.is_some()
        || config.gid.is_some()
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
    {
        return Err(crate::Error::InvalidConfig(
            "managed runtime options env/workdir/user now apply only to guest exec requests, not VM boot".to_owned(),
        ));
    }
    if config.root_disk.is_some() && config.rootfs.is_none() && config.base_disk.is_none() {
        return Err(crate::Error::InvalidConfig(
            "managed runtime does not yet support direct root_disk boot without a managed guest-rootfs preparation step".to_owned(),
        ));
    }
    if let Some(rootfs) = config.rootfs.as_deref() {
        guest.inject_into_rootfs(Path::new(rootfs))?;
    }

    config.exec_path = Some(ManagedGuestBinary::exec_path().to_owned());
    config.exec_args.clear();
    config.env = None;
    config.workdir = None;
    config.uid = None;
    config.gid = None;
    Ok(())
}

/// Writes config JSON, creates watchdog pipe, and spawns `bux-shim` inside a sandbox.
///
/// Shared by [`super::Runtime::spawn()`] and [`super::VmHandle::start()`].
pub(super) fn spawn_shim(
    config: &state::VmConfig,
    config_path: &Path,
    socks_dir: &Path,
    vm_id: &str,
    watch_parent: bool,
) -> io::Result<ShimSpawnResult> {
    let json =
        serde_json::to_string(config).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(config_path, &json)?;

    // Capture shim stderr to a file for post-mortem diagnostics.
    let stderr_path = config_path.with_extension("stderr");
    let stderr_file = fs::File::create(&stderr_path)?;

    let (shim_wd_fd, keepalive) = if watch_parent {
        let (fd, keepalive) = watchdog::create()?;
        (Some(fd), Some(keepalive))
    } else {
        (None, None)
    };
    let shim = find_shim()?;
    #[cfg(target_os = "macos")]
    ensure_shim_dylib_aliases(&shim)?;

    let jail_config = JailConfig {
        rootfs: config.rootfs.as_deref().map(PathBuf::from),
        root_disk: config.root_disk.as_deref().map(PathBuf::from),
        socks_dir: socks_dir.to_path_buf(),
        virtiofs_paths: config
            .virtiofs
            .iter()
            .map(|v| PathBuf::from(&v.path))
            .collect(),
        watchdog_fd: shim_wd_fd
            .as_ref()
            .map(std::os::unix::io::AsRawFd::as_raw_fd),
        sandbox: None,
        resource_limits: None,
        stderr_file: Some(stderr_file),
    };

    let result = jail::spawn(&shim, config_path, jail_config, vm_id).map_err(|e| {
        drop(fs::remove_file(config_path));
        io::Error::new(e.kind(), format!("failed to spawn {}: {e}", shim.display()))
    })?;

    #[allow(
        clippy::cast_possible_wrap,
        reason = "PID fits in i32 on all supported platforms"
    )]
    let pid = result.child.id() as i32;
    drop(shim_wd_fd);

    Ok(ShimSpawnResult { pid, keepalive })
}

/// Locates the `bux-shim` binary.
///
/// Search order:
/// 1. `$BUX_SHIM_PATH` environment variable (development override).
/// 2. Next to the current executable.
/// 3. In `$PATH`.
fn find_shim() -> io::Result<PathBuf> {
    const NAME: &str = "bux-shim";

    if let Ok(p) = std::env::var("BUX_SHIM_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(NAME);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("'{NAME}' not found; install it next to the bux binary or in $PATH"),
    ))
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::missing_docs_in_private_items,
    reason = "macOS-only helper with self-explanatory name"
)]
fn ensure_shim_dylib_aliases(shim: &Path) -> io::Result<()> {
    let Some(shim_dir) = shim.parent() else {
        return Ok(());
    };

    for (src, alias) in [
        ("libkrun.dylib", "libkrun.1.dylib"),
        ("libkrunfw.dylib", "libkrunfw.5.dylib"),
    ] {
        let src_path = shim_dir.join(src);
        let alias_path = shim_dir.join(alias);
        if alias_path.exists() {
            continue;
        }
        if !src_path.exists() {
            continue;
        }
        match std::os::unix::fs::symlink(src, &alias_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                fs::copy(&src_path, &alias_path)?;
            }
        }
    }

    Ok(())
}
