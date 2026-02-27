//! Linux sandbox using bubblewrap (bwrap).
//!
//! Wraps the shim binary with namespace isolation: new PID/IPC/UTS/mount
//! namespaces, read-only `/` bind, and selective writable mounts for
//! rootfs, sockets, and virtiofs paths.

use std::path::Path;
use std::process::Command;

use super::JailConfig;

/// Build a bubblewrap-wrapped command, or `None` if bwrap is unavailable.
pub fn wrap(shim: &Path, config_path: &Path, config: &JailConfig) -> Option<Command> {
    let bwrap = bux_bwrap::path()?;

    let mut cmd = Command::new(bwrap);

    // Namespace isolation.
    cmd.args(["--unshare-pid", "--unshare-ipc", "--unshare-uts"]);

    // Die when parent (bux) exits.
    cmd.arg("--die-with-parent");

    // Read-only root bind.
    cmd.args(["--ro-bind", "/", "/"]);

    // Writable /tmp and /dev/shm.
    cmd.args(["--tmpfs", "/tmp"]);
    cmd.args(["--tmpfs", "/dev/shm"]);

    // Writable /dev/kvm if it exists.
    if Path::new("/dev/kvm").exists() {
        cmd.args(["--dev-bind", "/dev/kvm", "/dev/kvm"]);
    }

    // Writable rootfs directory.
    if let Some(rootfs) = &config.rootfs {
        let s = rootfs.to_string_lossy();
        cmd.args(["--bind", &s, &s]);
    }

    // Writable root disk file.
    if let Some(disk) = &config.root_disk {
        let s = disk.to_string_lossy();
        cmd.args(["--bind", &s, &s]);
    }

    // Writable sockets directory.
    let socks = config.socks_dir.to_string_lossy();
    cmd.args(["--bind", &socks, &socks]);

    // Writable virtiofs host paths.
    for path in &config.virtiofs_paths {
        let s = path.to_string_lossy();
        cmd.args(["--bind", &s, &s]);
    }

    // Config file (read-only).
    let cfg = config_path.to_string_lossy();
    cmd.args(["--ro-bind", &cfg, &cfg]);

    // Shim binary + its arguments.
    cmd.arg("--");
    cmd.arg(shim);
    cmd.arg(config_path);

    Some(cmd)
}
