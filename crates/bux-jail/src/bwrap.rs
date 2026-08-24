//! Linux sandbox using bubblewrap (bwrap).
//!
//! Wraps the shim binary with namespace isolation: new PID/IPC/UTS/mount
//! namespaces, read-only `/` bind, and selective writable mounts for
//! rootfs, sockets, and virtiofs paths.

use std::path::Path;
use std::process::Command;

use bux_bwrap::{BwrapCommand, Namespace};

use super::{JailConfig, Sandbox, SandboxCapabilities, SandboxKind};

/// Bubblewrap (bwrap) sandbox for Linux.
///
/// Provides namespace isolation (PID/IPC/UTS/mount), a read-only root
/// bind, and selective writable mounts for VM resources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BwrapSandbox;

impl Sandbox for BwrapSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command> {
        let mut builder =
            BwrapCommand::new()
                .ok()?
                .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts]);
        if jail.die_with_parent {
            builder = builder.die_with_parent();
        }
        // `ro_bind("/", "/")` already covers resolver files (`/etc/resolv.conf`, `/etc/hosts`).
        builder = builder.ro_bind("/", "/").tmpfs("/tmp").tmpfs("/dev/shm");

        if Path::new("/dev/kvm").exists() {
            builder = builder.dev_bind("/dev/kvm", "/dev/kvm");
        }

        if let Some(rootfs) = &jail.rootfs {
            builder = builder.bind(rootfs, rootfs);
        }
        if let Some(disk) = &jail.root_disk {
            builder = builder.bind(disk, disk);
        }

        builder = builder.bind(&jail.socks_dir, &jail.socks_dir);
        for path in &jail.virtiofs_paths {
            builder = builder.bind(path, path);
        }
        builder = builder.ro_bind(config_path, config_path);

        Some(builder.program(shim).arg(config_path).into_command())
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            namespaces: true,
            seccomp: false,
            mandatory_access_control: false,
            cgroups: false,
        }
    }

    fn kind(&self) -> SandboxKind {
        SandboxKind::Bwrap
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn jail(die_with_parent: bool) -> JailConfig {
        JailConfig {
            rootfs: None,
            root_disk: None,
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![],
            watchdog_fd: None,
            sandbox: None,
            resource_limits: None,
            stderr_file: None,
            landlock: false,
            allow_degraded_security: false,
            die_with_parent,
            network_host: false,
        }
    }

    fn args_contain_die_with_parent(cmd: &Command) -> bool {
        cmd.get_args()
            .any(|a| a == std::ffi::OsStr::new("--die-with-parent"))
    }

    #[test]
    fn foreground_includes_die_with_parent() {
        let Some(cmd) = BwrapSandbox.wrap(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(true),
        ) else {
            return;
        };
        assert!(
            args_contain_die_with_parent(&cmd),
            "foreground jail must pass --die-with-parent"
        );
    }

    #[test]
    fn detached_omits_die_with_parent() {
        let Some(cmd) = BwrapSandbox.wrap(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(false),
        ) else {
            return;
        };
        assert!(
            !args_contain_die_with_parent(&cmd),
            "detached jail must not pass --die-with-parent"
        );
    }
}
