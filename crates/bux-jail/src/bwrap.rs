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
        let mut builder = BwrapCommand::from_path(jail.bwrap_path.as_ref()?)
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

        // Without bwrap's reaper, the outer process is the shim's parent, and the
        // shim dies with it (`bux_shim::die_with_jail`).
        Some(
            builder
                .run_as_pid_1()
                .program(shim)
                .arg(config_path)
                .into_command(),
        )
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            namespaces: true,
            seccomp: false,
            mandatory_access_control: false,
        }
    }

    fn kind(&self) -> SandboxKind {
        SandboxKind::Bwrap
    }
}

/// `bwrap` if it can create a user namespace on this host.
#[cfg(test)]
pub(crate) fn usable_bwrap() -> Option<std::path::PathBuf> {
    let bwrap = bux_bwrap::path()?;
    Command::new(bwrap)
        .args(["--unshare-pid", "--ro-bind", "/", "/", "--"])
        .arg(bwrap)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?
        .success()
        .then(|| bwrap.to_path_buf())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::*;
    use crate::process::live_group_members;
    use std::path::PathBuf;

    fn jail(die_with_parent: bool) -> JailConfig {
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
            die_with_parent,
            network_host: false,
            bwrap_path: Some(PathBuf::from("/bin/true")),
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
    fn kill_stops_every_process_in_the_jail() {
        let Some(bwrap) = usable_bwrap() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("cfg.sh");
        std::fs::write(&script, "exec /bin/sleep 30\n").unwrap();
        let cfg = JailConfig {
            socks_dir: dir.path().to_path_buf(),
            bwrap_path: Some(bwrap),
            ..jail(false)
        };

        // The shim is `sh`, which reads the config path as its script. A file this
        // process just wrote can fail to `exec` with `ETXTBSY`: a test forking in
        // parallel inherits the descriptor.
        let spawned = crate::spawn(Path::new("/bin/sh"), &script, cfg).unwrap();
        let group = spawned.process.pid();

        // bwrap's outer process and the shim.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while live_group_members(group) < 2 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(live_group_members(group), 2);

        spawned.process.kill().unwrap();
        assert_eq!(live_group_members(group), 0);
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
