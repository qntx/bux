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

        // After the tmpfs mounts, which may hide these paths. Only files: a parent
        // directory such as `/tmp` or `/` would cover those mounts and `/dev/kvm`.
        for path in jail.readonly_paths.iter().filter(|path| path.is_file()) {
            builder = builder.ro_bind(path, path);
        }
        // The shim and libkrun, which sits next to it, when a tmpfs hides them. The
        // mount points themselves stay empty.
        if let Some(dir) = shim.parent()
            && ["/tmp", "/dev/shm"]
                .iter()
                .any(|mount| dir.starts_with(mount) && dir != Path::new(mount))
        {
            builder = builder.ro_bind(dir, dir);
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

    /// The position of `seq` in the arguments of `cmd`.
    fn position(cmd: &Command, seq: &[&Path]) -> Option<usize> {
        let args: Vec<_> = cmd.get_args().map(Path::new).collect();
        args.windows(seq.len()).position(|window| window == seq)
    }

    /// `--ro-bind path path`.
    fn ro_bind(path: &Path) -> [&Path; 3] {
        [Path::new("--ro-bind"), path, path]
    }

    #[test]
    fn readonly_files_are_bound_after_the_tmpfs_but_not_directories() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        std::fs::write(&base, b"").unwrap();
        let mut cfg = jail(false);
        cfg.readonly_paths = vec![dir.path().to_path_buf(), base.clone()];
        let Some(cmd) =
            BwrapSandbox.wrap(Path::new("/usr/bin/true"), Path::new("/tmp/cfg.json"), &cfg)
        else {
            return;
        };

        let tmpfs = position(&cmd, &[Path::new("--tmpfs"), Path::new("/tmp")]).unwrap();
        let bound = position(&cmd, &ro_bind(&base)).unwrap();
        assert!(tmpfs < bound);
        assert_eq!(position(&cmd, &ro_bind(dir.path())), None);
    }

    #[test]
    fn a_shim_under_a_tmpfs_is_bound_with_its_directory() {
        let wrap = |shim: &str| {
            BwrapSandbox.wrap(Path::new(shim), Path::new("/tmp/cfg.json"), &jail(false))
        };
        let Some(hidden) = wrap("/tmp/build/debug/bux-shim") else {
            return;
        };
        let dir = Path::new("/tmp/build/debug");
        assert!(position(&hidden, &ro_bind(dir)).is_some());

        let at_the_mount_point = wrap("/tmp/bux-shim").unwrap();
        assert_eq!(
            position(&at_the_mount_point, &ro_bind(Path::new("/tmp"))),
            None
        );

        let visible = wrap("/usr/bin/true").unwrap();
        assert_eq!(position(&visible, &ro_bind(Path::new("/usr/bin"))), None);
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
