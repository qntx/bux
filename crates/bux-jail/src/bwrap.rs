//! Linux sandbox using bubblewrap (bwrap).
//!
//! Wraps the shim binary with namespace isolation: new PID/IPC/UTS/mount
//! namespaces, read-only `/` bind, and selective writable mounts for
//! rootfs, sockets, and virtiofs paths.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bux_bwrap::{BwrapCommand, Namespace};

use super::{Error, JailConfig, Result, Sandbox, SandboxCapabilities, SandboxKind};

/// How long a `bwrap` gets to start a jail and exit, which takes milliseconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The namespaces and base mounts of every jail.
fn base_command(bwrap: &Path) -> Option<BwrapCommand> {
    // `ro_bind("/", "/")` already covers resolver files (`/etc/resolv.conf`, `/etc/hosts`).
    let mut builder = BwrapCommand::from_path(bwrap)
        .ok()?
        .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts])
        .ro_bind("/", "/")
        .tmpfs("/tmp")
        .tmpfs("/dev/shm");

    if Path::new("/dev/kvm").exists() {
        builder = builder.dev_bind("/dev/kvm", "/dev/kvm");
    }
    Some(builder)
}

/// Check that `bwrap` can start a jail on this host, by running it with the
/// jail's namespaces and mounts around a command that does nothing.
///
/// # Errors
///
/// Returns [`Error::BwrapProbe`] with what `bwrap` printed, or if it is not a file
/// or does not exit in time, and [`Error::Io`] if it cannot run.
pub fn probe_bwrap(bwrap: &Path) -> Result<()> {
    probe_with_timeout(bwrap, PROBE_TIMEOUT)
}

/// [`probe_bwrap`] that gives up after `timeout`.
#[allow(
    clippy::disallowed_methods,
    reason = "polls a child in synchronous setup code"
)]
fn probe_with_timeout(bwrap: &Path, timeout: Duration) -> Result<()> {
    let builder = base_command(bwrap)
        .ok_or_else(|| Error::BwrapProbe(format!("{} is not a file", bwrap.display())))?;
    // The command is `bwrap` itself, which the tmpfs mounts may hide.
    let mut child = builder
        .die_with_parent()
        .ro_bind(bwrap, bwrap)
        .program(bwrap)
        .arg("--version")
        .into_command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            return Err(Error::BwrapProbe(format!(
                "did not exit within {} ms",
                timeout.as_millis()
            )));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    Err(Error::BwrapProbe(if stderr.is_empty() {
        output.status.to_string()
    } else {
        stderr.to_owned()
    }))
}

/// Bubblewrap (bwrap) sandbox for Linux.
///
/// Provides namespace isolation (PID/IPC/UTS/mount), a read-only root
/// bind, and selective writable mounts for VM resources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BwrapSandbox;

impl Sandbox for BwrapSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command> {
        let mut builder = base_command(jail.bwrap_path.as_ref()?)?;
        if jail.die_with_parent {
            builder = builder.die_with_parent();
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
    use std::process::Stdio;

    let bwrap = bux_bwrap::path()?;
    Command::new(bwrap)
        .args(["--unshare-pid", "--ro-bind", "/", "/", "--"])
        .arg(bwrap)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

    /// A fake `bwrap` in `dir`: appends its arguments to `args`, then runs `body`.
    ///
    /// A child creates the file. `exec` fails with `ETXTBSY` while any process holds
    /// the file open for writing, and a test forking in parallel inherits this
    /// process's descriptors.
    fn fake_bwrap(dir: &Path, body: &str) -> PathBuf {
        let bwrap = dir.join("bwrap");
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> {}\n{body}\n",
            dir.join("args").display()
        );
        let status = Command::new("/bin/sh")
            .args([
                "-c",
                r#"rm -f "$0" && printf %s "$1" > "$0" && chmod 755 "$0""#,
            ])
            .arg(&bwrap)
            .arg(script)
            .status()
            .unwrap();
        assert!(status.success());
        bwrap
    }

    #[test]
    fn probe_runs_the_jail_namespaces_and_mounts() {
        let dir = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(dir.path(), "exit 0");

        probe_bwrap(&bwrap).unwrap();

        let args = std::fs::read_to_string(dir.path().join("args")).unwrap();
        for flag in [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--ro-bind / /",
            "--tmpfs /tmp",
            "--tmpfs /dev/shm",
        ] {
            assert!(args.contains(flag), "{flag} missing: {args}");
        }
        assert!(
            args.trim_end()
                .ends_with(&format!("-- {} --version", bwrap.display())),
            "{args}"
        );
        let tmpfs = args.find("--tmpfs /tmp").unwrap();
        let bind = args
            .find(&format!("--ro-bind {0} {0}", bwrap.display()))
            .unwrap();
        assert!(
            tmpfs < bind,
            "the tmpfs must not hide the candidate: {args}"
        );
    }

    #[test]
    fn probe_gives_up_on_a_bwrap_that_hangs() {
        let dir = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(dir.path(), "exec /bin/sleep 60");
        let err = probe_with_timeout(&bwrap, Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("did not exit"), "{err}");
    }

    #[test]
    fn probe_returns_what_bwrap_printed() {
        let dir = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(
            dir.path(),
            "echo 'bwrap: setting up uid map: Permission denied' >&2; exit 1",
        );
        assert_eq!(
            probe_bwrap(&bwrap).unwrap_err().to_string(),
            "bwrap: setting up uid map: Permission denied"
        );

        let silent = fake_bwrap(dir.path(), "exit 3");
        assert!(
            probe_bwrap(&silent).unwrap_err().to_string().contains('3'),
            "a silent failure reports its exit status"
        );
        assert!(
            probe_bwrap(Path::new("/nonexistent/bwrap"))
                .unwrap_err()
                .to_string()
                .contains("not a file")
        );
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
    fn kill_stops_every_process_in_the_jail() {
        use std::time::{Duration, Instant};

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
        let deadline = Instant::now() + Duration::from_secs(10);
        while live_group_members(group).unwrap() < 2 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(live_group_members(group).unwrap(), 2);

        spawned.process.kill().unwrap();
        assert_eq!(live_group_members(group).unwrap(), 0);
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
