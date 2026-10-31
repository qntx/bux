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
