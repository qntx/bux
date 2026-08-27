//! Unix sockets, shim PID, and virtio-net JSON.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use bux_shim::{ShimGvproxy, ShimNetConn, ShimNetwork};
use nix::sys::signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::Result;
use crate::ports::{format_port_pairs, parse_publish_spec, resolve_ports};
use crate::secrets::LiveSecrets;
use crate::state::VmConfig;

/// macOS pathname `sun_path` is 104 bytes (trailing NUL); Linux is 108.
const MAX_SUN_PATH: usize = 104;

/// Fail closed when a unix socket path cannot fit in `sockaddr_un.sun_path`.
pub(super) fn reject_long_unix_path(path: &Path) -> Result<()> {
    let len = path.as_os_str().as_encoded_bytes().len();
    if len >= MAX_SUN_PATH {
        return Err(crate::Error::InvalidConfig(format!(
            "unix socket path {} ({len} bytes) exceeds sun_path {MAX_SUN_PATH}; use a shorter BUX_HOME",
            path.display(),
        )));
    }
    Ok(())
}

/// Last `last_n_lines` of shim stderr, formatted as a death/timeout hint.
pub(crate) fn stderr_tail(path: &Path, last_n_lines: usize) -> String {
    fs::read_to_string(path)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let total = s.lines().count();
            let skip = total.saturating_sub(last_n_lines);
            let tail: String = s.lines().skip(skip).collect::<Vec<_>>().join("\n");
            format!("\n  stderr:\n    {}", tail.replace('\n', "\n    "))
        })
        .unwrap_or_default()
}

/// Builds a diagnostic message when the shim dies before the guest agent is ready.
pub(crate) fn shim_death_message(pid: i32, exit_file: &Path) -> String {
    let detail = bux_shim::ExitInfo::from_file(exit_file)
        .map_or_else(|| "unknown reason".into(), |info| info.summary());
    let hint = stderr_tail(&exit_file.with_extension("stderr"), 5);
    format!("VM process (pid {pid}) died before ready: {detail}{hint}")
}

/// Timeout path: ready wait expired while the jail parent is still alive.
pub(crate) fn agent_not_ready_message(pid: i32, exit_file: &Path) -> String {
    let hint = stderr_tail(&exit_file.with_extension("stderr"), 5);
    format!("guest agent did not become ready (pid {pid}){hint}")
}

/// Unlink a Unix socket path. `NotFound` is success (already gone).
pub(crate) fn unlink_unix_socket(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Best-effort unlink of the vsock listen path (`{id}.sock`).
///
/// Leftover inode makes the next `krun_add_vsock_port2` bind EEXIST (-17).
pub(crate) fn clean_vsock_sock(socket: &Path) {
    drop(unlink_unix_socket(socket));
}

/// Removes transient files associated with a VM socket path.
pub(crate) fn clean_vm_files(socket: &Path) {
    clean_vsock_sock(socket);
    for ext in ["exit", "json", "stderr"] {
        drop(fs::remove_file(socket.with_extension(ext)));
    }
    clean_net_sock(socket);
}

/// Create-failure teardown: drop bind inodes and secrets JSON; keep logs for dump.
///
/// `{id}.stderr` / `{id}.exit` are the only host-visible guest/shim logs.
/// `clean_vm_files` deletes them — that is correct for `remove` / `auto_remove`,
/// not for abort of an unready create (`create_or_dump` cats `socks/*.stderr`).
pub(crate) fn clean_unready_files(socket: &Path) {
    clean_vsock_sock(socket);
    drop(fs::remove_file(socket.with_extension("json")));
    clean_net_sock(socket);
}

/// `{id}.sock` → `{id}.net.sock`.
pub(crate) fn clean_net_sock(socket: &Path) {
    drop(fs::remove_file(socket.with_extension("net.sock")));
}

/// Checks if a process is alive via `kill(pid, 0)`.
pub(crate) fn is_pid_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Blocks until a process exits.
#[allow(
    clippy::disallowed_methods,
    reason = "sync fallback poll cannot use tokio::time::sleep"
)]
pub(crate) fn wait_for_exit(pid: i32) {
    let nix_pid = Pid::from_raw(pid);
    if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(nix_pid, None) {
        return;
    }
    while is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Build virtio-net JSON for the shim binary. Both `Some` or both `None`.
pub(crate) fn prepare_virtio_net(
    id: &str,
    socks_dir: &Path,
    config: &mut VmConfig,
    live: Option<&LiveSecrets>,
) -> Result<(Option<ShimNetwork>, Option<ShimGvproxy>)> {
    if !config.network.is_enabled() {
        config.published_ports.clear();
        return Ok((None, None));
    }

    let mut specs = Vec::with_capacity(config.ports.len());
    for s in &config.ports {
        specs.push(parse_publish_spec(s)?);
    }
    let (pairs, published) = resolve_ports(&specs)?;
    config.ports = format_port_pairs(&pairs);
    config.published_ports = published;

    let socket_path = socks_dir.join(format!("{id}.net.sock"));
    reject_long_unix_path(&socket_path)?;
    unlink_unix_socket(&socket_path)?;

    let network = ShimNetwork {
        socket_path,
        connection: if cfg!(target_os = "macos") {
            ShimNetConn::UnixDgram
        } else {
            ShimNetConn::UnixStream
        },
        mac: bux_proto::net::GUEST_MAC,
    };
    let gvproxy = ShimGvproxy {
        port_mappings: pairs,
        allow_net: config.network.allow_net().to_vec(),
        secrets: live.map(LiveSecrets::to_shim_secrets).unwrap_or_default(),
        ca_cert_pem: live.map(|l| l.ca_cert_pem.clone()).unwrap_or_default(),
        ca_key_pem: live.map(|l| l.ca_key_pem.clone()).unwrap_or_default(),
    };
    Ok((Some(network), Some(gvproxy)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::options::NetworkSpec;

    #[test]
    fn reject_long_unix_path_threshold() {
        let ok = PathBuf::from("a".repeat(103));
        assert!(reject_long_unix_path(&ok).is_ok());
        let err = reject_long_unix_path(&PathBuf::from("a".repeat(104))).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidConfig(_)));
        assert!(err.to_string().contains("sun_path"));
    }

    #[test]
    fn prepare_virtio_net_rejects_long_unix_path() {
        let dir = tempfile::tempdir().unwrap();
        let long = dir.path().join("x".repeat(120));
        fs::create_dir_all(&long).unwrap();
        let mut cfg = VmConfig {
            network: NetworkSpec::Enabled {
                allow_net: Vec::new(),
            },
            ..VmConfig::default()
        };
        let err = prepare_virtio_net("abc", &long, &mut cfg, None).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, crate::Error::InvalidConfig(_)));
        assert!(msg.contains("sun_path"), "{msg}");
        assert!(msg.contains(".net.sock"), "{msg}");
    }

    #[test]
    fn prepare_virtio_net_both_none_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = VmConfig {
            network: NetworkSpec::Disabled,
            ..VmConfig::default()
        };
        let (net, gvp) = prepare_virtio_net("abc", dir.path(), &mut cfg, None).unwrap();
        assert!(net.is_none());
        assert!(gvp.is_none());
    }

    #[test]
    fn prepare_virtio_net_both_some_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = VmConfig {
            network: NetworkSpec::Enabled {
                allow_net: vec!["example.com".into()],
            },
            ports: vec!["18080:80".into()],
            ..VmConfig::default()
        };
        let (net, gvp) = prepare_virtio_net("abc", dir.path(), &mut cfg, None).unwrap();
        let net = net.expect("network");
        let gvp = gvp.expect("gvproxy");
        assert_eq!(net.socket_path, dir.path().join("abc.net.sock"));
        assert_eq!(net.mac, bux_proto::net::GUEST_MAC);
        assert_eq!(gvp.port_mappings, vec![(18080, 80)]);
        assert_eq!(gvp.allow_net, vec!["example.com".to_owned()]);
        #[cfg(target_os = "macos")]
        assert_eq!(net.connection, ShimNetConn::UnixDgram);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(net.connection, ShimNetConn::UnixStream);
    }

    #[test]
    fn clean_unready_files_keeps_stderr_and_exit_unlinks_json() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("id.sock");
        let stderr = sock.with_extension("stderr");
        let json = sock.with_extension("json");
        let exit = sock.with_extension("exit");
        let net = sock.with_extension("net.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        fs::write(&stderr, b"shim-and-guest-log").unwrap();
        fs::write(&json, b"{\"secrets\":true}").unwrap();
        fs::write(&exit, b"{}").unwrap();
        let _net = std::os::unix::net::UnixListener::bind(&net).unwrap();

        clean_unready_files(&sock);

        assert!(!sock.exists());
        assert!(!json.exists(), "secrets JSON must not linger on abort");
        assert!(!net.exists());
        assert!(stderr.exists(), "create_or_dump needs socks/*.stderr");
        assert!(exit.exists());
        assert_eq!(fs::read(&stderr).unwrap(), b"shim-and-guest-log");
    }

    #[test]
    fn agent_not_ready_message_includes_stderr_tail() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("id.sock");
        let stderr = sock.with_extension("stderr");
        let exit = sock.with_extension("exit");
        let planted = "bux-mitm-ca-write-failed";
        fs::write(&stderr, format!("line1\nline2\nline3\nline4\n{planted}\n")).unwrap();

        let msg = agent_not_ready_message(4242, &exit);
        assert_ne!(msg, "guest agent did not become ready");
        assert!(msg.contains("guest agent did not become ready"));
        assert!(msg.contains("4242"));
        assert!(msg.contains("stderr") && msg.contains(planted));
        assert!(stderr_tail(&stderr, 5).contains(planted));
        let death = shim_death_message(4242, &exit);
        assert!(death.contains("died before ready"));
        assert_ne!(msg, death);
    }

    #[test]
    fn clean_vsock_sock_unlinks_unix_socket_and_keeps_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("id.sock");
        let stderr = sock.with_extension("stderr");
        let json = sock.with_extension("json");
        let exit = sock.with_extension("exit");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        fs::write(&stderr, b"keep-me").unwrap();
        fs::write(&json, b"{}").unwrap();
        fs::write(&exit, b"{}").unwrap();

        clean_vsock_sock(&sock);

        assert!(
            !sock.exists(),
            "non-auto_remove stop must unlink vsock listen path"
        );
        assert!(stderr.exists(), "bux logs needs id.stderr after stop");
        assert!(json.exists());
        assert!(exit.exists());
    }

    #[test]
    fn unlink_unix_socket_not_found_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        unlink_unix_socket(&dir.path().join("missing.sock")).unwrap();
    }

    #[test]
    fn unlink_unix_socket_unlinks_listen_path() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("listen.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        unlink_unix_socket(&sock).unwrap();
        assert!(!sock.exists());
    }
}
