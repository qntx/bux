//! Overlay, secrets, jail spawn, and VM row insert.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::{fs, io};

use bux_jail::JailConfig;
use bux_proto::AGENT_PORT;
use bux_shim::{ShimConfig, ShimDiskFormat, ShimGvproxy, ShimNetwork, ShimVirtioFs, ShimVsockPort};
use nix::sys::signal;
use nix::unistd::Pid;
use tracing::info;

use super::super::{Runtime, Vm};
use super::guest::{inject_guest_boot_env, prepare_managed_config};
use super::unix::{
    clean_unready_files, prepare_virtio_net, reject_long_unix_path, unlink_unix_socket,
};
use crate::Result;
use crate::disk::DiskFormat;
use crate::secrets::{LiveSecrets, Secret};
use crate::state::{self, Status, VmConfig, VmState, VsockPort};
use crate::watchdog::{self, Keepalive};

/// Tears down overlay / secrets / shim / row if spawn fails after overlay.
struct SpawnAbort<'a> {
    /// Runtime that owns secrets, disk, and state.
    rt: &'a Runtime,
    /// VM id allocated for this spawn.
    id: String,
    /// Vsock socket path (also locates json/stderr/exit files).
    socket: PathBuf,
    /// Shim PID once spawned (`None` until jail spawn succeeds).
    pid: Option<i32>,
    /// When true, `Drop` runs abort cleanup.
    armed: bool,
}

impl SpawnAbort<'_> {
    /// Skip cleanup after a successful insert.
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SpawnAbort<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        abort_partial_spawn(self.rt, &self.id, &self.socket, self.pid);
    }
}

/// SIGKILL if spawned, then secrets/overlay/volumes/row.
fn abort_partial_spawn(rt: &Runtime, id: &str, socket: &Path, pid: Option<i32>) {
    if let Some(pid) = pid {
        signal::kill(Pid::from_raw(pid), signal::Signal::SIGKILL).ok();
    }
    rt.secrets
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(id);
    clean_unready_files(socket);
    drop(rt.volumes().unlink_vm(id));
    drop(rt.disk.remove_vm_disk(id));
    drop(rt.db.delete(id));
}

/// Result of spawning a shim subprocess.
pub(crate) struct ShimSpawnResult {
    /// Child PID (as i32 for nix compatibility).
    pub pid: i32,
    /// Parent-side watchdog keepalive.
    pub keepalive: Option<Keepalive>,
    /// Actual security posture from the jail spawn.
    pub security: crate::security::SecurityStatus,
}

/// Spawn a shim from a fully built [`VmConfig`].
///
/// # Errors
///
/// Returns an error if the name collides, overlay/network/jail spawn fails.
pub(crate) fn spawn_config(
    rt: &Runtime,
    mut config: VmConfig,
    staged_secrets: Vec<Secret>,
    image: Option<String>,
    name: Option<String>,
    auto_remove: bool,
) -> Result<Vm> {
    if let Some(ref n) = name
        && rt.db.get_by_name(n)?.is_some()
    {
        return Err(crate::Error::Ambiguous(format!(
            "a VM named '{n}' already exists"
        )));
    }

    let id = state::gen_id();
    let socket = rt.socks_dir.join(format!("{id}.sock"));
    reject_long_unix_path(&socket)?;
    let socket_str = socket.to_string_lossy().into_owned();

    prepare_managed_config(&mut config, rt.guest_path.as_deref())?;
    config.auto_remove = auto_remove;
    config.vsock_ports.push(VsockPort {
        port: AGENT_PORT,
        path: socket_str,
        listen: true,
    });

    if let Some(ref base) = config.base_disk {
        let overlay = rt
            .disk
            .create_overlay(Path::new(base), config.disk_format, &id)?;
        config.root_disk = Some(overlay.to_string_lossy().into_owned());
        config.disk_format = DiskFormat::Qcow2;
        config.base_disk = None;
    }

    let mut abort = SpawnAbort {
        rt,
        id: id.clone(),
        socket: socket.clone(),
        pid: None,
        armed: true,
    };

    let live_secrets = if staged_secrets.is_empty() {
        config.secrets_required = false;
        None
    } else {
        if !config.network.is_enabled() {
            return Err(crate::Error::SecretsNeedVirtioNet);
        }
        config.secrets_required = true;
        Some(LiveSecrets::mint(staged_secrets)?)
    };

    let mitm_ca = live_secrets.as_ref().map(|l| l.ca_cert_pem.clone());
    inject_guest_boot_env(&mut config, &id, mitm_ca)?;

    let (network, gvproxy) =
        prepare_virtio_net(&id, &rt.socks_dir, &mut config, live_secrets.as_ref())?;

    if let Some(live) = live_secrets {
        rt.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone(), live);
    }

    let config_path = rt.socks_dir.join(format!("{id}.json"));
    let shim = spawn_shim(
        &config,
        &config_path,
        &rt.socks_dir,
        network,
        gvproxy,
        rt.shim_path.as_deref(),
    )?;
    abort.pid = Some(shim.pid);

    config.security_status = shim.security.clone();

    let vm_state = VmState {
        id: id.clone(),
        name,
        pid: shim.pid,
        image,
        socket,
        status: Status::Running,
        config,
        created_at: std::time::SystemTime::now(),
    };
    rt.db.insert(&vm_state)?;
    abort.disarm();

    info!(
        vm_id = %id,
        pid = shim.pid,
        network_enabled = vm_state.config.network.is_enabled(),
        "VM spawned"
    );

    rt.metrics.on_vm_created();
    rt.events.emit(crate::events::AuditEvent::now(
        crate::events::AuditEventKind::VmCreated {
            id,
            image: vm_state.image.clone(),
        },
    ));

    Ok(Vm::new(
        vm_state,
        std::sync::Arc::clone(&rt.db),
        rt.disk.clone(),
        shim.keepalive,
        std::sync::Arc::clone(&rt.metrics),
        std::sync::Arc::clone(&rt.events),
        rt.snapshots.clone(),
        std::sync::Arc::clone(&rt.secrets),
        rt.volumes.clone(),
        rt.shim_path.clone(),
        rt.guest_path.clone(),
    ))
}

/// Map persisted [`VmConfig`] into engine [`ShimConfig`].
///
/// Port publish is gvproxy-only; this mapping never sets a TSI port map.
fn to_shim_config(
    config: &VmConfig,
    network: Option<ShimNetwork>,
    gvproxy: Option<ShimGvproxy>,
) -> ShimConfig {
    ShimConfig {
        vcpus: config.vcpus,
        ram_mib: config.ram_mib,
        rootfs: config.rootfs.clone(),
        root_disk: config.root_disk.clone(),
        disk_format: match config.disk_format {
            DiskFormat::Qcow2 => ShimDiskFormat::Qcow2,
            DiskFormat::Raw => ShimDiskFormat::Raw,
        },
        virtiofs: config
            .virtiofs
            .iter()
            .map(|v| ShimVirtioFs {
                tag: v.tag.clone(),
                path: v.path.clone(),
            })
            .collect(),
        vsock_ports: config
            .vsock_ports
            .iter()
            .map(|v| ShimVsockPort {
                port: v.port,
                path: v.path.clone(),
                listen: v.listen,
            })
            .collect(),
        network,
        gvproxy,
        exec_path: config.exec_path.clone(),
        exec_args: config.exec_args.clone(),
        env: config.env.clone(),
    }
}

/// Watchdog, PDEATHSIG, and bwrap `--die-with-parent` follow persisted detach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent spawn flags, not a state machine"
)]
pub(super) struct SpawnPolicy {
    /// Parent keepalive pipe.
    pub watch_parent: bool,
    /// `PR_SET_PDEATHSIG` and bwrap `--die-with-parent`.
    pub die_with_parent: bool,
    /// Seatbelt host net / Landlock `AccessNet`.
    pub network_host: bool,
}

/// Isolation flags for every spawn (`create` and `start_with`).
#[must_use]
pub(super) const fn spawn_policy(config: &VmConfig) -> SpawnPolicy {
    SpawnPolicy {
        watch_parent: !config.detach,
        die_with_parent: !config.detach,
        network_host: config.network.is_enabled(),
    }
}

/// Writes config JSON (mode 0o600), creates watchdog pipe, and spawns `bux-shim`.
///
/// `network` / `gvproxy` are both `Some` (virtio-net) or both `None` (offline).
pub(crate) fn spawn_shim(
    config: &VmConfig,
    config_path: &Path,
    socks_dir: &Path,
    network: Option<ShimNetwork>,
    gvproxy: Option<ShimGvproxy>,
    shim_path: Option<&Path>,
) -> Result<ShimSpawnResult> {
    if network.is_some() != gvproxy.is_some() {
        return Err(crate::Error::InvalidConfig(
            "gvproxy and network must both be set or both absent".into(),
        ));
    }
    let policy = spawn_policy(config);
    let shim_cfg = to_shim_config(config, network, gvproxy);
    let json = shim_cfg
        .to_json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_shim_json(config_path, &json)?;
    let mut unlink_json = UnlinkJsonOnErr {
        path: config_path,
        keep: false,
    };

    let stderr_path = config_path.with_extension("stderr");
    let stderr_file = fs::File::create(&stderr_path)?;

    let (shim_wd_fd, keepalive) = if policy.watch_parent {
        let (fd, keepalive) = watchdog::create()?;
        (Some(fd), Some(keepalive))
    } else {
        (None, None)
    };
    let shim = find_shim(shim_path)?;

    let readonly_paths = config
        .root_disk
        .as_deref()
        .map(|d| crate::disk::readonly_disk_paths(Path::new(d)))
        .unwrap_or_default();

    let sec = &config.security;
    let sandbox: Option<Box<dyn bux_jail::Sandbox>> = if sec.jailer {
        None
    } else {
        Some(Box::new(bux_jail::NoopSandbox::default()))
    };

    // leftover listen inode makes krun add_vsock_port2 EEXIST
    for vs in &config.vsock_ports {
        if vs.listen {
            unlink_unix_socket(Path::new(&vs.path))?;
        }
    }

    let jail_config = JailConfig {
        rootfs: config.rootfs.as_deref().map(PathBuf::from),
        root_disk: config.root_disk.as_deref().map(PathBuf::from),
        readonly_paths,
        socks_dir: socks_dir.to_path_buf(),
        virtiofs_paths: config
            .virtiofs
            .iter()
            .map(|v| PathBuf::from(&v.path))
            .collect(),
        watchdog_fd: shim_wd_fd.as_ref().map(AsRawFd::as_raw_fd),
        sandbox,
        stderr_file: Some(stderr_file),
        landlock: sec.landlock,
        allow_degraded_security: sec.allow_degraded,
        die_with_parent: policy.die_with_parent,
        network_host: policy.network_host,
    };

    let result =
        bux_jail::spawn(&shim, config_path, jail_config).map_err(|e| map_jail_error(e, &shim))?;

    #[allow(
        clippy::cast_possible_wrap,
        reason = "PID fits in i32 on all supported platforms"
    )]
    let pid = result.child.id() as i32;
    drop(shim_wd_fd);

    unlink_json.keep = true;
    Ok(ShimSpawnResult {
        pid,
        keepalive,
        security: crate::security::SecurityStatus::from_report(&result.security),
    })
}

/// Unlink shim JSON unless spawn succeeded (secrets/CA must not linger).
#[derive(Debug)]
struct UnlinkJsonOnErr<'a> {
    /// JSON path written for this spawn.
    path: &'a Path,
    /// Set when the shim process was spawned.
    keep: bool,
}

impl Drop for UnlinkJsonOnErr<'_> {
    fn drop(&mut self) {
        if !self.keep {
            drop(fs::remove_file(self.path));
        }
    }
}

/// Write shim JSON with mode 0o600.
fn write_shim_json(path: &Path, json: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(json)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Map jail errors to product errors (preserve K22 fail-closed).
fn map_jail_error(e: bux_jail::Error, shim: &Path) -> crate::Error {
    match e {
        bux_jail::Error::LandlockUnavailable => crate::Error::SecurityUnavailable(
            "landlock required but unavailable on this kernel (set SecurityOptions.allow_degraded to proceed)"
                .into(),
        ),
        bux_jail::Error::Landlock(msg) => {
            crate::Error::SecurityUnavailable(format!("landlock ruleset failed: {msg}"))
        }
        bux_jail::Error::Io(io_err) => crate::Error::Io(io::Error::new(
            io_err.kind(),
            format!("failed to spawn {}: {io_err}", shim.display()),
        )),
        other => crate::Error::Jail(other),
    }
}

/// Locates the `bux-shim` binary.
///
/// `Some` must be a regular file or [`crate::Error::NotFound`]; `None` searches
/// env, then a sibling of the running executable, then `$PATH`.
///
/// # Errors
///
/// Returns [`crate::Error::NotFound`] if the shim cannot be located.
pub(crate) fn find_shim(explicit: Option<&Path>) -> Result<PathBuf> {
    const NAME: &str = "bux-shim";

    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(crate::Error::NotFound(format!(
            "bux-shim not found at {} (RuntimeOptions.shim_path)",
            path.display()
        )));
    }

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

    Err(crate::Error::NotFound(
        "bux-shim not found (set RuntimeOptions.shim_path, BUX_SHIM_PATH, place bux-shim next to the running executable, or on PATH)".into(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::options::{NetworkSpec, VmOptions};

    #[test]
    fn to_shim_config_offline_has_no_network() {
        let cfg = VmConfig::default();
        let shim = to_shim_config(&cfg, None, None);
        assert!(shim.network.is_none());
        assert!(shim.gvproxy.is_none());
    }

    #[test]
    fn detach_from_options_disables_parent_death() {
        let opts = VmOptions::from_image("alpine").detach(true);
        let cfg = super::super::config_from_options(&opts, None, None, vec![]);
        assert!(cfg.detach);
        let policy = spawn_policy(&cfg);
        assert!(!policy.watch_parent);
        assert!(!policy.die_with_parent);
        assert!(policy.network_host);
    }

    #[test]
    fn start_with_of_detached_row_does_not_rearm_parent_death() {
        let cfg = VmConfig {
            detach: true,
            network: NetworkSpec::Disabled,
            ..VmConfig::default()
        };
        let policy = spawn_policy(&cfg);
        assert!(!policy.watch_parent);
        assert!(!policy.die_with_parent);
        assert!(!policy.network_host);
    }

    #[test]
    fn spawn_config_rejects_long_sock_path_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let long = dir.path().join("x".repeat(120));
        fs::create_dir_all(&long).unwrap();
        let rt = Runtime::open(&long).unwrap();
        let cfg = VmConfig {
            network: NetworkSpec::Disabled,
            ..VmConfig::default()
        };
        let err = spawn_config(&rt, cfg, Vec::new(), None, None, false).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, crate::Error::InvalidConfig(_)));
        assert!(msg.contains("sun_path"), "{msg}");
        assert!(msg.contains(".sock"), "{msg}");
        assert!(!msg.contains(".net.sock"), "{msg}");
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive find_shim"
    )]
    fn find_shim_some_missing_does_not_consult_path() {
        let mut env = crate::guest::sidecar_env::lock();
        let decoy_dir = tempfile::tempdir().unwrap();
        fs::write(decoy_dir.path().join("bux-shim"), b"decoy-shim").unwrap();
        env.prepend_path(decoy_dir.path());
        env.set("BUX_SHIM_PATH", decoy_dir.path().join("bux-shim"));

        let missing = decoy_dir.path().join("missing-shim");
        let err = find_shim(Some(&missing)).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, crate::Error::NotFound(_)), "{msg}");
        assert!(msg.contains("RuntimeOptions.shim_path"), "{msg}");
        assert!(!msg.contains("bux binary"), "{msg}");
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive find_shim"
    )]
    fn find_shim_none_finds_planted_sibling() {
        let mut env = crate::guest::sidecar_env::lock();
        env.unset("BUX_SHIM_PATH");
        let planted = crate::guest::sidecar_env::Planted::sibling("bux-shim", b"planted-shim");
        let found = find_shim(None).unwrap();
        assert_eq!(found, planted.path());
    }

    #[test]
    fn find_shim_some_planted_returns_that_path() {
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join("planted-shim");
        fs::write(&planted, b"shim").unwrap();
        let found = find_shim(Some(&planted)).unwrap();
        assert_eq!(found, planted);
    }
}
