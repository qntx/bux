//! Managed boot path: [`VmOptions`] → running [`Vm`].
//!
//! Image resolve, overlay, jail spawn, and guest-agent ready wait live here.
//! Engine JSON (`ShimNetwork` + `ShimGvproxy`) is produced only at spawn time.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use bux_jail::JailConfig;
use bux_proto::{AGENT_PORT, GuestBootConfig, GuestNetworkMode};
use bux_shim::{
    ShimConfig, ShimDiskFormat, ShimGvproxy, ShimNetConn, ShimNetwork, ShimVirtioFs, ShimVsockPort,
};
use nix::sys::signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use tracing::info;

use super::{Runtime, Vm};
use crate::Result;
use crate::disk::DiskFormat;
use crate::guest::ManagedGuestBinary;
use crate::options::{ImageRef, NetworkSpec, VmOptions};
use crate::ports::{format_port_pairs, parse_publish_spec, resolve_ports};
use crate::process::merge_image_config;
use crate::secrets::{LiveSecrets, Secret};
use crate::state::{self, Status, VirtioFs, VmConfig, VmState, VsockPort};
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
    clean_vm_files(socket);
    drop(rt.volumes().unlink_vm(id));
    drop(rt.disk.remove_vm_disk(id));
    drop(rt.db.delete(id));
}

/// Result of spawning a shim subprocess.
pub(super) struct ShimSpawnResult {
    /// Child PID (as i32 for nix compatibility).
    pub pid: i32,
    /// Parent-side watchdog keepalive.
    pub keepalive: Option<Keepalive>,
    /// Actual security posture from the jail spawn.
    pub security: crate::security::SecurityStatus,
}

/// Create and start a managed VM from product options.
///
/// # Errors
///
/// Propagates image pull, disk, network, spawn, or agent-ready failures.
pub(crate) async fn create(
    rt: &Runtime,
    mut opts: VmOptions,
    on_progress: impl Fn(&str) + Send + Sync,
) -> Result<Vm> {
    on_progress("validating options");
    validate(&opts)?;

    on_progress("resolving image");
    let resolved = resolve_image(rt, &opts.image, &on_progress).await?;

    if let Some(ref img) = resolved.oci_cfg {
        merge_image_config(
            &mut opts.env,
            &mut opts.workdir,
            &mut opts.user,
            &mut opts.command,
            img,
        );
    }

    on_progress("resolving volumes");
    let resolved_vols = rt.volumes().resolve_mounts(&opts.volumes)?;
    let virtiofs = resolved_vols
        .iter()
        .map(crate::volumes::ResolvedVolume::to_virtiofs)
        .collect();

    let secrets = opts.secrets.clone();
    let config = config_from_options(&opts, resolved.rootfs, resolved.base_disk, virtiofs);

    on_progress("spawning shim");
    let mut vm = spawn_config(
        rt,
        config,
        secrets,
        resolved.image_label,
        opts.name.clone(),
        opts.auto_remove,
    )?;

    if !resolved_vols.is_empty()
        && let Err(e) = rt
            .volumes()
            .link_vm(vm.stored().id.as_str(), &resolved_vols)
    {
        vm.abort_unready();
        return Err(e);
    }

    if !opts.ready_timeout.is_zero() {
        on_progress("waiting for guest agent");
        if let Err(e) = vm.wait_ready(opts.ready_timeout).await {
            vm.abort_unready();
            return Err(e);
        }
    }

    on_progress("running");
    Ok(vm)
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
    let socket_str = socket.to_string_lossy().into_owned();

    prepare_managed_config(&mut config)?;
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
    let shim = spawn_shim(&config, &config_path, &rt.socks_dir, &id, network, gvproxy)?;
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
    ))
}

/// Validate product options before expensive work.
fn validate(opts: &VmOptions) -> Result<()> {
    if opts.vcpus == 0 {
        return Err(crate::Error::InvalidConfig("vcpus must be >= 1".into()));
    }
    if opts.ram_mib == 0 {
        return Err(crate::Error::InvalidConfig("ram_mib must be >= 1".into()));
    }
    if !opts.secrets.is_empty() && !opts.network.is_enabled() {
        return Err(crate::Error::SecretsNeedVirtioNet);
    }
    if matches!(opts.network, NetworkSpec::Disabled) && !opts.ports.is_empty() {
        return Err(crate::Error::InvalidConfig(
            "port publish requires NetworkSpec::Enabled".into(),
        ));
    }
    for p in &opts.ports {
        parse_publish_spec(p)?;
    }
    Ok(())
}

/// Image resolution result used to fill [`VmConfig`].
struct ResolvedImage {
    /// virtiofs root directory, if any.
    rootfs: Option<String>,
    /// Shared ext4/raw base disk path, if any.
    base_disk: Option<String>,
    /// Label stored on the VM row.
    image_label: Option<String>,
    /// OCI process config for workload defaults.
    oci_cfg: Option<bux_oci::ImageConfig>,
}

/// Resolve [`ImageRef`] to rootfs / base disk paths.
async fn resolve_image(
    rt: &Runtime,
    image: &ImageRef,
    on_progress: &(impl Fn(&str) + Send + Sync),
) -> Result<ResolvedImage> {
    match image {
        ImageRef::Oci(reference) => {
            on_progress("pulling/ensuring OCI image");
            let pull = rt.oci().ensure(reference, on_progress).await?;
            let oci_cfg = pull.config.clone();

            on_progress("building ext4 base disk");
            let image_label = reference.clone();
            let base_path = {
                let disk = rt.disk().clone();
                let rootfs = pull.rootfs.clone();
                let digest = pull.digest.replace(':', "-");
                let pull_ref = pull.reference.clone();
                tokio::task::spawn_blocking(move || -> Result<PathBuf> {
                    info!(image = %pull_ref, "creating ext4 base image from rootfs");
                    disk.create_managed_base(&rootfs, &digest)
                })
                .await
                .map_err(io::Error::other)??
            };

            Ok(ResolvedImage {
                rootfs: None,
                base_disk: Some(base_path.to_string_lossy().into_owned()),
                image_label: Some(image_label),
                oci_cfg,
            })
        }
        ImageRef::Rootfs(path) => {
            if !path.is_dir() {
                return Err(crate::Error::InvalidConfig(format!(
                    "rootfs is not a directory: {}",
                    path.display()
                )));
            }
            Ok(ResolvedImage {
                rootfs: Some(path.to_string_lossy().into_owned()),
                base_disk: None,
                image_label: Some(path.display().to_string()),
                oci_cfg: None,
            })
        }
        ImageRef::BaseDisk(path) => {
            if !path.is_file() {
                return Err(crate::Error::InvalidConfig(format!(
                    "base disk not found: {}",
                    path.display()
                )));
            }
            Ok(ResolvedImage {
                rootfs: None,
                base_disk: Some(path.to_string_lossy().into_owned()),
                image_label: Some(path.display().to_string()),
                oci_cfg: None,
            })
        }
    }
}

/// Build persisted config from product options and resolved image/volumes.
fn config_from_options(
    opts: &VmOptions,
    rootfs: Option<String>,
    base_disk: Option<String>,
    virtiofs: Vec<VirtioFs>,
) -> VmConfig {
    VmConfig {
        vcpus: opts.vcpus,
        ram_mib: opts.ram_mib,
        rootfs,
        base_disk,
        ports: opts.ports.clone(),
        virtiofs,
        network: opts.network.clone(),
        secrets_required: !opts.secrets.is_empty(),
        workload_env: opts.env.clone(),
        workload_workdir: opts.workdir.clone(),
        workload_user: opts.user.clone(),
        workload_cmd: opts.command.clone().unwrap_or_default(),
        security: opts.security,
        auto_remove: opts.auto_remove,
        auto_stop_secs: opts.auto_stop_secs,
        auto_delete_secs: opts.auto_delete_secs,
        last_activity_at: Some(std::time::SystemTime::now()),
        detach: opts.detach,
        ..VmConfig::default()
    }
}

/// Map persisted [`VmConfig`] into engine [`ShimConfig`].
///
/// Port publish is gvproxy-only; this mapping never sets a TSI port map.
fn to_shim_config(
    vm_id: &str,
    config: &VmConfig,
    network: Option<ShimNetwork>,
    gvproxy: Option<ShimGvproxy>,
) -> ShimConfig {
    ShimConfig {
        vm_id: vm_id.to_owned(),
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
        log_level: config.log_level.map(|l| l as u32),
        exec_path: config.exec_path.clone(),
        exec_args: config.exec_args.clone(),
        env: config.env.clone(),
        workdir: None,
        uid: None,
        gid: None,
        rlimits: Vec::new(),
        nested_virt: None,
        snd_device: None,
        console_output: None,
    }
}

/// Builds a diagnostic message when the shim dies before the guest agent is ready.
pub(super) fn shim_death_message(pid: i32, exit_file: &Path) -> String {
    let detail = bux_shim::ExitInfo::from_file(exit_file)
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

/// Removes transient files associated with a VM socket path.
pub(super) fn clean_vm_files(socket: &Path) {
    drop(fs::remove_file(socket));
    for ext in ["exit", "json", "stderr"] {
        drop(fs::remove_file(socket.with_extension(ext)));
    }
    clean_net_sock(socket);
}

/// `{id}.sock` → `{id}.net.sock`.
pub(super) fn clean_net_sock(socket: &Path) {
    drop(fs::remove_file(socket.with_extension("net.sock")));
}

/// Checks if a process is alive via `kill(pid, 0)`.
pub(super) fn is_pid_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Blocks until a process exits.
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

/// First boot: inject guest into a host rootfs. Rejects unprepared raw disks.
pub(super) fn prepare_managed_config(config: &mut VmConfig) -> Result<()> {
    if is_overlay_only(config) {
        return Err(crate::Error::InvalidConfig(
            "managed runtime does not support direct root_disk boot without a managed guest-rootfs preparation step".to_owned(),
        ));
    }
    apply_guest_pid1(config)
}

/// Restart: overlay already has the injected guest. Skip host guest resolve.
pub(super) fn prepare_restart_config(config: &mut VmConfig) -> Result<()> {
    if is_overlay_only(config) {
        set_guest_pid1(config);
        return Ok(());
    }
    apply_guest_pid1(config)
}

/// Persisted overlay: `root_disk` set, no host rootfs / base to inject.
const fn is_overlay_only(config: &VmConfig) -> bool {
    config.root_disk.is_some() && config.rootfs.is_none() && config.base_disk.is_none()
}

/// Point PID 1 at the managed guest; clear leftover boot env.
fn set_guest_pid1(config: &mut VmConfig) {
    config.exec_path = Some(ManagedGuestBinary::exec_path().to_owned());
    config.exec_args.clear();
    config.env = None;
}

/// Resolve the host guest ELF and inject into a rootfs directory when present.
fn apply_guest_pid1(config: &mut VmConfig) -> Result<()> {
    let guest = ManagedGuestBinary::resolve()?;
    if let Some(rootfs) = config.rootfs.as_deref() {
        guest.inject_into_rootfs(Path::new(rootfs))?;
    }
    set_guest_pid1(config);
    Ok(())
}

/// Inject `BUX_GUEST_CONFIG` for the guest agent (network mode + optional MITM CA).
pub(super) fn inject_guest_boot_env(
    config: &mut VmConfig,
    vm_id: &str,
    mitm_ca_pem: Option<String>,
) -> Result<()> {
    let mode = if config.network.is_enabled() {
        GuestNetworkMode::Enabled
    } else {
        GuestNetworkMode::Disabled
    };
    let mut boot = GuestBootConfig::new(vm_id, mode);
    boot.mitm_ca_pem = mitm_ca_pem;
    let entry = boot
        .to_env_assignment()
        .map_err(crate::Error::InvalidConfig)?;
    config.env = Some(vec![entry]);
    Ok(())
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

/// Build virtio-net JSON for the shim binary. Both `Some` or both `None`.
pub(super) fn prepare_virtio_net(
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
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }

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

/// Writes config JSON (mode 0o600), creates watchdog pipe, and spawns `bux-shim`.
///
/// `network` / `gvproxy` are both `Some` (virtio-net) or both `None` (offline).
pub(super) fn spawn_shim(
    config: &VmConfig,
    config_path: &Path,
    socks_dir: &Path,
    vm_id: &str,
    network: Option<ShimNetwork>,
    gvproxy: Option<ShimGvproxy>,
) -> Result<ShimSpawnResult> {
    if network.is_some() != gvproxy.is_some() {
        return Err(crate::Error::InvalidConfig(
            "gvproxy and network must both be set or both absent".into(),
        ));
    }
    let policy = spawn_policy(config);
    let shim_cfg = to_shim_config(vm_id, config, network, gvproxy);
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
    let shim = find_shim()?;
    #[cfg(target_os = "macos")]
    ensure_shim_dylib_aliases(&shim)?;

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
        resource_limits: None,
        stderr_file: Some(stderr_file),
        landlock: sec.landlock,
        allow_degraded_security: sec.allow_degraded,
        die_with_parent: policy.die_with_parent,
        network_host: policy.network_host,
    };

    let result = bux_jail::spawn(&shim, config_path, jail_config, vm_id)
        .map_err(|e| map_jail_error(e, &shim))?;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use bux_proto::GUEST_BOOT_CONFIG_ENV;

    #[test]
    fn reject_secrets_when_offline() {
        let opts = VmOptions::from_image("alpine")
            .network(NetworkSpec::Disabled)
            .secrets([Secret::new("k", ["h"], "v")]);
        assert!(matches!(
            validate(&opts),
            Err(crate::Error::SecretsNeedVirtioNet)
        ));
    }

    #[test]
    fn reject_ports_when_offline() {
        let opts = VmOptions::from_image("alpine")
            .network(NetworkSpec::Disabled)
            .port("8080:80");
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn reject_zero_resources() {
        let mut opts = VmOptions::from_image("alpine");
        opts.vcpus = 0;
        assert!(validate(&opts).is_err());
        opts = VmOptions::from_image("alpine");
        opts.ram_mib = 0;
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn to_shim_config_offline_has_no_network() {
        let cfg = VmConfig::default();
        let shim = to_shim_config("vm1", &cfg, None, None);
        assert!(shim.network.is_none());
        assert!(shim.gvproxy.is_none());
        assert!(shim.uid.is_none());
        assert!(shim.gid.is_none());
        assert!(shim.rlimits.is_empty());
        assert!(shim.workdir.is_none());
    }

    #[test]
    fn detach_from_options_disables_parent_death() {
        let opts = VmOptions::from_image("alpine").detach(true);
        let cfg = config_from_options(&opts, None, None, vec![]);
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
    fn guest_boot_env_uses_bux_guest_config() {
        let mut cfg = VmConfig {
            network: NetworkSpec::default(),
            ..VmConfig::default()
        };
        inject_guest_boot_env(&mut cfg, "abc", None).unwrap();
        let env = cfg.env.expect("boot env");
        assert_eq!(env.len(), 1);
        assert!(
            env.first()
                .expect("boot env")
                .starts_with(&format!("{GUEST_BOOT_CONFIG_ENV}="))
        );
    }

    #[test]
    fn first_boot_rejects_bare_root_disk() {
        let mut cfg = VmConfig {
            root_disk: Some("/tmp/unprepared.raw".into()),
            ..VmConfig::default()
        };
        assert!(matches!(
            prepare_managed_config(&mut cfg),
            Err(crate::Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn restart_overlay_sets_guest_exec_without_host_binary() {
        let mut cfg = VmConfig {
            root_disk: Some("/tmp/vm.qcow2".into()),
            disk_format: DiskFormat::Qcow2,
            exec_path: Some("/bux/bin/bux-guest".into()),
            ..VmConfig::default()
        };
        prepare_restart_config(&mut cfg).unwrap();
        assert_eq!(
            cfg.exec_path.as_deref(),
            Some(ManagedGuestBinary::exec_path())
        );
        assert!(cfg.exec_args.is_empty());
        assert!(cfg.env.is_none());
    }
}
