//! Apply [`ShimConfig`] to a libkrun context and start the VM.
//!
//! Product callers are [`prepare`] / optional [`install_seccomp`] / [`start`].
//! This module never constructs gvproxy.

use bux_krun::ctx as sys;

use crate::config::{ShimConfig, ShimDiskFormat, ShimNetConn};
use crate::error::{Error, Result};

/// Prepared libkrun context ready for [`PreparedVm::start`].
#[derive(Debug)]
pub struct PreparedVm {
    /// Opaque libkrun context id (`None` after start or free).
    ctx: Option<u32>,
}

impl PreparedVm {
    /// Borrow the raw context id, if still held.
    #[must_use]
    pub const fn ctx(&self) -> Option<u32> {
        self.ctx
    }

    /// Consume the prepared VM and return the raw context id without freeing it.
    ///
    /// Caller becomes responsible for `start_enter` or `free_ctx`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context was already consumed.
    pub fn into_ctx(mut self) -> Result<u32> {
        self.ctx
            .take()
            .ok_or_else(|| Error::InvalidConfig("PreparedVm context already consumed".into()))
    }

    /// Takes over the process via `krun_start_enter`.
    ///
    /// On success this function never returns.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Krun`] if the FFI call fails before takeover.
    pub fn start(mut self) -> Result<()> {
        let ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::InvalidConfig("PreparedVm context already consumed".into()))?;
        match sys::start_enter(ctx) {
            Ok(()) => Ok(()),
            Err(e) => {
                // start_enter failed before takeover — free context.
                drop(sys::free_ctx(ctx));
                Err(Error::Krun(e))
            }
        }
    }
}

impl Drop for PreparedVm {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            drop(sys::free_ctx(ctx));
        }
    }
}

/// Create a libkrun context and apply `cfg` (does not enter the VM).
///
/// # Errors
///
/// Returns configuration or FFI errors. On failure the context is freed.
pub fn prepare(cfg: &ShimConfig) -> Result<PreparedVm> {
    let ctx = sys::create_ctx()?;
    match apply_all(ctx, cfg) {
        Ok(()) => Ok(PreparedVm { ctx: Some(ctx) }),
        Err(e) => {
            drop(sys::free_ctx(ctx));
            Err(e)
        }
    }
}

/// `krun_start_enter` — never returns on success.
///
/// # Errors
///
/// Returns [`Error::Krun`] if entry fails.
pub fn start(ctx: u32) -> Result<()> {
    Ok(sys::start_enter(ctx)?)
}

/// Install the default seccomp BPF filter (Linux `x86_64`/`aarch64`).
///
/// Other platforms: no-op. The `bux-shim` binary skips this when gvproxy
/// is in-process.
///
/// # Errors
///
/// Returns [`Error::Seccomp`] if installation fails (fail-closed).
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "Result/errors only arise on Linux x86_64/aarch64; other platforms no-op"
)]
pub fn install_seccomp() -> Result<()> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        bux_seccomp::install_default().map_err(|e| Error::Seccomp(e.to_string()))
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        Ok(())
    }
}

/// Apply every field of `cfg` to an existing libkrun context.
fn apply_all(ctx: u32, cfg: &ShimConfig) -> Result<()> {
    if let Some(level) = cfg.log_level {
        sys::set_log_level(level)?;
    }

    sys::set_vm_config(ctx, cfg.vcpus, cfg.ram_mib)?;

    match (&cfg.rootfs, &cfg.root_disk) {
        (Some(root), None) => {
            sys::set_root(ctx, root)?;
        }
        (None, Some(disk)) => {
            let sys_fmt = match cfg.disk_format {
                ShimDiskFormat::Qcow2 => sys::DiskFormat::Qcow2,
                ShimDiskFormat::Raw => sys::DiskFormat::Raw,
            };
            sys::add_disk2(ctx, "rootfs", disk, sys_fmt, false)?;
            sys::set_root_disk_remount(ctx, "/dev/vda", Some("ext4"), None)?;
        }
        (Some(_), Some(_)) => {
            return Err(Error::InvalidConfig(
                "ShimConfig: rootfs and root_disk are mutually exclusive".into(),
            ));
        }
        (None, None) => {
            return Err(Error::InvalidConfig(
                "ShimConfig: need rootfs or root_disk".into(),
            ));
        }
    }

    for share in &cfg.virtiofs {
        sys::add_virtiofs(ctx, &share.tag, &share.path)?;
    }

    // Virtio-net only. Never `set_port_map`.
    // Skipping `add_net_*` would auto-enable TSI (host-stack leak).
    if let Some(ref net) = cfg.network {
        const FEATURES: u32 = bux_krun::sys::COMPAT_NET_FEATURES;
        let flags = match net.connection {
            ShimNetConn::UnixDgram => bux_krun::sys::NET_FLAG_VFKIT,
            ShimNetConn::UnixStream => 0,
        };
        let path = net.socket_path.to_string_lossy();
        match net.connection {
            ShimNetConn::UnixStream => {
                sys::add_net_unixstream(ctx, Some(path.as_ref()), -1, &net.mac, FEATURES, flags)?;
            }
            ShimNetConn::UnixDgram => {
                sys::add_net_unixgram(ctx, Some(path.as_ref()), -1, &net.mac, FEATURES, flags)?;
            }
        }
    }
    if cfg.network.is_none() {
        sys::disable_implicit_vsock(ctx)?;
        sys::add_vsock(ctx, 0)?;
    }

    if let Some(ref workdir) = cfg.workdir {
        sys::set_workdir(ctx, workdir)?;
    }

    if let Some(ref exec_path) = cfg.exec_path {
        sys::set_exec(ctx, exec_path, &cfg.exec_args, cfg.env.as_deref())?;
    } else if let Some(ref env) = cfg.env {
        sys::set_env(ctx, env)?;
    }

    if let Some(uid) = cfg.uid {
        sys::setuid(ctx, uid)?;
    }
    if let Some(gid) = cfg.gid {
        sys::setgid(ctx, gid)?;
    }
    if !cfg.rlimits.is_empty() {
        sys::set_rlimits(ctx, &cfg.rlimits)?;
    }
    if let Some(enable) = cfg.nested_virt {
        sys::set_nested_virt(ctx, enable)?;
    }
    if let Some(enable) = cfg.snd_device {
        sys::set_snd_device(ctx, enable)?;
    }
    if let Some(ref path) = cfg.console_output {
        sys::set_console_output(ctx, path)?;
    }
    for vs in &cfg.vsock_ports {
        sys::add_vsock_port2(ctx, vs.port, &vs.path, vs.listen)?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    reason = "unit tests"
)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{ShimDiskFormat, ShimVsockPort};

    fn offline_cfg(rootfs: &str, vsock: &str) -> ShimConfig {
        ShimConfig {
            vm_id: "offline-tsi".into(),
            vcpus: 1,
            ram_mib: 128,
            rootfs: Some(rootfs.into()),
            root_disk: None,
            disk_format: ShimDiskFormat::Raw,
            virtiofs: vec![],
            vsock_ports: vec![ShimVsockPort {
                port: 1024,
                path: vsock.into(),
                listen: true,
            }],
            network: None,
            gvproxy: None,
            log_level: None,
            exec_path: None,
            exec_args: vec![],
            env: None,
            workdir: None,
            uid: None,
            gid: None,
            rlimits: vec![],
            nested_virt: None,
            snd_device: None,
            console_output: None,
        }
    }

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bux-shim-offline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn disable_implicit_vsock_then_add_vsock_zero() {
        // BoxLite engine.rs `disable_network`: same FFI order on this libkrun.
        let ctx = sys::create_ctx().expect("create_ctx");
        let applied = sys::disable_implicit_vsock(ctx).and_then(|()| sys::add_vsock(ctx, 0));
        drop(sys::free_ctx(ctx));
        applied.expect("disable_implicit_vsock + add_vsock(0)");
    }

    #[test]
    fn prepare_disabled_network_disables_tsi() {
        let dir = scratch_dir();
        let rootfs = dir.join("root");
        std::fs::create_dir_all(&rootfs).unwrap();
        let vsock = dir.join("agent.sock");
        let cfg = offline_cfg(
            rootfs.to_str().expect("utf8 rootfs"),
            vsock.to_str().expect("utf8 vsock"),
        );

        let prepared = prepare(&cfg).expect("prepare network=None");
        let ctx = prepared.ctx().expect("PreparedVm holds ctx");
        // libkrun allows one vsock device; prepare already called add_vsock(0).
        assert!(
            sys::add_vsock(ctx, 0).is_err(),
            "prepare must have called add_vsock already"
        );
        drop(prepared);
        drop(std::fs::remove_dir_all(&dir));
    }
}
