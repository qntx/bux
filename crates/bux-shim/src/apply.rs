//! Apply [`ShimConfig`] to a libkrun context and start the VM.
//!
//! Single code path used by the `bux-shim` binary and by host-side
//! builders that prepare a context without process takeover.

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

/// `prepare`, install default seccomp, then `start`. Never returns on success.
///
/// Seccomp is installed after libkrun `prepare()` (context fully configured)
/// and before `krun_start_enter` process takeover.
///
/// # Errors
///
/// Propagates prepare, seccomp, or start errors. Seccomp install failure
/// is fail-closed on Linux `x86_64`/`aarch64`.
pub fn boot(cfg: &ShimConfig) -> Result<()> {
    let prepared = prepare(cfg)?;
    install_seccomp()?;
    prepared.start()
}

/// Install the default seccomp BPF filter (Linux `x86_64`/`aarch64`).
///
/// Other platforms: no-op.
///
/// # Errors
///
/// Returns [`Error::Seccomp`] if installation fails (fail-closed).
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "Result/errors only arise on Linux x86_64/aarch64; other platforms no-op"
)]
fn install_seccomp() -> Result<()> {
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
    // `network=None` still auto-enables libkrun TSI (known D2).
    // PR2: `disable_implicit_vsock` + `add_vsock(0)` on this branch.
    if let Some(ref net) = cfg.network {
        let path = net.socket_path.to_string_lossy();
        match net.connection {
            ShimNetConn::UnixStream => {
                sys::add_net_unixstream(ctx, Some(path.as_ref()), -1, &net.mac, 0, 0)?;
            }
            ShimNetConn::UnixDgram => {
                sys::add_net_unixgram(ctx, Some(path.as_ref()), -1, &net.mac, 0, 0)?;
            }
        }
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
