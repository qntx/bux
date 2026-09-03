//! Managed boot path: [`VmOptions`] → running [`Vm`].
//!
//! Image resolve, overlay, jail spawn, and guest-agent ready wait live here.
//! Engine JSON (`ShimNetwork` + `ShimGvproxy`) is produced only at spawn time.

mod guest;
mod spawn;
mod unix;

pub(super) use guest::{inject_guest_boot_env, prepare_restart_config};
#[allow(unused_imports, reason = "return type of spawn_shim")]
pub(super) use spawn::ShimSpawnResult;
pub(crate) use spawn::spawn_config;
pub(super) use spawn::spawn_shim;
#[allow(unused_imports, reason = "crate re-export of timeout stderr dump")]
pub(super) use unix::stderr_tail;
pub(super) use unix::{
    agent_not_ready_message, clean_net_sock, clean_unready_files, clean_vm_files, clean_vsock_sock,
    is_pid_alive, prepare_virtio_net, shim_death_message, wait_for_exit,
};

use std::io;
use std::path::PathBuf;

use tracing::info;

use super::{Runtime, Vm};
use crate::Result;
use crate::options::{ImageRef, NetworkSpec, VmOptions};
use crate::ports::parse_publish_spec;
use crate::process::merge_image_config;
use crate::security::HostInfo;
use crate::state::{VirtioFs, VmConfig};

/// Create and start a managed VM from product options.
///
/// # Errors
///
/// Propagates validation, missing virtualization, image pull, disk, network,
/// spawn, or agent-ready failures.
pub(crate) async fn create(
    rt: &Runtime,
    mut opts: VmOptions,
    on_progress: impl Fn(&str) + Send + Sync,
) -> Result<Vm> {
    on_progress("validating options");
    validate(&opts)?;
    require_virtualization(HostInfo::probe().virtualization)?;

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

/// Reject create before image pull/disk work when hardware virtualization is absent.
fn require_virtualization(virtualization: bool) -> Result<()> {
    if !virtualization {
        return Err(crate::Error::SecurityUnavailable(
            "no hardware virtualization (KVM / HVF)".into(),
        ));
    }
    Ok(())
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
            let image_label = pull.reference.clone();
            let base_path = {
                let disk = rt.disk().clone();
                let rootfs = pull.rootfs.clone();
                let digest = pull.digest.replace(':', "-");
                let pull_ref = pull.reference.clone();
                let guest_path = rt.guest_path.clone();
                tokio::task::spawn_blocking(move || -> Result<PathBuf> {
                    info!(image = %pull_ref, "creating ext4 base image from rootfs");
                    disk.create_managed_base(&rootfs, &digest, guest_path.as_deref())
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
        agent_id: opts.agent_id.clone(),
        tenant_id: opts.tenant_id.clone(),
        ..VmConfig::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::secrets::Secret;

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
    fn require_virtualization_false_is_unavailable() {
        let err = require_virtualization(false).unwrap_err();
        assert!(matches!(err, crate::Error::SecurityUnavailable(_)));
        assert_eq!(err.to_string(), "no hardware virtualization (KVM / HVF)");
        assert!(require_virtualization(true).is_ok());
    }

    #[test]
    fn config_from_options_copies_identity() {
        let opts = VmOptions::from_image("alpine")
            .agent_id("agt")
            .tenant_id("ten")
            .vcpus(2)
            .ram_mib(1024)
            .env(["A=1"])
            .workdir("/work");
        let cfg = config_from_options(&opts, None, None, vec![]);
        assert_eq!(cfg.agent_id.as_deref(), Some("agt"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("ten"));
        assert_eq!(cfg.vcpus, 2);
        assert_eq!(cfg.ram_mib, 1024);
        assert_eq!(cfg.workload_env, vec!["A=1"]);
        assert_eq!(cfg.workload_workdir.as_deref(), Some("/work"));
    }
}
