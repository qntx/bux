//! Guest PID 1 injection and `BUX_GUEST_CONFIG`.

use std::path::Path;

use bux_proto::{GuestBootConfig, GuestNetworkMode, GuestVolume};

use crate::Result;
use crate::guest::ManagedGuestBinary;
use crate::state::VmConfig;

/// First boot: inject guest into a host rootfs. Rejects unprepared raw disks.
pub(super) fn prepare_managed_config(
    config: &mut VmConfig,
    guest_path: Option<&Path>,
) -> Result<()> {
    if is_overlay_only(config) {
        return Err(crate::Error::InvalidConfig(
            "managed runtime does not support direct root_disk boot without a managed guest-rootfs preparation step".to_owned(),
        ));
    }
    apply_guest_pid1(config, guest_path)
}

/// Restart: overlay already has the injected guest. Skip host guest resolve.
pub(crate) fn prepare_restart_config(
    config: &mut VmConfig,
    guest_path: Option<&Path>,
) -> Result<()> {
    if is_overlay_only(config) {
        set_guest_pid1(config);
        return Ok(());
    }
    apply_guest_pid1(config, guest_path)
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
fn apply_guest_pid1(config: &mut VmConfig, guest_path: Option<&Path>) -> Result<()> {
    let guest = ManagedGuestBinary::resolve(guest_path)?;
    if let Some(rootfs) = config.rootfs.as_deref() {
        guest.inject_into_rootfs(Path::new(rootfs))?;
    }
    set_guest_pid1(config);
    Ok(())
}

/// Inject `BUX_GUEST_CONFIG` (network, optional MITM CA, virtio-fs mount table).
pub(crate) fn inject_guest_boot_env(
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
    let mut volumes = Vec::with_capacity(config.virtiofs.len());
    for v in &config.virtiofs {
        let vol = GuestVolume {
            tag: v.tag.clone(),
            guest_path: v.guest_path.clone(),
            read_only: v.read_only,
        };
        vol.validate().map_err(crate::Error::InvalidConfig)?;
        volumes.push(vol);
    }
    boot.volumes = volumes;
    let entry = boot
        .to_env_assignment()
        .map_err(crate::Error::InvalidConfig)?;
    config.env = Some(vec![entry]);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::disk::DiskFormat;
    use crate::options::NetworkSpec;
    use crate::state::VirtioFs;
    use bux_proto::GUEST_BOOT_CONFIG_ENV;

    #[test]
    fn guest_boot_env_uses_bux_guest_config() {
        let mut cfg = VmConfig {
            network: NetworkSpec::default(),
            ..VmConfig::default()
        };
        inject_guest_boot_env(&mut cfg, "abc", None).unwrap();
        let env = cfg.env.expect("boot env");
        assert_eq!(env.len(), 1);
        let assignment = env.first().expect("boot env");
        assert!(assignment.starts_with(&format!("{GUEST_BOOT_CONFIG_ENV}=")));
        let json = assignment
            .strip_prefix(&format!("{GUEST_BOOT_CONFIG_ENV}="))
            .expect("boot env prefix");
        let boot: GuestBootConfig = serde_json::from_str(json).unwrap();
        assert!(boot.volumes.is_empty());
    }

    #[test]
    fn guest_boot_env_includes_virtiofs_volumes() {
        let mut cfg = VmConfig {
            virtiofs: vec![VirtioFs {
                tag: "vol0".into(),
                path: "/host/data".into(),
                guest_path: "/data".into(),
                read_only: true,
            }],
            ..VmConfig::default()
        };
        inject_guest_boot_env(&mut cfg, "abc", None).unwrap();
        let assignment = cfg.env.expect("boot env").into_iter().next().expect("env");
        let json = assignment
            .strip_prefix(&format!("{GUEST_BOOT_CONFIG_ENV}="))
            .expect("boot env prefix");
        let boot: GuestBootConfig = serde_json::from_str(json).unwrap();
        assert_eq!(boot.volumes.len(), 1);
        let vol = boot.volumes.first().expect("one volume");
        assert_eq!(vol.tag, "vol0");
        assert_eq!(vol.guest_path, "/data");
        assert!(vol.read_only);
    }

    #[test]
    fn guest_boot_env_rejects_empty_tag_or_root_path() {
        let mut cfg = VmConfig {
            virtiofs: vec![VirtioFs {
                tag: String::new(),
                path: "/host/data".into(),
                guest_path: "/data".into(),
                read_only: false,
            }],
            ..VmConfig::default()
        };
        assert!(matches!(
            inject_guest_boot_env(&mut cfg, "abc", None),
            Err(crate::Error::InvalidConfig(_))
        ));

        {
            let share = cfg.virtiofs.first_mut().expect("one virtiofs");
            share.tag = "vol0".into();
            share.guest_path.clear();
        }
        assert!(matches!(
            inject_guest_boot_env(&mut cfg, "abc", None),
            Err(crate::Error::InvalidConfig(_))
        ));

        cfg.virtiofs.first_mut().expect("one virtiofs").guest_path = "/".into();
        assert!(matches!(
            inject_guest_boot_env(&mut cfg, "abc", None),
            Err(crate::Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn first_boot_rejects_bare_root_disk() {
        let mut cfg = VmConfig {
            root_disk: Some("/tmp/unprepared.raw".into()),
            ..VmConfig::default()
        };
        assert!(matches!(
            prepare_managed_config(&mut cfg, None),
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
        prepare_restart_config(&mut cfg, None).unwrap();
        assert_eq!(
            cfg.exec_path.as_deref(),
            Some(ManagedGuestBinary::exec_path())
        );
        assert!(cfg.exec_args.is_empty());
        assert!(cfg.env.is_none());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive inject"
    )]
    fn apply_guest_pid1_uses_runtime_guest_path_not_path_decoy() {
        let mut env = crate::guest::sidecar_env::lock();
        let planted_bytes = crate::guest::test_static_guest_elf(b"PLANT-GUEST-ELF!");
        let decoy_bytes = crate::guest::test_static_guest_elf(b"DECOY-GUEST-ELF!");

        let files = tempfile::tempdir().unwrap();
        let planted = files.path().join("planted-guest");
        let decoy = files.path().join("decoy-guest");
        std::fs::write(&planted, &planted_bytes).unwrap();
        std::fs::write(&decoy, &decoy_bytes).unwrap();

        let decoy_bin = tempfile::tempdir().unwrap();
        std::fs::write(decoy_bin.path().join("bux-guest"), &decoy_bytes).unwrap();
        env.prepend_path(decoy_bin.path());
        env.set("BUX_GUEST_PATH", &decoy);

        let data = tempfile::tempdir().unwrap();
        let rt = crate::Runtime::open_with(crate::RuntimeOptions {
            data_dir: data.path().to_path_buf(),
            shim_path: None,
            guest_path: Some(planted),
            registry_auth: crate::RegistryAuth::Anonymous,
        })
        .unwrap();

        let rootfs = tempfile::tempdir().unwrap();
        let mut cfg = VmConfig {
            rootfs: Some(rootfs.path().to_string_lossy().into_owned()),
            ..VmConfig::default()
        };
        prepare_managed_config(&mut cfg, rt.guest_path.as_deref()).unwrap();
        let injected =
            std::fs::read(rootfs.path().join(ManagedGuestBinary::relative_path())).unwrap();
        assert_eq!(
            injected, planted_bytes,
            "rootfs must contain the planted ELF"
        );
        assert_ne!(
            injected, decoy_bytes,
            "rootfs must not contain the PATH decoy"
        );
    }
}
