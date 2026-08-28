//! Build Landlock path allowlists for the shim jail (Linux).

use std::path::{Path, PathBuf};

use bux_landlock::PathRestrictions;

use super::JailConfig;

/// Build a Landlock ruleset fd for the jail paths, or `None` if the kernel has no Landlock.
///
/// # Errors
///
/// Returns ruleset construction errors from the kernel (not mere unavailability).
pub(crate) fn build_fd(
    jail: &JailConfig,
    shim: &Path,
    config_path: &Path,
) -> Result<Option<std::os::fd::RawFd>, String> {
    let restrictions = path_restrictions(jail, shim, config_path);
    restrictions.build().map_err(|e| e.to_string())
}

/// Writable `/dev` leaves. `/dev` itself stays read-only because `PathBeneath` is recursive.
const DEV_RW_LEAVES: &[&str] = &[
    "/dev/kvm",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/shm",
];

/// Assemble allow-lists matching bwrap binds + paths the shim needs.
fn path_restrictions(jail: &JailConfig, shim: &Path, config_path: &Path) -> PathRestrictions {
    let mut r = PathRestrictions::new();

    // System trees the shim / bwrap / libkrun need (exist-only).
    for p in [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc",
        "/opt",
        "/System",
        "/Library",
        "/Applications", // macOS n/a on Linux but harmless if missing
    ] {
        if Path::new(p).exists() {
            r = r.allow_read(p);
        }
    }

    r = allow_dev(r, Path::exists);
    if Path::new("/tmp").exists() {
        r = r.allow_read_write("/tmp");
    }
    if Path::new("/var/tmp").exists() {
        r = r.allow_read_write("/var/tmp");
    }
    // proc is needed by some runtimes; landlock may not cover /proc on all ABIs.
    if Path::new("/proc").exists() {
        r = r.allow_read("/proc");
    }

    // Shim binary + sibling dylibs (libkrun).
    r = allow_path_and_parent(r, shim, true);
    r = allow_path_and_parent(r, config_path, true);

    if let Some(ref rootfs) = jail.rootfs {
        r = r.allow_read_write(rootfs);
    }
    if let Some(ref disk) = jail.root_disk {
        r = allow_path_and_parent(r, disk, false);
    }
    for p in &jail.readonly_paths {
        r = allow_path_and_parent(r, p, true);
    }
    r = r.allow_read_write(&jail.socks_dir);
    for p in &jail.virtiofs_paths {
        r = r.allow_read_write(p);
    }

    if !jail.network_host {
        r = r.deny_network();
    }

    r
}

/// Grant `/dev` read/traverse and RW only on listed leaves that exist.
///
/// `PathBeneath` is recursive, so `/dev` itself must not be RW.
fn allow_dev(mut r: PathRestrictions, exists: impl Fn(&Path) -> bool) -> PathRestrictions {
    if exists(Path::new("/dev")) {
        r = r.allow_read("/dev");
    }
    for p in DEV_RW_LEAVES {
        if exists(Path::new(p)) {
            r = r.allow_read_write(*p);
        }
    }
    r
}

/// Allow `path` and, when present, its parent — both with the same access mode.
///
/// Parent access is required so Landlock can traverse to the leaf. The parent
/// inherits the leaf's mode, so a RW leaf RW-allows its parent (`PathBeneath`
/// is recursive). Do not use this for `/dev/*`.
fn allow_path_and_parent(
    mut restrictions: PathRestrictions,
    path: &Path,
    read_only: bool,
) -> PathRestrictions {
    let add = |acc: PathRestrictions, p: PathBuf| {
        if read_only {
            acc.allow_read(p)
        } else {
            acc.allow_read_write(p)
        }
    };
    if path.exists() {
        restrictions = add(restrictions, path.to_path_buf());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
    {
        restrictions = add(restrictions, parent.to_path_buf());
    }
    restrictions
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn restrictions_include_socks_dir() {
        let jail = JailConfig {
            rootfs: None,
            root_disk: Some(PathBuf::from("/tmp/disk.qcow2")),
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![PathBuf::from("/tmp/vol")],
            watchdog_fd: None,
            sandbox: None,
            stderr_file: None,
            landlock: true,
            allow_degraded_security: false,
            die_with_parent: true,
            network_host: false,
        };
        let r = path_restrictions(
            &jail,
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
        );
        assert!(
            r.read_write_paths()
                .iter()
                .any(|p| p == Path::new("/tmp/bux-socks"))
        );
        assert!(r.network_denied(), "offline VMs deny Landlock AccessNet");
    }

    #[test]
    fn enabled_network_does_not_deny_landlock_net() {
        let jail = JailConfig {
            rootfs: None,
            root_disk: None,
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![],
            watchdog_fd: None,
            sandbox: None,
            stderr_file: None,
            landlock: true,
            allow_degraded_security: false,
            die_with_parent: true,
            network_host: true,
        };
        let r = path_restrictions(
            &jail,
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
        );
        assert!(
            !r.network_denied(),
            "virtio-net VMs must bind host ports and egress"
        );
    }

    #[test]
    fn dev_parent_is_read_only_leaves_are_read_write() {
        let r = allow_dev(PathRestrictions::new(), |_| true);
        assert!(r.read_paths().iter().any(|p| p == Path::new("/dev")));
        assert!(
            !r.read_write_paths().iter().any(|p| p == Path::new("/dev")),
            "/dev must not be RW; PathBeneath is recursive"
        );
        for leaf in DEV_RW_LEAVES {
            assert!(r.read_write_paths().iter().any(|p| p == Path::new(leaf)));
        }

        let jail = JailConfig {
            rootfs: None,
            root_disk: None,
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![],
            watchdog_fd: None,
            sandbox: None,
            stderr_file: None,
            landlock: true,
            allow_degraded_security: false,
            die_with_parent: true,
            network_host: false,
        };
        let assembled = path_restrictions(
            &jail,
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
        );
        assert!(
            !assembled
                .read_write_paths()
                .iter()
                .any(|p| p == Path::new("/dev")),
            "assembled jail must not RW-allow /dev via allow_path_and_parent"
        );
    }
}
