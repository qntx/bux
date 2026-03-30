//! macOS sandbox using seatbelt (`sandbox-exec`).
//!
//! Generates a deny-default SBPL (Sandbox Profile Language) profile that
//! allows only the minimal filesystem and process access needed by bux-shim.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

use super::{JailConfig, Sandbox};

/// Path to the macOS sandbox-exec binary (pre-installed on all macOS versions).
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// macOS seatbelt sandbox via `sandbox-exec`.
///
/// Generates a deny-default SBPL profile allowing only the minimal
/// filesystem and process access needed by bux-shim.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeatbeltSandbox;

impl Sandbox for SeatbeltSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command> {
        if !Path::new(SANDBOX_EXEC).is_file() {
            return None;
        }

        let profile = generate_profile(shim, config_path, jail);

        let mut cmd = Command::new(SANDBOX_EXEC);
        cmd.args(["-p", &profile, "--"]);
        cmd.arg(shim);
        cmd.arg(config_path);

        Some(cmd)
    }
}

/// Generate a deny-default SBPL profile string.
fn generate_profile(shim: &Path, config_path: &Path, config: &JailConfig) -> String {
    let mut p = String::with_capacity(1024);

    // Deny everything by default.
    p.push_str("(version 1)\n(deny default)\n\n");

    // Allow basic process execution.
    p.push_str("(allow process-exec process-fork)\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p.push_str("(allow process-info* (target same-sandbox))\n");
    p.push_str("(allow sysctl-read)\n\n");

    // Allow reading system libraries and frameworks.
    p.push_str("(allow file-read*\n");
    p.push_str("  (literal \"/\")\n");
    p.push_str("  (literal \"/var\")\n");
    p.push_str("  (literal \"/tmp\")\n");
    p.push_str("  (subpath \"/usr/lib\")\n");
    p.push_str("  (subpath \"/System\")\n");
    p.push_str("  (subpath \"/Library/Frameworks\")\n");
    p.push_str("  (subpath \"/private/var/db/dyld\")\n");
    p.push_str("  (literal \"/dev/null\")\n");
    p.push_str("  (literal \"/dev/urandom\")\n");
    p.push_str("  (literal \"/dev/random\")\n");
    p.push_str(")\n\n");

    p.push_str("(allow file-write*\n");
    p.push_str("  (subpath \"/private/tmp\")\n");
    p.push_str("  (subpath \"/private/var/tmp\")\n");
    p.push_str("  (subpath \"/private/var/folders\")\n");
    p.push_str(")\n\n");

    // Allow reading the shim binary.
    if let Some(shim_dir) = shim.parent() {
        allow_read(&mut p, &shim_dir.to_string_lossy());
    } else {
        allow_read(&mut p, &shim.to_string_lossy());
    }

    // Allow reading the config file.
    allow_read(&mut p, &config_path.to_string_lossy());

    // Allow read+write to the sockets directory.
    allow_readwrite(&mut p, &config.socks_dir.to_string_lossy());

    // Allow read+write to rootfs.
    if let Some(rootfs) = &config.rootfs {
        allow_readwrite(&mut p, &rootfs.to_string_lossy());
    }

    // Allow read+write to root disk.
    if let Some(disk) = &config.root_disk {
        allow_readwrite(&mut p, &disk.to_string_lossy());
        for backing_path in crate::disk::readonly_disk_paths(disk) {
            allow_read(&mut p, &backing_path.to_string_lossy());
        }
    }

    // Allow read+write to virtiofs paths.
    for path in &config.virtiofs_paths {
        allow_readwrite(&mut p, &path.to_string_lossy());
    }

    // Allow Hypervisor.framework (macOS KVM equivalent).
    p.push_str("(allow iokit-open\n");
    p.push_str("  (iokit-registry-entry-class \"RootDomainUserClient\")\n");
    p.push_str(")\n");

    // Allow mach lookups for Hypervisor.framework.
    p.push_str("(allow mach-lookup\n");
    p.push_str("  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n");
    p.push_str("  (global-name \"com.apple.PowerManagement.control\")\n");
    p.push_str("  (global-name \"com.apple.logd\")\n");
    p.push_str("  (global-name \"com.apple.system.notification_center\")\n");
    p.push_str(")\n");

    p
}

/// Emit an SBPL rule allowing read access to a path subtree.
fn allow_read(profile: &mut String, path: &str) {
    allow_path(profile, path, false);
}

/// Emit an SBPL rule allowing read+write access to a path subtree.
fn allow_readwrite(profile: &mut String, path: &str) {
    allow_path(profile, path, true);
}

#[allow(clippy::missing_docs_in_private_items)]
fn allow_path(profile: &mut String, path: &str, write: bool) {
    emit_path_rule(profile, path, write);
    if let Ok(canonical_path) = std::fs::canonicalize(path) {
        let canonical = canonical_path.to_string_lossy();
        if canonical != path {
            emit_path_rule(profile, &canonical, write);
        }
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn emit_path_rule(profile: &mut String, path: &str, write: bool) {
    if Path::new(path).is_dir() {
        if write {
            let _ = writeln!(
                profile,
                "(allow file-read* file-write* (literal \"{path}\"))"
            );
            let _ = writeln!(
                profile,
                "(allow file-read* file-write* (subpath \"{path}\"))"
            );
        } else {
            let _ = writeln!(profile, "(allow file-read* (literal \"{path}\"))");
            let _ = writeln!(profile, "(allow file-read* (subpath \"{path}\"))");
        }
    } else if write {
        let _ = writeln!(
            profile,
            "(allow file-read* file-write* (literal \"{path}\"))"
        );
    } else {
        let _ = writeln!(profile, "(allow file-read* (literal \"{path}\"))");
    }
}
