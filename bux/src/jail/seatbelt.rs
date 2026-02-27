//! macOS sandbox using seatbelt (`sandbox-exec`).
//!
//! Generates a deny-default SBPL (Sandbox Profile Language) profile that
//! allows only the minimal filesystem and process access needed by bux-shim.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

use super::JailConfig;

/// Path to the macOS sandbox-exec binary (pre-installed on all macOS versions).
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Build a sandbox-exec-wrapped command, or `None` if sandbox-exec is missing.
pub fn wrap(shim: &Path, config_path: &Path, config: &JailConfig) -> Option<Command> {
    if !Path::new(SANDBOX_EXEC).is_file() {
        return None;
    }

    let profile = generate_profile(shim, config_path, config);

    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.args(["-p", &profile, "--"]);
    cmd.arg(shim);
    cmd.arg(config_path);

    Some(cmd)
}

/// Generate a deny-default SBPL profile string.
fn generate_profile(shim: &Path, config_path: &Path, config: &JailConfig) -> String {
    let mut p = String::with_capacity(1024);

    // Deny everything by default.
    p.push_str("(version 1)\n(deny default)\n\n");

    // Allow basic process execution.
    p.push_str("(allow process-exec process-fork)\n");
    p.push_str("(allow signal (target self))\n");
    p.push_str("(allow sysctl-read)\n\n");

    // Allow reading system libraries and frameworks.
    p.push_str("(allow file-read*\n");
    p.push_str("  (subpath \"/usr/lib\")\n");
    p.push_str("  (subpath \"/System\")\n");
    p.push_str("  (subpath \"/Library/Frameworks\")\n");
    p.push_str("  (subpath \"/dev\")\n");
    p.push_str(")\n\n");

    // Allow reading the shim binary.
    allow_read(&mut p, &shim.to_string_lossy());

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
    }

    // Allow read+write to virtiofs paths.
    for path in &config.virtiofs_paths {
        allow_readwrite(&mut p, &path.to_string_lossy());
    }

    // Allow Hypervisor.framework (macOS KVM equivalent).
    p.push_str("(allow hv-all)\n");

    // Allow mach lookups for Hypervisor.framework.
    p.push_str("(allow mach-lookup)\n");

    p
}

/// Emit an SBPL rule allowing read access to a path subtree.
fn allow_read(profile: &mut String, path: &str) {
    let _ = writeln!(profile, "(allow file-read* (subpath \"{path}\"))");
}

/// Emit an SBPL rule allowing read+write access to a path subtree.
fn allow_readwrite(profile: &mut String, path: &str) {
    let _ = writeln!(
        profile,
        "(allow file-read* file-write* (subpath \"{path}\"))"
    );
}
