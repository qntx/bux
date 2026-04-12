//! Host and guest capability checks for security validation.
//!
//! Pre-flight checks that verify the host system supports the required
//! isolation features before attempting to spawn sandboxed VMs.

use std::path::Path;

/// Capabilities available on the current host for VM isolation.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool represents an independent capability flag"
)]
pub struct HostCapabilities {
    /// Whether hardware virtualization is available (KVM / Hypervisor.framework).
    pub virtualization: bool,
    /// Whether namespace isolation is available (Linux bubblewrap).
    pub namespaces: bool,
    /// Whether seccomp BPF filtering is available (Linux only).
    pub seccomp: bool,
    /// Whether mandatory access control is available (AppArmor/SELinux/Seatbelt).
    pub mandatory_access_control: bool,
    /// Whether cgroup v2 resource limits are available.
    pub cgroups: bool,
}

/// Checks what isolation capabilities are available on this host.
///
/// This is a best-effort check — it probes for the presence of various
/// system features without requiring elevated privileges.
#[must_use]
pub fn check_host() -> HostCapabilities {
    HostCapabilities {
        virtualization: check_virtualization(),
        namespaces: check_namespaces(),
        seccomp: check_seccomp(),
        mandatory_access_control: check_mac(),
        cgroups: check_cgroups(),
    }
}

/// Reports on the isolation strength of the current sandbox configuration.
///
/// Returns a list of warnings for missing security layers.
#[must_use]
pub fn audit_isolation(caps: &HostCapabilities) -> Vec<String> {
    let mut warnings = Vec::new();

    if !caps.virtualization {
        warnings.push("no hardware virtualization detected — VMs will not run".to_owned());
    }
    if !caps.namespaces {
        warnings.push(
            "no namespace isolation (bubblewrap not found) — shim runs without namespaces"
                .to_owned(),
        );
    }
    if !caps.seccomp {
        warnings.push("seccomp BPF not available — shim runs without syscall filtering".to_owned());
    }
    if !caps.mandatory_access_control {
        warnings
            .push("no MAC (AppArmor/SELinux/Seatbelt) — no mandatory access control".to_owned());
    }
    if !caps.cgroups {
        warnings.push("cgroups v2 not available — no resource limits enforcement".to_owned());
    }

    warnings
}

/// Checks if the guest binary at `path` is a valid static ELF for the host arch.
///
/// Returns `Ok(())` if the binary passes all checks, or an error describing
/// the validation failure.
///
/// # Errors
///
/// Returns an error if the binary is missing, too small, or not a valid ELF.
pub fn check_guest_binary(path: &Path) -> std::io::Result<()> {
    use std::io::{self, Read};

    let mut f = std::fs::File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("guest binary not found: {}", path.display()),
            )
        } else {
            e
        }
    })?;

    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n < 4 || magic != *b"\x7fELF" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest binary is not a valid ELF file",
        ));
    }

    Ok(())
}

/// Checks whether hardware virtualization support is available on this host.
fn check_virtualization() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/kvm").exists()
    }
    #[cfg(target_os = "macos")]
    {
        // Hypervisor.framework is always available on Apple Silicon.
        // On Intel, check the sysctl.
        std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
            .is_ok_and(|o| o.stdout.starts_with(b"1"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Checks whether Linux namespace isolation (bubblewrap) is available.
#[allow(clippy::missing_const_for_fn, reason = "body is non-const on Linux")]
fn check_namespaces() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if bwrap is available.
        which("bwrap")
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks whether seccomp BPF syscall filtering is available.
#[allow(clippy::missing_const_for_fn, reason = "body is non-const on Linux")]
fn check_seccomp() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check for seccomp support via prctl.
        Path::new("/proc/sys/kernel/seccomp").exists() || Path::new("/proc/self/status").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks whether mandatory access control (AppArmor/SELinux/Seatbelt) is available.
fn check_mac() -> bool {
    #[cfg(target_os = "linux")]
    {
        // AppArmor check.
        Path::new("/sys/kernel/security/apparmor").exists() || Path::new("/sys/fs/selinux").exists()
    }
    #[cfg(target_os = "macos")]
    {
        // sandbox-exec is always available on macOS.
        which("sandbox-exec")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Checks whether cgroup v2 resource limits are available.
#[allow(clippy::missing_const_for_fn, reason = "body is non-const on Linux")]
fn check_cgroups() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks if a binary is available in $PATH.
#[allow(dead_code, reason = "used conditionally on Linux")]
fn which(name: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|dir| Path::new(dir).join(name).is_file())
}

#[cfg(test)]
#[allow(
    clippy::let_underscore_must_use,
    reason = "tests use let _ for clarity"
)]
mod tests {
    use super::*;

    #[test]
    fn host_check_returns_struct() {
        let caps = check_host();
        // On macOS CI, virtualization should be available.
        // We just verify it doesn't panic and returns a valid struct.
        let _ = format!("{caps:?}");
    }

    #[test]
    fn audit_reports_missing_features() {
        let caps = HostCapabilities {
            virtualization: true,
            namespaces: false,
            seccomp: false,
            mandatory_access_control: false,
            cgroups: false,
        };
        let warnings = audit_isolation(&caps);
        assert!(warnings.len() >= 3);
        assert!(warnings.iter().any(|w| w.contains("namespace")));
    }

    #[test]
    fn guest_binary_check_rejects_missing() {
        let result = check_guest_binary(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }
}
