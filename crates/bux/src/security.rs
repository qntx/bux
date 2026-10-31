//! Product security options and host/VM security status (K22).

use serde::{Deserialize, Serialize};

/// Requested isolation policy for a managed VM.
///
/// Defaults: jailer on; Landlock **on** on Linux (fail-closed unless
/// [`Self::allow_degraded`]); Landlock off on other platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecurityOptions {
    /// Use the platform jailer (bwrap / seatbelt). Default `true`.
    pub jailer: bool,
    /// Request Landlock LSM on Linux. Default `true` on Linux, `false` elsewhere.
    pub landlock: bool,
    /// If true, missing Landlock (when requested) degrades instead of failing create/start.
    ///
    /// Only Landlock degrades. A jailer that cannot run always fails: dropping
    /// namespaces takes an explicit `jailer: false`.
    pub allow_degraded: bool,
}

impl Default for SecurityOptions {
    fn default() -> Self {
        Self {
            jailer: true,
            landlock: cfg!(target_os = "linux"),
            allow_degraded: false,
        }
    }
}

impl SecurityOptions {
    /// Product defaults (jailer on; Landlock on Linux fail-closed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable Landlock request.
    #[must_use]
    pub const fn landlock(mut self, enable: bool) -> Self {
        self.landlock = enable;
        self
    }

    /// Continue without Landlock when the kernel cannot enforce it.
    ///
    /// Only Landlock degrades. A jailer that cannot run always fails: dropping
    /// namespaces takes an explicit `jailer(false)`.
    #[must_use]
    pub const fn allow_degraded(mut self, yes: bool) -> Self {
        self.allow_degraded = yes;
        self
    }

    /// Enable/disable platform jailer (bwrap/seatbelt).
    #[must_use]
    pub const fn jailer(mut self, enable: bool) -> Self {
        self.jailer = enable;
        self
    }
}

/// Status of one isolation layer after spawn (persisted for inspect).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LayerStatus {
    /// Requested and active.
    Enforced,
    /// Requested, unavailable, continued under `allow_degraded`.
    Degraded,
    /// Not requested.
    #[default]
    Disabled,
    /// Does not apply on this platform.
    NotApplicable,
}

/// Actual security posture for a VM (from last successful spawn).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct SecurityStatus {
    /// Platform sandbox: `bwrap`, `seatbelt`, or `noop`.
    pub sandbox: String,
    /// Landlock layer status.
    pub landlock: LayerStatus,
    /// MAC / seatbelt layer status.
    pub mac: LayerStatus,
}

impl SecurityStatus {
    /// Build from a jail security report.
    #[cfg(unix)]
    #[must_use]
    pub fn from_report(r: &bux_jail::SecurityReport) -> Self {
        Self {
            sandbox: r.sandbox.as_str().to_owned(),
            landlock: map_layer(r.landlock),
            mac: map_layer(r.mac),
        }
    }
}

/// Map jail layer status into product enum.
#[cfg(unix)]
const fn map_layer(s: bux_jail::LayerStatus) -> LayerStatus {
    match s {
        bux_jail::LayerStatus::Enforced => LayerStatus::Enforced,
        bux_jail::LayerStatus::Degraded => LayerStatus::Degraded,
        bux_jail::LayerStatus::Disabled => LayerStatus::Disabled,
        bux_jail::LayerStatus::NotApplicable | _ => LayerStatus::NotApplicable,
    }
}

/// Host isolation for `Runtime::host_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags"
)]
pub struct HostInfo {
    /// KVM (Linux) or Hypervisor.framework (macOS).
    pub virtualization: bool,
    /// A bubblewrap that works on this host (Linux namespaces).
    pub namespaces: bool,
    /// The `bwrap` the Linux jailer runs. `None` if none works.
    pub bwrap: Option<std::path::PathBuf>,
    /// seccomp BPF present.
    pub seccomp: bool,
    /// AppArmor/SELinux/Seatbelt.
    pub mandatory_access_control: bool,
    /// cgroup v2.
    pub cgroups: bool,
    /// Landlock LSM (Linux 5.13+).
    pub landlock: bool,
    /// Isolation gaps from the jailer host audit.
    pub isolation_warnings: Vec<String>,
}

impl HostInfo {
    /// Probe the current host.
    ///
    /// The engine does not load libkrun. `virtualization` comes from the
    /// jailer host audit (KVM / HVF).
    #[must_use]
    pub fn probe() -> Self {
        #[cfg(unix)]
        {
            let mut caps = bux_jail::checks::check_host();
            let bwrap = host_bwrap();
            caps.namespaces = matches!(bwrap, Ok(Some(_)));
            let mut isolation_warnings = bux_jail::checks::audit_isolation(&caps);
            isolation_warnings.extend(bwrap.as_ref().err().cloned());
            Self {
                virtualization: caps.virtualization,
                namespaces: caps.namespaces,
                bwrap: bwrap.ok().flatten(),
                seccomp: caps.seccomp,
                mandatory_access_control: caps.mandatory_access_control,
                cgroups: caps.cgroups,
                landlock: caps.landlock,
                isolation_warnings,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                virtualization: false,
                namespaces: false,
                bwrap: None,
                seccomp: false,
                mandatory_access_control: false,
                cgroups: false,
                landlock: false,
                isolation_warnings: Vec::new(),
            }
        }
    }
}

/// The `bwrap` the jailer would run, or why none works.
#[cfg(target_os = "linux")]
fn host_bwrap() -> Result<Option<std::path::PathBuf>, String> {
    crate::bwrap::select().map(Some)
}

/// Only Linux has a `bwrap`.
#[cfg(all(unix, not(target_os = "linux")))]
#[allow(clippy::unnecessary_wraps, reason = "same signature as on Linux")]
const fn host_bwrap() -> Result<Option<std::path::PathBuf>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_platform() {
        let s = SecurityOptions::default();
        assert!(s.jailer);
        assert!(!s.allow_degraded);
        assert_eq!(s.landlock, cfg!(target_os = "linux"));
    }

    #[test]
    fn fluent() {
        let s = SecurityOptions::new()
            .landlock(false)
            .allow_degraded(true)
            .jailer(false);
        assert!(!s.landlock);
        assert!(s.allow_degraded);
        assert!(!s.jailer);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive probe"
    )]
    fn probe_namespaces_uses_engine_bwrap_lookup() {
        let mut env = crate::guest::sidecar_env::lock();
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());
        let planted = crate::guest::sidecar_env::Planted::sibling("bwrap", b"");
        crate::bwrap::fake_bwrap(planted.path(), "exit 0");
        assert!(
            !bux_jail::checks::check_host().namespaces,
            "PATH-only which(bwrap) must miss when PATH is empty"
        );
        let h = HostInfo::probe();
        assert!(
            h.namespaces,
            "engine lookup must see sibling bwrap: {}",
            planted.path().display()
        );
        assert_eq!(
            h.bwrap,
            Some(std::fs::canonicalize(planted.path()).unwrap())
        );
        assert!(
            !h.isolation_warnings
                .iter()
                .any(|w| w.contains("no usable bubblewrap")),
            "audit must use overwritten namespaces, got {:?}",
            h.isolation_warnings
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "env lock must outlive probe"
    )]
    fn probe_reports_a_bwrap_that_does_not_work() {
        let mut env = crate::guest::sidecar_env::lock();
        let empty = tempfile::tempdir().unwrap();
        env.set("PATH", empty.path());
        let planted = crate::guest::sidecar_env::Planted::sibling("bwrap", b"");
        crate::bwrap::fake_bwrap(planted.path(), "echo denied-by-policy >&2; exit 1");

        let h = HostInfo::probe();

        assert!(!h.namespaces);
        assert_eq!(h.bwrap, None);
        assert!(
            h.isolation_warnings
                .iter()
                .any(|w| w.contains("no usable bubblewrap")),
            "{:?}",
            h.isolation_warnings
        );
        assert!(
            h.isolation_warnings
                .iter()
                .any(|w| w.contains("denied-by-policy") && w.contains("--no-jailer")),
            "{:?}",
            h.isolation_warnings
        );
    }
}
