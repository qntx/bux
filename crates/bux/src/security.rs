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

    /// Allow degraded security when a requested layer is unavailable.
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

/// Host isolation and libkrun capabilities for `Runtime::host_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags"
)]
pub struct HostInfo {
    /// KVM (Linux) or Hypervisor.framework (macOS).
    pub virtualization: bool,
    /// bubblewrap available (Linux namespaces).
    pub namespaces: bool,
    /// seccomp BPF present.
    pub seccomp: bool,
    /// AppArmor/SELinux/Seatbelt.
    pub mandatory_access_control: bool,
    /// cgroup v2.
    pub cgroups: bool,
    /// Landlock LSM (Linux 5.13+).
    pub landlock: bool,
    /// Hypervisor max vCPUs. Always `None`: the engine does not load libkrun.
    pub max_vcpus: Option<u32>,
    /// Nested virtualization. Always `None`: the engine does not load libkrun.
    pub nested_virt: Option<bool>,
    /// libkrun build features. Always empty: the engine does not load libkrun.
    pub krun_features: Vec<String>,
    /// Isolation gaps from the jailer host audit.
    pub isolation_warnings: Vec<String>,
}

impl HostInfo {
    /// Probe the current host.
    ///
    /// `max_vcpus`, `nested_virt`, and `krun_features` are empty: the engine
    /// does not load libkrun. `virtualization` still comes from the jailer
    /// host audit (KVM / HVF).
    #[must_use]
    pub fn probe() -> Self {
        #[cfg(unix)]
        {
            let caps = bux_jail::checks::check_host();
            Self {
                virtualization: caps.virtualization,
                namespaces: caps.namespaces,
                seccomp: caps.seccomp,
                mandatory_access_control: caps.mandatory_access_control,
                cgroups: caps.cgroups,
                landlock: caps.landlock,
                max_vcpus: None,
                nested_virt: None,
                krun_features: Vec::new(),
                isolation_warnings: bux_jail::checks::audit_isolation(&caps),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                virtualization: false,
                namespaces: false,
                seccomp: false,
                mandatory_access_control: false,
                cgroups: false,
                landlock: false,
                max_vcpus: None,
                nested_virt: None,
                krun_features: Vec::new(),
                isolation_warnings: Vec::new(),
            }
        }
    }
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

    #[test]
    fn probe_does_not_load_libkrun() {
        let h = HostInfo::probe();
        assert!(
            h.krun_features.is_empty(),
            "engine must not probe libkrun features"
        );
        assert_eq!(h.max_vcpus, None, "engine must not probe libkrun max_vcpus");
        assert_eq!(
            h.nested_virt, None,
            "engine must not probe libkrun nested_virt"
        );
    }
}
