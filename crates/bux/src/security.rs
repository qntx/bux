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
    /// Hypervisor max vCPUs (`None` if libkrun cannot be probed).
    pub max_vcpus: Option<u32>,
    /// Nested virtualization (`None` if the probe fails).
    pub nested_virt: Option<bool>,
    /// libkrun build features that are present (e.g. `net`, `blk`, `gpu`).
    pub krun_features: Vec<String>,
    /// Isolation gaps from the jailer host audit.
    pub isolation_warnings: Vec<String>,
}

impl HostInfo {
    /// Probe the current host.
    #[must_use]
    pub fn probe() -> Self {
        #[cfg(unix)]
        {
            let caps = bux_jail::checks::check_host();
            let (max_vcpus, nested_virt, krun_features) = probe_krun();
            Self {
                virtualization: caps.virtualization,
                namespaces: caps.namespaces,
                seccomp: caps.seccomp,
                mandatory_access_control: caps.mandatory_access_control,
                cgroups: caps.cgroups,
                landlock: caps.landlock,
                max_vcpus,
                nested_virt,
                krun_features,
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

/// libkrun probes (shim is the only crate that links libkrun).
#[cfg(unix)]
fn probe_krun() -> (Option<u32>, Option<bool>, Vec<String>) {
    use bux_shim::host::{self, Feature};

    let max_vcpus = host::max_vcpus().ok();
    let nested_virt = host::check_nested_virt().ok();
    let mut krun_features = Vec::new();
    for (feature, name) in [
        (Feature::Net, "net"),
        (Feature::Blk, "blk"),
        (Feature::Gpu, "gpu"),
        (Feature::Snd, "snd"),
        (Feature::Input, "input"),
        (Feature::Efi, "efi"),
        (Feature::Tee, "tee"),
        (Feature::AmdSev, "amd-sev"),
        (Feature::IntelTdx, "intel-tdx"),
        (Feature::AwsNitro, "aws-nitro"),
        (Feature::VirglResourceMap2, "virgl-resource-map2"),
    ] {
        if host::has_feature(feature).unwrap_or(false) {
            krun_features.push(name.to_owned());
        }
    }
    (max_vcpus, nested_virt, krun_features)
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
}
