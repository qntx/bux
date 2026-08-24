//! Product-facing VM creation options ([`VmOptions`] / [`ImageRef`]).
//!
//! Managed Runtime entry points take [`VmOptions`] only.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::secrets::Secret;
use crate::security::SecurityOptions;
use crate::volumes::VolumeMount;

/// Source of the guest root filesystem / base disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ImageRef {
    /// Pull/ensure an OCI image reference (e.g. `python:slim`).
    Oci(String),
    /// Host directory used as virtiofs root (debug / custom rootfs).
    Rootfs(PathBuf),
    /// Existing base disk image path (raw/ext4); Runtime creates a QCOW2 overlay.
    BaseDisk(PathBuf),
}

impl From<&str> for ImageRef {
    fn from(s: &str) -> Self {
        Self::Oci(s.to_owned())
    }
}

impl From<String> for ImageRef {
    fn from(s: String) -> Self {
        Self::Oci(s)
    }
}

impl ImageRef {
    /// Human-readable label for logs / `VmState.image`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Oci(r) => r.clone(),
            Self::Rootfs(p) | Self::BaseDisk(p) => p.display().to_string(),
        }
    }
}

/// Guest networking mode for a managed VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkSpec {
    /// No virtio-net. Guest is offline. Ports and secrets are invalid.
    Disabled,
    /// gvproxy virtio-net. Empty `allow_net` means unrestricted egress.
    Enabled {
        /// Hostname / CIDR allow-list. Empty = full egress.
        #[serde(default)]
        allow_net: Vec<String>,
    },
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self::Enabled {
            allow_net: Vec::new(),
        }
    }
}

impl NetworkSpec {
    /// Whether virtio-net / gvproxy is attached.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    /// Egress allow-list (empty if disabled or unrestricted).
    #[must_use]
    pub fn allow_net(&self) -> &[String] {
        match self {
            Self::Enabled { allow_net } => allow_net,
            Self::Disabled => &[],
        }
    }
}

/// Options for creating a managed VM.
///
/// Construct only via [`VmOptions::from_image`] (image is required).
#[derive(Debug, Clone)]
pub struct VmOptions {
    /// Root image / rootfs / base disk.
    pub image: ImageRef,
    /// Optional unique name.
    pub name: Option<String>,
    /// vCPUs (default 1).
    pub vcpus: u8,
    /// RAM in MiB (default 512).
    pub ram_mib: u32,
    /// Publish specs (`host:guest`, ephemeral forms). Resolved at boot.
    pub ports: Vec<String>,
    /// Host-only secrets for MITM (memory only).
    pub secrets: Vec<Secret>,
    /// Guest network (gvproxy or offline).
    pub network: NetworkSpec,
    /// Volume mounts (bind or named) resolved at create.
    pub volumes: Vec<VolumeMount>,
    /// Optional first command run by the CLI after the agent is ready.
    ///
    /// Not PID 1. Merged from OCI `ENTRYPOINT`+`CMD` when unset.
    pub command: Option<Vec<String>>,
    /// Workload environment (`KEY=VALUE`) — applied to **exec**, not VM boot.
    ///
    /// Stored on the handle for Phase A; not passed as libkrun boot env.
    pub env: Vec<String>,
    /// Workload working directory for Phase A exec defaults.
    pub workdir: Option<String>,
    /// Workload user `uid[:gid]` for Phase A (parsed later).
    pub user: Option<String>,
    /// Auto-remove VM state when stopped.
    pub auto_remove: bool,
    /// Wait for guest agent after create (`Duration::ZERO` = skip).
    pub ready_timeout: Duration,
    /// Detach: do not watch parent process (survives Runtime drop of keepalive).
    pub detach: bool,
    /// Isolation policy (Landlock / jailer). Default: fail-closed Landlock on Linux.
    pub security: SecurityOptions,
    /// Stop after this many idle seconds (`None` = never). Default off.
    pub auto_stop_secs: Option<u64>,
    /// Delete a stopped VM after this many idle seconds (`None` = never). Default off.
    pub auto_delete_secs: Option<u64>,
}

impl VmOptions {
    /// Sole constructor — image is required (K27).
    #[must_use]
    pub fn from_image(image: impl Into<ImageRef>) -> Self {
        Self {
            image: image.into(),
            name: None,
            vcpus: 1,
            ram_mib: 512,
            ports: Vec::new(),
            secrets: Vec::new(),
            network: NetworkSpec::default(),
            volumes: Vec::new(),
            command: None,
            env: Vec::new(),
            workdir: None,
            user: None,
            auto_remove: false,
            ready_timeout: Duration::from_secs(30),
            detach: false,
            security: SecurityOptions::default(),
            auto_stop_secs: None,
            auto_delete_secs: None,
        }
    }

    /// Set VM name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set vCPU count.
    #[must_use]
    pub const fn vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Set RAM in MiB.
    #[must_use]
    pub const fn ram_mib(mut self, mib: u32) -> Self {
        self.ram_mib = mib;
        self
    }

    /// Add a port publish string.
    #[must_use]
    pub fn port(mut self, spec: impl Into<String>) -> Self {
        self.ports.push(spec.into());
        self
    }

    /// Set egress allow-list (implies [`NetworkSpec::Enabled`]).
    #[must_use]
    pub fn allow_net(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.network = NetworkSpec::Enabled {
            allow_net: hosts.into_iter().map(Into::into).collect(),
        };
        self
    }

    /// Set network mode.
    #[must_use]
    pub fn network(mut self, spec: NetworkSpec) -> Self {
        self.network = spec;
        self
    }

    /// Attach secrets for MITM.
    #[must_use]
    pub fn secrets(mut self, secrets: impl IntoIterator<Item = Secret>) -> Self {
        self.secrets = secrets.into_iter().collect();
        self
    }

    /// First command after agent ready (`None` = no auto-exec).
    #[must_use]
    pub fn command(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.command = Some(cmd.into_iter().map(Into::into).collect());
        self
    }

    /// Add a volume mount (bind or named).
    #[must_use]
    pub fn volume(mut self, mount: VolumeMount) -> Self {
        self.volumes.push(mount);
        self
    }

    /// Bind a host directory at `guest_path` (convenience).
    #[must_use]
    pub fn bind_volume(
        mut self,
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<String>,
    ) -> Self {
        self.volumes.push(VolumeMount::bind(host_path, guest_path));
        self
    }

    /// Attach a named volume at `guest_path` (convenience).
    #[must_use]
    pub fn named_volume(mut self, name: impl Into<String>, guest_path: impl Into<String>) -> Self {
        self.volumes.push(VolumeMount::named(name, guest_path));
        self
    }

    /// Auto-remove when stopped.
    #[must_use]
    pub const fn auto_remove(mut self, yes: bool) -> Self {
        self.auto_remove = yes;
        self
    }

    /// Guest agent ready wait.
    #[must_use]
    pub const fn ready_timeout(mut self, d: Duration) -> Self {
        self.ready_timeout = d;
        self
    }

    /// Detached spawn (no parent watchdog).
    #[must_use]
    pub const fn detach(mut self, yes: bool) -> Self {
        self.detach = yes;
        self
    }

    /// Workload environment (`KEY=VALUE`) for Phase A exec defaults.
    #[must_use]
    pub fn env(mut self, vars: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.env = vars.into_iter().map(Into::into).collect();
        self
    }

    /// Workload working directory for Phase A exec defaults.
    #[must_use]
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Workload user for Phase A (`uid[:gid]` or `name[:group]`).
    #[must_use]
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Isolation policy (K22 Landlock fail-closed on Linux by default).
    #[must_use]
    pub const fn security(mut self, opts: SecurityOptions) -> Self {
        self.security = opts;
        self
    }

    /// Auto-stop after idle seconds (default off).
    #[must_use]
    pub const fn auto_stop_secs(mut self, secs: Option<u64>) -> Self {
        self.auto_stop_secs = secs;
        self
    }

    /// Auto-delete stopped VMs after idle seconds (default off).
    #[must_use]
    pub const fn auto_delete_secs(mut self, secs: Option<u64>) -> Self {
        self.auto_delete_secs = secs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::ImageRef;

    #[test]
    fn from_image_defaults() {
        let o = VmOptions::from_image("python:slim");
        assert_eq!(o.image, ImageRef::Oci("python:slim".into()));
        assert_eq!(o.vcpus, 1);
        assert_eq!(o.ram_mib, 512);
        assert!(o.network.is_enabled());
        assert!(o.ports.is_empty());
        assert!(o.env.is_empty());
        assert!(o.workdir.is_none());
        assert!(o.user.is_none());
        assert!(!o.auto_remove);
        assert!(!o.detach);
    }

    #[test]
    fn fluent_chain() {
        let o = VmOptions::from_image("alpine")
            .name("n1")
            .vcpus(2)
            .ram_mib(1024)
            .port("8080:80")
            .allow_net(["example.com"])
            .env(["A=1", "B=2"])
            .workdir("/work")
            .user("1000:1000")
            .auto_remove(true)
            .detach(true);
        assert_eq!(o.name.as_deref(), Some("n1"));
        assert_eq!(o.vcpus, 2);
        assert_eq!(o.ram_mib, 1024);
        assert_eq!(o.ports, vec!["8080:80"]);
        assert_eq!(o.network.allow_net(), &["example.com".to_owned()]);
        assert_eq!(o.env, vec!["A=1", "B=2"]);
        assert_eq!(o.workdir.as_deref(), Some("/work"));
        assert_eq!(o.user.as_deref(), Some("1000:1000"));
        assert!(o.auto_remove);
        assert!(o.detach);
    }

    #[test]
    fn image_ref_from_str() {
        assert_eq!(ImageRef::from("x"), ImageRef::Oci("x".into()));
        assert_eq!(ImageRef::Rootfs("/tmp/r".into()).label(), "/tmp/r");
    }
}
