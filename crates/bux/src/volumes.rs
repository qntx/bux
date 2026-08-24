//! Named volumes, bind mounts, and host-path jail allowlist validation.
//!
//! **v1:** host directories exposed via virtio-fs. Named volumes live under
//! `{data_dir}/volumes/{name}/`. Jail paths are generated only from resolved
//! mounts (plus root disk / socks / system trees in the jailer).

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::error::Error;
use crate::state::{StateDb, VirtioFs};

/// Source of a volume mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VolumeSource {
    /// Bind-mount an existing host directory.
    Bind {
        /// Absolute host directory path.
        host_path: PathBuf,
    },
    /// Named volume under the runtime `volumes/` directory.
    Named {
        /// Unique volume name (filesystem-safe).
        name: String,
    },
}

/// Product volume mount request (create-time only; v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VolumeMount {
    /// Where data lives on the host (bind or named).
    pub source: VolumeSource,
    /// Intended guest mount point (recorded for inspect / future auto-mount).
    pub guest_path: String,
    /// Prefer read-only exposure (recorded; engine virtiofs is still RW in v1).
    #[serde(default)]
    pub read_only: bool,
    /// Permit otherwise default-denied sensitive host prefixes.
    #[serde(default)]
    pub allow_sensitive: bool,
}

impl VolumeMount {
    /// Bind a host directory into the guest at `guest_path`.
    #[must_use]
    pub fn bind(host_path: impl Into<PathBuf>, guest_path: impl Into<String>) -> Self {
        Self {
            source: VolumeSource::Bind {
                host_path: host_path.into(),
            },
            guest_path: guest_path.into(),
            read_only: false,
            allow_sensitive: false,
        }
    }

    /// Attach a named volume (created under `data_dir/volumes/` if missing).
    #[must_use]
    pub fn named(name: impl Into<String>, guest_path: impl Into<String>) -> Self {
        Self {
            source: VolumeSource::Named { name: name.into() },
            guest_path: guest_path.into(),
            read_only: false,
            allow_sensitive: false,
        }
    }

    /// Mark the mount read-only (metadata; virtiofs RW until engine supports RO).
    #[must_use]
    pub const fn read_only(mut self, yes: bool) -> Self {
        self.read_only = yes;
        self
    }

    /// Allow sensitive host prefixes for this mount.
    #[must_use]
    pub const fn allow_sensitive(mut self, yes: bool) -> Self {
        self.allow_sensitive = yes;
        self
    }
}

/// Resolved mount ready for virtio-fs + jail allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResolvedVolume {
    /// virtio-fs tag presented to the guest.
    pub tag: String,
    /// Absolute host directory.
    pub host_path: PathBuf,
    /// Guest path (product metadata).
    pub guest_path: String,
    /// Read-only preference.
    pub read_only: bool,
    /// Named volume id when source was named; `None` for binds.
    pub volume_id: Option<String>,
    /// Named volume name when source was named.
    pub volume_name: Option<String>,
}

impl ResolvedVolume {
    /// Convert to engine [`VirtioFs`].
    #[must_use]
    pub(crate) fn to_virtiofs(&self) -> VirtioFs {
        VirtioFs {
            tag: self.tag.clone(),
            path: self.host_path.to_string_lossy().into_owned(),
            guest_path: self.guest_path.clone(),
            read_only: self.read_only,
        }
    }
}

/// Metadata for a named volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VolumeInfo {
    /// Stable id (same as name for v1).
    pub id: String,
    /// Unique name.
    pub name: String,
    /// Absolute host path (`{data_dir}/volumes/{name}`).
    pub path: PathBuf,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Owns named-volume directories and validates mount paths for the jail.
#[derive(Debug, Clone)]
pub struct VolumeManager {
    /// Absolute `{data_dir}/volumes` directory.
    root: PathBuf,
    /// Shared product state database (volume + attachment rows).
    db: Arc<StateDb>,
}

impl VolumeManager {
    /// Open (create) the volumes directory under `data_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub(crate) fn open(data_dir: impl AsRef<Path>, db: Arc<StateDb>) -> Result<Self> {
        let root = data_dir.as_ref().join("volumes");
        fs::create_dir_all(&root)?;
        Ok(Self { root, db })
    }

    /// Root directory for named volumes.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create a named volume (idempotent if name already exists).
    ///
    /// # Errors
    ///
    /// Returns an error if the name is invalid or I/O fails.
    pub fn create(&self, name: &str) -> Result<VolumeInfo> {
        validate_volume_name(name)?;
        if let Some(existing) = self.db.get_volume_by_name(name)? {
            return Ok(existing);
        }
        let path = self.root.join(name);
        fs::create_dir_all(&path)?;
        let info = VolumeInfo {
            id: name.to_owned(),
            name: name.to_owned(),
            path: path.canonicalize().unwrap_or(path),
            created_at: SystemTime::now(),
        };
        self.db.insert_volume(&info)?;
        Ok(info)
    }

    /// List all named volumes.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn list(&self) -> Result<Vec<VolumeInfo>> {
        self.db.list_volumes()
    }

    /// Look up a named volume.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if missing.
    pub fn get(&self, name: &str) -> Result<VolumeInfo> {
        self.db
            .get_volume_by_name(name)?
            .ok_or_else(|| Error::NotFound(format!("volume '{name}' not found")))
    }

    /// Remove a named volume (fails if still attached to a VM).
    ///
    /// # Errors
    ///
    /// Returns an error if the volume is in use, missing, or I/O fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        let info = self.get(name)?;
        let n = self.db.count_volume_attachments(&info.id)?;
        if n > 0 {
            return Err(Error::Busy(format!(
                "volume '{name}' is attached to {n} VM(s); remove the VM or detach first"
            )));
        }
        self.db.delete_volume(&info.id)?;
        if info.path.exists() {
            fs::remove_dir_all(&info.path)?;
        }
        Ok(())
    }

    /// Validate and resolve product mounts into virtio-fs + jail paths.
    ///
    /// # Errors
    ///
    /// Returns an error on path escape, sensitive-prefix denial, missing bind
    /// dir, or invalid guest path.
    pub fn resolve_mounts(&self, mounts: &[VolumeMount]) -> Result<Vec<ResolvedVolume>> {
        let mut out = Vec::with_capacity(mounts.len());
        for (idx, m) in mounts.iter().enumerate() {
            out.push(self.resolve_one(idx, m)?);
        }
        Ok(out)
    }

    /// Record VM↔volume attachments after a successful spawn.
    ///
    /// # Errors
    ///
    /// Returns an error if the database insert fails.
    pub fn link_vm(&self, vm_id: &str, resolved: &[ResolvedVolume]) -> Result<()> {
        for r in resolved {
            if let Some(ref vol_id) = r.volume_id {
                self.db.insert_vm_volume(vm_id, vol_id, &r.guest_path)?;
            }
        }
        Ok(())
    }

    /// Drop all volume attachments for a VM (on remove).
    ///
    /// # Errors
    ///
    /// Returns an error if the database delete fails.
    pub fn unlink_vm(&self, vm_id: &str) -> Result<()> {
        self.db.delete_vm_volumes(vm_id)
    }

    /// Resolve a single mount request into a host path + virtio-fs tag.
    fn resolve_one(&self, idx: usize, m: &VolumeMount) -> Result<ResolvedVolume> {
        validate_guest_path(&m.guest_path)?;

        let (host_path, volume_id, volume_name, tag) = match &m.source {
            VolumeSource::Bind { host_path } => {
                let path = validate_bind_path(host_path, m.allow_sensitive)?;
                let tag = format!("vol{idx}");
                (path, None, None, tag)
            }
            VolumeSource::Named { name } => {
                let info = self.create(name)?;
                let tag = format!("vol_{}", sanitize_tag(name));
                let path = validate_resolved_path(&info.path, m.allow_sensitive)?;
                (path, Some(info.id), Some(info.name), tag)
            }
        };

        Ok(ResolvedVolume {
            tag,
            host_path,
            guest_path: m.guest_path.clone(),
            read_only: m.read_only,
            volume_id,
            volume_name,
        })
    }
}

/// Validate a named volume identifier.
///
/// # Errors
///
/// Returns [`Error::InvalidConfig`] if the name is empty or contains path separators.
pub fn validate_volume_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(Error::InvalidConfig(
            "volume name must be 1..=128 characters".into(),
        ));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(Error::InvalidConfig(format!(
            "invalid volume name {name:?}: path separators and '..' are not allowed"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::InvalidConfig(format!(
            "invalid volume name {name:?}: use [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Validate guest path (absolute, no `..`).
fn validate_guest_path(guest: &str) -> Result<()> {
    if guest.is_empty() {
        return Err(Error::InvalidConfig("guest_path must not be empty".into()));
    }
    if !guest.starts_with('/') {
        return Err(Error::InvalidConfig(format!(
            "guest_path must be absolute: {guest:?}"
        )));
    }
    let p = Path::new(guest);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::InvalidConfig(format!(
            "guest_path must not contain '..': {guest:?}"
        )));
    }
    Ok(())
}

/// Validate a bind-mount host path: exists, is dir, no escape, not sensitive.
fn validate_bind_path(path: &Path, allow_sensitive: bool) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidConfig("host volume path is empty".into()));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::InvalidConfig(format!(
            "host volume path must not contain '..': {}",
            path.display()
        )));
    }
    if !path.is_absolute() {
        return Err(Error::InvalidConfig(format!(
            "host volume path must be absolute: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(Error::InvalidConfig(format!(
            "host volume path is not a directory: {}",
            path.display()
        )));
    }
    let canon = path.canonicalize().map_err(|e| {
        Error::InvalidConfig(format!(
            "cannot canonicalize host volume {}: {e}",
            path.display()
        ))
    })?;
    validate_resolved_path(&canon, allow_sensitive)
}

/// Check a canonical (or absolute) path against sensitive denylist.
fn validate_resolved_path(path: &Path, allow_sensitive: bool) -> Result<PathBuf> {
    if path == Path::new("/") {
        return Err(Error::InvalidConfig(
            "refusing to expose host root filesystem as a volume".into(),
        ));
    }
    if !allow_sensitive {
        for denied in sensitive_prefixes() {
            if path_is_or_under(path, &denied) {
                return Err(Error::InvalidConfig(format!(
                    "host path {} is under default-denied prefix {} \
                     (set allow_sensitive on the mount to override)",
                    path.display(),
                    denied.display()
                )));
            }
        }
    }
    Ok(path.to_path_buf())
}

/// Whether `path` equals or is nested under `prefix`.
fn path_is_or_under(path: &Path, prefix: &Path) -> bool {
    if path == prefix {
        return true;
    }
    path.starts_with(prefix)
}

/// Default-denied host prefixes (credentials / secrets).
fn sensitive_prefixes() -> Vec<PathBuf> {
    let mut out = vec![
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/gshadow"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/ssh"),
        PathBuf::from("/root/.ssh"),
        PathBuf::from("/root/.gnupg"),
        PathBuf::from("/root/.aws"),
    ];
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".ssh"));
        out.push(home.join(".gnupg"));
        out.push(home.join(".aws"));
        out.push(home.join(".config/gcloud"));
        out.push(home.join(".azure"));
        out.push(home.join(".kube"));
        out.push(home.join(".docker/config.json"));
    }
    out
}

/// Sanitize a volume name into a virtio-fs tag (ASCII alnum/`-`/`_`, max 32).
fn sanitize_tag(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect()
}

/// Parse Docker-style `hostPath:guestPath[:ro]` into a bind [`VolumeMount`].
///
/// # Errors
///
/// Returns an error if the spec is malformed.
pub fn parse_bind_spec(spec: &str) -> Result<VolumeMount> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.as_slice() {
        [host, guest] => Ok(VolumeMount::bind(*host, *guest)),
        [host, guest, opts] => {
            let ro = opts.split(',').any(|o| o.eq_ignore_ascii_case("ro"));
            Ok(VolumeMount::bind(*host, *guest).read_only(ro))
        }
        _ => Err(Error::InvalidConfig(format!(
            "invalid volume spec {spec:?}; use hostPath:guestPath[:ro]"
        ))),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reject_parent_dir_in_guest() {
        assert!(validate_guest_path("/app/../etc").is_err());
        assert!(validate_guest_path("relative").is_err());
        assert!(validate_guest_path("/data").is_ok());
    }

    #[test]
    fn reject_volume_name_with_slash() {
        assert!(validate_volume_name("a/b").is_err());
        assert!(validate_volume_name("..").is_err());
        assert!(validate_volume_name("good_vol-1").is_ok());
    }

    #[test]
    fn deny_ssh_prefix() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let ssh = home.join(".ssh");
        if ssh.is_dir() {
            let err = validate_bind_path(&ssh, false).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("denied") || msg.contains("default-denied"));
            assert!(validate_bind_path(&ssh, true).is_ok());
        }
    }

    #[test]
    fn parse_bind_spec_ro() {
        let m = parse_bind_spec("/tmp/data:/data:ro").unwrap();
        assert!(m.read_only);
        assert_eq!(m.guest_path, "/data");
        let VolumeSource::Bind { host_path } = m.source else {
            unreachable!("expected bind source");
        };
        assert_eq!(host_path, PathBuf::from("/tmp/data"));
    }

    #[test]
    fn named_volume_roundtrip() {
        let dir = tempdir().unwrap();
        let db = Arc::new(StateDb::open(dir.path().join("bux.db")).unwrap());
        let vm = VolumeManager::open(dir.path(), Arc::clone(&db)).unwrap();
        let info = vm.create("cache").unwrap();
        assert!(info.path.is_dir());
        assert_eq!(vm.list().unwrap().len(), 1);
        let mounts = vec![VolumeMount::named("cache", "/var/cache")];
        let resolved = vm.resolve_mounts(&mounts).unwrap();
        let first = resolved.first().expect("one resolved mount");
        assert_eq!(first.guest_path, "/var/cache");
        let root_canon = vm
            .root()
            .canonicalize()
            .unwrap_or_else(|_| vm.root().to_path_buf());
        assert!(first.host_path.starts_with(&root_canon) || first.host_path.starts_with(vm.root()));
        let vm_state = crate::state::VmState {
            id: "vm1".into(),
            name: None,
            pid: 1,
            image: None,
            socket: dir.path().join("vm1.sock"),
            status: crate::state::Status::Running,
            config: crate::state::VmConfig::default(),
            created_at: SystemTime::now(),
        };
        db.insert(&vm_state).unwrap();
        vm.link_vm("vm1", &resolved).unwrap();
        assert!(vm.remove("cache").is_err());
        vm.unlink_vm("vm1").unwrap();
        vm.remove("cache").unwrap();
        assert!(vm.list().unwrap().is_empty());
    }

    #[test]
    fn bind_resolve_tmp() {
        let dir = tempdir().unwrap();
        let host = dir.path().join("bind");
        fs::create_dir_all(&host).unwrap();
        let db = Arc::new(StateDb::open(dir.path().join("bux.db")).unwrap());
        let vm = VolumeManager::open(dir.path(), db).unwrap();
        let mounts = vec![VolumeMount::bind(&host, "/mnt/data")];
        let resolved = vm.resolve_mounts(&mounts).unwrap();
        let first = resolved.first().expect("one resolved mount");
        assert_eq!(first.tag, "vol0");
        assert!(first.volume_id.is_none());
    }
}
