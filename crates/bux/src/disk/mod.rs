//! Disk image management with QCOW2 copy-on-write overlays.
//!
//! # Architecture
//!
//! - [`DiskFormat`] — Type-safe disk format enum (Raw / Qcow2) with serde support.
//! - [`DiskManager`] — Manages shared ext4 bases and per-VM QCOW2 overlays.
//! - QCOW2 operations themselves live in the `bux_qcow2` crate.
//!   Product code does not expose resize; callers that need it use `bux_qcow2::resize`.
//!
//! # Storage layout
//!
//! ```text
//! {data_dir}/disks/
//!   bases/{digest}.raw     — shared read-only ext4 base images
//!   vms/{vm_id}.qcow2     — per-VM QCOW2 COW overlays (~256 KiB each)
//! ```

use std::fmt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{fs, io};

use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::Result;
#[cfg(unix)]
use crate::guest::ManagedGuestBinary;
#[cfg(unix)]
use crate::util::push_unique_path;

/// Disk image format.
///
/// Used across `VmConfig` and the shim disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub(crate) enum DiskFormat {
    /// Raw disk image (default).
    #[default]
    Raw,
    /// QCOW2 copy-on-write image.
    Qcow2,
}

impl fmt::Display for DiskFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        })
    }
}

#[cfg(unix)]
impl From<DiskFormat> for bux_qcow2::BackingFormat {
    fn from(value: DiskFormat) -> Self {
        match value {
            DiskFormat::Raw => Self::Raw,
            DiskFormat::Qcow2 => Self::Qcow2,
        }
    }
}

/// Manages ext4 base images and per-VM QCOW2 overlay disks.
///
/// Base images are created once per OCI image digest and shared across VMs.
/// Each VM gets a tiny QCOW2 overlay (~256 KiB) that provides copy-on-write
/// semantics via a backing file reference to the shared base.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct DiskManager {
    /// Directory for shared base images.
    bases_dir: PathBuf,
    /// Directory for per-VM QCOW2 overlays.
    vms_dir: PathBuf,
}

#[cfg(unix)]
impl DiskManager {
    /// Opens (or creates) the disk storage directories under `data_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation fails.
    pub(crate) fn open(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let base = data_dir.as_ref().join("disks");
        let bases_dir = base.join("bases");
        let vms_dir = base.join("vms");
        fs::create_dir_all(&bases_dir)?;
        fs::create_dir_all(&vms_dir)?;
        Ok(Self { bases_dir, vms_dir })
    }

    /// Returns the directory where base disk images are stored.
    #[must_use]
    pub(crate) fn bases_dir(&self) -> &Path {
        &self.bases_dir
    }

    /// Returns the path for a base image (may or may not exist).
    #[must_use]
    pub(crate) fn base_path(&self, digest: &str) -> PathBuf {
        self.bases_dir.join(format!("{digest}.raw"))
    }

    /// Creates a base ext4 image from an OCI rootfs directory.
    ///
    /// Returns the path to the created image. If the image already exists
    /// for this digest, returns immediately (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if ext4 image creation or rename fails.
    pub(crate) fn create_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
        let path = self.base_path(digest);
        if path.exists() {
            return Ok(path);
        }

        let size = bux_e2fs::estimate_image_size(rootfs)?;

        // Write to a temporary file first, then rename for atomicity.
        let tmp = self.bases_dir.join(format!("{digest}.raw.tmp"));
        bux_e2fs::create_from_dir(rootfs, &tmp, size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Creates a managed base ext4 image with guest binary injected.
    ///
    /// # Errors
    ///
    /// Returns an error if image creation, injection, or rename fails.
    pub(crate) fn create_managed_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
        let guest = ManagedGuestBinary::resolve()?;
        let versioned = guest.versioned_cache_key(digest);
        let path = self.base_path(&versioned);
        if path.exists() {
            return Ok(path);
        }

        let size = bux_e2fs::estimate_image_size(rootfs)?
            .saturating_add(guest.image_size_overhead_bytes());
        let tmp = self.bases_dir.join(format!("{versioned}.raw.tmp"));

        let staged = (|| -> Result<()> {
            bux_e2fs::create_from_dir(rootfs, &tmp, size)?;
            guest.inject_into_disk(&tmp)?;
            Ok(())
        })();

        if let Err(err) = staged {
            drop(fs::remove_file(&tmp));
            return Err(err);
        }

        if let Err(err) = fs::rename(&tmp, &path) {
            drop(fs::remove_file(&tmp));
            return Err(err.into());
        }

        Ok(path)
    }

    /// Creates a QCOW2 overlay for a VM, backed by a shared base image.
    ///
    /// The overlay is ~256 KiB initially, regardless of `base` size.
    /// All writes go to the overlay; reads that miss fall through to the
    /// backing file. The `base` path is stored as an **absolute** path
    /// inside the QCOW2 header.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay creation or rename fails.
    pub(crate) fn create_overlay(
        &self,
        base: &Path,
        backing_format: DiskFormat,
        vm_id: &str,
    ) -> Result<PathBuf> {
        let path = self.vm_disk_path(vm_id);

        // Resolve the base to an absolute canonical path for the QCOW2 header.
        let abs_base = fs::canonicalize(base)?;
        let base_size = fs::metadata(&abs_base)?.len();
        let backing = abs_base.to_string_lossy();

        // Write to a temporary file, then rename for atomicity.
        let tmp = self.vms_dir.join(format!("{vm_id}.qcow2.tmp"));
        bux_qcow2::create_overlay(&tmp, &backing, backing_format.into(), base_size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Returns the QCOW2 overlay path for a VM (may or may not exist).
    #[must_use]
    pub(crate) fn vm_disk_path(&self, vm_id: &str) -> PathBuf {
        self.vms_dir.join(format!("{vm_id}.qcow2"))
    }

    /// Flattens a VM's QCOW2 overlay and its entire backing chain into
    /// a standalone QCOW2 file at `dst`.
    ///
    /// # Errors
    ///
    /// Returns an error if the flatten operation fails.
    pub(crate) fn flatten_vm_disk(&self, vm_id: &str, dst: &Path) -> Result<()> {
        Ok(bux_qcow2::flatten(&self.vm_disk_path(vm_id), dst)?)
    }

    /// Removes a VM's QCOW2 overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub(crate) fn remove_vm_disk(&self, vm_id: &str) -> io::Result<()> {
        let path = self.vm_disk_path(vm_id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Lists all base image digests.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub(crate) fn list_bases(&self) -> io::Result<Vec<String>> {
        let mut digests = Vec::new();
        for dir_entry in fs::read_dir(&self.bases_dir)? {
            let name = dir_entry?.file_name();
            if let Some(s) = name.to_str()
                && let Some(digest) = s.strip_suffix(".raw")
            {
                digests.push(digest.to_owned());
            }
        }
        Ok(digests)
    }

    /// Removes a base image by digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub(crate) fn remove_base(&self, digest: &str) -> io::Result<()> {
        let path = self.base_path(digest);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Returns the total disk usage of all bases and VM overlays in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if filesystem stat operations fail.
    pub(crate) fn disk_usage(&self) -> io::Result<u64> {
        let bases = dir_size(&self.bases_dir)?;
        let vms = dir_size(&self.vms_dir)?;
        Ok(bases + vms)
    }
}

/// Calculates total size of all regular files in a directory (non-recursive).
#[cfg(unix)]
fn dir_size(dir: &Path) -> io::Result<u64> {
    let mut total = 0_u64;
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata()
                    && meta.is_file()
                {
                    total += meta.len();
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(total)
}

/// Backing-chain paths that the jail should bind read-only (parents + files).
#[cfg(unix)]
pub(crate) fn readonly_disk_paths(path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for backing in bux_qcow2::read_backing_chain(path) {
        if let Some(parent) = backing.parent().filter(|p| p.exists()) {
            push_unique_path(&mut paths, parent.to_path_buf());
        }
        push_unique_path(&mut paths, backing);
    }
    paths
}
