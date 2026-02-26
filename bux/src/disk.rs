//! Ext4 disk image management for VM root filesystems.
//!
//! The [`DiskManager`] creates and manages ext4 base images from OCI rootfs
//! directories and per-VM writable copies.
//!
//! # Layout
//!
//! ```text
//! {data_dir}/
//!   disks/
//!     bases/
//!       {digest}.raw      — shared read-only base images
//!     vms/
//!       {vm_id}.raw       — per-VM writable copies
//! ```

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::Result;

/// Manages ext4 disk images for VM root filesystems.
///
/// Base images are created once per OCI image digest and shared across VMs.
/// Each VM gets its own writable copy (via filesystem-level copy).
#[derive(Debug, Clone)]
pub struct DiskManager {
    /// Directory for shared base images.
    bases_dir: PathBuf,
    /// Directory for per-VM writable copies.
    vms_dir: PathBuf,
}

impl DiskManager {
    /// Opens (or creates) the disk storage directories under `data_dir`.
    pub fn open(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let base = data_dir.as_ref().join("disks");
        let bases_dir = base.join("bases");
        let vms_dir = base.join("vms");
        fs::create_dir_all(&bases_dir)?;
        fs::create_dir_all(&vms_dir)?;
        Ok(Self { bases_dir, vms_dir })
    }

    /// Returns `true` if a base image for the given digest already exists.
    pub fn has_base(&self, digest: &str) -> bool {
        self.base_path(digest).exists()
    }

    /// Returns the path for a base image (may or may not exist).
    pub fn base_path(&self, digest: &str) -> PathBuf {
        self.bases_dir.join(format!("{digest}.raw"))
    }

    /// Creates a base ext4 image from an OCI rootfs directory.
    ///
    /// Returns the path to the created image. If the image already exists
    /// for this digest, returns immediately (idempotent).
    pub fn create_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
        let path = self.base_path(digest);
        if path.exists() {
            return Ok(path);
        }

        let size = bux_e2fs::estimate_image_size(rootfs)?;

        // Write to a temporary file first, then rename for atomicity.
        let tmp = self.bases_dir.join(format!("{digest}.raw.tmp"));
        bux_e2fs::Ext4Builder::new().create_from_dir(rootfs, &tmp, size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Creates a writable copy of a base image for a VM.
    ///
    /// Uses a simple file copy. On CoW filesystems (btrfs, APFS) this is
    /// space-efficient. Returns the path to the VM's disk image.
    pub fn create_vm_disk(&self, base: &Path, vm_id: &str) -> io::Result<PathBuf> {
        let path = self.vm_disk_path(vm_id);
        fs::copy(base, &path)?;
        Ok(path)
    }

    /// Returns the disk image path for a VM (may or may not exist).
    pub fn vm_disk_path(&self, vm_id: &str) -> PathBuf {
        self.vms_dir.join(format!("{vm_id}.raw"))
    }

    /// Removes a VM's disk image.
    pub fn remove_vm_disk(&self, vm_id: &str) -> io::Result<()> {
        let path = self.vm_disk_path(vm_id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Lists all base image digests.
    pub fn list_bases(&self) -> io::Result<Vec<String>> {
        let mut digests = Vec::new();
        for entry in fs::read_dir(&self.bases_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(s) = name.to_str()
                && let Some(digest) = s.strip_suffix(".raw") {
                    digests.push(digest.to_owned());
                }
        }
        Ok(digests)
    }

    /// Removes a base image by digest.
    pub fn remove_base(&self, digest: &str) -> io::Result<()> {
        let path = self.base_path(digest);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}
