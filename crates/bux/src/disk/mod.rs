//! Disk image management with QCOW2 copy-on-write overlays.
//!
//! # Architecture
//!
//! - [`DiskFormat`] — Type-safe disk format enum (Raw / Qcow2) with serde support.
//! - [`Disk`] — RAII handle that optionally auto-removes the file on drop.
//! - [`DiskManager`] — Manages shared ext4 bases and per-VM QCOW2 overlays.
//! - QCOW2 operations themselves live in the [`bux_qcow2`] sub-crate.
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
pub use bux_qcow2::Header as QcowHeader;

#[cfg(unix)]
use crate::Result;
#[cfg(unix)]
use crate::guest::ManagedGuestBinary;
#[cfg(unix)]
use crate::util::push_unique_path;

/// Disk image format.
///
/// Used across `VmConfig`, `VmBuilder`, and the FFI layer (`sys::add_disk2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DiskFormat {
    /// Raw disk image (default).
    #[default]
    Raw,
    /// QCOW2 copy-on-write image.
    Qcow2,
}

impl DiskFormat {
    /// Returns the file extension for this format.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
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

/// RAII handle for a disk image file.
///
/// When `persistent` is `false`, the file is deleted on drop — useful for
/// per-VM overlays that should be cleaned up when the VM is removed.
#[cfg(unix)]
#[derive(Debug)]
pub struct Disk {
    /// Absolute path to the disk image.
    path: PathBuf,
    /// Image format.
    format: DiskFormat,
    /// If `false`, the file is removed on drop.
    persistent: bool,
}

#[cfg(unix)]
impl Disk {
    /// Creates a new handle. Does **not** touch the filesystem.
    pub fn new(path: impl Into<PathBuf>, format: DiskFormat, persistent: bool) -> Self {
        Self {
            path: path.into(),
            format,
            persistent,
        }
    }

    /// Returns the disk image path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the disk format.
    #[must_use]
    pub const fn format(&self) -> DiskFormat {
        self.format
    }

    /// Returns whether the disk survives drop.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// Marks the disk as persistent (will **not** be deleted on drop).
    pub const fn set_persistent(&mut self, persistent: bool) {
        self.persistent = persistent;
    }

    /// Consumes the handle and returns the path without deleting the file.
    ///
    /// Use when transferring ownership to another component that manages
    /// the file's lifetime independently.
    #[must_use]
    pub fn into_path(self) -> PathBuf {
        let this = std::mem::ManuallyDrop::new(self);
        this.path.clone()
    }

    /// Reads the QCOW2 header.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is not QCOW2 or the file cannot be parsed.
    pub fn inspect(&self) -> Result<QcowHeader> {
        if self.format != DiskFormat::Qcow2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inspect is only supported for QCOW2 images",
            )
            .into());
        }
        Ok(bux_qcow2::read_header(&self.path)?)
    }

    /// Resizes the virtual size of a QCOW2 image using `qemu-img`.
    ///
    /// This is a no-op if the format is `Raw` (raw images do not have
    /// a virtual size distinct from their file size).
    ///
    /// # Errors
    ///
    /// Returns an error if the format is not QCOW2 or the resize fails.
    pub fn resize(&self, new_size: u64) -> Result<()> {
        if self.format != DiskFormat::Qcow2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resize is only supported for QCOW2 images",
            )
            .into());
        }
        Ok(bux_qcow2::resize(&self.path, new_size)?)
    }
}

#[cfg(unix)]
impl Drop for Disk {
    fn drop(&mut self) {
        if !self.persistent {
            drop(fs::remove_file(&self.path));
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
pub struct DiskManager {
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
    pub fn open(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let base = data_dir.as_ref().join("disks");
        let bases_dir = base.join("bases");
        let vms_dir = base.join("vms");
        fs::create_dir_all(&bases_dir)?;
        fs::create_dir_all(&vms_dir)?;
        Ok(Self { bases_dir, vms_dir })
    }

    /// Returns the directory where base disk images are stored.
    #[must_use]
    pub fn bases_dir(&self) -> &Path {
        &self.bases_dir
    }

    /// Returns `true` if a base image for the given digest already exists.
    #[must_use]
    pub fn has_base(&self, digest: &str) -> bool {
        self.base_path(digest).exists()
    }

    /// Returns the path for a base image (may or may not exist).
    #[must_use]
    pub fn base_path(&self, digest: &str) -> PathBuf {
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
    pub fn create_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
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
    pub fn create_managed_base(&self, rootfs: &Path, digest: &str) -> Result<PathBuf> {
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
    pub fn create_overlay(
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
    pub fn vm_disk_path(&self, vm_id: &str) -> PathBuf {
        self.vms_dir.join(format!("{vm_id}.qcow2"))
    }

    /// Reads the QCOW2 header of a VM's overlay disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the header cannot be read.
    pub fn inspect_vm_disk(&self, vm_id: &str) -> Result<QcowHeader> {
        Ok(bux_qcow2::read_header(&self.vm_disk_path(vm_id))?)
    }

    /// Resizes the virtual size of a VM's QCOW2 overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the resize operation fails.
    pub fn resize_vm_disk(&self, vm_id: &str, new_size: u64) -> Result<()> {
        Ok(bux_qcow2::resize(&self.vm_disk_path(vm_id), new_size)?)
    }

    /// Flattens a VM's QCOW2 overlay and its entire backing chain into
    /// a standalone QCOW2 file at `dst`.
    ///
    /// # Errors
    ///
    /// Returns an error if the flatten operation fails.
    pub fn flatten_vm_disk(&self, vm_id: &str, dst: &Path) -> Result<()> {
        Ok(bux_qcow2::flatten(&self.vm_disk_path(vm_id), dst)?)
    }

    /// Removes a VM's QCOW2 overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub fn remove_vm_disk(&self, vm_id: &str) -> io::Result<()> {
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
    pub fn list_bases(&self) -> io::Result<Vec<String>> {
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
    pub fn remove_base(&self, digest: &str) -> io::Result<()> {
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
    pub fn disk_usage(&self) -> io::Result<u64> {
        let bases = dir_size(&self.bases_dir)?;
        let vms = dir_size(&self.vms_dir)?;
        Ok(bases + vms)
    }

    /// Checks if at least `needed_bytes` of free space is available
    /// on the filesystem where the disk storage is located.
    ///
    /// Returns `Ok(())` if sufficient space exists, or an error if not.
    ///
    /// # Errors
    ///
    /// Returns an error if the stat fails or space is insufficient.
    pub fn check_space(&self, needed_bytes: u64) -> io::Result<()> {
        let stat = nix::sys::statvfs::statvfs(&self.bases_dir)?;
        let frag = stat.fragment_size();
        let blocks: u64 = stat.blocks_available().into();
        let available = frag * blocks;
        if available < needed_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "insufficient disk space: need {needed_bytes} bytes, only {available} available",
                ),
            ));
        }
        Ok(())
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

#[cfg(unix)]
#[allow(clippy::missing_docs_in_private_items, reason = "internal helper")]
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
