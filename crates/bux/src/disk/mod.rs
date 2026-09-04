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
//!   bases/{digest}.raw         — shared read-only ext4 base images
//!   bases/clone-{id}.qcow2     — flattened clone bases (not listed as OCI digests)
//!   vms/{vm_id}.qcow2          — per-VM QCOW2 COW overlays (~256 KiB each)
//! ```

use std::fmt;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{self, Read};
#[cfg(unix)]
use std::path::{Path, PathBuf};

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

/// QCOW2 on-disk magic (`QFI\xfb`).
#[cfg(unix)]
const QCOW2_MAGIC: [u8; 4] = [b'Q', b'F', b'I', 0xfb];

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
    /// `guest_path`: `Some` must be a regular file or [`crate::Error::NotFound`];
    /// `None` searches a canonical sibling of the running executable.
    ///
    /// # Errors
    ///
    /// Returns an error if image creation, injection, or rename fails.
    pub(crate) fn create_managed_base(
        &self,
        rootfs: &Path,
        digest: &str,
        guest_path: Option<&Path>,
    ) -> Result<PathBuf> {
        let guest = ManagedGuestBinary::resolve(guest_path)?;
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

    /// Creates a QCOW2 overlay for a VM, backed by `base`.
    ///
    /// The overlay is ~256 KiB initially, regardless of `base` size.
    /// All writes go to the overlay; reads that miss fall through to the
    /// backing file. The `base` path is stored as an **absolute** path
    /// inside the QCOW2 header.
    ///
    /// A leading QCOW2 magic byte sequence selects QCOW2 backing format and
    /// header `virtual_size`. Otherwise file length and `backing_format` are
    /// used as given.
    ///
    /// # Errors
    ///
    /// Returns an error if overlay creation or rename fails, or if `base`
    /// starts with QCOW2 magic but its header cannot be parsed.
    pub(crate) fn create_overlay(
        &self,
        base: &Path,
        backing_format: DiskFormat,
        vm_id: &str,
    ) -> Result<PathBuf> {
        let path = self.vm_disk_path(vm_id);

        // Resolve the base to an absolute canonical path for the QCOW2 header.
        let abs_base = fs::canonicalize(base)?;
        let (virtual_size, backing_format) = sniff_backing(&abs_base, backing_format)?;
        let backing = abs_base.to_string_lossy();

        // Write to a temporary file, then rename for atomicity.
        let tmp = self.vms_dir.join(format!("{vm_id}.qcow2.tmp"));
        bux_qcow2::create_overlay(&tmp, &backing, backing_format.into(), virtual_size)?;
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

/// Guest-visible size and backing format to record on a new overlay.
///
/// # Errors
///
/// Returns I/O errors from reading `abs_base`. If the file starts with QCOW2
/// magic, returns QCOW2 parse errors instead of treating the file as raw.
#[cfg(unix)]
fn sniff_backing(abs_base: &Path, caller_format: DiskFormat) -> Result<(u64, DiskFormat)> {
    let mut magic = [0_u8; 4];
    let is_qcow2 = match fs::File::open(abs_base)?.read_exact(&mut magic) {
        Ok(()) => magic == QCOW2_MAGIC,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => false,
        Err(err) => return Err(err.into()),
    };
    if is_qcow2 {
        let header = bux_qcow2::read_header(abs_base)?;
        Ok((header.virtual_size, DiskFormat::Qcow2))
    } else {
        Ok((fs::metadata(abs_base)?.len(), caller_format))
    }
}

#[cfg(test)]
#[cfg(unix)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use bux_qcow2::BackingFormat;

    #[test]
    fn create_overlay_sniffs_qcow2_after_flatten() {
        let dir = tempfile::tempdir().unwrap();
        let dm = DiskManager::open(dir.path()).unwrap();
        let payload = vec![0xAB_u8; 4096];
        let raw_len = u64::try_from(payload.len()).unwrap();
        let raw = dm.bases_dir().join("base.raw");
        fs::write(&raw, &payload).unwrap();

        let overlay_a = dm.create_overlay(&raw, DiskFormat::Raw, "vm-a").unwrap();
        let hdr_a = bux_qcow2::read_header(&overlay_a).unwrap();
        assert_eq!(
            hdr_a.backing_format,
            Some(BackingFormat::Raw),
            "raw backing must keep caller format"
        );
        assert_eq!(
            hdr_a.virtual_size, raw_len,
            "raw backing virtual_size must equal file length"
        );

        let flat = dm.bases_dir().join("clone-test.qcow2");
        dm.flatten_vm_disk("vm-a", &flat).unwrap();

        let overlay_b = dm.create_overlay(&flat, DiskFormat::Raw, "vm-b").unwrap();
        let hdr_b = bux_qcow2::read_header(&overlay_b).unwrap();
        assert_eq!(
            hdr_b.backing_format,
            Some(BackingFormat::Qcow2),
            "flatten dest magic must override caller DiskFormat::Raw"
        );
        assert_eq!(
            hdr_b.virtual_size, raw_len,
            "overlay over flattened qcow2 must keep the original virtual size"
        );
    }

    #[test]
    fn create_overlay_rejects_truncated_qcow2() {
        let dir = tempfile::tempdir().unwrap();
        let dm = DiskManager::open(dir.path()).unwrap();
        let truncated = dm.bases_dir().join("truncated.qcow2");
        fs::write(&truncated, QCOW2_MAGIC).unwrap();
        let err = dm
            .create_overlay(&truncated, DiskFormat::Raw, "vm-trunc")
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::Qcow2(bux_qcow2::Error::TooSmall)),
            "truncated QCOW2 must fail closed, not be treated as raw: {err}"
        );
    }

    #[test]
    fn clone_qcow2_is_not_listed_or_removed_as_base() {
        let dir = tempfile::tempdir().unwrap();
        let dm = DiskManager::open(dir.path()).unwrap();
        let oci_a = dm.bases_dir().join("sha256-aaa.raw");
        let oci_b = dm.bases_dir().join("sha256-bbb.raw");
        let clone = dm.bases_dir().join("clone-xyz.qcow2");
        fs::write(&oci_a, b"oci-a").unwrap();
        fs::write(&oci_b, b"oci-b").unwrap();
        fs::write(&clone, b"clone-base").unwrap();

        let mut bases = dm.list_bases().unwrap();
        bases.sort_unstable();
        assert_eq!(
            bases,
            vec!["sha256-aaa".to_owned(), "sha256-bbb".to_owned()],
            "clone-*.qcow2 must not appear as an OCI base digest"
        );

        dm.remove_base("unrelated-digest").unwrap();
        dm.remove_base("clone-xyz").unwrap();
        assert!(clone.exists(), "remove_base must not delete clone-*.qcow2");
        assert!(
            oci_a.exists(),
            "unrelated remove_base must not delete OCI bases"
        );
        assert!(
            oci_b.exists(),
            "unrelated remove_base must not delete OCI bases"
        );
    }
}
