//! Ext4 disk image management with QCOW2 copy-on-write overlays.
//!
//! The [`DiskManager`] creates shared ext4 base images from OCI rootfs
//! directories. Each VM gets a lightweight QCOW2 overlay that references
//! the shared base — writes go to the overlay, reads fall through to the
//! base. Initial overlay size is ~256 KiB regardless of base image size.
//!
//! # Layout
//!
//! ```text
//! {data_dir}/
//!   disks/
//!     bases/
//!       {digest}.raw        — shared read-only ext4 base images
//!     vms/
//!       {vm_id}.qcow2       — per-VM QCOW2 COW overlays
//! ```

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::Result;

/// Manages ext4 base images and per-VM QCOW2 overlay disks.
///
/// Base images are created once per OCI image digest and shared across VMs.
/// Each VM gets a tiny QCOW2 overlay (~256 KiB) that provides copy-on-write
/// semantics via a backing file reference to the shared base.
#[derive(Debug, Clone)]
pub struct DiskManager {
    /// Directory for shared base images.
    bases_dir: PathBuf,
    /// Directory for per-VM QCOW2 overlays.
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
        bux_e2fs::create_from_dir(rootfs, &tmp, size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Creates a QCOW2 overlay for a VM, backed by a shared base image.
    ///
    /// The overlay is ~256 KiB initially, regardless of `base` size.
    /// All writes go to the overlay; reads that miss fall through to the
    /// backing file. The `base` path is stored as an **absolute** path
    /// inside the QCOW2 header.
    pub fn create_overlay(&self, base: &Path, vm_id: &str) -> io::Result<PathBuf> {
        let path = self.vm_disk_path(vm_id);

        // Resolve the base to an absolute canonical path for the QCOW2 header.
        let abs_base = fs::canonicalize(base)?;
        let base_size = fs::metadata(&abs_base)?.len();
        let backing = abs_base.to_string_lossy();

        // Write to a temporary file, then rename for atomicity.
        let tmp = self.vms_dir.join(format!("{vm_id}.qcow2.tmp"));
        qcow2::create_overlay(&tmp, &backing, base_size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Returns the QCOW2 overlay path for a VM (may or may not exist).
    pub fn vm_disk_path(&self, vm_id: &str) -> PathBuf {
        self.vms_dir.join(format!("{vm_id}.qcow2"))
    }

    /// Removes a VM's QCOW2 overlay.
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
    pub fn remove_base(&self, digest: &str) -> io::Result<()> {
        let path = self.base_path(digest);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Minimal QCOW2 v3 image generator (pure Rust, no external dependencies)
// ---------------------------------------------------------------------------

mod qcow2 {
    //! Generates a minimal QCOW2 v3 overlay image with a backing file.
    //!
    //! The on-disk layout uses 4 clusters (64 KiB each = 256 KiB total):
    //!
    //! | Cluster | Contents                                          |
    //! |---------|---------------------------------------------------|
    //! | 0       | Header (104 B) + backing file name + padding      |
    //! | 1       | L1 table (all zeros → reads fall through to base) |
    //! | 2       | Refcount table (one 8-byte entry → cluster 3)     |
    //! | 3       | Refcount block (4 entries = 1, rest = 0)          |

    use std::io::{self, Write};
    use std::path::Path;

    /// QCOW2 magic number: `QFI\xfb`.
    const MAGIC: u32 = 0x5146_49fb;
    /// QCOW2 format version 3.
    const VERSION: u32 = 3;
    /// 64 KiB clusters (cluster_bits = 16).
    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: u64 = 1 << CLUSTER_BITS;
    /// 16-bit refcounts (refcount_order = 4, meaning 2^4 = 16 bits).
    const REFCOUNT_ORDER: u32 = 4;
    /// v3 header length (bytes 0–103).
    const HEADER_LENGTH: u32 = 104;

    /// Backing format header extension type.
    const EXT_BACKING_FMT: u32 = 0xE279_2ACA;
    /// End-of-extensions sentinel.
    const EXT_END: u32 = 0;

    /// Creates a minimal QCOW2 v3 overlay image at `path`.
    pub fn create_overlay(path: &Path, backing_file: &str, virtual_size: u64) -> io::Result<()> {
        let backing_bytes = backing_file.as_bytes();

        // -- Cluster layout --
        // Cluster 0: header + backing file name + header extensions + padding
        // Cluster 1: L1 table
        // Cluster 2: refcount table
        // Cluster 3: refcount block
        let l1_offset: u64 = CLUSTER_SIZE; // cluster 1
        let rctable_offset: u64 = 2 * CLUSTER_SIZE; // cluster 2
        let rcblock_offset: u64 = 3 * CLUSTER_SIZE; // cluster 3

        // L1 table entries: one per L2 table worth of data.
        // Each L2 table covers (cluster_size / 8) clusters = (cluster_size / 8) * cluster_size bytes.
        let l2_coverage = (CLUSTER_SIZE / 8) * CLUSTER_SIZE; // 512 MiB per L1 entry
        #[allow(clippy::cast_possible_truncation)]
        let l1_entries = virtual_size.div_ceil(l2_coverage) as u32;

        // Allocate the full file (4 clusters).
        let total_size = 4 * CLUSTER_SIZE;
        let mut buf = vec![0u8; total_size as usize];

        // -- Write header (104 bytes) --
        let h = &mut buf[..HEADER_LENGTH as usize];
        write_be32(h, 0, MAGIC);
        write_be32(h, 4, VERSION);
        // Backing file offset: immediately after the header + extensions.
        // We place it right after header extensions in cluster 0.
        // For now, set a placeholder — we'll compute it after writing extensions.
        write_be32(h, 16, backing_bytes.len() as u32); // backing_file_size
        write_be32(h, 20, CLUSTER_BITS);
        write_be64(h, 24, virtual_size);
        write_be32(h, 32, 0); // no encryption
        write_be32(h, 36, l1_entries);
        write_be64(h, 40, l1_offset);
        write_be64(h, 48, rctable_offset);
        write_be32(h, 56, 1); // refcount_table_clusters
        write_be32(h, 60, 0); // nb_snapshots
        write_be64(h, 64, 0); // snapshots_offset
        // v3 feature bits:
        write_be64(h, 72, 0); // incompatible_features
        write_be64(h, 80, 0); // compatible_features
        write_be64(h, 88, 0); // autoclear_features
        write_be32(h, 96, REFCOUNT_ORDER);
        write_be32(h, 100, HEADER_LENGTH);

        // -- Write header extensions after the 104-byte header --
        let mut off = HEADER_LENGTH as usize;

        // Extension: backing file format ("raw").
        let fmt = b"raw";
        write_be32(&mut buf, off, EXT_BACKING_FMT);
        write_be32(&mut buf, off + 4, fmt.len() as u32);
        buf[off + 8..off + 8 + fmt.len()].copy_from_slice(fmt);
        off += 8 + align8(fmt.len());

        // Extension: end sentinel.
        write_be32(&mut buf, off, EXT_END);
        write_be32(&mut buf, off + 4, 0);
        off += 8;

        // -- Write backing file name right after extensions --
        let backing_offset = off as u64;
        buf[off..off + backing_bytes.len()].copy_from_slice(backing_bytes);

        // Patch the backing_file_offset in the header (bytes 8–15).
        write_be64(&mut buf, 8, backing_offset);

        // -- Cluster 1: L1 table (all zeros = no allocated L2 tables) --
        // Already zero-filled.

        // -- Cluster 2: Refcount table (one entry pointing to cluster 3) --
        write_be64(&mut buf, rctable_offset as usize, rcblock_offset);

        // -- Cluster 3: Refcount block (16-bit refcounts) --
        // Mark clusters 0–3 as having refcount = 1.
        let rc_base = rcblock_offset as usize;
        for i in 0..4u16 {
            write_be16(&mut buf, rc_base + (i as usize) * 2, 1);
        }

        // -- Write to disk atomically --
        let mut f = std::fs::File::create(path)?;
        f.write_all(&buf)?;
        f.sync_all()?;

        Ok(())
    }

    #[inline]
    fn write_be16(buf: &mut [u8], offset: usize, val: u16) {
        buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
    }

    #[inline]
    fn write_be32(buf: &mut [u8], offset: usize, val: u32) {
        buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
    }

    #[inline]
    fn write_be64(buf: &mut [u8], offset: usize, val: u64) {
        buf[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
    }

    /// Round up to the next 8-byte boundary.
    #[inline]
    const fn align8(n: usize) -> usize {
        (n + 7) & !7
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn creates_valid_qcow2_header() {
            let dir = std::env::temp_dir().join("bux_qcow2_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("test.qcow2");
            let backing = "/tmp/base.raw";
            let vsize: u64 = 1 << 30; // 1 GiB

            create_overlay(&path, backing, vsize).unwrap();

            let data = std::fs::read(&path).unwrap();

            // Check file size = 4 clusters = 256 KiB.
            assert_eq!(data.len(), 4 * 65536);

            // Verify magic.
            assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), MAGIC);
            // Verify version.
            assert_eq!(u32::from_be_bytes(data[4..8].try_into().unwrap()), VERSION);
            // Verify virtual size.
            assert_eq!(u64::from_be_bytes(data[24..32].try_into().unwrap()), vsize);
            // Verify cluster bits.
            assert_eq!(
                u32::from_be_bytes(data[20..24].try_into().unwrap()),
                CLUSTER_BITS
            );
            // Verify backing file name is present.
            let bf_offset = u64::from_be_bytes(data[8..16].try_into().unwrap()) as usize;
            let bf_size = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;
            let bf_name = std::str::from_utf8(&data[bf_offset..bf_offset + bf_size]).unwrap();
            assert_eq!(bf_name, backing);

            // Verify L1 table is all zeros (no allocated data).
            let l1_start = CLUSTER_SIZE as usize;
            let l1_end = l1_start + CLUSTER_SIZE as usize;
            assert!(data[l1_start..l1_end].iter().all(|&b| b == 0));

            // Verify refcount block marks 4 clusters as allocated.
            let rc_base = (3 * CLUSTER_SIZE) as usize;
            for i in 0..4 {
                let rc = u16::from_be_bytes(
                    data[rc_base + i * 2..rc_base + i * 2 + 2]
                        .try_into()
                        .unwrap(),
                );
                assert_eq!(rc, 1, "cluster {i} refcount");
            }
            // Cluster 4+ should be unallocated.
            assert_eq!(
                u16::from_be_bytes(data[rc_base + 8..rc_base + 10].try_into().unwrap()),
                0
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn l1_entries_scale_with_size() {
            let dir = std::env::temp_dir().join("bux_qcow2_l1_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("big.qcow2");
            let vsize: u64 = 100 << 30; // 100 GiB

            create_overlay(&path, "/tmp/big.raw", vsize).unwrap();

            let data = std::fs::read(&path).unwrap();
            let l1_entries = u32::from_be_bytes(data[36..40].try_into().unwrap());
            // 100 GiB / 512 MiB per L1 entry = 200 entries.
            assert_eq!(l1_entries, 200);

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
