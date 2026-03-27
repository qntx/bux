//! Disk image management with QCOW2 copy-on-write overlays.
//!
//! # Architecture
//!
//! - [`DiskFormat`] — Type-safe disk format enum (Raw / Qcow2) with serde support.
//! - [`Disk`] — RAII handle that optionally auto-removes the file on drop.
//! - [`DiskManager`] — Manages shared ext4 bases and per-VM QCOW2 overlays.
//! - [`qcow2`] — Pure-Rust QCOW2 v3 operations (create / read / flatten / resize).
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

/// Parsed QCOW2 header information extracted via `qemu-img info`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct QcowHeader {
    /// Format version (2 or 3).
    pub version: u32,
    /// Virtual size of the disk in bytes.
    pub virtual_size: u64,
    /// Cluster size in bytes (always a power of two).
    pub cluster_size: u64,
    /// Cluster bits (log2 of `cluster_size`).
    pub cluster_bits: u32,
    /// Number of L1 table entries.
    pub l1_entries: u32,
    /// Refcount order (log2 of refcount bit width).
    pub refcount_order: u32,
    /// Number of snapshots stored in the image.
    pub snapshots: u32,
    /// Backing file path, if any.
    pub backing_file: Option<String>,
    /// Backing file format string from header extensions (e.g. `"raw"`).
    pub backing_format: Option<String>,
}

impl fmt::Display for QcowHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "version:        {}", self.version)?;
        writeln!(f, "virtual_size:   {} bytes", self.virtual_size)?;
        writeln!(f, "cluster_size:   {} bytes", self.cluster_size)?;
        writeln!(f, "l1_entries:     {}", self.l1_entries)?;
        writeln!(f, "refcount_order: {}", self.refcount_order)?;
        writeln!(f, "snapshots:      {}", self.snapshots)?;
        if let Some(ref bf) = self.backing_file {
            writeln!(f, "backing_file:   {bf}")?;
        }
        if let Some(ref bfmt) = self.backing_format {
            writeln!(f, "backing_format: {bfmt}")?;
        }
        Ok(())
    }
}

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
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the disk format.
    pub const fn format(&self) -> DiskFormat {
        self.format
    }

    /// Returns whether the disk survives drop.
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
    pub fn into_path(self) -> PathBuf {
        let path = self.path.clone();
        std::mem::forget(self);
        path
    }

    /// Reads the QCOW2 header. Returns an error if the format is not QCOW2
    /// or the file cannot be parsed.
    pub fn inspect(&self) -> io::Result<QcowHeader> {
        if self.format != DiskFormat::Qcow2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inspect is only supported for QCOW2 images",
            ));
        }
        qcow2::read_header(&self.path)
    }

    /// Resizes the virtual size of a QCOW2 image using `qemu-img`.
    ///
    /// This is a no-op if the format is `Raw` (raw images do not have
    /// a virtual size distinct from their file size).
    pub fn resize(&self, new_size: u64) -> io::Result<()> {
        if self.format != DiskFormat::Qcow2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resize is only supported for QCOW2 images",
            ));
        }
        qcow2::resize(&self.path, new_size)
    }
}

#[cfg(unix)]
impl Drop for Disk {
    fn drop(&mut self) {
        if !self.persistent {
            let _ = fs::remove_file(&self.path);
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
    pub fn create_overlay(
        &self,
        base: &Path,
        backing_format: DiskFormat,
        vm_id: &str,
    ) -> io::Result<PathBuf> {
        let path = self.vm_disk_path(vm_id);

        // Resolve the base to an absolute canonical path for the QCOW2 header.
        let abs_base = fs::canonicalize(base)?;
        let base_size = fs::metadata(&abs_base)?.len();
        let backing = abs_base.to_string_lossy();

        // Write to a temporary file, then rename for atomicity.
        let tmp = self.vms_dir.join(format!("{vm_id}.qcow2.tmp"));
        qcow2::create_overlay(&tmp, &backing, backing_format, base_size)?;
        fs::rename(&tmp, &path)?;

        Ok(path)
    }

    /// Returns the QCOW2 overlay path for a VM (may or may not exist).
    pub fn vm_disk_path(&self, vm_id: &str) -> PathBuf {
        self.vms_dir.join(format!("{vm_id}.qcow2"))
    }

    /// Reads the QCOW2 header of a VM's overlay disk.
    pub fn inspect_vm_disk(&self, vm_id: &str) -> io::Result<QcowHeader> {
        qcow2::read_header(&self.vm_disk_path(vm_id))
    }

    /// Resizes the virtual size of a VM's QCOW2 overlay.
    pub fn resize_vm_disk(&self, vm_id: &str, new_size: u64) -> io::Result<()> {
        qcow2::resize(&self.vm_disk_path(vm_id), new_size)
    }

    /// Flattens a VM's QCOW2 overlay and its entire backing chain into
    /// a standalone QCOW2 file at `dst`.
    pub fn flatten_vm_disk(&self, vm_id: &str, dst: &Path) -> io::Result<()> {
        qcow2::flatten(&self.vm_disk_path(vm_id), dst)
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

// ───────────────────────────────────────────────────────────────────────────
// QCOW2 v3 — pure-Rust generator + header parser + qemu-img resize
// ───────────────────────────────────────────────────────────────────────────

// All offsets/sizes in this module are compile-time constants well within
// usize range; truncation is impossible on any supported platform.
#[cfg(unix)]
#[allow(clippy::cast_possible_truncation)]
mod qcow2 {
    //! QCOW2 v3 image operations (pure Rust, zero external dependencies).
    //!
    //! - [`create_overlay`] — generates a minimal 256 KiB COW overlay.
    //! - [`read_header`] — parses the on-disk header into [`super::QcowHeader`].
    //! - [`read_backing_file`] — lightweight backing file path extraction.
    //! - [`flatten`] — merges a backing chain into a standalone QCOW2.
    //! - [`resize`] — changes the virtual size via `qemu-img resize`.

    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::path::Path;
    use std::process::Command;

    use super::{DiskFormat, QcowHeader};

    // -- Constants --

    /// QCOW2 magic number: `QFI\xfb`.
    const MAGIC: u32 = 0x5146_49fb;
    /// QCOW2 format version 3.
    const VERSION: u32 = 3;
    /// 64 KiB clusters (`cluster_bits = 16`).
    const CLUSTER_BITS: u32 = 16;
    /// Cluster size in bytes (`2^16 = 65_536`).
    const CLUSTER_SIZE: u64 = 1 << CLUSTER_BITS;
    /// 16-bit refcounts (`refcount_order = 4`, meaning `2^4 = 16` bits).
    const REFCOUNT_ORDER: u32 = 4;
    /// v3 header length in bytes (offsets 0–103).
    const HEADER_LENGTH: u32 = 104;
    /// Backing format header extension type.
    const EXT_BACKING_FMT: u32 = 0xE279_2ACA;
    /// End-of-extensions sentinel.
    const EXT_END: u32 = 0;
    /// Minimum valid header size for parsing (must contain all v2/v3 fields).
    const MIN_HEADER_BYTES: usize = 72;

    // -- create_overlay --

    /// Creates a minimal QCOW2 v3 overlay image at `path`.
    ///
    /// The on-disk layout uses 4 clusters (64 KiB each = 256 KiB total):
    ///
    /// | Cluster | Contents                                          |
    /// |---------|---------------------------------------------------|
    /// | 0       | Header (104 B) + extensions + backing file name   |
    /// | 1       | L1 table (all zeros — reads fall through to base) |
    /// | 2       | Refcount table (one 8-byte entry → cluster 3)     |
    /// | 3       | Refcount block (4 entries = 1, rest = 0)          |
    pub fn create_overlay(
        path: &Path,
        backing_file: &str,
        backing_format: DiskFormat,
        virtual_size: u64,
    ) -> io::Result<()> {
        let backing_bytes = backing_file.as_bytes();
        let fmt_str = backing_format.extension();
        let fmt_bytes = fmt_str.as_bytes();

        let l1_offset: u64 = CLUSTER_SIZE;
        let rctable_offset: u64 = 2 * CLUSTER_SIZE;
        let rcblock_offset: u64 = 3 * CLUSTER_SIZE;

        // One L1 entry per L2 table's worth of virtual data.
        let l2_coverage = (CLUSTER_SIZE / 8) * CLUSTER_SIZE; // 512 MiB
        let l1_entries = virtual_size.div_ceil(l2_coverage) as u32;

        let total_size = 4 * CLUSTER_SIZE;
        let mut buf = vec![0u8; total_size as usize];

        // -- Header (104 bytes) --
        let h = &mut buf[..HEADER_LENGTH as usize];
        write_be32(h, 0, MAGIC);
        write_be32(h, 4, VERSION);
        write_be32(h, 16, backing_bytes.len() as u32);
        write_be32(h, 20, CLUSTER_BITS);
        write_be64(h, 24, virtual_size);
        write_be32(h, 32, 0); // no encryption
        write_be32(h, 36, l1_entries);
        write_be64(h, 40, l1_offset);
        write_be64(h, 48, rctable_offset);
        write_be32(h, 56, 1); // refcount_table_clusters
        write_be32(h, 60, 0); // nb_snapshots
        write_be64(h, 64, 0); // snapshots_offset
        write_be64(h, 72, 0); // incompatible_features
        write_be64(h, 80, 0); // compatible_features
        write_be64(h, 88, 0); // autoclear_features
        write_be32(h, 96, REFCOUNT_ORDER);
        write_be32(h, 100, HEADER_LENGTH);

        // -- Header extensions --
        let mut off = HEADER_LENGTH as usize;

        // Backing file format extension.
        write_be32(&mut buf, off, EXT_BACKING_FMT);
        write_be32(&mut buf, off + 4, fmt_bytes.len() as u32);
        buf[off + 8..off + 8 + fmt_bytes.len()].copy_from_slice(fmt_bytes);
        off += 8 + align8(fmt_bytes.len());

        // End sentinel.
        write_be32(&mut buf, off, EXT_END);
        write_be32(&mut buf, off + 4, 0);
        off += 8;

        // Backing file name (placed after extensions in cluster 0).
        let backing_offset = off as u64;
        buf[off..off + backing_bytes.len()].copy_from_slice(backing_bytes);

        // Patch backing_file_offset (header bytes 8–15).
        write_be64(&mut buf, 8, backing_offset);

        // -- Cluster 2: Refcount table → cluster 3 --
        write_be64(&mut buf, rctable_offset as usize, rcblock_offset);

        // -- Cluster 3: Refcount block — mark clusters 0–3 as allocated --
        let rc_base = rcblock_offset as usize;
        for i in 0..4u16 {
            write_be16(&mut buf, rc_base + (i as usize) * 2, 1);
        }

        // -- Atomic write --
        let mut f = std::fs::File::create(path)?;
        f.write_all(&buf)?;
        f.sync_all()?;

        Ok(())
    }

    // -- read_header --

    /// Parses the QCOW2 header from `path`.
    ///
    /// Validates the magic number and version, then extracts all relevant
    /// fields including backing file name and format extension.
    pub fn read_header(path: &Path) -> io::Result<QcowHeader> {
        let mut f = std::fs::File::open(path)?;

        // Read the first cluster (contains header + extensions + backing name).
        let mut buf = vec![0u8; CLUSTER_SIZE as usize];
        let n = f.read(&mut buf)?;
        if n < MIN_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file too small for QCOW2 header",
            ));
        }

        // Validate magic.
        let magic = read_be32(&buf, 0);
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not a QCOW2 image (magic={magic:#010x}, expected={MAGIC:#010x})"),
            ));
        }

        let version = read_be32(&buf, 4);
        if !(2..=3).contains(&version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported QCOW2 version {version}"),
            ));
        }

        let bf_offset = read_be64(&buf, 8) as usize;
        let bf_size = read_be32(&buf, 16) as usize;
        let cluster_bits = read_be32(&buf, 20);
        let virtual_size = read_be64(&buf, 24);
        let l1_entries = read_be32(&buf, 36);
        let snapshots = read_be32(&buf, 60);

        // Validate cluster_bits to prevent shift overflow.
        if !(9..=30).contains(&cluster_bits) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid cluster_bits {cluster_bits} (must be 9–30)"),
            ));
        }
        let cluster_size = 1u64 << cluster_bits;

        // v3-only fields (with safe defaults for v2).
        let refcount_order = if version >= 3 && n >= 100 {
            read_be32(&buf, 96)
        } else {
            4 // v2 default: 16-bit refcounts
        };

        // Parse backing file name.
        let backing_file = if bf_size > 0 && bf_offset + bf_size <= n {
            std::str::from_utf8(&buf[bf_offset..bf_offset + bf_size])
                .ok()
                .map(String::from)
        } else {
            None
        };

        // Parse header extensions to find backing format.
        let backing_format = if version >= 3 && n >= HEADER_LENGTH as usize + 8 {
            parse_backing_format(&buf, HEADER_LENGTH as usize, n)
        } else {
            None
        };

        Ok(QcowHeader {
            version,
            virtual_size,
            cluster_size,
            cluster_bits,
            l1_entries,
            refcount_order,
            snapshots,
            backing_file,
            backing_format,
        })
    }

    /// Walks the header extension chain to find the backing format string.
    fn parse_backing_format(buf: &[u8], start: usize, limit: usize) -> Option<String> {
        let mut off = start;
        while off + 8 <= limit {
            let ext_type = read_be32(buf, off);
            let ext_len = read_be32(buf, off + 4) as usize;

            if ext_type == EXT_END {
                break;
            }

            let data_start = off + 8;
            let data_end = data_start + ext_len;
            if data_end > limit {
                break;
            }

            if ext_type == EXT_BACKING_FMT {
                return std::str::from_utf8(&buf[data_start..data_end])
                    .ok()
                    .map(String::from);
            }

            // Advance past data, aligned to 8 bytes.
            off = data_start + align8(ext_len);
        }
        None
    }

    // -- resize --

    /// Resizes the virtual size of a QCOW2 image.
    ///
    /// Delegates to `qemu-img resize` which correctly updates the header,
    /// L1/L2 tables, and refcounts.
    pub fn resize(path: &Path, new_size: u64) -> io::Result<()> {
        let output = Command::new("qemu-img")
            .args(["resize", "-f", "qcow2"])
            .arg(path)
            .arg(new_size.to_string())
            .output()
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "qemu-img not found — install qemu-utils to enable resize",
                    )
                } else {
                    e
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "qemu-img resize failed: {}",
                stderr.trim()
            )));
        }

        Ok(())
    }

    // -- read_backing_file --

    /// Returns the backing file path stored in a QCOW2 header, if any.
    ///
    /// This is a lightweight alternative to [`read_header`] when only the
    /// backing file path is needed (e.g. for walking a backing chain).
    #[allow(dead_code)]
    pub fn read_backing_file(path: &Path) -> io::Result<Option<String>> {
        let mut f = std::fs::File::open(path)?;
        let mut hdr = [0u8; 20];
        f.read_exact(&mut hdr)?;

        let magic = u32::from_be_bytes(
            hdr[0..4]
                .try_into()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not a QCOW2 image (magic={magic:#010x})"),
            ));
        }

        let bf_offset = u64::from_be_bytes(
            hdr[8..16]
                .try_into()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        let bf_size = u32::from_be_bytes(
            hdr[16..20]
                .try_into()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        ) as usize;

        if bf_offset == 0 || bf_size == 0 {
            return Ok(None);
        }

        f.seek(SeekFrom::Start(bf_offset))?;
        let mut buf = vec![0u8; bf_size];
        f.read_exact(&mut buf)?;

        String::from_utf8(buf)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    // -- flatten --

    /// Flattens a QCOW2 backing chain into a standalone QCOW2 file.
    ///
    /// Reads `src` and its entire backing chain, merging all COW layers
    /// into a single standalone QCOW2 at `dst` with no backing file.
    /// Only non-zero clusters are written (sparse output).
    ///
    /// Errors on compressed clusters (bit 62 in L2 entries).
    pub fn flatten(src: &Path, dst: &Path) -> io::Result<()> {
        use std::io::{Seek, SeekFrom};

        // Open the full backing chain (top layer first, base last).
        let mut chain = open_chain(src)?;

        let (virtual_size, cluster_bits) = match &chain[0] {
            Layer::Qcow2 {
                virtual_size,
                cluster_bits,
                ..
            } => (*virtual_size, *cluster_bits),
            Layer::Raw { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "flatten: source file is not QCOW2",
                ));
            }
        };

        let cluster_size = 1u64 << cluster_bits;
        let num_virtual_clusters = virtual_size.div_ceil(cluster_size);
        let l2_entries = cluster_size / 8;
        let num_l1 = num_virtual_clusters.div_ceil(l2_entries) as u32;
        let l1_clusters = (u64::from(num_l1) * 8).div_ceil(cluster_size);

        // Output layout:
        //   Cluster 0:                           Header
        //   Clusters 1..1+l1_clusters:           L1 table
        //   Clusters l2_start..l2_start+num_l1:  L2 tables (slots)
        //   Clusters data_start..:               Data clusters
        //   After data:                          Refcount table + blocks
        let l2_start = 1 + l1_clusters;
        let data_start = l2_start + u64::from(num_l1);

        let mut output = std::fs::File::create(dst)?;
        let zero_cluster = vec![0u8; cluster_size as usize];

        // Phase 1: Write data clusters, building L2 tables in memory.
        let mut l2_tables: Vec<Vec<u64>> = vec![vec![0u64; l2_entries as usize]; num_l1 as usize];
        let mut next_data = data_start;

        for vc in 0..num_virtual_clusters {
            let mut data = None;
            for layer in &mut chain {
                if let Some(d) = layer.read_cluster(vc, cluster_size)? {
                    data = Some(d);
                    break;
                }
            }

            if let Some(ref d) = data
                && d.as_slice() != zero_cluster.as_slice()
            {
                let offset = next_data * cluster_size;
                output.seek(SeekFrom::Start(offset))?;
                output.write_all(d)?;

                let l1_idx = (vc / l2_entries) as usize;
                let l2_idx = (vc % l2_entries) as usize;
                l2_tables[l1_idx][l2_idx] = offset;
                next_data += 1;
            }
        }

        // Phase 2: Refcount layout.
        let rc_entries_per_block = cluster_size / 2; // 16-bit refcounts
        let rc_table_cluster = next_data;
        let rc_block_start = rc_table_cluster + 1;
        let mut total_clusters = rc_block_start;
        loop {
            let blocks_needed = total_clusters.div_ceil(rc_entries_per_block);
            let new_total = rc_block_start + blocks_needed;
            if new_total <= total_clusters {
                break;
            }
            total_clusters = new_total;
        }
        let num_rc_blocks = total_clusters - rc_block_start;
        let rc_table_offset = rc_table_cluster * cluster_size;

        // Phase 3: Write L1 table.
        output.seek(SeekFrom::Start(cluster_size))?;
        for (i, l2) in l2_tables.iter().enumerate() {
            let entry: u64 = if l2.iter().any(|&e| e != 0) {
                (l2_start + i as u64) * cluster_size
            } else {
                0
            };
            output.write_all(&entry.to_be_bytes())?;
        }

        // Phase 4: Write L2 tables (only those with data).
        for (i, l2) in l2_tables.iter().enumerate() {
            if l2.iter().all(|&e| e == 0) {
                continue;
            }
            output.seek(SeekFrom::Start((l2_start + i as u64) * cluster_size))?;
            for entry in l2 {
                output.write_all(&entry.to_be_bytes())?;
            }
        }

        // Phase 5: Write refcount table.
        output.seek(SeekFrom::Start(rc_table_offset))?;
        for i in 0..num_rc_blocks {
            let block_offset = (rc_block_start + i) * cluster_size;
            output.write_all(&block_offset.to_be_bytes())?;
        }

        // Phase 6: Write refcount blocks.
        let mut used = vec![false; total_clusters as usize];
        used[0] = true;
        for c in 1..=l1_clusters {
            used[c as usize] = true;
        }
        for (i, l2) in l2_tables.iter().enumerate() {
            if l2.iter().any(|&e| e != 0) {
                used[(l2_start + i as u64) as usize] = true;
            }
        }
        for c in data_start..next_data {
            used[c as usize] = true;
        }
        used[rc_table_cluster as usize] = true;
        for c in rc_block_start..total_clusters {
            used[c as usize] = true;
        }

        for bi in 0..num_rc_blocks {
            output.seek(SeekFrom::Start((rc_block_start + bi) * cluster_size))?;
            let first = (bi * rc_entries_per_block) as usize;
            for c in 0..rc_entries_per_block as usize {
                let rc: u16 = u16::from(first + c < used.len() && used[first + c]);
                output.write_all(&rc.to_be_bytes())?;
            }
        }

        // Phase 7: Write standalone QCOW2 v3 header (no backing).
        output.seek(SeekFrom::Start(0))?;
        let mut hdr = [0u8; 112]; // 104 header + 8 end-of-extensions
        write_be32(&mut hdr, 0, MAGIC);
        write_be32(&mut hdr, 4, VERSION);
        // bytes 8-19 stay zero (no backing file)
        write_be32(&mut hdr, 20, cluster_bits);
        write_be64(&mut hdr, 24, virtual_size);
        write_be32(&mut hdr, 36, num_l1);
        write_be64(&mut hdr, 40, cluster_size); // L1 at cluster 1
        write_be64(&mut hdr, 48, rc_table_offset);
        write_be32(&mut hdr, 56, 1); // refcount_table_clusters
        write_be32(&mut hdr, 96, REFCOUNT_ORDER);
        write_be32(&mut hdr, 100, HEADER_LENGTH);
        // bytes 104-111: end-of-extensions (all zeros)
        output.write_all(&hdr)?;
        output.sync_all()?;

        Ok(())
    }

    // -- Backing chain layer --

    /// A layer in a QCOW2 backing chain, used during flatten.
    enum Layer {
        /// A QCOW2 layer with L1/L2 indirection.
        Qcow2 {
            /// Open file handle for the QCOW2 image.
            file: std::fs::File,
            /// Cluster size exponent (log2).
            cluster_bits: u32,
            /// Virtual disk size in bytes.
            virtual_size: u64,
            /// L1 table entries (physical offsets to L2 tables).
            l1_table: Vec<u64>,
        },
        /// A raw (non-QCOW2) base image.
        Raw {
            /// Open file handle for the raw image.
            file: std::fs::File,
            /// Size of the raw image in bytes.
            size: u64,
        },
    }

    impl Layer {
        /// Read a single virtual cluster from this layer.
        ///
        /// Returns `Some(data)` if allocated, `None` to fall through to backing.
        fn read_cluster(&mut self, vc: u64, cluster_size: u64) -> io::Result<Option<Vec<u8>>> {
            match self {
                Self::Raw { file, size } => {
                    let offset = vc * cluster_size;
                    if offset >= *size {
                        return Ok(None);
                    }
                    file.seek(SeekFrom::Start(offset))?;
                    let mut buf = vec![0u8; cluster_size as usize];
                    let remaining = (*size - offset).min(cluster_size) as usize;
                    file.read_exact(&mut buf[..remaining])?;
                    Ok(Some(buf))
                }
                Self::Qcow2 {
                    file,
                    cluster_bits,
                    l1_table,
                    ..
                } => {
                    let cs = 1u64 << *cluster_bits;
                    let l2_entries = cs / 8;
                    let l1_idx = (vc / l2_entries) as usize;
                    let l2_idx = vc % l2_entries;

                    if l1_idx >= l1_table.len() {
                        return Ok(None);
                    }

                    let l2_offset = l1_table[l1_idx] & 0x00FF_FFFF_FFFF_FE00;
                    if l2_offset == 0 {
                        return Ok(None);
                    }

                    file.seek(SeekFrom::Start(l2_offset + l2_idx * 8))?;
                    let mut entry_buf = [0u8; 8];
                    file.read_exact(&mut entry_buf)?;
                    let l2_entry = u64::from_be_bytes(entry_buf);

                    if l2_entry & (1 << 62) != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "compressed QCOW2 clusters are not supported",
                        ));
                    }

                    let data_offset = l2_entry & 0x00FF_FFFF_FFFF_FE00;
                    if data_offset == 0 {
                        return Ok(None);
                    }

                    file.seek(SeekFrom::Start(data_offset))?;
                    let mut buf = vec![0u8; cs as usize];
                    file.read_exact(&mut buf)?;
                    Ok(Some(buf))
                }
            }
        }
    }

    /// Opens the full backing chain from `path` (top layer first, base last).
    fn open_chain(path: &Path) -> io::Result<Vec<Layer>> {
        use std::io::{Seek, SeekFrom};
        let mut chain = Vec::new();
        let mut current = path.to_path_buf();

        loop {
            let mut file = std::fs::File::open(&current)?;
            let mut magic_buf = [0u8; 4];
            file.read_exact(&mut magic_buf)?;
            let magic = u32::from_be_bytes(magic_buf);

            if magic != MAGIC {
                // Raw file — end of chain.
                let size = file.metadata()?.len();
                chain.push(Layer::Raw { file, size });
                break;
            }

            // Parse QCOW2 header.
            let mut hdr = [0u8; 104];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut hdr)?;

            let bf_offset = read_be64(&hdr, 8);
            let bf_size = read_be32(&hdr, 16) as usize;
            let cluster_bits = read_be32(&hdr, 20);
            let virtual_size = read_be64(&hdr, 24);
            let l1_size = read_be32(&hdr, 36) as usize;
            let l1_offset = read_be64(&hdr, 40);

            // Read L1 table.
            file.seek(SeekFrom::Start(l1_offset))?;
            let mut l1_buf = vec![0u8; l1_size * 8];
            file.read_exact(&mut l1_buf)?;
            let l1_table: Vec<u64> = l1_buf
                .chunks_exact(8)
                .map(|c| {
                    let arr: [u8; 8] = [c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]];
                    u64::from_be_bytes(arr)
                })
                .collect();

            // Read backing file path.
            let backing = if bf_offset != 0 && bf_size != 0 {
                file.seek(SeekFrom::Start(bf_offset))?;
                let mut buf = vec![0u8; bf_size];
                file.read_exact(&mut buf)?;
                Some(
                    String::from_utf8(buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                )
            } else {
                None
            };

            chain.push(Layer::Qcow2 {
                file,
                cluster_bits,
                virtual_size,
                l1_table,
            });

            match backing {
                Some(bp) => current = std::path::PathBuf::from(bp),
                None => break,
            }
        }

        Ok(chain)
    }

    // -- Byte helpers --

    /// Reads a big-endian `u32` from `buf` at `offset`.
    #[inline]
    fn read_be32(buf: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    }

    /// Reads a big-endian `u64` from `buf` at `offset`.
    #[inline]
    fn read_be64(buf: &[u8], offset: usize) -> u64 {
        u64::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ])
    }

    /// Writes a big-endian `u16` at `offset` into `buf`.
    #[inline]
    fn write_be16(buf: &mut [u8], offset: usize, val: u16) {
        buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
    }

    /// Writes a big-endian `u32` at `offset` into `buf`.
    #[inline]
    fn write_be32(buf: &mut [u8], offset: usize, val: u32) {
        buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
    }

    /// Writes a big-endian `u64` at `offset` into `buf`.
    #[inline]
    fn write_be64(buf: &mut [u8], offset: usize, val: u64) {
        buf[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
    }

    /// Rounds `n` up to the next 8-byte boundary.
    #[inline]
    const fn align8(n: usize) -> usize {
        (n + 7) & !7
    }

    // -- Tests --

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::shadow_unrelated)]
    mod tests {
        use super::*;
        use crate::disk::DiskFormat;

        #[test]
        fn creates_valid_qcow2_header() {
            let dir = std::env::temp_dir().join("bux_qcow2_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("test.qcow2");
            let backing = "/tmp/base.raw";
            let vsize: u64 = 1 << 30; // 1 GiB

            create_overlay(&path, backing, DiskFormat::Raw, vsize).unwrap();

            // Verify via read_header.
            let hdr = read_header(&path).unwrap();
            assert_eq!(hdr.version, VERSION);
            assert_eq!(hdr.virtual_size, vsize);
            assert_eq!(hdr.cluster_bits, CLUSTER_BITS);
            assert_eq!(hdr.cluster_size, CLUSTER_SIZE);
            assert_eq!(hdr.backing_file.as_deref(), Some(backing));
            assert_eq!(hdr.backing_format.as_deref(), Some("raw"));
            assert_eq!(hdr.snapshots, 0);

            // Verify file size = 4 clusters = 256 KiB.
            let data = std::fs::read(&path).unwrap();
            assert_eq!(data.len(), 4 * 65536);

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

            create_overlay(&path, "/tmp/big.raw", DiskFormat::Raw, vsize).unwrap();

            let hdr = read_header(&path).unwrap();
            // 100 GiB / 512 MiB per L1 entry = 200 entries.
            assert_eq!(hdr.l1_entries, 200);
            assert_eq!(hdr.virtual_size, vsize);

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn read_header_rejects_non_qcow2() {
            let dir = std::env::temp_dir().join("bux_qcow2_reject_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("not_qcow2.bin");
            std::fs::write(&path, b"this is not a qcow2 image at all!!!!").unwrap();

            let err = read_header(&path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn read_header_rejects_too_small() {
            let dir = std::env::temp_dir().join("bux_qcow2_small_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("tiny.bin");
            std::fs::write(&path, b"QFI").unwrap();

            let err = read_header(&path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn overlay_with_qcow2_backing_format() {
            let dir = std::env::temp_dir().join("bux_qcow2_fmt_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("child.qcow2");
            let vsize: u64 = 1 << 30;

            create_overlay(&path, "/tmp/base.qcow2", DiskFormat::Qcow2, vsize).unwrap();

            let hdr = read_header(&path).unwrap();
            assert_eq!(hdr.backing_file.as_deref(), Some("/tmp/base.qcow2"));
            assert_eq!(hdr.backing_format.as_deref(), Some("qcow2"));

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn read_backing_file_returns_path() {
            let dir = std::env::temp_dir().join("bux_qcow2_bf_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("overlay.qcow2");

            create_overlay(&path, "/data/base.raw", DiskFormat::Raw, 1 << 30).unwrap();

            let bf = read_backing_file(&path).unwrap();
            assert_eq!(bf.as_deref(), Some("/data/base.raw"));

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn read_backing_file_none_for_standalone() {
            let dir = std::env::temp_dir().join("bux_qcow2_nobf_test");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("standalone.qcow2");

            // Create a minimal standalone QCOW2 (no backing) by writing header directly.
            let mut buf = vec![0u8; 104];
            write_be32(&mut buf, 0, MAGIC);
            write_be32(&mut buf, 4, VERSION);
            // bytes 8-19 = 0 → no backing file
            write_be32(&mut buf, 20, CLUSTER_BITS);
            write_be64(&mut buf, 24, 1 << 30);
            write_be32(&mut buf, 100, HEADER_LENGTH);
            std::fs::write(&path, &buf).unwrap();

            let bf = read_backing_file(&path).unwrap();
            assert_eq!(bf, None);

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn flatten_two_layer_chain() {
            let dir = std::env::temp_dir().join("bux_flatten_test");
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::create_dir_all(&dir);

            let cluster_size = CLUSTER_SIZE as usize;
            let raw_size = cluster_size * 4;

            // Create raw base with a known pattern.
            let base = dir.join("base.raw");
            let mut data = vec![0u8; raw_size];
            for i in 0..4u64 {
                let off = (i as usize) * cluster_size;
                let marker = (i + 1).to_be_bytes();
                data[off..off + 8].copy_from_slice(&marker);
            }
            std::fs::write(&base, &data).unwrap();

            // Create COW child pointing to the raw base.
            let child = dir.join("child.qcow2");
            let abs_base = std::fs::canonicalize(&base).unwrap();
            create_overlay(
                &child,
                &abs_base.to_string_lossy(),
                DiskFormat::Raw,
                raw_size as u64,
            )
            .unwrap();

            // Flatten.
            let dst = dir.join("flat.qcow2");
            flatten(&child, &dst).unwrap();

            // Verify no backing file.
            let bf = read_backing_file(&dst).unwrap();
            assert_eq!(bf, None);

            // Verify header is valid.
            let hdr = read_header(&dst).unwrap();
            assert_eq!(hdr.virtual_size, raw_size as u64);
            assert!(hdr.backing_file.is_none());

            // Read cluster 0 from flattened file via open_chain.
            let mut chain = open_chain(&dst).unwrap();
            let c0 = chain[0].read_cluster(0, CLUSTER_SIZE).unwrap();
            assert!(c0.is_some());
            let val = u64::from_be_bytes(c0.unwrap()[..8].try_into().unwrap());
            assert_eq!(val, 1, "cluster 0 marker");

            let c2 = chain[0].read_cluster(2, CLUSTER_SIZE).unwrap();
            assert!(c2.is_some());
            let val = u64::from_be_bytes(c2.unwrap()[..8].try_into().unwrap());
            assert_eq!(val, 3, "cluster 2 marker");

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
