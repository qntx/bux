//! Minimal QCOW2 v3 overlay creation.
//!
//! An "overlay" is a tiny QCOW2 image (256 KiB on disk) whose reads fall
//! through to a backing file. All guest writes land in the overlay, giving
//! cheap copy-on-write semantics over a read-only base image.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::format::{
    BackingFormat, CLUSTER_BITS, CLUSTER_SIZE, EXT_BACKING_FMT, EXT_END, HEADER_LENGTH, MAGIC,
    REFCOUNT_ORDER, VERSION, align8, write_be_u16, write_be_u32, write_be_u64,
};

/// Create a minimal 256 KiB QCOW2 v3 overlay at `path`.
///
/// The on-disk layout uses exactly 4 clusters (64 KiB each):
///
/// | Cluster | Contents                                          |
/// |---------|---------------------------------------------------|
/// | 0       | Header (104 B) + extensions + backing file name   |
/// | 1       | L1 table (all zeros — reads fall through to base) |
/// | 2       | Refcount table (one 8-byte entry → cluster 3)     |
/// | 3       | Refcount block (4 entries = 1, rest = 0)          |
///
/// The overlay is written atomically via a single `write_all` + `sync_all`
/// call on a freshly-created file. Callers that need cross-directory
/// atomicity should write to a temporary path and `rename` into place.
///
/// # Arguments
///
/// - `path` — destination file (will be created or truncated).
/// - `backing_file` — absolute path to the backing image (stored verbatim
///   in the QCOW2 header).
/// - `backing_format` — format of `backing_file` (raw / qcow2).
/// - `virtual_size` — virtual disk size exposed to the guest, in bytes.
///
/// # Errors
///
/// [`crate::Error::Io`] if file creation, writing, or fsync fails.
#[allow(
    clippy::cast_possible_truncation,
    reason = "l1_entries is capped at u32::MAX by QCOW2 spec and virtual_size upper bound"
)]
pub fn create_overlay(
    path: &Path,
    backing_file: &str,
    backing_format: BackingFormat,
    virtual_size: u64,
) -> Result<()> {
    let backing_bytes = backing_file.as_bytes();
    let fmt_bytes = backing_format.as_str().as_bytes();

    let l1_offset: u64 = CLUSTER_SIZE;
    let rctable_offset: u64 = 2 * CLUSTER_SIZE;
    let rcblock_offset: u64 = 3 * CLUSTER_SIZE;

    let l2_coverage = (CLUSTER_SIZE / 8) * CLUSTER_SIZE;
    let l1_entries = virtual_size.div_ceil(l2_coverage) as u32;

    let total_size = 4 * CLUSTER_SIZE;
    let mut buf = vec![0u8; total_size as usize];

    write_header_bytes(
        &mut buf,
        virtual_size,
        backing_bytes.len() as u32,
        l1_entries,
        l1_offset,
        rctable_offset,
    );

    let mut off = HEADER_LENGTH as usize;
    off = write_backing_format_extension(&mut buf, off, fmt_bytes);
    off = write_end_sentinel(&mut buf, off);
    let backing_offset = write_backing_file_name(&mut buf, off, backing_bytes);
    write_be_u64(&mut buf, 8, backing_offset);

    write_be_u64(&mut buf, rctable_offset as usize, rcblock_offset);

    let rc_base = rcblock_offset as usize;
    for i in 0..4u16 {
        write_be_u16(&mut buf, rc_base + (i as usize) * 2, 1);
    }

    let mut file = File::create(path)?;
    file.write_all(&buf)?;
    file.sync_all()?;
    Ok(())
}

/// Populate the fixed-size 104-byte QCOW2 v3 header inside `buf`.
///
/// The caller fills `backing_file_offset` (bytes 8..=15) separately once
/// the extensions are written, because the backing-file string is placed
/// after the extension list.
#[allow(
    clippy::indexing_slicing,
    reason = "buf is pre-sized to HEADER_LENGTH by the caller"
)]
fn write_header_bytes(
    buf: &mut [u8],
    virtual_size: u64,
    backing_size: u32,
    l1_entries: u32,
    l1_offset: u64,
    rctable_offset: u64,
) {
    let h = &mut buf[..HEADER_LENGTH as usize];
    write_be_u32(h, 0, MAGIC);
    write_be_u32(h, 4, VERSION);
    write_be_u32(h, 16, backing_size);
    write_be_u32(h, 20, CLUSTER_BITS);
    write_be_u64(h, 24, virtual_size);
    write_be_u32(h, 32, 0);
    write_be_u32(h, 36, l1_entries);
    write_be_u64(h, 40, l1_offset);
    write_be_u64(h, 48, rctable_offset);
    write_be_u32(h, 56, 1);
    write_be_u32(h, 60, 0);
    write_be_u64(h, 64, 0);
    write_be_u64(h, 72, 0);
    write_be_u64(h, 80, 0);
    write_be_u64(h, 88, 0);
    write_be_u32(h, 96, REFCOUNT_ORDER);
    write_be_u32(h, 100, HEADER_LENGTH);
}

/// Write the "backing file format" header extension (`EXT_BACKING_FMT`).
///
/// Returns the offset that the next extension header should be written at.
#[allow(
    clippy::cast_possible_truncation,
    reason = "fmt_bytes length is bounded by BackingFormat::as_str (max 5)"
)]
#[allow(
    clippy::indexing_slicing,
    reason = "buffer sizing invariant maintained by create_overlay (4 clusters)"
)]
fn write_backing_format_extension(buf: &mut [u8], off: usize, fmt_bytes: &[u8]) -> usize {
    write_be_u32(buf, off, EXT_BACKING_FMT);
    write_be_u32(buf, off + 4, fmt_bytes.len() as u32);
    buf[off + 8..off + 8 + fmt_bytes.len()].copy_from_slice(fmt_bytes);
    off + 8 + align8(fmt_bytes.len())
}

/// Write the end-of-extensions sentinel and return the offset that the
/// backing-file name should be placed at.
fn write_end_sentinel(buf: &mut [u8], off: usize) -> usize {
    write_be_u32(buf, off, EXT_END);
    write_be_u32(buf, off + 4, 0);
    off + 8
}

/// Copy the backing-file name into `buf` at `off`, returning the absolute
/// on-disk offset where it was placed.
#[allow(
    clippy::indexing_slicing,
    reason = "buffer sizing invariant maintained by create_overlay (4 clusters)"
)]
fn write_backing_file_name(buf: &mut [u8], off: usize, backing_bytes: &[u8]) -> u64 {
    buf[off..off + backing_bytes.len()].copy_from_slice(backing_bytes);
    off as u64
}
