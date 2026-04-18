//! QCOW2 header parsing.
//!
//! The on-disk layout handled here follows the QCOW2 v2/v3 specification
//! maintained by the QEMU project. Only the fields required by bux are
//! surfaced; the rest of the header is validated then ignored.

#![allow(
    clippy::cast_possible_truncation,
    reason = "QCOW2 offsets/sizes are 64-bit on disk but are read into usize-indexed slices; \
              sizes larger than isize::MAX are rejected upstream via read_header's buffer cap"
)]

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};
use crate::format::{
    BackingFormat, CLUSTER_SIZE, EXT_BACKING_FMT, EXT_END, HEADER_LENGTH, MAGIC, MIN_HEADER_BYTES,
    align8, read_be_u32, read_be_u64,
};

/// Parsed QCOW2 header.
///
/// Produced by [`read_header`]. Provides a read-only view of the most
/// commonly needed fields.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Header {
    /// On-disk format version (`2` or `3`).
    pub version: u32,
    /// Virtual disk size exposed to the guest, in bytes.
    pub virtual_size: u64,
    /// Cluster size in bytes (`2^cluster_bits`, always a power of two).
    pub cluster_size: u64,
    /// `log2(cluster_size)`, in the range `9..=30`.
    pub cluster_bits: u32,
    /// Number of entries in the L1 table (each entry points to an L2 table).
    pub l1_entries: u32,
    /// Refcount field width as a power of two (`4` = 16-bit entries, the
    /// default produced by this crate).
    pub refcount_order: u32,
    /// Number of snapshots stored in the image.
    pub snapshots: u32,
    /// Backing file path stored in the QCOW2 header, if any.
    pub backing_file: Option<String>,
    /// Recognised backing-format (`raw` / `qcow2`).
    ///
    /// `None` when the header has no backing-format extension or when the
    /// extension value is not a format this crate recognises. In the latter
    /// case [`Header::backing_format_raw`] still exposes the raw string.
    pub backing_format: Option<BackingFormat>,
    /// Raw backing-format string from the header extension, if present.
    ///
    /// Preserves the exact bytes written on disk even when the value is not
    /// a format [`BackingFormat`] recognises.
    pub backing_format_raw: Option<String>,
}

impl fmt::Display for Header {
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
        if let Some(ref raw) = self.backing_format_raw {
            writeln!(f, "backing_format: {raw}")?;
        }
        Ok(())
    }
}

/// Parse the QCOW2 header at `path`.
///
/// Reads the first cluster (64 KiB) of `path` and extracts every field
/// surfaced by [`Header`], including the optional backing-file path and
/// backing-format header extension.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be opened or read.
/// - [`Error::TooSmall`] if the file is shorter than 72 bytes.
/// - [`Error::InvalidMagic`] if the first four bytes are not the QCOW2 magic.
/// - [`Error::UnsupportedVersion`] for versions outside `2..=3`.
/// - [`Error::InvalidClusterBits`] if `cluster_bits` is outside `9..=30`.
pub fn read_header(path: &Path) -> Result<Header> {
    let mut file = File::open(path)?;

    let mut buf = vec![0u8; CLUSTER_SIZE as usize];
    let n = file.read(&mut buf)?;
    if n < MIN_HEADER_BYTES {
        return Err(Error::TooSmall);
    }

    let magic = read_be_u32(&buf, 0);
    if magic != MAGIC {
        return Err(Error::InvalidMagic {
            magic,
            expected: MAGIC,
        });
    }

    let version = read_be_u32(&buf, 4);
    if !(2..=3).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }

    let bf_offset = read_be_u64(&buf, 8) as usize;
    let bf_size = read_be_u32(&buf, 16) as usize;
    let cluster_bits = read_be_u32(&buf, 20);
    let virtual_size = read_be_u64(&buf, 24);
    let l1_entries = read_be_u32(&buf, 36);
    let snapshots = read_be_u32(&buf, 60);

    if !(9..=30).contains(&cluster_bits) {
        return Err(Error::InvalidClusterBits(cluster_bits));
    }
    let cluster_size = 1u64 << cluster_bits;

    let refcount_order = if version >= 3 && n >= 100 {
        read_be_u32(&buf, 96)
    } else {
        4
    };

    let backing_file = parse_backing_file(&buf, bf_offset, bf_size, n)?;
    let backing_format_raw = if version >= 3 && n >= HEADER_LENGTH as usize + 8 {
        parse_backing_format_extension(&buf, HEADER_LENGTH as usize, n)?
    } else {
        None
    };
    let backing_format = backing_format_raw.as_deref().and_then(BackingFormat::parse);

    Ok(Header {
        version,
        virtual_size,
        cluster_size,
        cluster_bits,
        l1_entries,
        refcount_order,
        snapshots,
        backing_file,
        backing_format,
        backing_format_raw,
    })
}

/// Extract the backing-file path from the header buffer.
#[allow(
    clippy::indexing_slicing,
    reason = "bf_offset/size bounds explicitly checked before slicing"
)]
fn parse_backing_file(
    buf: &[u8],
    bf_offset: usize,
    bf_size: usize,
    limit: usize,
) -> Result<Option<String>> {
    if bf_size == 0 {
        return Ok(None);
    }
    let Some(end) = bf_offset.checked_add(bf_size) else {
        return Ok(None);
    };
    if end > limit {
        return Ok(None);
    }
    let slice = &buf[bf_offset..end];
    std::str::from_utf8(slice)
        .map(|s| Some(s.to_owned()))
        .map_err(|_| Error::InvalidUtf8)
}

/// Walk the v3 header extensions and return the backing-format string
/// extension payload, if present.
#[allow(
    clippy::indexing_slicing,
    reason = "every slice is preceded by an explicit bounds check"
)]
fn parse_backing_format_extension(
    buf: &[u8],
    start: usize,
    limit: usize,
) -> Result<Option<String>> {
    let mut off = start;
    while off + 8 <= limit {
        let ext_type = read_be_u32(buf, off);
        let ext_len = read_be_u32(buf, off + 4) as usize;

        if ext_type == EXT_END {
            return Ok(None);
        }

        let data_start = off + 8;
        let Some(data_end) = data_start.checked_add(ext_len) else {
            return Ok(None);
        };
        if data_end > limit {
            return Ok(None);
        }

        if ext_type == EXT_BACKING_FMT {
            let slice = &buf[data_start..data_end];
            return std::str::from_utf8(slice)
                .map(|s| Some(s.to_owned()))
                .map_err(|_| Error::InvalidUtf8);
        }

        let Some(advanced) = data_start.checked_add(align8(ext_len)) else {
            return Ok(None);
        };
        off = advanced;
    }
    Ok(None)
}
