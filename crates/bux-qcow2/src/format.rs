//! On-disk QCOW2 v3 format constants and byte-order helpers.
//!
//! All multi-byte integers in QCOW2 are big-endian. This module centralises
//! every magic number, offset and helper so that the rest of the crate is
//! parser-style code without scattered literals.

use std::fmt;

/// QCOW2 magic number: the four bytes `Q`, `F`, `I`, `0xfb`.
pub(crate) const MAGIC: u32 = 0x5146_49fb;

/// QCOW2 format version written by this crate.
pub(crate) const VERSION: u32 = 3;

/// 64 KiB clusters (`cluster_bits = 16`).
pub(crate) const CLUSTER_BITS: u32 = 16;

/// Cluster size in bytes (`2^16 = 65_536`).
pub(crate) const CLUSTER_SIZE: u64 = 1 << CLUSTER_BITS;

/// 16-bit refcounts (`refcount_order = 4`, meaning `2^4 = 16` bits per entry).
pub(crate) const REFCOUNT_ORDER: u32 = 4;

/// v3 header length in bytes (offsets `0..=103`).
pub(crate) const HEADER_LENGTH: u32 = 104;

/// Header extension type identifier for "backing file format name".
pub(crate) const EXT_BACKING_FMT: u32 = 0xE279_2ACA;

/// Header extension sentinel marking the end of the extension list.
pub(crate) const EXT_END: u32 = 0;

/// Minimum bytes required to parse a QCOW2 v2/v3 header.
pub(crate) const MIN_HEADER_BYTES: usize = 72;

/// L2 entry mask for the cluster offset field (bits 0..55 with bottom bits
/// zeroed). Bits 62 (compression) and 63 (copied) are stripped.
pub(crate) const L2_OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// L2 entry bit 62 — set when a cluster is compressed.
pub(crate) const L2_COMPRESSED_BIT: u64 = 1 << 62;

/// Backing-image format as recorded in the QCOW2 backing-format header
/// extension.
///
/// QCOW2 itself stores this as a free-form string. bux-qcow2 currently
/// recognises `raw` and `qcow2`; other strings are surfaced through
/// [`crate::Header::backing_format_raw`] so callers can still inspect them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackingFormat {
    /// Raw disk image — no header, contents are the guest-visible bytes.
    Raw,
    /// Another QCOW2 image (nested COW).
    Qcow2,
}

impl BackingFormat {
    /// Canonical lowercase string representation (as written to the QCOW2
    /// header extension).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }

    /// Parse a format name from the on-disk header extension.
    ///
    /// Returns `None` when `s` does not match a recognised format.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "raw" => Some(Self::Raw),
            "qcow2" => Some(Self::Qcow2),
            _ => None,
        }
    }
}

impl fmt::Display for BackingFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read a big-endian `u32` from `buf` at `offset`.
///
/// # Panics
///
/// Panics if `offset + 4 > buf.len()`. Callers must ensure bounds are
/// validated beforehand.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "bounds validated by callers before invocation"
)]
pub(crate) fn read_be_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read a big-endian `u64` from `buf` at `offset`.
///
/// # Panics
///
/// Panics if `offset + 8 > buf.len()`.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "bounds validated by callers before invocation"
)]
pub(crate) fn read_be_u64(buf: &[u8], offset: usize) -> u64 {
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

/// Write `val` as big-endian `u16` into `buf` at `offset`.
///
/// # Panics
///
/// Panics if `offset + 2 > buf.len()`.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "bounds validated by callers before invocation"
)]
pub(crate) fn write_be_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
}

/// Write `val` as big-endian `u32` into `buf` at `offset`.
///
/// # Panics
///
/// Panics if `offset + 4 > buf.len()`.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "bounds validated by callers before invocation"
)]
pub(crate) fn write_be_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
}

/// Write `val` as big-endian `u64` into `buf` at `offset`.
///
/// # Panics
///
/// Panics if `offset + 8 > buf.len()`.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "bounds validated by callers before invocation"
)]
pub(crate) fn write_be_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
}

/// Round `n` up to the next multiple of 8 (QCOW2 extension payloads are
/// 8-byte aligned).
#[inline]
pub(crate) const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is acceptable in unit tests for asserting invariants"
)]
mod tests {
    use super::*;

    #[test]
    fn backing_format_roundtrip() {
        for f in [BackingFormat::Raw, BackingFormat::Qcow2] {
            assert_eq!(BackingFormat::parse(f.as_str()), Some(f));
            assert_eq!(f.to_string(), f.as_str());
        }
    }

    #[test]
    fn backing_format_unknown_returns_none() {
        assert_eq!(BackingFormat::parse("vmdk"), None);
        assert_eq!(BackingFormat::parse(""), None);
        assert_eq!(BackingFormat::parse("RAW"), None);
    }

    #[test]
    fn be_u32_roundtrip() {
        let mut buf = [0u8; 4];
        write_be_u32(&mut buf, 0, 0x1234_5678);
        assert_eq!(read_be_u32(&buf, 0), 0x1234_5678);
    }

    #[test]
    fn be_u64_roundtrip() {
        let mut buf = [0u8; 8];
        write_be_u64(&mut buf, 0, 0x0102_0304_0506_0708);
        assert_eq!(read_be_u64(&buf, 0), 0x0102_0304_0506_0708);
    }

    #[test]
    fn be_u16_write() {
        let mut buf = [0u8; 4];
        write_be_u16(&mut buf, 1, 0xABCD);
        assert_eq!(buf, [0, 0xAB, 0xCD, 0]);
    }

    #[test]
    fn align8_values() {
        assert_eq!(align8(0), 0);
        assert_eq!(align8(1), 8);
        assert_eq!(align8(7), 8);
        assert_eq!(align8(8), 8);
        assert_eq!(align8(9), 16);
        assert_eq!(align8(15), 16);
        assert_eq!(align8(16), 16);
    }

    #[test]
    fn format_constants_consistent() {
        assert_eq!(CLUSTER_SIZE, 1 << CLUSTER_BITS);
        assert_eq!(u64::from(HEADER_LENGTH), 104);
        assert!(MIN_HEADER_BYTES <= HEADER_LENGTH as usize);
    }
}
