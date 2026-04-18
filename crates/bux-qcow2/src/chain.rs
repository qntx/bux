//! Backing-chain navigation.
//!
//! QCOW2 images can reference a parent (the "backing file"), which itself
//! may reference another parent, etc. This module walks that chain without
//! opening the full header (cheap for chain-traversal use cases such as
//! exposing the list of read-only paths to a sandbox).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::MAGIC;

/// Default safety limit for backing-chain depth (matches bux legacy value).
///
/// QCOW2 allows arbitrarily deep chains, but a bounded walk protects
/// callers from pathological or adversarial images.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 16;

/// Read the backing-file path recorded in a QCOW2 header.
///
/// Returns `Ok(None)` when:
///
/// - `path` is a valid QCOW2 image without a backing file, or
/// - the backing-file offset/size fields are zero.
///
/// This is cheaper than [`crate::read_header`] when only the backing path
/// is needed.
///
/// # Errors
///
/// - [`Error::Io`] on I/O failure.
/// - [`Error::InvalidMagic`] if `path` is not a QCOW2 image.
/// - [`Error::InvalidUtf8`] if the backing-file bytes are not UTF-8.
pub fn read_backing_file(path: &Path) -> Result<Option<String>> {
    let mut file = File::open(path)?;
    let mut hdr = [0u8; 20];
    file.read_exact(&mut hdr)?;

    let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if magic != MAGIC {
        return Err(Error::InvalidMagic {
            magic,
            expected: MAGIC,
        });
    }

    let bf_offset = u64::from_be_bytes([
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
    ]);
    let bf_size = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;

    if bf_offset == 0 || bf_size == 0 {
        return Ok(None);
    }

    file.seek(SeekFrom::Start(bf_offset))?;
    let mut buf = vec![0u8; bf_size];
    file.read_exact(&mut buf)?;

    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| Error::InvalidUtf8)
}

/// Walk the full backing chain starting at `path`, using
/// [`DEFAULT_MAX_CHAIN_DEPTH`] as the safety cap.
///
/// Returns the resolved absolute paths of every backing layer, in order
/// from nearest parent to deepest ancestor. `path` itself is **not**
/// included. Relative backing paths stored in headers are resolved
/// against the parent's directory (matching `qemu-img` behaviour).
///
/// Non-existent or non-QCOW2 backing files terminate the walk without
/// producing an error, so that callers can freely use the result for
/// "mount read-only" logic.
#[must_use]
pub fn read_backing_chain(path: &Path) -> Vec<PathBuf> {
    read_backing_chain_with_depth(path, DEFAULT_MAX_CHAIN_DEPTH)
}

/// Variant of [`read_backing_chain`] with a caller-chosen depth cap.
#[must_use]
pub fn read_backing_chain_with_depth(path: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut chain = Vec::with_capacity(max_depth);
    let mut current = path.to_path_buf();

    for _ in 0..max_depth {
        let Ok(Some(backing)) = read_backing_file(&current) else {
            break;
        };

        let backing_path = PathBuf::from(&backing);
        let resolved = if backing_path.is_absolute() {
            backing_path
        } else if let Some(parent) = current.parent() {
            parent.join(backing_path)
        } else {
            PathBuf::from(backing)
        };

        if !resolved.exists() {
            break;
        }

        chain.push(resolved.clone());
        current = resolved;
    }

    chain
}

/// Check whether `candidate` appears in the backing chain of `image`.
///
/// Paths are canonicalised before comparison. Missing or unreadable
/// backing-chain entries stop the search early and return `Ok(false)`.
///
/// # Errors
///
/// Propagates I/O errors from canonicalising `candidate`.
pub fn is_backing_dependency(image: &Path, candidate: &Path) -> Result<bool> {
    let target = std::fs::canonicalize(candidate)?;
    for entry in read_backing_chain(image) {
        if std::fs::canonicalize(&entry).is_ok_and(|c| c == target) {
            return Ok(true);
        }
    }
    Ok(false)
}
