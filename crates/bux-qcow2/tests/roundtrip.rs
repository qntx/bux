//! End-to-end tests covering the public bux-qcow2 API.
//!
//! Each test writes through [`tempfile::TempDir`] so there is no shared
//! global state between test cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    clippy::cast_possible_truncation,
    clippy::tests_outside_test_module,
    reason = "integration tests intentionally use unwrap/expect/indexing for brevity; \
              Cargo's tests/ layout implies every fn is a test, no explicit #[cfg(test)] module"
)]

// `thiserror` is pulled in transitively through bux-qcow2::Error but never
// referenced by name from this binary — silence the workspace lint.
use thiserror as _;

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use bux_qcow2::{
    BackingFormat, DEFAULT_MAX_CHAIN_DEPTH, FORMAT_VERSION, create_overlay, flatten,
    is_backing_dependency, read_backing_chain, read_backing_chain_with_depth, read_backing_file,
    read_header,
};
use tempfile::TempDir;

const CLUSTER_SIZE: u64 = 1 << 16;

#[test]
fn create_overlay_produces_valid_header() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ovl.qcow2");
    let backing = "/data/base.raw";
    let vsize: u64 = 1 << 30;

    create_overlay(&path, backing, BackingFormat::Raw, vsize).unwrap();

    let hdr = read_header(&path).unwrap();
    assert_eq!(hdr.version, FORMAT_VERSION);
    assert_eq!(hdr.virtual_size, vsize);
    assert_eq!(hdr.cluster_size, CLUSTER_SIZE);
    assert_eq!(hdr.cluster_bits, 16);
    assert_eq!(hdr.backing_file.as_deref(), Some(backing));
    assert_eq!(hdr.backing_format, Some(BackingFormat::Raw));
    assert_eq!(hdr.backing_format_raw.as_deref(), Some("raw"));
    assert_eq!(hdr.snapshots, 0);
    assert_eq!(hdr.refcount_order, 4);

    let data = fs::read(&path).unwrap();
    assert_eq!(data.len(), 4 * CLUSTER_SIZE as usize);
}

#[test]
fn overlay_with_qcow2_backing_format() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("child.qcow2");
    create_overlay(&path, "/tmp/base.qcow2", BackingFormat::Qcow2, 1 << 30).unwrap();

    let hdr = read_header(&path).unwrap();
    assert_eq!(hdr.backing_format, Some(BackingFormat::Qcow2));
    assert_eq!(hdr.backing_format_raw.as_deref(), Some("qcow2"));
}

#[test]
fn l1_entries_scale_with_virtual_size() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("big.qcow2");
    let vsize: u64 = 100 << 30;

    create_overlay(&path, "/tmp/big.raw", BackingFormat::Raw, vsize).unwrap();

    let hdr = read_header(&path).unwrap();
    assert_eq!(hdr.l1_entries, 200);
    assert_eq!(hdr.virtual_size, vsize);
}

#[test]
fn read_header_rejects_non_qcow2() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("not.qcow2");
    fs::write(&path, vec![b'x'; 128]).unwrap();

    let err = read_header(&path).unwrap_err();
    assert!(matches!(err, bux_qcow2::Error::InvalidMagic { .. }));
}

#[test]
fn read_header_rejects_too_small() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tiny.bin");
    fs::write(&path, b"QFI").unwrap();

    let err = read_header(&path).unwrap_err();
    assert!(matches!(err, bux_qcow2::Error::TooSmall));
}

#[test]
fn read_header_rejects_invalid_cluster_bits() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad_bits.qcow2");
    create_overlay(&path, "/tmp/base.raw", BackingFormat::Raw, 1 << 30).unwrap();

    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(20)).unwrap();
    file.write_all(&99u32.to_be_bytes()).unwrap();

    let err = read_header(&path).unwrap_err();
    assert!(matches!(err, bux_qcow2::Error::InvalidClusterBits(99)));
}

#[test]
fn read_backing_file_returns_path() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ovl.qcow2");
    create_overlay(&path, "/data/base.raw", BackingFormat::Raw, 1 << 30).unwrap();

    let bf = read_backing_file(&path).unwrap();
    assert_eq!(bf.as_deref(), Some("/data/base.raw"));
}

#[test]
fn read_backing_file_none_for_standalone() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.raw");
    fs::write(&base, vec![0u8; 1024]).unwrap();

    let path = dir.path().join("ovl.qcow2");
    create_overlay(&path, &base.to_string_lossy(), BackingFormat::Raw, 1 << 30).unwrap();

    let flat = dir.path().join("flat.qcow2");
    flatten(&path, &flat).unwrap();

    let bf = read_backing_file(&flat).unwrap();
    assert_eq!(bf, None);
}

#[test]
fn read_backing_file_rejects_non_qcow2() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("not.qcow2");
    fs::write(&path, vec![0u8; 128]).unwrap();

    let err = read_backing_file(&path).unwrap_err();
    assert!(matches!(err, bux_qcow2::Error::InvalidMagic { .. }));
}

#[test]
fn read_backing_chain_terminates_on_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ovl.qcow2");
    create_overlay(
        &path,
        "/definitely/does/not/exist.raw",
        BackingFormat::Raw,
        1 << 30,
    )
    .unwrap();

    let chain = read_backing_chain(&path);
    assert!(chain.is_empty());
}

#[test]
fn read_backing_chain_respects_depth_cap() {
    let dir = TempDir::new().unwrap();

    let base = dir.path().join("base.raw");
    fs::write(&base, vec![0u8; 1024]).unwrap();

    let layer1 = dir.path().join("l1.qcow2");
    create_overlay(&layer1, &base.to_string_lossy(), BackingFormat::Raw, 1024).unwrap();

    let layer2 = dir.path().join("l2.qcow2");
    create_overlay(
        &layer2,
        &layer1.to_string_lossy(),
        BackingFormat::Qcow2,
        1024,
    )
    .unwrap();

    let full = read_backing_chain(&layer2);
    assert_eq!(full.len(), 2);

    let capped = read_backing_chain_with_depth(&layer2, 1);
    assert_eq!(capped.len(), 1);

    const { assert!(DEFAULT_MAX_CHAIN_DEPTH >= 2) };
}

#[test]
fn is_backing_dependency_detects_direct_parent() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.raw");
    fs::write(&base, vec![0u8; 1024]).unwrap();

    let ovl = dir.path().join("ovl.qcow2");
    create_overlay(&ovl, &base.to_string_lossy(), BackingFormat::Raw, 1024).unwrap();

    assert!(is_backing_dependency(&ovl, &base).unwrap());
}

#[test]
fn is_backing_dependency_false_for_unrelated() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.raw");
    fs::write(&base, vec![0u8; 1024]).unwrap();

    let other = dir.path().join("other.raw");
    fs::write(&other, vec![0u8; 1024]).unwrap();

    let ovl = dir.path().join("ovl.qcow2");
    create_overlay(&ovl, &base.to_string_lossy(), BackingFormat::Raw, 1024).unwrap();

    assert!(!is_backing_dependency(&ovl, &other).unwrap());
}

#[test]
fn flatten_two_layer_raw_chain() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.raw");
    let cluster_size = CLUSTER_SIZE as usize;
    let mut data = vec![0u8; cluster_size * 4];
    for i in 0..4u64 {
        let off = (i as usize) * cluster_size;
        data[off..off + 8].copy_from_slice(&(i + 1).to_be_bytes());
    }
    fs::write(&base, &data).unwrap();

    let abs_base = fs::canonicalize(&base).unwrap();
    let child = dir.path().join("child.qcow2");
    create_overlay(
        &child,
        &abs_base.to_string_lossy(),
        BackingFormat::Raw,
        data.len() as u64,
    )
    .unwrap();

    let flat = dir.path().join("flat.qcow2");
    flatten(&child, &flat).unwrap();

    let hdr = read_header(&flat).unwrap();
    assert_eq!(hdr.virtual_size, data.len() as u64);
    assert!(hdr.backing_file.is_none());

    let cluster0 = read_flat_cluster(&flat, 0);
    assert_eq!(u64::from_be_bytes(cluster0[..8].try_into().unwrap()), 1);

    let cluster2 = read_flat_cluster(&flat, 2);
    assert_eq!(u64::from_be_bytes(cluster2[..8].try_into().unwrap()), 3);
}

/// Helper: read one cluster's worth of payload from a standalone flat QCOW2
/// by following the top-level L1/L2 indirection.
fn read_flat_cluster(path: &std::path::Path, vc: u64) -> Vec<u8> {
    let mut file = fs::File::open(path).unwrap();
    let mut hdr = [0u8; 104];
    file.read_exact(&mut hdr).unwrap();
    let cluster_bits = u32::from_be_bytes(hdr[20..24].try_into().unwrap());
    let l1_offset = u64::from_be_bytes(hdr[40..48].try_into().unwrap());
    let cs = 1u64 << cluster_bits;
    let l2_entries = cs / 8;
    let l1_idx = vc / l2_entries;
    let l2_idx = vc % l2_entries;

    file.seek(SeekFrom::Start(l1_offset + l1_idx * 8)).unwrap();
    let mut l1_buf = [0u8; 8];
    file.read_exact(&mut l1_buf).unwrap();
    let l2_offset = u64::from_be_bytes(l1_buf) & 0x00FF_FFFF_FFFF_FE00;
    assert!(l2_offset != 0, "L2 table missing");

    file.seek(SeekFrom::Start(l2_offset + l2_idx * 8)).unwrap();
    let mut l2_buf = [0u8; 8];
    file.read_exact(&mut l2_buf).unwrap();
    let data_offset = u64::from_be_bytes(l2_buf) & 0x00FF_FFFF_FFFF_FE00;
    assert!(data_offset != 0, "data cluster missing");

    file.seek(SeekFrom::Start(data_offset)).unwrap();
    let mut buf = vec![0u8; cs as usize];
    file.read_exact(&mut buf).unwrap();
    buf
}
