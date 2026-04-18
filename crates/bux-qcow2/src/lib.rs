//! Pure-Rust operations on QCOW2 v3 images.
//!
//! bux-qcow2 is a small, dependency-minimal library for the QCOW2 operations
//! bux needs to manage per-VM copy-on-write disks:
//!
//! - [`create_overlay`] — write a 256 KiB COW overlay pointing at a backing file.
//! - [`read_header`] — parse a QCOW2 header into a structured [`Header`].
//! - [`read_backing_file`] / [`read_backing_chain`] — walk a backing chain.
//! - [`is_backing_dependency`] — check whether a file is in another image's chain.
//! - [`flatten`] — merge a QCOW2 + backing chain into a standalone QCOW2.
//! - [`resize`] — change the virtual size (delegated to `qemu-img`).
//!
//! The crate is `#![no_std]`-compatible in spirit but uses `std::fs` and
//! `std::process` so is built as a plain `std` library. It has no runtime
//! dependencies beyond `thiserror`.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use bux_qcow2::{BackingFormat, create_overlay, read_header};
//!
//! // Create a 1 GiB COW overlay that reads through to `/data/base.raw`.
//! create_overlay(
//!     Path::new("/tmp/overlay.qcow2"),
//!     "/data/base.raw",
//!     BackingFormat::Raw,
//!     1 << 30,
//! ).unwrap();
//!
//! let hdr = read_header(Path::new("/tmp/overlay.qcow2")).unwrap();
//! assert_eq!(hdr.virtual_size, 1 << 30);
//! assert_eq!(hdr.backing_file.as_deref(), Some("/data/base.raw"));
//! ```
//!
//! # Format scope
//!
//! Only QCOW2 v3 is produced by [`create_overlay`] and [`flatten`].
//! [`read_header`] also accepts v2 images for read-only inspection.
//! Compressed clusters (L2 entry bit 62) are rejected — bux never creates
//! them and does not need to support them.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod chain;
mod error;
mod format;
mod header;
mod ops;
mod overlay;

pub use chain::{
    DEFAULT_MAX_CHAIN_DEPTH, is_backing_dependency, read_backing_chain,
    read_backing_chain_with_depth, read_backing_file,
};
pub use error::{Error, Result};
pub use format::BackingFormat;
pub use header::{Header, read_header};
pub use ops::{flatten, resize};
pub use overlay::create_overlay;

/// QCOW2 format version produced by the write-path APIs.
pub const FORMAT_VERSION: u32 = 3;

/// `tempfile` is only used by integration tests (`tests/*.rs`). Re-use it
/// here under `cfg(test)` so the workspace lint does not flag it when the
/// lib's own unit tests run.
#[cfg(test)]
use tempfile as _;
