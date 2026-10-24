//! Safe OCI layer extraction for bux.
//!
//! [`Extractor`] applies image layer tarballs to a directory in order, with
//! OCI whiteout semantics; [`extract_layer_files`] does the same for layer
//! files on disk. Every member path is resolved inside the destination root:
//! symlinks are followed there and absolute targets are re-anchored at the
//! root, so a crafted layer cannot write or delete outside it. On Linux the
//! resolver uses `pathrs`.
//!
//! [`Options::keep_owners`] keeps the owners and extended attributes from the
//! tar headers, for an extractor that runs as root. [`scan`] reports what a
//! layer would create without writing it, so a filesystem can be sized first.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "internal modules have self-explanatory fields"
)]

mod error;
mod extract;
mod safe_root;
mod scan;

pub use error::{Error, Result};
pub use extract::{Extractor, Options, extract_layer_files};
pub use scan::{Member, scan};
