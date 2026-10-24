//! Layer scan: what extraction would create, without writing anything.

use std::io::{BufReader, Read};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use crate::Result;
use crate::extract::{is_gzip, whiteout};
use crate::safe_root::SafeRoot;

/// A member that extraction would create, as reported by [`scan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    /// A directory.
    Dir,
    /// A regular file.
    File {
        /// Data size in bytes.
        size: u64,
    },
    /// A symbolic link.
    Symlink {
        /// Length of the link target in bytes.
        target_len: u64,
    },
    /// A hard link to another member.
    Hardlink,
}

/// Streams one layer and calls `visit` for each member that an
/// [`Extractor`](crate::Extractor) would create.
///
/// As in extraction, the reader is buffered here, a gzip `media_type` selects
/// gzip decompression, and whiteouts, device nodes, FIFOs and paths above the
/// root are skipped. Whiteouts are not applied either, so the members of all
/// layers add up to an upper bound of the extracted tree.
///
/// # Errors
///
/// Returns an error if the layer cannot be read or decompressed.
pub fn scan(layer: impl Read, media_type: &str, mut visit: impl FnMut(Member)) -> Result<()> {
    let layer = BufReader::new(layer);
    if is_gzip(media_type) {
        scan_tar(GzDecoder::new(layer), &mut visit)
    } else {
        scan_tar(layer, &mut visit)
    }
}

fn scan_tar(tar: impl Read, visit: &mut impl FnMut(Member)) -> Result<()> {
    let mut archive = Archive::new(tar);
    for entry in archive.entries()? {
        let entry = entry?;
        let Some(rel) = SafeRoot::normalize(&entry.path()?) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let entry_type = entry.header().entry_type();
        let member = match entry_type {
            EntryType::Directory => Member::Dir,
            EntryType::Regular | EntryType::GNUSparse | EntryType::Continuous => {
                if whiteout(entry_type, &rel).is_some() {
                    continue;
                }
                Member::File { size: entry.size() }
            }
            EntryType::Symlink => Member::Symlink {
                target_len: entry
                    .link_name_bytes()
                    .map_or(0, |target| target.len() as u64),
            },
            EntryType::Link => Member::Hardlink,
            _ => continue,
        };
        visit(member);
    }
    Ok(())
}
