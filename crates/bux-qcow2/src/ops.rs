//! Heavy operations: flatten and resize.
//!
//! - [`flatten`] merges a QCOW2 backing chain into a single standalone
//!   QCOW2 file. Implemented in pure Rust.
//! - [`resize`] changes the virtual size of a QCOW2 image. Delegates to
//!   `qemu-img resize` because a correct in-place resize needs full
//!   L1/L2/refcount rewriting — a future revision may replace this with
//!   a native implementation.

#![allow(
    clippy::cast_possible_truncation,
    reason = "QCOW2 cluster sizes (max 2^30) fit in usize on every supported platform; \
              virtual_size/cluster bounds are validated by open_chain"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "flatten is a binary-format rewriter; every index is derived from validated sizes"
)]

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::format::{
    HEADER_LENGTH, L2_COMPRESSED_BIT, L2_OFFSET_MASK, MAGIC, REFCOUNT_ORDER, VERSION, read_be_u32,
    read_be_u64, write_be_u32, write_be_u64,
};

/// Resize the virtual size of a QCOW2 image via `qemu-img resize`.
///
/// This shells out to `qemu-img` because an in-place resize requires
/// rewriting the L1/L2 tables plus refcount book-keeping, which bux does
/// not yet implement natively.
///
/// # Errors
///
/// - [`Error::QemuImgNotFound`] if `qemu-img` is not on `PATH`.
/// - [`Error::QemuImgFailed`] if the subprocess exits non-zero.
/// - [`Error::Io`] for other I/O failures.
pub fn resize(path: &Path, new_size: u64) -> Result<()> {
    let output = Command::new("qemu-img")
        .args(["resize", "-f", "qcow2"])
        .arg(path)
        .arg(new_size.to_string())
        .output()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::QemuImgNotFound
            } else {
                Error::Io(e)
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::QemuImgFailed(stderr.trim().to_owned()));
    }
    Ok(())
}

/// Flatten `src` (a QCOW2 image) and its entire backing chain into a new
/// standalone QCOW2 at `dst`.
///
/// The resulting image has no backing file. Zero clusters are elided so
/// the output is sparse.
///
/// # Errors
///
/// - [`Error::NotQcow2`] if `src` is not QCOW2.
/// - [`Error::CompressedUnsupported`] if a compressed cluster is encountered.
/// - [`Error::Io`] on any I/O failure.
#[allow(
    clippy::too_many_lines,
    reason = "cohesive algorithm — splitting adds more noise than it removes"
)]
pub fn flatten(src: &Path, dst: &Path) -> Result<()> {
    let mut chain = open_chain(src)?;

    let (virtual_size, cluster_bits) = match chain.first() {
        Some(Layer::Qcow2 {
            virtual_size,
            cluster_bits,
            ..
        }) => (*virtual_size, *cluster_bits),
        _ => return Err(Error::NotQcow2),
    };

    let cluster_size = 1u64 << cluster_bits;
    let num_virtual_clusters = virtual_size.div_ceil(cluster_size);
    let l2_entries = cluster_size / 8;
    let num_l1 = num_virtual_clusters.div_ceil(l2_entries) as u32;
    let l1_clusters = (u64::from(num_l1) * 8).div_ceil(cluster_size);

    let l2_start = 1 + l1_clusters;
    let data_start = l2_start + u64::from(num_l1);

    let mut output = File::create(dst)?;
    let zero_cluster = vec![0u8; cluster_size as usize];

    let mut l2_tables: Vec<Vec<u64>> = vec![vec![0u64; l2_entries as usize]; num_l1 as usize];
    let mut next_data = data_start;

    for vc in 0..num_virtual_clusters {
        let mut data: Option<Vec<u8>> = None;
        for layer in &mut chain {
            if let Some(d) = layer.read_cluster(vc, cluster_size)? {
                data = Some(d);
                break;
            }
        }
        if let Some(d) = data {
            if d.as_slice() == zero_cluster.as_slice() {
                continue;
            }
            let offset = next_data * cluster_size;
            output.seek(SeekFrom::Start(offset))?;
            output.write_all(&d)?;

            let l1_idx = (vc / l2_entries) as usize;
            let l2_idx = (vc % l2_entries) as usize;
            l2_tables[l1_idx][l2_idx] = offset;
            next_data += 1;
        }
    }

    let rc_entries_per_block = cluster_size / 2;
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

    output.seek(SeekFrom::Start(cluster_size))?;
    for (i, l2) in l2_tables.iter().enumerate() {
        let entry: u64 = if l2.iter().any(|&e| e != 0) {
            (l2_start + i as u64) * cluster_size
        } else {
            0
        };
        output.write_all(&entry.to_be_bytes())?;
    }

    for (i, l2) in l2_tables.iter().enumerate() {
        if l2.iter().all(|&e| e == 0) {
            continue;
        }
        output.seek(SeekFrom::Start((l2_start + i as u64) * cluster_size))?;
        for entry in l2 {
            output.write_all(&entry.to_be_bytes())?;
        }
    }

    output.seek(SeekFrom::Start(rc_table_offset))?;
    for i in 0..num_rc_blocks {
        let block_offset = (rc_block_start + i) * cluster_size;
        output.write_all(&block_offset.to_be_bytes())?;
    }

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

    output.seek(SeekFrom::Start(0))?;
    let mut hdr = [0u8; 112];
    write_be_u32(&mut hdr, 0, MAGIC);
    write_be_u32(&mut hdr, 4, VERSION);
    write_be_u32(&mut hdr, 20, cluster_bits);
    write_be_u64(&mut hdr, 24, virtual_size);
    write_be_u32(&mut hdr, 36, num_l1);
    write_be_u64(&mut hdr, 40, cluster_size);
    write_be_u64(&mut hdr, 48, rc_table_offset);
    write_be_u32(&mut hdr, 56, 1);
    write_be_u32(&mut hdr, 96, REFCOUNT_ORDER);
    write_be_u32(&mut hdr, 100, HEADER_LENGTH);
    output.write_all(&hdr)?;
    output.sync_all()?;
    Ok(())
}

/// One layer in a backing chain loaded for [`flatten`].
///
/// Kept private — callers who need to traverse the chain should use the
/// higher-level helpers in [`crate::chain`].
#[derive(Debug)]
enum Layer {
    /// A QCOW2 image; `l1_table` is read up-front so cluster lookups are
    /// just an L2 seek.
    Qcow2 {
        /// Open file handle positioned arbitrarily between reads.
        file: File,
        /// `log2(cluster_size)` (9..=30).
        cluster_bits: u32,
        /// Virtual disk size exposed to the guest, in bytes.
        virtual_size: u64,
        /// Copy of the L1 table (each entry = physical offset of an L2 table).
        l1_table: Vec<u64>,
    },
    /// A raw image, treated as the terminal layer of the chain.
    Raw {
        /// Open file handle.
        file: File,
        /// File length in bytes.
        size: u64,
    },
}

impl Layer {
    /// Fetch the bytes for virtual cluster `vc`.
    ///
    /// `None` means "not allocated on this layer" — the caller should fall
    /// through to the next one. `Some(bytes)` is always exactly
    /// `cluster_size` long (zero-padded for the tail of a raw image).
    fn read_cluster(&mut self, vc: u64, cluster_size: u64) -> Result<Option<Vec<u8>>> {
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

                let Some(&l1_entry) = l1_table.get(l1_idx) else {
                    return Ok(None);
                };

                let l2_offset = l1_entry & L2_OFFSET_MASK;
                if l2_offset == 0 {
                    return Ok(None);
                }

                file.seek(SeekFrom::Start(l2_offset + l2_idx * 8))?;
                let mut entry_buf = [0u8; 8];
                file.read_exact(&mut entry_buf)?;
                let l2_entry = u64::from_be_bytes(entry_buf);

                if l2_entry & L2_COMPRESSED_BIT != 0 {
                    return Err(Error::CompressedUnsupported);
                }

                let data_offset = l2_entry & L2_OFFSET_MASK;
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

/// Open every layer of the backing chain rooted at `path`.
///
/// Returned in top-down order (top layer first, base image last). Stops
/// at the first non-QCOW2 file (treated as a raw base) or when a QCOW2
/// header has no backing-file entry.
fn open_chain(path: &Path) -> Result<Vec<Layer>> {
    let mut chain = Vec::new();
    let mut current = path.to_path_buf();

    loop {
        let mut file = File::open(&current)?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf)?;
        let magic = u32::from_be_bytes(magic_buf);

        if magic != MAGIC {
            let size = file.metadata()?.len();
            chain.push(Layer::Raw { file, size });
            break;
        }

        let mut hdr = [0u8; 104];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut hdr)?;

        let bf_offset = read_be_u64(&hdr, 8);
        let bf_size = read_be_u32(&hdr, 16) as usize;
        let cluster_bits = read_be_u32(&hdr, 20);
        let virtual_size = read_be_u64(&hdr, 24);
        let l1_size = read_be_u32(&hdr, 36) as usize;
        let l1_offset = read_be_u64(&hdr, 40);

        file.seek(SeekFrom::Start(l1_offset))?;
        let mut l1_buf = vec![0u8; l1_size * 8];
        file.read_exact(&mut l1_buf)?;
        let l1_table: Vec<u64> = l1_buf
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect();

        let backing = if bf_offset != 0 && bf_size != 0 {
            file.seek(SeekFrom::Start(bf_offset))?;
            let mut buf = vec![0u8; bf_size];
            file.read_exact(&mut buf)?;
            Some(String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?)
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
            Some(bp) => current = PathBuf::from(bp),
            None => break,
        }
    }
    Ok(chain)
}
