//! Safe, high-level API for creating and manipulating ext4 filesystem images.
//!
//! All `unsafe` interactions with [`libext2fs`](crate::sys) are confined to this module.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::Path;

use crate::error::{Error, Result};
use crate::sys;

/// Checks a libext2fs `errcode_t`, converting non-zero values to [`Error::Ext2fs`].
fn check(op: &'static str, code: sys::errcode_t) -> Result<()> {
    if code != 0 {
        Err(Error::Ext2fs {
            op,
            code: code as i64,
        })
    } else {
        Ok(())
    }
}

/// Converts a [`Path`] to a [`CString`], returning [`Error::InvalidPath`] on failure.
fn path_to_cstring(path: &Path) -> Result<CString> {
    let s = path.to_str().ok_or(Error::InvalidPath)?;
    Ok(CString::new(s)?)
}

/// Builder for creating and populating ext4 filesystem images.
///
/// # Example
///
/// ```no_run
/// use bux_e2fs::Ext4Builder;
/// use std::path::Path;
///
/// Ext4Builder::new()
///     .block_size(4096)
///     .reserved_ratio(0)
///     .create_from_dir(
///         Path::new("/tmp/rootfs"),
///         Path::new("/tmp/base.raw"),
///         512 * 1024 * 1024, // 512 MiB
///     )
///     .expect("failed to create ext4 image");
/// ```
#[derive(Debug, Clone)]
pub struct Ext4Builder {
    /// Block size in bytes (must be 1024, 2048, or 4096).
    block_size: u32,
    /// Reserved block percentage (default: 0 for containers).
    reserved_ratio: u8,
    /// Revision level (default: EXT2_DYNAMIC_REV).
    rev_level: u32,
}

impl Default for Ext4Builder {
    fn default() -> Self {
        Self {
            block_size: 4096,
            reserved_ratio: 0,
            rev_level: sys::EXT2_DYNAMIC_REV,
        }
    }
}

impl Ext4Builder {
    /// Creates a new builder with sensible defaults for container use.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the block size in bytes. Must be 1024, 2048, or 4096.
    #[must_use]
    pub const fn block_size(mut self, size: u32) -> Self {
        self.block_size = size;
        self
    }

    /// Sets the reserved block percentage (0–50). Default is 0.
    #[must_use]
    pub const fn reserved_ratio(mut self, pct: u8) -> Self {
        self.reserved_ratio = pct;
        self
    }

    /// Creates an ext4 image populated from `source_dir` and writes it to `output`.
    ///
    /// Equivalent to:
    /// ```sh
    /// mke2fs -t ext4 -d <source_dir> -b 4096 -m 0 -E root_owner=0:0 <output> <size>
    /// ```
    ///
    /// No external tools required — uses `libext2fs` and `populate_fs()` directly.
    pub fn create_from_dir(&self, source_dir: &Path, output: &Path, size_bytes: u64) -> Result<()> {
        let c_output = path_to_cstring(output)?;
        let c_source = path_to_cstring(source_dir)?;

        let blocks = size_bytes / u64::from(self.block_size);
        let log_block_size = match self.block_size {
            1024 => 0_u32,
            2048 => 1,
            4096 => 2,
            _ => {
                return Err(Error::Ext2fs {
                    op: "block_size_validate",
                    code: -1,
                });
            }
        };

        unsafe {
            // 1. Initialize the filesystem structure.
            let mut fs: sys::ext2_filsys = std::ptr::null_mut();
            let mut param: sys::ext2_super_block = std::mem::zeroed();

            param.s_blocks_count = blocks as u32;
            param.s_log_block_size = log_block_size;
            param.s_rev_level = self.rev_level;

            // Reserved blocks: percentage of total blocks.
            let reserved = blocks * u64::from(self.reserved_ratio) / 100;
            param.s_r_blocks_count = reserved as u32;

            check(
                "ext2fs_initialize",
                sys::ext2fs_initialize(
                    c_output.as_ptr(),
                    sys::EXT2_FLAG_EXCLUSIVE as i32,
                    &mut param,
                    sys::unix_io_manager,
                    &mut fs,
                ),
            )?;

            // 2. Allocate block/inode tables.
            check("allocate_tables", sys::ext2fs_allocate_tables(fs))?;

            // 3. Populate from the source directory.
            check(
                "populate_fs",
                sys::populate_fs(
                    fs,
                    sys::EXT2_ROOT_INO,
                    c_source.as_ptr(),
                    sys::EXT2_ROOT_INO,
                ),
            )?;

            // 4. Create the journal (size 0 = auto).
            check("add_journal_inode", sys::ext2fs_add_journal_inode(fs, 0, 0))?;

            // 5. Mark dirty and close.
            sys::ext2fs_mark_super_dirty(fs);
            check("ext2fs_close", sys::ext2fs_close(fs))?;
        }

        Ok(())
    }

    /// Injects a single file from the host into an existing ext4 image.
    ///
    /// Equivalent to `debugfs -w write <host_file> <guest_path>`, but
    /// uses `libext2fs` directly — no external tools.
    ///
    /// The file is written with uid=0, gid=0, mode=0555.
    pub fn inject_file(image: &Path, host_file: &Path, guest_path: &str) -> Result<()> {
        let c_image = path_to_cstring(image)?;
        let c_host = path_to_cstring(host_file)?;
        let c_guest = CString::new(guest_path)?;

        unsafe {
            let mut fs: sys::ext2_filsys = std::ptr::null_mut();

            check(
                "ext2fs_open",
                sys::ext2fs_open(
                    c_image.as_ptr(),
                    sys::EXT2_FLAG_RW as i32,
                    0,
                    0,
                    sys::unix_io_manager,
                    &mut fs,
                ),
            )?;

            // Write the host file into the filesystem image.
            check(
                "do_write_internal",
                sys::do_write_internal(
                    fs,
                    sys::EXT2_ROOT_INO,
                    c_host.as_ptr(),
                    c_guest.as_ptr(),
                    0,
                    sys::EXT2_ROOT_INO,
                ),
            )?;

            // Flush and close.
            check("ext2fs_close", sys::ext2fs_close(fs))?;
        }

        Ok(())
    }
}

/// Estimates the required image size for a directory tree.
///
/// Accounts for file content, inode overhead, ext4 metadata, and journal.
/// Returns the recommended image size in bytes.
pub fn estimate_image_size(dir: &Path) -> Result<u64> {
    let mut total_bytes: u64 = 0;
    let mut entry_count: u64 = 0;

    for entry in walkdir(dir)? {
        entry_count += 1;
        if let Ok(meta) = std::fs::metadata(&entry) {
            if meta.is_file() {
                // Round up to 4KB blocks.
                total_bytes += (meta.len() + 4095) & !4095;
            } else if meta.is_dir() {
                total_bytes += 4096; // At least one block per directory.
            }
        }
    }

    // Inode overhead: 256 bytes per entry.
    let inode_overhead = entry_count * 256;

    // Content + inodes + 10% metadata overhead + 64MB journal.
    let raw = total_bytes + inode_overhead;
    let with_overhead = raw * 11 / 10 + 64 * 1024 * 1024;

    // Minimum 256 MiB.
    Ok(with_overhead.max(256 * 1024 * 1024))
}

/// Simple recursive directory walker (avoids external dependency).
fn walkdir(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    walkdir_inner(dir, &mut paths)?;
    Ok(paths)
}

/// Recursive helper for [`walkdir`].
fn walkdir_inner(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Use symlink_metadata to avoid following symlinks into loops.
        let is_real_dir = path
            .symlink_metadata()
            .map(|m| m.is_dir())
            .unwrap_or(false);
        out.push(path.clone());
        if is_real_dir {
            walkdir_inner(&path, out)?;
        }
    }
    Ok(())
}
