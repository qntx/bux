//! Safe, high-level API for creating and manipulating ext4 filesystem images.
//!
//! The central type is [`Filesystem`] — an RAII wrapper around `ext2_filsys`
//! that guarantees resource cleanup via [`Drop`]. All unsafe FFI interactions
//! are confined to this module.
//!
//! For common use cases, the module-level convenience functions
//! [`create_from_dir`] and [`inject_file`] compose `Filesystem` operations
//! into single calls.

#![allow(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::ffi::CString;
use std::path::Path;

use crate::error::{Error, Result};
use crate::sys;

/// Block size for an ext4 filesystem.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BlockSize {
    /// 1024 bytes.
    B1024 = 0,
    /// 2048 bytes.
    B2048 = 1,
    /// 4096 bytes (default, recommended).
    B4096 = 2,
}

impl BlockSize {
    /// Returns the block size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::B1024 => 1024,
            Self::B2048 => 2048,
            Self::B4096 => 4096,
        }
    }
}

/// Options for creating a new ext4 filesystem.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    /// Block size (default: 4096).
    pub block_size: BlockSize,
    /// Reserved block percentage, 0–50 (default: 0 for containers).
    pub reserved_ratio: u8,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            block_size: BlockSize::B4096,
            reserved_ratio: 0,
        }
    }
}

/// File type for directory entries (maps to `EXT2_FT_*` constants).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FileType {
    /// Unknown or unspecified file type.
    Unknown = 0,
    /// Regular file.
    RegularFile = 1,
    /// Directory.
    Directory = 2,
    /// Character device.
    CharDevice = 3,
    /// Block device.
    BlockDevice = 4,
    /// Named pipe (FIFO).
    Fifo = 5,
    /// Unix domain socket.
    Socket = 6,
    /// Symbolic link.
    Symlink = 7,
}

/// RAII wrapper around an `ext2_filsys` handle.
///
/// [`Drop`] flushes and closes the filesystem, preventing resource leaks
/// even when operations fail or panic.
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use bux_e2fs::{Filesystem, CreateOptions};
///
/// let mut fs = Filesystem::create(
///     Path::new("/tmp/image.raw"),
///     512 * 1024 * 1024,
///     &CreateOptions::default(),
/// ).unwrap();
/// fs.populate(Path::new("/tmp/rootfs")).unwrap();
/// fs.add_journal().unwrap();
/// // Drop closes the filesystem automatically.
/// ```
pub struct Filesystem {
    /// Raw libext2fs filesystem handle.
    inner: sys::ext2_filsys,
}

impl std::fmt::Debug for Filesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filesystem")
            .field("open", &!self.inner.is_null())
            .finish()
    }
}

impl Drop for Filesystem {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // ext2fs operations (populate_fs, add_journal, etc.) set EXT2_FLAG_DIRTY
            // internally. ext2fs_close checks the flag and flushes if set.
            // We do NOT force-dirty here to avoid flushing partially-initialized images.
            unsafe {
                let _ = sys::ext2fs_close(self.inner);
            }
        }
    }
}

impl Filesystem {
    /// Creates a new ext4 filesystem image at `path`.
    ///
    /// Equivalent to `mke2fs -t ext4 -b <block_size> -m <reserved> <path> <size>`.
    pub fn create(path: &Path, size_bytes: u64, opts: &CreateOptions) -> Result<Self> {
        let c_path = to_cstring(path)?;
        let bs = opts.block_size;
        let blocks = size_bytes / u64::from(bs.bytes());
        let reserved = blocks * u64::from(opts.reserved_ratio) / 100;

        unsafe {
            let mut fs: sys::ext2_filsys = std::ptr::null_mut();
            let mut param: sys::ext2_super_block = std::mem::zeroed();
            param.s_blocks_count = blocks as u32;
            param.s_log_block_size = bs as u32;
            param.s_rev_level = sys::EXT2_DYNAMIC_REV;
            param.s_r_blocks_count = reserved as u32;

            check(
                "ext2fs_initialize",
                sys::ext2fs_initialize(
                    c_path.as_ptr(),
                    sys::EXT2_FLAG_EXCLUSIVE as i32,
                    std::ptr::from_mut(&mut param),
                    sys::unix_io_manager,
                    std::ptr::from_mut(&mut fs),
                ),
            )?;

            // Wrap immediately — Drop guarantees cleanup if allocate_tables fails.
            let this = Self { inner: fs };
            check(
                "ext2fs_allocate_tables",
                sys::ext2fs_allocate_tables(this.inner),
            )?;
            Ok(this)
        }
    }

    /// Opens an existing ext4 image for read-write operations.
    pub fn open(path: &Path) -> Result<Self> {
        let c_path = to_cstring(path)?;

        unsafe {
            let mut fs: sys::ext2_filsys = std::ptr::null_mut();
            check(
                "ext2fs_open",
                sys::ext2fs_open(
                    c_path.as_ptr(),
                    sys::EXT2_FLAG_RW as i32,
                    0,
                    0,
                    sys::unix_io_manager,
                    std::ptr::from_mut(&mut fs),
                ),
            )?;
            Ok(Self { inner: fs })
        }
    }

    /// Populates the filesystem from a host directory.
    ///
    /// Recursively copies all files, directories, symlinks, and permissions
    /// from `source_dir` into the image root.
    pub fn populate(&mut self, source_dir: &Path) -> Result<()> {
        let c_src = to_cstring(source_dir)?;
        unsafe {
            check(
                "populate_fs",
                sys::populate_fs(
                    self.inner,
                    sys::EXT2_ROOT_INO,
                    c_src.as_ptr(),
                    sys::EXT2_ROOT_INO,
                ),
            )
        }
    }

    /// Flushes all pending changes to disk without closing the filesystem.
    pub fn flush(&mut self) -> Result<()> {
        unsafe { check("ext2fs_flush", sys::ext2fs_flush(self.inner)) }
    }

    /// Writes a single host file into the filesystem image.
    ///
    /// Equivalent to `debugfs -w -R "write <host_path> <guest_path>"`.
    pub fn write_file(&mut self, host_path: &Path, guest_path: &str) -> Result<()> {
        let c_host = to_cstring(host_path)?;
        let c_guest = str_to_cstring(guest_path)?;
        unsafe {
            check(
                "do_write_internal",
                sys::do_write_internal(
                    self.inner,
                    sys::EXT2_ROOT_INO,
                    c_host.as_ptr(),
                    c_guest.as_ptr(),
                    sys::EXT2_ROOT_INO,
                ),
            )
        }
    }

    /// Creates a directory inside the filesystem image.
    pub fn mkdir(&mut self, name: &str) -> Result<()> {
        let c_name = str_to_cstring(name)?;
        unsafe {
            check(
                "do_mkdir_internal",
                sys::do_mkdir_internal(
                    self.inner,
                    sys::EXT2_ROOT_INO,
                    c_name.as_ptr(),
                    sys::EXT2_ROOT_INO,
                ),
            )
        }
    }

    /// Creates a symlink inside the filesystem image.
    pub fn symlink(&mut self, name: &str, target: &str) -> Result<()> {
        let c_name = str_to_cstring(name)?;
        let c_target = str_to_cstring(target)?;
        unsafe {
            check(
                "do_symlink_internal",
                sys::do_symlink_internal(
                    self.inner,
                    sys::EXT2_ROOT_INO,
                    c_name.as_ptr(),
                    c_target.as_ptr().cast_mut(),
                    sys::EXT2_ROOT_INO,
                ),
            )
        }
    }

    /// Adds an ext3/4 journal (size auto-calculated by libext2fs).
    pub fn add_journal(&mut self) -> Result<()> {
        unsafe {
            check(
                "ext2fs_add_journal_inode",
                sys::ext2fs_add_journal_inode(self.inner, 0, 0),
            )
        }
    }

    /// Creates a directory entry linking `name` to inode `ino` in directory `dir`.
    pub fn link(&mut self, dir: u32, name: &str, ino: u32, file_type: FileType) -> Result<()> {
        let c_name = str_to_cstring(name)?;
        unsafe {
            check(
                "ext2fs_link",
                sys::ext2fs_link(self.inner, dir, c_name.as_ptr(), ino, file_type as i32),
            )
        }
    }

    /// Reads the on-disk inode structure for the given inode number.
    pub fn read_inode(&self, ino: u32) -> Result<sys::ext2_inode> {
        unsafe {
            let mut inode: sys::ext2_inode = std::mem::zeroed();
            check(
                "ext2fs_read_inode",
                sys::ext2fs_read_inode(self.inner, ino, &raw mut inode),
            )?;
            Ok(inode)
        }
    }

    /// Writes the inode structure back to the filesystem.
    pub fn write_inode(&mut self, ino: u32, inode: &sys::ext2_inode) -> Result<()> {
        unsafe {
            let mut copy = *inode;
            check(
                "ext2fs_write_inode",
                sys::ext2fs_write_inode(self.inner, ino, &raw mut copy),
            )
        }
    }

    /// Writes a freshly allocated inode (initializes the on-disk slot).
    pub fn write_new_inode(&mut self, ino: u32, inode: &sys::ext2_inode) -> Result<()> {
        unsafe {
            let mut copy = *inode;
            check(
                "ext2fs_write_new_inode",
                sys::ext2fs_write_new_inode(self.inner, ino, &raw mut copy),
            )
        }
    }

    /// Allocates a new inode number near `dir` with the given POSIX `mode`.
    ///
    /// Updates the inode bitmap and allocation statistics automatically.
    /// Requires bitmaps to be loaded (always true after [`create`](Self::create)).
    pub fn alloc_inode(&mut self, dir: u32, mode: u16) -> Result<u32> {
        unsafe {
            let mut ino: sys::ext2_ino_t = 0;
            let map = (*self.inner).inode_map;
            check(
                "ext2fs_new_inode",
                sys::ext2fs_new_inode(self.inner, dir, i32::from(mode), map, &raw mut ino),
            )?;
            let is_dir = i32::from(mode & 0o040_000 != 0);
            sys::ext2fs_inode_alloc_stats2(self.inner, ino, 1, is_dir);
            Ok(ino)
        }
    }

    /// Allocates a new block near `goal`.
    ///
    /// Updates the block bitmap and allocation statistics automatically.
    /// Requires bitmaps to be loaded (always true after [`create`](Self::create)).
    pub fn alloc_block(&mut self, goal: u64) -> Result<u64> {
        unsafe {
            let mut blk: sys::blk64_t = 0;
            let map = (*self.inner).block_map;
            check(
                "ext2fs_new_block2",
                sys::ext2fs_new_block2(self.inner, goal, map, &raw mut blk),
            )?;
            sys::ext2fs_block_alloc_stats2(self.inner, blk, 1);
            Ok(blk)
        }
    }
}

/// Creates an ext4 image populated from a host directory.
///
/// This is the primary convenience function combining [`Filesystem::create`],
/// [`Filesystem::populate`], and [`Filesystem::add_journal`].
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
///
/// let size = bux_e2fs::estimate_image_size(Path::new("/tmp/rootfs")).unwrap();
/// bux_e2fs::create_from_dir(
///     Path::new("/tmp/rootfs"),
///     Path::new("/tmp/image.raw"),
///     size,
/// ).unwrap();
/// ```
pub fn create_from_dir(source_dir: &Path, output: &Path, size_bytes: u64) -> Result<()> {
    let mut fs = Filesystem::create(output, size_bytes, &CreateOptions::default())?;
    fs.populate(source_dir)?;
    fs.add_journal()?;
    Ok(())
}

/// Injects a single host file into an existing ext4 image.
///
/// Equivalent to `debugfs -w -R "write <host_file> <guest_path>" <image>`.
pub fn inject_file(image: &Path, host_file: &Path, guest_path: &str) -> Result<()> {
    let mut fs = Filesystem::open(image)?;
    fs.write_file(host_file, guest_path)
}

/// Estimates the required image size for a directory tree.
///
/// Accounts for file content, inode overhead, ext4 metadata, and journal.
/// Returns the recommended image size in bytes (minimum 256 MiB).
pub fn estimate_image_size(dir: &Path) -> Result<u64> {
    let mut total_bytes: u64 = 0;
    let mut inode_count: u64 = 0;

    walk(dir, &mut |meta| {
        inode_count += 1;
        if meta.is_file() {
            // Round up to 4 KiB block boundary.
            total_bytes += (meta.len() + 4095) & !4095;
        } else if meta.is_dir() {
            total_bytes += 4096;
        } else if meta.is_symlink() && meta.len() > 60 {
            // Symlink targets <= 60 bytes are stored inline in the inode.
            // Longer targets need a data block.
            total_bytes += 4096;
        }
    })?;

    // 256 bytes per inode + 10% metadata overhead + 64 MiB journal.
    let raw = total_bytes + inode_count * 256;
    let sized = raw * 11 / 10 + 64 * 1024 * 1024;
    Ok(sized.max(256 * 1024 * 1024))
}

/// Checks a libext2fs `errcode_t`, converting non-zero values to [`Error::Ext2fs`].
const fn check(op: &'static str, code: sys::errcode_t) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Ext2fs {
            op,
            code: code as i64,
        })
    }
}

/// Converts a [`Path`] to a [`CString`].
fn to_cstring(path: &Path) -> Result<CString> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(path.display().to_string()))?;
    CString::new(s).map_err(|e| Error::InvalidPath(e.to_string()))
}

/// Converts a `&str` to a [`CString`].
fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::InvalidPath(e.to_string()))
}

/// Walks a directory tree, calling `f` for each entry's metadata.
/// Uses `symlink_metadata` to avoid following symlinks.
fn walk(dir: &Path, f: &mut impl FnMut(&std::fs::Metadata)) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if let Ok(meta) = path.symlink_metadata() {
            f(&meta);
            if meta.is_dir() {
                walk(&path, f)?;
            }
        }
    }
    Ok(())
}
