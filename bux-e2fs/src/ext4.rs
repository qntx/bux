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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    inner: sys::ext2_filsys,
}

impl Drop for Filesystem {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                // Mark dirty so ext2fs_close flushes all changes.
                (*self.inner).flags |= (sys::EXT2_FLAG_DIRTY | sys::EXT2_FLAG_CHANGED) as i32;
                let _ = sys::ext2fs_close(self.inner);
            }
            self.inner = std::ptr::null_mut();
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

            check("ext2fs_allocate_tables", sys::ext2fs_allocate_tables(fs))?;

            Ok(Self { inner: fs })
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

    /// Writes a single host file into the filesystem image.
    ///
    /// Equivalent to `debugfs -w -R "write <host_path> <guest_path>"`.
    pub fn write_file(&mut self, host_path: &Path, guest_path: &str) -> Result<()> {
        let c_host = to_cstring(host_path)?;
        let c_guest = CString::new(guest_path).map_err(|e| Error::InvalidPath(e.to_string()))?;
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
        let c_name = CString::new(name).map_err(|e| Error::InvalidPath(e.to_string()))?;
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
        let c_name = CString::new(name).map_err(|e| Error::InvalidPath(e.to_string()))?;
        let c_target = CString::new(target).map_err(|e| Error::InvalidPath(e.to_string()))?;
        unsafe {
            check(
                "do_symlink_internal",
                sys::do_symlink_internal(
                    self.inner,
                    sys::EXT2_ROOT_INO,
                    c_name.as_ptr(),
                    c_target.as_ptr() as *mut _,
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
        Err(Error::Ext2fs { op, code })
    }
}

/// Converts a [`Path`] to a [`CString`].
fn to_cstring(path: &Path) -> Result<CString> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(path.display().to_string()))?;
    CString::new(s).map_err(|e| Error::InvalidPath(e.to_string()))
}

/// Walks a directory tree, calling `f` for each entry's metadata.
/// Uses `symlink_metadata` to avoid following symlinks.
fn walk(dir: &Path, f: &mut impl FnMut(std::fs::Metadata)) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if let Ok(meta) = path.symlink_metadata() {
            f(meta.clone());
            if meta.is_dir() {
                walk(&path, f)?;
            }
        }
    }
    Ok(())
}
