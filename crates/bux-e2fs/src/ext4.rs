//! Safe, high-level API for creating and manipulating ext4 filesystem images.
//!
//! The central type is [`Filesystem`] — an RAII wrapper around `ext2_filsys`
//! that guarantees resource cleanup via [`Drop`]. All unsafe FFI interactions
//! are confined to this module.
//!
//! For common use cases, the module-level convenience functions
//! [`create_from_dir`] and [`inject_file`] compose `Filesystem` operations
//! into single calls.

#![allow(unsafe_code, reason = "FFI wrapper over libext2fs")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "ext4 sizes require casts between i/u 32/64"
)]
#![allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    reason = "FFI calls to libext2fs are inherently unsafe with sequential operations"
)]

use std::ffi::CString;
use std::fs::OpenOptions;
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
    ///
    /// # Errors
    ///
    /// Returns an error if I/O, path conversion, or libext2fs initialization fails.
    pub fn create(path: &Path, size_bytes: u64, opts: &CreateOptions) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let image = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        image.set_len(size_bytes)?;
        drop(image);

        let c_path = to_cstring(path)?;
        let bs = opts.block_size;
        let blocks = size_bytes / u64::from(bs.bytes());
        let reserved = blocks * u64::from(opts.reserved_ratio) / 100;

        unsafe {
            let mut fs: sys::ext2_filsys = std::ptr::null_mut();
            let mut param: sys::ext2_super_block = std::mem::zeroed();
            param.s_blocks_count = blocks as u32;
            param.s_blocks_count_hi = (blocks >> 32) as u32;
            param.s_log_block_size = bs as u32;
            param.s_rev_level = sys::EXT2_DYNAMIC_REV;
            param.s_r_blocks_count = reserved as u32;
            param.s_r_blocks_count_hi = (reserved >> 32) as u32;

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
            check(
                "ext2fs_mkdir(root)",
                sys::ext2fs_mkdir(
                    this.inner,
                    sys::EXT2_ROOT_INO,
                    sys::EXT2_ROOT_INO,
                    std::ptr::null(),
                ),
            )?;
            Ok(this)
        }
    }

    /// Opens an existing ext4 image for read-write operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the image does not exist or libext2fs fails to open it.
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
    ///
    /// # Errors
    ///
    /// Returns an error if path conversion or the populate operation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the flush I/O fails.
    pub fn flush(&mut self) -> Result<()> {
        unsafe { check("ext2fs_flush", sys::ext2fs_flush(self.inner)) }
    }

    /// Writes a single host file into the filesystem image.
    ///
    /// Equivalent to `debugfs -w -R "write <host_path> <guest_path>"`.
    ///
    /// # Errors
    ///
    /// Returns an error if path conversion or the write operation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the mkdir operation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink creation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if journal size calculation or creation fails.
    pub fn add_journal(&mut self) -> Result<()> {
        unsafe {
            let superblock = (*self.inner).super_;
            let blocks = u64::from((*superblock).s_blocks_count)
                | (u64::from((*superblock).s_blocks_count_hi) << 32);
            let journal_blocks = sys::ext2fs_default_journal_size(blocks);
            if journal_blocks <= 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "ext2fs_default_journal_size returned {journal_blocks} for filesystem with {blocks} blocks"
                    ),
                )));
            }
            check(
                "ext2fs_add_journal_inode",
                sys::ext2fs_add_journal_inode(self.inner, journal_blocks as u32, 0),
            )
        }
    }

    /// Creates a directory entry linking `name` to inode `ino` in directory `dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the link operation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the inode read fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the inode write fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the inode write fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if inode allocation fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if block allocation fails.
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

/// Fluent builder for creating ext4 images with custom [`CreateOptions`].
///
/// Chains `block_size`, `reserved_ratio`, and `add_journal` into a single
/// expression, then finishes with [`Ext4Builder::create_from_dir`]. For
/// the common "build an image from a rootfs" case, [`create_from_dir`]
/// keeps the call-site to one line by using default options.
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use bux_e2fs::{BlockSize, Ext4Builder};
///
/// Ext4Builder::new()
///     .block_size(BlockSize::B4096)
///     .reserved_ratio(0)
///     .create_from_dir(
///         Path::new("/tmp/rootfs"),
///         Path::new("/tmp/base.raw"),
///         512 * 1024 * 1024,
///     )
///     .unwrap();
/// ```
#[derive(Debug, Clone, Copy)]
#[must_use = "Ext4Builder does nothing until you call `.create_from_dir()`"]
pub struct Ext4Builder {
    /// Underlying options passed to [`Filesystem::create`].
    opts: CreateOptions,
    /// Whether to create a journal (enabled → ext4, disabled → ext2).
    journal: bool,
}

impl Default for Ext4Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ext4Builder {
    /// Start a new builder with default options: 4 KiB blocks, 0 % reserved,
    /// journal enabled (`ext4`).
    pub const fn new() -> Self {
        Self {
            opts: CreateOptions {
                block_size: BlockSize::B4096,
                reserved_ratio: 0,
            },
            journal: true,
        }
    }

    /// Set the block size (default: 4 KiB).
    pub const fn block_size(mut self, size: BlockSize) -> Self {
        self.opts.block_size = size;
        self
    }

    /// Set the reserved-block percentage (default: 0). The kernel
    /// clamps this to `0..=50`; values above 50 are rejected by
    /// libext2fs at create time.
    pub const fn reserved_ratio(mut self, pct: u8) -> Self {
        self.opts.reserved_ratio = pct;
        self
    }

    /// Toggle journal creation. Default is `true` (ext4); set to
    /// `false` to produce an ext2 image.
    pub const fn add_journal(mut self, enabled: bool) -> Self {
        self.journal = enabled;
        self
    }

    /// Build the image at `output` populated from the `source_dir`
    /// rootfs, with the configured options.
    ///
    /// # Errors
    ///
    /// Returns an error if image creation, optional journal setup, or
    /// population fails.
    pub fn create_from_dir(self, source_dir: &Path, output: &Path, size_bytes: u64) -> Result<()> {
        let mut fs = Filesystem::create(output, size_bytes, &self.opts)?;
        if self.journal {
            fs.add_journal()?;
        }
        fs.populate(source_dir)?;
        Ok(())
    }
}

/// Create an ext4 image populated from a host directory with default options.
///
/// Equivalent to:
/// ```text
/// Ext4Builder::new().create_from_dir(source_dir, output, size_bytes)
/// ```
///
/// Use [`Ext4Builder`] if you need to customise block size, reserved
/// ratio, or journal creation.
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
///
/// # Errors
///
/// Returns an error if image creation, journal setup, or population fails.
pub fn create_from_dir(source_dir: &Path, output: &Path, size_bytes: u64) -> Result<()> {
    Ext4Builder::new().create_from_dir(source_dir, output, size_bytes)
}

/// Inject a single host file into an existing ext4 image.
///
/// Equivalent to `debugfs -w -R "write <host_file> <guest_path>"`.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or the write fails.
pub fn inject_file(image: &Path, host_file: &Path, guest_path: &str) -> Result<()> {
    let mut fs = Filesystem::open(image)?;
    fs.write_file(host_file, guest_path)
}

/// Estimates the required image size for a directory tree.
///
/// Accounts for file content, inode overhead, ext4 metadata, and journal.
/// Returns the recommended image size in bytes (minimum 256 MiB).
///
/// # Errors
///
/// Returns an error if directory traversal fails.
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

/// Converts a `&str` to a [`CString`].
fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::InvalidPath(e.to_string()))
}

/// Walks a directory tree, calling `f` for each entry's metadata.
/// Uses `symlink_metadata` to avoid following symlinks.
fn walk(dir: &Path, f: &mut impl FnMut(&std::fs::Metadata)) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let meta = path.symlink_metadata()?;
        f(&meta);
        if meta.is_dir() {
            walk(&path, f)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn block_size_bytes_match_log_levels() {
        assert_eq!(BlockSize::B1024.bytes(), 1024);
        assert_eq!(BlockSize::B2048.bytes(), 2048);
        assert_eq!(BlockSize::B4096.bytes(), 4096);
    }

    #[test]
    fn default_create_options_are_container_friendly() {
        let opts = CreateOptions::default();
        assert_eq!(opts.block_size, BlockSize::B4096);
        assert_eq!(opts.reserved_ratio, 0);
    }

    #[test]
    fn builder_default_matches_new() {
        let a = Ext4Builder::new();
        let b = Ext4Builder::default();
        assert_eq!(a.opts.block_size, b.opts.block_size);
        assert_eq!(a.opts.reserved_ratio, b.opts.reserved_ratio);
        assert_eq!(a.journal, b.journal);
    }

    #[test]
    fn builder_chain_applies_options() {
        let b = Ext4Builder::new()
            .block_size(BlockSize::B1024)
            .reserved_ratio(5)
            .add_journal(false);
        assert_eq!(b.opts.block_size, BlockSize::B1024);
        assert_eq!(b.opts.reserved_ratio, 5);
        assert!(!b.journal);
    }

    #[test]
    fn builder_journal_defaults_to_true() {
        let b = Ext4Builder::new();
        assert!(b.journal, "default should produce ext4 (with journal)");
    }
}
