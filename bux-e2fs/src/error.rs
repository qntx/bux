//! Error types for ext4 filesystem operations.

/// Errors returned by ext4 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A libext2fs function returned a non-zero error code.
    #[error("{op}: {}", describe_ext2fs_error(*.code))]
    Ext2fs {
        /// Name of the libext2fs operation that failed.
        op: &'static str,
        /// The raw `errcode_t` value.
        code: i64,
    },

    /// A path could not be converted to a C string.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// An I/O error occurred outside of libext2fs.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Maps common libext2fs error codes to human-readable descriptions.
///
/// Error codes are defined in `ext2_err.h` (base 2133571328 = 0x7F2C0000).
fn describe_ext2fs_error(code: i64) -> String {
    // ext2fs error table base: EXT2_ET_BASE = 2133571328
    const BASE: i64 = 2_133_571_328;
    match code - BASE {
        1 => "bad magic number in superblock".into(),
        2 => "filesystem revision too high".into(),
        4 => "illegal block number".into(),
        5 => "illegal inode number".into(),
        6 => "internal error in ext2fs_open_icount".into(),
        7 => "cannot write to an fs opened read-only".into(),
        8 => "block bitmap not loaded".into(),
        9 => "inode bitmap not loaded".into(),
        10 => "no free blocks".into(),
        11 => "no free inodes".into(),
        12 => "directory block not found".into(),
        16 => "inode already allocated".into(),
        17 => "block already allocated".into(),
        22 => "filesystem not open".into(),
        23 => "device is read-only".into(),
        24 => "directory corrupted".into(),
        25 => "short read".into(),
        26 => "short write".into(),
        28 => "filesystem too large".into(),
        _ => format!("libext2fs error {code:#x}"),
    }
}
