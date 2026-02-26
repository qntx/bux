// Placeholder bindings for bux-e2fs.
//
// These declarations will be replaced by bindgen-generated output once the CI
// pipeline produces the e2fsprogs static libraries and headers.  Until then,
// they provide correct type signatures so that downstream code compiles on all
// platforms (including unsupported ones where the library is not linked).
//
// IMPORTANT: Do NOT edit manually once real bindgen output is committed.
//
// Source headers:
//   - lib/ext2fs/ext2fs.h   (libext2fs core)
//   - lib/ext2fs/ext2_fs.h  (on-disk structures)
//   - lib/et/com_err.h      (error code type)
//   - misc/create_inode.h   (populate_fs)
//
// Reference: e2fsprogs v1.47.1 — https://github.com/tytso/e2fsprogs

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Primitive type aliases
// ---------------------------------------------------------------------------

/// Error code returned by libext2fs functions. Zero means success.
pub type errcode_t = core::ffi::c_long;

/// Inode number (32-bit).
pub type ext2_ino_t = u32;

/// Block number (32-bit, legacy).
pub type blk_t = u32;

/// Block number (64-bit).
pub type blk64_t = u64;

/// Block group descriptor index.
pub type dgrp_t = u32;

// ---------------------------------------------------------------------------
// Opaque pointer types
// ---------------------------------------------------------------------------

/// Opaque filesystem handle.  `struct struct_ext2_filsys *`.
pub type ext2_filsys = *mut core::ffi::c_void;

/// Opaque I/O manager. `struct struct_io_manager *`.
pub type io_manager = *mut core::ffi::c_void;

/// Opaque inode bitmap.
pub type ext2fs_inode_bitmap = *mut core::ffi::c_void;

/// Opaque block bitmap.
pub type ext2fs_block_bitmap = *mut core::ffi::c_void;

// ---------------------------------------------------------------------------
// On-disk structures (stable ABI — ext4 specification)
// ---------------------------------------------------------------------------

/// The ext2/3/4 superblock (1024 bytes, on-disk layout).
///
/// Field layout follows `linux/ext2_fs.h` / `e2fsprogs/lib/ext2fs/ext2_fs.h`.
/// All multi-byte fields are stored in native byte order in memory;
/// libext2fs handles endian conversion to/from disk.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ext2_super_block {
    pub s_inodes_count: u32,
    pub s_blocks_count: u32,
    pub s_r_blocks_count: u32,
    pub s_free_blocks_count: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: i16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // --- EXT2_DYNAMIC_REV fields ---
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    // --- Journal fields ---
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    // --- 64-bit fields ---
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_update_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_checksum_type: u8,
    pub s_encryption_level: u8,
    pub s_reserved_pad: u8,
    pub s_kbytes_written: u64,
    pub s_snapshot_inum: u32,
    pub s_snapshot_id: u32,
    pub s_snapshot_r_blocks_count: u64,
    pub s_snapshot_list: u32,
    pub s_error_count: u32,
    pub s_first_error_time: u32,
    pub s_first_error_ino: u32,
    pub s_first_error_block: u64,
    pub s_first_error_func: [u8; 32],
    pub s_first_error_line: u32,
    pub s_last_error_time: u32,
    pub s_last_error_ino: u32,
    pub s_last_error_line: u32,
    pub s_last_error_block: u64,
    pub s_last_error_func: [u8; 32],
    pub s_mount_opts: [u8; 64],
    pub s_usr_quota_inum: u32,
    pub s_grp_quota_inum: u32,
    pub s_overhead_blocks: u32,
    pub s_backup_bgs: [u32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: u32,
    pub s_prj_quota_inum: u32,
    pub s_checksum_seed: u32,
    pub s_wtime_hi: u8,
    pub s_mtime_hi: u8,
    pub s_mkfs_time_hi: u8,
    pub s_lastcheck_hi: u8,
    pub s_first_error_time_hi: u8,
    pub s_last_error_time_hi: u8,
    pub s_first_error_errcode: u8,
    pub s_last_error_errcode: u8,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    pub s_orphan_file_inum: u32,
    /// Padding to 1024 bytes.
    pub s_reserved: [u32; 94],
    pub s_checksum: u32,
}

/// The ext2 inode structure (128 bytes, on-disk layout).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ext2_inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks: u32,
    pub i_flags: u32,
    pub osd1: u32,
    pub i_block: [u32; 15],
    pub i_generation: u32,
    pub i_file_acl: u32,
    pub i_size_high: u32,
    pub i_faddr: u32,
    pub osd2: [u8; 12],
}

/// Hardlink tracking entry for `populate_fs`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct hdlink_s {
    pub src_dev: u64,
    pub src_ino: u64,
    pub dst_ino: ext2_ino_t,
}

/// Hardlink tracking list for `populate_fs`.
#[repr(C)]
#[derive(Debug)]
pub struct hdlinks_s {
    pub count: core::ffi::c_int,
    pub size: core::ffi::c_int,
    pub hdl: *mut hdlink_s,
}

/// Callback hooks for `populate_fs2` / `populate_fs3`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct fs_ops_callbacks {
    pub create_new_inode: Option<
        unsafe extern "C" fn(
            ext2_filsys,
            *const core::ffi::c_char,
            *const core::ffi::c_char,
            ext2_ino_t,
            ext2_ino_t,
            u32,
        ) -> errcode_t,
    >,
    pub end_create_new_inode: Option<
        unsafe extern "C" fn(
            ext2_filsys,
            *const core::ffi::c_char,
            *const core::ffi::c_char,
            ext2_ino_t,
            ext2_ino_t,
            u32,
        ) -> errcode_t,
    >,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Root directory inode number.
pub const EXT2_ROOT_INO: ext2_ino_t = 2;

/// Filesystem revision: original (fixed inode sizes).
pub const EXT2_GOOD_OLD_REV: u32 = 0;

/// Filesystem revision: dynamic (variable inode sizes, features).
pub const EXT2_DYNAMIC_REV: u32 = 1;

/// Default inode size for GOOD_OLD_REV.
pub const EXT2_GOOD_OLD_INODE_SIZE: u32 = 128;

// Filesystem open flags.
pub const EXT2_FLAG_RW: u32 = 0x01;
pub const EXT2_FLAG_CHANGED: u32 = 0x02;
pub const EXT2_FLAG_DIRTY: u32 = 0x04;
pub const EXT2_FLAG_VALID: u32 = 0x08;
pub const EXT2_FLAG_IB_DIRTY: u32 = 0x10;
pub const EXT2_FLAG_BB_DIRTY: u32 = 0x20;
pub const EXT2_FLAG_SWAP_BYTES: u32 = 0x40;
pub const EXT2_FLAG_64BITS: u32 = 0x20000;
pub const EXT2_FLAG_EXCLUSIVE: u32 = 0x4000;

// File type constants for ext2fs_link().
pub const EXT2_FT_UNKNOWN: u32 = 0;
pub const EXT2_FT_REG_FILE: u32 = 1;
pub const EXT2_FT_DIR: u32 = 2;
pub const EXT2_FT_CHRDEV: u32 = 3;
pub const EXT2_FT_BLKDEV: u32 = 4;
pub const EXT2_FT_FIFO: u32 = 5;
pub const EXT2_FT_SOCK: u32 = 6;
pub const EXT2_FT_SYMLINK: u32 = 7;

// Flags for populate_fs3().
pub const POPULATE_FS_NO_COPY_XATTRS: u32 = 0x0001;
pub const POPULATE_FS_LINK_APPEND: u32 = 0x0002;

// ---------------------------------------------------------------------------
// Extern functions — libext2fs
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // --- IO manager ---

    /// The Unix file-backed I/O manager.
    pub static unix_io_manager: io_manager;

    // --- Filesystem lifecycle ---

    /// Creates a new ext2/3/4 filesystem.
    pub fn ext2fs_initialize(
        name: *const core::ffi::c_char,
        flags: core::ffi::c_int,
        param: *mut ext2_super_block,
        manager: io_manager,
        ret_fs: *mut ext2_filsys,
    ) -> errcode_t;

    /// Opens an existing ext2/3/4 filesystem image.
    pub fn ext2fs_open(
        name: *const core::ffi::c_char,
        flags: core::ffi::c_int,
        superblock: core::ffi::c_int,
        block_size: core::ffi::c_uint,
        manager: io_manager,
        ret_fs: *mut ext2_filsys,
    ) -> errcode_t;

    /// Flushes pending writes to the filesystem image.
    pub fn ext2fs_flush(fs: ext2_filsys) -> errcode_t;

    /// Flushes and closes the filesystem, freeing all resources.
    pub fn ext2fs_close(fs: ext2_filsys) -> errcode_t;

    /// Allocates block group descriptor tables, inode tables, and bitmaps.
    pub fn ext2fs_allocate_tables(fs: ext2_filsys) -> errcode_t;

    /// Creates an internal journal inode. `num_blocks=0` means auto-size.
    pub fn ext2fs_add_journal_inode(
        fs: ext2_filsys,
        num_blocks: blk_t,
        flags: core::ffi::c_int,
    ) -> errcode_t;

    /// Marks the superblock as dirty (will be flushed on close).
    pub fn ext2fs_mark_super_dirty(fs: ext2_filsys);

    // --- Inode operations ---

    /// Creates a new directory.
    pub fn ext2fs_mkdir(
        fs: ext2_filsys,
        parent: ext2_ino_t,
        inum: ext2_ino_t,
        name: *const core::ffi::c_char,
    ) -> errcode_t;

    /// Links an inode into a directory.
    pub fn ext2fs_link(
        fs: ext2_filsys,
        dir: ext2_ino_t,
        name: *const core::ffi::c_char,
        ino: ext2_ino_t,
        flags: core::ffi::c_int,
    ) -> errcode_t;

    /// Allocates a new inode number.
    pub fn ext2fs_new_inode(
        fs: ext2_filsys,
        dir: ext2_ino_t,
        mode: core::ffi::c_int,
        map: ext2fs_inode_bitmap,
        ret: *mut ext2_ino_t,
    ) -> errcode_t;

    /// Writes a new inode to the filesystem.
    pub fn ext2fs_write_new_inode(
        fs: ext2_filsys,
        ino: ext2_ino_t,
        inode: *mut ext2_inode,
    ) -> errcode_t;

    /// Reads an inode from the filesystem.
    pub fn ext2fs_read_inode(
        fs: ext2_filsys,
        ino: ext2_ino_t,
        inode: *mut ext2_inode,
    ) -> errcode_t;

    /// Writes an inode to the filesystem.
    pub fn ext2fs_write_inode(
        fs: ext2_filsys,
        ino: ext2_ino_t,
        inode: *mut ext2_inode,
    ) -> errcode_t;

    /// Updates inode allocation statistics.
    pub fn ext2fs_inode_alloc_stats2(
        fs: ext2_filsys,
        ino: ext2_ino_t,
        inuse: core::ffi::c_int,
        isdir: core::ffi::c_int,
    );

    // --- Block operations ---

    /// Allocates a new block.
    pub fn ext2fs_new_block2(
        fs: ext2_filsys,
        goal: blk64_t,
        map: ext2fs_block_bitmap,
        ret: *mut blk64_t,
    ) -> errcode_t;

    /// Updates block allocation statistics.
    pub fn ext2fs_block_alloc_stats2(
        fs: ext2_filsys,
        blk: blk64_t,
        inuse: core::ffi::c_int,
    );

    // --- Directory population (from misc/create_inode.h) ---

    /// Populates an ext4 filesystem from a host directory tree.
    ///
    /// This is the core implementation behind `mke2fs -d <dir>`.
    pub fn populate_fs(
        fs: ext2_filsys,
        parent_ino: ext2_ino_t,
        source_dir: *const core::ffi::c_char,
        root: ext2_ino_t,
    ) -> errcode_t;

    /// Like [`populate_fs`] but with optional callbacks.
    pub fn populate_fs2(
        fs: ext2_filsys,
        parent_ino: ext2_ino_t,
        source_dir: *const core::ffi::c_char,
        root: ext2_ino_t,
        fs_callbacks: *mut fs_ops_callbacks,
    ) -> errcode_t;

    /// Like [`populate_fs2`] but with additional flags.
    pub fn populate_fs3(
        fs: ext2_filsys,
        parent_ino: ext2_ino_t,
        source_dir: *const core::ffi::c_char,
        root: ext2_ino_t,
        flags: core::ffi::c_int,
        fs_callbacks: *mut fs_ops_callbacks,
    ) -> errcode_t;

    /// Writes a host file into the filesystem at `dest` relative to `cwd`.
    pub fn do_write_internal(
        fs: ext2_filsys,
        cwd: ext2_ino_t,
        src: *const core::ffi::c_char,
        dest: *const core::ffi::c_char,
        flags: core::ffi::c_ulong,
        root: ext2_ino_t,
    ) -> errcode_t;

    /// Creates a directory inside the filesystem.
    pub fn do_mkdir_internal(
        fs: ext2_filsys,
        cwd: ext2_ino_t,
        name: *const core::ffi::c_char,
        flags: core::ffi::c_ulong,
        root: ext2_ino_t,
    ) -> errcode_t;

    /// Creates a symlink inside the filesystem.
    pub fn do_symlink_internal(
        fs: ext2_filsys,
        cwd: ext2_ino_t,
        name: *const core::ffi::c_char,
        target: *mut core::ffi::c_char,
        root: ext2_ino_t,
    ) -> errcode_t;

    /// Copies extra inode fields (timestamps, etc.) from a host `stat` struct.
    pub fn set_inode_extra(
        fs: ext2_filsys,
        ino: ext2_ino_t,
        st: *const core::ffi::c_void, // struct stat *
    ) -> errcode_t;

    /// Links an inode into a directory (from create_inode.h).
    pub fn add_link(
        fs: ext2_filsys,
        parent_ino: ext2_ino_t,
        ino: ext2_ino_t,
        name: *const core::ffi::c_char,
    ) -> errcode_t;
}
