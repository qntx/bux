//! Raw FFI bindings to [`libext2fs`] and `create_inode`.
//!
//! All types and functions are **auto-generated** by [`bindgen`](https://docs.rs/bindgen)
//! from the e2fsprogs headers. Do not edit `bindings.rs` manually.
//!
//! [`libext2fs`]: https://e2fsprogs.sourceforge.net/

// sys module: unsafe FFI, non-idiomatic generated code
#![allow(
    unsafe_code,
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::default_trait_access,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    unpredictable_function_pointer_comparisons,
    clippy::missing_docs_in_private_items,
    clippy::missing_safety_doc,
    clippy::pub_underscore_fields,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::unimplemented,
    clippy::unreadable_literal,
    clippy::unseparated_literal_suffix,
    clippy::unwrap_used,
    clippy::upper_case_acronyms,
    clippy::used_underscore_binding,
    clippy::useless_transmute,
    reason = "auto-generated FFI bindings"
)]

// When the `regenerate` feature is enabled, use freshly generated bindings.
// Otherwise, use the pre-generated bindings committed in the repository.
#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");

// Hand-written declarations for symbols that exist in libext2fs.a but are
// deliberately kept out of the bindgen allowlist in build.rs. Adding them to
// that list would produce duplicate definitions (E0428) in this module when
// the `regenerate` feature is enabled.
unsafe extern "C" {
    /// Recommended journal size in blocks for a filesystem of `num_blocks`;
    /// returns a negative value on failure.
    pub fn ext2fs_default_journal_size(num_blocks: __u64) -> ::core::ffi::c_int;

    /// Loads the on-disk inode and block bitmaps into `fs->inode_map` and
    /// `fs->block_map`.
    ///
    /// `ext2fs_open` leaves both maps NULL, so allocations
    /// (`ext2fs_new_inode`, `ext2fs_new_block2`) fail until this runs.
    /// Idempotent — maps already loaded are left alone — and it installs the
    /// `write_bitmaps` callback so `ext2fs_close` flushes them to disk.
    pub fn ext2fs_read_bitmaps(fs: ext2_filsys) -> errcode_t;

    /// Resolves `name` from `root`/`cwd` into an inode number.
    pub fn ext2fs_namei(
        fs: ext2_filsys,
        root: ext2_ino_t,
        cwd: ext2_ino_t,
        name: *const ::core::ffi::c_char,
        inode: *mut ext2_ino_t,
    ) -> errcode_t;
}
