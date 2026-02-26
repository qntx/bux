//! Raw FFI bindings to [`libext2fs`] and [`create_inode`].
//!
//! All types and functions are **auto-generated** by [`bindgen`](https://docs.rs/bindgen)
//! from the e2fsprogs headers. Do not edit `bindings.rs` manually.
//!
//! [`libext2fs`]: https://e2fsprogs.sourceforge.net/

// sys module: unsafe FFI, non-idiomatic generated code
#![allow(
    unsafe_code,
    missing_docs,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    clippy::missing_safety_doc,
    clippy::upper_case_acronyms,
    clippy::missing_docs_in_private_items,
    clippy::exhaustive_structs,
    clippy::exhaustive_enums,
    clippy::unimplemented,
    clippy::unwrap_used
)]

// When the `regenerate` feature is enabled, use freshly generated bindings.
// Otherwise, use the pre-generated bindings committed in the repository.
#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");
