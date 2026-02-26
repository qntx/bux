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
    clippy::unimplemented,
    clippy::unreadable_literal,
    clippy::unseparated_literal_suffix,
    clippy::unwrap_used,
    clippy::upper_case_acronyms,
    clippy::used_underscore_binding,
    clippy::useless_transmute
)]

// When the `regenerate` feature is enabled, use freshly generated bindings.
// Otherwise, use the pre-generated bindings committed in the repository.
#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");
