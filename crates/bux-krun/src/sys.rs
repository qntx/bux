//! Raw FFI bindings to [`libkrun`].
//!
//! All types and functions are **auto-generated** by [`bindgen`](https://docs.rs/bindgen)
//! from the [`libkrun.h`] header. Do not edit `bindings.rs` manually.
//!
//! [`libkrun`]: https://github.com/containers/libkrun
//! [`libkrun.h`]: https://github.com/qntx/libkrun/blob/main/include/libkrun.h

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
    clippy::doc_markdown,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::missing_docs_in_private_items,
    clippy::missing_safety_doc,
    clippy::multiple_unsafe_ops_per_block,
    clippy::pub_underscore_fields,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::undocumented_unsafe_blocks,
    clippy::unreadable_literal,
    clippy::unseparated_literal_suffix,
    clippy::upper_case_acronyms,
    clippy::useless_transmute,
    reason = "auto-generated FFI bindings from libkrun.h"
)]

// When the `regenerate` feature is enabled, use freshly generated bindings.
// Otherwise, use the pre-generated bindings committed in the repository.
#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");
