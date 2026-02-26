//! Raw FFI bindings to [`libkrun`] — a lightweight VM engine for sandboxed execution.
//!
//! All types and functions are **auto-generated** by [`bindgen`](https://docs.rs/bindgen)
//! from the [`libkrun.h`] header. Do not edit `bindings.rs` manually.
//!
//! # Build
//!
//! The build script (`build.rs`) automatically:
//! 1. Downloads the pre-built dynamic library from GitHub Releases
//!    (or uses a local path via `BUX_DEPS_DIR`).
//! 2. Configures the linker for dynamic linking.
//!
//! For local development, set `BUX_DEPS_DIR` to point at a directory
//! containing the pre-built `libkrun` dynamic library.
//!
//! [`libkrun`]: https://github.com/containers/libkrun
//! [`libkrun.h`]: https://github.com/qntx/libkrun/blob/main/include/libkrun.h

// sys crate: unsafe FFI, non-idiomatic generated code
#![allow(
    unsafe_code,
    missing_docs,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    clippy::missing_safety_doc,
    clippy::upper_case_acronyms
)]

// When the `regenerate` feature is enabled, use freshly generated bindings.
// Otherwise, use the pre-generated bindings committed in the repository.
#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");
