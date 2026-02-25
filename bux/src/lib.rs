//! Safe, ergonomic API for [`libkrun`] micro-VM sandboxing.
//!
//! `bux` wraps the raw FFI bindings from [`bux_sys`] into a type-safe,
//! Rust-idiomatic interface for creating and running lightweight virtual
//! machines powered by KVM (Linux) or Hypervisor.framework (macOS).
//!
//! # Quick start
//!
//! ```no_run
//! use bux::Vm;
//!
//! let vm = Vm::builder()
//!     .vcpus(2)
//!     .ram_mib(512)
//!     .root("/path/to/rootfs")
//!     .exec("/bin/bash", &["--login"])
//!     .build()
//!     .expect("invalid VM config");
//!
//! // Takes over the process — only returns on error.
//! vm.start().expect("failed to start VM");
//! ```
//!
//! [`libkrun`]: https://github.com/containers/libkrun

mod error;
mod sys;
mod vm;

pub use error::{Error, Result};
pub use sys::{DiskFormat, Feature, KernelFormat, LogStyle, SyncMode};
pub use vm::{LogLevel, Vm, VmBuilder};
