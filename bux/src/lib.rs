//! Embedded micro-VM sandbox for running AI agents.
//!
//! `bux` wraps [`libkrun`] into a safe Rust API for creating, running,
//! and managing lightweight virtual machines powered by KVM (Linux) or
//! Hypervisor.framework (macOS).
//!
//! # Quick start — one-shot execution
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

#[cfg(unix)]
mod client;
mod error;
#[cfg(unix)]
mod runtime;
mod state;
mod sys;
mod vm;

pub use bux_proto::ExecReq;
#[cfg(unix)]
pub use client::{Client, ExecOutput};
pub use error::{Error, Result};
#[cfg(unix)]
pub use runtime::{Runtime, VmHandle};
pub use state::{Status, VmConfig, VmState};
pub use sys::{DiskFormat, Feature, KernelFormat, LogStyle, SyncMode};
pub use vm::{LogLevel, Vm, VmBuilder};
