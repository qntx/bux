//! Embedded micro-VM sandbox for running AI agents.
//!
//! `bux` wraps [`libkrun`] into a safe Rust API for creating, running,
//! and managing lightweight virtual machines powered by KVM (Linux) or
//! Hypervisor.framework (macOS).
//!
//! # Quick start — managed VM via Runtime
//!
//! ```no_run
//! # #[cfg(unix)]
//! # async fn example() -> bux::Result<()> {
//! use bux::{Runtime, ExecStart};
//!
//! let rt = Runtime::global()?;
//! let mut handle = rt.run("alpine:latest", |b| b.vcpus(2).ram_mib(512), None).await?;
//! let output = handle.exec_output(ExecStart::new("echo").args(vec!["hello".into()])).await?;
//! handle.stop().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Quick start — low-level VM (takes over the process)
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
//! vm.start().expect("failed to start VM");
//! ```
//!
//! [`libkrun`]: https://github.com/containers/libkrun

#[cfg(unix)]
mod client;
mod disk;
mod error;
#[cfg(unix)]
mod jail;
#[cfg(unix)]
mod runtime;
mod state;
mod sys;
mod vm;
#[cfg(unix)]
pub mod watchdog;

pub use bux_proto::ExecStart;
#[cfg(unix)]
pub use client::{Client, ExecHandle, ExecOutput, PongInfo};
#[cfg(unix)]
pub use disk::{Disk, DiskManager};
pub use disk::{DiskFormat, QcowHeader};
pub use error::{Error, Result};
#[cfg(unix)]
pub use jail::{JailConfig, NoopSandbox, ResourceLimits, Sandbox};
#[cfg(unix)]
pub use runtime::{HealthStatus, Runtime, VmHandle};
#[cfg(unix)]
pub use state::StateDb;
pub use state::{Status, VirtioFs, VmConfig, VmState, VsockPort};
pub use sys::{Feature, KernelFormat, LogStyle, SyncMode};
pub use vm::{LogLevel, Vm, VmBuilder};
