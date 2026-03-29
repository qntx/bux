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
//! let mut vm = rt.run("python:slim", |b| b.vcpus(2).ram_mib(1024), None).await?;
//!
//! // Each VM gets a writable QCOW2 overlay — install packages, write files, etc.
//! vm.exec_output(ExecStart::new("pip").args(["install", "numpy"].map(Into::into).to_vec())).await?;
//! vm.write_file("/work/hello.py", b"print('hello')", 0o755).await?;
//! let out = vm.exec_output(ExecStart::new("python").args(vec!["/work/hello.py".into()])).await?;
//!
//! // Stop preserves disk state; start resumes from the same overlay.
//! vm.stop().await?;
//! vm.start(std::time::Duration::from_secs(30)).await?;
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
pub mod exit_info;
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
pub use exit_info::ExitInfo;
#[cfg(unix)]
pub use jail::{JailConfig, NoopSandbox, ResourceLimits, Sandbox};
#[cfg(unix)]
pub use runtime::{HealthStatus, RunOptions, Runtime, VmHandle};
#[cfg(unix)]
pub use state::StateDb;
pub use state::{Status, VirtioFs, VmConfig, VmState, VsockPort};
pub use sys::{Feature, KernelFormat, LogStyle, SyncMode};
pub use vm::{LogLevel, Vm, VmBuilder};
