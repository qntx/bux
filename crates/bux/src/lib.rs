//! Embedded micro-VM sandbox for running AI agents.
//!
//! `bux` wraps [`libkrun`] into a managed [`Runtime`]: create isolated
//! machines from OCI images, exec through the guest agent, and control
//! egress at the host gvproxy boundary.
//!
//! # Quick start
//!
//! ```no_run
//! # #[cfg(unix)]
//! # async fn example() -> bux::Result<()> {
//! use bux::{ExecStart, Runtime, VmOptions};
//!
//! let rt = Runtime::open(bux::default_data_dir())?;
//! let mut vm = rt
//!     .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
//!     .await?;
//!
//! vm.exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
//!     .await?;
//! vm.stop().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`libkrun`]: https://github.com/containers/libkrun

#[cfg(unix)]
mod client;
mod disk;
mod error;
mod events;
#[cfg(unix)]
mod guest;
#[cfg(unix)]
mod health;
#[cfg(unix)]
mod lifecycle;
mod log_level;
mod metrics;
#[cfg(unix)]
mod options;
mod ports;
#[cfg(unix)]
mod process;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
mod secrets;
mod security;
#[cfg(unix)]
mod snapshot;
mod state;
mod util;
#[cfg(unix)]
mod volumes;
#[cfg(unix)]
mod watchdog;

pub use bux_proto::ExecStart;
#[cfg(unix)]
pub use client::{ExecHandle, ExecOutput, PongInfo};
pub use error::{Error, Result};
pub use events::{AuditEvent, AuditEventKind, EventDispatcher, EventListener};
#[cfg(unix)]
pub use lifecycle::SweepReport;
pub use metrics::{RuntimeMetrics, VmMetrics};
#[cfg(unix)]
pub use options::{ImageRef, NetworkSpec, VmOptions};
pub use ports::{PortSpec, PublishedPort, parse_publish_spec};
#[cfg(unix)]
pub use runtime::{HealthStatus, ImageInfo, Runtime, Vm, VmInfo, default_data_dir};
#[cfg(unix)]
pub use secrets::{Secret, StartOptions};
pub use security::{HostInfo, LayerStatus, SecurityOptions, SecurityStatus};
#[cfg(unix)]
pub use snapshot::SnapshotInfo;
pub use state::Status;
#[cfg(unix)]
pub use volumes::{
    VolumeInfo, VolumeManager, VolumeMount, VolumeSource, parse_bind_spec, validate_volume_name,
};
