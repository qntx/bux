//! bux micro-VM engine crate: [`ShimConfig`] → libkrun.
//!
//! The host `bux` Runtime serialises a [`ShimConfig`] and spawns the
//! `bux-shim` binary. This library also exposes [`prepare`] / [`boot`]
//! so host-side builders share the same apply path (no dual logic).

mod apply;
mod config;
mod crash;
mod error;
mod exit_info;
pub mod host;
mod watchdog;

pub use apply::{PreparedVm, boot, prepare, start};
pub use config::{
    ShimConfig, ShimDiskFormat, ShimNetConn, ShimNetwork, ShimVirtioFs, ShimVsockPort,
};
pub use crash::{install_crash_capture, write_exit_error};
pub use error::{Error, Result};
pub use exit_info::{ExitInfo, PANIC_EXIT_CODE, SIGNAL_EXIT_BASE};
pub use watchdog::{ENV_WATCHDOG_FD, start_watchdog_thread, wait_for_parent_death};
