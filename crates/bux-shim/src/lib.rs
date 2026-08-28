//! bux micro-VM engine crate: [`ShimConfig`] → libkrun.
//!
//! The host `bux` Runtime serialises a [`ShimConfig`] and spawns the
//! `bux-shim` binary (`bux-shim-bin`). Product path is [`prepare`] /
//! [`install_seccomp`] / [`start`]. This library does not start gvproxy.

mod apply;
mod config;
mod crash;
mod error;
mod exit_info;
pub mod host;
mod watchdog;

pub use apply::{PreparedVm, install_seccomp, prepare, start};
pub use config::{
    ShimConfig, ShimDiskFormat, ShimGvproxy, ShimNetConn, ShimNetwork, ShimSecret, ShimVirtioFs,
    ShimVsockPort,
};
pub use crash::{install_crash_capture, write_exit_error};
pub use error::{Error, Result};
pub use exit_info::{ExitInfo, PANIC_EXIT_CODE, SIGNAL_EXIT_BASE};
pub use watchdog::{ENV_WATCHDOG_FD, start_watchdog_thread, wait_for_parent_death};
