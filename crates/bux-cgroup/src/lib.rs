//! cgroup v2 resource limits for Linux process trees.
//!
//! bux-cgroup is a tiny, zero-dependency (beyond `thiserror`) L1 platform
//! primitive. It creates per-VM cgroups under the unified cgroup v2
//! hierarchy (`/sys/fs/cgroup`), writes CPU / memory / swap limits, and
//! returns an RAII guard that removes the cgroup on drop.
//!
//! The crate is **Linux-only**: on every other target it compiles to an
//! empty module so downstream `cfg(target_os = "linux")` gates remain
//! simple. Callers should still gate their own usage behind
//! `#[cfg(target_os = "linux")]` to avoid linking the crate on other OSes.
//!
//! # Layout
//!
//! Every cgroup created by `create` lives at:
//!
//! ```text
//! /sys/fs/cgroup/bux/{name}/
//!     cpu.max
//!     memory.max
//!     memory.swap.max
//!     cgroup.procs   ← write PIDs here via `add_pid`
//! ```
//!
//! The parent `/sys/fs/cgroup/bux` directory is created on demand, and
//! the `cpu` / `memory` controllers are enabled there (best-effort —
//! failure is non-fatal because the subsequent control-file writes will
//! surface a clear error if they are not actually available).
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), bux_cgroup::Error> {
//! use bux_cgroup::{ResourceLimits, add_pid, create};
//!
//! let limits = ResourceLimits::builder()
//!     .cpu_cores(2.0)
//!     .memory_bytes(512 * 1024 * 1024)
//!     .memory_swap_bytes(512 * 1024 * 1024)
//!     .build();
//!
//! let guard = create("vm-abc123", &limits)?;
//! add_pid(&guard, std::process::id() as i32)?;
//! // `guard` removes /sys/fs/cgroup/bux/vm-abc123 on drop (best-effort).
//! # Ok(()) }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod limits;

#[cfg(target_os = "linux")]
mod guard;
#[cfg(target_os = "linux")]
mod ops;

pub use error::{Error, Result};
pub use limits::{ResourceLimits, ResourceLimitsBuilder};

#[cfg(target_os = "linux")]
pub use guard::CgroupGuard;
#[cfg(target_os = "linux")]
pub use ops::{add_pid, create};
