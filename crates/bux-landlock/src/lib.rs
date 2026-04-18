//! Safe Landlock LSM filesystem restrictions for the bux VMM shim.
//!
//! [Landlock] is a Linux Security Module (kernel 5.13+) that lets an
//! unprivileged process restrict its own and its descendants' ambient
//! filesystem rights. It complements seccomp (syscall filtering) and
//! bubblewrap (namespace isolation) with inode-based access control
//! that the kernel enforces regardless of what namespaces the process
//! sees.
//!
//! This crate is a deliberately thin, type-safe wrapper around the
//! community `landlock` crate. It exposes exactly three moving parts:
//!
//! 1. [`PathRestrictions`] — a fluent builder that accumulates
//!    read-only / read-write path lists and an optional network-deny
//!    flag. Compiles on every platform so configuration code stays
//!    `cfg`-free.
//! 2. `PathRestrictions::build` *(Linux only)* — turns the config into
//!    a kernel ruleset and returns its raw file descriptor; on older
//!    kernels (< 5.13) it returns `Ok(None)`.
//! 3. `restrict_self` *(Linux only)* — applies a previously built
//!    ruleset to the current thread. Designed to be called from a
//!    `pre_exec` hook, it is **async-signal-safe** (no allocation, no
//!    locks).
//!
//! # Kernel-version graceful degradation
//!
//! Landlock is a best-effort defence-in-depth layer, so "kernel does
//! not support Landlock" is signalled by `Ok(None)`, not an error.
//! Callers log a warning and continue without Landlock.
//!
//! # Example — parent/child split
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), bux_landlock::Error> {
//! use bux_landlock::{PathRestrictions, restrict_self};
//! use std::os::unix::process::CommandExt;
//! use std::process::Command;
//!
//! // Parent: build the ruleset.
//! let Some(fd) = PathRestrictions::new()
//!     .allow_read("/usr")
//!     .allow_read_write("/tmp")
//!     .deny_network()
//!     .build()?
//! else {
//!     // Older kernel — skip Landlock silently.
//!     return Ok(());
//! };
//!
//! // Child: apply the ruleset in pre_exec (async-signal-safe).
//! let mut cmd = Command::new("/bin/echo");
//! unsafe {
//!     cmd.pre_exec(move || {
//!         let errno = restrict_self(fd);
//!         if errno == 0 {
//!             Ok(())
//!         } else {
//!             Err(std::io::Error::from_raw_os_error(errno))
//!         }
//!     });
//! }
//! # Ok(()) }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! [Landlock]: https://docs.kernel.org/userspace-api/landlock.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    unsafe_code,
    reason = "L1 LSM wrapper — restrict_self is fundamentally unsafe (revokes caller thread rights permanently); safety contract documented on the function"
)]

mod error;
mod restrictions;

#[cfg(target_os = "linux")]
mod linux;

pub use error::{Error, Result};
pub use restrictions::PathRestrictions;

#[cfg(target_os = "linux")]
use std::os::fd::RawFd;

#[cfg(target_os = "linux")]
impl PathRestrictions {
    /// Build the Landlock ruleset as a raw file descriptor.
    ///
    /// Returns `Ok(Some(fd))` when the running kernel supports
    /// Landlock; the caller passes `fd` to a forked child and invokes
    /// [`restrict_self`] there. Returns `Ok(None)` on pre-5.13 kernels
    /// — a benign signal that Landlock is not enforceable here.
    ///
    /// Only compiled on Linux. The builder itself ([`PathRestrictions`])
    /// is cross-platform so configuration code can stay `cfg`-free;
    /// call sites gate the `build`/`restrict_self` pair with
    /// `#[cfg(target_os = "linux")]`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Ruleset` if the kernel rejects the compiled
    /// ruleset for any reason other than "Landlock unavailable".
    pub fn build(&self) -> Result<Option<RawFd>> {
        linux::build(self)
    }
}

/// Apply a previously built Landlock ruleset to the current thread.
///
/// Safe to call from a `std::os::unix::process::CommandExt::pre_exec`
/// closure: the function uses only raw syscalls (`prctl`, the
/// `landlock_restrict_self` syscall, `close`).
///
/// The `fd` is always closed, regardless of outcome.
///
/// # Safety
///
/// - `fd` must be a valid Landlock ruleset fd previously produced by
///   `PathRestrictions::build`.
/// - The call permanently revokes rights from the calling thread; it
///   cannot be undone or relaxed later.
///
/// # Returns
///
/// `0` on success, positive `errno` otherwise.
#[cfg(target_os = "linux")]
#[must_use = "non-zero errno indicates the ruleset was NOT applied; callers must propagate the failure"]
pub unsafe fn restrict_self(fd: RawFd) -> i32 {
    // SAFETY: Forwarded to the linux-only helper; same contract.
    unsafe { linux::restrict_self_raw(fd) }
}

/// Check whether the running kernel supports Landlock.
///
/// Performs a minimal ruleset creation probe on Linux; always returns
/// `false` on non-Linux targets.
#[must_use]
#[allow(
    clippy::missing_const_for_fn,
    reason = "Linux branch calls non-const Ruleset APIs"
)]
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
