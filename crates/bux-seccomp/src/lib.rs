//! Pure-Rust seccomp BPF syscall filtering for the bux VMM shim.
//!
//! bux-seccomp is a zero-deps-beyond-`libc`/`thiserror` L1 platform
//! primitive. It assembles a whitelist-mode BPF program and installs it
//! through the `seccomp(2)` syscall with `SECCOMP_FILTER_FLAG_TSYNC` so
//! every thread of the calling process inherits the filter atomically.
//!
//! The allowlist is intentionally broad — it exists to block things
//! that would be catastrophic if the shim were compromised (`mount`,
//! `ptrace`, `reboot`, `kexec_load`, `init_module`, `pivot_root`, …)
//! rather than to minimise attack surface down to what a perfectly
//! understood libkrun would need. Refining it is deferred to a later
//! phase once we have a syscall-tracing CI job.
//!
//! # Supported architectures
//!
//! Currently `x86_64` and `aarch64` on Linux. On every other platform
//! the crate compiles to a stub that exposes only the error type
//! (so downstream code can reference the types without `cfg` gating).
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
//! # fn main() -> Result<(), bux_seccomp::Error> {
//! bux_seccomp::install_default()?;
//! // From here on, any syscall not on the allowlist kills the process
//! // with SIGSYS.
//! # Ok(()) }
//! # #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
//! # fn main() {}
//! ```
//!
//! # Safety
//!
//! The crate encapsulates all `unsafe` inside the single `install`
//! function — callers never touch raw syscalls. Once
//! `install_default` / `install` succeeds, the filter is permanent
//! for the process.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod bpf;
mod error;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod arch;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod filter;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod install;

pub use error::{Error, Result};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use install::{default_allowlist_size, install, install_default};
