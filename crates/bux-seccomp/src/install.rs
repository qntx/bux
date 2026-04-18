//! Kernel-side seccomp filter installation.
//!
//! This module contains the only `unsafe` code in the crate — it wraps
//! two kernel entry points:
//!
//! 1. `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` — required for unprivileged
//!    seccomp; without it `seccomp(SECCOMP_SET_MODE_FILTER, ...)` returns
//!    `EACCES`.
//! 2. `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)`
//!    — atomically applies the filter to every thread in the current
//!    process. New threads created afterwards inherit it via `clone()`.
//!
//! After installation the process can only invoke syscalls on the
//! allowlist; anything else triggers `SIGSYS` (process kill).

use std::io;

use crate::bpf::{Instruction, MAX_LEN};
use crate::error::{Error, Result};
use crate::filter;

/// `struct sock_fprog` expected by the seccomp syscall.
#[repr(C)]
struct SockFprog {
    /// Number of BPF instructions (must fit in `u16`, kernel limit is 4096).
    len: u16,
    /// Pointer to the BPF instruction array.
    filter: *const Instruction,
}

/// Install the bux default seccomp filter on every thread of the
/// current process.
///
/// The filter allows only the syscalls in [`crate::arch::DEFAULT_ALLOWLIST`]
/// and kills the process (via `SIGSYS`) for anything else. The call is
/// synchronised across all existing threads using
/// `SECCOMP_FILTER_FLAG_TSYNC`; threads created *after* this returns
/// inherit the filter through the `clone()` contract.
///
/// # Safety
///
/// This is **irreversible**: once installed, the filter stays for the
/// remainder of the process lifetime. Callers must ensure they don't
/// need blacklisted syscalls later.
///
/// # Errors
///
/// - [`Error::FilterTooLarge`] if the compiled program exceeds the
///   kernel's `BPF_MAXINSNS` limit.
/// - [`Error::NoNewPrivs`] if `prctl(PR_SET_NO_NEW_PRIVS)` fails.
/// - [`Error::Install`] if the kernel rejects the filter.
/// - [`Error::TsyncFailed`] if at least one existing thread could not
///   be synchronised; the inner value is the non-synchronised TID.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn install_default() -> Result<()> {
    install(&filter::build_default())
}

/// Install an arbitrary pre-built seccomp BPF program.
///
/// Most callers want [`install_default`]. This variant exists for
/// tests and for callers that build a stricter program via
/// [`crate::filter::build`].
///
/// # Errors
///
/// See [`install_default`].
pub fn install(program: &[Instruction]) -> Result<()> {
    if program.len() > MAX_LEN {
        return Err(Error::FilterTooLarge(program.len()));
    }
    let filter_len =
        u16::try_from(program.len()).map_err(|_| Error::FilterTooLarge(program.len()))?;

    #[allow(
        unsafe_code,
        reason = "seccomp requires raw prctl/syscall — the only unsafe in this crate"
    )]
    // SAFETY: `libc::prctl` with PR_SET_NO_NEW_PRIVS(38) takes an integer
    // second argument; remaining three are ignored (passed as 0). The
    // seccomp syscall reads `sock_fprog` for exactly `len * 8` bytes from
    // `filter`, which we guarantee by backing it with the `program` slice
    // that outlives this unsafe block.
    unsafe {
        let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if rc != 0 {
            return Err(Error::NoNewPrivs(io::Error::last_os_error()));
        }

        let prog = SockFprog {
            len: filter_len,
            filter: program.as_ptr(),
        };
        let rc = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &raw const prog,
        );
        if rc > 0 {
            return Err(Error::TsyncFailed(rc));
        }
        if rc != 0 {
            return Err(Error::Install(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Number of syscalls in the default allowlist for the current architecture.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[must_use]
pub const fn default_allowlist_size() -> usize {
    crate::arch::DEFAULT_ALLOWLIST.len()
}
