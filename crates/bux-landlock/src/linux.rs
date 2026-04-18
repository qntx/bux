//! Linux implementation: build the kernel ruleset fd and apply it.
//!
//! This module is compiled **only on `target_os = "linux"`**. On other
//! platforms [`crate::PathRestrictions::build`] short-circuits to
//! `Ok(None)` without ever pulling this in.

use std::os::fd::{IntoRawFd, OwnedFd, RawFd};

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError,
};

use crate::error::{Error, Result};
use crate::restrictions::PathRestrictions;

/// Target Landlock ABI version. V5 (kernel 6.10+) supports
/// filesystem + network + ioctl-dev. `BestEffort` silently downgrades
/// on older kernels, so the build call still succeeds on 5.13+ with a
/// reduced ruleset.
const TARGET_ABI: ABI = ABI::V5;

/// Build a Landlock ruleset and return the raw fd.
///
/// Returns `Ok(None)` if the running kernel does not support Landlock
/// at all. Returns `Err` only for unexpected failures (e.g. a rule was
/// rejected for reasons other than kernel version).
///
/// The returned fd is a **raw** file descriptor — the caller is
/// responsible for passing it to a forked child and invoking
/// [`restrict_self`] in the child's `pre_exec` hook, which closes it.
pub(crate) fn build(r: &PathRestrictions) -> Result<Option<RawFd>> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| ruleset_err("handle filesystem access", &e))?;

    if r.network_denied() {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(TARGET_ABI))
            .map_err(|e| ruleset_err("handle network access", &e))?;
    }

    let mut created = ruleset
        .create()
        .map_err(|e| ruleset_err("create ruleset", &e))?
        .set_compatibility(CompatLevel::BestEffort);

    let read_access = AccessFs::from_read(TARGET_ABI);
    for path in r.read_paths() {
        if let Ok(fd) = PathFd::new(path) {
            created = created
                .add_rule(PathBeneath::new(fd, read_access))
                .map_err(|e| ruleset_err(&format!("add read rule for {}", path.display()), &e))?;
        }
    }

    let all_access = AccessFs::from_all(TARGET_ABI);
    for path in r.read_write_paths() {
        if let Ok(fd) = PathFd::new(path) {
            created = created
                .add_rule(PathBeneath::new(fd, all_access))
                .map_err(|e| ruleset_err(&format!("add write rule for {}", path.display()), &e))?;
        }
    }

    let owned_fd: Option<OwnedFd> = created.into();
    Ok(owned_fd.map(IntoRawFd::into_raw_fd))
}

/// Apply a previously built ruleset to the current thread.
///
/// This function is **async-signal-safe** — no allocation, no logging,
/// no mutex access — and therefore safe to call between `fork(2)` and
/// `execve(2)` from a `Command::pre_exec` closure.
///
/// The `fd` is always `close(2)`d, regardless of outcome.
///
/// # Safety
///
/// - `fd` must be a valid Landlock ruleset fd, typically produced by
///   [`build`] in the parent process and inherited across `fork`.
/// - Must be called in the child after `fork` but before `execve`, or
///   in a thread that does not need file-system access beyond the
///   ruleset afterwards.
///
/// # Returns
///
/// `0` on success, or a positive `errno` value on failure.
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "async-signal-safe path: errno deref + close on the same fd counted as two ops by clippy but each is minimal"
)]
pub(crate) unsafe fn restrict_self_raw(fd: RawFd) -> i32 {
    // PR_SET_NO_NEW_PRIVS is required before landlock_restrict_self
    // succeeds on an unprivileged process; bwrap may have set it
    // already, but prctl is idempotent.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes only an integer arg.
    let prctl_rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_rc != 0 {
        // SAFETY: errno is thread-local.
        let errno = unsafe { *libc::__errno_location() };
        // SAFETY: fd came from the caller who owns it.
        unsafe {
            libc::close(fd);
        }
        return errno;
    }

    // SAFETY: fd is a valid Landlock ruleset fd; flags must be 0.
    let syscall_rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            libc::c_long::from(fd),
            0_i64,
        )
    };
    let errno = if syscall_rc == 0 {
        0
    } else {
        // SAFETY: errno is thread-local.
        unsafe { *libc::__errno_location() }
    };

    // SAFETY: fd is no longer needed after restrict_self; close unconditionally.
    unsafe {
        libc::close(fd);
    }
    errno
}

/// Kernel-availability probe.
pub(crate) fn is_available() -> bool {
    Ruleset::default()
        .handle_access(AccessFs::Execute)
        .and_then(Ruleset::create)
        .is_ok()
}

/// Wrap a `RulesetError` into our crate's `Error` with an operation tag.
fn ruleset_err(context: &str, err: &RulesetError) -> Error {
    Error::Ruleset {
        context: context.to_owned(),
        message: err.to_string(),
    }
}
