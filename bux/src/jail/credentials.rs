//! Credential management for shim process privilege reduction (Linux only).
//!
//! Drops privileges by switching to an unprivileged uid/gid and clearing
//! all Linux capabilities. This ensures the shim process — even if
//! compromised — cannot escalate back to root or perform privileged
//! operations outside the VM.
//!
//! # Typical usage
//!
//! Called in the shim's `pre_exec` hook, after sandbox setup but before
//! libkrun takes over:
//!
//! ```text
//! fork() → bwrap namespace setup → credentials::drop_privileges() → libkrun start
//! ```

#![cfg(target_os = "linux")]

use std::io;

/// Configuration for credential reduction.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CredentialConfig {
    /// Target UID to switch to. `None` keeps the current UID.
    pub uid: Option<u32>,
    /// Target GID to switch to. `None` keeps the current GID.
    pub gid: Option<u32>,
    /// Whether to clear all Linux capabilities after switching.
    pub drop_caps: bool,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            uid: None,
            gid: None,
            drop_caps: true,
        }
    }
}

/// Drops privileges according to the given configuration.
///
/// Order of operations (security-critical):
/// 1. Set supplementary groups to empty (if switching GID).
/// 2. Switch GID (must happen before UID drop on some kernels).
/// 3. Switch UID.
/// 4. Clear all capabilities (if `drop_caps` is true).
/// 5. Set `PR_SET_NO_NEW_PRIVS` to prevent re-escalation.
///
/// # Errors
///
/// Returns an error if any privilege-reduction syscall fails. In that
/// case, the process is in a partially-reduced state and should be
/// terminated.
pub fn drop_privileges(config: &CredentialConfig) -> io::Result<()> {
    // 1. Clear supplementary groups.
    if config.gid.is_some() {
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // 2. Switch GID.
    if let Some(gid) = config.gid {
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setresgid(gid, gid, gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // 3. Switch UID.
    if let Some(uid) = config.uid {
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setresuid(uid, uid, uid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // 4. Clear all capabilities.
    if config.drop_caps {
        clear_caps()?;
    }

    // 5. PR_SET_NO_NEW_PRIVS — prevent re-escalation via execve of suid binaries.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Clears all Linux capabilities from the current thread.
///
/// Uses the `capset` syscall directly to avoid depending on libcap.
fn clear_caps() -> io::Result<()> {
    // struct __user_cap_header_struct
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    // struct __user_cap_data_struct (kernel v2 uses two of these)
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // _LINUX_CAPABILITY_VERSION_3 — supports 64 capabilities (2 data structs).
    const CAP_V3: u32 = 0x2008_0026;

    let header = CapHeader {
        version: CAP_V3,
        pid: 0, // current thread
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    #[allow(unsafe_code)]
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_drops_caps() {
        let config = CredentialConfig::default();
        assert!(config.drop_caps);
        assert!(config.uid.is_none());
        assert!(config.gid.is_none());
    }

    #[test]
    fn no_new_privs_succeeds() {
        // PR_SET_NO_NEW_PRIVS should always succeed (even in containers).
        #[allow(unsafe_code)]
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(rc, 0);
    }
}
