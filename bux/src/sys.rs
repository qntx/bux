//! Safe wrappers around [`bux_sys`] FFI functions.
//!
//! Every function in this module corresponds 1:1 to a `krun_*` FFI call.
//! All `unsafe` code in the crate is confined to this module.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a libkrun return code into a [`Result`].
const fn check(op: &'static str, ret: i32) -> Result<()> {
    if ret < 0 {
        Err(Error::Krun { op, code: ret })
    } else {
        Ok(())
    }
}

/// Owned NULL-terminated array of C strings.
///
/// Keeps the [`CString`] values alive while the pointer array is in use.
struct CStringArray {
    /// Prevents the owned strings from being dropped.
    _owned: Vec<CString>,
    /// NULL-terminated pointer array suitable for FFI.
    ptrs: Vec<*const c_char>,
}

impl CStringArray {
    /// Builds a NULL-terminated C string array from Rust strings.
    fn new(strings: &[String]) -> Result<Self> {
        let owned: Vec<CString> = strings
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    /// Returns a pointer to the NULL-terminated array.
    const fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

// ---------------------------------------------------------------------------
// Context lifecycle
// ---------------------------------------------------------------------------

/// Creates a new VM configuration context.
pub fn create_ctx() -> Result<u32> {
    let ret = unsafe { bux_sys::krun_create_ctx() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "create_ctx",
            code: ret,
        });
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as u32)
}

/// Frees an existing configuration context.
pub fn free_ctx(ctx: u32) -> Result<()> {
    check("free_ctx", unsafe { bux_sys::krun_free_ctx(ctx) })
}

// ---------------------------------------------------------------------------
// VM configuration
// ---------------------------------------------------------------------------

/// Sets the log level for the library (global, not per-context).
pub fn set_log_level(level: u32) -> Result<()> {
    check("set_log_level", unsafe {
        bux_sys::krun_set_log_level(level)
    })
}

/// Sets basic VM parameters: vCPU count and RAM size.
pub fn set_vm_config(ctx: u32, vcpus: u8, ram_mib: u32) -> Result<()> {
    check("set_vm_config", unsafe {
        bux_sys::krun_set_vm_config(ctx, vcpus, ram_mib)
    })
}

/// Sets the root filesystem path.
pub fn set_root(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_root", unsafe {
        bux_sys::krun_set_root(ctx, c.as_ptr())
    })
}

/// Sets the working directory inside the VM.
pub fn set_workdir(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_workdir", unsafe {
        bux_sys::krun_set_workdir(ctx, c.as_ptr())
    })
}

/// Sets the executable, arguments, and optionally environment variables.
///
/// If `env` is `None`, libkrun auto-inherits the host environment.
pub fn set_exec(ctx: u32, path: &str, args: &[String], env: Option<&[String]>) -> Result<()> {
    let c_path = CString::new(path)?;
    let argv = CStringArray::new(args)?;

    let c_envp = env.map(CStringArray::new).transpose()?;
    let envp_ptr = c_envp
        .as_ref()
        .map_or(std::ptr::null(), CStringArray::as_ptr);

    check("set_exec", unsafe {
        bux_sys::krun_set_exec(ctx, c_path.as_ptr(), argv.as_ptr(), envp_ptr)
    })
}

/// Sets environment variables without specifying an executable.
pub fn set_env(ctx: u32, env: &[String]) -> Result<()> {
    let array = CStringArray::new(env)?;
    check("set_env", unsafe {
        bux_sys::krun_set_env(ctx, array.as_ptr())
    })
}

/// Configures host-to-guest TCP port mappings (format: `"host:guest"`).
pub fn set_port_map(ctx: u32, ports: &[String]) -> Result<()> {
    let array = CStringArray::new(ports)?;
    check("set_port_map", unsafe {
        bux_sys::krun_set_port_map(ctx, array.as_ptr())
    })
}

/// Adds a virtio-fs shared directory.
pub fn add_virtiofs(ctx: u32, tag: &str, host_path: &str) -> Result<()> {
    let c_tag = CString::new(tag)?;
    let c_path = CString::new(host_path)?;
    check("add_virtiofs", unsafe {
        bux_sys::krun_add_virtiofs(ctx, c_tag.as_ptr(), c_path.as_ptr())
    })
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Starts the microVM and takes over the current process.
///
/// On success this function **never returns** — libkrun calls `exit()` when
/// the VM shuts down.  It only returns on pre-start configuration errors.
pub fn start_enter(ctx: u32) -> Result<()> {
    check("start_enter", unsafe { bux_sys::krun_start_enter(ctx) })
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Returns the maximum number of vCPUs supported by the hypervisor.
pub fn get_max_vcpus() -> Result<u32> {
    let ret = unsafe { bux_sys::krun_get_max_vcpus() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "get_max_vcpus",
            code: ret,
        });
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as u32)
}
