//! Low-level FFI declarations and safe wrappers for `libgvproxy`.
//!
//! All `unsafe` code for calling into the Go c-archive is confined here.
//! Higher-level modules (`instance`, `mod`) use only the safe wrappers.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_longlong, c_void};

use crate::error::{NetError, Result};
use crate::gvproxy::config::GvproxyConfig;

// ============================================================================
// Raw extern "C" declarations
// ============================================================================

/// Logging callback function type called by Go's slog handler.
///
/// - `level`: 0=trace, 1=debug, 2=info, 3=warn, 4=error
/// - `message`: null-terminated C string
#[allow(dead_code)]
pub(crate) type LogCallbackFn = extern "C" fn(level: c_int, message: *const c_char);

unsafe extern "C" {
    /// Create a new gvproxy instance from a JSON config string.
    ///
    /// Returns an instance handle (≥ 0) or −1 on error.
    fn gvproxy_create(config_json: *const c_char) -> c_longlong;

    /// Destroy a gvproxy instance and free its resources.
    ///
    /// Returns 0 on success, non-zero on error.
    fn gvproxy_destroy(id: c_longlong) -> c_int;

    /// Get network statistics as a JSON string.
    ///
    /// Returns a C string that must be freed with [`gvproxy_free_string`],
    /// or NULL on error.
    fn gvproxy_get_stats(id: c_longlong) -> *mut c_char;

    /// Get the library version string.
    ///
    /// Returns a C string that must be freed with [`gvproxy_free_string`].
    fn gvproxy_get_version() -> *mut c_char;

    /// Register a Rust log callback (or NULL to restore default stderr logging).
    fn gvproxy_set_log_callback(callback: *const c_void);

    /// Free a string allocated by the Go side.
    fn gvproxy_free_string(s: *mut c_char);
}

// ============================================================================
// Safe wrappers
// ============================================================================

/// Creates a new gvproxy instance with the given configuration.
///
/// Returns the instance handle on success.
pub(crate) fn create_instance(config: &GvproxyConfig) -> Result<i64> {
    let json = serde_json::to_string(config)?;

    let c_json =
        CString::new(json).map_err(|e| NetError::Ffi(format!("invalid config JSON: {e}")))?;

    let id = unsafe { gvproxy_create(c_json.as_ptr()) };

    if id < 0 {
        return Err(NetError::Ffi("gvproxy_create returned -1".into()));
    }

    tracing::info!(id, "created gvproxy instance via FFI");
    Ok(id)
}

/// Destroys a gvproxy instance, releasing Go-side resources.
pub(crate) fn destroy_instance(id: i64) -> Result<()> {
    let rc = unsafe { gvproxy_destroy(id) };
    if rc != 0 {
        return Err(NetError::Ffi(format!(
            "gvproxy_destroy failed for instance {id}: code {rc}"
        )));
    }
    tracing::info!(id, "destroyed gvproxy instance via FFI");
    Ok(())
}

/// Returns the gvproxy-bridge library version.
pub(crate) fn get_version() -> Result<String> {
    let ptr = unsafe { gvproxy_get_version() };
    if ptr.is_null() {
        return Err(NetError::Ffi("gvproxy_get_version returned NULL".into()));
    }

    let version = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| NetError::Ffi(format!("invalid UTF-8 in version string: {e}")))?
        .to_owned();

    unsafe { gvproxy_free_string(ptr) };
    Ok(version)
}

/// Returns raw network statistics JSON for the given instance.
pub(crate) fn get_stats_json(id: i64) -> Result<String> {
    let ptr = unsafe { gvproxy_get_stats(id) };
    if ptr.is_null() {
        return Err(NetError::Ffi(format!(
            "gvproxy_get_stats returned NULL for instance {id}"
        )));
    }

    let json = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| NetError::Ffi(format!("invalid UTF-8 in stats JSON: {e}")))?
        .to_owned();

    unsafe { gvproxy_free_string(ptr) };
    Ok(json)
}

/// Registers a Rust log callback with the Go side.
///
/// # Safety
///
/// `callback` must point to a function with the [`LogCallbackFn`] signature
/// that is thread-safe and never panics.  Pass `std::ptr::null()` to
/// restore default stderr logging.
pub(crate) unsafe fn set_log_callback(callback: *const c_void) {
    unsafe { gvproxy_set_log_callback(callback) };
}
