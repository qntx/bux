//! Go slog → Rust tracing log bridge.
//!
//! Registers a callback with the Go side so that all `logrus` / `slog`
//! messages from gvisor-tap-vsock are forwarded to Rust's `tracing`
//! system under the target `"gvproxy"`.
//!
//! Filter with: `RUST_LOG=gvproxy=debug`

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::Once;

/// Callback invoked from Go via CGO for every log message.
///
/// # Safety
///
/// This is `extern "C"` and called from Go — it must not panic.
/// The `message` pointer is guaranteed valid and null-terminated by Go.
extern "C" fn log_callback(level: c_int, message: *const c_char) {
    if message.is_null() {
        return;
    }

    let msg = match unsafe { CStr::from_ptr(message) }.to_str() {
        Ok(s) => s,
        Err(_) => return, // invalid UTF-8 — skip
    };

    match level {
        0 => tracing::trace!(target: "gvproxy", "{}", msg),
        1 => tracing::debug!(target: "gvproxy", "{}", msg),
        2 => tracing::info!(target: "gvproxy", "{}", msg),
        3 => tracing::warn!(target: "gvproxy", "{}", msg),
        4 => tracing::error!(target: "gvproxy", "{}", msg),
        _ => tracing::info!(target: "gvproxy", "{}", msg),
    }
}

/// Registers the logging bridge with the Go side (idempotent).
pub fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::debug!("initializing gvproxy log callback");
        unsafe {
            super::ffi::set_log_callback(log_callback as *const std::ffi::c_void);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        init();
        init();
        init();
    }
}
