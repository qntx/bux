//! RAII wrapper for a gvproxy instance.
//!
//! [`GvproxyInstance`] owns an FFI handle and calls `gvproxy_destroy`
//! on [`Drop`], ensuring Go-side resources are always released.

#![allow(
    unsafe_code,
    reason = "exposes `unsafe impl Send` for the FFI handle; CGO serialises internally"
)]

use std::path::{Path, PathBuf};
use std::sync::Weak;

use crate::config::GvproxyConfig;
use crate::error::{Error, Result};
use crate::{ffi, logging, stats::NetworkStats};

/// Safe, RAII wrapper around a gvproxy (gvisor-tap-vsock) instance.
///
/// # Resource management
///
/// Dropping the instance calls `gvproxy_destroy` so the Go runtime
/// shuts down the virtual network and cleans up its Unix socket.
///
/// # Thread safety
///
/// The underlying CGO layer handles synchronisation internally, so
/// `GvproxyInstance` is `Send`.
#[derive(Debug)]
pub struct GvproxyInstance {
    /// Opaque handle returned by `gvproxy_create`.
    id: i64,
    /// The socket path provided at creation time.
    socket_path: PathBuf,
}

impl GvproxyInstance {
    /// Creates a new gvproxy instance from a [`GvproxyConfig`].
    ///
    /// The Go→Rust logging bridge is initialised on first call
    /// (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if the config cannot be serialised and
    /// [`Error::Ffi`] if the Go side rejects the configuration.
    pub fn new(config: &GvproxyConfig) -> Result<Self> {
        logging::init();

        let socket_path = config.socket_path.clone();
        let id = ffi::create_instance(config)?;

        tracing::info!(id, ?socket_path, "created GvproxyInstance");

        Ok(Self { id, socket_path })
    }

    /// Unix socket path for the network tap interface.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// FFI handle (used by stats logging and other internal callers).
    #[must_use]
    pub const fn id(&self) -> i64 {
        self.id
    }

    /// Fetches live network statistics from the Go side.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Ffi`] if the Go side returns NULL or the JSON
    /// cannot be parsed.
    pub fn get_stats(&self) -> Result<NetworkStats> {
        let json = ffi::get_stats_json(self.id)?;
        tracing::debug!("received stats JSON: {json}");
        NetworkStats::from_json_str(&json).map_err(|e| {
            Error::Ffi(format!(
                "failed to parse stats JSON from gvproxy: {e} (raw: {json})"
            ))
        })
    }
}

impl Drop for GvproxyInstance {
    fn drop(&mut self) {
        tracing::debug!(id = self.id, "dropping GvproxyInstance");
        if let Err(e) = ffi::destroy_instance(self.id) {
            tracing::error!(id = self.id, error = %e, "failed to destroy gvproxy instance");
        }
    }
}

// SAFETY: The Go CGO runtime serialises all calls into `libgvproxy`
// internally, so passing the opaque handle across thread boundaries is
// sound. No Rust-side data inside `GvproxyInstance` is shared without
// a lock: only the `i64` handle and an immutable `PathBuf`.
unsafe impl Send for GvproxyInstance {}

/// Spawns a background tokio task that logs network statistics every
/// 30 seconds.  Holds only a [`Weak`] reference so it exits
/// automatically when the last `Arc<GvproxyInstance>` is dropped.
///
/// This is a convenience for callers that want "fire-and-forget"
/// stats visibility; ignore it if you poll [`GvproxyInstance::get_stats`]
/// on your own schedule.
pub fn start_stats_logging(instance: Weak<GvproxyInstance>) {
    tokio::spawn(async move {
        // Let the instance stabilise before the first log.
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        loop {
            let Some(inst) = instance.upgrade() else {
                tracing::debug!("stats logging task exiting (instance dropped)");
                break;
            };

            let stats = match inst.get_stats() {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "failed to get stats (instance may be shutting down)");
                    drop(inst);
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                    continue;
                }
            };

            tracing::info!(
                bytes_sent = stats.bytes_sent,
                bytes_received = stats.bytes_received,
                tcp_established = stats.tcp.current_established,
                tcp_failed = stats.tcp.failed_connection_attempts,
                tcp_retransmits = stats.tcp.retransmits,
                tcp_timeouts = stats.tcp.timeouts,
                "network statistics"
            );

            if stats.tcp.forward_max_inflight_drop > 0 {
                tracing::warn!(
                    drops = stats.tcp.forward_max_inflight_drop,
                    "TCP connections dropped due to maxInFlight limit"
                );
            }

            // Release the Arc before sleeping.
            drop(inst);
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });

    tracing::debug!("started background stats logging task");
}
