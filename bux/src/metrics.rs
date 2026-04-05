//! Runtime and per-box metrics collection.
//!
//! All counters use atomic operations for lock-free reads and writes.
//! Monotonically increasing counters (created, failed) never decrease;
//! gauges (running, disk usage) can go up and down.
//!
//! Callers are responsible for computing deltas when needed —
//! this matches the Prometheus / Tokio RuntimeMetrics convention.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Runtime-level metrics covering all VMs managed by this [`Runtime`](crate::Runtime).
///
/// Created once per [`Runtime`](crate::Runtime) and shared via `Arc`.
/// All reads use `Relaxed` ordering (sufficient for counters and gauges).
#[derive(Debug)]
pub struct RuntimeMetrics {
    /// Total number of VMs created (monotonic).
    boxes_created: AtomicU64,
    /// Number of currently running VMs (gauge).
    boxes_running: AtomicI64,
    /// Total number of VMs that exited with an error (monotonic).
    boxes_failed: AtomicU64,
    /// Cumulative uptime across all VMs in milliseconds (monotonic).
    total_uptime_ms: AtomicU64,
    /// Current total disk usage in bytes across all VM overlays (gauge).
    disk_bytes_used: AtomicU64,
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMetrics {
    /// Creates a new metrics instance with all counters at zero.
    pub const fn new() -> Self {
        Self {
            boxes_created: AtomicU64::new(0),
            boxes_running: AtomicI64::new(0),
            boxes_failed: AtomicU64::new(0),
            total_uptime_ms: AtomicU64::new(0),
            disk_bytes_used: AtomicU64::new(0),
        }
    }

    // ---- Read accessors ----

    /// Total number of VMs created since runtime start (monotonic counter).
    pub fn boxes_created_total(&self) -> u64 {
        self.boxes_created.load(Ordering::Relaxed)
    }

    /// Number of VMs currently in `Running` state (gauge).
    pub fn num_running_boxes(&self) -> i64 {
        self.boxes_running.load(Ordering::Relaxed)
    }

    /// Total number of VMs that exited with errors (monotonic counter).
    pub fn boxes_failed_total(&self) -> u64 {
        self.boxes_failed.load(Ordering::Relaxed)
    }

    /// Cumulative uptime of all VMs in milliseconds (monotonic counter).
    pub fn total_uptime_ms(&self) -> u64 {
        self.total_uptime_ms.load(Ordering::Relaxed)
    }

    /// Current total disk usage across all VM overlays in bytes (gauge).
    pub fn disk_bytes_used(&self) -> u64 {
        self.disk_bytes_used.load(Ordering::Relaxed)
    }

    // ---- Mutation (internal) ----

    /// Records that a new VM was created.
    pub(crate) fn on_box_created(&self) {
        self.boxes_created.fetch_add(1, Ordering::Relaxed);
        self.boxes_running.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a VM was stopped (normal exit).
    pub(crate) fn on_box_stopped(&self, uptime_ms: u64) {
        self.boxes_running.fetch_sub(1, Ordering::Relaxed);
        self.total_uptime_ms.fetch_add(uptime_ms, Ordering::Relaxed);
    }

    /// Records that a VM exited with an error.
    ///
    /// Called by the health check system when a VM process dies unexpectedly.
    pub fn on_box_failed(&self, uptime_ms: u64) {
        self.boxes_running.fetch_sub(1, Ordering::Relaxed);
        self.boxes_failed.fetch_add(1, Ordering::Relaxed);
        self.total_uptime_ms.fetch_add(uptime_ms, Ordering::Relaxed);
    }

    /// Updates the total disk usage gauge.
    ///
    /// Called after GC or disk operations to refresh the disk usage counter.
    pub fn set_disk_bytes_used(&self, bytes: u64) {
        self.disk_bytes_used.store(bytes, Ordering::Relaxed);
    }
}

/// Per-box metrics for a single VM instance.
///
/// Typically embedded in a [`VmHandle`](crate::VmHandle) and updated
/// as operations are performed on the VM.
#[derive(Debug)]
pub struct BoxMetrics {
    /// Time from spawn to guest-agent-ready in milliseconds.
    boot_duration_ms: AtomicU64,
    /// Total number of exec operations run on this VM (monotonic).
    exec_count: AtomicU64,
    /// Duration of the most recent exec in milliseconds.
    last_exec_duration_ms: AtomicU64,
}

impl Default for BoxMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BoxMetrics {
    /// Creates a new per-box metrics instance.
    pub const fn new() -> Self {
        Self {
            boot_duration_ms: AtomicU64::new(0),
            exec_count: AtomicU64::new(0),
            last_exec_duration_ms: AtomicU64::new(0),
        }
    }

    // ---- Read accessors ----

    /// Time from spawn to guest-agent-ready in milliseconds.
    pub fn boot_duration_ms(&self) -> u64 {
        self.boot_duration_ms.load(Ordering::Relaxed)
    }

    /// Total number of exec operations (monotonic counter).
    pub fn exec_count(&self) -> u64 {
        self.exec_count.load(Ordering::Relaxed)
    }

    /// Duration of the most recent exec in milliseconds.
    pub fn last_exec_duration_ms(&self) -> u64 {
        self.last_exec_duration_ms.load(Ordering::Relaxed)
    }

    // ---- Mutation (internal) ----

    /// Records the boot duration.
    pub(crate) fn set_boot_duration_ms(&self, ms: u64) {
        self.boot_duration_ms.store(ms, Ordering::Relaxed);
    }

    /// Records a completed exec operation.
    pub(crate) fn on_exec_completed(&self, duration_ms: u64) {
        self.exec_count.fetch_add(1, Ordering::Relaxed);
        self.last_exec_duration_ms
            .store(duration_ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn runtime_metrics_counters() {
        let m = RuntimeMetrics::new();
        assert_eq!(m.boxes_created_total(), 0);
        assert_eq!(m.num_running_boxes(), 0);

        m.on_box_created();
        m.on_box_created();
        assert_eq!(m.boxes_created_total(), 2);
        assert_eq!(m.num_running_boxes(), 2);

        m.on_box_stopped(5000);
        assert_eq!(m.num_running_boxes(), 1);
        assert_eq!(m.total_uptime_ms(), 5000);

        m.on_box_failed(3000);
        assert_eq!(m.num_running_boxes(), 0);
        assert_eq!(m.boxes_failed_total(), 1);
        assert_eq!(m.total_uptime_ms(), 8000);
    }

    #[test]
    fn box_metrics_exec_tracking() {
        let m = BoxMetrics::new();
        m.set_boot_duration_ms(1500);
        assert_eq!(m.boot_duration_ms(), 1500);

        m.on_exec_completed(200);
        m.on_exec_completed(350);
        assert_eq!(m.exec_count(), 2);
        assert_eq!(m.last_exec_duration_ms(), 350);
    }
}
