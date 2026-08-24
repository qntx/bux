//! Runtime and per-VM metrics collection.
//!
//! All counters use atomic operations for lock-free reads and writes.
//! Monotonically increasing counters (created, failed) never decrease;
//! gauges (running, disk usage) can go up and down.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Runtime-level metrics covering all VMs managed by this [`Runtime`](crate::Runtime).
///
/// Created once per [`Runtime`](crate::Runtime) and shared via `Arc`.
/// All reads use `Relaxed` ordering (sufficient for counters and gauges).
#[derive(Debug)]
pub struct RuntimeMetrics {
    /// Total number of VMs created (monotonic).
    vms_created: AtomicU64,
    /// Number of currently running VMs (gauge).
    vms_running: AtomicI64,
    /// Total number of VMs that exited with an error (monotonic).
    vms_failed: AtomicU64,
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
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vms_created: AtomicU64::new(0),
            vms_running: AtomicI64::new(0),
            vms_failed: AtomicU64::new(0),
            total_uptime_ms: AtomicU64::new(0),
            disk_bytes_used: AtomicU64::new(0),
        }
    }

    /// Total number of VMs created since runtime start (monotonic counter).
    pub fn vms_created_total(&self) -> u64 {
        self.vms_created.load(Ordering::Relaxed)
    }

    /// Number of VMs currently in `Running` state (gauge).
    pub fn num_running_vms(&self) -> i64 {
        self.vms_running.load(Ordering::Relaxed)
    }

    /// Total number of VMs that exited with errors (monotonic counter).
    pub fn vms_failed_total(&self) -> u64 {
        self.vms_failed.load(Ordering::Relaxed)
    }

    /// Cumulative uptime of all VMs in milliseconds (monotonic counter).
    pub fn total_uptime_ms(&self) -> u64 {
        self.total_uptime_ms.load(Ordering::Relaxed)
    }

    /// Current total disk usage across all VM overlays in bytes (gauge).
    pub fn disk_bytes_used(&self) -> u64 {
        self.disk_bytes_used.load(Ordering::Relaxed)
    }

    /// Records that a new VM was created.
    pub(crate) fn on_vm_created(&self) {
        self.vms_created.fetch_add(1, Ordering::Relaxed);
        self.vms_running.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a VM was stopped (normal exit).
    pub(crate) fn on_vm_stopped(&self, uptime_ms: u64) {
        self.vms_running.fetch_sub(1, Ordering::Relaxed);
        self.total_uptime_ms.fetch_add(uptime_ms, Ordering::Relaxed);
    }

    /// Records that a VM exited with an error.
    ///
    /// Called by the health check system when a VM process dies unexpectedly.
    pub fn on_vm_failed(&self, uptime_ms: u64) {
        self.vms_running.fetch_sub(1, Ordering::Relaxed);
        self.vms_failed.fetch_add(1, Ordering::Relaxed);
        self.total_uptime_ms.fetch_add(uptime_ms, Ordering::Relaxed);
    }

    /// Updates the total disk usage gauge.
    pub fn set_disk_bytes_used(&self, bytes: u64) {
        self.disk_bytes_used.store(bytes, Ordering::Relaxed);
    }
}

/// Per-VM metrics for a single instance.
///
/// Typically embedded in a [`Vm`](crate::Vm) and updated as operations run.
#[derive(Debug)]
pub struct VmMetrics {
    /// Time from spawn to guest-agent-ready in milliseconds.
    boot_duration_ms: AtomicU64,
    /// Total number of exec operations run on this VM (monotonic).
    exec_count: AtomicU64,
    /// Duration of the most recent exec in milliseconds.
    last_exec_duration_ms: AtomicU64,
}

impl Default for VmMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl VmMetrics {
    /// Creates a new per-VM metrics instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            boot_duration_ms: AtomicU64::new(0),
            exec_count: AtomicU64::new(0),
            last_exec_duration_ms: AtomicU64::new(0),
        }
    }

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
#[allow(clippy::unwrap_used, reason = "tests use unwrap for clarity")]
mod tests {
    use super::*;

    #[test]
    fn runtime_metrics_counters() {
        let m = RuntimeMetrics::new();
        assert_eq!(m.vms_created_total(), 0);
        assert_eq!(m.num_running_vms(), 0);

        m.on_vm_created();
        m.on_vm_created();
        assert_eq!(m.vms_created_total(), 2);
        assert_eq!(m.num_running_vms(), 2);

        m.on_vm_stopped(5000);
        assert_eq!(m.num_running_vms(), 1);
        assert_eq!(m.total_uptime_ms(), 5000);

        m.on_vm_failed(3000);
        assert_eq!(m.num_running_vms(), 0);
        assert_eq!(m.vms_failed_total(), 1);
        assert_eq!(m.total_uptime_ms(), 8000);
    }

    #[test]
    fn vm_metrics_exec_tracking() {
        let m = VmMetrics::new();
        m.set_boot_duration_ms(1500);
        assert_eq!(m.boot_duration_ms(), 1500);

        m.on_exec_completed(200);
        m.on_exec_completed(350);
        assert_eq!(m.exec_count(), 2);
        assert_eq!(m.last_exec_duration_ms(), 350);
    }
}
