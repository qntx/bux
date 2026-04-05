//! Background health checking for running VMs.
//!
//! Periodically pings the guest agent and updates the VM's [`HealthState`]
//! in the database. Optionally triggers automatic restart when a VM
//! becomes unhealthy.

#[cfg(unix)]
/// Unix health-check implementation using tokio background tasks.
mod inner {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::watch;
    use tracing::{info, warn};

    use crate::client::Client;
    use crate::state::{HealthState, StateDb};

    /// Configuration for periodic health checks.
    #[derive(Debug, Clone, Copy)]
    #[non_exhaustive]
    pub struct HealthCheckConfig {
        /// Interval between health probes (default: 30 s).
        pub interval: Duration,
        /// Timeout for each individual probe (default: 5 s).
        pub timeout: Duration,
        /// Number of consecutive failures before marking unhealthy (default: 3).
        pub failure_threshold: u32,
    }

    impl Default for HealthCheckConfig {
        fn default() -> Self {
            Self {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                failure_threshold: 3,
            }
        }
    }

    /// Handle to a running health check background task.
    ///
    /// Dropping this handle cancels the background task.
    #[derive(Debug)]
    pub struct HealthCheckHandle {
        /// Send to stop the background task.
        _cancel: watch::Sender<bool>,
        /// Current consecutive failure count (shared with the task).
        failures: Arc<AtomicU32>,
    }

    impl HealthCheckHandle {
        /// Returns the current number of consecutive health check failures.
        pub fn consecutive_failures(&self) -> u32 {
            self.failures.load(Ordering::Relaxed)
        }
    }

    /// Starts a background health check task for a VM.
    ///
    /// Returns a handle that can be used to query status or cancel the task
    /// (dropping the handle also cancels it).
    pub fn start(
        vm_id: String,
        client: Client,
        db: Arc<StateDb>,
        config: HealthCheckConfig,
    ) -> HealthCheckHandle {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let failures = Arc::new(AtomicU32::new(0));
        let failures_clone = Arc::clone(&failures);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(config.interval) => {},
                    () = async { let _ = cancel_rx.changed().await; } => break,
                }

                let result =
                    tokio::time::timeout(config.timeout, client.ping()).await;

                match result {
                    Ok(Ok(_)) => {
                        let prev = failures_clone.swap(0, Ordering::Relaxed);
                        if prev > 0 {
                            info!(vm_id = %vm_id, "health check recovered after {prev} failures");
                        }
                        let _ = db.update_health(&vm_id, HealthState::Healthy);
                    }
                    Ok(Err(e)) => {
                        let count = failures_clone.fetch_add(1, Ordering::Relaxed) + 1;
                        if count >= config.failure_threshold {
                            warn!(
                                vm_id = %vm_id,
                                failures = count,
                                error = %e,
                                "VM marked unhealthy"
                            );
                            let _ = db.update_health(&vm_id, HealthState::Unhealthy);
                        }
                    }
                    Err(_timeout) => {
                        let count = failures_clone.fetch_add(1, Ordering::Relaxed) + 1;
                        if count >= config.failure_threshold {
                            warn!(
                                vm_id = %vm_id,
                                failures = count,
                                "health check timed out — VM marked unhealthy"
                            );
                            let _ = db.update_health(&vm_id, HealthState::Unhealthy);
                        }
                    }
                }
            }
        });

        HealthCheckHandle {
            _cancel: cancel_tx,
            failures,
        }
    }
}

#[cfg(unix)]
pub use inner::{HealthCheckConfig, HealthCheckHandle, start};
