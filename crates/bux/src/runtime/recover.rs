//! Crash recovery and graceful shutdown for the [`Runtime`].

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use bux_jail::ShimProcess;
use tracing::{info, warn};

use super::Runtime;
use super::boot::clean_vm_files;
use crate::lifecycle::{self, RecoverAction};
use crate::state::{Status, VmState};

impl Runtime {
    /// Gracefully stops all active non-detached VMs.
    ///
    /// Asks each shim process to exit, waits briefly, then kills any
    /// survivors. Called automatically when the `Runtime` is dropped, or
    /// can be called manually for coordinated shutdown. Detached rows are
    /// left running.
    #[allow(
        clippy::disallowed_methods,
        reason = "sync shutdown cannot use tokio::time::sleep"
    )]
    pub fn shutdown_sync(&self) {
        let Ok(vms) = self.db.list() else {
            return;
        };

        for vm in vms {
            if !vm.status.is_active() || !vm.process().is_alive() || vm.config.detach {
                continue;
            }

            info!(vm_id = %vm.id, pid = vm.pid, "stopping VM on shutdown");
            terminate(vm.process(), &vm.id);
            drop(self.db.update_status(&vm.id, Status::Stopped));
        }
    }

    /// Recovers stale state from a previous run.
    ///
    /// Phases:
    /// 1. Auto-remove stopped VMs flagged with `auto_remove`.
    /// 2. For active rows: dead shim (or its PID now held by another
    ///    process) → Stopped; live shim → vsock-only (the shim owns
    ///    gvproxy and secrets; do not SIGTERM).
    /// 3. Clean up orphaned socket files.
    pub(super) fn recover(&self) {
        let vms = match self.db.list() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recovery: failed to list VMs");
                return;
            }
        };

        let mut cleaned = 0u32;
        for vm in vms {
            cleaned += self.recover_one(&vm);
        }

        let known_ids: HashSet<String> = self
            .db
            .list()
            .map(|list| list.into_iter().map(|v| v.id).collect())
            .unwrap_or_default();
        cleaned += clean_orphan_socks(&self.socks_dir, &known_ids);

        if cleaned > 0 {
            info!(cleaned, "recovery complete");
        }
    }

    /// Recover a single VM row; returns count of cleaned items (0 or 1+).
    fn recover_one(&self, vm: &VmState) -> u32 {
        if vm.status == Status::Stopped && vm.config.auto_remove {
            self.purge_vm_files(vm);
            return 1;
        }

        if !vm.status.is_active() {
            return 0;
        }

        match lifecycle::recover_action(vm.process().is_alive()) {
            RecoverAction::MarkDeadStopped => self.recover_dead(vm),
            RecoverAction::ReattachVsockOnly => {
                info!(vm_id = %vm.id, "recovery: live shim (vsock reattach; net stays in-process)");
                0
            }
        }
    }

    /// Mark a dead active VM as stopped (optionally purge).
    fn recover_dead(&self, vm: &VmState) -> u32 {
        warn!(vm_id = %vm.id, pid = vm.pid, "recovery: marking dead VM as stopped");
        drop(self.db.update_status(&vm.id, Status::Stopped));
        // purge_vm_files includes clean_vm_files; do not call both.
        if vm.config.auto_remove {
            self.purge_vm_files(vm);
        } else {
            clean_vm_files(&vm.socket);
        }
        1
    }

    /// Delete sock/disk/db rows for a VM.
    fn purge_vm_files(&self, vm: &VmState) {
        clean_vm_files(&vm.socket);
        drop(self.volumes.unlink_vm(&vm.id));
        drop(self.disk.remove_vm_disk(&vm.id));
        drop(self.db.delete(&vm.id));
    }

    /// Apply idle `auto_stop_secs` / `auto_delete_secs` policies (default off).
    ///
    /// Call periodically from the embedder (no background task is started by default).
    ///
    /// # Errors
    ///
    /// Returns an error if listing VMs fails. Individual stop/delete failures are logged.
    pub fn sweep(&self) -> crate::Result<lifecycle::SweepReport> {
        let now = SystemTime::now();
        let vms = self.db.list()?;
        let mut report = lifecycle::SweepReport::default();

        for vm in &vms {
            self.sweep_one(now, vm, &mut report);
        }

        Ok(report)
    }

    /// Evaluate idle policies for one VM row.
    fn sweep_one(&self, now: SystemTime, vm: &VmState, report: &mut lifecycle::SweepReport) {
        let expired = |policy: Option<u64>, last: Option<SystemTime>| {
            lifecycle::idle_expired(now, last, vm.created_at, policy)
        };

        if vm.status.is_active() && expired(vm.config.auto_stop_secs, vm.config.last_activity_at) {
            info!(vm_id = %vm.id, "sweep: auto-stop idle VM");
            terminate(vm.process(), &vm.id);
            drop(self.db.update_status(&vm.id, Status::Stopped));
            clean_vm_files(&vm.socket);
            let mut cfg = vm.config.clone();
            cfg.last_activity_at = Some(now);
            drop(self.db.update_config(&vm.id, &cfg));
            report.stopped += 1;

            let should_delete =
                vm.config.auto_remove || expired(vm.config.auto_delete_secs, Some(now));
            if should_delete && self.remove_stored(vm).is_ok() {
                report.deleted += 1;
            }
            return;
        }

        if vm.status == Status::Stopped
            && expired(vm.config.auto_delete_secs, vm.config.last_activity_at)
        {
            info!(vm_id = %vm.id, "sweep: auto-delete idle stopped VM");
            if self.remove_stored(vm).is_ok() {
                report.deleted += 1;
            }
        }
    }
}

/// Terminate a shim, then kill it if it is still alive after 5 s.
#[allow(
    clippy::disallowed_methods,
    reason = "sync recovery cannot use tokio::time::sleep"
)]
fn terminate(process: ShimProcess, vm_id: &str) {
    if !process.is_alive() {
        return;
    }
    log_failed_signal(vm_id, process.terminate());
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    while process.is_alive() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(50));
    }
    if process.is_alive() {
        warn!(
            vm_id,
            pid = process.pid(),
            "kill after recovery/stop timeout"
        );
        log_failed_signal(vm_id, process.kill());
    }
}

/// Log that a VM may still be running after `result`.
fn log_failed_signal(vm_id: &str, result: std::io::Result<()>) {
    if let Err(e) = result {
        warn!(vm_id, error = %e, "failed to stop VM");
    }
}

/// Remove sock/json/log files for VMs no longer in the database.
fn clean_orphan_socks(socks_dir: &Path, known_ids: &HashSet<String>) -> u32 {
    let Ok(entries) = fs::read_dir(socks_dir) else {
        return 0;
    };
    let mut cleaned = 0u32;
    for entry in entries.flatten() {
        if sock_entry_is_orphan(&entry.file_name(), known_ids) {
            drop(fs::remove_file(entry.path()));
            cleaned += 1;
        }
    }
    cleaned
}

/// Whether a `socks_dir` file name belongs to an unknown VM id.
fn sock_entry_is_orphan(name: &std::ffi::OsStr, known_ids: &HashSet<String>) -> bool {
    let Some(name_str) = name.to_str() else {
        return false;
    };
    if let Some(id) = name_str.strip_suffix(".net.sock") {
        return !known_ids.contains(id);
    }
    for ext in [".sock", ".exit", ".json", ".log"] {
        if let Some(id) = name_str.strip_suffix(ext)
            && !known_ids.contains(id)
        {
            return true;
        }
    }
    false
}
