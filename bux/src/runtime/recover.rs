//! Crash recovery and graceful shutdown for the [`Runtime`].

use std::collections::HashSet;
use std::fs;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

use super::Runtime;
use super::spawn::{clean_vm_files, is_pid_alive};
use crate::state::Status;

impl Runtime {
    /// Gracefully stops all active VMs.
    ///
    /// Sends `SIGTERM` to each shim process, waits briefly, then
    /// `SIGKILL` any survivors. Called automatically when the
    /// `Runtime` is dropped, or can be called manually for
    /// coordinated shutdown.
    #[allow(
        clippy::disallowed_methods,
        reason = "sync shutdown cannot use tokio::time::sleep"
    )]
    pub fn shutdown_sync(&self) {
        let Ok(vms) = self.db.list() else { return };

        for vm in vms {
            if !vm.status.is_active() || !is_pid_alive(vm.pid) {
                continue;
            }

            info!(vm_id = %vm.id, pid = vm.pid, "stopping VM on shutdown");
            signal::kill(Pid::from_raw(vm.pid), Signal::SIGTERM).ok();

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            while is_pid_alive(vm.pid) && start.elapsed() < timeout {
                std::thread::sleep(Duration::from_millis(50));
            }

            if is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "SIGKILL after timeout");
                signal::kill(Pid::from_raw(vm.pid), Signal::SIGKILL).ok();
            }

            drop(self.db.update_status(&vm.id, Status::Stopped));
        }
    }

    /// Recovers stale state from a previous run.
    ///
    /// Three phases:
    /// 1. Auto-remove stopped VMs flagged with `auto_remove`.
    /// 2. Mark dead-but-active processes as Stopped.
    /// 3. Clean up orphaned socket files.
    #[allow(
        clippy::cognitive_complexity,
        clippy::excessive_nesting,
        reason = "three-phase recovery logic with inherent branching"
    )]
    pub(super) fn recover(&self) {
        let vms = match self.db.list() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recovery: failed to list VMs");
                return;
            }
        };

        let mut cleaned = 0u32;
        for vm in &vms {
            if vm.status == Status::Stopped && vm.config.auto_remove {
                clean_vm_files(&vm.socket);
                drop(self.disk.remove_vm_disk(&vm.id));
                drop(self.db.delete(&vm.id));
                cleaned += 1;
                continue;
            }

            if vm.status.is_active() && !is_pid_alive(vm.pid) {
                warn!(vm_id = %vm.id, pid = vm.pid, "recovery: marking dead VM as stopped");
                drop(self.db.update_status(&vm.id, Status::Stopped));

                if vm.config.auto_remove {
                    clean_vm_files(&vm.socket);
                    drop(self.disk.remove_vm_disk(&vm.id));
                    drop(self.db.delete(&vm.id));
                    cleaned += 1;
                }
            }
        }

        let known_ids: HashSet<&str> = vms.iter().map(|v| v.id.as_str()).collect();
        let orphan_exts = [".sock", ".exit", ".json", ".stderr"];
        if let Ok(entries) = fs::read_dir(&self.socks_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                let is_orphan = orphan_exts.iter().any(|ext| {
                    name_str
                        .strip_suffix(ext)
                        .is_some_and(|id| !known_ids.contains(id))
                });
                if is_orphan {
                    drop(fs::remove_file(entry.path()));
                    cleaned += 1;
                }
            }
        }

        if cleaned > 0 {
            info!(cleaned, "recovery complete");
        }
    }
}
