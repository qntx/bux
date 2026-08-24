//! Crash recovery and graceful shutdown for the [`Runtime`].

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

use super::Runtime;
use super::boot::{clean_vm_files, is_pid_alive};
use crate::lifecycle::{self, RecoverAction, SECRETS_RESUPPLY_ERROR};
use crate::ports::{parse_concrete_port_strings, parse_publish_spec, resolve_ports};
use crate::state::{Status, VmConfig, VmState};

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
        let Ok(vms) = self.db.list() else {
            return;
        };

        for vm in vms {
            if !vm.status.is_active() || !is_pid_alive(vm.pid) {
                continue;
            }

            info!(vm_id = %vm.id, pid = vm.pid, "stopping VM on shutdown");
            terminate_pid(vm.pid, &vm.id);
            drop(self.db.update_status(&vm.id, Status::Stopped));
            self.net.stop(&vm.id);
        }

        self.net.stop_all();
    }

    /// Recovers stale state from a previous run.
    ///
    /// Phases:
    /// 1. Auto-remove stopped VMs flagged with `auto_remove`.
    /// 2. For active rows: dead PID → Stopped; live PID + secrets → fail-closed (K28);
    ///    live + `virtio_net` → reattach gvproxy; else vsock-only.
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
            cleaned += self.recover_one(vm);
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
    fn recover_one(&self, mut vm: VmState) -> u32 {
        if vm.status == Status::Stopped && vm.config.auto_remove {
            self.purge_vm_files(&vm);
            return 1;
        }

        if !vm.status.is_active() {
            return 0;
        }

        let action = lifecycle::recover_action(
            is_pid_alive(vm.pid),
            vm.config.secrets_required,
            vm.config.network.is_enabled(),
        );

        match action {
            RecoverAction::MarkDeadStopped => self.recover_dead(&vm),
            RecoverAction::FailClosedSecrets => self.recover_secrets_fail_closed(&mut vm),
            RecoverAction::ReattachNetwork => {
                self.recover_reattach_net(&vm);
                0
            }
            RecoverAction::ReattachVsockOnly => {
                info!(vm_id = %vm.id, "recovery: orphaned VM still alive (offline / vsock only)");
                0
            }
        }
    }

    /// Mark a dead active VM as stopped (optionally purge).
    fn recover_dead(&self, vm: &VmState) -> u32 {
        warn!(vm_id = %vm.id, pid = vm.pid, "recovery: marking dead VM as stopped");
        drop(self.db.update_status(&vm.id, Status::Stopped));
        self.net.stop(&vm.id);
        if vm.config.auto_remove {
            self.purge_vm_files(vm);
            1
        } else {
            0
        }
    }

    /// K28: stop live VM that needs secrets after Runtime restart.
    fn recover_secrets_fail_closed(&self, vm: &mut VmState) -> u32 {
        warn!(
            vm_id = %vm.id,
            pid = vm.pid,
            "recovery: secrets_required — fail-closed stop (K28)"
        );
        terminate_pid(vm.pid, &vm.id);
        vm.config.last_error = Some(SECRETS_RESUPPLY_ERROR.to_owned());
        drop(self.db.update_status(&vm.id, Status::Stopped));
        drop(self.db.update_config(&vm.id, &vm.config));
        self.net.stop(&vm.id);
        1
    }

    /// Rebuild host-side gvproxy for a still-running virtio-net VM.
    fn recover_reattach_net(&self, vm: &VmState) {
        match reattach_network_ports(self, &vm.id, &vm.config) {
            Ok(()) => info!(vm_id = %vm.id, "recovery: gvproxy reattached"),
            Err(e) => warn!(
                vm_id = %vm.id,
                error = %e,
                "recovery: gvproxy reattach failed; leaving VM running without host net backend"
            ),
        }
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
            if is_pid_alive(vm.pid) {
                terminate_pid(vm.pid, &vm.id);
            }
            drop(self.db.update_status(&vm.id, Status::Stopped));
            self.net.stop(&vm.id);
            let mut cfg = vm.config.clone();
            cfg.last_activity_at = Some(now);
            drop(self.db.update_config(&vm.id, &cfg));
            report.stopped += 1;

            let should_delete =
                vm.config.auto_remove || expired(vm.config.auto_delete_secs, Some(now));
            if should_delete && self.remove(&vm.id).is_ok() {
                report.deleted += 1;
            }
            return;
        }

        if vm.status == Status::Stopped
            && expired(vm.config.auto_delete_secs, vm.config.last_activity_at)
        {
            info!(vm_id = %vm.id, "sweep: auto-delete idle stopped VM");
            if self.remove(&vm.id).is_ok() {
                report.deleted += 1;
            }
        }
    }
}

/// Rebuild gvproxy for an orphaned virtio-net VM (no secrets).
fn reattach_network_ports(rt: &Runtime, vm_id: &str, config: &VmConfig) -> crate::Result<()> {
    let mut specs = Vec::with_capacity(config.ports.len());
    for s in &config.ports {
        if let Ok(pair) = parse_concrete_one(s) {
            specs.push(pair);
            continue;
        }
        let spec = parse_publish_spec(s)?;
        let (pairs, _) = resolve_ports(std::slice::from_ref(&spec))?;
        specs.extend(pairs);
    }
    if specs.is_empty() && !config.ports.is_empty() {
        specs = parse_concrete_port_strings(&config.ports)?;
    }
    let _ = rt
        .net
        .start(vm_id, specs, config.network.allow_net().to_vec(), None)?;
    Ok(())
}

/// SIGTERM then optional SIGKILL for a shim PID.
#[allow(
    clippy::disallowed_methods,
    reason = "sync recovery cannot use tokio::time::sleep"
)]
fn terminate_pid(pid: i32, vm_id: &str) {
    signal::kill(Pid::from_raw(pid), Signal::SIGTERM).ok();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    while is_pid_alive(pid) && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(50));
    }
    if is_pid_alive(pid) {
        warn!(vm_id, pid, "SIGKILL after recovery/stop timeout");
        signal::kill(Pid::from_raw(pid), Signal::SIGKILL).ok();
    }
}

/// Remove sock/json/stderr files for VMs no longer in the database.
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
    for ext in [".sock", ".exit", ".json", ".stderr"] {
        if let Some(id) = name_str.strip_suffix(ext)
            && !known_ids.contains(id)
        {
            return true;
        }
    }
    false
}

/// Parse a single concrete `host:guest` pair.
fn parse_concrete_one(s: &str) -> crate::Result<(u16, u16)> {
    let (h, g) = s
        .split_once(':')
        .ok_or_else(|| crate::Error::InvalidConfig(format!("invalid port pair {s}")))?;
    let host: u16 = h
        .parse()
        .map_err(|_| crate::Error::InvalidConfig(format!("invalid host port in {s}")))?;
    let guest: u16 = g
        .parse()
        .map_err(|_| crate::Error::InvalidConfig(format!("invalid guest port in {s}")))?;
    if host == 0 {
        return Err(crate::Error::InvalidConfig(
            "ephemeral host port not valid for reattach".into(),
        ));
    }
    Ok((host, guest))
}
