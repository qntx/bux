//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages VM state in a SQLite database and provides
//! methods to spawn VMs in child processes via `fork(2)` + `krun_start_enter`.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{fs, io};

use bux_proto::{AGENT_PORT, ExecReq};
use tokio::sync::OnceCell;

use crate::Result;
use crate::client::{Client, ExecEvent, ExecOutput};
use crate::disk::DiskManager;
use crate::state::{self, StateDb, Status, VmState};
use crate::vm::VmBuilder;

/// Manages the lifecycle of bux micro-VMs.
///
/// State is stored in `{data_dir}/bux.db` (SQLite).
#[derive(Debug)]
pub struct Runtime {
    /// SQLite state database.
    db: Arc<StateDb>,
    /// Directory for Unix sockets (`{data_dir}/socks/`).
    socks_dir: PathBuf,
    /// Disk image manager.
    disk: DiskManager,
}

impl Runtime {
    /// Opens (or creates) the runtime data directory and database.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let base = data_dir.as_ref();
        fs::create_dir_all(base)?;

        let socks_dir = base.join("socks");
        fs::create_dir_all(&socks_dir)?;

        let db_path = base.join("bux.db");
        let db = StateDb::open(db_path)?;
        let disk = DiskManager::open(base)?;

        #[allow(clippy::arc_with_non_send_sync)]
        // StateDb uses rusqlite::Connection (not Sync), but Arc is needed for VmHandle sharing within a single-threaded tokio runtime.
        Ok(Self {
            db: Arc::new(db),
            socks_dir,
            disk,
        })
    }

    /// Returns a reference to the disk image manager.
    pub const fn disk(&self) -> &DiskManager {
        &self.disk
    }

    /// Spawns a VM in a child process and returns a handle.
    ///
    /// # Safety
    ///
    /// Uses `fork(2)`. Must be called before spawning other threads, or
    /// from a single-threaded context.
    pub async fn spawn(
        &self,
        builder: VmBuilder,
        image: Option<String>,
        name: Option<String>,
        auto_remove: bool,
    ) -> Result<VmHandle> {
        // Validate name uniqueness via DB index.
        if let Some(ref n) = name
            && self.db.get_by_name(n)?.is_some()
        {
            return Err(crate::Error::Ambiguous(format!(
                "a VM named '{n}' already exists"
            )));
        }

        let id = state::gen_id();
        let socket = self.socks_dir.join(format!("{id}.sock"));

        // Extract config before consuming the builder.
        let mut config = builder.to_config();
        config.auto_remove = auto_remove;

        // Add vsock port so guest agent is reachable via Unix socket.
        let socket_str = socket.to_string_lossy().into_owned();
        let configured = builder.vsock_port(AGENT_PORT, &socket_str, true);

        // Fork: child becomes the VM, parent manages state.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => Err(io::Error::last_os_error().into()),
            0 => {
                // Child — build and start the VM (never returns on success).
                match configured.build().and_then(super::vm::Vm::start) {
                    Ok(()) => unreachable!(),
                    #[allow(clippy::print_stderr)] // Only way to report errors in forked child.
                    Err(e) => {
                        eprintln!("[bux] child VM start failed: {e}");
                        unsafe { libc::_exit(1) }
                    }
                }
            }
            child_pid => {
                let vm_state = VmState {
                    id,
                    name,
                    pid: child_pid,
                    image,
                    socket,
                    status: Status::Running,
                    config,
                    created_at: SystemTime::now(),
                };
                self.db.insert(&vm_state)?;

                let handle = VmHandle::new(vm_state, Arc::clone(&self.db), self.disk.clone());

                // Best-effort readiness wait.
                let _ = handle.wait_ready(Duration::from_secs(5)).await;

                Ok(handle)
            }
        }
    }

    /// Lists all known VMs, reconciling liveness and auto-removing stopped VMs.
    pub fn list(&self) -> Result<Vec<VmState>> {
        let vms = self.db.list()?;
        let mut keep = Vec::with_capacity(vms.len());

        for mut vm in vms {
            // Reconcile: mark dead processes as stopped.
            if vm.status == Status::Running && !is_pid_alive(vm.pid) {
                vm.status = Status::Stopped;
                let _ = self.db.update_status(&vm.id, Status::Stopped);
            }

            // Auto-remove stopped VMs with auto_remove flag.
            if vm.status == Status::Stopped && vm.config.auto_remove {
                let _ = fs::remove_file(&vm.socket);
                let _ = self.db.delete(&vm.id);
                continue;
            }

            keep.push(vm);
        }
        Ok(keep)
    }

    /// Retrieves a handle by name or ID prefix.
    pub fn get(&self, id_or_name: &str) -> Result<VmHandle> {
        // Try name lookup first (O(1) via UNIQUE index).
        let mut state = if let Some(s) = self.db.get_by_name(id_or_name)? {
            s
        } else {
            self.db.get_by_id_prefix(id_or_name)?
        };

        // Reconcile liveness.
        if state.status == Status::Running && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            let _ = self.db.update_status(&state.id, Status::Stopped);
        }

        Ok(VmHandle::new(
            state,
            Arc::clone(&self.db),
            self.disk.clone(),
        ))
    }

    /// Renames a VM.
    pub fn rename(&self, id_or_name: &str, new_name: &str) -> Result<()> {
        let handle = self.get(id_or_name)?;
        if let Some(existing) = self.db.get_by_name(new_name)?
            && existing.id != handle.state().id
        {
            return Err(crate::Error::Ambiguous(format!(
                "a VM named '{new_name}' already exists"
            )));
        }
        self.db.update_name(&handle.state().id, Some(new_name))?;
        Ok(())
    }

    /// Removes a stopped VM's state and socket.
    pub fn remove(&self, id_or_name: &str) -> Result<()> {
        let handle = self.get(id_or_name)?;
        let state = handle.state();

        if state.status == Status::Running && is_pid_alive(state.pid) {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VM {} is still running; stop it first", state.id),
            )));
        }

        let _ = fs::remove_file(&state.socket);
        let _ = self.disk.remove_vm_disk(&state.id);
        self.db.delete(&state.id)?;
        Ok(())
    }
}

/// Handle to a single managed VM with lazy persistent connection.
#[derive(Debug)]
pub struct VmHandle {
    /// Cached state snapshot.
    state: VmState,
    /// Shared database reference for status updates.
    db: Arc<StateDb>,
    /// Disk image manager for auto-remove cleanup.
    disk: DiskManager,
    /// Lazy persistent client connection.
    client: OnceCell<Client>,
}

impl VmHandle {
    /// Creates a new handle from a state snapshot, shared database, and disk manager.
    fn new(state: VmState, db: Arc<StateDb>, disk: DiskManager) -> Self {
        Self {
            state,
            db,
            disk,
            client: OnceCell::new(),
        }
    }

    /// Returns the current state snapshot.
    pub const fn state(&self) -> &VmState {
        &self.state
    }

    /// Lazily connects to the guest agent (reuses across calls).
    async fn client(&self) -> Result<&Client> {
        self.client
            .get_or_try_init(|| async {
                Client::connect(&self.state.socket)
                    .await
                    .map_err(crate::Error::from)
            })
            .await
    }

    /// Executes a command, streaming output via callback. Returns exit code.
    pub async fn exec_stream(&self, req: ExecReq, on: impl FnMut(ExecEvent)) -> Result<i32> {
        Ok(self.client().await?.exec_stream(req, on).await?)
    }

    /// Executes a command and collects all output.
    pub async fn exec(&self, req: ExecReq) -> Result<ExecOutput> {
        Ok(self.client().await?.exec(req).await?)
    }

    /// Graceful shutdown with default 10 s timeout.
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_timeout(Duration::from_secs(10)).await
    }

    /// Graceful shutdown: sends `Shutdown` request, waits up to `timeout`,
    /// then falls back to `SIGKILL`.
    pub async fn stop_timeout(&mut self, timeout: Duration) -> Result<()> {
        if let Ok(c) = self.client().await {
            let _ = c.shutdown().await;
        }

        let result = tokio::time::timeout(timeout, async {
            while is_pid_alive(self.state.pid) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        if result.is_ok() {
            return self.mark_stopped();
        }
        self.kill()
    }

    /// Sends `SIGKILL` to the VM process.
    pub fn kill(&mut self) -> Result<()> {
        unsafe {
            libc::kill(self.state.pid, libc::SIGKILL);
        }
        self.mark_stopped()
    }

    /// Returns `true` if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        is_pid_alive(self.state.pid)
    }

    /// Sends a POSIX signal to the VM process.
    pub fn signal(&self, sig: i32) -> Result<()> {
        let ret = unsafe { libc::kill(self.state.pid, sig) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    /// Waits for the VM process to exit. Returns the exit status.
    pub async fn wait(&mut self) -> Result<()> {
        while is_pid_alive(self.state.pid) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.mark_stopped()
    }

    /// Executes a command with stdin data piped to the process.
    pub async fn exec_with_stdin(
        &self,
        req: ExecReq,
        stdin_data: &[u8],
        on: impl FnMut(ExecEvent),
    ) -> Result<i32> {
        Ok(self
            .client()
            .await?
            .exec_with_stdin(req, stdin_data, on)
            .await?)
    }

    /// Reads a file from the guest filesystem.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client().await?.read_file(path).await?)
    }

    /// Writes a file to the guest filesystem.
    pub async fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        Ok(self.client().await?.write_file(path, data, mode).await?)
    }

    /// Copies a tar archive into the guest, unpacking at `dest`.
    pub async fn copy_in(&self, dest: &str, tar_data: &[u8]) -> Result<()> {
        Ok(self.client().await?.copy_in(dest, tar_data).await?)
    }

    /// Copies a path from the guest as a tar archive.
    pub async fn copy_out(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.client().await?.copy_out(path).await?)
    }

    /// Performs a version handshake with the guest agent.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.client().await?.handshake().await?)
    }

    /// Waits for the guest agent to become reachable via a single
    /// connect + handshake probe per attempt.
    async fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                if let Ok(c) = Client::connect(&self.state.socket).await
                    && c.handshake().await.is_ok()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest agent did not become ready"))
    }

    /// Updates status to Stopped and persists. If `auto_remove` is set,
    /// deletes the VM record, socket, and disk image.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;

        if self.state.config.auto_remove {
            let _ = fs::remove_file(&self.state.socket);
            let _ = self.disk.remove_vm_disk(&self.state.id);
            self.db.delete(&self.state.id)?;
        } else {
            self.db.update_status(&self.state.id, Status::Stopped)?;
        }
        Ok(())
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
fn is_pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}
