//! VM lifecycle management: spawn, list, stop, kill, remove.
//!
//! The [`Runtime`] manages a directory of VM state files and provides
//! methods to spawn VMs in child processes via `fork(2)` + `krun_start_enter`.
//!
//! # Platform
//!
//! This module is only available on Unix (Linux / macOS).

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

use bux_proto::{AGENT_PORT, ExecReq};

use crate::Result;
use crate::client::{Client, ExecOutput};
use crate::state::{self, Status, VmState};
use crate::vm::VmBuilder;

/// Manages the lifecycle of bux micro-VMs.
///
/// State files are stored as JSON in `{data_dir}/vms/`.
#[derive(Debug)]
pub struct Runtime {
    /// Directory containing `{id}.json` state files and `{id}.sock` sockets.
    vms_dir: PathBuf,
}

impl Runtime {
    /// Opens (or creates) the runtime state directory.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let vms_dir = data_dir.as_ref().join("vms");
        fs::create_dir_all(&vms_dir)?;
        Ok(Self { vms_dir })
    }

    /// Spawns a VM in a child process and returns a handle.
    ///
    /// The `builder` is consumed: a vsock port mapping is added automatically
    /// so the host can communicate with the guest agent. The child process
    /// calls [`VmBuilder::build`] + [`Vm::start`] (which never returns).
    ///
    /// # Safety
    ///
    /// Uses `fork(2)`. Must be called before spawning other threads, or
    /// from a single-threaded context.
    pub fn spawn(&self, builder: VmBuilder, image: Option<String>) -> Result<VmHandle> {
        let id = state::gen_id();
        let socket = self.vms_dir.join(format!("{id}.sock"));
        let state_path = self.vms_dir.join(format!("{id}.json"));

        // Extract config before consuming the builder.
        let config = builder.to_config();

        // Add vsock port so guest agent is reachable via Unix socket.
        let socket_str = socket.to_string_lossy().into_owned();
        let builder = builder.vsock_port(AGENT_PORT, &socket_str, true);

        // Fork: child becomes the VM, parent manages state.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => Err(io::Error::last_os_error().into()),
            0 => {
                // Child — build and start the VM (never returns on success).
                match builder.build().and_then(|vm| vm.start()) {
                    Ok(()) => unreachable!(),
                    Err(e) => {
                        eprintln!("[bux] child VM start failed: {e}");
                        unsafe { libc::_exit(1) }
                    }
                }
            }
            child_pid => {
                // Parent — persist state and wait for the guest agent.
                let vm_state = VmState {
                    id: id.clone(),
                    pid: child_pid as u32,
                    image,
                    socket: socket.clone(),
                    status: Status::Running,
                    config,
                    created_at: SystemTime::now(),
                };
                vm_state.save(&state_path)?;

                let handle = VmHandle {
                    state: vm_state,
                    state_path,
                };

                // Best-effort readiness wait (5 s timeout).
                let _ = handle.wait_ready(Duration::from_secs(5));

                Ok(handle)
            }
        }
    }

    /// Lists all known VMs (running and stopped).
    pub fn list(&self) -> Result<Vec<VmState>> {
        let mut vms = Vec::new();
        for entry in fs::read_dir(&self.vms_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Ok(mut st) = VmState::load(&path) {
                    // Reconcile status with actual process liveness.
                    if st.status == Status::Running && !is_pid_alive(st.pid) {
                        st.status = Status::Stopped;
                        let _ = st.save(&path);
                    }
                    vms.push(st);
                }
            }
        }
        Ok(vms)
    }

    /// Retrieves a handle to an existing VM by (prefix of) its ID.
    pub fn get(&self, id_prefix: &str) -> Result<VmHandle> {
        let state_path = self.resolve_id(id_prefix)?;
        let mut state = VmState::load(&state_path)?;
        if state.status == Status::Running && !is_pid_alive(state.pid) {
            state.status = Status::Stopped;
            let _ = state.save(&state_path);
        }
        Ok(VmHandle { state, state_path })
    }

    /// Removes a stopped VM's state and socket files.
    pub fn remove(&self, id_prefix: &str) -> Result<()> {
        let state_path = self.resolve_id(id_prefix)?;
        let state = VmState::load(&state_path)?;

        if state.status == Status::Running && is_pid_alive(state.pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VM {} is still running; stop it first", state.id),
            )
            .into());
        }

        let _ = fs::remove_file(&state.socket);
        fs::remove_file(&state_path)?;
        Ok(())
    }

    /// Resolves an ID prefix to the full state file path.
    fn resolve_id(&self, prefix: &str) -> Result<PathBuf> {
        // Try exact match first.
        let exact = self.vms_dir.join(format!("{prefix}.json"));
        if exact.exists() {
            return Ok(exact);
        }
        // Prefix search.
        let mut matches = Vec::new();
        for entry in fs::read_dir(&self.vms_dir)? {
            let path = entry?.path();
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.starts_with(prefix) && path.extension().is_some_and(|e| e == "json") {
                    matches.push(path);
                }
            }
        }
        match matches.len() {
            0 => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no VM matching prefix '{prefix}'"),
            )
            .into()),
            1 => Ok(matches.into_iter().next().expect("len == 1")),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ambiguous prefix '{prefix}' matches {} VMs", matches.len()),
            )
            .into()),
        }
    }
}

/// Handle to a single managed VM.
#[derive(Debug)]
pub struct VmHandle {
    /// Cached state (may be stale; call [`refresh`] to update).
    state: VmState,
    /// Path to the JSON state file.
    state_path: PathBuf,
}

impl VmHandle {
    /// Returns the current state snapshot.
    pub fn state(&self) -> &VmState {
        &self.state
    }

    /// Re-reads state from disk and reconciles liveness.
    pub fn refresh(&mut self) -> Result<()> {
        self.state = VmState::load(&self.state_path)?;
        if self.state.status == Status::Running && !is_pid_alive(self.state.pid) {
            self.state.status = Status::Stopped;
            let _ = self.state.save(&self.state_path);
        }
        Ok(())
    }

    /// Executes a command inside the guest and collects output.
    pub fn exec(&self, req: ExecReq) -> Result<ExecOutput> {
        let mut c = Client::connect(&self.state.socket)?;
        Ok(c.exec(req)?)
    }

    /// Graceful shutdown: sends `Shutdown` request, waits up to 5 s,
    /// then falls back to `SIGKILL`.
    pub fn stop(&mut self) -> Result<()> {
        // Try protocol-level shutdown.
        if let Ok(mut c) = Client::connect(&self.state.socket) {
            let _ = c.shutdown();
        }
        // Wait for process to exit.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !is_pid_alive(self.state.pid) {
                return self.mark_stopped();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Force kill.
        self.kill()
    }

    /// Sends `SIGKILL` to the VM process.
    pub fn kill(&mut self) -> Result<()> {
        unsafe {
            libc::kill(self.state.pid as i32, libc::SIGKILL);
        }
        std::thread::sleep(Duration::from_millis(100));
        self.mark_stopped()
    }

    /// Returns `true` if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        is_pid_alive(self.state.pid)
    }

    /// Reads a file from the guest filesystem.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let mut c = Client::connect(&self.state.socket)?;
        Ok(c.read_file(path)?)
    }

    /// Writes a file to the guest filesystem.
    pub fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let mut c = Client::connect(&self.state.socket)?;
        Ok(c.write_file(path, data, mode)?)
    }

    /// Pings the guest agent. Returns `Ok(())` if reachable.
    pub fn ping(&self) -> Result<()> {
        let mut c = Client::connect(&self.state.socket)?;
        Ok(c.ping()?)
    }

    /// Waits for the guest agent to become reachable.
    fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(mut c) = Client::connect(&self.state.socket) {
                if c.ping().is_ok() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "guest agent did not become ready",
        ))
    }

    /// Updates status to Stopped and persists.
    fn mark_stopped(&mut self) -> Result<()> {
        self.state.status = Status::Stopped;
        self.state.save(&self.state_path)?;
        Ok(())
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
fn is_pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}
