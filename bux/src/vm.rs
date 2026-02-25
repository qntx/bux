//! Virtual machine builder and lifecycle management.

use crate::error::Result;
use crate::sys;

// ---------------------------------------------------------------------------
// LogLevel
// ---------------------------------------------------------------------------

/// Log verbosity level for libkrun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
#[repr(u32)]
pub enum LogLevel {
    /// Logging disabled.
    Off = 0,
    /// Errors only.
    Error = 1,
    /// Errors and warnings.
    Warn = 2,
    /// Errors, warnings, and informational messages.
    #[default]
    Info = 3,
    /// Verbose debug output.
    Debug = 4,
    /// Maximum verbosity.
    Trace = 5,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(format!("unknown log level: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// VmBuilder
// ---------------------------------------------------------------------------

/// Builder for configuring a micro-VM.
///
/// Defaults: 1 vCPU, 512 MiB RAM, host environment inherited.
///
/// # Example
///
/// ```no_run
/// use bux::Vm;
///
/// let vm = Vm::builder()
///     .vcpus(2)
///     .ram_mib(1024)
///     .root("/path/to/rootfs")
///     .exec("/bin/bash", &["--login"])
///     .build()
///     .expect("invalid VM config");
/// ```
#[derive(Debug, Default)]
#[must_use = "a VmBuilder does nothing until .build() is called"]
pub struct VmBuilder {
    /// Number of virtual CPUs.
    vcpus: u8,
    /// RAM size in MiB.
    ram_mib: u32,
    /// Root filesystem path.
    root: Option<String>,
    /// Executable path inside the VM.
    exec_path: Option<String>,
    /// Arguments passed to the executable (does not include argv[0]).
    exec_args: Vec<String>,
    /// Environment variables (`KEY=VALUE`). `None` = inherit from host.
    env: Option<Vec<String>>,
    /// Working directory inside the VM.
    workdir: Option<String>,
    /// TCP port mappings (`"host_port:guest_port"`).
    ports: Vec<String>,
    /// virtio-fs shared directories `(tag, host_path)`.
    virtiofs: Vec<(String, String)>,
    /// Global log level for libkrun.
    log_level: Option<LogLevel>,
}

impl VmBuilder {
    /// Sets the number of virtual CPUs (default: 1).
    pub const fn vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Sets the RAM size in MiB (default: 512).
    pub const fn ram_mib(mut self, mib: u32) -> Self {
        self.ram_mib = mib;
        self
    }

    /// Sets the root filesystem path for process isolation.
    pub fn root(mut self, path: impl Into<String>) -> Self {
        self.root = Some(path.into());
        self
    }

    /// Sets the executable and its arguments to run inside the VM.
    ///
    /// `args` should **not** include the program name (argv\[0\]).
    pub fn exec(mut self, path: impl Into<String>, args: &[&str]) -> Self {
        self.exec_path = Some(path.into());
        self.exec_args = args.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Sets explicit environment variables (`KEY=VALUE` format).
    ///
    /// If never called, the host environment is inherited automatically.
    pub fn env(mut self, vars: &[&str]) -> Self {
        self.env = Some(vars.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    /// Sets the working directory inside the VM.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Adds a TCP port mapping in `"host_port:guest_port"` format.
    pub fn port(mut self, mapping: impl Into<String>) -> Self {
        self.ports.push(mapping.into());
        self
    }

    /// Adds a virtio-fs shared directory.
    ///
    /// - `tag` — identifier used to mount the filesystem in the guest.
    /// - `host_path` — absolute path to the directory on the host.
    pub fn virtiofs(mut self, tag: impl Into<String>, host_path: impl Into<String>) -> Self {
        self.virtiofs.push((tag.into(), host_path.into()));
        self
    }

    /// Sets the global libkrun log level (applies to all VMs in the process).
    pub const fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Builds and returns the configured [`Vm`].
    ///
    /// Creates a libkrun context and applies all configuration. If any step
    /// fails, the context is automatically freed.
    pub fn build(self) -> Result<Vm> {
        let ctx = sys::create_ctx()?;
        // Vm's Drop impl frees the context on any subsequent error.
        let vm = Vm { ctx };

        if let Some(level) = self.log_level {
            sys::set_log_level(level as u32)?;
        }

        sys::set_vm_config(vm.ctx, self.vcpus, self.ram_mib)?;

        if let Some(ref root) = self.root {
            sys::set_root(vm.ctx, root)?;
        }

        for (tag, host_path) in &self.virtiofs {
            sys::add_virtiofs(vm.ctx, tag, host_path)?;
        }

        if !self.ports.is_empty() {
            sys::set_port_map(vm.ctx, &self.ports)?;
        }

        if let Some(ref workdir) = self.workdir {
            sys::set_workdir(vm.ctx, workdir)?;
        }

        if let Some(ref exec_path) = self.exec_path {
            sys::set_exec(vm.ctx, exec_path, &self.exec_args, self.env.as_deref())?;
        } else if let Some(ref env) = self.env {
            sys::set_env(vm.ctx, env)?;
        }

        Ok(vm)
    }
}

// ---------------------------------------------------------------------------
// Vm
// ---------------------------------------------------------------------------

/// A configured micro-VM ready to start.
///
/// Created via [`Vm::builder()`]. The underlying libkrun context is
/// automatically freed when the `Vm` is dropped.
#[derive(Debug)]
pub struct Vm {
    /// libkrun configuration context ID.
    ctx: u32,
}

impl Vm {
    /// Returns a new [`VmBuilder`] with sensible defaults.
    pub fn builder() -> VmBuilder {
        VmBuilder {
            vcpus: 1,
            ram_mib: 512,
            ..VmBuilder::default()
        }
    }

    /// Returns the maximum number of vCPUs supported by the hypervisor.
    pub fn max_vcpus() -> Result<u32> {
        sys::get_max_vcpus()
    }

    /// Starts the microVM, taking over the current process.
    ///
    /// # Warning
    ///
    /// On success this function **never returns** — libkrun assumes full
    /// control of the process and calls `exit()` when the VM shuts down.
    /// It only returns if an error occurs *before* the VM starts.
    pub fn start(self) -> Result<()> {
        let ctx = self.ctx;
        // krun_start_enter consumes the context; prevent double-free via Drop.
        std::mem::forget(self);
        sys::start_enter(ctx)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = sys::free_ctx(self.ctx);
    }
}
