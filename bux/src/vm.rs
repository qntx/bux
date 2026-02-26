//! Virtual machine builder and lifecycle management.

use crate::error::Result;
#[cfg(unix)]
use crate::state::VmConfig;
use crate::sys::{self, DiskFormat, Feature, KernelFormat, LogStyle, SyncMode};

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
    /// Root filesystem directory path.
    root: Option<String>,
    /// Root filesystem disk image path (mutually exclusive with `root`).
    root_disk: Option<String>,
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
    /// UID to set before starting the VM.
    uid: Option<u32>,
    /// GID to set before starting the VM.
    gid: Option<u32>,
    /// Resource limits (`RESOURCE=RLIM_CUR:RLIM_MAX`).
    rlimits: Vec<String>,
    /// Enable nested virtualization (macOS only).
    nested_virt: Option<bool>,
    /// Enable/disable virtio-snd.
    snd_device: Option<bool>,
    /// Redirect console output to a file.
    console_output: Option<String>,
    /// vsock port mappings `(guest_port, host_socket_path, listen)`.
    vsock_ports: Vec<(u32, String, bool)>,
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

    /// Sets the root filesystem directory path (virtiofs-based).
    pub fn root(mut self, path: impl Into<String>) -> Self {
        self.root = Some(path.into());
        self.root_disk = None;
        self
    }

    /// Sets the root filesystem disk image path (block device-based).
    ///
    /// The image is attached as `/dev/vda` and remounted as the root
    /// filesystem during boot. Mutually exclusive with [`root()`](Self::root).
    pub fn root_disk(mut self, path: impl Into<String>) -> Self {
        self.root_disk = Some(path.into());
        self.root = None;
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

    /// Sets the UID before starting the VM.
    pub const fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Sets the GID before starting the VM.
    pub const fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    /// Adds a resource limit (`"RESOURCE=RLIM_CUR:RLIM_MAX"` format).
    pub fn rlimit(mut self, rlimit: impl Into<String>) -> Self {
        self.rlimits.push(rlimit.into());
        self
    }

    /// Enables or disables nested virtualization (macOS only).
    pub const fn nested_virt(mut self, enable: bool) -> Self {
        self.nested_virt = Some(enable);
        self
    }

    /// Enables or disables the virtio-snd audio device.
    pub const fn snd_device(mut self, enable: bool) -> Self {
        self.snd_device = Some(enable);
        self
    }

    /// Redirects console output to a file (ignores stdin).
    pub fn console_output(mut self, path: impl Into<String>) -> Self {
        self.console_output = Some(path.into());
        self
    }

    /// Maps a guest vsock port to a host Unix socket path.
    ///
    /// When `listen` is `true`, the guest listens on the vsock port and the
    /// host connects to the Unix socket (typical for guest agent pattern).
    pub fn vsock_port(mut self, port: u32, host_path: impl Into<String>, listen: bool) -> Self {
        self.vsock_ports.push((port, host_path.into(), listen));
        self
    }

    /// Extracts a serializable configuration snapshot.
    #[cfg(unix)]
    pub(crate) fn to_config(&self) -> VmConfig {
        VmConfig {
            vcpus: self.vcpus,
            ram_mib: self.ram_mib,
            rootfs: self.root.clone(),
            root_disk: self.root_disk.clone(),
            exec_path: self.exec_path.clone(),
            exec_args: self.exec_args.clone(),
            env: self.env.clone(),
            workdir: self.workdir.clone(),
            ports: self.ports.clone(),
            auto_remove: false,
        }
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
        } else if let Some(ref disk) = self.root_disk {
            sys::add_disk(vm.ctx, "rootfs", disk, false)?;
            sys::set_root_disk_remount(vm.ctx, "/dev/vda", Some("ext4"), None)?;
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

        if let Some(uid) = self.uid {
            sys::setuid(vm.ctx, uid)?;
        }
        if let Some(gid) = self.gid {
            sys::setgid(vm.ctx, gid)?;
        }
        if !self.rlimits.is_empty() {
            sys::set_rlimits(vm.ctx, &self.rlimits)?;
        }
        if let Some(enable) = self.nested_virt {
            sys::set_nested_virt(vm.ctx, enable)?;
        }
        if let Some(enable) = self.snd_device {
            sys::set_snd_device(vm.ctx, enable)?;
        }
        if let Some(ref path) = self.console_output {
            sys::set_console_output(vm.ctx, path)?;
        }
        for (port, path, listen) in &self.vsock_ports {
            sys::add_vsock_port2(vm.ctx, *port, path, *listen)?;
        }

        Ok(vm)
    }
}

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

    /// Checks if a build-time feature is enabled in this libkrun build.
    pub fn has_feature(feature: Feature) -> Result<bool> {
        sys::has_feature(feature)
    }

    /// Checks if nested virtualization is supported (macOS only).
    pub fn check_nested_virt() -> Result<bool> {
        sys::check_nested_virt()
    }

    /// Adds a raw disk image as a general partition.
    pub fn add_disk(&mut self, block_id: &str, path: &str, read_only: bool) -> Result<()> {
        sys::add_disk(self.ctx, block_id, path, read_only)
    }

    /// Adds a disk image with an explicit format.
    pub fn add_disk2(
        &mut self,
        block_id: &str,
        path: &str,
        format: DiskFormat,
        read_only: bool,
    ) -> Result<()> {
        sys::add_disk2(self.ctx, block_id, path, format, read_only)
    }

    /// Adds a disk image with full options: format, direct I/O, and sync mode.
    pub fn add_disk3(
        &mut self,
        block_id: &str,
        path: &str,
        format: DiskFormat,
        read_only: bool,
        direct_io: bool,
        sync: SyncMode,
    ) -> Result<()> {
        sys::add_disk3(self.ctx, block_id, path, format, read_only, direct_io, sync)
    }

    /// Configures a block device as the root filesystem (remount after boot).
    pub fn set_root_disk_remount(
        &mut self,
        device: &str,
        fstype: Option<&str>,
        options: Option<&str>,
    ) -> Result<()> {
        sys::set_root_disk_remount(self.ctx, device, fstype, options)
    }

    /// Adds a virtio-net device with a Unix stream backend (passt / socket\_vmnet).
    pub fn add_net_unixstream(
        &mut self,
        path: Option<&str>,
        fd: i32,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        sys::add_net_unixstream(self.ctx, path, fd, mac, features, flags)
    }

    /// Adds a virtio-net device with a Unix datagram backend (gvproxy / vmnet-helper).
    pub fn add_net_unixgram(
        &mut self,
        path: Option<&str>,
        fd: i32,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        sys::add_net_unixgram(self.ctx, path, fd, mac, features, flags)
    }

    /// Adds a virtio-net device with a TAP backend.
    pub fn add_net_tap(
        &mut self,
        name: &str,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        sys::add_net_tap(self.ctx, name, mac, features, flags)
    }

    /// Sets the MAC address for the virtio-net device.
    pub fn set_net_mac(&mut self, mac: &[u8; 6]) -> Result<()> {
        sys::set_net_mac(self.ctx, mac)
    }

    /// Maps a vsock port to a host Unix socket path.
    pub fn add_vsock_port(&mut self, port: u32, path: &str) -> Result<()> {
        sys::add_vsock_port(self.ctx, port, path)
    }

    /// Maps a vsock port to a host Unix socket with direction control.
    pub fn add_vsock_port2(&mut self, port: u32, path: &str, listen: bool) -> Result<()> {
        sys::add_vsock_port2(self.ctx, port, path, listen)
    }

    /// Adds a vsock device with specified TSI features.
    pub fn add_vsock(&mut self, tsi_features: u32) -> Result<()> {
        sys::add_vsock(self.ctx, tsi_features)
    }

    /// Disables the implicit vsock device.
    pub fn disable_implicit_vsock(&mut self) -> Result<()> {
        sys::disable_implicit_vsock(self.ctx)
    }

    /// Enables a virtio-gpu device.
    pub fn set_gpu_options(&mut self, virgl_flags: u32) -> Result<()> {
        sys::set_gpu_options(self.ctx, virgl_flags)
    }

    /// Enables a virtio-gpu device with SHM window size.
    pub fn set_gpu_options2(&mut self, virgl_flags: u32, shm_size: u64) -> Result<()> {
        sys::set_gpu_options2(self.ctx, virgl_flags, shm_size)
    }

    /// Adds a display output. Returns the display ID.
    pub fn add_display(&mut self, width: u32, height: u32) -> Result<u32> {
        sys::add_display(self.ctx, width, height)
    }

    /// Sets a custom EDID blob for a display.
    pub fn display_set_edid(&mut self, display_id: u32, edid: &[u8]) -> Result<()> {
        sys::display_set_edid(self.ctx, display_id, edid)
    }

    /// Sets DPI for a display.
    pub fn display_set_dpi(&mut self, display_id: u32, dpi: u32) -> Result<()> {
        sys::display_set_dpi(self.ctx, display_id, dpi)
    }

    /// Sets the physical size of a display in millimeters.
    pub fn display_set_physical_size(
        &mut self,
        display_id: u32,
        w_mm: u16,
        h_mm: u16,
    ) -> Result<()> {
        sys::display_set_physical_size(self.ctx, display_id, w_mm, h_mm)
    }

    /// Sets the refresh rate for a display in Hz.
    pub fn display_set_refresh_rate(&mut self, display_id: u32, hz: u32) -> Result<()> {
        sys::display_set_refresh_rate(self.ctx, display_id, hz)
    }

    /// Adds a host input device by file descriptor.
    pub fn add_input_device_fd(&mut self, fd: i32) -> Result<()> {
        sys::add_input_device_fd(self.ctx, fd)
    }

    /// Sets the firmware path.
    pub fn set_firmware(&mut self, path: &str) -> Result<()> {
        sys::set_firmware(self.ctx, path)
    }

    /// Sets the kernel, initramfs, and command line.
    pub fn set_kernel(
        &mut self,
        path: &str,
        format: KernelFormat,
        initramfs: Option<&str>,
        cmdline: Option<&str>,
    ) -> Result<()> {
        sys::set_kernel(self.ctx, path, format, initramfs, cmdline)
    }

    /// Sets the TEE configuration file path (libkrun-SEV only).
    pub fn set_tee_config_file(&mut self, path: &str) -> Result<()> {
        sys::set_tee_config_file(self.ctx, path)
    }

    /// Sets SMBIOS OEM strings.
    pub fn set_smbios_oem_strings(&mut self, strings: &[String]) -> Result<()> {
        sys::set_smbios_oem_strings(self.ctx, strings)
    }

    /// Initializes logging with full control.
    pub fn init_log(
        &mut self,
        target_fd: i32,
        level: u32,
        style: LogStyle,
        options: u32,
    ) -> Result<()> {
        sys::init_log(target_fd, level, style, options)
    }

    /// Disables the implicit console device.
    pub fn disable_implicit_console(&mut self) -> Result<()> {
        sys::disable_implicit_console(self.ctx)
    }

    /// Adds a default virtio console with explicit file descriptors.
    pub fn add_virtio_console_default(
        &mut self,
        input_fd: i32,
        output_fd: i32,
        err_fd: i32,
    ) -> Result<()> {
        sys::add_virtio_console_default(self.ctx, input_fd, output_fd, err_fd)
    }

    /// Adds a default serial console with explicit file descriptors.
    pub fn add_serial_console_default(&mut self, input_fd: i32, output_fd: i32) -> Result<()> {
        sys::add_serial_console_default(self.ctx, input_fd, output_fd)
    }

    /// Creates a virtio console multiport device. Returns the console ID.
    pub fn add_virtio_console_multiport(&mut self) -> Result<u32> {
        sys::add_virtio_console_multiport(self.ctx)
    }

    /// Adds a TTY port to a multiport console.
    pub fn add_console_port_tty(&mut self, console_id: u32, name: &str, tty_fd: i32) -> Result<()> {
        sys::add_console_port_tty(self.ctx, console_id, name, tty_fd)
    }

    /// Adds an I/O port to a multiport console.
    pub fn add_console_port_inout(
        &mut self,
        console_id: u32,
        name: &str,
        input_fd: i32,
        output_fd: i32,
    ) -> Result<()> {
        sys::add_console_port_inout(self.ctx, console_id, name, input_fd, output_fd)
    }

    /// Sets the kernel console device identifier.
    pub fn set_kernel_console(&mut self, console_id: &str) -> Result<()> {
        sys::set_kernel_console(self.ctx, console_id)
    }

    /// Returns the eventfd to signal guest shutdown (libkrun-EFI only).
    pub fn get_shutdown_eventfd(&self) -> Result<i32> {
        sys::get_shutdown_eventfd(self.ctx)
    }

    /// Enables or disables split IRQCHIP between host and guest.
    pub fn split_irqchip(&mut self, enable: bool) -> Result<()> {
        sys::split_irqchip(self.ctx, enable)
    }

    /// Starts the microVM, taking over the current process.
    ///
    /// On success this function **never returns** — libkrun assumes full
    /// control of the process and calls `exit()` when the VM shuts down.
    /// It only returns if an error occurs *before* the VM starts.
    pub fn start(self) -> Result<()> {
        let ctx = self.ctx;
        std::mem::forget(self);
        sys::start_enter(ctx)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = sys::free_ctx(self.ctx);
    }
}
