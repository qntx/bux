//! Virtual machine builder and lifecycle management.

mod builder;

pub use builder::VmBuilder;

use bux_krun::{Feature, KernelFormat, LogStyle, Result, SyncMode, ctx as sys};

use crate::log_level::LogLevel;

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
        VmBuilder::new()
    }

    /// Creates a `Vm` wrapping a raw libkrun context ID.
    pub(super) const fn from_raw_ctx(ctx: u32) -> Self {
        Self { ctx }
    }

    /// Returns the raw libkrun context ID.
    pub(super) const fn ctx(&self) -> u32 {
        self.ctx
    }

    /// Returns the maximum number of vCPUs supported by the hypervisor.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn max_vcpus() -> Result<u32> {
        sys::get_max_vcpus()
    }

    /// Checks if a build-time feature is enabled in this libkrun build.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn has_feature(feature: Feature) -> Result<bool> {
        sys::has_feature(feature)
    }

    /// Checks if nested virtualization is supported (macOS only).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn check_nested_virt() -> Result<bool> {
        sys::check_nested_virt()
    }

    /// Adds a raw disk image as a general partition.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_disk(&self, block_id: &str, path: &str, read_only: bool) -> Result<()> {
        sys::add_disk(self.ctx, block_id, path, read_only)
    }

    /// Adds a disk image with an explicit format.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_disk2(
        &self,
        block_id: &str,
        path: &str,
        format: sys::DiskFormat,
        read_only: bool,
    ) -> Result<()> {
        sys::add_disk2(self.ctx, block_id, path, format, read_only)
    }

    /// Adds a disk image with full options: format, direct I/O, and sync mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_disk3(
        &self,
        block_id: &str,
        path: &str,
        format: sys::DiskFormat,
        read_only: bool,
        direct_io: bool,
        sync: SyncMode,
    ) -> Result<()> {
        sys::add_disk3(self.ctx, block_id, path, format, read_only, direct_io, sync)
    }

    /// Configures a block device as the root filesystem (remount after boot).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_root_disk_remount(
        &self,
        device: &str,
        fstype: Option<&str>,
        options: Option<&str>,
    ) -> Result<()> {
        sys::set_root_disk_remount(self.ctx, device, fstype, options)
    }

    /// Adds a virtio-net device with a Unix stream backend (passt / socket\_vmnet).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_net_unixstream(
        &self,
        path: Option<&str>,
        fd: i32,
        mac: [u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        sys::add_net_unixstream(self.ctx, path, fd, &mac, features, flags)
    }

    /// Adds a virtio-net device with a Unix datagram backend (gvproxy / vmnet-helper).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_net_unixgram(
        &self,
        path: Option<&str>,
        fd: i32,
        mac: [u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        sys::add_net_unixgram(self.ctx, path, fd, &mac, features, flags)
    }

    /// Adds a virtio-net device with a TAP backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_net_tap(&self, name: &str, mac: [u8; 6], features: u32, flags: u32) -> Result<()> {
        sys::add_net_tap(self.ctx, name, &mac, features, flags)
    }

    /// Sets the MAC address for the virtio-net device.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_net_mac(&self, mac: [u8; 6]) -> Result<()> {
        sys::set_net_mac(self.ctx, &mac)
    }

    /// Maps a vsock port to a host Unix socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_vsock_port(&self, port: u32, path: &str) -> Result<()> {
        sys::add_vsock_port(self.ctx, port, path)
    }

    /// Maps a vsock port to a host Unix socket with direction control.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_vsock_port2(&self, port: u32, path: &str, listen: bool) -> Result<()> {
        sys::add_vsock_port2(self.ctx, port, path, listen)
    }

    /// Adds a vsock device with specified TSI features.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_vsock(&self, tsi_features: u32) -> Result<()> {
        sys::add_vsock(self.ctx, tsi_features)
    }

    /// Disables the implicit vsock device.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn disable_implicit_vsock(&self) -> Result<()> {
        sys::disable_implicit_vsock(self.ctx)
    }

    /// Enables a virtio-gpu device.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_gpu_options(&self, virgl_flags: u32) -> Result<()> {
        sys::set_gpu_options(self.ctx, virgl_flags)
    }

    /// Enables a virtio-gpu device with SHM window size.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_gpu_options2(&self, virgl_flags: u32, shm_size: u64) -> Result<()> {
        sys::set_gpu_options2(self.ctx, virgl_flags, shm_size)
    }

    /// Adds a display output. Returns the display ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_display(&self, width: u32, height: u32) -> Result<u32> {
        sys::add_display(self.ctx, width, height)
    }

    /// Sets a custom EDID blob for a display.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn display_set_edid(&self, display_id: u32, edid: &[u8]) -> Result<()> {
        sys::display_set_edid(self.ctx, display_id, edid)
    }

    /// Sets DPI for a display.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn display_set_dpi(&self, display_id: u32, dpi: u32) -> Result<()> {
        sys::display_set_dpi(self.ctx, display_id, dpi)
    }

    /// Sets the physical size of a display in millimeters.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn display_set_physical_size(&self, display_id: u32, w_mm: u16, h_mm: u16) -> Result<()> {
        sys::display_set_physical_size(self.ctx, display_id, w_mm, h_mm)
    }

    /// Sets the refresh rate for a display in Hz.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn display_set_refresh_rate(&self, display_id: u32, hz: u32) -> Result<()> {
        sys::display_set_refresh_rate(self.ctx, display_id, hz)
    }

    /// Adds a host input device by file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_input_device_fd(&self, fd: i32) -> Result<()> {
        sys::add_input_device_fd(self.ctx, fd)
    }

    /// Sets the firmware path.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_firmware(&self, path: &str) -> Result<()> {
        sys::set_firmware(self.ctx, path)
    }

    /// Sets the kernel, initramfs, and command line.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_kernel(
        &self,
        path: &str,
        format: KernelFormat,
        initramfs: Option<&str>,
        cmdline: Option<&str>,
    ) -> Result<()> {
        sys::set_kernel(self.ctx, path, format, initramfs, cmdline)
    }

    /// Sets the TEE configuration file path (libkrun-SEV only).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_tee_config_file(&self, path: &str) -> Result<()> {
        sys::set_tee_config_file(self.ctx, path)
    }

    /// Sets SMBIOS OEM strings.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_smbios_oem_strings(&self, strings: &[String]) -> Result<()> {
        sys::set_smbios_oem_strings(self.ctx, strings)
    }

    /// Initializes logging with full control.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn init_log(target_fd: i32, level: u32, style: LogStyle, options: u32) -> Result<()> {
        sys::init_log(target_fd, level, style, options)
    }

    /// Disables the implicit console device.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn disable_implicit_console(&self) -> Result<()> {
        sys::disable_implicit_console(self.ctx)
    }

    /// Adds a default virtio console with explicit file descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_virtio_console_default(
        &self,
        input_fd: i32,
        output_fd: i32,
        err_fd: i32,
    ) -> Result<()> {
        sys::add_virtio_console_default(self.ctx, input_fd, output_fd, err_fd)
    }

    /// Adds a default serial console with explicit file descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_serial_console_default(&self, input_fd: i32, output_fd: i32) -> Result<()> {
        sys::add_serial_console_default(self.ctx, input_fd, output_fd)
    }

    /// Creates a virtio console multiport device. Returns the console ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_virtio_console_multiport(&self) -> Result<u32> {
        sys::add_virtio_console_multiport(self.ctx)
    }

    /// Adds a TTY port to a multiport console.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_console_port_tty(&self, console_id: u32, name: &str, tty_fd: i32) -> Result<()> {
        sys::add_console_port_tty(self.ctx, console_id, name, tty_fd)
    }

    /// Adds an I/O port to a multiport console.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn add_console_port_inout(
        &self,
        console_id: u32,
        name: &str,
        input_fd: i32,
        output_fd: i32,
    ) -> Result<()> {
        sys::add_console_port_inout(self.ctx, console_id, name, input_fd, output_fd)
    }

    /// Sets the kernel console device identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn set_kernel_console(&self, console_id: &str) -> Result<()> {
        sys::set_kernel_console(self.ctx, console_id)
    }

    /// Returns the eventfd to signal guest shutdown (libkrun-EFI only).
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn get_shutdown_eventfd(&self) -> Result<i32> {
        sys::get_shutdown_eventfd(self.ctx)
    }

    /// Enables or disables split IRQCHIP between host and guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the FFI call fails.
    pub fn split_irqchip(&self, enable: bool) -> Result<()> {
        sys::split_irqchip(self.ctx, enable)
    }

    /// Starts the microVM, taking over the current process.
    ///
    /// On success this function **never returns** — libkrun assumes full
    /// control of the process and calls `exit()` when the VM shuts down.
    /// It only returns if an error occurs *before* the VM starts.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM fails to start.
    pub fn start(self) -> Result<()> {
        let this = std::mem::ManuallyDrop::new(self);
        sys::start_enter(this.ctx)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        drop(sys::free_ctx(self.ctx));
    }
}
