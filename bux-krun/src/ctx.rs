//! Safe wrappers around the raw `krun_*` FFI calls.
//!
//! Every public function in this module corresponds 1:1 to a
//! non-deprecated `krun_*` C entry point declared by [`libkrun.h`].
//! All `unsafe` inside `bux-krun` is confined here and in [`crate::sys`].
//!
//! Callers manage libkrun context IDs directly: start with
//! [`create_ctx`] (returns `u32`), pass the ID to the various
//! configuration helpers (`set_vm_config`, `add_disk`, …), and either
//! [`start_enter`] (takes over the process) or [`free_ctx`] to release
//! it. Higher layers (`bux`) wrap the raw context ID in RAII types.
//!
//! [`libkrun`]: https://github.com/containers/libkrun
//! [`libkrun.h`]: https://github.com/qntx/libkrun/blob/main/include/libkrun.h

#![allow(
    unsafe_code,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::missing_safety_doc,
    reason = "FFI wrapper module — every unsafe block is a direct 1:1 krun_* call; safety invariants are documented on the wrapping function"
)]

use std::ffi::{CString, c_char};

use crate::error::{Error, Result};
use crate::sys;

/// Disk image format for [`add_disk2`] / [`add_disk3`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum DiskFormat {
    /// Raw disk image.
    Raw = 0,
    /// QCOW2 copy-on-write image.
    Qcow2 = 1,
    /// VMDK image.
    Vmdk = 2,
}

/// Block-device sync mode for [`add_disk3`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
#[repr(u32)]
pub enum SyncMode {
    /// No sync.
    #[default]
    None = 0,
    /// Relaxed sync (macOS: skip drive flush).
    Relaxed = 1,
    /// Full sync with `VIRTIO_BLK_F_FLUSH`.
    Full = 2,
}

/// Log output style (terminal escape sequences) for [`init_log`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
#[repr(u32)]
pub enum LogStyle {
    /// Auto-detect based on terminal.
    #[default]
    Auto = 0,
    /// Always use color.
    Always = 1,
    /// Never use color.
    Never = 2,
}

/// Kernel image format for [`set_kernel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum KernelFormat {
    /// Raw binary.
    Raw = 0,
    /// ELF executable.
    Elf = 1,
    /// PE compressed with gzip.
    PeGz = 2,
    /// Linux Image compressed with bzip2.
    ImageBz2 = 3,
    /// Linux Image compressed with gzip.
    ImageGz = 4,
    /// Linux Image compressed with zstd.
    ImageZstd = 5,
}

/// Build-time feature flag for [`has_feature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u64)]
pub enum Feature {
    /// Networking (TSI).
    Net = 0,
    /// Block devices.
    Blk = 1,
    /// GPU (virgl).
    Gpu = 2,
    /// Sound.
    Snd = 3,
    /// Input devices.
    Input = 4,
    /// EFI firmware.
    Efi = 5,
    /// Trusted Execution Environment.
    Tee = 6,
    /// AMD SEV.
    AmdSev = 7,
    /// Intel TDX.
    IntelTdx = 8,
    /// AWS Nitro Enclaves.
    AwsNitro = 9,
    /// virgl resource map v2.
    VirglResourceMap2 = 10,
}

/// Translate a signed libkrun status code into a [`Result`].
const fn check(op: &'static str, ret: i32) -> Result<()> {
    if ret < 0 {
        Err(Error::Krun { op, code: ret })
    } else {
        Ok(())
    }
}

/// Owned NULL-terminated C string array for FFI calls expecting
/// `*const *const c_char`.
struct CStringArray {
    /// Retained to keep the `CString` buffers alive while `ptrs` holds
    /// raw pointers into them.
    _owned: Vec<CString>,
    /// `NULL`-terminated array of pointers handed to libkrun.
    ptrs: Vec<*const c_char>,
}

impl CStringArray {
    /// Build from a slice of owned Rust strings.
    fn new(strings: &[String]) -> Result<Self> {
        let owned: Vec<CString> = strings
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    /// Pointer to the first element; the array is NULL-terminated.
    fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

// ----------------------------------------------------------------------
// Context lifecycle
// ----------------------------------------------------------------------

/// Create a new VM configuration context.
///
/// Returns the context ID on success.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun fails to allocate a new context.
pub fn create_ctx() -> Result<u32> {
    let ret = unsafe { sys::krun_create_ctx() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "create_ctx",
            code: ret,
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "krun returns non-negative i32 on success"
    )]
    Ok(ret as u32)
}

/// Free an existing configuration context.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun reports a failure freeing the
/// context.
pub fn free_ctx(ctx: u32) -> Result<()> {
    check("free_ctx", unsafe { sys::krun_free_ctx(ctx) })
}

/// Start the microVM and take over the current process.
///
/// On success this function **never returns** — libkrun calls `exit()`
/// when the VM shuts down. Only returns on pre-start configuration
/// errors.
///
/// # Errors
///
/// Returns [`Error::Krun`] with the start-up diagnostic code if the VM
/// cannot enter.
pub fn start_enter(ctx: u32) -> Result<()> {
    check("start_enter", unsafe { sys::krun_start_enter(ctx) })
}

// ----------------------------------------------------------------------
// Logging
// ----------------------------------------------------------------------

/// Set the global log level.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun rejects the level.
pub fn set_log_level(level: u32) -> Result<()> {
    check("set_log_level", unsafe { sys::krun_set_log_level(level) })
}

/// Initialise logging with full control over target, level, style and
/// options.
///
/// Use `target_fd = -1` for stderr. Set `KRUN_LOG_OPTION_NO_ENV` (1)
/// in `options` to prevent environment-variable overrides.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun rejects the configuration.
pub fn init_log(target_fd: i32, level: u32, style: LogStyle, options: u32) -> Result<()> {
    check("init_log", unsafe {
        sys::krun_init_log(target_fd, level, style as u32, options)
    })
}

// ----------------------------------------------------------------------
// VM configuration
// ----------------------------------------------------------------------

/// Set basic VM parameters: vCPU count and RAM size.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun rejects the configuration.
pub fn set_vm_config(ctx: u32, vcpus: u8, ram_mib: u32) -> Result<()> {
    check("set_vm_config", unsafe {
        sys::krun_set_vm_config(ctx, vcpus, ram_mib)
    })
}

/// Set the root filesystem directory path.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] if `path` has embedded NULs, or
/// [`Error::Krun`] if libkrun rejects the path.
pub fn set_root(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_root", unsafe { sys::krun_set_root(ctx, c.as_ptr()) })
}

/// Set the working directory inside the VM.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] if `path` has embedded NULs, or
/// [`Error::Krun`] if libkrun rejects the path.
pub fn set_workdir(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_workdir", unsafe {
        sys::krun_set_workdir(ctx, c.as_ptr())
    })
}

/// Set the executable, arguments, and optionally environment variables.
///
/// If `env` is `None`, libkrun auto-inherits the host environment.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] if any string has embedded NULs, or
/// [`Error::Krun`] if libkrun rejects the configuration.
pub fn set_exec(ctx: u32, path: &str, args: &[String], env: Option<&[String]>) -> Result<()> {
    let c_path = CString::new(path)?;
    let argv = CStringArray::new(args)?;
    let c_envp = env.map(CStringArray::new).transpose()?;
    let envp_ptr = c_envp
        .as_ref()
        .map_or(std::ptr::null(), CStringArray::as_ptr);
    check("set_exec", unsafe {
        sys::krun_set_exec(ctx, c_path.as_ptr(), argv.as_ptr(), envp_ptr)
    })
}

/// Set environment variables without specifying an executable.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_env(ctx: u32, env: &[String]) -> Result<()> {
    let array = CStringArray::new(env)?;
    check("set_env", unsafe { sys::krun_set_env(ctx, array.as_ptr()) })
}

// ----------------------------------------------------------------------
// virtio-fs
// ----------------------------------------------------------------------

/// Add a virtio-fs shared directory.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_virtiofs(ctx: u32, tag: &str, host_path: &str) -> Result<()> {
    let c_tag = CString::new(tag)?;
    let c_path = CString::new(host_path)?;
    check("add_virtiofs", unsafe {
        sys::krun_add_virtiofs(ctx, c_tag.as_ptr(), c_path.as_ptr())
    })
}

/// Add a virtio-fs shared directory with a custom DAX SHM window size.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_virtiofs2(ctx: u32, tag: &str, host_path: &str, shm_size: u64) -> Result<()> {
    let c_tag = CString::new(tag)?;
    let c_path = CString::new(host_path)?;
    check("add_virtiofs2", unsafe {
        sys::krun_add_virtiofs2(ctx, c_tag.as_ptr(), c_path.as_ptr(), shm_size)
    })
}

// ----------------------------------------------------------------------
// Disks
// ----------------------------------------------------------------------

/// Add a raw disk image as a general partition.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_disk(ctx: u32, block_id: &str, disk_path: &str, read_only: bool) -> Result<()> {
    let c_id = CString::new(block_id)?;
    let c_path = CString::new(disk_path)?;
    check("add_disk", unsafe {
        sys::krun_add_disk(ctx, c_id.as_ptr(), c_path.as_ptr(), read_only)
    })
}

/// Add a disk image with an explicit format (Raw, QCOW2, or VMDK).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_disk2(
    ctx: u32,
    block_id: &str,
    disk_path: &str,
    format: DiskFormat,
    read_only: bool,
) -> Result<()> {
    let c_id = CString::new(block_id)?;
    let c_path = CString::new(disk_path)?;
    check("add_disk2", unsafe {
        sys::krun_add_disk2(
            ctx,
            c_id.as_ptr(),
            c_path.as_ptr(),
            format as u32,
            read_only,
        )
    })
}

/// Add a disk image with full options: format, direct I/O, and sync mode.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_disk3(
    ctx: u32,
    block_id: &str,
    disk_path: &str,
    format: DiskFormat,
    read_only: bool,
    direct_io: bool,
    sync: SyncMode,
) -> Result<()> {
    let c_id = CString::new(block_id)?;
    let c_path = CString::new(disk_path)?;
    check("add_disk3", unsafe {
        sys::krun_add_disk3(
            ctx,
            c_id.as_ptr(),
            c_path.as_ptr(),
            format as u32,
            read_only,
            direct_io,
            sync as u32,
        )
    })
}

/// Configure a block device as the root filesystem (remount after boot).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_root_disk_remount(
    ctx: u32,
    device: &str,
    fstype: Option<&str>,
    options: Option<&str>,
) -> Result<()> {
    let c_dev = CString::new(device)?;
    let c_fs = fstype.map(CString::new).transpose()?;
    let c_opts = options.map(CString::new).transpose()?;
    check("set_root_disk_remount", unsafe {
        sys::krun_set_root_disk_remount(
            ctx,
            c_dev.as_ptr(),
            c_fs.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            c_opts.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    })
}

// ----------------------------------------------------------------------
// Networking
// ----------------------------------------------------------------------

/// Configure host-to-guest TCP port mappings (format: `"host:guest"`).
///
/// Passing an empty slice exposes none.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_port_map(ctx: u32, ports: &[String]) -> Result<()> {
    let array = CStringArray::new(ports)?;
    check("set_port_map", unsafe {
        sys::krun_set_port_map(ctx, array.as_ptr())
    })
}

/// Add a virtio-net device with a Unix stream backend (passt / socket\_vmnet).
///
/// `path` and `fd` are mutually exclusive. If no network device is added,
/// libkrun uses the built-in TSI backend.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_net_unixstream(
    ctx: u32,
    path: Option<&str>,
    fd: i32,
    mac: &[u8; 6],
    features: u32,
    flags: u32,
) -> Result<()> {
    let c_path = path.map(CString::new).transpose()?;
    check("add_net_unixstream", unsafe {
        sys::krun_add_net_unixstream(
            ctx,
            c_path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            fd,
            mac.as_ptr().cast_mut(),
            features,
            flags,
        )
    })
}

/// Add a virtio-net device with a Unix datagram backend (gvproxy / vmnet-helper).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_net_unixgram(
    ctx: u32,
    path: Option<&str>,
    fd: i32,
    mac: &[u8; 6],
    features: u32,
    flags: u32,
) -> Result<()> {
    let c_path = path.map(CString::new).transpose()?;
    check("add_net_unixgram", unsafe {
        sys::krun_add_net_unixgram(
            ctx,
            c_path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            fd,
            mac.as_ptr().cast_mut(),
            features,
            flags,
        )
    })
}

/// Add a virtio-net device with a TAP backend.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_net_tap(
    ctx: u32,
    tap_name: &str,
    mac: &[u8; 6],
    features: u32,
    flags: u32,
) -> Result<()> {
    let c = CString::new(tap_name)?;
    check("add_net_tap", unsafe {
        sys::krun_add_net_tap(
            ctx,
            c.as_ptr().cast_mut(),
            mac.as_ptr().cast_mut(),
            features,
            flags,
        )
    })
}

/// Set the MAC address for the virtio-net device.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn set_net_mac(ctx: u32, mac: &[u8; 6]) -> Result<()> {
    check("set_net_mac", unsafe {
        sys::krun_set_net_mac(ctx, mac.as_ptr().cast_mut())
    })
}

// ----------------------------------------------------------------------
// vsock
// ----------------------------------------------------------------------

/// Map a vsock port to a host Unix socket path.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_vsock_port(ctx: u32, port: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("add_vsock_port", unsafe {
        sys::krun_add_vsock_port(ctx, port, c.as_ptr())
    })
}

/// Map a vsock port to a host Unix socket with direction control.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_vsock_port2(ctx: u32, port: u32, path: &str, listen: bool) -> Result<()> {
    let c = CString::new(path)?;
    check("add_vsock_port2", unsafe {
        sys::krun_add_vsock_port2(ctx, port, c.as_ptr(), listen)
    })
}

/// Add a vsock device with specified TSI features.
///
/// Requires [`disable_implicit_vsock`] first. Use `KRUN_TSI_HIJACK_INET`
/// (1) and/or `KRUN_TSI_HIJACK_UNIX` (2) as bitmask values, or 0 for
/// none.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_vsock(ctx: u32, tsi_features: u32) -> Result<()> {
    check("add_vsock", unsafe {
        sys::krun_add_vsock(ctx, tsi_features)
    })
}

/// Disable the implicit vsock device created by default.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn disable_implicit_vsock(ctx: u32) -> Result<()> {
    check("disable_implicit_vsock", unsafe {
        sys::krun_disable_implicit_vsock(ctx)
    })
}

// ----------------------------------------------------------------------
// GPU / display
// ----------------------------------------------------------------------

/// Enable a virtio-gpu device with virglrenderer flags.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn set_gpu_options(ctx: u32, virgl_flags: u32) -> Result<()> {
    check("set_gpu_options", unsafe {
        sys::krun_set_gpu_options(ctx, virgl_flags)
    })
}

/// Enable a virtio-gpu device with virglrenderer flags and SHM window size.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn set_gpu_options2(ctx: u32, virgl_flags: u32, shm_size: u64) -> Result<()> {
    check("set_gpu_options2", unsafe {
        sys::krun_set_gpu_options2(ctx, virgl_flags, shm_size)
    })
}

/// Add a display output. Returns the display ID (`0..KRUN_MAX_DISPLAYS`).
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_display(ctx: u32, width: u32, height: u32) -> Result<u32> {
    let ret = unsafe { sys::krun_add_display(ctx, width, height) };
    if ret < 0 {
        return Err(Error::Krun {
            op: "add_display",
            code: ret,
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "krun returns non-negative i32 on success"
    )]
    Ok(ret as u32)
}

/// Set a custom EDID blob for a display.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn display_set_edid(ctx: u32, display_id: u32, edid: &[u8]) -> Result<()> {
    check("display_set_edid", unsafe {
        sys::krun_display_set_edid(ctx, display_id, edid.as_ptr(), edid.len())
    })
}

/// Set DPI for a display.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn display_set_dpi(ctx: u32, display_id: u32, dpi: u32) -> Result<()> {
    check("display_set_dpi", unsafe {
        sys::krun_display_set_dpi(ctx, display_id, dpi)
    })
}

/// Set the physical size of a display in millimetres.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn display_set_physical_size(ctx: u32, display_id: u32, w_mm: u16, h_mm: u16) -> Result<()> {
    check("display_set_physical_size", unsafe {
        sys::krun_display_set_physical_size(ctx, display_id, w_mm, h_mm)
    })
}

/// Set the refresh rate for a display in Hz.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn display_set_refresh_rate(ctx: u32, display_id: u32, hz: u32) -> Result<()> {
    check("display_set_refresh_rate", unsafe {
        sys::krun_display_set_refresh_rate(ctx, display_id, hz)
    })
}

// ----------------------------------------------------------------------
// Input / sound
// ----------------------------------------------------------------------

/// Add a host input device by file descriptor (`/dev/input/*`).
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_input_device_fd(ctx: u32, fd: i32) -> Result<()> {
    check("add_input_device_fd", unsafe {
        sys::krun_add_input_device_fd(ctx, fd)
    })
}

/// Enable or disable a virtio-snd audio device.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn set_snd_device(ctx: u32, enable: bool) -> Result<()> {
    check("set_snd_device", unsafe {
        sys::krun_set_snd_device(ctx, enable)
    })
}

// ----------------------------------------------------------------------
// Resource limits / SMBIOS / UID-GID
// ----------------------------------------------------------------------

/// Set resource limits (format: `"RESOURCE=RLIM_CUR:RLIM_MAX"`).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_rlimits(ctx: u32, rlimits: &[String]) -> Result<()> {
    let array = CStringArray::new(rlimits)?;
    check("set_rlimits", unsafe {
        sys::krun_set_rlimits(ctx, array.as_ptr())
    })
}

/// Set SMBIOS OEM strings.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_smbios_oem_strings(ctx: u32, strings: &[String]) -> Result<()> {
    let array = CStringArray::new(strings)?;
    check("set_smbios_oem_strings", unsafe {
        sys::krun_set_smbios_oem_strings(ctx, array.as_ptr())
    })
}

/// Set the UID before the microVM starts.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn setuid(ctx: u32, uid: u32) -> Result<()> {
    check("setuid", unsafe { sys::krun_setuid(ctx, uid) })
}

/// Set the GID before the microVM starts.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn setgid(ctx: u32, gid: u32) -> Result<()> {
    check("setgid", unsafe { sys::krun_setgid(ctx, gid) })
}

// ----------------------------------------------------------------------
// Nested virt / TEE / firmware / kernel
// ----------------------------------------------------------------------

/// Enable or disable nested virtualisation (macOS only).
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn set_nested_virt(ctx: u32, enable: bool) -> Result<()> {
    check("set_nested_virt", unsafe {
        sys::krun_set_nested_virt(ctx, enable)
    })
}

/// Check if nested virtualisation is supported (macOS only).
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn check_nested_virt() -> Result<bool> {
    let ret = unsafe { sys::krun_check_nested_virt() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "check_nested_virt",
            code: ret,
        });
    }
    Ok(ret == 1)
}

/// Set the TEE configuration file path (libkrun-SEV only).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_tee_config_file(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_tee_config_file", unsafe {
        sys::krun_set_tee_config_file(ctx, c.as_ptr())
    })
}

/// Set the firmware path.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_firmware(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_firmware", unsafe {
        sys::krun_set_firmware(ctx, c.as_ptr())
    })
}

/// Set the kernel, initramfs, and command line.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_kernel(
    ctx: u32,
    kernel_path: &str,
    format: KernelFormat,
    initramfs: Option<&str>,
    cmdline: Option<&str>,
) -> Result<()> {
    let c_kernel = CString::new(kernel_path)?;
    let c_initrd = initramfs.map(CString::new).transpose()?;
    let c_cmd = cmdline.map(CString::new).transpose()?;
    check("set_kernel", unsafe {
        sys::krun_set_kernel(
            ctx,
            c_kernel.as_ptr(),
            format as u32,
            c_initrd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            c_cmd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    })
}

// ----------------------------------------------------------------------
// Console
// ----------------------------------------------------------------------

/// Redirect console output to a file (ignores stdin).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_console_output(ctx: u32, path: &str) -> Result<()> {
    let c = CString::new(path)?;
    check("set_console_output", unsafe {
        sys::krun_set_console_output(ctx, c.as_ptr())
    })
}

/// Disable the implicit console device.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn disable_implicit_console(ctx: u32) -> Result<()> {
    check("disable_implicit_console", unsafe {
        sys::krun_disable_implicit_console(ctx)
    })
}

/// Add a default virtio console with explicit file descriptors.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_virtio_console_default(
    ctx: u32,
    input_fd: i32,
    output_fd: i32,
    err_fd: i32,
) -> Result<()> {
    check("add_virtio_console_default", unsafe {
        sys::krun_add_virtio_console_default(ctx, input_fd, output_fd, err_fd)
    })
}

/// Add a default serial console with explicit file descriptors.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_serial_console_default(ctx: u32, input_fd: i32, output_fd: i32) -> Result<()> {
    check("add_serial_console_default", unsafe {
        sys::krun_add_serial_console_default(ctx, input_fd, output_fd)
    })
}

/// Create a virtio console multiport device. Returns the console ID.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_virtio_console_multiport(ctx: u32) -> Result<u32> {
    let ret = unsafe { sys::krun_add_virtio_console_multiport(ctx) };
    if ret < 0 {
        return Err(Error::Krun {
            op: "add_virtio_console_multiport",
            code: ret,
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "krun returns non-negative i32 on success"
    )]
    Ok(ret as u32)
}

/// Add a TTY port to a multiport console.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_console_port_tty(ctx: u32, console_id: u32, name: &str, tty_fd: i32) -> Result<()> {
    let c = CString::new(name)?;
    check("add_console_port_tty", unsafe {
        sys::krun_add_console_port_tty(ctx, console_id, c.as_ptr(), tty_fd)
    })
}

/// Add an I/O port to a multiport console.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_console_port_inout(
    ctx: u32,
    console_id: u32,
    name: &str,
    input_fd: i32,
    output_fd: i32,
) -> Result<()> {
    let c = CString::new(name)?;
    check("add_console_port_inout", unsafe {
        sys::krun_add_console_port_inout(ctx, console_id, c.as_ptr(), input_fd, output_fd)
    })
}

/// Set the kernel console device identifier.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_kernel_console(ctx: u32, console_id: &str) -> Result<()> {
    let c = CString::new(console_id)?;
    check("set_kernel_console", unsafe {
        sys::krun_set_kernel_console(ctx, c.as_ptr())
    })
}

// ----------------------------------------------------------------------
// Capability / capacity queries
// ----------------------------------------------------------------------

/// Return the maximum number of vCPUs supported by the hypervisor.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn get_max_vcpus() -> Result<u32> {
    let ret = unsafe { sys::krun_get_max_vcpus() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "get_max_vcpus",
            code: ret,
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "krun returns non-negative i32 on success"
    )]
    Ok(ret as u32)
}

/// Check if a build-time feature is enabled in this libkrun build.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn has_feature(feature: Feature) -> Result<bool> {
    let ret = unsafe { sys::krun_has_feature(feature as u64) };
    if ret < 0 {
        return Err(Error::Krun {
            op: "has_feature",
            code: ret,
        });
    }
    Ok(ret == 1)
}

/// Return the eventfd to signal guest shutdown (libkrun-EFI only).
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn get_shutdown_eventfd(ctx: u32) -> Result<i32> {
    let ret = unsafe { sys::krun_get_shutdown_eventfd(ctx) };
    if ret < 0 {
        return Err(Error::Krun {
            op: "get_shutdown_eventfd",
            code: ret,
        });
    }
    Ok(ret)
}

/// Enable or disable split IRQCHIP between host and guest.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn split_irqchip(ctx: u32, enable: bool) -> Result<()> {
    check("split_irqchip", unsafe {
        sys::krun_split_irqchip(ctx, enable)
    })
}
