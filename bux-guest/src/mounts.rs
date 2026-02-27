//! Essential tmpfs mounts and filesystem freeze/thaw operations.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

/// Tmpfs mount specification.
struct TmpfsMount {
    /// Mount point path.
    path: &'static str,
    /// Unix permission mode.
    mode: u32,
}

/// Directories that require tmpfs for correct operation.
///
/// virtio-fs does not support the open-unlink-fstat pattern that many
/// programs rely on (apt, pip, etc.), so these must be real tmpfs.
const TMPFS_MOUNTS: &[TmpfsMount] = &[
    TmpfsMount {
        path: "/tmp",
        mode: 0o1777,
    },
    TmpfsMount {
        path: "/var/tmp",
        mode: 0o1777,
    },
    TmpfsMount {
        path: "/run",
        mode: 0o755,
    },
];

/// Virtual/pseudo filesystem types that must not be frozen.
const SKIP_FS_TYPES: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "pstore",
    "binfmt_misc",
    "autofs",
    "rpc_pipefs",
    "nfsd",
    "overlay",
    "virtiofs",
];

// Linux ioctl constants for filesystem freeze/thaw.
// Defined in include/uapi/linux/fs.h:
//   #define FIFREEZE  _IOWR('X', 119, int)  = 0xC0045877
//   #define FITHAW    _IOWR('X', 120, int)  = 0xC0045878
/// `FIFREEZE` ioctl — flush dirty pages and block new writes.
const FIFREEZE: libc::c_ulong = 0xC004_5877;
/// `FITHAW` ioctl — unblock writes on a frozen filesystem.
const FITHAW: libc::c_ulong = 0xC004_5878;

/// Mounts essential tmpfs directories early during boot.
pub fn mount_essential_tmpfs() {
    for m in TMPFS_MOUNTS {
        let path = std::path::Path::new(m.path);

        // Skip if already tmpfs.
        if is_tmpfs(m.path) {
            continue;
        }

        let _ = fs::create_dir_all(path);

        let Ok(target) = std::ffi::CString::new(m.path) else {
            continue;
        };
        let Ok(fstype) = std::ffi::CString::new("tmpfs") else {
            continue;
        };

        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };

        if ret == 0 {
            // Set correct permissions after mount.
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(m.mode));
        }
    }
}

/// Returns `true` if `path` is already mounted as tmpfs.
fn is_tmpfs(path: &str) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let mount_point = fields.nth(1).unwrap_or("");
        let fs_type = fields.next().unwrap_or("");
        mount_point == path && fs_type == "tmpfs"
    })
}

/// Freezes all writable, non-virtual filesystems via `FIFREEZE`.
///
/// Returns the list of mount points that were successfully frozen.
/// Caller must pass this list to [`thaw_frozen`] to unblock writes.
pub fn freeze_filesystems() -> Vec<PathBuf> {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };

    let mut frozen = Vec::new();

    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let mount_point = fields[1];
        let fs_type = fields[2];
        let options = fields[3];

        // Skip virtual/pseudo filesystems.
        if SKIP_FS_TYPES.contains(&fs_type) {
            continue;
        }
        // Skip read-only mounts.
        if options.split(',').any(|opt| opt == "ro") {
            continue;
        }

        let Ok(f) = fs::File::open(mount_point) else {
            continue;
        };
        let ret = unsafe { libc::ioctl(f.as_raw_fd(), FIFREEZE, 0) };
        if ret == 0 {
            frozen.push(PathBuf::from(mount_point));
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // EBUSY = already frozen → count as success.
            if errno == libc::EBUSY {
                frozen.push(PathBuf::from(mount_point));
            }
            // EOPNOTSUPP = fs doesn't support freeze → skip silently.
        }
    }

    frozen
}

/// Thaws a specific set of previously frozen mount points via `FITHAW`.
///
/// Returns the number of filesystems successfully thawed.
pub fn thaw_frozen(frozen: &[PathBuf]) -> u32 {
    let mut thawed = 0u32;

    for mount_point in frozen {
        let Ok(f) = fs::File::open(mount_point) else {
            continue;
        };
        if unsafe { libc::ioctl(f.as_raw_fd(), FITHAW, 0) } == 0 {
            thawed += 1;
        }
    }

    thawed
}
