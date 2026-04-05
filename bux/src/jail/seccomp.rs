//! Seccomp BPF syscall filtering for shim process isolation (Linux only).
//!
//! Installs a whitelist-mode seccomp filter that restricts the shim process
//! to only the system calls required by libkrun. Any syscall not on the
//! allowlist results in the process being killed with `SIGSYS`.
//!
//! The filter is applied with `SECCOMP_FILTER_FLAG_TSYNC` to synchronize
//! across all threads, ensuring vCPU threads created by libkrun also
//! inherit the restriction.
//!
//! # Filter Design
//!
//! The allowlist covers:
//! - Standard I/O and memory management (read, write, mmap, mprotect, ...)
//! - KVM ioctls (ioctl is allowed broadly since KVM needs many ioctl codes)
//! - Thread/process management (clone, futex, exit_group, ...)
//! - Signal handling (rt_sigaction, rt_sigprocmask, ...)
//! - File operations needed by libkrun (open, close, fstat, ...)
//! - Networking (socket, connect, bind — for vsock/virtio-net)
//!
//! Blocked by default: mount, ptrace, reboot, kexec_load, init_module,
//! pivot_root, and other dangerous operations.

#![cfg(target_os = "linux")]

use std::io;

/// Each BPF instruction is 8 bytes (matching `struct sock_filter`).
type BpfInstruction = u64;

/// Errors from seccomp filter installation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeccompError {
    /// Filter exceeds the kernel's BPF_MAX_LEN limit (4096 instructions).
    #[error("seccomp filter too large ({0} instructions, max 4096)")]
    FilterTooLarge(usize),
    /// `prctl(PR_SET_NO_NEW_PRIVS)` failed.
    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivs(io::Error),
    /// `seccomp(SECCOMP_SET_MODE_FILTER)` failed.
    #[error("seccomp filter installation failed: {0}")]
    Install(io::Error),
    /// Thread synchronization failed (TSYNC). The value is the
    /// TID of the non-synchronized thread.
    #[error("seccomp TSYNC failed for thread {0}")]
    TsyncFailed(i64),
}

/// Maximum BPF program length the kernel accepts.
const BPF_MAX_LEN: usize = 4096;

// BPF instruction encoding helpers.
// `struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }`
// Packed into a u64: low 16 = code, next 8 = jt, next 8 = jf, high 32 = k.
const fn bpf(code: u16, jt: u8, jf: u8, k: u32) -> BpfInstruction {
    (code as u64) | ((jt as u64) << 16) | ((jf as u64) << 24) | ((k as u64) << 32)
}

// BPF opcodes (from linux/bpf_common.h and linux/filter.h).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

// seccomp return values.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// seccomp_data offsets.
/// Offset of `nr` (syscall number) in `struct seccomp_data`.
const SECCOMP_NR_OFFSET: u32 = 0;
/// Offset of `arch` in `struct seccomp_data`.
const SECCOMP_ARCH_OFFSET: u32 = 4;

/// x86_64 audit architecture constant.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64

/// aarch64 audit architecture constant.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// Syscalls allowed for the bux-shim VMM process.
///
/// This is a broad allowlist covering libkrun's needs. It includes
/// standard I/O, memory management, KVM ioctls, threading, signals,
/// and networking (for vsock).
#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS: &[u32] = &[
    0,   // read
    1,   // write
    2,   // open
    3,   // close
    4,   // stat
    5,   // fstat
    6,   // lstat
    7,   // poll
    8,   // lseek
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    16,  // ioctl (KVM needs many ioctls)
    17,  // pread64
    18,  // pwrite64
    19,  // readv
    20,  // writev
    21,  // access
    22,  // pipe
    23,  // select
    24,  // sched_yield
    25,  // mremap
    28,  // madvise
    32,  // dup
    33,  // dup2
    35,  // nanosleep
    39,  // getpid
    41,  // socket
    42,  // connect
    43,  // accept
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    48,  // shutdown
    49,  // bind
    50,  // listen
    51,  // getsockname
    52,  // getpeername
    54,  // setsockopt
    55,  // getsockopt
    56,  // clone
    57,  // fork
    60,  // exit
    62,  // kill
    72,  // fcntl
    73,  // flock
    74,  // fsync
    75,  // fdatasync
    78,  // getdents
    79,  // getcwd
    80,  // chdir
    82,  // rename
    83,  // mkdir
    87,  // unlink
    89,  // readlink
    91,  // fchmod
    96,  // gettimeofday
    97,  // getrlimit
    102, // getuid
    104, // getgid
    107, // geteuid
    108, // getegid
    110, // getppid
    131, // sigaltstack
    157, // prctl
    158, // arch_prctl
    186, // gettid
    200, // tkill
    202, // futex
    204, // sched_getaffinity
    217, // getdents64
    218, // set_tid_address
    228, // clock_gettime
    230, // clock_nanosleep
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    257, // openat
    262, // newfstatat
    269, // faccessat
    271, // ppoll
    280, // eventfd2
    282, // signalfd4
    284, // eventfd
    288, // accept4
    291, // epoll_create1
    292, // dup3
    293, // pipe2
    302, // prlimit64
    309, // getcpu
    318, // getrandom
    332, // statx
    334, // rseq
    435, // clone3
    439, // faccessat2
    448, // process_mrelease
    449, // futex_waitv
    451, // cachestat
];

/// Syscalls allowed for the bux-shim VMM process (aarch64).
#[cfg(target_arch = "aarch64")]
const ALLOWED_SYSCALLS: &[u32] = &[
    0,   // io_setup
    17,  // getcwd
    23,  // dup
    24,  // dup3
    25,  // fcntl
    29,  // ioctl (KVM needs many ioctls)
    34,  // mkdirat
    35,  // unlinkat
    37,  // renameat
    46,  // ftruncate
    48,  // faccessat
    49,  // chdir
    50,  // fchmod
    56,  // openat
    57,  // close
    61,  // getdents64
    62,  // lseek
    63,  // read
    64,  // write
    65,  // readv
    66,  // writev
    67,  // pread64
    68,  // pwrite64
    73,  // ppoll
    78,  // readlinkat
    79,  // newfstatat
    80,  // fstat
    82,  // fsync
    83,  // fdatasync
    96,  // set_tid_address
    98,  // futex
    99,  // set_robust_list
    113, // clock_gettime
    115, // clock_nanosleep
    117, // sched_yield
    122, // sched_getaffinity
    124, // sched_yield
    129, // kill
    130, // tkill
    131, // sigaltstack
    132, // rt_sigprocmask
    133, // rt_sigaction
    134, // rt_sigreturn
    135, // rt_sigpending
    137, // rt_sigtimedwait
    139, // rt_sigreturn
    160, // uname
    167, // prctl
    172, // getpid
    173, // getppid
    174, // getuid
    175, // geteuid
    176, // getgid
    177, // getegid
    178, // gettid
    179, // sysinfo
    196, // brk
    198, // socket
    200, // bind
    201, // listen
    202, // accept
    203, // connect
    204, // getsockname
    205, // getpeername
    206, // sendto
    207, // recvfrom
    208, // setsockopt
    209, // getsockopt
    210, // shutdown
    211, // sendmsg
    212, // recvmsg
    214, // brk
    215, // munmap
    216, // mremap
    220, // clone
    221, // execve
    222, // mmap
    226, // mprotect
    228, // madvise
    233, // exit
    234, // exit_group
    242, // accept4
    260, // wait4
    261, // prlimit64
    278, // getrandom
    281, // epoll_create1
    282, // epoll_ctl
    283, // epoll_pwait
    291, // statx
    293, // rseq
    435, // clone3
    439, // faccessat2
    449, // futex_waitv
];

/// Builds a seccomp BPF program that allows only the syscalls in `ALLOWED_SYSCALLS`.
///
/// Structure:
/// 1. Load architecture from seccomp_data, reject if wrong arch
/// 2. Load syscall number
/// 3. For each allowed syscall: JEQ → ALLOW
/// 4. Default: KILL_PROCESS
fn build_filter() -> Vec<BpfInstruction> {
    let n = ALLOWED_SYSCALLS.len();
    // Program size: 2 (arch check) + 1 (load nr) + n (one JEQ per syscall) + 1 (default kill) + 1 (allow target)
    let prog_len = 2 + 1 + n + 1 + 1;
    let mut prog = Vec::with_capacity(prog_len);

    // 1. Load architecture
    prog.push(bpf(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_ARCH_OFFSET));
    // If arch != expected, jump to kill (skip all remaining instructions)
    #[allow(clippy::cast_possible_truncation)]
    let kill_offset = (n + 2) as u8; // skip load_nr + all JEQs + allow
    prog.push(bpf(BPF_JMP | BPF_JEQ | BPF_K, 0, kill_offset, AUDIT_ARCH));

    // 2. Load syscall number
    prog.push(bpf(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_NR_OFFSET));

    // 3. For each allowed syscall: if nr == syscall, jump to ALLOW
    for (i, &syscall) in ALLOWED_SYSCALLS.iter().enumerate() {
        // Distance to the ALLOW instruction at the end
        #[allow(clippy::cast_possible_truncation)]
        let allow_offset = (n - i) as u8;
        prog.push(bpf(BPF_JMP | BPF_JEQ | BPF_K, allow_offset, 0, syscall));
    }

    // 4. Default: KILL_PROCESS
    prog.push(bpf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS));

    // 5. ALLOW target
    prog.push(bpf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));

    prog
}

/// `struct sock_fprog` for the seccomp syscall.
#[repr(C)]
struct SockFprog {
    /// Number of BPF instructions.
    len: u16,
    /// Pointer to BPF instruction array.
    filter: *const BpfInstruction,
}

/// Installs the bux seccomp filter on all threads in the current process.
///
/// Uses `SECCOMP_FILTER_FLAG_TSYNC` to synchronize the filter across all
/// existing threads. New threads created after this call automatically
/// inherit the filter via `clone()`.
///
/// # Safety
///
/// After this call, the process can only invoke syscalls on the allowlist.
/// Any other syscall triggers `SIGSYS` (process kill).
///
/// # Errors
///
/// Returns an error if the kernel rejects the filter or thread
/// synchronization fails.
pub fn install() -> Result<(), SeccompError> {
    let filter = build_filter();

    if filter.len() > BPF_MAX_LEN {
        return Err(SeccompError::FilterTooLarge(filter.len()));
    }

    let filter_len =
        u16::try_from(filter.len()).map_err(|_| SeccompError::FilterTooLarge(filter.len()))?;

    #[allow(unsafe_code)]
    unsafe {
        // Set PR_SET_NO_NEW_PRIVS (required for unprivileged seccomp).
        let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if rc != 0 {
            return Err(SeccompError::NoNewPrivs(io::Error::last_os_error()));
        }

        // Install filter with TSYNC.
        let prog = SockFprog {
            len: filter_len,
            filter: filter.as_ptr(),
        };
        let rc = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const SockFprog,
        );
        if rc > 0 {
            return Err(SeccompError::TsyncFailed(rc));
        }
        if rc != 0 {
            return Err(SeccompError::Install(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Returns the number of syscalls in the current allowlist.
pub const fn allowlist_size() -> usize {
    ALLOWED_SYSCALLS.len()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn filter_builds_without_overflow() {
        let filter = build_filter();
        assert!(filter.len() <= BPF_MAX_LEN);
        // At minimum: 2 (arch) + 1 (load nr) + N (JEQs) + 1 (kill) + 1 (allow)
        assert!(filter.len() >= 5);
    }

    #[test]
    fn allowlist_is_sorted_and_unique() {
        for window in ALLOWED_SYSCALLS.windows(2) {
            assert!(
                window[0] < window[1],
                "allowlist not sorted/unique: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn bpf_instruction_encoding() {
        // Verify BPF instruction packing matches kernel struct layout.
        let insn = bpf(0x20, 0, 0, 4);
        // code=0x20 in low 16 bits, jt=0 in bits 16-23, jf=0 in bits 24-31, k=4 in bits 32-63
        assert_eq!(insn & 0xFFFF, 0x20);
        assert_eq!((insn >> 32) & 0xFFFF_FFFF, 4);
    }

    #[test]
    fn audit_arch_is_correct() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(AUDIT_ARCH, 0xc000_003e);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(AUDIT_ARCH, 0xc000_00b7);
    }
}
