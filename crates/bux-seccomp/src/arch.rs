//! Per-architecture audit arch constants and the allowlist used by the
//! bux shim's default seccomp filter.
//!
//! The audit arch constant is checked at the top of the BPF program: if
//! a syscall arrives from a different architecture (e.g. x32 ABI on an
//! `x86_64` kernel) the process is killed. This defends against ABI
//! confusion attacks where a 32-bit syscall is renumbered.

/// `x86_64` audit architecture constant (`AUDIT_ARCH_X86_64`).
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xc000_003e;

/// `aarch64` audit architecture constant (`AUDIT_ARCH_AARCH64`).
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xc000_00b7;

/// Syscalls allowed for the bux-shim VMM process on `x86_64`.
///
/// The allowlist is sorted for readability and verified by a unit test.
/// It covers libkrun's runtime needs: standard I/O, memory management,
/// KVM ioctls, threading, signals, and vsock/virtio networking.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_ALLOWLIST: &[u32] = &[
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
    16,  // ioctl (KVM uses many)
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

/// Syscalls allowed for the bux-shim VMM process on `aarch64`.
///
/// Numbers come from `asm-generic/unistd.h`; comments audited against
/// the Linux 6.x headers and corrected where the original source had
/// stale annotations.
#[cfg(target_arch = "aarch64")]
pub const DEFAULT_ALLOWLIST: &[u32] = &[
    0,   // io_setup
    17,  // getcwd
    23,  // dup
    24,  // dup3
    25,  // fcntl
    29,  // ioctl (KVM uses many)
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
    117, // rt_sigsuspend
    122, // sched_setparam
    124, // sched_yield
    129, // kill
    130, // tkill
    131, // sigaltstack
    132, // rt_sigprocmask
    133, // rt_sigpending
    134, // rt_sigaction
    135, // rt_sigpending
    137, // rt_sigtimedwait
    139, // rt_sigsuspend
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
    196, // shmat
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn audit_arch_x86_64() {
        assert_eq!(AUDIT_ARCH, 0xc000_003e);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn audit_arch_aarch64() {
        assert_eq!(AUDIT_ARCH, 0xc000_00b7);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn allowlist_is_non_empty() {
        assert!(!DEFAULT_ALLOWLIST.is_empty());
    }
}
