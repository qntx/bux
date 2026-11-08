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
/// Sorted and unique; frozen by a unit test. Covers libkrun, including the
/// virtio-blk (imago) and virtio-fs passthrough backends, plus the in-process
/// gvproxy/Go runtime (clone3, rseq, netpoll, timers).
pub const X86_64_ALLOWLIST: &[u32] = &[
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
    27,  // mincore
    28,  // madvise
    32,  // dup
    33,  // dup2
    35,  // nanosleep
    38,  // setitimer
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
    63,  // uname
    72,  // fcntl
    73,  // flock
    74,  // fsync
    75,  // fdatasync
    77,  // ftruncate
    78,  // getdents
    79,  // getcwd
    80,  // chdir
    82,  // rename
    83,  // mkdir
    87,  // unlink
    89,  // readlink
    91,  // fchmod
    95,  // umask
    96,  // gettimeofday
    97,  // getrlimit
    102, // getuid
    104, // getgid
    107, // geteuid
    108, // getegid
    110, // getppid
    117, // setresuid
    119, // setresgid
    125, // capget
    126, // capset
    131, // sigaltstack
    138, // fstatfs
    157, // prctl
    158, // arch_prctl
    186, // gettid
    189, // lsetxattr
    190, // fsetxattr
    192, // lgetxattr
    193, // fgetxattr
    195, // llistxattr
    196, // flistxattr
    198, // lremovexattr
    199, // fremovexattr
    200, // tkill
    202, // futex
    204, // sched_getaffinity
    217, // getdents64
    218, // set_tid_address
    222, // timer_create
    223, // timer_settime
    226, // timer_delete
    228, // clock_gettime
    230, // clock_nanosleep
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    234, // tgkill
    257, // openat
    258, // mkdirat
    259, // mknodat
    260, // fchownat
    262, // newfstatat
    263, // unlinkat
    265, // linkat
    266, // symlinkat
    267, // readlinkat
    268, // fchmodat
    269, // faccessat
    271, // ppoll
    273, // set_robust_list
    280, // utimensat
    281, // epoll_pwait
    282, // signalfd4
    284, // eventfd
    285, // fallocate
    288, // accept4
    290, // eventfd2
    291, // epoll_create1
    292, // dup3
    293, // pipe2
    295, // preadv
    296, // pwritev
    302, // prlimit64
    309, // getcpu
    316, // renameat2
    318, // getrandom
    326, // copy_file_range
    332, // statx
    334, // rseq
    435, // clone3
    439, // faccessat2
    441, // epoll_pwait2
    448, // process_mrelease
    449, // futex_waitv
    451, // cachestat
];

/// Syscalls allowed for the bux-shim VMM process on `aarch64`.
///
/// Sorted and unique; frozen by a unit test. Numbers and names from
/// `asm-generic/unistd.h`. Covers libkrun, including the virtio-blk (imago)
/// and virtio-fs passthrough backends, plus in-process gvproxy/Go (clone3,
/// rseq, netpoll, timers). `ptrace` is not listed.
pub const AARCH64_ALLOWLIST: &[u32] = &[
    0,   // io_setup
    6,   // lsetxattr
    7,   // fsetxattr
    9,   // lgetxattr
    10,  // fgetxattr
    12,  // llistxattr
    13,  // flistxattr
    15,  // lremovexattr
    16,  // fremovexattr
    17,  // getcwd
    19,  // eventfd2
    20,  // epoll_create1
    21,  // epoll_ctl
    22,  // epoll_pwait
    23,  // dup
    24,  // dup3
    25,  // fcntl
    29,  // ioctl (KVM uses many)
    33,  // mknodat
    34,  // mkdirat
    35,  // unlinkat
    36,  // symlinkat
    37,  // linkat
    38,  // renameat
    44,  // fstatfs
    46,  // ftruncate
    47,  // fallocate
    48,  // faccessat
    49,  // chdir
    52,  // fchmod
    53,  // fchmodat
    54,  // fchownat
    56,  // openat
    57,  // close
    59,  // pipe2
    61,  // getdents64
    62,  // lseek
    63,  // read
    64,  // write
    65,  // readv
    66,  // writev
    67,  // pread64
    68,  // pwrite64
    69,  // preadv
    70,  // pwritev
    73,  // ppoll
    78,  // readlinkat
    79,  // newfstatat
    80,  // fstat
    82,  // fsync
    83,  // fdatasync
    88,  // utimensat
    90,  // capget
    91,  // capset
    93,  // exit
    94,  // exit_group
    96,  // set_tid_address
    98,  // futex
    99,  // set_robust_list
    101, // nanosleep
    103, // setitimer
    107, // timer_create
    110, // timer_settime
    111, // timer_delete
    113, // clock_gettime
    115, // clock_nanosleep
    122, // sched_setaffinity
    123, // sched_getaffinity
    124, // sched_yield
    129, // kill
    130, // tkill
    131, // tgkill
    132, // sigaltstack
    133, // rt_sigsuspend
    134, // rt_sigaction
    135, // rt_sigprocmask
    137, // rt_sigtimedwait
    139, // rt_sigreturn
    147, // setresuid
    149, // setresgid
    160, // uname
    166, // umask
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
    232, // mincore
    233, // madvise
    242, // accept4
    260, // wait4
    261, // prlimit64
    276, // renameat2
    278, // getrandom
    285, // copy_file_range
    291, // statx
    293, // rseq
    435, // clone3
    439, // faccessat2
    441, // epoll_pwait2
    449, // futex_waitv
];

/// Default allowlist for the compiled architecture.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_ALLOWLIST: &[u32] = X86_64_ALLOWLIST;

/// Default allowlist for the compiled architecture.
#[cfg(target_arch = "aarch64")]
pub const DEFAULT_ALLOWLIST: &[u32] = AARCH64_ALLOWLIST;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::indexing_slicing,
    reason = "tests are allowed to use unwrap/indexing and omit docs"
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

    fn assert_sorted_unique(list: &[u32], arch: &str) {
        assert!(!list.is_empty(), "{arch} allowlist is empty");
        for window in list.windows(2) {
            assert!(
                window[0] < window[1],
                "{arch} allowlist not strictly increasing: {} followed by {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn allowlists_are_sorted_and_unique() {
        // Unsorted or duplicate nrs hide a hole until SIGSYS at create.
        assert_sorted_unique(X86_64_ALLOWLIST, "x86_64");
        assert_sorted_unique(AARCH64_ALLOWLIST, "aarch64");
    }

    #[test]
    fn allowlists_include_clone3_and_rseq() {
        // Go starts threads with these; TSYNC cannot add them after install.
        assert!(
            X86_64_ALLOWLIST.contains(&435),
            "clone3 missing from x86_64 allowlist"
        );
        assert!(
            X86_64_ALLOWLIST.contains(&334),
            "rseq missing from x86_64 allowlist"
        );
        assert!(
            AARCH64_ALLOWLIST.contains(&435),
            "clone3 missing from aarch64 allowlist"
        );
        assert!(
            AARCH64_ALLOWLIST.contains(&293),
            "rseq missing from aarch64 allowlist"
        );
    }

    #[test]
    fn allowlists_include_disk_and_virtiofs_io() {
        // libkrun's virtio-blk (imago) and virtio-fs passthrough threads make these.
        for (nr, name) in [
            (295, "preadv"),
            (296, "pwritev"),
            (285, "fallocate"),
            (258, "mkdirat"),
            (263, "unlinkat"),
            (316, "renameat2"),
            (193, "fgetxattr"),
        ] {
            assert!(
                X86_64_ALLOWLIST.contains(&nr),
                "{name} ({nr}) missing from x86_64 allowlist"
            );
        }
        for (nr, name) in [
            (69, "preadv"),
            (70, "pwritev"),
            (47, "fallocate"),
            (34, "mkdirat"),
            (35, "unlinkat"),
            (276, "renameat2"),
            (10, "fgetxattr"),
        ] {
            assert!(
                AARCH64_ALLOWLIST.contains(&nr),
                "{name} ({nr}) missing from aarch64 allowlist"
            );
        }
    }

    #[test]
    fn aarch64_allowlist_omits_ptrace() {
        // Filter exists to block ptrace; 117 is ptrace on asm-generic.
        assert!(
            !AARCH64_ALLOWLIST.contains(&117),
            "aarch64 allowlist must not contain ptrace"
        );
    }
}
