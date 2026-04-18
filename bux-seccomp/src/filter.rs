//! Assemble the BPF program that enforces the default bux allowlist.
//!
//! Program structure (identical to what libseccomp would emit for an
//! allow-list with `SCMP_ACT_KILL_PROCESS` as the default action):
//!
//! ```text
//! LD  W  ABS   seccomp_data.arch         ; load the syscall's arch
//! JEQ K       AUDIT_ARCH, +0, +kill_off  ; wrong arch -> jump to kill
//! LD  W  ABS   seccomp_data.nr           ; load the syscall number
//! JEQ K       nr_0, +allow_off_0, +0     ; for each allowed syscall:
//! JEQ K       nr_1, +allow_off_1, +0     ;   jump to ALLOW on match
//! ...
//! RET K       SECCOMP_RET_KILL_PROCESS   ; default: kill
//! RET K       SECCOMP_RET_ALLOW          ; allow target
//! ```

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::arch::{AUDIT_ARCH, DEFAULT_ALLOWLIST};
use crate::bpf::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, Instruction, SECCOMP_ARCH_OFFSET,
    SECCOMP_NR_OFFSET, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, instruction,
};

/// Build the bux default seccomp BPF program.
///
/// Returns a `Vec<Instruction>` that kills the process with `SIGSYS`
/// for any syscall not on [`crate::arch::DEFAULT_ALLOWLIST`], or if the
/// syscall comes from the wrong audit arch.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[must_use]
pub fn build_default() -> Vec<Instruction> {
    build(DEFAULT_ALLOWLIST, AUDIT_ARCH)
}

/// Build an allowlist filter with an explicit audit-arch and syscall list.
///
/// Exposed for testing and for callers that want a reduced allowlist
/// (e.g. a stricter filter for the guest agent).
#[must_use]
pub fn build(allowlist: &[u32], audit_arch: u32) -> Vec<Instruction> {
    let n = allowlist.len();
    // 2 (arch check) + 1 (load nr) + n (one JEQ per syscall) + 1 (kill) + 1 (allow)
    let prog_len = 2 + 1 + n + 1 + 1;
    let mut prog = Vec::with_capacity(prog_len);

    prog.push(instruction(
        BPF_LD | BPF_W | BPF_ABS,
        0,
        0,
        SECCOMP_ARCH_OFFSET,
    ));
    #[allow(
        clippy::cast_possible_truncation,
        reason = "BPF jump offset fits in u8 when len < BPF::MAX_LEN"
    )]
    let kill_offset = (n + 2) as u8;
    prog.push(instruction(
        BPF_JMP | BPF_JEQ | BPF_K,
        0,
        kill_offset,
        audit_arch,
    ));

    prog.push(instruction(
        BPF_LD | BPF_W | BPF_ABS,
        0,
        0,
        SECCOMP_NR_OFFSET,
    ));

    for (i, &syscall) in allowlist.iter().enumerate() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "BPF jump offset fits in u8 when len < BPF::MAX_LEN"
        )]
        let allow_offset = (n - i) as u8;
        prog.push(instruction(
            BPF_JMP | BPF_JEQ | BPF_K,
            allow_offset,
            0,
            syscall,
        ));
    }

    prog.push(instruction(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
    prog.push(instruction(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));

    prog
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::indexing_slicing,
    reason = "tests are allowed to use unwrap/indexing and omit docs"
)]
mod tests {
    use super::*;
    use crate::bpf::MAX_LEN;

    #[test]
    fn empty_allowlist_kills_everything() {
        let prog = build(&[], 0);
        // 2 (arch check) + 1 (load nr) + 0 (no JEQs) + 1 (kill) + 1 (allow) = 5
        assert_eq!(prog.len(), 5);
    }

    #[test]
    fn program_size_matches_prediction() {
        let list: Vec<u32> = (0..100).collect();
        let prog = build(&list, 0);
        assert_eq!(prog.len(), 2 + 1 + 100 + 1 + 1);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn default_filter_within_kernel_limit() {
        let prog = build_default();
        assert!(prog.len() <= MAX_LEN);
        assert!(prog.len() >= 5);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn default_allowlist_is_strictly_sorted() {
        for window in DEFAULT_ALLOWLIST.windows(2) {
            assert!(
                window[0] < window[1],
                "allowlist not strictly sorted: {} followed by {}",
                window[0],
                window[1]
            );
        }
    }
}
