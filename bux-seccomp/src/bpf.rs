//! BPF instruction encoding for seccomp filters.
//!
//! A seccomp BPF program is an array of `struct sock_filter`:
//!
//! ```c
//! struct sock_filter {
//!     __u16 code;  // opcode
//!     __u8  jt;    // jump-true offset
//!     __u8  jf;    // jump-false offset
//!     __u32 k;     // generic argument
//! };
//! ```
//!
//! This module packs those into a `u64` in little-endian bit layout so
//! the resulting `Vec<u64>` is directly usable as the BPF program array.

/// A single BPF instruction, packed into 64 bits matching `struct sock_filter`.
pub type Instruction = u64;

/// Maximum number of instructions the kernel accepts in one BPF program
/// (`BPF_MAXINSNS`). Seccomp filters larger than this are rejected.
pub const MAX_LEN: usize = 4096;

/// Encode a `struct sock_filter` as a single `u64`.
///
/// Layout:
///
/// | bits   | field  |
/// |--------|--------|
/// | 0..16  | `code` |
/// | 16..24 | `jt`   |
/// | 24..32 | `jf`   |
/// | 32..64 | `k`    |
#[must_use]
pub const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> Instruction {
    (code as u64) | ((jt as u64) << 16) | ((jf as u64) << 24) | ((k as u64) << 32)
}

// BPF opcodes (from linux/bpf_common.h and linux/filter.h).

/// Load instruction class.
pub const BPF_LD: u16 = 0x00;

/// Jump instruction class.
pub const BPF_JMP: u16 = 0x05;

/// Return instruction class.
pub const BPF_RET: u16 = 0x06;

/// 32-bit word size.
pub const BPF_W: u16 = 0x00;

/// Absolute addressing mode.
pub const BPF_ABS: u16 = 0x20;

/// Jump if equal.
pub const BPF_JEQ: u16 = 0x10;

/// Immediate (constant) operand.
pub const BPF_K: u16 = 0x00;

// seccomp return actions (from linux/seccomp.h).

/// Allow the syscall.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Kill the offending process with `SIGSYS`.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// `struct seccomp_data` field offsets.

/// Offset of `nr` (syscall number) in `struct seccomp_data`.
pub const SECCOMP_NR_OFFSET: u32 = 0;

/// Offset of `arch` (audit architecture) in `struct seccomp_data`.
pub const SECCOMP_ARCH_OFFSET: u32 = 4;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    reason = "tests are allowed to use unwrap and omit docs"
)]
mod tests {
    use super::*;

    #[test]
    fn instruction_packs_fields_into_correct_bits() {
        let i = instruction(0x1234, 0x56, 0x78, 0x9abc_def0);
        assert_eq!(i & 0xFFFF, 0x1234);
        assert_eq!((i >> 16) & 0xFF, 0x56);
        assert_eq!((i >> 24) & 0xFF, 0x78);
        assert_eq!((i >> 32) & 0xFFFF_FFFF, 0x9abc_def0);
    }

    #[test]
    fn opcodes_have_expected_kernel_values() {
        // Verify against linux/bpf_common.h.
        assert_eq!(BPF_LD, 0x00);
        assert_eq!(BPF_JMP, 0x05);
        assert_eq!(BPF_RET, 0x06);
        assert_eq!(BPF_ABS, 0x20);
        assert_eq!(BPF_JEQ, 0x10);
    }

    #[test]
    fn seccomp_return_values_match_kernel_header() {
        assert_eq!(SECCOMP_RET_ALLOW, 0x7fff_0000);
        assert_eq!(SECCOMP_RET_KILL_PROCESS, 0x8000_0000);
    }

    #[test]
    fn seccomp_data_offsets_are_byte_correct() {
        // struct seccomp_data { int nr; __u32 arch; ... }
        assert_eq!(SECCOMP_NR_OFFSET, 0);
        assert_eq!(SECCOMP_ARCH_OFFSET, 4);
    }
}
