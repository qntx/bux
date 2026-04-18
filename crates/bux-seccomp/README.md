# bux-seccomp

Pure-Rust seccomp BPF syscall filter for the bux VMM shim. Zero external
dependencies beyond `libc` and `thiserror`, no C libraries, no async
runtime. Linux only.

## Scope

| Operation                    | Implementation                |
|------------------------------|-------------------------------|
| `build_default()`            | Pure Rust (builds BPF program)|
| `build(allowlist, arch)`     | Pure Rust                     |
| `install_default()`          | `prctl` + `seccomp(2)`        |
| `install(program)`           | `prctl` + `seccomp(2)`        |

The filter is whitelist-mode (`SECCOMP_RET_KILL_PROCESS` default) and is
applied with `SECCOMP_FILTER_FLAG_TSYNC` so every existing thread in the
process inherits it atomically.

## Example

```rust,no_run
# #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
# fn main() -> Result<(), bux_seccomp::Error> {
bux_seccomp::install_default()?;
# Ok(()) }
# #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
# fn main() {}
```

## Status

Extracted from the `bux` main crate as part of the Phase 1 L1 refactor.
See `docs/design/L1-platform-primitives.md` in the workspace root for
the design rationale.
