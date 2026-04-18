# bux-cgroup

Pure-Rust cgroup v2 resource limits — zero external dependencies beyond
`thiserror`, no C libraries, no async runtime. Linux-only.

## Scope

| Operation                          | Implementation |
|------------------------------------|----------------|
| `create(name, &ResourceLimits)`    | `fs::write`    |
| `add_pid(&guard, pid)`             | `fs::write`    |
| `CgroupGuard` (RAII cleanup)       | `fs::remove_dir` on drop |

All limits are applied through the unified `/sys/fs/cgroup` hierarchy.
Only cgroup v2 is supported — bux is a modern-Linux project and v1 is
being removed upstream.

## Example

```rust,no_run
# #[cfg(target_os = "linux")]
# fn main() -> Result<(), bux_cgroup::Error> {
use bux_cgroup::{ResourceLimits, add_pid, create};

let limits = ResourceLimits::builder()
    .cpu_cores(2.0)
    .memory_bytes(512 * 1024 * 1024)
    .build();

let guard = create("vm-abc", &limits)?;
add_pid(&guard, std::process::id() as i32)?;
# Ok(()) }
# #[cfg(not(target_os = "linux"))]
# fn main() {}
```

## Status

Extracted from the `bux` main crate as part of the Phase 1 L1 refactor.
See `docs/design/L1-platform-primitives.md` in the workspace root for the
design rationale.
