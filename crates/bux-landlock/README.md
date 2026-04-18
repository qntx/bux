# bux-landlock

Safe, thin wrapper over the community [`landlock`] crate for bux. Zero
business logic (no hard-coded paths), Linux-only, graceful degradation
on old kernels.

## Scope

| Operation                                 | Implementation                                  |
|-------------------------------------------|-------------------------------------------------|
| `PathRestrictions::new().allow_read(...)` | Pure Rust builder (cross-platform)              |
| `.build()`                                | Linux: `landlock::Ruleset::create`; others: `None` |
| `restrict_self(fd)`                       | Raw `prctl` + `SYS_landlock_restrict_self`      |
| `is_available()`                          | Probe-create a minimal ruleset                  |

## Example

```rust,no_run
# #[cfg(target_os = "linux")]
# fn main() -> Result<(), bux_landlock::Error> {
use bux_landlock::{PathRestrictions, restrict_self};

let fd_opt = PathRestrictions::new()
    .allow_read("/usr")
    .allow_read("/etc")
    .allow_read_write("/tmp")
    .deny_network()
    .build()?;

if let Some(fd) = fd_opt {
    // In a forked child's pre_exec hook, call `restrict_self(fd)`.
    drop(fd);
}
# Ok(()) }
# #[cfg(not(target_os = "linux"))]
# fn main() {}
```

## Graceful degradation

- Non-Linux targets: `build()` returns `Ok(None)`.
- Linux < 5.13 (no Landlock): `build()` returns `Ok(None)`.
- Linux 5.13+ < 6.7 (no network rules): `deny_network()` silently
  no-ops thanks to the `BestEffort` compatibility mode.

## Status

Fresh crate, extracted per the Phase 1 L1 refactor. See
`docs/design/L1-platform-primitives.md` in the workspace root for the
design rationale.

[`landlock`]: https://crates.io/crates/landlock
