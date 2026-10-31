# bux-jail

Process isolation for the `bux-shim` child process (`bux-bwrap`,
`bux-landlock`).

## Scope

| Platform | Default sandbox |
|----------|-----------------|
| Linux | bubblewrap (`bux-bwrap`) namespaces |
| macOS | `sandbox-exec` (Seatbelt) |
| fallback | pre-exec FD cleanup + die-with-parent only |

## Public surface

- [`JailConfig`] / [`spawn`] — spawn shim under isolation (bwrap/seatbelt + Landlock on Linux, K22 fail-closed)
- [`ShimProcess`] — the spawned shim as pid + start time: `is_alive`, `terminate`, `kill`, `signal`, `wait`.
  Rebuild it after a host restart with `ShimProcess::open(pid, start_time)`; a pid
  whose start time differs is treated as gone, so a reused pid is never signalled.
- [`Keepalive`] — parent end of the watchdog pipe, returned unless the VM is
  detached. Dropping it makes the shim shut down.
- [`SecurityReport`] / [`LayerStatus`] — actual posture after spawn
- [`Sandbox`] / [`NoopSandbox`] — pluggable sandbox trait
- Host capability probes (`check_host`, `audit_isolation`, `probe_bwrap`)

## Dependency rules

- Does **not** depend on `bux` or `bux-krun`.
- Watchdog FD env key: [`ENV_WATCHDOG_FD`] (`BUX_WATCHDOG_FD`), set by [`spawn`].
- QCOW2 backing-chain read-only paths are supplied by the caller via
  [`JailConfig::readonly_paths`] (Runtime computes them).
