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
- [`SecurityReport`] / [`LayerStatus`] — actual posture after spawn
- [`Sandbox`] / [`NoopSandbox`] — pluggable sandbox trait
- Host capability probes (`check_host`, `audit_isolation`)

## Dependency rules

- Does **not** depend on `bux` or `bux-krun`.
- Watchdog FD env key: [`ENV_WATCHDOG_FD`] (`BUX_WATCHDOG_FD`).
- QCOW2 backing-chain read-only paths are supplied by the caller via
  [`JailConfig::readonly_paths`] (Runtime computes them).
