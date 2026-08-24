# bux-shim

Owns the **engine boundary**: serializable [`ShimConfig`] applied to libkrun,
plus the `bux-shim` binary that takes over the process via `krun_start_enter`.

## Why a separate crate

- libkrun **process takeover** must not run inside the host tokio Runtime.
- Host `bux` maps product state → `ShimConfig` JSON; shim never depends on `bux`.
- Virtio-net via `add_net_unixstream` / `add_net_unixgram`. The shim never
  calls TSI `set_port_map`. When `network` is `None`, libkrun still
  auto-enables TSI (known D2).

## Wire format

Runtime writes `ShimConfig` JSON to a temp file and execs:

```text
bux-shim <path/to/config.json>
```

Optional env: `BUX_WATCHDOG_FD=<fd>` (read end of parent keepalive pipe).

## Library API

| Item | Role |
|------|------|
| `ShimConfig` | serde JSON config for the engine |
| `prepare` | create libkrun ctx + apply config |
| `start` | `krun_start_enter` (never returns on success) |
| `boot` | `prepare` + seccomp + `start` |
| `host` | host-side libkrun probes |
| `ExitInfo` | crash diagnostics JSON |
