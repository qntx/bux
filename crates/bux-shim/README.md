# bux-shim

Owns the **engine boundary**: serializable [`ShimConfig`] applied to libkrun.
The process-takeover binary lives in `bux-shim-bin` (`[[bin]] name = "bux-shim"`).

## Why a separate crate

- libkrun **process takeover** must not run inside the host tokio Runtime.
- Host `bux` maps product state → `ShimConfig` JSON; shim never depends on `bux`.
- Virtio-net via `add_net_unixstream` / `add_net_unixgram`. The shim never
  calls TSI `set_port_map`. The vsock device is always explicit with TSI
  off (`disable_implicit_vsock` + `add_vsock(0)`), with or without
  `network`.
- A directory root is a virtio-fs device tagged `/dev/root`
  (`add_virtiofs3`), not `krun_set_root`, which the smolvm libkrun fork
  lacks.

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
| `prepare` | create libkrun ctx + apply config (never starts gvproxy) |
| `install_seccomp` | default VMM seccomp (Linux `x86_64`/`aarch64`; Darwin no-op). Binary installs after gvproxy threads exist. |
| `start` | `krun_start_enter` (never returns on success) |
| `die_with_jail` | as PID 1 of a jail, die with bwrap's outer process (Linux) |
| `ExitInfo` | crash diagnostics JSON |
