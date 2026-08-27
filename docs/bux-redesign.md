# Bux architecture

This file replaces the stale L0–L4 RFC (`spawn.rs`, TSI `set_port_map`, Phase B
libcontainer). Those paths are gone. Source of truth is the code.

## Product

Embeddable library: [`Runtime`](../crates/bux/src/lib.rs) + `Vm` + `VmOptions`.
The CLI is a client of that API. No gRPC, youki, REST, or multi-language SDK.

Spine:

1. OCI (or rootfs / base disk) → ext4 base with injected static `bux-guest` → QCOW2 overlay.
2. The `bux-shim` binary starts gvproxy (virtio-net) or stays offline. Never calls `krun_set_port_map`.
3. Jail (`bux-jail`) spawns `bux-shim`; shim applies `ShimConfig` and `krun_start_enter`.
4. Guest agent is PID 1 (Phase A). Workload is `exec`.
5. Host `Client` uses postcard protocol v9 (one Unix-socket connection per op).
6. SQLite `user_version` 5; mismatch refuses to open (wipe `data_dir`).

## Known defects

| ID | Status |
|----|--------|
| D1 | Fixed: gvproxy in `bux-shim-bin`; `VmConfig.detach` gates parent-death |
| D2 | Fixed in engine: `disable_implicit_vsock` + `add_vsock(0)`; **guest proof is FULL `offline-no-eth0`** |
| D3 | Fixed in agent: virtiofs mount from `GuestBootConfig`; **guest proof is FULL volume ls** |
| D4 | Open: FULL never recorded green |
| D5 | Open: engine fix landed, guest proof pending |

D1–D3 are complete in code. Production is a recorded green `BUX_E2E_FULL=1` on
local HVF (Apple Silicon). Host CI (`BUX_E2E_FULL=0`) is not that proof.

## See also

- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — build, env, tests
- [`crates/bux/src/runtime/boot/mod.rs`](../crates/bux/src/runtime/boot/mod.rs) — managed boot
- [`crates/bux-shim/README.md`](../crates/bux-shim/README.md) — engine boundary
