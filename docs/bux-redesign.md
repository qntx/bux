# Bux architecture

Source of truth is the code. Stale RFC paths (`spawn.rs` TSI `set_port_map`,
youki, Phase B libcontainer) are gone.

Production-ready 1.0 bar: [`docs/1.0-release-bar.md`](1.0-release-bar.md).
Crate version for that increment is 0.8.0; the bar is not a `v1.0.0` tag
instruction.

## Product

Embeddable library: [`Runtime`](../crates/bux/src/lib.rs) + `Vm` + `VmOptions`.
The CLI is a client of that API. No gRPC, youki, REST, or multi-language SDK.

Spine:

1. OCI (or rootfs / base disk) → ext4 base with injected static `bux-guest` → QCOW2 overlay.
2. The `bux-shim` binary starts gvproxy (virtio-net) or stays offline. Never calls `krun_set_port_map`.
3. Jail (`bux-jail`) spawns `bux-shim`; shim applies `ShimConfig` and `krun_start_enter`.
4. Guest agent is PID 1 (Phase A). Workload is `exec`. Concurrent execs share the guest with the agent; isolation vs the host is the hardware VM boundary (KVM / HVF) plus shim jail.
5. Host `Client` uses postcard protocol v9 (one Unix-socket connection per op).
6. SQLite `user_version` 5 (1.0 restore does not bump it); mismatch refuses to open (wipe `data_dir`). Snapshot rows `ON DELETE CASCADE` on the source VM.

## Known defects

| ID | Status |
|----|--------|
| D1 | Fixed: gvproxy in `bux-shim-bin`; `VmConfig.detach` gates parent-death |
| D2 | Fixed in engine: `disable_implicit_vsock` + `add_vsock(0)`; **guest proof is FULL `offline-no-eth0`** |
| D3 | Fixed in agent: virtiofs mount from `GuestBootConfig`; **guest proof is FULL volume ls** |
| D4 | Fixed: CONTRIBUTING Layer 1 |
| D5 | Fixed: CONTRIBUTING item 16 / smoke |

D1–D3 are complete in code. D4 is the recorded green `BUX_E2E_FULL=1` on local
HVF (Apple Silicon) in CONTRIBUTING Layer 1. D5 is clone flatten in CONTRIBUTING
item 16 / smoke. Host CI (`BUX_E2E_FULL=0`) is not that proof. There is no Linux
KVM FULL record.

## See also

- [`docs/1.0-release-bar.md`](1.0-release-bar.md) — production-ready 1.0 checklist
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — build, env, tests
- [`crates/bux/src/runtime/boot/mod.rs`](../crates/bux/src/runtime/boot/mod.rs) — managed boot
- [`crates/bux-shim/README.md`](../crates/bux-shim/README.md) — engine boundary
