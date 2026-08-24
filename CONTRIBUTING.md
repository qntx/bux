# Contributing to bux

## Build

```bash
cargo build -p bux -p bux-cli -p bux-shim
# Linux guest agent (static musl recommended for rootfs injection):
cargo build -p bux-guest --target aarch64-unknown-linux-musl   # or x86_64-...
```

Requires a working C toolchain for libkrun / e2fs / qcow2 native deps, and Go for `bux-gvproxy` (build.rs compiles the bridge).

## Capture environment

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` (else next to CLI or `$PATH`) |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF (Runtime inject) |
| `BUX_GUEST_DIR` | Directory with prebuilt `bux-guest` Linux ELF for host arch (CLI build) |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

Inspect the live host with:

```bash
bux system info
bux system info --format json
```

## Architecture notes

- Product entry: `Runtime` + `Vm` + `VmOptions` (`crates/bux`).
- Engine boundary: product `VmConfig` → `ShimConfig` → `bux-shim` → libkrun.
- Managed network: gvproxy virtio-net owned by Runtime (known D1); no TSI `set_port_map`.
- Guest agent: postcard protocol v9; Phase A process identity only.
- Schema: SQLite `user_version` 4 — **no migrations**; wipe `BUX_HOME` on mismatch.

Current architecture: `docs/bux-redesign.md`.

## Tests

```bash
cargo test -p bux --lib
cargo test -p bux-proto --lib
# Host-only smoke (no hypervisor):
./scripts/e2e/smoke.sh
# Full VM e2e — requires HVF (macOS) or KVM (Linux), a Linux guest ELF, and a network-capable image:
BUX_E2E_FULL=1 ./scripts/e2e/smoke.sh
```

Host-only smoke is the CI gate (`.github/workflows/e2e-host.yml` forces
`BUX_E2E_FULL=0`). `BUX_E2E_FULL=1` is a **manual** production proof on a local
machine with HVF (macOS) or KVM (Linux): boot/exec/egress/allow_net/ports.
Never set `BUX_E2E_FULL=1` on GitHub-hosted runners. Do not treat host-only as
that proof. Schema mismatches require `bux system reset` (or wiping `$BUX_HOME`).

## Lints

Workspace clippy is strict (`unsafe_code = deny` with crate exceptions). Prefer small, modular PRs along the redesign plan spine.
