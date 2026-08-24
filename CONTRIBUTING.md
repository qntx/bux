# Contributing to bux

## Build

```bash
cargo build -p bux-cli -p bux-shim-bin
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
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF (`bux-cli` stages a sibling copy) |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

Release packaging ships `bux-guest-*` next to the CLI. Runtime resolution
(`ManagedGuestBinary::resolve`) is: `BUX_GUEST_PATH`, then a sibling of the
running executable (`bux-guest-<triple>`, `bux-guest-linux`, `bux-guest`),
then `$PATH`. There is no download protocol and the ELF is not vendored into
the crate.

Inspect the live host with:

```bash
bux system info
bux system info --format json
```

## Architecture notes

- Product entry: `Runtime` + `Vm` + `VmOptions` (`crates/bux`).
- Engine boundary: product `VmConfig` → `ShimConfig` → `bux-shim` → libkrun.
- Managed network: gvproxy virtio-net in the `bux-shim` process (`bux-shim-bin`); no TSI `set_port_map`.
- Guest agent: postcard protocol v9; Phase A process identity only.
- Schema: SQLite `user_version` 4 — **no migrations**; wipe `BUX_HOME` on mismatch.

Current architecture: `docs/bux-redesign.md`.

## Tests

```bash
cargo test -p bux --lib
cargo test -p bux-proto --lib
# Host-only smoke (no hypervisor). This is the GitHub-hosted CI gate:
./scripts/e2e/smoke.sh
# Full VM e2e — documented **manual** gate on local HVF (Apple Silicon).
# Never set BUX_E2E_FULL=1 on GitHub-hosted runners.
BUX_E2E_FULL=1 ./scripts/e2e/smoke.sh
```

`.github/workflows/e2e-host.yml` forces `BUX_E2E_FULL=0` on `ubuntu-latest` and
`macos-latest`. Host-only is not production proof. `BUX_E2E_FULL=1` is not a CI
job. GitHub-hosted runners must not set `BUX_E2E_FULL=1`. Self-hosted runners
can take it later without redesign.

The first green FULL is recorded by the operator on **local HVF (Apple
Silicon)**. Until this file contains that record (OS, arch, `bux system info`
libkrun features, image ref/digest, date), do not call the tree
production-ready. KVM later without redesign.

FULL always builds `target/debug/bux` and `target/debug/bux-shim` and ignores a
PATH `bux`. On Darwin the script ad-hoc codesigns the shim with
`crates/bux-shim/bux-shim.entitlements`. Darwin HVF needs that codesign plus a
guest ELF via `BUX_GUEST_PATH` (CD `workflow_dispatch` artifact, or a prior
`aarch64-unknown-linux-musl` build). Darwin does not compile the guest and does
not use zig cc. Linux FULL may `cargo build -p bux-guest --target
$ARCH-unknown-linux-musl` only when `musl-gcc` and that rustc target are already
present; the ELF must still pass validation (64-bit LE, host guest arch
x86_64/aarch64, no `PT_INTERP`). Missing or dynamic ELF exits before `bux
create`.

Pin `$BUX_E2E_IMAGE` if alpine wget/httpd is missing. There is no in-repo
custom e2e image.

`bux disk create` / `ImageRef::BaseDisk` does not inject guest PID 1. FULL uses
OCI (`bux pull` / `bux create IMAGE`).

`scripts/e2e/smoke.sh` with `BUX_E2E_FULL=1` covers:

1. `bux pull` alpine (or `$BUX_E2E_IMAGE`)
2. `bux create --name t1 IMAGE` then CLI exits (`create` is always detach)
3. `bux exec t1 -- echo ok`
4. egress `wget http://example.com`
5. `bux create --allow-net 127.0.0.1` then wget example.com **fails**
6. D1 publish: `bux create -p 0:80`, CLI exits, `inspect` host ≠ 0 and
   `bind_addr=0.0.0.0`, host TCP to that port **reaches the guest**
7. **`offline-no-eth0`:** `bux create --network=disabled`, wget fails (no TSI),
   `/sys/class/net/eth0` absent (do not also assert dummy-nic)
8. volume: `bux create -v host:/data` then `bux exec -- ls /data`
9. `bux stop` / `bux restart` / `bux rm` of a `detach=true` VM (no `bux start`;
   restart must still survive CLI exit)
10. secrets: value not in `bux.db` or guest `/proc/1/environ`

Until that checklist is green on local HVF (Apple Silicon), do not call the
tree production-ready.

Schema mismatches require `bux system reset` (or wiping `$BUX_HOME`).

## Lints

Workspace clippy is strict (`unsafe_code = deny` with crate exceptions). Prefer small, modular PRs along the redesign plan spine.
