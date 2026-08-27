# Contributing to bux

## Build

```bash
cargo build -p bux-cli -p bux-shim-bin
# Linux guest agent (static musl recommended for rootfs injection):
cargo build -p bux-guest --target aarch64-unknown-linux-musl   # or x86_64-...
```

Requires a working C toolchain for libkrun / e2fs / qcow2 native deps, and Go for `bux-gvproxy` (build.rs compiles the bridge).

## Native libraries

Prebuilt libkrun, e2fsprogs, and (Linux) bubblewrap download from GitHub
Releases tagged `krun-v{LIBKRUN_VERSION}` (not crate versions). Pins,
compile-from-cold, bindgen, and the tag-PR-SHA-then-merge loop:
[`docs/native-deps.md`](docs/native-deps.md).

## Capture environment

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` (else next to CLI or `$PATH`) |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF (Runtime inject) |
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF (`bux-cli` stages a sibling copy) |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

Release packaging ships `bux`, `bux-shim`, `bux-guest-*`, and
`libkrun*`/`libkrunfw*` (including soname aliases) in the same directory.
`cargo build` stages those dylibs into the cargo profile directory next to
`bux` / `bux-shim`. Versioned aliases (`libkrun.1.dylib` /
`libkrunfw.5.dylib`, Linux `libkrun.so.1` / `libkrunfw.so.5`) are required:
libkrun `dlopen`s the firmware leaf name (`libkrunfw.5.dylib` /
`libkrunfw.so.5`).

Darwin: `bux-krun` copies `libkrun.dylib` and `libkrunfw.dylib` into
`$OUT_DIR/link-lib`, sets `LC_ID_DYLIB` to `@loader_path/libkrun.dylib` and
`@loader_path/libkrunfw.dylib`, adds `LC_RPATH @loader_path` on
`libkrun.dylib` so `dlopen("libkrunfw.5.dylib")` searches the dylib's
directory, ad-hoc codesigns those copies, and link-searches only `link-lib`.
Linked binaries record `@loader_path/libkrun.dylib`. Downstream Darwin
embedders do not need rpath rustflags.

Linux: `DT_NEEDED` stays the soname. This workspace stamps
`-Wl,-rpath,$ORIGIN` via `.cargo/config.toml`. Downstream embedders must set:

```toml
# embedder .cargo/config.toml (Linux)
[target.'cfg(target_os = "linux")']
rustflags = ["-C", "link-arg=-Wl,-rpath,$ORIGIN"]
```

`crates/bux-shim-bin/build.rs` emits `-Wl,-rpath,@executable_path` (Darwin)
or `-Wl,-rpath,$ORIGIN` (Linux) so this repo's shim does not depend solely
on `.cargo/config.toml`. Keep the workspace rustflags file.

Runtime guest resolution (`ManagedGuestBinary::resolve`) is: `BUX_GUEST_PATH`,
then a sibling of the running executable (`bux-guest-<triple>`,
`bux-guest-linux`, `bux-guest`), then `$PATH`. There is no download protocol
and the ELF is not vendored into the crate.

Tarball layout (Darwin; Linux uses `libkrun.so` / `libkrun.so.1` and
`libkrunfw.so` / `libkrunfw.so.5`):

```
bux-<ver>-aarch64-apple-darwin/
  bux
  bux-shim
  bux-guest-aarch64-unknown-linux-musl
  libkrun.dylib
  libkrun.1.dylib
  libkrunfw.dylib
  libkrunfw.5.dylib
  LICENSE-MIT
  LICENSE-APACHE
```

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
- Schema: SQLite `user_version` 5 — **no migrations**; wipe `BUX_HOME` on mismatch.

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

The first green FULL is recorded below on **local HVF (Apple Silicon)**.
Host CI (`BUX_E2E_FULL=0`) is not that proof. KVM later without redesign.

### Layer 1 FULL record

Operator FULL 2026-08-28 local HVF (smoke START 2026-08-27T19:48:37Z UTC,
`SMOKE_EXIT=0`, `OK (full e2e)`). Capture binary `./target/debug/bux` (not
PATH `bux`). `$BUX_HOME` was `/Users/xu/bux-full-hvf-119` (no `bux-e2e`
substring).

| Field | Value |
| ----- | ----- |
| Date | 2026-08-28 |
| uname | Darwin X-2.local 25.6.0 Darwin Kernel Version 25.6.0: Fri Jul 31 19:16:20 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_T8142 arm64 |
| kern.hv_support | 1 |
| rustc | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| git | 42f02b0bbfe3c883417ad132f21e025afcc102a0 |
| BUX_GUEST_PATH triple | aarch64-unknown-linux-musl |
| ELF sha256 | 03ade6fffdc2d7968f5429a2257c14b9c42e2501d6fd14153a7500dceb2157d2 |
| host.virtualization | true |
| host.krun_features | ["net","blk"] |
| host.mandatory_access_control | true |
| image reference | docker.io/library/alpine:latest |
| image digest | sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18 |

Leftover sibling `BUX_GUEST_PATH` host mode **0644** is OK to record (inject
0555 is #108 sidecar). Item 7 `NO_ETH0` sysfs still counts as offline proof.
Item 5/7 wget-fail is unclassified; do not treat as HVF proof of
`allow_net` / offline **policy**. This record is not GitHub-hosted
`BUX_E2E_FULL=1`.

Capture `.host.*` with `./target/debug/bux system info --format json` and image
reference/digest with `./target/debug/bux images --format json`. Pin `$BUX_HOME`
to a path **without** substring `bux-e2e` (`scripts/e2e/smoke.sh` removes that
data dir on exit). Darwin guest ELF: `scripts/e2e/fetch-guest.sh`.

FULL always builds `target/debug/bux` and `target/debug/bux-shim` and ignores a
PATH `bux`. On Darwin the script ad-hoc codesigns the shim with
`crates/bux-shim/bux-shim.entitlements`. Darwin HVF needs that codesign plus a
guest ELF via `BUX_GUEST_PATH` from `scripts/e2e/fetch-guest.sh` (not a cwd
`gh run download` that leaves the ELF nested). Darwin does not compile the guest
and does not use zig cc. Linux FULL may `cargo build -p bux-guest --target
$ARCH-unknown-linux-musl` only when `musl-gcc` and that rustc target are already
present; the ELF must still pass validation (64-bit LE, host guest arch
x86_64/aarch64, no `PT_INTERP`). Missing or dynamic ELF exits before `bux
create`. FULL needs python3 for the guest ELF validator and Go for
`bux-shim-bin`; Darwin FULL still needs `BUX_GUEST_PATH` and `gh` authenticated
to `qntx/bux` with `workflow` if they must dispatch; `gh release download
guest-<sha>` is enough when that Release exists; `gh run download` is enough
when a matching run already exists.

CD `cd.yml` musl guest:

- Release tag: `guest-<40-char-sha>` of that commit (never `v0.4.1`)
- Release asset **file**: `bux-guest-<triple>`
- GHA artifact **name**: `guest-<triple>` (never `bux-guest-*`)
- **file** inside the artifact: `bux-guest-<triple>`
- sibling after fetch: `target/debug/bux-guest-<triple>`

Do not vendor the ELF in git. Do not fill the FULL record above from a
Release download.

`scripts/e2e/fetch-guest.sh` prefers the `guest-<sha>` Release asset, else
polls the `guest-<triple>` workflow artifact for this `HEAD`, and copies the
file next to `target/debug/bux`. Dest is `chmod 0755` after copy; the script
exits 1 if not `-x`. Do not `gh run download -n bux-guest-*`.

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

The Layer 1 record above is that green local HVF run. Host CI
(`BUX_E2E_FULL=0`) is not that proof.

Items 11–15 are not in the `42f02b0` Layer 1 row.

11. copy: host↔guest file round-trip and directory `copy_in`
12. `bux create --allow-net example.com --allow-net www.example.com` then wget example.com succeeds
13. snapshot create / list / delete
14. recover: dead shim inspect JSON `"Stopped"`, then `rm` without `-f`
15. named-vol dir: `bux volume create` then bind `${BUX_HOME}/volumes/${NV}:/data`

Item 16 is not in the `42f02b0` Layer 1 row.

16. clone flatten: `bux clone` of an OCI VM; `/clone-marker` on the root disk (not tmpfs)

Schema mismatches require `bux system reset` (or wiping `$BUX_HOME`).

## Lints

Workspace clippy is strict (`unsafe_code = deny` with crate exceptions). Prefer small, modular PRs along the redesign plan spine.
