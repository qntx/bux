# Contributing to bux

The product is a hosted per-agent sandbox (`bux serve`). The engine
(`Runtime` / `Vm` / `VmOptions`) is the substrate. **1.0 is hosted + FULL
proof** (HVF v10 guest from that commit, Linux `/dev/kvm` FULL, load/chaos),
not library-only. Do not tag `v1.0.0` until that bar is true. Do not invent
FULL sha256 rows.

Operator docs: root `README.md`, `docs/architecture.md`,
`docs/security-model.md`, `docs/serve.md`.

## Build

```bash
cargo build -p bux-cli -p bux-shim-bin
# Linux guest agent (static musl recommended for rootfs injection):
cargo build -p bux-guest --target aarch64-unknown-linux-musl   # or x86_64-...
```

Requires a working C toolchain for libkrun / e2fs / qcow2 native deps, and Go for `bux-gvproxy` (build.rs compiles the bridge).

## Native libraries

Prebuilt libkrun, e2fsprogs, and (Linux) bubblewrap download from GitHub
Releases tagged `krun-v{LIBKRUN_VERSION}` (not crate versions).

## Capture environment

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` (else next to CLI or `$PATH`) |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF (Runtime inject) |
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF (`bux-cli` stages a sibling copy) |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

Release packaging ships `bux`, `bux-shim`, `bux-guest-*`,
`libkrun*`/`libkrunfw*` (including soname aliases), and Linux `bwrap` in the
same directory.
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
The `bux-shim` binary records `@loader_path/libkrun.dylib`. `crates/bux`
does not link libkrun.

Linux: `DT_NEEDED` on `bux-shim` stays the soname. This workspace stamps
`-Wl,-rpath,$ORIGIN` via `.cargo/config.toml` for in-tree bins.

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

- Product: hosted per-agent sandbox (`bux serve`). HTTP is a client of
  `Runtime`; it does not live in `crates/bux`. 1.0 is that worker plus
  recorded FULL proof, not library-only.
- Engine: `Runtime` + `Vm` + `VmOptions` (`crates/bux`). Exclusive flock;
  one process owns `BUX_HOME`. Second serve (or CLI Runtime) on the same
  dir is `Busy`.
- Engine boundary: product `VmConfig` → `ShimConfig` → `bux-shim` → libkrun.
- Managed network: gvproxy virtio-net in the `bux-shim` process (`bux-shim-bin`); no TSI `set_port_map`.
- Guest agent: postcard protocol v10; Phase A process identity only.
- Schema: SQLite `user_version` 5 — **no migrations**; wipe `BUX_HOME` on mismatch.
- Isolation vs host: hardware VM. Isolation vs other agents: one VM per agent.
- `create` fail-closed: `require_virtualization` before image resolve
  (`Error::SecurityUnavailable`; HTTP 412).

## Tests

```bash
cargo test -p bux --lib
cargo test -p bux-proto --lib
# Host-only smoke (no hypervisor). This is the GitHub-hosted CI gate:
./scripts/e2e/smoke.sh
./scripts/e2e/serve.sh
# Full VM e2e — documented **manual** gate (HVF recorded; KVM needs /dev/kvm).
# Never set BUX_E2E_FULL=1 on GitHub-hosted runners.
BUX_E2E_FULL=1 ./scripts/e2e/smoke.sh
# Load / chaos / serve — same FULL pin as smoke (cli+shim, guest ELF). Manual HVF/KVM.
# GitHub-hosted CI does not run these; e2e-host.yml stays BUX_E2E_FULL=0.
BUX_E2E_FULL=1 ./scripts/e2e/load.sh
BUX_E2E_FULL=1 ./scripts/e2e/chaos.sh
BUX_E2E_FULL=1 ./scripts/e2e/serve.sh
```

`.github/workflows/e2e-host.yml` forces `BUX_E2E_FULL=0` on `ubuntu-latest` and
`macos-latest` (`smoke.sh` and `serve.sh` help/openapi). Host-only is not
production proof. `BUX_E2E_FULL=1` is not a CI job. GitHub-hosted runners must
not set `BUX_E2E_FULL=1`. Self-hosted runners can take it later without
redesign. `load.sh`, `chaos.sh`, and `serve.sh` FULL are the same manual gate,
not GitHub-hosted jobs.

The first green FULL is recorded below on **local HVF (Apple Silicon)**.
Host CI (`BUX_E2E_FULL=0`) is not that proof. Linux KVM has **no** Layer 1
row in this tree (procedure under **Linux KVM FULL record**).

The HVF captures below (`42f02b0`, `f4ff20f`, `04fca66`) ran against pre-v10
guests. They are **not ship proof**. Do not invent a new uname or ELF sha256
to update this table. Linux KVM stays empty until an operator records a v10
run.

### Layer 1 FULL record

Operator FULL 2026-08-28 local HVF (smoke START 2026-08-27T19:48:37Z UTC,
`SMOKE_EXIT=0`, `OK (full e2e)`). Capture binary `./target/debug/bux` (not
PATH `bux`). `$BUX_HOME` was `/Users/xu/bux-full-hvf-119` (no `bux-e2e`
substring). **Pre-v10; not ship proof.**

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

Leftover sibling `BUX_GUEST_PATH` host mode **0644** is OK to record; Runtime
inject writes the guest ELF at mode `0555`. Item 7 `NO_ETH0` sysfs still counts as offline proof.
Item 5/7 wget-fail is unclassified; do not treat as HVF proof of
`allow_net` / offline **policy**. This record is not GitHub-hosted
`BUX_E2E_FULL=1`.

### Linux KVM FULL record

Empty. 0.8 ships **without** a Linux KVM FULL record until an operator with
`/dev/kvm` runs `BUX_E2E_FULL=1 ./scripts/e2e/smoke.sh` and the script prints
`OK (full e2e)`. Do not copy the HVF `uname`, git SHA, ELF sha256, or image
digest. Do not invent those values or `SMOKE_EXIT=0`. Host identity is a
checklist input, not a GitHub-hosted job. `.github/workflows/e2e-host.yml`
keeps `BUX_E2E_FULL=0` on `ubuntu-latest`. If smoke fails, a code PR first.

After that green run, fill a Layer 1 row from **that** host (capture binary
`./target/debug/bux`, not PATH `bux`; `$BUX_HOME` without substring
`bux-e2e`):

| Field | How to capture |
| ----- | -------------- |
| Date | calendar date of the run |
| uname | `uname -a` |
| /dev/kvm | character device present (`test -c /dev/kvm`) |
| rustc | `rustc --version` |
| git | `git rev-parse HEAD` of the tree that ran smoke |
| guest ELF sha256 | sha256 of `$BUX_GUEST_PATH` (the ELF smoke used) |
| image digest | `./target/debug/bux images --format json` |
| SMOKE_EXIT | `0` only with `OK (full e2e)` |
| boot_s | optional; wall seconds create → first successful exec; not a fail gate |

Capture `.host.*` with `./target/debug/bux system info --format json` and image
reference/digest with `./target/debug/bux images --format json`. Pin `$BUX_HOME`
to a path **without** substring `bux-e2e` (`scripts/e2e/smoke.sh` removes that
data dir on exit). Darwin guest ELF: `scripts/e2e/fetch-guest.sh`.

FULL always builds `target/debug/bux` and `target/debug/bux-shim` and ignores a
PATH `bux`. On Darwin the script ad-hoc codesigns the shim with
`crates/bux-shim/bux-shim.entitlements`. Darwin FULL **requires**
`BUX_GUEST_PATH` from `scripts/e2e/fetch-guest.sh` of this HEAD (not a cwd
`gh run download` that leaves the ELF nested). There is no leftover
`target/debug/bux-guest-*` fall-through: unset `BUX_GUEST_PATH` plus a leftover
ELF must fail before `bux create`. Before fetch, unset `BUX_GUEST_PATH` **and**
delete leftover `target/debug/bux-guest-*`. Darwin does not compile the guest
and does not use zig cc.

Before any FULL `bux create`, `pin_full_binaries` calls
`refuse_fake_ip_example_com`: Python `getaddrinfo("example.com", 443,
type=SOCK_STREAM)`, log every record, fail if any address's IPv4 form is in
`198.18.0.0/15` (IPv4; else `ipv4_mapped`; else last 4 bytes of the AAAA
packed form — macOS translated `::ffff:0:c612:a0` is not
`::ffff:198.18.0.0/111`). Fake-ip / MacPacket is hygiene, not a recorded 502.
Disable fake-ip for the HVF v10 record. Do not invent FULL sha256.

Linux FULL when `BUX_GUEST_PATH` is unset: musl-gcc build of this tree (when
`musl-gcc` and that rustc target are already present) **or**
`scripts/e2e/fetch-guest.sh`. Do not silently accept a leftover v9 ELF. After
musl-build/fetch, the ELF must still contain the literal bytes
`bux-guest-protocol-v10`. Missing stamp, missing ELF, or a dynamic ELF exits
before `bux create`. Validation is 64-bit LE, host guest arch x86_64/aarch64,
no `PT_INTERP`, plus that stamp.

FULL needs python3 for the guest ELF validator and Go for `bux-shim-bin`;
Darwin FULL still needs `BUX_GUEST_PATH` and `gh` authenticated to `qntx/bux`
with `workflow` if they must dispatch; `gh release download guest-v0.1.0` is
enough when that Release exists; `gh run download` is enough when a matching
run already exists.

CD `cd.yml` musl guest:

- Release tag: `guest-v{crates/bux-guest version}` (never `v0.8.0`, never `guest-<sha>`)
- Release asset **file**: `bux-guest-<triple>` and `bux-guest-<triple>.sha256`
- GHA artifact **name**: `guest-<triple>` (never `bux-guest-*`)
- **file** inside the artifact: `bux-guest-<triple>`
- sibling after fetch: `target/debug/bux-guest-<triple>`

After this merge is on `main`, tag the guest of that commit (`guest-v` plus
`crates/bux-guest/Cargo.toml` `version`; `0.1.0` today):

```bash
git fetch origin
git checkout main
git pull --ff-only origin main
git tag guest-v0.1.0
git push origin guest-v0.1.0
```

Do not vendor the ELF in git. Do not fill the FULL record above from a
Release download.

`scripts/e2e/fetch-guest.sh` prefers the `guest-<sha>` Release asset, else
polls the `guest-<triple>` workflow artifact for this `HEAD`, and copies the
file next to `target/debug/bux`. Dest is `chmod 0755` after copy; the script
exits 1 if not `-x`. The same `bux-guest-protocol-v10` bytes check as
`full_common.sh` applies: a v9 ELF is rejected even if `guest-<sha>` exists.
Do not `gh run download -n bux-guest-*`.

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
8. volume: `bux create -v host:/data` then `bux exec -- ls /data`; `:ro`
   write-fail (guest can read; `touch` on the volume fails)
9. `bux stop` / `bux restart` / `bux rm` of a `detach=true` VM (no `bux start`;
   restart must still survive CLI exit)
10. secrets: value not in `bux.db` or guest `/proc/1/environ`; HTTPS MITM
    handshake returns a **non-empty body**

The Layer 1 record above is that green local HVF run (**pre-v10, not ship
proof**). Host CI (`BUX_E2E_FULL=0`) is not that proof. Linux KVM FULL remains
empty. HEAD `smoke.sh` asserts `:ro` write-fail, HTTPS MITM non-empty body,
clone flatten, restore flatten + CASCADE; `load.sh` / `chaos.sh` are the same
FULL pin.

Items 11–15 are not in the `42f02b0` Layer 1 row.

11. copy: host↔guest file round-trip and directory `copy_in`
12. `bux create --allow-net example.com --allow-net www.example.com` then wget example.com succeeds
13. snapshot create / list / delete
14. recover: dead shim inspect JSON `"Stopped"`, then `rm` without `-f`
15. named-vol dir: `bux volume create` then bind `${BUX_HOME}/volumes/${NV}:/data`

Operator FULL 2026-08-28 on `f4ff20ffaabfde6aedb30d9e2e23d5916405765f`
(capture binary `./target/debug/bux`, `$BUX_HOME=/Users/xu/bux-full-hvf-addenda3`)
exited 0 including items 11–15 (`SMOKE_EXIT=0`, `OK (full e2e)`).
**Pre-v10; not ship proof.**

Item 16 is not in the `42f02b0` Layer 1 row.

16. clone flatten: `bux clone` of an OCI VM; `/clone-marker` on the root disk (not tmpfs)

Operator FULL 2026-08-28 on `04fca66945fe24fc16fda5aff113c8e4782cbc68`
(capture binary `./target/debug/bux`, `$BUX_HOME=/Users/xu/bux-full-hvf-clone`)
exited 0 including clone flatten (`SMOKE_EXIT=0`, `OK (full e2e)`).
**Pre-v10; not ship proof.**

Item 17 is not in the Layer 1 or clone FULL rows.

17. snapshot restore flatten: write `/restore-marker` → `bux snapshot create` →
    `bux snapshot restore` → `exec` cat marker; source still listed; `rm`
    restore; `rm` source drops snapshot rows (`ON DELETE CASCADE`)
18. load.sh (below)
19. chaos.sh (below)

`scripts/e2e/load.sh` (`BUX_E2E_FULL=1`, dedicated `$BUX_HOME`):

- `bux create` 8 detached alpine VMs (default 512 MiB each); all `bux ps` Running
- 16 concurrent `Vm::exec_output(echo ok)` on **one** `Runtime`
  (`crates/bux/examples/concurrent_exec.rs`); all exit 0. Not 16 `bux exec`
  CLI processes (R5 exclusive `bux.lock`)
- `bux rm -f` all 8; `bux ps -q` empty; no leftover `$BUX_HOME/disks/vms/*.qcow2`
- If available RAM is below 8×512 MiB plus per-VM/host overhead, the script
  exits with a message (no OOM flake)

`scripts/e2e/chaos.sh` (`BUX_E2E_FULL=1`):

- create → `kill -9` shim PID → `inspect` JSON `"Stopped"` within 5s → `bux rm`
  without `-f`
- no leftover overlay `$BUX_HOME/disks/vms/{id}.qcow2` for that id
- no `ulimit` disk-full test

`scripts/e2e/serve.sh` host-only (`BUX_E2E_FULL=0`, GitHub-hosted `e2e-host.yml`):

- `bux serve start --help`
- `bux serve openapi` (JSON document including `/v1/health` and sandbox routes)
- no hypervisor, no `bux-shim-bin` / guest ELF

`BUX_E2E_FULL=1 ./scripts/e2e/serve.sh` is the same cli+shim+guest pin as
`smoke.sh` (Darwin: `BUX_GUEST_PATH` from `scripts/e2e/fetch-guest.sh` of this
HEAD; Linux: musl-gcc or fetch). Skip FULL when `host.virtualization` is not
true. Capture binary `./target/debug/bux`. Pin `$BUX_HOME` without substring
`bux-e2e` if the data dir must survive script exit. Do not invent an HVF/KVM
sha256 row here — record a real run in a later docs PR.

FULL loop (HTTP, two API keys `t1` / `t2`):

1. `POST /v1/images/pull` alpine (or `$BUX_E2E_IMAGE`)
2. `POST /v1/sandboxes` twice with the same `agent_id` / image → same exact
   12-char id (201 then 200)
3. `POST .../exec` `echo` (stdout `e2e-ok`, code 0)
4. `PUT`/`GET .../files?path=/workspace/x`
5. `allow_net: ["127.0.0.1"]` then guest wget example.com **fails**
6. stop/start: `auto_stop_secs=1` + sweep then `POST .../start`; workspace
   file persists (HTTP has no stop route; idle sweep is the stop)
7. `DELETE` removes `{BUX_HOME}/volumes/ws-{tenant}-{agent}`
8. second tenant GET `{id}` → 404 (same envelope as missing)
9. SIGTERM the serve process, start again, exec still works (R3 reattach)
10. after auto-stop, `POST /v1/sandboxes` resume then GET is still `running`
    (`start_with` idle clock; do not wait a sweep tick with `auto_stop_secs=1`)
11. `curl --unix-socket` `GET /v1/health` (worker also binds TCP loopback)
12. snapshot create → restore `{agent_id}` → exec overlay marker
13. clone `{agent_id}` → exec overlay marker
14. other tenant 404 on snapshot GET/POST

Schema mismatches require `bux system reset` (or wiping `$BUX_HOME`).

## Lints

Workspace clippy is strict (`unsafe_code = deny` with crate exceptions). Prefer small, modular PRs. Hosted worker and engine stay separate crates.
