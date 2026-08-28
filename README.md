# Bux

Embeddable micro-VM sandbox for untrusted agent code. Product entry is
`Runtime` + `Vm` + `VmOptions` in the `bux` crate. The `bux` CLI is a client of
that API. Isolation vs the host is the hardware VM (Linux KVM / macOS HVF) plus
shim jail. Concurrent execs in one VM are not isolated from each other or from
the guest agent (Phase A).

This tree is workspace **0.7.0**. Production-ready 1.0 bar:
[`docs/1.0-release-bar.md`](docs/1.0-release-bar.md) (crate version for that
increment: 0.8.0; do not tag `v1.0.0`). Architecture:
[`docs/bux-redesign.md`](docs/bux-redesign.md). Isolation:
[`docs/security-model.md`](docs/security-model.md).

## Install

```bash
cargo build -p bux-cli -p bux-shim-bin
```

Linux guest agent (static musl, injected as PID 1):

```bash
cargo build -p bux-guest --target aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl
```

Requires a C toolchain for libkrun / e2fs / qcow2 native deps, and Go for
`bux-gvproxy`. Pins and bindgen: [`docs/native-deps.md`](docs/native-deps.md).
Build, tarball layout, Darwin guest fetch, and FULL procedure:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

`cd.yml` ships `bux`, `bux-shim`, `bux-guest-<triple>`, and `libkrun*` /
`libkrunfw*` (including soname aliases) in one directory.

## Getting started

Use `./target/debug/bux` from the build above, not a PATH `bux`. `bux-shim`
must sit next to that binary or be set via `BUX_SHIM_PATH`. Darwin does not
compile the guest; fetch a static Linux ELF with `scripts/e2e/fetch-guest.sh`
and set `BUX_GUEST_PATH`. Linux may `cargo build -p bux-guest --target
$ARCH-unknown-linux-musl` when that rustc target and `musl-gcc` are present.

```bash
export BUX_HOME="${BUX_HOME:-$PWD/.bux-home}"
./target/debug/bux system info --format json
./target/debug/bux pull alpine
./target/debug/bux create --name t1 alpine
./target/debug/bux exec t1 -- echo ok
./target/debug/bux stop t1
./target/debug/bux rm t1
```

`create` is always detach: the CLI exits; the VM survives. Equivalent to
`bux run -d IMAGE` with no command override.

Empty `--allow-net` is **unrestricted** egress. Non-empty is default-deny
except listed IP / CIDR / hostname / `*.suffix`. Offline:
`--network=disabled` (no `eth0`). Production profile is an allow-list or
disabled, not the default.

`bux system info --format json` is the capture surface (flock-free; does not
`Runtime::open`). Schema `user_version` 5: mismatch refuses to open — wipe
`$BUX_HOME` or `bux system reset`.

## Embed

```rust
use bux::{ExecStart, Runtime, VmOptions};

let rt = Runtime::open(bux::default_data_dir())?;
let mut vm = rt
    .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
    .await?;

vm.exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
    .await?;
vm.stop().await?;
```

Compile gate: `cargo build -p bux --example embed`
([`crates/bux/examples/embed.rs`](crates/bux/examples/embed.rs)), matching
`crates/bux/src/lib.rs`. Sidecar `bux-shim` and `bux-guest` are
`RuntimeOptions::shim_path` / `guest_path`, else `BUX_SHIM_PATH` /
`BUX_GUEST_PATH`, a sibling of the running executable, then `$PATH`.
`Runtime::open` takes an exclusive flock; a second open on the same data dir
is `Error::Busy`.

Linux embedders must set `$ORIGIN` rpath so libkrun can `dlopen` firmware next
to the binary. Darwin copies already use `@loader_path`. Details:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Isolation model

See [`docs/security-model.md`](docs/security-model.md). This tree:

- **Host boundary:** libkrun VM (KVM or HVF). Jailer on by default (Linux:
  bubblewrap + Landlock fail-closed unless `allow_degraded`; macOS:
  `sandbox-exec` Seatbelt). Missing virtualization is an `isolation_warnings`
  entry on `HostInfo`, not a create hard-fail.
- **Phase A:** workload processes share the guest rootfs and kernel namespaces
  with the agent. Compromise of a workload is compromise of the agent
  filesystem. Hardware boundary vs the host still holds. Inspect
  `isolation_note` carries this text.
- **Egress:** empty `allow_net` is unrestricted. Non-empty is default-deny
  except listed IP / CIDR / hostname / `*.suffix`. Gateway and guest TAP IPs
  stay allowed. Inspect serializes `network` (`NetworkSpec`).
- **Snapshots:** create / list / delete of the QCOW2 overlay. Rows
  `ON DELETE CASCADE` on the source VM (`bux rm` of the source drops snapshot
  rows). No restore on this tree.
- **Volumes:** bind and named. Sensitive host prefixes denied unless
  `allow_sensitive`. `read_only` / CLI `:ro` is metadata; engine virtio-fs is
  RW.
- **Secrets:** values are memory-only on `Runtime`; they must not appear in
  `bux.db` or guest `/proc/1/environ`. MITM CA validity is 24h.
- **Protocol:** postcard v9.

1.0-bar items that are **not** current (virtio-fs `:ro` via
`krun_add_virtiofs3`, snapshot restore, protocol v10, Linux seccomp with
in-process gvproxy, create fail-closed without virtualization, KVM FULL
record): [`docs/1.0-release-bar.md`](docs/1.0-release-bar.md).

## Capture env

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` (else next to CLI or `$PATH`) |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF (Runtime inject) |
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF (`bux-cli` stages a sibling copy) |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

## CLI

See [`crates/bux-cli/README.md`](crates/bux-cli/README.md).

## License

MIT OR Apache-2.0. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).
