# Bux

Embeddable micro-VM sandbox for untrusted agent code. Product entry is
`Runtime` + `Vm` + `VmOptions` in the `bux` crate. The `bux` CLI is a client of
that API. Isolation vs the host is the hardware VM (Linux KVM / macOS HVF) plus
shim jail. Concurrent execs in one VM are not isolated from each other or from
the guest agent (Phase A).

Production-ready 1.0 bar: [`docs/1.0-release-bar.md`](docs/1.0-release-bar.md)
(crate version for that increment: 0.8.0). Architecture:
[`docs/bux-redesign.md`](docs/bux-redesign.md).

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
Build, tarball layout, and FULL procedure: [`CONTRIBUTING.md`](CONTRIBUTING.md).

`cd.yml` ships `bux`, `bux-shim`, `bux-guest-<triple>`, and `libkrun*` /
`libkrunfw*` (including soname aliases) in one directory.

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

Also: `crates/bux/examples/embed.rs`. Sidecar `bux-shim` and `bux-guest` are
`RuntimeOptions::shim_path` / `guest_path`, else `BUX_SHIM_PATH` /
`BUX_GUEST_PATH`, a sibling of the running executable, then `$PATH`.

## Isolation model

- **Host boundary:** libkrun VM (KVM or HVF). Jailer on by default (Linux:
  bubblewrap + Landlock; macOS: `sandbox-exec` Seatbelt).
- **Phase A:** workload processes share the guest rootfs and kernel namespaces
  with the agent. Compromise of a workload is compromise of the agent
  filesystem. Hardware boundary vs the host still holds.
- **Egress:** empty `allow_net` is unrestricted. Non-empty is default-deny
  except listed IP / CIDR / hostname / `*.suffix`.
- **Snapshots:** rows `ON DELETE CASCADE` on the source VM.
- **Secrets:** values are memory-only on `Runtime`; they must not appear in
  `bux.db` or guest `/proc/1/environ`.

`bux system info --format json` is the capture surface (flock-free).

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
