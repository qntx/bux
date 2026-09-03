# Bux

Hosted per-agent sandbox. Every agent gets its own hardware-isolated micro-VM
(libkrun on KVM or Hypervisor.framework), addressable over HTTP (`bux serve`)
or by embedding [`Runtime`](crates/bux/src/lib.rs). Isolation versus the host
is the VM. Isolation versus other agents is **one VM per agent** — never share
a guest across agents.

The engine (`Runtime` / `Vm` / `VmOptions`) is the substrate. It is not a
library-only 1.0. **1.0 is the hosted worker plus recorded FULL proof** (HVF
v10 guest, Linux `/dev/kvm` FULL, load/chaos). Workspace version is **0.8.0**.
Do not tag `v1.0.0` until that bar is true. Recorded HVF rows in
[CONTRIBUTING.md](CONTRIBUTING.md) are pre-v10 and are **not ship proof**.
Linux KVM FULL is empty.

## Isolation

```text
                    untrusted (one agent)
┌─────────────────────────────────────────────┐
│ guest kernel (libkrunfw)                    │
│  bux-guest PID 1 + that agent's execs       │
│  /workspace ← named volume                  │
└──────────────────┬──────────────────────────┘
                   │ virtio blk, fs, vsock, net
┌──────────────────▼──────────────────────────┐
│ bux-shim + optional gvproxy                 │
│  seccomp (Linux) · Landlock · bwrap/seatbelt│
└──────────────────┬──────────────────────────┘
                   │ Unix sockets, overlay, volumes
┌──────────────────▼──────────────────────────┐
│ bux serve / Runtime (trusted)               │
│  SQLite, OCI cache, API keys                │
└─────────────────────────────────────────────┘
```

Phase A: concurrent execs in one VM share the guest rootfs and namespaces.
That is acceptable because one agent owns the guest. Inspect JSON includes
`PHASE_A_LIMITS` and `egress`.

`create` calls `require_virtualization` before image resolve. Missing KVM/HVF
is `Error::SecurityUnavailable` (HTTP **412**). GitHub-hosted CI does not
provide `/dev/kvm`; it is not Linux production proof.

CLI default network is unrestricted (`NetworkSpec::Enabled { allow_net: [] }`).
HTTP default is deny. Two entry points, one engine type.

## Install

Product artifact is the GitHub Release tarball (`v*` tags), not crates.io.

| Host | Asset |
|------|--------|
| Linux x86_64 | `bux-<ver>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `bux-<ver>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS aarch64 | `bux-<ver>-aarch64-apple-darwin.tar.gz` |

```bash
tar xf bux-*-x86_64-unknown-linux-gnu.tar.gz
./bux system info
```

Members are at archive root (`tar czf … -C "$staging" .`). Run `./bux` from
the directory that received the extract.

Extracted layout (Linux `.so` / Darwin `.dylib`; keep `libkrun*` next to `bux`):

```text
bux
bux-shim
bux-guest-<linux-musl-triple>
libkrun*
libkrunfw*
LICENSE-MIT
LICENSE-APACHE
```

Linux binaries stamp `DT_RPATH` `$ORIGIN` (this repo’s `.cargo/config.toml`).
Downstream Linux embedders must set the same rustflag. Darwin uses
`@loader_path`; embedders do not need rpath rustflags.

Operator path, 412, Busy flock, data-dir sizing, rollback:
[docs/serve.md](docs/serve.md).

## Serve

One process owns one data dir. `Runtime::open` takes an exclusive flock;
a second `bux serve start` (or `bux create`) on the same `BUX_HOME` is `Busy`.

```bash
./bux serve start --api-key-file /etc/bux/keys
```

Omitted `--listen` is `127.0.0.1:8080` and
`unix://$XDG_RUNTIME_DIR/bux.sock` (fallback `/tmp/bux-$UID.sock`). At least
one API key is required to start, including loopback and Unix. `--public` is
required to bind a non-loopback TCP address. Terminate TLS in a reverse
proxy; the worker does not.

Flags, keys, listeners, proxy, disk: [docs/serve.md](docs/serve.md).

## Embed

`crates/bux` stays daemonless. HTTP does not live in this crate.

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

The CLI (`bux create` / `exec` / `cp` / …) is a client of the same methods.
Local CLI cannot run **during** serve (same flock). After serve stops, CLI
verbs on that `BUX_HOME` work.

## Capture env

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF |
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF |

`bux system info --format json` is flock-free.

## Docs

| Doc | Contents |
|-----|----------|
| [docs/architecture.md](docs/architecture.md) | Crate map, worker process, isolation layers, native/guest/product tags |
| [docs/security-model.md](docs/security-model.md) | Current engine isolation + hosted threat model |
| [docs/serve.md](docs/serve.md) | Tarball, `/dev/kvm`, rpath, flags, data dir, rollback |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, capture env, FULL procedure, recorded runs |
