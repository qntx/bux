<!-- markdownlint-disable MD033 MD041 MD036 -->

# Bux

Embedded micro-VM sandbox for running AI agents, powered by [libkrun](https://github.com/containers/libkrun) with KVM (Linux) or Hypervisor.framework (macOS).

The product is a Rust library: `Runtime` + `Vm` + `VmOptions`. The CLI is a client of that API. Linking `bux` loads libkrun in the embedder process for host probes; `krun_start_enter` runs in jailed `bux-shim`.

## Library

```rust
use bux::{ExecStart, RegistryAuth, Runtime, RuntimeOptions, VmOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> bux::Result<()> {
    let rt = Runtime::open_with(RuntimeOptions {
        data_dir: std::env::temp_dir().join("bux-embed-example"),
        shim_path: std::env::var_os("BUX_SHIM_PATH").map(Into::into),
        guest_path: std::env::var_os("BUX_GUEST_PATH").map(Into::into),
        registry_auth: RegistryAuth::Anonymous,
    })?;
    let mut vm = rt
        .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
        .await?;
    let out = vm
        .exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
        .await?;
    assert_eq!(out.code, 0, "python -c print");
    vm.stop().await?;
    Ok(())
}
```

Compiling example: [`crates/bux/examples/embed.rs`](crates/bux/examples/embed.rs). `Runtime::open(dir)` is the same constructor with anonymous registry auth and no explicit sidecar paths. Use `#[tokio::main(flavor = "current_thread")]`; crate `bux` does not enable Tokio `rt-multi-thread`.

## Sidecars

`create` needs `bux-shim`, a static Linux `bux-guest` ELF, and sibling `libkrun*` / `libkrunfw*` (including soname aliases). `bux-shim-bin` is `publish = false`; take those files from a workspace `cargo build` or the CD tarball.

Tarball layout is the directory tree in [CONTRIBUTING.md](CONTRIBUTING.md) (`bux`, `bux-shim`, `bux-guest-<triple>`, `libkrun*` / `libkrunfw*` and their soname aliases).

Resolution (`RuntimeOptions.shim_path` / `guest_path`):

- `Some(path)` must be a regular file at first use or `Error::NotFound` (no search fallthrough).
- `None` searches `BUX_SHIM_PATH` / `BUX_GUEST_PATH` (falls through if set but not a file), then a sibling of the running executable, then `$PATH`.

Linux embedder binaries must stamp `$ORIGIN` so libkrun resolves next to the executable. This workspace sets that in `.cargo/config.toml`; `cargo add bux` does not inherit those rustflags. Embedder `.cargo/config.toml`:

```toml
[target.'cfg(target_os = "linux")']
rustflags = ["-C", "link-arg=-Wl,-rpath,$ORIGIN"]
```

Further rpath / dylib notes: [CONTRIBUTING.md](CONTRIBUTING.md).

## Environment

| Variable | Role |
|----------|------|
| `BUX_HOME` | Data directory used by `default_data_dir()` (CLI) |
| `BUX_SHIM_PATH` | `bux-shim` when `RuntimeOptions.shim_path` is `None` |
| `BUX_GUEST_PATH` | Static Linux `bux-guest` ELF when `RuntimeOptions.guest_path` is `None` |
| `PATH` | Last search location for shim and guest |

## Detach and flock

`VmOptions.detach` defaults to `false`. Non-detached VMs are `SIGTERM`'d when `Runtime` is dropped. CLI `bux create` always sets `detach: true`.

One `Runtime` per `data_dir`. A second `Runtime::open` / `open_with` on a locked directory returns `Error::Busy`.

## Network and secrets

`NetworkSpec` defaults to `Enabled { allow_net: [] }` (unrestricted gvproxy egress). Restrict with `VmOptions::allow_net(...)`. `NetworkSpec::Disabled` is offline: no virtio-net, no guest `eth0`.

`Secret` is opt-in gvproxy MITM. Values are memory-only (never SQLite). After Runtime process death they must be re-supplied via `StartOptions`. Agent keys belong in `VmOptions.env` / `ExecStart.env`, not MITM.

Private registry pull uses `RuntimeOptions.registry_auth` (`RegistryAuth::Basic` / `Bearer`). Default is `Anonymous`.

## Phase A

Guest `bux-guest` is PID 1. Workloads are `exec`. Workload processes share the guest rootfs and kernel namespaces with the agent; concurrent execs are not mutually isolated; compromise of a workload is compromise of the agent filesystem. The hardware boundary versus the host still holds.

## FULL

`BUX_E2E_FULL=1` is an operator HVF record on local Apple Silicon, written into [CONTRIBUTING.md](CONTRIBUTING.md) when green. Host CI is `BUX_E2E_FULL=0` and is not production proof. Do not treat this tree as FULL-green.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
