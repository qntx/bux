# Architecture

Source of truth is this document, then the code under `crates/`. Workspace
version is **0.8.0**. Protocol is postcard **v10**. SQLite `user_version` is
**5** (no migrations; wipe `BUX_HOME` on mismatch).

The product is a **hosted per-agent sandbox** (`bux serve`). The engine is
libkrun. Library-only 1.0 is revoked. Local notes that defined REST as a
non-goal are not this repo.

## Spine

```text
validate → require_virtualization → oci.ensure → ext4 base + inject guest 0555
  → volumes → spawn_config (QCOW2 overlay, ShimConfig JSON 0600, jail.spawn)
  → wait_ready (postcard Hello::Control Ping on vsock :1024)
```

Code: `crates/bux/src/runtime/boot/mod.rs` `create`.

```text
OCI image → ext4 base + QCOW2 overlay → jailed bux-shim
  → libkrun (KVM / HVF) → static bux-guest PID 1
  → postcard v10 over vsock
```

The shim never calls TSI `krun_set_port_map`. Offline VMs use
`disable_implicit_vsock` + `add_vsock(0)`. Every virtio-fs share is
`krun_add_virtiofs3(..., shm_size=0, read_only)`.

## Crate map

Engine (this workspace):

| Crate | Role |
|-------|------|
| `bux` | `Runtime` / `Vm` / `VmOptions`. Exclusive `bux.lock`. Schema v5. Daemonless. |
| `bux-cli` | Operator CLI (`run`/`create`/`exec`/`serve`). Binary name `bux`. Serve is in this 0.8.0 workspace; the product tag is not 1.0. |
| `bux-shim` | `ShimConfig` apply to libkrun. Never starts gvproxy. |
| `bux-shim-bin` | Process that `krun_start_enter`. gvproxy in-process when networked. Seccomp **after** `GvproxyInstance::new`. |
| `bux-guest` | Static musl ELF, PID 1, protocol stamp `bux-guest-protocol-v10`. |
| `bux-proto` | Postcard v10. Per-op connection. `ControlReq` is Ping/Shutdown/Quiesce/Thaw only. |
| `bux-oci` | `oci-client` pull; `images.db` + content-addressed `layers/` `configs/` `rootfs/`. |
| `bux-e2fs` | Ext4 base images. |
| `bux-qcow2` | Overlay / flatten. |
| `bux-krun` | libkrun **1.19.4** / libkrunfw **5.5.0** FFI. |
| `bux-gvproxy` | gvisor-tap-vsock **0.8.9**. Virtio-net + MITM. |
| `bux-jail` / `bux-bwrap` / `bux-landlock` / `bux-seccomp` | Linux: bwrap PID/IPC/UTS + Landlock fail-closed + seccomp TSYNC. Darwin: seatbelt. `bux-bwrap` crate **0.2.0** downloads bubblewrap **0.12.0**. |

HTTP lives in `bux-serve` (this 0.8.0 workspace; the product tag is not
1.0), **not** in `crates/bux`. Embedders keep `Runtime::open` without an
HTTP stack. Serve is a client of the public `Runtime` / `Vm` API the same
way the CLI is.

Not in this product: dashboard, NestJS control plane, Go FFI runner,
OpenTelemetry collector, language SDKs, GPU/VNC, Windows, in-guest OCI
runtime.

## Worker process

Single-node **is** the first production topology: one KVM box, one
`bux serve`, N agents, N VMs.

```text
bux serve start
  Runtime::open(BUX_HOME)     # Busy if another process holds the flock
  bind each --listen (TCP and/or unix://)
  sweep loop
  SIGTERM → drain → unlink unix socket → drop Runtime
            detached VMs keep running (shim child, detach=true)
```

`Runtime::open` takes `FlockArg::LockExclusiveNonblock`. Two processes cannot
share `BUX_HOME`. Hosted means **one worker process owns one data dir**.
CLI verbs that open a Runtime cannot run during serve.

API-created VMs are `detach: true` (same as `bux create`). Serve Drop must
not SIGTERM sandboxes. Restart reattaches live detached VMs (`Runtime::open`
recovery).

A sandbox **is** a `Vm`. No parallel sandbox type. Identity is
`(tenant_id, agent_id)` → injective VM name `a-{tenant}-{agent}`. `-` is the
separator only; it is not in the id alphabet `[A-Za-z0-9._]`. Workspace volume
is `ws-{tenant}-{agent}`, not the VM name.

HTTP `{id}` is the exact 12-char hex primary key. Prefix lookup (`Runtime::get`)
is CLI-only.

## Isolation layers

```text
                    untrusted (one agent)
┌─────────────────────────────────────────────┐
│ guest kernel (libkrunfw)                    │
│  bux-guest PID 1 + that agent's execs       │  Phase A, single owner
│  /workspace ← ws-{tenant}-{agent}           │
└──────────────────┬──────────────────────────┘
                   │ virtio blk, fs, vsock, net
┌──────────────────▼──────────────────────────┐
│ bux-shim + optional gvproxy                 │
│  seccomp (Linux) · Landlock · bwrap/seatbelt│
└──────────────────┬──────────────────────────┘
                   │ Unix sockets, overlay, volumes
┌──────────────────▼──────────────────────────┐
│ bux serve (trusted)                         │
│  SQLite, OCI cache, API keys                │
└─────────────────────────────────────────────┘
```

| Layer | Mechanism |
|-------|-----------|
| Versus host | Guest kernel + KVM / HVF. `require_virtualization` before image resolve. |
| Versus other agents | Separate VM, overlay `disks/vms/{id}.qcow2`, volume `ws-{tenant}-{agent}`, gvproxy sockets. |
| Versus shim escape | Linux: bwrap + Landlock fail-closed + seccomp. Darwin: seatbelt. VM is the real fence. |
| Versus unrestricted egress | HTTP omit/`[]` → `NetworkSpec::Disabled`. CLI empty allow-list stays unrestricted. |
| Versus host binds | HTTP: named volume only. CLI may bind; sensitive prefixes denied unless `allow_sensitive`. |

Do not put two agents in one guest.

## Network

Guest topology (`crates/bux-proto/src/net.rs`):

| | Value |
|--|--------|
| Subnet | `192.168.127.0/24` |
| Gateway / DNS | `192.168.127.1` |
| Guest | `192.168.127.2` (per-VM isolated gvproxy) |
| MAC | `5a:94:ef:e4:0c:ee` |
| Agent vsock | port **1024** |

`allow_net` is gvproxy DNS + SNI/Host/CIDR, not a package-manager profile.
Hostnames and `*.suffix` get DNS zones; everything else sinkholes to
`0.0.0.0`. IPs/CIDRs skip DNS and hit TCP allow. TLS is matched on SNI/Host.
UDP is not published. A working pip install needs every hostname the client
will resolve (e.g. `pypi.org` **and** `files.pythonhosted.org`).

## Filesystem

| Store | Path | Lifetime |
|-------|------|----------|
| OCI blobs | `{data_dir}/layers`, `configs`, `rootfs`, `images.db` | until image delete (layers refcounted; bases not) |
| Ext4 base | `{data_dir}/disks/bases/{digest}.raw` | shared read-only backing; leftover after rmi is expected |
| Overlay | `{data_dir}/disks/vms/{id}.qcow2` | per VM; deleted in `Runtime::remove` |
| Workspace | `{data_dir}/volumes/{name}/` | named volume; HTTP DELETE of a sandbox removes `ws-{tenant}-{agent}` |
| Snapshots | `{data_dir}/snapshots/{sid}.qcow2` | disk overlay copy; `ON DELETE CASCADE` on source VM |
| Socks | `{data_dir}/socks/{id}` + `.stderr` + `.exit` | per VM |

Empty overlay is ~256 KiB.

## Guest protocol

Per-op connection. Concurrent execs do not share a mux. `Hello`: Control,
Exec, FileRead, FileWrite, CopyIn, CopyOut. A protocol bump is a guest ELF
rebuild + `guest-<40-char-sha>` Release + Darwin fetch.

## Native / guest / product tags

Independent tag families. Serve does not retag libkrun.

| Tag | Asset |
|-----|--------|
| `krun-v1.19.4` | `bux-deps-{target}.tar.gz` (libkrun 1.19.4 + libkrunfw 5.5.0) |
| `e2fs-v1.47.4` | `bux-e2fs-{target}.tar.gz` |
| `bwrap-v0.12.0` | `bux-bwrap-{target}.tar.gz` (Linux) |
| `guest-<40-char-sha>` | static musl `bux-guest-<triple>` for **that** commit |
| `v*.*.*` | product tarball: `bux`, `bux-shim`, guest ELF, `libkrun*` |

URLs:

```text
https://github.com/qntx/bux/releases/download/krun-v1.19.4/bux-deps-{target}.tar.gz
https://github.com/qntx/bux/releases/download/e2fs-v1.47.4/bux-e2fs-{target}.tar.gz
https://github.com/qntx/bux/releases/download/bwrap-v0.12.0/bux-bwrap-{target}.tar.gz
```

A native pin bump retags **that** native tag on the PR SHA, waits for all
matrix assets, then merges. Never merge-then-tag. `PROTOCOL_VERSION` bump
tags `guest-<sha>` on that commit before Darwin FULL, then a product `v*`.

CD (`cd.yml`) ships three host tarballs: `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`. No Windows. Guest
builds are `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

## Control plane

1.0 live is one Linux machine with `/dev/kvm`, extract the tarball,
`./bux serve start`. Multi-worker coordinator is after that loop is boring.
Workers remain `bux serve`. Image bases are per-worker.

## See also

- [security-model.md](security-model.md)
- [serve.md](serve.md)
- [native-deps.md](native-deps.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
