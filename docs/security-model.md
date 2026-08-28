# Security model

Source of truth is the code on this tree (workspace **0.7.0**). This document
describes **current** isolation. The production-ready 1.0 checklist is
[`docs/1.0-release-bar.md`](1.0-release-bar.md) (crate version for that
increment: 0.8.0). Do not read unchecked boxes there as behavior that already
ships.

Architecture spine: [`docs/bux-redesign.md`](bux-redesign.md).

## Threat model

| Party | Trust | Goal if hostile |
|-------|-------|-----------------|
| Host operator / embedder | Trusted | Sets `allow_net`, volumes, jail flags |
| Guest image + workload + concurrent execs | Untrusted | Escape the VM, read host secrets, reach network beyond `allow_net`, persist secret values |

Isolation **versus the host** is the hardware VM (Linux KVM / macOS HVF) plus
the shim jail. Isolation **between execs in one VM** is not a guarantee (Phase
A). Compromise of a workload is compromise of the guest agent filesystem. The
hardware boundary vs the host still holds.

Out of scope here: REST/SDK multi-tenant clouds, Phase B in-guest namespaces,
Windows, GPU, TEE.

## Host boundary

`bux-shim` is the process that applies `ShimConfig` and `krun_start_enter`.
The product library never process-takeovers libkrun on the embedder thread.

- **Hypervisor:** libkrun on KVM (`/dev/kvm`) or Hypervisor.framework
  (`kern.hv_support`). `HostInfo::probe()` records `virtualization`. Create
  does **not** fail closed when that flag is false; `audit_isolation` appends
  an `isolation_warnings` string. Fail-closed `Error::SecurityUnavailable` is
  a 1.0-bar item, not current.
- **Jailer:** `SecurityOptions.jailer` defaults **on**. Linux: bubblewrap
  (PID/IPC/UTS) plus Landlock, fail-closed unless `allow_degraded`. macOS:
  `sandbox-exec` Seatbelt, deny-default. Inspect persists `SecurityStatus`
  from the last successful spawn (`sandbox`, `landlock`, `mac`).
- **Landlock `/dev`:** this tree allowlists `/dev` read-write as a tree. Leaf
  RW on `/dev/kvm` and a few character devices only is a 1.0-bar item.
- **Seccomp:** `bux-shim` installs the default BPF filter on Linux
  `x86_64`/`aarch64` **only when gvproxy is not in-process** (`gvp.is_none()`).
  Networked VMs skip seccomp. Darwin is a no-op. Installing after in-process
  gvproxy is a 1.0-bar item, gated on KVM FULL, not HVF.

`bux system info` / `HostInfo` is the probe surface. It does not open
`Runtime` (flock-free).

## Phase A

Guest agent is PID 1. Workload is `exec` through that agent. Concurrent execs
share the guest rootfs and kernel namespaces with the agent.

Inspect / `VmInfo.isolation_note` is always:

> Phase A: workload processes share the guest rootfs and kernel namespaces
> with the agent; concurrent execs are not mutually isolated; compromise of a
> workload is compromise of the agent filesystem. Hardware boundary vs host
> still holds.

(`PHASE_A_LIMITS` in `crates/bux/src/process.rs`.) Protocol is postcard **v9**
(Phase A only). `ControlReq::{Metrics,HealthCheck,PrepareSnapshot}` still
exist on the wire; the host never sends them; the guest tears down the
control connection if they arrive. Protocol v10 (delete those variants) is a
1.0-bar item.

## Egress (labeled)

Default create network is `NetworkSpec::Enabled { allow_net: [] }`.

| `network` | Meaning |
|-----------|---------|
| `Enabled { allow_net: [] }` | **Unrestricted** guest egress through gvproxy virtio-net |
| `Enabled { allow_net: [...] }` | Default-deny except listed IP / CIDR / hostname / `*.suffix`. Gateway and guest TAP IPs always allowed |
| `Disabled` | No virtio-net. Guest has no `eth0`. Ports and secrets are invalid |

Empty allow-list is unrestricted on purpose. Inspect JSON serializes
`network` (`NetworkSpec`). A separate `VmInfo.egress` class field
(`"unrestricted"` / `"disabled"` / `{ "allow": [...] }`) is a 1.0-bar item,
not current. Production profile is a non-empty allow-list or `Disabled`.

The shim never calls TSI `set_port_map`. Offline VMs use
`disable_implicit_vsock` + `add_vsock(0)` so TSI cannot leak. Published ports
are TCP only, bind `0.0.0.0`; UDP is rejected.

## Volumes

Bind mounts and named volumes (`{data_dir}/volumes/{name}/`) are virtio-fs
shares. Guest path is validated. Host-root and credential prefixes
(`/etc/shadow`, `~/.ssh`, `~/.aws`, …) are denied unless `allow_sensitive`.

`VolumeMount.read_only` / CLI `:ro` is **metadata**. The engine calls
`krun_add_virtiofs` (no read-only flag). Guest `mount(2)` does not set
`MS_RDONLY`. A guest write to a `:ro` share can succeed. Enforcing RO via
`krun_add_virtiofs3(..., read_only)` is a 1.0-bar item, not current.

## Secrets

`Secret` values are memory-only on `Runtime`. They must not appear in
`bux.db` or guest `/proc/1/environ`. `Debug` redacts the value. After Runtime
process death, restart requires `StartOptions.secrets`.

CLI `--secret` is visible on host `/proc/<pid>/cmdline`. Prefer
`--secret-file` (mode `0600`).

MITM CA `not_after` is **now + 24h** (`crates/bux/src/secrets.rs`,
`crates/bux-gvproxy/src/ca.rs`). Guest PID 1 writes sibling PEMs
(`ca_trust.rs`); it does not append `ca-certificates.crt` or set
`SSL_CERT_FILE`. Alpine HTTPS through MITM is not a current guarantee.
10-year CA + alpine trust + handshake FULL are 1.0-bar items.

Shim config JSON is unlinked after read (`bux-shim-bin`).

## Snapshots

`Vm::create_snapshot` / `list_snapshots` / `delete_snapshot` (CLI
`bux snapshot create|list|rm`) copy the QCOW2 overlay, optionally quiescing
via `FIFREEZE`. Disk-only; no memory snapshot, no live migration.

SQLite `snapshots.vm_id REFERENCES vms(id) ON DELETE CASCADE`. `bux rm` of
the source VM deletes snapshot **rows**. Schema `user_version` is **5**;
mismatch refuses to open (wipe `BUX_HOME` / `bux system reset`). There is no
`Runtime::restore` and no `bux snapshot restore` on this tree. Restore
(flatten like `clone`) is a 1.0-bar item.

`Runtime::clone` flattens the overlay into a new base and boots detached. It
is not snapshot restore.

## Proof

`scripts/e2e/smoke.sh` with `BUX_E2E_FULL=1` is a **manual** gate. The
recorded green run is local HVF (Apple Silicon) in
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Host CI forces `BUX_E2E_FULL=0`.
There is **no** Linux KVM FULL record. Do not invent one.

## 1.0 bar (not this tree)

Unchecked boxes in [`docs/1.0-release-bar.md`](1.0-release-bar.md) include
create fail-closed without virtualization, virtio-fs `:ro`, seccomp+gvproxy,
Landlock `/dev` leaf RW, 10-year MITM CA + alpine `SSL_CERT_FILE`, snapshot
restore, `VmInfo.egress`, protocol v10, and a KVM FULL row. This document
does not treat those as shipped.
