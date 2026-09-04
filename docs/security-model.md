# Security model

Source of truth is the code on this tree (workspace **0.8.0**). This document
describes **current** engine isolation and the hosted-worker threat model.
It supersedes local gitignored notes that claimed `create` does not fail-closed
on virtualization and that Landlock `/dev` is a RW tree.

## Threat model

| Actor | Trust | Goal if hostile |
|-------|-------|-----------------|
| Operator | Trusted | Runs the worker, sets API keys, `--allow-unrestricted-net` |
| Tenant (API key holder) | Semi-trusted | Must not escape the VM, must not see other tenants’ sandboxes, must not bind-mount host paths |
| Agent / guest image / exec | Untrusted | Escape, host creds, cross-agent read, egress beyond `allow_net` |
| Registry | Digest-addressed cache | Tamper layers |
| Host operator / embedder (CLI / `Runtime`) | Trusted | Sets `allow_net`, volumes, jail flags |

Isolation **versus the host** is the hardware VM (Linux KVM / macOS HVF) plus
the shim jail. Isolation **between agents** is one VM per agent. Isolation
**between execs in one VM** is not a guarantee (Phase A). Compromise of a
workload is compromise of that guest’s filesystem. The hardware boundary vs
the host still holds.

Out of scope: Windows, GPU, TEE, in-guest namespaces, browser/VNC.

## Host boundary (engine, this tree)

`bux-shim` is the process that applies `ShimConfig` and `krun_start_enter`.
The product library never process-takeovers libkrun on the embedder thread.

- **Hypervisor:** libkrun on KVM (`/dev/kvm`) or Hypervisor.framework
  (`kern.hv_support`). `HostInfo::probe()` records `virtualization`. `create`
  calls `require_virtualization` **before** `resolve_image`
  (`crates/bux/src/runtime/boot/mod.rs`). Missing virt is
  `Error::SecurityUnavailable` (`"no hardware virtualization (KVM / HVF)"`).
  HTTP maps that to **412**.
- **Jailer:** `SecurityOptions.jailer` defaults **on**. Linux: bubblewrap
  (PID/IPC/UTS) plus Landlock, fail-closed unless `allow_degraded`. macOS:
  `sandbox-exec` Seatbelt, deny-default. Inspect persists `SecurityStatus`
  from the last successful spawn (`sandbox`, `landlock`, `mac`).
- **Landlock `/dev`:** `/dev` is read/traverse only. RW leaves that exist:
  `/dev/kvm`, `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`,
  `/dev/shm` (`crates/bux-jail/src/landlock_setup.rs`). `PathBeneath` is
  recursive, so `/dev` itself is never RW. Do not `allow_path_and_parent` RW
  on a `/dev/*` leaf.
- **Seccomp:** `bux-shim-bin` installs the default BPF filter on Linux
  `x86_64`/`aarch64` **after** `GvproxyInstance::new` (TSYNC inherits to Go
  threads). Darwin is a no-op. Unit asserts order
  (`crates/bux-shim-bin/src/main.rs`).
- **Virtio-fs:** every share uses `krun_add_virtiofs3(tag, path, shm_size=0,
  read_only)`. `VolumeMount.read_only` / CLI `:ro` is a device flag, not a
  guest remount. FFI error fails create.

`bux system info` / `HostInfo` is the probe surface. It does not open
`Runtime` (flock-free).

Guest ELF is static musl, no `PT_INTERP`, injected at mode `0555`. Shim
config JSON is unlinked after read.

## Phase A

Guest agent is PID 1. Workload is `exec` through that agent. Concurrent execs
share the guest rootfs and kernel namespaces with the agent.

Inspect / `VmInfo.isolation_note` is always `PHASE_A_LIMITS`
(`crates/bux/src/process.rs`):

> Phase A: workload processes share the guest rootfs and kernel namespaces
> with the agent; concurrent execs are not mutually isolated; compromise of a
> workload is compromise of the agent filesystem. Hardware boundary vs host
> still holds.

Protocol is postcard **v10**. `ControlReq` is Ping/Shutdown/Quiesce/Thaw
only. Concurrent execs sharing the guest is acceptable **because** the guest
has one owner (one agent per VM).

## Egress (labeled)

CLI / engine default create network is `NetworkSpec::Enabled { allow_net: [] }`.

| `network` | Meaning |
|-----------|---------|
| `Enabled { allow_net: [] }` | **Unrestricted** guest egress through gvproxy virtio-net |
| `Enabled { allow_net: [...] }` | Default-deny except listed IP / CIDR / hostname / `*.suffix`. Gateway and guest TAP IPs always allowed |
| `Disabled` | No virtio-net. Guest has no `eth0`. Ports and secrets are invalid |

Empty allow-list is unrestricted **on the engine type**. Inspect JSON
serializes `network` (`NetworkSpec`) and `VmInfo.egress`
(`"unrestricted"` / `"disabled"` / `{ "allow": [...] }`).

HTTP translation (permanent; not a 1.1 enum):

| Request | Engine |
|---------|--------|
| `allow_net` omitted or `[]` | `NetworkSpec::Disabled` |
| `allow_net` non-empty | `NetworkSpec::Enabled { allow_net }` |
| `"unrestricted": true` without `--allow-unrestricted-net` | 400 |
| `"unrestricted": true` with that flag | `Enabled { allow_net: [] }` |

`allow_net` is DNS+SNI/Host/CIDR. It is not “PyPI works.” UDP is not
published. Host port publish is off on the API; engine `ports.rs` stays for
CLI. Bind `0.0.0.0` only; UDP publish is rejected.

The shim never calls TSI `set_port_map`. Offline VMs use
`disable_implicit_vsock` + `add_vsock(0)`.

## Volumes

Bind mounts and named volumes (`{data_dir}/volumes/{name}/`) are virtio-fs
shares. Guest path is validated. Host-root and credential prefixes
(`/etc/shadow`, `~/.ssh`, `~/.aws`, …) are denied unless `allow_sensitive`.

HTTP does not expose bind mounts. Named volume `ws-{tenant}-{agent}` at
`/workspace`. `-` is not in the id alphabet, so `ws-{tenant}-{agent}` is
injective. Occupied name (other tenant / CLI) is 409 `name_occupied`.

## Secrets

`Secret` values are memory-only on `Runtime`. They must not appear in
`bux.db` or guest `/proc/1/environ`. `Debug` redacts the value. After Runtime
process death, restart requires `StartOptions.secrets`.

CLI `--secret` is visible on host `/proc/<pid>/cmdline`. Prefer
`--secret-file` (mode `0600`).

MITM CA `not_after` is **now + 10 years** (`crates/bux-gvproxy/src/ca.rs`).
Guest PID 1 writes PEMs, appends `ca-certificates.crt` when present, and sets
`SSL_CERT_FILE=/etc/ssl/certs/bux-ca-bundle.pem` (`ca_trust.rs`).

HTTP does not expose MITM secret values. Exec `env` is the injection path;
values are visible in guest `/proc/<pid>/environ`.

## Snapshots

`Vm::create_snapshot` / `list_snapshots` / `delete_snapshot` copy the QCOW2
overlay, optionally quiescing via `FIFREEZE`. Disk-only; no memory snapshot,
no live migration.

`Runtime::restore` flatten-like-clone. CLI `bux snapshot restore`. SQLite
`snapshots.vm_id REFERENCES vms(id) ON DELETE CASCADE`. `bux rm` of the
source VM deletes snapshot rows. Restore after delete is `NotFound`. Schema
`user_version` is **5**.

`Runtime::clone` flattens the overlay into a new base and boots detached.

## Hosted worker

A sandbox is a `Vm`. Tenancy is Bearer API keys. Key **id** is `tenant_id`
(alphabet `[A-Za-z0-9._]`, 1..=32). Serve refuses to start with zero keys
(including loopback and Unix). Compare the Bearer token to **every** secret
with constant-time equality.

Unauthenticated: **`GET /v1/health` only**. `/v1/config` and `/v1/metrics`
require Bearer. `/v1/metrics` and `GET /v1/images` are worker-global (same
JSON for every valid key).

HTTP `{id}` is exact 12-char hex (`get_exact`). Unknown **or** other-tenant →
**404** (same body). Never prefix lookup. Leftover `Error::Ambiguous` → 409
`name_occupied`, never 404.

API cannot disable jailer, Landlock, or set `allow_degraded`. API cannot
pass bind mounts, host rootfs, MITM secrets, or port publish.

`GET /v1/health` is the only public route. `--public` without a key is a
hard error. `--public` applies to non-loopback **TCP** only.

## Residual risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Phase A: exec pwns agent FS | High *inside* VM | One owner; hardware boundary vs host and vs other VMs |
| libkrun/KVM 0-day | Critical | Pin 1.19.4; native rebuild workflow; jail+seccomp defense in depth |
| Seatbelt/bwrap escape | High | VM is the real fence |
| Unrestricted net if operator sets `--allow-unrestricted-net` | Medium | Flag off by default; inspect `egress` |
| Shared ext4 base copy-on-write bug | High | QCOW2 overlay; FULL clone/restore tests |
| Image supply chain | Medium | Digest store; `cargo deny`; pull from pinned refs in production |
| Loopback serve accidentally `--public` | Medium | `--public` requires API key; default 127.0.0.1 |
| Prefix IDOR via `Runtime::get` | High | HTTP uses exact id only; other-tenant 404 |
| Tenant OOM via huge `ram_mib` / exec stdout | High | admission flags + exec output cap |
| Hyphen in tenant/agent ids collapsing names | High | alphabet rejects `-`; `a-{t}-{a}` injective |

No telemetry. Guest egress is the only network besides OCI pull. Overlay
at-rest encryption is the operator’s (LUKS). Product does not add it.

## Proof

`scripts/e2e/smoke.sh` with `BUX_E2E_FULL=1` is a **manual** gate. Recorded
HVF runs in [CONTRIBUTING.md](../CONTRIBUTING.md) are **pre-v10** and are
not ship proof. Host CI forces `BUX_E2E_FULL=0`. There is **no** Linux KVM
FULL record. Do not invent uname, git SHA, ELF sha256, or `SMOKE_EXIT=0`.
