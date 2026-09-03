# Serve

Operator page for `bux serve`: one process, one `Runtime`, many per-agent
VMs. Extract the GitHub tarball. Do not expect a fourth artifact.

Workspace is **0.8.0**. Tag `v1.0.0` only when the hosted worker is in that
tarball and FULL proof is recorded. Rollback target is **`v0.8.x`**. Schema
`user_version` stays **5**; rollback does not wipe `BUX_HOME` unless a later
release bumps schema.

## Extract tarball

```bash
tar xf bux-<ver>-x86_64-unknown-linux-gnu.tar.gz
./bux system info --format json
./bux serve start --help
```

Members are at archive root (`cd.yml` packs with `tar czf … -C "$staging" .`).
Run `./bux` from the directory that received the extract.

Targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin`. Layout:

```text
bux
bux-shim
bux-guest-<linux-musl-triple>
libkrun* / libkrunfw*     # .so + soname aliases on Linux; .dylib on Darwin
LICENSE-MIT
LICENSE-APACHE
```

Keep `libkrun*` in the **same directory** as `./bux`. Linux `DT_NEEDED` is
the soname (`libkrun.so.1`, `libkrunfw.so.5`). This repo stamps
`-Wl,-rpath,$ORIGIN` (`.cargo/config.toml` and `bux-shim-bin` `build.rs`).
Downstream Linux embedders must set:

```toml
# embedder .cargo/config.toml (Linux)
[target.'cfg(target_os = "linux")']
rustflags = ["-C", "link-arg=-Wl,-rpath,$ORIGIN"]
```

Darwin records `@loader_path/libkrun.dylib`. Embedders on Darwin do not need
rpath rustflags. libkrun `dlopen`s `libkrunfw.5.dylib` / `libkrunfw.so.5`;
versioned aliases are required.

Capture env: `BUX_HOME`, `BUX_SHIM_PATH`, `BUX_GUEST_PATH`, `BUX_GUEST_DIR`
(see root README). Guest resolution: `BUX_GUEST_PATH`, then a sibling of the
running executable (`bux-guest-<triple>`, `bux-guest-linux`, `bux-guest`),
then `$PATH`. There is no download protocol.

## `/dev/kvm` and 412

Linux production is a machine with a `/dev/kvm` character device (x86_64 or
aarch64; nested virt not required on a KVM instance or bare metal).
`create` / sandbox create calls `require_virtualization` before image
resolve. Missing KVM or HVF is `Error::SecurityUnavailable` → HTTP **412**
`security_unavailable`. That is fail-closed, not a warning.

GitHub-hosted `e2e-host.yml` forces `BUX_E2E_FULL=0`. It is not Linux
production proof.

Darwin needs `kern.hv_support=1`. Codesign `bux-shim` with
`crates/bux-shim/bux-shim.entitlements` when building from source.

## Start

Zero API keys → process exits **2** before bind. No “warn and listen
unauthenticated.” `--public` without a key is a hard error.

```bash
./bux serve start --api-key-file /etc/bux/keys
```

Omitted `--listen` binds both defaults (TCP loopback and Unix; see Listen).

```bash
bux serve openapi   # JSON on stdout, exit 0
```

### Keys

| Flag / env | Form |
|------------|------|
| `--api-key-file PATH` / `BUX_API_KEY_FILE` | `id=secret` lines. Blank and `#` comments skipped. Mode `0600` preferred; warn if group/other readable, do not refuse. |
| `--api-key ID:SECRET` (repeatable) / `BUX_API_KEYS` | `id:secret` pairs, comma-separated in env. |

`--api-key SECRET` with no `:` is a startup error. Duplicate ids: startup
error. `id` alphabet is `[A-Za-z0-9._]`, length 1..=32 (same as `tenant_id`).
`id=foo-bar` is a startup error.

Auth: Bearer on every route except `GET /v1/health`. Compare the token to
**every** secret with constant-time equality; matching row’s `id` is
`tenant_id`. Keys live in process memory, not SQLite. Restart to rotate.

`--api-key id:secret` leaks via `/proc/pid/cmdline`. Prefer `--api-key-file`.

### Listen

`--listen` is repeatable. Each value is `HOST:PORT` or `unix://ABS_PATH`
(a path starting with `/` is Unix). Default if omitted:

```text
--listen 127.0.0.1:8080
--listen unix://$XDG_RUNTIME_DIR/bux.sock   # fallback /tmp/bux-$UID.sock
```

`BUX_LISTEN` is comma-separated, same grammar.

- `--public` is required to bind a non-loopback **TCP** address.
- Unix sockets are always local. `--public` does not apply to them and is a
  startup error if the only listeners are Unix.
- API keys are still required on Unix.
- `--listen unix://...` alone (no TCP) is valid.
- Unlink the socket file on shutdown.

### Flags

| Flag | Default | On exceed / notes |
|------|---------|-------------------|
| `--allow-unrestricted-net` | off | Required for request `"unrestricted": true` |
| `--max-sandboxes` | 32 per tenant | 429 |
| `--max-sandboxes-global` | same as `--max-sandboxes` | 429 |
| `--max-ram-mib` | 2048 per sandbox | 400 |
| `--max-vcpus` | 4 | 400 |
| `--max-running-ram-mib` | 8192 (sum Running+Stopping + request) | 429 |
| `--max-disk-bytes` | 32 GiB (`Runtime::data_dir_usage`, recursive) | 429 |
| `--max-pull-bytes` | 4 GiB (manifest compressed bytes before blobs) | 413 |
| `--max-exec-output-bytes` | 1048576 per stream | truncate + `truncated: true`; SIGKILL guest child |
| `--default-ram-mib` | 512 | default if omitted |
| `--default-vcpus` | 1 | default if omitted |
| `--ready-timeout-secs` | 30 | create failure 503/504 with shim stderr tail |
| `--pull-timeout-secs` | 300 | |

`disk_bytes_used` on metrics is overlays+bases only and is **not** the
admission cap. Alert on `data_dir_bytes` vs `--max-disk-bytes`.

Logs: `RUST_LOG` / `--log-level`. No secret values in logs.

## Busy flock

`Runtime::open` takes an exclusive non-blocking flock on `{BUX_HOME}/bux.lock`.
A second `bux serve start` on the same data dir exits `Busy`. Local CLI that
opens a Runtime (`create`, `exec`, `ps`, …) cannot run **during** serve.
`bux system info` is flock-free.

One worker owns one data dir. That is the process model, not a bug.

## Proxy

The worker does not terminate TLS. Put it behind a reverse proxy if the org
needs TLS or SSO. No JWT/OIDC in the worker. Copying Auth0 into this repo is
a non-goal.

Typical: proxy `127.0.0.1:8080` or the Unix socket. Forward
`Authorization: Bearer`. Do not put the secret in query strings (they leak
via access logs).

## Data-dir layout

Default dir: `$BUX_HOME`, else Linux `$XDG_DATA_HOME/bux` /
`~/.local/share/bux`, macOS `~/Library/Application Support/bux`.

```text
{data_dir}/
  bux.lock
  bux.db                 # schema user_version 5
  images.db              # OCI index; not merged with bux.db
  layers/ configs/ rootfs/
  disks/bases/{digest}.raw      # shared ext4 bases (size the disk for these)
  disks/vms/{id}.qcow2          # per-VM overlay (~256 KiB empty)
  volumes/ws-{tenant}-{agent}/  # HTTP workspace → guest /workspace
  snapshots/{sid}.qcow2
  socks/{id}
  socks/{id}.stderr             # shim/guest stderr; GET /v1/sandboxes/{id}/logs
  socks/{id}.exit
```

**Disk for shared bases:** each distinct image digest keeps a full ext4
`.raw` under `disks/bases/`. Overlays are cheap; bases are not. `DELETE
/v1/images?reference=` removes the OCI index entry and may drop unused
layers. It does **not** delete `disks/bases/{digest}.raw`. Leftover bases
after rmi are expected. Size `--max-disk-bytes` and the volume for layers +
bases + overlays + workspace writes.

HTTP DELETE of a sandbox: stop, `Runtime::remove` (drops overlay), then
`VolumeManager::remove` of `ws-{tenant}-{agent}` (host directory gone).

## `{id}.stderr`

Shim and guest stderr land at `{data_dir}/socks/{id}.stderr`. CLI: `bux logs`.
HTTP: `GET /v1/sandboxes/{id}/logs`. Create failure should return 503/504
with a tail of this file, not hang past `--ready-timeout-secs`.

## Restart and rollback

Serve process restart: live **detached** VMs reattach; the worker must not
SIGTERM them on Drop. `secrets_required` VMs are 409 on start/exec until
secrets are re-supplied (CLI path). HTTP does not expose MITM secrets.

Rollback: previous **`v0.8.x`** tarball. Schema v5 is unchanged; replacing
the binary and restarting serve does not wipe. A later schema bump refuses
`Runtime::open` until `bux system reset` (or deleting `BUX_HOME`).

Native pins (`krun-v1.19.4` / `e2fs-v1.47.4` / `bwrap-v0.12.0`) are
independent of product tags. Serve does not retag them.

## HTTP (1.0)

Error envelope:

```json
{ "error": { "code": "<snake>", "message": "...", "existing_id": "...", "field": "..." } }
```

`existing_id` / `field` only when applicable (`name_occupied`,
`sandbox_exists`).

| `bux::Error` / serve | HTTP |
|----------------------|------|
| `InvalidConfig` | 400 `invalid_config` |
| `NotFound` / other-tenant / bad `{id}` | 404 `not_found` |
| `Ambiguous` | 409 `name_occupied` |
| `InvalidState` | 409 `invalid_state` |
| `Busy` | 409 `busy` |
| `GuestUnavailable` | 503 `guest_unavailable` |
| `SecretsRequired` | 409 `secrets_required` |
| `SecurityUnavailable` | **412** `security_unavailable` |
| admission count/RAM/disk | 429 `resource_exhausted` |
| body too large / pull over `--max-pull-bytes` | 413 `payload_too_large` |
| missing/invalid Bearer | 401 `unauthorized` |

```text
GET    /v1/health                            # no auth
GET    /v1/config                            # Bearer
GET    /v1/me                                # { tenant_id, max_sandboxes }
GET    /v1/metrics                           # Bearer; RuntimeMetrics + data_dir_bytes

POST   /v1/images/pull                       # { "reference" }
GET    /v1/images                            # worker-global
DELETE /v1/images?reference=

POST   /v1/sandboxes                         # get-or-create by (tenant_id, agent_id)
GET    /v1/sandboxes                         # this tenant only
GET    /v1/sandboxes/{id}                    # exact 12-char hex
POST   /v1/sandboxes/{id}/start
POST   /v1/sandboxes/{id}/stop
DELETE /v1/sandboxes/{id}                    # stop+remove+volume rm; 204
GET    /v1/sandboxes/{id}/logs

POST   /v1/sandboxes/{id}/exec               # collect-only
PUT    /v1/sandboxes/{id}/files?path=        # raw bytes, 32 MiB; mode decimal u32
GET    /v1/sandboxes/{id}/files?path=

POST   /v1/sandboxes/{id}/clone
POST   /v1/sandboxes/{id}/snapshots
GET    /v1/sandboxes/{id}/snapshots
DELETE /v1/sandboxes/{id}/snapshots/{sid}
POST   /v1/sandboxes/{id}/snapshots/{sid}/restore
```

Not in 1.0: exec_id routes, WebSocket attach, tar upload, port publish, bind
mounts, memory snapshot.

`POST /v1/sandboxes` get-or-create. `agent_id` alphabet `[A-Za-z0-9._]`,
1..=64 (`-` → 400). Same spec → same exact id. Spec mismatch → 409
`sandbox_exists`. Name occupied by another tenant or a CLI VM → 409
`name_occupied`. Network omit/`[]` → deny. `auto_stop_secs` default **1800**
on API create. Sweep every 30 s. Idle clock resets on create, start, exec,
file PUT/GET.

Exec: collect-only. `timeout_ms` default 30000, min 1, max 300000, **never
0**. Guest `ExecStart::timeout` kills the guest process. Do not rely on host
`tokio::time::timeout` alone (leaks the guest child).

Files: `path` query required, absolute guest path, no `..`. PUT default mode
`0o644`; query `mode` is decimal `u32` (`mode=420` for 0644). JSON body
limit 1 MiB; files route 32 MiB.

Registry auth is process-wide (`BUX_REGISTRY_USER` / `BUX_REGISTRY_PASSWORD`
or anonymous), not per-tenant.

## Isolation reminder

Jailer on, Landlock fail-closed, no `allow_degraded` on the API. One VM per
`(tenant_id, agent_id)`. Details: [security-model.md](security-model.md).
