# bux-cli

CLI client of the `bux` `Runtime` / `Vm` / `VmOptions` API. Binary name: `bux`.

Build: `cargo build -p bux-cli -p bux-shim-bin`. Capture env, tarball layout,
and FULL procedure: [`CONTRIBUTING.md`](../../CONTRIBUTING.md). Architecture:
[`docs/bux-redesign.md`](../../docs/bux-redesign.md). Production-ready 1.0 bar:
[`docs/1.0-release-bar.md`](../../docs/1.0-release-bar.md).

## Commands

| Command | Role |
|---------|------|
| `run` | Create and run a command in a new micro-VM |
| `create` | Create and start a managed VM without an initial command (print ID) |
| `exec` | Execute a command in a running VM |
| `logs` | Show shim stderr for a VM |
| `ps` / `ls` | List VMs |
| `stop` / `kill` / `rm` | Stop, force-kill, or remove VMs |
| `inspect` | Detailed VM information |
| `cp` | Copy files between host and a running VM (`<vm>:<path>`) |
| `wait` | Block until VMs stop |
| `prune` | Remove all stopped VMs |
| `rename` / `restart` | Rename; restart a stopped or running VM |
| `stats` | VM identity, status, and health |
| `snapshot create` / `list` / `rm` | Disk overlay snapshots |
| `clone` | Disk-clone (overlay flatten); always boots detached |
| `export` | Export a VM disk as standalone QCOW2 |
| `pull` / `images` / `rmi` | OCI images |
| `volume create` / `list` / `rm` | Named volumes under `{data_dir}/volumes/` |
| `disk create` / `list` / `rm` | Ext4 base images |
| `sweep` | Apply idle auto-stop / auto-delete policies |
| `system info` | Host capabilities, data dir, capture env (flock-free) |
| `system reset` | Delete the runtime data directory (requires flock) |
| `info` | Alias of `system info` |

List/info commands take `--format table|json` where present.

`create` is always detach (CLI exits; VM survives). Equivalent to
`bux run -d IMAGE` with no command override.

## Capture env

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` |
| `BUX_GUEST_PATH` | Absolute path to a static Linux `bux-guest` ELF |
| `BUX_GUEST_DIR` | Build-time directory of a prebuilt Linux guest ELF |
| `PATH` | Locates `bux-shim`, `bwrap`, `sandbox-exec`, `go` |
