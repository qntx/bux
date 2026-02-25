# bux-oci

Async OCI image management for [bux](https://github.com/qntx/bux) micro-VMs, powered by [`oci-client`](https://github.com/oras-project/rust-oci-client) (CNCF ORAS project).

Pulls OCI images from any compliant registry, extracts layers into a directory-based rootfs, and provides the filesystem path to `libkrun`'s `krun_set_root()` — no external tools required.

## Features

- **Async pull** from any OCI Distribution Spec–compliant registry (Docker Hub, GHCR, ECR, etc.)
- **Local caching** with content-addressable storage; `ensure()` skips the network when the image is already present
- **Layer extraction** via `flate2` + `tar` — no runtime dependency on `skopeo`, `umoci`, or container runtimes
- **Progress reporting** through a caller-supplied callback
- **Multi-arch resolution** delegated to `oci-client` (selects the manifest matching the host platform)

## Installation

Add to your `Cargo.toml`:

```bash
cargo add bux-oci
```

## Usage

```rust
let mut oci = bux_oci::Oci::open()?;

// Pull (always fetches from registry)
let result = oci.pull("ubuntu:24.04", |msg| eprintln!("{msg}")).await?;

// Ensure (cache hit → instant, cache miss → pull)
let result = oci.ensure("ubuntu:24.04", |msg| eprintln!("{msg}")).await?;
println!("rootfs: {}", result.rootfs.display());

// List cached images
for img in oci.images()? {
    println!("{}", img.reference);
}

// Remove a cached image
oci.remove("ubuntu:24.04")?;
```

## API Overview

| Method | Description |
| --- | --- |
| `Oci::open()` | Open the local image store (creates it if absent) |
| `oci.pull(reference, callback)` | Pull an image from the registry unconditionally |
| `oci.ensure(reference, callback)` | Return cached rootfs if present, otherwise pull |
| `oci.images()` | List all locally cached images |
| `oci.remove(reference)` | Delete a cached image and its extracted rootfs |

**Registry protocol** (authentication, manifest negotiation, digest verification, multi-arch resolution) is entirely delegated to `oci-client`. bux-oci is responsible only for layer extraction, rootfs assembly, and metadata persistence.

## Storage Layout

```text
$BUX_HOME/                          # or <platform_data_dir>/bux
├── images.json                     # Metadata index (reference, digest, size)
└── rootfs/
    ├── <storage_key>/              # Extracted filesystem tree
    │   ├── bin/
    │   ├── etc/
    │   └── ...
    └── <storage_key>.json          # Cached image config (Cmd, Env, ...)
```

Layers are applied in order (bottom → top) via sequential tar extraction into a single directory, producing a merged rootfs equivalent to an overlay filesystem.

## Design: Directory rootfs vs. QCOW2 Disk Image

This is the core architectural decision that differentiates bux from projects like [BoxLite](https://github.com/boxlite-ai/boxlite):

| Feature | Directory rootfs | QCOW2 block device |
| --- | --- | --- |
| libkrun API | `krun_set_root()` + virtio-fs | `krun_add_disk()` + virtio-blk |
| Image → rootfs | tar extract to directory | tar extract → `mkfs.ext4` → QCOW2 |
| External deps | None | `e2fsprogs` (mkfs.ext4) |
| Snapshot / Clone | Not supported | QCOW2 CoW backing chain |
| Stateful sandbox | No (ephemeral by design) | Yes (state persists in QCOW2) |
| Host inspection | Direct filesystem access | Must mount QCOW2 |
| Target use case | Stateless execution: CI, tool calls, one-shot tasks | Stateful agents: persistent sessions, snapshot/restore |

**bux chooses directory rootfs** because:

1. **`krun_set_root()` is the simplest libkrun path** — host directory → guest rootfs via virtio-fs. No kernel, initrd, or bootloader. No disk image creation toolchain.
2. **Stateless execution is the primary use case** — `bux run ubuntu -- cmd` is analogous to `docker run --rm`. The VM runs, produces output, and exits. No state to persist.
3. **Zero external dependencies** — QCOW2 conversion requires `mkfs.ext4` + `qemu-img` (or equivalent Rust implementations that don't exist at production quality). Directory extraction requires only `flate2` + `tar`.
4. **Non-exclusive** — QCOW2 support via `krun_add_disk()` can be added as a separate code path without changing the OCI pull pipeline. The layer extraction is the same; only the final storage format differs.

## Limitations

- **Pull-only** — no OCI image build or push. Image creation is out of scope.
- **No layer deduplication** — each image stores a fully merged rootfs. Shared base layers are not deduplicated across images.

## License

Same as the parent `bux` project. See [LICENSE](../LICENSE).
