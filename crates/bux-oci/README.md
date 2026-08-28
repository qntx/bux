# bux-oci

Async OCI image management for [bux](https://github.com/qntx/bux) micro-VMs, powered by [`oci-client`](https://github.com/oras-project/rust-oci-client) (CNCF ORAS project).

Pulls OCI images from any compliant registry, caches them, and extracts layers into a directory. The managed Runtime converts that directory into an ext4 base plus QCOW2 overlay (`DiskManager::create_managed_base`).

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

SQLite index plus content-addressed blobs (`src/store.rs`). Default root is
`$BUX_HOME` or `<platform_data_dir>/bux`.

```text
{root}/
├── images.db                 # SQLite: image index + layer refs
├── layers/                   # sha256-addressed layer tarballs
├── configs/                  # sha256-addressed image config blobs
└── rootfs/{digest}/          # extracted rootfs (keyed by manifest digest)
```

Layers are applied in order (bottom → top) via sequential tar extraction into a single directory, producing a merged rootfs equivalent to an overlay filesystem.

## Limitations

- **Pull-only** — no OCI image build or push. Image creation is out of scope.
- **No layer deduplication** — each image stores a fully merged rootfs. Shared base layers are not deduplicated across images.

## License

Same as the parent `bux` project. See [`LICENSE-MIT`](../../LICENSE-MIT) and
[`LICENSE-APACHE`](../../LICENSE-APACHE).
