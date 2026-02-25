# bux-oci

Pure Rust OCI image management for the [bux](https://github.com/qntx/bux) micro-VM sandbox.

Pulls, stores, and extracts OCI container images from any OCI-compliant registry (Docker Hub, GHCR, etc.) and prepares root filesystems for [libkrun](https://github.com/containers/libkrun) micro-VMs — with zero external tool dependencies.

## Features

- **Docker-compatible reference parsing** — `ubuntu`, `ubuntu:22.04`, `ghcr.io/org/app:v1`, digests
- **OCI Distribution protocol** — bearer token auth for Docker Hub and GHCR
- **Multi-architecture support** — automatic platform selection from image index manifests
- **Content-addressable blob storage** — SHA-256 verified, deduplicated layer cache
- **OCI whiteout handling** — correct `.wh.<name>` deletion and `.wh..wh..opq` opaque directories
- **Image config inheritance** — `CMD`, `ENTRYPOINT`, `ENV`, `WorkingDir` forwarded to the VM
- **Self-contained** — no `buildah`, `skopeo`, `e2fsprogs`, or any external binaries required

## Usage

```rust
let mut oci = bux_oci::Oci::open()?;

// Pull an image
let result = oci.pull("ubuntu:24.04", |msg| eprintln!("{msg}"))?;
println!("rootfs: {}", result.rootfs.display());

// Ensure (use cache or pull)
let result = oci.ensure("ubuntu:24.04", |msg| eprintln!("{msg}"))?;

// List local images
for img in oci.images()? {
    println!("{} ({})", img.reference, img.digest);
}

// Remove an image
oci.remove("ubuntu:24.04")?;
```

### Pull Pipeline

```text
parse reference → resolve manifest (handle multi-arch index)
    → download config blob → download layer blobs (skip cached)
    → extract layers in order (tar+gzip, whiteout handling)
    → persist metadata + config → return rootfs path
```

### Storage Layout

```text
$BUX_HOME/                          # or <platform_data_dir>/bux
├── blobs/sha256/
│   ├── <layer-digest-hex>          # Compressed layer tarballs
│   └── <config-digest-hex>         # Image config JSON blobs
├── rootfs/
│   ├── <storage_key>/              # Extracted root filesystem
│   └── <storage_key>.json          # Cached image config
└── images.json                     # Image index (reference, digest, size)
```

## Design Decisions

### Why Pure Rust? (vs. shelling out to external tools)

We evaluated three major approaches for OCI image management:

| Approach | Pros | Cons |
| --- | --- | --- |
| **A. `buildah` / `skopeo`** | Mature, battle-tested, full OCI spec | Heavy external dependency (~50MB), requires root or `newuidmap`, complex installation, not embeddable |
| **B. `oci-client` (async)** | Official Rust OCI Distribution client | Pulls in `tokio` + full async runtime (~2MB+ compile), over-engineered for synchronous CLI use case |
| **C. Pure Rust (sync) ✅** | Zero external deps, minimal binary size, single-threaded simplicity | Must implement protocol ourselves (but it's simple HTTP) |

**We chose Approach C** for the following reasons:

1. **Self-contained distribution** — `bux` ships as a single static binary. Requiring `buildah` or `skopeo` would break this promise and add complex installation requirements across platforms.

2. **No async runtime needed** — OCI pulls are inherently sequential (resolve manifest → download blobs → extract). An async runtime adds ~2MB to compile time and significant complexity for no practical throughput benefit in this use case.

3. **OCI Distribution is simple HTTP** — The core protocol is just a few REST endpoints (`/v2/<repo>/manifests/<ref>`, `/v2/<repo>/blobs/<digest>`) with optional bearer token auth. Implementing this directly with `ureq` (a synchronous HTTP client) takes ~150 lines.

4. **`krunvm` demonstrates the problem** — The existing [krunvm](https://github.com/containers/krunvm) project depends on `buildah` for image management, which causes installation friction, platform-specific issues, and requires `newuidmap`/`newgidmap` for rootless operation. We explicitly avoid this path.

### Why Directory-based rootfs? (vs. ext4 disk image)

| Approach | Pros | Cons |
| --- | --- | --- |
| **A. Directory rootfs ✅** | Simple, fast extraction, `krun_set_root` native support, easy inspection/debugging | Slightly slower VM boot vs. block device, no CoW |
| **B. ext4 disk image** | Block-level CoW possible, closer to real VM experience | Requires `e2fsprogs` or pure-Rust ext4 writer (none mature), `krun_add_disk` needs kernel+initrd, much more complex |

**We chose directory-based rootfs** because:

1. **`libkrun` natively supports it** — `krun_set_root(ctx, path)` directly mounts a host directory as the guest rootfs via virtio-fs. No kernel, initrd, or bootloader needed.

2. **No `e2fsprogs` dependency** — Creating ext4 images requires either shelling out to `mkfs.ext4` (external dependency) or using an immature pure-Rust ext4 writer. Neither is acceptable for a self-contained tool.

3. **Simpler mental model** — Users can inspect, modify, and debug the extracted rootfs directly on the host filesystem.

4. **ext4 remains a future option** — If block-level performance becomes necessary, `krun_add_disk` support can be added later without changing the pull/store pipeline.

### Why `ureq`? (vs. `reqwest` / `hyper`)

| Crate | Async | TLS | Binary size impact |
| --- | --- | --- | --- |
| **`reqwest`** | Yes (tokio) | native-tls or rustls | ~2MB+ |
| **`hyper`** | Yes (tokio) | BYO | ~1.5MB+ |
| **`ureq` ✅** | No (blocking) | rustls built-in | ~500KB |

`ureq` is the natural choice for a synchronous application: minimal dependencies, built-in `rustls` TLS, and a clean streaming API for large blob downloads. Since our pull pipeline is inherently sequential, async provides no benefit.

### Why custom reference parser? (vs. `oci-spec` / `docker-reference`)

The OCI image reference format is well-defined but no standalone Rust crate handles the full Docker-compatible normalization (implicit `docker.io` registry, `library/` prefix for official images, default `latest` tag). Our parser is ~80 lines with 7 unit tests covering all common formats. Adding a dependency for this would be heavier than the implementation itself.

### Content Integrity

Every blob downloaded from a registry is verified against its content digest using streaming SHA-256 (`HashWriter`). If the computed digest doesn't match, the blob is deleted and an error is returned. This follows the OCI Distribution spec requirement for content-addressable storage.

## License

Same as the parent `bux` project. See [LICENSE](../LICENSE).
