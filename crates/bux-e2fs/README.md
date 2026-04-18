# bux-e2fs

Ext4 filesystem image creation via [`libext2fs`](https://e2fsprogs.sourceforge.net/) — static FFI bindings and safe Rust API.

> **Note:** This crate statically links `libext2fs` from e2fsprogs.
> For most use cases, prefer the high-level [`bux`](https://crates.io/crates/bux) crate.

## How it works

Pre-generated `bindgen` bindings are committed in `src/bindings.rs` so end
users do **not** need `libclang` installed. At build time the build script:

1. Downloads pre-built static libraries from [GitHub Releases](https://github.com/qntx/bux/releases) (or uses `BUX_E2FS_DIR`).
2. Statically links `libext2fs`, `libcom_err`, `libe2p`, `libuuid`, and `libcreate_inode`.

### Regenerating bindings

To update bindings from the pinned e2fsprogs headers (requires `libclang`, Linux/macOS only):

```sh
BUX_UPDATE_BINDINGS=1 cargo check -p bux-e2fs --features regenerate
```

## Safe API

```rust,no_run
use bux_e2fs::{BlockSize, Ext4Builder, inject_file};
use std::path::Path;

// Create an ext4 image from a directory (like mke2fs -d).
Ext4Builder::new()
    .block_size(BlockSize::B4096)
    .reserved_ratio(0)
    .create_from_dir(
        Path::new("/tmp/rootfs"),
        Path::new("/tmp/base.raw"),
        512 * 1024 * 1024,
    )?;

// Inject a file into an existing image (like debugfs write).
inject_file(
    Path::new("/tmp/base.raw"),
    Path::new("/usr/local/bin/bux-guest"),
    "usr/local/bin/bux-guest",
)?;
# Ok::<_, bux_e2fs::Error>(())
```

Prefer [`create_from_dir`] if default options are fine:

```rust,no_run
use bux_e2fs::{create_from_dir, estimate_image_size};
use std::path::Path;

let size = estimate_image_size(Path::new("/tmp/rootfs"))?;
create_from_dir(
    Path::new("/tmp/rootfs"),
    Path::new("/tmp/base.raw"),
    size,
)?;
# Ok::<_, bux_e2fs::Error>(())
```

## Environment variables

| Variable | Description |
| --- | --- |
| `BUX_E2FS_DIR` | Path to a local directory containing pre-built static libraries. Skips downloading. |
| `BUX_E2FS_VERSION` | Override the e2fsprogs release version (default: crate version). |
| `BUX_UPDATE_BINDINGS` | Copy generated bindings back to `src/bindings.rs` (with `regenerate` feature). |

## Supported platforms

| Target | Status |
| --- | --- |
| `aarch64-apple-darwin` | ✅ |
| `x86_64-unknown-linux-gnu` | ✅ |
| `aarch64-unknown-linux-gnu` | ✅ |

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT License](../LICENSE-MIT) at your option.
