# bux-qcow2

Pure-Rust operations on QCOW2 v3 images — no external dependencies beyond
`thiserror`, no C libraries, no async runtime.

## Scope

| Operation                 | Implementation             |
|---------------------------|----------------------------|
| `create_overlay`          | Pure Rust                  |
| `read_header`             | Pure Rust                  |
| `read_backing_file`       | Pure Rust                  |
| `read_backing_chain`      | Pure Rust                  |
| `is_backing_dependency`   | Pure Rust                  |
| `flatten`                 | Pure Rust                  |
| `resize`                  | Shells out to `qemu-img`   |

`create_overlay` and `flatten` produce QCOW2 v3 images. `read_header` also
accepts v2 images for inspection. Compressed clusters are rejected.

## Example

```rust,no_run
use std::path::Path;
use bux_qcow2::{BackingFormat, create_overlay, read_header};

create_overlay(
    Path::new("/tmp/overlay.qcow2"),
    "/data/base.raw",
    BackingFormat::Raw,
    1 << 30,
)?;

let hdr = read_header(Path::new("/tmp/overlay.qcow2"))?;
assert_eq!(hdr.virtual_size, 1 << 30);
# Ok::<_, bux_qcow2::Error>(())
```

## Status

Extracted from the `bux` main crate as part of the Phase 1 L1 refactor.
See `docs/design/L1-platform-primitives.md` in the workspace root for the
design rationale.
