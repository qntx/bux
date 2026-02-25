# bux-sys

Raw FFI bindings to [`libkrun`](https://github.com/containers/libkrun) — a lightweight VM engine for sandboxed code execution.

> **Note:** This crate provides unsafe, low-level bindings. Prefer the
> safe [`bux`](https://crates.io/crates/bux) crate for application code.

## How it works

Pre-generated `bindgen` bindings are committed in `src/bindings.rs` so end
users do **not** need `libclang` installed. At build time the build script:

1. Downloads the pre-built dynamic library from [GitHub Releases](https://github.com/pyroth/bux/releases) (or uses `BUX_DEPS_DIR`).
2. Configures the linker for dynamic linking and exports `DEP_KRUN_LIB_DIR`.

### Regenerating bindings

To update bindings from the pinned [qntx/libkrun](https://github.com/qntx/libkrun) fork header (requires `libclang`, Linux/macOS only):

```sh
make regenerate-bindings
# or manually:
BUX_UPDATE_BINDINGS=1 cargo check -p bux-sys --features regenerate
```

## Environment variables

| Variable | Description |
| --- | --- |
| `BUX_DEPS_DIR` | Path to a local directory containing pre-built libraries. Skips downloading. |
| `BUX_DEPS_VERSION` | Override the deps release version (default: crate version). |
| `BUX_UPDATE_BINDINGS` | Copy generated bindings back to `src/bindings.rs` (with `regenerate` feature). |

## Supported platforms

| Target | Backend |
| --- | --- |
| `aarch64-apple-darwin` | Hypervisor.framework |
| `x86_64-unknown-linux-gnu` | KVM |
| `aarch64-unknown-linux-gnu` | KVM |

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT License](../LICENSE-MIT) at your option.
