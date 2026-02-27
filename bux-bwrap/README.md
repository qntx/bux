# bux-bwrap

Bundles the [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) sandbox binary for bux.

**Linux only.** On other platforms, `path()` returns `None`.

## How it works

| Stage | Component | Action |
| ------- | ----------- | -------- |
| **CI** | `bwrap-build.yml` | Builds bwrap from source (meson + ninja) → uploads `bux-bwrap-{target}.tar.gz` to GitHub Releases |
| **Build** | `build.rs` | Downloads pre-built binary from GitHub Releases (or uses `BUX_BWRAP_DIR`) |
| **Runtime** | `lib.rs` | `path()` discovers bwrap: sibling of exe → `$PATH` → build-time fallback |

## Environment variables

- **`BUX_BWRAP_DIR`** — Local directory containing a pre-built `bwrap` binary. Skips downloading.
- **`BUX_BWRAP_VERSION`** — Override the release version to download (default: crate version).

## License

MIT OR Apache-2.0
