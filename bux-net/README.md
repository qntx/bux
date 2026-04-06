# bux-net

Network backend abstraction and [gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) integration for bux micro-VMs.

## Overview

This crate provides:

- **`NetworkBackend` trait** — pluggable interface for network backends (gvproxy, libslirp, passt, …)
- **`GvproxyBackend`** — concrete implementation using gvisor-tap-vsock via a Go c-archive (CGO bridge)
- **Network constants** — shared subnet, gateway/guest IP and MAC addresses
- **Socket shortener** — handles Unix socket `sun_path` length limits via symlinks

## Build requirements

- **Go 1.21+** — required to compile the `gvproxy-bridge` Go sources into `libgvproxy.a`
- Set `BUX_DEPS_STUB=1` to skip the Go build (CI lint mode)

## Architecture

```
Rust (bux-net)                          Go (gvproxy-bridge)
┌──────────────────┐                    ┌───────────────────┐
│ GvproxyBackend   │──── FFI (CGO) ────▶│ gvisor-tap-vsock  │
│ (NetworkBackend) │                    │ virtual network    │
└──────────────────┘                    └───────────────────┘
        │
        ▼
  NetworkEndpoint
  (UnixSocket path + MAC)
        │
        ▼
  VM engine (bux-krun)
```

## License

MIT OR Apache-2.0
