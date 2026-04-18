# bux-gvproxy

Safe Rust wrapper over [gvisor-tap-vsock] (gvproxy), packaged as an L1
platform primitive for the bux workspace. Owns the Go toolchain
integration, static linkage of `libgvproxy.a`, and the raw FFI surface
so that higher layers can consume a tiny, safe Rust API.

## Scope

| Item | Description |
| --- | --- |
| `GvproxyConfig` | JSON-serialised config sent to the Go side (subnet, ports, DNS zones, capture file, …) |
| `GvproxyInstance` | RAII handle that owns the Go-side resources and releases them on drop |
| `NetworkStats` / `TcpStats` | Live counters decoded from `gvproxy_get_stats` |
| `start_stats_logging` | Optional background tokio task that logs stats every 30 s |
| `init_logging` | Go `slog` → Rust `tracing` bridge (idempotent) |
| `version()` | `libgvproxy.a` version string |
| `constants` | Default subnet / gateway / guest IP & MAC values |

This crate intentionally does **not** depend on any bux trait (e.g.
`NetworkBackend`); the `bux-net` crate layers that abstraction on top
so `bux-gvproxy` can be reused independently.

## Build requirements

- **Go 1.21+** — compiles `gvproxy-bridge/` into `libgvproxy.a`.
- Set `BUX_DEPS_STUB=1` to skip the Go build entirely (useful for `cargo
  check`/lint without a Go toolchain).

## Environment variables

| Variable | Effect |
| --- | --- |
| `BUX_GVPROXY_CAPTURE_FILE` | If set, enables pcap capture to the given path and turns on verbose logging |
| `BUX_DEPS_STUB` | Skip the Go build in `build.rs` |

## Example

```rust,no_run
use std::path::PathBuf;
use bux_gvproxy::{GvproxyConfig, GvproxyInstance};

let config = GvproxyConfig::new(
    PathBuf::from("/tmp/my-vm/net.sock"),
    vec![(8080, 80), (8443, 443)],
);

let instance = GvproxyInstance::new(config)?;
let stats = instance.get_stats()?;
eprintln!("bytes sent: {}", stats.bytes_sent);
# Ok::<(), bux_gvproxy::Error>(())
```

## Layering

```text
bux-net        (L5 — NetworkBackend trait, GvproxyBackend impl)
    │ depends on
    ▼
bux-gvproxy    (L1 — Go CGO bridge, raw FFI, safe wrappers)
    │ depends on
    ▼
libgvproxy.a   (Go c-archive built from gvproxy-bridge/)
```

[gvisor-tap-vsock]: https://github.com/containers/gvisor-tap-vsock
