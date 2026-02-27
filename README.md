# bux

Embedded micro-VM sandbox for running AI agents.

Lightweight virtual machines powered by [libkrun](https://github.com/containers/libkrun) with KVM (Linux) or Hypervisor.framework (macOS).

## Quick Start

### Install

```sh
# From source
cargo install --path bux-cli

# Or use the installer script
curl -fsSL https://sh.qntx.fun/bux | sh
```

### Library Usage

```rust
use bux::Vm;

let vm = Vm::builder()
    .vcpus(2)
    .ram_mib(512)
    .root("/path/to/rootfs")
    .exec("/bin/bash", &["--login"])
    .build()
    .expect("invalid VM config");

vm.start().expect("failed to start VM");
```

### CLI

```sh
# Run a command in a new VM from an OCI image
bux run ubuntu:latest -- /bin/bash

# Managed VM lifecycle
bux ps                          # List running VMs
bux exec <vm> ls /              # Execute in a running VM
bux stop <vm>                   # Graceful shutdown (10s timeout)
bux kill <vm>                   # Force kill
bux rm <vm>                     # Remove stopped VM

# File operations
bux cp ./local <vm>:/guest/path # Host → Guest
bux cp <vm>:/guest/path ./local # Guest → Host

# Image management
bux pull alpine:latest
bux images
bux rmi alpine:latest

# Disk management
bux disk create <rootfs> <digest>
bux disk list
bux disk rm <digest>

# Utilities
bux inspect <vm>                # JSON details
bux wait <vm>                   # Block until exit
bux prune                       # Remove all stopped VMs
bux rename <vm> new-name
bux info                        # System capabilities
bux completion bash             # Shell completions
```

## Protocol

Host and guest communicate over vsock (port 1024) using a binary protocol (v3):

- **Serialization**: [postcard](https://crates.io/crates/postcard) (compact, no-std compatible)
- **Framing**: 4-byte big-endian length prefix per message
- **Handshake**: First message on every connection negotiates `PROTOCOL_VERSION`
- **Max frame**: 16 MiB per chunk
- **Streaming transfers**: File and tar operations use chunked streaming (`Chunk` + `EndOfStream` messages), removing the previous 16 MiB total size limit. Default chunk size is 256 KiB.

## Development

```sh
make check      # Compilation check
make test       # Run all tests
make clippy     # Lint with auto-fix
make fmt        # Format code
make doc        # Generate and open docs
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.
