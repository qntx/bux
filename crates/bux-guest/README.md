# bux-guest

Guest agent (PID 1) inside a bux micro-VM.

The agent is the control plane: vsock listener, exec, files, mounts. Workload
processes share the agent’s namespaces (Phase A). Hardware isolation vs the
host is the VM boundary.

Prebuilt ELF tag is `guest-v{version}` (`0.1.0` today), asset
`bux-guest-<linux-musl-triple>` plus `.sha256`. Not `guest-<sha>`.
