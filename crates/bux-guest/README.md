# bux-guest

Guest agent (PID 1) inside a bux micro-VM.

The agent is the control plane: vsock listener, exec, files, mounts. Workload
processes share the agent’s namespaces (Phase A). Hardware isolation vs the
host is the VM boundary.

In-guest OCI containers are a 1.0 milestone, not this agent.
