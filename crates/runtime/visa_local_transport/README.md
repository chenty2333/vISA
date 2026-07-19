# vISA local transport primitives

`visa_local_transport` contains the mechanical same-host peer verification
shared by vISA's fixed user-bus endpoints. It reuses zbus for bus-controlled
unique names and credentials, and rustix for Linux pidfds and secure procfs
inspection.

For one expected well-known-name owner, the verifier checks the bus GUID,
requires unchanged name ownership before and after inspection, prefers the
bus-provided `ProcessFD`, falls back to a double-credential-query plus
`pidfd_open`, and verifies the live process's opened `/proc/<pid>/exe` identity
and SHA-256 digest. The returned peer retains the pidfd so the caller can hold
the process identity through its own admission barrier.

This crate does not define an RPC abstraction, encode any vISA wire family,
select an authority role, decide replay or recovery, manage readiness, or own
an admission gate. Those policies remain in the concrete ownership, agent,
and Nexus endpoints.
