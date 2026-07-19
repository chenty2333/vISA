# vISA ownership daemon process slice

`visa-ownershipd` is the O2 process layer around the transport-independent
`visa_ownership_service` authority core. It reuses zbus 5.18.0 for the systemd
user-bus interface, rustix 1.1.4 for Linux pidfd/proc-file admission, bundled
SQLite through O1, and `sd-notify` 0.5.0 for readiness.

The daemon owns no second ownership state machine, replay cache, database, or
workflow engine. A single worker thread is the only caller of
`AuthorityStore::execute_exact`. The D-Bus side performs bounded pre-admission,
then atomically orders a fully admitted request against name/bus-loss fencing
before it can enter the 16-item worker queue. O1 commits the authority change
and exact response bytes before the transport can send a reply.

The explicit bootstrap input is secure-opened, canonical RFC 8785 JSON and is
bound to a SHA-256 supplied out of band. It avoids compiling another product
binary's digest into this binary, but is not yet the release runtime trust root.
O3 must freeze its installed path/provenance and connect real source and
destination agents before any ownership readiness ID can become satisfied.

The daemon has no ambient configuration fallback. Its launch interface is:

```text
visa-ownershipd \
  --bootstrap /absolute/private/ownershipd.json \
  --bootstrap-sha256 64-lowercase-hex-digits
```

The bootstrap must be one euid-owned, single-link, regular file with exact
mode `0600`; its canonical bytes must match the argv digest. The daemon creates
the configured store only when `CreateIfMissingExact` observes an exact
`NotFound`, otherwise it reopens and audits the existing identity. A fresh
nonzero process nonce is generated before O1 advances its durable generation;
same-process bus reconnects reuse that already-open store and generation. O1
publishes a first store only after its temporary SQLite database is audited,
checkpointed, explicitly closed, sidecar-free, fsynced, and atomically moved
without replacing an existing final path.

Process exits use stable sysexits-style classes: `64` invalid CLI, `65`
invalid/digest-mismatched bootstrap data, `70` internal/integrity failure, `75`
temporary host/bus/lock/worker failure, and `78` unusable runtime
configuration. Help and version requests exit `0` and never open the store.

Every call revalidates the bus-controlled unique sender, role-name ownership,
UID/PID, ProcessFD or double-query pidfd fallback, and the opened
`/proc/<pid>/exe` identity/digest. `ProcessFD` is allowed only as a D-Bus
credentials control-plane result; the frozen `Execute(ay) -> ay` business
method rejects attached Unix FDs. This is same-UID trusted-binary admission,
not hostile same-UID isolation or cryptographic peer authenticity.

This O2 slice deliberately leaves `public-ownership-service`,
`agent-ownership-rpc-v1`, `ownership-single-writer-restart-replay`, and the
shared `crash-recovery-and-replay` readiness IDs pending. Real systemd units,
agents, crash/lost-ACK evidence, Ubuntu 24.04 compatibility, and the exact-tag
release archive belong to O3 and later release gates.
