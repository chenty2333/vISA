# vISA ownership daemon process slice

`visa-ownershipd` is the O2/O3 process layer around the transport-independent
`visa_ownership_service` authority core. It reuses `visa_local_transport` for
the zbus 5.18.0 and rustix 1.1.4 Linux pidfd/proc-file peer admission, bundled
SQLite through O1, and `sd-notify` 0.5.0 for readiness.

The daemon owns no second ownership state machine, replay cache, database, or
workflow engine. A single worker thread is the only caller of
`AuthorityStore::execute_exact`. The D-Bus side performs bounded pre-admission,
then atomically orders a fully admitted request against name/bus-loss fencing
before it can enter the 16-item worker queue. O1 commits the authority change
and exact response bytes before the transport can send a reply.

The v2 bootstrap input is secure-opened, canonical RFC 8785 JSON and bound to a
SHA-256 supplied out of band. It pins each agent's product/cohort/boot/session,
role, stable logical incarnation, and executable digest, but deliberately does
not pin a process nonce or generation. It avoids compiling another product
binary's digest into this binary, but is not yet the release runtime trust
root. O3 must still freeze its installed path/provenance and connect real source
and destination agents before any ownership readiness ID can become satisfied.

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
`/proc/<pid>/exe` identity/digest. A narrow zbus proxy then resolves the live
systemd user manager to one unique bus owner and twice calls the frozen
`GetUnit` method for the exact `visa-agent@source.service` or
`visa-agent@destination.service`. It requires the returned object's primary
Unit `Id`, a 16-byte Unit `InvocationID` equal to the caller nonce, and a
Service `MainPID` equal to the bus-controlled PID. The retained pidfd stays
local, brackets both systemd observations with liveness checks, and remains the
admission lease through a final synchronous liveness check immediately before
queue insertion.

The frozen `Execute(ay) -> ay` business method rejects attached Unix FDs.
systemd attests invocation nonce, not process generation: the future agent
store allocates that durable order and O1's caller cursor enforces forward
nonce/generation pairs at commit. These sequential checks are same-UID
trusted-binary admission, not an atomic cross-subsystem snapshot, hostile
same-UID isolation, or cryptographic peer authenticity.

This bounded slice deliberately leaves `public-ownership-service`,
`agent-ownership-rpc-v1`, `ownership-single-writer-restart-replay`, and the
shared `crash-recovery-and-replay` readiness IDs pending. Real agent stores and
processes, installed systemd units, crash/lost-ACK evidence, Ubuntu 24.04
systemd-255 compatibility, and the exact-tag release archive remain separate
O3 and release gates.
