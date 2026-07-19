# vISA ownership authority core

`visa_ownership_service` is the transport-independent product authority core
for the vISA 0.1 single-host ownership service. It owns the unique durable
`InitializeUnit`, `Reserve`, `Seal`, `Abort`, `Commit`, and `Query` decisions;
it does not open an agent/provider database or act as a workflow engine.

The sole mutation boundary accepts an already admitted `AgentBinding` and the
exact canonical `visa_local_rpc::ownership` request bytes. One SQLite
`BEGIN IMMEDIATE` transaction then:

1. admits a new `(family_id, request_id)` or returns the stored exact replay;
2. rejects the same request ID with different bytes;
3. decodes the operation-specific canonical proposal;
4. applies the ownership transition and neutral receipt checks;
5. constructs and validates the request-paired response;
6. persists the authority projection and exact response bytes; and
7. commits before any future transport may send the reply.

The store uses bundled SQLite through `rusqlite` 0.40.1 with WAL,
`synchronous=FULL`, foreign keys, `trusted_schema=OFF`, strict tables, a private
`0700` parent, `0600` database/lock files, and a lifetime exclusive process
lock. Create-new and reopen-existing are distinct operations. Cohort, boot,
runtime session, ownership issuer namespace, receipt-policy digest, quotas,
and process generation are persisted and must match before the first authority
write on reopen.

First creation initializes and audits a nonce-named database in the final
directory, checkpoints and explicitly closes SQLite, requires every temporary
sidecar to be absent, fsyncs the self-contained database, publishes it with
Linux `RENAME_NOREPLACE`, and fsyncs the parent directory. A crash before
publication can leave only an untrusted orphan; a crash after publication
leaves a complete generation-zero store that the next process can audit and
advance. Existing malformed final files and preexisting temporary or final
SQLite sidecars fail closed and are never replaced, consumed, or cleaned up.

Active-cohort RPC exchanges are retained without TTL pruning because local wire
v1 has no `ReplayExpired` result. Startup audits the exact schema, foreign keys,
canonical records, authority history, response/service bindings, completion
order, and quotas. Every service process generation has a durable unique nonce
and start-completion boundary, including generations that served no requests;
historical responses must fall in and name that exact process interval. Startup
also replays every persisted exact RPC exchange through
the same state machine and `joint_handoff_core` reducer into an in-memory
shadow authority; the historical outcomes and final projection must match the
durable database exactly.

The same canonical exchange ledger reconstructs an independent caller cursor
for each agent role. A role may continue with the same process nonce and
generation or advance to a greater generation with a different nonce; rollback,
equal-generation nonce substitution, nonce reuse, or stable logical-identity
substitution fails before authority mutation. Generation gaps are valid because
an agent may crash before its first RPC. The in-memory cursor advances only
after a new terminal exchange commits, so request-ID conflict, capacity, and
storage rollback cannot manufacture a newer admitted process. No second caller
ledger or SQLite schema migration is required.

Seal admission uses typed canonical neutral receipts and the pure
`joint_handoff_core` reducer rather than a duplicate protocol validator. The
fixed `PinnedLocalReceiptAuthenticator` policy derives the ownership log ID
from the persisted namespace and handoff ID and pins the source-vISA,
destination-vISA, and effect-closure issuer coordinates. The policy digest is
part of the store identity.

This authenticator is deliberately bounded to the vISA 0.1 same-UID trusted
binary TCB. It checks role/issuer lineage but the current local wire carries no
authenticated `ReceiptEnvelope`; therefore it is **not** cryptographic
authenticity, hostile same-UID isolation, or proof of the original peer
request. A future stronger envelope can implement the same admission trait
without changing the ownership state machine.

This crate is the O1 authority-core slice only. It contains no zbus server,
D-Bus credential admission, ProcessFD/pidfd executable verification,
application queue, name-loss fence, sd-notify lifecycle, systemd unit, or real
agent client. Its presence does not satisfy `public-ownership-service`,
`agent-ownership-rpc-v1`, `ownership-single-writer-restart-replay`, or the
shared `crash-recovery-and-replay` readiness ID. Those remain pending until the
O2/O3 process and evidence slices consume this exact core.
