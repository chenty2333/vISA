# Transparent WASI migration

## Scope

This design adds a carrier-neutral resource personality for complete
compute-plus-resource migration. Wanco checkpoints guest compute state; the
external provider checkpoints and rebinds host resource state.

“Transparent stock application” has a precise meaning here:

- the upstream application revision is source-locked and receives zero source
  patches;
- it imports ordinary WASI Preview1 functions and contains no migration
  callback;
- Wanco may instrument the Wasm module at build time to carry compute state;
- the linked WASI host library and the external provider are part of the
  migration platform.

## Ownership split

Wanco carries frames, globals, tables, and linear memory. `visa_wasi_host`
owns the virtual descriptor table, namespace, stable object identities,
offsets, rights, append state, timestamps, operation replay ledger, and locks.
`visa_wanco_wasi` is a marshalling bridge and owns no recoverable resource
state.

Every guest request binds:

`session × stable owner × process client × guest capability × request sequence
× stable effect ID × authority epoch`.

The process client changes on restore, while the owner does not. This prevents
request-counter aliasing and lets locks survive the source/destination process
change. A random guest capability admits the exact runtime process without
giving it the separate administrative capability used for provider
transitions. Restore rotates both capabilities, so a source runtime cannot
authenticate to the destination even if it knows the destination session,
owner, client, and epoch. The provider accepts mutations only in `active` mode
at the exact authority epoch. Freeze makes the source read-only for the
handoff; activation advances the destination epoch; a committed source never
becomes active again.
These local modes and epochs are a projection of the canonical vISA
coordinator/joint-handoff decision, not a second ownership authority. The
migration driver may issue provider `freeze`, `fence`, and `activate` only as
the corresponding canonical transition is prepared or committed, and binds
the resulting receipt identities into the joint capsule manifest.

The process-local `(client, sequence)` pair identifies one delivery attempt.
The effect ID is deterministically derived from a domain-separated digest of
the stable delivery identity and canonical request bytes. It therefore remains
identical if a native restore process is replayed after a driver crash, while
still changing with the client, sequence, authority epoch, or operation. The
provider stores the operation digest and response by effect ID, rejects an
incompatible reuse, and does not admit a handoff barrier while any recorded
delivery remains incomplete.

## Virtual filesystem

Guest fd 3 is the root preopen. Descriptors above 3 refer to stable object IDs,
not host descriptors. Namespace paths and chunked sparse object extents are
separate so open descriptors remain valid across rename and unlink. A migration
capsule contains the durable provider database, object extents, and a digest
manifest; absolute host paths never enter the semantic state.

All mutating calls are replay-safe. The provider serializes calls, records the
delivery and stable-effect digests, and returns the byte-identical recorded
response for an exact retry or a same-effect retry from a replacement client.
A conflicting reuse fails closed. Writes use an explicit resolved object
offset, including append, so replay cannot duplicate bytes.

## Locks and SQLite boundary

WASI Preview1 has no POSIX record-lock syscall. Upstream SQLite's stock WASI
configuration can nevertheless use its `unix-dotfile` rollback-journal locking
path: the lock directory is expressed through ordinary create/remove-directory
calls, so it is covered by the standard virtual namespace above. This is the
initial stock, single-process SQLite baseline.

The same host library also exposes a versioned vISA VFS extension with `lock`,
`unlock`, and `check-reserved` operations over SQLite's
`SHARED → RESERVED → PENDING → EXCLUSIVE` states. Locks bind to the stable
owner and are transferred in the provider capsule. This extension is the
host-side substrate for full concurrent rollback-journal locking and, together
with a future shared-memory extension, WAL. An unmodified SQLite build cannot
discover this non-standard ABI without a VFS adapter, and this design does not
claim otherwise.

The stock SQLite qualification path deliberately stays on the ordinary
`unix-dotfile` ABI. It runs the official unmodified CLI in rollback-journal
`DELETE` mode with `synchronous=FULL`; exact cut predicates target the real
directory, journal, database, sync, unlink, and cursor hostcalls emitted by
that binary. The private lock extension is tested as provider substrate but is
not counted as part of the stock-application result.

## Exact post-hostcall barrier

The controller arms a predicate before starting the operation. A predicate
contains the hostcall kind, exact resource path or descriptor, outcome, and
occurrence. The provider durably commits the effect and response, changes the
barrier from `armed` to `triggered`, and blocks admission of the next hostcall.
Only after the bridge has copied the response into guest linear memory does it
send `GuestCompletion`, allowing `triggered` to become `held`. Releasing the
barrier with `checkpoint` makes the blocked bridge request a Wanco checkpoint;
the matching barrier token is then required by provider freeze.

Byte counters and external signals are observations or cleanup mechanisms,
not checkpoint triggers. A namespace snapshot is allowed only at the retained
`checkpoint_released` boundary. It serializes the whole logical namespace,
including linked and unlinked objects, file bytes, descriptors, offsets,
locks, sidecars, and a digest of the stable-effect frontier.

## Handoff order

1. Arm an exact post-hostcall predicate on the active source provider.
2. Run the stock application until the target response is durable and copied
   into guest memory, then release the held bridge to checkpoint.
3. Require the nonempty Wanco checkpoint, freeze with the same barrier token,
   and export the provider's digest-bound capsule.
4. Restore the destination provider as `prepared`.
5. Commit ownership, fence the source, and activate the destination at the next
   epoch.
6. Restore Wanco compute state with a fresh process client and the stable owner.
7. Verify the application’s externally materialized output against an
   uninterrupted control.

The migration intent content-binds the exact checkpoint barrier token as well
as the handoff and epochs, so a real provider adapter can replay the same
freeze after a controller crash. The migration driver persists an intent-bound action before every external
compute or provider transition. On restart it first queries canonical
ownership/fence state, then idempotently replays the pending action. A
pre-commit abort resumes the source provider and restores the source compute
checkpoint with the intent's separate fresh `source_restore_client`; a
canonical commit prevents that abort path. The source, source-restore, and
destination client identities are pairwise distinct because native bridge
request counters are process-local and are not part of guest checkpoint state.

`visa_wasi_migration::ProviderProcessProjection` sends those projections over
the provider's versioned Unix protocol; it does not shell out through the
administrative CLI. `WancoProcessControl` verifies a durable source-exit receipt
against the bound checkpoint and runs the configured Wanco `--restore` command
without a shell. The command contract binds both the selected AOT application
and checkpoint before the guest-argument delimiter. It fsyncs a command-bound
completion receipt before returning,
so loss of the driver's completion update reuses the completed action. The
`visa-wasi-migration-driver` binary exposes the pre-commit initialization and
abort-recovery path with `FileDriverRecordStore`; a durable adapter binding
rejects a different provider or Wanco configuration on restart. Barrier arm/release and the
initial source launch remain an explicit upper-layer preflight because they
precede `ComputeControl::confirm_source_exit`.

`CanonicalAuthorityFileVerifier` reopens a separate authority-owned state on
every proof check and restart. The state must be euid-owned, singly linked,
`0600`, canonical JSON, and exactly manifest-bound; `uncommitted` is an explicit
decision rather than an inference from missing data. Its production contract
requires one authority writer to publish replacements atomically. The stock
source-abort qualifier also proves that a valid committed state blocks resume
before the provider changes.

Wanco restore runs under a separate lock-holding supervisor. A canonical spec
and `started` receipt precede process launch; every exit, including failure and
timeout, produces a terminal completion receipt. If the supervisor dies without
one, its replacement runs the exact configured cleanup and restarts the same
fingerprinted command, whose stable provider effects are replay-idempotent.

Destination-provider restore publishes a manifest-bound receipt containing
the restored database identity. Reusing an existing database or already-live
prepared endpoint requires that receipt plus exact `prepared@source_epoch`
session status; file or socket existence alone is never accepted as restore.

## Stock-zstd qualification boundary

The committed runner qualifies zero-patch upstream zstd sources linked with the
platform compatibility object; it does not claim that an upstream-distributed
binary is reused unchanged. The matrix contains one uninterrupted control and
two distinct mid-execution Wanco checkpoints selected by prearmed successful
`fd_write` occurrences on `output.zst`. Each checkpoint restores into a fresh
provider database and process, then requires both native-zstd decompression
equivalence and compressed-byte identity with the control.

Five negative cells accompany each cut: carrier-only restore into an empty
provider, compute-checkpoint tamper, provider-capsule tamper, commit/fence proof
pairing tamper, and destination guest-capability spoof. The runner checks the
expected detector class for each rejection and hard-checks the provider
transition chain:

`active@1 → frozen@1 → prepared@1 → fenced@1 → active@2`.

Before execution, the v3 matrix receipt cross-checks the stock-zstd source
lock, stock build receipt, Wanco source lock, Wanco build receipt, all retained
application artifacts, and the live Docker image ID. The authority statement
remains deliberately narrower: these bindings and local transitions are
verified, while external coordinator authenticity is not.
