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
× authority epoch`.

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

## Virtual filesystem

Guest fd 3 is the root preopen. Descriptors above 3 refer to stable object IDs,
not host descriptors. Namespace paths and chunked sparse object extents are
separate so open descriptors remain valid across rename and unlink. A migration
capsule contains the durable provider database, object extents, and a digest
manifest; absolute host paths never enter the semantic state.

All mutating calls are replay-safe. The provider serializes calls, records the
request identity and digest, and returns the byte-identical recorded response
for an exact retry. A conflicting reuse fails closed. Writes use an explicit
resolved object offset, including append, so replay cannot duplicate bytes.

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

## Handoff order

1. Run the stock application against an active source provider.
2. Ask Wanco to checkpoint at an AOT migration point; no hostcall is in flight
   after the source process exits.
3. Freeze the source provider and export its digest-bound capsule.
4. Restore the destination provider as `prepared`.
5. Commit ownership, fence the source, and activate the destination at the next
   epoch.
6. Restore Wanco compute state with a fresh process client and the stable owner.
7. Verify the application’s externally materialized output against an
   uninterrupted control.

## Stock-zstd qualification boundary

The committed runner qualifies zero-patch upstream zstd sources linked with the
platform compatibility object; it does not claim that an upstream-distributed
binary is reused unchanged. The matrix contains one uninterrupted control and
two distinct mid-execution Wanco checkpoints. Each checkpoint restores into a
fresh provider database and process, then requires both native-zstd
decompression equivalence and compressed-byte identity with the control.

Five negative cells accompany each cut: carrier-only restore into an empty
provider, compute-checkpoint tamper, provider-capsule tamper, commit/fence proof
pairing tamper, and destination guest-capability spoof. The runner checks the
expected detector class for each rejection and hard-checks the provider
transition chain:

`active@1 → frozen@1 → prepared@1 → fenced@1 → active@2`.

Before execution, the v2 matrix receipt cross-checks the stock-zstd source
lock, stock build receipt, Wanco source lock, Wanco build receipt, all retained
application artifacts, and the live Docker image ID. The authority statement
remains deliberately narrower: these bindings and local transitions are
verified, while external coordinator authenticity is not.
