# Stock SQLite rollback-journal cut matrix

## Claim boundary

This matrix targets an unmodified SQLite application compiled for WASI,
running in `journal_mode=DELETE` with `synchronous=FULL`. It qualifies
provider-process failure and Wanco compute handoff. It does not claim safety
under power loss, torn sectors, storage-controller write reordering, or a
lying `fsync` implementation.

The stage names follow SQLite's official [Atomic Commit In
SQLite](https://www.sqlite.org/atomiccommit.html) rollback-mode model. The
hardware limitations follow SQLite's [How To Corrupt An SQLite Database
File](https://www.sqlite.org/howtocorrupt.html). A retained matrix receipt
must keep the narrower process-crash scope explicit.

Stock SQLite selects `unix-dotfile` under `__wasi__`. Its first file lock is
implemented as `mkdir("<database>.lock")`; later SQLite lock levels are local
state while that directory exists. Consequently the stock lock cell targets
`path-create-directory` on the exact `.lock` path. It does not target or claim
use of vISA's private `VfsLock` extension.

## Exact cells

For the default database `workload/accounts.db`, the canonical plan is:

The final stock Wasm import trace is retained as an execution input. This plan
binds its sequential file I/O to Preview1 `fd_read`/`fd_write` and sync to
`fd_sync`; it does not infer positional hostcalls from the native SQLite VFS
source.

| Cell | SQLite model stage | Pre-armed predicate | Required continuation or anchor |
| --- | --- | --- | --- |
| `lock-acquired` | 3.2, acquire read lock | successful `path-create-directory` on `workload/accounts.db.lock`, occurrence 1 | later journal `path-open` |
| `partial-journal` | 3.5, create rollback journal | successful `fd-write` on `workload/accounts.db-journal`, occurrence 1 | another journal `fd-write` |
| `post-journal-sync` | 3.7, flush rollback journal | successful `fd-sync` on `workload/accounts.db-journal`, occurrence 2 | later database `fd-write` |
| `mid-db-page-write` | 3.9, write database pages | successful `fd-write` on `workload/accounts.db`, occurrence 2 | another database `fd-write` |
| `post-db-sync` | 3.10, flush database | successful `fd-sync` on `workload/accounts.db`, occurrence 1 | later journal unlink |
| `journal-delete-commit-point` | 3.11, delete rollback journal | successful `path-unlink-file` on `workload/accounts.db-journal`, occurrence 1 | exactly one external transaction acknowledgement |
| `lost-response` | 3.11 plus delivery fault | the same journal-unlink predicate, held at `triggered` | same source request retry, then completed-ACK drain |
| `active-read-cursor` | 3.3, read database pages | successful `fd-read` on `workload/accounts.db`, occurrence 12 | a nonempty, nonterminal ordered row-output prefix |

The partial-journal and mid-database-write names are not inferred from byte
counters. Their destination-side continuation barriers prove that a later
write of the same class still occurs. The tracked workload uses 512 accounts,
a 512-byte SQLite page size, and a transaction that updates both halves of the
account B-tree. A calibration run observed a 15-page database, both rollback-
journal syncs, at least three database writes, and all 512 cursor rows. Cursor
read occurrences 1 through 8 preceded the first visible row; occurrence 12
left exactly one row visible, so it is the first retained nonempty/nonterminal
prefix used by this matrix.

## Controller order

Every normal cell uses this order:

1. Require the source provider to be `active/open` with no uncertain delivery.
2. Arm the exact hostcall kind, exact canonical path, successful outcome, and
   static occurrence before starting the relevant workload segment.
3. Observe `armed`, then wait only on the provider barrier phase. Workload byte
   counters and output size are not cut triggers.
4. The provider records the effect and response before entering `triggered`.
   The bridge writes the result into guest linear memory and sends
   `GuestCompletion`; only then may the provider enter `held`.
5. Release `checkpoint` and retain the status returned by that same atomic
   `BarrierRelease` response. Require `checkpoint_released` with the same
   effect, unchanged effect/request counters, and empty `completed_barrier` and
   `completed_barrier_effect`, then require a nonempty Wanco checkpoint before
   freezing the provider.
6. Execute the canonical source-frozen, destination-prepared, source-fenced,
   destination-active handoff with a fresh destination process client.
7. For cells with a continuation witness, arm that second exact predicate
   after destination activation and before compute restore, then release it
   with `continue`. The status in that atomic release response must be `open`,
   must preserve the held counters, and must bind `completed_barrier` and
   `completed_barrier_effect` to the exact released token/effect. The
   controller must not issue a second `status` request to establish the release:
   after `continue` the guest may execute another hostcall before that request,
   creating a TOCTOU observation rather than evidence of the release edge.
8. Parse `VISA_ACK` terminals from the cell's raw stock-SQLite stdout and
   generate that cell's expected-ACK input. The runner rejects a missing,
   duplicated, or invented transaction identifier before invoking the oracle.
9. Complete one ordered application-level cursor readback. The active-cursor
   cell finishes its checkpointed cursor; the other seven cells use a fresh
   post-handoff client. All eight must emit the same 512 typed rows and terminal
   as the uninterrupted control.
10. Take one atomic namespace snapshot and run `visa-sqlite-oracle` against it.
    The native oracle emits its own logical-content hashes and invariant
    projection. The standalone validator combines that projection with raw
    ACK/cursor observables and requires exact equality with the uninterrupted
    control.

`scripts/sqlite_rollback_matrix.py` implements the canonical plan, the exact
barrier controller, and strict matrix-receipt validation. Its `plan` command
emits an artifact marked `plan-not-execution-evidence`; it never creates a
placeholder execution receipt.

`scripts/run-stock-sqlite-rollback-matrix.py` is the fail-closed real runner.
It uses the source-locked `seed.sql`, `transaction.sql`, and `cursor.sql`
directly, drives Wanco checkpoint/restore in the locked container image, seals
the migration manifest and authority proofs, snapshots the complete provider
namespace, and invokes the independent native-SQLite oracle. `--only-cell` is
explicitly a development mode and never publishes a matrix receipt.

## Uninterrupted control

A full run first executes the same stock seed, transaction, and ordered cursor
readback without a compute or provider handoff. It snapshots that provider
namespace and passes it through the same native oracle used by every migrated
cell. The control is not a constant fixture: its ACK set comes from raw client
stdout, its cursor projection comes from all emitted `VISA_ROW` terminals, and
its database projection comes from the native oracle's materialized namespace.

The compact receipt embeds the native oracle projection and an
`equivalence_projection` derived from both sources. The standalone validator
reconstructs this projection independently. Each migrated cell must be
internally consistent and then exactly equal to the control on logical account
and transaction contents, integrity/schema/balance/transaction invariants,
acknowledgements, and final cursor-visible rows. The source-prefix length is
excluded from equivalence because it identifies the active-cursor cut rather
than final behavior.

## Process crash and source abort

Before a full matrix can publish, the runner executes the two provider
kill/reopen cases that qualify durable response replay and `fd_sync`/
`fd_datasync` under the provider-process-crash model. Their report explicitly
retains power loss, torn sectors, and device write reordering as nonclaims.

The pre-commit abort path is one integrated driver qualification. A real Wanco
run checkpoints at the partial-journal cut, then the production provider and
compute adapters drive `FileDriverRecordStore` through freeze, export, and
manifest seal. Before touching the source provider, the driver uses the same
locked, fsynced authority CAS as ownership commit to publish the irreversible,
manifest-bound `source_retained` terminal. Exactly one of `source_retained` and
`ownership_committed` can advance the initialized generation-one authority to
generation two. The retained proof is durably copied into the driver record
before provider resume.

The runner injects coordinator death after source-provider `resume` succeeds
but before the pending action is completed in the driver record. A fresh
coordinator opens that same record and terminal authority, replays the
idempotent provider operation, and restores the same Wanco checkpoint under the
distinct source-restore client with a command that binds both the staged AOT and
the checkpoint. A third fresh client then executes the full ordered cursor
readback against the resumed source provider; the source-abort transcript must
therefore satisfy the same ACK, row, terminal, and native-oracle equivalence
projection as the uninterrupted control. Before restart, the runner retains the
canonical pending record as independent evidence rather than replacing it with
a summary constant.
Absence of a commit proof or a transient `uncommitted` observation is never
permission to resume.

The negative control uses a separate record, adapter binding, and authority
instance. That authority is initialized and advanced to a valid manifest-bound
`ownership_committed` terminal through the production CAS API; source resume
must fail while the real provider remains frozen. Neither terminal authority is
rewritten or reset for the other control. The live record must finish at
`source_resumed`, and the
resulting transaction must still emit one raw ACK and pass a new namespace
snapshot plus native-SQLite oracle. Fake-driver tests and provider-only
`resume` are not matrix evidence.

## Lost-response cell

The lost-response cell intentionally stops at provider phase `triggered`,
after the effect and response are durable but before guest completion. A
transport injector must drop the first response and retain its injection
trace. The bridge's bounded transport retry must send the identical encoded
request using the same source `client`, `sequence`, and `effect`. The provider
returns the cached response, the guest materializes it, sends
`GuestCompletion`, reaches `held`, and checkpoints. The provider effect count
must be unchanged by the retry.

No fresh-client uncertain replay is permitted. A separate negative control
kills source compute while the barrier is still `triggered`; migration must be
rejected by the incomplete-delivery drain gate. The normal cell may create a
fresh destination process client only after the source request reaches
`held`, the controller releases `checkpoint`, and all request completions are
drained. This uses the strict drain alternative to a cross-process stable
operation ID.

## Evidence validity

A valid `visa-stock-sqlite-rollback-journal-matrix-v10` receipt contains one
uninterrupted control and exactly eight
`visa-stock-sqlite-rollback-journal-cell-v5` cells in canonical order. Each
cell binds its plan entry, exact barrier
effect, nonempty compute checkpoint, four-state handoff, namespace snapshot,
raw per-segment stdout/stderr/exit status and parsed ACK/cursor terminals,
stdout-derived expected-ACK input,
an accepted independent-oracle report, and an independently reconstructed
control-equivalence projection. The control and every cell retain
receipt-relative copies of each role-ordered application run, the reconstructed
raw client transcript, canonical expected-ACK input, verdict-free namespace
snapshot, and original native-oracle report. The active-cursor prefix is
rederived from the retained `source` run rather than a second runner-produced
copy. The standalone validator opens those files without following symlinks,
verifies their exact hashes, sizes, zero exit statuses, quiet ordinary segments,
and closed Wanco checkpoint/restore diagnostic grammar, reconstructs the
transcript from the individual stdout streams, reparses the application
terminals, and reruns the bound oracle binary over private copies of the
retained snapshot and ACK input. It therefore does not accept runner-generated
summaries in place of the raw observations. The
top-level input chain also binds the SQLite and Wanco source locks and build
receipts, stock Wasm and AOT, provider, migration binder and migration driver
binaries, oracle binary,
the stock Wasm import trace, an exact clean-tree and full-HEAD projection, the complete
twelve-case O0/O1/O2 typed-restore qualification, provider
kill/reopen qualification, and
`visa-sqlite-source-abort-reconciliation-v3` qualification.
Provider recovery retains the exact Cargo test stdout, stderr, and canonical
process report; the outer validator reparses the two named test terminals and
the `2 passed, 0 failed` harness terminal. Source-abort recovery retains the
application segments, checkpoint, client transcript, namespace snapshot,
native-oracle report, pending and final driver records, crash marker, Wanco
started/completion receipts, source-exit receipt, authority states, adapter
bindings, and integrated driver report. The validator reparses those documents,
reconstructs the client transcript, decodes the checkpoint envelope and LZ4
memory block, reruns the native oracle, and checks the pending-to-resumed
transition rather than accepting the runner's qualification summary.
The validator opens the retained provider capsule as schema-5 SQLite state and
rederives its frozen cut status. For every control, migrated cell, and
source-abort run, it also binds the top-level effect count and effect frontier to
the snapshot summary decoded by the rerun native oracle; re-sealing only the
runner summaries cannot move those counters.
The WASI provider protocol v3.0 status projection carries
`completed_barrier` and `completed_barrier_effect`. The validator requires both
to remain empty at the frozen `checkpoint_released` cut, binds the activated
destination and source-abort resume to the exact checkpoint token/effect, and
binds each continuation witness to the exact token/effect returned by its
atomic `BarrierRelease(continue)` response. It rejects a release observation
reconstructed from a later `status` request.
Source-abort evidence distinguishes the application recovery terminal from the
subsequent namespace-oracle cut. Frozen and provider-resumed counters are
equal; completed source restore plus readback advances both counters; the
stock-SQLite snapshot-gate workload then advances the independently decoded
namespace snapshot beyond that recovery terminal. No fixed observer-hostcall
delta is part of the contract.
The typed-corpus v5 manifest contains no observed values or verdict. It
references retained process observations, control/checkpoint/restore stdout
and stderr, protobuf checkpoints, the locked source/build receipts, and
post-import causal events through exact relative paths, SHA-256, and size. The
validator safely rereads those raw bytes and independently reconstructs exact
case inventory, process exit status, frame and typed-value observations,
exact-stackmap record counts, checkpoint markers, compressed-memory validity,
wrong-target exclusion, and checkpoint-prefix plus restore-suffix equality to
the uninterrupted control. For each post-import O0/O1/O2 cell it also reparses
the nonce-bound causal event trace against the fixed order; this replaces the
former timing-only checkpoint window. The complete raw bundle is copied into
the final SQLite artifact, and its canonical manifest bytes are digest-bound
as an execution input rather than inferred from a build capability flag.
The validator independently reconstructs both terminal authority documents from
their compact fields, independently reconstructs both adapter-binding receipts
from their retained documents, and requires distinct adapter configurations for
the source-retained and committed controls. It rejects state, proof, receipt,
manifest, adapter, or cross-control binding drift. The validator
rejects missing continuation witnesses, path or occurrence drift, fresh-client
uncertain replays, changed source sequences, increased effect counts on retry,
missing source-death rejection, terminal cursor anchors, an oracle binary that
differs from the bound input, rejected oracle reports, and power-loss
overclaims.

A receipt is published only after the real stock binary, typed Wanco restore,
same-request lost-response retry and drain rejection, all eight handoffs, all
ten oracle runs (one uninterrupted control plus eight migrated cells, followed
by one source-abort recovery oracle), provider kill/reopen qualification, and
source-compute abort reconciliation complete. The `plan` subcommand remains
explicitly non-evidence; the real runner's compact v10
receipt is the validation input.
