# vISA agent store

`visa_agent_store` is the transport-independent durable identity and process
incarnation store for one vISA agent role. It is deliberately smaller than the
ownership authority store: it does not make ownership decisions, admit effects,
or implement an RPC/replay ledger.

The three operations have intentionally different authority:

* `publish_new` creates a generation-zero store during exact cohort
  initialization;
* `audit_unstarted` checks that an existing store is exact without creating a
  process generation; and
* `reopen_existing` is the only runtime-open operation and durably allocates a
  fresh process nonce/generation in one `BEGIN IMMEDIATE` transaction.

Runtime code cannot reset, adopt, relabel, or recreate an existing store. The
stable identity is the product/cohort/boot/runtime-session/role/logical
incarnation tuple. Process nonce and generation are live-process metadata and
are not part of the stable identity or a future semantic projection digest.

The SQLite schema is an implementation detail of this slice, not a replacement
for the release contract. The mechanical private-file publication lifecycle is
shared with the ownership store through `visa_durable_sqlite`.
