# vISA SQLite namespace oracle

`visa-sqlite-oracle` is an independent, native-SQLite observer for the stock
accounts workload. Its vISA-facing input is exactly one serialized
`visa_wasi_protocol::NamespaceSnapshot` v2. It does not read a provider database,
provider receipt, migration-runner report, terminal, assertion, or producer
verdict.

The oracle performs four steps:

1. Decode the postcard snapshot and independently validate its version,
   canonical encoding/order, paths, objects, byte lengths, references,
   descriptors, locks, unlinked-open objects, and the nonzero shape of the
   opaque effect-frontier anchor.
2. Rebuild every linked namespace path under a mode-0700 temporary root.
   Regular-file hard links remain hard links. Directories, symlinks, rollback
   journals, dotfile lock directories, SQLite temporary files, and all other
   paths are retained. Unlinked objects held by descriptors are represented
   under `unlinked/<object-id>` rather than invented guest paths. Raw
   descriptor/lock/path/metadata state is written to `namespace-state.json`.
3. Copy the selected main database plus any adjacent `-journal`, `-wal`, and
   `-shm` files into a second analysis directory. Only this disposable copy is
   opened by bundled native `rusqlite`, so journal recovery or SQLite cleanup
   cannot modify the reconstructed namespace.
4. Emit a deterministic JSON report containing `integrity_check`,
   `foreign_key_check`, sorted logical rows, stock-schema checks, conserved and
   nonnegative balances, positive transfer amounts, unique transaction IDs,
   an exact comparison with an external acknowledgement set, and a compact
   native `visa-sqlite-semantic-projection-v1` over those rows and invariants.

Run it with:

```text
cargo run -p visa-sqlite-oracle -- \
  namespace.snapshot expected-acks.json workload/bank.db
```

Exit status is zero only when every structural and SQLite check passes, one
for a valid report with rejected findings, and two for CLI or local I/O usage
errors. See `SCHEMA.md` for the workload and JSON contracts.

## Boundary

The materialized tree is an inspection representation, not a restored WASI
provider. Stable object aliases and complete bytes are recreated; uid, gid,
timestamps, virtual descriptor offsets/rights, and virtual lock ownership are
preserved in `namespace-state.json` rather than asserted against the host
kernel. Native SQLite is therefore an independent logical database oracle,
not proof that the destination provider restored live descriptors or locks.
The initial stock baseline is rollback-journal/single-process; WAL sidecars are
copied defensively but shared-memory continuity is not claimed.
The snapshot does not contain the provider effect ledger, so this oracle cannot
and does not recompute `effect_frontier`; it only rejects a zero anchor when the
snapshot declares one or more effects.
