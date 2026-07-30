# Stock SQLite rollback-journal workload

This directory builds the official SQLite 3.53.4 amalgamation as a stock WASI
CLI and lowers it through the source-locked Wanco carrier. The upstream
`shell.c`, `sqlite3.c`, `sqlite3.h`, and `sqlite3ext.h` files are verified
against the official release archive and are never patched.

The additional object in `abi/` supplies only WASI compatibility that the
amalgamation expects at link time. `chmod` is forwarded to the vISA metadata
hostcall. WASI cannot implement POSIX `realpath` faithfully without a complete
host namespace traversal, so the optional shell function fails with
`ENOTSUP` instead of returning a false canonical path. The evaluated database
workload does not call that optional function.

SQLite selects its upstream `unix-dotfile` VFS on WASI. A lock is therefore a
provider-owned `<database>.lock` directory, and all lock files, journals,
temporary files, descriptors, and cursors live in the same virtual namespace
as the database. This mode deliberately trades reader concurrency for a stock,
source-unmodified locking path. The separate `visa_wasi_vfs_*` bridge ABI is
available for a future SQLite VFS with fine-grained lock levels; this build
does not claim that the upstream CLI calls that extension.

SQL is imported into the provider and opened by the stock CLI through `.read`;
it is never piped over host stdin. `workload/basic.sql` is the short build
smoke. The rollback-journal matrix uses three separately invocable stock-CLI
segments: `seed.sql` creates 512 fixed-balance accounts at a 512-byte page
size, `transaction.sql` dirties account pages across the B-tree and emits its
unique transaction acknowledgement only after `COMMIT` returns, and
`cursor.sql` emits a 512-row ordered read stream. Separating the segments lets
every exact cut start from the same closed, seeded database without treating
host stdin or runner-generated state as a migrated resource.

Run:

```bash
python3 scripts/check-sqlite-source.py
python3 scripts/test-check-sqlite-source.py
scripts/build-stock-sqlite.sh

# Full clean-SHA application lane: control, eight cuts, raw retention, and
# independent replay validation.
VISA_SYSTEM_EVIDENCE_PARENT=/absolute/new/artifact-root \
  scripts/ci-gate.sh system-stock-sqlite
```

The resulting `receipt.json` binds the official archive, Wasm, Wanco IR and
executable, bridge, toolchain images, actual import surface, and smoke-workload
result. The large intermediate IR is represented by hash and size but is not
retained. The formal matrix retains each role-ordered application segment's
stdout, stderr, and exit status, the reconstructed client transcript,
expected-acknowledgement inputs, namespace snapshots, native-oracle reports,
and the complete raw Wanco typed-restore corpus needed for independent replay;
provider databases, application checkpoints, and compiler scratch remain
disposable. The v7 validator requires a clean exact repository SHA, securely
reads every retained reference, validates the closed Wanco
checkpoint/restore diagnostic grammar, reconstructs and reparses the stock
application output, and reruns the bound SQLite oracle. This is process-crash
and migration test infrastructure. It is not a claim about power loss, torn
sectors, device caches, or write reordering.
