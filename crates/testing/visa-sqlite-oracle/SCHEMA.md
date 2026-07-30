# SQLite oracle schemas

## Stock workload database

The oracle recognizes these two application tables. Column order, declared
type, `NOT NULL`, primary key, and both foreign-key bindings are checked.

```sql
CREATE TABLE accounts (
    account_id INTEGER PRIMARY KEY,
    balance INTEGER NOT NULL
);

CREATE TABLE transactions (
    txid TEXT NOT NULL PRIMARY KEY,
    from_account INTEGER NOT NULL REFERENCES accounts(account_id),
    to_account INTEGER NOT NULL REFERENCES accounts(account_id),
    amount INTEGER NOT NULL CHECK(amount > 0)
);
```

Additional application or SQLite tables are allowed. Logical rows are sorted
by their full typed tuples before serialization, independently of SQLite query
planner order or locale. Transaction IDs are compared as case-sensitive UTF-8
strings with SQLite/Rust binary ordering.

The external expected-acknowledgement document is strict JSON:

```json
{
  "schema_version": "visa-sqlite-expected-acks-v1",
  "initial_total_balance": 1000000,
  "acknowledged_txids": ["tx-000001", "tx-000002"]
}
```

`initial_total_balance` is the workload's pre-run conserved balance. It must be
nonnegative. `acknowledged_txids` must contain unique, nonempty UTF-8 strings
of at most 256 bytes. Input order is irrelevant; the report sorts both the
expected list and the transaction-table projection. Acceptance requires exact
list equality, so a lost acknowledged transaction, an unacknowledged durable
transaction, a duplicate, or a NULL all fail.

## Report

`visa-sqlite-oracle-report-v1` contains:

- a snapshot header/count summary;
- the complete byte-path/object projection, descriptor and lock state, SQLite
  sidecars, and separately represented unlinked-open objects;
- native SQLite version and all rows returned by `PRAGMA integrity_check` and
  `PRAGMA foreign_key_check`;
- exact sorted `accounts` and `transactions` rows;
- balance, transaction-ID, amount, and acknowledgement invariants;
- stable finding codes and details.

The report contains no producer-supplied pass bit. Its top-level `accepted`
field is derived only from the snapshot bytes, database contents, and external
expected-acknowledgement document.
