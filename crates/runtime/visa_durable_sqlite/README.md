# vISA durable SQLite mechanics

`visa_durable_sqlite` contains the small, transport- and schema-independent
filesystem mechanics shared by vISA durable stores. It does not define a
database schema, identity model, replay ledger, or authority state machine.

The helper deliberately keeps the publication protocol explicit:

- the parent directory and private regular files are checked against the
  current uid and `0700`/`0600` permissions;
- lock and database opens use `O_NOFOLLOW`, and the lock is held with a
  non-blocking exclusive `flock` for the store lifetime;
- SQLite initialization may happen in a nonce-named temporary file, with all
  SQLite sidecars required to be absent before publication;
- the closed database is fsynced and published with Linux `RENAME_NOREPLACE`,
  followed by a parent-directory fsync; and
- failed initialization cleanup is inode-bound, so a changed path is never
  unlinked merely because it has the same name.

Callers own schema creation and all semantic validation. In particular,
`publish_noreplace` does not make an incomplete or un-audited SQLite database
valid; it only enforces the mechanical publication boundary.
