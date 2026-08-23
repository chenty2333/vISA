# vISA

vISA is the portable semantic-continuation layer of the Semantic World
architecture. It moves explicit logical state and continuity requirements
across a runtime or provider change, then validates the exact external facts
that permit a prepared runtime to continue.

Portable state never contains file descriptors, sockets, native pointers,
physical addresses, credentials, capabilities, Wasmtime instances, SQLite
connections, or provider handles. The destination receives fresh host-local
bindings from the authority that owns them.

## Architecture

The active workspace has one dependency direction:

```text
visa-reference  ->  visa-coordinator  ->  visa-core
    std                 no_std              no_std
```

- `visa-core` contains the portable contract, canonical snapshots and exact
  receipts, plus the pure continuation reducer.
- `visa-coordinator` contains the restartable `plan -> arm -> query/invoke ->
  observe` workflow, atomic lineage-CAS contract, and thin runtime/authority
  dispatcher.
- `visa-reference` is a non-published Counter/KV vertical with a private
  concrete profile, fresh Wasmtime Component instances, a SQLite record store,
  binding authority, and durable provider.

The reference process may host several roles, but their truth remains
separate: the continuation store owns records and lineage, the binding
authority owns bindings and execution fences, the provider owns KV values,
and the runtime owns Wasmtime instances and safe points.

## Exact recovery protocol

Every external action is assigned a stable operation ID and its full request is
durably armed before invocation. Recovery first queries that exact operation:

- `Applied` must carry a receipt for the same operation and request digest;
- `Absent` before first invocation is the only authority to invoke that
  operation ID; after an unknown invoke, exact absence closes the old pending
  operation and a retry must be armed separately;
- `Indeterminate` becomes an explicit recovery requirement;
- reusing an operation ID with different request material is a conflict.

Source capture is always durable and queryable. The runtime records an armed
capture before freezing; an armed but unsealed capture queries as
`Indeterminate`. Once the sealed snapshot and receipt are durable, a lost
acknowledgement is recovered by query without freezing again.

The continuation path is:

```text
capture
-> prepare bindings and a fresh destination runtime
-> durably commit the source fence, then CAS the canonical lineage successor
-> restore the destination
-> obtain an authority-owned activation permit
-> open the runtime-local activation gate
-> retire the durable source capture
```

Before commit, rejection or operator abort cleans up the destination and
restores the source through exact operations. After commit, the source is
permanently fenced; later failures can only enter destination recovery.

The first vertical has one exact `durable-kv-cas` Component import backed by a
fresh host-local binding. Other Component imports fail preflight, and escaped
effects must be explicitly empty. Nexus/CSER effect continuity will be designed
only when a real consumer and authority protocol exist.

## Toolchain

[`rust-toolchain.toml`](rust-toolchain.toml) is the only Rust toolchain source.
It follows rolling `nightly` and requests only `rustfmt` and `clippy`; the
workspace does not declare a second MSRV or repeat a compiler version in CI.

To move to the newest available nightly:

```sh
rustup update nightly
rustc --version --verbose
```

`Cargo.lock` still fixes dependency resolution. If a future compiler update
breaks the project, fix the active code against that nightly rather than adding
a compatibility toolchain or parallel build path.

## Development

CI is one job and uses only Cargo's native checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo check -p visa-coordinator --no-default-features --locked
```

There is no xtask, task runner, generated fault matrix, measurement gate,
coverage pipeline, artifact upload, compatibility workspace, or release
workflow. Tests remain close to pure reducers, with one Cargo integration
target for the real SQLite/Wasmtime vertical and its durability cuts.

## Project guidance

`AGENTS.md` contains the repository operating rules. `maproom/` is user-owned
project context and is not rewritten as routine progress bookkeeping.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
