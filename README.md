# vISA

vISA is the portable semantic-continuation layer of the Semantic World
architecture. It carries explicit portable state and continuity requirements
across a runtime or provider change, then validates that a prepared runtime
may continue.

Portable state is not a serialization of native execution. File descriptors,
sockets, native pointers, credentials, capabilities, physical addresses, DMA
state, and runtime- or provider-private handles remain host-local. A
destination must obtain fresh bindings and equal-or-narrower authority from
the authority that owns them.

## Ownership boundary

vISA owns continuity scope, state lineage, continuity profiles, portable
snapshots, runtime semantic safe points, and continuation recovery. TheKernel
owns worlds, provider generations, capabilities, native resources, admission,
and execution fences. Nexus/CSER owns escaped effects, custody, outcomes,
physical claims, settlement, and retirement. vISA coordinates these systems
through exact receipts without becoming a second ledger.

## Workspace

The implementation is intentionally small:

- `visa-core`: `no_std + alloc` contract, portable snapshot vocabulary, exact
  receipts, lineage, and a pure preflight/apply reducer;
- `visa-coordinator`: durable pending operations, exact lost-ack queries,
  restart discovery, structured process-local diagnostics, deterministic
  control-path counters, opaque runtime tokens, and atomic lineage updates;
- `visa-profile`: typed portable-state codecs and resource rebind semantics;
- `visa-wasi`: a real Wasmtime Component frontend with cooperative freeze,
  restore, and activation gating;
- `visa-reference`: SQLite-backed continuation store, authority, durable KV
  provider, and the end-to-end reference path.

There is no compatibility layer for the removed implementation. The current
contract is free to change while the project is under development.

## First reference path

The reference test runs one continuation through the real coordinator:

1. freeze a source Wasmtime Component at a semantic safe point;
2. encode only typed counter/session state and a logical durable-KV
   requirement;
3. ask the SQLite authority to prepare a fresh destination binding in the
   next provider generation;
4. atomically fence the source and transfer authority to a closed destination
   binding;
5. recover a deliberately lost commit acknowledgement by querying the exact
   durable operation ID;
6. restore and activate a fresh Wasmtime instance, then continue execution.

The reference safe point first stops guest dispatch, then atomically captures
the logical KV revision and closes provider dispatch for every clone of the
source binding. Commit permanently fences that source; destination provider
dispatch remains closed until the freshly restored runtime passes its exact
activation gate. Runtime instances, SQLite connections, provider handles, and
capabilities are never serialized into portable state.

Destination release uses two gates: the guest first validates the exact
commit while business dispatch remains closed; the authority durably records
one admitted activation while provider dispatch still denies requests; the
guest opens its local dispatch; and the authority finally confirms the permit
as activated. Only that final state admits destination provider calls. The
durable permit lets a restarted coordinator resolve a lost activation
acknowledgement without creating a second runtime owner. Exact
source-restoration receipts likewise prevent a repeated `recover()` call from
replaying an old snapshot over resumed work. If the restored source's host
process later disappears, that is a new runtime fault: the durable receipt
completes the old continuation but never synthesizes a live process or grants
authority to replay its old snapshot.

Source capture now has an explicit durability capability. The reference
runtime implements `AuthorityDurableQueryable`: it stores the sealed snapshot,
safe-point receipt, and capture receipt under the exact capture operation
before acknowledging the coordinator. It durably arms that operation before
freezing the source, so a crash between freeze and sealed-state persistence is
reported as `Indeterminate`, never as retryable absence. If an acknowledgement
and the whole source process disappear after capture persistence, a fresh
coordinator discovers the unfinished continuation, queries the same operation,
validates the exact receipt, and continues without calling capture again. A
queried result whose coordinator CAS acknowledgement is lost also remains a
query, never a duplicate capture.

An embedding that can only return process-local capture state declares
`ProcessLocal`. An indeterminate capture then becomes the explicit
`ProcessLocalCaptureDualCrashRisk` recovery requirement; it is never hidden
behind a promise that the runtime cannot satisfy. Missing or corrupt durable
facts remain recovery requirements or fatal receipt conflicts rather than
being guessed into success, absence, retry, or abort.

This first profile deliberately excludes unresolved escaped effects, timers,
networking, transparent native-process migration, and direct TheKernel or
Nexus integration. Unknown external outcomes fail closed. Future World,
runtime, authority, and effect integrations implement the narrow coordinator
ports without moving their authority into vISA.

## Diagnostics and measurement

Embeddings may use the structured step API to observe the current control
stage, exact operation, capture capability, recovery cause, rejection text,
and qualitative retry/backoff hint. These diagnostics are process-local and
never become authority facts. `discover_unfinished` supplies restart work from
the durable record store, while deterministic counters expose loads, CAS,
reducer applications, external calls, and exact queries.

Timing is opt-in and lives only in the reference measurement harness; the
ordinary guest/provider path has no vISA probes. The release runner measures a
real SQLite/Wasmtime continuation with warmup and median/p95 reporting:

```sh
cargo run --release -p visa-reference --example control_path_measure -- \
  --warmup 2 --samples 12 --max-coordinator-ratio-pct 35
```

The release gate compares coordinator-owned record/reducer/dispatch work with
aggregate external control work (component preflight and instantiation,
runtime capture, resource rebind/restore, authority prepare/commit,
activation, and exact recovery query). The report also exposes the stricter
in-flow ratio, which excludes preflight and instantiation, so slow setup cannot
hide control-path overhead. Both are reproducible local engineering signals,
not portable latency guarantees. Ordinary guest and provider calls do not
enter the coordinator.

## Development

The repository pins Rust 1.95.0.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p visa-core --no-default-features
cargo check -p visa-profile --no-default-features
```

## Project guidance

`AGENTS.md` contains the repository operating rules. `maproom/` contains the
current terrain, route, basecamp, and verified hazards. Those files are the
current project context; old qualification and publication material has been
removed from the active tree and remains available through Git history.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
