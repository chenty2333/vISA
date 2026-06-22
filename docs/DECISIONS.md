# vISA Decisions

## Semantic Identity Contract

`ObjectRef` is a contract-visible identity triple: object kind, non-zero object
id, and exact generation. The kind string is part of the snapshot vocabulary;
changing or removing a core kind string is a schema-affecting change.

Live edges name the current live generation and must not point at tombstoned,
dead, retired, revoked, or inactive objects. Historical and cleanup-effect edges
must carry the exact target generation. A historical or cleanup-effect edge may
name a retired generation only when the snapshot carries the matching tombstone.

Tombstones preserve the identity of a generation after cleanup or retirement.
They do not make that generation live again. Live ownership edges to tombstones
are invalid; historical evidence edges to matching tombstones are valid.

The contract graph artifact schema is
`contract-graph-snapshot-v0.1`, defined by
`CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION`. Breaking changes to object
identity fields, edge modes, tombstone shape, or required snapshot arrays must
change that schema string.

Fixture migration strategy: tests and conformance fixtures should use the schema
constant for valid snapshots, keep explicit negative fixtures for unsupported
schema versions, and update both fixture shape and validator expectations in the
same change when the schema is bumped.

## Semantic View And Snapshot Contract

ViewV1 and `osctl view --json` are stable external observation APIs. The stable
view envelope is `schema`, `schema_version`, `kind`, `command`, `package`,
`count`, and `items`. Stable object views must preserve `schema`, `kind`, `id`,
`generation`, `state`, `owner`, `references`, `last_transition`, and
`last_error` for store, capability, wait, cleanup, code object, activation,
trap, and hostcall families.

`activation` remains the scheduler/runtime activation view kind. Target runtime
activation records use `activation-record` in the stable collection so existing
`activation` consumers do not silently switch meaning.

Durable API fields are identity, generation, lifecycle state, owner,
contract-visible references, attribution status, profile/hash/signature gate
status, and validation issue classification. Debug/internal fields include raw
runtime structs, host/private page tables, native stack frames, raw device
bindings, debug labels, counts used only to summarize hidden arrays, and prose
notes that are not required for validation.

The contract graph snapshot artifact keeps the stable portable fields
`schema_version`, `claimed_evidence_level`, `artifacts`, `code_objects`,
`stores`, `activations`, `hostcalls`, `traps`, `capabilities`, `waits`,
`cleanup_transactions`, `tombstones`, `external_objects`, and `explicit_edges`.
Unknown top-level fields are invalid until the schema is bumped. Unsupported
schema versions, missing required fields, illegal fields, unsupported restore
records, and evidence-boundary overclaims must stay covered by negative
fixtures.

`ContractGraphSnapshot::portable_subset` keeps portable semantic identity and
artifact runtime records, including artifacts, code objects, stores,
capabilities, target activations, traps, hostcalls, cleanup transactions, tasks,
process-family records, runtime activations, and supported tombstones. It strips
host/device bindings, scheduler projections not rebuilt by restore, external
audit edges, raw window/device state, and records that
`VisaRuntime::restore_portable_subset` cannot rebuild without identity remap.
