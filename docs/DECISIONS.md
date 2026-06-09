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
