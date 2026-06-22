# vISA Semantic Identity Contract

## Goal
Stabilize `ObjectRef`, generation, tombstone, and live/historical edge semantics as durable vISA contract interfaces rather than implementation details.

## Accepted Scope
Define and verify identity rules for core contract objects, live versus historical generation edges, tombstone semantics for dead objects and retired generations, cleanup-after-history references, validator positive/negative coverage, schema versioning, and fixture migration strategy. Prefer durable docs only for stable project knowledge; use tests and fixtures as executable evidence. Do not change core semantic meaning without strong validator coverage.

## Current Plan
Complete. Move this task to `tasks/done/`.

## Progress
Policies under `docs/policies/` were read. Audit found existing `ObjectRef`, tombstone, live/historical edge checks, and conformance schema gates. Added focused semantic-core tests for core object kind names and `object_ref()` triples, live vs historical generation behavior, tombstone history, trap history generation requirements, and snapshot schema version. Updated trap validator paths to use the shared historical edge checker for `trap->code` and `trap->artifact`. Added `docs/DECISIONS.md` with durable identity, tombstone, schema version, and fixture migration policy.

## Next Actions
Future schema-breaking changes must bump `CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION` and migrate fixtures in the same change.

## Risks
No known remaining Goal 5 risk. Existing kernel dead-code warnings remain outside this goal.

## Result
Semantic identity contract behavior is now covered by focused validator tests and durable decision docs. Verification passed: `cargo fmt --all --check`, `cargo test -p semantic_core`, `cargo test -p visa-conformance`, `git diff --check`, old-name scan, and `sudo scripts/run-docker-ci-gate.sh --ci-cache`.
