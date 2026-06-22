# vISA Semantic View And Snapshot Contract

## Goal
Stabilize snapshot, ViewV1, osctl view, and fixture restore as durable external observation interfaces.

## Accepted Scope
Define and verify stable portable subset rules for `ContractGraphSnapshot`; stable `osctl`/ViewV1 output for capability, wait, cleanup, activation, trap, store, and code object views; view schema versioning or compatibility strategy; restore fixtures for old snapshots, missing fields, illegal fields, and unsupported records; validator classification for schema, semantic, and evidence-boundary issues; and durable documentation distinguishing API fields from debug/internal fields.

## Current Plan
Complete. Move this task to `tasks/done/`.

## Progress
Policies under `docs/policies/` were read. Stable target-runtime view collections were added for artifact, code-object, activation-record, trap, and hostcall while preserving legacy `activation` as runtime activation. Typed ViewV1 structs now cover CodeObject, Activation, and Trap. Contract validation JSON now classifies schema, semantic, and evidence-boundary issues. Contract graph portable subset tests pin retained runtime artifact records and stripped scheduler/audit/device projections. Conformance artifact validation rejects unsupported snapshot schema, missing fields, illegal fields, unsupported restore records, and boundary overclaims. `docs/DECISIONS.md` records durable view/snapshot API fields and debug/internal boundaries.

## Next Actions
Future ViewV1 or snapshot shape changes must preserve the documented stable envelope/fields or bump schema and migrate fixtures in the same change.

## Risks
View and snapshot shape are external observation contracts. The target activation naming decision intentionally uses `activation-record` for artifact runtime activations to avoid silently changing existing `activation` consumers.

## Result
Semantic ViewV1, `osctl view --json`, contract graph snapshot artifact validation, portable subset behavior, and fixture restore negative cases are now covered by focused tests and durable decision docs. Verification passed: `cargo fmt --all --check`, `cargo test -p semantic_core`, `cargo test -p osctl-view`, `cargo test -p visa-conformance`, `cargo test -p contract_core`, `cargo test -p contract_validate`, `git diff --check`, and old-name scan.
