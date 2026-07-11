# Implementation Plan: Stage 1 Spine Modularization

Status: accepted

## Design Commitments

This is a mechanical ownership-preserving refactor. `contract_core`,
`semantic_core`, `visa_runtime::Coordinator`, providers, adapters, runners, and
the independent verifier retain their Stage 1 responsibilities.

The runner is split first so it can provide a stable matrix/evidence harness
while the reducer is moved. Each move must compile and test before the next
responsibility is extracted.

## Target Structure

```text
crates/testing/visa-system/src/
  runner.rs
  runner/
    worker_client.rs
    registry.rs
    provenance.rs
    stage1.rs
    harness.rs
    finalize.rs
    artifacts.rs
    scenarios/{mod,common,success,provider_faults,rejections,recovery}.rs

crates/core/semantic_core/src/
  lib.rs
  reducer/{mod,preflight,transition,authority,effect,handoff,timer}.rs
  restore.rs
  replay.rs
  tests/{mod,support,authority,effect,handoff,replay}.rs
```

The exact file grouping may be simplified when a proposed file would contain
only forwarding code, but responsibility boundaries and private visibility may
not be weakened.

## Delivery Sequence

1. Record the clean Stage 1 focused and system baseline.
2. Extract worker transport, registry, provenance, and run orchestration.
3. Extract case harness, scenario families, finalization, and artifact
   derivation without changing order or assertions.
4. Run the full 31-case system gate and independent verifier.
5. Move reducer tests, restore, and replay behind root re-exports.
6. Move the reducer and then extract transition/preflight and semantic helper
   families while keeping both exhaustive dispatchers centralized.
7. Re-run focused, no-std, full, system, and Docker gates.
8. Tighten internal visibility, file-size reporting, docs, and final audits.

## Compatibility Comparison

Do not compare run-variant fields such as source provenance, bundle ID, paths,
timestamps, PIDs, or whole bundle hashes. Compare:

- registry case IDs and outcomes;
- config and policy digests;
- canonical final and replay state digests;
- normalized semantic traces;
- snapshot and binding receipt semantics;
- ownership, authority, lease, and source-fencing observations;
- fault schedules and assertion names/order; and
- independent verifier acceptance.

## Validation

```sh
cargo test --locked -p semantic_core -p visa-system
cargo check --locked -p semantic_core --target x86_64-unknown-none
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
git diff --check
```

## Constraints

- Preserve statement order in runner finalization and race/fault scenarios.
- Preserve restore and replay validation order and all rejection precedence.
- Preserve vector insertion order because canonical encoding and state digests
  observe it.
- Do not run a system case while modifying a source-provenance input.
- Do not combine these moves with optimization or API redesign.
