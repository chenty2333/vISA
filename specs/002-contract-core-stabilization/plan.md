# Implementation Plan: Contract Core Stabilization

**Branch**: `not branch-bound` | **Date**: 2026-06-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/002-contract-core-stabilization/spec.md`

## Summary

Implement the Phase 2 Contract Core Stabilization slice from the accepted vISA
semantic roadmap. The technical approach is to stabilize the contract-visible
effect language and validation model around Phase 2-owned semantic units:
object identity, generation, graph edges, capability authority, wait state,
event evidence, trap attribution, cleanup, guest memory, stable views, and
graph validation. Machine-readable validation evidence will reuse existing
artifact or migration package-shaped structures as a feature-local contract
evidence carrier, without claiming artifact execution, profile-gate
completion, real substrate behavior, frontend compatibility breadth, or
cross-ISA migration behavior.

## Technical Context

**Language/Version**: Rust workspace using the nightly toolchain declared in
`rust-toolchain.toml`; planning artifacts are Markdown.

**Primary Dependencies**: `contract_core`, `semantic_core`,
`contract_validate`, `artifact_manifest`, `visa_profile`, existing Spec Kit
artifacts, archived semantic-contract background under
`docs/archive/achieve/specs/semantic-contract-v0.1/`, and Docker validation
guidance in `docs/DOCKER.md`.

**Storage**: Rust data structures and package-shaped manifest records in the
workspace; no new persistent service storage is planned for this feature.

**Testing**: Focused `cargo test` for affected core crates; Docker gates from
`docs/DOCKER.md` when workspace parity, target components, or conformance
evidence require container validation. The planned validation surface must
include positive and negative scenarios for every Phase 2-owned coverage unit.

**Target Platform**: Repository-local Rust workspace and semantic-model
validation boundary; no new runtime target, frontend personality, substrate
hardware, or migration target claim.

**Project Type**: Rust library workspace plus Spec Kit planning and validation
feature.

**Performance Goals**: No runtime performance claim. Reviewer-facing goals are:
100% Phase 2-owned coverage units represented in the coverage matrix, 100%
validation claims naming their weakest evidence boundary, and scope
classification against Feature 001 in under 10 minutes.

**Constraints**: Do not expand scope to Phase 3 artifact/profile gates, Phase 4
personality normalization, Phase 5 substrate authority, or Phase 6 snapshot and
cross-ISA portability. Do not treat raw host page tables, register frames,
native pointers, substrate bindings, frontend ABI handles, CLI formatting, or
private runtime state as semantic truth. The Phase 2 evidence shape is
feature-local and does not establish a post-completion compatibility policy.

**Scale/Scope**: One Feature 002 Spec Kit directory plus targeted changes in
core contract/semantic validation crates during implementation. Exhaustive
coverage applies only to Phase 2-owned object kinds, edge modes, command areas,
and state transitions.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Spec Kit First**: PASS. The active source of truth is
  `specs/002-contract-core-stabilization/`; archived material is background.
- **Semantic Contract Integrity**: PASS. The spec and this plan make identity,
  authority, capability, lifetime/generation, trap, wait, cleanup, guest
  memory, and evidence semantics explicit before implementation.
- **Evidence Before Claims**: PASS. The maximum claim for this feature is
  semantic-model evidence with machine-readable records; stronger claims are
  explicitly deferred.
- **Complete Accepted Scope**: PASS. Completion requires exhaustive Phase
  2-owned coverage units, not placeholder or sample-only validation.
- **Durable Documentation**: PASS. Current decisions are captured in Spec Kit
  artifacts; long-lived archived docs are referenced only as historical
  semantic background.

## Project Structure

### Documentation (this feature)

```text
specs/002-contract-core-stabilization/
├── plan.md
├── spec.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── contract-core-evidence.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
crates/core/
├── contract_core/
│   └── src/lib.rs
├── semantic_core/
│   ├── src/contract_graph.rs
│   ├── src/graph/command/
│   ├── src/graph/guest_memory.rs
│   ├── src/guest_memory.rs
│   └── src/tests/
├── contract_validate/
│   ├── src/lib.rs
│   ├── src/migration.rs
│   ├── src/audit.rs
│   └── src/tests/
├── artifact_manifest/
│   ├── src/artifact_bundle.rs
│   ├── src/boundary.rs
│   ├── src/semantic_snapshot.rs
│   ├── src/target_runtime.rs
│   └── src/views_events/
└── visa_profile/
    └── src/lib.rs

docs/
├── DOCKER.md
└── archive/achieve/specs/semantic-contract-v0.1/
```

**Structure Decision**: Feature 002 plans core Rust library and validation
work. `contract_core` owns stable effect language records and evidence-level
terms; `semantic_core` owns in-memory ledger behavior and graph validation;
`contract_validate` owns package-shaped validation/audit checks; and
`artifact_manifest` supplies the feature-local evidence carrier shape. Runtime
executors, frontend personalities, substrate backends, and migration behavior
are context only unless a task needs them as generic evidence-shape references.

## Phase 0 Research Output

Research decisions are consolidated in [research.md](./research.md). They
resolve the evidence carrier, compatibility commitment, exhaustive coverage
scope, crate ownership, validation strategy, and roadmap deferrals with no
remaining unresolved clarification items.

## Phase 1 Design Output

- Data model: [data-model.md](./data-model.md)
- Contract: [contracts/contract-core-evidence.md](./contracts/contract-core-evidence.md)
- Validation guide: [quickstart.md](./quickstart.md)
- Agent context: `AGENTS.md` managed Spec Kit block points to this plan.

## Constitution Check (Post-Design)

- **Spec Kit First**: PASS. Plan, research, model, contract, and quickstart
  are all under the active Feature 002 directory.
- **Semantic Contract Integrity**: PASS. Design artifacts preserve Phase 2
  semantic ownership and later-phase exclusions.
- **Evidence Before Claims**: PASS. The contract and quickstart require
  weakest-boundary claims and reject artifact/profile, substrate, frontend, and
  migration overclaims.
- **Complete Accepted Scope**: PASS. The coverage matrix and validation guide
  make exhaustive Phase 2-owned coverage a completion condition.
- **Durable Documentation**: PASS. Durable planning facts are current Spec Kit
  artifacts; archived docs remain background.

## Complexity Tracking

No constitution violations require justification.
