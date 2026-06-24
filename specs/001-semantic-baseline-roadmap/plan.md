# Implementation Plan: Semantic Baseline Roadmap

**Branch**: `not branch-bound` | **Date**: 2026-06-23 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-semantic-baseline-roadmap/spec.md`

**Note**: This plan is for the Phase 1 semantic-baseline package. It produces
current Spec Kit planning artifacts and validation guidance only; it does not
implement runtime behavior.

## Summary

Establish the first executable Spec Kit fact source for vISA's semantic
roadmap. The implementation approach is to preserve the accepted scope as a
documentation and validation increment: refine the active Spec Kit artifacts,
define a source-backed semantic baseline package contract, map the baseline
entities, and document checks that prove the package is ready for task
generation without copying archived workflow or changing runtime code.

## Technical Context

**Language/Version**: Rust workspace using the repository toolchain in
`rust-toolchain.toml`; this feature itself is Markdown/Spec Kit artifact work.

**Primary Dependencies**: Spec Kit files under `.specify/`, repository scripts
under `scripts/`, Docker validation guidance in `docs/DOCKER.md`, archived
semantic background under `docs/archive/achieve/`, and current code anchors
under `crates/`.

**Storage**: Markdown and JSON files in
`specs/001-semantic-baseline-roadmap/`, plus the managed Spec Kit block in
`AGENTS.md`.

**Testing**: Artifact existence checks, unresolved-marker scans,
`git diff --check`, and existing repository checks appropriate to changed
artifacts. Docker gates from `docs/DOCKER.md` are used when Rust/Cargo/kernel
or parity-relevant files change.

**Target Platform**: Repository-local Spec Kit workflow on the vISA Rust
workspace; no runtime target platform changes in Phase 1.

**Project Type**: Rust workspace plus Spec Kit documentation/planning feature.

**Performance Goals**: A maintainer can classify a proposed semantic change by
boundary, layer, phase, and evidence level in under 10 minutes.

**Constraints**: Do not change runtime behavior; do not import archived
workflow as active process; do not claim evidence beyond the weakest validated
boundary; preserve existing unrelated workspace edits.

**Scale/Scope**: One feature directory, one active plan pointer in `AGENTS.md`,
six roadmap phases, the baseline semantic families listed in `SC-003`, and a
single first implementable increment.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Spec Kit First**: PASS. The active source of truth remains under
  `specs/001-semantic-baseline-roadmap/`; archived material is background only.
- **Semantic Contract Integrity**: PASS. The spec and plan make identity,
  authority, capability, lifetime, generation, trap, wait, cleanup, artifact,
  profile, and evidence boundaries explicit before implementation.
- **Evidence Before Claims**: PASS. Phase 1 claims only semantic-model and
  source-backed review evidence, plus existing checks appropriate to changed
  artifacts.
- **Complete Accepted Scope**: PASS. The accepted scope is a complete
  baseline/roadmap package, not a placeholder implementation.
- **Durable Documentation**: PASS. Durable decisions stay in Spec Kit
  artifacts; long-lived docs are referenced only for stable background.

## Project Structure

### Documentation (this feature)

```text
specs/001-semantic-baseline-roadmap/
├── plan.md
├── spec.md
├── research.md
├── data-model.md
├── quickstart.md
├── tasks.md
├── contracts/
│   └── semantic-baseline-package.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```text
.specify/
├── feature.json
├── memory/constitution.md
├── scripts/bash/
└── templates/

AGENTS.md
docs/
├── DOCKER.md
└── archive/achieve/
    ├── specs/
    └── vision/

crates/
├── core/
├── runtime/
├── backend/
├── host/
├── services/
└── testing/
```

**Structure Decision**: Phase 1 modifies only Spec Kit feature artifacts and
the managed Spec Kit section in `AGENTS.md`. Runtime crates, services,
backends, host code, Docker files, and CI scripts are current code anchors and
validation context, not implementation targets for this increment.

## Phase 0 Research Output

Research decisions are consolidated in [research.md](./research.md). They
resolve the Phase 1 evidence level, historical-source handling, artifact
surface, validation strategy, and roadmap ownership model without unresolved
clarifications.

## Phase 1 Design Output

- Data model: [data-model.md](./data-model.md)
- Contract: [contracts/semantic-baseline-package.md](./contracts/semantic-baseline-package.md)
- Validation guide: [quickstart.md](./quickstart.md)
- Task ledger: [tasks.md](./tasks.md)
- Agent context: `AGENTS.md` managed Spec Kit block points to this plan.

## Constitution Check (Post-Design)

- **Spec Kit First**: PASS. The generated artifacts live in the active feature
  directory and are ready for `/speckit-tasks`.
- **Semantic Contract Integrity**: PASS. The data model and contract preserve
  all baseline semantic families and explicit exclusions.
- **Evidence Before Claims**: PASS. The quickstart validates documentation
  readiness and defers stronger runtime claims to later phases.
- **Complete Accepted Scope**: PASS. The Phase 1 package now has plan,
  research, model, contract, quickstart, and checklist coverage.
- **Durable Documentation**: PASS. Current decisions are captured in Spec Kit
  artifacts; no archived workflow is promoted.

## Complexity Tracking

No constitution violations require justification.
