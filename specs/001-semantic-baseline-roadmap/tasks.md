# Tasks: Semantic Baseline Roadmap

**Input**: Design documents from `specs/001-semantic-baseline-roadmap/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/semantic-baseline-package.md`, `quickstart.md`

**Tests**: No new test suite is requested. Validation tasks use the existing repository checks and quickstart commands appropriate to documentation and Spec Kit artifacts.

**Organization**: Tasks are grouped by user story so the Phase 1 semantic-baseline package can be completed and reviewed incrementally.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the active feature paths and managed Spec Kit context before story work begins.

- [X] T001 Verify `.specify/feature.json` points to `specs/001-semantic-baseline-roadmap`.
- [X] T002 Verify `AGENTS.md` managed Spec Kit block points to `specs/001-semantic-baseline-roadmap/plan.md`.
- [X] T003 [P] Verify required artifact inventory in `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T004 [P] Verify specification checklist state in `specs/001-semantic-baseline-roadmap/checklists/requirements.md`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Align the shared planning artifacts that all user stories depend on.

**Critical**: No user story work should begin until this phase is complete.

- [X] T005 [P] Consolidate Phase 1 evidence, archive-handling, and validation decisions in `specs/001-semantic-baseline-roadmap/research.md`.
- [X] T006 [P] Ensure all baseline entities, validation rules, and a concrete semantic-claim traceability matrix or list covering current code anchors, historical sources, and documented assumptions are defined in `specs/001-semantic-baseline-roadmap/data-model.md`.
- [X] T007 [P] Ensure required artifacts, scope limits, evidence limits, and rejection cases are defined in `specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md`.
- [X] T008 Align constitution checks, technical context, and structure decision in `specs/001-semantic-baseline-roadmap/plan.md`.
- [X] T009 Align validation commands and expected outcomes with Phase 1 scope in `specs/001-semantic-baseline-roadmap/quickstart.md`.

**Checkpoint**: Foundation ready. User story phases can proceed independently after this point.

---

## Phase 3: User Story 1 - Establish Semantic Baseline (Priority: P1)

**Goal**: Provide one current Spec Kit source that states what vISA is, what it is not, which semantic facts are stable enough to plan against, and what first increment can be built next.

**Independent Test**: A reviewer can read the baseline and answer the identity, boundary, layer ownership, validation level, and first-increment questions without opening historical workflow notes.

### Implementation for User Story 1

- [X] T010 [US1] Strengthen vISA identity and non-goal language in `specs/001-semantic-baseline-roadmap/spec.md`.
- [X] T011 [P] [US1] Ensure Semantic Baseline fields cover identity, core semantic boundary ownership and exclusions, semantic families, frontend/personality normalization, guest-memory semantic truth, profile compatibility distinctions, validation level, and first increment in `specs/001-semantic-baseline-roadmap/data-model.md`.
- [X] T012 [P] [US1] Ensure baseline content requirements and rejection cases reject archived workflow migration in `specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md`.
- [X] T013 [US1] Cross-check that historical sources are background only across `specs/001-semantic-baseline-roadmap/spec.md`.
- [X] T014 [US1] Confirm the first implementable increment excludes runtime behavior in `specs/001-semantic-baseline-roadmap/spec.md`.
- [X] T015 [US1] Run artifact-presence and marker-scan commands from `specs/001-semantic-baseline-roadmap/quickstart.md`.

**Checkpoint**: User Story 1 is independently reviewable as the MVP baseline.

---

## Phase 4: User Story 2 - Plan Long-Term Semantic Evolution (Priority: P2)

**Goal**: Split the long-term roadmap into coherent phases that future work can map to by semantic layer, phase, and evidence boundary.

**Independent Test**: A planned feature can be mapped to one roadmap phase, one primary semantic layer, and one expected evidence boundary.

### Implementation for User Story 2

- [X] T016 [US2] Ensure all six roadmap phases include purpose, included semantic families, entry condition, exit condition, and expected evidence boundary in `specs/001-semantic-baseline-roadmap/spec.md`.
- [X] T017 [P] [US2] Ensure Roadmap Phase fields and state transitions are complete in `specs/001-semantic-baseline-roadmap/data-model.md`.
- [X] T018 [P] [US2] Ensure the roadmap ownership decision rejects crate-only and frontend-breadth organization in `specs/001-semantic-baseline-roadmap/research.md`.
- [X] T019 [US2] Cross-check roadmap phase ordering against Layer Ownership Map responsibilities in `specs/001-semantic-baseline-roadmap/data-model.md`.
- [X] T020 [US2] Confirm Phase 1 scope does not require changes under `crates/`, `scripts/`, `Dockerfile`, `Cargo.toml`, `Cargo.lock`, `compose.yaml`, or `compose.ci.yaml` by running the scope-drift command in `specs/001-semantic-baseline-roadmap/quickstart.md`.

**Checkpoint**: User Story 2 is independently reviewable as a roadmap classification guide.

---

## Phase 5: User Story 3 - Validate Semantic Claims (Priority: P3)

**Goal**: Ensure every phase and baseline claim states the evidence required before vISA can claim semantic, portable-artifact, substrate, frontend-personality, migration, or performance behavior.

**Independent Test**: A reviewer can classify a claim by evidence level and reject claims that lack the required machine-readable evidence.

### Implementation for User Story 3

- [X] T021 [US3] Ensure Evidence Claim fields and validation rules name weakest evidence boundary and stable evidence roots in `specs/001-semantic-baseline-roadmap/data-model.md`.
- [X] T022 [P] [US3] Ensure Evidence Contract rejects portable artifact execution and real target substrate claims for Phase 1 in `specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md`.
- [X] T023 [P] [US3] Ensure quickstart documents Docker gates only for Rust, Cargo, kernel, substrate, or parity-sensitive changes in `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T024 [US3] Align success criteria with weakest-boundary claim rules in `specs/001-semantic-baseline-roadmap/spec.md`.
- [X] T025 [US3] Cross-check Evidence Before Claims constitution compliance in `specs/001-semantic-baseline-roadmap/plan.md`.

**Checkpoint**: User Story 3 is independently reviewable as an evidence-boundary gate.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation and cleanup across the whole Phase 1 package.

- [X] T026 [P] Run required-artifact validation commands from `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T027 [P] Run `AGENTS.md` plan-pointer validation command from `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T028 [P] Run unresolved-marker scan from `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T029 [P] Run Phase 1 scope-drift scan from `specs/001-semantic-baseline-roadmap/quickstart.md`.
- [X] T030 Run `git diff --check -- specs/001-semantic-baseline-roadmap .specify/feature.json AGENTS.md`.
- [X] T031 Revalidate `specs/001-semantic-baseline-roadmap/checklists/requirements.md` after story and validation edits, then update task wording if findings require changes in `specs/001-semantic-baseline-roadmap/tasks.md`.

---

## Dependencies & Execution Order

### Phase Dependencies

- Setup (Phase 1): no dependencies; start immediately.
- Foundational (Phase 2): depends on Phase 1; blocks all user stories.
- User Story 1 (Phase 3): depends on Phase 2; MVP.
- User Story 2 (Phase 4): depends on Phase 2; can run in parallel with US1 after foundation, but priority order is US1 then US2.
- User Story 3 (Phase 5): depends on Phase 2; can run in parallel with US1/US2 after foundation, but priority order is US1 then US2 then US3.
- Polish (Phase 6): depends on the desired user stories being complete.

### User Story Dependencies

- US1 Establish Semantic Baseline: independent after foundation.
- US2 Plan Long-Term Semantic Evolution: independent after foundation, but should preserve the semantic boundary established by US1.
- US3 Validate Semantic Claims: independent after foundation, but should preserve Phase 1 evidence limits from US1 and roadmap phase limits from US2.

### Parallel Opportunities

- T003 and T004 can run in parallel after T001 and T002 are understood.
- T005, T006, and T007 can run in parallel because they update different files.
- T011 and T012 can run in parallel within US1.
- T017 and T018 can run in parallel within US2.
- T022 and T023 can run in parallel within US3.
- T026, T027, T028, and T029 can run in parallel during final validation.

---

## Parallel Example: User Story 1

```text
Task: "T011 [P] [US1] Ensure Semantic Baseline fields cover identity, core semantic boundary ownership and exclusions, semantic families, frontend/personality normalization, guest-memory semantic truth, profile compatibility distinctions, validation level, and first increment in specs/001-semantic-baseline-roadmap/data-model.md"
Task: "T012 [P] [US1] Ensure baseline content requirements and rejection cases reject archived workflow migration in specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md"
```

## Parallel Example: User Story 2

```text
Task: "T017 [P] [US2] Ensure Roadmap Phase fields and state transitions are complete in specs/001-semantic-baseline-roadmap/data-model.md"
Task: "T018 [P] [US2] Ensure the roadmap ownership decision rejects crate-only and frontend-breadth organization in specs/001-semantic-baseline-roadmap/research.md"
```

## Parallel Example: User Story 3

```text
Task: "T022 [P] [US3] Ensure Evidence Contract rejects portable artifact execution and real target substrate claims for Phase 1 in specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md"
Task: "T023 [P] [US3] Ensure quickstart documents Docker gates only for Rust, Cargo, kernel, substrate, or parity-sensitive changes in specs/001-semantic-baseline-roadmap/quickstart.md"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational.
3. Complete Phase 3: User Story 1.
4. Stop and validate User Story 1 independently using `specs/001-semantic-baseline-roadmap/quickstart.md`.

### Incremental Delivery

1. Deliver US1 to establish the current baseline.
2. Deliver US2 to make the long-term roadmap actionable.
3. Deliver US3 to lock evidence-boundary validation.
4. Complete Polish validation before considering `/speckit-implement` complete.

### Scope Guard

- Do not edit runtime crates, Docker or CI scripts, archived documents, or validation harnesses for this Phase 1 package.
- If a task appears to require runtime behavior, split it into a later roadmap phase and record the scope decision in `specs/001-semantic-baseline-roadmap/plan.md`.
