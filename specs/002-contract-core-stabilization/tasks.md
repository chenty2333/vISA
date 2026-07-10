# Tasks: Contract Core Stabilization

**Input**: Design documents from `specs/002-contract-core-stabilization/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/contract-core-evidence.md`, `quickstart.md`

**Tests**: Included because the feature specification requires positive and
negative validation coverage for every Phase 2-owned semantic family.

**Organization**: Tasks are grouped by user story so each increment can be
implemented and validated against its independent test criteria.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the active Spec Kit source of truth and prepare dedicated
Feature 002 test surfaces before implementation.

- [X] T001 Run the artifact readiness and marker scans from `specs/002-contract-core-stabilization/quickstart.md`
- [X] T002 [P] Inspect current crate ownership boundaries in `crates/core/contract_core/src/lib.rs`, `crates/core/semantic_core/src/contract_graph.rs`, `crates/core/contract_validate/src/lib.rs`, `crates/core/artifact_manifest/src/artifact_bundle.rs`, `crates/core/artifact_manifest/src/boundary.rs`, and `crates/core/artifact_manifest/src/semantic_snapshot.rs`
- [X] T003 [P] Add Phase 2 semantic-core test module wiring in `crates/core/semantic_core/src/tests/core_io.rs` and create `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T004 [P] Add Feature 002 validation test module wiring in `crates/core/contract_validate/src/tests/mod.rs` and create `crates/core/contract_validate/src/tests/contract_core_evidence.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish shared record, carrier, and validator entrypoints that
all user stories depend on.

**Critical**: No user story implementation should begin until this phase is
complete.

- [X] T005 Define the canonical Phase 2 semantic family and coverage-unit registry in `crates/core/contract_core/src/lib.rs`
- [X] T006 Define feature-local artifact-shaped and migration-shaped evidence carrier manifest records in `crates/core/artifact_manifest/src/artifact_bundle.rs`, `crates/core/artifact_manifest/src/boundary.rs`, and `crates/core/artifact_manifest/src/semantic_snapshot.rs`
- [X] T007 Add the `contract_core_evidence` validator module export in `crates/core/contract_validate/src/lib.rs` and create `crates/core/contract_validate/src/contract_core_evidence.rs`
- [X] T008 Preserve dependency direction for the evidence carrier in `crates/core/artifact_manifest/Cargo.toml` and `crates/core/contract_validate/Cargo.toml`
- [X] T009 Add reusable Feature 002 semantic-model fixtures in `crates/core/contract_validate/src/tests/contract_core_evidence.rs`

**Checkpoint**: Foundation ready; user story implementation can now proceed in
priority order.

---

## Phase 3: User Story 1 - Stabilize Contract Effect Language (Priority: P1) MVP

**Goal**: Define one stable, machine-readable contract language for Phase
2-owned vISA-visible effects without importing private runtime, frontend,
substrate, or host-specific state.

**Independent Test**: Inspect and run the contract-core and carrier tests to
confirm every Phase 2 semantic family can be represented as stable contract
facts with a semantic-model evidence boundary.

### Tests for User Story 1

- [X] T010 [US1] Add object reference and generation contract tests in `crates/core/contract_core/src/lib.rs`
- [X] T011 [US1] Add edge mode and evidence-boundary contract tests in `crates/core/contract_core/src/lib.rs`
- [X] T012 [US1] Add command transaction, event evidence, stable view, and validation violation contract tests in `crates/core/contract_core/src/lib.rs`
- [X] T013 [P] [US1] Add carrier serialization tests for Feature 002 evidence envelopes in `crates/core/artifact_manifest/src/semantic_snapshot.rs`

### Implementation for User Story 1

- [X] T014 [US1] Implement Phase 2 semantic family, canonical coverage-unit registry, and coverage-unit APIs in `crates/core/contract_core/src/lib.rs`
- [X] T015 [US1] Implement object reference validation for stable object kind, nonzero identity, nonzero generation, and external-reference exceptions in `crates/core/contract_core/src/lib.rs`
- [X] T016 [US1] Implement live, historical, cleanup-effect, and external contract edge records with evidence-boundary metadata in `crates/core/contract_core/src/lib.rs`
- [X] T017 [US1] Implement command transaction records for preconditions, effects, events, postconditions, status, and violations in `crates/core/contract_core/src/lib.rs`
- [X] T018 [US1] Implement event evidence, stable view, validation violation, and claim-limit records in `crates/core/contract_core/src/lib.rs`
- [X] T019 [US1] Implement Feature 002 artifact-shaped and migration-shaped carrier manifest fields in `crates/core/artifact_manifest/src/artifact_bundle.rs`, `crates/core/artifact_manifest/src/boundary.rs`, and `crates/core/artifact_manifest/src/semantic_snapshot.rs`
- [X] T020 [US1] Implement artifact-shaped and migration-shaped carrier-to-contract evidence mapping helpers in `crates/core/contract_validate/src/contract_core_evidence.rs`

**Checkpoint**: User Story 1 is complete when stable contract facts and the
feature-local carrier can represent all Phase 2 semantic families without
stronger roadmap claims.

---

## Phase 4: User Story 2 - Validate Phase 2 Semantic Families (Priority: P2)

**Goal**: Provide positive and negative validation coverage for every Phase
2-owned object kind, edge mode, command area, and state transition.

**Independent Test**: Run the relevant validation tests and confirm accepted
examples pass, rejected examples fail with structured reasons, and independent
violations are all reported.

### Tests for User Story 2

- [X] T021 [US2] Add positive and negative identity, generation, and graph-edge validation tests in `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T022 [US2] Add command transaction rejection and no-mutation validation tests in `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T023 [US2] Add capability authority and wait-state lifecycle validation tests in `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T024 [US2] Add event evidence, trap attribution, cleanup, and stable-view validation tests in `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T025 [US2] Add guest-memory semantic truth and substrate-truth rejection tests in `crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs`
- [X] T026 [P] [US2] Add coverage matrix and all-violations validation tests in `crates/core/contract_validate/src/tests/contract_core_evidence.rs`

### Implementation for User Story 2

- [X] T027 [US2] Implement exhaustive object identity, generation, live, historical, cleanup-effect, and external edge validation in `crates/core/semantic_core/src/contract_graph.rs`
- [X] T028 [US2] Implement all-independent-violations collection for contract graph validation in `crates/core/semantic_core/src/contract_graph/validator_core.rs`
- [X] T029 [US2] Implement command transaction precondition failure, rejected status, and no-mutation semantics in `crates/core/semantic_core/src/graph/command/preflight.rs` and `crates/core/semantic_core/src/graph/command/apply.rs`
- [X] T030 [US2] Implement capability grant, delegation, attenuation, revocation, stale handle, generation, and provenance validation in `crates/core/semantic_core/src/graph/capability.rs`
- [X] T031 [US2] Implement wait creation, pending, resolution, cancellation, restart, resume eligibility, owner generation, and event bridge validation in `crates/core/semantic_core/src/graph/wait.rs`
- [X] T032 [US2] Implement event evidence and trap attribution validation at the semantic-model boundary in `crates/core/semantic_core/src/event_log.rs` and `crates/core/semantic_core/src/graph/transaction.rs`
- [X] T033 [US2] Implement cleanup begin, step, commit, idempotence, wait cancellation, capability revocation, tombstone interaction, and live-leak validation in `crates/core/semantic_core/src/graph/cleanup.rs`
- [X] T034 [US2] Implement guest memory validation for GuestAddressSpace, VmaRegion, PageObject, GuestMemoryOperation, and generation-bearing history in `crates/core/semantic_core/src/guest_memory.rs`
- [X] T035 [US2] Implement stable validation views and structured violation records for Phase 2 validation outcomes in `crates/core/semantic_core/src/contract_graph.rs`
- [X] T036 [US2] Implement Feature 002 coverage matrix validation against the canonical Phase 2 coverage-unit registry in `crates/core/contract_validate/src/contract_core_evidence.rs`

**Checkpoint**: User Story 2 is complete when every Phase 2 family has positive
and negative validation, rejected commands do not mutate semantic state, and
all independently detectable violations are exposed.

---

## Phase 5: User Story 3 - Preserve Roadmap Boundaries For The Full Goal (Priority: P3)

**Goal**: Keep Feature 002 limited to Phase 2 contract-core stabilization while
making later Phase 3-6 surfaces explicit deferrals.

**Independent Test**: Review or run the scope tests to classify proposed
artifact/profile, frontend/personality, substrate, and migration additions as
Phase 2 evidence-shape use or later-roadmap work in under 10 minutes.

### Tests for User Story 3

- [X] T037 [US3] Add overclaim rejection tests for artifact/profile, frontend/personality, substrate, migration, and portability claims in `crates/core/contract_validate/src/tests/contract_core_evidence.rs`
- [X] T038 [US3] Add semantic-model-only evidence boundary tests for Feature 002 carriers in `crates/core/contract_validate/src/tests/contract_core_evidence.rs`
- [X] T039 [P] [US3] Add feature-local evidence shape tests that reject post-completion compatibility assumptions in `crates/core/artifact_manifest/src/semantic_snapshot.rs`

### Implementation for User Story 3

- [X] T040 [US3] Implement roadmap deferral classification records against `specs/001-semantic-baseline-roadmap/spec.md` and `specs/001-semantic-baseline-roadmap/data-model.md` for Phase 3 artifact/profile, Phase 4 frontend/personality, Phase 5 substrate, and Phase 6 portability surfaces in `crates/core/contract_core/src/lib.rs`
- [X] T041 [US3] Enforce semantic-model-only Feature 002 evidence boundary checks in `crates/core/contract_validate/src/contract_core_evidence.rs`
- [X] T042 [US3] Enforce carrier reuse overclaim guards for artifact-shaped and migration-shaped envelopes in `crates/core/contract_validate/src/contract_core_evidence.rs`
- [X] T043 [US3] Encode feature-local evidence shape status without long-term compatibility promises in `crates/core/artifact_manifest/src/semantic_snapshot.rs`
- [X] T044 [US3] Update implementation-facing roadmap boundary notes and Feature 001 baseline revalidation guidance in `specs/002-contract-core-stabilization/quickstart.md`

**Checkpoint**: User Story 3 is complete when Feature 002 evidence can reuse
package-shaped carriers without implying artifact execution, profile-gate
completion, frontend breadth, substrate behavior, migration restoration, or
cross-ISA portability.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validate the complete feature, update Spec Kit artifacts, and
confirm there is no scope drift.

- [X] T045 [P] Run `cargo test -p contract_core` for `crates/core/contract_core/Cargo.toml`
- [X] T046 [P] Run `cargo test -p artifact_manifest` for `crates/core/artifact_manifest/Cargo.toml`
- [X] T047 Run `cargo test -p semantic_core` for `crates/core/semantic_core/Cargo.toml`
- [X] T048 Run `cargo test -p contract_validate` for `crates/core/contract_validate/Cargo.toml`
- [X] T049 Run Docker validation gates from `docs/DOCKER.md` if implementation touches conformance-facing evidence, target components, or workspace parity-sensitive behavior
- [X] T050 Run marker scan, scope drift scan, Feature 001 baseline revalidation, evidence boundary review, and `git diff --check` from `specs/002-contract-core-stabilization/quickstart.md`
- [X] T051 Update completed-task evidence and any changed validation commands in `specs/002-contract-core-stabilization/tasks.md` and `specs/002-contract-core-stabilization/quickstart.md`

**Validation Evidence (2026-06-25)**:

- `cargo test -p contract_core` passed: 11 tests.
- `cargo test -p artifact_manifest` passed: 2 tests.
- `cargo test -p semantic_core` passed: 529 tests.
- `cargo test -p contract_validate` passed: 204 tests.
- Quickstart artifact readiness, marker scan, Feature 001 baseline file
  revalidation, Feature 001 baseline grep, and `git diff --check` passed.
- Scope drift scan returned only explicit exclusion, deferral, and overclaim
  guard contexts.
- `scripts/run-docker-ci-gate.sh metadata fmt visa-conformance` passed after
  formatting the single file reported by the first Docker `fmt` attempt:
  `crates/core/semantic_core/src/graph/guest_memory.rs`.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; can start immediately.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user stories.
- **User Story 1 (Phase 3)**: Depends on Foundational; suggested MVP.
- **User Story 2 (Phase 4)**: Depends on Foundational and the stable records
  from User Story 1.
- **User Story 3 (Phase 5)**: Depends on Foundational; can be implemented
  after User Story 1 or in parallel with User Story 2 once carrier records
  exist.
- **Polish (Phase 6)**: Depends on all selected user stories.

### User Story Dependencies

- **US1 (P1)**: Required MVP and record-language foundation.
- **US2 (P2)**: Requires US1 record APIs and evidence carrier mapping.
- **US3 (P3)**: Requires US1 carrier and evidence-boundary records; should be
  complete before final acceptance.

### Within Each User Story

- Write story-specific tests first and confirm they fail for missing behavior.
- Implement contract/core records before validator logic that consumes them.
- Implement validators before final carrier acceptance checks.
- Complete the story checkpoint before moving to the next priority.

### Parallel Opportunities

- T002, T003, and T004 can run in parallel after T001.
- T013 can run in parallel with the ordered contract-core tests T010 through
  T012 because it touches carrier serialization in a different file.
- T026 can run in parallel with the ordered semantic-core tests T021 through
  T025 because it touches validator coverage in a different file.
- T039 can run in parallel with the ordered validator tests T037 and T038
  because it touches carrier shape tests in a different file.
- T045 and T046 can run in parallel with each other; run T047 and T048 after
  implementation stabilizes to avoid shared target-directory churn.

---

## Parallel Example: User Story 1

```bash
# Carrier tests can be prepared while contract_core tests are written in order:
Task: "T010 Add object reference and generation contract tests in crates/core/contract_core/src/lib.rs"
Task: "T011 Add edge mode and evidence-boundary contract tests in crates/core/contract_core/src/lib.rs"
Task: "T012 Add command transaction, event evidence, stable view, and validation violation contract tests in crates/core/contract_core/src/lib.rs"
Task: "T013 Add carrier serialization tests for Feature 002 evidence envelopes in crates/core/artifact_manifest/src/semantic_snapshot.rs"
```

## Parallel Example: User Story 2

```bash
# Contract_validate coverage tests can be prepared while semantic_core tests are written in order:
Task: "T021 Add identity, generation, and graph-edge validation tests in crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs"
Task: "T023 Add capability authority and wait-state lifecycle validation tests in crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs"
Task: "T025 Add guest-memory semantic truth and substrate-truth rejection tests in crates/core/semantic_core/src/tests/core_io/phase2_contract_core.rs"
Task: "T026 Add coverage matrix and all-violations validation tests in crates/core/contract_validate/src/tests/contract_core_evidence.rs"
```

## Parallel Example: User Story 3

```bash
# Carrier shape tests can be prepared while validator boundary tests are written in order:
Task: "T037 Add overclaim rejection tests in crates/core/contract_validate/src/tests/contract_core_evidence.rs"
Task: "T038 Add semantic-model-only evidence boundary tests in crates/core/contract_validate/src/tests/contract_core_evidence.rs"
Task: "T039 Add feature-local evidence shape tests in crates/core/artifact_manifest/src/semantic_snapshot.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 setup.
2. Complete Phase 2 foundational module and carrier entrypoints.
3. Complete User Story 1.
4. Stop and validate `cargo test -p contract_core` and `cargo test -p artifact_manifest`.
5. Review the carrier envelope against `contracts/contract-core-evidence.md`.

### Incremental Delivery

1. Deliver US1 effect language and carrier representation.
2. Add US2 exhaustive positive and negative validation coverage.
3. Add US3 roadmap boundary and overclaim enforcement.
4. Run full quickstart validation and update evidence notes.

### Completion Gate

Feature 002 is not complete until every Phase 2 semantic family has contract
facts, positive validation, negative validation, structured violation evidence,
and an explicit semantic-model evidence boundary.

## Notes

- `[P]` means the task can run in parallel because it touches different files or
  independent test concerns.
- `[US1]`, `[US2]`, and `[US3]` labels map tasks to the user stories in
  `spec.md`.
- Artifact-shaped and migration-shaped records are carriers only; they do not
  upgrade Feature 002 to artifact execution or migration behavior.
- Historical docs under `docs/archive/achieve/` are background only; active
  implementation scope comes from this Spec Kit directory.
