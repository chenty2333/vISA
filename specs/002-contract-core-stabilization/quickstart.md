# Quickstart: Contract Core Stabilization Validation

## Prerequisites

- Work from the repository root.
- Read the active feature artifacts:
  - `specs/002-contract-core-stabilization/spec.md`
  - `specs/002-contract-core-stabilization/plan.md`
  - `specs/002-contract-core-stabilization/data-model.md`
  - `specs/002-contract-core-stabilization/contracts/contract-core-evidence.md`
  - `specs/002-contract-core-stabilization/tasks.md` after `/speckit-tasks`
- Use `docs/DOCKER.md` for Docker validation commands when Rust workspace
  parity, target components, or conformance evidence matter.

## Artifact Readiness Check

```sh
test -f specs/002-contract-core-stabilization/spec.md
test -f specs/002-contract-core-stabilization/plan.md
test -f specs/002-contract-core-stabilization/research.md
test -f specs/002-contract-core-stabilization/data-model.md
test -f specs/002-contract-core-stabilization/contracts/contract-core-evidence.md
test -f specs/002-contract-core-stabilization/quickstart.md
test -f specs/002-contract-core-stabilization/tasks.md
test -f specs/002-contract-core-stabilization/checklists/requirements.md
```

Expected outcome: all commands exit successfully.

## Marker Scan

```sh
rg -n "NEEDS[[:space:]]+CLARIFICATION|TO\"\"DO|TB\"\"D|ACTION[[:space:]]+REQUIRED" \
  specs/002-contract-core-stabilization/spec.md \
  specs/002-contract-core-stabilization/plan.md \
  specs/002-contract-core-stabilization/research.md \
  specs/002-contract-core-stabilization/data-model.md \
  specs/002-contract-core-stabilization/contracts/contract-core-evidence.md \
  specs/002-contract-core-stabilization/quickstart.md \
  specs/002-contract-core-stabilization/tasks.md
```

Expected outcome: no unresolved placeholders or clarification markers. Markdown
links in the checklist are acceptable and should be reviewed separately if the
scan includes checklist files.

## Scope Drift Scan

```sh
rg -n "portable artifact execution|real target substrate|Linux compatibility|WASI compatibility|migration restoration|cross-ISA portability|profile-gate completion" \
  specs/002-contract-core-stabilization
```

Expected outcome: matches only appear in explicit exclusion, deferral, or
overclaim-guard language.

## Coverage Matrix Review

Review `data-model.md` and `contracts/contract-core-evidence.md` for the Phase
2 coverage matrix.

Expected outcome:

- Object identity, generation, graph edges, capability authority, wait state,
  event evidence, trap attribution, cleanup, guest memory, stable views, and
  graph validation are all present.
- Each family names positive and negative evidence expectations.
- Later-phase surfaces are excluded unless used only as generic evidence
  shapes for Phase 2-owned units.

## Implementation Validation Path

After `/speckit-tasks` and implementation, validate changed Rust crates with
focused tests first:

```sh
cargo test -p contract_core
cargo test -p semantic_core
cargo test -p contract_validate
cargo test -p artifact_manifest
```

Expected outcome: affected crate tests pass, including positive and negative
coverage for all Phase 2-owned coverage units touched by the implementation.

When implementation touches conformance-facing evidence, target components, or
workspace parity-sensitive behavior, use the Docker gate documented in
`docs/DOCKER.md`:

```sh
scripts/run-docker-ci-gate.sh metadata fmt visa-conformance
```

Expected outcome: Docker gates pass for the selected validation scope.

Executed validation evidence for 2026-06-25:

- `scripts/run-docker-ci-gate.sh metadata fmt visa-conformance` passed.
- Docker gate results included `metadata: cargo metadata`, `fmt: cargo fmt`,
  `visa-conformance: cargo test`, and
  `visa-conformance: validate sample reports and evidence matrix`.

## Feature 001 Baseline Revalidation

Feature 002 must remain an implementation increment under the Feature 001
semantic baseline roadmap. Revalidate the baseline source before completion:

```sh
test -f specs/001-semantic-baseline-roadmap/spec.md
test -f specs/001-semantic-baseline-roadmap/plan.md
test -f specs/001-semantic-baseline-roadmap/data-model.md
test -f specs/001-semantic-baseline-roadmap/tasks.md
rg -n "semantic-model|semantic family|traceability|Phase 2|contract core" \
  specs/001-semantic-baseline-roadmap/spec.md \
  specs/001-semantic-baseline-roadmap/plan.md \
  specs/001-semantic-baseline-roadmap/data-model.md \
  specs/001-semantic-baseline-roadmap/tasks.md
```

Expected outcome: Feature 001 still frames Contract Core as a Phase 2
semantic-model increment, with traceability and semantic-family coverage
preserved as roadmap baseline facts.

## Evidence Boundary Review

For each validation claim produced by the implementation:

- Confirm the weakest exercised boundary is `semantic-model`.
- Confirm artifact-shaped or migration-shaped records are carriers only.
- Reject claims of artifact/profile completion, frontend compatibility,
  substrate hardware behavior, migration restoration, or cross-ISA portability.

Expected outcome: no Feature 002 claim exceeds the semantic-model boundary.

## Final Implementation Revalidation

Before completion, confirm:

```sh
git diff --check
```

Expected outcome: no whitespace errors. The feature is complete when the spec,
plan, research, data model, contract, quickstart, checklist, and tasks align
with the implemented semantic-model evidence boundary.
