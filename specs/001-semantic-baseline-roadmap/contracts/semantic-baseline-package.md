# Contract: Semantic Baseline Package

## Purpose

This contract defines the artifact-level interface for Phase 1 of the
semantic-baseline-roadmap feature. It is consumed by maintainers and downstream
Spec Kit commands, not by runtime code.

## Required Artifacts

The package MUST contain:

- `spec.md`: accepted feature specification and clarification record.
- `plan.md`: implementation plan for the Phase 1 baseline package.
- `research.md`: Phase 0 decisions with rationale and alternatives.
- `data-model.md`: entities, fields, relationships, validation rules, and
  state transitions.
- `contracts/semantic-baseline-package.md`: this artifact contract.
- `quickstart.md`: runnable validation guide for the Phase 1 package.
- `tasks.md`: implementation ledger for the accepted Phase 1 package.
- `checklists/requirements.md`: specification quality checklist.
- `AGENTS.md` managed Spec Kit block pointing to the current `plan.md`.

## Baseline Content Requirements

The package MUST define:

- vISA's core identity as a cross-ISA Semantic Virtual ISA.
- Explicit exclusions from the core identity.
- The semantic boundary and all baseline semantic families.
- Long-term layer ownership.
- Ordered roadmap phases with purpose, included semantic families, entry
  condition, exit condition, and expected evidence boundary.
- The Phase 1 evidence boundary.
- The first implementable increment.
- Stable handling of archived sources as historical background only.
- Claim-level traceability to current code anchors, historical sources marked as
  background, or documented assumptions.

## Evidence Contract

Phase 1 claims MUST be limited to:

- semantic model and source-backed review evidence;
- existing repository checks appropriate to changed artifacts;
- no new runtime behavior;
- no portable artifact execution claim;
- no real target substrate claim.

Every semantic claim in the Phase 1 package MUST name the weakest evidence
boundary it can claim. Traceability to current code or archived background does
not by itself upgrade the claim beyond the exercised boundary.

Any claim that depends on runtime execution, substrate authority, frontend
compatibility breadth, migration, or performance MUST be deferred to a later
roadmap phase unless a future spec narrows and validates that stronger claim.

## Scope Contract

The Phase 1 package MAY update:

- files under `specs/001-semantic-baseline-roadmap/`;
- `.specify/feature.json`;
- the managed Spec Kit marker block in `AGENTS.md`.

The Phase 1 package MUST NOT require changes to:

- runtime crates under `crates/`;
- Docker or CI scripts;
- archived documents under `docs/archive/achieve/`;
- validation harnesses;
- target runtime or substrate behavior.

If a future task needs any of those changes, it MUST be split into a later
phase or explicitly justified in a new Spec Kit artifact.

## Validation Contract

The package is valid when:

- every required artifact exists;
- the spec and plan contain no unresolved clarification or template markers;
- the task ledger contains no unresolved clarification or template markers;
- `AGENTS.md` points to `specs/001-semantic-baseline-roadmap/plan.md`;
- no runtime/source paths are changed for Phase 1 without a new accepted scope;
- `git diff --check` passes for changed artifacts;
- the requirements checklist remains complete after implementation edits.

## Rejection Cases

Reject the package if it:

- copies archived workflow rules into the active process;
- treats Linux, WASI, service, debugger, or substrate breadth as vISA core
  completeness;
- claims portable artifact execution or real target substrate evidence;
- introduces speculative code or placeholder implementation;
- leaves a semantic family without a roadmap phase or validation rule;
- leaves a semantic claim without current-code, historical-source, or assumption
  traceability.
