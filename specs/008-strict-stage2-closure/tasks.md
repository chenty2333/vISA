# Tasks: Strict Stage 2 Closure

## Specification and repository convergence

- [x] T001 Confirm the active scope, security model, qualification gate, exact
  claim names, validation order, and explicit Stage 3+ exclusions.
- [x] T002 Audit completed specs 003-007 against canonical docs and executable
  tests; extract only missing durable decisions.
- [x] T003 Add the Apache-2.0 license and workspace/package license metadata.
- [x] T004 Remove completed specs, unused Dev Container configuration,
  `deny.toml`, deprecated LTP alias, and their stale documentation references.
- [x] T005 Update Roadmap review state, validation limitations, README license
  discovery, and any stale active-plan/workflow references.
- [x] T006 Run metadata, formatting, structural, focused, `fast`, and `full`
  convergence gates and review the deletion diff.

## JcoNode sealed carrier

- [x] T007 Record the selected sealed-carrier mechanism and exact same-UID
  hostile-publisher boundary after comparing viable Node ESM load mechanisms.
- [x] T008 Implement the sealed carrier from captured verified artifacts and
  make JcoNode fail closed rather than load the old mutable pathname tree.
- [x] T009 Add deterministic replacement/symlink/directory/publication-root race
  tests proving substituted code cannot execute.
- [x] T010 Preserve Jco preflight, provenance, RPC, no-fallback, recoverable
  instantiation, cleanup, and all 31 cases.
- [x] T011 Pass focused, Host, Docker, and existing Stage 2 Jco gates.

## Independent Runtime B qualification

- [x] T012 Audit candidate runtime implementation lineages, licenses, pinned
  artifacts, host APIs, Component Model coverage, and operational constraints.
- [x] T013 Build retained qualification probes against the byte-identical
  Component/WIT, advance candidates through prerequisite gates in order, and
  stop before host-bridge implementation when the public surface fails earlier.
- [x] T014 Execute and retain the qualification record, including negative
  unsupported/no-fallback cases and a go/no-go decision.
- [ ] T015 Name the selected runtime and update this spec/plan only after the
  executable qualification gate passes.

T015 is qualification-blocked: WACS parser, typed-harness, CLI/Transpiler, and
NativeAOT public paths, WasmEdge, and wacogo are retained as executable no-go
evidence. wacogo independently loads the unchanged Component and builds both
host interface instances, but its nested-component instantiation leaves the
direct `kv-error` type argument unresolved. `selected_runtime` remains null,
and T016-T022 must not begin. The upstream unblock conditions are recorded in
`runtime-b-qualification.json`.

## Strict Stage 2 implementation

- [ ] T016 Add the qualified runtime crate with pinned provenance, non-executing
  preflight, recoverable instantiation, shared lifecycle, and no fallback.
- [ ] T017 Replace duplicated concrete worker lifecycle matches with one typed
  runtime registry/factory and erased prepared/live instance boundaries.
- [ ] T018 Generalize Stage 2 cell descriptors and claim-set membership while
  preserving the existing four Wasmtime/JcoNode cells and evidence claim.
- [ ] T019 Add the qualified-runtime same-path and both Wasmtime mixed-direction
  cells over the unchanged 31-case registry and common inputs.
- [ ] T020 Extend independent evidence validation for exact runtime lineage,
  identity, cell completeness, no fallback, normalized equality, and the strict
  claim without overclaiming cross-ISA or new resources.
- [ ] T021 Add focused no-fallback and failure tests for the qualified runtime.
- [ ] T022 Add locked local and Docker qualification, same-path, and strict
  Stage 2 gates with retained partial evidence.

## Completion

- [ ] T023 After Runtime B qualifies and T016-T022 complete, run `fast`, `full`,
  all strict same-path and matrix gates on Host and Docker; independently
  verify every retained bundle.
- [ ] T024 After strict evidence changes current truth, update README,
  Architecture, Roadmap, Development, Validation, and Research only where that
  evidence requires it.
- [ ] T025 Remove this completed active spec after durable extraction, verify no
  stale paths or unsupported claims remain, and perform a final diff review.
- [ ] T026 After T023-T025, commit the strict closure, push, confirm GitHub
  Actions at the exact commit, and stop before Stage 3.

The 2026-07-12 qualification-boundary handoff has completed every currently
executable Host and Docker gate, including the existing 124-case Stage 2 claim.
T023-T026 remain open because they are completion tasks for the qualified
Runtime B and strict claim, not permission to reinterpret the no-go result as a
pass. This repository-convergence/Jco-sealing/qualification boundary may still
be reviewed, committed, pushed, and validated by CI while this active spec is
retained.
