# Tasks: Stage 2a Runtime-Neutral Component Adapter Contract

Status values reflect repository state and must be updated with validation.

- [x] T001 Complete Stage 1 spine modularization and record a fresh focused,
  no-std, dependency, 31-case system, and independent-verifier baseline.
- [x] T002 Add `visa_component_adapter` to the workspace, active-spine gates,
  and strict one-way dependency policy.
- [x] T003 Move activation/safe-point/status types, component digest, and the
  exact `VISACS01` codec into the shared crate with golden compatibility tests
  and single-definition compatibility re-exports.
- [x] T004 Define structured adapter/workload failure kinds, preserve KV/timer/
  binding/codec distinctions, and remove adapter message-string assertions.
- [x] T005 Extract the engine-neutral provider bound, logical binding checks,
  operation/idempotency derivation, and coordinator-mediated host effects while
  leaving Wasmtime resource handles and WIT conversions local.
- [x] T006 Extract shared safe-point, rollback, restore, thaw, cancellation, and
  callback lifecycle rules and refactor Wasmtime through that one path.
- [x] T007 Implement Wasmtime artifact/digest/WIT/capability preflight without a
  Store, guest instantiation, export call, provider effect, coordinator restore,
  or binding creation.
- [x] T008 Require a matching opaque prepared artifact before destination load;
  test valid repetition, invalid artifact/link rejection, stale or missing
  preparation, and unchanged pre-commit ownership/provider state.
- [x] T009 Add the explicit worker runtime selector and observed runtime
  identity for Wasmtime, with no fallback and structured adapter/workload error
  fields.
- [x] T010 Derive Stage 1 source/destination runtime evidence from worker
  results and verify requested, observed, and bundled identities agree without
  adding a cross-runtime claim.
- [x] T011 Run focused adapter/protocol/lifecycle tests and execute all 31
  Wasmtime-to-Wasmtime cases; compare portable state, normalized traces,
  state/replay digests, authority/fencing, fault schedules, and outcomes with
  the accepted baseline.
- [x] T012 Run formatting, strict Clippy, dependency/deletion checks, local
  fast/full/system, Docker full/system, independent retained-bundle validation,
  and final diff audits.
- [x] T013 Record Stage 2a completion evidence, link the completed Stage 2b and
  Stage 2c closeout records, and leave strict Roadmap Stage 2 in progress.
