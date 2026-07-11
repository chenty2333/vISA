# Tasks: Stage 2b Jco/Node Reference Execution Cell

Status values reflect repository state and must be updated with validation.

- [x] T001 Complete Stage 2a and record focused, dependency, Wasmtime 31/31,
  independent-verifier, local, and Docker entry baselines.
- [x] T002 Add exact project-local locks for Jco 1.25.2,
  `js-component-bindgen` 2.0.11, disclosed `wasmtime-environ` 45.0.1 lineage,
  Node v24.15.0, and V8 13.6.233.17-node.48, including Cargo/archive integrity
  and a machine-checkable toolchain gate.
- [x] T003 Add `visa_jco_node` to the workspace and active-spine gates with a
  strict one-way dependency on `visa_component_adapter`; forbid reverse core,
  coordinator, provider, and Wasmtime fallback edges.
- [x] T004 Implement Jco translation preflight over the exact existing
  Component bytes, fixed options, complete generated-graph hashing, interface
  validation, opaque prepared values, cache revalidation if used, and proof
  that no guest code or provider/coordinator mutation occurs.
- [x] T005 Add the adapter-internal versioned Node/V8 startup handshake and
  synchronous nested RPC protocol with exact semantic-`u64`/byte conversion,
  strict correlation, matching terminal-settlement boundaries, one-MiB
  size/order/state checks, process-exit handling, and malformed protocol tests;
  leave production timeout policy outside this research-cell claim.
- [x] T006 Implement the Rust typed resource table, Jco owned-resource mirror
  objects, method/drop dispatch, idempotent high-level disposal, stale/wrong-
  kind/duplicate-raw-drop rejection, and real live-resource fault control.
- [x] T007 Route every JcoNode KV/timer host call through the shared binding and
  effect helpers into the instance's sole Rust coordinator; prove Node has no
  SQLite/provider/journal or semantic-ledger path.
- [x] T008 Implement `CooperativeRuntimeFactory` and
  `CooperativeRuntimeInstance` for JcoNode by forwarding guest calls over RPC
  while retaining the single shared safe-point, restore, thaw, cancellation,
  cleanup, callback-parent, and rollback implementation.
- [x] T009 Add concrete `JcoNode` prepared/instance worker dispatch, requested
  and observed execution identity, structured translation/transport/exit/trap
  failures, separate source/destination Node processes, and strict no-fallback
  tests.
- [x] T010 Require destination translation/interface preflight before
  coordinator restore and instantiate the Node destination only after durable
  commit; cover pre-commit rejection and post-commit startup/guest failures.
- [x] T011 Parameterize the runner with explicit source/destination selectors,
  retain the inner Stage 1 bundle shape, and keep mixed pairs unclaimed until
  Stage 2c.
- [x] T012 Extend provenance and composed Stage 1/toolchain/Stage 2 outer
  validation for the original Component digest, tool/source locks, translation
  graph aggregate, driver/core-module digests, runtime-local per-file manifest
  enforcement, adapter-validated startup, inferred typed instantiation,
  no-fallback identity, and explicit strict-independence-not-proven guard.
- [x] T013 Run focused JcoNode success, portable-state, owned-resource,
  safe-point rollback, child/protocol failure, invalid artifact/toolchain, and
  source/destination isolation tests.
- [x] T014 Execute all 31 JcoNode-to-JcoNode cases and independently validate
  every referenced artifact, runtime observation, semantic trace, state/replay
  digest, authority/fencing result, fault schedule, and claim boundary.
- [x] T015 Rerun all 31 Wasmtime-to-Wasmtime cases and its independent verifier;
  compare every stable Stage 1 semantic dimension with the accepted baseline.
- [x] T016 Run formatting, strict Clippy, dependency/deletion/toolchain checks,
  local fast/full/system/JcoNode-system, Docker full/system/JcoNode-system, and
  final diff, transcript, provenance, fallback, and overclaim audits.
- [x] T017 Record retained bundle paths, IDs, hashes, 31/31 counts, toolchain
  observations, and verifier results; close the JcoNode same-path cell while
  leaving mixed execution-path evidence to Stage 2c. Strict Component Model
  independence remains unproven and Roadmap Stage 2 remains in progress.
