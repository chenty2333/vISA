# Tasks: Stage 2c Cross-Execution-Path Handoff Matrix

Status values reflect repository state and must be updated with retained
validation evidence.

- [x] T001 Complete Stage 2a and Stage 2b; retain fresh independently verified
  31/31 Wasmtime-to-Wasmtime and JcoNode-to-JcoNode execution bundles, common
  input digests, exact toolchain observations, and no-fallback entry results.
- [x] T002 Add versioned Stage 2 matrix-manifest/evidence types, the four exact
  cell IDs and selector pairs, the `cross-execution-path-portability` claim,
  strict-independence-not-proven guards, and unknown-field rejection.
- [x] T003 Implement a canonical common-input manifest covering the exact
  original Component/world/profile/configuration/policy artifacts, component-
  state codec, ordered 31-case registry, per-case digests, fault schedules,
  allowed outcomes, and bound schema versions before the first cell runs.
- [x] T004 Bind the same pre-run common-input identity into every cell as
  `stage2-common-input-identity-bound`, then make the outer verifier prove exact
  common/per-case bytes and digests while creating fresh workers, runtime/Node
  instances, SQLite provider roots, and local handle/RPC namespaces. Workers do
  not parse the manifest JSON; forbid pair-specific fixture or expectation
  changes.
- [x] T005 Implement
  `visa-stage2-normalized-observable-trace-v1` as a typed canonical projection
  from a successfully verified Stage 1 case and hash-checked artifacts, not a
  generic JSON filter or second reducer.
- [x] T006 Preserve execution/handoff/snapshot identities, per-case input
  digests, case outcome/fault order, semantic branch and journal-entry order,
  effect/workload outcomes, resource identities/generations, rights, authority
  roots, lease/fencing epochs, ownership/source fencing, binding, cancellation,
  rollback, cleanup, no-resurrection, structured worker errors, assertion name/
  order, normalized state/replay/snapshot, explicit derived-integrity markers,
  recomputed enclosing normalized-content digests, and normalized portable-
  envelope serialized size in V1.
- [x] T007 Preserve the source `TimerArm` requested duration exactly and map
  elapsed freeze/restore/rearm remaining duration only to zero versus positive.
  Keep raw timing and raw serialized-size samples in inner evidence; exclude
  PID, filesystem/generated path, and human diagnostic/message/assertion detail
  from V1 while rejecting unknown fields and retaining all unprofiled timer
  semantics exactly.
- [x] T008 Add exhaustive normalizer mutation tests: permitted metadata-only
  changes, raw timing/size changes, and positive-to-positive remaining changes
  remain equal. Missing/duplicated/reordered events or cleanup, zero/positive
  timer-class changes, assertion name/order changes, structured error changes,
  and changed outcomes/effects/rights/generations/epochs/ownership/fencing/
  bindings/state/fault order must fail. Original derived digests must first pass
  inner integrity validation; V1 then uses its declared marker and recomputes
  enclosing normalized-content digests.
- [x] T009 Add exact four-cell matrix orchestration over the existing explicit
  Stage 1 runtime-pair runner, with clean contained artifact roots, canonical
  case order, atomic publication, structured partial failure, and no selector
  default, alias, retry, result copy, or fallback.
- [x] T010 Record and cross-check requested and preflight-verified identities
  plus typed instantiation inferred from successful bootstrap or post-commit
  resume after adapter-internal startup validation; bind those facts into the
  inner and outer bundles for both directions, and use honest typed
  not-instantiated markers for accepted pre-destination rejection cases.
- [x] T011 Add mixed-direction no-fallback tests for missing/wrong Jco/Node
  tools, translation failure, Node exit, Wasmtime compile/link failure,
  selector mismatch, and child-handshake mismatch; audit dependencies and
  transcripts for the selected execution path.
- [x] T012 Add the contained Stage 2 artifact writer for one common-input
  manifest, four complete Stage 1 roots, 124 execution references, exactly four
  typed V1 aggregate caches with 31 cases each, exact runtime/toolchain
  provenance, 31 per-case comparison digests, outer manifest hash, and
  overclaim guards.
- [x] T013 Implement the independent Stage 2 verifier so it checks outer
  schema/path/hash integrity, then invokes complete existing Stage 1 structural
  and artifact validation on each cell before any cross-cell comparison.
- [x] T014 Make the verifier require exactly four execution-kind bundles,
  exactly 31 unique required cases per bundle, exact cell selectors and
  observations, identical common/per-case inputs, Jco lineage disclosure,
  absence of fallback, and only accepted inner/outer claims.
- [x] T015 Make the verifier independently recompute canonical V1 bytes for all
  124 records, reject any mismatched four-cell aggregate cache, and require one
  exactly equal four-cell group for each of the 31 case IDs, including equal
  selected outcome and the declared timer/integrity normalization profile.
- [x] T016 Run focused mixed-path cases for successful restore, source-retained
  rejection, pre-commit abort/retry, post-commit recovery, timer cancellation,
  unknown KV outcome, rights attenuation/rejection, live-resource safe-point
  failure, cleanup/no-resurrection, and evidence regeneration.
- [x] T017 Execute all 31 Wasmtime-to-JcoNode cases with the common input
  identity bound and later byte/digest-proven by the outer verifier; retain the
  complete Stage 1 bundle and pass its independent Stage 1 verifier.
- [x] T018 Execute all 31 JcoNode-to-Wasmtime cases with the common input
  identity bound and later byte/digest-proven by the outer verifier; retain the
  complete Stage 1 bundle and pass its independent Stage 1 verifier.
- [x] T019 Rerun all 31 Wasmtime-to-Wasmtime and all 31 JcoNode-to-JcoNode cases
  with the same pre-run common-input identity bound and subsequently proven;
  retain both complete bundles and pass both independent Stage 1 verifiers.
- [x] T020 Build the local 124/124 outer evidence bundle and pass the separate
  Stage 2 verifier with exact four-cell identity, 31 four-way-equal V1 groups,
  full artifact integrity, and no fallback or skipped cell.
- [x] T021 Add and pass locked local `system-stage2` plus Docker
  `system-stage2` gates; rerun fast/full, both same-path system gates, Docker
  full/same-path gates, strict Clippy, dependency/deletion/toolchain checks,
  and final diff/transcript/provenance/claim audits.
- [x] T022 Record retained local and Docker Stage 2 root paths, manifest and
  bundle IDs/hashes, four inner bundle IDs/hashes, 31/31 counts per cell,
  124/124 count, toolchain/runtime observations, four Stage 1 verifier results,
  Stage 2 verifier result, and V1 equality digest set.
- [x] T023 Publish only the precise cross-execution-path portability statement,
  record the accepted decision to retain the independent-implementation exit
  criterion, keep strict Roadmap Stage 2 in progress, and leave strict
  cross-runtime, Stage 3 file/network, Stage 4 cross-ISA, Stage 5 confidential,
  and production claims unearned.
