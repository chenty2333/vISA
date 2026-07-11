# Implementation Plan: Stage 2c Cross-Execution-Path Handoff Matrix

Status: accepted; Stage 2c is complete, the strict independent-runtime
criterion is retained, and Roadmap Stage 2 remains in progress.

## Entry Condition

Complete `005-stage2a-runtime-adapter-contract` and
`006-stage2b-jco-node-reference-cell` first. Retain independently verified
31/31 Wasmtime-to-Wasmtime and JcoNode-to-JcoNode execution bundles, their
common Component/profile/configuration/policy digests, exact toolchain
provenance, and focused no-fallback results.

Do not begin matrix acceptance while adapter, worker-protocol, case-registry,
evidence-schema, or source-provenance inputs are still changing. A feasibility
run or two mixed smoke cases do not satisfy this entry condition.

## Design Commitments

This slice composes the two concrete Stage 2a/2b adapters; it does not add
another lifecycle implementation. `semantic_core` remains the only transition
authority, `visa_runtime::Coordinator` remains the only production sequencer
and durable commit path, and `visa_component_adapter` remains the only shared
component/host lifecycle contract.

The Stage 1 runner continues to produce a complete standalone bundle for one
explicit source/destination pair. Stage 2 orchestration calls that same public
path four times with immutable common inputs and isolated artifact/provider
roots. It does not special-case a scenario by pair or copy a previously
accepted cell into another matrix slot.

The outer verifier adds composition checks only. It reuses the existing Stage
1 validator and derives a deterministic projection from already verified
canonical artifacts; it does not replay commands through a second reducer or
decide what the canonical result should have been.

## Target Structure

The exact file grouping may follow the existing modular layout, but ownership
should remain recognizable:

```text
crates/testing/visa-system/src/
  Stage 1 pair runner (retained)
  Stage 2 matrix orchestration
  common-input manifest writer
  normalized-trace cache writer
  outer evidence writer

crates/testing/visa-conformance/src/
  existing Stage 1 validation (retained)
  stage2 schema and structural validation
  normalized observable trace V1 projection
  Stage 2 artifact/matrix verifier

scripts/
  existing local and Docker gate dispatch
  new locked Stage 2 full-matrix tier
```

The schema/projection belongs in the independent conformance crate so the
runner cannot be its own authority. Runner code may call the public projection
to emit cache artifacts, but acceptance recomputes them in a separate
`visa-conformance` process.

## Immutable Common-Input Design

Before launching a cell, derive one `Stage2CommonInputManifest` from checked
artifacts and typed registry data. Serialize it canonically, hash it, and bind
its identity to all four Stage 1 pair runs. The manifest covers:

- original Component bytes, digest, and WIT world;
- profile/configuration/policy bytes and digests;
- component-state codec identity;
- ordered Stage 1 case definition registry;
- every case's derived configuration and policy digest;
- every fault schedule and allowed outcome set; and
- the Stage 1 evidence/trace schema versions bound by this slice.

The orchestrator creates the manifest before the first cell and records its
digest in each cell as `stage2-common-input-identity-bound`. Workers do not read
or parse the JSON manifest, so this is an identity binding rather than a claim
of direct manifest consumption. A cell may create only its own fresh work
directory, SQLite database files, worker processes, engine-prepared objects,
Node children, and local handle/RPC namespaces. Cell identity never changes
fixture derivation, expected outcomes, fault injection, profile support, or
policy.

The outer verifier independently reconstructs the registry portion from its
compiled Stage 1 catalog, validates the identity-bound assertion in every cell,
and checks every inner bundle against the common manifest. It reads the exact
Component/world/profile/configuration/policy bytes, recomputes hashes and typed
digests, and proves global and per-case equality rather than trusting declared
strings.

## Matrix Execution Design

Represent each matrix cell as a closed typed pair:

```text
Stage2CellId                  RuntimeCell
wasmtime-to-wasmtime         Wasmtime -> Wasmtime
jco-node-to-jco-node         JcoNode  -> JcoNode
wasmtime-to-jco-node         Wasmtime -> JcoNode
jco-node-to-wasmtime         JcoNode  -> Wasmtime
```

The matrix runner rejects a missing, duplicate, unknown, or aliased cell. It
supplies both selectors explicitly to every Stage 1 invocation and requires
the worker-reported identities to match. Concrete adapter dispatch remains a
closed enum; a failure cannot be caught and retried under another variant.

Run each cell into a clean contained root. Run cases serially or in a proven
isolated schedule, but never share a case database or guest process across
cells. Preserve the canonical case order in evidence even if orchestration is
parallelized. Failure of one cell stops publication of a passing outer bundle;
partial roots may be retained for diagnosis but are marked incomplete.

Both mixed directions exercise the ordinary handoff order:

```text
source selected adapter executes and reaches the accepted safe point
  -> portable component state and canonical snapshot are produced
  -> destination selected adapter preflights the same original Component
  -> destination Coordinator restore and binding preparation
  -> durable commit and source fencing
  -> destination selected adapter instantiates
  -> portable guest state restores and canonical resume executes
```

No adapter-specific state conversion is inserted between source and
destination. Jco translation remains a preflight-derived execution artifact,
not a destination-specific Component or portable-state codec.

## Runtime Identity and No-Fallback Design

Record identity and activation at the boundaries the retained artifacts can
honestly establish:

- requested selector in the matrix cell;
- adapter factory/preflight identity and version;
- Wasmtime prepared identity or Jco translator/toolchain identity;
- adapter-internal startup validation, including strict consumption of the
  Jco Node/V8 `ready` envelope without persisting that envelope;
- typed `Live` instantiation inferred from a successful source bootstrap or
  destination post-commit resume protocol result;
- Stage 1 environment source/destination identities; and
- the corresponding outer cell identity.

Positive cases require typed `Live` instantiation at both executed activation
boundaries. Cases rejected before destination instantiation require a typed
absence reason and retain destination preflight identity. The verifier infers
these facts from successful worker protocol progression; it neither persists
nor inspects a Jco `ready` envelope. It knows which lifecycle boundary each
Stage 1 case reaches and rejects fabricated or unexpectedly missing
observations.

No-fallback tests inject missing tools, invalid translation, Wasmtime compile/
link failure, Node exit, and selector/handshake mismatch. Each must return a
structured selected-adapter failure. Dependency and transcript audits ensure a
JcoNode execution does not instantiate Wasmtime and a Wasmtime execution does
not spawn the Jco driver.

## Normalized Observable Trace Design

Define a deny-unknown-fields `NormalizedObservableTraceV1` with a canonical
serialization and a projection function whose input is a successfully
validated Stage 1 case plus its decoded, hash-checked artifacts.

The top-level projection should group, without reordering:

```text
case, execution, handoff, and snapshot identities plus selected outcome
per-case configuration and policy digests
ordered fault schedule
authority, leases, fencing, ownership
source semantic branch
destination semantic branch when present
decoded binding/rights observations
portable snapshot/state/replay observations
typed effect, structured worker error, cancellation, rollback, and cleanup observations
assertion names in recorded order
normalized portable-envelope serialized size
```

Semantic branches retain `role`, `scope`, `base_cursor`, `base_state`, every
ordered `JournalEntry`, `final_state`, and `claimed_final`. This naturally
retains canonical command/event order, effect outcomes, resource generations,
rights, epochs, ownership transitions, and cleanup state. Any supplementary
typed observation required by the Stage 1 verifier but not present in the
journal is projected explicitly. Structured worker error code, retryability,
provider kind, adapter kind, workload kind, role, and order are retained; human
error messages are not. Assertion names and order are retained while human
assertion details are not compared as untyped strings. The dedicated outer
schema validates common-input binding and runtime/translation provenance.

The implementation uses an explicit typed projection, not recursive key-name
deletion. Wall/host observation times, elapsed/performance timing samples,
PIDs, filesystem/generated paths, human diagnostics/details, and raw serialized
snapshot-size samples remain available to the verified inner bundle but are
not four-cell V1 equality fields. V1 instead records the serialized size of the
normalized portable envelope. Unknown fields or a newer Stage 1 schema fail
closed until a new normalizer version defines their treatment.

Timer comparison follows an explicit profile. The source's original
`TimerArm` requested duration remains exact. Remaining duration observed after
real time has elapsed in freeze, restore, rearm, or canonical timer state is
projected to `zero` or `positive`. All other timer semantics remain exact:
state and event order, operation/idempotency identity, rights, epochs,
ownership, delivery, cancellation, and cleanup. The existing Stage 1 verifier
must first validate every raw duration and timer constraint.

Journal input/output state digests, `EffectRequest.request_digest`,
`EvidenceRef.digest`, and `SnapshotEnvelope` integrity are derived from content.
The inner verifier checks the original value against original typed content
before normalization. V1 replaces those derived fields with its declared
schema marker, then recomputes the enclosing normalized trace, snapshot, and
cache digests from normalized typed content. These fields are never ignored
merely because raw path values differ.

Runtime selectors/versions, bundle IDs, artifact hashes, translation
provenance, and local RPC/request/handle identities remain in dedicated outer
validation. They are not inputs to semantic equality and are not discarded by
the normalizer.

For every case ID, calculate the canonical V1 bytes for all four cells and
require exact equality. Cache exactly four typed aggregate files under
`normalized/<cell-id>.json`, each containing the ordered 31 cases, and retain
31 sorted per-case comparison digests in outer evidence. The verifier
recomputes all 124 case projections itself and rejects any aggregate cache that
differs.

Mutation tests are part of the contract:

- timestamp, elapsed/performance timing, PID, path, human diagnostic/detail,
  raw serialized-size, and valid positive-to-positive remaining-duration
  mutations leave V1 unchanged while enclosing hashes are regenerated honestly;
- event reordering, duplicated or missing effects/cleanup, changed outcome,
  right, generation, authority root, lease/fencing epoch, ownership,
  source-fenced state, binding disposition, timer zero/positive class,
  assertion name/order, structured worker-error field, or fault order changes
  V1 and fails equality;
- an original integrity digest inconsistent with its typed content fails the
  inner verifier, while changing normalized typed content changes its
  regenerated V1 digest; and
- an unknown source field, unsupported schema version, malformed typed
  observation, or missing artifact fails normalization rather than comparing
  equal.

## Outer Manifest and Evidence Design

Add separate versioned types for intent/integrity and for observed results:

- `Stage2MatrixManifest` binds the common inputs, exact four cell definitions,
  inner bundle references/hashes, requested/observed identities, toolchain
  provenance, four normalized aggregate references, and claim guards.
- `Stage2EvidenceBundle` binds the manifest hash, 124 execution results, four
  Stage 1 verification summaries, 31 four-way comparison results, and the
  single cross-execution-path claim.

Every reference uses a safe relative URI under one Stage 2 root and a SHA-256.
The writer uses atomic publication: write cell artifacts and an incomplete
working manifest first, validate in a separate process, then publish the final
outer evidence only after 124/124 passes. Existing files with different bytes
cause conflict rather than overwrite.

The outer bundle does not duplicate all inner truth. It references complete
Stage 1 bundles and records enough identity/count/digest information for a
consumer to discover and verify them. Four independently valid inner bundles
are mandatory; an outer fixture or summary cannot substitute for one.

The accepted outer claim identifier is
`cross-execution-path-portability`. Add explicit guards:

```text
strict_component_model_runtime_independence = not-proven
cross_runtime_portability_under_current_roadmap = not-claimed
cross_isa_portability = not-claimed
transparent_live_migration = not-claimed
production_readiness = not-claimed
performance = not-claimed
```

The Jco cell provenance continues to disclose the exact translator lineage
from Stage 2b. An outer claim cannot rename JcoNode to an independent Runtime B.

## Independent Verification Design

Expose a separate command conceptually equivalent to:

```text
visa-conformance stage2 <stage2-evidence.json> <stage2-root>
```

Its implementation order is fixed:

1. Load Stage 2 manifest/evidence with schema and containment checks.
2. Verify all referenced bytes and hashes without following paths outside the
   root.
3. For each exact cell ID, invoke the complete existing Stage 1 structural and
   artifact validation against that cell root.
4. Require execution evidence, 31 unique catalog cases, accepted case
   lifecycle observations, and only the cooperative Stage 1 claim.
5. Validate the cell's requested/preflight/live/bundled identities and
   path-specific provenance, including Jco/Node locks and no fallback.
6. Compare common and per-case input artifacts/digests across all four cells.
7. Verify each `stage2-common-input-identity-bound` assertion, recompute V1 for
   all 124 case records, byte-check the four aggregate caches, and require one
   four-way-equal group for each of the 31 catalog IDs.
8. Validate counts, matrix/evidence cross-references, comparison records, and
   outer claim guards.

The command returns nonzero for any finding and emits structured codes that
name the cell and case. It never proceeds from a failed inner bundle to a
semantic equality claim.

## Delivery Sequence

1. Finish Stage 2a/2b and freeze fresh independently verified 31/31 same-path
   entry bundles plus exact common/toolchain identities.
2. Add Stage 2 schema constants, exact cell IDs, typed runtime-pair mapping,
   cross-execution-path claim, and overclaim guards in the conformance crate.
3. Implement the immutable pre-run common-input manifest, bind its identity to
   every pair without claiming that workers parse its JSON, and prove identical
   bytes/digests without changing Stage 1 fixture derivation.
4. Implement V1 from verified typed Stage 1 evidence, canonical encoding, and
   exhaustive allowed-exclusion/retained-semantic mutation tests.
5. Add outer artifact/manifest/evidence validation, safe-path/hash checks, and
   composition over the existing Stage 1 verifier.
6. Add the Stage 2 matrix runner and atomic evidence writer over four explicit
   calls to the existing pair-parameterized Stage 1 runner.
7. Add identity/no-fallback observation coverage for both mixed directions,
   including honest pre-instantiation destination absence.
8. Run focused representative mixed cases for success, source-retained
   rejection, pre-commit failure, post-commit failure, cancellation, cleanup,
   unknown effect, rights attenuation, and live-resource rejection.
9. Execute and independently validate all 31 Wasmtime-to-JcoNode cases.
10. Execute and independently validate all 31 JcoNode-to-Wasmtime cases.
11. Rerun and independently validate the 31 Wasmtime-to-Wasmtime and 31
    JcoNode-to-JcoNode regressions with the same pre-run common-input identity
    bound and subsequently proven.
12. Build the 124-execution outer bundle and pass the independent Stage 2
    verifier with 31 four-way-equal V1 groups.
13. Run local and locked Docker full-matrix gates plus dependency, transcript,
    provenance, fallback, and claim audits.
14. Record Stage 2c cross-execution-path completion and the accepted decision
    to retain the strict independent-runtime criterion, leaving Roadmap Stage 2
    in progress.

## Compatibility and Equality Audit

The following must be exactly equal across cells for the same case:

- original Component/world/profile/configuration/policy identities;
- case registry definition, execution/handoff/snapshot identities, per-case
  configuration/policy digests, fault schedule, and selected outcome;
- portable component-state codec and semantic snapshot projection;
- normalized source/destination canonical traces and event order;
- effect and workload outcomes, cancellation, rollback, and cleanup;
- resource identities/generations, claims, rights, binding dispositions;
- authority roots, lease/fencing epochs, ownership, source fencing;
- normalized final canonical state, replay state, explicit derived-integrity
  markers, and recomputed enclosing normalized-content digests;
- timer remaining-duration zero/positive class while preserving the initial
  arm request and all other timer semantics exactly; and
- normalized portable-envelope serialized size and all other V1 fields.

Runtime-specific differences are validated rather than compared for V1
equality: runtime selector/version, Wasmtime versus Jco/Node/V8 provenance,
generated execution graph, selected adapter path, local protocol/handle
namespace, and source file/toolchain digests that legitimately include the
concrete adapter. The typed activation boundary is likewise validated outside
V1 and must remain the canonical bootstrap or post-commit-resume boundary for
the case; it is not permission for path-dependent lifecycle behavior.

Observation/performance timing samples, PIDs, filesystem/generated paths,
human diagnostic/detail text, and raw serialized snapshot-size samples may be
absent from V1. A valid positive remaining duration may differ only through the
declared timer profile. Content-derived fields use the declared marker after
inner verification; enclosing normalized-content digests are recomputed rather
than copied from raw evidence. A mismatch outside these rules is a failed
portability result, not an invitation to widen normalization.

## Validation

```sh
python3 scripts/check-jco-node-toolchain.py
cargo fmt --all --check
cargo test --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa_jco_node -p visa-system -p visa-conformance
cargo clippy --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa_jco_node -p visa-system -p visa-conformance \
  --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/ci-gate.sh system-jco-node
scripts/ci-gate.sh system-stage2
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
scripts/run-docker-ci-gate.sh system-jco-node
scripts/run-docker-ci-gate.sh system-stage2
git diff --check
```

`system-stage2` and its Docker counterpart are deliverables of this slice. Each
must execute all four 31-case cells and invoke a separate Stage 2 conformance
process. Calling the two same-path gates plus mixed smoke tests is not
equivalent to the full-matrix gate.

## Constraints

- Do not change the guest Component, WIT world, portable-state codec, profile,
  policy, case definitions, or fault schedules for a mixed pair.
- Do not insert a source/destination adapter-specific state converter or a
  second coordinator/reducer/effect ledger.
- Do not instantiate a destination guest before durable commit or weaken the
  Stage 2a preflight ordering.
- Do not let a JcoNode selector execute Wasmtime or a Wasmtime selector execute
  JcoNode, even as a recovery fallback.
- Do not compare runner-authored summaries without independently validating
  the complete inner artifacts.
- Do not broaden V1 exclusions when a semantic mismatch appears; fix the path
  or report the failed hypothesis.
- Do not collapse allowed alternative outcomes, effect errors, authority,
  ownership, epochs, or cleanup into weaker equivalence classes.
- Do not treat translator lineage disclosure as either proof that V8 executes
  on Wasmtime or proof of independent Component Model implementation.
- Retain the accepted independent-implementation criterion: do not mark strict
  Roadmap Stage 2 complete from this shared-lineage matrix.
