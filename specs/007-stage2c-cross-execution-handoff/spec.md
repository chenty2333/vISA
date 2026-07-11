# Feature Specification: Stage 2c Cross-Execution-Path Handoff Matrix

Status: accepted; Stage 2c is complete, the strict independent-runtime
criterion is retained, and Roadmap Stage 2 remains in progress.

Stage 2c executes the completed cooperative-handoff profile in all four
source/destination combinations of the Stage 2a Wasmtime adapter and the Stage
2b JcoNode translated execution path. Every cell runs the unchanged 31-case
registry over the same original Component, profile, configuration, policy, and
fault schedules. An outer evidence bundle proves matrix completeness and equal
normalized observable behavior across all 124 case executions.

The earned claim is deliberately named **cross-execution-path portability**.
JcoNode executes generated core WebAssembly with Node/V8, but its pinned Jco
translator lineage includes `wasmtime-environ`. Therefore this slice does not,
by itself, prove two genuinely independent Component Model implementations,
cross-ISA portability, or the current strict wording of Roadmap Stage 2.

## Scope

- Execute exactly these four named cells:
  `Wasmtime -> Wasmtime`, `JcoNode -> JcoNode`, `Wasmtime -> JcoNode`, and
  `JcoNode -> Wasmtime`.
- Run all 31 registered Stage 1 cases in every cell, producing 124 real case
  executions rather than fixtures, copied results, or selector-only tests.
- Use one immutable input set: the exact same original Component bytes and
  component digest, WIT world, profile bytes and digest, runner configuration,
  per-case configuration, policy, case registry, and fault schedules.
- Add a versioned normalized observable trace whose projection preserves every
  portable behavioral distinction needed to detect cross-path divergence.
- Add a Stage 2 outer matrix manifest and evidence envelope that hash and
  reference four complete, independently valid Stage 1 execution bundles.
- Add an independent Stage 2 verifier that validates each inner Stage 1 bundle
  first, then proves matrix completeness, input and runtime identity, artifact
  integrity, no fallback, and four-way trace equality.
- Add locked local and Docker full-matrix gates while retaining the individual
  Wasmtime and JcoNode cell gates.

## Exact Matrix

The outer manifest uses stable cell IDs and admits no alias or implicit
default:

| Cell ID | Requested source | Requested destination |
| --- | --- | --- |
| `wasmtime-to-wasmtime` | `Wasmtime` | `Wasmtime` |
| `jco-node-to-jco-node` | `JcoNode` | `JcoNode` |
| `wasmtime-to-jco-node` | `Wasmtime` | `JcoNode` |
| `jco-node-to-wasmtime` | `JcoNode` | `Wasmtime` |

Every worker receives its selector explicitly. Requested and preflight-verified
identities must agree with the inner and outer bundles. A typed instantiation
observation is inferred only from successful source bootstrap or destination
post-commit resume protocol progression. A selected path that is unavailable or
fails does not retry through the other implementation. Missing Jco/Node tools,
a translation failure, a child failure, or an unsupported interface fails the
cell and therefore the matrix.

Cases whose accepted path rejects before destination instantiation remain real
case executions. They record the selected and successfully preflighted
destination plus an explicit `not-instantiated-by-case-design` observation;
they do not fabricate a destination instantiation observation. Positive
destination cases must include a typed `Live` observation inferred from a
successful post-commit resume. For JcoNode, the adapter first strictly validates
the Node/V8 `ready` envelope internally; that envelope is not persisted.

## Common Input Invariant

Within each host or Docker matrix run, the runner creates one immutable input
manifest before starting any cell. It identifies and hashes:

- the original `.component.wasm` bytes and accepted Component Model world;
- the component, profile, global configuration, and authority-policy bytes;
- all 31 case IDs in canonical registry order;
- each case's derived configuration and policy digest;
- every deterministic fault schedule and allowed outcome set;
- the portable component-state codec/version; and
- the Stage 1 evidence and semantic-trace schema versions bound by this slice.

The orchestrator serializes and hashes that manifest before starting any cell,
then binds the manifest identity into every retained cell with the
`stage2-common-input-identity-bound` assertion. Workers do not read or parse the
JSON manifest; the assertion records identity binding, not direct worker
consumption. The outer verifier independently reads the referenced bytes,
recomputes their hashes and typed digests, and proves that every inner bundle
has the same global and per-case inputs. Each cell still creates fresh worker
processes, runtime instances, provider storage, and execution-local handles. A
translated Jco output graph is a derived execution artifact; it can differ from
a Wasmtime prepared artifact but cannot replace the original Component
identity.

Runtime-specific component source, a changed WIT world, a Jco-only relinked
Component, a selector-dependent profile, or a cell-specific expected result is
forbidden.

## Normalized Observable Trace V1

Stage 2c introduces
`visa-stage2-normalized-observable-trace-v1`. It is a typed projection from an
already verified Stage 1 case and its hash-checked artifacts, not a generic JSON
filter and not a second reducer or semantic oracle.

For each case, V1 retains at least:

- case ID, execution/handoff/snapshot identities, per-case configuration and
  policy digests, selected outcome, exit classification, and the ordered fault
  schedule;
- every source and destination semantic trace with its fixed role, scope, base
  cursor, base state, ordered journal entries, final state, and claimed-final
  marker;
- canonical command/event order and payloads, including effect request,
  completion, denial, conflict, unavailable, indeterminate, cancellation, and
  cleanup outcomes;
- resource identities and generations, required/exposed rights, authority
  roots and derivation-relevant results, lease and fencing epochs, binding
  dispositions and receipts, ownership, and source-fenced status;
- safe-point, snapshot/restore, rollback, abort, retry, activation, cleanup,
  and no-resurrection observations represented by the typed Stage 1 evidence;
- structured worker-error observations in their original role and order,
  including code, retryability, provider kind, adapter kind, and workload kind;
- final canonical state, replay state, and portable-state/snapshot semantic
  identity where the case produces them; and
- the serialized size of the normalized portable envelope where one is
  present.

The projection preserves the order in which each journal branch was recorded.
It may sort only collections whose contract is explicitly unordered, using a
schema-defined canonical key. It must not sort journal entries, collapse
duplicate effects or cleanup attempts, merge source and destination branches,
replace structured outcomes with success/failure booleans, or discard a field
because two paths disagree.

Within the observable source domain, V1 excludes:

- wall-clock or host-monotonic observation timestamps, elapsed-time samples,
  and raw performance timing samples;
- operating-system process IDs;
- filesystem or generated-artifact paths; and
- human-readable engine/translator diagnostics, worker error messages, and
  assertion detail text; and
- raw serialized snapshot-size samples, which remain in the verified inner
  evidence rather than becoming a four-cell equality requirement.

Assertion names and their recorded order remain in V1. Common-input identity
and runtime/translation provenance are validated from their dedicated typed
outer fields and raw assertions, not from human assertion details.

Timer equality uses one explicit profile. The original source `TimerArm`
requested duration is retained exactly. A remaining duration observed after
real execution time has elapsed, including freeze, restore, and rearm state, is
projected as the typed class `zero` or `positive`. Changing zero to positive or
positive to zero changes V1; changing one valid positive remaining duration to
another does not. Timer state and event order, operation/idempotency identity,
rights, lease/fencing epochs, ownership, cancellation, delivery, and cleanup
remain exact. The complete Stage 1 verifier first validates every raw timer
value and profile constraint before Stage 2 applies this equivalence.

`JournalEntry` input/output state digests, `EffectRequest.request_digest`,
`EvidenceRef.digest`, and `SnapshotEnvelope` integrity are content-derived
integrity fields rather than independent portable observations. The inner
verifier first checks their original values against the original typed content.
V1 then replaces those already-verified derived fields with its explicit
schema marker and computes the enclosing normalized trace, snapshot, and cache
digests from normalized typed content. This is not arbitrary digest deletion,
and a path-specific integrity failure cannot be normalized away. Unknown fields
in a supported input schema cause normalization failure rather than silent
deletion.

Runtime selectors and versions, bundle IDs, artifact hashes, toolchain
provenance, and local RPC/request/handle IDs are not portable behavioral trace
fields. They are validated separately by exact outer-matrix, provenance,
containment, and no-fallback rules; the normalizer cannot delete or rewrite
them to satisfy trace equality. Adapter startup handshakes are validated inside
the adapter and tested for strict rejection, but their envelopes are not
persisted or inspected by the outer rules.

The independent verifier recomputes V1 from each inner bundle. Runner-emitted
normalized artifacts are caches only and must byte-match the verifier's
canonical encoding. A schema change requires a new version and an explicit
four-cell regeneration; the verifier never guesses compatibility.

For each of the 31 case IDs, all four recomputed V1 traces must be exactly
equal. An outcome that is individually allowed by Stage 1 but differs between
cells still fails Stage 2c.

## Outer Evidence Contract

The retained artifact tree has this logical shape:

```text
stage2-root/
  stage2-common-input.json
  inputs/
    component.wasm
    world.wit
    profile.json
    configuration.json
    authority-policy.json
  stage2-matrix-manifest.json
  stage2-evidence.json
  normalized/
    wasmtime-to-wasmtime.json
    jco-node-to-jco-node.json
    wasmtime-to-jco-node.json
    jco-node-to-wasmtime.json
  cells/
    wasmtime-to-wasmtime/
      stage1-evidence.json
      ... complete Stage 1 artifact root ...
    jco-node-to-jco-node/
      stage1-evidence.json
      ... complete Stage 1 artifact root ...
    wasmtime-to-jco-node/
      stage1-evidence.json
      ... complete Stage 1 artifact root ...
    jco-node-to-wasmtime/
      stage1-evidence.json
      ... complete Stage 1 artifact root ...
```

The versioned outer manifest records the common-input manifest and digest,
exact cell table, each inner bundle path and SHA-256, requested and observed
source/destination identities, execution/translation provenance, registry
digest, 31-case count, normalized-trace references, and explicit no-fallback
and claim-boundary fields. Paths are safe relative paths beneath the Stage 2
root; symlinks, escapes, duplicate cell IDs, duplicate bundle references, and
unmanifested cells are rejected.

Each normalized cache is one typed aggregate containing the ordered 31 cases
for its cell. The versioned outer evidence envelope records 124/124 completed
execution results, four inner-verifier results, 31 per-case four-way comparison
digests, the outer manifest digest, and only the
`cross-execution-path-portability` claim. A `passed` boolean, precomputed
digest, or runner-generated verifier report is not proof on its own.

The independent Stage 2 verifier executes these gates in order:

1. load the outer schemas with unknown-field rejection and verify root
   containment plus every referenced hash;
2. run the existing complete Stage 1 structural and artifact verifier over
   each of the four inner bundles;
3. require exactly four execution-kind bundles and exactly 31 unique required
   case IDs in each, for 124 executions total;
4. validate the exact requested/observed identity pair for each cell, including
   Jco translation/Node/V8 provenance and absence of Wasmtime fallback;
5. prove exact common Component/profile/configuration/policy/registry/fault-
   schedule identity across all cells and every case;
6. independently derive V1 for each case/cell and require four-way equality;
7. validate the outer manifest/evidence relationship and claim guards; and
8. return success only if all prior gates succeeded.

An inner Stage 1 failure stops that cell from participating in comparison; the
outer verifier must not normalize malformed evidence and report a misleading
cross-path result.

## Requirements

- **FR-001**: The matrix must contain exactly the four stable cells above, with
  explicit source and destination selectors and no default, alias, retry, or
  fallback path.
- **FR-002**: Each cell must execute all 31 required cases through its selected
  source and destination adapters, producing exactly 124 execution records.
- **FR-003**: Within one matrix run, all cells must use byte-identical original
  Component, world, profile, configuration, and policy inputs plus identical
  case registry and fault schedules. Per-case configuration and policy digests
  must also agree. The pre-run common manifest identity must be bound into every
  cell with `stage2-common-input-identity-bound`; workers are not required to
  parse that JSON, and the outer verifier must prove the underlying byte/digest
  identity.
- **FR-004**: Wasmtime and JcoNode must consume the same portable component
  state and canonical snapshot contract. Runtime/translator objects, native
  handles, generated paths, and engine identity must not enter portable truth.
- **FR-005**: Every cell must use fresh isolated workers, providers, runtime
  instances, and local handle namespaces; no cell may consume another cell's
  provider state or replay its worker outputs.
- **FR-006**: Requested and preflight-verified execution identities must agree
  with the inner and outer bundles. Typed `Live` instantiation must be inferred
  only from successful source bootstrap or destination post-commit resume after
  adapter-internal startup validation. A Jco `ready` envelope is not retained.
  Honest pre-instantiation rejection markers are permitted only for cases whose
  verified path never instantiates the destination.
- **FR-007**: Selecting JcoNode must never load, invoke, or retry through
  `visa_wasmtime`; selecting Wasmtime must never route guest execution through
  Node. Provenance and raw transcripts must make this machine-checkable.
- **FR-008**: The normalized observable trace must use a versioned,
  deny-unknown-fields schema and deterministic canonical encoding.
- **FR-009**: Normalization must preserve journal branch/entry order, effect
  outcomes, resource identities/generations, rights, authority, lease/fencing
  epochs, ownership/source fencing, cancellation, rollback, cleanup, and
  no-resurrection behavior. It must also preserve structured worker error code,
  retryability, provider/adapter/workload kind, role, and order while excluding
  only the human message.
- **FR-010**: V1 must preserve the original source timer-arm request exactly
  and compare elapsed remaining durations with the explicit zero-versus-
  positive profile. Raw timing and raw serialized snapshot-size observations
  remain in verified inner evidence; V1 records normalized portable-envelope
  serialized size. PID, path, and human diagnostic/detail values are excluded.
- **FR-011**: Runtime identity, toolchain provenance, artifact integrity, and
  local protocol isolation must be verified outside trace equality rather than
  silently normalized away.
- **FR-012**: For each case, the selected outcome and independently recomputed
  V1 trace must be exactly equal across all four cells; merely belonging to the
  same Stage 1 allowed-outcome set is insufficient.
- **FR-013**: The outer evidence must hash-reference four self-contained Stage
  1 execution bundles, exactly four typed normalized cell aggregates with 31
  cases each, and all common-input artifacts beneath one contained root. It
  must record 31 per-case comparison digests rather than claim 124 cache files.
- **FR-014**: The Stage 2 verifier must invoke the complete existing Stage 1
  bundle and artifact validation for each cell before any cross-cell check.
- **FR-015**: The verifier must recompute normalized traces from verified inner
  artifacts and reject missing, extra, duplicated, reordered, or mutated
  cases/events/effects/rights/epochs/ownership/cleanup observations. Original
  content-derived integrity values must pass Stage 1 first; V1 must replace
  derived fields only with its declared marker and recompute enclosing
  normalized-content digests.
- **FR-016**: Mutation tests must prove that changing only an excluded
  timestamp, PID, path, human diagnostic/detail, valid positive remaining
  duration, or raw timing/size sample leaves V1 equal as specified, while
  changing timer zero-versus-positive class, assertion name/order, structured
  error fields, or any other retained semantic value/order fails verification.
- **FR-017**: The outer claim must be exactly cross-execution-path portability
  for the named cooperative-handoff profile. Inner bundles retain only their
  Stage 1 cooperative-handoff claim.
- **FR-018**: Evidence must disclose Jco 1.25.2,
  `js-component-bindgen` 2.0.11, `wasmtime-environ` 45.0.1 translator lineage,
  Node v24.15.0, and V8 13.6.233.17-node.48, subject to the Stage 2b locked
  toolchain verifier.
- **FR-019**: The outer verifier must reject strict Component Model runtime
  independence, generic cross-runtime, cross-ISA, transparent migration,
  production, security, or performance claims from this matrix.
- **FR-020**: Local focused, individual-cell, and full-matrix gates plus locked
  Docker full/system/full-matrix gates must pass with independent verifier
  agreement and no skipped matrix cell.
- **FR-021**: Completion records must preserve the accepted strict independent-
  implementation criterion, leave Roadmap Stage 2 in progress, and require a
  genuinely independent Runtime B before claiming strict cross-runtime
  portability.

## Non-goals

- Implementing a third execution path or replacing JcoNode in this slice.
- Claiming two genuinely independent Component Model implementations,
  `CrossRuntimePortability` under the current strict roadmap wording, or
  cross-ISA portability.
- Adding file/network resources, WASI 0.3 async, transparent stack/process
  continuation, confidential computing, production hardening, or performance
  targets.
- Changing the Component, WIT world, 31-case registry, canonical
  command/event/state/journal schemas, profile, snapshot, component-state codec,
  coordinator authority, or Stage 1 failure semantics.
- Replacing the four independent Stage 1 validations with an outer schema
  check, trusting runner-authored pass flags, or turning normalization into a
  second semantic ledger.
- Ignoring a mismatched outcome because both values are allowed, erasing an
  engine-specific semantic bug as a diagnostic, or using a Wasmtime fallback
  to keep a JcoNode cell green.
- Editing `docs/ROADMAP.md` or declaring Stage 2 complete as an automatic side
  effect of implementing this specification.

## Completion and Roadmap Decision Rule

Stage 2c is complete when all four explicitly selected cells execute 31/31
cases over identical inputs, each inner Stage 1 bundle independently passes,
the Stage 2 verifier proves exact matrix identity and four-way V1 equality for
124/124 executions, local and Docker gates agree, all provenance is retained,
and no fallback or claim overreach is present.

That completion earns this precise statement:

> The named cooperative stateful handoff profile preserves its normalized
> observable behavior across the Wasmtime execution path and the Jco-translated
> Node/V8 execution path in both source/destination directions.

It does not satisfy the current Roadmap Stage 2 exit condition of "two
independently implemented runtime paths." The accepted decision is to retain
that strict criterion. Implementation status therefore says “Stage 2c matrix
complete” while keeping “strict Roadmap Stage 2 in progress”; a genuinely
independent Runtime B is still required for strict closure.
