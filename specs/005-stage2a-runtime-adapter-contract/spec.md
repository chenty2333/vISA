# Feature Specification: Stage 2a Runtime-Neutral Component Adapter Contract

Status: accepted

Stage 2a creates the smallest real adapter boundary needed to add another
WebAssembly execution path. It extracts the engine-neutral rules already
exercised by the completed Stage 1 Wasmtime cell, requires destination runtime
compatibility to be established before durable handoff commit, and keeps the
existing Wasmtime cell fully executable.

This is an enabling slice, not a cross-runtime claim. Stage 2b and Stage 2c now
exercise the Jco-translated Node/V8 path, but its disclosed
`wasmtime-environ` lineage does not satisfy the independent-implementation exit
criterion. Strict Roadmap Stage 2 therefore remains in progress.

## Scope

- Add a workspace runtime crate, `visa_component_adapter`, for the shared
  component-adapter contract, portable component state, normalized failures,
  logical host bridge, and guest/coordinator lifecycle rules.
- Refactor `visa_wasmtime` into one implementation of that contract while
  retaining only Wasmtime engine, bindgen, WIT conversion, store, resource-table,
  link, instantiation, and trap glue in that crate.
- Add a non-executing destination runtime preflight that validates the selected
  runtime's artifact and Component Model interface support before coordinator
  restore, destination binding preparation, or durable handoff commit.
- Add an explicit worker runtime selector and report the runtime implementation
  and version actually used by each worker. Stage 2a accepts only the Wasmtime
  implementation.
- Replace adapter/workload error-string assertions with structured,
  runtime-neutral failure categories while retaining engine text only as
  diagnostic detail.
- Re-run the unchanged 31-case Stage 1 registry through explicitly selected
  Wasmtime source and destination workers and its independent evidence verifier.

## Adapter Contract

The repository-public contract is limited to the accepted cooperative-handoff
profile. It exposes the operations the current component actually needs:

```text
runtime artifact preflight
  -> instantiate after durable commit or source recovery
  -> activate
  -> reach or roll back a safe point
  -> restore destination state or thaw source state
  -> deliver/cancel the profiled timer callback
  -> inspect normalized workload status
  -> return the unchanged Coordinator when setup fails before guest execution
```

The contract also separates three shared responsibilities:

- **State:** `ActivationRequest`, `ComponentSafePoint`, portable component
  state, normalized component status and phase, component digest, and the
  existing `VISACS01` / `visa-component-state-v1` codec.
- **Host:** logical KV/timer bindings, authority and receipt validation,
  operation/idempotency derivation, coordinator-mediated effects, and exact
  mapping from canonical/provider outcomes to workload results.
- **Lifecycle:** safe-point ordering, state/timer agreement, rollback,
  destination restore preconditions, source thaw preconditions, exact binding
  of public restore/thaw input to canonical portable-state bytes, and timer
  callback causal-parent handling. Private safe-point rollback may thaw the
  just-frozen uncommitted state; that path is not the public thaw contract.

These shared modules do not own canonical state or durable handoff sequencing.
`visa_runtime::Coordinator` remains the only production semantic sequencer and
`semantic_core` remains the only transition authority.

## Destination Ordering

The destination path must execute in this order:

```text
snapshot, profile, and provider-support validation
  -> selected runtime artifact/digest/WIT/capability preflight
  -> Coordinator restore from the validated snapshot and journal
  -> reauthorization and candidate binding preparation
  -> durable handoff commit and source fencing
  -> instantiate the preflighted engine artifact
  -> restore component-owned state and fresh runtime-local handles
  -> canonical destination resume
```

Runtime preflight may create and compile an engine artifact and perform
non-executing link/type checks. It must not instantiate the guest, call an
export, create guest-visible resource handles, execute a provider effect, take
the destination provider from its pending state, restore a coordinator, append
a journal event, or create a binding receipt.

Successful preflight produces an opaque, process-local prepared artifact bound
to the selected runtime implementation, component digest, profile digest, and
required Component Model world. It is neither portable state nor evidence and
must never be serialized. Destination load and post-commit instantiation must
reject a missing, stale, or mismatched prepared artifact.

Preflight cannot promise that later memory allocation or host execution will
never fail. A genuine operational failure after commit remains explicit and
must leave the source fenced. Artifact invalidity, unsupported imports/exports,
profile incompatibility, and known runtime capability mismatch must not first
be discovered after commit.

## Requirements

- **FR-001**: `visa_component_adapter` must contain no Wasmtime type, bindgen
  output, store/resource-table handle, engine object, or engine-specific error
  string in its portable or normalized public types.
- **FR-002**: Moving the component-state codec must preserve its accepted magic,
  encoding name, field order, canonical bytes, corruption behavior, and digest
  inputs. Existing Stage 1 snapshots remain readable without a compatibility
  shim or second codec.
- **FR-003**: Shared host code may access effects only through
  `visa_runtime::Coordinator`; it may not call provider mutation ports directly
  or maintain a component-side semantic ledger.
- **FR-004**: Runtime-local resource tables contain only fresh host bindings.
  Native handles, table indices, engine objects, and prepared artifacts never
  enter `contract_core`, a profile, snapshot, journal, or canonical digest.
- **FR-005**: Shared lifecycle code must preserve current safe-point, rollback,
  restore, thaw, cancellation, cleanup, and callback ordering, including the
  rule that all guest-owned imported handles are returned at a safe point.
  Public destination restore and source thaw must reject portable bytes that
  differ from the coordinator's canonical state before invoking the guest or
  creating fresh runtime-local handles.
- **FR-006**: Wasmtime-specific code must be limited to engine configuration,
  component compilation/pre-instantiation, generated WIT value conversion,
  linker/store/resource-table operations, guest calls, and trap diagnostics.
- **FR-007**: Destination runtime preflight must complete successfully before
  `Coordinator::restore`, destination preparation, binding receipts, or commit
  are reachable through the worker protocol.
- **FR-008**: Repeated valid preflight is side-effect free and equivalent;
  invalid artifact, digest, world, or runtime capability results are structured
  pre-commit failures and leave source ownership usable and the destination
  inactive.
- **FR-009**: Adapter and workload failures have stable structured kinds.
  Runners and conformance assertions compare those kinds and canonical
  outcomes, never engine display strings. Human-readable engine text may be
  retained as non-normative diagnostic detail.
- **FR-010**: Existing typed workload distinctions remain observable, including
  denied, conflict, stale binding, indeterminate, unavailable, wrong timer,
  invalid state, and safe-point unavailable results.
- **FR-011**: Worker initialization must select a `RuntimeImplementation`, and
  initialization results must report the actual implementation and version.
  Stage 2a exposes only `Wasmtime`; the runner rejects a requested/observed
  identity mismatch.
- **FR-012**: Runtime selection and identity are execution metadata only. They
  must not enter the canonical contract, profile digest, portable component
  state, snapshot, resource claim, or handoff journal.
- **FR-013**: The Stage 1 evidence environment must be derived from the runtime
  identities returned by the source and destination workers rather than an
  unverified runner constant. It continues to claim only the Wasmtime-to-
  Wasmtime reference cell.
- **FR-014**: All 31 existing case IDs, allowed outcomes, canonical traces,
  final/replay state digests, authority and fencing results, and fault schedules
  must remain semantically unchanged. Runtime identity fields and structured
  diagnostic projections may become more precise; run IDs, paths, timestamps,
  provenance, and whole-bundle hashes may change.
- **FR-015**: Dependency checks must enforce the one-way edge from
  `visa_wasmtime` to `visa_component_adapter`, and forbid dependencies from the
  contract, reducer, profile, provider ports, or coordinator back to a concrete
  engine adapter.
- **FR-016**: Focused adapter tests, the complete local 31-case system run, its
  independent verifier, and local/Docker full and system gates must pass with
  the locked dependency graph.

## Non-goals

- Adding the second named execution cell in the engineering matrix; that is
  Stage 2b. It does not by itself establish an independently implemented
  Runtime B.
- Wasmtime-to-JcoNode, JcoNode-to-Wasmtime, or a four-cell execution-path
  evidence bundle; that is Stage 2c.
- Claiming cross-runtime, cross-ISA, new file/network resource, transparent
  process migration, confidential-computing, production, or performance
  support.
- Changing the cooperative-handoff WIT world, the 31-case registry, canonical
  command/event/state/journal schemas, profile semantics, snapshot schema, or
  the `VISACS01` state format.
- Introducing a dynamic plugin ABI, runtime registry service, general WASI
  implementation, or abstraction for workloads not exercised by this profile.
- Instantiating or executing guest code during preflight, serializing an
  engine-prepared artifact, or allowing a runtime adapter to commit canonical
  state directly.
- Creating a Stage 2 cross-runtime verifier or claiming that one refactored
  Wasmtime implementation constitutes runtime independence.

## Completion Rule

Stage 2a is complete only when the shared contract has one Wasmtime
implementation, invalid or unsupported destination artifacts fail through the
non-executing preflight before coordinator restore and binding preparation, the
worker reports and verifies its selected runtime with structured errors, all 31
Stage 1 cases and the independent verifier pass unchanged, dependency checks
prove the engine boundary, and local/Docker full and system gates agree. The
resulting project status must still identify strict Roadmap Stage 2 as in
progress.
