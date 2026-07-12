# Capability Roadmap

Status: current capability sequence; implementation evidence controls progress.

Last reviewed: 2026-07-12.

This roadmap is ordered by architectural risk and executable evidence, not by
dates, crate count, or API breadth. A stage advances only when its exit claims
are demonstrated by the validation matrix.

## Why a vertical slice

A horizontal milestone finishes one layer, such as defining all object types or
writing an entire snapshot schema, before exercising the complete system. That
approach allowed vISA's models, projections, runtimes, and scenarios to grow
without proving that they form one authoritative path.

A vertical slice is narrow in breadth but crosses the full responsibility
chain:

```text
component
  -> runtime adapter
  -> coordinator
  -> canonical reducer and authority
  -> real resource adapter
  -> committed journal
  -> snapshot/rebind
  -> restore/fencing
  -> executable evidence
```

The slice is not a throwaway MVP. It uses the intended dependency direction and
includes success, denial, unsupported behavior, cancellation, failure,
rollback, cleanup, and evidence. Later capabilities widen the resource and
platform matrix without replacing the architecture.

## Stage 0: Architecture and repository reset

Status: complete. Durable project truth is concentrated in the README and six
canonical documents; active feature specifications remain temporary execution
plans and are removed after their accepted decisions are extracted.

Goal: establish one current project boundary and an honest development and
validation surface before expanding behavior.

Exit conditions:

- README, vision, architecture, development, validation, research, and this
  roadmap are the only durable, canonical project-level documentation sources;
- completed feature specifications are extracted into those durable truth
  sources, removed from the active tree, and retained in Git history; older
  pre-reset workflow and specification material is additionally preserved by
  the `pre-architecture-reset-2026-07-11` tag;
- local and CI commands refer to the same gate implementation;
- current test coverage and claim limitations are documented; and
- the next implementation work is the capability below, not another broad
  semantic family expansion.

Claim on exit: the project boundary and repository interface are coherent. No
new runtime-continuity claim is implied.

## Stage 1: Cooperative Stateful Component Handoff

Status: complete for the named reference cell using isolated vISA Wasmtime
adapter processes on x86-64 Linux, host-process isolation, and the durable
SQLite timer/KV provider. All 31 registered cases executed and their evidence
bundle passed independent validation.

This is the first architecture-complete capability. Its completed baseline does
not expand any of the exclusions below.

### User-visible capability

A real stateful WebAssembly component can reach an explicit safe point, move
its portable logical state from a source runtime instance to a destination
runtime instance, reacquire equal or narrower authority, rebuild a timer and a
durable key-value binding, fence the source, resume, and emit a verifiable
semantic trace.

The initial profile uses:

- component-owned job or session state;
- a paused-duration monotonic timer with a pending wait and cancellation path;
- a real durable key-value namespace with versioned or idempotent writes; and
- one externally visible effect carrying an idempotency key.

The exact KV implementation is an implementation decision, but it must be a
real persistent adapter rather than an in-memory mock.

### Why timer and durable KV

The timer exercises asynchronous waiting, deadlines, cancellation, quiescence,
and reconstruction without importing network protocol complexity.

The Stage 1 timer stores a remaining logical duration at freeze and starts a
fresh host-monotonic wait after destination commit. Time spent frozen does not
consume that duration. This deliberately avoids comparing unrelated host
monotonic epochs and makes no wall-clock deadline-continuity claim.

The KV namespace exercises external authority, persistent effects,
idempotency, target-side rebinding, and source fencing. Together they expose the
central vISA problems while keeping the resource profile reviewable.

A console-only demo would not test continuity. Starting with TCP would combine
the core protocol with connection-transfer and peer-coordination research
before the handoff state machine is trustworthy.

### End-to-end path

1. Load the component only after artifact and profile validation.
2. Grant scoped timer and KV claims through the canonical authority model.
3. Execute real effects through the runtime coordinator and adapters.
4. Request handoff and stop admitting new effects.
5. Complete, cancel, or mark every in-flight operation with an explicit
   outcome.
6. Build a portable snapshot with no fd, socket, native pointer, PC/SP,
   credential, or runtime-private object.
7. Validate the destination profile and snapshot before component execution.
8. Reauthorize the claims and create new timer and KV bindings.
9. Commit the handoff, advance the fencing epoch, and disable source writes.
10. Resume the component and verify the canonical post-restore trace and state.

### Required outcomes

The same public path must cover:

- successful handoff and resume;
- missing or insufficient destination authority rejection before any
  destination effect, plus successful attenuation to sufficient narrower
  authority;
- unsupported resource/profile rejection;
- stale generation and revoked capability rejection;
- timer completion and timer cancellation during quiescence;
- pre-commit destination failure with source continuation;
- post-commit failure with source remaining fenced;
- lost commit acknowledgement and duplicate handoff messages;
- duplicate snapshot restore and stale fencing epoch rejection;
- tampered snapshot and incompatible version rejection;
- an unknown KV outcome that is queried by operation and idempotency identity,
  then blocks handoff as indeterminate if it cannot be reconciled safely; and
- retryable, idempotent abort and cleanup without leaked bindings.

### Exit evidence

- one canonical command/event/state vocabulary for the exercised path;
- one runtime coordinator and no parallel write authority;
- real component, timer, and durable KV adapters;
- state digest equality after journal replay;
- portable snapshot round-trip and destination binding receipts;
- authority root and fencing epoch evidence before and after handoff;
- the complete named Stage 1 lifecycle and fault matrix;
- a machine-readable report tied to raw runner evidence; and
- documented steady-state cost, snapshot size, and handoff interruption, without
  setting a performance claim before measurement.

### Required deletion

The slice is not complete while its production path still depends on duplicate
object references, command/result/event vocabularies, manually synchronized
runtime ledgers, or workload-specific snapshot counters. Replaced code and
projection paths must be deleted in the same capability stage.

### Claims explicitly not earned

This stage does not prove cross-runtime or cross-ISA portability, transparent
live migration, arbitrary process continuation, open TCP preservation,
universal exactly-once effects, real kernel/device enforcement, production
availability, or a validated commercial market.

## Stage 2: Independent runtime portability

Status: in progress. The runtime-neutral adapter contract, Jco-translated
Node/V8 reference cell, and four-direction cross-execution-path harness are
implemented. The strict exit criterion below remains open because Jco's
Component translation lineage includes `wasmtime-environ`.

Goal: restore the same Stage 1 envelope through a genuinely independent
WebAssembly execution adapter, with no destination-specific component code or
bypass path.

Entry condition: Stage 1 is complete and its adapter contract is public inside
the repository.

Engineering substages:

1. **Stage 2a -- runtime adapter contract (complete):** one engine-neutral
   lifecycle, portable component-state, host bridge, and structured failure
   contract.
2. **Stage 2b -- second execution cell (complete):** the unchanged Component
   translated by the pinned Jco toolchain and executed in isolated Node/V8
   processes, without a Wasmtime execution fallback.
3. **Stage 2c -- bidirectional matrix (complete):** all four Wasmtime/JcoNode
   source and destination pairs over the unchanged 31-case registry, with four
   inner Stage 1 verifications and one normalized outer verifier.

Completing these substages earns only the named
`cross-execution-path-portability` result. It does not silently weaken the
independent-implementation exit criterion.

Exit conditions:

- two independently implemented runtime paths execute the same capability
  profile;
- normalized semantic traces satisfy the same observable rules;
- differences in scheduling or internal resource tables do not enter the
  portable envelope; and
- unsupported runtime features appear as explicit profile results.

Claim on exit: the published component/resource profile is portable across the
two named runtime implementations. No broader runtime or ISA claim follows.

## Stage 3: Rich external resources

Status: not started. The current timer/KV profile does not implement file or
network continuity.

Goal: validate the continuity-policy extension model with resources whose
correct result is not always direct reconstruction.

Candidate profiles include file identity/offset/lock state and a network
resource that must reconnect, proxy, or reject. Each profile must define
pending-operation, peer, credential, and cleanup behavior.

Exit condition: at least two resource families extend the core without adding
provider implementations or scenario names to the canonical vocabulary.

Claim on exit: only the named resource dispositions and adapters are supported.

## Stage 4: Real target and ISA matrix

Status: not started. All current system and Stage 2 matrix executions use
x86-64/amd64.

Goal: exercise the same semantic contract through a no-std/reference kernel or
other real target adapter and on each ISA named in a published matrix.

This stage validates that machine authority and code/execution carriers remain
outside portable semantic truth. Emulation, real hardware, runtime portability,
and device enforcement remain separate evidence dimensions.

Exit condition: every advertised matrix cell has an executable runner,
identified artifacts, raw evidence, and explicit not-supported/not-run states.

## Stage 5: Confidential continuity profile

Status: not started. No TEE, attestation, KMS, or confidential-continuity cell
has executed.

Goal: integrate fresh destination attestation and external policy/KMS decisions
without making vISA an attestation or secret-management service.

The profile binds component, state, policy, authority, journal, and evidence
digests to a fresh verifier result. Destination secrets are newly released;
source authority is revoked and fenced.

Entry condition: ordinary authority continuity and failure recovery are already
proven under Stage 1 and Stage 2 fault injection.

Claim on exit: only the named TEE/verifier/policy integration is supported.

## Roadmap governance

- Do not advance a stage because types, schemas, or tests exist; advance when
  the end-to-end evidence and deletion conditions are satisfied.
- Add a capability only when it exercises the final dependency direction.
- Keep unsupported matrix entries explicit.
- Promote durable boundary changes into vision or architecture; keep
  implementation details in code and tests.
- Revise or stop the roadmap when research hypotheses or external demand are
  falsified.
