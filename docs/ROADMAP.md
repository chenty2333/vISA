# Capability Roadmap

Status: current capability sequence; implementation evidence controls progress.

Last reviewed: 2026-07-17.

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

The Stage 1 timer stores a remaining logical duration only for a pending freeze
and starts a fresh host-monotonic wait after destination commit. Completed or
cancelled freezes retain their terminal disposition and are not recreated. Time
spent frozen does not consume a pending duration. This deliberately avoids
comparing unrelated host monotonic epochs and makes no wall-clock
deadline-continuity claim.

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

Status: complete for the named Wasmtime and source-lock-bound Wacogo runtime
paths on x86-64/amd64 Linux with the timer/KV profile. The strict implementation
and fresh Host/Docker exit evidence completed the exact four-cell matrix with
124/124 executions and 31/31 normalized equality groups, all inner and outer
independent verification passed, and the stage-closing repository revision
passed pushed CI at its exact commit. The legacy Wasmtime/JcoNode path remains
a separate `cross-execution-path-portability` result.

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

The separate strict closure path qualifies the source-lock-bound Wacogo
derivative as independent of Wasmtime and `wasmtime-environ` lineage for the
exercised Component Model surface. It executes Wacogo same-path and both
Wasmtime/Wacogo mixed directions over the unchanged 31-case registry and
independently verifies the exact four-cell strict matrix. This does not upgrade
the legacy JcoNode evidence or imply support by unmodified upstream Wacogo.

Exit conditions:

- two independently implemented runtime paths execute the same capability
  profile;
- normalized semantic traces satisfy the same observable rules;
- differences in scheduling or internal resource tables do not enter the
  portable envelope; and
- unsupported runtime features appear as explicit profile results.

Fresh Host and Docker runs satisfy these technical exit conditions for the two
named runtime implementations, and the stage-closing repository revision passed
pushed CI at its exact commit.

Claim on exit: `strict-cross-runtime-continuity` for Wasmtime and the
source-lock-bound Wacogo derivative on x86-64/amd64 Linux with the timer/KV
profile. The legacy Wasmtime/JcoNode evidence remains
`cross-execution-path-portability`. No cross-ISA, file/network, confidential,
production-readiness, or broader runtime claim follows.

## Stage 3: Rich external resources

Status: complete for the two named bounded Wasmtime-to-Wasmtime resource
profiles on x86-64/amd64 Linux. Stage 3A and Stage 3B passed their executable
runners and independent structural bundle verifiers, the unchanged Strict
Stage 2 control remained green on the stage-closing implementation revision,
and that revision passed pushed CI at its exact commit.

The completed Strict Stage 2 timer/KV matrix is the immutable control baseline
for this widening step. Stage 3 does not modify or re-sign its Component,
31-case registry, WIT, normalizers, or digest locks.

Goal: validate the continuity-policy extension model with resources whose
correct result is not always direct reconstruction.

### Stage 3A -- bounded regular-file continuity

Implementation status: the separate regular-file WIT world, guest, typed
profile, portable state codec, Wasmtime adapter, Linux host provider, 12-case
system runner, evidence schema, registry lock, and independent structural
verifier are in place. The executable gate passes all 12 accepted cases for the
`bounded-regular-file-continuity` claim.

The portable state contains logical object identity, relative path, logical
offset, version, size, content digest, durability, lock state, and operation
identity. Destination binding uses scoped Linux `openat2` resolution and
revalidates the root, object, authority, and lease rather than serializing an
fd, inode, device number, birth time, or absolute host root. A qualified
filesystem must report `STATX_BTIME`; the provider checks the fd-derived
device/inode/birth-time tuple for both root and file and fails closed when that
capability is absent. This detects ordinary inode-number reuse with a different
creation timestamp, not hostile-host metadata forgery or every possible tuple
collision. A second SQLite immediate transaction holds the final
authority/lease/pre-state recheck, file effect, and provider outcome in the same
ordering domain as handoff commit.

The accepted cases cover read/write and offset continuity, append, truncate,
rename while preserving object identity, replacement rejection, detection of
identity/content/version drift already observable before a provider operation,
advisory-lock conflict and reacquisition, durability with lost-ack
reconciliation, source fencing, idempotent cleanup, indeterminate-write
blocking, and destination reauthorization denial. Concurrent writers are
ordered or rejected only when they participate in the same advisory lock/lease
protocol. The SQLite fence orders effect admission against handoff commit; it
does not make the native file change and SQLite outcome one atomic transaction,
so a local finalization failure remains indeterminate until reconciliation.

Explicit non-claims: arbitrary directory-tree continuity, devices, FIFOs,
arbitrary already-open file descriptors, and transparent migration of every
filesystem object. Stage 3A also does not provide atomic compare-and-mutate
against an uncooperative concurrent writer that bypasses its advisory
lock/lease protocol.

### Stage 3B -- bounded logical-request continuity

Implementation status: the separate logical-request WIT world, guest, typed
profile, portable state codec, Wasmtime adapter, durable provider ledger, real
bounded loopback TCP peer/protocol, 14-case system runner, evidence schema,
registry lock, and independent structural verifier are in place. The executable
gate passes all 14 accepted cases for the
`bounded-logical-request-continuity` claim.

The portable state contains peer identity, a credential reference, logical
operation ID, request digest, request phase, response cursor and metadata,
rejection, and continuity disposition. Native socket/TCP sequence state,
runtime futures, and credential material remain provider-local. Destination
binding reacquires credential material and uses provider-level operation-ID
lookup/deduplication instead of treating a transport handle as continuity.
The bounded `VISALR03` loopback protocol authenticates the configured peer
with a fresh nonce and HMAC-SHA-256 before sending an application request
frame, never transmits the reusable credential itself, derives the Execute
digest from authenticated request bytes, and binds Lookup/Cancel to both
operation ID and the explicitly carried expected digest. Application sends are serialized with
the SQLite handoff transaction by a last-moment authority/lease/binding check;
an immediate-transaction revision compare-and-save preserves terminal phase,
response cursor, and cleanup monotonicity. This is a bounded host-provider
admission fence, not atomic commit of the remote peer's effect.

The accepted cases cover completion before freeze, pending-before-send,
lost-ack deduplication, unknown-completion reconciliation, partial-response
resume, timeout, cancellation/completion races, peer mismatch, credential
reacquisition and denial, unsafe non-idempotent replay blocking, explicit raw
live-TCP rejection, source fencing, and idempotent cleanup.

Explicit non-claims: unconditional preservation of an arbitrary live TCP
transport, socket sequence state, generic future/stream continuation, and a
general asynchronous runtime. The authenticated loopback protocol is not a
general encrypted transport or TLS replacement.

### Stage 3 qualification boundary

Both current Stage 3 runners use separate source and destination Wasmtime
stores, coordinators, and provider instances backed by local SQLite continuity
within one OS system-runner process on x86-64/amd64 Linux. This is sufficient
for the current local-rebinding profiles; it is not dual-worker, process-
isolation, cross-host, or cross-target evidence. Their evidence requires
`independent_runtime_coverage=false` and lists Wacogo as an unsupported Stage 3
runtime. The independent Wasmtime/Wacogo result earned in Strict Stage 2
therefore does not carry into either Stage 3 resource profile.

Exit conditions:

- both named resource families extend the shared canonical profile/effect path
  without adding provider implementations or scenario names to the canonical
  vocabulary;
- each accepted registry executes through its public Component, runtime,
  coordinator, provider, handoff, and evidence boundaries and passes its
  independent structural bundle verifier;
- the ordinary repository gate, both Stage 3 system gates, and the unchanged
  Strict Stage 2 four-cell control matrix pass on the final revision; and
- the stage-closing revision passes pushed CI before this status changes to
  `complete`.

Claim on exit: only the two named Wasmtime-to-Wasmtime resource profiles and
their declared dispositions are supported. Independent-runtime Stage 3,
cross-ISA/substrate, confidential-continuity, and production claims do not
follow.

## Stage 4: Target, ISA, and substrate qualification

Status: complete for `named-target-substrate-continuity-v1` and
`emulated-cross-isa-continuity-v1` at accepted qualification revision
`457ae1d64915c0b3febd84e136d08be53063210f`. Actions run
`29386011420` passed its exact-SHA closure, and its uploaded Stage 4 artifact
was downloaded and independently reverified at a different root. The exact
receipt is recorded in [validation](VALIDATION.md#stage-4-closure-receipt).

Goal: hold the Stage 1 Wasmtime timer/KV semantic input fixed while changing
the named target, ISA, and user-mode execution carrier. This stage asks whether
the portable state, authority, fencing, and externally observable behavior
remain equal when the x86-64 worker and separately cross-built AArch64 worker
execute natively or through QEMU-user. It does not introduce a new runtime or
resource family.

### Fixed qualification profile

The profile has one x86-64 Linux orchestrator and three explicit endpoints:

- **Hx** -- the artifact-owned `x86_64-unknown-linux-gnu` worker executed
  natively;
- **Qx** -- the same artifact-owned x86-64 worker executed through the
  artifact-owned `qemu-x86_64` executable with `-cpu max` and the identified
  `/` sysroot; and
- **Qa** -- an artifact-owned, separately cross-built
  `aarch64-unknown-linux-gnu` worker executed through the artifact-owned
  `qemu-aarch64` executable with `-cpu max` and the identified AArch64 GNU
  sysroot at `/usr/aarch64-linux-gnu`.

All endpoints keep the Wasmtime runtime, locked Stage 1 Component/WIT world,
31-case registry, host-process-isolation substrate, and durable SQLite timer/KV
provider fixed. Stage 3 file and logical-request profiles are not inputs to this
matrix. Artifact-owned worker/QEMU executables plus identified endpoint-specific
loader/sysroot inputs and their receipts, build receipts, nonce-bound target
hellos, and recorded Rust/Cargo toolchain identity identify the actual execution
carriers and reject ambient loader or QEMU substitution.

The completed matrix earns exactly these two bounded claims:

- `named-target-substrate-continuity-v1`: `Hx->Hx`, `Hx->Qx`, `Qx->Hx`, and
  `Qx->Qx`; and
- `emulated-cross-isa-continuity-v1`: `Qx->Qx`, `Qx->Qa`, `Qa->Qx`, and
  `Qa->Qa`.

`Qx->Qx` is the shared control, so the two claims require seven unique cells.
Each cell executes all 31 Stage 1 cases: 217 case executions in total and one
seven-cell normalized equality group for each of the 31 registered cases. The
Stage 4 common input and verifier also retain the same typed 3 Pending / 22
Precompleted / 6 ScenarioControlled timer-strategy partition used by Stage 2.

### Evidence boundary

Semantic cross-ISA continuity is not AOT binary portability. Hx/Qx and Qa run
target-specific worker executables around the same Component and portable
semantic envelope; Stage 4 does not copy an x86-64 native code image, compiled
Wasmtime artifact, stack, register file, or process checkpoint into AArch64.

QEMU-user execution is not real AArch64 hardware qualification. Qa establishes
only the named emulated AArch64 Linux user-mode path on the same orchestrator;
it does not execute a real ARM machine, system emulator, reference kernel, or
device-enforcement path. Runtime, provider, host trust, and cross-host movement
remain separate dimensions.

The `performance-observations` case retains the common 50 ms Stage 1 timer.
Five raw source reads can exceed that duration under QEMU, so the corrected
scenario deliberately reaches the `Completed` timer branch before handoff
timing begins, then proves that destination restore does not recreate or
redeliver it. It neither lengthens an unrecorded workload input nor accepts
`Pending` and `Completed` as equivalent. Target speed affects only retained raw
performance samples, for which this stage makes no performance claim.

### Exit conditions satisfied at closure

- Hx, Qx, and Qa are identified by retained executable, ELF ISA, build,
  recorded Rust/Cargo toolchain identity, launcher, loader/sysroot,
  QEMU-version where applicable, and nonce-bound runtime target-hello evidence;
- all seven unique cells pass all 31 cases, producing 217/217 completed
  executions and 31/31 equal normalized observable groups;
- every cell's complete Stage 1 bundle passes its full inner artifact-aware
  verification, rather than relying on the outer summary or cached normalized
  output;
- the independent Stage 4 verifier reconstructs the common input and case
  manifests from retained artifacts, recomputes Stage 2 normalization, checks
  every snapshot and authoritative final branch against the typed timer
  strategy, checks both exact claim cell sets, and rejects failed, unsupported,
  or not-run cells from either claim;
- successful evidence publication is atomic and fail-closed, contains the exact
  expected artifact set with no incomplete marker or unreferenced additions,
  and preserves explicit `unsupported` and `not-run` qualification records;
- a successful bundle is moved as a whole to a different absolute location,
  without rewriting its JSON, and passes the independent verifier again,
  proving that artifact lookup is relocation-safe while the historical path is
  retained solely to validate the original launcher argv;
- the ordinary repository gate, Stage 1 Wasmtime and JcoNode controls, legacy
  and Strict Stage 2 four-cell controls, both Stage 3 resource gates, and the
  dedicated Stage 4 gate all passed at accepted qualification revision
  `457ae1d64915c0b3febd84e136d08be53063210f`; and
- Actions run `29386011420` completed its exact-SHA closure successfully, after
  which the uploaded Stage 4 artifact was downloaded and independently
  rechecked for verification, exact-set closure, and relocation as recorded in
  the [closure receipt](VALIDATION.md#stage-4-closure-receipt).

### Claims explicitly not earned

Stage 4 does not claim real AArch64 hardware, no-std/reference-kernel execution,
real-device enforcement, cross-target Stage 3 file or request continuity, a
second Stage 4 runtime, AOT binary portability, cross-host continuity, 32-bit or
big-endian targets, hostile-host protection or confidentiality, or production
and performance readiness. The legacy reference-kernel path remains explicitly
`unsupported` because its runtime is not linked and its engine is a legacy
stub; real AArch64 hardware remains explicitly `not-run`.

Claim earned: only `named-target-substrate-continuity-v1` and
`emulated-cross-isa-continuity-v1` for the fixed Wasmtime, Linux user-mode,
timer/KV profile and the exact Hx/Qx/Qa cells above.

## Accepted research track: bounded joint-handoff refinement

Status: complete for the named same-boot boundary. The accepted claim is
`bounded-joint-handoff-refinement-v1`; it is an independent bounded research
track before Stage 5, not evidence that Stage 5 has started. Its evidence
remains split between the neutral composition, vISA HostSubstrate, Nexus-local
refinement, and exact-binary process axes; no axis may stand in for another.
The accepted vISA implementation identity is
`d3b07f1114cb49e26dd62fb252a895022ac2a743`. The later documentation-only
receipt commit records lineage and does not replace that implementation
identity.

The track asks whether vISA semantic freeze, one durable non-equivocating
ownership decision, and native closure of a frozen effect cohort can compose
without a copied ownership ledger, dual execution authority, or serialization
of native device state. Its two kill conditions remain mandatory:

1. no vISA or effect adapter may maintain a second ownership ledger; and
2. source thaw requires the exact durable abort decision for that reservation
   and, when effect freeze occurred, the exact thaw of that freeze generation.

The current source lock pins remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79` (tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`). It fixes the v1 wire
contract, TLA+ models, independent oracle, mutation corpus, 16-case normative
registry, and Nexus native-v1 field mapping. Its machine contract is
`f054fa08d48b7eed8fef18c274a464f66443410e6698474ff721bfb1a6b5cbf5`.
The accepted artifact was independently reverified after download; receipt
commit `be250c30...` is documentation lineage, not the source identity.
The current mapping explicitly declares `adapter_qualification=false`; Nexus
execution truth is separate.

The TLA+ `BeginFreeze` action is an atomic abstraction of admission close,
source freeze, generation advance, and boundary capture. TLC does not prove the
concrete WAL-before-effect ordering. That obligation is discharged on the vISA
axis by the Rust/SQLite durable projection and independently replayed raw
transcript evidence.

The accepted vISA implementation provides the pure joint reducer, pinned
native receipt admission, append-only durable replay, a SQLite projection
backend, reference ownership/effect peers, independent semantic verification,
exact artifact inventory, and relocation checks. The concrete reference runner
executes the 16 normative cases plus one supplemental post-commit
retained-tombstone recovery scenario.

The same system runner executes a distinct online HostSubstrate vertical
through production `Coordinator<SqliteProvider>` APIs. Its 14-record commit and
9-record abort transcripts retain durable attempt/observed/completion lineage
and canonical pre-call bytes for seven ownership/effect peer-invocation
classes. The independent verifier recomputes receipts, peer relations,
journals, leases, log heads, crash/reopen checkpoints, lost acknowledgements,
the pre-resume exposure gate, and the completion record authorizing the final
destination resume.

This vISA result declares `exclusive_trusted_coordinator_api=true` as a TCB
assumption. A second raw coordinator/provider handle or hostile caller of the
public projection surface is outside the bounded claim; the current guard is
not provider- or kernel-enforced adversarial admission.

The Nexus-local axis is locked to clean revision
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`, source fingerprint
`017c681b...`, matrix `9f3f1579...`, and v2 qualification-lock SHA-256
`21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
The receipt records production Registry refinement as checked. The main
workflow for that exact Nexus revision passed, and its downloaded canonical
bundle independently passed `./x verify-bundle` from a clean checkout.
Generated receipt and local binary digests are run identities, not stable
revision identities; final process artifacts retain the exact executed binary
bytes. The separate Nexus qualification lock remains `prospective=true`, and
the neutral mapping remains `adapter_qualification=false`. Acceptance here is
vISA's decision about the bounded evidence composition; it does not change
Nexus v0.1 or RFC acceptance and does not rewrite either separate boundary.

The supplemental logical-request experiment crosses both lost-acknowledgement
boundaries. Ownership loses the Commit acknowledgement only after the SQLite
decision is durable, then reopens, queries, and replays exactly. Nexus loses the
terminal close response after the child produced it but before adapter
acceptance, then admits one byte-identical same-request-ID replay. The logical
request executes once and its Nexus Register/Prepare/Commit publication occurs
once. Because the request completes first and no vISA freeze/fence/activation
runs, this cell does not qualify Nexus effect admission or a vISA runtime
handoff.

The standalone process publisher now owns a strict three-file
manifest/report/executed-binary artifact; the supplemental logical publisher owns
a strict five-file artifact including two SQLite databases and the same binary
content identity. Download verification does not re-execute the retained binary
and does not treat normalized file mode as evidence. Both publishers bind clean
implementation revision `d3b07f1114cb49e26dd62fb252a895022ac2a743`.

Closure completed at the final exact revisions: the clean vISA joint cell
consumed the neutral source lock and separate Nexus v2 qualification lock;
local and Docker repository gates, the dedicated joint gate, and pushed
exact-SHA CI passed for the implementation revision; the combined receipt kept
the neutral composition, vISA runtime execution, and Nexus-local refinement as
distinct axes; and downloaded evidence was independently reverified. The
documentation receipt extracts Feature 009's accepted decisions into the
canonical documents and removes that temporary execution specification in the
same receipt commit. It does not add implementation behavior or widen the
accepted claim.

No current result establishes real OSTD or IRQ/SMP execution, Registry
replacement, the production retained-tombstone path, host reboot or permanent
source-loss recovery, cross-host transport, Byzantine ownership-service
behavior, cryptographic receipt authenticity, hostile-storage anti-rollback or
freshness, TEE/KMS behavior, confidentiality, or production readiness.

## Stage 5: Confidential continuity profile

Status: not started. No TEE, attestation, KMS, or confidential-continuity cell
has executed.

Goal: integrate fresh destination attestation and external policy/KMS decisions
without making vISA an attestation or secret-management service.

The profile binds component, state, policy, authority, journal, and evidence
digests to a fresh verifier result. Destination secrets are newly released;
source authority is revoked and fenced.

The named TEE, verifier, policy engine, KMS, rollback/freshness mechanism,
storage protection, and secure channel are all explicit parts of the Stage 5
TCB and qualification matrix. Attestation does not retroactively make the host
SQLite database, `statx` metadata, or the Stage 3 loopback protocol trusted, and
it does not by itself prove rollback resistance, state freshness, protected
storage, or confidential transport.

Entry condition: ordinary authority continuity and failure recovery are already
proven for the named timer/KV and rich-resource profiles, and Stage 4 has made
the target/ISA/substrate evidence boundary explicit.

Claim on exit: only the named TEE/verifier/policy integration is supported.

## Roadmap governance

- Do not advance a stage because types, schemas, or tests exist; advance when
  the end-to-end evidence and deletion conditions are satisfied.
- Require a stage-closing repository revision to pass pushed CI at its exact
  final commit before changing the roadmap status to `complete`.
- Add a capability only when it exercises the final dependency direction.
- Keep unsupported matrix entries explicit.
- Promote durable boundary changes into vision or architecture; keep
  implementation details in code and tests.
- Revise or stop the roadmap when research hypotheses or external demand are
  falsified.
