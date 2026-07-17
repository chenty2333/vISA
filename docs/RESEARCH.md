# Research Context

Status: current related-work and hypothesis summary.

Last reviewed: 2026-07-17.

This document records why vISA exists alongside WebAssembly, WASI, checkpoint
systems, capability systems, and durable execution platforms. It is not a claim
that vISA is the first system to migrate WebAssembly state or to use
capability-based security.

## Research position

The useful vISA hypothesis is:

> A stateful component can preserve observable system behavior across runtime
> and substrate changes by transferring canonical logical state and authority
> provenance, rebuilding native resource bindings under target policy, and
> verifying the result with a canonical effect trace.

The broader research contribution remains a hypothesis subject to further
evaluation and a systematic literature review. The current implementation
combines runtime-external resource semantics, authority continuity, explicit
handoff failure, and executable cross-adapter evidence; that implementation
does not by itself establish paper novelty.

Cross-ISA or cross-runtime WebAssembly execution is a validation dimension. It
is not sufficient novelty on its own.

## Closest standards and systems

### WebAssembly Component Model and WASI

[WASI 0.3](https://wasi.dev/roadmap) adds native asynchronous functions,
`future<T>`, and `stream<T>` to the Component Model. WIT
[resources](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md#item-resource)
define typed owned and borrowed handles with destruction semantics.

These standards provide the application-facing interface and lifetime
vocabulary that vISA should reuse. The active
[WASI proposals](https://github.com/WebAssembly/WASI/blob/main/docs/Proposals.md)
do not currently define a general checkpoint, state-continuity, cross-host
resource-rebinding, or handoff protocol.

vISA therefore must not create another general IDL, component linker, handle
system, or async primitive. It should define continuity profiles around
existing WIT/WASI interfaces.

### WebAssembly checkpoint and migration

- [Nomad, IC2E 2021](https://doi.org/10.1109/IC2E52221.2021.00032) demonstrates
  cross-platform WebAssembly offloading and migration.
- [Stateful VM Migration Among Heterogeneous WebAssembly Runtimes, EdgeSys
  2024](https://doi.org/10.1145/3642968.3654816) prototypes migration between
  WasmEdge and WAMR.
- [Bringing Together Cross-ISA Checkpoint/Restoration and AOT Compilation of
  WebAssembly Programs, MPLR 2025](https://doi.org/10.1145/3759426.3760985)
  uses on-stack replacement to bridge ISA-dependent machine state and
  ISA-independent WebAssembly state.
- [Self-Hosted WebAssembly Runtime for Runtime-Neutral Checkpoint/Restore,
  2025](https://doi.org/10.1145/3774898.3778040) places a runtime inside
  WebAssembly to normalize execution-state representation. Its published
  [author material](https://speakerdeck.com/chikuwait/restore-in-edge-cloud-continuum)
  identifies WASI execution state outside the runtime as future work.
- [Lightweight and Highly Portable Migration of Extreme Edge Workloads using
  WebAssembly, CCNC 2026](https://doi.org/10.1109/CCNC65079.2026.11366342) uses
  Asyncify to capture stack and CPU-related state without modifying the host
  runtime.

These systems mean vISA must not claim that WebAssembly migration,
runtime-neutral compute-state capture, cross-ISA continuation, Asyncify, or OSR
is new. A compute-state checkpoint may be a replaceable carrier under the vISA
handoff protocol.

### Capability systems

[EROS](https://doi.org/10.1145/319151.319163) and
[seL4](https://doi.org/10.1145/1629575.1629596) provide object-capability and
derivation/revocation lessons.
[Capsicum](https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf)
demonstrates explicit capability-mode authority and rights attenuation.
[CHERI](https://doi.org/10.1109/SP.2015.9) provides architectural
unforgeability, bounds, permissions, and monotonic narrowing; temporal safety
requires an additional revocation design.

vISA should reuse those principles. Its narrower question is how logical
authority is mapped, narrowed, revoked, and prevented from resurrecting when a
component receives new native bindings on another substrate.

### VM and process checkpoint systems

[QEMU migration](https://www.qemu.org/docs/master/devel/migration/main.html)
provides established practice for versioned modeled state, compatibility,
conditional state, source preservation before commit, and migration blockers.
[CRIU](https://criu.org/Main_Page) handles Linux process state, while its
[external-resource](https://criu.org/External_resources) model explicitly
requires caller help when part of a resource lives outside the dumped
container.

vISA should not reimplement memory pre-copy, dirty-page tracking, device
serialization, transport, or arbitrary Linux process restore. It should define
the semantic contract that decides whether an external resource is portable,
recreated, reconnected, reattached, proxied, replayed, or a blocker.

### Durable execution and evidence

[Temporal](https://docs.temporal.io/workflow-definition) and
[Restate](https://docs.restate.dev/foundations/key-concepts) demonstrate effect
journaling, deterministic replay constraints, durable timers, and idempotency
patterns at the application/workflow level.

[in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias)
and the [IETF RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
provide existing provenance and attestation roles. vISA evidence should compose
with in-toto statement/provenance formats and the RATS roles and trust model
rather than inventing an isolated security-attestation claim.

vISA is intended to occupy the layer between application-level workflow replay
and machine-level snapshots: component runtime semantics plus external resource
continuity. It is not intended to become another workflow engine.

### Ownership, effect closure, and confidential migration

Opaque snapshots preserve machine state, but do not establish external-effect,
authority, and freshness continuity. Two-phase commit, atomic RPC,
presumed-abort/presumed-commit recovery, idempotency keys, and fencing leases
already provide the basic vocabulary for prepared state, decision recovery, and
stale-writer exclusion. The bounded contribution must not be described as the
invention of a prepared record, signed receipt, epoch, or commit protocol.

Confidential VM migration and attestation-bound key release additionally protect
machine-state transport and constrain which destination can receive secrets.
Those mechanisms do not by themselves determine whether a non-idempotent
external effect completed, close every descendant effect on the old source, or
prove that a replayed ownership history is fresh. Conversely, a semantic
handoff receipt graph does not provide encryption, attestation, rollback
resistance, or protected storage.

The accepted bounded systems/research claim
`bounded-joint-handoff-refinement-v1` is narrower: an executable refinement
among vISA portable continuity, one externally owned non-equivocating decision,
and an independently owned native effect-cohort closure service. The boundary
is useful only if neither adapter copies the other's state machine or ledger,
unknown outcomes remain fail closed, and destination activation is derived
from the exact commit, closure, and source
fence chain. No monolithic, cross-host, or production execution cell runs all
three evidence axes end to end; acceptance is a bounded composition result.

The current source lock pins remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79` (tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`). It supplies the reviewed wire
contract, 16-case normative model, TLA+ safety/progress checks, expected rollback
counterexample, independent mutation-tested oracle, and exact Nexus native-v1
field mapping. Earlier remote results, including `8fcdaf42...`, remain historical
evidence rather than the current source identity. The separate Nexus
qualification lock remains `prospective=true`, and the neutral mapping still
declares `adapter_qualification=false`; neither becomes Nexus execution truth.
The vISA registry has 16 case-identity mappings plus one supplemental
retained-tombstone recovery scenario.

The TLA+ `BeginFreeze` action deliberately makes gate close, source freeze,
freeze-generation advance, and boundary capture one atomic abstract step. TLC
therefore checks the abstract safety and conditional-progress relation, not the
concrete WAL-before-effect ordering. The latter is a separate refinement result
from the Rust durable session, SQLite append/reopen evidence, exact pre-call
peer-invocation bytes, and independent transcript replay.

The vISA system runner now executes a same-boot HostSubstrate commit/abort
vertical through `Coordinator<SqliteProvider>`. Its strict verifier reconstructs
14 commit records, 9 abort records, seven ownership/effect peer-invocation
classes, local journals and leases, crash/reopen checkpoints, and the exact
completion record authorizing destination resume. This result is conditional
on `exclusive_trusted_coordinator_api=true`: an adversarial second raw
coordinator/provider handle or hostile public-projection caller is outside the
model. The separate Nexus-local axis is locally clean at
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`; its v2 receipt records that the
production Registry refinement was checked. Exact-binary process tests pass;
their artifacts retain the executed bytes by content identity, while generated
receipt and binary digests remain run-specific rather than revision identity.
The accepted vISA implementation identity is
`d3b07f1114cb49e26dd62fb252a895022ac2a743`. Its exact-SHA CI artifacts were
downloaded under independent roots, and the reference, Nexus-lock, exact-binary
process, and supplemental logical-request verifier paths all passed against the
committed locks. This receipt-only documentation lineage records acceptance
without replacing that implementation identity. Acceptance is limited to this
bounded evidence composition; it is neither a universal proof of RQ4 nor a
claim of paper novelty.

### Independent Component Model runtime availability

A 2026-07-12 executable qualification advanced three pinned upstream candidate
runtimes, WACS, WasmEdge, and wacogo, against the unchanged Stage 1 Component
and WIT world; none of those recorded inputs passed. This is not an exhaustive
claim about every released runtime or source snapshot. WACS
0.16.14 with WACS.ComponentModel 0.10.3 has an independent pure-C#
implementation and parses the three-module Component, its interface-instance
export, and all six timer/KV method and resource-drop imports. Its 0.27.2 typed
harness rejects the unchanged nested error variant before a callable surface is
emitted.

The released WACS.Cli 1.10.1 / Transpiler.Lib 0.12.12 paths were also executed,
not inferred from API names. With the unchanged WIT directory, component build
and NativeAOT reject the two interface-reference imports because their v0
contract validator cannot compare those shapes. Without that contract, build
emits only raw core imports and Canonical-ABI exports: `activate` is a single
`i32` indirect-area pointer and there is no typed workload surface. vISA will
not hand-write that ABI as an adapter bypass. WasmEdge 0.17.1 rejects the same
Component during resource validation. These are explicit no-go qualifications,
not adapters or support claims. Other runtimes listed in the machine record are
only preliminary discovery screens and do not support this decision.

The durable [Runtime B qualification record](../third_party/runtime-b-qualification/README.md)
retains the exact candidate identities, executable probes, and go/no-go
boundaries used by this decision.

Unmodified wacogo pseudo-version
`v0.0.0-20260617023329-3de16a61796c` has an independent Go Component parser,
validator, linker, Canonical ABI, and resource implementation over wazero. It
loads and compiles the exact Component, and its generator builds real key-value
and timer host instances from the unchanged WIT. Its unmodified public path
nevertheless fails before workload execution because the nested
`import-type-kv-error` argument references unresolved type 24. That retained
result remains a scoped upstream no-go, not a claim that wazero itself
implements the Component Model.

The selected Runtime B is instead the source-lock-bound derivative
`partite-ai/wacogo v0.0.0-20260617023329-3de16a61796c + vISA downstream
patchset v1`. Three retained patches expose the required root-scope named type,
host-owned value, and non-executing preflight plumbing; they are not represented
as merged upstream support or as a general fix for nested component scopes. An
official Go 1.26.5 qualification passed 7/7 gates through public typed APIs:
byte-identical parse/world validation, non-executing preflight, typed
owned-resource transfer, all six timer/KV callbacks, source and fresh-
destination lifecycle, deterministic missing-import link failure, cleanup, and
no fallback. The source lock, patch digests, module input, toolchain, generated
host surface, and reproducible sidecar identities are machine-readably bound by
repository locks. The source-only Airbus WAMR Component Model fork remains a
future retest candidate and supplies no vISA execution evidence here.

The qualified derivative subsequently entered the shared production adapter
and runtime registry. A separate strict v3 matrix executed exactly
Wasmtime-to-Wasmtime, Wacogo-to-Wacogo, Wasmtime-to-Wacogo, and
Wacogo-to-Wasmtime over the unchanged 31-case profile. Fresh Host and Docker
runs completed 124/124 executions and 31/31 normalized equality groups with
all inner and outer independent verification passing. This supports only
`strict-cross-runtime-continuity` for the named x86-64 Linux timer/KV profile;
it does not imply cross-ISA, file/network, confidential-continuity, production,
or unmodified-upstream-wacogo support. This is the evidence basis for the
completed named Stage 2 scope; every broader claim still requires its own
Roadmap gate and pushed exact-commit evidence.

## Claims vISA must not make without new evidence

- that WebAssembly code, memory, or stack migration is novel;
- that a component can migrate merely because its module is portable;
- that every fd, socket, device, or external effect is migratable;
- that a schema-valid sample report proves executable behavior;
- that one real-machine run proves cross-runtime or cross-ISA portability;
- that capability vocabulary alone proves authority safety;
- that a local transaction can provide universal exactly-once external effects;
- that the joint-handoff reference peers qualify production Nexus, cross-host
  ownership, cryptographic receipts, freshness, or rollback resistance;
- that the current candidate users constitute a validated market; or
- that vISA is a standard, production platform, or complete OS.

## Falsifiable research questions

### RQ1: Minimal semantic state

Can canonical logical state plus target-side rebinding preserve the same
observable effect trace without serializing native resource bindings?

Evaluation should cover real timers, durable key-value state, files, and
eventually network resources across multiple adapters. It should inject
handoff during pending I/O, timeout, cancellation, error, and cleanup paths.

The hypothesis fails if correct recovery requires continuously expanding the
core until it duplicates runtime, Linux, or device-internal state.

### RQ2: Authority continuity

Can handoff preserve all of these properties under crash, retry, reorder,
rollback, replay, and concurrent revocation?

```text
authority_after <= compatible(authority_before)
revoked_before => unusable_after
one fencing epoch => at most one active writer
failed pre-commit handoff => no destination authority
committed handoff => source cannot act
```

The hypothesis fails on any authority amplification, stale capability
resurrection, dual ownership, or undeclared global trusted coordinator.

### RQ3: Evidence as a semantic leak detector

Can a compact bundle of artifact/profile identity, pre/post state roots,
authority lineage, binding receipts, and canonical trace detect externally
visible adapter divergence?

Evaluation should inject stale-generation acceptance, lost cancellation,
duplicate close, incorrect error mapping, late profile checks, missing source
fencing, silent authority downgrade, and omitted events.

The hypothesis fails when an observable semantic error passes verification, or
when detecting errors requires recording nearly all native execution state.

### RQ4: Minimal semantic handoff across authority domains

Given a durable non-equivocating ownership decision and fail-closed recovery,
can reversible vISA freeze and irreversible native effect closure preserve both
at-most-one execution authority and complete accounting of the frozen effect
cohort under crash, retry, reordering, duplicate delivery, and lost
acknowledgements without serializing native device state?

The hypothesis fails if any accepted trace permits dual source/destination
authority, accepts a post-freeze untracked effect, activates the destination
before terminal source closure, thaws on timeout or lookup absence, accepts
conflicting abort and commit decisions, loses a retained cleanup obligation, or
accepts a stale/mismatched receipt without a state-preserving rejection.

The first evaluation boundary is same-boot process crash. The 16 abstract
schedules and 16 concrete cases exercise both freeze/publication orders,
abort/thaw, lost commit acknowledgement, rebind, stale receipts, decision
races, crash recovery, and substituted destination preparation; the concrete
runner adds one supplemental retained-tombstone recovery case. The HostSubstrate
and Nexus-local axes are implemented, and exact-revision local plus downloaded-
artifact verification closes the named same-boot bounded claim. The real
logical-request experiment loses the ownership Commit acknowledgement only
after durability, then separately discards the terminal Nexus child response
before adapter acceptance. Exact query/retry and same-request-ID byte-identical
replay preserve one ownership decision, one accepted native receipt, and one
external execution. This is supplemental, post-hoc observational binding: the
external request completes before native Register/Prepare/Commit, and the cell
does not execute vISA source freeze/fence or destination activation. It therefore
does not test whether Nexus admission serialized the external effect or prove a
vISA runtime handoff vertical.

Mutation evidence is also deliberately split. The neutral verifier executes 10
corrupted semantic-trace mutations. The Nexus lock structurally binds 11 named
falsifier classes, while its actual model/oracle/Registry suites execute their
declared sequence, property, and Loom tests. The 11-name catalog is not eleven
independently source-mutated Nexus builds.

The standalone publication/relocation path, exact-revision remote CI, and
post-download verification passed. This closes only
`bounded-joint-handoff-refinement-v1` under the named same-boot TCB and fault
matrix. The accumulated evidence cannot establish real OSTD execution, IRQ/SMP
behavior, Registry replacement, the production retained-tombstone path,
host-reboot recovery, permanent source loss, cross-host progress, Byzantine safety,
cryptographic authenticity, anti-rollback, freshness, TEE/KMS behavior, or
confidentiality. Roadmap Stage 5 remains not started.

## Demand validation

Candidate users are WebAssembly runtime/platform teams, stateful
serverless/edge operators, and later confidential-computing platforms. Before
calling this a product market, the project should obtain concrete incidents or
workarounds from multiple teams, real workloads from at least three design
partners, and independent conformance runs from at least two external users.

If restart plus external storage already satisfies those users, vISA should
remain a focused research and conformance project rather than manufacturing a
platform category.

## Maintenance rule

Add related work only when it changes the problem boundary, provides a concrete
mechanism to reuse, or affects an experiment. Keep detailed reading notes
outside the repository; this file is the current comparison and hypothesis
summary, not a bibliography archive.
