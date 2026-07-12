# Research Context

Status: current related-work and hypothesis summary.

Last reviewed: 2026-07-12.

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

The candidate research contribution, subject to implementation, evaluation,
and a systematic literature review, is the combination of runtime-external
resource semantics, authority continuity, explicit handoff failure, and
executable cross-adapter evidence.

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

### Independent Component Model runtime availability

A 2026-07-12 executable qualification advanced three pinned candidate runtimes,
WACS, WasmEdge, and wacogo, against the unchanged Stage 1 Component and WIT
world; none passed. This is a result for those recorded candidates, not an
exhaustive claim about every released runtime or source snapshot. WACS
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

wacogo pseudo-version `v0.0.0-20260617023329-3de16a61796c` has an independent
Go Component parser, validator, linker, Canonical ABI, and resource
implementation over wazero. It loads and compiles the exact Component, and its
generator builds real key-value and timer host instances from the unchanged
WIT. Real Component instantiation nevertheless fails before workload execution:
the nested `import-type-kv-error` argument references unresolved type 24. This
is a scoped executable no-go, not a claim that wazero itself implements the
Component Model. The source-only Airbus WAMR Component Model fork remains a
future retest candidate and supplies no vISA execution evidence here.

Strict Stage 2 therefore remains open. A candidate must execute the byte-identical
world through public, supportable APIs, including owned-resource transfer and
the full lifecycle, before vISA adds a runtime selector or evidence cell. The
active qualification record pins packages, hashes, fail-closed input checks,
commands, failures, and the upstream conditions for retesting.

## Claims vISA must not make without new evidence

- that WebAssembly code, memory, or stack migration is novel;
- that a component can migrate merely because its module is portable;
- that every fd, socket, device, or external effect is migratable;
- that a schema-valid sample report proves executable behavior;
- that one real-machine run proves cross-runtime or cross-ISA portability;
- that capability vocabulary alone proves authority safety;
- that a local transaction can provide universal exactly-once external effects;
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
