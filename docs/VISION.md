# vISA Vision

Status: accepted target boundary.

Implementation status: transitional and incomplete.

Last reviewed: 2026-07-17.

This document defines the intended system boundary. It does not imply that
every described capability is implemented or validated.

See the [target architecture](ARCHITECTURE.md), [capability roadmap](ROADMAP.md),
and [validation contract](VALIDATION.md) for the corresponding responsibilities,
implementation order, and evidence rules.

## Project statement

vISA is a capability-safe system-resource continuity and conformance layer for
stateful WebAssembly components running across heterogeneous runtimes and
substrates.

Its central claim is narrow:

> Portable execution requires a stable boundary between component-owned
> semantic state and host-owned native bindings.

Cross-runtime and cross-ISA execution are validation dimensions for that
boundary. They are not, by themselves, the project's research contribution.

## The problem

WebAssembly and the Component Model provide portable code, typed interfaces,
resource handles, and increasingly capable asynchronous execution. Existing VM,
process, and runtime snapshot systems can preserve various forms of memory and
execution state.

The unresolved boundary is the state that lives between an application and its
environment:

- logical resources versus native file descriptors, sockets, and provider
  objects;
- granted authority versus a host-local handle;
- pending effects whose completion status may be unknown;
- cancellation, cleanup, leases, and source/destination ownership;
- compatibility across different runtime and substrate capabilities; and
- evidence that restored behavior did not silently diverge.

For example, moving a component with a timer, a file cursor, a key-value
namespace, and an outbound request requires more than copying memory. The timer
may need to be recreated, the file identity and offset revalidated, the
namespace reauthorized, and the outbound request deduplicated or declared
indeterminate. A connection that cannot be preserved must be reconnected,
proxied, or rejected explicitly.

## Candidate users

The first candidate users are engineers who build WebAssembly runtimes,
component platforms, stateful serverless systems, and heterogeneous edge
platforms. They may need a common lifecycle, adapter contract, and executable
oracle for recovery behavior. These are demand hypotheses, not yet a validated
market; external workloads and design partners are required before making a
product-demand claim.

Confidential and regulated execution is a later integration profile. In that
setting, vISA can bind component, state, policy, authority, and evidence digests
to fresh attestation and reauthorization. It does not replace a TEE, KMS,
attestation protocol, or cloud control plane.

## The complete system boundary

vISA completely owns:

- the portable semantic contract and its versioning rules;
- the canonical state machine and authoritative effect journal;
- authority, attenuation, revocation, generation, and lease invariants;
- success, denial, unsupported behavior, failure, cancellation, and cleanup;
- quiescence, snapshot, destination preparation, commit, abort, and fencing;
- resource claims and continuity dispositions;
- compatibility profiles and extension negotiation;
- runtime coordination and adapter contracts; and
- conformance, differential execution, and evidence semantics.

vISA integrates with, but does not semantically own:

- WebAssembly engines and compiler internals;
- kernels, schedulers, page tables, and native register frames;
- Linux, WASI, or other guest/personality API breadth;
- Virtio, filesystems, network stacks, and device implementations;
- memory pre-copy, dirty-page transport, and arbitrary process checkpointing;
- workflow engines and external databases;
- external ownership-decision services and kernel-enforced causal-effect
  closure services; or
- TEE, KMS, attestation, and infrastructure orchestration services.

These systems may be adapters, reference implementations, test substrates, or
comparison baselines. They must not become portable semantic truth.

## Unit of continuity

The Stage 1 reference cell uses a vISA-aware WebAssembly component at an
explicit quiescence boundary. Whether the eventual stable unit is one
component, a composed component group, or another workload container remains
to be validated by real use cases.

vISA does not promise transparent continuation of an arbitrary unmodified
native process at any instruction. A compute-state carrier may preserve Wasm
memory or continuation state, but vISA is responsible for coordinating that
carrier with semantic state, external effects, authority, resource rebinding,
and commit/abort.

## Joint handoff research boundary

Opaque snapshots can preserve machine state, but they do not establish whether
an external effect completed, whether old authority is irreversibly closed, or
whether an observed ownership decision is fresh. The earned historical bounded
systems/research claim `bounded-joint-handoff-refinement-v1`, and its cumulative
candidate successor `bounded-joint-handoff-refinement-v2`, evaluate whether a
minimal semantic handoff layer can compose three separate authorities without
copying any of their native state: vISA portable continuity, one durable
ownership decision, and native closure of the frozen source effect cohort. The
v2 identity inherits the complete v1 evidence composition; it does not rename
the v1 neutral wire, source locks, registries, or receipts.

The earned v1 claim is deliberately same-boot. Its vISA implementation identity
is `d3b07f1114cb49e26dd62fb252a895022ac2a743`; this receipt-only documentation
lineage records acceptance without replacing that identity. Its source lock
pins remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79`
(tree `a65f264bb7eaf390cbd6285d791b4f7f43e9be25`), which defines the 16
normative schedules and current Nexus native-v1 mapping. Its exact-SHA artifact
was independently reverified after download; `be250c30...` is the later receipt
lineage. Earlier accepted revisions remain historical evidence only. The
separate Nexus qualification lock remains `prospective=true`, while the neutral
mapping preserves `adapter_qualification=false`: it freezes a relation, not
Nexus execution truth. The reference lane maps the 16 normative cases by
identity to 16 vISA cases and adds one supplemental retained-tombstone recovery.

The system runner separately executes an online HostSubstrate commit/abort
vertical through `Coordinator<SqliteProvider>`. Its strict verifier reconstructs
14 commit records, 9 abort records, canonical pre-call bytes for seven
ownership/effect peer-invocation classes, local journals and leases,
crash/reopen checkpoints, and the completion record authorizing destination
resume. The SQLite projection remains a local crash-recovery record, not a
second ownership ledger.

This result declares `exclusive_trusted_coordinator_api=true`: it trusts an
exclusive, non-Byzantine coordinator API. A second raw coordinator/provider
handle or hostile public-projection caller is outside the boundary; provider-
or kernel-enforced adversarial admission is not claimed.

The Nexus-local axis is locked to clean revision
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`. Its v2 receipt records
`production_registry_refinement_checked=true`, while the neutral mapping
correctly keeps `adapter_qualification=false`. Exact-binary process tests include
two distinct acknowledgement-loss boundaries: ownership Commit after its
durable SQLite transaction, and the terminal Nexus close response after the
child produced it but before the adapter accepted it. Exact query and same-
request replay recover one decision and one accepted native receipt-chain
entry. The older logical-request cell is supplemental post-hoc binding: it neither
places Nexus admission before the external effect nor executes the vISA runtime
handoff lifecycle.

The v2 candidate adds a different real-Wasmtime logical-request witness. The
testing cell stages the previewed operation through production-Registry-backed
Nexus Register/Prepare/Commit, recovers a suppressed Commit acknowledgement by
exact same-request replay in the same live child, and only then sends the
application request. That recovery does not prove Nexus process-death
durability. The external effect executes once. Its outcome joins the admitted
cohort; ownership Commit survives a separate lost acknowledgement and SQLite
reopen; Nexus frozen-cohort closure and the vISA source fence then precede
destination activation and Reconcile. This is a single
same-boot commit-path witness, not a live implementation of all 16 neutral
schedules or a production live-wire adapter. It does not absorb the older cell,
which uniquely tests terminal Nexus close-response loss.

The threat model is same-boot crash-stop with named retry/reorder/lost-ACK
faults. A non-equivocating, no-rollback ownership log, both local SQLite stores,
the Nexus Registry, exact receipt-admission code, and the publishers/verifiers
remain in the TCB. Authentication is test identity/integrity binding rather than
cryptographic freshness, and progress depends on recovery services eventually
becoming available.

This work is not Stage 5. Exact-SHA CI and post-download verification closed v1.
Preliminary exact-SHA CI also exercised the v2 admission witness, but v2 remains
`candidate` until the final governance SHA and permanent archive are bound by a
closure receipt. Neither identity establishes dual Stage 3 workers/processes,
Registry replacement, the production retained-tombstone path, real OSTD,
IRQ/SMP/DMA, host-reboot or permanent-source-loss recovery, cross-host
continuity, provider-enforced raw-bypass prevention, Byzantine ownership safety,
cryptographic authenticity, anti-rollback or freshness, raw TCP continuation,
general exactly-once behavior, TEE/KMS behavior, confidentiality,
source-to-binary reproducibility, performance, or production readiness. Stage 5
remains not started.

## Desired outcomes

A conforming implementation should be able to:

1. stop admitting new effects and classify every in-flight operation;
2. export component-owned logical state without native handles or credentials;
3. validate the destination profile before starting component code;
4. reacquire equal or narrower authority;
5. recreate, reconnect, reattach, proxy, replay, or reject every resource by
   an explicit rule;
6. commit the destination and fence the source without dual ownership;
7. resume with defined failure, cancellation, and cleanup semantics; and
8. produce evidence that identifies the exact runtime, ISA, substrate, resource
   profile, fault coverage, and authority boundary exercised.

## Research hypotheses

The project should attempt to falsify, not assume, these hypotheses:

1. A compact canonical resource state plus target-side rebinding is sufficient
   to preserve observable behavior without serializing native bindings.
2. Authority can remain non-amplifying and non-resurrecting across every crash,
   retry, rollback, replay, revocation, and handoff transition.
3. A compact semantic trace and evidence bundle can detect externally visible
   adapter or substrate divergence without recording native execution state.
4. Given one non-equivocating ownership decision and fail-closed recovery, a
   reversible semantic freeze can compose with irreversible native effect
   closure without admitting dual execution authority or losing accounting of
   the frozen effect cohort.

If these hypotheses fail, vISA must narrow its claims rather than expand the
core model until every platform detail appears portable.

## Success criteria

The project earns claims incrementally. The first architecture-complete
capability runs between isolated source and destination instances. A
cross-runtime portability claim is earned only from evidence produced by
genuinely independent runtime implementations. Across those explicitly
identified paths, the success criteria are:

- one canonical model and runtime coordinator;
- real, non-mock resource adapters;
- successful, denied, unsupported, failed, cancelled, and cleanup paths;
- destination reauthorization and source fencing;
- portable snapshot and replayable semantic evidence;
- the named Stage 1 lifecycle and fault matrix; and
- external users who can run the conformance harness on their own workload.

vISA remains a research prototype while later matrix cells and external
workloads are unvalidated. A schema-valid report, a reference harness, or a
broad object catalog is not evidence that a wider system claim has been
achieved.
