# vISA Vision

Status: accepted target boundary.

Implementation status: transitional and incomplete.

Last reviewed: 2026-07-13.

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
- workflow engines and external databases; or
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
