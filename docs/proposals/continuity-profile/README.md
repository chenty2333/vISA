# State Continuity Profiles for WebAssembly Components

> A portable contract for rebinding host resources, reacquiring authority,
> and reconciling in-flight effects.

Status: working discussion draft for a possible WASI Phase 0 pre-proposal.
[Phase 0](https://github.com/WebAssembly/WASI/blob/main/CONTRIBUTING.md#the-phase-process)
is an idea-sharing stage; this document is not proposed specification text.

Initial contributor: vISA maintainer. Champion or champions: to be determined
through community discussion.

## Summary

The Component Model defines typed interfaces and ownership semantics for
[resource handles](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md#handles).
WASI defines host capabilities exposed through those interfaces. The
[current WASI proposal list](https://github.com/WebAssembly/WASI/blob/main/docs/Proposals.md)
does not identify a cross-interface contract for host-bound state when a
stateful component stops in one runtime or host and resumes in another.

That boundary has three separate problems:

- **Resource identity and state:** an
  [instance-scoped capability handle](https://github.com/WebAssembly/WASI/blob/main/docs/Capabilities.md#runtime-capabilities)
  is not a portable identity for a timer, file, namespace, request, or other
  host object.
- **Authority:** access must be granted again under destination policy, must
  not become broader, and must become unusable at the source after commit.
- **Effects:** an operation may be complete, failed, not started, or
  indeterminate. Retry is safe only when the interface defines sufficient
  operation identity and recovery semantics.

The proposed direction is a **continuity profile** associated with an existing
WIT/WASI interface. It describes portable logical state, resource rebinding,
effect recovery, authority compatibility, and lifecycle invariants. It does
not serialize native handles or standardize a memory snapshot format.

The desired interoperability statement is:

> If a component, source host, and destination host claim support for profile
> P, the destination either resumes with P's profile-defined portable
> observations and no broader authority, or returns a typed rejection before
> any destination effect. Unsupported and indeterminate states never become
> implicit success.

How a profile is encoded is deliberately open. The semantic contract should
be agreed before choosing wrapping worlds, companion metadata, world
composition, or a generic WIT hook.

## Motivating use case

Consider a component on host A that owns a key-value namespace and issues a
conditional write with an operation ID. The provider durably applies the
write, but the acknowledgement is lost just before the platform must relocate
or restart the component.

1. The component reaches a cooperative safe point and exports namespace
   identity, last observed version, operation ID, and request phase. It does
   not export a resource-table index, provider connection, or credential.
2. The source reconciles the operation by its identity. If the result cannot
   be established under the profile, it remains explicitly `indeterminate`
   and destination activation is blocked rather than guessed.
3. Host A's source authority is fenced before host B becomes active. Host B
   applies its own policy, grants equal or narrower authority, and creates a
   fresh namespace binding.
4. The component restores its logical state with the new binding. It does not
   observe the old handle as having survived the move.

A private platform can implement this sequence today. The interoperability gap
is that another component or host cannot discover a standard declaration of
the required state, outcomes, and safety conditions for the resource
interface.

## Proposed contract

A continuity profile is associated with a resource kind and the operations
that affect its portable observations. It specifies:

1. **Portable state.** Logical fields, versions, and validation rules. File
   descriptors, sockets, native pointers, reusable credentials, and
   runtime-private objects are excluded.
2. **Resource disposition.** Allowed destination actions and their conditions:
   `revalidate`, `recreate`, `reconnect`, or `reject`. Selection is explicit
   and produces a typed result, not an untyped fallback.
3. **Effect recovery.** Operation IDs or idempotency keys, completion queries,
   replay conditions, and the meaning of `indeterminate`. Replay is an effect
   rule, not evidence that a native resource survived.
4. **Authority compatibility.** A profile-specific relation for an acceptable
   destination grant. The destination may attenuate authority but may not
   silently widen it.
5. **Lifecycle invariants.** Safe-point requirements, source fencing before
   destination activation, and authority state after pre-commit failure or
   committed handoff.

`reject` is a valid interoperable result. Some resources, such as an arbitrary
live TCP connection, may have no safe disposition under a given profile.

## Responsibility boundary

| Participant | Responsibility |
| --- | --- |
| Interface and profile author | Defines portable state, dispositions, effect rules, authority compatibility, and typed outcomes. |
| Component | Cooperates at a declared safe point and exports or restores profile-defined logical state. |
| Source host or provider | Reconciles effects, freezes native bindings, and makes old authority unusable when commit requires it. |
| Destination host or provider | Applies policy, reacquires authority, validates state, and creates fresh native bindings. |
| Orchestrator and state carrier | Sequences the handoff and transports state; its coordination and transport protocols are outside the profile. |

The profile standardizes observable preconditions, results, and invariants. It
does not require WASI itself to implement a migration coordinator or
distributed consensus.

## Goals and non-goals

Goals:

- Define reusable vocabulary for portable state, disposition, effect
  reconciliation, authority attenuation, safe points, and fencing.
- Make "interface I is continuity-capable under profile P" a testable,
  runtime-neutral statement, including typed denial, failure, duplicate,
  lost-acknowledgement, and indeterminate paths.
- Reuse existing WIT/WASI vocabulary and remain independent of the
  compute-state capture mechanism.

Non-goals:

- No second IDL, replacement handle system, new async primitive, memory
  snapshot format, memory transport, or arbitrary-process checkpointing.
- No serialization of native handles, credential material, or runtime-private
  state, and no transparent preemptive migration of arbitrary unmodified
  programs. Profile-aware continuity uses cooperative safe points.
- No universal exactly-once guarantee. Profiles expose replay conditions,
  reconciliation, and indeterminacy without hiding distributed-systems limits.
- No standard consensus, attestation, key-distribution, transport-security,
  or source-fencing protocol. Such mechanisms may satisfy profile requirements
  but remain separate concerns.

## Possible shape (non-normative)

The vISA reference implementation expresses a profile as a concrete WIT world
plus a host-side contract. Its timer/key-value world
([`visa:continuity@0.1.0`](../../../wit/cooperative-handoff/world.wit)) uses
three potentially reusable idioms:

- mutating operations carry an operation or idempotency identity;
- errors distinguish policy denial, conflict, stale binding, unavailability,
  and indeterminate completion; and
- `freeze` exports logical state while `restore` accepts fresh owned bindings
  rather than reviving old handles.

A standardized surface might include a small `wasi:continuity` interface
family for safe-point signaling, a versioned state envelope, and binding
reacquisition. Resource-family semantics could instead remain in wrapping
worlds or companion profile documents. This draft assumes no WIT syntax or
Canonical ABI change.

## Standardization home and open questions

The semantics attach to host-resource interfaces such as clocks, key-value
stores, filesystems, and outbound requests, so WASI is the initial discussion
venue. If profiles eventually require a generic WIT annotation or Canonical
ABI facility, that minimal mechanism may belong in the Component Model while
resource semantics remain with WASI interface owners.

1. Is this continuity contract in scope for WASI, and is that WASI/Component
   Model boundary correct?
2. What is the smallest useful interoperability target: a wrapping world per
   resource family, a separately versioned profile document, or a shared
   interface family plus resource-specific rules?
3. Should safe-point signaling and the state envelope be component exports,
   host imports, composed interfaces, or something lower-level?
4. Which interface owners and independent implementers would test one profile,
   and which motivating use cases are missing?

Detailed conformance tiers, portability criteria, and implementation-count
requirements are later-phase questions to define with interested implementers.

## Discussion path

The [WASI contribution process](https://github.com/WebAssembly/WASI/blob/main/CONTRIBUTING.md#contributing-to-proposals)
says a new API idea starts as an issue describing scope, use cases, and expected
implementation points. No vote is required to begin Phase 0.

The immediate next step is one WASI issue with a short problem statement and a
link to this explainer. That discussion can refine scope, find champions, and
decide whether a separate Component Model issue is needed. A proposal
repository and formal portability criteria become relevant only if the idea
attracts enough interest to advance.

## Appendix A: Reference implementation evidence

vISA is a research prototype, not the proposed standard. All evidence below is
bounded to x86-64 Linux; exact scope lives in the
[validation contract](../../VALIDATION.md) and
[claim registry](../../../claims/registry.json).

- The timer/key-value profile runs a fixed 31-case lifecycle/fault matrix in
  all four source/destination directions formed by Wasmtime and the
  source-locked Wacogo derivative: 124/124 case executions and 31/31
  normalized equality groups.
- The regular-file profile runs a separate 12-case matrix in the same four
  directions, with three required stability runs per cell. Its earned claim is
  bound by a permanent
  [closure receipt](../../../claims/receipts/cross-runtime-regular-file-continuity-v1.json),
  [GitHub evidence release](https://github.com/chenty2333/vISA/releases/tag/cross-runtime-regular-file-continuity-v1-evidence),
  and [Zenodo record](https://doi.org/10.5281/zenodo.21627497).
- A reconnectable logical-request profile separately passes a 14-case
  Wasmtime-to-Wasmtime matrix and does not inherit cross-runtime evidence.

These results cover two runtime lineages under one shared vISA coordinator,
not two independent end-to-end implementations. They do not establish physical
cross-host deployment, unmodified upstream Wacogo support, arbitrary live-TCP
continuation, general exactly-once effects, or production readiness.

## Appendix B: Relationship to adjacent work

- Component Model and WASI handles define ordinary ownership and capability
  use; a continuity profile addresses a later stop/rebind/resume boundary.
- Engine, process, and VM checkpoint mechanisms are possible compute-state
  carriers. They do not by themselves standardize resource semantics across
  WASI hosts.
- Durable workflow systems provide effect journaling and idempotency at a
  workflow layer. A resource profile should compose with, not replace, them.
