# State Continuity Profiles for WebAssembly Components

A pre-proposal discussion draft prepared from the vISA reference
implementation.

Status: working draft for community discussion. This is not a WASI proposal,
not a Component Model design document, and not a canonical vISA truth
source. It exists to test whether the continuity-profile concept is worth
bringing to the WASI Subgroup as a phase-0 proposal. Statements about
executable evidence below are scoped exactly as in the vISA validation
documents; nothing here widens them.

Champion: to be determined (vISA maintainer).

## The problem

The Component Model gives components portable code, typed interfaces, and
resource handles with ownership and destruction semantics. WASI 0.3 adds
native async. None of the active WASI proposals defines what happens to the
state *between* a component and its host when the component must stop on one
host and continue on another:

- A WIT `resource` handle is host-local. The logical thing it names — a
  timer with remaining duration, a key-value namespace, a file cursor, an
  in-flight outbound request — may or may not be reconstructible elsewhere.
- Granted authority is host-local. "This component may write namespace N"
  must be re-established under the destination's policy, possibly narrower,
  and must become unusable at the source once the move commits.
- An in-flight effect may have completed, failed, or be unknowable at the
  moment of the move. Pretending any one of those is the general case
  produces either lost effects or duplicated ones.

Today every platform that moves stateful components — stateful serverless,
edge relocation, runtime upgrades — answers these questions privately and
incompatibly. Machine-level snapshots (CRIU, VM migration) preserve memory
faithfully but cannot answer them at all, because the answers are semantic:
they are about idempotency, authority, and effect status, not bytes.

## The claim this draft makes

Portable execution requires a stable boundary between component-owned
semantic state and host-owned native bindings. That boundary can be
expressed as a **continuity profile** over existing WIT interfaces, without
a new IDL, a new handle system, or a standard checkpoint format.

A continuity profile for an interface answers, per resource type and per
operation:

1. **Portable state**: which logical state crosses hosts (e.g. remaining
   logical timer duration; namespace name and last observed version; file
   identity, cursor, and content digest; request operation-id and phase).
   Never file descriptors, sockets, pointers, credentials, or
   runtime-private objects.
2. **Continuity disposition**: what the destination does to the resource —
   `revalidate` (same underlying object, checked), `recreate` (fresh
   binding, logical state re-applied), `reconnect` (session re-established),
   `replay` (idempotent re-issue), or `reject` (the move must fail, before
   any destination effect). Dispositions are declared per type, not
   discovered at runtime.
3. **Effect discipline**: which operations carry idempotency keys or
   operation-ids, and what `indeterminate` means for each. An operation
   whose completion is unknowable at a safe point must be representable as
   explicitly unresolved, and resolvable by reconciliation, not guessed.
4. **Authority rule**: what "equal or narrower authority" means for the
   type, and what evidence the destination host needs to grant it.

The lifecycle around the profile is deliberately small: a component reaches
an explicit safe point (cooperative quiescence, not preemption), exports its
portable state, is fenced at the source under an epoch, and is resumed at
the destination with freshly granted bindings. One fencing epoch admits at
most one active writer; a committed move makes the source unable to act; a
failed pre-commit move leaves the destination without authority.

## Goals

- Define the vocabulary (safe point, portable state, disposition,
  idempotency/indeterminacy, fencing epoch, attenuated reauthorization) as
  profile annotations *around* existing WIT/WASI interfaces.
- Make "this interface is continuity-capable under profile P" a testable,
  runtime-neutral statement, with a conformance suite that exercises
  success, denial, unsupported, cancellation, failure, duplicate delivery,
  and lost-acknowledgement paths — not only the happy path.
- Stay carrier-neutral: linear-memory capture (Asyncify, engine snapshots,
  OSR-based approaches) is a replaceable compute-state carrier underneath
  the same semantic contract, not part of it.

## Non-goals

- No second IDL, component linker, handle system, or async primitive. WIT
  resources and WASI 0.3 futures/streams are the vocabulary; this profile
  layer must reuse them or fail its own premise.
- No standard snapshot byte format, no memory pre-copy or dirty-page
  transport, no arbitrary-process checkpointing.
- No claim of universal exactly-once effects. The profile makes effect
  status explicit and reconcilable; it does not repeal distributed-systems
  reality.
- No transparent migration of arbitrary unmodified programs at arbitrary
  instructions. Safe points are explicit and cooperative.
- No security-protocol invention: attestation, key release, and transport
  protection compose from existing mechanisms (RATS, in-toto formats) and
  are out of scope here.

## Shape sketch (non-normative)

The reference implementation currently expresses a profile as a concrete
WIT world plus host-side contract. The timer/key-value world that all
cross-runtime evidence uses (`visa:continuity@0.1.0`, in
[`wit/cooperative-handoff/world.wit`](../../../wit/cooperative-handoff/world.wit))
illustrates the idioms a standardized profile would name generically:

- Every mutating operation takes an explicit idempotency key
  (`conditional-put(idempotency-key, key, expected-version, value)`), so
  destination-side replay after an indeterminate outcome is safe by
  construction.
- Error variants distinguish `denied`, `conflict`, `stale-binding`,
  `unavailable`, and `indeterminate` — the five answers a host can honestly
  give across a continuity boundary. `stale-binding` is what a fenced
  source returns after commit.
- The component exports `freeze -> component-state` and
  `restore(component-state, remaining-duration-ns, own<namespace>,
  own<timer-binding>)`: portable state out, fresh owned bindings in. The
  component never sees a rebound native handle "survive"; it is always
  handed new ones with old logical state.
- The logical-request world
  ([`wit/logical-request-continuity/world.wit`](../../../wit/logical-request-continuity/world.wit))
  adds the harder vocabulary: `delivery-policy`
  (deduplicated / at-most-once / at-least-once / non-recoverable),
  `replay-policy`, `request-phase` including `unknown-completion` and
  `reconciling`, and a `continuity-disposition` enum
  (revalidate / reconnect / replay / reject) declared per transport. A raw
  live TCP connection is honestly `non-recoverable`: the profile's answer
  is explicit rejection or reconnection, not silent preservation.

A standardized version would likely be: a small `wasi:continuity` interface
family (safe-point signaling, portable-state envelope, binding
reacquisition) plus a convention for annotating existing interfaces (for
example `wasi:keyvalue`, `wasi:clocks`-based timers, `wasi:http` outbound)
with per-type dispositions and idempotency requirements. Whether annotation
lives in WIT syntax, in a sidecar profile document, or in world composition
is an open design question — deliberately not answered here.

## Reference implementation evidence

All evidence is x86-64 Linux, produced by exact-commit CI with independent
verifier binaries, and each result names its own boundary; the receipts live
in the vISA validation contract (`docs/VALIDATION.md`).

- The timer/KV profile above completed a 31-case lifecycle/fault matrix
  (success, denial, attenuation, unsupported profile, stale generation,
  revocation, timer completion/cancellation during quiescence, pre/post
  commit failure, lost acknowledgements, duplicate restore, tampered
  snapshot, version rejection) on Wasmtime.
- The same unchanged component and profile then ran a strict four-cell
  cross-runtime matrix — Wasmtime and a source-locked wacogo derivative
  with an independent Component Model lineage, in all four
  source/destination pairings — at 124/124 case executions and 31/31
  normalized-equality groups. This is the profile's strongest evidence:
  continuity semantics held across two independently implemented runtimes,
  which is exactly what a standard must survive.
- Bounded regular-file and reconnectable logical-request profiles passed
  their 12- and 14-case matrices (Wasmtime-to-Wasmtime only; they do not
  inherit the cross-runtime result).
- A target/substrate matrix held the profile fixed across one native and
  two QEMU-user-emulated endpoints (217/217 executions). Emulated, not real
  second-ISA hardware.

Equally relevant is what the reference implementation refuses to claim:
no cross-runtime coverage for file/request profiles yet, no real ARM
hardware, no raw TCP continuation, no general exactly-once, no production
readiness. A profile standard needs precisely this discipline in its
conformance tiers, and the vISA claim registry demonstrates one workable
mechanization of it.

## Relationship to existing work

- **WASI 0.3 / Component Model**: provides async, typed resources, and
  ownership — the vocabulary this layers on. No active WASI proposal
  covers checkpoint/continuity/rebinding today.
- **Wasm migration research** (Nomad; WasmEdge/WAMR migration; OSR-based
  cross-ISA C/R; self-hosted runtimes; Asyncify-based capture): carriers
  for compute state. This profile is the missing contract those systems
  each reinvent for external resources; several explicitly name
  runtime-external state as future work.
- **CRIU / VM migration**: precedent for versioned state, blockers, and
  source preservation before commit; CRIU's external-resource callouts are
  the process-level statement of the same gap.
- **Durable execution** (Temporal, Restate): effect journaling and
  idempotency at the workflow layer; this profile sits below, at the
  component/host interface, and should compose with rather than replace
  them.

## Open questions for discussion

1. Is per-interface annotation (dispositions, idempotency requirements)
   acceptable to interface owners, or must continuity remain a separate
   wrapping world per resource family?
2. Should safe-point/quiescence signaling be a host import, an export
   convention (as in the reference `freeze`/`restore`), or a canonical-ABI
   level facility?
3. What is the minimal portable-state envelope worth standardizing —
   opaque-bytes-plus-digest with versioning rules, or typed per-profile
   records as the reference does?
4. Where do conformance tiers live, and can the evidence discipline
   (named environment, named fault matrix, no inheritance between cells)
   be part of the standard's conformance language rather than an
   implementation virtue?
5. Is there appetite from a second, independent implementation? The
   strongest current evidence used two runtime lineages under one shared
   coordinator; a standard needs two independent full stacks.

## Suggested next steps

1. Circulate this draft in the WASI Subgroup and Component Model issue
   trackers for temperature; collect which existing proposals' owners
   would accept continuity annotations.
2. If temperature warrants, extract a phase-0 proposal repository:
   explainer, the two reference WIT worlds generalized under a neutral
   `wasi:continuity` namespace, and the 31-case matrix restated as a
   runtime-neutral conformance list.
3. Recruit a second implementation before requesting phase 1; the vISA
   Wacogo-derivative cell demonstrates feasibility but shares a
   coordinator, so it does not count as the second stack.
