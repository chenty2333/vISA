# Feature 009: Joint Handoff Refinement

Status: active implementation and qualification. The candidate claim remains
open; implemented or locally tested components are not final qualification.

## Purpose

Define and qualify a bounded composition between vISA's portable handoff
lifecycle and an external kernel-enforced causal-effect closure service. The
composition must preserve one authoritative ownership decision while separating
reversible source freeze, irreversible source closure, and destination
activation.

This feature is a prerequisite research track for later confidential
continuity. It is not a TEE, attestation, KMS, cross-host production, or
confidential-continuity claim.

## Current Evidence State

Local-clean neutral revision `75c5dacde8179e31eb88e17c5b7e8e3a9050e50b`
(tree `1572ca83969e091898444c880d91885008d4cef7`) defines 16 normative cases
and the current Nexus native-v1 mapping. It is unpushed; earlier remote-accepted
revisions are historical evidence. The vISA reference lane executes those 16
cases plus one supplemental retained-tombstone recovery case. Its vISA freeze
and destination-prepared inputs remain explicit synthetic references.

The system runner separately executes a HostSubstrate vertical with durable
attempt/observed/completion records for source abort, source fence, and
destination activation, followed by independent verification. Nexus-local
handoff-admission and production Registry refinement are locally clean at
`a890e5c3e25138662c213f19280ba3b209939813`. Four live process tests pass
against the exact binary SHA-256
`574580e5190f9aab2e54d37f3959c6872a1226ede5b22c064fa3609f35a3c689`,
including same-Registry service crash/rebind and a real logical-request
dual-lost-ack cell. Service rebind is not Registry replacement.

The ownership loss occurs after the Commit decision is durable; the Nexus loss
occurs after the child emits terminal `Closed` but before adapter acceptance.
Both recover through exact query/retry and same-request-ID replay without
duplicate execution or publication. The standalone exact-two-file publisher and
relocation verifier have a smoke pass. The final artifact still requires the
committed clean vISA SHA, and remote CI has not been observed. Registry
replacement, the production retained-tombstone path, real OSTD IRQ/SMP, and
reboot recovery remain unsupported.

## Kill Conditions

Stop the feature rather than weakening the boundary if either condition is
required:

1. the vISA or effect-closure adapter must copy or maintain a second ownership
   ledger; or
2. source thaw can occur without a durable, authoritative abort decision for
   the exact handoff reservation and freeze generation.

## Research Hypothesis

Given a non-equivocating ownership decision log and fail-closed recovery, a
composition of portable vISA handoff and kernel-enforced effect closure can
preserve at-most-one execution authority and complete accounting of the frozen
effect cohort under process crash, retry, reordering, duplicate delivery, and
lost acknowledgements without serializing native device state.

The hypothesis is falsified by any accepted trace with dual execution
authority, a post-freeze untracked effect publication, destination activation
before source closure, source thaw without an exact abort decision, conflicting
terminal decisions, or acceptance of a stale or mismatched receipt.

## Required Protocol Shape

The composition state machine must distinguish at least:

```text
OwnedSource
  -> PrepareIntent
  -> PreparedFrozen(ReadyToCommit | Blocked)
  -> AbortDecided
       -> Thawed | SourceRecoveryRequired
       -> SourceActive
  -> CommitDecided
       -> SourceClosePending
       -> SourceClosed
       -> DestinationActive
       \-> RetainedTombstone
           -> DestinationRecoveryRequired
```

`CommitDecided` is a durable ownership decision, not permission to execute at
the destination. Only a verified source `ClosureReceipt` permits destination
activation. A retained tombstone after commit is a durable recovery obligation;
it cannot turn a committed handoff into an abort.

An ownership reservation must exist before the local freeze gate closes. This
allows the authority service to issue an exact abort decision if the coordinator
crashes after local freeze but before the prepared record is sealed.

The vISA freeze receipt is recorded before issuing the effect-freeze request.
If the effect request may have reached the peer but its receipt is unavailable,
the coordinator retains a durable freeze obligation and queries or retries that
exact request before consuming an ownership abort. Receipt absence never proves
that the effect gate remained open.

## Required Native Boundaries

The joint runtime consumes native receipts through pinned verification
policies. A joint mapping receipt is post-hoc evidence and never grants runtime
authority.

The ownership boundary must provide idempotent reserve, seal, decide, and query
operations. A terminal abort or commit decision is immutable and remains
queryable after acknowledgement loss.

The effect-closure boundary must provide idempotent freeze, thaw, close, and
query operations. Freeze and first external publication must serialize on one
gate. A freeze token is bound to the ownership reservation, source lease epoch,
scope lineage, registry instance, and freeze generation.

Receipt issuer identity is fixed for one handoff. A service-binding or scope
generation may advance before effect freeze, but changing the native signer
incarnation requires aborting that reservation and starting a new handoff.

## Trusted Computing Base

The bounded reference cell trusts:

- the ownership service to be linearizable, durable, non-equivocating, and not
  rolled back;
- each native receipt verifier and its pinned authority identity;
- the vISA canonical reducer, runtime coordinator, provider admission checks,
  and committed journal;
- the effect-closure gate and its same-boot kernel state; and
- the exact binaries, schemas, configurations, and source revisions recorded
  in the evidence bundle.

Signatures and nonces prove authenticity and uniqueness, not freshness. Until a
rollback-resistant external anchor is qualified, hostile storage rollback,
forked authority history, and KMS equivocation remain explicit non-claims.

## Bounded Qualification Scope

The first accepted cell covers one source, one destination, one ownership
service, one vISA continuity unit, and one effect scope. It covers coordinator
and user-service process crashes within one boot. A user-service crash/rebind
keeps the same Registry and scope and advances its binding identity; replacing
the Registry process is a separate unsupported boundary. The cell does not
cover host reboot, permanent source-host loss, anti-rollback/freshness,
SMP/production kernel locking, Byzantine services, real TEE/KMS integration, or
arbitrary durable external providers.

The system matrix must include deterministic cases for:

1. first effect publication racing freeze in both winning orders;
2. destination preparation failure followed by exact abort and source thaw;
3. commit acknowledgement loss, coordinator restart, query, and close;
4. frozen service crash/rebind with stale binding rejection;
5. a pre-commit unresolved tombstone blocking commit;
6. stale scope, lease, freeze-generation, registry, and handoff receipts;
7. abort racing commit with one immutable terminal decision;
8. source crash after commit decision but before closure;
9. destination crash after commit decision but before activation;
10. two concurrent handoffs targeting different destinations;
11. crash after freeze but before sealing `Prepared`; and
12. a stale or substituted destination-prepared receipt.

The independent verifier must additionally reject a bundle containing validly
authenticated abort and commit receipts for the same reservation, even though
the bounded runtime TCB excludes authority-store rollback.

## Implementation Boundary

The feature must not change `contract_core::CONTRACT_VERSION`, the existing
`CanonicalState` wire shape, or any Stage 1-4 registry. Joint protocol state is a
versioned host-side composition profile. It may project a verified terminal
decision into the existing vISA coordinator, but it may not redefine existing
handoff commands or treat local SQLite ownership as cross-host authority truth.

Nexus-native scope, effect, binding, device, and tombstone state must not enter a
vISA portable snapshot. Only typed native receipt digests and the immutable
scope/cohort mapping cross the composition boundary.

## Exit Conditions

This feature closes only when all of the following are true:

- the protocol and threat model pass preflight with both kill conditions intact;
- a pure composition reducer and an independently implemented oracle agree on
  every accepted case and disagree on the retained mutation corpus;
- the bounded TLA+ model checks the safety invariants and the stated recovery
  progress property under its fairness assumptions;
- the vISA host-side composition profile durably recovers every intermediate
  state and requires typed commit/abort/closure evidence;
- the system runner produces a relocatable, exact-artifact evidence bundle and
  the independent verifier semantically recomputes its result;
- one reference effect-closure peer and one clean exact-SHA Nexus process peer
  both pass the unchanged wire contract and applicable case registry, with
  unsupported Registry-replacement and retained-production paths reported
  explicitly rather than synthesized;
- ordinary repository gates and the dedicated joint-handoff gate pass in local
  Docker and pushed CI at the exact closing revision; and
- accepted claims and non-claims are extracted into canonical documentation and
  this temporary feature specification is removed.

## Claim On Exit

Only `bounded-joint-handoff-refinement-v1` for the named ownership service,
vISA adapter, Nexus adapter, same-boot process-crash boundary, fixed case
registry, and exact source revisions.
