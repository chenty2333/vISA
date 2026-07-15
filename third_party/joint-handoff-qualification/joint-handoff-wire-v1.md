# Joint Handoff Wire v1

Status: normative neutral contract.

This repository owns the versioned composition boundary. vISA and Nexus may
use different native encodings, but a qualification adapter must strictly map
its authenticated native receipts to these typed fields and operations. This
contract does not copy either upstream state machine or ownership ledger.

## Authority Order

```text
ownership.reserve
  -> vISA source freeze
  -> durable effect-freeze attempt
  -> effect freeze
  -> vISA destination prepare
  -> ownership seal
  -> exactly one ownership decision
      -> abort: effect thaw -> vISA source resume
      -> commit: effect close -> vISA source fence -> destination activation
```

An effect-freeze timeout is `unknown`, not `not frozen`. A coordinator must
recover and resolve that exact durable request before it may consume an abort
receipt and resume the source.

The v1 mutating operation set is closed: reserve, vISA source freeze, durable
effect-freeze-attempt recording, effect freeze, destination prepare, ownership
seal, ownership abort or commit, effect thaw or close, vISA source resume or
fence, and destination activation. The machine-readable contract separates the
common prefix from the mutually exclusive abort and commit branches.

An ownership commit changes durable ownership but does not activate the
destination. Activation requires an exact commit receipt, exact effect closure
for the frozen cohort, and an exact vISA source-fence receipt. A retained
tombstone keeps activation blocked until a later closure revision closes the
same cohort.

## Request Identity

Every mutating request binds:

```text
(handoff_id, operation_kind, request_digest, expected_state_sequence)
```

The same tuple is idempotent. Reusing a handoff and operation kind with a
different digest is a conflict. Abort and commit are mutually exclusive. Thaw
and close are mutually exclusive. Timeouts, missing acknowledgements, negative
cache entries, and lease expiry are never terminal decisions.

## Handoff Key

```text
JointHandoffKey {
  continuity_unit
  handoff_id                 // never reused
  source
  destination
  expected_source_epoch
  next_destination_epoch    // exactly expected_source_epoch + 1
}
```

All fields are typed domains. Numerically equal values from different domains
are not interchangeable.

## Receipt Header

Every typed receipt has:

```text
ReceiptHeader {
  protocol_version = 1.0
  kind
  issuer
  issuer_incarnation
  key_id
  log_id
  sequence
  previous_digest?
}
```

`previous_digest` links only the same issuer, issuer incarnation, key, and log
namespace. Cross-issuer causality is represented by typed payload references.
Each handoff uses a unique log namespace per issuer. The ownership, vISA
source, vISA destination, and effect-closure issuer identities are fixed for
the handoff; a signer-incarnation change requires a new handoff.

Native authentication is verified by an issuer-specific pinned verifier before
the neutral typed value exists. A public caller cannot construct `Verified<T>`
or substitute a `verified=true` flag. Stage 0 checksum authentication is
explicitly non-cryptographic test evidence and does not qualify a production
native verifier.

## Receipt Kinds

The v1 receipt set is closed:

| Kind | Issuer role | Required causal evidence |
| --- | --- | --- |
| `prepare-intent` | ownership | key, reservation, expected ownership version |
| `visa-freeze` | vISA source | prepare intent, journal position, state digests |
| `nexus-freeze` | effect closure | prepare intent, scope lineage, cohort, readiness |
| `destination-prepared` | vISA destination | both freezes, exact snapshot and lease-commit request |
| `ownership-prepared` | ownership | reservation and all immutable prepared bindings |
| `ownership-abort` | ownership | reservation and optional exact prepared record |
| `ownership-commit` | ownership | exact prepared record and destination epoch |
| `nexus-thaw` | effect closure | exact abort and frozen generation |
| `closure-progress` | effect closure | exact commit, cohort, closure revision |
| `closure` | effect closure | exact commit, cohort, terminal manifest and revision |
| `retained-tombstone` | effect closure | exact commit, cohort, blocker and revision |
| `visa-source-fence` | vISA source | exact commit, closure, and vISA freeze |
| `visa-source-resume` | vISA source | exact abort and vISA freeze; exact thaw when a Nexus freeze exists |
| `visa-destination-activation` | vISA destination | prepared destination, commit, closure, source fence |

The machine-readable causal references define the normalized typed evidence
graph. They do not assert that an unqualified upstream native struct already
embeds every reference in the same shape. A qualification adapter must derive
them from authenticated native receipts and their validated native log parents;
an unbound local-state observation or boolean summary is insufficient.

`ownership-prepared` binds, at minimum, both freeze receipt digests, the exact
snapshot and integrity digest, source journal position and state digest,
component and profile digests, destination-prepared digest and state,
authority/binding digests, effect-cohort manifest, and joint mapping manifest.

Classification counts are indexes only. A verifier recomputes them from the
immutable cohort or terminal manifest. An unresolved pre-commit tombstone makes
the freeze blocked and prevents ownership seal. A resolved or accounted
post-commit tombstone may produce retained recovery, but never permits abort or
activation.

## Recovery Queries

The ownership peer must durably return one of:

```text
not-found | reserved | prepared | abort-decided | commit-decided
```

The effect peer must durably return one of:

```text
not-found | frozen-ready | frozen-blocked | thawed |
closing | retained | closed
```

`not-found` is useful only before a request could have reached that peer. Once a
durable effect-freeze attempt exists, absence of a receipt remains unknown
until the exact request is resolved. Lost append or response acknowledgements
are recovered by querying and replaying the same authenticated receipt, not by
minting a replacement history.

## Claim Boundary

The v1 contract covers same-boot process crash, retry, duplicate delivery,
reordering, and lost acknowledgements under a durable non-equivocating
ownership log and crash-stable local projection. It does not establish host
reboot recovery, permanent source loss, Byzantine or rollback resistance,
cryptographic receipt verification, cross-host production transport, real
Nexus kernel integration, TEE/KMS behavior, or confidentiality.
