# Joint Handoff Wire v1 Review Contract

Status: pre-implementation review contract. The neutral composition artifact
will own the accepted machine-readable schema and golden vectors.

## Operations

```text
ownership.reserve(key, expected_owner_version)
  -> PrepareIntentReceipt | Conflict

effects.freeze(scope, key, prepare_intent_receipt)
  -> EffectFreezeReceipt

ownership.seal(reservation, prepared_bindings)
  -> OwnershipPreparedReceipt | Blocked | Conflict

ownership.abort(reservation, expected_version)
  -> OwnershipAbortReceipt | ExistingCommit | Conflict

ownership.commit(prepared, expected_version)
  -> OwnershipCommitReceipt | ExistingAbort | Conflict

ownership.query(handoff_id)
  -> Reserved | Prepared | AbortDecided | CommitDecided | NotFound

effects.thaw(freeze_token, ownership_abort_receipt)
  -> EffectThawReceipt | Conflict

effects.close(freeze_token, ownership_commit_receipt)
  -> EffectClosureProgressReceipt | EffectClosureReceipt | Conflict

effects.query(handoff_id, freeze_generation)
  -> FrozenReady | FrozenBlocked | Closing | Retained | Closed | Thawed
```

## Request Rules

Every mutating request binds:

```text
(handoff_id, operation_kind, request_digest, expected_state_sequence)
```

The same tuple is idempotent and returns the same receipt. Reuse of the same
handoff and operation kind with a different request digest is a conflict. A
timeout or unavailable response never implies abort.

## Verification Rules

The receiving adapter verifies native authentication inside its own trust
boundary. It must also validate the exact issuer, incarnation, handoff, source,
destination, source and destination epochs, reservation, prepared digest,
scope, scope generation, freeze generation, and receipt-parent digest required
by the current joint state.

A caller cannot submit a boolean such as `verified=true`. If an implementation
uses a `Verified<T>` type, external code cannot construct it without passing the
pinned native verifier.

## Recovery Rules

- no decision or an unavailable ownership service: remain frozen;
- authoritative abort: thaw the exact freeze generation, then project vISA
  abort and resume;
- authoritative commit: irreversibly close the exact freeze generation;
- retained closure: keep destination inactive and retain the cleanup
  obligation;
- closed source: project the external decision into vISA and only then permit
  destination resume;
- host reboot before a crash-stable freeze marker is restored: fail closed.

No timeout, coordinator lease expiry, or local cache entry may substitute for an
authoritative ownership query.
