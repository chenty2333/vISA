# Feature 009 Data Model

## Identifiers

All identities are typed by their field. Numerically equal values in different
domains are not interchangeable.

```text
JointHandoffKey {
  continuity_unit
  handoff_id
  source_node
  destination_node
  source_lease_epoch
  destination_lease_epoch
}

OwnershipVersion {
  service_id
  service_incarnation
  log_sequence
}

EffectScopeVersion {
  registry_instance
  scope_id
  scope_generation
  authority_epoch
  freeze_generation
}
```

`handoff_id` is never reused. An ownership service must retain enough terminal
history to reject a late or conflicting message for a completed handoff.

## Immutable Bindings

An ownership `PreparedFrozen` record binds all of the following:

```text
prepare_intent_receipt_digest
visa_freeze_receipt_digest
effect_freeze_receipt_digest
snapshot_id
snapshot_integrity_digest
source_journal_position
source_state_digest
component_digest
profile_digest
destination_prepared_receipt_digest
destination_state_digest
prepared_authorities_digest
prepared_bindings_digest
effect_cohort_manifest_digest
joint_mapping_manifest_digest
```

The immutable effect cohort identity is distinct from mutable closure progress.
Classification counts are display indexes only and must be recomputed from the
retained cohort manifest.

## Receipt Envelope

Every native receipt crosses the joint boundary in an envelope containing:

```text
ReceiptEnvelope {
  schema
  issuer
  issuer_incarnation
  kind
  handoff_id
  request_digest
  state_sequence
  payload_digest
  previous_receipt_digest?
  authentication
}
```

The payload is strictly decoded according to `kind`; unknown and duplicate JSON
fields are rejected. Runtime authorization trusts only native receipts accepted
by the issuer-specific pinned verifier. The neutral verifier retains and checks
the exact native bytes.

`state_sequence` is monotonic within one non-rollback issuer incarnation. It is
not by itself an external freshness anchor.

## Ownership Receipts

```text
PrepareIntentReceipt {
  key
  reservation_id
  ownership_version
}

OwnershipPreparedReceipt {
  key
  reservation_id
  prepared_bindings
  ownership_version
}

OwnershipAbortReceipt {
  key
  reservation_id
  prepared_digest?
  decision = abort
  ownership_version
}

OwnershipCommitReceipt {
  key
  reservation_id
  prepared_digest
  decision = commit
  ownership_version
}
```

Abort is legal for an unsealed exact reservation or a sealed prepared record.
Commit is legal only for the exact sealed prepared record. Abort and commit are
mutually exclusive terminal decisions.

## Effect-Closure Receipts

```text
EffectFreezeReceipt {
  key
  ownership_reservation_digest
  effect_scope_version
  effect_cohort_manifest_digest
  readiness = ready | blocked(blocker_code)
}

EffectThawReceipt {
  key
  effect_scope_version
  ownership_abort_receipt_digest
  result = active | recovery_required
}

EffectClosureProgressReceipt {
  key
  effect_scope_version
  ownership_commit_receipt_digest
  closure_revision
  classification_manifest_digest
  result = closing | retained(blocker_code)
}

EffectClosureReceipt {
  key
  effect_scope_version
  ownership_commit_receipt_digest
  closure_revision
  terminal_manifest_digest
  result = closed
}
```

Freeze, thaw, and close are idempotent for the same handoff, generation, and
request digest. A different request at the same step is a conflict. Thaw and
close are mutually exclusive.

## Joint Mapping Evidence

```text
JointMappingManifest {
  schema
  key
  visa_operation_cohort_digest
  nexus_scope
  nexus_effect_cohort_digest
  domain_bindings_manifest_digest
  ownership_service
  protocol_revision
}
```

The mapping is fixed before `PreparedFrozen` is sealed. Per-operation evidence
may map one vISA operation to one or more native effects, but the handoff root is
always a continuity-unit/cohort mapping rather than a singular operation.

## Durable Joint Projection

The vISA host-side wrapper stores:

```text
JointProjectionState {
  protocol_version
  key
  revision
  phase
  prepare_intent_digest
  visa_freeze_digest?
  effect_freeze_digest?
  prepared_digest?
  decision_digest?
  thaw_or_closure_digest?
  local_journal_position?
}
```

This is a crash-recovery projection, not an ownership ledger. On recovery it is
accepted only after querying the authoritative ownership service and matching
the exact native receipt chain. An unavailable or inconsistent query leaves the
wrapper fail closed and does not expose the underlying runtime coordinator.

The projection also retains the exact canonical effect-peer invocation in an
effect-freeze attempt record before the real peer call is issued. A
response-derived receipt-issuance binding is not peer-invocation evidence. An
attempt without a recovered freeze or authoritative
not-frozen result is an unresolved obligation; an abort receipt alone cannot
clear it or resume the source.
