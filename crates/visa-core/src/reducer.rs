//! Pure state reduction for durable capture facts owned by vISA.
//!
//! Binding, fencing, source restoration, activation, and recovery decisions
//! belong to the coordinator and their external authorities. This reducer
//! intentionally does not project those facts into a second core ledger.

use serde::{Deserialize, Serialize};

use crate::{
    ContinuationId, ContractError, LineagePoint, ProfileRef, ScopeId, SnapshotEnvelope,
    SnapshotReceipt,
};

/// Durable intent, independent of host-local runtime and authority handles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationIntent {
    pub id: ContinuationId,
    pub scope: ScopeId,
    pub lineage_parent: LineagePoint,
    pub profile: ProfileRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
    /// A durable capture has been requested but no capture fact is recorded.
    Capturing,
    /// An exact `SnapshotReceipt` binds the recorded portable snapshot.
    Captured,
    /// Only the local, pre-capture intent was cancelled. This is not proof
    /// that a frozen source was restored or that any external action aborted.
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationRecord {
    pub revision: u64,
    pub intent: ContinuationIntent,
    pub phase: Progress,
    pub snapshot: Option<SnapshotEnvelope>,
    pub capture: Option<SnapshotReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Begun(ContinuationIntent),
    CaptureRecorded { snapshot: SnapshotEnvelope, receipt: SnapshotReceipt },
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Decision {
    Apply(Event),
    AlreadyApplied,
    Reject(ContractError),
}

/// Validate an event without changing state or invoking an external system.
#[must_use]
pub fn preflight(record: Option<&ContinuationRecord>, event: &Event) -> Decision {
    match (record, event) {
        (None, Event::Begun(intent)) => Decision::Apply(Event::Begun(intent.clone())),
        (Some(_), Event::Begun(_)) => Decision::Reject(ContractError::RecordAlreadyExists),
        (None, _) => Decision::Reject(ContractError::MissingRecord),
        (Some(record), Event::CaptureRecorded { snapshot, receipt }) => {
            capture(record, snapshot, receipt)
        }
        (Some(record), Event::Aborted) => abort(record),
    }
}

fn capture(
    record: &ContinuationRecord,
    snapshot: &SnapshotEnvelope,
    receipt: &SnapshotReceipt,
) -> Decision {
    if record.phase == Progress::Captured
        && record.snapshot.as_ref() == Some(snapshot)
        && record.capture.as_ref() == Some(receipt)
    {
        return Decision::AlreadyApplied;
    }
    if record.phase != Progress::Capturing || record.snapshot.is_some() {
        return Decision::Reject(ContractError::InvalidPhase);
    }
    if let Err(error) = snapshot.verify().and_then(|()| receipt.verify()) {
        return Decision::Reject(error);
    }
    let body = &snapshot.body;
    if body.continuation != record.intent.id
        || body.scope != record.intent.scope
        || body.lineage.parent != record.intent.lineage_parent
        || body.profile != record.intent.profile
        || receipt.continuation != body.continuation
        || receipt.scope != body.scope
        || receipt.snapshot != body.snapshot
        || receipt.snapshot_digest != snapshot.body_digest
        || receipt.lineage != body.lineage
        || receipt.profile != body.profile
        || receipt.source != body.source
        || receipt.semantic_cut != body.semantic_cut
    {
        return Decision::Reject(ContractError::CaptureMismatch);
    }
    Decision::Apply(Event::CaptureRecorded { snapshot: snapshot.clone(), receipt: receipt.clone() })
}

fn abort(record: &ContinuationRecord) -> Decision {
    match record.phase {
        Progress::Capturing => Decision::Apply(Event::Aborted),
        Progress::Captured => Decision::Reject(ContractError::InvalidPhase),
        Progress::Aborted => Decision::AlreadyApplied,
    }
}

/// Apply a previously accepted pure event.
pub fn apply(
    record: Option<&ContinuationRecord>,
    event: &Event,
) -> Result<ContinuationRecord, ContractError> {
    let accepted = match preflight(record, event) {
        Decision::Apply(value) => value,
        Decision::AlreadyApplied => return record.cloned().ok_or(ContractError::MissingRecord),
        Decision::Reject(error) => return Err(error),
    };
    Ok(match accepted {
        Event::Begun(intent) => ContinuationRecord {
            revision: 0,
            intent,
            phase: Progress::Capturing,
            snapshot: None,
            capture: None,
        },
        Event::CaptureRecorded { snapshot, receipt } => {
            next(record, Progress::Captured, Some(snapshot), Some(receipt))?
        }
        Event::Aborted => next(record, Progress::Aborted, None, None)?,
    })
}

fn next(
    record: Option<&ContinuationRecord>,
    progress: Progress,
    snapshot: Option<SnapshotEnvelope>,
    capture: Option<SnapshotReceipt>,
) -> Result<ContinuationRecord, ContractError> {
    let mut next = record.expect("non-begin event has a record").clone();
    next.revision = next.revision.checked_add(1).ok_or(ContractError::RevisionOverflow)?;
    next.phase = progress;
    if snapshot.is_some() {
        next.snapshot = snapshot;
    }
    if capture.is_some() {
        next.capture = capture;
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use crate::*;
    use alloc::vec;

    fn intent() -> ContinuationIntent {
        ContinuationIntent {
            id: ContinuationId::from_u128(1),
            scope: ScopeId::from_u128(2),
            lineage_parent: LineagePoint {
                lineage: LineageId::from_u128(3),
                generation: 4,
                state_digest: Digest::ZERO,
            },
            profile: ProfileRef {
                id: ProfileId::from_u128(5),
                version: ProfileVersion { major: 1, minor: 0 },
                contract_digest: Digest::ZERO,
                state_schema: SchemaRef { id: SchemaId::from_u128(6), version: 1 },
            },
        }
    }

    fn captured(intent: &ContinuationIntent) -> (SnapshotEnvelope, SnapshotReceipt) {
        let source = ExternalCoordinate {
            authority: AuthorityId::from_u128(7),
            value: OpaqueBytes(vec![9]),
        };
        let semantic_cut = SemanticCut {
            sequence: 4,
            safe_point_digest: Digest::of_bytes(b"safe point"),
            admission_digest: Digest::of_bytes(b"admission closed"),
        };
        let snapshot = SnapshotEnvelope::seal(PortableSnapshot {
            snapshot: SnapshotId::from_u128(8),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance {
                parent: intent.lineage_parent.clone(),
                successor_generation: 5,
            },
            profile: intent.profile.clone(),
            source: source.clone(),
            semantic_cut,
            state: OpaqueBytes(vec![1, 2, 3]),
            state_digest: Digest::ZERO,
            resources: vec![],
        })
        .unwrap();
        let receipt = SnapshotReceipt {
            operation: OperationId::from_u128(9),
            request_digest: Digest::ZERO,
            continuation: intent.id,
            scope: intent.scope,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            lineage: snapshot.body.lineage.clone(),
            profile: intent.profile.clone(),
            source,
            semantic_cut,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        (snapshot, receipt)
    }

    #[test]
    fn snapshot_integrity_covers_state_and_contract() {
        let intent = intent();
        let (mut snapshot, _) = captured(&intent);
        snapshot.body.state.0.push(4);
        assert_eq!(snapshot.verify(), Err(ContractError::StateDigestMismatch));
    }

    #[test]
    fn lineage_successor_uses_the_portable_state_digest() {
        let intent = intent();
        let (snapshot, _) = captured(&intent);
        let successor = snapshot.successor_point().unwrap();
        assert_eq!(successor.state_digest, snapshot.body.state_digest);
    }

    #[test]
    fn reducer_accepts_only_a_matching_durable_capture() {
        let intent = intent();
        let started = apply(None, &Event::Begun(intent.clone())).unwrap();
        let (snapshot, receipt) = captured(&intent);
        let captured =
            apply(Some(&started), &Event::CaptureRecorded { snapshot, receipt }).unwrap();
        assert_eq!(captured.phase, Progress::Captured);
    }

    #[test]
    fn capture_rejects_a_receipt_for_a_different_source_or_cut() {
        let intent = intent();
        let record = apply(None, &Event::Begun(intent.clone())).unwrap();
        let (snapshot, mut receipt) = captured(&intent);
        receipt.semantic_cut.sequence += 1;
        receipt = receipt.seal().unwrap();
        assert!(matches!(
            preflight(Some(&record), &Event::CaptureRecorded { snapshot, receipt }),
            Decision::Reject(ContractError::CaptureMismatch)
        ));

        let (snapshot, mut receipt) = captured(&intent);
        receipt.source.value.0.push(10);
        receipt = receipt.seal().unwrap();
        assert!(matches!(
            preflight(Some(&record), &Event::CaptureRecorded { snapshot, receipt }),
            Decision::Reject(ContractError::CaptureMismatch)
        ));
    }

    #[test]
    fn snapshot_rejects_duplicate_requirement_ids_on_seal_and_verify() {
        let intent = intent();
        let (snapshot, _) = captured(&intent);
        let requirement = ResourceRequirement {
            id: RequirementId::from_u128(10),
            schema: SchemaRef { id: SchemaId::from_u128(11), version: 1 },
            logical_name: OpaqueBytes(vec![1]),
            required_rights: Rights(1),
            profile_data: OpaqueBytes(vec![]),
        };
        let mut body = snapshot.body.clone();
        body.resources = vec![requirement.clone(), requirement];
        assert_eq!(SnapshotEnvelope::seal(body), Err(ContractError::DuplicateResourceRequirement));

        let mut malformed = snapshot;
        let requirement = ResourceRequirement {
            id: RequirementId::from_u128(12),
            schema: SchemaRef { id: SchemaId::from_u128(13), version: 1 },
            logical_name: OpaqueBytes(vec![2]),
            required_rights: Rights(1),
            profile_data: OpaqueBytes(vec![]),
        };
        malformed.body.resources = vec![requirement.clone(), requirement];
        malformed.body_digest = canonical_digest(&malformed.body).unwrap();
        assert_eq!(malformed.verify(), Err(ContractError::DuplicateResourceRequirement));
    }

    #[test]
    fn arithmetic_overflow_fails_closed() {
        let mut overflowing = intent();
        overflowing.lineage_parent.generation = u64::MAX;
        let (snapshot, _) = captured(&intent());
        let mut body = snapshot.body.clone();
        body.lineage.parent = overflowing.lineage_parent;
        body.lineage.successor_generation = 0;
        assert_eq!(SnapshotEnvelope::seal(body), Err(ContractError::InvalidLineageAdvance));

        let intent = intent();
        let mut record = apply(None, &Event::Begun(intent.clone())).unwrap();
        record.revision = u64::MAX;
        let (snapshot, receipt) = captured(&intent);
        assert_eq!(
            apply(Some(&record), &Event::CaptureRecorded { snapshot, receipt }),
            Err(ContractError::RevisionOverflow)
        );
    }

    #[test]
    fn captured_continuation_cannot_be_aborted_without_external_receipts() {
        let intent = intent();
        let (snapshot, receipt) = captured(&intent);
        let started = apply(None, &Event::Begun(intent)).unwrap();
        let captured =
            apply(Some(&started), &Event::CaptureRecorded { snapshot, receipt }).unwrap();
        assert_eq!(
            preflight(Some(&captured), &Event::Aborted),
            Decision::Reject(ContractError::InvalidPhase)
        );
    }

    #[test]
    fn binding_closure_is_exact() {
        let intent = intent();
        let (snapshot, _) = captured(&intent);
        let requirement = ResourceRequirement {
            id: RequirementId::from_u128(20),
            schema: SchemaRef { id: SchemaId::from_u128(21), version: 1 },
            logical_name: OpaqueBytes(vec![1]),
            required_rights: Rights(3),
            profile_data: OpaqueBytes(vec![]),
        };
        let mut body = snapshot.body;
        body.resources = vec![requirement.clone()];
        let snapshot = SnapshotEnvelope::seal(body).unwrap();
        let coordinate = ExternalCoordinate {
            authority: AuthorityId::from_u128(22),
            value: OpaqueBytes(vec![1]),
        };
        let receipt = BindingPreparationReceipt {
            operation: OperationId::from_u128(23),
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            destination: coordinate.clone(),
            grants: vec![BindingGrant {
                requirement: requirement.id,
                provider: coordinate.clone(),
                provider_generation: 1,
                binding: coordinate,
                granted_rights: requirement.required_rights,
            }],
            request_digest: Digest::of_bytes(b"prepare bindings"),
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        assert_eq!(receipt.validate_for(&snapshot), Ok(()));

        let mut mismatched = receipt.clone();
        mismatched.grants[0].granted_rights = Rights(1);
        mismatched = mismatched.seal().unwrap();
        assert_eq!(mismatched.validate_for(&snapshot), Err(ContractError::BindingMismatch));
    }

    #[test]
    fn snapshot_contract_is_bounded() {
        let intent = intent();
        let (snapshot, _) = captured(&intent);
        let requirement = ResourceRequirement {
            id: RequirementId::from_u128(24),
            schema: SchemaRef { id: SchemaId::from_u128(25), version: 1 },
            logical_name: OpaqueBytes(vec![]),
            required_rights: Rights(1),
            profile_data: OpaqueBytes(vec![]),
        };
        let mut body = snapshot.body;
        body.resources = vec![requirement; MAX_RESOURCE_REQUIREMENTS + 1];
        assert_eq!(SnapshotEnvelope::seal(body), Err(ContractError::TooManyResourceRequirements));
    }
}
