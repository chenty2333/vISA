use contract_core::{
    CanonicalState, CleanupStatus, Decision, EffectKind, EffectOutcome, EffectRequest,
    EffectResult, EntityRef, Event, EventKind, HandoffPhase, Identity, LeaseEpoch, NodeIdentity,
    OperationRecord, Rejection, Replay, Rights, TimerDisposition, TimerStatus,
};
use visa_profile::ProfilePayloadError;

use super::{authorize, commit, local_active, push_evidence, quiescing_timer_completion_parent};

pub(super) fn preflight_effect_request(
    state: &CanonicalState,
    event_id: Identity,
    request: &EffectRequest,
) -> Decision {
    if request.operation.is_zero() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }
    if let Some(existing) = operation_record(state, request.operation) {
        return if existing.request == *request {
            Decision::Replay(Replay::Operation(existing.clone()))
        } else {
            Decision::Reject(Rejection::DuplicateOperation { operation: request.operation })
        };
    }
    if let Some(existing) = state
        .operations
        .iter()
        .find(|record| record.request.idempotency_key == request.idempotency_key)
    {
        return if equivalent_idempotent_request(&existing.request, request) {
            Decision::Replay(Replay::Operation(existing.clone()))
        } else {
            Decision::Reject(Rejection::IdempotencyConflict { key: request.idempotency_key })
        };
    }

    let (node, subject, resource, required, expected_epoch) =
        match validate_effect_shape(state, request) {
            Ok(validated) => validated,
            Err(rejection) => return Decision::Reject(rejection),
        };
    if request.node != node {
        return Decision::Reject(Rejection::NodeMismatch { expected: node, actual: request.node });
    }
    if request.subject.identity == subject.identity
        && request.subject.generation != subject.generation
    {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: subject.identity,
            expected: subject.generation,
            actual: request.subject.generation,
        });
    }
    if request.subject != subject {
        return Decision::Reject(Rejection::AuthoritySubjectMismatch);
    }
    if request.resource.identity == resource.identity
        && request.resource.generation != resource.generation
    {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: resource.identity,
            expected: resource.generation,
            actual: request.resource.generation,
        });
    }
    if request.resource != resource {
        return Decision::Reject(Rejection::AuthorityResourceMismatch);
    }
    if request.lease_epoch != expected_epoch {
        return Decision::Reject(Rejection::LeaseEpochMismatch {
            expected: expected_epoch,
            actual: request.lease_epoch,
        });
    }
    if let Err(rejection) = authorize(state, request.authority, subject, resource, required) {
        return Decision::Reject(rejection);
    }

    let event = Event::new(event_id, EventKind::EffectPrepared { request: request.clone() });
    Decision::Execute { intent: event, request: request.clone() }
}

pub(super) fn preflight_effect_resolution(
    state: &CanonicalState,
    event_id: Identity,
    operation_id: Identity,
    outcome: &EffectOutcome,
    reconciliation: bool,
) -> Decision {
    let Some(record) = operation_record(state, operation_id) else {
        return Decision::Reject(Rejection::UnknownOperation { operation: operation_id });
    };
    if reconciliation {
        match &record.outcome {
            Some(existing) if existing == outcome => {
                return Decision::Replay(Replay::Operation(record.clone()));
            }
            Some(EffectOutcome::Indeterminate { .. }) => {}
            Some(_) => {
                return Decision::Reject(Rejection::OperationAlreadyResolved {
                    operation: operation_id,
                });
            }
            None => {}
        }
        if outcome.is_indeterminate() {
            return Decision::Reject(Rejection::OutcomeMismatch);
        }
    } else if let Some(existing) = &record.outcome {
        return if existing == outcome {
            Decision::Replay(Replay::Operation(record.clone()))
        } else {
            Decision::Reject(Rejection::OperationAlreadyResolved { operation: operation_id })
        };
    }
    if !outcome_matches(&record.request.kind, outcome) {
        return Decision::Reject(Rejection::OutcomeMismatch);
    }

    if let (
        EffectKind::LeaseCommit { handoff, snapshot, destination, expected_epoch, next_epoch },
        EffectOutcome::Succeeded { result: EffectResult::LeaseAdvanced { .. }, .. },
    ) = (&record.request.kind, outcome)
    {
        let Some(source) = state.ownership.owner else {
            return Decision::Reject(Rejection::EventNotApplicable);
        };
        return commit(
            event_id,
            EventKind::HandoffCommitted {
                operation: operation_id,
                handoff: *handoff,
                snapshot: *snapshot,
                source,
                destination: *destination,
                previous_epoch: *expected_epoch,
                new_epoch: *next_epoch,
                outcome: outcome.clone(),
            },
        );
    }

    let kind = if reconciliation {
        EventKind::EffectReconciled { operation: operation_id, outcome: outcome.clone() }
    } else {
        EventKind::EffectResolved { operation: operation_id, outcome: outcome.clone() }
    };
    commit(event_id, kind)
}

pub(super) fn preflight_cleanup(
    state: &CanonicalState,
    event_id: Identity,
    operation_id: Identity,
    evidence: contract_core::EvidenceRef,
) -> Decision {
    let Some(record) = operation_record(state, operation_id) else {
        return Decision::Reject(Rejection::UnknownOperation { operation: operation_id });
    };
    if record.cleanup == CleanupStatus::Cleaned {
        return Decision::Replay(Replay::Operation(record.clone()));
    }
    match &record.outcome {
        None => {
            return Decision::Reject(Rejection::CleanupBlocked { operation: operation_id });
        }
        Some(EffectOutcome::Indeterminate { .. }) => {
            return Decision::Reject(Rejection::IndeterminateEffect { operation: operation_id });
        }
        Some(_) => {}
    }
    commit(event_id, EventKind::OperationCleaned { operation: operation_id, evidence })
}

fn validate_effect_shape(
    state: &CanonicalState,
    request: &EffectRequest,
) -> Result<(NodeIdentity, EntityRef, EntityRef, Rights, LeaseEpoch), Rejection> {
    match &request.kind {
        EffectKind::TimerArm { remaining } => {
            if remaining.0 == 0 {
                return Err(Rejection::TimerStateConflict);
            }
            match (state.phase, state.timer.status) {
                (HandoffPhase::Running, TimerStatus::Idle | TimerStatus::Cleaned)
                    if local_active(state) => {}
                (
                    HandoffPhase::Committed,
                    TimerStatus::Frozen(TimerDisposition::Pending {
                        remaining: frozen,
                        arm_operation,
                    }),
                ) if frozen == *remaining
                    && request.causal_parent == Some(arm_operation)
                    && local_active(state) => {}
                _ => return Err(Rejection::InvalidPhase { actual: state.phase }),
            }
            Ok((
                state.activation.node,
                state.component,
                state.timer.claim.resource,
                Rights::TIMER_ARM,
                state.ownership.epoch,
            ))
        }
        EffectKind::TimerCancel { target_operation } => {
            if !matches!(state.phase, HandoffPhase::Running | HandoffPhase::Quiescing)
                || !matches!(state.timer.status, TimerStatus::Armed { .. })
                || state.timer.active_operation != Some(*target_operation)
                || !local_active(state)
            {
                return Err(Rejection::TimerStateConflict);
            }
            Ok((
                state.activation.node,
                state.component,
                state.timer.claim.resource,
                Rights::TIMER_CANCEL,
                state.ownership.epoch,
            ))
        }
        EffectKind::KeyValueRead { .. } => {
            if state.phase != HandoffPhase::Running || !local_active(state) {
                return Err(Rejection::InvalidPhase { actual: state.phase });
            }
            Ok((
                state.activation.node,
                state.component,
                state.key_value.claim.resource,
                Rights::KV_READ,
                state.ownership.epoch,
            ))
        }
        EffectKind::KeyValueCompareAndSet { .. } => {
            let admitted_completion = state.phase == HandoffPhase::Quiescing
                && quiescing_timer_completion_parent(state, request.causal_parent);
            if (state.phase != HandoffPhase::Running && !admitted_completion)
                || !local_active(state)
            {
                return Err(Rejection::InvalidPhase { actual: state.phase });
            }
            Ok((
                state.activation.node,
                state.component,
                state.key_value.claim.resource,
                Rights::KV_WRITE,
                state.ownership.epoch,
            ))
        }
        EffectKind::Profile { profile, access, payload } => {
            if state.phase != HandoffPhase::Running || !local_active(state) {
                return Err(Rejection::InvalidPhase { actual: state.phase });
            }
            let required = visa_profile::validate_profile_effect(
                &state.extensions,
                *profile,
                request.resource,
                *access,
                payload,
            )
            .map_err(|error| profile_rejection(*profile, error))?;
            Ok((
                state.activation.node,
                state.component,
                request.resource,
                required,
                state.ownership.epoch,
            ))
        }
        EffectKind::LeaseCommit { handoff, snapshot, destination, expected_epoch, next_epoch } => {
            if state.phase != HandoffPhase::DestinationPrepared {
                return Err(Rejection::InvalidPhase { actual: state.phase });
            }
            let Some(prepared) = &state.prepared_destination else {
                return Err(Rejection::SnapshotUnavailable);
            };
            if *handoff != prepared.handoff
                || *snapshot != prepared.snapshot
                || *destination != prepared.destination
            {
                return Err(Rejection::SnapshotMismatch);
            }
            if *expected_epoch != prepared.expected_epoch || *next_epoch != prepared.next_epoch {
                return Err(Rejection::LeaseEpochMismatch {
                    expected: prepared.next_epoch,
                    actual: *next_epoch,
                });
            }
            Ok((
                prepared.destination,
                EntityRef::new(state.component.identity, prepared.component_generation),
                EntityRef::new(state.component.identity, prepared.component_generation),
                Rights::HANDOFF,
                prepared.expected_epoch,
            ))
        }
    }
}

pub(super) fn operation_record(
    state: &CanonicalState,
    operation: Identity,
) -> Option<&OperationRecord> {
    state.operations.iter().find(|record| record.request.operation == operation)
}

fn equivalent_idempotent_request(left: &EffectRequest, right: &EffectRequest) -> bool {
    left.idempotency_key == right.idempotency_key
        && left.causal_parent == right.causal_parent
        && left.node == right.node
        && left.subject == right.subject
        && left.resource == right.resource
        && left.authority == right.authority
        && left.lease_epoch == right.lease_epoch
        && left.request_digest == right.request_digest
        && left.kind == right.kind
}

fn outcome_matches(kind: &EffectKind, outcome: &EffectOutcome) -> bool {
    match outcome {
        EffectOutcome::Succeeded { result, .. } => match (kind, result) {
            (EffectKind::TimerArm { .. }, EffectResult::TimerArmed { .. })
            | (EffectKind::TimerCancel { .. }, EffectResult::TimerCancelled)
            | (EffectKind::KeyValueRead { .. }, EffectResult::KeyValueRead { .. })
            | (EffectKind::KeyValueCompareAndSet { .. }, EffectResult::KeyValue { .. }) => true,
            (EffectKind::Profile { .. }, EffectResult::Profile { .. }) => {
                visa_profile::profile_result_matches(kind, result)
            }
            (
                EffectKind::LeaseCommit { destination, next_epoch, .. },
                EffectResult::LeaseAdvanced { owner, epoch, .. },
            ) => destination == owner && next_epoch == epoch,
            _ => false,
        },
        _ => true,
    }
}

pub(super) fn apply_effect_outcome(
    state: &mut CanonicalState,
    operation_id: Identity,
    outcome: &EffectOutcome,
    reconciliation: bool,
) -> Result<bool, Rejection> {
    let index = state
        .operations
        .iter()
        .position(|record| record.request.operation == operation_id)
        .ok_or(Rejection::UnknownOperation { operation: operation_id })?;
    let existing = state.operations[index].outcome.as_ref();
    if existing == Some(outcome) {
        return Ok(true);
    }
    if reconciliation {
        if existing.is_some_and(|outcome| !outcome.is_indeterminate()) || outcome.is_indeterminate()
        {
            return Err(Rejection::EventNotApplicable);
        }
    } else if existing.is_some() {
        return Err(Rejection::EventNotApplicable);
    }
    if !outcome_matches(&state.operations[index].request.kind, outcome) {
        return Err(Rejection::OutcomeMismatch);
    }

    state.operations[index].outcome = Some(outcome.clone());
    apply_resource_outcome(state, index, outcome)?;
    if let Some(evidence) = outcome_evidence(outcome) {
        push_evidence(&mut state.evidence, evidence);
    }
    Ok(false)
}

fn apply_resource_outcome(
    state: &mut CanonicalState,
    operation_index: usize,
    outcome: &EffectOutcome,
) -> Result<(), Rejection> {
    let request = state.operations[operation_index].request.clone();
    let EffectOutcome::Succeeded { result, .. } = outcome else {
        return Ok(());
    };
    match (&request.kind, result) {
        (EffectKind::TimerArm { .. }, EffectResult::TimerArmed { remaining }) => {
            state.timer.status = TimerStatus::Armed { remaining: *remaining };
            state.timer.active_operation = Some(request.operation);
        }
        (EffectKind::TimerCancel { .. }, EffectResult::TimerCancelled) => {
            state.timer.status = TimerStatus::Cancelled;
            state.timer.active_operation = None;
        }
        (EffectKind::KeyValueRead { .. }, EffectResult::KeyValueRead { value }) => {
            state.key_value.last_version = value.as_ref().map(|value| value.version);
            state.key_value.last_operation = Some(request.operation);
        }
        (EffectKind::KeyValueCompareAndSet { .. }, EffectResult::KeyValue { version, .. }) => {
            state.key_value.last_version = Some(*version);
            state.key_value.last_operation = Some(request.operation);
        }
        (EffectKind::Profile { profile, .. }, EffectResult::Profile { .. }) => {
            visa_profile::apply_profile_result(
                &mut state.extensions,
                &request.kind,
                result,
                request.operation,
            )
            .map_err(|error| profile_rejection(*profile, error))?;
        }
        (EffectKind::LeaseCommit { .. }, EffectResult::LeaseAdvanced { .. }) => {
            return Err(Rejection::EventNotApplicable);
        }
        _ => return Err(Rejection::OutcomeMismatch),
    }
    Ok(())
}

fn profile_rejection(profile: Identity, error: ProfilePayloadError) -> Rejection {
    match error {
        ProfilePayloadError::UnknownProfile | ProfilePayloadError::MissingExtension => {
            Rejection::UnknownProfile { id: profile }
        }
        ProfilePayloadError::ResourceMismatch => Rejection::AuthorityResourceMismatch,
        ProfilePayloadError::AccessMismatch => Rejection::InvalidRights,
        ProfilePayloadError::DuplicateExtension
        | ProfilePayloadError::VersionMismatch
        | ProfilePayloadError::InvalidPayload
        | ProfilePayloadError::StateConflict
        | ProfilePayloadError::UnsupportedContinuity => {
            Rejection::InvalidProfilePayload { id: profile }
        }
    }
}

pub(super) fn outcome_evidence(outcome: &EffectOutcome) -> Option<contract_core::EvidenceRef> {
    match outcome {
        EffectOutcome::Succeeded { evidence, .. } => Some(*evidence),
        EffectOutcome::Failed(failure) => failure.evidence,
        EffectOutcome::Cancelled { evidence }
        | EffectOutcome::Unsupported { evidence }
        | EffectOutcome::Indeterminate { evidence } => *evidence,
    }
}
