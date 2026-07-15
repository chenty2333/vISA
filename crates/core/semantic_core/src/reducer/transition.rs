use contract_core::{
    ActivationRole, ActivationStatus, AuthorityStatus, CanonicalState, CleanupStatus,
    EffectOutcome, EffectResult, Event, EventKind, HandoffPhase, OperationRecord, Ownership,
    Rejection, TimerStatus,
};

use super::{
    apply_effect_outcome, grant_by_identity, local_active, operation_record, outcome_evidence,
    push_evidence, thaw_timer,
};

/// Result of applying a committed event, including idempotent journal replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    Applied(CanonicalState),
    Replay(CanonicalState),
}

impl ApplyResult {
    pub fn state(&self) -> &CanonicalState {
        match self {
            Self::Applied(state) | Self::Replay(state) => state,
        }
    }

    pub fn into_state(self) -> CanonicalState {
        match self {
            Self::Applied(state) | Self::Replay(state) => state,
        }
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::Replay(_))
    }
}

/// Apply one accepted event. Invalid or out-of-order events are rejected.
pub fn apply(state: &CanonicalState, event: &Event) -> Result<ApplyResult, Rejection> {
    if !state.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: state.version });
    }
    if !event.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: event.version });
    }
    if event.identity.is_zero() {
        return Err(Rejection::InvalidIdentity);
    }

    let mut next = state.clone();
    let replay = match &event.kind {
        EventKind::Activated { lease_epoch } => {
            if state.phase == HandoffPhase::Running
                && local_active(state)
                && state.ownership.epoch == *lease_epoch
            {
                true
            } else if state.phase == HandoffPhase::Dormant
                && state.activation.status == ActivationStatus::Inactive
                && state.ownership.owner.is_none()
            {
                next.phase = HandoffPhase::Running;
                next.activation.status = ActivationStatus::Active;
                next.ownership = Ownership::owned(state.activation.node, *lease_epoch);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::AuthorityAttenuated { grant } => {
            if let Some(existing) = grant_by_identity(state, grant.authority.identity) {
                if existing == grant {
                    true
                } else {
                    return Err(Rejection::EventNotApplicable);
                }
            } else {
                next.authorities.push(grant.clone());
                false
            }
        }
        EventKind::AuthorityRevoked { authority, revoked_generation } => {
            if let Some(existing) = grant_by_identity(state, authority.identity) {
                if existing.status == AuthorityStatus::Revoked
                    && existing.authority.generation == *revoked_generation
                {
                    true
                } else if existing.authority == *authority
                    && existing.status == AuthorityStatus::Active
                {
                    let target = next
                        .authorities
                        .iter_mut()
                        .find(|grant| grant.authority == *authority)
                        .ok_or(Rejection::EventNotApplicable)?;
                    target.status = AuthorityStatus::Revoked;
                    target.authority.generation = *revoked_generation;
                    false
                } else {
                    return Err(Rejection::EventNotApplicable);
                }
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::EffectPrepared { request } => {
            if let Some(existing) = operation_record(state, request.operation) {
                if existing.request == *request {
                    true
                } else {
                    return Err(Rejection::EventNotApplicable);
                }
            } else {
                next.operations.push(OperationRecord::prepared(request.clone()));
                false
            }
        }
        EventKind::EffectResolved { operation, outcome } => {
            apply_effect_outcome(&mut next, *operation, outcome, false)?
        }
        EventKind::EffectReconciled { operation, outcome } => {
            apply_effect_outcome(&mut next, *operation, outcome, true)?
        }
        EventKind::OperationCleaned { operation, evidence } => {
            let existing = operation_record(state, *operation)
                .ok_or(Rejection::UnknownOperation { operation: *operation })?;
            if existing.cleanup == CleanupStatus::Cleaned {
                true
            } else {
                let record = next
                    .operations
                    .iter_mut()
                    .find(|record| record.request.operation == *operation)
                    .ok_or(Rejection::EventNotApplicable)?;
                record.cleanup = CleanupStatus::Cleaned;
                if record.request.resource == next.timer.claim.resource
                    && matches!(next.timer.status, TimerStatus::Completed | TimerStatus::Cancelled)
                {
                    next.timer.status = TimerStatus::Cleaned;
                }
                push_evidence(&mut next.evidence, *evidence);
                false
            }
        }
        EventKind::TimerCompleted { timer, arm_operation, evidence } => {
            if state.timer.claim.resource != *timer {
                return Err(Rejection::EventNotApplicable);
            }
            if matches!(state.timer.status, TimerStatus::Completed | TimerStatus::Cleaned) {
                true
            } else if matches!(state.timer.status, TimerStatus::Armed { .. })
                && state.timer.active_operation == Some(*arm_operation)
            {
                next.timer.status = TimerStatus::Completed;
                next.timer.active_operation = None;
                push_evidence(&mut next.evidence, *evidence);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::HandoffStarted => {
            if state.phase == HandoffPhase::Quiescing {
                true
            } else if state.phase == HandoffPhase::Running {
                next.phase = HandoffPhase::Quiescing;
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::Frozen { portable_state, timer } => {
            if state.phase == HandoffPhase::Frozen
                && state.portable_state == *portable_state
                && state.timer.status == TimerStatus::Frozen(*timer)
            {
                true
            } else if state.phase == HandoffPhase::Quiescing {
                next.phase = HandoffPhase::Frozen;
                next.portable_state = portable_state.clone();
                next.timer.status = TimerStatus::Frozen(*timer);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::SnapshotExported { snapshot } => {
            if state.exported_snapshot.as_ref() == Some(snapshot) {
                true
            } else if state.phase == HandoffPhase::Frozen && state.exported_snapshot.is_none() {
                next.phase = HandoffPhase::Exported;
                next.exported_snapshot = Some(snapshot.clone());
                push_evidence(&mut next.evidence, snapshot.evidence);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::DestinationPrepared { prepared } => {
            if state.phase == HandoffPhase::DestinationPrepared
                && state.prepared_destination.as_ref() == Some(prepared)
            {
                true
            } else if state.phase == HandoffPhase::Exported
                && state.activation.role == ActivationRole::Destination
                && state.activation.status == ActivationStatus::Inactive
            {
                next.phase = HandoffPhase::DestinationPrepared;
                next.activation.status = ActivationStatus::Prepared;
                next.prepared_destination = Some(prepared.clone());
                for receipt in &prepared.bindings {
                    push_evidence(&mut next.evidence, receipt.evidence);
                }
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::HandoffCommitted {
            operation,
            handoff,
            snapshot,
            source,
            destination,
            previous_epoch,
            new_epoch,
            outcome,
        } => {
            if state.phase == HandoffPhase::Committed
                && state.ownership == Ownership::owned(*destination, *new_epoch)
            {
                true
            } else {
                if !matches!(
                    state.phase,
                    HandoffPhase::Exported | HandoffPhase::DestinationPrepared
                ) || state.ownership != Ownership::owned(*source, *previous_epoch)
                    || !state.exported_snapshot.as_ref().is_some_and(|record| {
                        record.snapshot == *snapshot && record.handoff == *handoff
                    })
                {
                    return Err(Rejection::EventNotApplicable);
                }

                if let Some(record) =
                    next.operations.iter_mut().find(|record| record.request.operation == *operation)
                {
                    if let Some(existing) = &record.outcome {
                        if existing != outcome {
                            return Err(Rejection::EventNotApplicable);
                        }
                    } else {
                        record.outcome = Some(outcome.clone());
                    }
                } else if state.activation.node == *destination {
                    return Err(Rejection::UnknownOperation { operation: *operation });
                }

                next.phase = HandoffPhase::Committed;
                next.ownership = Ownership::owned(*destination, *new_epoch);
                if state.activation.node == *destination {
                    let prepared =
                        state.prepared_destination.as_ref().ok_or(Rejection::EventNotApplicable)?;
                    next.component.generation = prepared.component_generation;
                    next.activation.status = ActivationStatus::Active;
                    for grant in &prepared.authorities {
                        if !next
                            .authorities
                            .iter()
                            .any(|existing| existing.authority.identity == grant.authority.identity)
                        {
                            next.authorities.push(grant.clone());
                        }
                    }
                } else if state.activation.node == *source {
                    next.activation.status = ActivationStatus::Fenced;
                } else {
                    next.activation.status = ActivationStatus::Inactive;
                }
                if let Some(evidence) = outcome_evidence(outcome) {
                    push_evidence(&mut next.evidence, evidence);
                }
                if let EffectOutcome::Succeeded {
                    result: EffectResult::LeaseAdvanced { source_fence, .. },
                    ..
                } = outcome
                {
                    push_evidence(&mut next.evidence, *source_fence);
                }
                false
            }
        }
        EventKind::HandoffAborted { evidence } => {
            if state.phase == HandoffPhase::Aborted {
                true
            } else {
                if state.activation.role == ActivationRole::Source
                    && local_active(state)
                    && matches!(
                        state.phase,
                        HandoffPhase::Quiescing | HandoffPhase::Frozen | HandoffPhase::Exported
                    )
                {
                    next.phase = HandoffPhase::Aborted;
                } else if state.activation.role == ActivationRole::Destination
                    && state.activation.status == ActivationStatus::Prepared
                    && state.phase == HandoffPhase::DestinationPrepared
                {
                    next.phase = HandoffPhase::Aborted;
                    next.activation.status = ActivationStatus::Inactive;
                } else {
                    return Err(Rejection::EventNotApplicable);
                }
                if let Some(evidence) = evidence {
                    push_evidence(&mut next.evidence, *evidence);
                }
                false
            }
        }
        EventKind::PreparationCleaned { cleanup } => {
            if state.preparation_cleanup.as_ref() == Some(cleanup) {
                true
            } else if state.phase == HandoffPhase::Aborted
                && state
                    .exported_snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.snapshot == cleanup.snapshot)
                && state
                    .prepared_destination
                    .as_ref()
                    .is_none_or(|prepared| prepared.snapshot == cleanup.snapshot)
            {
                next.exported_snapshot = None;
                next.prepared_destination = None;
                next.preparation_cleanup = Some(*cleanup);
                if let Some(evidence) = cleanup.evidence {
                    push_evidence(&mut next.evidence, evidence);
                }
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::SourceResumed => {
            if state.phase == HandoffPhase::Running
                && state.activation.role == ActivationRole::Source
                && local_active(state)
            {
                true
            } else if state.phase == HandoffPhase::Aborted
                && state.activation.role == ActivationRole::Source
                && local_active(state)
            {
                next.phase = HandoffPhase::Running;
                thaw_timer(&mut next);
                next.preparation_cleanup = None;
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::DestinationResumed => {
            if state.phase == HandoffPhase::Running && local_active(state) {
                true
            } else if state.phase == HandoffPhase::Committed
                && state.activation.role == ActivationRole::Destination
                && local_active(state)
            {
                next.phase = HandoffPhase::Running;
                thaw_timer(&mut next);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
        EventKind::JointDestinationResumed { activation_record_digest } => {
            if *activation_record_digest == contract_core::Digest::ZERO {
                return Err(Rejection::EventNotApplicable);
            }
            if state.phase == HandoffPhase::Running && local_active(state) {
                true
            } else if state.phase == HandoffPhase::Committed
                && state.activation.role == ActivationRole::Destination
                && local_active(state)
            {
                next.phase = HandoffPhase::Running;
                thaw_timer(&mut next);
                false
            } else {
                return Err(Rejection::EventNotApplicable);
            }
        }
    };

    if replay { Ok(ApplyResult::Replay(state.clone())) } else { Ok(ApplyResult::Applied(next)) }
}
