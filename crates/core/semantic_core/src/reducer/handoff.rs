use contract_core::{
    ActivationRole, ActivationStatus, CanonicalState, Decision, EffectOutcome, EntityRef,
    EventKind, HandoffPhase, Identity, LeaseEpoch, PreparationCleanup, PreparedDestination,
    Rejection, Replay, Rights, TimerDisposition, TimerStatus,
};

use super::{
    authorize, commit, local_active, reject_phase, valid_timer_freeze,
    validate_destination_authorities,
};

pub(super) fn preflight_activate(
    state: &CanonicalState,
    event_id: Identity,
    authority: EntityRef,
    lease_epoch: LeaseEpoch,
) -> Decision {
    if state.phase == HandoffPhase::Running
        && local_active(state)
        && state.ownership.epoch == lease_epoch
    {
        return Decision::Replay(Replay::NoChange);
    }
    if state.phase != HandoffPhase::Dormant {
        return reject_phase(state);
    }
    if state.activation.status != ActivationStatus::Inactive || state.ownership.owner.is_some() {
        return reject_phase(state);
    }
    let Some(expected_epoch) = state.ownership.epoch.next() else {
        return Decision::Reject(Rejection::LeaseEpochExhausted);
    };
    if lease_epoch != expected_epoch {
        return Decision::Reject(Rejection::LeaseEpochMismatch {
            expected: expected_epoch,
            actual: lease_epoch,
        });
    }
    if let Err(rejection) =
        authorize(state, authority, state.component, state.component, Rights::HANDOFF)
    {
        return Decision::Reject(rejection);
    }
    commit(event_id, EventKind::Activated { lease_epoch })
}

pub(super) fn preflight_begin_handoff(
    state: &CanonicalState,
    event_id: Identity,
    authority: EntityRef,
) -> Decision {
    if state.phase == HandoffPhase::Quiescing {
        return Decision::Replay(Replay::NoChange);
    }
    if state.phase != HandoffPhase::Running {
        return reject_phase(state);
    }
    if !local_active(state) {
        return reject_phase(state);
    }
    if let Err(rejection) =
        authorize(state, authority, state.component, state.component, Rights::HANDOFF)
    {
        return Decision::Reject(rejection);
    }
    commit(event_id, EventKind::HandoffStarted)
}

pub(super) fn preflight_freeze(
    state: &CanonicalState,
    event_id: Identity,
    portable_state: &[u8],
    timer: TimerDisposition,
) -> Decision {
    if state.phase == HandoffPhase::Frozen
        && state.portable_state == portable_state
        && state.timer.status == TimerStatus::Frozen(timer)
    {
        return Decision::Replay(Replay::NoChange);
    }
    if state.phase != HandoffPhase::Quiescing {
        return reject_phase(state);
    }
    if let Some(record) = state.operations.iter().find(|record| record.outcome.is_none()) {
        return Decision::Reject(Rejection::InFlightEffect { operation: record.request.operation });
    }
    if let Some(record) = state
        .operations
        .iter()
        .find(|record| record.outcome.as_ref().is_some_and(EffectOutcome::is_indeterminate))
    {
        return Decision::Reject(Rejection::IndeterminateEffect {
            operation: record.request.operation,
        });
    }
    if visa_profile::validate_profile_handoff(&state.extensions).is_err() {
        return Decision::Reject(Rejection::ProfileMismatch);
    }
    if !valid_timer_freeze(state, timer) {
        return Decision::Reject(Rejection::TimerStateConflict);
    }
    commit(event_id, EventKind::Frozen { portable_state: portable_state.to_vec(), timer })
}

pub(super) fn preflight_export(
    state: &CanonicalState,
    event_id: Identity,
    snapshot: &contract_core::SnapshotRecord,
) -> Decision {
    if let Some(existing) = &state.exported_snapshot {
        return if existing == snapshot {
            Decision::Replay(Replay::NoChange)
        } else {
            Decision::Reject(Rejection::SnapshotAlreadyExported)
        };
    }
    if state.phase != HandoffPhase::Frozen {
        return reject_phase(state);
    }
    if snapshot.handoff.is_zero()
        || snapshot.snapshot.is_zero()
        || snapshot.evidence.identity.is_zero()
    {
        return Decision::Reject(Rejection::InvalidIdentity);
    }
    commit(event_id, EventKind::SnapshotExported { snapshot: snapshot.clone() })
}

pub(super) fn preflight_prepare(
    state: &CanonicalState,
    event_id: Identity,
    prepared: &PreparedDestination,
) -> Decision {
    if state.phase == HandoffPhase::DestinationPrepared {
        return if state.prepared_destination.as_ref() == Some(prepared) {
            Decision::Replay(Replay::NoChange)
        } else {
            reject_phase(state)
        };
    }
    if state.phase != HandoffPhase::Exported
        || state.activation.role != ActivationRole::Destination
        || state.activation.status != ActivationStatus::Inactive
    {
        return reject_phase(state);
    }
    let Some(snapshot) = &state.exported_snapshot else {
        return Decision::Reject(Rejection::SnapshotUnavailable);
    };
    if prepared.handoff != snapshot.handoff
        || prepared.snapshot != snapshot.snapshot
        || prepared.destination != state.activation.node
        || prepared.destination.is_zero()
    {
        return Decision::Reject(Rejection::SnapshotMismatch);
    }
    let Some(expected_generation) = state.component.generation.next() else {
        return Decision::Reject(Rejection::GenerationExhausted);
    };
    if prepared.component_generation != expected_generation {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: state.component.identity,
            expected: expected_generation,
            actual: prepared.component_generation,
        });
    }
    let last_epoch = state.ownership.epoch;
    let Some(next_epoch) = last_epoch.next() else {
        return Decision::Reject(Rejection::LeaseEpochExhausted);
    };
    if prepared.expected_epoch != last_epoch || prepared.next_epoch != next_epoch {
        return Decision::Reject(Rejection::LeaseEpochMismatch {
            expected: next_epoch,
            actual: prepared.next_epoch,
        });
    }
    if let Err(rejection) = validate_destination_authorities(state, prepared) {
        return Decision::Reject(rejection);
    }
    if let Err(rejection) = validate_bindings(state, prepared) {
        return Decision::Reject(rejection);
    }
    commit(event_id, EventKind::DestinationPrepared { prepared: prepared.clone() })
}

pub(super) fn preflight_abort(
    state: &CanonicalState,
    event_id: Identity,
    evidence: Option<contract_core::EvidenceRef>,
) -> Decision {
    if state.phase == HandoffPhase::Aborted {
        return Decision::Replay(Replay::NoChange);
    }
    let legal = (state.activation.role == ActivationRole::Source
        && local_active(state)
        && matches!(
            state.phase,
            HandoffPhase::Quiescing | HandoffPhase::Frozen | HandoffPhase::Exported
        ))
        || (state.activation.role == ActivationRole::Destination
            && state.activation.status == ActivationStatus::Prepared
            && state.phase == HandoffPhase::DestinationPrepared);
    if !legal {
        return reject_phase(state);
    }
    commit(event_id, EventKind::HandoffAborted { evidence })
}

pub(super) fn preflight_cleanup_preparation(
    state: &CanonicalState,
    event_id: Identity,
    snapshot: Identity,
    evidence: Option<contract_core::EvidenceRef>,
) -> Decision {
    let cleanup = PreparationCleanup { snapshot, evidence };
    if let Some(existing) = state.preparation_cleanup {
        return if existing == cleanup {
            Decision::Replay(Replay::NoChange)
        } else {
            Decision::Reject(Rejection::SnapshotMismatch)
        };
    }
    if state.phase != HandoffPhase::Aborted {
        return reject_phase(state);
    }
    let Some(exported) = &state.exported_snapshot else {
        return Decision::Reject(Rejection::SnapshotUnavailable);
    };
    if snapshot.is_zero()
        || exported.snapshot != snapshot
        || state.prepared_destination.as_ref().is_some_and(|prepared| prepared.snapshot != snapshot)
    {
        return Decision::Reject(Rejection::SnapshotMismatch);
    }
    commit(event_id, EventKind::PreparationCleaned { cleanup })
}

pub(super) fn preflight_resume(state: &CanonicalState, event_id: Identity) -> Decision {
    if state.phase == HandoffPhase::Running && local_active(state) {
        return Decision::Replay(Replay::NoChange);
    }
    if state.phase != HandoffPhase::Committed
        || state.activation.role != ActivationRole::Destination
        || !local_active(state)
    {
        return reject_phase(state);
    }
    if let Some(record) = state.operations.iter().find(|record| record.outcome.is_none()) {
        return Decision::Reject(Rejection::InFlightEffect { operation: record.request.operation });
    }
    if let Some(record) = state
        .operations
        .iter()
        .find(|record| record.outcome.as_ref().is_some_and(EffectOutcome::is_indeterminate))
    {
        return Decision::Reject(Rejection::IndeterminateEffect {
            operation: record.request.operation,
        });
    }
    if matches!(state.timer.status, TimerStatus::Frozen(TimerDisposition::Pending { .. })) {
        return Decision::Reject(Rejection::TimerStateConflict);
    }
    commit(event_id, EventKind::DestinationResumed)
}

pub(super) fn preflight_resume_source(state: &CanonicalState, event_id: Identity) -> Decision {
    if state.phase == HandoffPhase::Running
        && state.activation.role == ActivationRole::Source
        && local_active(state)
    {
        return Decision::Replay(Replay::NoChange);
    }
    if state.phase != HandoffPhase::Aborted
        || state.activation.role != ActivationRole::Source
        || !local_active(state)
        || state.exported_snapshot.is_some()
        || state.prepared_destination.is_some()
    {
        return reject_phase(state);
    }
    commit(event_id, EventKind::SourceResumed)
}

fn validate_bindings(
    state: &CanonicalState,
    prepared: &PreparedDestination,
) -> Result<(), Rejection> {
    validate_binding(
        state,
        prepared,
        &state.timer.claim.resource,
        state.timer.claim.required_rights,
    )?;
    validate_binding(
        state,
        prepared,
        &state.key_value.claim.resource,
        state.key_value.claim.required_rights,
    )?;
    let profile_resources = visa_profile::profile_resources(&state.extensions)
        .map_err(|_| Rejection::ProfileMismatch)?;
    for resource in &profile_resources {
        validate_binding(state, prepared, &resource.resource, resource.required_rights)?;
    }
    for receipt in &prepared.bindings {
        if receipt.claim != state.timer.claim.resource
            && receipt.claim != state.key_value.claim.resource
            && !profile_resources.iter().any(|resource| resource.resource == receipt.claim)
        {
            return Err(Rejection::InvalidBinding { claim: receipt.claim });
        }
    }
    Ok(())
}

fn validate_binding(
    state: &CanonicalState,
    prepared: &PreparedDestination,
    claim: &EntityRef,
    required: Rights,
) -> Result<(), Rejection> {
    let mut receipts = prepared.bindings.iter().filter(|receipt| receipt.claim == *claim);
    let receipt = receipts.next().ok_or(Rejection::MissingBinding { claim: *claim })?;
    if receipts.next().is_some()
        || receipt.handoff != prepared.handoff
        || receipt.snapshot != prepared.snapshot
        || receipt.node != prepared.destination
        || receipt.binding.identity.is_zero()
        || receipt.lease_epoch != prepared.next_epoch
    {
        return Err(Rejection::InvalidBinding { claim: *claim });
    }
    let grant = prepared
        .authorities
        .iter()
        .find(|grant| grant.authority == receipt.authority)
        .ok_or(Rejection::UnknownAuthority { authority: receipt.authority })?;
    if grant.resource != *claim || !receipt.exposed_rights.is_subset_of(grant.rights) {
        return Err(Rejection::InvalidBinding { claim: *claim });
    }
    if !receipt.exposed_rights.contains(required) {
        return Err(Rejection::InsufficientAuthority { required, granted: receipt.exposed_rights });
    }
    let _ = state;
    Ok(())
}
