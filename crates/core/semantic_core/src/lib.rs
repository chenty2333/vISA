//! Pure canonical reducer for vISA state continuity.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, AuthorityStatus, CONTRACT_VERSION,
    CanonicalState, CleanupStatus, Command, CommandKind, Decision, Digest, EffectKind,
    EffectOutcome, EffectRequest, EffectResult, EntityRef, Event, EventKind, ExtensionSupport,
    HandoffPhase, Identity, JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity,
    OperationRecord, Ownership, PreparationCleanup, PreparedDestination, Rejection, Replay, Rights,
    SnapshotEnvelope, TimerDisposition, TimerStatus,
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

/// A journal entry cannot be applied unless both order and state digests agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    UnsupportedVersion,
    JournalGap { expected: JournalPosition, actual: JournalPosition },
    InputStateDigestMismatch { expected: Digest, actual: Digest },
    OutputStateDigestMismatch { expected: Digest, actual: Digest },
    EventRejected(Rejection),
}

/// Pure preflight. It never mutates `state` and never executes an effect.
pub fn preflight(state: &CanonicalState, command: &Command) -> Decision {
    if !state.version.is_supported() {
        return Decision::Reject(Rejection::UnsupportedVersion { found: state.version });
    }
    if !command.version.is_supported() {
        return Decision::Reject(Rejection::UnsupportedVersion { found: command.version });
    }
    if command.identity.is_zero() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }

    match &command.kind {
        CommandKind::Activate { authority, lease_epoch } => {
            preflight_activate(state, command.identity, *authority, *lease_epoch)
        }
        CommandKind::AttenuateAuthority { parent, derived } => {
            preflight_attenuation(state, command.identity, *parent, derived)
        }
        CommandKind::RevokeAuthority { authority } => {
            preflight_revocation(state, command.identity, *authority)
        }
        CommandKind::RequestEffect(request) => {
            preflight_effect_request(state, command.identity, request)
        }
        CommandKind::ResolveEffect { operation, outcome } => {
            preflight_effect_resolution(state, command.identity, *operation, outcome, false)
        }
        CommandKind::ReconcileEffect { operation, outcome } => {
            preflight_effect_resolution(state, command.identity, *operation, outcome, true)
        }
        CommandKind::CleanupOperation { operation, evidence } => {
            preflight_cleanup(state, command.identity, *operation, *evidence)
        }
        CommandKind::TimerCompleted { timer, arm_operation, lease_epoch, evidence } => {
            preflight_timer_completed(
                state,
                command.identity,
                *timer,
                *arm_operation,
                *lease_epoch,
                *evidence,
            )
        }
        CommandKind::BeginHandoff { authority } => {
            preflight_begin_handoff(state, command.identity, *authority)
        }
        CommandKind::Freeze { portable_state, timer } => {
            preflight_freeze(state, command.identity, portable_state, *timer)
        }
        CommandKind::ExportSnapshot { snapshot } => {
            preflight_export(state, command.identity, snapshot)
        }
        CommandKind::PrepareDestination(prepared) => {
            preflight_prepare(state, command.identity, prepared)
        }
        CommandKind::AbortHandoff { evidence } => {
            preflight_abort(state, command.identity, *evidence)
        }
        CommandKind::CleanupPreparation { snapshot, evidence } => {
            preflight_cleanup_preparation(state, command.identity, *snapshot, *evidence)
        }
        CommandKind::ResumeSource => preflight_resume_source(state, command.identity),
        CommandKind::ResumeDestination => preflight_resume(state, command.identity),
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
    };

    if replay { Ok(ApplyResult::Replay(state.clone())) } else { Ok(ApplyResult::Applied(next)) }
}

/// Restore a destination candidate from a validated portable snapshot.
pub fn restore(
    envelope: &SnapshotEnvelope,
    computed_body_integrity: Digest,
    expected_component_digest: Digest,
    expected_profile_digest: Digest,
    expected_profile_version: contract_core::SchemaVersion,
    supported_extensions: &[ExtensionSupport],
    destination: NodeIdentity,
) -> Result<CanonicalState, Rejection> {
    if !envelope.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: envelope.version });
    }
    if envelope.integrity != computed_body_integrity {
        return Err(Rejection::SnapshotIntegrityMismatch);
    }
    let snapshot = &envelope.body;
    if !snapshot.version.is_supported() {
        return Err(Rejection::UnsupportedVersion { found: snapshot.version });
    }
    if snapshot.snapshot.handoff.is_zero()
        || snapshot.snapshot.snapshot.is_zero()
        || snapshot.source_node.is_zero()
        || destination.is_zero()
        || snapshot.component.identity.is_zero()
    {
        return Err(Rejection::SnapshotMismatch);
    }
    if snapshot.component_digest != expected_component_digest {
        return Err(Rejection::SnapshotMismatch);
    }
    if snapshot.profile_digest != expected_profile_digest
        || snapshot.profile_version != expected_profile_version
    {
        return Err(Rejection::ProfileMismatch);
    }
    if let Some(extension) = snapshot.extensions.iter().find(|extension| {
        extension.required
            && !supported_extensions.iter().any(|supported| {
                supported.id == extension.id && supported.version == extension.version
            })
    }) {
        return Err(Rejection::UnsupportedExtension {
            id: extension.id,
            version: extension.version,
        });
    }
    if snapshot.operations.iter().any(|record| record.outcome.is_none()) {
        let operation = snapshot
            .operations
            .iter()
            .find(|record| record.outcome.is_none())
            .map(|record| record.request.operation)
            .unwrap_or(Identity::ZERO);
        return Err(Rejection::InFlightEffect { operation });
    }
    if let Some(record) = snapshot
        .operations
        .iter()
        .find(|record| record.outcome.as_ref().is_some_and(EffectOutcome::is_indeterminate))
    {
        return Err(Rejection::IndeterminateEffect { operation: record.request.operation });
    }

    Ok(CanonicalState {
        version: CONTRACT_VERSION,
        profile_version: snapshot.profile_version,
        component: snapshot.component,
        component_digest: snapshot.component_digest,
        profile_digest: snapshot.profile_digest,
        phase: HandoffPhase::Exported,
        activation: contract_core::Activation {
            node: destination,
            role: ActivationRole::Destination,
            status: ActivationStatus::Inactive,
        },
        ownership: Ownership::owned(snapshot.source_node, snapshot.source_lease_epoch),
        portable_state: snapshot.portable_state.clone(),
        timer: contract_core::TimerState {
            claim: snapshot.claims.timer.clone(),
            status: TimerStatus::Frozen(snapshot.timer),
            active_operation: match snapshot.timer {
                TimerDisposition::Pending { arm_operation, .. } => Some(arm_operation),
                _ => None,
            },
        },
        key_value: contract_core::KeyValueState {
            claim: snapshot.claims.key_value.clone(),
            last_version: snapshot.key_value_last_version,
            last_operation: snapshot.key_value_last_operation,
        },
        extensions: snapshot.extensions.clone(),
        authorities: snapshot.authorities.clone(),
        operations: snapshot.operations.clone(),
        exported_snapshot: Some(snapshot.snapshot.clone()),
        prepared_destination: None,
        preparation_cleanup: None,
        evidence: alloc::vec![snapshot.snapshot.evidence],
    })
}

/// Replay a digest-bound journal from an initial state.
///
/// The caller supplies the canonical state digest function so the reducer does
/// not couple the contract to one encoding or hashing implementation.
pub fn replay<F>(
    initial: &CanonicalState,
    entries: &[JournalEntry],
    digest: F,
) -> Result<CanonicalState, ReplayError>
where
    F: Fn(&CanonicalState) -> Digest,
{
    replay_from(initial, JournalPosition::ORIGIN, entries, digest)
}

/// Replay entries that continue from an already committed snapshot cursor.
pub fn replay_from<F>(
    initial: &CanonicalState,
    base_position: JournalPosition,
    entries: &[JournalEntry],
    digest: F,
) -> Result<CanonicalState, ReplayError>
where
    F: Fn(&CanonicalState) -> Digest,
{
    let mut state = initial.clone();
    let mut position = base_position;

    for entry in entries {
        if !entry.version.is_supported() {
            return Err(ReplayError::UnsupportedVersion);
        }
        let expected_position = position
            .next()
            .ok_or(ReplayError::JournalGap { expected: position, actual: entry.position })?;
        if entry.position != expected_position {
            return Err(ReplayError::JournalGap {
                expected: expected_position,
                actual: entry.position,
            });
        }

        let actual_input = digest(&state);
        if entry.input_state != actual_input {
            return Err(ReplayError::InputStateDigestMismatch {
                expected: entry.input_state,
                actual: actual_input,
            });
        }

        state = apply(&state, &entry.event).map_err(ReplayError::EventRejected)?.into_state();

        let actual_output = digest(&state);
        if entry.output_state != actual_output {
            return Err(ReplayError::OutputStateDigestMismatch {
                expected: entry.output_state,
                actual: actual_output,
            });
        }
        position = entry.position;
    }

    Ok(state)
}

fn preflight_activate(
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

fn preflight_attenuation(
    state: &CanonicalState,
    event_id: Identity,
    parent: EntityRef,
    derived: &AuthorityGrant,
) -> Decision {
    if derived.authority.identity.is_zero() || derived.rights.is_empty() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }
    if let Some(existing) = grant_by_identity(state, derived.authority.identity) {
        return if existing == derived {
            Decision::Replay(Replay::NoChange)
        } else {
            Decision::Reject(Rejection::InvalidIdentity)
        };
    }
    if derived.parent != Some(parent) || derived.status != AuthorityStatus::Active {
        return Decision::Reject(Rejection::AuthoritySubjectMismatch);
    }
    let parent_grant = match exact_grant(state, parent) {
        Ok(grant) => grant,
        Err(rejection) => return Decision::Reject(rejection),
    };
    let available = match effective_rights(state, parent) {
        Ok(rights) => rights,
        Err(rejection) => return Decision::Reject(rejection),
    };
    if derived.subject.identity != parent_grant.subject.identity {
        return Decision::Reject(Rejection::AuthoritySubjectMismatch);
    }
    if derived.resource.identity != parent_grant.resource.identity {
        return Decision::Reject(Rejection::AuthorityResourceMismatch);
    }
    if !derived.rights.is_subset_of(available) {
        return Decision::Reject(Rejection::AuthorityAmplification {
            requested: derived.rights,
            available,
        });
    }
    commit(event_id, EventKind::AuthorityAttenuated { grant: derived.clone() })
}

fn preflight_revocation(
    state: &CanonicalState,
    event_id: Identity,
    authority: EntityRef,
) -> Decision {
    let Some(grant) = grant_by_identity(state, authority.identity) else {
        return Decision::Reject(Rejection::UnknownAuthority { authority });
    };
    if grant.status == AuthorityStatus::Revoked {
        return Decision::Replay(Replay::NoChange);
    }
    if grant.authority.generation != authority.generation {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: authority.identity,
            expected: grant.authority.generation,
            actual: authority.generation,
        });
    }
    let Some(revoked_generation) = authority.generation.next() else {
        return Decision::Reject(Rejection::GenerationExhausted);
    };
    commit(event_id, EventKind::AuthorityRevoked { authority, revoked_generation })
}

fn preflight_effect_request(
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

fn preflight_effect_resolution(
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

fn preflight_cleanup(
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

fn preflight_timer_completed(
    state: &CanonicalState,
    event_id: Identity,
    timer: EntityRef,
    arm_operation: Identity,
    lease_epoch: LeaseEpoch,
    evidence: contract_core::EvidenceRef,
) -> Decision {
    if !matches!(state.phase, HandoffPhase::Running | HandoffPhase::Quiescing) {
        return reject_phase(state);
    }
    if timer.identity == state.timer.claim.resource.identity
        && timer.generation != state.timer.claim.resource.generation
    {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: timer.identity,
            expected: state.timer.claim.resource.generation,
            actual: timer.generation,
        });
    }
    if timer != state.timer.claim.resource {
        return Decision::Reject(Rejection::TimerStateConflict);
    }
    if !local_active(state) {
        return reject_phase(state);
    }
    let epoch = state.ownership.epoch;
    if epoch != lease_epoch {
        return Decision::Reject(Rejection::LeaseEpochMismatch {
            expected: epoch,
            actual: lease_epoch,
        });
    }
    match state.timer.status {
        TimerStatus::Armed { .. } if state.timer.active_operation == Some(arm_operation) => {
            commit(event_id, EventKind::TimerCompleted { timer, arm_operation, evidence })
        }
        TimerStatus::Completed | TimerStatus::Cleaned => Decision::Replay(Replay::NoChange),
        _ => Decision::Reject(Rejection::TimerStateConflict),
    }
}

fn preflight_begin_handoff(
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

fn preflight_freeze(
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
    if !valid_timer_freeze(state, timer) {
        return Decision::Reject(Rejection::TimerStateConflict);
    }
    commit(event_id, EventKind::Frozen { portable_state: portable_state.to_vec(), timer })
}

fn preflight_export(
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

fn preflight_prepare(
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

fn preflight_abort(
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

fn preflight_cleanup_preparation(
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

fn preflight_resume(state: &CanonicalState, event_id: Identity) -> Decision {
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

fn preflight_resume_source(state: &CanonicalState, event_id: Identity) -> Decision {
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

fn quiescing_timer_completion_parent(
    state: &CanonicalState,
    causal_parent: Option<Identity>,
) -> bool {
    if state.timer.status != TimerStatus::Completed {
        return false;
    }
    let Some(causal_parent) = causal_parent else {
        return false;
    };

    state.operations.iter().rev().find_map(|record| match (&record.request.kind, &record.outcome) {
        (
            EffectKind::TimerArm { .. },
            Some(EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. }),
        ) if record.request.resource == state.timer.claim.resource => {
            Some(record.request.operation)
        }
        _ => None,
    }) == Some(causal_parent)
}

fn validate_destination_authorities(
    state: &CanonicalState,
    prepared: &PreparedDestination,
) -> Result<(), Rejection> {
    let destination_subject =
        EntityRef::new(state.component.identity, prepared.component_generation);
    for (index, grant) in prepared.authorities.iter().enumerate() {
        if grant.authority.identity.is_zero()
            || grant.rights.is_empty()
            || grant.status != AuthorityStatus::Active
            || grant.subject != destination_subject
            || state
                .authorities
                .iter()
                .any(|existing| existing.authority.identity == grant.authority.identity)
            || prepared.authorities[..index]
                .iter()
                .any(|existing| existing.authority.identity == grant.authority.identity)
        {
            return Err(Rejection::InvalidIdentity);
        }
        let parent =
            grant.parent.ok_or(Rejection::UnknownAuthority { authority: grant.authority })?;
        let parent_grant = exact_grant(state, parent)?;
        if parent_grant.subject.identity != grant.subject.identity {
            return Err(Rejection::AuthoritySubjectMismatch);
        }
        if parent_grant.resource.identity != grant.resource.identity {
            return Err(Rejection::AuthorityResourceMismatch);
        }
        let available = effective_rights(state, parent)?;
        if !grant.rights.is_subset_of(available) {
            return Err(Rejection::AuthorityAmplification { requested: grant.rights, available });
        }
    }
    Ok(())
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
    for receipt in &prepared.bindings {
        if receipt.claim != state.timer.claim.resource
            && receipt.claim != state.key_value.claim.resource
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

fn authorize(
    state: &CanonicalState,
    authority: EntityRef,
    subject: EntityRef,
    resource: EntityRef,
    required: Rights,
) -> Result<(), Rejection> {
    let grant = any_exact_grant(state, authority)?;
    if grant.subject.identity == subject.identity && grant.subject.generation != subject.generation
    {
        return Err(Rejection::StaleGeneration {
            identity: subject.identity,
            expected: grant.subject.generation,
            actual: subject.generation,
        });
    }
    if grant.subject != subject {
        return Err(Rejection::AuthoritySubjectMismatch);
    }
    if grant.resource.identity == resource.identity
        && grant.resource.generation != resource.generation
    {
        return Err(Rejection::StaleGeneration {
            identity: resource.identity,
            expected: grant.resource.generation,
            actual: resource.generation,
        });
    }
    if grant.resource != resource {
        return Err(Rejection::AuthorityResourceMismatch);
    }
    let available = effective_rights_with_prepared(state, authority)?;
    if !available.contains(required) {
        return Err(Rejection::InsufficientAuthority { required, granted: available });
    }
    Ok(())
}

fn exact_grant(state: &CanonicalState, authority: EntityRef) -> Result<&AuthorityGrant, Rejection> {
    let Some(grant) = grant_by_identity(state, authority.identity) else {
        return Err(Rejection::UnknownAuthority { authority });
    };
    validate_grant_reference(grant, authority)
}

fn any_exact_grant(
    state: &CanonicalState,
    authority: EntityRef,
) -> Result<&AuthorityGrant, Rejection> {
    let grant = state
        .authorities
        .iter()
        .chain(state.prepared_destination.iter().flat_map(|prepared| prepared.authorities.iter()))
        .find(|grant| grant.authority.identity == authority.identity)
        .ok_or(Rejection::UnknownAuthority { authority })?;
    validate_grant_reference(grant, authority)
}

fn validate_grant_reference(
    grant: &AuthorityGrant,
    authority: EntityRef,
) -> Result<&AuthorityGrant, Rejection> {
    if grant.status == AuthorityStatus::Revoked {
        return Err(Rejection::AuthorityRevoked { authority });
    }
    if grant.authority.generation != authority.generation {
        return Err(Rejection::StaleGeneration {
            identity: authority.identity,
            expected: grant.authority.generation,
            actual: authority.generation,
        });
    }
    Ok(grant)
}

fn effective_rights(state: &CanonicalState, authority: EntityRef) -> Result<Rights, Rejection> {
    effective_rights_inner(state, authority, false)
}

fn effective_rights_with_prepared(
    state: &CanonicalState,
    authority: EntityRef,
) -> Result<Rights, Rejection> {
    effective_rights_inner(state, authority, true)
}

fn effective_rights_inner(
    state: &CanonicalState,
    authority: EntityRef,
    include_prepared: bool,
) -> Result<Rights, Rejection> {
    let mut current = authority;
    let mut effective = Rights::from_bits(u16::MAX).unwrap_or(
        Rights::TIMER_ARM
            .union(Rights::TIMER_CANCEL)
            .union(Rights::KV_READ)
            .union(Rights::KV_WRITE)
            .union(Rights::REBIND)
            .union(Rights::HANDOFF),
    );
    let max_depth = state.authorities.len()
        + if include_prepared {
            state.prepared_destination.as_ref().map_or(0, |prepared| prepared.authorities.len())
        } else {
            0
        }
        + 1;

    for _ in 0..max_depth {
        let grant = if include_prepared {
            any_exact_grant(state, current)?
        } else {
            exact_grant(state, current)?
        };
        effective = effective.intersection(grant.rights);
        let Some(parent) = grant.parent else {
            return Ok(effective);
        };
        current = parent;
    }
    Err(Rejection::UnknownAuthority { authority })
}

fn grant_by_identity(state: &CanonicalState, identity: Identity) -> Option<&AuthorityGrant> {
    state.authorities.iter().find(|grant| grant.authority.identity == identity)
}

fn operation_record(state: &CanonicalState, operation: Identity) -> Option<&OperationRecord> {
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
            (
                EffectKind::LeaseCommit { destination, next_epoch, .. },
                EffectResult::LeaseAdvanced { owner, epoch, .. },
            ) => destination == owner && next_epoch == epoch,
            _ => false,
        },
        _ => true,
    }
}

fn apply_effect_outcome(
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
    let request = &state.operations[operation_index].request;
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
        (EffectKind::LeaseCommit { .. }, EffectResult::LeaseAdvanced { .. }) => {
            return Err(Rejection::EventNotApplicable);
        }
        _ => return Err(Rejection::OutcomeMismatch),
    }
    Ok(())
}

fn outcome_evidence(outcome: &EffectOutcome) -> Option<contract_core::EvidenceRef> {
    match outcome {
        EffectOutcome::Succeeded { evidence, .. } => Some(*evidence),
        EffectOutcome::Failed(failure) => failure.evidence,
        EffectOutcome::Cancelled { evidence }
        | EffectOutcome::Unsupported { evidence }
        | EffectOutcome::Indeterminate { evidence } => *evidence,
    }
}

fn valid_timer_freeze(state: &CanonicalState, disposition: TimerDisposition) -> bool {
    match (state.timer.status, disposition) {
        (TimerStatus::Idle, TimerDisposition::Idle)
        | (TimerStatus::Completed, TimerDisposition::Completed)
        | (TimerStatus::Cancelled, TimerDisposition::Cancelled)
        | (TimerStatus::Cleaned, TimerDisposition::Cleaned) => true,
        (
            TimerStatus::Armed { remaining: armed },
            TimerDisposition::Pending { remaining, arm_operation },
        ) => {
            remaining.0 > 0
                && remaining.0 <= armed.0
                && state.timer.active_operation == Some(arm_operation)
        }
        _ => false,
    }
}

fn thaw_timer(state: &mut CanonicalState) {
    state.timer.status = match state.timer.status {
        TimerStatus::Frozen(TimerDisposition::Idle) => TimerStatus::Idle,
        TimerStatus::Frozen(TimerDisposition::Pending { remaining, arm_operation }) => {
            state.timer.active_operation = Some(arm_operation);
            TimerStatus::Armed { remaining }
        }
        TimerStatus::Frozen(TimerDisposition::Completed) => {
            state.timer.active_operation = None;
            TimerStatus::Completed
        }
        TimerStatus::Frozen(TimerDisposition::Cancelled) => {
            state.timer.active_operation = None;
            TimerStatus::Cancelled
        }
        TimerStatus::Frozen(TimerDisposition::Cleaned) => {
            state.timer.active_operation = None;
            TimerStatus::Cleaned
        }
        status => status,
    };
}

fn commit(identity: Identity, kind: EventKind) -> Decision {
    Decision::Commit(Event::new(identity, kind))
}

fn reject_phase(state: &CanonicalState) -> Decision {
    Decision::Reject(Rejection::InvalidPhase { actual: state.phase })
}

fn local_active(state: &CanonicalState) -> bool {
    state.activation.status == ActivationStatus::Active
        && state.ownership.owner == Some(state.activation.node)
}

fn push_evidence(evidence: &mut Vec<contract_core::EvidenceRef>, item: contract_core::EvidenceRef) {
    if !evidence.contains(&item) {
        evidence.push(item);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;

    use contract_core::{
        AuthorityGrant, AuthorityStatus, BindingReceipt, Command, CommandKind, DeliveryPolicy,
        Digest, EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, EvidenceKind,
        EvidenceRef, ExtensionSupport, Generation, IdempotencyKey, JournalEntry, JournalPosition,
        KeyValueClaim, LeaseEpoch, LogicalDurationNanos, NodeIdentity, PreparedDestination,
        ResourceClaims, Rights, SnapshotEnvelope, SnapshotRecord, TimerClaim, TimerClock,
        VersionedValue,
    };

    use super::*;

    fn id(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn digest(value: u8) -> Digest {
        Digest::from_bytes([value; 32])
    }

    fn evidence(value: u128, kind: EvidenceKind) -> EvidenceRef {
        EvidenceRef { identity: id(value), kind, digest: digest(value as u8) }
    }

    struct Fixture {
        state: CanonicalState,
        component: EntityRef,
        timer: EntityRef,
        kv: EntityRef,
        component_authority: EntityRef,
        timer_authority: EntityRef,
        kv_authority: EntityRef,
        source_node: NodeIdentity,
        destination_node: NodeIdentity,
    }

    fn fixture() -> Fixture {
        let component = EntityRef::initial(id(1));
        let timer = EntityRef::initial(id(2));
        let kv = EntityRef::initial(id(3));
        let component_authority = EntityRef::initial(id(10));
        let timer_authority = EntityRef::initial(id(11));
        let kv_authority = EntityRef::initial(id(12));
        let source_node = NodeIdentity::new(id(100));
        let destination_node = NodeIdentity::new(id(101));
        let timer_rights = Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND);
        let kv_rights = Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND);
        let claims = ResourceClaims {
            timer: TimerClaim {
                resource: timer,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: timer_rights,
            },
            key_value: KeyValueClaim {
                resource: kv,
                namespace: id(30),
                required_rights: kv_rights,
                delivery: DeliveryPolicy::Deduplicated,
            },
        };
        let authorities = vec![
            AuthorityGrant::active_root(component_authority, component, component, Rights::HANDOFF),
            AuthorityGrant::active_root(timer_authority, component, timer, timer_rights),
            AuthorityGrant::active_root(kv_authority, component, kv, kv_rights),
        ];
        Fixture {
            state: CanonicalState::dormant(
                component,
                source_node,
                digest(1),
                digest(2),
                CONTRACT_VERSION,
                claims,
                authorities,
            ),
            component,
            timer,
            kv,
            component_authority,
            timer_authority,
            kv_authority,
            source_node,
            destination_node,
        }
    }

    fn command(value: u128, kind: CommandKind) -> Command {
        Command::new(id(value), kind)
    }

    fn commit(state: &CanonicalState, command: Command) -> CanonicalState {
        let event = match preflight(state, &command) {
            Decision::Commit(event) => event,
            other => panic!("expected commit, got {other:?}"),
        };
        apply(state, &event).expect("event applies").into_state()
    }

    fn activate(fixture: &Fixture) -> CanonicalState {
        commit(
            &fixture.state,
            command(
                100,
                CommandKind::Activate {
                    authority: fixture.component_authority,
                    lease_epoch: LeaseEpoch(1),
                },
            ),
        )
    }

    fn kv_request(fixture: &Fixture, operation: u128, key: u128) -> EffectRequest {
        EffectRequest {
            operation: id(operation),
            idempotency_key: IdempotencyKey::from_u128(key),
            causal_parent: None,
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.kv,
            authority: fixture.kv_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(operation as u8),
            kind: EffectKind::KeyValueCompareAndSet {
                key: vec![1],
                expected_version: None,
                value: vec![2],
            },
        }
    }

    fn prepare_effect(state: &CanonicalState, request: EffectRequest) -> CanonicalState {
        let decision = preflight(
            state,
            &command(200 + request.operation.0[15] as u128, CommandKind::RequestEffect(request)),
        );
        let Decision::Execute { intent, .. } = decision else {
            panic!("expected effect execution, got {decision:?}");
        };
        apply(state, &intent).expect("intent applies").into_state()
    }

    #[test]
    fn every_rejection_leaves_state_equal() {
        let fixture = fixture();
        let state = activate(&fixture);
        let cases = [
            command(
                301,
                CommandKind::RequestEffect(EffectRequest {
                    subject: EntityRef::new(fixture.component.identity, Generation(99)),
                    ..kv_request(&fixture, 1_000, 1)
                }),
            ),
            command(
                302,
                CommandKind::RequestEffect(EffectRequest {
                    authority: fixture.timer_authority,
                    ..kv_request(&fixture, 1_001, 2)
                }),
            ),
            command(
                303,
                CommandKind::Freeze { portable_state: vec![1], timer: TimerDisposition::Idle },
            ),
        ];

        for rejected in cases {
            let before = state.clone();
            assert!(matches!(preflight(&state, &rejected), Decision::Reject(_)));
            assert_eq!(state, before);
        }
    }

    #[test]
    fn stale_revoked_and_attenuated_authority_are_enforced() {
        let fixture = fixture();
        let state = activate(&fixture);
        let child = AuthorityGrant {
            authority: EntityRef::initial(id(20)),
            parent: Some(fixture.kv_authority),
            subject: fixture.component,
            resource: fixture.kv,
            rights: Rights::KV_WRITE,
            status: AuthorityStatus::Active,
        };
        let state = commit(
            &state,
            command(
                310,
                CommandKind::AttenuateAuthority {
                    parent: fixture.kv_authority,
                    derived: child.clone(),
                },
            ),
        );
        let accepted =
            EffectRequest { authority: child.authority, ..kv_request(&fixture, 1_010, 10) };
        assert!(matches!(
            preflight(&state, &command(311, CommandKind::RequestEffect(accepted))),
            Decision::Execute { .. }
        ));

        let state = commit(
            &state,
            command(312, CommandKind::RevokeAuthority { authority: fixture.kv_authority }),
        );
        let rejected =
            EffectRequest { authority: child.authority, ..kv_request(&fixture, 1_011, 11) };
        assert!(matches!(
            preflight(&state, &command(313, CommandKind::RequestEffect(rejected))),
            Decision::Reject(Rejection::AuthorityRevoked { .. })
                | Decision::Reject(Rejection::StaleGeneration { .. })
        ));
    }

    #[test]
    fn key_value_reads_use_the_same_authority_lease_and_journal_path() {
        let fixture = fixture();
        let state = activate(&fixture);
        let request = EffectRequest {
            operation: id(1_015),
            idempotency_key: IdempotencyKey::from_u128(15),
            causal_parent: None,
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.kv,
            authority: fixture.kv_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(15),
            kind: EffectKind::KeyValueRead { key: vec![1] },
        };
        let state = prepare_effect(&state, request);
        let state = commit(
            &state,
            command(
                316,
                CommandKind::ResolveEffect {
                    operation: id(1_015),
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::KeyValueRead {
                            value: Some(VersionedValue { value: vec![2], version: 7 }),
                        },
                        evidence: evidence(316, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        assert_eq!(state.key_value.last_version, Some(7));
        assert_eq!(state.key_value.last_operation, Some(id(1_015)));
    }

    #[test]
    fn duplicate_operation_and_idempotency_never_execute_twice() {
        let fixture = fixture();
        let state = activate(&fixture);
        let request = kv_request(&fixture, 1_020, 20);
        let state = prepare_effect(&state, request.clone());

        assert!(matches!(
            preflight(&state, &command(320, CommandKind::RequestEffect(request.clone()))),
            Decision::Replay(Replay::Operation(_))
        ));
        let duplicate_key = EffectRequest { operation: id(1_021), ..request.clone() };
        assert!(matches!(
            preflight(&state, &command(321, CommandKind::RequestEffect(duplicate_key))),
            Decision::Replay(Replay::Operation(_))
        ));
        let conflict =
            EffectRequest { operation: id(1_022), request_digest: digest(99), ..request };
        assert!(matches!(
            preflight(&state, &command(322, CommandKind::RequestEffect(conflict))),
            Decision::Reject(Rejection::IdempotencyConflict { .. })
        ));
    }

    #[test]
    fn indeterminate_effect_blocks_freeze_until_reconciled() {
        let fixture = fixture();
        let state = activate(&fixture);
        let state = prepare_effect(&state, kv_request(&fixture, 1_030, 30));
        let state = commit(
            &state,
            command(
                330,
                CommandKind::ResolveEffect {
                    operation: id(1_030),
                    outcome: EffectOutcome::Indeterminate {
                        evidence: Some(evidence(330, EvidenceKind::EffectOutcome)),
                    },
                },
            ),
        );
        let state = commit(
            &state,
            command(331, CommandKind::BeginHandoff { authority: fixture.component_authority }),
        );
        assert!(matches!(
            preflight(
                &state,
                &command(
                    332,
                    CommandKind::Freeze { portable_state: vec![1], timer: TimerDisposition::Idle },
                )
            ),
            Decision::Reject(Rejection::IndeterminateEffect { .. })
        ));

        let state = commit(
            &state,
            command(
                333,
                CommandKind::ReconcileEffect {
                    operation: id(1_030),
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::KeyValue { version: 1, applied: true },
                        evidence: evidence(333, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        assert!(matches!(
            preflight(
                &state,
                &command(
                    334,
                    CommandKind::Freeze { portable_state: vec![1], timer: TimerDisposition::Idle },
                )
            ),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn provider_truth_reconciles_a_prepared_effect_without_an_intermediate_resolution() {
        let fixture = fixture();
        let state = activate(&fixture);
        let operation = id(1_031);
        let state = prepare_effect(&state, kv_request(&fixture, 1_031, 31));
        let outcome = EffectOutcome::Succeeded {
            result: EffectResult::KeyValue { version: 1, applied: true },
            evidence: evidence(335, EvidenceKind::EffectOutcome),
        };
        let reconcile_command =
            command(335, CommandKind::ReconcileEffect { operation, outcome: outcome.clone() });

        assert!(matches!(
            preflight(&state, &reconcile_command),
            Decision::Commit(Event {
                kind: EventKind::EffectReconciled {
                    operation: reconciled_operation,
                    outcome: reconciled_outcome,
                },
                ..
            }) if reconciled_operation == operation && reconciled_outcome == outcome
        ));
        let state = commit(&state, reconcile_command);
        assert_eq!(
            operation_record(&state, operation).and_then(|record| record.outcome.as_ref()),
            Some(&outcome)
        );
        assert!(matches!(
            preflight(
                &state,
                &command(336, CommandKind::ReconcileEffect { operation, outcome: outcome.clone() },),
            ),
            Decision::Replay(Replay::Operation(_))
        ));
    }

    #[test]
    fn quiescing_admits_only_the_completed_timer_causal_kv_effect() {
        let fixture = fixture();
        let arm_operation = id(1_035);
        let mut state = activate(&fixture);
        let arm = EffectRequest {
            operation: arm_operation,
            idempotency_key: IdempotencyKey::from_u128(35),
            causal_parent: None,
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.timer,
            authority: fixture.timer_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(35),
            kind: EffectKind::TimerArm { remaining: LogicalDurationNanos(1_000) },
        };
        state = prepare_effect(&state, arm);
        state = commit(
            &state,
            command(
                335,
                CommandKind::ResolveEffect {
                    operation: arm_operation,
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::TimerArmed { remaining: LogicalDurationNanos(1_000) },
                        evidence: evidence(335, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        state = commit(
            &state,
            command(336, CommandKind::BeginHandoff { authority: fixture.component_authority }),
        );
        state = commit(
            &state,
            command(
                337,
                CommandKind::TimerCompleted {
                    timer: fixture.timer,
                    arm_operation,
                    lease_epoch: LeaseEpoch(1),
                    evidence: evidence(337, EvidenceKind::EffectOutcome),
                },
            ),
        );

        let completion =
            EffectRequest { causal_parent: Some(arm_operation), ..kv_request(&fixture, 1_036, 36) };
        assert!(matches!(
            preflight(&state, &command(338, CommandKind::RequestEffect(completion.clone()))),
            Decision::Execute { .. }
        ));

        for (command_id, request) in [
            (339, EffectRequest { causal_parent: None, ..completion.clone() }),
            (340, EffectRequest { causal_parent: Some(id(99_999)), ..completion.clone() }),
        ] {
            assert!(matches!(
                preflight(&state, &command(command_id, CommandKind::RequestEffect(request))),
                Decision::Reject(Rejection::InvalidPhase { actual: HandoffPhase::Quiescing })
            ));
        }

        let read = EffectRequest {
            operation: id(1_037),
            idempotency_key: IdempotencyKey::from_u128(37),
            causal_parent: Some(arm_operation),
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.kv,
            authority: fixture.kv_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(37),
            kind: EffectKind::KeyValueRead { key: vec![1] },
        };
        assert!(matches!(
            preflight(&state, &command(341, CommandKind::RequestEffect(read))),
            Decision::Reject(Rejection::InvalidPhase { actual: HandoffPhase::Quiescing })
        ));
    }

    #[test]
    fn source_abort_stays_frozen_until_source_resume_commits() {
        let fixture = fixture();
        let arm_operation = id(1_038);
        let mut state = activate(&fixture);
        state = prepare_effect(
            &state,
            EffectRequest {
                operation: arm_operation,
                idempotency_key: IdempotencyKey::from_u128(38),
                causal_parent: None,
                node: fixture.source_node,
                subject: fixture.component,
                resource: fixture.timer,
                authority: fixture.timer_authority,
                lease_epoch: LeaseEpoch(1),
                request_digest: digest(38),
                kind: EffectKind::TimerArm { remaining: LogicalDurationNanos(1_000) },
            },
        );
        state = commit(
            &state,
            command(
                342,
                CommandKind::ResolveEffect {
                    operation: arm_operation,
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::TimerArmed { remaining: LogicalDurationNanos(1_000) },
                        evidence: evidence(342, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        state = commit(
            &state,
            command(343, CommandKind::BeginHandoff { authority: fixture.component_authority }),
        );
        let frozen =
            TimerDisposition::Pending { remaining: LogicalDurationNanos(800), arm_operation };
        state = commit(
            &state,
            command(344, CommandKind::Freeze { portable_state: vec![4], timer: frozen }),
        );
        state = commit(&state, command(345, CommandKind::AbortHandoff { evidence: None }));

        assert_eq!(state.phase, HandoffPhase::Aborted);
        assert_eq!(state.timer.status, TimerStatus::Frozen(frozen));
        assert!(matches!(
            preflight(
                &state,
                &command(346, CommandKind::RequestEffect(kv_request(&fixture, 1_039, 39)))
            ),
            Decision::Reject(Rejection::InvalidPhase { actual: HandoffPhase::Aborted })
        ));

        let resume = command(347, CommandKind::ResumeSource);
        state = commit(&state, resume.clone());
        assert_eq!(state.phase, HandoffPhase::Running);
        assert_eq!(state.timer.status, TimerStatus::Armed { remaining: LogicalDurationNanos(800) });
        assert_eq!(state.timer.active_operation, Some(arm_operation));
        assert!(matches!(preflight(&state, &resume), Decision::Replay(Replay::NoChange)));
        assert!(matches!(
            preflight(
                &state,
                &command(348, CommandKind::RequestEffect(kv_request(&fixture, 1_040, 40)))
            ),
            Decision::Execute { .. }
        ));
    }

    #[test]
    fn aborted_export_retains_cleanup_identity_until_cleanup_commits() {
        let fixture = fixture();
        let mut state = activate(&fixture);
        state = commit(
            &state,
            command(349, CommandKind::BeginHandoff { authority: fixture.component_authority }),
        );
        state = commit(
            &state,
            command(
                350,
                CommandKind::Freeze { portable_state: vec![5], timer: TimerDisposition::Idle },
            ),
        );
        let snapshot = SnapshotRecord {
            handoff: id(55),
            snapshot: id(56),
            journal_position: JournalPosition(3),
            evidence: evidence(350, EvidenceKind::SnapshotIntegrity),
        };
        state = commit(
            &state,
            command(351, CommandKind::ExportSnapshot { snapshot: snapshot.clone() }),
        );
        state = commit(&state, command(352, CommandKind::AbortHandoff { evidence: None }));

        assert_eq!(state.phase, HandoffPhase::Aborted);
        assert_eq!(state.exported_snapshot, Some(snapshot.clone()));
        assert!(matches!(
            preflight(&state, &command(353, CommandKind::ResumeSource)),
            Decision::Reject(Rejection::InvalidPhase { actual: HandoffPhase::Aborted })
        ));

        let cleanup = command(
            354,
            CommandKind::CleanupPreparation {
                snapshot: snapshot.snapshot,
                evidence: Some(evidence(354, EvidenceKind::Cleanup)),
            },
        );
        state = commit(&state, cleanup.clone());
        assert_eq!(state.exported_snapshot, None);
        assert_eq!(state.prepared_destination, None);
        assert_eq!(
            state.preparation_cleanup,
            Some(PreparationCleanup {
                snapshot: snapshot.snapshot,
                evidence: Some(evidence(354, EvidenceKind::Cleanup)),
            })
        );
        assert!(matches!(preflight(&state, &cleanup), Decision::Replay(Replay::NoChange)));

        state = commit(&state, command(355, CommandKind::ResumeSource));
        assert_eq!(state.phase, HandoffPhase::Running);
        assert_eq!(state.preparation_cleanup, None);
    }

    #[test]
    fn cancel_and_cleanup_are_idempotent() {
        let fixture = fixture();
        let mut state = activate(&fixture);
        let arm = EffectRequest {
            operation: id(1_040),
            idempotency_key: IdempotencyKey::from_u128(40),
            causal_parent: None,
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.timer,
            authority: fixture.timer_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(40),
            kind: EffectKind::TimerArm { remaining: LogicalDurationNanos(1_000) },
        };
        state = prepare_effect(&state, arm);
        state = commit(
            &state,
            command(
                340,
                CommandKind::ResolveEffect {
                    operation: id(1_040),
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::TimerArmed { remaining: LogicalDurationNanos(1_000) },
                        evidence: evidence(340, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        let cancel = EffectRequest {
            operation: id(1_041),
            idempotency_key: IdempotencyKey::from_u128(41),
            causal_parent: Some(id(1_040)),
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.timer,
            authority: fixture.timer_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(41),
            kind: EffectKind::TimerCancel { target_operation: id(1_040) },
        };
        state = prepare_effect(&state, cancel);
        state = commit(
            &state,
            command(
                341,
                CommandKind::ResolveEffect {
                    operation: id(1_041),
                    outcome: EffectOutcome::Succeeded {
                        result: EffectResult::TimerCancelled,
                        evidence: evidence(341, EvidenceKind::EffectOutcome),
                    },
                },
            ),
        );
        let cleanup = command(
            342,
            CommandKind::CleanupOperation {
                operation: id(1_041),
                evidence: evidence(342, EvidenceKind::Cleanup),
            },
        );
        state = commit(&state, cleanup.clone());
        assert_eq!(state.timer.status, TimerStatus::Cleaned);
        assert!(matches!(preflight(&state, &cleanup), Decision::Replay(Replay::Operation(_))));
    }

    #[test]
    fn prepare_commit_resume_and_source_fencing_follow_epoch_order() {
        let fixture = fixture();
        let source = activate(&fixture);
        let source = commit(
            &source,
            command(350, CommandKind::BeginHandoff { authority: fixture.component_authority }),
        );
        let source = commit(
            &source,
            command(
                351,
                CommandKind::Freeze { portable_state: vec![7, 8], timer: TimerDisposition::Idle },
            ),
        );
        let snapshot = SnapshotRecord {
            handoff: id(49),
            snapshot: id(50),
            journal_position: JournalPosition(3),
            evidence: evidence(350, EvidenceKind::SnapshotIntegrity),
        };
        let source = commit(
            &source,
            command(352, CommandKind::ExportSnapshot { snapshot: snapshot.clone() }),
        );
        let body = source.snapshot_body().expect("exported snapshot");
        let envelope = SnapshotEnvelope { version: CONTRACT_VERSION, body, integrity: digest(99) };
        let mut destination = restore(
            &envelope,
            digest(99),
            digest(1),
            digest(2),
            CONTRACT_VERSION,
            &[] as &[ExtensionSupport],
            fixture.destination_node,
        )
        .expect("restore");
        let generation = Generation(1);
        let subject = EntityRef::new(fixture.component.identity, generation);
        let timer_grant = AuthorityGrant {
            authority: EntityRef::initial(id(60)),
            parent: Some(fixture.timer_authority),
            subject,
            resource: fixture.timer,
            rights: fixture.state.timer.claim.required_rights,
            status: AuthorityStatus::Active,
        };
        let kv_grant = AuthorityGrant {
            authority: EntityRef::initial(id(61)),
            parent: Some(fixture.kv_authority),
            subject,
            resource: fixture.kv,
            rights: fixture.state.key_value.claim.required_rights,
            status: AuthorityStatus::Active,
        };
        let handoff_grant = AuthorityGrant {
            authority: EntityRef::initial(id(62)),
            parent: Some(fixture.component_authority),
            subject,
            resource: subject,
            rights: Rights::HANDOFF,
            status: AuthorityStatus::Active,
        };
        let prepared = PreparedDestination {
            handoff: snapshot.handoff,
            snapshot: snapshot.snapshot,
            destination: fixture.destination_node,
            component_generation: generation,
            expected_epoch: LeaseEpoch(1),
            next_epoch: LeaseEpoch(2),
            authorities: vec![timer_grant.clone(), kv_grant.clone(), handoff_grant.clone()],
            bindings: vec![
                BindingReceipt {
                    handoff: snapshot.handoff,
                    snapshot: snapshot.snapshot,
                    claim: fixture.timer,
                    binding: EntityRef::initial(id(70)),
                    node: fixture.destination_node,
                    authority: timer_grant.authority,
                    exposed_rights: fixture.state.timer.claim.required_rights,
                    lease_epoch: LeaseEpoch(2),
                    evidence: evidence(351, EvidenceKind::Binding),
                },
                BindingReceipt {
                    handoff: snapshot.handoff,
                    snapshot: snapshot.snapshot,
                    claim: fixture.kv,
                    binding: EntityRef::initial(id(71)),
                    node: fixture.destination_node,
                    authority: kv_grant.authority,
                    exposed_rights: fixture.state.key_value.claim.required_rights,
                    lease_epoch: LeaseEpoch(2),
                    evidence: evidence(352, EvidenceKind::Binding),
                },
            ],
        };
        let mut wrong_node = prepared.clone();
        wrong_node.bindings[0].node = fixture.source_node;
        assert!(matches!(
            preflight(&destination, &command(353, CommandKind::PrepareDestination(wrong_node))),
            Decision::Reject(Rejection::InvalidBinding { .. })
        ));
        destination = commit(&destination, command(353, CommandKind::PrepareDestination(prepared)));
        let lease = EffectRequest {
            operation: id(1_050),
            idempotency_key: IdempotencyKey::from_u128(50),
            causal_parent: None,
            node: fixture.destination_node,
            subject,
            resource: subject,
            authority: handoff_grant.authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(50),
            kind: EffectKind::LeaseCommit {
                handoff: snapshot.handoff,
                snapshot: snapshot.snapshot,
                destination: fixture.destination_node,
                expected_epoch: LeaseEpoch(1),
                next_epoch: LeaseEpoch(2),
            },
        };
        destination = prepare_effect(&destination, lease);
        let commit_command = command(
            354,
            CommandKind::ResolveEffect {
                operation: id(1_050),
                outcome: EffectOutcome::Succeeded {
                    result: EffectResult::LeaseAdvanced {
                        owner: fixture.destination_node,
                        epoch: LeaseEpoch(2),
                        source_fence: evidence(355, EvidenceKind::SourceFence),
                    },
                    evidence: evidence(354, EvidenceKind::LeaseCommit),
                },
            },
        );
        let commit_event = match preflight(&destination, &commit_command) {
            Decision::Commit(event) => event,
            other => panic!("expected atomic handoff commit, got {other:?}"),
        };
        destination =
            apply(&destination, &commit_event).expect("destination commit applies").into_state();
        let source = apply(&source, &commit_event).expect("same commit fences source").into_state();
        destination = commit(&destination, command(355, CommandKind::ResumeDestination));
        assert_eq!(destination.component.generation, Generation(1));
        assert_eq!(destination.phase, HandoffPhase::Running);
        assert_eq!(
            destination.ownership,
            Ownership::owned(fixture.destination_node, LeaseEpoch(2))
        );
        assert_eq!(source.phase, HandoffPhase::Committed);
        assert_eq!(source.activation.status, ActivationStatus::Fenced);
        assert_eq!(source.ownership, destination.ownership);
        let stale = EffectRequest {
            operation: id(1_051),
            idempotency_key: IdempotencyKey::from_u128(51),
            causal_parent: None,
            node: fixture.source_node,
            subject: fixture.component,
            resource: fixture.kv,
            authority: fixture.kv_authority,
            lease_epoch: LeaseEpoch(1),
            request_digest: digest(51),
            kind: EffectKind::KeyValueCompareAndSet {
                key: vec![1],
                expected_version: None,
                value: vec![2],
            },
        };
        assert!(matches!(
            preflight(&source, &command(357, CommandKind::RequestEffect(stale))),
            Decision::Reject(Rejection::InvalidPhase { .. })
        ));
    }

    #[test]
    fn journal_replay_checks_the_digest_of_each_input_state() {
        let fixture = fixture();
        let activate = match preflight(
            &fixture.state,
            &command(
                360,
                CommandKind::Activate {
                    authority: fixture.component_authority,
                    lease_epoch: LeaseEpoch(1),
                },
            ),
        ) {
            Decision::Commit(event) => event,
            other => panic!("expected event, got {other:?}"),
        };
        let active = apply(&fixture.state, &activate).expect("activation applies").into_state();
        let state_digest = |state: &CanonicalState| {
            let mut bytes = [0_u8; 32];
            bytes[0] = state.phase as u8;
            bytes[1..9].copy_from_slice(&state.component.generation.0.to_be_bytes());
            bytes[9..17].copy_from_slice(&state.ownership.epoch().0.to_be_bytes());
            Digest(bytes)
        };
        let entry = JournalEntry {
            version: CONTRACT_VERSION,
            position: JournalPosition(1),
            input_state: state_digest(&fixture.state),
            output_state: state_digest(&active),
            event: activate,
        };
        assert_eq!(
            replay(&fixture.state, core::slice::from_ref(&entry), state_digest)
                .expect("journal replays"),
            active
        );
        let continued = JournalEntry { position: JournalPosition(8), ..entry.clone() };
        assert_eq!(
            replay_from(&fixture.state, JournalPosition(7), &[continued], state_digest,)
                .expect("snapshot cursor continues"),
            active
        );

        let wrong = JournalEntry { input_state: digest(0xff), ..entry };
        assert!(matches!(
            replay(&fixture.state, &[wrong], state_digest),
            Err(ReplayError::InputStateDigestMismatch { .. })
        ));
    }
}
