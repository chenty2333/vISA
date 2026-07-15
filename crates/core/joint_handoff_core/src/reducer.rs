use crate::{
    ApplyResult, ClosureStatus, Command, Decision, Event, EventKind, FreezeDisposition, JointPhase,
    JointState, OwnershipDecision, ReceiptRef, Rejection, Replay, TypedReceipt,
    all_digests_nonzero, no_duplicate_receipts, nonzero_digest, receipt_reference,
};

pub fn preflight(state: &JointState, command: &Command) -> Decision {
    if !state.version.is_supported() || !command.version.is_supported() {
        return Decision::Reject(Rejection::UnsupportedVersion);
    }
    if command.identity.is_zero() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }
    let event = Event {
        version: command.version,
        identity: command.identity,
        kind: command.kind.clone().into(),
    };
    match apply(state, &event) {
        Ok(ApplyResult::Applied(_)) => Decision::Commit(alloc::boxed::Box::new(event)),
        Ok(ApplyResult::Replay(_, replay)) => Decision::Replay(replay),
        Err(rejection) => Decision::Reject(rejection),
    }
}

pub fn apply(state: &JointState, event: &Event) -> Result<ApplyResult, Rejection> {
    if !state.version.is_supported() || !event.version.is_supported() {
        return Err(Rejection::UnsupportedVersion);
    }
    if event.identity.is_zero() {
        return Err(Rejection::InvalidIdentity);
    }
    if !state.key.is_well_formed() {
        return Err(Rejection::InvalidHandoffKey);
    }

    let mut next = state.clone();
    let replay = transition(&mut next, event)?;
    if let Some(replay) = replay {
        Ok(ApplyResult::Replay(state.clone(), replay))
    } else {
        next.revision = state.revision.checked_add(1).ok_or(Rejection::RevisionExhausted)?;
        Ok(ApplyResult::Applied(next))
    }
}

fn transition(state: &mut JointState, event: &Event) -> Result<Option<Replay>, Rejection> {
    match &event.kind {
        EventKind::PrepareIntentRecorded(receipt) => record_intent(state, receipt),
        EventKind::VisaFreezeRecorded(receipt) => record_visa_freeze(state, receipt),
        EventKind::NexusFreezeRecorded(receipt) => record_nexus_freeze(state, receipt),
        EventKind::DestinationPreparedRecorded(receipt) => {
            record_destination_prepared(state, receipt)
        }
        EventKind::PreparedFrozenSealed(receipt) => seal_prepared(state, receipt),
        EventKind::AbortDecisionRecorded(receipt) => record_abort(state, receipt),
        EventKind::ThawRecorded(receipt) => record_thaw(state, receipt),
        EventKind::SourceResumeRecorded(receipt) => record_source_resume(state, receipt),
        EventKind::CommitDecisionRecorded(receipt) => record_commit(state, receipt),
        EventKind::ClosureProgressRecorded(receipt) => record_progress(state, receipt),
        EventKind::ClosureRecorded(receipt) => record_closure(state, receipt),
        EventKind::RetainedTombstoneRecorded(receipt) => record_tombstone(state, receipt),
        EventKind::SourceFenceRecorded(receipt) => record_source_fence(state, receipt),
        EventKind::DestinationActivationStarted { commit, closure } => {
            begin_destination_activation(state, event.identity, *commit, *closure)
        }
        EventKind::DestinationActivationRecorded(receipt) => {
            record_destination_activation(state, event.identity, receipt)
        }
    }
}

fn validate_receipt<T: TypedReceipt>(
    state: &JointState,
    receipt: &T,
) -> Result<ReceiptRef, Rejection> {
    if receipt.key() != state.key {
        return Err(Rejection::HandoffMismatch);
    }
    receipt_reference(receipt)
}

fn replay_or_conflict(
    existing: Option<ReceiptRef>,
    candidate: ReceiptRef,
) -> Result<Option<Replay>, Rejection> {
    match existing {
        Some(current) if current == candidate => Ok(Some(Replay::Receipt(current))),
        Some(_) => Err(Rejection::ConflictingReceipt),
        None => Ok(None),
    }
}

fn require_ref(actual: Option<ReceiptRef>, expected: ReceiptRef) -> Result<(), Rejection> {
    match actual {
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(Rejection::ReceiptMismatch),
        None => Err(Rejection::MissingPrerequisite),
    }
}

fn require_child(parent: ReceiptRef, child: &crate::ReceiptHeader) -> Result<(), Rejection> {
    if child.issuer != parent.issuer
        || child.issuer_incarnation != parent.issuer_incarnation
        || child.key_id != parent.key_id
        || child.log_id != parent.log_id
        || child.sequence <= parent.sequence
        || child.previous_digest != Some(parent.digest)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    Ok(())
}

fn require_root(header: &crate::ReceiptHeader) -> Result<(), Rejection> {
    if header.previous_digest.is_some() {
        return Err(Rejection::ReceiptMismatch);
    }
    Ok(())
}

fn wrong_phase(state: &JointState) -> Rejection {
    Rejection::InvalidPhase { actual: state.phase }
}

fn record_intent(
    state: &mut JointState,
    receipt: &crate::PrepareIntentReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    if receipt.ownership_service.is_zero()
        || receipt.service_incarnation.is_zero()
        || receipt.reservation.is_zero()
        || receipt.header.issuer != receipt.ownership_service
        || receipt.header.issuer_incarnation != receipt.service_incarnation
        || receipt.intent_revision == 0
        || !nonzero_digest(receipt.request_digest)
    {
        return Err(Rejection::InvalidRevision);
    }
    require_root(&receipt.header)?;
    if let Some(replay) = replay_or_conflict(state.intent, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::SourceOwned {
        return Err(wrong_phase(state));
    }
    state.intent = Some(reference);
    state.reservation = Some(receipt.reservation);
    state.intent_revision = Some(receipt.intent_revision);
    state.phase = JointPhase::PrepareIntent;
    Ok(None)
}

fn record_visa_freeze(
    state: &mut JointState,
    receipt: &crate::VisaFreezeReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    require_ref(state.intent, receipt.intent)?;
    require_root(&receipt.header)?;
    if !all_digests_nonzero(&[receipt.state_digest, receipt.portable_state_digest]) {
        return Err(Rejection::InvalidDigest);
    }
    if let Some(replay) = replay_or_conflict(state.visa_freeze, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::PrepareIntent || state.nexus_freeze.is_some() {
        return Err(wrong_phase(state));
    }
    state.visa_freeze = Some(reference);
    state.source_journal_position = Some(receipt.journal_position);
    state.source_state_digest = Some(receipt.state_digest);
    state.phase = JointPhase::FrozenUnsealed;
    Ok(None)
}

fn record_nexus_freeze(
    state: &mut JointState,
    receipt: &crate::NexusFreezeReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    require_ref(state.intent, receipt.intent)?;
    if state.visa_freeze.is_none() {
        return Err(Rejection::MissingPrerequisite);
    }
    require_root(&receipt.header)?;
    if receipt.registry_instance.is_zero()
        || receipt.scope_id.is_zero()
        || receipt.scope_generation == 0
        || receipt.freeze_generation == 0
        || !all_digests_nonzero(&[
            receipt.domain_bindings_digest,
            receipt.effect_cohort_digest,
            receipt.classification_root,
        ])
        || receipt.counts.tombstones > receipt.counts.registered
        || receipt.counts.unresolved > receipt.counts.registered
        || matches!(
            receipt.disposition,
            FreezeDisposition::Blocked { blocker_digest } if !nonzero_digest(blocker_digest)
        )
    {
        return Err(Rejection::InvalidDigest);
    }
    if let Some(replay) = replay_or_conflict(state.nexus_freeze, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::FrozenUnsealed {
        return Err(wrong_phase(state));
    }
    state.nexus_freeze = Some(reference);
    state.effect_cohort_digest = Some(receipt.effect_cohort_digest);
    state.freeze_disposition = Some(receipt.disposition);
    state.freeze_counts = Some(receipt.counts);
    state.phase = JointPhase::FrozenUnsealed;
    Ok(None)
}

fn record_destination_prepared(
    state: &mut JointState,
    receipt: &crate::DestinationPreparedReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    require_ref(state.intent, receipt.intent)?;
    require_ref(state.visa_freeze, receipt.visa_freeze)?;
    require_ref(state.nexus_freeze, receipt.nexus_freeze)?;
    require_root(&receipt.header)?;
    if receipt.snapshot.snapshot.is_zero()
        || receipt.lease_commit_operation.is_zero()
        || !all_digests_nonzero(&[
            receipt.snapshot.integrity,
            receipt.snapshot.body_digest,
            receipt.snapshot.component_digest,
            receipt.snapshot.profile_digest,
            receipt.state_digest,
            receipt.prepared_destination_digest,
            receipt.authorities_digest,
            receipt.bindings_digest,
            receipt.joint_mapping_manifest_digest,
            receipt.lease_commit_request_digest,
        ])
    {
        return Err(Rejection::InvalidDigest);
    }
    if let Some(replay) = replay_or_conflict(state.destination_prepared, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::FrozenUnsealed {
        return Err(wrong_phase(state));
    }
    let source_journal_position =
        state.source_journal_position.ok_or(Rejection::MissingPrerequisite)?;
    if receipt.snapshot.source_journal_position != source_journal_position {
        return Err(Rejection::ReceiptMismatch);
    }
    let intent = state.intent.ok_or(Rejection::MissingPrerequisite)?;
    let visa_freeze = state.visa_freeze.ok_or(Rejection::MissingPrerequisite)?;
    let effect_freeze = state.nexus_freeze.ok_or(Rejection::MissingPrerequisite)?;
    state.pending_bindings = Some(crate::PreparedBindings {
        prepare_intent_receipt_digest: intent.digest,
        visa_freeze_receipt_digest: visa_freeze.digest,
        effect_freeze_receipt_digest: effect_freeze.digest,
        snapshot: receipt.snapshot.snapshot,
        snapshot_integrity_digest: receipt.snapshot.integrity,
        source_journal_position,
        source_state_digest: state.source_state_digest.ok_or(Rejection::MissingPrerequisite)?,
        component_digest: receipt.snapshot.component_digest,
        profile_digest: receipt.snapshot.profile_digest,
        destination_prepared_receipt_digest: reference.digest,
        destination_state_digest: receipt.state_digest,
        prepared_authorities_digest: receipt.authorities_digest,
        prepared_bindings_digest: receipt.bindings_digest,
        effect_cohort_manifest_digest: state
            .effect_cohort_digest
            .ok_or(Rejection::MissingPrerequisite)?,
        joint_mapping_manifest_digest: receipt.joint_mapping_manifest_digest,
    });
    state.destination_prepared = Some(reference);
    Ok(None)
}

fn seal_prepared(
    state: &mut JointState,
    receipt: &crate::OwnershipPreparedReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    require_ref(state.intent, receipt.intent)?;
    require_ref(state.visa_freeze, receipt.visa_freeze)?;
    require_ref(state.nexus_freeze, receipt.nexus_freeze)?;
    require_ref(state.destination_prepared, receipt.destination_prepared)?;
    if state.reservation != Some(receipt.reservation) {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(receipt.intent, &receipt.header)?;
    if state.pending_bindings != Some(receipt.bindings) {
        return Err(Rejection::ReceiptMismatch);
    }
    let intent_revision = state.intent_revision.ok_or(Rejection::MissingPrerequisite)?;
    if receipt.prepared_revision <= intent_revision
        || receipt.header.sequence < receipt.prepared_revision
    {
        return Err(Rejection::InvalidRevision);
    }
    if let Some(replay) = replay_or_conflict(state.prepared, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::FrozenUnsealed {
        return Err(wrong_phase(state));
    }
    let counts = state.freeze_counts.ok_or(Rejection::MissingPrerequisite)?;
    if state.freeze_disposition != Some(FreezeDisposition::ReadyToCommit) || counts.unresolved != 0
    {
        return Err(Rejection::ClosureBlocked);
    }
    state.prepared = Some(reference);
    state.prepared_revision = Some(receipt.prepared_revision);
    state.phase = JointPhase::PreparedFrozen;
    Ok(None)
}

fn abort_basis(state: &JointState) -> Result<(ReceiptRef, u64), Rejection> {
    match (state.prepared, state.prepared_revision) {
        (Some(receipt), Some(revision)) => Ok((receipt, revision)),
        (None, None) => Ok((
            state.intent.ok_or(Rejection::MissingPrerequisite)?,
            state.intent_revision.ok_or(Rejection::MissingPrerequisite)?,
        )),
        _ => Err(Rejection::EventNotApplicable),
    }
}

fn record_abort(
    state: &mut JointState,
    receipt: &crate::OwnershipAbortReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    if let OwnershipDecision::Abort(existing) = state.decision {
        return replay_or_conflict(Some(existing), reference);
    }
    if !matches!(state.decision, OwnershipDecision::Undecided) {
        return Err(Rejection::DecisionConflict);
    }
    if !matches!(
        state.phase,
        JointPhase::PrepareIntent | JointPhase::FrozenUnsealed | JointPhase::PreparedFrozen
    ) {
        return Err(wrong_phase(state));
    }
    let (basis, revision) = abort_basis(state)?;
    if state.reservation != Some(receipt.reservation)
        || receipt.basis != basis
        || receipt.basis_revision != revision
    {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(basis, &receipt.header)?;
    if receipt.decision_sequence <= revision
        || receipt.header.sequence != receipt.decision_sequence
        || !nonzero_digest(receipt.non_equivocation_root)
    {
        return Err(Rejection::InvalidRevision);
    }
    state.decision = OwnershipDecision::Abort(reference);
    state.phase = JointPhase::AbortDecided;
    Ok(None)
}

fn record_thaw(
    state: &mut JointState,
    receipt: &crate::NexusThawReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let OwnershipDecision::Abort(abort) = state.decision else {
        return Err(Rejection::DecisionConflict);
    };
    let freeze = state.nexus_freeze.ok_or(Rejection::MissingPrerequisite)?;
    if receipt.abort != abort || receipt.nexus_freeze != freeze {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(freeze, &receipt.header)?;
    if receipt.thaw_generation == 0 {
        return Err(Rejection::InvalidRevision);
    }
    if let Some(replay) = replay_or_conflict(state.thaw, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::AbortDecided {
        return Err(wrong_phase(state));
    }
    state.thaw = Some(reference);
    state.phase = JointPhase::SourceThawPending;
    Ok(None)
}

fn record_source_resume(
    state: &mut JointState,
    receipt: &crate::VisaSourceResumeReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let OwnershipDecision::Abort(abort) = state.decision else {
        return Err(Rejection::DecisionConflict);
    };
    if receipt.abort != abort || !nonzero_digest(receipt.state_digest) {
        return Err(Rejection::ReceiptMismatch);
    }
    let visa_freeze = state.visa_freeze.ok_or(Rejection::MissingPrerequisite)?;
    require_child(visa_freeze, &receipt.header)?;
    let expected_phase = if state.nexus_freeze.is_some() {
        let thaw = state.thaw.ok_or(Rejection::MissingPrerequisite)?;
        if receipt.thaw != Some(thaw) {
            return Err(Rejection::ReceiptMismatch);
        }
        JointPhase::SourceThawPending
    } else {
        if receipt.thaw.is_some() {
            return Err(Rejection::ReceiptMismatch);
        }
        JointPhase::AbortDecided
    };
    if let Some(replay) = replay_or_conflict(state.source_resume, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != expected_phase {
        return Err(wrong_phase(state));
    }
    state.source_resume = Some(reference);
    state.phase = JointPhase::SourceActive;
    Ok(None)
}

fn record_commit(
    state: &mut JointState,
    receipt: &crate::OwnershipCommitReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    if let OwnershipDecision::Commit(existing) = state.decision {
        return replay_or_conflict(Some(existing), reference);
    }
    if !matches!(state.decision, OwnershipDecision::Undecided) {
        return Err(Rejection::DecisionConflict);
    }
    if state.phase != JointPhase::PreparedFrozen {
        return Err(wrong_phase(state));
    }
    let prepared = state.prepared.ok_or(Rejection::MissingPrerequisite)?;
    let revision = state.prepared_revision.ok_or(Rejection::MissingPrerequisite)?;
    if state.reservation != Some(receipt.reservation)
        || receipt.prepared != prepared
        || receipt.prepared_revision != revision
    {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(prepared, &receipt.header)?;
    if receipt.decision_sequence <= revision
        || receipt.header.sequence != receipt.decision_sequence
        || !nonzero_digest(receipt.non_equivocation_root)
    {
        return Err(Rejection::InvalidRevision);
    }
    state.decision = OwnershipDecision::Commit(reference);
    state.phase = JointPhase::CommitDecided;
    Ok(None)
}

fn closure_basis(state: &JointState) -> Result<(ReceiptRef, ReceiptRef), Rejection> {
    let OwnershipDecision::Commit(commit) = state.decision else {
        return Err(Rejection::DecisionConflict);
    };
    Ok((commit, state.nexus_freeze.ok_or(Rejection::MissingPrerequisite)?))
}

fn current_closure_revision(state: &JointState) -> u64 {
    match state.closure {
        ClosureStatus::NotStarted => 0,
        ClosureStatus::Pending { revision, .. }
        | ClosureStatus::Closed { revision, .. }
        | ClosureStatus::RetainedTombstone { revision, .. } => revision,
    }
}

fn record_progress(
    state: &mut JointState,
    receipt: &crate::ClosureProgressReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let (commit, nexus_freeze) = closure_basis(state)?;
    if receipt.commit != commit
        || receipt.nexus_freeze != nexus_freeze
        || receipt.closure_revision == 0
        || receipt.retained_tombstones != 0
        || !nonzero_digest(receipt.progress_root)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    if let ClosureStatus::Pending { receipt: existing, revision } = state.closure {
        if existing == reference {
            return Ok(Some(Replay::Receipt(existing)));
        }
        require_child(existing, &receipt.header)?;
        if receipt.closure_revision <= revision {
            return Err(Rejection::StaleRevision);
        }
    } else if !matches!(state.closure, ClosureStatus::NotStarted) {
        return Err(Rejection::ClosureBlocked);
    } else {
        require_child(nexus_freeze, &receipt.header)?;
    }
    if !matches!(state.phase, JointPhase::CommitDecided | JointPhase::ClosurePending) {
        return Err(wrong_phase(state));
    }
    state.closure =
        ClosureStatus::Pending { receipt: reference, revision: receipt.closure_revision };
    state.phase = JointPhase::ClosurePending;
    Ok(None)
}

fn record_closure(
    state: &mut JointState,
    receipt: &crate::ClosureReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let (commit, nexus_freeze) = closure_basis(state)?;
    if receipt.commit != commit
        || receipt.nexus_freeze != nexus_freeze
        || receipt.closure_revision == 0
        || receipt.closed_authority_epoch == 0
        || !nonzero_digest(receipt.effect_manifest_digest)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    if let ClosureStatus::Closed { receipt: existing, .. } = state.closure {
        return replay_or_conflict(Some(existing), reference);
    }
    let closure_parent = match state.closure {
        ClosureStatus::Pending { receipt, .. }
        | ClosureStatus::RetainedTombstone { receipt, .. } => receipt,
        _ => nexus_freeze,
    };
    require_child(closure_parent, &receipt.header)?;
    if receipt.closure_revision <= current_closure_revision(state) {
        return Err(Rejection::StaleRevision);
    }
    if !matches!(
        state.phase,
        JointPhase::CommitDecided | JointPhase::ClosurePending | JointPhase::RecoveryRequired
    ) {
        return Err(wrong_phase(state));
    }
    state.closure =
        ClosureStatus::Closed { receipt: reference, revision: receipt.closure_revision };
    state.phase = JointPhase::SourceClosed;
    Ok(None)
}

fn record_tombstone(
    state: &mut JointState,
    receipt: &crate::RetainedTombstoneReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let (commit, nexus_freeze) = closure_basis(state)?;
    if receipt.commit != commit
        || receipt.nexus_freeze != nexus_freeze
        || receipt.closure_revision == 0
        || receipt.tombstone_count == 0
        || !nonzero_digest(receipt.tombstone_manifest_digest)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    if let ClosureStatus::RetainedTombstone { receipt: existing, .. } = state.closure {
        return replay_or_conflict(Some(existing), reference);
    }
    let tombstone_parent = match state.closure {
        ClosureStatus::Pending { receipt, .. } => receipt,
        _ => nexus_freeze,
    };
    require_child(tombstone_parent, &receipt.header)?;
    if receipt.closure_revision <= current_closure_revision(state) {
        return Err(Rejection::StaleRevision);
    }
    if !matches!(state.phase, JointPhase::CommitDecided | JointPhase::ClosurePending) {
        return Err(wrong_phase(state));
    }
    state.closure =
        ClosureStatus::RetainedTombstone { receipt: reference, revision: receipt.closure_revision };
    state.phase = JointPhase::RecoveryRequired;
    Ok(None)
}

fn closed_basis(state: &JointState) -> Result<(ReceiptRef, ReceiptRef), Rejection> {
    let OwnershipDecision::Commit(commit) = state.decision else {
        return Err(Rejection::DecisionConflict);
    };
    let ClosureStatus::Closed { receipt: closure, .. } = state.closure else {
        return Err(Rejection::ClosureBlocked);
    };
    Ok((commit, closure))
}

fn record_source_fence(
    state: &mut JointState,
    receipt: &crate::VisaSourceFenceReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let (commit, closure) = closed_basis(state)?;
    if receipt.commit != commit
        || receipt.closure != closure
        || !nonzero_digest(receipt.state_digest)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(state.visa_freeze.ok_or(Rejection::MissingPrerequisite)?, &receipt.header)?;
    if let Some(replay) = replay_or_conflict(state.source_fence, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::SourceClosed {
        return Err(wrong_phase(state));
    }
    state.source_fence = Some(reference);
    Ok(None)
}

fn begin_destination_activation(
    state: &mut JointState,
    activation_command: crate::Identity,
    commit: ReceiptRef,
    closure: ReceiptRef,
) -> Result<Option<Replay>, Rejection> {
    let (expected_commit, expected_closure) = closed_basis(state)?;
    if commit != expected_commit || closure != expected_closure {
        return Err(Rejection::ReceiptMismatch);
    }
    if matches!(
        state.phase,
        JointPhase::DestinationActivationPending | JointPhase::DestinationActive
    ) {
        return if state.destination_activation_command == Some(activation_command) {
            Ok(Some(Replay::NoChange))
        } else {
            Err(Rejection::ConflictingReceipt)
        };
    }
    if state.phase != JointPhase::SourceClosed {
        return Err(wrong_phase(state));
    }
    if state.source_fence.is_none() {
        return Err(Rejection::MissingPrerequisite);
    }
    state.destination_activation_command = Some(activation_command);
    state.phase = JointPhase::DestinationActivationPending;
    Ok(None)
}

fn record_destination_activation(
    state: &mut JointState,
    completion_command: crate::Identity,
    receipt: &crate::VisaDestinationActivationReceipt,
) -> Result<Option<Replay>, Rejection> {
    let reference = validate_receipt(state, receipt)?;
    let (commit, closure) = closed_basis(state)?;
    let source_fence = state.source_fence.ok_or(Rejection::MissingPrerequisite)?;
    if receipt.commit != commit
        || receipt.closure != closure
        || receipt.source_fence != source_fence
        || state.destination_activation_command != Some(receipt.activation_command)
        || receipt.resume_command.is_zero()
        || receipt.resume_command == receipt.activation_command
        || receipt.resume_command == completion_command
        || !nonzero_digest(receipt.activation_attempt_record_digest)
        || !nonzero_digest(receipt.state_digest)
    {
        return Err(Rejection::ReceiptMismatch);
    }
    require_child(
        state.destination_prepared.ok_or(Rejection::MissingPrerequisite)?,
        &receipt.header,
    )?;
    if let Some(replay) = replay_or_conflict(state.destination_activation, reference)? {
        return Ok(Some(replay));
    }
    if state.phase != JointPhase::DestinationActivationPending {
        return Err(wrong_phase(state));
    }
    if !no_duplicate_receipts(alloc::vec![reference, commit, closure, source_fence]) {
        return Err(Rejection::ConflictingReceipt);
    }
    state.destination_activation = Some(reference);
    state.phase = JointPhase::DestinationActive;
    Ok(None)
}
