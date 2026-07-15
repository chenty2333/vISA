use alloc::{boxed::Box, vec};

use super::*;

const OWNERSHIP_ISSUER: u128 = 100;
const OWNERSHIP_INCARNATION: u128 = 101;
const OWNERSHIP_KEY: u128 = 102;
const OWNERSHIP_LOG: u128 = 103;
const EFFECT_ISSUER: u128 = 200;
const EFFECT_INCARNATION: u128 = 201;
const EFFECT_KEY: u128 = 202;
const EFFECT_LOG: u128 = 203;
const VISA_SOURCE_ISSUER: u128 = 300;
const VISA_SOURCE_INCARNATION: u128 = 301;
const VISA_SOURCE_KEY: u128 = 302;
const VISA_SOURCE_LOG: u128 = 303;
const VISA_DESTINATION_ISSUER: u128 = 400;
const VISA_DESTINATION_INCARNATION: u128 = 401;
const VISA_DESTINATION_KEY: u128 = 402;
const VISA_DESTINATION_LOG: u128 = 403;

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn key() -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: EntityRef::initial(id(1)),
        handoff: id(2),
        source: NodeIdentity::new(id(3)),
        destination: NodeIdentity::new(id(4)),
        expected_epoch: LeaseEpoch(7),
        next_epoch: LeaseEpoch(8),
    }
}

fn header(
    kind: ReceiptKind,
    issuer: u128,
    incarnation: u128,
    key_id: u128,
    log: u128,
    sequence: u64,
    previous_digest: Option<Digest>,
) -> ReceiptHeader {
    ReceiptHeader {
        version: JOINT_PROTOCOL_VERSION,
        kind,
        issuer: id(issuer),
        issuer_incarnation: id(incarnation),
        key_id: id(key_id),
        log_id: id(log),
        sequence,
        previous_digest,
    }
}

fn ownership_header(kind: ReceiptKind, sequence: u64, parent: Option<ReceiptRef>) -> ReceiptHeader {
    header(
        kind,
        OWNERSHIP_ISSUER,
        OWNERSHIP_INCARNATION,
        OWNERSHIP_KEY,
        OWNERSHIP_LOG,
        sequence,
        parent.map(|value| value.digest),
    )
}

fn effect_header(kind: ReceiptKind, sequence: u64, parent: Option<ReceiptRef>) -> ReceiptHeader {
    header(
        kind,
        EFFECT_ISSUER,
        EFFECT_INCARNATION,
        EFFECT_KEY,
        EFFECT_LOG,
        sequence,
        parent.map(|value| value.digest),
    )
}

fn visa_source_header(
    kind: ReceiptKind,
    sequence: u64,
    parent: Option<ReceiptRef>,
) -> ReceiptHeader {
    header(
        kind,
        VISA_SOURCE_ISSUER,
        VISA_SOURCE_INCARNATION,
        VISA_SOURCE_KEY,
        VISA_SOURCE_LOG,
        sequence,
        parent.map(|value| value.digest),
    )
}

fn visa_destination_header(
    kind: ReceiptKind,
    sequence: u64,
    parent: Option<ReceiptRef>,
) -> ReceiptHeader {
    header(
        kind,
        VISA_DESTINATION_ISSUER,
        VISA_DESTINATION_INCARNATION,
        VISA_DESTINATION_KEY,
        VISA_DESTINATION_LOG,
        sequence,
        parent.map(|value| value.digest),
    )
}

fn intent() -> PrepareIntentReceipt {
    PrepareIntentReceipt {
        header: ownership_header(ReceiptKind::PrepareIntent, 10, None),
        key: key(),
        ownership_service: id(OWNERSHIP_ISSUER),
        service_incarnation: id(OWNERSHIP_INCARNATION),
        reservation: id(104),
        intent_revision: 10,
        request_digest: digest(1),
    }
}

fn visa_freeze(intent: ReceiptRef) -> VisaFreezeReceipt {
    VisaFreezeReceipt {
        header: visa_source_header(ReceiptKind::VisaFreeze, 1, None),
        key: key(),
        intent,
        journal_position: JournalPosition(20),
        state_digest: digest(2),
        portable_state_digest: digest(3),
    }
}

fn effect_freeze(
    intent: ReceiptRef,
    disposition: FreezeDisposition,
    unresolved: u64,
    tombstones: u64,
) -> NexusFreezeReceipt {
    NexusFreezeReceipt {
        header: effect_header(ReceiptKind::NexusFreeze, 20, None),
        key: key(),
        intent,
        registry_instance: id(210),
        scope_id: id(211),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
        domain_bindings_digest: digest(4),
        effect_cohort_digest: digest(5),
        classification_root: digest(6),
        counts: ClassificationCounts {
            registered: 5,
            committed: 5 - unresolved,
            aborted: 0,
            unresolved,
            tombstones,
        },
        disposition,
    }
}

fn destination_prepared(
    intent: ReceiptRef,
    visa_freeze: ReceiptRef,
    nexus_freeze: ReceiptRef,
) -> DestinationPreparedReceipt {
    DestinationPreparedReceipt {
        header: visa_destination_header(ReceiptKind::DestinationPrepared, 1, None),
        key: key(),
        intent,
        visa_freeze,
        nexus_freeze,
        snapshot: SnapshotBinding {
            snapshot: id(20),
            integrity: digest(7),
            body_digest: digest(8),
            source_journal_position: JournalPosition(20),
            component_digest: digest(9),
            profile_digest: digest(10),
        },
        journal_position: JournalPosition(21),
        state_digest: digest(11),
        prepared_destination_digest: digest(12),
        authorities_digest: digest(13),
        bindings_digest: digest(14),
        joint_mapping_manifest_digest: digest(16),
        lease_commit_operation: id(21),
        lease_commit_idempotency: IdempotencyKey::from_bytes([22; 16]),
        lease_commit_request_digest: digest(15),
    }
}

fn prepared(
    intent: ReceiptRef,
    visa_freeze: ReceiptRef,
    nexus_freeze: ReceiptRef,
    destination_prepared: ReceiptRef,
    bindings: PreparedBindings,
) -> OwnershipPreparedReceipt {
    OwnershipPreparedReceipt {
        header: ownership_header(ReceiptKind::OwnershipPrepared, 30, Some(intent)),
        key: key(),
        reservation: id(104),
        intent,
        visa_freeze,
        nexus_freeze,
        destination_prepared,
        bindings,
        prepared_revision: 30,
    }
}

fn commit(prepared: ReceiptRef) -> OwnershipCommitReceipt {
    OwnershipCommitReceipt {
        header: ownership_header(ReceiptKind::OwnershipCommit, 40, Some(prepared)),
        key: key(),
        reservation: id(104),
        prepared,
        prepared_revision: 30,
        decision_sequence: 40,
        non_equivocation_root: digest(17),
    }
}

fn abort(basis: ReceiptRef, basis_revision: u64) -> OwnershipAbortReceipt {
    OwnershipAbortReceipt {
        header: ownership_header(ReceiptKind::OwnershipAbort, 40, Some(basis)),
        key: key(),
        reservation: id(104),
        basis,
        basis_revision,
        decision_sequence: 40,
        non_equivocation_root: digest(18),
    }
}

fn progress(commit: ReceiptRef, freeze: ReceiptRef, parent: ReceiptRef) -> ClosureProgressReceipt {
    ClosureProgressReceipt {
        header: effect_header(ReceiptKind::ClosureProgress, parent.sequence + 1, Some(parent)),
        key: key(),
        commit,
        nexus_freeze: freeze,
        closure_revision: 1,
        remaining_effects: 2,
        retained_tombstones: 0,
        progress_root: digest(19),
    }
}

fn closure(
    commit: ReceiptRef,
    freeze: ReceiptRef,
    parent: ReceiptRef,
    revision: u64,
) -> ClosureReceipt {
    ClosureReceipt {
        header: effect_header(ReceiptKind::Closure, parent.sequence + 1, Some(parent)),
        key: key(),
        commit,
        nexus_freeze: freeze,
        closure_revision: revision,
        effect_manifest_digest: digest(20),
        closed_authority_epoch: 6,
    }
}

fn source_fence(
    commit: ReceiptRef,
    closure: ReceiptRef,
    visa_freeze: ReceiptRef,
) -> VisaSourceFenceReceipt {
    VisaSourceFenceReceipt {
        header: visa_source_header(ReceiptKind::VisaSourceFence, 2, Some(visa_freeze)),
        key: key(),
        commit,
        closure,
        journal_position: JournalPosition(22),
        state_digest: digest(21),
    }
}

fn activation(
    commit: ReceiptRef,
    closure: ReceiptRef,
    source_fence: ReceiptRef,
    activation_command: Identity,
    destination_prepared: ReceiptRef,
) -> VisaDestinationActivationReceipt {
    VisaDestinationActivationReceipt {
        header: visa_destination_header(
            ReceiptKind::VisaDestinationActivation,
            2,
            Some(destination_prepared),
        ),
        key: key(),
        commit,
        closure,
        source_fence,
        activation_command,
        resume_command: id(50_000),
        activation_attempt_record_digest: digest(22),
        journal_position: JournalPosition(23),
        state_digest: digest(23),
    }
}

fn command(value: u128, kind: CommandKind) -> Command {
    Command::new(id(value), kind)
}

fn advance(state: &mut JointState, command: Command) -> Event {
    let previous_revision = state.revision;
    let Decision::Commit(event) = preflight(state, &command) else {
        panic!("command was not accepted: {:?}", preflight(state, &command));
    };
    *state = apply(state, &event).expect("committed event applies").into_state();
    assert_eq!(state.revision, previous_revision + 1);
    assert!(matches!(preflight(state, &command), Decision::Replay(_)));
    *event
}

struct PreparedFixture {
    state: JointState,
    visa_freeze: ReceiptRef,
    effect_freeze: ReceiptRef,
    destination_prepared: ReceiptRef,
    prepared: ReceiptRef,
}

fn prepared_fixture() -> PreparedFixture {
    let mut state = JointState::new(key()).unwrap();
    let intent_receipt = intent();
    let intent = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(1_000, CommandKind::RecordPrepareIntent(intent_receipt)));

    let visa_receipt = visa_freeze(intent);
    let visa_ref = visa_receipt.receipt_ref().unwrap();
    let effect_receipt = effect_freeze(intent, FreezeDisposition::ReadyToCommit, 0, 0);
    let effect_ref = effect_receipt.receipt_ref().unwrap();
    advance(&mut state, command(1_002, CommandKind::RecordVisaFreeze(visa_receipt)));
    advance(&mut state, command(1_001, CommandKind::RecordNexusFreeze(effect_receipt)));

    let destination = destination_prepared(intent, visa_ref, effect_ref);
    let destination_ref = destination.receipt_ref().unwrap();
    advance(
        &mut state,
        command(1_003, CommandKind::RecordDestinationPrepared(Box::new(destination))),
    );
    let bindings = state.pending_bindings.unwrap();
    let prepared_receipt = prepared(intent, visa_ref, effect_ref, destination_ref, bindings);
    let prepared_ref = prepared_receipt.receipt_ref().unwrap();
    advance(
        &mut state,
        command(1_004, CommandKind::SealPreparedFrozen(Box::new(prepared_receipt))),
    );
    PreparedFixture {
        state,
        visa_freeze: visa_ref,
        effect_freeze: effect_ref,
        destination_prepared: destination_ref,
        prepared: prepared_ref,
    }
}

#[test]
fn commit_close_fence_and_activation_follow_the_blocking_order() {
    let PreparedFixture { mut state, visa_freeze, effect_freeze, destination_prepared, prepared } =
        prepared_fixture();
    assert_eq!(state.phase, JointPhase::PreparedFrozen);

    let commit_receipt = commit(prepared);
    let commit_ref = commit_receipt.receipt_ref().unwrap();
    advance(&mut state, command(2_000, CommandKind::RecordCommitDecision(commit_receipt)));
    assert_eq!(state.phase, JointPhase::CommitDecided);

    let progress_receipt = progress(commit_ref, effect_freeze, effect_freeze);
    let progress_ref = progress_receipt.receipt_ref().unwrap();
    advance(&mut state, command(2_001, CommandKind::RecordClosureProgress(progress_receipt)));
    assert_eq!(state.phase, JointPhase::ClosurePending);

    let closure_receipt = closure(commit_ref, effect_freeze, progress_ref, 2);
    let closure_ref = closure_receipt.receipt_ref().unwrap();
    advance(&mut state, command(2_002, CommandKind::RecordClosure(closure_receipt)));
    assert_eq!(state.phase, JointPhase::SourceClosed);

    let begin = command(
        2_003,
        CommandKind::BeginDestinationActivation { commit: commit_ref, closure: closure_ref },
    );
    assert_eq!(preflight(&state, &begin), Decision::Reject(Rejection::MissingPrerequisite));

    let fence = source_fence(commit_ref, closure_ref, visa_freeze);
    let fence_ref = fence.receipt_ref().unwrap();
    advance(&mut state, command(2_004, CommandKind::RecordSourceFence(fence)));
    advance(&mut state, begin.clone());
    assert_eq!(state.phase, JointPhase::DestinationActivationPending);

    let activation_command = command(
        2_005,
        CommandKind::RecordDestinationActivation(activation(
            commit_ref,
            closure_ref,
            fence_ref,
            begin.identity,
            destination_prepared,
        )),
    );
    advance(&mut state, activation_command);
    assert_eq!(state.phase, JointPhase::DestinationActive);
    assert!(matches!(preflight(&state, &begin), Decision::Replay(Replay::NoChange)));
}

#[test]
fn visa_freeze_precedes_effect_freeze_and_both_are_required() {
    assert_eq!(prepared_fixture().state.phase, JointPhase::PreparedFrozen);

    let mut state = JointState::new(key()).unwrap();
    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(3_000, CommandKind::RecordPrepareIntent(intent_receipt)));
    let effect = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 0);
    let effect_ref = effect.receipt_ref().unwrap();
    assert_eq!(
        preflight(&state, &command(3_001, CommandKind::RecordNexusFreeze(effect.clone()))),
        Decision::Reject(Rejection::MissingPrerequisite)
    );
    let visa_ref = visa_freeze(intent_ref).receipt_ref().unwrap();
    let destination = destination_prepared(intent_ref, visa_ref, effect_ref);
    assert!(matches!(
        preflight(
            &state,
            &command(3_002, CommandKind::RecordDestinationPrepared(Box::new(destination)))
        ),
        Decision::Reject(Rejection::MissingPrerequisite)
    ));
    advance(&mut state, command(3_003, CommandKind::RecordVisaFreeze(visa_freeze(intent_ref))));
    advance(&mut state, command(3_001, CommandKind::RecordNexusFreeze(effect)));
}

#[test]
fn blocked_or_unresolved_freeze_can_be_recorded_but_never_sealed() {
    for (disposition, unresolved, tombstones) in [
        (FreezeDisposition::Blocked { blocker_digest: digest(30) }, 0, 0),
        (FreezeDisposition::ReadyToCommit, 1, 0),
    ] {
        let mut state = JointState::new(key()).unwrap();
        let intent_receipt = intent();
        let intent_ref = intent_receipt.receipt_ref().unwrap();
        advance(&mut state, command(4_000, CommandKind::RecordPrepareIntent(intent_receipt)));
        let visa_receipt = visa_freeze(intent_ref);
        let visa_ref = visa_receipt.receipt_ref().unwrap();
        advance(&mut state, command(4_001, CommandKind::RecordVisaFreeze(visa_receipt)));
        let effect_receipt = effect_freeze(intent_ref, disposition, unresolved, tombstones);
        let effect_ref = effect_receipt.receipt_ref().unwrap();
        advance(&mut state, command(4_002, CommandKind::RecordNexusFreeze(effect_receipt)));
        let destination = destination_prepared(intent_ref, visa_ref, effect_ref);
        let destination_ref = destination.receipt_ref().unwrap();
        advance(
            &mut state,
            command(4_003, CommandKind::RecordDestinationPrepared(Box::new(destination))),
        );
        let seal = prepared(
            intent_ref,
            visa_ref,
            effect_ref,
            destination_ref,
            state.pending_bindings.unwrap(),
        );
        let before = state.clone();
        assert_eq!(
            preflight(&state, &command(4_004, CommandKind::SealPreparedFrozen(Box::new(seal)))),
            Decision::Reject(Rejection::ClosureBlocked)
        );
        assert_eq!(state, before);
    }

    let mut state = JointState::new(key()).unwrap();
    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(4_100, CommandKind::RecordPrepareIntent(intent_receipt)));
    let visa_receipt = visa_freeze(intent_ref);
    let visa_ref = visa_receipt.receipt_ref().unwrap();
    advance(&mut state, command(4_101, CommandKind::RecordVisaFreeze(visa_receipt)));
    let effect_receipt = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 1);
    let effect_ref = effect_receipt.receipt_ref().unwrap();
    advance(&mut state, command(4_102, CommandKind::RecordNexusFreeze(effect_receipt)));
    let destination = destination_prepared(intent_ref, visa_ref, effect_ref);
    let destination_ref = destination.receipt_ref().unwrap();
    advance(
        &mut state,
        command(4_103, CommandKind::RecordDestinationPrepared(Box::new(destination))),
    );
    let seal = prepared(
        intent_ref,
        visa_ref,
        effect_ref,
        destination_ref,
        state.pending_bindings.unwrap(),
    );
    advance(&mut state, command(4_104, CommandKind::SealPreparedFrozen(Box::new(seal))));
    assert_eq!(state.phase, JointPhase::PreparedFrozen);
}

#[test]
fn authoritative_abort_then_exact_thaw_is_required_for_source_resume() {
    let mut fixture = prepared_fixture();
    let abort_receipt = abort(fixture.prepared, 30);
    let abort_ref = abort_receipt.receipt_ref().unwrap();
    advance(&mut fixture.state, command(5_000, CommandKind::RecordAbortDecision(abort_receipt)));
    assert_eq!(fixture.state.phase, JointPhase::AbortDecided);

    let thaw = NexusThawReceipt {
        header: effect_header(ReceiptKind::NexusThaw, 21, Some(fixture.effect_freeze)),
        key: key(),
        abort: abort_ref,
        nexus_freeze: fixture.effect_freeze,
        thaw_generation: 7,
    };
    let thaw_ref = thaw.receipt_ref().unwrap();
    advance(&mut fixture.state, command(5_001, CommandKind::RecordThaw(thaw)));
    let resume = VisaSourceResumeReceipt {
        header: visa_source_header(ReceiptKind::VisaSourceResume, 2, Some(fixture.visa_freeze)),
        key: key(),
        abort: abort_ref,
        thaw: Some(thaw_ref),
        journal_position: JournalPosition(22),
        state_digest: digest(31),
    };
    advance(&mut fixture.state, command(5_002, CommandKind::RecordSourceResume(resume)));
    assert_eq!(fixture.state.phase, JointPhase::SourceActive);
    assert!(matches!(
        preflight(
            &fixture.state,
            &command(5_003, CommandKind::RecordCommitDecision(commit(fixture.prepared)))
        ),
        Decision::Reject(Rejection::DecisionConflict | Rejection::InvalidPhase { .. })
    ));
}

#[test]
fn abort_before_visa_freeze_cannot_invent_a_source_resume_receipt() {
    let mut state = JointState::new(key()).unwrap();
    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(5_100, CommandKind::RecordPrepareIntent(intent_receipt)));
    let abort_receipt = abort(intent_ref, 10);
    let abort_ref = abort_receipt.receipt_ref().unwrap();
    advance(&mut state, command(5_101, CommandKind::RecordAbortDecision(abort_receipt)));

    let resume = VisaSourceResumeReceipt {
        header: visa_source_header(ReceiptKind::VisaSourceResume, 1, None),
        key: key(),
        abort: abort_ref,
        thaw: None,
        journal_position: JournalPosition(1),
        state_digest: digest(33),
    };
    assert_eq!(
        preflight(&state, &command(5_102, CommandKind::RecordSourceResume(resume))),
        Decision::Reject(Rejection::MissingPrerequisite)
    );
    assert_eq!(state.phase, JointPhase::AbortDecided);
    assert!(state.source_resume.is_none());
    assert!(state.thaw.is_none());
}

#[test]
fn ownership_chain_cannot_switch_issuer_log_key_incarnation_or_parent() {
    let fixture = prepared_fixture();
    for mutation in 0..5 {
        let mut receipt = commit(fixture.prepared);
        match mutation {
            0 => receipt.header.issuer = id(999),
            1 => receipt.header.issuer_incarnation = id(999),
            2 => receipt.header.key_id = id(999),
            3 => receipt.header.log_id = id(999),
            4 => receipt.header.previous_digest = Some(digest(99)),
            _ => unreachable!(),
        }
        assert_eq!(
            preflight(
                &fixture.state,
                &command(6_000 + mutation, CommandKind::RecordCommitDecision(receipt))
            ),
            Decision::Reject(Rejection::ReceiptMismatch)
        );
    }
}

#[test]
fn issuer_roots_and_source_destination_parent_chains_fail_closed() {
    let mut state = JointState::new(key()).unwrap();
    let mut bad_intent = intent();
    bad_intent.header.previous_digest = Some(digest(90));
    assert_eq!(
        preflight(&state, &command(6_010, CommandKind::RecordPrepareIntent(bad_intent))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );

    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_011, CommandKind::RecordPrepareIntent(intent_receipt)));
    let mut bad_visa_freeze = visa_freeze(intent_ref);
    bad_visa_freeze.header.previous_digest = Some(intent_ref.digest);
    assert_eq!(
        preflight(&state, &command(6_012, CommandKind::RecordVisaFreeze(bad_visa_freeze))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
    let mut bad_effect_freeze = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 0);
    bad_effect_freeze.header.previous_digest = Some(intent_ref.digest);
    assert_eq!(
        preflight(&state, &command(6_013, CommandKind::RecordNexusFreeze(bad_effect_freeze))),
        Decision::Reject(Rejection::MissingPrerequisite)
    );

    let visa_receipt = visa_freeze(intent_ref);
    let visa_ref = visa_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_014, CommandKind::RecordVisaFreeze(visa_receipt)));
    let mut bad_effect_freeze = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 0);
    bad_effect_freeze.header.previous_digest = Some(intent_ref.digest);
    assert_eq!(
        preflight(&state, &command(6_013, CommandKind::RecordNexusFreeze(bad_effect_freeze))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
    let effect_receipt = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 0);
    let effect_ref = effect_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_015, CommandKind::RecordNexusFreeze(effect_receipt)));
    let mut bad_destination = destination_prepared(intent_ref, visa_ref, effect_ref);
    bad_destination.header.previous_digest = Some(visa_ref.digest);
    assert_eq!(
        preflight(
            &state,
            &command(6_016, CommandKind::RecordDestinationPrepared(Box::new(bad_destination)))
        ),
        Decision::Reject(Rejection::ReceiptMismatch)
    );

    let PreparedFixture { mut state, visa_freeze, effect_freeze, destination_prepared, prepared } =
        prepared_fixture();
    let commit_receipt = commit(prepared);
    let commit_ref = commit_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_017, CommandKind::RecordCommitDecision(commit_receipt)));
    let closure_receipt = closure(commit_ref, effect_freeze, effect_freeze, 1);
    let closure_ref = closure_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_018, CommandKind::RecordClosure(closure_receipt)));

    let mut bad_fence = source_fence(commit_ref, closure_ref, visa_freeze);
    bad_fence.header.previous_digest = Some(closure_ref.digest);
    assert_eq!(
        preflight(&state, &command(6_019, CommandKind::RecordSourceFence(bad_fence))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
    let fence = source_fence(commit_ref, closure_ref, visa_freeze);
    let fence_ref = fence.receipt_ref().unwrap();
    advance(&mut state, command(6_020, CommandKind::RecordSourceFence(fence)));
    let begin = command(
        6_021,
        CommandKind::BeginDestinationActivation { commit: commit_ref, closure: closure_ref },
    );
    advance(&mut state, begin.clone());
    let mut bad_activation =
        activation(commit_ref, closure_ref, fence_ref, begin.identity, destination_prepared);
    bad_activation.header.previous_digest = Some(visa_freeze.digest);
    assert_eq!(
        preflight(
            &state,
            &command(6_022, CommandKind::RecordDestinationActivation(bad_activation))
        ),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
    let mut missing_attempt_lineage =
        activation(commit_ref, closure_ref, fence_ref, begin.identity, destination_prepared);
    missing_attempt_lineage.activation_attempt_record_digest = Digest::ZERO;
    assert_eq!(
        preflight(
            &state,
            &command(6_023, CommandKind::RecordDestinationActivation(missing_attempt_lineage))
        ),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
}

#[test]
fn effect_chain_cannot_skip_freeze_or_progress_and_retained_progress_is_terminally_typed() {
    let PreparedFixture { mut state, effect_freeze, prepared, .. } = prepared_fixture();
    let commit_receipt = commit(prepared);
    let commit_ref = commit_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_100, CommandKind::RecordCommitDecision(commit_receipt)));

    let mut wrong_parent = progress(commit_ref, effect_freeze, effect_freeze);
    wrong_parent.header.previous_digest = Some(digest(90));
    assert_eq!(
        preflight(&state, &command(6_101, CommandKind::RecordClosureProgress(wrong_parent))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );

    let mut retained = progress(commit_ref, effect_freeze, effect_freeze);
    retained.retained_tombstones = 1;
    assert_eq!(
        preflight(&state, &command(6_102, CommandKind::RecordClosureProgress(retained))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );

    let progress_receipt = progress(commit_ref, effect_freeze, effect_freeze);
    let progress_ref = progress_receipt.receipt_ref().unwrap();
    advance(&mut state, command(6_103, CommandKind::RecordClosureProgress(progress_receipt)));
    let mut skipped = closure(commit_ref, effect_freeze, progress_ref, 2);
    skipped.header.previous_digest = Some(effect_freeze.digest);
    assert_eq!(
        preflight(&state, &command(6_104, CommandKind::RecordClosure(skipped))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
}

#[test]
fn handoff_epoch_parent_and_payload_mutations_fail_closed() {
    let fixture = prepared_fixture();

    let mut wrong_handoff = commit(fixture.prepared);
    wrong_handoff.key.handoff = id(999);
    assert!(matches!(
        preflight(
            &fixture.state,
            &command(7_000, CommandKind::RecordCommitDecision(wrong_handoff))
        ),
        Decision::Reject(Rejection::HandoffMismatch)
    ));

    let mut wrong_epoch = commit(fixture.prepared);
    wrong_epoch.key.next_epoch = LeaseEpoch(9);
    assert!(matches!(
        preflight(&fixture.state, &command(7_001, CommandKind::RecordCommitDecision(wrong_epoch))),
        Decision::Reject(Rejection::HandoffMismatch)
    ));

    let mut wrong_parent = commit(fixture.prepared);
    wrong_parent.prepared.digest = digest(99);
    assert_eq!(
        preflight(&fixture.state, &command(7_002, CommandKind::RecordCommitDecision(wrong_parent))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );

    let mut wrong_kind = commit(fixture.prepared);
    wrong_kind.header.kind = ReceiptKind::OwnershipAbort;
    assert_eq!(
        preflight(&fixture.state, &command(7_003, CommandKind::RecordCommitDecision(wrong_kind))),
        Decision::Reject(Rejection::InvalidReceiptHeader)
    );
}

#[test]
fn commit_and_abort_are_mutually_exclusive_even_when_raced() {
    let mut commit_wins = prepared_fixture();
    let commit_receipt = commit(commit_wins.prepared);
    advance(
        &mut commit_wins.state,
        command(8_000, CommandKind::RecordCommitDecision(commit_receipt)),
    );
    assert_eq!(
        preflight(
            &commit_wins.state,
            &command(8_001, CommandKind::RecordAbortDecision(abort(commit_wins.prepared, 30)))
        ),
        Decision::Reject(Rejection::DecisionConflict)
    );

    let mut abort_wins = prepared_fixture();
    let abort_receipt = abort(abort_wins.prepared, 30);
    advance(&mut abort_wins.state, command(8_002, CommandKind::RecordAbortDecision(abort_receipt)));
    assert_eq!(
        preflight(
            &abort_wins.state,
            &command(8_003, CommandKind::RecordCommitDecision(commit(abort_wins.prepared)))
        ),
        Decision::Reject(Rejection::DecisionConflict)
    );
}

#[test]
fn retained_tombstone_blocks_activation_until_a_fresh_closure() {
    let PreparedFixture { mut state, visa_freeze, effect_freeze, destination_prepared, prepared } =
        prepared_fixture();
    let commit_receipt = commit(prepared);
    let commit_ref = commit_receipt.receipt_ref().unwrap();
    advance(&mut state, command(9_000, CommandKind::RecordCommitDecision(commit_receipt)));
    let tombstone = RetainedTombstoneReceipt {
        header: effect_header(ReceiptKind::RetainedTombstone, 21, Some(effect_freeze)),
        key: key(),
        commit: commit_ref,
        nexus_freeze: effect_freeze,
        closure_revision: 1,
        tombstone_count: 1,
        tombstone_manifest_digest: digest(32),
    };
    let tombstone_ref = tombstone.receipt_ref().unwrap();
    advance(&mut state, command(9_001, CommandKind::RecordRetainedTombstone(tombstone)));
    assert_eq!(state.phase, JointPhase::RecoveryRequired);
    assert!(matches!(
        preflight(
            &state,
            &command(
                9_002,
                CommandKind::BeginDestinationActivation {
                    commit: commit_ref,
                    closure: effect_freeze,
                }
            )
        ),
        Decision::Reject(Rejection::ClosureBlocked)
    ));

    let recovered = closure(commit_ref, effect_freeze, tombstone_ref, 2);
    let recovered_ref = recovered.receipt_ref().unwrap();
    advance(&mut state, command(9_003, CommandKind::RecordClosure(recovered)));
    let fence = source_fence(commit_ref, recovered_ref, visa_freeze);
    let fence_ref = fence.receipt_ref().unwrap();
    advance(&mut state, command(9_004, CommandKind::RecordSourceFence(fence)));
    let begin = command(
        9_005,
        CommandKind::BeginDestinationActivation { commit: commit_ref, closure: recovered_ref },
    );
    advance(&mut state, begin.clone());
    advance(
        &mut state,
        command(
            9_006,
            CommandKind::RecordDestinationActivation(activation(
                commit_ref,
                recovered_ref,
                fence_ref,
                begin.identity,
                destination_prepared,
            )),
        ),
    );
    assert_eq!(state.phase, JointPhase::DestinationActive);
}

#[test]
fn stale_closure_progress_and_conflicting_step_reuse_are_rejected() {
    let PreparedFixture { mut state, effect_freeze, prepared, .. } = prepared_fixture();
    let commit_receipt = commit(prepared);
    let commit_ref = commit_receipt.receipt_ref().unwrap();
    advance(&mut state, command(10_000, CommandKind::RecordCommitDecision(commit_receipt)));
    let first = progress(commit_ref, effect_freeze, effect_freeze);
    let first_ref = first.receipt_ref().unwrap();
    advance(&mut state, command(10_001, CommandKind::RecordClosureProgress(first)));

    let mut stale = progress(commit_ref, effect_freeze, first_ref);
    stale.closure_revision = 1;
    assert_eq!(
        preflight(&state, &command(10_002, CommandKind::RecordClosureProgress(stale))),
        Decision::Reject(Rejection::StaleRevision)
    );

    let mut conflicting_intent = intent();
    conflicting_intent.request_digest = digest(99);
    assert_eq!(
        preflight(&state, &command(10_003, CommandKind::RecordPrepareIntent(conflicting_intent))),
        Decision::Reject(Rejection::ConflictingReceipt)
    );
}

#[test]
fn canonical_codec_is_strict_and_receipt_digest_is_domain_bound() {
    let receipt = intent();
    let bytes = canonical_bytes(&receipt).unwrap();
    assert_eq!(canonical_from_bytes::<PrepareIntentReceipt>(&bytes).unwrap(), receipt);

    let mut with_trailing = bytes.clone();
    with_trailing.push(0);
    assert_eq!(
        canonical_from_bytes::<PrepareIntentReceipt>(&with_trailing),
        Err(DecodeError::TrailingBytes)
    );

    let original = receipt.receipt_ref().unwrap();
    let mut mutated = receipt.clone();
    mutated.request_digest = digest(99);
    assert_ne!(original.digest, mutated.receipt_ref().unwrap().digest);
    assert_ne!(
        receipt_digest(ReceiptKind::PrepareIntent, &receipt).unwrap(),
        receipt_digest(ReceiptKind::OwnershipPrepared, &receipt).unwrap()
    );

    let mut envelope = ReceiptEnvelope {
        schema: JOINT_PROTOCOL_VERSION,
        issuer: receipt.header.issuer,
        issuer_incarnation: receipt.header.issuer_incarnation,
        kind: ReceiptKind::PrepareIntent,
        handoff: receipt.key.handoff,
        request_digest: ReceiptRequest::for_receipt(id(500), &receipt).digest().unwrap(),
        state_sequence: receipt.header.sequence,
        payload_digest: canonical_digest(&receipt).unwrap(),
        previous_receipt_digest: receipt.header.previous_digest,
        authentication: vec![1, 2, 3],
    };
    assert_eq!(envelope.matches(&receipt), Ok(true));
    let request = ReceiptRequest::for_receipt(id(500), &receipt);
    assert_eq!(envelope.matches_request(&request, &receipt), Ok(true));
    assert_eq!(request.digest(), ReceiptRequest::for_receipt(id(500), &receipt).digest());

    let mut changed_operation = request.clone();
    changed_operation.operation = id(501);
    assert_ne!(changed_operation.digest().unwrap(), request.digest().unwrap());
    assert_eq!(envelope.matches_request(&changed_operation, &receipt), Ok(false));

    let mut changed_sequence = request.clone();
    changed_sequence.expected_state_sequence += 1;
    assert_ne!(changed_sequence.digest().unwrap(), request.digest().unwrap());
    assert!(!changed_sequence.matches(&receipt));

    let freeze = visa_freeze(receipt.receipt_ref().unwrap());
    let freeze_request = ReceiptRequest::for_receipt(id(502), &freeze);
    let mut changed_cause = freeze_request.clone();
    let ReceiptRequestParameters::VisaFreeze { intent } = &mut changed_cause.parameters else {
        unreachable!()
    };
    intent.digest = digest(98);
    assert_ne!(changed_cause.digest().unwrap(), freeze_request.digest().unwrap());
    assert!(!changed_cause.matches(&freeze));

    envelope.authentication.clear();
    assert_eq!(envelope.matches(&receipt), Ok(false));
}

#[test]
fn prepared_frozen_seal_rejects_any_mutated_immutable_binding() {
    let mut state = JointState::new(key()).unwrap();
    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    advance(&mut state, command(10_100, CommandKind::RecordPrepareIntent(intent_receipt)));
    let visa_receipt = visa_freeze(intent_ref);
    let visa_ref = visa_receipt.receipt_ref().unwrap();
    advance(&mut state, command(10_101, CommandKind::RecordVisaFreeze(visa_receipt)));
    let effect_receipt = effect_freeze(intent_ref, FreezeDisposition::ReadyToCommit, 0, 0);
    let effect_ref = effect_receipt.receipt_ref().unwrap();
    advance(&mut state, command(10_102, CommandKind::RecordNexusFreeze(effect_receipt)));
    let destination = destination_prepared(intent_ref, visa_ref, effect_ref);
    let destination_ref = destination.receipt_ref().unwrap();
    advance(
        &mut state,
        command(10_103, CommandKind::RecordDestinationPrepared(Box::new(destination))),
    );
    let mut seal = prepared(
        intent_ref,
        visa_ref,
        effect_ref,
        destination_ref,
        state.pending_bindings.unwrap(),
    );
    seal.bindings.destination_state_digest = digest(99);
    assert_eq!(
        preflight(&state, &command(10_104, CommandKind::SealPreparedFrozen(Box::new(seal)))),
        Decision::Reject(Rejection::ReceiptMismatch)
    );
}

#[test]
fn unsupported_versions_zero_commands_and_invalid_keys_are_rejected() {
    let mut bad_key = key();
    bad_key.destination = bad_key.source;
    assert_eq!(JointState::new(bad_key), Err(Rejection::InvalidHandoffKey));

    let state = JointState::new(key()).unwrap();
    let zero = Command::new(Identity::ZERO, CommandKind::RecordPrepareIntent(intent()));
    assert_eq!(preflight(&state, &zero), Decision::Reject(Rejection::InvalidIdentity));

    let mut unsupported = command(11_000, CommandKind::RecordPrepareIntent(intent()));
    unsupported.version = JointProtocolVersion::new(2, 0);
    assert_eq!(preflight(&state, &unsupported), Decision::Reject(Rejection::UnsupportedVersion));
}

#[test]
fn receipt_references_are_exact_and_distinct_across_typed_kinds() {
    let intent_receipt = intent();
    let intent_ref = intent_receipt.receipt_ref().unwrap();
    let freeze = visa_freeze(intent_ref).receipt_ref().unwrap();
    assert_eq!(intent_ref.kind, ReceiptKind::PrepareIntent);
    assert_eq!(freeze.kind, ReceiptKind::VisaFreeze);
    assert_ne!(intent_ref.digest, freeze.digest);
    assert!(refs_are_distinct(&[intent_ref, freeze]));
    assert!(no_duplicate_receipts(vec![intent_ref, freeze]));
    assert!(!no_duplicate_receipts(vec![intent_ref, intent_ref]));
}

#[test]
fn durable_projection_revision_advances_only_for_new_events() {
    let initial = JointState::new(key()).unwrap();
    let command = command(12_000, CommandKind::RecordPrepareIntent(intent()));
    let Decision::Commit(event) = preflight(&initial, &command) else {
        panic!("intent must commit");
    };
    let applied = apply(&initial, &event).unwrap().into_state();
    assert_eq!(applied.revision, 1);

    let replay = apply(&applied, &event).unwrap();
    assert!(matches!(replay, ApplyResult::Replay(_, _)));
    assert_eq!(replay.state().revision, 1);
    let bytes = canonical_bytes(replay.state()).unwrap();
    assert_eq!(canonical_from_bytes::<JointProjectionState>(&bytes).unwrap(), applied);
}
