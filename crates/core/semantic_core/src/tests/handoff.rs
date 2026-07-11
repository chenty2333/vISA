use super::*;

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
    let frozen = TimerDisposition::Pending { remaining: LogicalDurationNanos(800), arm_operation };
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
    state =
        commit(&state, command(351, CommandKind::ExportSnapshot { snapshot: snapshot.clone() }));
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
    let source =
        commit(&source, command(352, CommandKind::ExportSnapshot { snapshot: snapshot.clone() }));
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
    assert_eq!(destination.ownership, Ownership::owned(fixture.destination_node, LeaseEpoch(2)));
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
