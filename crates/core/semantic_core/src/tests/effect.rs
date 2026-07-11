use super::*;

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
    let conflict = EffectRequest { operation: id(1_022), request_digest: digest(99), ..request };
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
        state
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .and_then(|record| record.outcome.as_ref()),
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
