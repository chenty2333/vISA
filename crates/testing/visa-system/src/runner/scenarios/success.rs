use std::{
    collections::BTreeSet,
    thread,
    time::{Duration, Instant},
};

use visa_conformance::Stage1PerformanceMetric;

use super::{
    super::{
        RunnerError, TIMER_MARGIN,
        artifacts::snapshot_envelope,
        harness::CaseHarness,
        support::{elapsed_nanos, state_result, timer_result},
    },
    common::abort_precommit_to_source,
};
use crate::{
    evidence::PerformanceMeasurement,
    fixture::AuthorityPolicyMode,
    protocol::{
        DestinationSupportMode, SafePointTimerView, SnapshotExpectationOverrides, TimerPollView,
        WorkerCommand, WorkerResult, WorkloadPhaseView,
    },
};

pub(super) fn run_completed_timer_handoff(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    thread::sleep(Duration::from_nanos(harness.fixture.activation.delay_ns) + TIMER_MARGIN);
    let transfer = harness.freeze()?;
    harness.observe(
        "quiescing-completion-captured",
        matches!(transfer.timer, SafePointTimerView::Completed { .. }),
        format!("timer={:?}", transfer.timer),
    )?;
    harness.export(transfer)?;
    harness.normal_commit()?;
    let result = harness.destination_success(WorkerCommand::PollTimer { deliver: true })?;
    let (poll, delivered, view) = timer_result(harness.definition.id, result)?;
    harness.observe(
        "completed-timer-not-recreated",
        poll == TimerPollView::Completed
            && !delivered
            && view.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Completed && component.expected_version == 2
            }),
        format!("poll={poll:?}, delivered={delivered}, component={:?}", view.component),
    )
}

pub(super) fn run_cancelled_timer_handoff(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::CancelPending)?;
    let transfer = harness.freeze()?;
    harness.observe(
        "cancelled-timer-captured",
        transfer.timer == SafePointTimerView::Cancelled,
        format!("timer={:?}", transfer.timer),
    )?;
    harness.export(transfer)?;
    let first_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    let second_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    harness.observe(
        "timer-cleanup-idempotent",
        first_cleanup.state_digest == second_cleanup.state_digest
            && first_cleanup.journal_position == second_cleanup.journal_position,
        format!(
            "first={:?}/{:?}, second={:?}/{:?}",
            first_cleanup.journal_position,
            first_cleanup.state_digest,
            second_cleanup.journal_position,
            second_cleanup.state_digest
        ),
    )?;
    harness.normal_commit()?;
    let result = harness.destination_success(WorkerCommand::PollTimer { deliver: true })?;
    let (poll, delivered, _) = timer_result(harness.definition.id, result)?;
    harness.observe(
        "cancelled-timer-not-recreated",
        matches!(poll, TimerPollView::Cancelled | TimerPollView::Cleaned) && !delivered,
        format!("poll={poll:?}, delivered={delivered}"),
    )
}

pub(super) fn assert_narrow_destination_authority(
    harness: &mut CaseHarness,
) -> Result<(), RunnerError> {
    let dump = harness.dump_destination()?;
    let prepared = dump.canonical_state.prepared_destination.as_ref().ok_or_else(|| {
        RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: "destination has no prepared authority set".to_owned(),
        }
    })?;
    let subject = harness.fixture.ids.destination_component;
    let expected_grants = [
        contract_core::AuthorityGrant {
            authority: harness.fixture.handoff_authority.destination_authority,
            parent: Some(harness.fixture.handoff_authority.source_authority),
            subject,
            resource: subject,
            rights: contract_core::Rights::HANDOFF,
            status: contract_core::AuthorityStatus::Active,
        },
        contract_core::AuthorityGrant {
            authority: harness.fixture.timer_authority.destination_authority,
            parent: Some(harness.fixture.timer_authority.source_authority),
            subject,
            resource: harness.fixture.ids.timer_resource,
            rights: harness.fixture.claims.timer.required_rights,
            status: contract_core::AuthorityStatus::Active,
        },
        contract_core::AuthorityGrant {
            authority: harness.fixture.key_value_authority.destination_authority,
            parent: Some(harness.fixture.key_value_authority.source_authority),
            subject,
            resource: harness.fixture.ids.key_value_resource,
            rights: harness.fixture.claims.key_value.required_rights,
            status: contract_core::AuthorityStatus::Active,
        },
    ];
    let prepared_resources =
        prepared.authorities.iter().map(|grant| grant.resource).collect::<BTreeSet<_>>();
    let prepared_exact = prepared.authorities.len() == expected_grants.len()
        && prepared_resources.len() == expected_grants.len()
        && expected_grants.iter().all(|expected| prepared.authorities.contains(expected));
    let mut expected_canonical = snapshot_envelope(harness)?.body.authorities;
    expected_canonical.extend(expected_grants.iter().cloned());
    let canonical_exact = dump.canonical_state.authorities.len() == expected_canonical.len()
        && expected_canonical
            .iter()
            .all(|expected| dump.canonical_state.authorities.contains(expected));
    let expected_bindings = [
        (
            harness.fixture.ids.timer_resource,
            harness.fixture.timer_authority.destination_authority,
            harness.fixture.claims.timer.required_rights,
        ),
        (
            harness.fixture.ids.key_value_resource,
            harness.fixture.key_value_authority.destination_authority,
            harness.fixture.claims.key_value.required_rights,
        ),
    ];
    let binding_claims =
        prepared.bindings.iter().map(|receipt| receipt.claim).collect::<BTreeSet<_>>();
    let bindings_exact = prepared.bindings.len() == expected_bindings.len()
        && binding_claims.len() == expected_bindings.len()
        && expected_bindings.iter().all(|(claim, authority, rights)| {
            prepared.bindings.iter().any(|receipt| {
                receipt.handoff == harness.fixture.ids.handoff
                    && receipt.snapshot == harness.fixture.ids.snapshot
                    && receipt.claim == *claim
                    && receipt.node == harness.fixture.ids.destination_node
                    && receipt.authority == *authority
                    && receipt.exposed_rights == *rights
                    && receipt.lease_epoch == prepared.next_epoch
            })
        });
    harness.observe(
        "destination-authority-is-exactly-profiled",
        prepared_exact && canonical_exact && bindings_exact,
        format!(
            "prepared_grants={:?}, canonical_grants={:?}, bindings={:?}",
            prepared.authorities, dump.canonical_state.authorities, prepared.bindings
        ),
    )
}

pub(super) fn assert_broader_policy_input(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let expected = [
        (harness.fixture.ids.destination_component, contract_core::Rights::HANDOFF),
        (harness.fixture.ids.timer_resource, harness.fixture.claims.timer.required_rights),
        (harness.fixture.ids.key_value_resource, harness.fixture.claims.key_value.required_rights),
    ];
    let policies = &harness.fixture.policy_digest_input.destination_policies;
    let policy_is_strictly_broader = harness.plan.options.authority_policy
        == AuthorityPolicyMode::Broader
        && policies.len() == expected.len()
        && expected.iter().all(|(resource, required)| {
            policies.iter().any(|policy| {
                policy.subject == harness.fixture.ids.destination_component
                    && policy.resource == *resource
                    && policy.allowed_rights.contains(*required)
                    && policy.allowed_rights != *required
            })
        });
    harness.observe(
        "broader-policy-is-attenuated-at-destination-boundary",
        policy_is_strictly_broader,
        format!("mode={:?}, policies={policies:?}", harness.plan.options.authority_policy),
    )
}

pub(super) fn assert_duplicate_kv_replay(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let result = harness.destination_success(WorkerCommand::DuplicateCompletionKvProbe)?;
    let WorkerResult::EffectProbe { outcome, replayed, view, .. } = result else {
        return Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("duplicate KV probe returned {result:?}"),
        });
    };
    let applied_once = matches!(
        outcome,
        Some(contract_core::EffectOutcome::Succeeded {
            result: contract_core::EffectResult::KeyValue { version: 2, applied: true },
            ..
        })
    );
    harness.observe(
        "duplicate-kv-replayed-once",
        replayed
            && applied_once
            && view.component.is_some_and(|component| component.expected_version == 2),
        format!("replayed={replayed}, outcome={outcome:?}"),
    )
}

pub(super) fn run_repeated_validation_prepare(
    harness: &mut CaseHarness,
) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    let envelope = snapshot_envelope(harness)?;
    harness.validate_destination(
        envelope.clone(),
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.validate_destination(
        envelope,
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let first = harness.prepare_destination()?;
    let second = harness.prepare_destination()?;
    harness.observe(
        "validation-and-prepare-idempotent",
        first.state_digest == second.state_digest
            && first.journal_position == second.journal_position
            && second.canonical_phase == contract_core::HandoffPhase::DestinationPrepared,
        format!(
            "first={:?}/{:?}, second={:?}/{:?}",
            first.journal_position,
            first.state_digest,
            second.journal_position,
            second.state_digest
        ),
    )?;
    abort_precommit_to_source(harness, "repeated-prepare-aborts-to-source")
}

pub(super) fn assert_evidence_identities(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let source = harness.dump_source()?;
    let destination = harness.dump_destination()?;
    let envelope = snapshot_envelope(harness)?;
    let snapshot = &envelope.body.snapshot;
    let receipts_match = destination.binding_receipts.iter().all(|receipt| {
        receipt.handoff == harness.fixture.ids.handoff
            && receipt.snapshot == harness.fixture.ids.snapshot
            && receipt.node == harness.fixture.ids.destination_node
    });
    harness.observe(
        "evidence-identities-cross-check",
        snapshot.handoff == harness.fixture.ids.handoff
            && snapshot.snapshot == harness.fixture.ids.snapshot
            && source.canonical_state.exported_snapshot.as_ref() == Some(snapshot)
            && receipts_match,
        format!("snapshot={snapshot:?}, receipts={:?}", destination.binding_receipts),
    )
}

pub(super) fn run_performance_case(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    let mut steady = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        harness.source_success(WorkerCommand::Read)?;
        steady.push(elapsed_nanos(started));
    }
    harness.performance.push(PerformanceMeasurement {
        metric: Stage1PerformanceMetric::SteadyStateCost,
        samples: steady,
    });
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    let transfer = harness.export(transfer)?;
    let snapshot_size = serde_json::to_vec(
        transfer.envelope.as_ref().expect("export populated the snapshot envelope"),
    )
    .map_err(|error| RunnerError::Json {
        context: format!("encode {} snapshot size", harness.definition.id),
        detail: error.to_string(),
    })?
    .len() as u64;
    harness.performance.push(PerformanceMeasurement {
        metric: Stage1PerformanceMetric::SnapshotSize,
        samples: vec![snapshot_size],
    });
    harness.normal_commit()?;
    harness.deliver_pending_timer()?;
    harness.observe(
        "raw-performance-samples-recorded",
        harness.performance.len() == 3
            && harness.performance.iter().all(|measurement| !measurement.samples.is_empty()),
        format!("measurements={:?}", harness.performance),
    )
}
