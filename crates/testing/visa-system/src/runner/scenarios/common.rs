use std::{thread, time::Duration};

use super::super::{
    RunnerError, TIMER_MARGIN, artifacts::snapshot_envelope, harness::CaseHarness,
    support::state_result,
};
use crate::protocol::{
    DestinationSupportMode, SafePointTimerView, SnapshotExpectationOverrides, WorkerCommand,
    WorkerErrorCode, WorkloadPhaseView,
};

pub(super) fn run_pending_handoff(
    harness: &mut CaseHarness,
    long_pause: bool,
) -> Result<(), RunnerError> {
    let transfer = harness.bootstrap_snapshot()?;
    let SafePointTimerView::Pending { remaining, .. } = transfer.timer else {
        return Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("pending handoff froze timer as {:?}", transfer.timer),
        });
    };
    if long_pause {
        thread::sleep(Duration::from_nanos(remaining.0) + TIMER_MARGIN);
        let source =
            state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
        harness.observe(
            "frozen-time-does-not-expire",
            source.canonical_phase == contract_core::HandoffPhase::Exported,
            format!("phase={:?}, slept_ns={}", source.canonical_phase, remaining.0),
        )?;
    }
    let envelope = snapshot_envelope(harness)?;
    harness.validate_destination(
        envelope,
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.normal_commit()?;
    harness.deliver_pending_timer()
}

pub(super) fn assert_post_commit_source_rejected(
    harness: &mut CaseHarness,
) -> Result<(), RunnerError> {
    let before = harness.dump_source()?.key_value_entry;
    let error = harness.source_rejection(WorkerCommand::AdversarialStaleKvWriteProbe)?;
    let after = harness.dump_source()?.key_value_entry;
    harness.observe(
        "post-commit-adversarial-source-write-fenced",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("StaleEpoch")
            && before == after,
        format!("error={error:?}, before={before:?}, after={after:?}"),
    )
}

pub(super) fn abort_precommit_to_source(
    harness: &mut CaseHarness,
    observation: &'static str,
) -> Result<(), RunnerError> {
    harness.archive_destination()?;
    let aborted =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let dump = harness.dump_source()?;
    let snapshot_timer = harness.snapshot.as_ref().map(|snapshot| snapshot.timer);
    let workload_resumed = match snapshot_timer {
        Some(SafePointTimerView::Pending { .. }) => {
            dump.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            }) && matches!(
                dump.canonical_state.timer.status,
                contract_core::TimerStatus::Armed { remaining } if remaining.0 > 0
            ) && dump.key_value_entry.as_ref().is_some_and(|value| {
                value.version == 1 && value.value == harness.fixture.activation.initial_value
            })
        }
        Some(SafePointTimerView::Completed { .. }) => {
            dump.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Completed && component.expected_version == 2
            }) && dump.canonical_state.timer.status == contract_core::TimerStatus::Completed
                && dump.key_value_entry.as_ref().is_some_and(|value| {
                    value.version == 2 && value.value == harness.fixture.activation.completion_value
                })
        }
        _ => false,
    };
    let source_lease_epoch = harness.fixture.activation.initial_lease_epoch;
    harness.observe(
        observation,
        aborted.canonical_phase == contract_core::HandoffPhase::Aborted
            && resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.activation.role == contract_core::ActivationRole::Source
            && dump.canonical_state.activation.status == contract_core::ActivationStatus::Active
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.ownership.epoch == source_lease_epoch
            && dump.canonical_state.exported_snapshot.is_none()
            && dump.canonical_state.prepared_destination.is_none()
            && dump.binding_receipts.is_empty()
            && dump.leases.iter().all(|lease| {
                lease.owner == harness.fixture.ids.source_node && lease.epoch == source_lease_epoch
            })
            && workload_resumed,
        format!(
            "aborted={:?}, resumed={:?}, canonical={:?}, activation={:?}, ownership={:?}, leases={:?}, receipts={:?}, snapshot_timer={snapshot_timer:?}, timer={:?}, component={:?}, kv={:?}",
            aborted.canonical_phase,
            resumed.canonical_phase,
            dump.canonical_state.phase,
            dump.canonical_state.activation,
            dump.canonical_state.ownership,
            dump.leases,
            dump.binding_receipts,
            dump.canonical_state.timer.status,
            dump.component,
            dump.key_value_entry,
        ),
    )
}
