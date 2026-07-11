use std::thread;

use super::{
    super::{RunnerError, WORKER_TIMEOUT, harness::CaseHarness, support::state_result},
    common::{abort_precommit_to_source, assert_post_commit_source_rejected, run_pending_handoff},
};
use crate::protocol::{
    CrashMode, ResponseEnvelope, ResponseOutcome, WorkerCommand, WorkerErrorCode, WorkerResult,
};

pub(super) fn run_crash_before_commit(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    harness
        .destination_mut()
        .crash_and_expect_exit(CrashMode::Immediate, 42, WORKER_TIMEOUT)
        .map_err(|source| harness.worker_error("destination", source))?;
    harness.restart_destination("destination-recovery-before-commit")?;
    harness.load_destination(&[contract_core::HandoffPhase::DestinationPrepared])?;
    let repeated = harness.prepare_destination()?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "precommit-crash-retries-inactive-preparation",
        repeated.canonical_phase == contract_core::HandoffPhase::DestinationPrepared
            && dump.leases.iter().all(|lease| lease.owner == harness.fixture.ids.source_node),
        format!("phase={:?}, leases={:?}", repeated.canonical_phase, dump.leases),
    )?;
    abort_precommit_to_source(harness, "precommit-crash-retry-aborts-to-source")
}

pub(super) fn run_duplicate_prepare(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let first = harness.prepare_destination()?;
    let second = harness.prepare_destination()?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "duplicate-prepare-remains-inactive",
        first.state_digest == second.state_digest
            && first.journal_position == second.journal_position
            && dump.leases.iter().all(|lease| lease.owner == harness.fixture.ids.source_node),
        format!("first={first:?}, second={second:?}, leases={:?}", dump.leases),
    )?;
    abort_precommit_to_source(harness, "duplicate-prepare-aborts-to-source")
}

pub(super) fn run_source_commit_race(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let mut destination = harness.destination.take().expect("destination worker is present");
    let commit = thread::spawn(move || {
        let result = destination.request_success(WorkerCommand::CommitDestination);
        (destination, result)
    });
    let source_response = harness.source_mut().request(WorkerCommand::StaleSourceKvProbe);
    let (destination, commit_result) = commit.join().map_err(|_| RunnerError::Assertion {
        case_id: harness.definition.id.to_owned(),
        detail: "destination commit thread panicked".to_owned(),
    })?;
    harness.destination = Some(destination);
    let commit_view = state_result(
        harness.definition.id,
        commit_result.map_err(|source| harness.worker_error("destination", source))?,
    )?;
    let source_precommit_admitted =
        match source_response.map_err(|source| harness.worker_error("source", source))? {
            ResponseEnvelope { outcome: ResponseOutcome::Success { result }, .. } => {
                matches!(result.as_ref(), WorkerResult::State { .. })
            }
            ResponseEnvelope { outcome: ResponseOutcome::Error { error }, .. } => {
                harness.observe(
                    "racing-source-lease-probe-lost-to-commit",
                    error.code == WorkerErrorCode::Provider
                        && error.provider_kind.as_deref() == Some("StaleEpoch"),
                    format!("stale_source_kv_probe_error={error:?}"),
                )?;
                false
            }
        };
    harness.latest_destination = Some(commit_view.clone());
    harness.observe(
        "commit-race-selected-destination-epoch",
        commit_view.canonical_phase == contract_core::HandoffPhase::Committed,
        format!(
            "phase={:?}, source_precommit_admitted={source_precommit_admitted}",
            commit_view.canonical_phase
        ),
    )?;
    assert_post_commit_source_rejected(harness)?;
    harness.resume_destination()?;
    Ok(())
}

pub(super) fn run_crash_after_commit(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let committed = harness.commit_destination()?;
    harness
        .destination_mut()
        .crash_and_expect_exit(CrashMode::Immediate, 43, WORKER_TIMEOUT)
        .map_err(|source| harness.worker_error("destination", source))?;
    assert_post_commit_source_rejected(harness)?;
    harness.restart_destination("destination-recovery-after-commit")?;
    let recovered = harness.load_destination(&[contract_core::HandoffPhase::Committed])?;
    harness.observe(
        "postcommit-crash-requires-destination-recovery",
        recovered.canonical_phase == contract_core::HandoffPhase::Committed
            && recovered.state_digest == committed.state_digest,
        format!("committed={:?}, recovered={:?}", committed.state_digest, recovered.state_digest),
    )
}

pub(super) fn run_duplicate_restore(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    run_pending_handoff(harness, false)?;
    let expected = harness
        .latest_destination
        .as_ref()
        .expect("normal handoff records destination state")
        .state_digest;
    harness.restart_destination("duplicate-destination")?;
    let replayed = harness.load_destination(&[contract_core::HandoffPhase::Running])?;
    let error = harness.destination_startup_rejection(WorkerCommand::ResumeDestination)?;
    harness.observe(
        "duplicate-restore-cannot-reactivate",
        replayed.state_digest == expected && error.code == WorkerErrorCode::InvalidState,
        format!("replayed={:?}, error={error:?}", replayed.state_digest),
    )
}

pub(super) fn run_repeated_cleanup(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::CancelPending)?;
    let transfer = harness.freeze()?;
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
        "cancel-cleanup-idempotent-after-export",
        first_cleanup.state_digest == second_cleanup.state_digest
            && first_cleanup.journal_position == second_cleanup.journal_position,
        format!("first={first_cleanup:?}, second={second_cleanup:?}"),
    )?;
    let first_abort =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    let second_abort =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    harness.observe(
        "abort-cleanup-idempotent",
        first_abort.state_digest == second_abort.state_digest
            && first_abort.journal_position == second_abort.journal_position,
        format!("first={first_abort:?}, second={second_abort:?}"),
    )?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "cleanup-does-not-resurrect-timer-or-destination",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && matches!(
                dump.canonical_state.timer.status,
                contract_core::TimerStatus::Cancelled | contract_core::TimerStatus::Cleaned
            ),
        format!(
            "phase={:?}, owner={:?}, timer={:?}",
            resumed.canonical_phase,
            dump.canonical_state.ownership.owner,
            dump.canonical_state.timer.status
        ),
    )
}

pub(super) fn run_report_failure(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    run_pending_handoff(harness, false)
}
