use std::collections::BTreeSet;

use super::{
    super::{
        RunnerError, WorkerClient,
        harness::{CaseDatabase, CaseHarness, DumpData},
        registry::STAGE1_PROVIDER_FAULT_COVERAGE,
        support::{WorkerInitialization, archive_client, spawn_initialized, state_result},
    },
    common::abort_precommit_to_source,
};
use crate::{
    fixture::{FixtureOptions, FixtureSpec},
    protocol::{
        AdapterFailureKindView, FaultObservationView, FaultPointSpec, ResponseEnvelope,
        ResponseOutcome, WorkerCommand, WorkerError, WorkerErrorCode, WorkerRole,
        WorkloadFailureKindView, WorkloadPhaseView,
    },
};

pub(super) fn run_supplemental_fault_coverage(
    harness: &mut CaseHarness,
) -> Result<(), RunnerError> {
    run_before_activation_fault(harness)?;
    run_after_activation_fault(harness)?;
    run_before_journal_fault(harness)?;
    run_after_journal_fault(harness)?;

    let points = STAGE1_PROVIDER_FAULT_COVERAGE
        .iter()
        .map(|entry| format!("{:?}", entry.point))
        .collect::<BTreeSet<_>>();
    harness.observe(
        "all-provider-fault-points-have-system-scenarios",
        STAGE1_PROVIDER_FAULT_COVERAGE.len() == 7 && points.len() == 7,
        format!("coverage={STAGE1_PROVIDER_FAULT_COVERAGE:?}"),
    )
}

fn run_before_activation_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-before-activation-bundle",
        FaultPointSpec::BeforeActivationBundle,
    )?;
    let initial = supplemental_dump(&case_id, &mut source)?;
    let response = source
        .request(WorkerCommand::BootstrapSource)
        .map_err(|source| harness.worker_error("supplemental-source", source))?;
    let error = supplemental_rejection(harness, &case_id, response)?;
    let rejected = supplemental_dump(&case_id, &mut source)?;
    harness.observe(
        "before-activation-bundle-rolls-back-atomically",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Unavailable")
            && rejected.canonical_state.phase == contract_core::HandoffPhase::Dormant
            && rejected.state_digest == initial.state_digest
            && rejected.journal.is_empty()
            && rejected.leases.is_empty()
            && fault_fired(&rejected, FaultPointSpec::BeforeActivationBundle),
        format!(
            "error={error:?}, phase={:?}, journal={}, leases={:?}, fault={:?}",
            rejected.canonical_state.phase,
            rejected.journal.len(),
            rejected.leases,
            rejected.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.launchers,
        &case_id,
        WorkerInitialization::new(
            "supplemental-source-retry",
            WorkerRole::Source,
            harness.source_runtime,
            database.path(),
            &fixture.options,
        ),
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let running = state_result(
        &case_id,
        recovered
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "before-activation-bundle-retries-from-durable-dormant-state",
        replay.state_digest == rejected.state_digest
            && running.canonical_phase == contract_core::HandoffPhase::Running
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            }),
        format!(
            "replay={:?}, running={:?}, leases={:?}",
            replay.state_digest, running.canonical_phase, committed.leases
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_after_activation_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-after-activation-bundle",
        FaultPointSpec::AfterActivationBundle,
    )?;
    let running = state_result(
        &case_id,
        source
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut source)?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.launchers,
        &case_id,
        WorkerInitialization::new(
            "supplemental-source-recovery",
            WorkerRole::Source,
            harness.source_runtime,
            database.path(),
            &fixture.options,
        ),
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "after-activation-bundle-lost-ack-is-reconciled",
        running.canonical_phase == contract_core::HandoffPhase::Running
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && committed.state_digest == replay.state_digest
            && committed.journal == replay.journal
            && fault_fired(&committed, FaultPointSpec::AfterActivationBundle),
        format!(
            "phase={:?}, live={:?}, replay={:?}, leases={:?}, fault={:?}",
            running.canonical_phase,
            committed.state_digest,
            replay.state_digest,
            committed.leases,
            committed.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_before_journal_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-before-journal-write",
        FaultPointSpec::BeforeJournalWrite,
    )?;
    let response = source
        .request(WorkerCommand::BootstrapSource)
        .map_err(|source| harness.worker_error("supplemental-source", source))?;
    let error = supplemental_rejection(harness, &case_id, response)?;
    let rejected = supplemental_dump(&case_id, &mut source)?;
    let only_activation = rejected.journal.len() == 1
        && matches!(&rejected.journal[0].event.kind, contract_core::EventKind::Activated { .. });
    let explicit_unavailable = (error.code == WorkerErrorCode::Provider
        && error.provider_kind.as_deref() == Some("Unavailable"))
        || (error.code == WorkerErrorCode::Adapter
            && error.adapter_kind == Some(AdapterFailureKindView::Workload)
            && error.workload_kind == Some(WorkloadFailureKindView::KeyValueUnavailable));
    harness.observe(
        "before-journal-write-leaves-no-partial-effect-entry",
        explicit_unavailable
            && rejected.canonical_state.phase == contract_core::HandoffPhase::Running
            && only_activation
            && rejected.leases.len() == 2
            && rejected.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && fault_fired(&rejected, FaultPointSpec::BeforeJournalWrite),
        format!(
            "error={error:?}, phase={:?}, journal={:?}, leases={:?}, fault={:?}",
            rejected.canonical_state.phase,
            rejected.journal,
            rejected.leases,
            rejected.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.launchers,
        &case_id,
        WorkerInitialization::new(
            "supplemental-source-retry",
            WorkerRole::Source,
            harness.source_runtime,
            database.path(),
            &fixture.options,
        ),
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let retried = state_result(
        &case_id,
        recovered
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let completed = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "before-journal-write-retry-starts-at-durable-cursor",
        replay.state_digest == rejected.state_digest
            && replay.journal == rejected.journal
            && retried.canonical_phase == contract_core::HandoffPhase::Running
            && completed.journal.len() > replay.journal.len()
            && retried.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            }),
        format!(
            "replay_entries={}, completed_entries={}, component={:?}",
            replay.journal.len(),
            completed.journal.len(),
            retried.component
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_after_journal_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-after-journal-write",
        FaultPointSpec::AfterJournalWrite,
    )?;
    let running = state_result(
        &case_id,
        source
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut source)?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.launchers,
        &case_id,
        WorkerInitialization::new(
            "supplemental-source-recovery",
            WorkerRole::Source,
            harness.source_runtime,
            database.path(),
            &fixture.options,
        ),
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let positions = replay.journal.iter().map(|entry| entry.position).collect::<BTreeSet<_>>();
    harness.observe(
        "after-journal-write-lost-ack-is-reconciled",
        running.canonical_phase == contract_core::HandoffPhase::Running
            && running.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            })
            && committed.state_digest == replay.state_digest
            && committed.journal == replay.journal
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && positions.len() == replay.journal.len()
            && fault_fired(&committed, FaultPointSpec::AfterJournalWrite),
        format!(
            "live={:?}, replay={:?}, entries={}, unique_positions={}, fault={:?}",
            committed.state_digest,
            replay.state_digest,
            replay.journal.len(),
            positions.len(),
            committed.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn supplemental_source_worker(
    harness: &CaseHarness,
    suffix: &str,
    fault: FaultPointSpec,
) -> Result<(String, FixtureSpec, CaseDatabase, WorkerClient), RunnerError> {
    let case_id = format!("{}-{suffix}", harness.definition.id);
    let options = FixtureOptions::new(case_id.clone());
    let fixture = FixtureSpec::with_options(options).map_err(|error| RunnerError::Fixture {
        case_id: case_id.clone(),
        detail: error.to_string(),
    })?;
    let database = CaseDatabase::new(&harness.work_root, &case_id)?;
    let source = spawn_initialized(
        &harness.launchers,
        &case_id,
        WorkerInitialization::new(
            "supplemental-source",
            WorkerRole::Source,
            harness.source_runtime,
            database.path(),
            &fixture.options,
        )
        .with_fault(Some(fault)),
    )?;
    Ok((case_id, fixture, database, source))
}

fn supplemental_dump(case_id: &str, source: &mut WorkerClient) -> Result<DumpData, RunnerError> {
    let result = source.request_success(WorkerCommand::Dump).map_err(|source| {
        RunnerError::Worker { case_id: case_id.to_owned(), role: "supplemental-source", source }
    })?;
    DumpData::from_result(case_id, result)
}

pub(super) fn fault_fired(dump: &DumpData, point: FaultPointSpec) -> bool {
    dump.fault_observation == Some(FaultObservationView { point, count: 1 })
}

fn supplemental_rejection(
    harness: &CaseHarness,
    case_id: &str,
    response: ResponseEnvelope,
) -> Result<WorkerError, RunnerError> {
    match response.outcome {
        ResponseOutcome::Error { error } => Ok(error),
        ResponseOutcome::Success { result } => Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("supplemental case {case_id} unexpectedly succeeded with {result:?}"),
        }),
    }
}

fn archive_supplemental_source(
    harness: &mut CaseHarness,
    source: WorkerClient,
) -> Result<(), RunnerError> {
    harness.source_transcripts.push(archive_client(&source)?);
    drop(source);
    Ok(())
}

pub(super) fn run_unknown_kv_reconciliation(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    let dump = harness.dump_source()?;
    let reconciled = dump
        .journal
        .iter()
        .any(|entry| matches!(entry.event.kind, contract_core::EventKind::EffectReconciled { .. }));
    harness.observe(
        "unknown-kv-outcome-reconciled",
        reconciled
            && dump.canonical_state.key_value.last_version == Some(1)
            && fault_fired(&dump, FaultPointSpec::AfterKvCommit),
        format!(
            "reconciled={reconciled}, version={:?}, fault={:?}",
            dump.canonical_state.key_value.last_version, dump.fault_observation
        ),
    )?;
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    harness.export(transfer)?;
    harness.normal_commit()?;
    harness.deliver_pending_timer()
}

pub(super) fn run_durable_write_failure(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let error = harness.destination_rejection(WorkerCommand::CommitDestination)?;
    harness.observe(
        "failed-durable-commit-not-reported",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Unavailable"),
        format!("error={error:?}"),
    )?;
    let destination =
        state_result(harness.definition.id, harness.destination_success(WorkerCommand::Read)?)?;
    let destination_dump = harness.dump_destination()?;
    harness.observe(
        "failed-commit-remains-precommit",
        destination.canonical_phase == contract_core::HandoffPhase::DestinationPrepared
            && !destination.component_instantiated
            && fault_fired(&destination_dump, FaultPointSpec::BeforeCommitBundle),
        format!(
            "phase={:?}, component_instantiated={}, fault={:?}",
            destination.canonical_phase,
            destination.component_instantiated,
            destination_dump.fault_observation
        ),
    )?;
    abort_precommit_to_source(harness, "failed-commit-aborts-to-source")
}
