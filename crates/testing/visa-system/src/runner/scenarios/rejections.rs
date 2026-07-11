use super::{
    super::{
        RunnerError, artifacts::snapshot_envelope, harness::CaseHarness, support::state_result,
    },
    common::abort_precommit_to_source,
};
use crate::protocol::{
    AdapterFailureKindView, DestinationSupportMode, RequiredAuthority,
    SnapshotExpectationOverrides, WorkerCommand, WorkerErrorCode, WorkloadFailureKindView,
    WorkloadPhaseView,
};

pub(super) fn run_safe_point_unavailable(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    let error = harness.source_rejection(WorkerCommand::FreezeSource)?;
    let timed_out =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    harness.observe(
        "safe-point-unavailable-is-explicit",
        error.code == WorkerErrorCode::Adapter
            && error.adapter_kind == Some(AdapterFailureKindView::Workload)
            && error.workload_kind == Some(WorkloadFailureKindView::SafePointUnavailable)
            && timed_out.canonical_phase == contract_core::HandoffPhase::Quiescing
            && timed_out.component_instantiated
            && timed_out.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            }),
        format!("error={error:?}, state={timed_out:?}"),
    )?;
    harness.source_success(WorkerCommand::AbortSource)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let continued =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "safe-point-unavailable-retains-source",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && continued.canonical_phase == contract_core::HandoffPhase::Running
            && continued.component_instantiated
            && continued.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            })
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.exported_snapshot.is_none(),
        format!(
            "resumed={:?}, continued={continued:?}, ownership={:?}",
            resumed.canonical_phase, dump.canonical_state.ownership
        ),
    )
}

pub(super) fn run_live_resource_rejection(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::InjectUnsupportedLiveResource)?;
    let error = harness.source_rejection(WorkerCommand::FreezeSource)?;
    harness.observe(
        "live-resource-freeze-rejected",
        error.code == WorkerErrorCode::Adapter
            && error.adapter_kind == Some(AdapterFailureKindView::LiveResourcesAtSafePoint),
        format!("error={error:?}"),
    )?;
    let export = harness.source_rejection(WorkerCommand::ExportSourceSnapshot)?;
    harness.observe(
        "rejected-freeze-exports-no-snapshot",
        export.code == WorkerErrorCode::InvalidState,
        format!("error={export:?}"),
    )?;
    harness.source_success(WorkerCommand::ClearUnsupportedLiveResource)?;
    let rolled_back =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    harness.source_success(WorkerCommand::AbortSource)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let continued =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "live-resource-rejection-retains-source",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.exported_snapshot.is_none(),
        format!(
            "resumed={:?}, canonical={:?}, ownership={:?}",
            resumed.canonical_phase, dump.canonical_state.phase, dump.canonical_state.ownership
        ),
    )?;
    harness.observe(
        "live-resource-rejection-rolls-back-guest",
        [rolled_back.component.as_ref(), continued.component.as_ref()].into_iter().all(
            |component| {
                component.is_some_and(|component| {
                    component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
                })
            },
        ),
        format!(
            "after_rejection={:?}, after_resume={:?}",
            rolled_back.component, continued.component
        ),
    )
}

#[derive(Clone, Copy)]
pub(super) enum ValidationFailure {
    CorruptSnapshot,
    Version,
    Profile,
    TimerSupport,
}

pub(super) fn run_snapshot_validation_rejection(
    harness: &mut CaseHarness,
    failure: ValidationFailure,
) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    let mut envelope = snapshot_envelope(harness)?;
    let mut expectations = SnapshotExpectationOverrides::default();
    let mut support = DestinationSupportMode::Compatible;
    match failure {
        ValidationFailure::CorruptSnapshot => {
            envelope.integrity = contract_core::Digest::from_bytes([0xa5; 32]);
        }
        ValidationFailure::Version => {
            expectations.profile_version = Some(contract_core::SchemaVersion::new(u16::MAX, 0));
        }
        ValidationFailure::Profile => {
            expectations.profile_digest = Some(contract_core::Digest::from_bytes([0x5a; 32]));
        }
        ValidationFailure::TimerSupport => {
            support = DestinationSupportMode::TimerSemanticsUnsupported;
        }
    }
    let error = harness.destination_startup_rejection(WorkerCommand::ValidateDestination {
        envelope,
        expectations,
        support,
    })?;
    harness.observe(
        "destination-validation-rejected-before-bindings",
        matches!(error.code, WorkerErrorCode::Runtime | WorkerErrorCode::Adapter),
        format!("error={error:?}"),
    )?;
    let source = harness.dump_source()?;
    harness.observe(
        "validation-rejection-retains-source",
        source.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node),
        format!("ownership={:?}", source.canonical_state.ownership),
    )?;
    abort_precommit_to_source(harness, "validation-rejection-aborts-to-source")
}

pub(super) fn run_prepare_rejection(
    harness: &mut CaseHarness,
    expected_provider: &str,
) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let error = harness.destination_rejection(WorkerCommand::PrepareDestination)?;
    harness.observe(
        "destination-prepare-rejected",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some(expected_provider),
        format!("error={error:?}"),
    )?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "prepare-rejection-created-no-bindings",
        dump.canonical_state.phase == contract_core::HandoffPhase::Exported
            && !dump.component_instantiated
            && dump.component.is_none()
            && dump.binding_receipts.is_empty(),
        format!(
            "phase={:?}, component_instantiated={}, receipts={}",
            dump.canonical_state.phase,
            dump.component_instantiated,
            dump.binding_receipts.len()
        ),
    )?;
    abort_precommit_to_source(harness, "prepare-rejection-aborts-to-source")
}

pub(super) fn run_revoked_capability(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.source_success(WorkerCommand::RevokeRequiredAuthority {
        authority: RequiredAuthority::Timer,
    })?;
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    harness.export(transfer)?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let error = harness.destination_rejection(WorkerCommand::PrepareDestination)?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "revoked-capability-not-resurrected",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Revoked")
            && !dump.component_instantiated
            && dump.component.is_none()
            && dump.binding_receipts.is_empty(),
        format!(
            "error={error:?}, component_instantiated={}, receipts={:?}",
            dump.component_instantiated, dump.binding_receipts
        ),
    )
}
