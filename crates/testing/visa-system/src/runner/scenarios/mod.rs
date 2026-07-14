use visa_conformance::Stage1CaseOutcome;

use super::{
    RunnerError,
    harness::CaseHarness,
    registry::{CaseKind, case_kind},
};
use crate::protocol::FaultPointSpec;

mod common;
mod provider_faults;
mod recovery;
mod rejections;
mod success;

use common::{assert_post_commit_source_rejected, run_pending_handoff};
use provider_faults::{
    fault_fired, run_durable_write_failure, run_supplemental_fault_coverage,
    run_unknown_kv_reconciliation,
};
use recovery::{
    run_crash_after_commit, run_crash_before_commit, run_duplicate_prepare, run_duplicate_restore,
    run_repeated_cleanup, run_report_failure, run_source_commit_race,
};
use rejections::{
    ValidationFailure, run_live_resource_rejection, run_prepare_rejection, run_revoked_capability,
    run_safe_point_unavailable, run_snapshot_validation_rejection,
};
use success::{
    assert_broader_policy_input, assert_duplicate_kv_replay, assert_evidence_identities,
    assert_narrow_destination_authority, run_cancelled_timer_handoff, run_completed_timer_handoff,
    run_handoff_with_precompleted_timer, run_performance_case, run_repeated_validation_prepare,
};

pub(super) fn execute_case(harness: &mut CaseHarness) -> Result<Stage1CaseOutcome, RunnerError> {
    use Stage1CaseOutcome::{
        AuthorityRejectedBeforeExecution, BindingRejectedNoSubstitution,
        CancelledTimerCleanedNotRecreated, CleanupIdempotentNoResurrection,
        CompletedTimerNotRecreated, DuplicateActivationRejected, DuplicateKvAppliedOnce,
        DuplicatePrepareInactive, DurableDestinationOwnerSelected, DurableWriteAbortedBeforeCommit,
        EvidenceIdentityVerified, EvidenceRegeneratedWithoutStateChange, ExcessAuthorityAttenuated,
        FreezeRejectedNoSnapshot, PreCommitPreparationRetried, PrepareIdempotentInactive,
        ProfileRejectedWithoutDowngrade, RawPerformanceRecorded, ReplayDigestMatched,
        RestoredWithNarrowerAuthority, RevocationRejectedNoResurrection,
        SafePointRejectedSourceRetained, SingleLeaseEpochAccepted, SnapshotRejectedBeforeBindings,
        SourceFencedRecoveryRequired, StaleSourceRejected, TimerPausedThenResumed,
        TimerRecreatedSingleExpiry, TimerSemanticsRejected, UnknownKvReconciled,
        VersionRejectedBeforeBindings,
    };
    match case_kind(harness.definition.id).expect("case registry was checked") {
        CaseKind::TimerPositive => {
            run_pending_handoff(harness, false)?;
            Ok(TimerRecreatedSingleExpiry)
        }
        CaseKind::TimerPaused => {
            run_pending_handoff(harness, true)?;
            Ok(TimerPausedThenResumed)
        }
        CaseKind::TimerCompleted => {
            run_completed_timer_handoff(harness)?;
            Ok(CompletedTimerNotRecreated)
        }
        CaseKind::TimerCancelled => {
            run_cancelled_timer_handoff(harness)?;
            Ok(CancelledTimerCleanedNotRecreated)
        }
        CaseKind::AuthorityNarrower => {
            run_pending_handoff(harness, false)?;
            assert_narrow_destination_authority(harness)?;
            Ok(RestoredWithNarrowerAuthority)
        }
        CaseKind::KvDuplicate => {
            // This case proves operation replay, not timer-pending behavior.
            // Complete the timer before handoff so slow or descheduled hosts
            // cannot change the case's semantic branch between matrix cells.
            run_handoff_with_precompleted_timer(harness)?;
            assert_duplicate_kv_replay(harness)?;
            Ok(DuplicateKvAppliedOnce)
        }
        CaseKind::RepeatedValidationPrepare => {
            run_repeated_validation_prepare(harness)?;
            Ok(PrepareIdempotentInactive)
        }
        CaseKind::JournalReplay => {
            run_pending_handoff(harness, false)?;
            Ok(ReplayDigestMatched)
        }
        CaseKind::StaleSource => {
            run_pending_handoff(harness, false)?;
            assert_post_commit_source_rejected(harness)?;
            Ok(StaleSourceRejected)
        }
        CaseKind::EvidenceVerification => {
            run_pending_handoff(harness, false)?;
            assert_evidence_identities(harness)?;
            run_supplemental_fault_coverage(harness)?;
            Ok(EvidenceIdentityVerified)
        }
        CaseKind::Performance => {
            run_performance_case(harness)?;
            Ok(RawPerformanceRecorded)
        }
        CaseKind::SafePointUnreachable => {
            run_safe_point_unavailable(harness)?;
            Ok(SafePointRejectedSourceRetained)
        }
        CaseKind::UnsupportedLiveResource => {
            run_live_resource_rejection(harness)?;
            Ok(FreezeRejectedNoSnapshot)
        }
        CaseKind::KvUnknown => {
            run_unknown_kv_reconciliation(harness)?;
            Ok(UnknownKvReconciled)
        }
        CaseKind::CorruptSnapshot => {
            run_snapshot_validation_rejection(harness, ValidationFailure::CorruptSnapshot)?;
            Ok(SnapshotRejectedBeforeBindings)
        }
        CaseKind::IncompatibleVersion => {
            run_snapshot_validation_rejection(harness, ValidationFailure::Version)?;
            Ok(VersionRejectedBeforeBindings)
        }
        CaseKind::ProfileMismatch => {
            run_snapshot_validation_rejection(harness, ValidationFailure::Profile)?;
            Ok(ProfileRejectedWithoutDowngrade)
        }
        CaseKind::MissingAuthority => {
            run_prepare_rejection(harness, "Denied")?;
            Ok(AuthorityRejectedBeforeExecution)
        }
        CaseKind::RevokedCapability => {
            run_revoked_capability(harness)?;
            Ok(RevocationRejectedNoResurrection)
        }
        CaseKind::BroaderAuthority => {
            run_pending_handoff(harness, false)?;
            assert_broader_policy_input(harness)?;
            assert_narrow_destination_authority(harness)?;
            Ok(ExcessAuthorityAttenuated)
        }
        CaseKind::MissingNamespace => {
            run_prepare_rejection(harness, "NotFound")?;
            Ok(BindingRejectedNoSubstitution)
        }
        CaseKind::TimerUnsupported => {
            run_snapshot_validation_rejection(harness, ValidationFailure::TimerSupport)?;
            Ok(TimerSemanticsRejected)
        }
        CaseKind::CrashBeforeCommit => {
            run_crash_before_commit(harness)?;
            Ok(PreCommitPreparationRetried)
        }
        CaseKind::DuplicatePrepare => {
            run_duplicate_prepare(harness)?;
            Ok(DuplicatePrepareInactive)
        }
        CaseKind::LostCommitAck => {
            // This case proves durable commit reconciliation, not timer-pending
            // behavior. Select the completed branch before the fault window so
            // host descheduling cannot change its semantics between cells.
            run_handoff_with_precompleted_timer(harness)?;
            let dump = harness.dump_destination()?;
            harness.observe(
                "lost-commit-ack-reconciled",
                harness.latest_destination.as_ref().is_some_and(|view| {
                    view.canonical_phase == contract_core::HandoffPhase::Running
                }) && fault_fired(&dump, FaultPointSpec::AfterCommitBundle),
                format!(
                    "AfterCommitBundle resolved to durable destination truth; fault={:?}",
                    dump.fault_observation
                ),
            )?;
            Ok(DurableDestinationOwnerSelected)
        }
        CaseKind::SourceCommitRace => {
            run_source_commit_race(harness)?;
            Ok(SingleLeaseEpochAccepted)
        }
        CaseKind::CrashAfterCommit => {
            run_crash_after_commit(harness)?;
            Ok(SourceFencedRecoveryRequired)
        }
        CaseKind::DuplicateRestore => {
            run_duplicate_restore(harness)?;
            Ok(DuplicateActivationRejected)
        }
        CaseKind::RepeatedCleanup => {
            run_repeated_cleanup(harness)?;
            Ok(CleanupIdempotentNoResurrection)
        }
        CaseKind::DurableWriteFailure => {
            run_durable_write_failure(harness)?;
            Ok(DurableWriteAbortedBeforeCommit)
        }
        CaseKind::ReportFailure => {
            run_report_failure(harness)?;
            Ok(EvidenceRegeneratedWithoutStateChange)
        }
    }
}
