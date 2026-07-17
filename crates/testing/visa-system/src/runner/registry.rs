use std::collections::BTreeSet;

use serde::Serialize;
use visa_conformance::{
    STAGE1_CASE_DEFINITIONS, Stage1CaseClass, Stage1CaseDefinition, Stage1FaultInjection,
    Stage1FaultSchedule, Stage2SnapshotTimerStrategy, stage2_snapshot_timer_strategy,
};
use visa_runtime::{canonical_bytes, canonical_digest};

use super::RunnerError;
use crate::{
    fixture::{AuthorityPolicyMode, FixtureOptions, FixtureSpec, NamespaceAvailability},
    protocol::{DestinationSupportMode, FaultPointSpec},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct FaultCoverageManifestEntry {
    pub(super) point: FaultPointSpec,
    pub(super) case_id: &'static str,
    pub(super) role: &'static str,
    pub(super) trigger: &'static str,
    pub(super) expected: &'static str,
}

pub(super) const STAGE1_PROVIDER_FAULT_COVERAGE: &[FaultCoverageManifestEntry] = &[
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeJournalWrite,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "first component effect journal intent",
        expected: "write rejected before persistence; restart retries from durable activation",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterJournalWrite,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "first component effect journal intent",
        expected: "lost acknowledgement reconciled against the durable journal",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeActivationBundle,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "source activation bundle",
        expected: "activation and initial leases remain absent before retry",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterActivationBundle,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "source activation bundle",
        expected: "lost acknowledgement reconciled against journal and both leases",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeCommitBundle,
        case_id: "durable-journal-or-commit-write-fails",
        role: "destination",
        trigger: "handoff commit bundle",
        expected: "commit rejected and source resumed under the old epoch",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterCommitBundle,
        case_id: "commit-acknowledgement-lost",
        role: "destination",
        trigger: "handoff commit bundle",
        expected: "lost acknowledgement reconciled to durable destination ownership",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterKvCommit,
        case_id: "kv-unknown-outcome",
        role: "source",
        trigger: "key-value compare-and-set",
        expected: "operation identity reconciles the committed provider outcome",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaseKind {
    TimerPositive,
    TimerPaused,
    TimerCompleted,
    TimerCancelled,
    AuthorityNarrower,
    KvDuplicate,
    RepeatedValidationPrepare,
    JournalReplay,
    StaleSource,
    EvidenceVerification,
    Performance,
    SafePointUnreachable,
    UnsupportedLiveResource,
    KvUnknown,
    CorruptSnapshot,
    IncompatibleVersion,
    ProfileMismatch,
    MissingAuthority,
    RevokedCapability,
    BroaderAuthority,
    MissingNamespace,
    TimerUnsupported,
    CrashBeforeCommit,
    DuplicatePrepare,
    LostCommitAck,
    SourceCommitRace,
    CrashAfterCommit,
    DuplicateRestore,
    RepeatedCleanup,
    DurableWriteFailure,
    ReportFailure,
}

pub(super) fn case_kind(case_id: &str) -> Option<CaseKind> {
    Some(match case_id {
        "timer-positive-duration-at-freeze" => CaseKind::TimerPositive,
        "timer-paused-during-long-handoff" => CaseKind::TimerPaused,
        "timer-completes-during-quiescence" => CaseKind::TimerCompleted,
        "timer-cancelled-during-quiescence" => CaseKind::TimerCancelled,
        "authority-sufficient-narrower" => CaseKind::AuthorityNarrower,
        "kv-duplicate-idempotent-request" => CaseKind::KvDuplicate,
        "handoff-repeated-validation-prepare" => CaseKind::RepeatedValidationPrepare,
        "journal-replay" => CaseKind::JournalReplay,
        "source-post-commit-stale-attempt" => CaseKind::StaleSource,
        "evidence-verification" => CaseKind::EvidenceVerification,
        "performance-observations" => CaseKind::Performance,
        "safe-point-unreachable" => CaseKind::SafePointUnreachable,
        "unsupported-live-resource-or-borrow" => CaseKind::UnsupportedLiveResource,
        "kv-unknown-outcome" => CaseKind::KvUnknown,
        "corrupt-snapshot-or-component-digest" => CaseKind::CorruptSnapshot,
        "incompatible-snapshot-or-profile-version" => CaseKind::IncompatibleVersion,
        "unknown-extension-or-profile-mismatch" => CaseKind::ProfileMismatch,
        "destination-authority-missing-or-insufficient" => CaseKind::MissingAuthority,
        "required-capability-revoked" => CaseKind::RevokedCapability,
        "adapter-broader-authority" => CaseKind::BroaderAuthority,
        "kv-binding-wrong-or-missing" => CaseKind::MissingNamespace,
        "timer-semantics-unsupported" => CaseKind::TimerUnsupported,
        "destination-crash-before-commit" => CaseKind::CrashBeforeCommit,
        "prepare-message-duplicate-or-lost" => CaseKind::DuplicatePrepare,
        "commit-acknowledgement-lost" => CaseKind::LostCommitAck,
        "source-races-with-commit" => CaseKind::SourceCommitRace,
        "destination-crash-after-commit" => CaseKind::CrashAfterCommit,
        "duplicate-restore-or-stale-snapshot" => CaseKind::DuplicateRestore,
        "repeated-cancel-abort-cleanup" => CaseKind::RepeatedCleanup,
        "durable-journal-or-commit-write-fails" => CaseKind::DurableWriteFailure,
        "report-generation-fails-after-commit" => CaseKind::ReportFailure,
        _ => return None,
    })
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct CasePlan {
    pub(super) case_id: String,
    pub(super) options: FixtureOptions,
    pub(super) source_fault: Option<FaultPointSpec>,
    pub(super) destination_fault: Option<FaultPointSpec>,
    pub(super) destination_support: DestinationSupportMode,
    pub(super) snapshot_timer_strategy: Stage2SnapshotTimerStrategy,
    pub(super) scenario: String,
}

impl CasePlan {
    pub(super) fn new(definition: &Stage1CaseDefinition) -> Result<Self, RunnerError> {
        let kind = case_kind(definition.id).ok_or_else(|| RunnerError::Registry {
            detail: format!("{} has no executable scenario", definition.id),
        })?;
        let mut options = FixtureOptions::new(definition.id);
        let mut source_fault = None;
        let mut destination_fault = None;
        let mut destination_support = DestinationSupportMode::Compatible;
        let snapshot_timer_strategy =
            stage2_snapshot_timer_strategy(definition.id).ok_or_else(|| RunnerError::Registry {
                detail: format!("{} has no snapshot timer strategy", definition.id),
            })?;
        match kind {
            CaseKind::KvUnknown => source_fault = Some(FaultPointSpec::AfterKvCommit),
            CaseKind::MissingAuthority => {
                options.authority_policy = AuthorityPolicyMode::Missing;
            }
            CaseKind::BroaderAuthority => {
                options.authority_policy = AuthorityPolicyMode::Broader;
            }
            CaseKind::MissingNamespace => {
                options.namespace_availability = NamespaceAvailability::Missing;
            }
            CaseKind::TimerUnsupported => {
                destination_support = DestinationSupportMode::TimerSemanticsUnsupported;
            }
            CaseKind::LostCommitAck => {
                destination_fault = Some(FaultPointSpec::AfterCommitBundle);
            }
            CaseKind::DurableWriteFailure => {
                destination_fault = Some(FaultPointSpec::BeforeCommitBundle);
            }
            _ => {}
        }
        Ok(Self {
            case_id: definition.id.to_owned(),
            options,
            source_fault,
            destination_fault,
            destination_support,
            snapshot_timer_strategy,
            scenario: format!("{kind:?}/timer={snapshot_timer_strategy:?}"),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MatrixEntry {
    pub(super) case_id: String,
    pub(super) options: FixtureOptions,
    pub(super) config_digest: contract_core::Digest,
    pub(super) policy_digest: contract_core::Digest,
    pub(super) source_fault: Option<FaultPointSpec>,
    pub(super) destination_fault: Option<FaultPointSpec>,
    pub(super) destination_support: DestinationSupportMode,
    pub(super) scenario: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MatrixManifest {
    pub(super) schema: &'static str,
    pub(super) entries: Vec<MatrixEntry>,
    pub(super) provider_fault_coverage: Vec<FaultCoverageManifestEntry>,
}

pub(super) struct PreparedAuthorityPolicyCase {
    pub(super) case_id: String,
    pub(super) policy_digest: contract_core::Digest,
    pub(super) canonical_bytes: Vec<u8>,
}

pub(super) struct PreparedStage1Registry {
    pub(super) plans: Vec<CasePlan>,
    pub(super) manifest: MatrixManifest,
    pub(super) authority_policy_cases: Vec<PreparedAuthorityPolicyCase>,
    pub(super) config_digest: contract_core::Digest,
    pub(super) policy_digest: contract_core::Digest,
}

pub(super) fn prepare_stage1_registry() -> Result<PreparedStage1Registry, RunnerError> {
    let mut plans = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut matrix_entries = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut policy_entries = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut seen = BTreeSet::new();
    for definition in STAGE1_CASE_DEFINITIONS {
        if !seen.insert(definition.id) {
            return Err(RunnerError::Registry {
                detail: format!("duplicate case id {}", definition.id),
            });
        }
        let plan = CasePlan::new(definition)?;
        let fixture = FixtureSpec::with_options(plan.options.clone()).map_err(|error| {
            RunnerError::Fixture { case_id: definition.id.to_owned(), detail: error.to_string() }
        })?;
        let config_digest = fixture.config_digest().map_err(|error| RunnerError::Fixture {
            case_id: definition.id.to_owned(),
            detail: error.to_string(),
        })?;
        let policy_digest = fixture.policy_digest().map_err(|error| RunnerError::Fixture {
            case_id: definition.id.to_owned(),
            detail: error.to_string(),
        })?;
        matrix_entries.push(MatrixEntry {
            case_id: plan.case_id.clone(),
            options: plan.options.clone(),
            config_digest,
            policy_digest,
            source_fault: plan.source_fault,
            destination_fault: plan.destination_fault,
            destination_support: plan.destination_support,
            scenario: plan.scenario.clone(),
        });
        let canonical_policy_bytes =
            canonical_bytes(&fixture.policy_digest_input).map_err(|_| RunnerError::Registry {
                detail: format!("cannot encode authority policy for {}", definition.id),
            })?;
        policy_entries.push(PreparedAuthorityPolicyCase {
            case_id: plan.case_id.clone(),
            policy_digest,
            canonical_bytes: canonical_policy_bytes,
        });
        plans.push(plan);
    }

    let config_projection = matrix_entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                &entry.options,
                entry.config_digest,
                entry.source_fault,
                entry.destination_fault,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let policy_projection = matrix_entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                entry.policy_digest,
                entry.options.authority_policy,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let provider_fault_coverage = STAGE1_PROVIDER_FAULT_COVERAGE.to_vec();
    let config_digest =
        canonical_digest(&(config_projection, &provider_fault_coverage)).map_err(|_| {
            RunnerError::Registry { detail: "cannot encode Stage 1 config matrix".to_owned() }
        })?;
    let policy_digest = canonical_digest(&policy_projection).map_err(|_| {
        RunnerError::Registry { detail: "cannot encode Stage 1 policy matrix".to_owned() }
    })?;

    Ok(PreparedStage1Registry {
        plans,
        manifest: MatrixManifest {
            schema: visa_conformance::STAGE1_MATRIX_SCHEMA_VERSION,
            entries: matrix_entries,
            provider_fault_coverage,
        },
        authority_policy_cases: policy_entries,
        config_digest,
        policy_digest,
    })
}

pub(super) fn fault_schedule(
    definition: &Stage1CaseDefinition,
    plan: &CasePlan,
) -> Stage1FaultSchedule {
    match definition.class {
        Stage1CaseClass::Acceptance => {
            Stage1FaultSchedule { schedule_id: "none".to_owned(), injections: Vec::new() }
        }
        Stage1CaseClass::FailureRecovery => Stage1FaultSchedule {
            schedule_id: format!("execute-{}", definition.id),
            injections: vec![Stage1FaultInjection {
                transition: definition.id.to_owned(),
                action: format!(
                    "scenario={};source_fault={:?};destination_fault={:?};support={:?}",
                    plan.scenario,
                    plan.source_fault,
                    plan.destination_fault,
                    plan.destination_support
                ),
            }],
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::runner::WORKER_TIMEOUT;

    const SAFE_POINT_FINAL_EVIDENCE_REQUESTS: u32 = 8;
    const LIVE_RESOURCE_FINAL_EVIDENCE_REQUESTS: u32 = 11;
    const TIMER_UNSUPPORTED_PRE_FREEZE_REQUESTS: u32 = 3;

    #[test]
    fn every_stage1_case_has_one_executable_fixture_plan() {
        assert_eq!(STAGE1_CASE_DEFINITIONS.len(), 31);

        let mut case_ids = BTreeSet::new();
        for definition in STAGE1_CASE_DEFINITIONS {
            assert!(case_ids.insert(definition.id), "duplicate case id {}", definition.id);
            assert!(case_kind(definition.id).is_some(), "missing runner for {}", definition.id);

            let plan = CasePlan::new(definition).expect("registered cases have executable plans");
            let fixture = FixtureSpec::with_options(plan.options)
                .expect("registered case plans produce deterministic fixtures");
            fixture.config_digest().expect("fixture config is canonically encodable");
            fixture.policy_digest().expect("fixture policy is canonically encodable");
        }
    }

    #[test]
    fn prepared_registry_preserves_the_exact_stage1_catalog_order() {
        let prepared = prepare_stage1_registry().expect("registry is deterministic");
        assert_eq!(prepared.plans.len(), 31);
        assert_eq!(prepared.manifest.entries.len(), 31);
        assert_eq!(
            prepared
                .manifest
                .entries
                .iter()
                .map(|entry| entry.case_id.as_str())
                .collect::<Vec<_>>(),
            STAGE1_CASE_DEFINITIONS.iter().map(|definition| definition.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_case_has_one_explicit_snapshot_timer_strategy() {
        let pending = BTreeSet::from([
            "timer-positive-duration-at-freeze",
            "timer-paused-during-long-handoff",
            "timer-semantics-unsupported",
        ]);
        let scenario_controlled = BTreeSet::from([
            "timer-completes-during-quiescence",
            "timer-cancelled-during-quiescence",
            "performance-observations",
            "safe-point-unreachable",
            "unsupported-live-resource-or-borrow",
            "repeated-cancel-abort-cleanup",
        ]);
        let precompleted = BTreeSet::from([
            "authority-sufficient-narrower",
            "kv-duplicate-idempotent-request",
            "handoff-repeated-validation-prepare",
            "journal-replay",
            "source-post-commit-stale-attempt",
            "evidence-verification",
            "kv-unknown-outcome",
            "corrupt-snapshot-or-component-digest",
            "incompatible-snapshot-or-profile-version",
            "unknown-extension-or-profile-mismatch",
            "destination-authority-missing-or-insufficient",
            "required-capability-revoked",
            "adapter-broader-authority",
            "kv-binding-wrong-or-missing",
            "destination-crash-before-commit",
            "prepare-message-duplicate-or-lost",
            "commit-acknowledgement-lost",
            "source-races-with-commit",
            "destination-crash-after-commit",
            "duplicate-restore-or-stale-snapshot",
            "durable-journal-or-commit-write-fails",
            "report-generation-fails-after-commit",
        ]);

        assert!(pending.is_disjoint(&scenario_controlled));
        assert!(pending.is_disjoint(&precompleted));
        assert!(scenario_controlled.is_disjoint(&precompleted));
        let catalog =
            STAGE1_CASE_DEFINITIONS.iter().map(|definition| definition.id).collect::<BTreeSet<_>>();
        let partition = pending
            .union(&scenario_controlled)
            .copied()
            .chain(precompleted.iter().copied())
            .collect::<BTreeSet<_>>();
        assert_eq!(partition, catalog);
        let long_delay_cases = STAGE1_CASE_DEFINITIONS
            .iter()
            .filter(|definition| {
                visa_conformance::stage1_timer_delay_ns(definition.id)
                    != visa_conformance::STAGE1_DEFAULT_TIMER_DELAY_NS
            })
            .map(|definition| definition.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            long_delay_cases,
            BTreeSet::from([
                "safe-point-unreachable",
                "timer-semantics-unsupported",
                "unsupported-live-resource-or-borrow",
            ])
        );

        for definition in STAGE1_CASE_DEFINITIONS {
            let plan = CasePlan::new(definition).expect("registered case has a timer strategy");
            let expected = if pending.contains(definition.id) {
                Stage2SnapshotTimerStrategy::Pending
            } else if scenario_controlled.contains(definition.id) {
                Stage2SnapshotTimerStrategy::ScenarioControlled
            } else if precompleted.contains(definition.id) {
                Stage2SnapshotTimerStrategy::Precompleted
            } else {
                panic!("{} is missing from the timer strategy partition", definition.id)
            };
            assert_eq!(plan.snapshot_timer_strategy, expected, "{}", definition.id);
            let expected_timer_delay_ns = visa_conformance::stage1_timer_delay_ns(definition.id);
            assert_eq!(plan.options.timer_delay_ns, expected_timer_delay_ns, "{}", definition.id);
            assert_eq!(
                FixtureSpec::with_options(plan.options.clone())
                    .expect("registered plan has a valid fixture")
                    .activation
                    .delay_ns,
                expected_timer_delay_ns,
                "{}",
                definition.id
            );
            assert!(
                plan.scenario.ends_with(&format!("timer={expected:?}")),
                "timer strategy must be bound into scenario provenance"
            );
        }
    }

    #[test]
    fn timer_delay_is_bound_into_stage1_config_provenance() {
        let mut prepared = prepare_stage1_registry().expect("registry is deterministic");
        let accepted = prepared.config_digest;
        let unsupported = prepared
            .manifest
            .entries
            .iter_mut()
            .find(|entry| entry.case_id == "timer-semantics-unsupported")
            .expect("timer unsupported case is registered");
        unsupported.options.timer_delay_ns -= 1;
        let config_projection = prepared
            .manifest
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.case_id.as_str(),
                    &entry.options,
                    entry.config_digest,
                    entry.source_fault,
                    entry.destination_fault,
                    entry.destination_support,
                    entry.scenario.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let mutated =
            canonical_digest(&(config_projection, &prepared.manifest.provider_fault_coverage))
                .expect("mutated config projection is encodable");
        assert_ne!(mutated, accepted);
    }

    #[test]
    fn long_timer_delays_exceed_the_complete_observation_request_budgets() {
        for (case_id, request_count, expected_budget) in [
            ("safe-point-unreachable", SAFE_POINT_FINAL_EVIDENCE_REQUESTS, 80),
            ("unsupported-live-resource-or-borrow", LIVE_RESOURCE_FINAL_EVIDENCE_REQUESTS, 110),
            ("timer-semantics-unsupported", TIMER_UNSUPPORTED_PRE_FREEZE_REQUESTS, 30),
        ] {
            let bounded_request_budget =
                WORKER_TIMEOUT.checked_mul(request_count).expect("request budget is representable");
            assert_eq!(bounded_request_budget, Duration::from_secs(expected_budget));
            assert!(
                Duration::from_nanos(visa_conformance::stage1_timer_delay_ns(case_id))
                    > bounded_request_budget,
                "{case_id} timer starts inside BootstrapSource, so its delay must exceed every worker request through the final timer-state observation"
            );
        }
    }
}
