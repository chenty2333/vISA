use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};

use crate::artifact_io::{SecureArtifactError, SecureArtifactErrorKind, SecureArtifactRoot};

pub const STAGE1_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage1-evidence-v0.4";
pub const STAGE1_WORKER_PROTOCOL_VERSION: u64 = 4;
pub const STAGE1_CAPABILITY_ID: &str = "cooperative-stateful-component-handoff";
pub const STAGE1_DEFAULT_TIMER_DELAY_NS: u64 = 50_000_000;
// The unsupported-timer cell must still present a Pending disposition when
// destination validation rejects its semantics. The visa-system registry test
// keeps this evidence input strictly above the bounded BootstrapSource tail +
// BeginQuiesce + FreezeSource steady-state request budget. Unlike the two
// accepted pending-timer cells, this rejection path never waits for expiry.
pub const STAGE1_TIMER_UNSUPPORTED_DELAY_NS: u64 = 60_000_000_000;
const MAX_STAGE1_RETAINED_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1CaseClass {
    Acceptance,
    FailureRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1CaseOutcome {
    TimerRecreatedSingleExpiry,
    TimerPausedThenResumed,
    CompletedTimerNotRecreated,
    CancelledTimerCleanedNotRecreated,
    RestoredWithNarrowerAuthority,
    DuplicateKvAppliedOnce,
    PrepareIdempotentInactive,
    ReplayDigestMatched,
    StaleSourceRejected,
    EvidenceIdentityVerified,
    RawPerformanceRecorded,
    SafePointRejectedSourceRetained,
    FreezeRejectedNoSnapshot,
    UnknownKvReconciled,
    UnknownKvBlockedIndeterminate,
    SnapshotRejectedBeforeBindings,
    VersionRejectedBeforeBindings,
    ProfileRejectedWithoutDowngrade,
    AuthorityRejectedBeforeExecution,
    RevocationRejectedNoResurrection,
    ExcessAuthorityAttenuated,
    ExcessAuthorityRejected,
    BindingRejectedNoSubstitution,
    TimerSemanticsRejected,
    PreCommitPreparationAborted,
    PreCommitPreparationRetried,
    DuplicatePrepareInactive,
    DurableSourceOwnerSelected,
    DurableDestinationOwnerSelected,
    SingleLeaseEpochAccepted,
    SourceFencedRecoveryRequired,
    DuplicateActivationRejected,
    CleanupIdempotentNoResurrection,
    DurableWriteAbortedBeforeCommit,
    DurableWriteBlockedIndeterminate,
    EvidenceRegeneratedWithoutStateChange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stage1CaseDefinition {
    pub id: &'static str,
    pub class: Stage1CaseClass,
    pub allowed_outcomes: &'static [Stage1CaseOutcome],
}

use Stage1CaseClass::{Acceptance, FailureRecovery};
use Stage1CaseOutcome::*;

pub const STAGE1_CASE_DEFINITIONS: &[Stage1CaseDefinition] = &[
    Stage1CaseDefinition {
        id: "timer-positive-duration-at-freeze",
        class: Acceptance,
        allowed_outcomes: &[TimerRecreatedSingleExpiry],
    },
    Stage1CaseDefinition {
        id: "timer-paused-during-long-handoff",
        class: Acceptance,
        allowed_outcomes: &[TimerPausedThenResumed],
    },
    Stage1CaseDefinition {
        id: "timer-completes-during-quiescence",
        class: Acceptance,
        allowed_outcomes: &[CompletedTimerNotRecreated],
    },
    Stage1CaseDefinition {
        id: "timer-cancelled-during-quiescence",
        class: Acceptance,
        allowed_outcomes: &[CancelledTimerCleanedNotRecreated],
    },
    Stage1CaseDefinition {
        id: "authority-sufficient-narrower",
        class: Acceptance,
        allowed_outcomes: &[RestoredWithNarrowerAuthority],
    },
    Stage1CaseDefinition {
        id: "kv-duplicate-idempotent-request",
        class: Acceptance,
        allowed_outcomes: &[DuplicateKvAppliedOnce],
    },
    Stage1CaseDefinition {
        id: "handoff-repeated-validation-prepare",
        class: Acceptance,
        allowed_outcomes: &[PrepareIdempotentInactive],
    },
    Stage1CaseDefinition {
        id: "journal-replay",
        class: Acceptance,
        allowed_outcomes: &[ReplayDigestMatched],
    },
    Stage1CaseDefinition {
        id: "source-post-commit-stale-attempt",
        class: Acceptance,
        allowed_outcomes: &[StaleSourceRejected],
    },
    Stage1CaseDefinition {
        id: "evidence-verification",
        class: Acceptance,
        allowed_outcomes: &[EvidenceIdentityVerified],
    },
    Stage1CaseDefinition {
        id: "performance-observations",
        class: Acceptance,
        allowed_outcomes: &[RawPerformanceRecorded],
    },
    Stage1CaseDefinition {
        id: "safe-point-unreachable",
        class: FailureRecovery,
        allowed_outcomes: &[SafePointRejectedSourceRetained],
    },
    Stage1CaseDefinition {
        id: "unsupported-live-resource-or-borrow",
        class: FailureRecovery,
        allowed_outcomes: &[FreezeRejectedNoSnapshot],
    },
    Stage1CaseDefinition {
        id: "kv-unknown-outcome",
        class: FailureRecovery,
        allowed_outcomes: &[UnknownKvReconciled, UnknownKvBlockedIndeterminate],
    },
    Stage1CaseDefinition {
        id: "corrupt-snapshot-or-component-digest",
        class: FailureRecovery,
        allowed_outcomes: &[SnapshotRejectedBeforeBindings],
    },
    Stage1CaseDefinition {
        id: "incompatible-snapshot-or-profile-version",
        class: FailureRecovery,
        allowed_outcomes: &[VersionRejectedBeforeBindings],
    },
    Stage1CaseDefinition {
        id: "unknown-extension-or-profile-mismatch",
        class: FailureRecovery,
        allowed_outcomes: &[ProfileRejectedWithoutDowngrade],
    },
    Stage1CaseDefinition {
        id: "destination-authority-missing-or-insufficient",
        class: FailureRecovery,
        allowed_outcomes: &[AuthorityRejectedBeforeExecution],
    },
    Stage1CaseDefinition {
        id: "required-capability-revoked",
        class: FailureRecovery,
        allowed_outcomes: &[RevocationRejectedNoResurrection],
    },
    Stage1CaseDefinition {
        id: "adapter-broader-authority",
        class: FailureRecovery,
        allowed_outcomes: &[ExcessAuthorityAttenuated, ExcessAuthorityRejected],
    },
    Stage1CaseDefinition {
        id: "kv-binding-wrong-or-missing",
        class: FailureRecovery,
        allowed_outcomes: &[BindingRejectedNoSubstitution],
    },
    Stage1CaseDefinition {
        id: "timer-semantics-unsupported",
        class: FailureRecovery,
        allowed_outcomes: &[TimerSemanticsRejected],
    },
    Stage1CaseDefinition {
        id: "destination-crash-before-commit",
        class: FailureRecovery,
        allowed_outcomes: &[PreCommitPreparationAborted, PreCommitPreparationRetried],
    },
    Stage1CaseDefinition {
        id: "prepare-message-duplicate-or-lost",
        class: FailureRecovery,
        allowed_outcomes: &[DuplicatePrepareInactive],
    },
    Stage1CaseDefinition {
        id: "commit-acknowledgement-lost",
        class: FailureRecovery,
        allowed_outcomes: &[DurableSourceOwnerSelected, DurableDestinationOwnerSelected],
    },
    Stage1CaseDefinition {
        id: "source-races-with-commit",
        class: FailureRecovery,
        allowed_outcomes: &[SingleLeaseEpochAccepted],
    },
    Stage1CaseDefinition {
        id: "destination-crash-after-commit",
        class: FailureRecovery,
        allowed_outcomes: &[SourceFencedRecoveryRequired],
    },
    Stage1CaseDefinition {
        id: "duplicate-restore-or-stale-snapshot",
        class: FailureRecovery,
        allowed_outcomes: &[DuplicateActivationRejected],
    },
    Stage1CaseDefinition {
        id: "repeated-cancel-abort-cleanup",
        class: FailureRecovery,
        allowed_outcomes: &[CleanupIdempotentNoResurrection],
    },
    Stage1CaseDefinition {
        id: "durable-journal-or-commit-write-fails",
        class: FailureRecovery,
        allowed_outcomes: &[DurableWriteAbortedBeforeCommit, DurableWriteBlockedIndeterminate],
    },
    Stage1CaseDefinition {
        id: "report-generation-fails-after-commit",
        class: FailureRecovery,
        allowed_outcomes: &[EvidenceRegeneratedWithoutStateChange],
    },
];

pub fn required_stage1_case_ids() -> impl Iterator<Item = &'static str> {
    STAGE1_CASE_DEFINITIONS.iter().map(|definition| definition.id)
}

pub fn stage1_case_definition(case_id: &str) -> Option<&'static Stage1CaseDefinition> {
    STAGE1_CASE_DEFINITIONS.iter().find(|definition| definition.id == case_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1EvidenceKind {
    Execution,
    Fixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1Claim {
    CooperativeStatefulComponentHandoff,
    CrossRuntimePortability,
    CrossIsaPortability,
    TransparentLiveMigration,
    UniversalExactlyOnce,
    Performance,
    ProductionReadiness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1VersionedIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1IsaIdentity {
    pub architecture: String,
    pub abi: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ProviderIdentity {
    pub implementation: Stage1VersionedIdentity,
    pub durable: bool,
    pub mock: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1AuthorityEnforcementIdentity {
    pub implementation: Stage1VersionedIdentity,
    pub policy_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1ResourceKind {
    PausedDurationTimer,
    DurableKeyValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ResourceProfile {
    pub resource: Stage1ResourceKind,
    pub profile_id: String,
    pub version: String,
    pub profile_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ExecutionEnvironment {
    pub carrier: Stage1VersionedIdentity,
    pub source_runtime: Stage1VersionedIdentity,
    pub destination_runtime: Stage1VersionedIdentity,
    pub source_isa: Stage1IsaIdentity,
    pub destination_isa: Stage1IsaIdentity,
    pub substrate: Stage1VersionedIdentity,
    pub provider: Stage1ProviderIdentity,
    pub authority_enforcement: Stage1AuthorityEnforcementIdentity,
    pub resource_profiles: Vec<Stage1ResourceProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1Provenance {
    pub component_sha256: String,
    pub profile_sha256: String,
    pub config_sha256: String,
    pub source_sha256: String,
    pub toolchain_sha256: String,
    pub executable_sha256: String,
    pub artifacts: Stage1ProvenanceArtifacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ProvenanceArtifactReference {
    pub uri: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ProvenanceArtifacts {
    pub component: Stage1ProvenanceArtifactReference,
    pub profile: Stage1ProvenanceArtifactReference,
    pub source_manifest: Stage1ProvenanceArtifactReference,
    pub toolchain: Stage1ProvenanceArtifactReference,
    pub build_source_manifest: Stage1ProvenanceArtifactReference,
    pub build_toolchain: Stage1ProvenanceArtifactReference,
    pub executable: Stage1ProvenanceArtifactReference,
    pub matrix_manifest: Stage1ProvenanceArtifactReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1OwnershipStatus {
    SourceActive,
    DestinationActive,
    DestinationRecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1AuthorityEvidence {
    pub enforcement_policy_sha256: String,
    pub source_authority_root_sha256: String,
    pub destination_authority_root_sha256: String,
    pub source_lease_epoch: u64,
    pub destination_lease_epoch: Option<u64>,
    pub fencing_epoch: u64,
    pub ownership: Stage1OwnershipStatus,
    pub source_fenced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1FaultInjection {
    pub transition: String,
    pub action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1FaultSchedule {
    pub schedule_id: String,
    pub injections: Vec<Stage1FaultInjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1ArtifactReference {
    pub uri: String,
    pub sha256: String,
    pub bundle_id: String,
    pub case_id: String,
    pub execution_id: String,
    pub handoff_id: String,
    pub snapshot_id: String,
    pub component_sha256: String,
    pub profile_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1BindingReceiptReference {
    pub resource: Stage1ResourceKind,
    pub receipt_id: String,
    pub artifact: Stage1ArtifactReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1TraceRole {
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1JournalScope {
    pub node: contract_core::NodeIdentity,
    pub component: contract_core::Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1SemanticTraceArtifact {
    pub schema_version: String,
    pub role: Stage1TraceRole,
    pub scope: Stage1JournalScope,
    pub base_cursor: contract_core::JournalPosition,
    pub base_state: contract_core::CanonicalState,
    pub entries: Vec<contract_core::JournalEntry>,
    pub final_state: contract_core::CanonicalState,
    pub claimed_final: bool,
}

pub const STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION: &str = "visa-stage1-semantic-trace-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1CaseArtifacts {
    pub snapshot: Option<Stage1ArtifactReference>,
    pub semantic_traces: Vec<Stage1ArtifactReference>,
    pub binding_receipts: Vec<Stage1BindingReceiptReference>,
    pub raw_execution: Vec<Stage1ArtifactReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1StateEvidence {
    pub state_sha256: String,
    pub replay_state_sha256: String,
    pub snapshot_sha256: Option<String>,
    pub trace_sha256s: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1CaseEvidence {
    pub case_id: String,
    pub execution_id: String,
    pub handoff_id: String,
    pub snapshot_id: String,
    pub case_config_sha256: String,
    pub case_policy_sha256: String,
    pub outcome: Stage1CaseOutcome,
    pub exit_status: i32,
    pub fault_schedule: Stage1FaultSchedule,
    pub authority: Stage1AuthorityEvidence,
    pub artifacts: Stage1CaseArtifacts,
    pub state: Stage1StateEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1PerformanceMetric {
    SteadyStateCost,
    SnapshotSize,
    HandoffInterruption,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage1PerformanceUnit {
    Nanoseconds,
    Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1PerformanceObservation {
    pub metric: Stage1PerformanceMetric,
    pub unit: Stage1PerformanceUnit,
    pub samples: Vec<u64>,
    pub execution_id: String,
    pub raw_artifact_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1EvidenceBundle {
    pub schema_version: String,
    pub capability_id: String,
    pub bundle_id: String,
    pub evidence_kind: Stage1EvidenceKind,
    pub claims: Vec<Stage1Claim>,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub environment: Stage1ExecutionEnvironment,
    pub provenance: Stage1Provenance,
    pub cases: Vec<Stage1CaseEvidence>,
    pub performance_observations: Vec<Stage1PerformanceObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage1ValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage1ValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage1ValidationFinding>,
}

impl Stage1ValidationReport {
    fn new(findings: Vec<Stage1ValidationFinding>) -> Self {
        Self { ok: findings.is_empty(), findings }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage1EvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage1EvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage1EvidenceLoadError>,
    pub validation: Option<Stage1ValidationReport>,
}

pub fn validate_stage1_evidence_bundle(bundle: &Stage1EvidenceBundle) -> Stage1ValidationReport {
    let mut findings = Vec::new();

    if bundle.schema_version != STAGE1_EVIDENCE_SCHEMA_VERSION {
        push_finding(
            &mut findings,
            "unsupported-stage1-schema",
            format!("unsupported Stage 1 evidence schema {}", bundle.schema_version),
        );
    }
    if bundle.capability_id != STAGE1_CAPABILITY_ID {
        push_finding(
            &mut findings,
            "wrong-stage1-capability",
            format!("expected capability {STAGE1_CAPABILITY_ID}, found {}", bundle.capability_id),
        );
    }
    require_nonempty(
        &bundle.bundle_id,
        "bundle_id",
        "missing-stage1-bundle-identity",
        &mut findings,
    );
    if bundle.evidence_kind != Stage1EvidenceKind::Execution {
        push_finding(
            &mut findings,
            "fixture-not-execution-evidence",
            "a comparison fixture cannot satisfy the Stage 1 execution gate",
        );
    }
    validate_claims(&bundle.claims, &mut findings);
    if bundle.started_at_unix_ms == 0
        || bundle.finished_at_unix_ms == 0
        || bundle.finished_at_unix_ms < bundle.started_at_unix_ms
    {
        push_finding(
            &mut findings,
            "invalid-stage1-timestamps",
            "Stage 1 execution timestamps must be non-zero and ordered",
        );
    }

    validate_environment(&bundle.environment, &mut findings);
    validate_provenance(&bundle.provenance, &mut findings);
    validate_cases(bundle, &mut findings);
    validate_performance_observations(bundle, &mut findings);

    Stage1ValidationReport::new(findings)
}

pub fn parse_stage1_evidence_bundle_json(
    bytes: &[u8],
) -> Result<Stage1EvidenceBundle, Stage1EvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|error| Stage1EvidenceLoadError {
        code: "invalid-stage1-evidence-json".to_string(),
        detail: error.to_string(),
    })
}

pub fn gate_stage1_evidence_bundle_json(bytes: &[u8]) -> Stage1EvidenceGateResult {
    match parse_stage1_evidence_bundle_json(bytes) {
        Ok(bundle) => {
            let validation = validate_stage1_evidence_bundle(&bundle);
            Stage1EvidenceGateResult {
                ok: validation.ok,
                load_error: None,
                validation: Some(validation),
            }
        }
        Err(error) => {
            Stage1EvidenceGateResult { ok: false, load_error: Some(error), validation: None }
        }
    }
}

pub(crate) struct VerifiedStage1Artifact {
    sha256: String,
    bytes: Option<Vec<u8>>,
}

pub(crate) struct VerifiedStage1Artifacts {
    artifacts: BTreeMap<String, VerifiedStage1Artifact>,
    #[cfg(all(test, target_os = "linux"))]
    successful_regular_open_counts: BTreeMap<String, usize>,
}

impl VerifiedStage1Artifacts {
    pub(crate) fn bytes(&self, uri: &str) -> Option<&[u8]> {
        self.artifacts.get(uri)?.bytes.as_deref()
    }

    pub(crate) fn sha256(&self, uri: &str) -> Option<&str> {
        Some(self.artifacts.get(uri)?.sha256.as_str())
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn artifact_uris(&self) -> impl Iterator<Item = &str> {
        self.artifacts.keys().map(String::as_str)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn successful_regular_open_counts(&self) -> &BTreeMap<String, usize> {
        &self.successful_regular_open_counts
    }

    #[cfg(test)]
    pub(crate) fn capture_for_test<'a>(
        artifact_root: &Path,
        uris: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let root = SecureArtifactRoot::open(artifact_root).expect("open test artifact root");
        let artifacts = uris
            .into_iter()
            .map(|uri| {
                let bytes = root.read_regular(uri).expect("capture test artifact");
                (
                    uri.to_owned(),
                    VerifiedStage1Artifact {
                        sha256: crate::sha256_hex(&bytes),
                        bytes: Some(bytes),
                    },
                )
            })
            .collect();
        Self {
            artifacts,
            #[cfg(target_os = "linux")]
            successful_regular_open_counts: root.successful_regular_open_counts(),
        }
    }
}

pub fn validate_stage1_evidence_artifacts(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
) -> Stage1ValidationReport {
    validate_stage1_evidence_artifacts_with_snapshot(bundle, artifact_root).0
}

pub(crate) fn validate_stage1_evidence_artifacts_with_snapshot(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
) -> (Stage1ValidationReport, Option<VerifiedStage1Artifacts>) {
    validate_stage1_evidence_artifacts_with_snapshot_impl(bundle, artifact_root, || {})
}

#[cfg(test)]
pub(crate) fn validate_stage1_evidence_artifacts_with_snapshot_after_capture(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
    after_capture: impl FnOnce(),
) -> (Stage1ValidationReport, Option<VerifiedStage1Artifacts>) {
    validate_stage1_evidence_artifacts_with_snapshot_impl(bundle, artifact_root, after_capture)
}

fn validate_stage1_evidence_artifacts_with_snapshot_impl(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
    after_capture: impl FnOnce(),
) -> (Stage1ValidationReport, Option<VerifiedStage1Artifacts>) {
    let (mut findings, snapshot) = capture_stage1_evidence_artifacts(bundle, artifact_root);
    after_capture();
    if let Some(snapshot) = snapshot.as_ref() {
        findings.extend(crate::stage1_artifacts::validate_artifact_contents(bundle, snapshot));
    }
    (Stage1ValidationReport::new(findings), snapshot)
}

pub(crate) fn capture_stage1_evidence_artifacts(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
) -> (Vec<Stage1ValidationFinding>, Option<VerifiedStage1Artifacts>) {
    let mut findings = Vec::new();
    let artifact_root = match SecureArtifactRoot::open(artifact_root.as_ref()) {
        Ok(root) => root,
        Err(error) => {
            push_stage1_artifact_error(&mut findings, None, error);
            return (findings, None);
        }
    };

    let mut uris = BTreeSet::new();
    let provenance = [
        &bundle.provenance.artifacts.component,
        &bundle.provenance.artifacts.profile,
        &bundle.provenance.artifacts.source_manifest,
        &bundle.provenance.artifacts.toolchain,
        &bundle.provenance.artifacts.build_source_manifest,
        &bundle.provenance.artifacts.build_toolchain,
        &bundle.provenance.artifacts.executable,
        &bundle.provenance.artifacts.matrix_manifest,
    ];
    let artifacts = provenance
        .into_iter()
        .map(|artifact| {
            (
                artifact.uri.as_str(),
                artifact.sha256.as_str(),
                artifact.uri != bundle.provenance.artifacts.component.uri
                    && artifact.uri != bundle.provenance.artifacts.toolchain.uri
                    && artifact.uri != bundle.provenance.artifacts.build_toolchain.uri
                    && artifact.uri != bundle.provenance.artifacts.executable.uri,
            )
        })
        .chain(
            stage1_artifact_references(bundle)
                .into_iter()
                .map(|artifact| (artifact.uri.as_str(), artifact.sha256.as_str(), true)),
        );
    let mut captured = BTreeMap::new();
    let mut retained_bytes = 0_u64;
    for (uri, expected_sha256, retain_bytes) in artifacts {
        if !artifact_uri_is_relative(uri) {
            push_finding(
                &mut findings,
                "invalid-stage1-artifact-uri",
                format!("unsafe artifact URI {uri}"),
            );
            continue;
        }
        if !uris.insert(uri) {
            push_finding(
                &mut findings,
                "duplicate-stage1-artifact-path",
                format!("artifact URI {uri} is referenced more than once"),
            );
            continue;
        }

        let captured_artifact = if retain_bytes {
            artifact_root.read_regular(uri).map(|bytes| VerifiedStage1Artifact {
                sha256: crate::sha256_hex(&bytes),
                bytes: Some(bytes),
            })
        } else {
            artifact_root
                .sha256_regular(uri)
                .map(|sha256| VerifiedStage1Artifact { sha256, bytes: None })
        };
        let captured_artifact = match captured_artifact {
            Ok(artifact) => artifact,
            Err(error) => {
                push_stage1_artifact_error(&mut findings, Some(uri), error);
                continue;
            }
        };
        if let Some(bytes) = captured_artifact.bytes.as_ref() {
            retained_bytes =
                retained_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            if retained_bytes > MAX_STAGE1_RETAINED_ARTIFACT_BYTES {
                push_finding(
                    &mut findings,
                    "stage1-artifact-set-too-large",
                    format!(
                        "retained Stage 1 artifacts exceed the \
                         {MAX_STAGE1_RETAINED_ARTIFACT_BYTES}-byte limit"
                    ),
                );
                continue;
            }
        }
        if captured_artifact.sha256 != expected_sha256 {
            push_finding(
                &mut findings,
                "stage1-artifact-digest-mismatch",
                format!(
                    "artifact {uri} digest is {}, expected {expected_sha256}",
                    captured_artifact.sha256
                ),
            );
        }
        captured.insert(uri.to_owned(), captured_artifact);
    }

    let snapshot = (captured.len() == uris.len()).then_some(VerifiedStage1Artifacts {
        artifacts: captured,
        #[cfg(all(test, target_os = "linux"))]
        successful_regular_open_counts: artifact_root.successful_regular_open_counts(),
    });
    (findings, snapshot)
}

pub fn gate_stage1_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    artifact_root: impl AsRef<Path>,
) -> Stage1EvidenceGateResult {
    match parse_stage1_evidence_bundle_json(bytes) {
        Ok(bundle) => {
            let (validation, _) =
                validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, artifact_root);
            Stage1EvidenceGateResult {
                ok: validation.ok,
                load_error: None,
                validation: Some(validation),
            }
        }
        Err(error) => {
            Stage1EvidenceGateResult { ok: false, load_error: Some(error), validation: None }
        }
    }
}

pub(crate) fn validate_stage1_evidence_bundle_with_artifact_snapshot(
    bundle: &Stage1EvidenceBundle,
    artifact_root: impl AsRef<Path>,
) -> (Stage1ValidationReport, Option<VerifiedStage1Artifacts>) {
    let mut validation = validate_stage1_evidence_bundle(bundle);
    let (artifact_validation, snapshot) =
        validate_stage1_evidence_artifacts_with_snapshot(bundle, artifact_root);
    validation.findings.extend(artifact_validation.findings);
    validation.ok = validation.findings.is_empty();
    let snapshot = validation.ok.then_some(snapshot).flatten();
    (validation, snapshot)
}

fn stage1_artifact_references(bundle: &Stage1EvidenceBundle) -> Vec<&Stage1ArtifactReference> {
    let mut artifacts = Vec::new();
    for case in &bundle.cases {
        if let Some(snapshot) = &case.artifacts.snapshot {
            artifacts.push(snapshot);
        }
        artifacts.extend(&case.artifacts.semantic_traces);
        artifacts.extend(case.artifacts.binding_receipts.iter().map(|receipt| &receipt.artifact));
        artifacts.extend(&case.artifacts.raw_execution);
    }
    artifacts
}

fn validate_claims(claims: &[Stage1Claim], findings: &mut Vec<Stage1ValidationFinding>) {
    let mut seen = BTreeSet::new();
    for claim in claims {
        if !seen.insert(*claim) {
            push_finding(
                findings,
                "duplicate-stage1-claim",
                format!("duplicate Stage 1 claim {claim:?}"),
            );
        }
        if *claim != Stage1Claim::CooperativeStatefulComponentHandoff {
            push_finding(
                findings,
                "stage1-overclaim",
                format!("Stage 1 evidence cannot claim {claim:?}"),
            );
        }
    }
    if !seen.contains(&Stage1Claim::CooperativeStatefulComponentHandoff) {
        push_finding(
            findings,
            "missing-stage1-claim",
            "the cooperative stateful component handoff claim is missing",
        );
    }
}

fn validate_environment(
    environment: &Stage1ExecutionEnvironment,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    validate_versioned_identity(&environment.carrier, "carrier", findings);
    validate_versioned_identity(&environment.source_runtime, "source_runtime", findings);
    validate_versioned_identity(&environment.destination_runtime, "destination_runtime", findings);
    validate_isa_identity(&environment.source_isa, "source_isa", findings);
    validate_isa_identity(&environment.destination_isa, "destination_isa", findings);
    validate_versioned_identity(&environment.substrate, "substrate", findings);
    validate_versioned_identity(&environment.provider.implementation, "provider", findings);
    if !environment.provider.durable {
        push_finding(
            findings,
            "non-durable-stage1-provider",
            "Stage 1 execution evidence requires a durable provider",
        );
    }
    if environment.provider.mock {
        push_finding(
            findings,
            "mock-stage1-provider",
            "a mock provider cannot satisfy Stage 1 execution evidence",
        );
    }
    validate_versioned_identity(
        &environment.authority_enforcement.implementation,
        "authority_enforcement",
        findings,
    );
    validate_sha256(
        &environment.authority_enforcement.policy_sha256,
        "authority_enforcement.policy_sha256",
        findings,
    );

    let mut resources = BTreeSet::new();
    for profile in &environment.resource_profiles {
        if !resources.insert(profile.resource) {
            push_finding(
                findings,
                "duplicate-stage1-resource-profile",
                format!("duplicate resource profile for {:?}", profile.resource),
            );
        }
        require_nonempty(
            &profile.profile_id,
            "resource_profile.profile_id",
            "missing-stage1-environment-dimension",
            findings,
        );
        require_nonempty(
            &profile.version,
            "resource_profile.version",
            "missing-stage1-environment-dimension",
            findings,
        );
        validate_sha256(&profile.profile_sha256, "resource_profile.profile_sha256", findings);
    }
    for resource in [Stage1ResourceKind::PausedDurationTimer, Stage1ResourceKind::DurableKeyValue] {
        if !resources.contains(&resource) {
            push_finding(
                findings,
                "missing-stage1-resource-profile",
                format!("missing Stage 1 resource profile for {resource:?}"),
            );
        }
    }
}

fn validate_versioned_identity(
    identity: &Stage1VersionedIdentity,
    label: &str,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    require_nonempty(
        &identity.name,
        &format!("{label}.name"),
        "missing-stage1-environment-dimension",
        findings,
    );
    require_nonempty(
        &identity.version,
        &format!("{label}.version"),
        "missing-stage1-environment-dimension",
        findings,
    );
}

fn validate_isa_identity(
    identity: &Stage1IsaIdentity,
    label: &str,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    require_nonempty(
        &identity.architecture,
        &format!("{label}.architecture"),
        "missing-stage1-environment-dimension",
        findings,
    );
    require_nonempty(
        &identity.abi,
        &format!("{label}.abi"),
        "missing-stage1-environment-dimension",
        findings,
    );
}

fn validate_provenance(provenance: &Stage1Provenance, findings: &mut Vec<Stage1ValidationFinding>) {
    for (label, digest) in [
        ("component_sha256", provenance.component_sha256.as_str()),
        ("profile_sha256", provenance.profile_sha256.as_str()),
        ("config_sha256", provenance.config_sha256.as_str()),
        ("source_sha256", provenance.source_sha256.as_str()),
        ("toolchain_sha256", provenance.toolchain_sha256.as_str()),
        ("executable_sha256", provenance.executable_sha256.as_str()),
    ] {
        validate_sha256(digest, label, findings);
    }
    for (label, artifact) in [
        ("component", &provenance.artifacts.component),
        ("profile", &provenance.artifacts.profile),
        ("source_manifest", &provenance.artifacts.source_manifest),
        ("toolchain", &provenance.artifacts.toolchain),
        ("build_source_manifest", &provenance.artifacts.build_source_manifest),
        ("build_toolchain", &provenance.artifacts.build_toolchain),
        ("executable", &provenance.artifacts.executable),
        ("matrix_manifest", &provenance.artifacts.matrix_manifest),
    ] {
        if !artifact_uri_is_relative(&artifact.uri) {
            push_finding(
                findings,
                "invalid-stage1-provenance-artifact-uri",
                format!("{label} uses unsafe artifact URI {}", artifact.uri),
            );
        }
        validate_sha256(
            &artifact.sha256,
            &format!("provenance.artifacts.{label}.sha256"),
            findings,
        );
    }
}

fn validate_cases(bundle: &Stage1EvidenceBundle, findings: &mut Vec<Stage1ValidationFinding>) {
    let mut case_ids = BTreeSet::new();
    let mut execution_ids = BTreeSet::new();
    let mut handoff_ids = BTreeSet::new();
    let mut snapshot_ids = BTreeSet::new();
    let mut artifact_dimensions = ArtifactDimensions::default();

    for case in &bundle.cases {
        let definition = stage1_case_definition(&case.case_id);
        if !case_ids.insert(case.case_id.as_str()) {
            push_finding(
                findings,
                "duplicate-stage1-case",
                format!("duplicate Stage 1 case {}", case.case_id),
            );
        }
        let Some(definition) = definition else {
            push_finding(
                findings,
                "unknown-stage1-case",
                format!("unknown Stage 1 case {}", case.case_id),
            );
            continue;
        };

        validate_case_identity(
            case,
            &mut execution_ids,
            &mut handoff_ids,
            &mut snapshot_ids,
            findings,
        );
        if !definition.allowed_outcomes.contains(&case.outcome) {
            push_finding(
                findings,
                "incorrect-stage1-case-outcome",
                format!(
                    "{} reported {:?}; allowed outcomes are {:?}",
                    case.case_id, case.outcome, definition.allowed_outcomes
                ),
            );
        }
        if case.exit_status != 0 {
            push_finding(
                findings,
                "stage1-case-execution-failed",
                format!("{} runner exited with {}", case.case_id, case.exit_status),
            );
        }
        validate_sha256(
            &case.case_config_sha256,
            &format!("{}.case_config_sha256", case.case_id),
            findings,
        );
        validate_sha256(
            &case.case_policy_sha256,
            &format!("{}.case_policy_sha256", case.case_id),
            findings,
        );
        validate_fault_schedule(case, definition, findings);
        validate_authority_evidence(
            case,
            &bundle.environment.authority_enforcement.policy_sha256,
            findings,
        );
        validate_case_artifacts(bundle, case, &mut artifact_dimensions, findings);
        validate_state_evidence(case, findings);
    }

    for required in required_stage1_case_ids() {
        if !case_ids.contains(required) {
            push_finding(
                findings,
                "missing-stage1-case",
                format!("Stage 1 evidence omits required case {required}"),
            );
        }
    }
    if !artifact_dimensions.snapshot {
        push_finding(
            findings,
            "missing-stage1-snapshot-evidence",
            "Stage 1 bundle contains no snapshot artifact reference",
        );
    }
    if !artifact_dimensions.semantic_trace {
        push_finding(
            findings,
            "missing-stage1-trace-evidence",
            "Stage 1 bundle contains no semantic trace artifact reference",
        );
    }
    for resource in [Stage1ResourceKind::PausedDurationTimer, Stage1ResourceKind::DurableKeyValue] {
        if !artifact_dimensions.binding_receipts.contains(&resource) {
            push_finding(
                findings,
                "missing-stage1-binding-receipt-evidence",
                format!("Stage 1 bundle contains no binding receipt for {resource:?}"),
            );
        }
    }
    if !artifact_dimensions.raw_execution {
        push_finding(
            findings,
            "missing-stage1-raw-evidence",
            "Stage 1 bundle contains no raw execution artifact reference",
        );
    }
}

fn validate_case_identity(
    case: &Stage1CaseEvidence,
    execution_ids: &mut BTreeSet<String>,
    handoff_ids: &mut BTreeSet<String>,
    snapshot_ids: &mut BTreeSet<String>,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    for (label, value) in [
        ("execution_id", case.execution_id.as_str()),
        ("handoff_id", case.handoff_id.as_str()),
        ("snapshot_id", case.snapshot_id.as_str()),
    ] {
        require_nonempty(
            value,
            &format!("{}.{}", case.case_id, label),
            "missing-stage1-case-identity",
            findings,
        );
    }
    for (label, value, ids) in [
        ("execution", case.execution_id.as_str(), execution_ids),
        ("handoff", case.handoff_id.as_str(), handoff_ids),
        ("snapshot", case.snapshot_id.as_str(), snapshot_ids),
    ] {
        if !value.trim().is_empty() && !ids.insert(value.to_string()) {
            push_finding(
                findings,
                "duplicate-stage1-execution-identity",
                format!("duplicate {label} identity {value}"),
            );
        }
    }
}

fn validate_fault_schedule(
    case: &Stage1CaseEvidence,
    definition: &Stage1CaseDefinition,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    require_nonempty(
        &case.fault_schedule.schedule_id,
        &format!("{}.fault_schedule.schedule_id", case.case_id),
        "missing-stage1-fault-schedule",
        findings,
    );
    if definition.class == Stage1CaseClass::FailureRecovery
        && case.fault_schedule.injections.is_empty()
    {
        push_finding(
            findings,
            "missing-stage1-fault-injection",
            format!("{} is a failure/recovery case without an injected condition", case.case_id),
        );
    }
    for injection in &case.fault_schedule.injections {
        require_nonempty(
            &injection.transition,
            &format!("{}.fault.transition", case.case_id),
            "incomplete-stage1-fault-injection",
            findings,
        );
        require_nonempty(
            &injection.action,
            &format!("{}.fault.action", case.case_id),
            "incomplete-stage1-fault-injection",
            findings,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage1ExpectedOwnership {
    SourceRetained,
    DestinationCommitted,
    DestinationRecoveryRequired,
}

pub const fn stage1_expected_ownership(outcome: Stage1CaseOutcome) -> Stage1ExpectedOwnership {
    match outcome {
        PrepareIdempotentInactive
        | SafePointRejectedSourceRetained
        | FreezeRejectedNoSnapshot
        | UnknownKvBlockedIndeterminate
        | SnapshotRejectedBeforeBindings
        | VersionRejectedBeforeBindings
        | ProfileRejectedWithoutDowngrade
        | AuthorityRejectedBeforeExecution
        | RevocationRejectedNoResurrection
        | ExcessAuthorityRejected
        | BindingRejectedNoSubstitution
        | TimerSemanticsRejected
        | PreCommitPreparationAborted
        | PreCommitPreparationRetried
        | DuplicatePrepareInactive
        | DurableSourceOwnerSelected
        | CleanupIdempotentNoResurrection
        | DurableWriteAbortedBeforeCommit
        | DurableWriteBlockedIndeterminate => Stage1ExpectedOwnership::SourceRetained,
        SourceFencedRecoveryRequired => Stage1ExpectedOwnership::DestinationRecoveryRequired,
        TimerRecreatedSingleExpiry
        | TimerPausedThenResumed
        | CompletedTimerNotRecreated
        | CancelledTimerCleanedNotRecreated
        | RestoredWithNarrowerAuthority
        | DuplicateKvAppliedOnce
        | ReplayDigestMatched
        | StaleSourceRejected
        | EvidenceIdentityVerified
        | RawPerformanceRecorded
        | UnknownKvReconciled
        | ExcessAuthorityAttenuated
        | DurableDestinationOwnerSelected
        | SingleLeaseEpochAccepted
        | DuplicateActivationRejected
        | EvidenceRegeneratedWithoutStateChange => Stage1ExpectedOwnership::DestinationCommitted,
    }
}

fn validate_authority_evidence(
    case: &Stage1CaseEvidence,
    policy_sha256: &str,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let authority = &case.authority;
    for (label, digest) in [
        ("enforcement_policy_sha256", authority.enforcement_policy_sha256.as_str()),
        ("source_authority_root_sha256", authority.source_authority_root_sha256.as_str()),
        ("destination_authority_root_sha256", authority.destination_authority_root_sha256.as_str()),
    ] {
        validate_sha256(digest, &format!("{}.authority.{label}", case.case_id), findings);
    }
    if authority.enforcement_policy_sha256 != policy_sha256 {
        push_finding(
            findings,
            "inconsistent-stage1-authority-policy",
            format!("{} authority policy does not match the execution environment", case.case_id),
        );
    }
    if authority.source_lease_epoch == 0 || authority.fencing_epoch == 0 {
        push_finding(
            findings,
            "invalid-stage1-authority-epoch",
            format!("{} contains a zero authority or fencing epoch", case.case_id),
        );
    }

    let authority_ok = match stage1_expected_ownership(case.outcome) {
        Stage1ExpectedOwnership::SourceRetained => {
            authority.destination_lease_epoch.is_none()
                && authority.fencing_epoch == authority.source_lease_epoch
                && authority.ownership == Stage1OwnershipStatus::SourceActive
                && !authority.source_fenced
        }
        Stage1ExpectedOwnership::DestinationCommitted => {
            authority.destination_lease_epoch.is_some_and(|epoch| {
                epoch > authority.source_lease_epoch
                    && authority.fencing_epoch == epoch
                    && authority.ownership == Stage1OwnershipStatus::DestinationActive
                    && authority.source_fenced
            })
        }
        Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            authority.destination_lease_epoch.is_some_and(|epoch| {
                epoch > authority.source_lease_epoch
                    && authority.fencing_epoch == epoch
                    && authority.ownership == Stage1OwnershipStatus::DestinationRecoveryRequired
                    && authority.source_fenced
            })
        }
    };
    if !authority_ok {
        push_finding(
            findings,
            "inconsistent-stage1-ownership-evidence",
            format!(
                "{} authority roots, lease epochs, fencing epoch, and ownership do not agree with {:?}",
                case.case_id, case.outcome
            ),
        );
    }
}

#[derive(Default)]
struct ArtifactDimensions {
    snapshot: bool,
    semantic_trace: bool,
    binding_receipts: BTreeSet<Stage1ResourceKind>,
    raw_execution: bool,
}

fn validate_case_artifacts(
    bundle: &Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    dimensions: &mut ArtifactDimensions,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let mut uris = BTreeSet::new();
    let mut receipt_resources = BTreeSet::new();
    let mut receipt_ids = BTreeSet::new();

    if let Some(snapshot) = &case.artifacts.snapshot {
        dimensions.snapshot = true;
        validate_artifact_reference(bundle, case, "snapshot", snapshot, &mut uris, findings);
    }
    if case.artifacts.semantic_traces.is_empty() {
        push_finding(
            findings,
            "missing-stage1-case-semantic-trace",
            format!("{} contains no scoped semantic trace", case.case_id),
        );
    }
    for trace in &case.artifacts.semantic_traces {
        dimensions.semantic_trace = true;
        validate_artifact_reference(bundle, case, "semantic_trace", trace, &mut uris, findings);
    }
    for receipt in &case.artifacts.binding_receipts {
        dimensions.binding_receipts.insert(receipt.resource);
        if !receipt_resources.insert(receipt.resource) {
            push_finding(
                findings,
                "duplicate-stage1-binding-receipt",
                format!("{} has duplicate receipts for {:?}", case.case_id, receipt.resource),
            );
        }
        require_nonempty(
            &receipt.receipt_id,
            &format!("{}.binding_receipt.receipt_id", case.case_id),
            "missing-stage1-binding-receipt-identity",
            findings,
        );
        if !receipt.receipt_id.trim().is_empty() && !receipt_ids.insert(receipt.receipt_id.as_str())
        {
            push_finding(
                findings,
                "duplicate-stage1-binding-receipt-identity",
                format!("{} repeats receipt id {}", case.case_id, receipt.receipt_id),
            );
        }
        validate_artifact_reference(
            bundle,
            case,
            "binding_receipt",
            &receipt.artifact,
            &mut uris,
            findings,
        );
    }
    if case.artifacts.raw_execution.is_empty() {
        push_finding(
            findings,
            "missing-stage1-case-raw-evidence",
            format!("{} contains no raw runner artifact", case.case_id),
        );
    }
    for raw in &case.artifacts.raw_execution {
        dimensions.raw_execution = true;
        validate_artifact_reference(bundle, case, "raw_execution", raw, &mut uris, findings);
    }

    let expected_ownership = stage1_expected_ownership(case.outcome);
    let snapshot_required = expected_ownership != Stage1ExpectedOwnership::SourceRetained
        || case.outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection;
    if snapshot_required && case.artifacts.snapshot.is_none() {
        push_finding(
            findings,
            "missing-stage1-case-snapshot",
            format!("{} requires a locked snapshot reference", case.case_id),
        );
    }
    if expected_ownership != Stage1ExpectedOwnership::SourceRetained {
        for resource in
            [Stage1ResourceKind::PausedDurationTimer, Stage1ResourceKind::DurableKeyValue]
        {
            if !receipt_resources.contains(&resource) {
                push_finding(
                    findings,
                    "missing-stage1-case-binding-receipt",
                    format!("{} completed commit without a {resource:?} receipt", case.case_id),
                );
            }
        }
    }
}

fn validate_artifact_reference(
    bundle: &Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    label: &str,
    artifact: &Stage1ArtifactReference,
    uris: &mut BTreeSet<String>,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    if !artifact_uri_is_relative(&artifact.uri) {
        push_finding(
            findings,
            "invalid-stage1-artifact-uri",
            format!("{}.{} uses unsafe artifact URI {}", case.case_id, label, artifact.uri),
        );
    } else if !uris.insert(artifact.uri.clone()) {
        push_finding(
            findings,
            "duplicate-stage1-artifact-uri",
            format!("{} repeats artifact URI {}", case.case_id, artifact.uri),
        );
    }
    validate_sha256(&artifact.sha256, &format!("{}.{}.sha256", case.case_id, label), findings);

    let expected = [
        ("bundle_id", bundle.bundle_id.as_str(), artifact.bundle_id.as_str()),
        ("case_id", case.case_id.as_str(), artifact.case_id.as_str()),
        ("execution_id", case.execution_id.as_str(), artifact.execution_id.as_str()),
        ("handoff_id", case.handoff_id.as_str(), artifact.handoff_id.as_str()),
        ("snapshot_id", case.snapshot_id.as_str(), artifact.snapshot_id.as_str()),
        (
            "component_sha256",
            bundle.provenance.component_sha256.as_str(),
            artifact.component_sha256.as_str(),
        ),
        (
            "profile_sha256",
            bundle.provenance.profile_sha256.as_str(),
            artifact.profile_sha256.as_str(),
        ),
    ];
    for (identity_label, expected, observed) in expected {
        if expected != observed {
            push_finding(
                findings,
                "inconsistent-stage1-artifact-identity",
                format!(
                    "{}.{} artifact {identity_label} is {observed:?}, expected {expected:?}",
                    case.case_id, label
                ),
            );
        }
    }
}

fn validate_state_evidence(case: &Stage1CaseEvidence, findings: &mut Vec<Stage1ValidationFinding>) {
    validate_sha256(
        &case.state.state_sha256,
        &format!("{}.state.state_sha256", case.case_id),
        findings,
    );
    validate_sha256(
        &case.state.replay_state_sha256,
        &format!("{}.state.replay_state_sha256", case.case_id),
        findings,
    );
    for trace_sha256 in &case.state.trace_sha256s {
        validate_sha256(trace_sha256, &format!("{}.state.trace_sha256s", case.case_id), findings);
    }
    if let Some(snapshot_sha256) = &case.state.snapshot_sha256 {
        validate_sha256(
            snapshot_sha256,
            &format!("{}.state.snapshot_sha256", case.case_id),
            findings,
        );
    }

    if case.state.state_sha256 != case.state.replay_state_sha256 {
        push_finding(
            findings,
            "inconsistent-stage1-state-replay-digest",
            format!("{} state and replay digests differ", case.case_id),
        );
    }
    let artifact_trace_digests = case
        .artifacts
        .semantic_traces
        .iter()
        .map(|artifact| artifact.sha256.as_str())
        .collect::<Vec<_>>();
    let state_trace_digests =
        case.state.trace_sha256s.iter().map(String::as_str).collect::<Vec<_>>();
    if state_trace_digests != artifact_trace_digests {
        push_finding(
            findings,
            "inconsistent-stage1-trace-digest",
            format!("{} state evidence and scoped trace artifact digests differ", case.case_id),
        );
    }
    match (&case.state.snapshot_sha256, &case.artifacts.snapshot) {
        (Some(state_digest), Some(snapshot)) if state_digest == &snapshot.sha256 => {}
        (None, None) => {}
        _ => push_finding(
            findings,
            "inconsistent-stage1-snapshot-digest",
            format!("{} state evidence and snapshot artifact do not agree", case.case_id),
        ),
    }
}

fn validate_performance_observations(
    bundle: &Stage1EvidenceBundle,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let performance_case =
        bundle.cases.iter().find(|case| case.case_id == "performance-observations");
    let mut metrics = BTreeSet::new();
    for observation in &bundle.performance_observations {
        if !metrics.insert(observation.metric) {
            push_finding(
                findings,
                "duplicate-stage1-performance-observation",
                format!("duplicate raw observation for {:?}", observation.metric),
            );
        }
        if observation.samples.is_empty() {
            push_finding(
                findings,
                "missing-stage1-performance-samples",
                format!("{:?} contains no raw samples", observation.metric),
            );
        }
        let expected_unit = match observation.metric {
            Stage1PerformanceMetric::SteadyStateCost
            | Stage1PerformanceMetric::HandoffInterruption => Stage1PerformanceUnit::Nanoseconds,
            Stage1PerformanceMetric::SnapshotSize => Stage1PerformanceUnit::Bytes,
        };
        if observation.unit != expected_unit {
            push_finding(
                findings,
                "invalid-stage1-performance-unit",
                format!(
                    "{:?} uses {:?}, expected {:?}",
                    observation.metric, observation.unit, expected_unit
                ),
            );
        }
        if observation.metric == Stage1PerformanceMetric::SnapshotSize
            && observation.samples.contains(&0)
        {
            push_finding(
                findings,
                "invalid-stage1-performance-sample",
                "snapshot size observations must be greater than zero",
            );
        }
        validate_sha256(
            &observation.raw_artifact_sha256,
            &format!("performance.{:?}.raw_artifact_sha256", observation.metric),
            findings,
        );

        match performance_case {
            Some(case) => {
                if observation.execution_id != case.execution_id {
                    push_finding(
                        findings,
                        "inconsistent-stage1-performance-identity",
                        format!(
                            "{:?} observation execution {} does not match {}",
                            observation.metric, observation.execution_id, case.execution_id
                        ),
                    );
                }
                if !case
                    .artifacts
                    .raw_execution
                    .iter()
                    .any(|artifact| artifact.sha256 == observation.raw_artifact_sha256)
                {
                    push_finding(
                        findings,
                        "unbound-stage1-performance-artifact",
                        format!(
                            "{:?} raw digest is not referenced by the performance case",
                            observation.metric
                        ),
                    );
                }
            }
            None => push_finding(
                findings,
                "missing-stage1-performance-case",
                "performance observations have no required performance case",
            ),
        }
    }

    for metric in [
        Stage1PerformanceMetric::SteadyStateCost,
        Stage1PerformanceMetric::SnapshotSize,
        Stage1PerformanceMetric::HandoffInterruption,
    ] {
        if !metrics.contains(&metric) {
            push_finding(
                findings,
                "missing-stage1-performance-observation",
                format!("missing raw performance observation for {metric:?}"),
            );
        }
    }
}

fn require_nonempty(
    value: &str,
    label: &str,
    code: &str,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    if value.trim().is_empty() {
        push_finding(findings, code, format!("{label} is empty"));
    }
}

fn validate_sha256(value: &str, label: &str, findings: &mut Vec<Stage1ValidationFinding>) {
    if !is_sha256(value) {
        push_finding(
            findings,
            "invalid-stage1-digest",
            format!("{label} is not a lowercase SHA-256 digest"),
        );
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn artifact_uri_is_relative(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.trim().is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn push_stage1_artifact_error(
    findings: &mut Vec<Stage1ValidationFinding>,
    uri: Option<&str>,
    error: SecureArtifactError,
) {
    if uri.is_none() {
        let code = if error.kind == SecureArtifactErrorKind::Unsupported {
            "stage1-secure-artifact-reader-unavailable"
        } else {
            "invalid-stage1-artifact-root"
        };
        push_finding(findings, code, error.detail);
        return;
    }
    let code = match error.kind {
        SecureArtifactErrorKind::UnsafeUri => "invalid-stage1-artifact-uri",
        SecureArtifactErrorKind::Missing => "missing-stage1-artifact-file",
        SecureArtifactErrorKind::Symlink => "stage1-artifact-symlink-rejected",
        SecureArtifactErrorKind::Escape => "stage1-artifact-path-escape",
        SecureArtifactErrorKind::NotRegular => "invalid-stage1-artifact-file",
        SecureArtifactErrorKind::TooLarge => "stage1-artifact-too-large",
        SecureArtifactErrorKind::ResourceExhausted => "unreadable-stage1-artifact-file",
        SecureArtifactErrorKind::ConcurrentMutation => "stage1-artifact-concurrent-mutation",
        SecureArtifactErrorKind::Unsupported => "stage1-secure-artifact-reader-unavailable",
        SecureArtifactErrorKind::Io => "unreadable-stage1-artifact-file",
    };
    push_finding(findings, code, error.detail);
}

fn push_finding(
    findings: &mut Vec<Stage1ValidationFinding>,
    code: &str,
    detail: impl Into<String>,
) {
    findings.push(Stage1ValidationFinding { code: code.to_string(), detail: detail.into() });
}
