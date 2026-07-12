use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityStatus, BindingReceipt, CanonicalState, Digest,
    EventKind, ExtensionSupport, HandoffPhase, Identity, LeaseEpoch, Rights, SnapshotEnvelope,
    canonical_digest, snapshot_integrity, state_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    stage1::{
        STAGE1_CASE_DEFINITIONS, STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION, Stage1ArtifactReference,
        Stage1BindingReceiptReference, Stage1CaseEvidence, Stage1EvidenceBundle,
        Stage1ExecutionEnvironment, Stage1ExpectedOwnership, Stage1ResourceKind,
        Stage1SemanticTraceArtifact, Stage1TraceRole, Stage1ValidationFinding,
        Stage1VersionedIdentity, VerifiedStage1Artifacts, stage1_expected_ownership,
    },
    stage2::{
        ObservedRuntimeIdentity, ProtocolCommandKind, ProtocolResponseProjection, Stage2Runtime,
        observed_runtime_matches, project_request_command, project_response,
        runtime_identity_matches, success_result_matches, translation_provenance_matches,
        validate_initialize_worker_binding,
    },
};

pub(crate) fn validate_artifact_contents(
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
) -> Vec<Stage1ValidationFinding> {
    let mut findings = Vec::new();
    let mut runtime_observations = RawRuntimeObservations::default();
    let matrix = validate_provenance_contents(bundle, artifacts, &mut findings);
    for case in &bundle.cases {
        validate_case_contents(
            bundle,
            case,
            matrix.as_ref(),
            artifacts,
            &mut runtime_observations,
            &mut findings,
        );
    }
    findings
}

fn finding(
    findings: &mut Vec<Stage1ValidationFinding>,
    code: &'static str,
    detail: impl Into<String>,
) {
    findings.push(Stage1ValidationFinding { code: code.to_owned(), detail: detail.into() });
}

fn read_artifact<'a>(
    artifacts: &'a VerifiedStage1Artifacts,
    uri: &str,
    label: &str,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<&'a [u8]> {
    match artifacts.bytes(uri) {
        Some(bytes) => Some(bytes),
        None => {
            finding(
                findings,
                "missing-stage1-captured-artifact",
                format!("{label} {uri} was not retained in the stable artifact view"),
            );
            None
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn contract_digest_hex(digest: Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identity_hex(identity: Identity) -> String {
    identity.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    schema: String,
    files: Vec<SourceManifestFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatrixNamespaceAvailability {
    Correct,
    Missing,
    Wrong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatrixAuthorityPolicyMode {
    Sufficient,
    Missing,
    Broader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixOptions {
    case_id: String,
    namespace_availability: MatrixNamespaceAvailability,
    authority_policy: MatrixAuthorityPolicyMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatrixFaultPoint {
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    AfterKvCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatrixDestinationSupport {
    Compatible,
    TimerSemanticsUnsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixEntry {
    case_id: String,
    options: MatrixOptions,
    config_digest: Digest,
    policy_digest: Digest,
    source_fault: Option<MatrixFaultPoint>,
    destination_fault: Option<MatrixFaultPoint>,
    destination_support: MatrixDestinationSupport,
    scenario: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixManifest {
    schema: String,
    entries: Vec<MatrixEntry>,
    provider_fault_coverage: Vec<FaultCoverageEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultCoverageEntry {
    point: MatrixFaultPoint,
    case_id: String,
    role: String,
    trigger: String,
    expected: String,
}

fn validate_provenance_contents(
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<MatrixManifest> {
    let component_reference = &bundle.provenance.artifacts.component;
    if artifacts.sha256(&component_reference.uri)
        != Some(bundle.provenance.component_sha256.as_str())
    {
        finding(
            findings,
            "inconsistent-stage1-component-provenance",
            "component artifact bytes do not produce the claimed component digest",
        );
    }

    let profile_reference = &bundle.provenance.artifacts.profile;
    if let Some(bytes) =
        read_artifact(artifacts, &profile_reference.uri, "Stage 1 profile", findings)
    {
        match serde_json::from_slice::<visa_profile::CooperativeHandoffProfile>(bytes) {
            Ok(profile) => match canonical_digest(&profile) {
                Ok(digest) if contract_digest_hex(digest) == bundle.provenance.profile_sha256 => {}
                _ => finding(
                    findings,
                    "inconsistent-stage1-profile-provenance",
                    "typed profile artifact does not produce the claimed profile digest",
                ),
            },
            Err(error) => finding(
                findings,
                "invalid-stage1-profile-artifact",
                format!("cannot parse {}: {error}", profile_reference.uri),
            ),
        }
    }

    let source_reference = &bundle.provenance.artifacts.source_manifest;
    if let Some(bytes) =
        read_artifact(artifacts, &source_reference.uri, "source provenance manifest", findings)
    {
        match serde_json::from_slice::<SourceManifest>(bytes) {
            Ok(manifest) => validate_source_manifest(bundle, &manifest, findings),
            Err(error) => finding(
                findings,
                "invalid-stage1-source-manifest",
                format!("cannot parse {}: {error}", source_reference.uri),
            ),
        }
    }

    let build_source_reference = &bundle.provenance.artifacts.build_source_manifest;
    if let Some(bytes) = read_artifact(
        artifacts,
        &build_source_reference.uri,
        "build source provenance manifest",
        findings,
    ) {
        match serde_json::from_slice::<SourceManifest>(bytes) {
            Ok(manifest) => validate_source_manifest(bundle, &manifest, findings),
            Err(error) => finding(
                findings,
                "invalid-stage1-build-source-manifest",
                format!("cannot parse {}: {error}", build_source_reference.uri),
            ),
        }
    }

    let toolchain_reference = &bundle.provenance.artifacts.toolchain;
    if artifacts.sha256(&toolchain_reference.uri)
        != Some(bundle.provenance.toolchain_sha256.as_str())
    {
        finding(
            findings,
            "inconsistent-stage1-toolchain-provenance",
            "toolchain artifact bytes do not produce the claimed toolchain digest",
        );
    }

    let build_toolchain_reference = &bundle.provenance.artifacts.build_toolchain;
    if artifacts.sha256(&build_toolchain_reference.uri)
        != Some(bundle.provenance.toolchain_sha256.as_str())
    {
        finding(
            findings,
            "inconsistent-stage1-build-toolchain-provenance",
            "build toolchain artifact does not match the runtime toolchain digest",
        );
    }

    let executable_reference = &bundle.provenance.artifacts.executable;
    if artifacts.sha256(&executable_reference.uri)
        != Some(bundle.provenance.executable_sha256.as_str())
    {
        finding(
            findings,
            "inconsistent-stage1-executable-provenance",
            "executable artifact does not match the claimed executable digest",
        );
    }

    let matrix_reference = &bundle.provenance.artifacts.matrix_manifest;
    let bytes =
        read_artifact(artifacts, &matrix_reference.uri, "matrix provenance manifest", findings)?;
    match serde_json::from_slice::<MatrixManifest>(bytes) {
        Ok(matrix) => {
            validate_matrix_manifest(bundle, &matrix, findings);
            Some(matrix)
        }
        Err(error) => {
            finding(
                findings,
                "invalid-stage1-matrix-manifest",
                format!("cannot parse {}: {error}", matrix_reference.uri),
            );
            None
        }
    }
}

fn validate_source_manifest(
    bundle: &Stage1EvidenceBundle,
    manifest: &SourceManifest,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    if manifest.schema != "visa-stage1-source-manifest-v1" || manifest.files.is_empty() {
        finding(
            findings,
            "invalid-stage1-source-manifest",
            "source manifest has the wrong schema or no files",
        );
    }
    let mut paths = BTreeSet::new();
    let mut previous = None;
    for file in &manifest.files {
        let path = Path::new(&file.path);
        if file.path.is_empty()
            || path.is_absolute()
            || path.components().any(|component| !matches!(component, Component::Normal(_)))
            || !paths.insert(file.path.as_str())
            || previous.is_some_and(|value: &str| value >= file.path.as_str())
            || !is_sha256(&file.sha256)
        {
            finding(
                findings,
                "invalid-stage1-source-manifest-entry",
                format!("invalid or unordered source manifest entry {}", file.path),
            );
        }
        previous = Some(file.path.as_str());
    }
    match serde_json::to_vec(manifest) {
        Ok(canonical) if sha256_hex(&canonical) == bundle.provenance.source_sha256 => {}
        Ok(_) => finding(
            findings,
            "inconsistent-stage1-source-provenance",
            "source manifest does not produce the claimed source digest",
        ),
        Err(error) => finding(
            findings,
            "invalid-stage1-source-manifest",
            format!("cannot canonicalize source manifest: {error}"),
        ),
    }
}

fn validate_matrix_manifest(
    bundle: &Stage1EvidenceBundle,
    matrix: &MatrixManifest,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    if matrix.schema != "visa-stage1-matrix-provenance-v1" {
        finding(
            findings,
            "invalid-stage1-matrix-manifest",
            format!("unsupported matrix schema {}", matrix.schema),
        );
    }
    let entries = matrix
        .entries
        .iter()
        .map(|entry| (entry.case_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    if entries.len() != matrix.entries.len() {
        finding(findings, "duplicate-stage1-matrix-case", "matrix contains duplicate case ids");
    }
    let expected_case_ids =
        STAGE1_CASE_DEFINITIONS.iter().map(|definition| definition.id).collect::<Vec<_>>();
    let observed_case_ids =
        matrix.entries.iter().map(|entry| entry.case_id.as_str()).collect::<Vec<_>>();
    if observed_case_ids != expected_case_ids {
        finding(
            findings,
            "invalid-stage1-matrix-registry",
            "matrix entries must exactly match the ordered 31-case Stage 1 registry",
        );
    }
    let covered_points =
        matrix.provider_fault_coverage.iter().map(|entry| entry.point).collect::<BTreeSet<_>>();
    if matrix.provider_fault_coverage.len() != 7
        || covered_points.len() != 7
        || matrix.provider_fault_coverage.iter().any(|coverage| {
            coverage.case_id.is_empty()
                || coverage.role.is_empty()
                || coverage.trigger.is_empty()
                || coverage.expected.is_empty()
                || entries.get(coverage.case_id.as_str()).is_none_or(|entry| {
                    match coverage.role.as_str() {
                        "source" => entry.source_fault != Some(coverage.point),
                        "destination" => entry.destination_fault != Some(coverage.point),
                        "supplemental-source" => {
                            coverage.case_id != "evidence-verification"
                                || !matches!(
                                    coverage.point,
                                    MatrixFaultPoint::BeforeJournalWrite
                                        | MatrixFaultPoint::AfterJournalWrite
                                        | MatrixFaultPoint::BeforeActivationBundle
                                        | MatrixFaultPoint::AfterActivationBundle
                                )
                        }
                        _ => true,
                    }
                })
        })
    {
        finding(
            findings,
            "incomplete-stage1-provider-fault-coverage",
            "matrix must map each provider fault point to one concrete scenario and bind source/destination roles to the corresponding matrix fault",
        );
    }
    for case in &bundle.cases {
        let Some(entry) = entries.get(case.case_id.as_str()) else {
            finding(
                findings,
                "missing-stage1-matrix-case",
                format!("matrix omits {}", case.case_id),
            );
            continue;
        };
        if entry.options.case_id != entry.case_id
            || contract_digest_hex(entry.config_digest) != case.case_config_sha256
            || contract_digest_hex(entry.policy_digest) != case.case_policy_sha256
        {
            finding(
                findings,
                "inconsistent-stage1-case-matrix",
                format!("{} config/policy/options do not match its matrix entry", case.case_id),
            );
        }
    }

    let config_projection = matrix
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
    let policy_projection = matrix
        .entries
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
    match canonical_digest(&(config_projection, &matrix.provider_fault_coverage)) {
        Ok(digest) if contract_digest_hex(digest) == bundle.provenance.config_sha256 => {}
        _ => finding(
            findings,
            "inconsistent-stage1-config-provenance",
            "matrix config projection does not produce the claimed config digest",
        ),
    }
    match canonical_digest(&policy_projection) {
        Ok(digest)
            if contract_digest_hex(digest)
                == bundle.environment.authority_enforcement.policy_sha256 => {}
        _ => finding(
            findings,
            "inconsistent-stage1-policy-provenance",
            "matrix policy projection does not produce the claimed enforcement policy digest",
        ),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_case_contents(
    bundle: &Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    matrix: Option<&MatrixManifest>,
    artifacts: &VerifiedStage1Artifacts,
    runtime_observations: &mut RawRuntimeObservations,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let snapshot = parse_snapshot(case, artifacts, findings);
    let traces = parse_traces(case, artifacts, findings);
    let receipts = parse_receipts(case, artifacts, findings);
    let raw = validate_raw_artifacts(
        case,
        &bundle.environment,
        matrix,
        artifacts,
        runtime_observations,
        findings,
    );

    validate_snapshot(bundle, case, snapshot.as_ref(), &traces, findings);
    validate_traces(bundle, case, snapshot.as_ref(), &traces, &raw, findings);
    validate_receipts(case, snapshot.as_ref(), &traces, &receipts, findings);
}

struct ParsedTrace {
    artifact_sha256: String,
    trace: Stage1SemanticTraceArtifact,
    replayed: Option<CanonicalState>,
}

struct ParsedReceipt {
    resource: Stage1ResourceKind,
    claimed_identity: String,
    receipt: BindingReceipt,
}

#[derive(Default)]
struct RawEvidence {
    dumps: Vec<RawDump>,
    assertion_names: BTreeSet<String>,
    revoked_provider_workers: BTreeSet<(Stage1TraceRole, String)>,
    primary_worker_pids: BTreeMap<Stage1TraceRole, u32>,
}

#[derive(Default)]
struct RawRuntimeObservations {
    source: Option<ObservedRuntimeIdentity>,
    destination: Option<ObservedRuntimeIdentity>,
}

impl RawRuntimeObservations {
    fn observe(
        &mut self,
        role: Stage1TraceRole,
        runtime: &ObservedRuntimeIdentity,
        case: &Stage1CaseEvidence,
        findings: &mut Vec<Stage1ValidationFinding>,
    ) {
        let slot = match role {
            Stage1TraceRole::Source => &mut self.source,
            Stage1TraceRole::Destination => &mut self.destination,
        };
        if let Some(previous) = slot.as_ref() {
            if previous != runtime {
                finding(
                    findings,
                    "inconsistent-stage1-runtime-identity",
                    format!(
                        "{} {} runtime identity or translation provenance changed across the matrix",
                        case.case_id,
                        trace_role_name(role)
                    ),
                );
            }
        } else {
            *slot = Some(runtime.clone());
        }
    }
}

struct RawDump {
    role: Stage1TraceRole,
    state: CanonicalState,
}

const REPORT_REGENERATION_CASE_ID: &str = "report-generation-fails-after-commit";
const REPORT_REGENERATION_ASSERTION: &str = "report-publication-failed-and-regenerated";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRegenerationDetail {
    publish_error_kind: String,
    publish_error_message: String,
    bundle_path: String,
    case_manifest_count: usize,
    case_manifest_set_sha256: String,
    regenerated_bundle_sha256: String,
    committed_state_sha256_before: String,
    committed_state_sha256_after: String,
}

fn parse_snapshot(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<SnapshotEnvelope> {
    let reference = case.artifacts.snapshot.as_ref()?;
    let bytes = read_case_artifact(case, reference, "snapshot", artifacts, findings)?;
    match serde_json::from_slice(bytes) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            finding(
                findings,
                "invalid-stage1-snapshot-artifact",
                format!("{} snapshot is not a typed SnapshotEnvelope: {error}", case.case_id),
            );
            None
        }
    }
}

fn parse_traces(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Vec<ParsedTrace> {
    let mut traces = Vec::new();
    for reference in &case.artifacts.semantic_traces {
        let Some(bytes) =
            read_case_artifact(case, reference, "semantic trace", artifacts, findings)
        else {
            continue;
        };
        let trace = match serde_json::from_slice::<Stage1SemanticTraceArtifact>(bytes) {
            Ok(trace) => trace,
            Err(error) => {
                finding(
                    findings,
                    "invalid-stage1-semantic-trace",
                    format!("{} trace {} is not typed: {error}", case.case_id, reference.uri),
                );
                continue;
            }
        };
        let replayed = replay_trace(case, &trace, findings);
        traces.push(ParsedTrace { artifact_sha256: reference.sha256.clone(), trace, replayed });
    }
    traces
}

fn replay_trace(
    case: &Stage1CaseEvidence,
    trace: &Stage1SemanticTraceArtifact,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<CanonicalState> {
    if trace.schema_version != STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage1-semantic-trace-schema",
            format!("{} has trace schema {}", case.case_id, trace.schema_version),
        );
    }
    if trace.scope.node.is_zero()
        || trace.scope.component.is_zero()
        || trace.base_state.activation.node != trace.scope.node
        || trace.base_state.component.identity != trace.scope.component
        || trace.final_state.activation.node != trace.scope.node
        || trace.final_state.component.identity != trace.scope.component
        || role_of(trace.base_state.activation.role) != trace.role
        || role_of(trace.final_state.activation.role) != trace.role
    {
        finding(
            findings,
            "inconsistent-stage1-trace-scope",
            format!(
                "{} {:?} trace scope does not match its canonical states",
                case.case_id, trace.role
            ),
        );
    }
    let replayed = match semantic_core::replay_from(
        &trace.base_state,
        trace.base_cursor,
        &trace.entries,
        infallible_state_digest,
    ) {
        Ok(state) => state,
        Err(error) => {
            finding(
                findings,
                "invalid-stage1-semantic-replay",
                format!(
                    "{} {:?} trace failed canonical replay: {error:?}",
                    case.case_id, trace.role
                ),
            );
            return None;
        }
    };
    if replayed != trace.final_state {
        finding(
            findings,
            "inconsistent-stage1-trace-final-state",
            format!(
                "{} {:?} replay does not equal its recorded final state",
                case.case_id, trace.role
            ),
        );
    }
    Some(replayed)
}

fn infallible_state_digest(state: &CanonicalState) -> Digest {
    state_digest(state).unwrap_or(Digest::ZERO)
}

const fn role_of(role: ActivationRole) -> Stage1TraceRole {
    match role {
        ActivationRole::Source => Stage1TraceRole::Source,
        ActivationRole::Destination => Stage1TraceRole::Destination,
    }
}

fn parse_receipts(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Vec<ParsedReceipt> {
    case.artifacts
        .binding_receipts
        .iter()
        .filter_map(|reference| parse_receipt(case, reference, artifacts, findings))
        .collect()
}

fn parse_receipt(
    case: &Stage1CaseEvidence,
    reference: &Stage1BindingReceiptReference,
    artifacts: &VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<ParsedReceipt> {
    let bytes =
        read_case_artifact(case, &reference.artifact, "binding receipt", artifacts, findings)?;
    match serde_json::from_slice::<BindingReceipt>(bytes) {
        Ok(receipt) => Some(ParsedReceipt {
            resource: reference.resource,
            claimed_identity: reference.receipt_id.clone(),
            receipt,
        }),
        Err(error) => {
            finding(
                findings,
                "invalid-stage1-binding-receipt-artifact",
                format!("{} receipt is not a typed BindingReceipt: {error}", case.case_id),
            );
            None
        }
    }
}

fn read_case_artifact<'a>(
    case: &Stage1CaseEvidence,
    reference: &Stage1ArtifactReference,
    label: &str,
    artifacts: &'a VerifiedStage1Artifacts,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<&'a [u8]> {
    read_artifact(artifacts, &reference.uri, &format!("{} {label}", case.case_id), findings)
}

fn validate_snapshot(
    bundle: &Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    snapshot: Option<&SnapshotEnvelope>,
    traces: &[ParsedTrace],
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    let body = &snapshot.body;
    let integrity = snapshot_integrity(body);
    if integrity != Ok(snapshot.integrity) {
        finding(
            findings,
            "invalid-stage1-snapshot-integrity",
            format!("{} snapshot body does not match its integrity digest", case.case_id),
        );
    }
    if identity_hex(body.snapshot.handoff) != case.handoff_id
        || identity_hex(body.snapshot.snapshot) != case.snapshot_id
        || contract_digest_hex(body.component_digest) != bundle.provenance.component_sha256
        || contract_digest_hex(body.profile_digest) != bundle.provenance.profile_sha256
        || body.source_lease_epoch.0 != case.authority.source_lease_epoch
        || body.portable_state.is_empty()
    {
        finding(
            findings,
            "inconsistent-stage1-snapshot-contract",
            format!(
                "{} snapshot identities, digests, lease epoch, or portable state disagree",
                case.case_id
            ),
        );
    }

    match traces.iter().find(|trace| trace.trace.role == Stage1TraceRole::Source) {
        Some(source) => validate_source_snapshot_projection(case, snapshot, source, findings),
        None => finding(
            findings,
            "missing-stage1-source-snapshot-trace",
            format!("{} snapshot has no canonical source trace", case.case_id),
        ),
    }
    if let Some(destination) =
        traces.iter().find(|trace| trace.trace.role == Stage1TraceRole::Destination)
    {
        let supported = body
            .extensions
            .iter()
            .map(|extension| ExtensionSupport { id: extension.id, version: extension.version })
            .collect::<Vec<_>>();
        match semantic_core::restore(
            snapshot,
            integrity.unwrap_or(Digest::ZERO),
            body.component_digest,
            body.profile_digest,
            body.profile_version,
            &supported,
            destination.trace.scope.node,
        ) {
            Ok(expected) if expected == destination.trace.base_state => {}
            Ok(_) => finding(
                findings,
                "inconsistent-stage1-destination-trace-base",
                format!(
                    "{} destination trace is not based on the snapshot restore state",
                    case.case_id
                ),
            ),
            Err(error) => finding(
                findings,
                "invalid-stage1-snapshot-restore",
                format!("{} snapshot cannot seed destination replay: {error:?}", case.case_id),
            ),
        }
    }
}

fn validate_source_snapshot_projection(
    case: &Stage1CaseEvidence,
    snapshot: &SnapshotEnvelope,
    source: &ParsedTrace,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let cursor = snapshot.body.snapshot.journal_position;
    if source.trace.base_cursor.0 > cursor.0 {
        finding(
            findings,
            "missing-stage1-snapshot-trace-prefix",
            format!("{} source trace starts after its snapshot cursor", case.case_id),
        );
        return;
    }
    let prefix = source
        .trace
        .entries
        .iter()
        .take_while(|entry| entry.position.0 <= cursor.0)
        .cloned()
        .collect::<Vec<_>>();
    let exported = prefix.last().is_some_and(|entry| {
        entry.position == cursor
            && matches!(
                &entry.event.kind,
                EventKind::SnapshotExported { snapshot: record }
                    if record == &snapshot.body.snapshot
            )
    });
    let projected = semantic_core::replay_from(
        &source.trace.base_state,
        source.trace.base_cursor,
        &prefix,
        infallible_state_digest,
    );
    if !exported
        || !matches!(projected, Ok(ref state) if state.snapshot_body().as_ref() == Some(&snapshot.body))
    {
        finding(
            findings,
            "inconsistent-stage1-snapshot-trace",
            format!(
                "{} snapshot is not the canonical projection at its source journal cursor",
                case.case_id
            ),
        );
    }
}

fn validate_traces(
    bundle: &Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    _snapshot: Option<&SnapshotEnvelope>,
    traces: &[ParsedTrace],
    raw: &RawEvidence,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let mut roles = BTreeSet::new();
    let claimed = traces.iter().filter(|trace| trace.trace.claimed_final).collect::<Vec<_>>();
    for trace in traces {
        if !roles.insert(trace.trace.role) {
            finding(
                findings,
                "duplicate-stage1-trace-role",
                format!("{} contains multiple {:?} traces", case.case_id, trace.trace.role),
            );
        }
        for state in [&trace.trace.base_state, &trace.trace.final_state] {
            if contract_digest_hex(state.component_digest) != bundle.provenance.component_sha256
                || contract_digest_hex(state.profile_digest) != bundle.provenance.profile_sha256
            {
                finding(
                    findings,
                    "inconsistent-stage1-trace-provenance",
                    format!(
                        "{} {:?} trace uses different component/profile digests",
                        case.case_id, trace.trace.role
                    ),
                );
            }
        }
    }
    validate_authority_roots(case, traces, findings);
    if claimed.len() != 1 {
        finding(
            findings,
            "invalid-stage1-claimed-final-trace",
            format!(
                "{} must mark exactly one trace as the authoritative final branch",
                case.case_id
            ),
        );
        return;
    }
    let claimed = claimed[0];
    let expected_role = match stage1_expected_ownership(case.outcome) {
        Stage1ExpectedOwnership::SourceRetained => Stage1TraceRole::Source,
        Stage1ExpectedOwnership::DestinationCommitted
        | Stage1ExpectedOwnership::DestinationRecoveryRequired => Stage1TraceRole::Destination,
    };
    let digest = state_digest(&claimed.trace.final_state).unwrap_or(Digest::ZERO);
    if claimed.trace.role != expected_role
        || contract_digest_hex(digest) != case.state.state_sha256
        || contract_digest_hex(digest) != case.state.replay_state_sha256
        || claimed.replayed.as_ref() != Some(&claimed.trace.final_state)
        || !case.state.trace_sha256s.contains(&claimed.artifact_sha256)
    {
        finding(
            findings,
            "inconsistent-stage1-claimed-final-state",
            format!("{} claimed final trace does not prove its reported state", case.case_id),
        );
    }
    if case.outcome == crate::stage1::Stage1CaseOutcome::RevocationRejectedNoResurrection
        && !claimed.trace.final_state.authorities.iter().any(|grant| {
            grant.status == AuthorityStatus::Revoked
                && grant.authority.generation != contract_core::Generation::INITIAL
        })
    {
        finding(
            findings,
            "missing-stage1-revoked-authority-tombstone",
            format!(
                "{} final source trace has no generation-advanced revoked authority",
                case.case_id
            ),
        );
    }
    validate_final_ownership(case, &claimed.trace, findings);

    if !raw
        .dumps
        .iter()
        .any(|dump| dump.role == claimed.trace.role && dump.state == claimed.trace.final_state)
    {
        finding(
            findings,
            "missing-stage1-final-state-observation",
            format!(
                "{} raw worker dumps do not contain the claimed final canonical state",
                case.case_id
            ),
        );
    }
}

fn validate_authority_roots(
    case: &Stage1CaseEvidence,
    traces: &[ParsedTrace],
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let source_matches = traces
        .iter()
        .find(|trace| trace.trace.role == Stage1TraceRole::Source)
        .and_then(|trace| canonical_digest(trace.trace.final_state.authorities.as_slice()).ok())
        .is_some_and(|digest| {
            contract_digest_hex(digest) == case.authority.source_authority_root_sha256
        });
    if !source_matches {
        finding(
            findings,
            "inconsistent-stage1-source-authority-root",
            format!(
                "{} source authority root is not derived from its canonical trace",
                case.case_id
            ),
        );
    }

    let destination_digest = match stage1_expected_ownership(case.outcome) {
        Stage1ExpectedOwnership::SourceRetained => {
            let empty: &[contract_core::AuthorityGrant] = &[];
            canonical_digest(empty).ok()
        }
        Stage1ExpectedOwnership::DestinationCommitted
        | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            traces.iter().find(|trace| trace.trace.role == Stage1TraceRole::Destination).and_then(
                |trace| canonical_digest(trace.trace.final_state.authorities.as_slice()).ok(),
            )
        }
    };
    if !destination_digest.is_some_and(|digest| {
        contract_digest_hex(digest) == case.authority.destination_authority_root_sha256
    }) {
        finding(
            findings,
            "inconsistent-stage1-destination-authority-root",
            format!(
                "{} destination authority root is not derived from its canonical outcome",
                case.case_id
            ),
        );
    }
}

fn validate_final_ownership(
    case: &Stage1CaseEvidence,
    trace: &Stage1SemanticTraceArtifact,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let final_state = &trace.final_state;
    let consistent = match stage1_expected_ownership(case.outcome) {
        Stage1ExpectedOwnership::SourceRetained => {
            let expected_phase = match case.outcome {
                crate::stage1::Stage1CaseOutcome::RevocationRejectedNoResurrection => {
                    HandoffPhase::Exported
                }
                crate::stage1::Stage1CaseOutcome::UnknownKvBlockedIndeterminate => {
                    HandoffPhase::Quiescing
                }
                crate::stage1::Stage1CaseOutcome::DurableWriteBlockedIndeterminate => {
                    HandoffPhase::Exported
                }
                _ => HandoffPhase::Running,
            };
            trace.role == Stage1TraceRole::Source
                && final_state.activation.role == ActivationRole::Source
                && final_state.activation.status == ActivationStatus::Active
                && final_state.phase == expected_phase
                && final_state.ownership.owner == Some(trace.scope.node)
                && final_state.ownership.epoch == LeaseEpoch(case.authority.source_lease_epoch)
                && case.authority.destination_lease_epoch.is_none()
        }
        Stage1ExpectedOwnership::DestinationCommitted => {
            let epoch = case.authority.destination_lease_epoch.map(LeaseEpoch);
            trace.role == Stage1TraceRole::Destination
                && final_state.activation.role == ActivationRole::Destination
                && final_state.activation.status == ActivationStatus::Active
                && final_state.phase == HandoffPhase::Running
                && final_state.ownership.owner == Some(trace.scope.node)
                && Some(final_state.ownership.epoch) == epoch
        }
        Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            let epoch = case.authority.destination_lease_epoch.map(LeaseEpoch);
            trace.role == Stage1TraceRole::Destination
                && final_state.activation.role == ActivationRole::Destination
                && final_state.activation.status == ActivationStatus::Active
                && final_state.phase == HandoffPhase::Committed
                && final_state.ownership.owner == Some(trace.scope.node)
                && Some(final_state.ownership.epoch) == epoch
        }
    };
    if !consistent || final_state.ownership.epoch.0 != case.authority.fencing_epoch {
        finding(
            findings,
            "inconsistent-stage1-final-ownership-trace",
            format!("{} final canonical branch disagrees with ownership evidence", case.case_id),
        );
    }
}

fn validate_receipts(
    case: &Stage1CaseEvidence,
    snapshot: Option<&SnapshotEnvelope>,
    traces: &[ParsedTrace],
    receipts: &[ParsedReceipt],
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let Some(snapshot) = snapshot else {
        if !receipts.is_empty() {
            finding(
                findings,
                "binding-receipt-without-stage1-snapshot",
                format!("{} contains binding receipts without a snapshot", case.case_id),
            );
        }
        return;
    };
    let destination = traces.iter().find(|trace| trace.trace.role == Stage1TraceRole::Destination);
    let prepared = destination
        .and_then(|trace| trace.trace.final_state.prepared_destination.as_ref())
        .or_else(|| {
            destination.and_then(|trace| {
                trace.trace.entries.iter().rev().find_map(|entry| match &entry.event.kind {
                    EventKind::DestinationPrepared { prepared } => Some(prepared),
                    _ => None,
                })
            })
        });
    let mut binding_ids = BTreeSet::new();
    for parsed in receipts {
        let receipt = &parsed.receipt;
        let (claim, rights) = match parsed.resource {
            Stage1ResourceKind::PausedDurationTimer => {
                (snapshot.body.claims.timer.resource, snapshot.body.claims.timer.required_rights)
            }
            Stage1ResourceKind::DurableKeyValue => (
                snapshot.body.claims.key_value.resource,
                snapshot.body.claims.key_value.required_rights,
            ),
        };
        let expected_epoch = case.authority.destination_lease_epoch.map(LeaseEpoch);
        let receipt_in_trace = prepared
            .is_some_and(|prepared| prepared.bindings.iter().any(|candidate| candidate == receipt));
        let authority_in_trace = prepared.is_some_and(|prepared| {
            prepared.authorities.iter().any(|grant| {
                grant.authority == receipt.authority
                    && grant.subject.identity == snapshot.body.component.identity
                    && grant.resource == claim
                    && grant.rights == rights
                    && grant.status == AuthorityStatus::Active
            })
        });
        if identity_hex(receipt.binding.identity) != parsed.claimed_identity
            || !binding_ids.insert(receipt.binding)
            || receipt.handoff != snapshot.body.snapshot.handoff
            || receipt.snapshot != snapshot.body.snapshot.snapshot
            || receipt.claim != claim
            || receipt.exposed_rights != rights
            || Some(receipt.lease_epoch) != expected_epoch
            || destination.is_some_and(|trace| receipt.node != trace.trace.scope.node)
            || !receipt_in_trace
            || !authority_in_trace
        {
            finding(
                findings,
                "inconsistent-stage1-binding-receipt-content",
                format!(
                    "{} {:?} receipt disagrees with snapshot, authority, epoch, or trace",
                    case.case_id, parsed.resource
                ),
            );
        }
    }
    if stage1_expected_ownership(case.outcome) != Stage1ExpectedOwnership::SourceRetained {
        validate_exact_destination_authority(case, snapshot, prepared, findings);
    }
}

fn validate_exact_destination_authority(
    case: &Stage1CaseEvidence,
    snapshot: &SnapshotEnvelope,
    prepared: Option<&contract_core::PreparedDestination>,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let Some(prepared) = prepared else {
        finding(
            findings,
            "missing-stage1-prepared-destination-trace",
            format!("{} committed without typed prepared destination state", case.case_id),
        );
        return;
    };
    let expected_subject = contract_core::EntityRef::new(
        snapshot.body.component.identity,
        prepared.component_generation,
    );
    let expected = [
        (expected_subject, Rights::HANDOFF),
        (snapshot.body.claims.timer.resource, snapshot.body.claims.timer.required_rights),
        (snapshot.body.claims.key_value.resource, snapshot.body.claims.key_value.required_rights),
    ];
    let observed = prepared
        .authorities
        .iter()
        .map(|grant| (grant.resource, grant.rights))
        .collect::<BTreeSet<_>>();
    let exact = prepared.authorities.len() == expected.len()
        && observed.len() == expected.len()
        && expected.iter().all(|entry| observed.contains(entry))
        && prepared.authorities.iter().all(|grant| {
            grant.subject == expected_subject && grant.status == AuthorityStatus::Active
        });
    if !exact {
        finding(
            findings,
            "excess-stage1-destination-authority",
            format!("{} destination authority set is not the exact Stage 1 profile", case.case_id),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawTranscriptStream {
    ParentRequest,
    WorkerResponse,
    WorkerStderr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTranscriptLine {
    worker: String,
    pid: u32,
    sequence: u64,
    stream: RawTranscriptStream,
    line: String,
}

#[derive(Debug, Deserialize)]
struct RawDumpResult {
    canonical_state: Box<CanonicalState>,
    state_digest: Digest,
    portable_component_state: Option<Vec<u8>>,
}

fn validate_raw_artifacts(
    case: &Stage1CaseEvidence,
    environment: &Stage1ExecutionEnvironment,
    matrix: Option<&MatrixManifest>,
    artifacts: &VerifiedStage1Artifacts,
    runtime_observations: &mut RawRuntimeObservations,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> RawEvidence {
    let mut evidence = RawEvidence::default();
    let observed_raw_uris = case
        .artifacts
        .raw_execution
        .iter()
        .map(|reference| reference.uri.as_str())
        .collect::<Vec<_>>();
    let raw_prefix = format!("cases/{}/raw", case.case_id);
    let mut expected_raw_uris = vec![
        format!("{raw_prefix}/source.jsonl"),
        format!("{raw_prefix}/destination.jsonl"),
        format!("{raw_prefix}/assertions.jsonl"),
    ];
    if case.case_id == "performance-observations" {
        expected_raw_uris.push(format!("{raw_prefix}/performance.json"));
    }
    let expected_raw_uri_refs = expected_raw_uris.iter().map(String::as_str).collect::<Vec<_>>();
    if observed_raw_uris != expected_raw_uri_refs {
        finding(
            findings,
            "invalid-stage1-raw-artifact-set",
            format!(
                "{} raw artifacts must be the exact ordered canonical URI set {:?}",
                case.case_id, expected_raw_uris
            ),
        );
    }
    for reference in &case.artifacts.raw_execution {
        let Some(bytes) = read_case_artifact(case, reference, "raw execution", artifacts, findings)
        else {
            continue;
        };
        let file_name = Path::new(&reference.uri)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        match file_name {
            "source.jsonl" => validate_transcript(
                case,
                TranscriptExpectation {
                    role: Stage1TraceRole::Source,
                    runtime: &environment.source_runtime,
                    matrix,
                },
                bytes,
                &mut evidence,
                runtime_observations,
                findings,
            ),
            "destination.jsonl" => validate_transcript(
                case,
                TranscriptExpectation {
                    role: Stage1TraceRole::Destination,
                    runtime: &environment.destination_runtime,
                    matrix,
                },
                bytes,
                &mut evidence,
                runtime_observations,
                findings,
            ),
            "assertions.jsonl" => validate_assertions(case, bytes, &mut evidence, findings),
            "performance.json" => validate_performance_raw(case, bytes, findings),
            _ => finding(
                findings,
                "unknown-stage1-raw-artifact",
                format!("{} has untyped raw artifact {}", case.case_id, reference.uri),
            ),
        }
    }
    if evidence.assertion_names.is_empty() {
        finding(
            findings,
            "missing-stage1-raw-assertions",
            format!("{} has no typed passing assertion observations", case.case_id),
        );
    }
    match (
        evidence.primary_worker_pids.get(&Stage1TraceRole::Source),
        evidence.primary_worker_pids.get(&Stage1TraceRole::Destination),
    ) {
        (Some(source), Some(destination)) if source != destination => {}
        (Some(_), Some(_)) => finding(
            findings,
            "non-independent-stage1-primary-workers",
            format!("{} source and destination primary workers share one pid", case.case_id),
        ),
        _ => finding(
            findings,
            "missing-stage1-primary-worker-process",
            format!("{} does not bind both primary worker processes", case.case_id),
        ),
    }
    if case.case_id == REPORT_REGENERATION_CASE_ID
        && !evidence.assertion_names.contains(REPORT_REGENERATION_ASSERTION)
    {
        finding(
            findings,
            "missing-stage1-report-regeneration-assertion",
            format!("{} does not prove failed publication and evidence regeneration", case.case_id),
        );
    }
    if case.outcome == crate::stage1::Stage1CaseOutcome::RevocationRejectedNoResurrection {
        let roles = evidence
            .revoked_provider_workers
            .iter()
            .map(|(role, _)| *role)
            .collect::<BTreeSet<_>>();
        if evidence.revoked_provider_workers.len() < 2
            || !roles.contains(&Stage1TraceRole::Source)
            || !roles.contains(&Stage1TraceRole::Destination)
        {
            finding(
                findings,
                "missing-stage1-revocation-provider-observation",
                format!(
                    "{} must observe Provider/Revoked from destination prepare and fresh source recovery",
                    case.case_id
                ),
            );
        }
        for required in
            ["revoked-capability-not-resurrected", "source-recovery-requires-reauthorization"]
        {
            if !evidence.assertion_names.contains(required) {
                finding(
                    findings,
                    "missing-stage1-revocation-assertion",
                    format!("{} omits required assertion {required}", case.case_id),
                );
            }
        }
    }
    evidence
}

struct TranscriptExpectation<'a> {
    role: Stage1TraceRole,
    runtime: &'a Stage1VersionedIdentity,
    matrix: Option<&'a MatrixManifest>,
}

fn validate_transcript(
    case: &Stage1CaseEvidence,
    expectation: TranscriptExpectation<'_>,
    bytes: &[u8],
    evidence: &mut RawEvidence,
    runtime_observations: &mut RawRuntimeObservations,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let TranscriptExpectation { role, runtime: expected_runtime_identity, matrix } = expectation;
    let lines = parse_json_lines::<RawTranscriptLine>(
        case,
        "worker transcript",
        bytes,
        "invalid-stage1-raw-transcript",
        findings,
    );
    let mut worker_processes = BTreeMap::<String, (u32, u64)>::new();
    let mut requests = BTreeMap::new();
    let mut responses = BTreeSet::new();
    let mut worker_handshakes = BTreeMap::<String, RawWorkerHandshake>::new();
    let mut primary_initializations = 0_usize;
    let primary_worker = format!("{}-{}", case.case_id, trace_role_name(role));
    for transcript in lines {
        if transcript.pid == 0
            || !transcript.worker.starts_with(&case.case_id)
            || transcript.sequence == 0
        {
            finding(
                findings,
                "invalid-stage1-raw-transcript-sequence",
                format!("{} contains an invalid worker transcript sequence", case.case_id),
            );
            continue;
        }
        if let Some((pid, last_sequence)) = worker_processes.get_mut(&transcript.worker) {
            if *pid != transcript.pid {
                finding(
                    findings,
                    "invalid-stage1-worker-process",
                    format!(
                        "{} worker {} changed pid within one transcript",
                        case.case_id, transcript.worker
                    ),
                );
                continue;
            }
            if last_sequence.checked_add(1) != Some(transcript.sequence) {
                finding(
                    findings,
                    "invalid-stage1-raw-transcript-sequence",
                    format!(
                        "{} contains a non-contiguous worker transcript sequence",
                        case.case_id
                    ),
                );
                continue;
            }
            *last_sequence = transcript.sequence;
        } else {
            if transcript.sequence != 1 {
                finding(
                    findings,
                    "invalid-stage1-raw-transcript-sequence",
                    format!("{} worker transcript does not begin at sequence 1", case.case_id),
                );
                continue;
            }
            worker_processes
                .insert(transcript.worker.clone(), (transcript.pid, transcript.sequence));
        }
        if transcript.stream == RawTranscriptStream::WorkerStderr {
            continue;
        }
        let value = match serde_json::from_str::<serde_json::Value>(&transcript.line) {
            Ok(value) => value,
            Err(error) => {
                finding(
                    findings,
                    "invalid-stage1-worker-protocol-json",
                    format!("{} raw protocol line is invalid: {error}", case.case_id),
                );
                continue;
            }
        };
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        let id = value.get("id").and_then(serde_json::Value::as_str).unwrap_or_default();
        if version != Some(crate::STAGE1_WORKER_PROTOCOL_VERSION) || id.is_empty() {
            finding(
                findings,
                "invalid-stage1-worker-protocol-envelope",
                format!("{} raw protocol envelope has invalid version or id", case.case_id),
            );
            continue;
        }
        match transcript.stream {
            RawTranscriptStream::ParentRequest => {
                let command = value.get("command").and_then(serde_json::Value::as_object);
                let untrusted_command_kind = command
                    .and_then(|command| command.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let projection = match project_request_command(&value) {
                    Ok(projection) => Some(projection),
                    Err(detail) => {
                        finding(
                            findings,
                            "invalid-stage1-worker-request",
                            format!(
                                "{} request {id} has an invalid exact shape: {detail}",
                                case.case_id
                            ),
                        );
                        None
                    }
                };
                let command_kind = projection.map(|projection| projection.kind);
                let permits_no_response =
                    projection.is_some_and(|projection| projection.permits_no_response);
                let forbids_response =
                    projection.is_some_and(|projection| projection.forbids_response);
                let is_initialize = command_kind == Some(ProtocolCommandKind::Initialize);
                let handshake = worker_handshakes.entry(transcript.worker.clone()).or_default();
                if !handshake.saw_request && !is_initialize {
                    finding(
                        findings,
                        "stage1-worker-first-request-not-initialize",
                        format!(
                            "{} worker {} did not initialize before its first command",
                            case.case_id, transcript.worker
                        ),
                    );
                }
                handshake.saw_request = true;
                let initialization = command.filter(|_| is_initialize).map(|_| {
                    parse_raw_initialization(
                        case,
                        role,
                        transcript.worker == primary_worker,
                        &transcript.worker,
                        expected_runtime_identity,
                        matrix,
                        &value,
                    )
                });
                let initialization = match initialization.transpose() {
                    Ok(initialization) => initialization,
                    Err(detail) => {
                        finding(
                            findings,
                            "invalid-stage1-initialize-request",
                            format!("{} {detail}", case.case_id),
                        );
                        None
                    }
                };
                if is_initialize {
                    if handshake.initialize_request_id.is_some() {
                        finding(
                            findings,
                            "duplicate-stage1-worker-initialization",
                            format!(
                                "{} worker {} requested initialization more than once",
                                case.case_id, transcript.worker
                            ),
                        );
                    } else {
                        handshake.initialize_request_id = Some(id.to_owned());
                        handshake.state = RawInitializationState::Pending;
                    }
                } else if handshake.state != RawInitializationState::Succeeded {
                    finding(
                        findings,
                        "stage1-worker-command-before-initialization",
                        format!(
                            "{} worker {} issued a command before successful initialization",
                            case.case_id, transcript.worker
                        ),
                    );
                }
                if command.is_none()
                    || requests
                        .insert(
                            (transcript.worker.clone(), id.to_owned()),
                            RawRequestObservation {
                                kind: command_kind,
                                kind_name: untrusted_command_kind.to_owned(),
                                permits_no_response,
                                forbids_response,
                                initialization,
                            },
                        )
                        .is_some()
                {
                    finding(
                        findings,
                        "invalid-stage1-worker-request",
                        format!(
                            "{} contains a malformed or duplicate worker request",
                            case.case_id
                        ),
                    );
                }
            }
            RawTranscriptStream::WorkerResponse => {
                let response = match serde_json::from_value::<RawProtocolResponse>(value.clone()) {
                    Ok(response)
                        if response.version == crate::STAGE1_WORKER_PROTOCOL_VERSION
                            && !response.id.is_empty() =>
                    {
                        response
                    }
                    Ok(_) => {
                        finding(
                            findings,
                            "invalid-stage1-worker-protocol-response",
                            format!("{} response {id} has an invalid version or id", case.case_id),
                        );
                        continue;
                    }
                    Err(error) => {
                        finding(
                            findings,
                            "invalid-stage1-worker-protocol-response",
                            format!("{} response {id} has an invalid shape: {error}", case.case_id),
                        );
                        continue;
                    }
                };
                let request_key = (transcript.worker.clone(), id.to_owned());
                let request = requests.get(&request_key).cloned();
                if request.is_none() {
                    finding(
                        findings,
                        "unmatched-stage1-worker-response",
                        format!("{} response {id} has no matching request", case.case_id),
                    );
                }
                let first_response = responses.insert(request_key);
                if !first_response {
                    finding(
                        findings,
                        "duplicate-stage1-worker-response",
                        format!("{} response {id} is duplicated", case.case_id),
                    );
                }
                if first_response
                    && request.as_ref().is_some_and(|request| request.forbids_response)
                {
                    finding(
                        findings,
                        "unexpected-stage1-worker-response",
                        format!(
                            "{} worker {} request {id} ({}) forbids a response",
                            case.case_id,
                            transcript.worker,
                            request
                                .as_ref()
                                .map_or("unknown", |request| request.kind_name.as_str())
                        ),
                    );
                }
                let result = match &response.outcome {
                    RawProtocolOutcome::Success { result } => Some(result),
                    RawProtocolOutcome::Error { .. } => None,
                };
                let result_kind = result
                    .and_then(|result| result.get("kind"))
                    .and_then(serde_json::Value::as_str);
                let response_projection = match project_response(&value) {
                    Ok(projection) => Some(projection),
                    Err(detail) => {
                        finding(
                            findings,
                            "invalid-stage1-worker-protocol-response",
                            format!(
                                "{} response {id} has an invalid closed shape: {detail}",
                                case.case_id
                            ),
                        );
                        None
                    }
                };
                if first_response
                    && let (Some(request), Some(ProtocolResponseProjection::Success(result_kind))) =
                        (request.as_ref(), response_projection)
                    && request
                        .kind
                        .is_none_or(|command| !success_result_matches(command, result_kind))
                {
                    finding(
                        findings,
                        "incompatible-stage1-worker-result",
                        format!(
                            "{} response {id} result {result_kind:?} is impossible for request {}",
                            case.case_id, request.kind_name
                        ),
                    );
                }
                if first_response
                    && request.as_ref().is_some_and(|request| {
                        request.kind == Some(ProtocolCommandKind::Initialize)
                    })
                {
                    let handshake = worker_handshakes.entry(transcript.worker.clone()).or_default();
                    if handshake.initialize_request_id.as_deref() != Some(id) {
                        finding(
                            findings,
                            "invalid-stage1-worker-initialization-order",
                            format!(
                                "{} worker {} answered an initialization outside its one handshake",
                                case.case_id, transcript.worker
                            ),
                        );
                    } else {
                        handshake.initialize_response_seen = true;
                        match &response.outcome {
                            RawProtocolOutcome::Success { result } => {
                                let runtime = request
                                    .as_ref()
                                    .and_then(|request| request.initialization.as_ref())
                                    .and_then(|initialization| {
                                        validate_initialized_runtime(
                                            case,
                                            role,
                                            expected_runtime_identity,
                                            initialization,
                                            result,
                                            findings,
                                        )
                                    });
                                if let Some(runtime) = runtime {
                                    runtime_observations.observe(role, &runtime, case, findings);
                                    handshake.state = RawInitializationState::Succeeded;
                                    if transcript.worker == primary_worker {
                                        primary_initializations += 1;
                                        if evidence
                                            .primary_worker_pids
                                            .insert(role, transcript.pid)
                                            .is_some()
                                        {
                                            finding(
                                                findings,
                                                "duplicate-stage1-primary-worker-process",
                                                format!(
                                                    "{} {} primary pid was observed twice",
                                                    case.case_id,
                                                    trace_role_name(role)
                                                ),
                                            );
                                        }
                                    }
                                } else {
                                    handshake.state = RawInitializationState::Failed;
                                    if request
                                        .as_ref()
                                        .is_none_or(|request| request.initialization.is_none())
                                    {
                                        finding(
                                            findings,
                                            "invalid-stage1-initialized-runtime",
                                            format!(
                                                "{} initialized response {id} did not answer a typed initialize request",
                                                case.case_id
                                            ),
                                        );
                                    }
                                }
                            }
                            RawProtocolOutcome::Error { error } => {
                                if !error.is_object() {
                                    finding(
                                        findings,
                                        "invalid-stage1-worker-protocol-response",
                                        format!(
                                            "{} initialize error response {id} is not an object",
                                            case.case_id
                                        ),
                                    );
                                }
                                handshake.state = RawInitializationState::Failed;
                            }
                        }
                    }
                } else if result_kind == Some("initialized") {
                    finding(
                        findings,
                        "invalid-stage1-initialized-runtime",
                        format!(
                            "{} initialized response {id} did not answer its one initialize request",
                            case.case_id
                        ),
                    );
                }
                if result_kind == Some("dump") {
                    match result
                        .cloned()
                        .and_then(|result| serde_json::from_value::<RawDumpResult>(result).ok())
                    {
                        Some(dump) => validate_raw_dump(case, role, dump, evidence, findings),
                        None => finding(
                            findings,
                            "invalid-stage1-raw-dump",
                            format!("{} contains a malformed typed worker dump", case.case_id),
                        ),
                    }
                }
                if matches!(
                    &response.outcome,
                    RawProtocolOutcome::Error { error }
                        if error.get("code").and_then(serde_json::Value::as_str) == Some("provider")
                            && error.get("provider_kind").and_then(serde_json::Value::as_str)
                                == Some("Revoked")
                ) {
                    evidence.revoked_provider_workers.insert((role, transcript.worker));
                }
            }
            RawTranscriptStream::WorkerStderr => unreachable!(),
        }
    }
    for (worker, handshake) in worker_handshakes {
        if handshake.initialize_request_id.is_none() {
            finding(
                findings,
                "missing-stage1-worker-initialization",
                format!("{} worker {worker} has no initialize request", case.case_id),
            );
        } else if !handshake.initialize_response_seen {
            finding(
                findings,
                "missing-stage1-worker-initialize-response",
                format!("{} worker {worker} has no initialize response", case.case_id),
            );
        }
    }
    for ((worker, request_id), request) in &requests {
        if !request.permits_no_response
            && !responses.contains(&(worker.clone(), request_id.clone()))
        {
            finding(
                findings,
                "missing-stage1-worker-response",
                format!(
                    "{} worker {worker} request {request_id} ({}) has no response",
                    case.case_id, request.kind_name
                ),
            );
        }
    }
    if primary_initializations != 1 {
        finding(
            findings,
            "missing-stage1-primary-initialization",
            format!(
                "{} {} transcript has {primary_initializations} primary initialized responses",
                case.case_id,
                trace_role_name(role)
            ),
        );
    }
}

#[derive(Clone, Debug)]
struct RawRequestObservation {
    kind: Option<ProtocolCommandKind>,
    kind_name: String,
    permits_no_response: bool,
    forbids_response: bool,
    initialization: Option<RawInitialization>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RawInitializationState {
    #[default]
    NotRequested,
    Pending,
    Succeeded,
    Failed,
}

#[derive(Debug, Default)]
struct RawWorkerHandshake {
    saw_request: bool,
    initialize_request_id: Option<String>,
    initialize_response_seen: bool,
    state: RawInitializationState,
}

#[derive(Clone, Debug)]
struct RawInitialization {
    role: Stage1TraceRole,
    runtime: Stage2Runtime,
    case_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtocolResponse {
    version: u64,
    id: String,
    outcome: RawProtocolOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RawProtocolOutcome {
    Success { result: serde_json::Value },
    Error { error: serde_json::Value },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInitializedResult {
    kind: String,
    role: Stage1TraceRole,
    case_id: String,
    runtime: ObservedRuntimeIdentity,
}

fn parse_raw_initialization(
    case: &Stage1CaseEvidence,
    transcript_role: Stage1TraceRole,
    primary_worker: bool,
    worker: &str,
    expected_runtime_identity: &Stage1VersionedIdentity,
    matrix: Option<&MatrixManifest>,
    value: &serde_json::Value,
) -> Result<RawInitialization, String> {
    let command = value
        .get("command")
        .and_then(serde_json::Value::as_object)
        .ok_or("initialize request command is not an object")?;
    let required = ["kind", "role", "runtime", "database_path", "options", "fault"];
    if command.len() != required.len() || required.iter().any(|field| !command.contains_key(*field))
    {
        return Err("initialize request does not have the exact protocol fields".into());
    }
    let role = match command.get("role").and_then(serde_json::Value::as_str) {
        Some("source") => Stage1TraceRole::Source,
        Some("destination") => Stage1TraceRole::Destination,
        _ => return Err("initialize request has an invalid role".into()),
    };
    if role != transcript_role {
        return Err(format!(
            "initialize request role {} does not match the {} transcript",
            trace_role_name(role),
            trace_role_name(transcript_role)
        ));
    }
    let runtime = match command.get("runtime").and_then(serde_json::Value::as_str) {
        Some("wasmtime") => Stage2Runtime::Wasmtime,
        Some("jco_node") => Stage2Runtime::JcoNode,
        _ => return Err("initialize request has an invalid runtime selector".into()),
    };
    if !runtime_identity_matches(runtime, expected_runtime_identity) {
        return Err("initialize request runtime selector does not match the environment".into());
    }
    if command.get("database_path").and_then(serde_json::Value::as_str).is_none_or(str::is_empty) {
        return Err("initialize request has an empty database path".into());
    }
    let options = serde_json::from_value::<MatrixOptions>(
        command.get("options").cloned().ok_or("initialize request options are missing")?,
    )
    .map_err(|error| format!("initialize request options are not exact: {error}"))?;
    let fault = serde_json::from_value::<Option<MatrixFaultPoint>>(
        command.get("fault").cloned().ok_or("initialize request fault is missing")?,
    )
    .map_err(|error| format!("initialize request fault is invalid: {error}"))?;
    validate_initialization_matrix_binding(
        case,
        transcript_role,
        primary_worker,
        worker,
        &options,
        fault,
        matrix,
    )?;
    Ok(RawInitialization { role, runtime, case_id: options.case_id })
}

fn validate_initialization_matrix_binding(
    case: &Stage1CaseEvidence,
    role: Stage1TraceRole,
    primary_worker: bool,
    worker: &str,
    options: &MatrixOptions,
    fault: Option<MatrixFaultPoint>,
    matrix: Option<&MatrixManifest>,
) -> Result<(), String> {
    validate_initialize_worker_binding(
        worker,
        match role {
            Stage1TraceRole::Source => "source.jsonl",
            Stage1TraceRole::Destination => "destination.jsonl",
        },
        &case.case_id,
        &options.case_id,
    )?;
    let matrix = matrix.ok_or("initialize request cannot be checked without a typed matrix")?;
    let entry = matrix
        .entries
        .iter()
        .find(|entry| entry.case_id == case.case_id)
        .ok_or("initialize request has no matrix entry")?;
    if options.case_id == case.case_id {
        if options != &entry.options {
            return Err("initialize request options do not match the matrix entry".into());
        }
        let expected_fault = if primary_worker {
            match role {
                Stage1TraceRole::Source => entry.source_fault,
                Stage1TraceRole::Destination => entry.destination_fault,
            }
        } else {
            None
        };
        if fault != expected_fault {
            return Err("initialize request fault does not match its matrix/worker role".into());
        }
        return Ok(());
    }

    if case.case_id != "evidence-verification" || role != Stage1TraceRole::Source {
        return Err("initialize request options do not bind the top-level case".into());
    }
    let expected_options = MatrixOptions {
        case_id: options.case_id.clone(),
        namespace_availability: MatrixNamespaceAvailability::Correct,
        authority_policy: MatrixAuthorityPolicyMode::Sufficient,
    };
    if options != &expected_options {
        return Err("supplemental initialize options are not the exact default profile".into());
    }
    let coverage = matrix
        .provider_fault_coverage
        .iter()
        .filter(|coverage| {
            coverage.case_id == case.case_id
                && coverage.role == "supplemental-source"
                && supplemental_case_id(coverage.point) == options.case_id
        })
        .collect::<Vec<_>>();
    if coverage.len() != 1 {
        return Err(
            "supplemental initialize is not uniquely bound to provider fault coverage".into()
        );
    }
    let primary = format!("{}-supplemental-source", options.case_id);
    let retry = format!("{primary}-retry");
    let recovery = format!("{primary}-recovery");
    let expected_fault = if worker == primary {
        Some(coverage[0].point)
    } else if worker == retry || worker == recovery {
        None
    } else {
        return Err("supplemental initialize uses an unknown worker identity".into());
    };
    if fault != expected_fault {
        return Err("supplemental initialize fault does not match provider coverage".into());
    }
    Ok(())
}

fn supplemental_case_id(point: MatrixFaultPoint) -> String {
    let point = match point {
        MatrixFaultPoint::BeforeJournalWrite => "before-journal-write",
        MatrixFaultPoint::AfterJournalWrite => "after-journal-write",
        MatrixFaultPoint::BeforeActivationBundle => "before-activation-bundle",
        MatrixFaultPoint::AfterActivationBundle => "after-activation-bundle",
        MatrixFaultPoint::BeforeCommitBundle => "before-commit-bundle",
        MatrixFaultPoint::AfterCommitBundle => "after-commit-bundle",
        MatrixFaultPoint::AfterKvCommit => "after-kv-commit",
    };
    format!("evidence-verification-fault-{point}")
}

fn validate_initialized_runtime(
    case: &Stage1CaseEvidence,
    transcript_role: Stage1TraceRole,
    expected_runtime_identity: &Stage1VersionedIdentity,
    initialization: &RawInitialization,
    result: &serde_json::Value,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Option<ObservedRuntimeIdentity> {
    let initialized = match serde_json::from_value::<RawInitializedResult>(result.clone()) {
        Ok(initialized) => initialized,
        Err(error) => {
            finding(
                findings,
                "invalid-stage1-initialized-runtime",
                format!(
                    "{} {} initialized response has an invalid exact shape: {error}",
                    case.case_id,
                    trace_role_name(transcript_role)
                ),
            );
            return None;
        }
    };
    let valid = initialized.kind == "initialized"
        && initialized.role == initialization.role
        && initialization.role == transcript_role
        && initialized.case_id == initialization.case_id
        && observed_runtime_matches(initialization.runtime, &initialized.runtime)
        && translation_provenance_matches(initialization.runtime, &initialized.runtime)
        && observed_environment_identity(&initialized.runtime) == *expected_runtime_identity;
    if !valid {
        finding(
            findings,
            "invalid-stage1-initialized-runtime",
            format!(
                "{} {} initialization does not match its selector, role, environment, or required provenance",
                case.case_id,
                trace_role_name(transcript_role)
            ),
        );
        return None;
    }
    Some(initialized.runtime)
}

fn observed_environment_identity(runtime: &ObservedRuntimeIdentity) -> Stage1VersionedIdentity {
    Stage1VersionedIdentity {
        name: format!("{} adapter with {}", runtime.implementation, runtime.engine),
        version: format!(
            "{}+{}.{}",
            runtime.implementation_version, runtime.engine, runtime.engine_version
        ),
    }
}

const fn trace_role_name(role: Stage1TraceRole) -> &'static str {
    match role {
        Stage1TraceRole::Source => "source",
        Stage1TraceRole::Destination => "destination",
    }
}

fn validate_raw_dump(
    case: &Stage1CaseEvidence,
    role: Stage1TraceRole,
    dump: RawDumpResult,
    evidence: &mut RawEvidence,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let digest = state_digest(&dump.canonical_state).unwrap_or(Digest::ZERO);
    let portable_matches = dump.portable_component_state.as_ref().map_or_else(
        || dump.canonical_state.portable_state.is_empty(),
        |portable| portable == &dump.canonical_state.portable_state,
    );
    if digest != dump.state_digest
        || !portable_matches
        || role_of(dump.canonical_state.activation.role) != role
    {
        finding(
            findings,
            "inconsistent-stage1-raw-dump",
            format!(
                "{} worker dump role, digest, or opaque portable state is inconsistent",
                case.case_id
            ),
        );
    }
    evidence.dumps.push(RawDump { role, state: *dump.canonical_state });
}

fn validate_assertions(
    case: &Stage1CaseEvidence,
    bytes: &[u8],
    evidence: &mut RawEvidence,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let values = parse_json_lines::<serde_json::Value>(
        case,
        "assertions",
        bytes,
        "invalid-stage1-raw-assertions",
        findings,
    );
    for value in values {
        let name = value.get("name").and_then(serde_json::Value::as_str).unwrap_or_default();
        if name.is_empty() || !evidence.assertion_names.insert(name.to_owned()) {
            finding(
                findings,
                "invalid-stage1-raw-assertion",
                format!("{} contains an unnamed or duplicate assertion", case.case_id),
            );
        }
        if name == REPORT_REGENERATION_ASSERTION {
            validate_report_regeneration_assertion(case, &value, findings);
        }
        let config = value.get("case_config_digest");
        let policy = value.get("case_policy_digest");
        match (config, policy) {
            (Some(config), Some(policy)) => {
                let config = serde_json::from_value::<Digest>(config.clone());
                let policy = serde_json::from_value::<Digest>(policy.clone());
                if !matches!(config, Ok(digest) if contract_digest_hex(digest) == case.case_config_sha256)
                    || !matches!(policy, Ok(digest) if contract_digest_hex(digest) == case.case_policy_sha256)
                {
                    finding(
                        findings,
                        "inconsistent-stage1-raw-assertion-config",
                        format!(
                            "{} assertion {name} has different case config/policy digests",
                            case.case_id
                        ),
                    );
                }
            }
            (None, None) if name == "stage1-provenance-inputs" => {}
            _ => finding(
                findings,
                "incomplete-stage1-raw-assertion",
                format!("{} assertion {name} omits case config/policy digests", case.case_id),
            ),
        }
    }
}

fn validate_report_regeneration_assertion(
    case: &Stage1CaseEvidence,
    value: &serde_json::Value,
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let detail = value.get("detail").cloned().ok_or(()).and_then(|detail| {
        serde_json::from_value::<ReportRegenerationDetail>(detail).map_err(|_| ())
    });
    let valid = detail.is_ok_and(|detail| {
        case.case_id == REPORT_REGENERATION_CASE_ID
            && detail.publish_error_kind == "io"
            && !detail.publish_error_message.trim().is_empty()
            && detail.bundle_path == "stage1-evidence.json"
            && detail.case_manifest_count == crate::stage1::STAGE1_CASE_DEFINITIONS.len()
            && is_sha256(&detail.case_manifest_set_sha256)
            && is_sha256(&detail.regenerated_bundle_sha256)
            && is_sha256(&detail.committed_state_sha256_before)
            && is_sha256(&detail.committed_state_sha256_after)
            && detail.committed_state_sha256_before == case.state.state_sha256
            && detail.committed_state_sha256_after == case.state.state_sha256
    });
    if !valid {
        finding(
            findings,
            "invalid-stage1-report-regeneration-assertion",
            format!("{} contains invalid or misplaced report regeneration evidence", case.case_id),
        );
    }
}

fn validate_performance_raw(
    case: &Stage1CaseEvidence,
    bytes: &[u8],
    findings: &mut Vec<Stage1ValidationFinding>,
) {
    let valid = serde_json::from_slice::<serde_json::Value>(bytes)
        .is_ok_and(|value| value.as_array().is_some_and(|measurements| !measurements.is_empty()));
    if case.case_id != "performance-observations" || !valid {
        finding(
            findings,
            "invalid-stage1-raw-performance",
            format!("{} has invalid raw performance evidence", case.case_id),
        );
    }
}

fn parse_json_lines<T>(
    case: &Stage1CaseEvidence,
    label: &str,
    bytes: &[u8],
    code: &'static str,
    findings: &mut Vec<Stage1ValidationFinding>,
) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut parsed = Vec::new();
    for (index, line) in
        bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
    {
        match serde_json::from_slice(line) {
            Ok(value) => parsed.push(value),
            Err(error) => finding(
                findings,
                code,
                format!("{} {label} line {} is invalid: {error}", case.case_id, index + 1),
            ),
        }
    }
    if parsed.is_empty() {
        finding(findings, code, format!("{} {label} is empty", case.case_id));
    }
    parsed
}
