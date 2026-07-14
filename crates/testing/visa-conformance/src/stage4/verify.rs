use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::model::*;
use crate::{
    STAGE1_CAPABILITY_ID, STAGE1_CASE_DEFINITIONS, STAGE1_EVIDENCE_SCHEMA_VERSION,
    STAGE2_ACCEPTED_REGISTRY_SHA256, STAGE2_WASMTIME_ENVIRONMENT_NAME,
    STAGE2_WASMTIME_ENVIRONMENT_VERSION, STAGE2_WIT_WORLD_NAME, STAGE2_WIT_WORLD_SHA256,
    Stage1EvidenceBundle, Stage1IsaIdentity, Stage2CommonCaseInput, Stage2NormalizedCellV1,
    artifact_io::{SecureArtifactErrorKind, SecureArtifactRoot},
    canonical_stage2_json_bytes, parse_stage1_evidence_bundle_json, sha256_hex,
    stage2_normalize::normalize_stage2_cell,
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

const UNAME_PROGRAM: &str = "/usr/bin/uname";

pub fn parse_stage4_evidence_bundle_json(
    bytes: &[u8],
) -> Result<Stage4EvidenceBundle, Stage4EvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|source| Stage4EvidenceLoadError {
        code: "invalid-stage4-evidence-json".to_owned(),
        detail: source.to_string(),
    })
}

pub fn stage4_registry_sha256() -> String {
    #[derive(Serialize)]
    struct Registry<'a> {
        endpoints: &'a [Stage4EndpointId],
        cells: &'a [Stage4CellId],
        claims: Vec<Stage4ClaimDefinition>,
        case_ids: Vec<&'static str>,
        stage2_case_registry_sha256: &'static str,
    }
    let registry = Registry {
        endpoints: STAGE4_ENDPOINT_CATALOG,
        cells: STAGE4_CELL_CATALOG,
        claims: required_stage4_claims(),
        case_ids: STAGE1_CASE_DEFINITIONS.iter().map(|definition| definition.id).collect(),
        stage2_case_registry_sha256: STAGE2_ACCEPTED_REGISTRY_SHA256,
    };
    sha256_hex(&serde_json::to_vec(&registry).expect("static Stage 4 registry serializes"))
}

pub fn stage4_bundle_id_from_matrix_sha256(matrix_sha256: &str) -> Option<String> {
    is_sha256(matrix_sha256).then(|| format!("stage4-{}", &matrix_sha256[..24]))
}

pub fn gate_stage4_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    artifact_root: impl AsRef<Path>,
) -> Stage4EvidenceGateResult {
    let bundle = match parse_stage4_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return Stage4EvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let artifact_root = artifact_root.as_ref();
    let mut validation = validate_stage4_evidence_bundle(&bundle, artifact_root);
    match SecureArtifactRoot::open(artifact_root)
        .and_then(|root| root.read_regular(STAGE4_EVIDENCE_FILE))
    {
        Ok(on_disk) if on_disk == bytes => {}
        Ok(_) => finding(
            &mut validation.findings,
            "stage4-gate-bundle-bytes-mismatch",
            "the supplied JSON is not byte-identical to stage4-evidence.json",
        ),
        Err(source) => {
            finding(&mut validation.findings, "invalid-stage4-bundle-artifact", source.to_string())
        }
    }
    validation.ok = validation.findings.is_empty();
    Stage4EvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn validate_stage4_evidence_bundle(
    bundle: &Stage4EvidenceBundle,
    artifact_root: &Path,
) -> Stage4ValidationReport {
    validate_stage4_evidence_bundle_impl(bundle, artifact_root, PublicationMode::Published)
}

pub(crate) fn validate_stage4_evidence_bundle_for_publication(
    bundle: &Stage4EvidenceBundle,
    artifact_root: &Path,
) -> Stage4ValidationReport {
    validate_stage4_evidence_bundle_impl(bundle, artifact_root, PublicationMode::Staged)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationMode {
    Published,
    Staged,
}

struct VerifiedCell {
    cell_id: Stage4CellId,
    bundle: Stage1EvidenceBundle,
    bundle_bytes: Vec<u8>,
    normalized: Stage2NormalizedCellV1,
}

fn validate_stage4_evidence_bundle_impl(
    bundle: &Stage4EvidenceBundle,
    artifact_root: &Path,
    mode: PublicationMode,
) -> Stage4ValidationReport {
    let mut findings = Vec::new();
    validate_evidence_shape(bundle, &mut findings);
    let root = match SecureArtifactRoot::open(artifact_root) {
        Ok(root) => root,
        Err(source) => {
            finding(&mut findings, "invalid-stage4-artifact-root", source.to_string());
            return report(findings);
        }
    };
    validate_marker(&root, mode, &mut findings);
    validate_main_bundle_artifact(&root, bundle, &mut findings);

    let matrix_bytes =
        read_reference(&root, &bundle.matrix_manifest, "Stage 4 matrix manifest", &mut findings);
    let matrix = matrix_bytes.as_deref().and_then(|bytes| {
        match serde_json::from_slice::<Stage4MatrixManifest>(bytes) {
            Ok(matrix) => Some(matrix),
            Err(source) => {
                finding(
                    &mut findings,
                    "invalid-stage4-matrix-json",
                    format!("cannot parse {}: {source}", bundle.matrix_manifest.uri),
                );
                None
            }
        }
    });
    let Some(matrix) = matrix else {
        validate_exact_artifact_set(artifact_root, bundle, None, &[], mode, &mut findings);
        return report(findings);
    };
    if serde_json::to_vec_pretty(&matrix).ok().as_deref() != matrix_bytes.as_deref() {
        finding(
            &mut findings,
            "noncanonical-stage4-matrix-artifact",
            "matrix.json is not the canonical publisher encoding",
        );
    }
    validate_matrix_shape(&matrix, bundle, &mut findings);
    validate_host_receipt(&root, &matrix.orchestrator_host, &mut findings);

    let common_bytes =
        read_reference(&root, &matrix.common_input, "Stage 4 common input", &mut findings);
    let common = common_bytes.as_deref().and_then(|bytes| {
        match serde_json::from_slice::<Stage4CommonInputIdentity>(bytes) {
            Ok(common) => Some(common),
            Err(source) => {
                finding(
                    &mut findings,
                    "invalid-stage4-common-input-json",
                    format!("cannot parse {}: {source}", matrix.common_input.uri),
                );
                None
            }
        }
    });
    if let Some(common) = common.as_ref() {
        if serde_json::to_vec_pretty(common).ok().as_deref() != common_bytes.as_deref() {
            finding(
                &mut findings,
                "noncanonical-stage4-common-input-artifact",
                "common input is not the canonical publisher encoding",
            );
        }
        validate_common_shape(common, &mut findings);
    }

    let endpoints = validate_endpoints(&root, &matrix, common.as_ref(), &mut findings);
    let mut nonces = BTreeSet::new();
    let mut verified = Vec::new();
    let mut loaded_stage1 = Vec::new();
    for cell in &matrix.cells {
        let Some((source_id, destination_id)) = canonical_cell_endpoints(cell, &mut findings)
        else {
            continue;
        };
        let source = endpoints.get(&source_id);
        let destination = endpoints.get(&destination_id);
        match &cell.disposition {
            Stage4CellDisposition::Passed {
                stage1_bundle,
                normalized_observable_trace,
                source_hello,
                destination_hello,
            } => {
                validate_passed_paths(
                    cell.cell_id,
                    stage1_bundle,
                    normalized_observable_trace,
                    source_hello,
                    destination_hello,
                    &mut findings,
                );
                if let Some(endpoint) = source {
                    validate_hello(
                        &root,
                        cell.cell_id,
                        Stage4Role::Source,
                        source_hello,
                        endpoint,
                        &mut nonces,
                        &mut findings,
                    );
                }
                if let Some(endpoint) = destination {
                    validate_hello(
                        &root,
                        cell.cell_id,
                        Stage4Role::Destination,
                        destination_hello,
                        endpoint,
                        &mut nonces,
                        &mut findings,
                    );
                }
                let Some(bundle_bytes) =
                    read_reference(&root, stage1_bundle, "inner Stage 1 evidence", &mut findings)
                else {
                    continue;
                };
                let inner = match parse_stage1_evidence_bundle_json(&bundle_bytes) {
                    Ok(inner) => inner,
                    Err(source) => {
                        finding(
                            &mut findings,
                            "invalid-stage4-inner-stage1-json",
                            format!("{}: {}", cell.cell_id.as_str(), source.detail),
                        );
                        continue;
                    }
                };
                loaded_stage1.push((cell.cell_id, inner.clone()));
                let cell_root = artifact_root.join(cell.cell_id.cell_root_uri());
                let (inner_report, snapshot) =
                    validate_stage1_evidence_bundle_with_artifact_snapshot(&inner, &cell_root);
                if !inner_report.ok {
                    for inner_finding in inner_report.findings {
                        finding(
                            &mut findings,
                            "stage4-inner-stage1-verification-failed",
                            format!(
                                "{}: {}: {}",
                                cell.cell_id.as_str(),
                                inner_finding.code,
                                inner_finding.detail
                            ),
                        );
                    }
                    continue;
                }
                if let Some(common) = common.as_ref() {
                    validate_cell_common_input(cell.cell_id, &inner, common, &mut findings);
                }
                if let (Some(source), Some(destination)) = (source, destination) {
                    validate_inner_target_environment(
                        cell.cell_id,
                        &inner,
                        source,
                        destination,
                        &mut findings,
                    );
                    if inner.provenance.executable_sha256 != source.worker_executable.sha256 {
                        finding(
                            &mut findings,
                            "stage4-inner-source-executable-mismatch",
                            format!(
                                "{} inner executable provenance differs from source endpoint",
                                cell.cell_id.as_str()
                            ),
                        );
                    }
                }
                let Some(snapshot) = snapshot else {
                    finding(
                        &mut findings,
                        "missing-stage4-inner-artifact-snapshot",
                        cell.cell_id.as_str(),
                    );
                    continue;
                };
                validate_case_manifest_set(
                    &cell_root,
                    cell.cell_id,
                    &inner,
                    &snapshot,
                    &mut findings,
                );
                let normalized = match normalize_stage2_cell(&inner, &snapshot) {
                    Ok(normalized) => normalized,
                    Err(source) => {
                        finding(
                            &mut findings,
                            "stage4-normalization-failed",
                            format!(
                                "{}: {}: {}",
                                cell.cell_id.as_str(),
                                source.code,
                                source.detail
                            ),
                        );
                        continue;
                    }
                };
                validate_normalized_cache(
                    &root,
                    cell.cell_id,
                    normalized_observable_trace,
                    &normalized,
                    &mut findings,
                );
                verified.push(VerifiedCell {
                    cell_id: cell.cell_id,
                    bundle: inner,
                    bundle_bytes,
                    normalized,
                });
            }
            Stage4CellDisposition::Failed { reason, diagnostics } => {
                require_reason(reason, cell.cell_id, "failed", &mut findings);
                for diagnostic in diagnostics {
                    let _ = read_reference(
                        &root,
                        diagnostic,
                        "Stage 4 failure diagnostic",
                        &mut findings,
                    );
                }
                required_cell_not_passed(cell.cell_id, "failed", &mut findings);
            }
            Stage4CellDisposition::NotRun { reason } => {
                require_reason(reason, cell.cell_id, "not-run", &mut findings);
                required_cell_not_passed(cell.cell_id, "not-run", &mut findings);
            }
            Stage4CellDisposition::Unsupported { reason } => {
                require_reason(reason, cell.cell_id, "unsupported", &mut findings);
                required_cell_not_passed(cell.cell_id, "unsupported", &mut findings);
            }
        }
    }

    let comparisons = compare_verified_cells(&verified, &mut findings);
    validate_evidence_summaries(bundle, &matrix, &verified, &comparisons, &mut findings);
    validate_exact_artifact_set(
        artifact_root,
        bundle,
        Some(&matrix),
        &loaded_stage1,
        mode,
        &mut findings,
    );
    report(findings)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage4StoredArtifact {
    uri: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage4StoredBindingReceipt {
    resource: crate::Stage1ResourceKind,
    receipt_id: String,
    artifact: Stage4StoredArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage4StoredPerformanceMeasurement {
    metric: crate::Stage1PerformanceMetric,
    samples: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage4StoredPerformance {
    measurements: Vec<Stage4StoredPerformanceMeasurement>,
    artifact: Stage4StoredArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage4StoredCaseManifest {
    schema_version: String,
    bundle_id: String,
    component_sha256: String,
    profile_sha256: String,
    case_id: String,
    case_config_sha256: String,
    case_policy_sha256: String,
    execution_id: String,
    handoff_id: String,
    snapshot_id: String,
    outcome: crate::Stage1CaseOutcome,
    exit_status: i32,
    fault_schedule: crate::Stage1FaultSchedule,
    authority: crate::Stage1AuthorityEvidence,
    state_sha256: String,
    replay_state_sha256: String,
    snapshot: Option<Stage4StoredArtifact>,
    semantic_traces: Vec<Stage4StoredArtifact>,
    binding_receipts: Vec<Stage4StoredBindingReceipt>,
    raw_execution: Vec<Stage4StoredArtifact>,
    performance: Option<Stage4StoredPerformance>,
}

fn validate_case_manifest_set(
    cell_root: &Path,
    cell: Stage4CellId,
    bundle: &Stage1EvidenceBundle,
    artifacts: &crate::VerifiedStage1Artifacts,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let root = match SecureArtifactRoot::open(cell_root) {
        Ok(root) => root,
        Err(source) => {
            finding(
                findings,
                "invalid-stage4-case-manifest-root",
                format!("{}: {source}", cell.as_str()),
            );
            return;
        }
    };
    let mut digest = Sha256::new();
    let mut expected_set_digests = Vec::new();
    for definition in STAGE1_CASE_DEFINITIONS {
        let uri = format!("cases/{}/manifest.json", definition.id);
        let bytes = match root.read_regular(&uri) {
            Ok(bytes) => bytes,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage4-case-manifest",
                    format!("{} {uri}: {source}", cell.as_str()),
                );
                return;
            }
        };
        let mut manifest = match serde_json::from_slice::<Stage4StoredCaseManifest>(&bytes) {
            Ok(manifest) => manifest,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage4-case-manifest-json",
                    format!("{} {uri}: {source}", cell.as_str()),
                );
                return;
            }
        };
        let Some(case) = bundle.cases.iter().find(|case| case.case_id == definition.id) else {
            finding(
                findings,
                "missing-stage4-case-manifest-bundle-case",
                format!("{} {}", cell.as_str(), definition.id),
            );
            return;
        };
        if !stored_manifest_matches_bundle(&manifest, bundle, case) {
            finding(
                findings,
                "stage4-case-manifest-bundle-mismatch",
                format!("{} {} differs from final Stage 1 evidence", cell.as_str(), definition.id),
            );
        }
        let canonical_final = canonical_case_manifest_bytes(&manifest);
        if canonical_final.as_deref() != Some(bytes.as_slice()) {
            finding(
                findings,
                "noncanonical-stage4-case-manifest",
                format!("{} {uri}", cell.as_str()),
            );
        }
        if let Err(detail) =
            restore_pre_binding_manifest(&mut manifest, artifacts, &mut expected_set_digests)
        {
            finding(
                findings,
                "invalid-stage4-case-manifest-binding-history",
                format!("{} {}: {detail}", cell.as_str(), definition.id),
            );
            return;
        }
        let Some(pre_binding_bytes) = canonical_case_manifest_bytes(&manifest) else {
            finding(
                findings,
                "unencodable-stage4-case-manifest",
                format!("{} {}", cell.as_str(), definition.id),
            );
            return;
        };
        digest.update(u64::try_from(definition.id.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(definition.id.as_bytes());
        digest.update(u64::try_from(pre_binding_bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(pre_binding_bytes);
    }
    let actual = format!("{:x}", digest.finalize());
    if expected_set_digests.len() != 1 || expected_set_digests[0] != actual {
        finding(
            findings,
            "stage4-case-manifest-set-digest-mismatch",
            format!("{} case manifests differ from retained Stage 1 assertion", cell.as_str()),
        );
    }
}

fn canonical_case_manifest_bytes(manifest: &Stage4StoredCaseManifest) -> Option<Vec<u8>> {
    serde_json::to_vec_pretty(manifest).ok().map(|mut bytes| {
        bytes.push(b'\n');
        bytes
    })
}

fn stored_manifest_matches_bundle(
    manifest: &Stage4StoredCaseManifest,
    bundle: &Stage1EvidenceBundle,
    case: &crate::Stage1CaseEvidence,
) -> bool {
    let artifacts_match = manifest
        .snapshot
        .as_ref()
        .zip(case.artifacts.snapshot.as_ref())
        .is_none_or(|(stored, artifact)| stored_artifact_matches(stored, artifact))
        && manifest.snapshot.is_some() == case.artifacts.snapshot.is_some()
        && manifest.semantic_traces.len() == case.artifacts.semantic_traces.len()
        && manifest
            .semantic_traces
            .iter()
            .zip(&case.artifacts.semantic_traces)
            .all(|(stored, artifact)| stored_artifact_matches(stored, artifact))
        && manifest.binding_receipts.len() == case.artifacts.binding_receipts.len()
        && manifest.binding_receipts.iter().zip(&case.artifacts.binding_receipts).all(
            |(stored, receipt)| {
                stored.resource == receipt.resource
                    && stored.receipt_id == receipt.receipt_id
                    && stored_artifact_matches(&stored.artifact, &receipt.artifact)
            },
        )
        && manifest.raw_execution.len() == case.artifacts.raw_execution.len()
        && manifest
            .raw_execution
            .iter()
            .zip(&case.artifacts.raw_execution)
            .all(|(stored, artifact)| stored_artifact_matches(stored, artifact));
    let observations = bundle
        .performance_observations
        .iter()
        .filter(|observation| observation.execution_id == case.execution_id)
        .collect::<Vec<_>>();
    let performance_matches = match manifest.performance.as_ref() {
        None => observations.is_empty(),
        Some(performance) => {
            performance.measurements.len() == observations.len()
                && performance.measurements.iter().zip(observations).all(
                    |(measurement, observation)| {
                        measurement.metric == observation.metric
                            && measurement.samples == observation.samples
                            && performance.artifact.sha256 == observation.raw_artifact_sha256
                    },
                )
                && manifest.raw_execution.iter().any(|artifact| artifact == &performance.artifact)
        }
    };
    manifest.schema_version == "visa-system-case-artifacts-v1"
        && manifest.bundle_id == bundle.bundle_id
        && manifest.component_sha256 == bundle.provenance.component_sha256
        && manifest.profile_sha256 == bundle.provenance.profile_sha256
        && manifest.case_id == case.case_id
        && manifest.case_config_sha256 == case.case_config_sha256
        && manifest.case_policy_sha256 == case.case_policy_sha256
        && manifest.execution_id == case.execution_id
        && manifest.handoff_id == case.handoff_id
        && manifest.snapshot_id == case.snapshot_id
        && manifest.outcome == case.outcome
        && manifest.exit_status == case.exit_status
        && manifest.fault_schedule == case.fault_schedule
        && manifest.authority == case.authority
        && manifest.state_sha256 == case.state.state_sha256
        && manifest.replay_state_sha256 == case.state.replay_state_sha256
        && artifacts_match
        && performance_matches
}

fn stored_artifact_matches(
    stored: &Stage4StoredArtifact,
    artifact: &crate::Stage1ArtifactReference,
) -> bool {
    stored.uri == artifact.uri && stored.sha256 == artifact.sha256
}

fn restore_pre_binding_manifest(
    manifest: &mut Stage4StoredCaseManifest,
    artifacts: &crate::VerifiedStage1Artifacts,
    expected_set_digests: &mut Vec<String>,
) -> Result<(), String> {
    let assertion = manifest
        .raw_execution
        .iter_mut()
        .find(|artifact| artifact.uri.ends_with("/raw/assertions.jsonl"))
        .ok_or_else(|| "manifest has no assertions artifact".to_owned())?;
    let bytes = artifacts
        .bytes(&assertion.uri)
        .ok_or_else(|| "assertions artifact is absent from the stable snapshot".to_owned())?;
    let mut restored = Vec::with_capacity(bytes.len());
    let mut removed = 0_usize;
    for line in bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let value: serde_json::Value = serde_json::from_slice(line)
            .map_err(|source| format!("invalid assertion JSON: {source}"))?;
        let name = value.get("name").and_then(serde_json::Value::as_str);
        let post_digest = matches!(
            name,
            Some("report-publication-failed-and-regenerated")
                | Some("stage2-common-input-identity-bound")
        );
        if post_digest {
            removed += 1;
            if name == Some("report-publication-failed-and-regenerated") {
                let expected = value
                    .get("detail")
                    .and_then(|detail| detail.get("case_manifest_set_sha256"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|digest| is_sha256(digest))
                    .ok_or_else(|| {
                        "report assertion omits a valid manifest-set digest".to_owned()
                    })?;
                expected_set_digests.push(expected.to_owned());
            }
        } else {
            restored.extend_from_slice(line);
            restored.push(b'\n');
        }
    }
    if removed > 0 {
        assertion.sha256 = sha256_hex(&restored);
    }
    Ok(())
}

fn validate_evidence_shape(
    bundle: &Stage4EvidenceBundle,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if bundle.schema_version != STAGE4_EVIDENCE_SCHEMA_VERSION {
        finding(findings, "unsupported-stage4-schema", &bundle.schema_version);
    }
    if stage4_bundle_id_from_matrix_sha256(&bundle.matrix_manifest.sha256).as_deref()
        != Some(&bundle.bundle_id)
    {
        finding(
            findings,
            "invalid-stage4-bundle-id",
            "bundle_id must be derived from the retained matrix SHA-256",
        );
    }
    if bundle.matrix_manifest.uri != STAGE4_MATRIX_FILE {
        finding(
            findings,
            "noncanonical-stage4-matrix-path",
            format!("matrix manifest must be {STAGE4_MATRIX_FILE}"),
        );
    }
    if bundle.completed_execution_count != STAGE4_EXECUTION_COUNT {
        finding(
            findings,
            "incomplete-stage4-execution-count",
            format!("expected {STAGE4_EXECUTION_COUNT} completed executions"),
        );
    }
    validate_claim_boundary(&bundle.claims, &bundle.claim_guards, &bundle.qualifications, findings);
}

fn validate_matrix_shape(
    matrix: &Stage4MatrixManifest,
    bundle: &Stage4EvidenceBundle,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if matrix.schema_version != STAGE4_MATRIX_SCHEMA_VERSION {
        finding(findings, "unsupported-stage4-matrix-schema", &matrix.schema_version);
    }
    if matrix.common_input.uri != STAGE4_COMMON_INPUT_FILE {
        finding(
            findings,
            "noncanonical-stage4-common-input-path",
            format!("common input must be {STAGE4_COMMON_INPUT_FILE}"),
        );
    }
    let execution_root = Path::new(&matrix.execution_artifact_root);
    if !execution_root.is_absolute()
        || matrix.execution_artifact_root.is_empty()
        || !execution_root
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        finding(
            findings,
            "invalid-stage4-execution-artifact-root",
            "historical execution artifact root must be an absolute normalized UTF-8 path",
        );
    }
    if matrix.registry_sha256 != STAGE4_ACCEPTED_REGISTRY_SHA256
        || stage4_registry_sha256() != STAGE4_ACCEPTED_REGISTRY_SHA256
    {
        finding(
            findings,
            "invalid-stage4-registry-digest",
            "matrix registry digest does not match the compiled catalog",
        );
    }
    if matrix.execution_count != STAGE4_EXECUTION_COUNT
        || matrix.execution_count != bundle.completed_execution_count
    {
        finding(
            findings,
            "inconsistent-stage4-execution-count",
            format!("matrix and bundle must record {STAGE4_EXECUTION_COUNT} executions"),
        );
    }
    if matrix.claims != bundle.claims
        || matrix.claim_guards != bundle.claim_guards
        || matrix.qualifications != bundle.qualifications
    {
        finding(
            findings,
            "inconsistent-stage4-claim-boundary",
            "matrix and evidence claim boundaries differ",
        );
    }
    validate_claim_boundary(&matrix.claims, &matrix.claim_guards, &matrix.qualifications, findings);
    validate_cell_catalog(matrix.cells.iter().map(|cell| cell.cell_id), findings);
    let actual_endpoints =
        matrix.endpoints.iter().map(|endpoint| endpoint.endpoint_id).collect::<Vec<_>>();
    if actual_endpoints != STAGE4_ENDPOINT_CATALOG {
        finding(
            findings,
            "invalid-stage4-endpoint-catalog",
            "matrix must contain the exact ordered Hx, Qx, Qa endpoint catalog",
        );
    }
    validate_orchestrator(&matrix.orchestrator, findings);
}

fn validate_cell_catalog(
    ids: impl IntoIterator<Item = Stage4CellId>,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if ids.into_iter().collect::<Vec<_>>() != STAGE4_CELL_CATALOG {
        finding(
            findings,
            "invalid-stage4-cell-catalog",
            "matrix must contain the exact ordered seven-cell catalog without duplicates",
        );
    }
}

fn validate_claim_boundary(
    claims: &[Stage4ClaimDefinition],
    guards: &Stage4ClaimGuards,
    qualifications: &[Stage4QualificationRecord],
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if claims != required_stage4_claims() {
        finding(
            findings,
            "invalid-stage4-claim-catalog",
            "claims must exactly match the two compiled claim definitions and cell sets",
        );
    }
    if guards != &Stage4ClaimGuards::required() {
        finding(
            findings,
            "stage4-nonclaim-overclaim",
            "Stage 4 nonclaims must remain explicitly not-claimed",
        );
    }
    if qualifications != required_stage4_qualifications() {
        finding(
            findings,
            "invalid-stage4-qualification-boundary",
            "legacy kernel must remain unsupported and real AArch64 hardware not-run",
        );
    }
}

fn validate_orchestrator(
    orchestrator: &Stage4TargetIdentity,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if orchestrator.architecture != "x86_64"
        || orchestrator.os != "linux"
        || orchestrator.endianness != "little"
        || orchestrator.pointer_width_bits != 64
    {
        finding(
            findings,
            "invalid-stage4-orchestrator-identity",
            "this named profile requires a separate x86_64 Linux orchestrator identity",
        );
    }
}

fn validate_host_receipt(
    root: &SecureArtifactRoot,
    receipt: &Stage4HostReceipt,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let expected_argv = [UNAME_PROGRAM, "-s", "-r", "-m"].map(str::to_owned);
    if receipt.schema_version != STAGE4_HOST_RECEIPT_SCHEMA_VERSION
        || receipt.program != UNAME_PROGRAM
        || !is_sha256(&receipt.program_sha256)
        || receipt.program_size == 0
        || receipt.argv != expected_argv
        || receipt.exit_status != 0
    {
        finding(
            findings,
            "invalid-stage4-host-receipt",
            "host receipt must bind the exact successful uname invocation",
        );
    }
    if receipt.identity.sysname != "Linux"
        || receipt.identity.machine != "x86_64"
        || receipt.identity.kernel_release.is_empty()
        || receipt.identity.kernel_release.chars().any(char::is_whitespace)
    {
        finding(
            findings,
            "invalid-stage4-host-identity",
            "Stage 4 requires a runtime-observed native x86_64 Linux orchestrator host",
        );
    }
    if receipt.raw_stdout.uri != STAGE4_HOST_UNAME_STDOUT_FILE
        || receipt.raw_stderr.uri != STAGE4_HOST_UNAME_STDERR_FILE
    {
        finding(
            findings,
            "noncanonical-stage4-host-receipt-path",
            "host receipt must use the canonical raw uname paths",
        );
    }
    let stdout = read_reference(root, &receipt.raw_stdout, "host uname stdout", findings);
    let stderr = read_reference(root, &receipt.raw_stderr, "host uname stderr", findings);
    let expected_stdout = format!(
        "{} {} {}\n",
        receipt.identity.sysname, receipt.identity.kernel_release, receipt.identity.machine
    );
    if stdout.as_deref() != Some(expected_stdout.as_bytes()) || stderr.as_deref() != Some(&[]) {
        finding(
            findings,
            "stage4-host-receipt-raw-mismatch",
            "host identity must be independently reconstructed from clean raw uname output",
        );
    }
}

fn validate_common_shape(
    common: &Stage4CommonInputIdentity,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if common.schema_version != STAGE4_COMMON_INPUT_SCHEMA_VERSION
        || common.stage1_schema_version != STAGE1_EVIDENCE_SCHEMA_VERSION
        || common.capability_id != STAGE1_CAPABILITY_ID
        || common.evidence_kind != crate::Stage1EvidenceKind::Execution
        || common.component_sha256 != STAGE4_ACCEPTED_COMPONENT_SHA256
        || common.wit_world_name != STAGE2_WIT_WORLD_NAME
        || common.wit_world_sha256 != STAGE2_WIT_WORLD_SHA256
    {
        finding(
            findings,
            "invalid-stage4-common-input-identity",
            "common input has a wrong schema, capability, Component, WIT world, or evidence kind",
        );
    }
    if common.source_runtime.name != STAGE2_WASMTIME_ENVIRONMENT_NAME
        || common.source_runtime.version != STAGE2_WASMTIME_ENVIRONMENT_VERSION
        || common.destination_runtime != common.source_runtime
    {
        finding(
            findings,
            "non-wasmtime-stage4-runtime",
            "Stage 4 holds the Wasmtime runtime implementation fixed",
        );
    }
    if common.substrate.name != "host-process-isolation"
        || common.substrate.version.trim().is_empty()
    {
        finding(
            findings,
            "invalid-stage4-inner-substrate",
            "inner Stage 1 evidence must retain the named host-process isolation substrate",
        );
    }
    if common.cases.len() != STAGE1_CASE_DEFINITIONS.len()
        || common
            .cases
            .iter()
            .zip(STAGE1_CASE_DEFINITIONS)
            .any(|(case, definition)| case.case_id != definition.id)
    {
        finding(
            findings,
            "invalid-stage4-common-case-catalog",
            "common input must cover the exact ordered 31-case Stage 1 registry",
        );
    }
    let accepted_cases = common
        .cases
        .iter()
        .zip(STAGE1_CASE_DEFINITIONS)
        .map(|(case, definition)| Stage2CommonCaseInput {
            case_id: case.case_id.clone(),
            class: definition.class,
            allowed_outcomes: definition.allowed_outcomes.to_vec(),
            case_config_sha256: case.case_config_sha256.clone(),
            case_policy_sha256: case.case_policy_sha256.clone(),
            fault_schedule: case.fault_schedule.clone(),
        })
        .collect::<Vec<_>>();
    let accepted_digest =
        canonical_stage2_json_bytes(&accepted_cases).map(|bytes| sha256_hex(&bytes)).ok();
    if accepted_digest.as_deref() != Some(STAGE2_ACCEPTED_REGISTRY_SHA256) {
        finding(
            findings,
            "invalid-stage4-common-case-registry-lock",
            "common case inputs must equal the accepted Stage 2 31-case registry lock",
        );
    }
}

fn validate_endpoints<'a>(
    root: &SecureArtifactRoot,
    matrix: &'a Stage4MatrixManifest,
    common: Option<&Stage4CommonInputIdentity>,
    findings: &mut Vec<Stage4ValidationFinding>,
) -> BTreeMap<Stage4EndpointId, &'a Stage4EndpointEvidence> {
    let mut endpoints = BTreeMap::new();
    let mut sysroot_manifests = BTreeMap::new();
    for endpoint in &matrix.endpoints {
        if endpoints.insert(endpoint.endpoint_id, endpoint).is_some() {
            finding(findings, "duplicate-stage4-endpoint", endpoint.endpoint_id.as_str());
        }
        if let Some(manifest) = validate_endpoint(
            root,
            endpoint,
            &matrix.orchestrator,
            &matrix.execution_artifact_root,
            findings,
        ) {
            sysroot_manifests.insert(endpoint.endpoint_id, manifest);
        }
    }
    validate_cross_endpoint_invariants(&endpoints, &sysroot_manifests, common, findings);
    endpoints
}

fn validate_cross_endpoint_invariants(
    endpoints: &BTreeMap<Stage4EndpointId, &Stage4EndpointEvidence>,
    sysroot_manifests: &BTreeMap<Stage4EndpointId, Stage4SysrootManifest>,
    common: Option<&Stage4CommonInputIdentity>,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let (Some(hx), Some(qx), Some(qa)) = (
        endpoints.get(&Stage4EndpointId::Hx),
        endpoints.get(&Stage4EndpointId::Qx),
        endpoints.get(&Stage4EndpointId::Qa),
    ) else {
        return;
    };
    if hx.worker_executable.sha256 != qx.worker_executable.sha256
        || hx.worker_executable.size != qx.worker_executable.size
    {
        finding(
            findings,
            "stage4-hx-qx-worker-mismatch",
            "Hx and Qx must execute byte-identical x86_64 workers",
        );
    }
    let source = &hx.build_receipt.build_source_sha256;
    let toolchain = &hx.build_receipt.build_toolchain_sha256;
    if [qx, qa].into_iter().any(|endpoint| {
        endpoint.build_receipt.build_source_sha256 != *source
            || endpoint.build_receipt.build_toolchain_sha256 != *toolchain
    }) || common.is_some_and(|common| {
        common.source_sha256 != *source || common.toolchain_sha256 != *toolchain
    }) {
        finding(
            findings,
            "mixed-stage4-build-input",
            "all endpoints must use the common source and identical build toolchain receipt",
        );
    }
    let qx_qemu = qx.launcher_receipt.qemu.as_ref();
    let qa_qemu = qa.launcher_receipt.qemu.as_ref();
    if qx_qemu.zip(qa_qemu).is_none_or(|(qx_qemu, qa_qemu)| {
        qx_qemu.adapter_family != qa_qemu.adapter_family
            || qx_qemu.emulator_version != qa_qemu.emulator_version
    }) {
        finding(
            findings,
            "mixed-stage4-qemu-adapter-version",
            "Qx and Qa must use one QEMU-user adapter family and exact version",
        );
    }
    if sysroot_manifests
        .get(&Stage4EndpointId::Hx)
        .zip(sysroot_manifests.get(&Stage4EndpointId::Qx))
        .is_none_or(|(hx, qx)| hx.entries != qx.entries)
    {
        finding(
            findings,
            "stage4-hx-qx-sysroot-manifest-mismatch",
            "Hx and Qx must resolve the same x86_64 loader dependency bytes",
        );
    }
}

fn validate_endpoint(
    root: &SecureArtifactRoot,
    endpoint: &Stage4EndpointEvidence,
    orchestrator: &Stage4TargetIdentity,
    execution_artifact_root: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) -> Option<Stage4SysrootManifest> {
    let id = endpoint.endpoint_id;
    validate_named_target(id, &endpoint.target, findings);
    if id == Stage4EndpointId::Hx && endpoint.target != *orchestrator {
        finding(
            findings,
            "stage4-native-endpoint-orchestrator-mismatch",
            "Hx must be the native orchestrator target",
        );
    }
    validate_canonical_reference(
        &endpoint.worker_executable,
        &id.worker_uri(),
        "worker executable",
        findings,
    );
    let worker_bytes =
        read_reference(root, &endpoint.worker_executable, "target worker executable", findings);
    if let Some(bytes) = worker_bytes.as_deref() {
        validate_worker_elf(id, bytes, findings);
    }

    validate_canonical_reference(
        &endpoint.build_receipt_artifact,
        &id.build_receipt_uri(),
        "build receipt",
        findings,
    );
    validate_typed_json_artifact(
        root,
        &endpoint.build_receipt_artifact,
        &endpoint.build_receipt,
        "build receipt",
        findings,
    );
    let build = &endpoint.build_receipt;
    if build.schema_version != STAGE4_BUILD_RECEIPT_SCHEMA_VERSION
        || build.endpoint_id != id
        || build.target != endpoint.target
        || build.executable_sha256 != endpoint.worker_executable.sha256
        || build.executable_size != endpoint.worker_executable.size
        || !is_sha256(&build.build_source_sha256)
        || !is_sha256(&build.build_toolchain_sha256)
    {
        finding(
            findings,
            "invalid-stage4-build-receipt",
            format!("{} build receipt disagrees with retained worker bytes", id.as_str()),
        );
    }

    validate_canonical_reference(
        &endpoint.sysroot_receipt_artifact,
        &id.sysroot_receipt_uri(),
        "sysroot receipt",
        findings,
    );
    validate_typed_json_artifact(
        root,
        &endpoint.sysroot_receipt_artifact,
        &endpoint.sysroot_receipt,
        "sysroot receipt",
        findings,
    );
    let expected_sysroot = match id {
        Stage4EndpointId::Hx | Stage4EndpointId::Qx => "/",
        Stage4EndpointId::Qa => "/usr/aarch64-linux-gnu",
    };
    if endpoint.sysroot_receipt.schema_version != STAGE4_SYSROOT_RECEIPT_SCHEMA_VERSION
        || endpoint.sysroot_receipt.endpoint_id != id
        || endpoint.sysroot_receipt.identity != expected_sysroot
        || endpoint.sysroot_receipt.manifest.uri != id.sysroot_manifest_uri()
    {
        finding(
            findings,
            "invalid-stage4-sysroot-receipt",
            format!("{} has an incomplete sysroot receipt", id.as_str()),
        );
    }
    validate_canonical_reference(
        &endpoint.sysroot_receipt.manifest,
        &id.sysroot_manifest_uri(),
        "sysroot owned manifest",
        findings,
    );
    validate_canonical_reference(
        &endpoint.sysroot_receipt.loader_resolution_stdout,
        &id.loader_resolution_stdout_uri(),
        "loader resolution stdout",
        findings,
    );
    validate_canonical_reference(
        &endpoint.sysroot_receipt.loader_resolution_stderr,
        &id.loader_resolution_stderr_uri(),
        "loader resolution stderr",
        findings,
    );
    let loader_stdout = read_reference(
        root,
        &endpoint.sysroot_receipt.loader_resolution_stdout,
        "loader resolution stdout",
        findings,
    );
    if let Some(stderr) = read_reference(
        root,
        &endpoint.sysroot_receipt.loader_resolution_stderr,
        "loader resolution stderr",
        findings,
    ) && !stderr.is_empty()
    {
        finding(findings, "nonempty-stage4-loader-resolution-stderr", id.as_str());
    }
    let sysroot_manifest = read_reference(
        root,
        &endpoint.sysroot_receipt.manifest,
        "sysroot owned manifest",
        findings,
    )
    .and_then(|bytes| match serde_json::from_slice::<Stage4SysrootManifest>(&bytes) {
        Ok(manifest) => Some((bytes, manifest)),
        Err(source) => {
            finding(
                findings,
                "invalid-stage4-sysroot-manifest-json",
                format!("{}: {source}", id.as_str()),
            );
            None
        }
    });
    if let Some((manifest_bytes, manifest)) = sysroot_manifest.as_ref() {
        if serde_json::to_vec_pretty(&manifest).ok().as_deref() != Some(manifest_bytes.as_slice()) {
            finding(findings, "noncanonical-stage4-sysroot-manifest", id.as_str());
        }
        let sorted_unique = manifest.entries.windows(2).all(|entries| {
            (&entries[0].name, &entries[0].version, &entries[0].sha256)
                < (&entries[1].name, &entries[1].version, &entries[1].sha256)
        });
        let has_loader = manifest.entries.iter().any(|entry| {
            let name = entry.name.to_ascii_lowercase();
            name.contains("ld-linux") || name.contains("ld.so") || name.contains("loader")
        });
        let has_libc = manifest
            .entries
            .iter()
            .any(|entry| entry.name.to_ascii_lowercase().contains("libc.so"));
        if manifest.schema_version != STAGE4_SYSROOT_MANIFEST_SCHEMA_VERSION
            || manifest.endpoint_id != id
            || manifest.entries.is_empty()
            || !sorted_unique
            || !has_loader
            || !has_libc
            || manifest.entries.iter().any(|entry| {
                entry.name.trim().is_empty()
                    || entry.version != "target-loader-list-v1"
                    || !is_sha256(&entry.sha256)
            })
        {
            finding(
                findings,
                "invalid-stage4-sysroot-manifest",
                format!("{} sysroot manifest is incomplete", id.as_str()),
            );
        }
        if let Some(stdout) = loader_stdout.as_deref() {
            let parsed = std::str::from_utf8(stdout)
                .map_err(|source| source.to_string())
                .and_then(|stdout| parse_loader_guest_paths(stdout, expected_sysroot));
            let manifest_names =
                manifest.entries.iter().map(|entry| entry.name.clone()).collect::<BTreeSet<_>>();
            if parsed.as_ref() != Ok(&manifest_names) {
                finding(
                    findings,
                    "stage4-sysroot-manifest-loader-output-mismatch",
                    format!(
                        "{} manifest exact path set differs from raw loader output: {:?}",
                        id.as_str(),
                        parsed.err()
                    ),
                );
            }
        }
    }

    validate_canonical_reference(
        &endpoint.launcher_receipt_artifact,
        &id.launcher_receipt_uri(),
        "launcher receipt",
        findings,
    );
    validate_typed_json_artifact(
        root,
        &endpoint.launcher_receipt_artifact,
        &endpoint.launcher_receipt,
        "launcher receipt",
        findings,
    );
    let launcher = &endpoint.launcher_receipt;
    if launcher.schema_version != STAGE4_LAUNCHER_RECEIPT_SCHEMA_VERSION
        || launcher.endpoint_id != id
        || launcher.execution_mode != id.required_execution_mode()
        || launcher.boundary != Stage4ExecutionBoundary::for_mode(id.required_execution_mode())
        || launcher.argv.is_empty()
        || launcher.sysroot != endpoint.sysroot_receipt_artifact
        || launcher.native_fallback_allowed
        || launcher.observed_native_fallback
    {
        finding(
            findings,
            "invalid-stage4-launcher-receipt",
            format!("{} launcher violates the named execution boundary", id.as_str()),
        );
    }
    match (id, launcher.qemu.as_ref()) {
        (Stage4EndpointId::Hx, None) => {
            let canonical_argv = launcher.argv.len() == 1
                && owned_path_matches(
                    &launcher.argv[0],
                    execution_artifact_root,
                    Stage4EndpointId::Hx,
                    "worker",
                );
            if launcher.program_sha256 != endpoint.worker_executable.sha256
                || launcher.program_size != endpoint.worker_executable.size
                || !canonical_argv
            {
                finding(
                    findings,
                    "invalid-stage4-native-launcher-argv",
                    "Hx fixed argv must contain only the owned worker path",
                );
            }
        }
        (Stage4EndpointId::Hx, Some(_)) => finding(
            findings,
            "invalid-stage4-native-launcher",
            "Hx must execute directly without QEMU",
        ),
        (Stage4EndpointId::Qx | Stage4EndpointId::Qa, Some(qemu)) => {
            let expected_name =
                if id == Stage4EndpointId::Qx { "qemu-x86_64" } else { "qemu-aarch64" };
            if qemu.adapter_family != "qemu-user"
                || qemu.emulator_name != expected_name
                || qemu.emulator_version.trim().is_empty()
                || qemu.argv_prefix.is_empty()
            {
                finding(
                    findings,
                    "invalid-stage4-qemu-receipt",
                    format!("{} must use the pinned {expected_name} user adapter", id.as_str()),
                );
            }
            validate_canonical_reference(
                &qemu.executable,
                &id.qemu_uri(),
                "QEMU executable",
                findings,
            );
            validate_canonical_reference(
                &qemu.version_stdout,
                &id.qemu_version_stdout_uri(),
                "QEMU version stdout",
                findings,
            );
            validate_canonical_reference(
                &qemu.version_stderr,
                &id.qemu_version_stderr_uri(),
                "QEMU version stderr",
                findings,
            );
            let _ = read_reference(root, &qemu.executable, "QEMU executable", findings);
            let canonical_prefix = qemu.argv_prefix.len() == 5
                && qemu.argv_prefix[0] == "-cpu"
                && qemu.argv_prefix[1] == "max"
                && qemu.argv_prefix[2] == "-L"
                && qemu.argv_prefix[3] == endpoint.sysroot_receipt.identity
                && Path::new(&qemu.argv_prefix[3]).is_absolute()
                && owned_path_matches(&qemu.argv_prefix[4], execution_artifact_root, id, "worker");
            let canonical_argv = launcher.argv.len() == 6
                && owned_path_matches(&launcher.argv[0], execution_artifact_root, id, "qemu")
                && launcher.argv[1..] == qemu.argv_prefix;
            if launcher.program_sha256 != qemu.executable.sha256
                || launcher.program_size != qemu.executable.size
                || !canonical_prefix
                || !canonical_argv
            {
                finding(
                    findings,
                    "invalid-stage4-qemu-launcher-argv",
                    format!(
                        "{} fixed argv must be owned QEMU, -cpu max, -L sysroot, owned worker",
                        id.as_str()
                    ),
                );
            }
            let version_stdout =
                read_reference(root, &qemu.version_stdout, "QEMU version stdout", findings);
            if let Some(bytes) = version_stdout {
                let first_line = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| text.lines().next())
                    .unwrap_or_default();
                if first_line.is_empty() || !first_line.contains(&qemu.emulator_version) {
                    finding(
                        findings,
                        "stage4-qemu-version-receipt-mismatch",
                        format!("{} QEMU version is not present in raw stdout", id.as_str()),
                    );
                }
            }
            if let Some(bytes) =
                read_reference(root, &qemu.version_stderr, "QEMU version stderr", findings)
                && !bytes.is_empty()
            {
                finding(findings, "nonempty-stage4-qemu-version-stderr", id.as_str());
            }
        }
        (Stage4EndpointId::Qx | Stage4EndpointId::Qa, None) => finding(
            findings,
            "stage4-native-fallback-detected",
            format!("{} lacks its required QEMU-user receipt", id.as_str()),
        ),
    }
    sysroot_manifest.map(|(_, manifest)| manifest)
}

fn parse_loader_guest_paths(stdout: &str, sysroot: &str) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("linux-vdso") || line.contains("linux-gate") {
            continue;
        }
        let candidate = match line.split_once("=>") {
            Some((_, resolution)) => {
                let resolution = resolution.trim();
                if resolution.starts_with("not found") {
                    return Err(format!("unresolved loader dependency: {line}"));
                }
                resolution.split_whitespace().next().unwrap_or_default()
            }
            None => line.split_whitespace().next().unwrap_or_default(),
        };
        let candidate = Path::new(candidate);
        if !candidate.is_absolute()
            || !candidate
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(format!("invalid absolute loader path: {line}"));
        }
        let normalized = if sysroot != "/" && candidate.starts_with(sysroot) {
            let relative = candidate
                .strip_prefix(sysroot)
                .map_err(|source| format!("cannot strip sysroot: {source}"))?;
            format!("/{}", relative.display())
        } else {
            candidate.display().to_string()
        };
        paths.insert(normalized);
    }
    if paths.is_empty() {
        return Err("loader output contains no resolved dependency paths".to_owned());
    }
    Ok(paths)
}

fn owned_path_matches(
    path: &str,
    execution_artifact_root: &str,
    endpoint: Stage4EndpointId,
    leaf: &str,
) -> bool {
    Path::new(path)
        == Path::new(execution_artifact_root).join(format!("targets/{}/{leaf}", endpoint.as_str()))
}

fn validate_named_target(
    id: Stage4EndpointId,
    target: &Stage4TargetIdentity,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if target.target_triple != id.target_triple()
        || target.architecture != id.architecture()
        || target.os != "linux"
        || target.abi != "linux-gnu"
        || target.endianness != "little"
        || target.pointer_width_bits != 64
    {
        finding(
            findings,
            "invalid-stage4-named-target",
            format!("{} does not match its locked target identity", id.as_str()),
        );
    }
}

fn validate_worker_elf(
    endpoint: Stage4EndpointId,
    bytes: &[u8],
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let expected_machine = match endpoint {
        Stage4EndpointId::Hx | Stage4EndpointId::Qx => 62_u16,
        Stage4EndpointId::Qa => 183_u16,
    };
    let machine = bytes
        .get(..20)
        .filter(|header| header.starts_with(b"\x7fELF"))
        .filter(|header| header[4] == 2 && header[5] == 1)
        .map(|header| u16::from_le_bytes([header[18], header[19]]));
    if machine != Some(expected_machine) {
        finding(
            findings,
            "stage4-worker-elf-isa-mismatch",
            format!(
                "{} retained worker is not the expected 64-bit little-endian ELF ISA",
                endpoint.as_str()
            ),
        );
    }
}

fn canonical_cell_endpoints(
    cell: &Stage4CellEvidence,
    findings: &mut Vec<Stage4ValidationFinding>,
) -> Option<(Stage4EndpointId, Stage4EndpointId)> {
    let expected = cell.cell_id.endpoints();
    if (cell.source_endpoint, cell.destination_endpoint) != expected {
        finding(
            findings,
            "invalid-stage4-cell-endpoints",
            format!("{} has forged source or destination endpoints", cell.cell_id.as_str()),
        );
    }
    Some(expected)
}

fn validate_passed_paths(
    cell: Stage4CellId,
    stage1: &Stage4ArtifactReference,
    normalized: &Stage4ArtifactReference,
    source: &Stage4TargetHelloObservation,
    destination: &Stage4TargetHelloObservation,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    validate_canonical_reference(stage1, &cell.stage1_bundle_uri(), "Stage 1 bundle", findings);
    validate_canonical_reference(normalized, &cell.normalized_uri(), "normalized cache", findings);
    validate_canonical_reference(
        &source.raw_stdout,
        &cell.hello_stdout_uri(Stage4Role::Source),
        "source hello stdout",
        findings,
    );
    validate_canonical_reference(
        &source.raw_stderr,
        &cell.hello_stderr_uri(Stage4Role::Source),
        "source hello stderr",
        findings,
    );
    validate_canonical_reference(
        &destination.raw_stdout,
        &cell.hello_stdout_uri(Stage4Role::Destination),
        "destination hello stdout",
        findings,
    );
    validate_canonical_reference(
        &destination.raw_stderr,
        &cell.hello_stderr_uri(Stage4Role::Destination),
        "destination hello stderr",
        findings,
    );
}

#[allow(clippy::too_many_arguments)]
fn validate_hello(
    root: &SecureArtifactRoot,
    cell: Stage4CellId,
    role: Stage4Role,
    observation: &Stage4TargetHelloObservation,
    endpoint: &Stage4EndpointEvidence,
    nonces: &mut BTreeSet<String>,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let hello = &observation.hello;
    if observation.exit_status != 0 {
        finding(
            findings,
            "stage4-target-hello-failed",
            format!("{} {} hello exited non-zero", cell.as_str(), role.as_str()),
        );
    }
    if observation.expected_nonce.len() != 64
        || !observation
            .expected_nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hello.nonce != observation.expected_nonce
    {
        finding(
            findings,
            "stage4-target-hello-nonce-mismatch",
            format!("{} {} hello is not bound to its challenge", cell.as_str(), role.as_str()),
        );
    }
    if !nonces.insert(observation.expected_nonce.clone()) {
        finding(
            findings,
            "duplicate-stage4-target-hello-nonce",
            format!("{} {} reused a hello challenge", cell.as_str(), role.as_str()),
        );
    }
    let target = &endpoint.target;
    let build = &endpoint.build_receipt;
    if hello.schema_version != STAGE4_TARGET_HELLO_SCHEMA_VERSION
        || hello.target_triple != target.target_triple
        || hello.architecture != target.architecture
        || hello.os != target.os
        || hello.abi != target.abi
        || hello.endianness != target.endianness
        || hello.pointer_width_bits != target.pointer_width_bits
        || hello.executable_sha256 != endpoint.worker_executable.sha256
        || hello.executable_size != endpoint.worker_executable.size
        || hello.build_source_sha256 != build.build_source_sha256
        || hello.build_toolchain_sha256 != build.build_toolchain_sha256
        || hello.worker_protocol_version != STAGE4_WORKER_PROTOCOL_VERSION
    {
        finding(
            findings,
            "stage4-target-hello-identity-mismatch",
            format!(
                "{} {} hello disagrees with retained target receipts",
                cell.as_str(),
                role.as_str()
            ),
        );
    }
    let stdout = read_reference(root, &observation.raw_stdout, "target hello stdout", findings);
    if let Some(stdout) = stdout {
        let canonical_stdout = serde_json::to_vec(hello)
            .map(|mut bytes| {
                bytes.push(b'\n');
                bytes
            })
            .unwrap_or_default();
        if stdout != canonical_stdout {
            finding(
                findings,
                "noncanonical-stage4-target-hello-stdout",
                format!(
                    "{} {} hello stdout must be one canonical JSON line",
                    cell.as_str(),
                    role.as_str()
                ),
            );
        }
        match serde_json::from_slice::<Stage4TargetHello>(&stdout) {
            Ok(raw) if raw == *hello => {}
            Ok(_) => finding(
                findings,
                "stage4-target-hello-stdout-mismatch",
                format!("{} {} parsed hello differs from raw stdout", cell.as_str(), role.as_str()),
            ),
            Err(source) => finding(
                findings,
                "invalid-stage4-target-hello-stdout",
                format!("{} {}: {source}", cell.as_str(), role.as_str()),
            ),
        }
    }
    if let Some(stderr) =
        read_reference(root, &observation.raw_stderr, "target hello stderr", findings)
        && !stderr.is_empty()
    {
        finding(
            findings,
            "nonempty-stage4-target-hello-stderr",
            format!("{} {} hello wrote stderr", cell.as_str(), role.as_str()),
        );
    }
}

fn validate_cell_common_input(
    cell: Stage4CellId,
    bundle: &Stage1EvidenceBundle,
    common: &Stage4CommonInputIdentity,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let actual = common_input_from_stage1(bundle);
    validate_common_identity(cell, &actual, common, findings);
}

fn validate_common_identity(
    cell: Stage4CellId,
    actual: &Stage4CommonInputIdentity,
    common: &Stage4CommonInputIdentity,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if actual != common {
        finding(
            findings,
            "mixed-stage4-common-input",
            format!(
                "{} does not use the locked common Component/profile/config/cases",
                cell.as_str()
            ),
        );
    }
}

pub(crate) fn common_input_from_stage1(bundle: &Stage1EvidenceBundle) -> Stage4CommonInputIdentity {
    Stage4CommonInputIdentity {
        schema_version: STAGE4_COMMON_INPUT_SCHEMA_VERSION.to_owned(),
        stage1_schema_version: bundle.schema_version.clone(),
        capability_id: bundle.capability_id.clone(),
        evidence_kind: bundle.evidence_kind,
        component_sha256: bundle.provenance.component_sha256.clone(),
        wit_world_name: STAGE2_WIT_WORLD_NAME.to_owned(),
        wit_world_sha256: STAGE2_WIT_WORLD_SHA256.to_owned(),
        profile_sha256: bundle.provenance.profile_sha256.clone(),
        config_sha256: bundle.provenance.config_sha256.clone(),
        source_sha256: bundle.provenance.source_sha256.clone(),
        toolchain_sha256: bundle.provenance.toolchain_sha256.clone(),
        carrier: bundle.environment.carrier.clone(),
        source_runtime: bundle.environment.source_runtime.clone(),
        destination_runtime: bundle.environment.destination_runtime.clone(),
        substrate: bundle.environment.substrate.clone(),
        provider: bundle.environment.provider.clone(),
        authority_enforcement: bundle.environment.authority_enforcement.clone(),
        resource_profiles: bundle.environment.resource_profiles.clone(),
        cases: bundle
            .cases
            .iter()
            .map(|case| Stage4CommonCaseInput {
                case_id: case.case_id.clone(),
                case_config_sha256: case.case_config_sha256.clone(),
                case_policy_sha256: case.case_policy_sha256.clone(),
                fault_schedule: case.fault_schedule.clone(),
            })
            .collect(),
    }
}

fn validate_inner_target_environment(
    cell: Stage4CellId,
    bundle: &Stage1EvidenceBundle,
    source: &Stage4EndpointEvidence,
    destination: &Stage4EndpointEvidence,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let expected_source = Stage1IsaIdentity {
        architecture: source.target.architecture.clone(),
        abi: source.target.abi.clone(),
    };
    let expected_destination = Stage1IsaIdentity {
        architecture: destination.target.architecture.clone(),
        abi: destination.target.abi.clone(),
    };
    if bundle.environment.source_isa != expected_source
        || bundle.environment.destination_isa != expected_destination
    {
        finding(
            findings,
            "stage4-inner-target-environment-mismatch",
            format!("{} Stage 1 ISA fields do not match worker-observed endpoints", cell.as_str()),
        );
    }
}

fn validate_normalized_cache(
    root: &SecureArtifactRoot,
    cell: Stage4CellId,
    reference: &Stage4ArtifactReference,
    recomputed: &Stage2NormalizedCellV1,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let Some(bytes) = read_reference(root, reference, "normalized Stage 4 cache", findings) else {
        return;
    };
    let expected = match canonical_stage2_json_bytes(recomputed) {
        Ok(expected) => expected,
        Err(source) => {
            finding(findings, source.code, source.detail);
            return;
        }
    };
    if bytes != expected {
        finding(
            findings,
            "stage4-normalized-cache-mismatch",
            format!("{} cache differs from independently recomputed normalization", cell.as_str()),
        );
    }
}

fn compare_verified_cells(
    cells: &[VerifiedCell],
    findings: &mut Vec<Stage4ValidationFinding>,
) -> Vec<Stage4CaseComparison> {
    if cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>() != STAGE4_CELL_CATALOG {
        finding(
            findings,
            "incomplete-stage4-normalized-matrix",
            "all seven ordered passed cells are required before semantic comparison",
        );
        return Vec::new();
    }
    let mut comparisons = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let Some(baseline) = cells[0].normalized.cases.get(index) else {
            finding(findings, "missing-stage4-normalized-case", definition.id);
            continue;
        };
        if baseline.case_id != definition.id {
            finding(findings, "misordered-stage4-normalized-case", definition.id);
            continue;
        }
        if cells.iter().any(|cell| cell.normalized.cases.get(index) != Some(baseline)) {
            finding(
                findings,
                "stage4-normalized-observable-divergence",
                format!("{} differs across target/substrate cells", definition.id),
            );
            continue;
        }
        let normalized_case_sha256 = match canonical_stage2_json_bytes(baseline) {
            Ok(bytes) => sha256_hex(&bytes),
            Err(source) => {
                finding(findings, source.code, source.detail);
                continue;
            }
        };
        comparisons.push(Stage4CaseComparison {
            case_id: definition.id.to_owned(),
            normalized_case_sha256,
            equal_across_all_cells: true,
        });
    }
    comparisons
}

fn validate_evidence_summaries(
    evidence: &Stage4EvidenceBundle,
    matrix: &Stage4MatrixManifest,
    verified: &[VerifiedCell],
    comparisons: &[Stage4CaseComparison],
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if evidence.case_comparisons != comparisons
        || evidence.case_comparisons.len() != STAGE1_CASE_DEFINITIONS.len()
    {
        finding(
            findings,
            "invalid-stage4-case-comparison-set",
            "published case comparisons differ from independent seven-cell comparison",
        );
    }
    if evidence.inner_verifications.len() != STAGE4_CELL_COUNT
        || evidence.inner_verifications.iter().map(|summary| summary.cell_id).collect::<Vec<_>>()
            != STAGE4_CELL_CATALOG
    {
        finding(
            findings,
            "invalid-stage4-inner-verification-catalog",
            "inner summaries must cover the exact ordered seven-cell catalog",
        );
    }
    let by_id = verified.iter().map(|cell| (cell.cell_id, cell)).collect::<BTreeMap<_, _>>();
    for (summary, cell) in evidence.inner_verifications.iter().zip(&matrix.cells) {
        let Some(verified) = by_id.get(&cell.cell_id) else {
            if summary.cell_id != cell.cell_id
                || summary.disposition != cell.disposition.status()
                || summary.stage1_bundle_id.is_some()
                || summary.stage1_bundle_sha256.is_some()
                || summary.case_count != 0
                || summary.independently_verified
                || cell.disposition.is_passed()
            {
                finding(
                    findings,
                    "forged-stage4-inner-verification-summary",
                    cell.cell_id.as_str(),
                );
            }
            continue;
        };
        if summary.cell_id != cell.cell_id
            || summary.disposition != Stage4CellStatus::Passed
            || summary.stage1_bundle_id.as_deref() != Some(&verified.bundle.bundle_id)
            || summary.stage1_bundle_sha256.as_deref()
                != Some(sha256_hex(&verified.bundle_bytes).as_str())
            || summary.case_count != STAGE1_CASE_DEFINITIONS.len()
            || !summary.independently_verified
        {
            finding(findings, "stage4-inner-verification-summary-mismatch", cell.cell_id.as_str());
        }
    }
}

fn require_reason(
    reason: &str,
    cell: Stage4CellId,
    status: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if reason.trim().is_empty() {
        finding(
            findings,
            "missing-stage4-cell-disposition-reason",
            format!("{} {status}", cell.as_str()),
        );
    }
}

fn required_cell_not_passed(
    cell: Stage4CellId,
    status: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    finding(
        findings,
        "required-stage4-cell-not-passed",
        format!("{} is {status}; required claim cells are satisfied only by passed", cell.as_str()),
    );
}

fn validate_typed_json_artifact<T>(
    root: &SecureArtifactRoot,
    reference: &Stage4ArtifactReference,
    expected: &T,
    label: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) where
    T: serde::de::DeserializeOwned + Serialize + PartialEq,
{
    let Some(bytes) = read_reference(root, reference, label, findings) else { return };
    if serde_json::to_vec_pretty(expected).ok().as_deref() != Some(bytes.as_slice()) {
        finding(
            findings,
            "noncanonical-stage4-typed-receipt",
            format!("{label} is not the canonical publisher encoding"),
        );
    }
    match serde_json::from_slice::<T>(&bytes) {
        Ok(actual) if actual == *expected => {}
        Ok(_) => finding(
            findings,
            "stage4-typed-receipt-mismatch",
            format!("{label} bytes differ from the typed matrix receipt"),
        ),
        Err(source) => {
            finding(findings, "invalid-stage4-typed-receipt-json", format!("{label}: {source}"))
        }
    }
}

fn read_reference(
    root: &SecureArtifactRoot,
    reference: &Stage4ArtifactReference,
    label: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) -> Option<Vec<u8>> {
    if !safe_relative_uri(&reference.uri) {
        finding(
            findings,
            "invalid-stage4-artifact-uri",
            format!("unsafe {label} URI {}", reference.uri),
        );
        return None;
    }
    let bytes = match root.read_regular(&reference.uri) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(
                findings,
                "invalid-stage4-artifact",
                format!("{label} {}: {source}", reference.uri),
            );
            return None;
        }
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.size {
        finding(findings, "stage4-artifact-size-mismatch", format!("{label} {}", reference.uri));
    }
    if sha256_hex(&bytes) != reference.sha256 {
        finding(findings, "stage4-artifact-digest-mismatch", format!("{label} {}", reference.uri));
    }
    Some(bytes)
}

fn validate_canonical_reference(
    reference: &Stage4ArtifactReference,
    expected_uri: &str,
    label: &str,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    if reference.uri != expected_uri {
        finding(
            findings,
            "noncanonical-stage4-artifact-path",
            format!("{label} must be {expected_uri}, found {}", reference.uri),
        );
    }
    if !is_sha256(&reference.sha256) {
        finding(
            findings,
            "invalid-stage4-artifact-digest",
            format!("{label} has a non-SHA-256 digest"),
        );
    }
}

fn validate_main_bundle_artifact(
    root: &SecureArtifactRoot,
    bundle: &Stage4EvidenceBundle,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let bytes = match root.read_regular(STAGE4_EVIDENCE_FILE) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(findings, "invalid-stage4-bundle-artifact", source.to_string());
            return;
        }
    };
    match serde_json::to_vec_pretty(bundle) {
        Ok(expected) if expected == bytes => {}
        Ok(_) => finding(
            findings,
            "noncanonical-stage4-bundle-artifact",
            "stage4-evidence.json is not the canonical publisher encoding",
        ),
        Err(source) => finding(findings, "unencodable-stage4-bundle", source.to_string()),
    }
}

fn validate_marker(
    root: &SecureArtifactRoot,
    mode: PublicationMode,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    match (mode, root.read_regular(STAGE4_INCOMPLETE_MARKER_FILE)) {
        (PublicationMode::Published, Ok(_)) => finding(
            findings,
            "incomplete-stage4-publication",
            format!("{STAGE4_INCOMPLETE_MARKER_FILE} remains present"),
        ),
        (PublicationMode::Published, Err(source))
            if source.kind == SecureArtifactErrorKind::Missing => {}
        (PublicationMode::Published, Err(source)) => {
            finding(findings, "unreadable-stage4-publication-marker", source.to_string())
        }
        (PublicationMode::Staged, Ok(bytes)) if bytes == STAGE4_INCOMPLETE_MARKER_CONTENT => {}
        (PublicationMode::Staged, Ok(_)) => finding(
            findings,
            "invalid-stage4-publication-marker",
            "staged marker has unexpected content",
        ),
        (PublicationMode::Staged, Err(source))
            if source.kind == SecureArtifactErrorKind::Missing =>
        {
            finding(
                findings,
                "missing-stage4-publication-marker",
                "prepublication verification requires the incomplete marker",
            )
        }
        (PublicationMode::Staged, Err(source)) => {
            finding(findings, "unreadable-stage4-publication-marker", source.to_string())
        }
    }
}

fn validate_exact_artifact_set(
    artifact_root: &Path,
    bundle: &Stage4EvidenceBundle,
    matrix: Option<&Stage4MatrixManifest>,
    loaded_stage1: &[(Stage4CellId, Stage1EvidenceBundle)],
    mode: PublicationMode,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let mut expected_files = BTreeSet::from([STAGE4_EVIDENCE_FILE.to_owned()]);
    if safe_relative_uri(&bundle.matrix_manifest.uri) {
        expected_files.insert(bundle.matrix_manifest.uri.clone());
    }
    if mode == PublicationMode::Staged {
        expected_files.insert(STAGE4_INCOMPLETE_MARKER_FILE.to_owned());
    }
    if let Some(matrix) = matrix {
        insert_reference(&matrix.common_input, &mut expected_files);
        insert_reference(&matrix.orchestrator_host.raw_stdout, &mut expected_files);
        insert_reference(&matrix.orchestrator_host.raw_stderr, &mut expected_files);
        for endpoint in &matrix.endpoints {
            for reference in [
                &endpoint.worker_executable,
                &endpoint.build_receipt_artifact,
                &endpoint.launcher_receipt_artifact,
                &endpoint.sysroot_receipt_artifact,
            ] {
                insert_reference(reference, &mut expected_files);
            }
            if let Some(qemu) = endpoint.launcher_receipt.qemu.as_ref() {
                insert_reference(&qemu.executable, &mut expected_files);
                insert_reference(&qemu.version_stdout, &mut expected_files);
                insert_reference(&qemu.version_stderr, &mut expected_files);
            }
            insert_reference(&endpoint.sysroot_receipt.manifest, &mut expected_files);
            insert_reference(
                &endpoint.sysroot_receipt.loader_resolution_stdout,
                &mut expected_files,
            );
            insert_reference(
                &endpoint.sysroot_receipt.loader_resolution_stderr,
                &mut expected_files,
            );
        }
        for cell in &matrix.cells {
            match &cell.disposition {
                Stage4CellDisposition::Passed {
                    stage1_bundle,
                    normalized_observable_trace,
                    source_hello,
                    destination_hello,
                } => {
                    for reference in [
                        stage1_bundle,
                        normalized_observable_trace,
                        &source_hello.raw_stdout,
                        &source_hello.raw_stderr,
                        &destination_hello.raw_stdout,
                        &destination_hello.raw_stderr,
                    ] {
                        insert_reference(reference, &mut expected_files);
                    }
                }
                Stage4CellDisposition::Failed { diagnostics, .. } => {
                    for reference in diagnostics {
                        insert_reference(reference, &mut expected_files);
                    }
                }
                Stage4CellDisposition::NotRun { .. }
                | Stage4CellDisposition::Unsupported { .. } => {}
            }
        }
    }
    for (cell, stage1) in loaded_stage1 {
        for definition in STAGE1_CASE_DEFINITIONS {
            let manifest =
                format!("{}/cases/{}/manifest.json", cell.cell_root_uri(), definition.id);
            if !expected_files.insert(manifest.clone()) {
                finding(findings, "duplicate-stage4-case-manifest-path", manifest);
            }
        }
        for uri in stage1_artifact_uris(stage1) {
            let prefixed = format!("{}/{}", cell.cell_root_uri(), uri);
            if !safe_relative_uri(&prefixed) || !expected_files.insert(prefixed.clone()) {
                finding(findings, "duplicate-or-unsafe-stage4-inner-artifact-path", prefixed);
            }
        }
    }
    let mut expected_directories = BTreeSet::new();
    for uri in &expected_files {
        let mut parent = Path::new(uri).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            if let Some(path) = path.to_str() {
                expected_directories.insert(path.replace(std::path::MAIN_SEPARATOR, "/"));
            }
            parent = path.parent();
        }
    }
    let mut observed = BTreeSet::new();
    enumerate_exact_directory(
        artifact_root,
        "",
        &expected_files,
        &expected_directories,
        &mut observed,
        findings,
    );
    for missing in expected_files.difference(&observed) {
        finding(
            findings,
            "missing-stage4-artifact-entry",
            format!("manifested file {missing} is absent"),
        );
    }
}

fn insert_reference(reference: &Stage4ArtifactReference, files: &mut BTreeSet<String>) {
    if safe_relative_uri(&reference.uri) {
        files.insert(reference.uri.clone());
    }
}

fn stage1_artifact_uris(bundle: &Stage1EvidenceBundle) -> Vec<&str> {
    let provenance = &bundle.provenance.artifacts;
    let mut uris = vec![
        provenance.component.uri.as_str(),
        provenance.profile.uri.as_str(),
        provenance.source_manifest.uri.as_str(),
        provenance.toolchain.uri.as_str(),
        provenance.build_source_manifest.uri.as_str(),
        provenance.build_toolchain.uri.as_str(),
        provenance.executable.uri.as_str(),
        provenance.matrix_manifest.uri.as_str(),
    ];
    for case in &bundle.cases {
        if let Some(snapshot) = case.artifacts.snapshot.as_ref() {
            uris.push(snapshot.uri.as_str());
        }
        uris.extend(case.artifacts.semantic_traces.iter().map(|artifact| artifact.uri.as_str()));
        uris.extend(
            case.artifacts.binding_receipts.iter().map(|receipt| receipt.artifact.uri.as_str()),
        );
        uris.extend(case.artifacts.raw_execution.iter().map(|artifact| artifact.uri.as_str()));
    }
    uris
}

fn enumerate_exact_directory(
    directory: &Path,
    relative: &str,
    expected_files: &BTreeSet<String>,
    expected_directories: &BTreeSet<String>,
    observed: &mut BTreeSet<String>,
    findings: &mut Vec<Stage4ValidationFinding>,
) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) => {
            finding(
                findings,
                "unreadable-stage4-artifact-directory",
                format!("cannot enumerate {}: {source}", directory.display()),
            );
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                finding(findings, "unreadable-stage4-directory-entry", source.to_string());
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                finding(
                    findings,
                    "non-utf8-stage4-artifact-entry",
                    entry.path().display().to_string(),
                );
                continue;
            }
        };
        let uri = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(source) => {
                finding(findings, "unreadable-stage4-directory-entry", format!("{uri}: {source}"));
                continue;
            }
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            finding(findings, "invalid-stage4-artifact-entry-type", format!("{uri} is a symlink"));
        } else if file_type.is_dir() {
            if expected_directories.contains(&uri) {
                enumerate_exact_directory(
                    &entry.path(),
                    &uri,
                    expected_files,
                    expected_directories,
                    observed,
                    findings,
                );
            } else {
                finding(
                    findings,
                    "unexpected-stage4-artifact-entry",
                    format!("unmanifested directory {uri}"),
                );
            }
        } else if file_type.is_file() {
            observed.insert(uri.clone());
            if uri.ends_with(".tmp") || uri.contains(".tmp.") {
                finding(
                    findings,
                    "temporary-stage4-artifact-entry",
                    format!("temporary file {uri} remains"),
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    finding(
                        findings,
                        "hardlinked-stage4-artifact-entry",
                        format!("{uri} has link count {}", metadata.nlink()),
                    );
                }
            }
            if !expected_files.contains(&uri) {
                finding(
                    findings,
                    "unexpected-stage4-artifact-entry",
                    format!("unmanifested file {uri}"),
                );
            }
        } else {
            finding(
                findings,
                "invalid-stage4-artifact-entry-type",
                format!("{uri} is not a regular file or directory"),
            );
        }
    }
}

fn safe_relative_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn finding(
    findings: &mut Vec<Stage4ValidationFinding>,
    code: impl Into<String>,
    detail: impl Into<String>,
) {
    findings.push(Stage4ValidationFinding { code: code.into(), detail: detail.into() });
}

fn report(findings: Vec<Stage4ValidationFinding>) -> Stage4ValidationReport {
    Stage4ValidationReport { ok: findings.is_empty(), findings }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "visa-stage4-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn artifact(uri: impl Into<String>, bytes: &[u8]) -> Stage4ArtifactReference {
        Stage4ArtifactReference {
            uri: uri.into(),
            sha256: sha256_hex(bytes),
            size: u64::try_from(bytes.len()).unwrap(),
        }
    }

    fn placeholder(uri: impl Into<String>, byte: u8) -> Stage4ArtifactReference {
        artifact(uri, &[byte])
    }

    fn target(id: Stage4EndpointId) -> Stage4TargetIdentity {
        Stage4TargetIdentity {
            target_triple: id.target_triple().to_owned(),
            architecture: id.architecture().to_owned(),
            os: "linux".to_owned(),
            abi: "linux-gnu".to_owned(),
            endianness: "little".to_owned(),
            pointer_width_bits: 64,
        }
    }

    fn host_receipt(root: &Path) -> Stage4HostReceipt {
        let stdout = b"Linux 6.12.0-test x86_64\n";
        let stderr = b"";
        for (uri, bytes) in [
            (STAGE4_HOST_UNAME_STDOUT_FILE, stdout.as_slice()),
            (STAGE4_HOST_UNAME_STDERR_FILE, stderr.as_slice()),
        ] {
            let path = root.join(uri);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        Stage4HostReceipt {
            schema_version: STAGE4_HOST_RECEIPT_SCHEMA_VERSION.to_owned(),
            program: UNAME_PROGRAM.to_owned(),
            program_sha256: "f".repeat(64),
            program_size: 1,
            argv: [UNAME_PROGRAM, "-s", "-r", "-m"].map(str::to_owned).to_vec(),
            exit_status: 0,
            identity: Stage4HostIdentity {
                sysname: "Linux".to_owned(),
                kernel_release: "6.12.0-test".to_owned(),
                machine: "x86_64".to_owned(),
            },
            raw_stdout: artifact(STAGE4_HOST_UNAME_STDOUT_FILE, stdout),
            raw_stderr: artifact(STAGE4_HOST_UNAME_STDERR_FILE, stderr),
        }
    }

    fn endpoint(id: Stage4EndpointId) -> Stage4EndpointEvidence {
        let worker = placeholder(id.worker_uri(), 1);
        let sysroot_artifact = placeholder(id.sysroot_receipt_uri(), 2);
        let sysroot = Stage4SysrootReceipt {
            schema_version: STAGE4_SYSROOT_RECEIPT_SCHEMA_VERSION.to_owned(),
            endpoint_id: id,
            identity: "/locked-sysroot".to_owned(),
            manifest: placeholder(id.sysroot_manifest_uri(), 3),
            loader_resolution_stdout: placeholder(id.loader_resolution_stdout_uri(), 4),
            loader_resolution_stderr: artifact(id.loader_resolution_stderr_uri(), b""),
        };
        let qemu = (id != Stage4EndpointId::Hx).then(|| Stage4QemuReceipt {
            adapter_family: "qemu-user".to_owned(),
            emulator_name: if id == Stage4EndpointId::Qx { "qemu-x86_64" } else { "qemu-aarch64" }
                .to_owned(),
            emulator_version: "10.0.2".to_owned(),
            executable: placeholder(id.qemu_uri(), 5),
            version_stdout: placeholder(id.qemu_version_stdout_uri(), 6),
            version_stderr: artifact(id.qemu_version_stderr_uri(), b""),
            argv_prefix: vec![
                "-cpu".to_owned(),
                "max".to_owned(),
                "-L".to_owned(),
                "/locked-sysroot".to_owned(),
                format!("/owned/targets/{}/worker", id.as_str()),
            ],
        });
        let (program, argv) = if let Some(qemu) = qemu.as_ref() {
            let mut argv = vec![format!("/owned/targets/{}/qemu", id.as_str())];
            argv.extend(qemu.argv_prefix.clone());
            (&qemu.executable, argv)
        } else {
            (&worker, vec![format!("/owned/targets/{}/worker", id.as_str())])
        };
        Stage4EndpointEvidence {
            endpoint_id: id,
            target: target(id),
            worker_executable: worker.clone(),
            build_receipt_artifact: placeholder(id.build_receipt_uri(), 7),
            build_receipt: Stage4BuildReceipt {
                schema_version: STAGE4_BUILD_RECEIPT_SCHEMA_VERSION.to_owned(),
                endpoint_id: id,
                target: target(id),
                executable_sha256: worker.sha256.clone(),
                executable_size: worker.size,
                build_source_sha256: "a".repeat(64),
                build_toolchain_sha256: "b".repeat(64),
            },
            launcher_receipt_artifact: placeholder(id.launcher_receipt_uri(), 8),
            launcher_receipt: Stage4LauncherReceipt {
                schema_version: STAGE4_LAUNCHER_RECEIPT_SCHEMA_VERSION.to_owned(),
                endpoint_id: id,
                execution_mode: id.required_execution_mode(),
                boundary: Stage4ExecutionBoundary::for_mode(id.required_execution_mode()),
                program_sha256: program.sha256.clone(),
                program_size: program.size,
                argv,
                qemu,
                sysroot: sysroot_artifact.clone(),
                native_fallback_allowed: false,
                observed_native_fallback: false,
            },
            sysroot_receipt_artifact: sysroot_artifact,
            sysroot_receipt: sysroot,
        }
    }

    fn common_input() -> Stage4CommonInputIdentity {
        let identity = crate::Stage1VersionedIdentity {
            name: STAGE2_WASMTIME_ENVIRONMENT_NAME.to_owned(),
            version: STAGE2_WASMTIME_ENVIRONMENT_VERSION.to_owned(),
        };
        Stage4CommonInputIdentity {
            schema_version: STAGE4_COMMON_INPUT_SCHEMA_VERSION.to_owned(),
            stage1_schema_version: STAGE1_EVIDENCE_SCHEMA_VERSION.to_owned(),
            capability_id: STAGE1_CAPABILITY_ID.to_owned(),
            evidence_kind: crate::Stage1EvidenceKind::Execution,
            component_sha256: STAGE4_ACCEPTED_COMPONENT_SHA256.to_owned(),
            wit_world_name: STAGE2_WIT_WORLD_NAME.to_owned(),
            wit_world_sha256: STAGE2_WIT_WORLD_SHA256.to_owned(),
            profile_sha256: "c".repeat(64),
            config_sha256: "d".repeat(64),
            source_sha256: "a".repeat(64),
            toolchain_sha256: "b".repeat(64),
            carrier: identity.clone(),
            source_runtime: identity.clone(),
            destination_runtime: identity.clone(),
            substrate: crate::Stage1VersionedIdentity {
                name: "host-process-isolation".to_owned(),
                version: "0.1.0".to_owned(),
            },
            provider: crate::Stage1ProviderIdentity {
                implementation: identity.clone(),
                durable: true,
                mock: false,
            },
            authority_enforcement: crate::Stage1AuthorityEnforcementIdentity {
                implementation: identity,
                policy_sha256: "e".repeat(64),
            },
            resource_profiles: Vec::new(),
            cases: Vec::new(),
        }
    }

    #[test]
    fn catalogs_lock_two_claims_seven_unique_cells_and_217_executions() {
        assert_eq!(stage4_registry_sha256(), STAGE4_ACCEPTED_REGISTRY_SHA256);
        assert_eq!(STAGE4_EXECUTION_COUNT, 217);
        assert_eq!(STAGE4_CELL_CATALOG.len(), 7);
        let claims = required_stage4_claims();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].required_cells.len(), 4);
        assert_eq!(claims[1].required_cells.len(), 4);
        let unique = claims
            .iter()
            .flat_map(|claim| claim.required_cells.iter().copied())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), 7);
        assert_eq!(claims[0].required_cells[3], claims[1].required_cells[0]);
    }

    #[test]
    fn host_receipt_reconstructs_a_native_x86_linux_identity_from_raw_bytes() {
        let root = test_root("host-receipt");
        let mut receipt = host_receipt(&root);
        let secure = SecureArtifactRoot::open(&root).unwrap();
        let mut findings = Vec::new();
        validate_host_receipt(&secure, &receipt, &mut findings);
        assert!(findings.is_empty());

        receipt.identity.machine = "aarch64".to_owned();
        let mut findings = Vec::new();
        validate_host_receipt(&secure, &receipt, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "invalid-stage4-host-identity"));
        assert!(findings.iter().any(|finding| finding.code == "stage4-host-receipt-raw-mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execution_boundaries_are_mutually_exclusive() {
        for mode in [
            Stage4ExecutionMode::NativeHost,
            Stage4ExecutionMode::UserEmulated,
            Stage4ExecutionMode::FullSystem,
            Stage4ExecutionMode::Hardware,
        ] {
            let boundary = Stage4ExecutionBoundary::for_mode(mode);
            let count = [
                boundary.native_host,
                boundary.user_emulated,
                boundary.full_system,
                boundary.hardware,
            ]
            .into_iter()
            .filter(|value| *value)
            .count();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn worker_elf_check_rejects_qa_running_x86_and_accepts_aarch64() {
        let mut x86 = vec![0_u8; 20];
        x86[..6].copy_from_slice(b"\x7fELF\x02\x01");
        x86[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let mut arm = x86.clone();
        arm[18..20].copy_from_slice(&183_u16.to_le_bytes());
        let mut findings = Vec::new();
        validate_worker_elf(Stage4EndpointId::Qa, &x86, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "stage4-worker-elf-isa-mismatch"));
        findings.clear();
        validate_worker_elf(Stage4EndpointId::Qa, &arm, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn loader_output_is_independently_normalized_to_exact_guest_paths() {
        let stdout = concat!(
            "linux-vdso.so.1 (0x00000000)\n",
            "/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 (0x00000000)\n",
            "libc.so.6 => /usr/aarch64-linux-gnu/lib/libc.so.6 (0x00000000)\n",
        );
        let paths = parse_loader_guest_paths(stdout, "/usr/aarch64-linux-gnu").unwrap();
        assert_eq!(
            paths,
            BTreeSet::from(["/lib/ld-linux-aarch64.so.1".to_owned(), "/lib/libc.so.6".to_owned(),])
        );
        assert!(parse_loader_guest_paths("libc.so.6 => not found\n", "/").is_err());
    }

    #[test]
    fn hardware_overclaim_and_qualification_forgery_are_rejected() {
        let mut guards = Stage4ClaimGuards::required();
        guards.real_aarch64_hardware = Stage4ClaimBoundary::Proven;
        let mut findings = Vec::new();
        validate_claim_boundary(
            &required_stage4_claims(),
            &guards,
            &required_stage4_qualifications(),
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "stage4-nonclaim-overclaim"));
    }

    #[test]
    fn missing_or_duplicate_cell_catalog_is_rejected() {
        let mut cells = STAGE4_CELL_CATALOG.to_vec();
        cells.pop();
        let mut findings = Vec::new();
        validate_cell_catalog(cells.clone(), &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "invalid-stage4-cell-catalog"));
        cells.push(Stage4CellId::QaToQx);
        findings.clear();
        validate_cell_catalog(cells, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "invalid-stage4-cell-catalog"));
    }

    #[test]
    fn required_cell_disposition_cannot_be_forged_as_success() {
        let mut findings = Vec::new();
        for status in ["failed", "not-run", "unsupported"] {
            required_cell_not_passed(Stage4CellId::HxToHx, status, &mut findings);
        }
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "required-stage4-cell-not-passed")
                .count(),
            3
        );
    }

    #[test]
    fn normalized_cache_tamper_is_recomputed_and_rejected() {
        let root = test_root("normalized-tamper");
        fs::create_dir_all(root.join("normalized")).unwrap();
        let bytes = b"{}";
        let uri = Stage4CellId::HxToHx.normalized_uri();
        fs::write(root.join(&uri), bytes).unwrap();
        let reference = artifact(uri, bytes);
        let recomputed = Stage2NormalizedCellV1 {
            schema_version: crate::STAGE2_NORMALIZED_TRACE_SCHEMA_VERSION.to_owned(),
            timer_equivalence: crate::Stage2TimerEquivalenceProfile::PausedDurationZeroVsPositiveV1,
            derived_integrity_equivalence:
                crate::Stage2DerivedIntegrityEquivalenceProfile::Stage1VerifiedDerivedDigestsV1,
            cases: Vec::new(),
        };
        let secure = SecureArtifactRoot::open(&root).unwrap();
        let mut findings = Vec::new();
        validate_normalized_cache(
            &secure,
            Stage4CellId::HxToHx,
            &reference,
            &recomputed,
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "stage4-normalized-cache-mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hello_nonce_arch_and_digest_tamper_are_rejected_from_raw_bytes() {
        let root = test_root("hello-tamper");
        let cell = Stage4CellId::HxToHx;
        fs::create_dir_all(root.join(cell.cell_root_uri()).join("hello")).unwrap();
        let hello = Stage4TargetHello {
            schema_version: STAGE4_TARGET_HELLO_SCHEMA_VERSION.to_owned(),
            nonce: "b".repeat(64),
            target_triple: Stage4EndpointId::Hx.target_triple().to_owned(),
            architecture: "aarch64".to_owned(),
            os: "linux".to_owned(),
            abi: "linux-gnu".to_owned(),
            endianness: "little".to_owned(),
            pointer_width_bits: 64,
            executable_sha256: "f".repeat(64),
            executable_size: 1,
            build_source_sha256: "a".repeat(64),
            build_toolchain_sha256: "b".repeat(64),
            worker_protocol_version: STAGE4_WORKER_PROTOCOL_VERSION,
        };
        let mut stdout = serde_json::to_vec(&hello).unwrap();
        stdout.push(b'\n');
        let stdout_uri = cell.hello_stdout_uri(Stage4Role::Source);
        let stderr_uri = cell.hello_stderr_uri(Stage4Role::Source);
        fs::write(root.join(&stdout_uri), &stdout).unwrap();
        fs::write(root.join(&stderr_uri), b"").unwrap();
        let observation = Stage4TargetHelloObservation {
            expected_nonce: "a".repeat(64),
            exit_status: 0,
            hello: hello.clone(),
            raw_stdout: artifact(stdout_uri, &stdout),
            raw_stderr: artifact(stderr_uri, b""),
        };
        let secure = SecureArtifactRoot::open(&root).unwrap();
        let mut nonces = BTreeSet::new();
        let mut findings = Vec::new();
        validate_hello(
            &secure,
            cell,
            Stage4Role::Source,
            &observation,
            &endpoint(Stage4EndpointId::Hx),
            &mut nonces,
            &mut findings,
        );
        assert!(
            findings.iter().any(|finding| finding.code == "stage4-target-hello-nonce-mismatch")
        );
        assert!(
            findings.iter().any(|finding| finding.code == "stage4-target-hello-identity-mismatch")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qx_native_fallback_is_rejected() {
        let root = test_root("qx-native-fallback");
        let secure = SecureArtifactRoot::open(&root).unwrap();
        let mut qx = endpoint(Stage4EndpointId::Qx);
        qx.launcher_receipt.qemu = None;
        let mut findings = Vec::new();
        validate_endpoint(&secure, &qx, &target(Stage4EndpointId::Hx), "/owned", &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "stage4-native-fallback-detected"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_common_input_is_rejected() {
        let common = common_input();
        let mut actual = common.clone();
        actual.component_sha256 = "0".repeat(64);
        let mut findings = Vec::new();
        validate_common_identity(Stage4CellId::QaToQa, &actual, &common, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "mixed-stage4-common-input"));
    }

    #[test]
    fn common_shape_locks_the_stage4_release_component() {
        let common = common_input();
        let mut findings = Vec::new();
        validate_common_shape(&common, &mut findings);
        assert!(
            findings.iter().all(|finding| finding.code != "invalid-stage4-common-input-identity")
        );

        assert_ne!(
            STAGE4_ACCEPTED_COMPONENT_SHA256,
            crate::STAGE2_STRICT_COMPONENT_SHA256,
            "Stage 4 release and Strict Stage 2 dev Components are distinct byte artifacts"
        );
        let mut strict_stage2 = common;
        strict_stage2.component_sha256 = crate::STAGE2_STRICT_COMPONENT_SHA256.to_owned();
        let mut findings = Vec::new();
        validate_common_shape(&strict_stage2, &mut findings);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.code == "invalid-stage4-common-input-identity" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_inventory_rejects_extra_tmp_symlink_hardlink_and_special_file() {
        use std::os::unix::fs::symlink;

        let root = test_root("exact-inventory");
        fs::write(root.join("kept"), b"bytes").unwrap();
        fs::write(root.join("extra"), b"extra").unwrap();
        fs::write(root.join("orphan.tmp"), b"temporary").unwrap();
        fs::hard_link(root.join("kept"), root.join("alias")).unwrap();
        symlink("kept", root.join("link")).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
        let expected_files = BTreeSet::from(["kept".to_owned()]);
        let mut observed = BTreeSet::new();
        let mut findings = Vec::new();
        enumerate_exact_directory(
            &root,
            "",
            &expected_files,
            &BTreeSet::new(),
            &mut observed,
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "unexpected-stage4-artifact-entry"));
        assert!(
            findings.iter().any(|finding| finding.code == "invalid-stage4-artifact-entry-type")
        );
        assert!(findings.iter().any(|finding| finding.code == "hardlinked-stage4-artifact-entry"));
        assert!(findings.iter().any(|finding| finding.code == "temporary-stage4-artifact-entry"));
        drop(socket);
        fs::remove_dir_all(root).unwrap();
    }
}
