use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use super::{
    artifacts::{
        finding, read_and_hash, read_contained, render_findings, single_finding,
        validate_cell_directory_set, validate_normalized_directory_set,
    },
    common::{
        accepted_registry_sha256, parse_common_input, validate_common_input,
        validate_cross_cell_inputs,
    },
    model::*,
    runtime::{
        translation_presence_matches, validate_inner_cell, validate_inner_cell_without_manifest,
    },
    strict_model::Stage2StrictRuntimeIdentityChain,
};
use crate::{
    STAGE1_CASE_DEFINITIONS, Stage1EvidenceBundle, VerifiedStage1Artifacts,
    canonical_stage2_json_bytes, canonical_stage2_sha256, parse_stage1_evidence_bundle_json,
    sha256_hex,
    stage2_normalize::{Stage2NormalizedCellV1, normalize_stage2_cell},
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

pub(super) struct VerifiedCell {
    pub(super) descriptor: &'static Stage2CellDescriptor,
    pub(super) bundle: Stage1EvidenceBundle,
    pub(super) bundle_bytes: Vec<u8>,
    pub(super) artifacts: VerifiedStage1Artifacts,
    pub(super) normalized: Stage2NormalizedCellV1,
    pub(super) source_translation_provenance: Option<Stage2TranslationProvenance>,
    pub(super) destination_translation_provenance: Option<Stage2TranslationProvenance>,
    pub(super) instantiation_observations: Stage2InstantiationObservations,
    pub(super) source_runtime_chain: Option<Stage2StrictRuntimeIdentityChain>,
    pub(super) destination_runtime_chain: Option<Stage2StrictRuntimeIdentityChain>,
}

pub fn parse_stage2_evidence_bundle_json(
    bytes: &[u8],
) -> Result<Stage2EvidenceBundle, Stage2EvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|source| Stage2EvidenceLoadError {
        code: "invalid-stage2-evidence-json".to_owned(),
        detail: source.to_string(),
    })
}

pub fn gate_stage2_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    stage2_root: impl AsRef<Path>,
) -> Stage2EvidenceGateResult {
    let bundle = match parse_stage2_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return Stage2EvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let validation = validate_stage2_evidence_artifacts(&bundle, stage2_root);
    Stage2EvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn validate_stage2_evidence_artifacts(
    evidence: &Stage2EvidenceBundle,
    stage2_root: impl AsRef<Path>,
) -> Stage2ValidationReport {
    validate_stage2_evidence_artifacts_impl(evidence, stage2_root.as_ref(), false)
}

pub(crate) fn validate_stage2_evidence_artifacts_for_publication(
    evidence: &Stage2EvidenceBundle,
    stage2_root: impl AsRef<Path>,
) -> Stage2ValidationReport {
    validate_stage2_evidence_artifacts_impl(evidence, stage2_root.as_ref(), true)
}

fn validate_stage2_evidence_artifacts_impl(
    evidence: &Stage2EvidenceBundle,
    stage2_root: &Path,
    allow_publisher_marker: bool,
) -> Stage2ValidationReport {
    let mut findings = Vec::new();
    validate_evidence_shape(evidence, &mut findings);
    let root = match stage2_root.canonicalize() {
        Ok(root) => root,
        Err(source) => {
            finding(
                &mut findings,
                "invalid-stage2-artifact-root",
                format!("cannot resolve artifact root: {source}"),
            );
            return Stage2ValidationReport::new(findings);
        }
    };
    let publisher_marker = root.join(STAGE2_INCOMPLETE_MARKER_FILE);
    let (publisher_marker_present, publisher_marker_regular) =
        match fs::symlink_metadata(&publisher_marker) {
            Ok(metadata) => (true, metadata.is_file() && !metadata.file_type().is_symlink()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => (false, false),
            Err(source) => {
                finding(
                    &mut findings,
                    "unreadable-stage2-publication-marker",
                    format!("cannot inspect {}: {source}", publisher_marker.display()),
                );
                return Stage2ValidationReport::new(findings);
            }
        };
    let legacy_marker = root.join(".stage2-incomplete.json");
    let legacy_marker_present = match fs::symlink_metadata(&legacy_marker) {
        Ok(_) => true,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            finding(
                &mut findings,
                "unreadable-stage2-publication-marker",
                format!("cannot inspect {}: {source}", legacy_marker.display()),
            );
            return Stage2ValidationReport::new(findings);
        }
    };
    if legacy_marker_present
        || (!allow_publisher_marker && publisher_marker_present)
        || (allow_publisher_marker && !publisher_marker_regular)
    {
        finding(
            &mut findings,
            "incomplete-stage2-publication",
            if allow_publisher_marker {
                "prepublication verification requires exactly the regular publisher marker"
                    .to_owned()
            } else {
                format!("{STAGE2_INCOMPLETE_MARKER_FILE} is still present")
            },
        );
        return Stage2ValidationReport::new(findings);
    }

    let manifest_bytes = match read_and_hash(
        &root,
        &evidence.matrix_manifest,
        "Stage 2 matrix manifest",
        &mut findings,
    ) {
        Some(bytes) => bytes,
        None => return Stage2ValidationReport::new(findings),
    };
    let manifest: Stage2MatrixManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(source) => {
            finding(&mut findings, "invalid-stage2-matrix-manifest-json", source.to_string());
            return Stage2ValidationReport::new(findings);
        }
    };
    let expected_bundle_id = format!("stage2-{}", &sha256_hex(&manifest_bytes)[..24]);
    if evidence.bundle_id != expected_bundle_id {
        finding(
            &mut findings,
            "inconsistent-stage2-bundle-id",
            format!("expected {expected_bundle_id}, found {}", evidence.bundle_id),
        );
    }
    validate_manifest_shape(&manifest, evidence, &mut findings);

    let common_bytes =
        match read_and_hash(&root, &manifest.common_input, "Stage 2 common input", &mut findings) {
            Some(bytes) => bytes,
            None => return Stage2ValidationReport::new(findings),
        };
    let common = match parse_common_input(&common_bytes) {
        Ok(common) => common,
        Err(source) => {
            finding(&mut findings, source.code, source.detail);
            return Stage2ValidationReport::new(findings);
        }
    };
    findings.extend(validate_common_input(&common, &root));
    match accepted_registry_sha256(&common.cases) {
        Ok(digest)
            if digest == STAGE2_ACCEPTED_REGISTRY_SHA256
                && manifest.registry_sha256 == STAGE2_ACCEPTED_REGISTRY_SHA256 => {}
        Ok(_) => finding(
            &mut findings,
            "stage2-registry-digest-mismatch",
            "common and matrix registry digests must equal the accepted 31-case catalog lock",
        ),
        Err(source) => finding(&mut findings, source.code, source.detail),
    }
    validate_cell_directory_set(&root, &mut findings);
    validate_normalized_directory_set(&root, &mut findings);

    let descriptors =
        stage2_cell_descriptors(Stage2ClaimSet::CrossExecutionPathPortability).collect::<Vec<_>>();
    let mut verified = Vec::with_capacity(descriptors.len());
    let cells_by_id =
        manifest.cells.iter().map(|cell| (cell.cell_id, cell)).collect::<BTreeMap<_, _>>();
    for descriptor in &descriptors {
        let cell_id = descriptor.id;
        let Some(cell_manifest) = cells_by_id.get(&cell_id) else {
            continue;
        };
        let expected_bundle_uri = cell_id.stage1_bundle_uri();
        if cell_manifest.stage1_bundle.uri != expected_bundle_uri {
            finding(
                &mut findings,
                "noncanonical-stage2-cell-bundle-path",
                format!("{} must use {expected_bundle_uri}", cell_id.as_str()),
            );
            continue;
        }
        let bundle_bytes = match read_and_hash(
            &root,
            &cell_manifest.stage1_bundle,
            "Stage 1 cell bundle",
            &mut findings,
        ) {
            Some(bytes) => bytes,
            None => continue,
        };
        let bundle = match parse_stage1_evidence_bundle_json(&bundle_bytes) {
            Ok(bundle) => bundle,
            Err(source) => {
                finding(
                    &mut findings,
                    "stage2-inner-stage1-parse-failed",
                    format!("{}: {}", cell_id.as_str(), source.detail),
                );
                continue;
            }
        };
        let cell_root = cell_id.cell_root(&root);
        let (inner, artifacts) =
            validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, &cell_root);
        if !inner.ok {
            finding(
                &mut findings,
                "stage2-inner-stage1-verification-failed",
                format!(
                    "{}: {}",
                    cell_id.as_str(),
                    serde_json::to_string(&inner).unwrap_or_default()
                ),
            );
            continue;
        }
        let Some(artifacts) = artifacts else {
            finding(
                &mut findings,
                "stage2-inner-stage1-artifact-snapshot-missing",
                format!("{} passed without a stable artifact snapshot", cell_id.as_str()),
            );
            continue;
        };
        let observed_transcript = validate_inner_cell(
            descriptor,
            cell_manifest,
            &bundle,
            &artifacts,
            &cell_root,
            &mut findings,
        );
        let normalized = match normalize_stage2_cell(&bundle, &artifacts) {
            Ok(normalized) => normalized,
            Err(source) => {
                finding(
                    &mut findings,
                    "stage2-normalization-failed",
                    format!("{}: {source}", cell_id.as_str()),
                );
                continue;
            }
        };
        validate_normalized_cache(&root, cell_manifest, &normalized, &mut findings);
        verified.push(VerifiedCell {
            descriptor,
            bundle,
            bundle_bytes,
            artifacts,
            normalized,
            source_translation_provenance: observed_transcript.translation_provenance.source,
            destination_translation_provenance: observed_transcript
                .translation_provenance
                .destination,
            instantiation_observations: observed_transcript.instantiation_observations,
            source_runtime_chain: observed_transcript.source_runtime_chain,
            destination_runtime_chain: observed_transcript.destination_runtime_chain,
        });
    }

    if verified.len() == descriptors.len() {
        findings.extend(validate_cross_cell_inputs(
            &common,
            &manifest.common_input.sha256,
            &verified,
        ));
        match compare_normalized_cells(&verified) {
            Ok(comparisons) => {
                if evidence.case_comparisons != comparisons {
                    finding(
                        &mut findings,
                        "stage2-comparison-record-mismatch",
                        "outer comparison records differ from independently recomputed V1",
                    );
                }
            }
            Err(source) => findings.push(source),
        }
        validate_inner_summaries(evidence, &verified, &mut findings);
    }

    Stage2ValidationReport::new(findings)
}

pub(super) fn load_verified_cell(
    descriptor: &'static Stage2CellDescriptor,
    root: &Path,
) -> Result<VerifiedCell, Stage2ValidationFinding> {
    let id = descriptor.id;
    let uri = id.stage1_bundle_uri();
    let bundle_bytes = read_contained(root, &uri)?;
    let bundle = parse_stage1_evidence_bundle_json(&bundle_bytes).map_err(|source| {
        single_finding(
            "stage2-inner-stage1-parse-failed",
            format!("{}: {}", id.as_str(), source.detail),
        )
    })?;
    let cell_root = id.cell_root(root);
    let (result, artifacts) =
        validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, &cell_root);
    if !result.ok {
        return Err(single_finding(
            "stage2-inner-stage1-verification-failed",
            format!("{}: {}", id.as_str(), serde_json::to_string(&result).unwrap_or_default()),
        ));
    }
    let artifacts = artifacts.ok_or_else(|| {
        single_finding(
            "stage2-inner-stage1-artifact-snapshot-missing",
            format!("{} passed without a stable artifact snapshot", id.as_str()),
        )
    })?;
    let mut findings = Vec::new();
    let observed_transcript = validate_inner_cell_without_manifest(
        descriptor,
        &bundle,
        &artifacts,
        &cell_root,
        &mut findings,
    );
    if !findings.is_empty() {
        return Err(single_finding("invalid-stage2-inner-cell", render_findings(&findings)));
    }
    let normalized = normalize_stage2_cell(&bundle, &artifacts).map_err(|source| {
        single_finding("stage2-normalization-failed", format!("{}: {source}", id.as_str()))
    })?;
    Ok(VerifiedCell {
        descriptor,
        bundle,
        bundle_bytes,
        artifacts,
        normalized,
        source_translation_provenance: observed_transcript.translation_provenance.source,
        destination_translation_provenance: observed_transcript.translation_provenance.destination,
        instantiation_observations: observed_transcript.instantiation_observations,
        source_runtime_chain: observed_transcript.source_runtime_chain,
        destination_runtime_chain: observed_transcript.destination_runtime_chain,
    })
}

pub(crate) fn validate_evidence_shape(
    evidence: &Stage2EvidenceBundle,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if evidence.schema_version != STAGE2_EVIDENCE_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage2-evidence-schema",
            format!("found {}", evidence.schema_version),
        );
    }
    if evidence.bundle_id.is_empty() {
        finding(findings, "missing-stage2-bundle-id", "bundle_id is empty");
    }
    if evidence.matrix_manifest.uri != STAGE2_MATRIX_MANIFEST_FILE {
        finding(
            findings,
            "noncanonical-stage2-manifest-path",
            format!("manifest must be {STAGE2_MATRIX_MANIFEST_FILE}"),
        );
    }
    if evidence.completed_execution_count != STAGE2_EXECUTION_COUNT {
        finding(
            findings,
            "wrong-stage2-execution-count",
            format!(
                "expected {STAGE2_EXECUTION_COUNT}, found {}",
                evidence.completed_execution_count
            ),
        );
    }
    validate_claims_and_guards(&evidence.claims, &evidence.claim_guards, findings);
    require_exact_cell_ids(
        evidence.inner_verifications.iter().map(|verification| verification.cell_id),
        "inner verification",
        findings,
    );
    if evidence.case_comparisons.len() != STAGE1_CASE_DEFINITIONS.len()
        || evidence.case_comparisons.iter().zip(STAGE1_CASE_DEFINITIONS).any(
            |(comparison, definition)| {
                comparison.case_id != definition.id || !comparison.equal_across_all_cells
            },
        )
    {
        finding(
            findings,
            "invalid-stage2-case-comparison-set",
            "comparison records must cover the ordered 31-case registry and all be equal",
        );
    }
}

pub(crate) fn validate_manifest_shape(
    manifest: &Stage2MatrixManifest,
    evidence: &Stage2EvidenceBundle,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if manifest.schema_version != STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage2-matrix-schema",
            format!("found {}", manifest.schema_version),
        );
    }
    if manifest.common_input.uri != STAGE2_COMMON_INPUT_FILE {
        finding(
            findings,
            "noncanonical-stage2-common-input-path",
            format!("common input must be {STAGE2_COMMON_INPUT_FILE}"),
        );
    }
    if manifest.registry_sha256 != STAGE2_ACCEPTED_REGISTRY_SHA256 {
        finding(
            findings,
            "invalid-stage2-registry-digest",
            "matrix registry digest does not equal the accepted catalog lock",
        );
    }
    if manifest.execution_count != STAGE2_EXECUTION_COUNT
        || manifest.execution_count != evidence.completed_execution_count
    {
        finding(
            findings,
            "inconsistent-stage2-execution-count",
            "matrix and evidence must both record exactly 124 executions",
        );
    }
    if manifest.claims != evidence.claims || manifest.claim_guards != evidence.claim_guards {
        finding(
            findings,
            "inconsistent-stage2-claim-boundary",
            "matrix and evidence claim boundaries differ",
        );
    }
    validate_claims_and_guards(&manifest.claims, &manifest.claim_guards, findings);
    require_exact_cell_ids(manifest.cells.iter().map(|cell| cell.cell_id), "matrix cell", findings);
    let mut bundle_uris = BTreeSet::new();
    let mut normalized_uris = BTreeSet::new();
    for cell in &manifest.cells {
        validate_instantiation_observations_shape(cell, findings);
        let Some(descriptor) = stage2_cell_descriptor(cell.cell_id) else {
            finding(
                findings,
                "invalid-stage2-cell-manifest",
                format!("{} has no catalog descriptor", cell.cell_id.as_str()),
            );
            continue;
        };
        if cell.requested_source != descriptor.source_runtime
            || cell.requested_destination != descriptor.destination_runtime
            || cell.case_count != STAGE1_CASE_DEFINITIONS.len()
            || !cell.no_fallback_observed
            || !translation_presence_matches(
                cell.requested_source,
                cell.source_translation_provenance.as_ref(),
            )
            || !translation_presence_matches(
                cell.requested_destination,
                cell.destination_translation_provenance.as_ref(),
            )
        {
            finding(
                findings,
                "invalid-stage2-cell-manifest",
                format!("{} has wrong pair, count, or fallback marker", cell.cell_id.as_str()),
            );
        }
        if !bundle_uris.insert(&cell.stage1_bundle.uri)
            || !normalized_uris.insert(&cell.normalized_observable_trace.uri)
            || cell.normalized_observable_trace.uri != cell.cell_id.normalized_uri()
        {
            finding(
                findings,
                "duplicate-or-noncanonical-stage2-cell-artifact",
                format!("{} has duplicate or noncanonical artifacts", cell.cell_id.as_str()),
            );
        }
    }
}

pub(super) fn validate_instantiation_observations_shape(
    cell: &Stage2CellManifest,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let observations = &cell.instantiation_observations;
    if observations.schema_version != STAGE2_INSTANTIATION_OBSERVATIONS_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage2-instantiation-observations-schema",
            format!("{} found {}", cell.cell_id.as_str(), observations.schema_version),
        );
    }
    let canonical_cases = observations.cases.len() == STAGE1_CASE_DEFINITIONS.len()
        && observations
            .cases
            .iter()
            .zip(STAGE1_CASE_DEFINITIONS)
            .all(|(observation, definition)| observation.case_id == definition.id);
    if !canonical_cases {
        finding(
            findings,
            "invalid-stage2-instantiation-observation-case-set",
            format!(
                "{} instantiation observations must use the exact ordered 31-case registry",
                cell.cell_id.as_str()
            ),
        );
    }
    for case in &observations.cases {
        let valid_source = matches!(
            case.source,
            Stage2InstantiationObservation::Live {
                boundary: Stage2LiveInstantiationBoundary::BootstrapSource
            }
        );
        let valid_destination = matches!(
            case.destination,
            Stage2InstantiationObservation::Live {
                boundary: Stage2LiveInstantiationBoundary::PostCommitResume
            } | Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::BeforeCommit,
                reason: Stage2NotInstantiatedReason::SourceRetained
            } | Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::AfterCommitBeforeResume,
                reason: Stage2NotInstantiatedReason::RecoveryRequired
            }
        );
        if !valid_source || !valid_destination {
            finding(
                findings,
                "invalid-stage2-instantiation-observation-boundary",
                format!(
                    "{} {} has a noncanonical source or destination boundary",
                    cell.cell_id.as_str(),
                    case.case_id
                ),
            );
        }
    }
}

pub(super) fn compare_normalized_cells(
    cells: &[VerifiedCell],
) -> Result<Vec<Stage2CaseComparison>, Stage2ValidationFinding> {
    compare_normalized_cells_for_claim(cells, Stage2ClaimSet::CrossExecutionPathPortability)
}

pub(super) fn compare_normalized_cells_for_claim(
    cells: &[VerifiedCell],
    claim_set: Stage2ClaimSet,
) -> Result<Vec<Stage2CaseComparison>, Stage2ValidationFinding> {
    if !stage2_cell_ids_match_claim(cells.iter().map(|cell| cell.descriptor.id), claim_set) {
        return Err(single_finding(
            "incomplete-stage2-normalized-matrix",
            "cells do not match the exact ordered execution-path descriptor set",
        ));
    }
    let mut comparisons = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let Some(baseline) = cells[0].normalized.cases.get(index) else {
            return Err(single_finding("missing-stage2-normalized-case", definition.id));
        };
        if baseline.case_id != definition.id {
            return Err(single_finding("misordered-stage2-normalized-case", definition.id));
        }
        let equal = cells.iter().all(|cell| cell.normalized.cases.get(index) == Some(baseline));
        if !equal {
            return Err(single_finding(
                "stage2-normalized-observable-divergence",
                format!("{} differs across execution paths", definition.id),
            ));
        }
        let normalized_case_sha256 = canonical_stage2_sha256(baseline)
            .map_err(|source| single_finding(source.code, source.detail))?;
        comparisons.push(Stage2CaseComparison {
            case_id: definition.id.to_owned(),
            normalized_case_sha256,
            equal_across_all_cells: true,
        });
    }
    Ok(comparisons)
}

pub(crate) fn validate_normalized_cache(
    root: &Path,
    manifest: &Stage2CellManifest,
    recomputed: &Stage2NormalizedCellV1,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let Some(bytes) = read_and_hash(
        root,
        &manifest.normalized_observable_trace,
        "normalized observable trace",
        findings,
    ) else {
        return;
    };
    let canonical = match canonical_stage2_json_bytes(recomputed) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(findings, source.code, source.detail);
            return;
        }
    };
    if bytes != canonical {
        finding(
            findings,
            "stage2-normalized-cache-mismatch",
            format!("{} cache differs from recomputed V1", manifest.cell_id.as_str()),
        );
    }
}

fn validate_inner_summaries(
    evidence: &Stage2EvidenceBundle,
    verified: &[VerifiedCell],
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let by_id = evidence
        .inner_verifications
        .iter()
        .map(|summary| (summary.cell_id, summary))
        .collect::<BTreeMap<_, _>>();
    for cell in verified {
        let Some(summary) = by_id.get(&cell.descriptor.id) else { continue };
        if summary.stage1_bundle_id != cell.bundle.bundle_id
            || summary.stage1_bundle_sha256 != sha256_hex(&cell.bundle_bytes)
            || summary.case_count != STAGE1_CASE_DEFINITIONS.len()
            || !summary.independently_verified
        {
            finding(
                findings,
                "stage2-inner-verification-summary-mismatch",
                format!("{} summary differs from raw Stage 1 bundle", cell.descriptor.id.as_str()),
            );
        }
    }
}

fn validate_claims_and_guards(
    claims: &[Stage2Claim],
    guards: &Stage2ClaimGuards,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if claims != [Stage2Claim::CrossExecutionPathPortability] {
        finding(
            findings,
            "invalid-or-overstated-stage2-claim",
            format!("only {STAGE2_CLAIM_ID} is accepted"),
        );
    }
    if guards != &Stage2ClaimGuards::required() {
        finding(
            findings,
            "invalid-stage2-claim-guards",
            "strict independence and broader claims must remain unproven/unclaimed",
        );
    }
}

fn require_exact_cell_ids(
    ids: impl Iterator<Item = Stage2CellId>,
    label: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let ids = ids.collect::<Vec<_>>();
    if !stage2_cell_ids_match_claim(ids, Stage2ClaimSet::CrossExecutionPathPortability) {
        finding(
            findings,
            "invalid-stage2-cell-set",
            format!("{label} IDs must be the exact canonical four-cell order"),
        );
    }
}
