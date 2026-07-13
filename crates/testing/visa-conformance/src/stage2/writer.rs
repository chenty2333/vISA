use std::{fs, path::Path};

use super::{
    artifacts::{
        ensure_incomplete_marker, publish_atomic, read_contained, remove_if_exists,
        render_findings, sync_directory, write_error, write_from_finding,
    },
    common::{accepted_registry_sha256, validate_common_input, validate_cross_cell_inputs},
    model::{
        STAGE2_COMMON_INPUT_FILE, STAGE2_EVIDENCE_FILE, STAGE2_EVIDENCE_SCHEMA_VERSION,
        STAGE2_EXECUTION_COUNT, STAGE2_INCOMPLETE_MARKER_FILE, STAGE2_MATRIX_MANIFEST_FILE,
        STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION, Stage2ArtifactReference, Stage2CellManifest,
        Stage2Claim, Stage2ClaimGuards, Stage2ClaimSet, Stage2CommonInputManifest,
        Stage2EvidenceBundle, Stage2InnerVerification, Stage2MatrixManifest, Stage2WriteError,
        Stage2WriteResult, stage2_cell_descriptors,
    },
    verify::{
        compare_normalized_cells, load_verified_cell,
        validate_stage2_evidence_artifacts_for_publication,
    },
};
use crate::{
    canonical_stage2_json_bytes, parse_stage1_evidence_bundle_json, sha256_hex,
    stage2_normalize::{Stage2NormalizedCellV1, normalize_stage2_cell},
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

pub fn normalize_verified_stage1_bundle_for_stage2(
    bundle_bytes: &[u8],
    artifact_root: impl AsRef<Path>,
) -> Result<Stage2NormalizedCellV1, Stage2WriteError> {
    let artifact_root = artifact_root.as_ref();
    let bundle = parse_stage1_evidence_bundle_json(bundle_bytes)
        .map_err(|source| write_error("stage2-inner-stage1-parse-failed", source.detail))?;
    let (gate, artifacts) =
        validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, artifact_root);
    if !gate.ok {
        return Err(write_error(
            "stage2-inner-stage1-verification-failed",
            serde_json::to_string(&gate).unwrap_or_default(),
        ));
    }
    let artifacts = artifacts.ok_or_else(|| {
        write_error(
            "stage2-inner-stage1-artifact-snapshot-missing",
            "Stage 1 passed without a stable artifact snapshot",
        )
    })?;
    normalize_stage2_cell(&bundle, &artifacts)
        .map_err(|source| write_error(source.code, source.detail))
}

pub fn write_stage2_evidence_artifacts(
    stage2_root: impl AsRef<Path>,
) -> Result<Stage2WriteResult, Stage2WriteError> {
    let stage2_root = stage2_root.as_ref();
    fs::create_dir_all(stage2_root).map_err(|source| {
        write_error(
            "cannot-create-stage2-root",
            format!("cannot create {}: {source}", stage2_root.display()),
        )
    })?;
    let stage2_root = stage2_root.canonicalize().map_err(|source| {
        write_error(
            "invalid-stage2-root",
            format!("cannot resolve {}: {source}", stage2_root.display()),
        )
    })?;
    ensure_incomplete_marker(&stage2_root)?;

    let common_uri = STAGE2_COMMON_INPUT_FILE.to_owned();
    let common_bytes = read_contained(&stage2_root, &common_uri).map_err(write_from_finding)?;
    let common: Stage2CommonInputManifest =
        serde_json::from_slice(&common_bytes).map_err(|source| {
            write_error(
                "invalid-stage2-common-input-json",
                format!("cannot parse {STAGE2_COMMON_INPUT_FILE}: {source}"),
            )
        })?;
    let common_findings = validate_common_input(&common, &stage2_root);
    if !common_findings.is_empty() {
        return Err(write_error("invalid-stage2-common-input", render_findings(&common_findings)));
    }

    let descriptors =
        stage2_cell_descriptors(Stage2ClaimSet::CrossExecutionPathPortability).collect::<Vec<_>>();
    let mut verified = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        verified.push(load_verified_cell(descriptor, &stage2_root).map_err(write_from_finding)?);
    }
    let common_sha256 = sha256_hex(&common_bytes);
    let cross_findings = validate_cross_cell_inputs(&common, &common_sha256, &verified);
    if !cross_findings.is_empty() {
        return Err(write_error("stage2-cell-input-mismatch", render_findings(&cross_findings)));
    }

    fs::create_dir_all(stage2_root.join("normalized")).map_err(|source| {
        write_error(
            "cannot-create-stage2-normalized-root",
            format!("cannot create normalized directory: {source}"),
        )
    })?;
    let mut cells = Vec::with_capacity(verified.len());
    for cell in &verified {
        let descriptor = cell.descriptor;
        let normalized_bytes = canonical_stage2_json_bytes(&cell.normalized)
            .map_err(|source| write_error(source.code, source.detail))?;
        let normalized_uri = descriptor.id.normalized_uri();
        publish_atomic(&stage2_root, &normalized_uri, &normalized_bytes)?;
        cells.push(Stage2CellManifest {
            cell_id: descriptor.id,
            requested_source: descriptor.source_runtime,
            requested_destination: descriptor.destination_runtime,
            observed_source: cell.bundle.environment.source_runtime.clone(),
            observed_destination: cell.bundle.environment.destination_runtime.clone(),
            source_translation_provenance: cell.source_translation_provenance.clone(),
            destination_translation_provenance: cell.destination_translation_provenance.clone(),
            instantiation_observations: cell.instantiation_observations.clone(),
            stage1_bundle: Stage2ArtifactReference {
                uri: descriptor.id.stage1_bundle_uri(),
                sha256: sha256_hex(&cell.bundle_bytes),
            },
            normalized_observable_trace: Stage2ArtifactReference {
                uri: normalized_uri,
                sha256: sha256_hex(&normalized_bytes),
            },
            case_count: cell.bundle.cases.len(),
            no_fallback_observed: true,
        });
    }

    let comparisons = compare_normalized_cells(&verified).map_err(write_from_finding)?;
    let claims = vec![Stage2Claim::CrossExecutionPathPortability];
    let guards = Stage2ClaimGuards::required();
    let manifest = Stage2MatrixManifest {
        schema_version: STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION.to_owned(),
        common_input: Stage2ArtifactReference {
            uri: common_uri,
            sha256: sha256_hex(&common_bytes),
        },
        registry_sha256: accepted_registry_sha256(&common.cases)
            .map_err(|source| write_error(source.code, source.detail))?,
        cells,
        execution_count: STAGE2_EXECUTION_COUNT,
        claims: claims.clone(),
        claim_guards: guards.clone(),
    };
    let manifest_bytes = canonical_stage2_json_bytes(&manifest)
        .map_err(|source| write_error(source.code, source.detail))?;
    publish_atomic(&stage2_root, STAGE2_MATRIX_MANIFEST_FILE, &manifest_bytes)?;

    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let bundle_id = format!("stage2-{}", &manifest_sha256[..24]);
    let evidence = Stage2EvidenceBundle {
        schema_version: STAGE2_EVIDENCE_SCHEMA_VERSION.to_owned(),
        bundle_id: bundle_id.clone(),
        matrix_manifest: Stage2ArtifactReference {
            uri: STAGE2_MATRIX_MANIFEST_FILE.to_owned(),
            sha256: manifest_sha256,
        },
        completed_execution_count: STAGE2_EXECUTION_COUNT,
        inner_verifications: verified
            .iter()
            .map(|cell| Stage2InnerVerification {
                cell_id: cell.descriptor.id,
                stage1_bundle_id: cell.bundle.bundle_id.clone(),
                stage1_bundle_sha256: sha256_hex(&cell.bundle_bytes),
                case_count: cell.bundle.cases.len(),
                independently_verified: true,
            })
            .collect(),
        case_comparisons: comparisons,
        claims,
        claim_guards: guards,
    };
    let evidence_bytes = canonical_stage2_json_bytes(&evidence)
        .map_err(|source| write_error(source.code, source.detail))?;
    let independent = validate_stage2_evidence_artifacts_for_publication(&evidence, &stage2_root);
    if !independent.ok {
        return Err(write_error(
            "stage2-independent-verification-failed",
            serde_json::to_string(&independent).unwrap_or_else(|_| format!("{independent:?}")),
        ));
    }
    publish_atomic(&stage2_root, STAGE2_EVIDENCE_FILE, &evidence_bytes)?;
    remove_if_exists(&stage2_root.join(STAGE2_INCOMPLETE_MARKER_FILE))?;
    sync_directory(&stage2_root)?;

    Ok(Stage2WriteResult {
        evidence_path: stage2_root.join(STAGE2_EVIDENCE_FILE),
        manifest_path: stage2_root.join(STAGE2_MATRIX_MANIFEST_FILE),
        bundle_id,
        bundle_sha256: sha256_hex(&evidence_bytes),
    })
}
