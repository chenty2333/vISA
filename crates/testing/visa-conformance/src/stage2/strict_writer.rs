use std::{fs, path::Path};

use super::{
    artifacts::{
        ensure_incomplete_marker, publish_atomic, read_contained, remove_if_exists,
        render_findings, sync_directory, write_error, write_from_finding,
    },
    common::{
        accepted_registry_sha256, parse_common_input, validate_common_input,
        validate_cross_cell_inputs,
    },
    model::*,
    strict_lineage::load_and_validate_strict_lineage,
    strict_model::*,
    strict_verify::{
        validate_stage2_strict_evidence_artifacts_for_publication,
        validate_verified_cell_cargo_lock_binding,
    },
    verify::{compare_normalized_cells_for_claim, load_verified_cell},
};
use crate::{canonical_stage2_json_bytes, sha256_hex};

pub fn write_stage2_strict_evidence_artifacts(
    stage2_root: impl AsRef<Path>,
) -> Result<Stage2WriteResult, Stage2WriteError> {
    let stage2_root = stage2_root.as_ref();
    fs::create_dir_all(stage2_root).map_err(|source| {
        write_error(
            "cannot-create-stage2-strict-root",
            format!("cannot create {}: {source}", stage2_root.display()),
        )
    })?;
    let stage2_root = stage2_root.canonicalize().map_err(|source| {
        write_error(
            "invalid-stage2-strict-root",
            format!("cannot resolve {}: {source}", stage2_root.display()),
        )
    })?;
    ensure_incomplete_marker(&stage2_root)?;

    let common_uri = STAGE2_COMMON_INPUT_FILE.to_owned();
    let common_bytes = read_contained(&stage2_root, &common_uri).map_err(write_from_finding)?;
    let common = parse_common_input(&common_bytes).map_err(|source| {
        write_error(
            source.code,
            format!("cannot parse {STAGE2_COMMON_INPUT_FILE}: {}", source.detail),
        )
    })?;
    let common_findings = validate_common_input(&common, &stage2_root);
    if !common_findings.is_empty() {
        return Err(write_error(
            "invalid-stage2-strict-common-input",
            render_findings(&common_findings),
        ));
    }
    if common.original_component.sha256 != STAGE2_STRICT_COMPONENT_SHA256 {
        return Err(write_error(
            "wrong-stage2-strict-component",
            "common input is not bound to the strict byte-exact Component",
        ));
    }

    let lineage = load_and_validate_strict_lineage(&stage2_root).map_err(write_from_finding)?;
    let descriptors =
        stage2_cell_descriptors(Stage2ClaimSet::StrictCrossRuntimeContinuity).collect::<Vec<_>>();
    let mut verified = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        verified.push(load_verified_cell(descriptor, &stage2_root).map_err(write_from_finding)?);
    }
    for cell in &verified {
        validate_verified_cell_cargo_lock_binding(cell, &lineage.cargo_lock_identity)
            .map_err(write_from_finding)?;
    }
    let common_sha256 = sha256_hex(&common_bytes);
    let cross_findings = validate_cross_cell_inputs(&common, &common_sha256, &verified);
    if !cross_findings.is_empty() {
        return Err(write_error(
            "stage2-strict-cell-input-mismatch",
            render_findings(&cross_findings),
        ));
    }

    fs::create_dir_all(stage2_root.join("normalized")).map_err(|source| {
        write_error(
            "cannot-create-stage2-strict-normalized-root",
            format!("cannot create normalized directory: {source}"),
        )
    })?;
    let mut cells = Vec::with_capacity(verified.len());
    for cell in &verified {
        let descriptor = cell.descriptor;
        let source = cell.source_runtime_chain.clone().ok_or_else(|| {
            write_error(
                "missing-stage2-strict-source-runtime-chain",
                format!("{} has no transcript-derived source chain", descriptor.id.as_str()),
            )
        })?;
        let destination = cell.destination_runtime_chain.clone().ok_or_else(|| {
            write_error(
                "missing-stage2-strict-destination-runtime-chain",
                format!("{} has no transcript-derived destination chain", descriptor.id.as_str()),
            )
        })?;
        let normalized_bytes = canonical_stage2_json_bytes(&cell.normalized)
            .map_err(|source| write_error(source.code, source.detail))?;
        let normalized_uri = descriptor.id.normalized_uri();
        publish_atomic(&stage2_root, &normalized_uri, &normalized_bytes)?;
        cells.push(Stage2StrictCellManifest {
            cell_id: descriptor.id,
            source,
            destination,
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
            // This marker is emitted only after load_verified_cell has audited
            // every selector and prepared/live transcript observation. The
            // independent verifier recomputes and compares the complete chains.
            no_fallback_observed: true,
        });
    }

    let comparisons =
        compare_normalized_cells_for_claim(&verified, Stage2ClaimSet::StrictCrossRuntimeContinuity)
            .map_err(write_from_finding)?;
    let claims = vec![Stage2Claim::StrictCrossRuntimeContinuity];
    let guards = Stage2StrictClaimGuards::required();
    let manifest = Stage2StrictMatrixManifest {
        schema_version: STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION.to_owned(),
        common_input: Stage2ArtifactReference { uri: common_uri, sha256: common_sha256 },
        scope: Stage2StrictScope::required(),
        registry_sha256: accepted_registry_sha256(&common.cases)
            .map_err(|source| write_error(source.code, source.detail))?,
        runtime_lineages: lineage.runtime_lineages,
        cells,
        execution_count: STAGE2_STRICT_EXECUTION_COUNT,
        claims: claims.clone(),
        claim_guards: guards.clone(),
    };
    let manifest_bytes = canonical_stage2_json_bytes(&manifest)
        .map_err(|source| write_error(source.code, source.detail))?;
    publish_atomic(&stage2_root, STAGE2_MATRIX_MANIFEST_FILE, &manifest_bytes)?;

    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let bundle_id = format!("stage2-strict-{}", &manifest_sha256[..24]);
    let evidence = Stage2StrictEvidenceBundle {
        schema_version: STAGE2_STRICT_EVIDENCE_SCHEMA_VERSION.to_owned(),
        bundle_id: bundle_id.clone(),
        matrix_manifest: Stage2ArtifactReference {
            uri: STAGE2_MATRIX_MANIFEST_FILE.to_owned(),
            sha256: manifest_sha256,
        },
        completed_execution_count: STAGE2_STRICT_EXECUTION_COUNT,
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
    let independent =
        validate_stage2_strict_evidence_artifacts_for_publication(&evidence, &stage2_root);
    if !independent.ok {
        return Err(write_error(
            "stage2-strict-independent-verification-failed",
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
