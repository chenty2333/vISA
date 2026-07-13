use std::{collections::BTreeSet, fs, path::Path};

use super::{
    artifacts::{finding, read_and_hash, read_contained, single_finding},
    common::{accepted_registry_sha256, validate_common_input, validate_cross_cell_inputs},
    model::*,
    strict_lineage::{
        STAGE2_STRICT_LINEAGE_ROOT, StrictCargoLockIdentity, load_and_validate_strict_lineage,
        required_wacogo_metadata, required_wasmtime_metadata,
        validate_stage1_manifest_cargo_lock_binding,
    },
    strict_model::*,
    verify::{
        VerifiedCell, compare_normalized_cells_for_claim, load_verified_cell,
        validate_instantiation_observations_shape,
    },
};
use crate::{
    STAGE1_CASE_DEFINITIONS, Stage1VersionedIdentity, canonical_stage2_json_bytes, sha256_hex,
    stage2_normalize::normalize_stage2_cell,
};

pub fn parse_stage2_strict_evidence_bundle_json(
    bytes: &[u8],
) -> Result<Stage2StrictEvidenceBundle, Stage2EvidenceLoadError> {
    match parse_stage2_evidence_document_json(bytes) {
        Ok(Stage2EvidenceDocument::StrictV3(bundle)) => Ok(bundle),
        Ok(Stage2EvidenceDocument::V2(_)) => Err(Stage2EvidenceLoadError {
            code: "mixed-stage2-evidence-version".to_owned(),
            detail: "strict validation rejects a v2 Stage 2 evidence document".to_owned(),
        }),
        Err(source) => {
            Err(Stage2EvidenceLoadError { code: source.code.to_owned(), detail: source.detail })
        }
    }
}

pub fn gate_stage2_strict_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    stage2_root: impl AsRef<Path>,
) -> Stage2EvidenceGateResult {
    let bundle = match parse_stage2_strict_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return Stage2EvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let validation = validate_stage2_strict_evidence_artifacts(&bundle, stage2_root);
    Stage2EvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn validate_stage2_strict_evidence_artifacts(
    evidence: &Stage2StrictEvidenceBundle,
    stage2_root: impl AsRef<Path>,
) -> Stage2ValidationReport {
    validate_stage2_strict_evidence_artifacts_impl(evidence, stage2_root.as_ref(), false)
}

pub(crate) fn validate_stage2_strict_evidence_artifacts_for_publication(
    evidence: &Stage2StrictEvidenceBundle,
    stage2_root: impl AsRef<Path>,
) -> Stage2ValidationReport {
    validate_stage2_strict_evidence_artifacts_impl(evidence, stage2_root.as_ref(), true)
}

fn validate_stage2_strict_evidence_artifacts_impl(
    evidence: &Stage2StrictEvidenceBundle,
    stage2_root: &Path,
    allow_publisher_marker: bool,
) -> Stage2ValidationReport {
    let mut findings = Vec::new();
    validate_strict_evidence_shape(evidence, &mut findings);
    let root = match stage2_root.canonicalize() {
        Ok(root) => root,
        Err(source) => {
            finding(
                &mut findings,
                "invalid-stage2-strict-artifact-root",
                format!("cannot resolve artifact root: {source}"),
            );
            return Stage2ValidationReport::new(findings);
        }
    };
    if !validate_publication_marker(&root, allow_publisher_marker, &mut findings) {
        return Stage2ValidationReport::new(findings);
    }

    let manifest_bytes = match read_and_hash(
        &root,
        &evidence.matrix_manifest,
        "Strict Stage 2 matrix manifest",
        &mut findings,
    ) {
        Some(bytes) => bytes,
        None => return Stage2ValidationReport::new(findings),
    };
    let manifest = match parse_stage2_matrix_manifest_document_json(&manifest_bytes) {
        Ok(Stage2MatrixManifestDocument::StrictV3(manifest)) => manifest,
        Ok(Stage2MatrixManifestDocument::V2(_)) => {
            finding(
                &mut findings,
                "mixed-stage2-matrix-version",
                "strict evidence references a v2 matrix manifest",
            );
            return Stage2ValidationReport::new(findings);
        }
        Err(source) => {
            finding(&mut findings, source.code, source.detail);
            return Stage2ValidationReport::new(findings);
        }
    };
    let expected_bundle_id = format!("stage2-strict-{}", &sha256_hex(&manifest_bytes)[..24]);
    if evidence.bundle_id != expected_bundle_id {
        finding(
            &mut findings,
            "inconsistent-stage2-strict-bundle-id",
            format!("expected {expected_bundle_id}, found {}", evidence.bundle_id),
        );
    }
    validate_strict_manifest_shape(&manifest, evidence, &mut findings);

    let common_bytes = match read_and_hash(
        &root,
        &manifest.common_input,
        "Strict Stage 2 common input",
        &mut findings,
    ) {
        Some(bytes) => bytes,
        None => return Stage2ValidationReport::new(findings),
    };
    let common: Stage2CommonInputManifest = match serde_json::from_slice(&common_bytes) {
        Ok(common) => common,
        Err(source) => {
            finding(&mut findings, "invalid-stage2-common-input-json", source.to_string());
            return Stage2ValidationReport::new(findings);
        }
    };
    findings.extend(validate_common_input(&common, &root));
    validate_strict_scope_binding(&manifest, &common, &root, &mut findings);
    match accepted_registry_sha256(&common.cases) {
        Ok(digest)
            if digest == STAGE2_ACCEPTED_REGISTRY_SHA256
                && manifest.registry_sha256 == STAGE2_ACCEPTED_REGISTRY_SHA256 => {}
        Ok(_) => finding(
            &mut findings,
            "stage2-strict-registry-digest-mismatch",
            "common and strict matrix registry digests must equal the accepted 31-case lock",
        ),
        Err(source) => finding(&mut findings, source.code, source.detail),
    }

    validate_strict_directory_set(&root, "cells", false, &mut findings);
    validate_strict_directory_set(&root, "normalized", true, &mut findings);
    validate_lineage_directory_set(&root, &mut findings);
    let validated_lineage = match load_and_validate_strict_lineage(&root) {
        Ok(lineage) => {
            if lineage.runtime_lineages != manifest.runtime_lineages {
                finding(
                    &mut findings,
                    "stage2-strict-runtime-lineage-mismatch",
                    "manifest runtime lineages differ from independently validated retained artifacts",
                );
            }
            Some(lineage)
        }
        Err(source) => {
            findings.push(source);
            None
        }
    };

    let descriptors =
        stage2_cell_descriptors(Stage2ClaimSet::StrictCrossRuntimeContinuity).collect::<Vec<_>>();
    let mut verified = Vec::with_capacity(descriptors.len());
    for (index, descriptor) in descriptors.iter().enumerate() {
        let Some(cell_manifest) = manifest.cells.get(index) else { continue };
        if cell_manifest.cell_id != descriptor.id {
            continue;
        }
        let cell = match load_verified_cell(descriptor, &root) {
            Ok(cell) => cell,
            Err(source) => {
                findings.push(source);
                continue;
            }
        };
        if let Some(lineage) = validated_lineage.as_ref()
            && let Err(source) =
                validate_verified_cell_cargo_lock_binding(&cell, &lineage.cargo_lock_identity)
        {
            findings.push(source);
        }
        validate_strict_cell_manifest(cell_manifest, &cell, &root, &mut findings);
        verified.push(cell);
    }

    if verified.len() == descriptors.len() {
        findings.extend(validate_cross_cell_inputs(
            &common,
            &manifest.common_input.sha256,
            &verified,
        ));
        match compare_normalized_cells_for_claim(
            &verified,
            Stage2ClaimSet::StrictCrossRuntimeContinuity,
        ) {
            Ok(comparisons) if evidence.case_comparisons == comparisons => {}
            Ok(_) => finding(
                &mut findings,
                "stage2-strict-comparison-record-mismatch",
                "strict comparison records differ from independently recomputed V1",
            ),
            Err(source) => findings.push(source),
        }
        validate_strict_inner_summaries(evidence, &verified, &mut findings);
    }

    Stage2ValidationReport::new(findings)
}

pub(super) fn validate_verified_cell_cargo_lock_binding(
    cell: &VerifiedCell,
    retained: &StrictCargoLockIdentity,
) -> Result<(), Stage2ValidationFinding> {
    for (label, reference) in [
        ("source manifest", &cell.bundle.provenance.artifacts.source_manifest),
        ("build source manifest", &cell.bundle.provenance.artifacts.build_source_manifest),
    ] {
        let bytes = cell.artifacts.bytes(&reference.uri).ok_or_else(|| {
            single_finding(
                "missing-stage2-strict-cell-source-manifest",
                format!(
                    "{} {label} {} was not retained in the verified Stage 1 artifact snapshot",
                    cell.descriptor.id.as_str(),
                    reference.uri
                ),
            )
        })?;
        validate_stage1_manifest_cargo_lock_binding(
            bytes,
            retained,
            &format!("{} {label}", cell.descriptor.id.as_str()),
        )?;
    }
    Ok(())
}

fn validate_strict_evidence_shape(
    evidence: &Stage2StrictEvidenceBundle,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if evidence.schema_version != STAGE2_STRICT_EVIDENCE_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage2-strict-evidence-schema",
            format!("found {}", evidence.schema_version),
        );
    }
    if evidence.bundle_id.is_empty() {
        finding(findings, "missing-stage2-strict-bundle-id", "bundle_id is empty");
    }
    if evidence.matrix_manifest.uri != STAGE2_MATRIX_MANIFEST_FILE {
        finding(
            findings,
            "noncanonical-stage2-strict-manifest-path",
            format!("manifest must be {STAGE2_MATRIX_MANIFEST_FILE}"),
        );
    }
    if evidence.completed_execution_count != STAGE2_STRICT_EXECUTION_COUNT {
        finding(
            findings,
            "wrong-stage2-strict-execution-count",
            format!(
                "expected {STAGE2_STRICT_EXECUTION_COUNT}, found {}",
                evidence.completed_execution_count
            ),
        );
    }
    validate_strict_claims_and_guards(&evidence.claims, &evidence.claim_guards, findings);
    require_exact_strict_cell_ids(
        evidence.inner_verifications.iter().map(|verification| verification.cell_id),
        "inner verification",
        findings,
    );
    if evidence.case_comparisons.len() != STAGE2_STRICT_CASE_COUNT
        || evidence.case_comparisons.iter().zip(STAGE1_CASE_DEFINITIONS).any(
            |(comparison, definition)| {
                comparison.case_id != definition.id || !comparison.equal_across_all_cells
            },
        )
    {
        finding(
            findings,
            "invalid-stage2-strict-case-comparison-set",
            "comparison records must cover the ordered 31-case registry and all be equal",
        );
    }
}

fn validate_strict_manifest_shape(
    manifest: &Stage2StrictMatrixManifest,
    evidence: &Stage2StrictEvidenceBundle,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if manifest.schema_version != STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-stage2-strict-matrix-schema",
            format!("found {}", manifest.schema_version),
        );
    }
    if manifest.common_input.uri != STAGE2_COMMON_INPUT_FILE {
        finding(
            findings,
            "noncanonical-stage2-strict-common-input-path",
            format!("common input must be {STAGE2_COMMON_INPUT_FILE}"),
        );
    }
    if manifest.scope != Stage2StrictScope::required() {
        finding(
            findings,
            "invalid-stage2-strict-scope",
            "strict scope must remain Linux x86-64, fixed Component/world, timer/KV, 31 cases",
        );
    }
    if manifest.registry_sha256 != STAGE2_ACCEPTED_REGISTRY_SHA256 {
        finding(
            findings,
            "invalid-stage2-strict-registry-digest",
            "strict matrix registry digest differs from the accepted catalog lock",
        );
    }
    if manifest.execution_count != STAGE2_STRICT_EXECUTION_COUNT
        || manifest.execution_count != evidence.completed_execution_count
    {
        finding(
            findings,
            "inconsistent-stage2-strict-execution-count",
            "strict matrix and evidence must both record exactly 124 executions",
        );
    }
    if manifest.claims != evidence.claims || manifest.claim_guards != evidence.claim_guards {
        finding(
            findings,
            "inconsistent-stage2-strict-claim-boundary",
            "strict matrix and evidence claim boundaries differ",
        );
    }
    validate_strict_claims_and_guards(&manifest.claims, &manifest.claim_guards, findings);
    require_exact_strict_cell_ids(
        manifest.cells.iter().map(|cell| cell.cell_id),
        "matrix cell",
        findings,
    );
    if manifest.runtime_lineages.len() != 2 {
        finding(
            findings,
            "invalid-stage2-strict-runtime-lineage-set",
            "strict matrix must name exactly Wasmtime and Wacogo lineage records",
        );
    }
    let mut bundle_uris = BTreeSet::new();
    let mut normalized_uris = BTreeSet::new();
    for cell in &manifest.cells {
        validate_strict_instantiation_observations_shape(cell, findings);
        if !bundle_uris.insert(&cell.stage1_bundle.uri)
            || !normalized_uris.insert(&cell.normalized_observable_trace.uri)
            || cell.stage1_bundle.uri != cell.cell_id.stage1_bundle_uri()
            || cell.normalized_observable_trace.uri != cell.cell_id.normalized_uri()
        {
            finding(
                findings,
                "duplicate-or-noncanonical-stage2-strict-cell-artifact",
                format!("{} has duplicate or noncanonical artifacts", cell.cell_id.as_str()),
            );
        }
    }
}

fn validate_strict_cell_manifest(
    manifest: &Stage2StrictCellManifest,
    cell: &VerifiedCell,
    root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let descriptor = cell.descriptor;
    let source = cell.source_runtime_chain.as_ref();
    let destination = cell.destination_runtime_chain.as_ref();
    if manifest.cell_id != descriptor.id
        || source != Some(&manifest.source)
        || destination != Some(&manifest.destination)
        || manifest.instantiation_observations != cell.instantiation_observations
        || manifest.case_count != STAGE2_STRICT_CASE_COUNT
        || !manifest.no_fallback_observed
    {
        finding(
            findings,
            "stage2-strict-cell-observation-mismatch",
            format!(
                "{} manifest differs from transcript-derived identity/lifecycle facts",
                descriptor.id.as_str()
            ),
        );
    }
    validate_runtime_chain(
        &manifest.source,
        descriptor.source_runtime,
        descriptor.id,
        "source",
        findings,
    );
    validate_runtime_chain(
        &manifest.destination,
        descriptor.destination_runtime,
        descriptor.id,
        "destination",
        findings,
    );

    let Some(bundle_bytes) =
        read_and_hash(root, &manifest.stage1_bundle, "strict Stage 1 cell bundle", findings)
    else {
        return;
    };
    if bundle_bytes != cell.bundle_bytes {
        finding(
            findings,
            "stage2-strict-cell-bundle-reference-mismatch",
            format!("{} manifest does not reference the verified bundle", descriptor.id.as_str()),
        );
    }
    let normalized = match normalize_stage2_cell(&cell.bundle, &cell.artifacts) {
        Ok(normalized) => normalized,
        Err(source) => {
            finding(findings, source.code, source.detail);
            return;
        }
    };
    let expected_bytes = match canonical_stage2_json_bytes(&normalized) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(findings, source.code, source.detail);
            return;
        }
    };
    let Some(observed_bytes) = read_and_hash(
        root,
        &manifest.normalized_observable_trace,
        "strict normalized observable trace",
        findings,
    ) else {
        return;
    };
    if observed_bytes != expected_bytes {
        finding(
            findings,
            "stage2-strict-normalized-cache-mismatch",
            format!("{} cache differs from independently recomputed V1", descriptor.id.as_str()),
        );
    }
}

fn validate_runtime_chain(
    chain: &Stage2StrictRuntimeIdentityChain,
    runtime: Stage2Runtime,
    cell_id: Stage2CellId,
    role: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let expected = match runtime {
        Stage2Runtime::Wasmtime => required_wasmtime_metadata(),
        Stage2Runtime::Wacogo => required_wacogo_metadata(),
        Stage2Runtime::JcoNode => {
            finding(
                findings,
                "invalid-stage2-strict-runtime",
                format!("{} unexpectedly includes JcoNode", cell_id.as_str()),
            );
            return;
        }
    };
    if chain.requested != runtime
        || chain.prepared != expected
        || chain.live != expected
        || chain.prepared_observation_count == 0
        || chain.live_observation_count == 0
    {
        finding(
            findings,
            "invalid-stage2-strict-runtime-identity-chain",
            format!(
                "{} {role} is not the exact requested/prepared/live {:?} identity",
                cell_id.as_str(),
                runtime
            ),
        );
    }
}

fn validate_strict_scope_binding(
    manifest: &Stage2StrictMatrixManifest,
    common: &Stage2CommonInputManifest,
    root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let component = read_contained(root, &common.original_component.uri).ok();
    if manifest.scope != Stage2StrictScope::required()
        || common.original_component.sha256 != STAGE2_STRICT_COMPONENT_SHA256
        || component.as_ref().map(Vec::len) != Some(STAGE2_STRICT_COMPONENT_BYTE_LENGTH)
        || component.as_ref().map(|bytes| sha256_hex(bytes))
            != Some(STAGE2_STRICT_COMPONENT_SHA256.to_owned())
        || common.wit_world.world_name != manifest.scope.wit_world.world_name
        || common.wit_world.artifact.sha256 != manifest.scope.wit_world.sha256
        || common.cases.len() != manifest.scope.case_count
    {
        finding(
            findings,
            "stage2-strict-scope-input-mismatch",
            "strict scope is not bound to the byte-exact Component, WIT world, and 31-case input",
        );
    }
}

fn validate_strict_instantiation_observations_shape(
    cell: &Stage2StrictCellManifest,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let legacy_shape = Stage2CellManifest {
        cell_id: cell.cell_id,
        requested_source: cell.source.requested,
        requested_destination: cell.destination.requested,
        observed_source: Stage1VersionedIdentity { name: String::new(), version: String::new() },
        observed_destination: Stage1VersionedIdentity {
            name: String::new(),
            version: String::new(),
        },
        source_translation_provenance: None,
        destination_translation_provenance: None,
        instantiation_observations: cell.instantiation_observations.clone(),
        stage1_bundle: cell.stage1_bundle.clone(),
        normalized_observable_trace: cell.normalized_observable_trace.clone(),
        case_count: cell.case_count,
        no_fallback_observed: cell.no_fallback_observed,
    };
    validate_instantiation_observations_shape(&legacy_shape, findings);
}

fn validate_strict_inner_summaries(
    evidence: &Stage2StrictEvidenceBundle,
    verified: &[VerifiedCell],
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    for (cell, summary) in verified.iter().zip(&evidence.inner_verifications) {
        if summary.cell_id != cell.descriptor.id
            || summary.stage1_bundle_id != cell.bundle.bundle_id
            || summary.stage1_bundle_sha256 != sha256_hex(&cell.bundle_bytes)
            || summary.case_count != STAGE2_STRICT_CASE_COUNT
            || !summary.independently_verified
        {
            finding(
                findings,
                "stage2-strict-inner-verification-summary-mismatch",
                format!(
                    "{} summary differs from the independently verified raw bundle",
                    cell.descriptor.id.as_str()
                ),
            );
        }
    }
}

fn validate_strict_claims_and_guards(
    claims: &[Stage2Claim],
    guards: &Stage2StrictClaimGuards,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if claims != [Stage2Claim::StrictCrossRuntimeContinuity] {
        finding(
            findings,
            "invalid-stage2-strict-claim",
            format!("only {STAGE2_STRICT_CLAIM_ID} is accepted by strict v3"),
        );
    }
    if guards != &Stage2StrictClaimGuards::required() {
        finding(
            findings,
            "invalid-stage2-strict-claim-guards",
            "strict independence must be proven while Stage 3+, cross-ISA, and readiness remain unclaimed",
        );
    }
}

fn require_exact_strict_cell_ids(
    ids: impl Iterator<Item = Stage2CellId>,
    label: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    if !stage2_cell_ids_match_claim(ids, Stage2ClaimSet::StrictCrossRuntimeContinuity) {
        finding(
            findings,
            "invalid-stage2-strict-cell-set",
            format!("{label} IDs must be the exact ordered Wasmtime/Wacogo four-cell set"),
        );
    }
}

fn validate_strict_directory_set(
    root: &Path,
    directory: &str,
    json_suffix: bool,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let expected = stage2_cell_descriptors(Stage2ClaimSet::StrictCrossRuntimeContinuity)
        .map(|descriptor| {
            if json_suffix {
                format!("{}.json", descriptor.id.as_str())
            } else {
                descriptor.id.as_str().to_owned()
            }
        })
        .collect::<BTreeSet<_>>();
    let path = root.join(directory);
    let observed = read_directory_names(&path, findings);
    if observed.as_ref() != Some(&expected) {
        finding(
            findings,
            "invalid-stage2-strict-directory-set",
            format!("{directory}/ must contain exactly the strict four-cell artifact set"),
        );
    }
}

fn validate_lineage_directory_set(root: &Path, findings: &mut Vec<Stage2ValidationFinding>) {
    let expected = [
        "Cargo.lock",
        "visa-wacogo-runtime",
        "wacogo-build-receipt.json",
        "wacogo-source-lock.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let path = root.join(STAGE2_STRICT_LINEAGE_ROOT);
    if read_directory_names(&path, findings).as_ref() != Some(&expected) {
        finding(
            findings,
            "invalid-stage2-strict-lineage-directory-set",
            "lineage/ must contain exactly Cargo.lock, source lock, build receipt, and sidecar",
        );
    }
}

fn read_directory_names(
    path: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<BTreeSet<String>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(source) => {
            finding(
                findings,
                "unreadable-stage2-strict-directory",
                format!("cannot read {}: {source}", path.display()),
            );
            return None;
        }
    };
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                finding(
                    findings,
                    "unreadable-stage2-strict-directory-entry",
                    format!("cannot enumerate {}: {source}", path.display()),
                );
                return None;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) => {
                finding(
                    findings,
                    "unreadable-stage2-strict-directory-entry",
                    format!("cannot inspect {}: {source}", entry.path().display()),
                );
                return None;
            }
        };
        if file_type.is_symlink()
            || (path.file_name().and_then(|name| name.to_str()) == Some("cells")
                && !file_type.is_dir())
            || (path.file_name().and_then(|name| name.to_str()) != Some("cells")
                && !file_type.is_file())
        {
            finding(
                findings,
                "invalid-stage2-strict-directory-entry-type",
                format!("{} has the wrong entry type", entry.path().display()),
            );
        }
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                finding(
                    findings,
                    "non-utf8-stage2-strict-directory-entry",
                    format!("{} contains a non-UTF-8 name", path.display()),
                );
                return None;
            }
        };
        names.insert(name);
    }
    Some(names)
}

fn validate_publication_marker(
    root: &Path,
    allow_publisher_marker: bool,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> bool {
    let marker = root.join(STAGE2_INCOMPLETE_MARKER_FILE);
    let marker_state = match fs::symlink_metadata(&marker) {
        Ok(metadata) => Some(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            finding(
                findings,
                "unreadable-stage2-publication-marker",
                format!("cannot inspect {}: {source}", marker.display()),
            );
            return false;
        }
    };
    let valid =
        if allow_publisher_marker { marker_state == Some(true) } else { marker_state.is_none() };
    if !valid {
        finding(
            findings,
            "incomplete-stage2-strict-publication",
            if allow_publisher_marker {
                "prepublication validation requires the regular incomplete marker"
            } else {
                "strict publication is still marked incomplete"
            },
        );
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parser_rejects_a_well_formed_v2_document() {
        let evidence = Stage2EvidenceBundle {
            schema_version: STAGE2_EVIDENCE_SCHEMA_VERSION.to_owned(),
            bundle_id: "v2".to_owned(),
            matrix_manifest: Stage2ArtifactReference {
                uri: STAGE2_MATRIX_MANIFEST_FILE.to_owned(),
                sha256: "a".repeat(64),
            },
            completed_execution_count: STAGE2_EXECUTION_COUNT,
            inner_verifications: Vec::new(),
            case_comparisons: Vec::new(),
            claims: vec![Stage2Claim::CrossExecutionPathPortability],
            claim_guards: Stage2ClaimGuards::required(),
        };
        let error = parse_stage2_strict_evidence_bundle_json(
            &serde_json::to_vec(&evidence).expect("serialize v2 evidence"),
        )
        .expect_err("v2 must not enter the strict verifier");
        assert_eq!(error.code, "mixed-stage2-evidence-version");
    }

    #[test]
    fn strict_cell_catalog_is_exact_and_excludes_jco() {
        let descriptors = stage2_cell_descriptors(Stage2ClaimSet::StrictCrossRuntimeContinuity)
            .collect::<Vec<_>>();
        assert_eq!(descriptors.len(), STAGE2_STRICT_CELL_COUNT);
        assert!(descriptors.iter().all(|descriptor| {
            descriptor.source_runtime != Stage2Runtime::JcoNode
                && descriptor.destination_runtime != Stage2Runtime::JcoNode
        }));
        assert_eq!(
            descriptors.iter().map(|descriptor| descriptor.id).collect::<Vec<_>>(),
            [
                Stage2CellId::WasmtimeToWasmtime,
                Stage2CellId::WacogoToWacogo,
                Stage2CellId::WasmtimeToWacogo,
                Stage2CellId::WacogoToWasmtime,
            ]
        );
    }
}
