use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use serde_json::Value;

use super::model::*;
use crate::{
    EvidenceMatrix, EvidenceMatrixRun, MatrixHandoffTopology, MatrixRuntime,
    STAGE2_STRICT_WACOGO_SIDECAR_SHA256, STAGE2_STRICT_WACOGO_SIDECAR_SIZE,
    STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256, Stage3ArtifactReference, Stage3EvidenceBundle,
    Stage3EvidenceGateResult, Stage3Profile, Stage3RuntimeIdentity, evidence_matrix_sha256,
    gate_stage3_evidence_bundle_json_with_artifacts, parse_evidence_matrix_json,
    parse_evidence_matrix_run_json, sha256_hex, validate_evidence_matrix,
    validate_evidence_matrix_run,
};

const REGULAR_FILE_COMPONENT_SHA256: &str =
    "d5f50655bd62916dc2b821bc3878547ed6800b16be2ab19bec5e1f39a6628109";
const REGULAR_FILE_COMPONENT_SIZE: u64 = 215_376;
const ENVIRONMENT_SCHEMA: &str = "visa-stage3a-cross-runtime-environment-v1";

pub fn gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    artifact_root: &Path,
) -> Stage3aCrossRuntimeEvidenceGateResult {
    let bundle: Stage3aCrossRuntimeEvidenceBundle = match serde_json::from_slice(bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            return load_failure(
                "invalid-stage3a-cross-runtime-json",
                format!("cannot decode cross-runtime Stage 3A bundle: {error}"),
            );
        }
    };
    let published = artifact_root.join(STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE);
    match fs::read(&published) {
        Ok(published_bytes) if published_bytes == bytes => {}
        Ok(_) => {
            return load_failure(
                "stage3a-cross-runtime-bundle-bytes-mismatch",
                "supplied bundle bytes differ from the published root bundle",
            );
        }
        Err(error) => {
            return load_failure(
                "stage3a-cross-runtime-bundle-unreadable",
                format!("cannot read {}: {error}", published.display()),
            );
        }
    }
    let validation = validate_stage3a_cross_runtime_evidence(&bundle, artifact_root);
    Stage3aCrossRuntimeEvidenceGateResult {
        ok: validation.ok,
        load_error: None,
        validation: Some(validation),
    }
}

pub fn validate_stage3a_cross_runtime_evidence(
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
    artifact_root: &Path,
) -> Stage3aCrossRuntimeValidationReport {
    let mut findings = Vec::new();
    if bundle.schema_version != STAGE3A_CROSS_RUNTIME_EVIDENCE_SCHEMA_VERSION {
        finding(
            &mut findings,
            "unknown-stage3a-cross-runtime-schema",
            format!("unexpected schema {}", bundle.schema_version),
        );
    }
    if bundle.claim_id != STAGE3A_CROSS_RUNTIME_CLAIM_ID
        || bundle.required_runs_per_cell != STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS
        || !bundle.relocated_verification_required
        || !lower_hex(&bundle.git_sha, 40)
        || bundle.finished_at_unix_ms < bundle.started_at_unix_ms
        || !bundle.bundle_id.starts_with("stage3a-cross-runtime-")
    {
        finding(
            &mut findings,
            "invalid-stage3a-cross-runtime-identity",
            "claim, stability policy, Git revision, timestamps, or bundle ID is invalid",
        );
    }

    let mut expected_files = BTreeSet::from([STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE.to_owned()]);
    let lineage_bytes = validate_lineage(bundle, artifact_root, &mut expected_files, &mut findings);
    let matrix =
        lineage_bytes.as_ref().and_then(|bytes| parse_evidence_matrix_json(&bytes.matrix).ok());
    if let Some(matrix) = &matrix {
        let report = validate_evidence_matrix(matrix);
        if !report.ok {
            finding(
                &mut findings,
                "invalid-canonical-evidence-matrix",
                format!("canonical evidence matrix failed validation: {:?}", report.findings),
            );
        }
        match evidence_matrix_sha256(matrix) {
            Ok(digest) if digest == bundle.matrix_sha256 => {}
            Ok(digest) => finding(
                &mut findings,
                "stage3a-cross-runtime-matrix-digest-mismatch",
                format!("expected {}, found {digest}", bundle.matrix_sha256),
            ),
            Err(error) => finding(&mut findings, "stage3a-cross-runtime-matrix-unencodable", error),
        }
    } else {
        finding(
            &mut findings,
            "unreadable-canonical-evidence-matrix",
            "the retained evidence matrix could not be decoded",
        );
    }

    let mut observed_keys = BTreeSet::new();
    let mut common_normalized: Option<String> = None;
    let mut cell_bundles = BTreeMap::new();
    for cell in &bundle.cells {
        let key = (cell.cell_id.clone(), cell.run_ordinal);
        if !observed_keys.insert(key.clone()) {
            finding(
                &mut findings,
                "duplicate-stage3a-cross-runtime-cell-run",
                format!("duplicate {} run {}", cell.cell_id, cell.run_ordinal),
            );
        }
        let Some(expected) = expected_cell(&cell.cell_id) else {
            finding(
                &mut findings,
                "unknown-stage3a-cross-runtime-cell",
                format!("unknown cell {}", cell.cell_id),
            );
            continue;
        };
        validate_cell_metadata(cell, &expected, &mut findings);
        let original = validate_child_bundle(
            artifact_root,
            &cell.original_bundle,
            &mut expected_files,
            &mut findings,
            "original",
        );
        let relocated = validate_child_bundle(
            artifact_root,
            &cell.relocated_bundle,
            &mut expected_files,
            &mut findings,
            "relocated",
        );
        if let (
            Some((original_bytes, original_bundle)),
            Some((relocated_bytes, relocated_bundle)),
        ) = (original, relocated)
        {
            if original_bytes != relocated_bytes || original_bundle != relocated_bundle {
                finding(
                    &mut findings,
                    "stage3a-relocation-content-mismatch",
                    format!("{} run {} changed during relocation", cell.cell_id, cell.run_ordinal),
                );
            }
            validate_child_runtime(cell, &relocated_bundle, &mut findings);
            match normalized_stage3a_semantics_sha256(&relocated_bundle) {
                Ok(digest) => {
                    if digest != cell.normalized_semantics_sha256 {
                        finding(
                            &mut findings,
                            "stage3a-cell-normalization-mismatch",
                            format!(
                                "{} run {} has the wrong normalized digest",
                                cell.cell_id, cell.run_ordinal
                            ),
                        );
                    }
                    if let Some(common) = &common_normalized {
                        if common != &digest {
                            finding(
                                &mut findings,
                                "stage3a-cross-runtime-semantic-divergence",
                                format!(
                                    "{} run {} differs from the matrix baseline",
                                    cell.cell_id, cell.run_ordinal
                                ),
                            );
                        }
                    } else {
                        common_normalized = Some(digest.clone());
                    }
                    cell_bundles.insert(key, relocated_bundle);
                }
                Err(error) => finding(&mut findings, "stage3a-cell-normalization-failed", error),
            }
        }
        validate_validation_report(
            artifact_root,
            &cell.validation_report,
            &mut expected_files,
            &mut findings,
        );
        validate_environment(artifact_root, cell, &mut expected_files, &mut findings);
    }
    let expected_keys = expected_cell_keys();
    if observed_keys != expected_keys {
        finding(
            &mut findings,
            "incomplete-stage3a-cross-runtime-matrix",
            format!("expected {expected_keys:?}, found {observed_keys:?}"),
        );
    }
    if common_normalized.as_deref() != Some(bundle.normalized_semantics_sha256.as_str()) {
        finding(
            &mut findings,
            "stage3a-cross-runtime-aggregate-normalization-mismatch",
            "outer normalized digest does not match every cell run",
        );
    }

    validate_matrix_run(bundle, artifact_root, matrix.as_ref(), &mut expected_files, &mut findings);
    validate_exact_outer_file_set(artifact_root, &expected_files, &mut findings);

    Stage3aCrossRuntimeValidationReport { ok: findings.is_empty(), findings }
}

struct LineageBytes {
    matrix: Vec<u8>,
}

fn validate_lineage(
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
    root: &Path,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) -> Option<LineageBytes> {
    let lineage = &bundle.lineage;
    let expected = [
        (&lineage.cargo_lock, "lineage/Cargo.lock"),
        (&lineage.evidence_matrix, "lineage/evidence-matrix.json"),
        (&lineage.regular_file_component, "lineage/stage3-file-component.component.wasm"),
        (&lineage.regular_file_wit, "lineage/regular-file-continuity.wit"),
        (&lineage.wacogo_source_lock, "lineage/wacogo-source-lock.json"),
        (&lineage.wacogo_build_receipt, "lineage/wacogo-build-receipt.json"),
        (&lineage.wacogo_sidecar, "lineage/visa-wacogo-runtime"),
    ];
    let mut bytes = BTreeMap::new();
    for (reference, uri) in expected {
        if reference.uri != uri {
            finding(
                findings,
                "stage3a-cross-runtime-lineage-uri-mismatch",
                format!("expected {uri}, found {}", reference.uri),
            );
        }
        if let Some(value) = read_reference(root, reference, expected_files, findings) {
            bytes.insert(uri, value);
        }
    }
    if lineage.regular_file_component.sha256 != REGULAR_FILE_COMPONENT_SHA256
        || lineage.regular_file_component.size != REGULAR_FILE_COMPONENT_SIZE
        || lineage.wacogo_source_lock.sha256 != STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256
        || lineage.wacogo_sidecar.sha256 != STAGE2_STRICT_WACOGO_SIDECAR_SHA256
        || lineage.wacogo_sidecar.size != STAGE2_STRICT_WACOGO_SIDECAR_SIZE as u64
    {
        finding(
            findings,
            "stage3a-cross-runtime-lineage-identity-mismatch",
            "component, Wacogo source lock, or sidecar identity is not the accepted build",
        );
    }
    if let Some(receipt) = bytes.get("lineage/wacogo-build-receipt.json") {
        validate_wacogo_receipt(receipt, findings);
    }
    Some(LineageBytes { matrix: bytes.remove("lineage/evidence-matrix.json")? })
}

fn validate_wacogo_receipt(bytes: &[u8], findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>) {
    let Ok(receipt) = serde_json::from_slice::<Value>(bytes) else {
        finding(findings, "invalid-wacogo-build-receipt", "build receipt is not JSON");
        return;
    };
    let gates_ok = receipt
        .get("gates")
        .and_then(Value::as_object)
        .is_some_and(|gates| !gates.is_empty() && gates.values().all(|value| value == "passed"));
    let regular_profile =
        receipt.get("accepted_components").and_then(Value::as_array).is_some_and(|components| {
            components.iter().any(|component| {
                component.get("profile") == Some(&Value::String("regular-file-v1".to_owned()))
                    && component.get("sha256")
                        == Some(&Value::String(REGULAR_FILE_COMPONENT_SHA256.to_owned()))
                    && component.get("size") == Some(&Value::from(REGULAR_FILE_COMPONENT_SIZE))
            })
        });
    if receipt.get("schema") != Some(&Value::String("visa.wacogo-sidecar-build-receipt.v1".into()))
        || receipt.get("source_lock_sha256")
            != Some(&Value::String(STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256.into()))
        || receipt.pointer("/binary/sha256")
            != Some(&Value::String(STAGE2_STRICT_WACOGO_SIDECAR_SHA256.into()))
        || receipt.pointer("/binary/size")
            != Some(&Value::from(STAGE2_STRICT_WACOGO_SIDECAR_SIZE as u64))
        || receipt.get("carrier_magic") != Some(&Value::String("VISAWCG2".into()))
        || receipt.get("carrier_version")
            != Some(&Value::String("owned-component-profile-stdin-frame-v2".into()))
        || !gates_ok
        || !regular_profile
    {
        finding(
            findings,
            "invalid-wacogo-build-receipt",
            "build receipt does not close the exact two-profile reproducible sidecar build",
        );
    }
}

#[derive(Clone, Copy)]
struct ExpectedCell {
    source: MatrixRuntime,
    destination: MatrixRuntime,
    topology: MatrixHandoffTopology,
    boundary: &'static str,
}

fn expected_cell(cell_id: &str) -> Option<ExpectedCell> {
    match cell_id {
        "s3a.cross.wacogo-to-wacogo.regular-file" => Some(ExpectedCell {
            source: MatrixRuntime::SourceLockedWacogo,
            destination: MatrixRuntime::SourceLockedWacogo,
            topology: MatrixHandoffTopology::RunnerWithDualSidecars,
            boundary: "runner-with-distinct-source-and-destination-wacogo-sidecars-and-provider-instances",
        }),
        "s3a.cross.wacogo-to-wasmtime.regular-file" => Some(ExpectedCell {
            source: MatrixRuntime::SourceLockedWacogo,
            destination: MatrixRuntime::Wasmtime,
            topology: MatrixHandoffTopology::RunnerWithSourceSidecar,
            boundary: "runner-with-source-wacogo-sidecar-and-destination-wasmtime-store",
        }),
        "s3a.cross.wasmtime-to-wacogo.regular-file" => Some(ExpectedCell {
            source: MatrixRuntime::Wasmtime,
            destination: MatrixRuntime::SourceLockedWacogo,
            topology: MatrixHandoffTopology::RunnerWithDestinationSidecar,
            boundary: "runner-with-source-wasmtime-store-and-destination-wacogo-sidecar",
        }),
        "s3a.cross.wasmtime-to-wasmtime.regular-file" => Some(ExpectedCell {
            source: MatrixRuntime::Wasmtime,
            destination: MatrixRuntime::Wasmtime,
            topology: MatrixHandoffTopology::InProcessDistinctStores,
            boundary: "same-process-distinct-wasmtime-store-and-provider-instance",
        }),
        _ => None,
    }
}

fn expected_cell_keys() -> BTreeSet<(String, u32)> {
    [
        "s3a.cross.wacogo-to-wacogo.regular-file",
        "s3a.cross.wacogo-to-wasmtime.regular-file",
        "s3a.cross.wasmtime-to-wacogo.regular-file",
        "s3a.cross.wasmtime-to-wasmtime.regular-file",
    ]
    .into_iter()
    .flat_map(|cell| {
        (1..=STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS).map(move |run| (cell.to_owned(), run))
    })
    .collect()
}

fn validate_cell_metadata(
    cell: &Stage3aCrossRuntimeCellRun,
    expected: &ExpectedCell,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    if !(1..=STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS).contains(&cell.run_ordinal)
        || cell.source_runtime != expected.source
        || cell.destination_runtime != expected.destination
        || cell.handoff_topology != expected.topology
        || cell.execution_boundary != expected.boundary
        || !valid_identity(expected.source, &cell.source_identity)
        || !valid_identity(expected.destination, &cell.destination_identity)
    {
        finding(
            findings,
            "invalid-stage3a-cross-runtime-cell-metadata",
            format!("{} run {} metadata is invalid", cell.cell_id, cell.run_ordinal),
        );
    }
}

fn valid_identity(runtime: MatrixRuntime, identity: &Stage3RuntimeIdentity) -> bool {
    !identity.implementation_version.is_empty()
        && !identity.engine_version.is_empty()
        && match runtime {
            MatrixRuntime::Wasmtime => {
                identity.implementation == "visa_wasmtime_stage3a" && identity.engine == "wasmtime"
            }
            MatrixRuntime::SourceLockedWacogo => {
                identity.implementation == "visa_wacogo"
                    && identity.engine == "partite-ai/wacogo+wazero"
            }
            MatrixRuntime::JcoNode | MatrixRuntime::NotApplicable => false,
        }
}

fn validate_child_bundle(
    root: &Path,
    reference: &Stage3ArtifactReference,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
    label: &str,
) -> Option<(Vec<u8>, Stage3EvidenceBundle)> {
    let bytes = read_reference(root, reference, expected_files, findings)?;
    let child_root = Path::new(&reference.uri).parent()?;
    let gate = gate_stage3_evidence_bundle_json_with_artifacts(
        Stage3Profile::RegularFile,
        &bytes,
        root.join(child_root),
    );
    if !gate.ok {
        finding(
            findings,
            "invalid-stage3a-cross-runtime-child-bundle",
            format!("{label} child bundle failed Stage 3 verification: {gate:?}"),
        );
        return None;
    }
    collect_child_files(root, child_root, expected_files, findings);
    let bundle = serde_json::from_slice(&bytes).ok()?;
    Some((bytes, bundle))
}

fn validate_child_runtime(
    cell: &Stage3aCrossRuntimeCellRun,
    bundle: &Stage3EvidenceBundle,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    if bundle.runtime.source != cell.source_identity
        || bundle.runtime.destination != cell.destination_identity
        || bundle.runtime.execution_boundary != cell.execution_boundary
        || bundle.runtime.substrate != "substrate_host::SqliteProvider"
    {
        finding(
            findings,
            "stage3a-child-runtime-lineage-mismatch",
            format!(
                "{} run {} child runtime scope differs from its outer cell",
                cell.cell_id, cell.run_ordinal
            ),
        );
    }
}

fn validate_validation_report(
    root: &Path,
    reference: &Stage3ArtifactReference,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    let Some(bytes) = read_reference(root, reference, expected_files, findings) else { return };
    match serde_json::from_slice::<Stage3EvidenceGateResult>(&bytes) {
        Ok(report) if report.ok => {}
        Ok(report) => finding(
            findings,
            "failed-relocated-stage3a-validation",
            format!("relocated validation failed: {report:?}"),
        ),
        Err(error) => {
            finding(findings, "invalid-relocated-stage3a-validation-report", error.to_string())
        }
    }
}

fn validate_environment(
    root: &Path,
    cell: &Stage3aCrossRuntimeCellRun,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    let Some(bytes) = read_reference(root, &cell.environment, expected_files, findings) else {
        return;
    };
    match serde_json::from_slice::<Stage3aCrossRuntimeEnvironment>(&bytes) {
        Ok(environment)
            if environment.schema_version == ENVIRONMENT_SCHEMA
                && environment.run_ordinal == cell.run_ordinal
                && environment.cell_id == cell.cell_id
                && environment.source_runtime == cell.source_runtime
                && environment.destination_runtime == cell.destination_runtime
                && environment.host_os == "linux"
                && environment.host_isa == "x86_64"
                && environment.substrate == "substrate_host::SqliteProvider"
                && environment.component_sha256 == REGULAR_FILE_COMPONENT_SHA256
                && environment.source_lock_sha256 == STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256
                && environment.sidecar_sha256 == STAGE2_STRICT_WACOGO_SIDECAR_SHA256
                && environment.fallback_runtime.is_none() => {}
        Ok(_) => finding(
            findings,
            "invalid-stage3a-cross-runtime-environment",
            format!("{} run {} environment is not exact", cell.cell_id, cell.run_ordinal),
        ),
        Err(error) => {
            finding(findings, "invalid-stage3a-cross-runtime-environment-json", error.to_string())
        }
    }
}

fn validate_matrix_run(
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
    root: &Path,
    matrix: Option<&EvidenceMatrix>,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    if bundle.matrix_run.uri != STAGE3A_CROSS_RUNTIME_MATRIX_RUN_FILE {
        finding(
            findings,
            "invalid-stage3a-cross-runtime-matrix-run-uri",
            "matrix run must use its canonical top-level path",
        );
    }
    let Some(bytes) = read_reference(root, &bundle.matrix_run, expected_files, findings) else {
        return;
    };
    let Ok(run) = parse_evidence_matrix_run_json(&bytes) else {
        finding(
            findings,
            "invalid-stage3a-cross-runtime-matrix-run",
            "matrix run is not valid JSON",
        );
        return;
    };
    if run.git_sha != bundle.git_sha
        || run.git_dirty != bundle.git_dirty
        || run.matrix_sha256 != bundle.matrix_sha256
        || run.claim_ids != vec![STAGE3A_CROSS_RUNTIME_CLAIM_ID.to_owned()]
    {
        finding(
            findings,
            "stage3a-cross-runtime-matrix-run-binding-mismatch",
            "matrix run does not bind the outer bundle identity",
        );
    }
    validate_matrix_receipts(bundle, &run, findings);
    if let Some(matrix) = matrix {
        let report = validate_evidence_matrix_run(matrix, &run);
        if !report.ok {
            finding(
                findings,
                "stage3a-cross-runtime-matrix-closure-failed",
                format!("matrix closure failed: {:?}", report.findings),
            );
        }
    }
}

fn validate_matrix_receipts(
    bundle: &Stage3aCrossRuntimeEvidenceBundle,
    run: &EvidenceMatrixRun,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    let cells = bundle
        .cells
        .iter()
        .map(|cell| ((cell.cell_id.as_str(), cell.run_ordinal), cell))
        .collect::<BTreeMap<_, _>>();
    for receipt in &run.receipts {
        let source = if receipt.cell_id == "s3a.wasmtime-to-wasmtime.regular-file" {
            cells.get(&("s3a.cross.wasmtime-to-wasmtime.regular-file", 1)).copied()
        } else {
            cells.get(&(receipt.cell_id.as_str(), receipt.run_ordinal)).copied()
        };
        let Some(cell) = source else {
            finding(
                findings,
                "orphaned-stage3a-cross-runtime-matrix-receipt",
                format!("{} run {} has no cell", receipt.cell_id, receipt.run_ordinal),
            );
            continue;
        };
        if receipt.evidence_bundle.uri != cell.relocated_bundle.uri
            || receipt.evidence_bundle.sha256 != cell.relocated_bundle.sha256
            || receipt.validation_report.uri != cell.validation_report.uri
            || receipt.environment.uri != cell.environment.uri
            || !receipt.passed
            || !receipt.relocated_verification
        {
            finding(
                findings,
                "stage3a-cross-runtime-matrix-receipt-mismatch",
                format!(
                    "{} run {} does not bind its cell artifacts",
                    receipt.cell_id, receipt.run_ordinal
                ),
            );
        }
    }
    if run.receipts.len() != bundle.cells.len() + 1 {
        finding(
            findings,
            "incomplete-stage3a-cross-runtime-matrix-receipts",
            format!("expected {} receipts, found {}", bundle.cells.len() + 1, run.receipts.len()),
        );
    }
}

fn read_reference(
    root: &Path,
    reference: &Stage3ArtifactReference,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) -> Option<Vec<u8>> {
    if !safe_uri(&reference.uri) || !lower_hex(&reference.sha256, 64) || reference.size == 0 {
        finding(
            findings,
            "invalid-stage3a-cross-runtime-artifact-reference",
            format!("invalid artifact reference {}", reference.uri),
        );
        return None;
    }
    expected_files.insert(reference.uri.clone());
    let path = root.join(&reference.uri);
    if has_symlink(root, &reference.uri) {
        finding(
            findings,
            "stage3a-cross-runtime-artifact-symlink",
            format!("artifact path contains a symlink: {}", reference.uri),
        );
        return None;
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            finding(
                findings,
                "unreadable-stage3a-cross-runtime-artifact",
                format!("cannot read {}: {error}", path.display()),
            );
            return None;
        }
    };
    if bytes.len() as u64 != reference.size || sha256_hex(&bytes) != reference.sha256 {
        finding(
            findings,
            "stage3a-cross-runtime-artifact-digest-mismatch",
            format!("artifact {} differs from its reference", reference.uri),
        );
        return None;
    }
    Some(bytes)
}

fn collect_child_files(
    root: &Path,
    child_root: &Path,
    expected_files: &mut BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    let directory = root.join(child_root);
    let mut pending = vec![directory];
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            finding(findings, "unreadable-stage3a-child-tree", path.display().to_string());
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else { continue };
            if metadata.file_type().is_symlink() {
                finding(findings, "stage3a-child-tree-symlink", path.display().to_string());
            } else if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && let Ok(relative) = path.strip_prefix(root)
            {
                expected_files.insert(relative.to_string_lossy().into_owned());
            }
        }
    }
}

fn validate_exact_outer_file_set(
    root: &Path,
    expected: &BTreeSet<String>,
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
) {
    let mut observed = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            finding(findings, "unreadable-stage3a-cross-runtime-tree", path.display().to_string());
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else { continue };
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                finding(
                    findings,
                    "unsafe-stage3a-cross-runtime-tree-entry",
                    path.display().to_string(),
                );
            } else if metadata.is_dir() {
                pending.push(path);
            } else if let Ok(relative) = path.strip_prefix(root) {
                observed.insert(relative.to_string_lossy().into_owned());
            }
        }
    }
    if &observed != expected {
        finding(
            findings,
            "stage3a-cross-runtime-file-set-mismatch",
            format!("expected {expected:?}, found {observed:?}"),
        );
    }
}

fn safe_uri(uri: &str) -> bool {
    !uri.is_empty()
        && !Path::new(uri).is_absolute()
        && Path::new(uri).components().all(|component| matches!(component, Component::Normal(_)))
}

fn has_symlink(root: &Path, uri: &str) -> bool {
    let mut path = root.to_path_buf();
    for component in Path::new(uri).components() {
        let Component::Normal(component) = component else { return true };
        path.push(component);
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn load_failure(code: &str, detail: impl Into<String>) -> Stage3aCrossRuntimeEvidenceGateResult {
    Stage3aCrossRuntimeEvidenceGateResult {
        ok: false,
        load_error: Some(Stage3aCrossRuntimeValidationFinding {
            code: code.to_owned(),
            detail: detail.into(),
        }),
        validation: None,
    }
}

fn finding(
    findings: &mut Vec<Stage3aCrossRuntimeValidationFinding>,
    code: &str,
    detail: impl Into<String>,
) {
    findings.push(Stage3aCrossRuntimeValidationFinding {
        code: code.to_owned(),
        detail: detail.into(),
    });
}
