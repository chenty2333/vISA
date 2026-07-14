use std::{
    fs,
    io::Write,
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    model::*,
    verify::{
        common_input_from_stage1, stage4_bundle_id_from_matrix_sha256, stage4_registry_sha256,
        validate_stage4_evidence_bundle_for_publication,
    },
};
use crate::{
    STAGE1_CASE_DEFINITIONS, Stage1EvidenceBundle, Stage2NormalizedCellV1,
    artifact_io::SecureArtifactRoot, canonical_stage2_json_bytes,
    parse_stage1_evidence_bundle_json, sha256_hex, stage2_normalize::normalize_stage2_cell,
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

static NEXT_STAGE4_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

struct WrittenCell {
    cell_id: Stage4CellId,
    bundle: Stage1EvidenceBundle,
    bundle_bytes: Vec<u8>,
    normalized: Stage2NormalizedCellV1,
}

pub fn write_stage4_evidence_artifacts(
    stage4_root: impl AsRef<Path>,
    input: &Stage4PublicationInput,
) -> Result<Stage4WriteResult, Stage4WriteError> {
    let stage4_root = prepare_root(stage4_root.as_ref())?;
    ensure_incomplete_marker(&stage4_root)?;
    validate_input_catalog(input)?;

    let secure_root = SecureArtifactRoot::open(&stage4_root)
        .map_err(|source| write_error("invalid-stage4-root", source.to_string()))?;
    let mut written = Vec::new();
    let mut cells = Vec::with_capacity(input.cells.len());
    let mut common = None;
    for cell in &input.cells {
        let disposition = match &cell.disposition {
            Stage4PublicationCellDisposition::Passed {
                stage1_bundle,
                source_hello,
                destination_hello,
            } => {
                let bundle_bytes =
                    read_existing_reference(&secure_root, stage1_bundle, "inner Stage 1 bundle")?;
                let bundle =
                    parse_stage1_evidence_bundle_json(&bundle_bytes).map_err(|source| {
                        write_error(
                            "invalid-stage4-inner-stage1-json",
                            format!("{}: {}", cell.cell_id.as_str(), source.detail),
                        )
                    })?;
                let cell_root = stage4_root.join(cell.cell_id.cell_root_uri());
                let (validation, snapshot) =
                    validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, &cell_root);
                if !validation.ok {
                    return Err(write_error(
                        "stage4-inner-stage1-verification-failed",
                        render_stage1_findings(cell.cell_id, &validation.findings),
                    ));
                }
                let snapshot = snapshot.ok_or_else(|| {
                    write_error("missing-stage4-inner-artifact-snapshot", cell.cell_id.as_str())
                })?;
                let normalized = normalize_stage2_cell(&bundle, &snapshot).map_err(|source| {
                    write_error(
                        "stage4-normalization-failed",
                        format!("{}: {}: {}", cell.cell_id.as_str(), source.code, source.detail),
                    )
                })?;
                let actual_common = common_input_from_stage1(&bundle);
                match common.as_ref() {
                    Some(expected) if expected != &actual_common => {
                        return Err(write_error(
                            "mixed-stage4-common-input",
                            format!("{} differs from the first passed cell", cell.cell_id.as_str()),
                        ));
                    }
                    None => common = Some(actual_common),
                    _ => {}
                }
                let normalized_bytes = canonical_stage2_json_bytes(&normalized)
                    .map_err(|source| write_error(source.code, source.detail))?;
                let normalized_uri = cell.cell_id.normalized_uri();
                publish_atomic(&stage4_root, &normalized_uri, &normalized_bytes)?;
                let normalized_observable_trace =
                    reference_for_bytes(normalized_uri, &normalized_bytes);
                written.push(WrittenCell {
                    cell_id: cell.cell_id,
                    bundle,
                    bundle_bytes,
                    normalized,
                });
                Stage4CellDisposition::Passed {
                    stage1_bundle: stage1_bundle.clone(),
                    normalized_observable_trace,
                    source_hello: source_hello.clone(),
                    destination_hello: destination_hello.clone(),
                }
            }
            Stage4PublicationCellDisposition::Failed { reason, diagnostics } => {
                Stage4CellDisposition::Failed {
                    reason: reason.clone(),
                    diagnostics: diagnostics.clone(),
                }
            }
            Stage4PublicationCellDisposition::NotRun { reason } => {
                Stage4CellDisposition::NotRun { reason: reason.clone() }
            }
            Stage4PublicationCellDisposition::Unsupported { reason } => {
                Stage4CellDisposition::Unsupported { reason: reason.clone() }
            }
        };
        cells.push(Stage4CellEvidence {
            cell_id: cell.cell_id,
            source_endpoint: cell.source_endpoint,
            destination_endpoint: cell.destination_endpoint,
            disposition,
        });
    }
    let common = common.ok_or_else(|| {
        write_error(
            "missing-stage4-common-input-source",
            "at least one independently verified passed cell is required",
        )
    })?;
    let common_bytes = pretty_json(&common, "cannot-encode-stage4-common-input")?;
    publish_atomic(&stage4_root, STAGE4_COMMON_INPUT_FILE, &common_bytes)?;
    let common_input = reference_for_bytes(STAGE4_COMMON_INPUT_FILE.to_owned(), &common_bytes);

    let completed_execution_count = written.len() * STAGE4_CASE_COUNT;
    let matrix = Stage4MatrixManifest {
        schema_version: STAGE4_MATRIX_SCHEMA_VERSION.to_owned(),
        common_input,
        execution_artifact_root: stage4_root
            .to_str()
            .ok_or_else(|| {
                write_error("non-utf8-stage4-execution-root", stage4_root.display().to_string())
            })?
            .to_owned(),
        orchestrator: input.orchestrator.clone(),
        orchestrator_host: input.orchestrator_host.clone(),
        registry_sha256: stage4_registry_sha256(),
        endpoints: input.endpoints.clone(),
        claims: required_stage4_claims(),
        claim_guards: Stage4ClaimGuards::required(),
        qualifications: required_stage4_qualifications(),
        cells,
        execution_count: completed_execution_count,
    };
    let matrix_bytes = pretty_json(&matrix, "cannot-encode-stage4-matrix")?;
    publish_atomic(&stage4_root, STAGE4_MATRIX_FILE, &matrix_bytes)?;
    let matrix_manifest = reference_for_bytes(STAGE4_MATRIX_FILE.to_owned(), &matrix_bytes);
    let bundle_id = stage4_bundle_id_from_matrix_sha256(&matrix_manifest.sha256)
        .expect("publisher SHA-256 is canonical");
    let comparisons = compare_written_cells(&written)?;
    let inner_verifications = input
        .cells
        .iter()
        .map(|cell| {
            written
                .iter()
                .find(|written| written.cell_id == cell.cell_id)
                .map(|written| Stage4InnerVerification {
                    cell_id: cell.cell_id,
                    disposition: Stage4CellStatus::Passed,
                    stage1_bundle_id: Some(written.bundle.bundle_id.clone()),
                    stage1_bundle_sha256: Some(sha256_hex(&written.bundle_bytes)),
                    case_count: written.bundle.cases.len(),
                    independently_verified: true,
                })
                .unwrap_or_else(|| Stage4InnerVerification {
                    cell_id: cell.cell_id,
                    disposition: publication_disposition_name(&cell.disposition),
                    stage1_bundle_id: None,
                    stage1_bundle_sha256: None,
                    case_count: 0,
                    independently_verified: false,
                })
        })
        .collect();
    let evidence = Stage4EvidenceBundle {
        schema_version: STAGE4_EVIDENCE_SCHEMA_VERSION.to_owned(),
        bundle_id,
        matrix_manifest,
        completed_execution_count,
        inner_verifications,
        case_comparisons: comparisons,
        claims: required_stage4_claims(),
        claim_guards: Stage4ClaimGuards::required(),
        qualifications: required_stage4_qualifications(),
    };
    let evidence_bytes = pretty_json(&evidence, "cannot-encode-stage4-evidence")?;
    publish_atomic(&stage4_root, STAGE4_EVIDENCE_FILE, &evidence_bytes)?;

    let validation = validate_stage4_evidence_bundle_for_publication(&evidence, &stage4_root);
    if !validation.ok {
        return Err(write_error(
            "stage4-prepublication-verification-failed",
            validation
                .findings
                .iter()
                .map(|finding| format!("{}: {}", finding.code, finding.detail))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    fs::remove_file(stage4_root.join(STAGE4_INCOMPLETE_MARKER_FILE)).map_err(|source| {
        write_error(
            "cannot-commit-stage4-publication",
            format!("cannot remove incomplete marker: {source}"),
        )
    })?;
    sync_directory(&stage4_root)?;
    Ok(Stage4WriteResult {
        bundle_path: stage4_root.join(STAGE4_EVIDENCE_FILE).display().to_string(),
        matrix_path: stage4_root.join(STAGE4_MATRIX_FILE).display().to_string(),
        completed_execution_count,
    })
}

/// Creates the durable incomplete marker before target acquisition or cell execution begins.
/// A crashed Stage 4 run therefore cannot be mistaken for a published artifact root.
pub fn begin_stage4_evidence_publication(
    stage4_root: impl AsRef<Path>,
) -> Result<(), Stage4WriteError> {
    let stage4_root = prepare_root(stage4_root.as_ref())?;
    ensure_incomplete_marker(&stage4_root)?;
    sync_directory(&stage4_root)
}

pub fn stage4_artifact_reference_for_file(
    stage4_root: impl AsRef<Path>,
    uri: &str,
) -> Result<Stage4ArtifactReference, Stage4WriteError> {
    let root = SecureArtifactRoot::open(stage4_root.as_ref())
        .map_err(|source| write_error("invalid-stage4-root", source.to_string()))?;
    let bytes = root
        .read_regular(uri)
        .map_err(|source| write_error("invalid-stage4-owned-artifact", source.to_string()))?;
    Ok(reference_for_bytes(uri.to_owned(), &bytes))
}

fn validate_input_catalog(input: &Stage4PublicationInput) -> Result<(), Stage4WriteError> {
    if input.endpoints.iter().map(|endpoint| endpoint.endpoint_id).collect::<Vec<_>>()
        != STAGE4_ENDPOINT_CATALOG
    {
        return Err(write_error(
            "invalid-stage4-endpoint-catalog",
            "publication input must contain ordered Hx, Qx, Qa",
        ));
    }
    if input.cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>() != STAGE4_CELL_CATALOG {
        return Err(write_error(
            "invalid-stage4-cell-catalog",
            "publication input must contain the exact ordered seven cells",
        ));
    }
    for cell in &input.cells {
        if (cell.source_endpoint, cell.destination_endpoint) != cell.cell_id.endpoints() {
            return Err(write_error("invalid-stage4-cell-endpoints", cell.cell_id.as_str()));
        }
    }
    Ok(())
}

fn compare_written_cells(
    cells: &[WrittenCell],
) -> Result<Vec<Stage4CaseComparison>, Stage4WriteError> {
    if cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>() != STAGE4_CELL_CATALOG {
        return Ok(Vec::new());
    }
    let mut comparisons = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let baseline = cells[0]
            .normalized
            .cases
            .get(index)
            .ok_or_else(|| write_error("missing-stage4-normalized-case", definition.id))?;
        if baseline.case_id != definition.id
            || cells.iter().any(|cell| cell.normalized.cases.get(index) != Some(baseline))
        {
            return Err(write_error("stage4-normalized-observable-divergence", definition.id));
        }
        let bytes = canonical_stage2_json_bytes(baseline)
            .map_err(|source| write_error(source.code, source.detail))?;
        comparisons.push(Stage4CaseComparison {
            case_id: definition.id.to_owned(),
            normalized_case_sha256: sha256_hex(&bytes),
            equal_across_all_cells: true,
        });
    }
    Ok(comparisons)
}

fn publication_disposition_name(
    disposition: &Stage4PublicationCellDisposition,
) -> Stage4CellStatus {
    match disposition {
        Stage4PublicationCellDisposition::Passed { .. } => Stage4CellStatus::Passed,
        Stage4PublicationCellDisposition::Failed { .. } => Stage4CellStatus::Failed,
        Stage4PublicationCellDisposition::NotRun { .. } => Stage4CellStatus::NotRun,
        Stage4PublicationCellDisposition::Unsupported { .. } => Stage4CellStatus::Unsupported,
    }
}

fn read_existing_reference(
    root: &SecureArtifactRoot,
    reference: &Stage4ArtifactReference,
    label: &str,
) -> Result<Vec<u8>, Stage4WriteError> {
    if !safe_relative_uri(&reference.uri) {
        return Err(write_error(
            "invalid-stage4-artifact-uri",
            format!("unsafe {label} URI {}", reference.uri),
        ));
    }
    let bytes = root
        .read_regular(&reference.uri)
        .map_err(|source| write_error("invalid-stage4-owned-artifact", source.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.size
        || sha256_hex(&bytes) != reference.sha256
    {
        return Err(write_error(
            "stage4-owned-artifact-identity-mismatch",
            format!("{label} {}", reference.uri),
        ));
    }
    Ok(bytes)
}

fn prepare_root(root: &Path) -> Result<std::path::PathBuf, Stage4WriteError> {
    fs::create_dir_all(root).map_err(|source| {
        write_error(
            "cannot-create-stage4-root",
            format!("cannot create {}: {source}", root.display()),
        )
    })?;
    let metadata = fs::symlink_metadata(root).map_err(|source| {
        write_error("cannot-inspect-stage4-root", format!("{}: {source}", root.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(write_error(
            "invalid-stage4-root",
            "Stage 4 root must be a real directory, not a symlink",
        ));
    }
    root.canonicalize().map_err(|source| {
        write_error("invalid-stage4-root", format!("{}: {source}", root.display()))
    })
}

fn ensure_incomplete_marker(root: &Path) -> Result<(), Stage4WriteError> {
    let path = root.join(STAGE4_INCOMPLETE_MARKER_FILE);
    match fs::read(&path) {
        Ok(bytes) if bytes == STAGE4_INCOMPLETE_MARKER_CONTENT => Ok(()),
        Ok(_) => Err(write_error("invalid-stage4-incomplete-marker", path.display().to_string())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            publish_atomic(root, STAGE4_INCOMPLETE_MARKER_FILE, STAGE4_INCOMPLETE_MARKER_CONTENT)
        }
        Err(source) => Err(write_error(
            "cannot-inspect-stage4-incomplete-marker",
            format!("{}: {source}", path.display()),
        )),
    }
}

fn publish_atomic(root: &Path, uri: &str, bytes: &[u8]) -> Result<(), Stage4WriteError> {
    if !safe_relative_uri(uri) {
        return Err(write_error("invalid-stage4-publication-uri", uri));
    }
    reject_symlink_components(root, uri)?;
    let destination = root.join(uri);
    let parent = destination.parent().ok_or_else(|| {
        write_error("invalid-stage4-publication-uri", destination.display().to_string())
    })?;
    fs::create_dir_all(parent).map_err(|source| {
        write_error(
            "cannot-create-stage4-publication-parent",
            format!("{}: {source}", parent.display()),
        )
    })?;
    reject_symlink_components(root, uri)?;
    let file_name = destination.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
        write_error("invalid-stage4-publication-uri", destination.display().to_string())
    })?;
    let nonce = NEXT_STAGE4_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|source| {
            write_error(
                "cannot-create-stage4-temporary-artifact",
                format!("{}: {source}", temporary.display()),
            )
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(write_error(
            "cannot-write-stage4-temporary-artifact",
            format!("{}: {source}", temporary.display()),
        ));
    }
    drop(file);
    if let Err(source) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        let code = if source.kind() == std::io::ErrorKind::AlreadyExists {
            "stage4-publication-conflict"
        } else {
            "cannot-publish-stage4-artifact"
        };
        return Err(write_error(code, format!("{}: {source}", destination.display())));
    }
    fs::remove_file(&temporary).map_err(|source| {
        write_error(
            "cannot-remove-stage4-temporary-artifact",
            format!("{}: {source}", temporary.display()),
        )
    })?;
    sync_directory(parent)
}

fn reject_symlink_components(root: &Path, uri: &str) -> Result<(), Stage4WriteError> {
    let mut path = root.to_path_buf();
    for component in Path::new(uri).components() {
        let Component::Normal(component) = component else { unreachable!() };
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(write_error(
                    "stage4-publication-symlink-rejected",
                    path.display().to_string(),
                ));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(write_error(
                    "cannot-inspect-stage4-publication-path",
                    format!("{}: {source}", path.display()),
                ));
            }
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), Stage4WriteError> {
    fs::File::open(path).and_then(|directory| directory.sync_all()).map_err(|source| {
        write_error(
            "cannot-sync-stage4-publication-directory",
            format!("{}: {source}", path.display()),
        )
    })
}

fn reference_for_bytes(uri: String, bytes: &[u8]) -> Stage4ArtifactReference {
    Stage4ArtifactReference {
        uri,
        sha256: sha256_hex(bytes),
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn pretty_json<T: serde::Serialize>(
    value: &T,
    code: &'static str,
) -> Result<Vec<u8>, Stage4WriteError> {
    serde_json::to_vec_pretty(value).map_err(|source| write_error(code, source.to_string()))
}

fn safe_relative_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn render_stage1_findings(
    cell: Stage4CellId,
    findings: &[crate::Stage1ValidationFinding],
) -> String {
    findings
        .iter()
        .map(|finding| format!("{}: {}: {}", cell.as_str(), finding.code, finding.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

fn write_error(code: impl Into<String>, detail: impl Into<String>) -> Stage4WriteError {
    Stage4WriteError { code: code.into(), detail: detail.into() }
}
