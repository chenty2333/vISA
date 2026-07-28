use std::{
    fs,
    io::Write,
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{model::*, verify::*};
use crate::{
    STAGE1_CASE_DEFINITIONS, Stage1EvidenceBundle, Stage2NormalizedCellV1,
    artifact_io::SecureArtifactRoot, canonical_stage2_json_bytes,
    parse_stage1_evidence_bundle_json, sha256_hex, stage2_normalize::normalize_stage2_cell,
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

struct WrittenCell {
    cell_id: Stage4NativeCellId,
    bundle: Stage1EvidenceBundle,
    bundle_bytes: Vec<u8>,
    normalized: Stage2NormalizedCellV1,
}

pub fn begin_stage4_native_evidence_publication(
    root: impl AsRef<Path>,
) -> Result<(), Stage4NativeWriteError> {
    let root = prepare_root(root.as_ref())?;
    let marker = root.join(STAGE4_NATIVE_INCOMPLETE_MARKER_FILE);
    match fs::read(&marker) {
        Ok(bytes) if bytes == STAGE4_NATIVE_INCOMPLETE_MARKER_CONTENT => Ok(()),
        Ok(_) => Err(write_error("invalid-stage4-native-incomplete-marker", marker.display())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => publish_atomic(
            &root,
            STAGE4_NATIVE_INCOMPLETE_MARKER_FILE,
            STAGE4_NATIVE_INCOMPLETE_MARKER_CONTENT,
        ),
        Err(source) => {
            Err(write_error("cannot-inspect-stage4-native-incomplete-marker", source.to_string()))
        }
    }
}

pub fn stage4_native_artifact_reference_for_file(
    root: impl AsRef<Path>,
    uri: &str,
) -> Result<crate::Stage4ArtifactReference, Stage4NativeWriteError> {
    let root = SecureArtifactRoot::open(root.as_ref())
        .map_err(|source| write_error("invalid-stage4-native-root", source.to_string()))?;
    let bytes = root
        .read_regular(uri)
        .map_err(|source| write_error("invalid-stage4-native-artifact", source.to_string()))?;
    Ok(reference_for_bytes(uri.to_owned(), &bytes))
}

pub fn write_stage4_native_evidence_artifacts(
    root: impl AsRef<Path>,
    input: &Stage4NativePublicationInput,
) -> Result<Stage4NativeWriteResult, Stage4NativeWriteError> {
    let root = prepare_root(root.as_ref())?;
    require_catalogs(input)?;
    let marker = root.join(STAGE4_NATIVE_INCOMPLETE_MARKER_FILE);
    if fs::read(&marker).ok().as_deref() != Some(STAGE4_NATIVE_INCOMPLETE_MARKER_CONTENT) {
        return Err(write_error(
            "missing-stage4-native-incomplete-marker",
            "begin publication before acquiring or running endpoints",
        ));
    }
    let secure = SecureArtifactRoot::open(&root)
        .map_err(|source| write_error("invalid-stage4-native-root", source.to_string()))?;

    let mut common = None;
    let mut written = Vec::with_capacity(STAGE4_NATIVE_CELL_COUNT);
    let mut cells = Vec::with_capacity(STAGE4_NATIVE_CELL_COUNT);
    for cell in &input.cells {
        let bundle_bytes = read_reference(&secure, &cell.stage1_bundle, "inner Stage 1 bundle")?;
        let bundle = parse_stage1_evidence_bundle_json(&bundle_bytes).map_err(|source| {
            write_error(
                "invalid-stage4-native-inner-json",
                format!("{}: {}", cell.cell_id.as_str(), source.detail),
            )
        })?;
        let cell_root = root.join(cell.cell_id.cell_root_uri());
        let (report, snapshot) =
            validate_stage1_evidence_bundle_with_artifact_snapshot(&bundle, &cell_root);
        if !report.ok {
            return Err(write_error(
                "stage4-native-inner-verification-failed",
                report
                    .findings
                    .iter()
                    .map(|finding| format!("{}: {}", finding.code, finding.detail))
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        let snapshot = snapshot.ok_or_else(|| {
            write_error("missing-stage4-native-inner-artifact-snapshot", cell.cell_id.as_str())
        })?;
        let normalized = normalize_stage2_cell(&bundle, &snapshot).map_err(|source| {
            write_error(
                "stage4-native-normalization-failed",
                format!("{}: {}: {}", cell.cell_id.as_str(), source.code, source.detail),
            )
        })?;
        let actual_common = crate::stage4::common_input_from_stage1(&bundle);
        match common.as_ref() {
            Some(expected) if expected != &actual_common => {
                return Err(write_error("mixed-stage4-native-common-input", cell.cell_id.as_str()));
            }
            None => common = Some(actual_common),
            _ => {}
        }
        let normalized_bytes = canonical_stage2_json_bytes(&normalized)
            .map_err(|source| write_error(source.code, source.detail))?;
        let normalized_uri = cell.cell_id.normalized_uri();
        publish_atomic(&root, &normalized_uri, &normalized_bytes)?;
        let normalized_ref = reference_for_bytes(normalized_uri, &normalized_bytes);
        cells.push(Stage4NativeCellEvidence {
            cell_id: cell.cell_id,
            source_endpoint: cell.source_endpoint,
            destination_endpoint: cell.destination_endpoint,
            stage1_bundle: cell.stage1_bundle.clone(),
            normalized_observable_trace: normalized_ref,
            source_hello: cell.source_hello.clone(),
            destination_hello: cell.destination_hello.clone(),
        });
        written.push(WrittenCell { cell_id: cell.cell_id, bundle, bundle_bytes, normalized });
    }

    let common = common.ok_or_else(|| {
        write_error("missing-stage4-native-common-input", "four passed cells are required")
    })?;
    let common_bytes = pretty_json(&common, "cannot-encode-stage4-native-common-input")?;
    publish_atomic(&root, STAGE4_NATIVE_COMMON_INPUT_FILE, &common_bytes)?;
    let common_input =
        reference_for_bytes(STAGE4_NATIVE_COMMON_INPUT_FILE.to_owned(), &common_bytes);
    let comparisons = compare_written(&written)?;
    let matrix = Stage4NativeMatrixManifest {
        schema_version: STAGE4_NATIVE_MATRIX_SCHEMA_VERSION.to_owned(),
        common_input,
        execution_artifact_root: root
            .to_str()
            .ok_or_else(|| write_error("non-utf8-stage4-native-root", root.display()))?
            .to_owned(),
        registry_sha256: stage4_native_registry_sha256(),
        hosts: input.hosts.clone(),
        endpoints: input.endpoints.clone(),
        provider: input.provider.clone(),
        claim: required_stage4_native_claim(),
        claim_guards: Stage4NativeClaimGuards::required(),
        cells,
        execution_count: STAGE4_NATIVE_EXECUTION_COUNT,
    };
    let matrix_bytes = pretty_json(&matrix, "cannot-encode-stage4-native-matrix")?;
    publish_atomic(&root, STAGE4_NATIVE_MATRIX_FILE, &matrix_bytes)?;
    let matrix_manifest = reference_for_bytes(STAGE4_NATIVE_MATRIX_FILE.to_owned(), &matrix_bytes);
    let bundle_id = stage4_native_bundle_id_from_matrix_sha256(&matrix_manifest.sha256)
        .expect("publisher creates a canonical digest");
    let inner_verifications = written
        .iter()
        .map(|cell| Stage4NativeInnerVerification {
            cell_id: cell.cell_id,
            stage1_bundle_id: cell.bundle.bundle_id.clone(),
            stage1_bundle_sha256: sha256_hex(&cell.bundle_bytes),
            case_count: cell.bundle.cases.len(),
            independently_verified: true,
        })
        .collect();
    let evidence = Stage4NativeEvidenceBundle {
        schema_version: STAGE4_NATIVE_EVIDENCE_SCHEMA_VERSION.to_owned(),
        bundle_id,
        matrix_manifest,
        completed_execution_count: STAGE4_NATIVE_EXECUTION_COUNT,
        inner_verifications,
        case_comparisons: comparisons,
        claim: required_stage4_native_claim(),
        claim_guards: Stage4NativeClaimGuards::required(),
    };
    let evidence_bytes = pretty_json(&evidence, "cannot-encode-stage4-native-evidence")?;
    publish_atomic(&root, STAGE4_NATIVE_EVIDENCE_FILE, &evidence_bytes)?;

    let report = validate_stage4_native_evidence_bundle_for_publication(&evidence, &root);
    if !report.ok {
        return Err(write_error(
            "stage4-native-prepublication-verification-failed",
            report
                .findings
                .iter()
                .map(|finding| format!("{}: {}", finding.code, finding.detail))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    fs::remove_file(&marker).map_err(|source| {
        write_error("cannot-commit-stage4-native-publication", source.to_string())
    })?;
    sync_directory(&root)?;
    Ok(Stage4NativeWriteResult {
        bundle_path: root.join(STAGE4_NATIVE_EVIDENCE_FILE).display().to_string(),
        matrix_path: root.join(STAGE4_NATIVE_MATRIX_FILE).display().to_string(),
        completed_execution_count: STAGE4_NATIVE_EXECUTION_COUNT,
    })
}

fn require_catalogs(input: &Stage4NativePublicationInput) -> Result<(), Stage4NativeWriteError> {
    if input.hosts.iter().map(|host| host.host_id).collect::<Vec<_>>() != STAGE4_NATIVE_HOST_CATALOG
    {
        return Err(write_error(
            "invalid-stage4-native-host-catalog",
            "expected ordered Hx-host, Ha-host",
        ));
    }
    if input.endpoints.iter().map(|endpoint| endpoint.endpoint_id).collect::<Vec<_>>()
        != STAGE4_NATIVE_ENDPOINT_CATALOG
    {
        return Err(write_error(
            "invalid-stage4-native-endpoint-catalog",
            "expected ordered Hx, Ha",
        ));
    }
    if input.cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>() != STAGE4_NATIVE_CELL_CATALOG
    {
        return Err(write_error(
            "invalid-stage4-native-cell-catalog",
            "expected the exact ordered four-direction native matrix",
        ));
    }
    if input.provider.receipt_artifact.uri != STAGE4_NATIVE_PROVIDER_RECEIPT_FILE {
        return Err(write_error(
            "noncanonical-stage4-native-provider-receipt-path",
            &input.provider.receipt_artifact.uri,
        ));
    }
    let expected_domains = STAGE4_NATIVE_CELL_CATALOG.iter().copied().flat_map(|cell_id| {
        STAGE1_CASE_DEFINITIONS
            .iter()
            .map(move |definition| (cell_id, definition.id, cell_id.endpoints()))
    });
    if input.provider.receipt.case_domains.len() != STAGE4_NATIVE_EXECUTION_COUNT
        || input.provider.receipt.case_domains.iter().zip(expected_domains).any(
            |(domain, (cell_id, case_id, endpoints))| {
                domain.cell_id != cell_id
                    || domain.case_id != case_id
                    || (domain.source_endpoint, domain.destination_endpoint) != endpoints
            },
        )
    {
        return Err(write_error(
            "invalid-stage4-native-provider-case-domain-catalog",
            "expected exact ordered cell x case provider domains",
        ));
    }
    for cell in &input.cells {
        if (cell.source_endpoint, cell.destination_endpoint) != cell.cell_id.endpoints() {
            return Err(write_error("invalid-stage4-native-cell-endpoints", cell.cell_id.as_str()));
        }
        if cell.stage1_bundle.uri != cell.cell_id.stage1_bundle_uri() {
            return Err(write_error(
                "noncanonical-stage4-native-stage1-path",
                cell.cell_id.as_str(),
            ));
        }
    }
    Ok(())
}

fn compare_written(
    cells: &[WrittenCell],
) -> Result<Vec<Stage4NativeCaseComparison>, Stage4NativeWriteError> {
    if cells.len() != STAGE4_NATIVE_CELL_COUNT {
        return Err(write_error("incomplete-stage4-native-matrix", cells.len().to_string()));
    }
    let mut comparisons = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let baseline = cells[0]
            .normalized
            .cases
            .get(index)
            .ok_or_else(|| write_error("missing-stage4-native-case", definition.id))?;
        if baseline.case_id != definition.id
            || cells.iter().any(|cell| cell.normalized.cases.get(index) != Some(baseline))
        {
            return Err(write_error(
                "stage4-native-normalized-observable-divergence",
                definition.id,
            ));
        }
        let bytes = canonical_stage2_json_bytes(baseline)
            .map_err(|source| write_error(source.code, source.detail))?;
        comparisons.push(Stage4NativeCaseComparison {
            case_id: definition.id.to_owned(),
            normalized_case_sha256: sha256_hex(&bytes),
            equal_across_all_cells: true,
        });
    }
    Ok(comparisons)
}

fn read_reference(
    root: &SecureArtifactRoot,
    reference: &crate::Stage4ArtifactReference,
    label: &str,
) -> Result<Vec<u8>, Stage4NativeWriteError> {
    if !safe_uri(&reference.uri) {
        return Err(write_error("invalid-stage4-native-artifact-uri", &reference.uri));
    }
    let bytes = root
        .read_regular(&reference.uri)
        .map_err(|source| write_error("invalid-stage4-native-artifact", source.to_string()))?;
    if reference.size != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || reference.sha256 != sha256_hex(&bytes)
    {
        return Err(write_error(
            "stage4-native-artifact-identity-mismatch",
            format!("{label} {}", reference.uri),
        ));
    }
    Ok(bytes)
}

fn prepare_root(root: &Path) -> Result<std::path::PathBuf, Stage4NativeWriteError> {
    fs::create_dir_all(root)
        .map_err(|source| write_error("cannot-create-stage4-native-root", source.to_string()))?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| write_error("cannot-inspect-stage4-native-root", source.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(write_error("invalid-stage4-native-root", root.display()));
    }
    root.canonicalize()
        .map_err(|source| write_error("invalid-stage4-native-root", source.to_string()))
}

fn publish_atomic(root: &Path, uri: &str, bytes: &[u8]) -> Result<(), Stage4NativeWriteError> {
    if !safe_uri(uri) {
        return Err(write_error("invalid-stage4-native-publication-uri", uri));
    }
    let destination = root.join(uri);
    let parent = destination
        .parent()
        .ok_or_else(|| write_error("invalid-stage4-native-publication-uri", uri))?;
    fs::create_dir_all(parent)
        .map_err(|source| write_error("cannot-create-stage4-native-parent", source.to_string()))?;
    let nonce = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".stage4-native-{}-{nonce}.tmp", std::process::id()));
    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|source| {
            write_error("cannot-create-stage4-native-temporary", source.to_string())
        })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|source| {
        write_error("cannot-write-stage4-native-temporary", source.to_string())
    })?;
    drop(file);
    fs::hard_link(&temporary, &destination).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        write_error("cannot-publish-stage4-native-artifact", source.to_string())
    })?;
    fs::remove_file(&temporary).map_err(|source| {
        write_error("cannot-remove-stage4-native-temporary", source.to_string())
    })?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), Stage4NativeWriteError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| write_error("cannot-sync-stage4-native-directory", source.to_string()))
}

fn pretty_json<T: serde::Serialize>(
    value: &T,
    code: &'static str,
) -> Result<Vec<u8>, Stage4NativeWriteError> {
    serde_json::to_vec_pretty(value).map_err(|source| write_error(code, source.to_string()))
}

fn reference_for_bytes(uri: String, bytes: &[u8]) -> crate::Stage4ArtifactReference {
    crate::Stage4ArtifactReference {
        uri,
        sha256: sha256_hex(bytes),
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn safe_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn write_error(code: impl Into<String>, detail: impl std::fmt::Display) -> Stage4NativeWriteError {
    Stage4NativeWriteError { code: code.into(), detail: detail.to_string() }
}
