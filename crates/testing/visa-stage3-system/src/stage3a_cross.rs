use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as _, Sha256};
use visa_conformance::{
    EVIDENCE_MATRIX_RUN_SCHEMA_VERSION, EvidenceMatrix, EvidenceMatrixArtifactReference,
    EvidenceMatrixCellReceipt, EvidenceMatrixCoordinates, EvidenceMatrixRun,
    EvidenceMatrixSemanticOutcome, EvidenceMatrixVerifierIdentity, MatrixRuntime,
    STAGE2_STRICT_WACOGO_SIDECAR_SHA256, STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256,
    STAGE3A_CROSS_RUNTIME_CLAIM_ID, STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE,
    STAGE3A_CROSS_RUNTIME_EVIDENCE_SCHEMA_VERSION, STAGE3A_CROSS_RUNTIME_MATRIX_RUN_FILE,
    STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS, Stage3ArtifactReference, Stage3EvidenceBundle,
    Stage3Profile, Stage3aCrossRuntimeCellRun, Stage3aCrossRuntimeEnvironment,
    Stage3aCrossRuntimeEvidenceBundle, Stage3aCrossRuntimeLineage, evidence_matrix_sha256,
    gate_stage3_evidence_bundle_json_with_artifacts,
    gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts,
    normalized_stage3a_semantics_sha256, parse_evidence_matrix_json, sha256_hex,
    validate_evidence_matrix,
};

use crate::{
    component,
    evidence::{publish_atomic, sync_directory, write_artifact, write_json_artifact},
    regular_file_runtime::{RegularFileRuntimeKind, RegularFileRuntimePair},
    stage3a::run_stage3a_for_pair,
};

const INCOMPLETE_MARKER: &str = "stage3a-cross-runtime-incomplete";
const INCOMPLETE_CONTENT: &[u8] = b"cross-runtime Stage 3A publication incomplete\n";
const ENVIRONMENT_SCHEMA: &str = "visa-stage3a-cross-runtime-environment-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct GitWorktreeSeal {
    sha: String,
    dirty: bool,
}

pub fn run_stage3a_cross_runtime(artifact_root: &Path) -> Result<PathBuf, String> {
    create_root(artifact_root)?;
    let started = now_unix_ms()?;
    let initial_git_seal = current_git_worktree_seal()?;
    let git_sha = initial_git_seal.sha.clone();
    let git_dirty = initial_git_seal.dirty;
    let lineage = publish_lineage(artifact_root)?;
    let matrix_bytes = fs::read("claims/evidence-matrix.json")
        .map_err(|error| format!("cannot read canonical evidence matrix: {error}"))?;
    let matrix = parse_evidence_matrix_json(&matrix_bytes)
        .map_err(|error| format!("cannot parse canonical evidence matrix: {error}"))?;
    let matrix_report = validate_evidence_matrix(&matrix);
    if !matrix_report.ok {
        return Err(format!("canonical evidence matrix is invalid: {:?}", matrix_report.findings));
    }
    let matrix_sha256 = evidence_matrix_sha256(&matrix)?;
    let verifier = verifier_identity()?;

    let mut cells = Vec::with_capacity(
        RegularFileRuntimePair::FOUR_DIRECTIONS.len()
            * STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS as usize,
    );
    let mut receipts = Vec::with_capacity(cells.capacity() + 1);
    let mut normalized_semantics_sha256 = None;
    for pair in RegularFileRuntimePair::FOUR_DIRECTIONS {
        for run_ordinal in 1..=STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS {
            let cell = run_cell(artifact_root, pair, run_ordinal)?;
            if let Some(expected) = &normalized_semantics_sha256 {
                if expected != &cell.normalized_semantics_sha256 {
                    return Err(format!(
                        "{} run {} diverged from normalized regular-file semantics",
                        cell.cell_id, run_ordinal
                    ));
                }
            } else {
                normalized_semantics_sha256 = Some(cell.normalized_semantics_sha256.clone());
            }
            receipts.push(matrix_receipt(&matrix, &cell, verifier.clone())?);
            cells.push(cell);
        }
    }
    let baseline = cells
        .iter()
        .find(|cell| {
            cell.cell_id == "s3a.cross.wasmtime-to-wasmtime.regular-file" && cell.run_ordinal == 1
        })
        .ok_or("missing Wasmtime supporting baseline")?;
    receipts.push(supporting_baseline_receipt(&matrix, baseline, verifier)?);
    receipts.sort_by(|left, right| {
        (left.cell_id.as_str(), left.run_ordinal).cmp(&(right.cell_id.as_str(), right.run_ordinal))
    });
    let finished = now_unix_ms()?;
    let run = EvidenceMatrixRun {
        schema_version: EVIDENCE_MATRIX_RUN_SCHEMA_VERSION.to_owned(),
        matrix_sha256: matrix_sha256.clone(),
        git_sha: git_sha.clone(),
        git_dirty,
        run_id: format!("stage3a-cross-runtime-{}-{started}", &git_sha[..12]),
        started_at_unix_ms: started,
        finished_at_unix_ms: finished,
        claim_ids: vec![STAGE3A_CROSS_RUNTIME_CLAIM_ID.to_owned()],
        receipts,
    };
    let matrix_run =
        write_json_artifact(artifact_root, STAGE3A_CROSS_RUNTIME_MATRIX_RUN_FILE, &run)?;
    let normalized_semantics_sha256 =
        normalized_semantics_sha256.ok_or("cross-runtime matrix produced no cells")?;
    let fingerprint = serde_json::to_vec(&(
        &git_sha,
        started,
        finished,
        &matrix_sha256,
        &normalized_semantics_sha256,
        &cells,
    ))
    .map_err(|error| format!("cannot encode cross-runtime bundle fingerprint: {error}"))?;
    let bundle = Stage3aCrossRuntimeEvidenceBundle {
        schema_version: STAGE3A_CROSS_RUNTIME_EVIDENCE_SCHEMA_VERSION.to_owned(),
        claim_id: STAGE3A_CROSS_RUNTIME_CLAIM_ID.to_owned(),
        bundle_id: format!(
            "stage3a-cross-runtime-{}",
            &format!("{:x}", Sha256::digest(fingerprint))[..24]
        ),
        git_sha,
        git_dirty,
        started_at_unix_ms: started,
        finished_at_unix_ms: finished,
        matrix_sha256,
        required_runs_per_cell: STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS,
        relocated_verification_required: true,
        normalized_semantics_sha256,
        lineage,
        matrix_run,
        cells,
    };
    let bundle_bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("cannot encode cross-runtime Stage 3A bundle: {error}"))?;
    require_unchanged_git_worktree_seal(&initial_git_seal, &current_git_worktree_seal()?)?;
    publish_atomic(artifact_root, STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE, &bundle_bytes)?;
    fs::remove_file(artifact_root.join(INCOMPLETE_MARKER))
        .map_err(|error| format!("cannot remove cross-runtime publication marker: {error}"))?;
    sync_directory(artifact_root)?;

    let gate = gate_stage3a_cross_runtime_evidence_bundle_json_with_artifacts(
        &bundle_bytes,
        artifact_root,
    );
    if !gate.ok {
        let findings = gate
            .validation
            .as_ref()
            .map(|validation| validation.findings.as_slice())
            .unwrap_or_default();
        let dirty_only = git_dirty
            && !findings.is_empty()
            && findings.iter().all(|finding| {
                finding.code == "stage3a-cross-runtime-matrix-closure-failed"
                    && finding.detail.contains("dirty-evidence-matrix-run")
            });
        if !dirty_only {
            let _ = publish_atomic(artifact_root, INCOMPLETE_MARKER, INCOMPLETE_CONTENT);
            return Err(format!(
                "cross-runtime Stage 3A prepublication verification failed: {gate:#?}"
            ));
        }
    }
    Ok(artifact_root.join(STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE))
}

fn run_cell(
    root: &Path,
    pair: RegularFileRuntimePair,
    run_ordinal: u32,
) -> Result<Stage3aCrossRuntimeCellRun, String> {
    let directory = pair.artifact_directory();
    let original_relative = format!("runs/run-{run_ordinal}/original/{directory}");
    let relocated_relative = format!("runs/run-{run_ordinal}/relocated/{directory}");
    let original_root = root.join(&original_relative);
    let relocated_root = root.join(&relocated_relative);
    fs::create_dir_all(&original_root)
        .map_err(|error| format!("cannot create {}: {error}", original_root.display()))?;
    let original_path = run_stage3a_for_pair(&original_root, pair)?;
    copy_tree(&original_root, &relocated_root)?;
    let relocated_path = relocated_root.join("stage3a-evidence.json");
    let relocated_bytes = fs::read(&relocated_path)
        .map_err(|error| format!("cannot read {}: {error}", relocated_path.display()))?;
    let validation = gate_stage3_evidence_bundle_json_with_artifacts(
        Stage3Profile::RegularFile,
        &relocated_bytes,
        &relocated_root,
    );
    if !validation.ok {
        return Err(format!(
            "{} run {run_ordinal} failed relocated Stage 3 verification: {validation:#?}",
            pair.cell_id()
        ));
    }
    let child: Stage3EvidenceBundle = serde_json::from_slice(&relocated_bytes)
        .map_err(|error| format!("cannot decode relocated Stage 3A bundle: {error}"))?;
    let normalized_semantics_sha256 = normalized_stage3a_semantics_sha256(&child, &relocated_root)?;
    let receipt_root = format!("runs/run-{run_ordinal}/receipts/{directory}");
    let validation_report = write_json_artifact(
        root,
        &format!("{receipt_root}/relocated-validation.json"),
        &validation,
    )?;
    let environment = Stage3aCrossRuntimeEnvironment {
        schema_version: ENVIRONMENT_SCHEMA.to_owned(),
        run_ordinal,
        cell_id: pair.cell_id(),
        source_runtime: matrix_runtime(pair.source),
        destination_runtime: matrix_runtime(pair.destination),
        host_os: std::env::consts::OS.to_owned(),
        host_isa: std::env::consts::ARCH.to_owned(),
        substrate: "substrate_host::SqliteProvider".to_owned(),
        original_artifact_root: original_relative.clone(),
        relocated_artifact_root: relocated_relative.clone(),
        component_sha256: sha256_hex(component::stage3a_bytes()),
        source_lock_sha256: STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256.to_owned(),
        sidecar_sha256: STAGE2_STRICT_WACOGO_SIDECAR_SHA256.to_owned(),
        fallback_runtime: None,
    };
    let environment =
        write_json_artifact(root, &format!("{receipt_root}/environment.json"), &environment)?;
    Ok(Stage3aCrossRuntimeCellRun {
        run_ordinal,
        cell_id: pair.cell_id(),
        source_runtime: matrix_runtime(pair.source),
        destination_runtime: matrix_runtime(pair.destination),
        source_identity: child.runtime.source.clone(),
        destination_identity: child.runtime.destination.clone(),
        handoff_topology: matrix_topology(pair),
        execution_boundary: pair.execution_boundary().to_owned(),
        original_bundle: reference_for_existing(
            root,
            &original_path,
            format!("{original_relative}/stage3a-evidence.json"),
        )?,
        relocated_bundle: reference_for_existing(
            root,
            &relocated_path,
            format!("{relocated_relative}/stage3a-evidence.json"),
        )?,
        validation_report,
        environment,
        normalized_semantics_sha256,
    })
}

fn publish_lineage(root: &Path) -> Result<Stage3aCrossRuntimeLineage, String> {
    Ok(Stage3aCrossRuntimeLineage {
        cargo_lock: copy_artifact(root, "Cargo.lock", "lineage/Cargo.lock")?,
        evidence_matrix: copy_artifact(
            root,
            "claims/evidence-matrix.json",
            "lineage/evidence-matrix.json",
        )?,
        regular_file_component: write_artifact(
            root,
            "lineage/stage3-file-component.component.wasm",
            component::stage3a_bytes(),
        )?,
        regular_file_wit: write_artifact(
            root,
            "lineage/regular-file-continuity.wit",
            include_bytes!("../../../../wit/regular-file-continuity/world.wit"),
        )?,
        wacogo_source_lock: copy_artifact(
            root,
            "third_party/wacogo/source-lock.json",
            "lineage/wacogo-source-lock.json",
        )?,
        wacogo_build_receipt: copy_artifact(
            root,
            "target/visa-wacogo/build-receipt.json",
            "lineage/wacogo-build-receipt.json",
        )?,
        wacogo_sidecar: copy_artifact(
            root,
            "target/visa-wacogo/visa-wacogo-runtime",
            "lineage/visa-wacogo-runtime",
        )?,
    })
}

fn copy_artifact(root: &Path, source: &str, uri: &str) -> Result<Stage3ArtifactReference, String> {
    let bytes = fs::read(source).map_err(|error| format!("cannot read {source}: {error}"))?;
    write_artifact(root, uri, &bytes)
}

fn reference_for_existing(
    root: &Path,
    path: &Path,
    uri: String,
) -> Result<Stage3ArtifactReference, String> {
    if path.strip_prefix(root).ok().and_then(Path::to_str) != Some(uri.as_str()) {
        return Err(format!("artifact path {} does not match URI {uri}", path.display()));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(Stage3ArtifactReference {
        uri,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        size: bytes.len() as u64,
    })
}

fn matrix_receipt(
    matrix: &EvidenceMatrix,
    cell: &Stage3aCrossRuntimeCellRun,
    verifier: EvidenceMatrixVerifierIdentity,
) -> Result<EvidenceMatrixCellReceipt, String> {
    let definition = matrix
        .cells
        .iter()
        .find(|definition| definition.id == cell.cell_id)
        .ok_or_else(|| format!("matrix does not contain {}", cell.cell_id))?;
    Ok(EvidenceMatrixCellReceipt {
        cell_id: cell.cell_id.clone(),
        run_ordinal: cell.run_ordinal,
        coordinates: EvidenceMatrixCoordinates::from(definition),
        evidence_bundle: matrix_reference(&cell.relocated_bundle),
        validation_report: matrix_reference(&cell.validation_report),
        environment: matrix_reference(&cell.environment),
        verifier_identity: verifier,
        expected_semantic_outcome: EvidenceMatrixSemanticOutcome::Accepted,
        observed_semantic_outcome: EvidenceMatrixSemanticOutcome::Accepted,
        relocated_verification: true,
    })
}

fn supporting_baseline_receipt(
    matrix: &EvidenceMatrix,
    cell: &Stage3aCrossRuntimeCellRun,
    verifier: EvidenceMatrixVerifierIdentity,
) -> Result<EvidenceMatrixCellReceipt, String> {
    let definition = matrix
        .cells
        .iter()
        .find(|definition| definition.id == "s3a.wasmtime-to-wasmtime.regular-file")
        .ok_or("matrix does not contain the Stage 3A supporting baseline")?;
    Ok(EvidenceMatrixCellReceipt {
        cell_id: definition.id.clone(),
        run_ordinal: 1,
        coordinates: EvidenceMatrixCoordinates::from(definition),
        evidence_bundle: matrix_reference(&cell.relocated_bundle),
        validation_report: matrix_reference(&cell.validation_report),
        environment: matrix_reference(&cell.environment),
        verifier_identity: verifier,
        expected_semantic_outcome: EvidenceMatrixSemanticOutcome::Accepted,
        observed_semantic_outcome: EvidenceMatrixSemanticOutcome::Accepted,
        relocated_verification: true,
    })
}

fn matrix_reference(reference: &Stage3ArtifactReference) -> EvidenceMatrixArtifactReference {
    EvidenceMatrixArtifactReference {
        uri: reference.uri.clone(),
        sha256: reference.sha256.clone(),
        size: reference.size,
    }
}

fn verifier_identity() -> Result<EvidenceMatrixVerifierIdentity, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve Stage 3A runner executable: {error}"))?;
    let bytes = fs::read(&executable)
        .map_err(|error| format!("cannot read {}: {error}", executable.display()))?;
    Ok(EvidenceMatrixVerifierIdentity {
        name: "visa-stage3-system::embedded-stage3a-verifier".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        executable_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn matrix_runtime(runtime: RegularFileRuntimeKind) -> MatrixRuntime {
    match runtime {
        RegularFileRuntimeKind::Wasmtime => MatrixRuntime::Wasmtime,
        RegularFileRuntimeKind::SourceLockedWacogo => MatrixRuntime::SourceLockedWacogo,
    }
}

fn matrix_topology(pair: RegularFileRuntimePair) -> visa_conformance::MatrixHandoffTopology {
    use visa_conformance::MatrixHandoffTopology;
    match (pair.source, pair.destination) {
        (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::Wasmtime) => {
            MatrixHandoffTopology::InProcessDistinctStores
        }
        (
            RegularFileRuntimeKind::SourceLockedWacogo,
            RegularFileRuntimeKind::SourceLockedWacogo,
        ) => MatrixHandoffTopology::RunnerWithDualSidecars,
        (RegularFileRuntimeKind::SourceLockedWacogo, RegularFileRuntimeKind::Wasmtime) => {
            MatrixHandoffTopology::RunnerWithSourceSidecar
        }
        (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::SourceLockedWacogo) => {
            MatrixHandoffTopology::RunnerWithDestinationSidecar
        }
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        return Err(format!("relocated artifact root already exists: {}", destination.display()));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((from, to)) = pending.pop() {
        for entry in fs::read_dir(&from)
            .map_err(|error| format!("cannot enumerate {}: {error}", from.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot inspect copy source: {error}"))?;
            let metadata = entry
                .metadata()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if entry.file_type().map_err(|error| error.to_string())?.is_symlink() {
                return Err(format!("copy source contains a symlink: {}", entry.path().display()));
            }
            let target = to.join(entry.file_name());
            if metadata.is_dir() {
                fs::create_dir(&target)
                    .map_err(|error| format!("cannot create {}: {error}", target.display()))?;
                pending.push((entry.path(), target));
            } else if metadata.is_file() {
                fs::copy(entry.path(), &target)
                    .map_err(|error| format!("cannot copy to {}: {error}", target.display()))?;
            } else {
                return Err(format!(
                    "copy source contains a special file: {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(())
}

fn create_root(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    if fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate {}: {error}", root.display()))?
        .next()
        .is_some()
    {
        return Err(format!("cross-runtime artifact root must be empty: {}", root.display()));
    }
    write_artifact(root, INCOMPLETE_MARKER, INCOMPLETE_CONTENT).map(|_| ())
}

fn git_output(arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("git output is not UTF-8: {error}"))
}

fn current_git_worktree_seal() -> Result<GitWorktreeSeal, String> {
    Ok(GitWorktreeSeal {
        sha: git_output(&["rev-parse", "HEAD"])?,
        dirty: !git_output(&["status", "--porcelain", "--untracked-files=normal"])?.is_empty(),
    })
}

fn require_unchanged_git_worktree_seal(
    initial: &GitWorktreeSeal,
    publication: &GitWorktreeSeal,
) -> Result<(), String> {
    if initial.sha != publication.sha {
        return Err(format!(
            "cross-runtime Stage 3A HEAD changed during evidence generation: {} -> {}",
            initial.sha, publication.sha
        ));
    }
    if initial.dirty != publication.dirty {
        return Err(format!(
            "cross-runtime Stage 3A worktree cleanliness changed during evidence generation: {} -> {}",
            initial.dirty, publication.dirty
        ));
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    u64::try_from(duration.as_millis()).map_err(|_| "timestamp does not fit u64".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{GitWorktreeSeal, require_unchanged_git_worktree_seal};

    fn seal(sha: char, dirty: bool) -> GitWorktreeSeal {
        GitWorktreeSeal { sha: sha.to_string().repeat(40), dirty }
    }

    #[test]
    fn publication_seal_accepts_an_unchanged_checkout() {
        assert!(require_unchanged_git_worktree_seal(&seal('a', false), &seal('a', false)).is_ok());
    }

    #[test]
    fn publication_seal_rejects_a_head_change() {
        let error =
            require_unchanged_git_worktree_seal(&seal('a', false), &seal('b', false)).unwrap_err();
        assert!(error.contains("HEAD changed"));
    }

    #[test]
    fn publication_seal_rejects_a_cleanliness_change() {
        let error =
            require_unchanged_git_worktree_seal(&seal('a', false), &seal('a', true)).unwrap_err();
        assert!(error.contains("cleanliness changed"));
    }
}
