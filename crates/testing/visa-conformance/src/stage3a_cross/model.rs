use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    EvidenceMatrixArtifactReference, MatrixHandoffTopology, MatrixRuntime, Stage3ArtifactReference,
    Stage3Assertion, Stage3CaseTerminal, Stage3EvidenceBundle, Stage3Profile,
    Stage3RuntimeIdentity,
};

pub const STAGE3A_CROSS_RUNTIME_EVIDENCE_SCHEMA_VERSION: &str =
    "visa-stage3a-cross-runtime-evidence-v1";
pub const STAGE3A_CROSS_RUNTIME_EVIDENCE_FILE: &str = "stage3a-cross-runtime-evidence.json";
pub const STAGE3A_CROSS_RUNTIME_MATRIX_RUN_FILE: &str = "evidence-matrix-run.json";
pub const STAGE3A_CROSS_RUNTIME_CLAIM_ID: &str = "cross-runtime-regular-file-continuity-v1";
pub const STAGE3A_CROSS_RUNTIME_REQUIRED_RUNS: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeLineage {
    pub cargo_lock: Stage3ArtifactReference,
    pub evidence_matrix: Stage3ArtifactReference,
    pub regular_file_component: Stage3ArtifactReference,
    pub regular_file_wit: Stage3ArtifactReference,
    pub wacogo_source_lock: Stage3ArtifactReference,
    pub wacogo_build_receipt: Stage3ArtifactReference,
    pub wacogo_sidecar: Stage3ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeEnvironment {
    pub schema_version: String,
    pub run_ordinal: u32,
    pub cell_id: String,
    pub source_runtime: MatrixRuntime,
    pub destination_runtime: MatrixRuntime,
    pub host_os: String,
    pub host_isa: String,
    pub substrate: String,
    pub original_artifact_root: String,
    pub relocated_artifact_root: String,
    pub component_sha256: String,
    pub source_lock_sha256: String,
    pub sidecar_sha256: String,
    pub fallback_runtime: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aNormalizedCase {
    pub case_id: String,
    pub terminal: Stage3CaseTerminal,
    pub passed: bool,
    pub assertions: Vec<Stage3Assertion>,
    pub canonical_before_sha256: String,
    pub canonical_after_sha256: String,
    pub source_epoch: u64,
    pub destination_epoch: Option<u64>,
    pub profile_operations: Vec<String>,
    pub file_before_sha256: String,
    pub file_before_size: u64,
    pub file_after_sha256: String,
    pub file_after_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aNormalizedSemantics {
    pub profile: Stage3Profile,
    pub registry_sha256: String,
    pub component_sha256: String,
    pub wit_world_sha256: String,
    pub cases: Vec<Stage3aNormalizedCase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeCellRun {
    pub run_ordinal: u32,
    pub cell_id: String,
    pub source_runtime: MatrixRuntime,
    pub destination_runtime: MatrixRuntime,
    pub source_identity: Stage3RuntimeIdentity,
    pub destination_identity: Stage3RuntimeIdentity,
    pub handoff_topology: MatrixHandoffTopology,
    pub execution_boundary: String,
    pub original_bundle: Stage3ArtifactReference,
    pub relocated_bundle: Stage3ArtifactReference,
    pub validation_report: Stage3ArtifactReference,
    pub environment: Stage3ArtifactReference,
    pub normalized_semantics_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeEvidenceBundle {
    pub schema_version: String,
    pub claim_id: String,
    pub bundle_id: String,
    pub git_sha: String,
    pub git_dirty: bool,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub matrix_sha256: String,
    pub required_runs_per_cell: u32,
    pub relocated_verification_required: bool,
    pub normalized_semantics_sha256: String,
    pub lineage: Stage3aCrossRuntimeLineage,
    pub matrix_run: Stage3ArtifactReference,
    pub cells: Vec<Stage3aCrossRuntimeCellRun>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage3aCrossRuntimeValidationFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aCrossRuntimeEvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage3aCrossRuntimeValidationFinding>,
    pub validation: Option<Stage3aCrossRuntimeValidationReport>,
}

pub fn normalize_stage3a_semantics(
    bundle: &Stage3EvidenceBundle,
) -> Result<Stage3aNormalizedSemantics, String> {
    if bundle.profile != Stage3Profile::RegularFile {
        return Err("normalized Stage 3A bundle is not the regular-file profile".to_owned());
    }
    let mut cases = Vec::with_capacity(bundle.cases.len());
    for case in &bundle.cases {
        let before = unique_artifact(&case.artifacts, "file-before.bin")?;
        let after = unique_artifact(&case.artifacts, "file-after.bin")?;
        cases.push(Stage3aNormalizedCase {
            case_id: case.case_id.clone(),
            terminal: case.terminal,
            passed: case.passed,
            assertions: case.assertions.clone(),
            canonical_before_sha256: case.canonical_before_sha256.clone(),
            canonical_after_sha256: case.canonical_after_sha256.clone(),
            source_epoch: case.source_epoch,
            destination_epoch: case.destination_epoch,
            profile_operations: case.profile_operations.clone(),
            file_before_sha256: before.sha256.clone(),
            file_before_size: before.size,
            file_after_sha256: after.sha256.clone(),
            file_after_size: after.size,
        });
    }
    Ok(Stage3aNormalizedSemantics {
        profile: bundle.profile,
        registry_sha256: bundle.registry_sha256.clone(),
        component_sha256: bundle.component.sha256.clone(),
        wit_world_sha256: bundle.wit_world.sha256.clone(),
        cases,
    })
}

pub fn normalized_stage3a_semantics_sha256(
    bundle: &Stage3EvidenceBundle,
) -> Result<String, String> {
    let normalized = normalize_stage3a_semantics(bundle)?;
    serde_json::to_vec(&normalized)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("cannot encode normalized Stage 3A semantics: {error}"))
}

fn unique_artifact<'a>(
    artifacts: &'a [Stage3ArtifactReference],
    suffix: &str,
) -> Result<&'a Stage3ArtifactReference, String> {
    let mut matches = artifacts.iter().filter(|artifact| artifact.uri.ends_with(suffix));
    let artifact = matches.next().ok_or_else(|| format!("missing {suffix} artifact"))?;
    if matches.next().is_some() {
        return Err(format!("duplicate {suffix} artifact"));
    }
    Ok(artifact)
}

impl From<&Stage3ArtifactReference> for EvidenceMatrixArtifactReference {
    fn from(reference: &Stage3ArtifactReference) -> Self {
        Self { uri: reference.uri.clone(), sha256: reference.sha256.clone(), size: reference.size }
    }
}
