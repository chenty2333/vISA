use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_regular_file_oracle::{
    DerivedAssertion, DerivedTerminal, ObservableProjection, evaluate_equivalence,
};

use crate::{
    EvidenceMatrixArtifactReference, MatrixHandoffTopology, MatrixRuntime,
    STAGE3A_CANDIDATE_OBSERVATION_FILE, STAGE3A_CONTROL_OBSERVATION_FILE, Stage3ArtifactReference,
    Stage3EvidenceBundle, Stage3Profile, Stage3RuntimeIdentity,
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
    pub terminal: DerivedTerminal,
    pub assertions: Vec<Stage3aNormalizedAssertion>,
    pub observable_projection: ObservableProjection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aNormalizedAssertion {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3aNormalizedSemantics {
    pub oracle_schema_version: String,
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
    artifact_root: &Path,
) -> Result<Stage3aNormalizedSemantics, String> {
    if bundle.profile != Stage3Profile::RegularFile {
        return Err("normalized Stage 3A bundle is not the regular-file profile".to_owned());
    }
    let control = fs::read(artifact_root.join(STAGE3A_CONTROL_OBSERVATION_FILE))
        .map_err(|error| format!("cannot read regular-file control observation: {error}"))?;
    let candidate = fs::read(artifact_root.join(STAGE3A_CANDIDATE_OBSERVATION_FILE))
        .map_err(|error| format!("cannot read regular-file candidate observation: {error}"))?;
    let oracle = evaluate_equivalence(&control, &candidate);
    if !oracle.accepted {
        return Err(format!(
            "independent regular-file oracle rejected the paired observation: {:?}",
            oracle.findings
        ));
    }
    let candidate_reports = oracle
        .candidate_validation
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let equivalence_cases =
        oracle.cases.iter().map(|case| (case.case_id.as_str(), case)).collect::<BTreeMap<_, _>>();
    let mut cases = Vec::with_capacity(Stage3Profile::RegularFile.cases().len());
    for definition in Stage3Profile::RegularFile.cases() {
        let report = candidate_reports
            .get(definition.id)
            .ok_or_else(|| format!("oracle report is missing {}", definition.id))?;
        let equivalence = equivalence_cases
            .get(definition.id)
            .ok_or_else(|| format!("equivalence report is missing {}", definition.id))?;
        if !equivalence.equivalent {
            return Err(format!("{} is not observably equivalent", definition.id));
        }
        cases.push(Stage3aNormalizedCase {
            case_id: definition.id.to_owned(),
            terminal: report.terminal.ok_or_else(|| {
                format!("{} has no independently derived terminal", definition.id)
            })?,
            assertions: normalized_assertions(&report.assertions),
            observable_projection: equivalence
                .candidate_projection
                .clone()
                .ok_or_else(|| format!("{} has no observable projection", definition.id))?,
        });
    }
    Ok(Stage3aNormalizedSemantics {
        oracle_schema_version: oracle.schema_version,
        profile: bundle.profile,
        registry_sha256: bundle.registry_sha256.clone(),
        component_sha256: bundle.component.sha256.clone(),
        wit_world_sha256: bundle.wit_world.sha256.clone(),
        cases,
    })
}

fn normalized_assertions(assertions: &[DerivedAssertion]) -> Vec<Stage3aNormalizedAssertion> {
    let mut canonical = assertions
        .iter()
        .map(|assertion| Stage3aNormalizedAssertion {
            name: assertion.name.clone(),
            passed: assertion.passed,
        })
        .collect::<Vec<_>>();
    canonical.sort_by(|left, right| {
        left.name.cmp(&right.name).then_with(|| left.passed.cmp(&right.passed))
    });
    canonical
}

pub fn normalized_stage3a_semantics_sha256(
    bundle: &Stage3EvidenceBundle,
    artifact_root: &Path,
) -> Result<String, String> {
    let normalized = normalize_stage3a_semantics(bundle, artifact_root)?;
    serde_json::to_vec(&normalized)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("cannot encode normalized Stage 3A semantics: {error}"))
}

impl From<&Stage3ArtifactReference> for EvidenceMatrixArtifactReference {
    fn from(reference: &Stage3ArtifactReference) -> Self {
        Self { uri: reference.uri.clone(), sha256: reference.sha256.clone(), size: reference.size }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_assertions_are_normalized_without_trace_sequence_noise() {
        let first = DerivedAssertion {
            name: "transient_observe_retried".to_owned(),
            passed: true,
            supporting_sequences: vec![7, 8],
        };
        let second = DerivedAssertion {
            name: "bytes_preserved".to_owned(),
            passed: true,
            supporting_sequences: vec![19],
        };

        assert_eq!(
            normalized_assertions(&[first, second]),
            vec![
                Stage3aNormalizedAssertion { name: "bytes_preserved".to_owned(), passed: true },
                Stage3aNormalizedAssertion {
                    name: "transient_observe_retried".to_owned(),
                    passed: true,
                },
            ]
        );
    }
}
