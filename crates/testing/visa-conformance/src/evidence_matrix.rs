use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::artifact_io::SecureArtifactRoot;

pub const EVIDENCE_MATRIX_SCHEMA_VERSION: &str = "visa.evidence-matrix.v1";
pub const EVIDENCE_MATRIX_RUN_SCHEMA_VERSION: &str = "visa.evidence-matrix-run.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixRuntime {
    JcoNode,
    NotApplicable,
    SourceLockedWacogo,
    WancoAot,
    Wasmtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixIsa {
    Aarch64,
    NotApplicable,
    X86_64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixSubstrate {
    LinuxHost,
    LinuxQemuUser,
    NeutralModel,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixEndpoint {
    pub runtime: MatrixRuntime,
    pub isa: MatrixIsa,
    pub substrate: MatrixSubstrate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixResourceProfile {
    JointHandoff,
    LogicalRequest,
    RegularFile,
    SqliteRollbackJournal,
    TimerKv,
    ZstdStreamingRegularFiles,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixHandoffTopology {
    InProcessDistinctStores,
    NeutralStateMachine,
    ProcessIsolatedWorkers,
    RunnerWithDestinationSidecar,
    RunnerWithDualSidecars,
    RunnerWithSourceSidecar,
    SameBootMultiProcess,
    VisaPlusWancoCarrier,
    VisaPlusWancoCarrierWithProviderHandoff,
    WancoCarrierOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixFaultModel {
    JointAdmissionLostAck,
    JointNeutralSixteenCase,
    Stage1ThirtyOneCase,
    Stage3aRegularFileTwelveCase,
    Stage3bLogicalRequestFourteenCase,
    Stage4Stage1ThirtyOneCase,
    SqliteRollbackEightCutPlusProcessCrash,
    WancoRegularFileTwoCase,
    ZstdTwoPostFdWriteCutsPlusNegatives,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixVerifier {
    JointAdmissionArtifactStatic,
    JointArtifactStatic,
    JointNeutralOracle,
    RegularFileRawObservableOracle,
    Stage1ArtifactSemantic,
    Stage2OuterNormalized,
    Stage2StrictOuterNormalized,
    Stage3Structural,
    Stage3aCrossRuntimeOuterAndRawOracle,
    Stage4ReconstructedNormalized,
    SqliteNamespaceNativeOracle,
    NativeZstdDecompressionAndControlByteIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixCellDisposition {
    Candidate,
    DeclaredGap,
    Qualified,
}

/// The semantic disposition a validation report is expected to establish.
///
/// This is intentionally separate from a generic `passed` bit: a negative
/// control is successful when the independent oracle rejects equivalence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceMatrixSemanticOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixCell {
    pub id: String,
    pub source: MatrixEndpoint,
    pub destination: MatrixEndpoint,
    pub resource_profile: MatrixResourceProfile,
    pub handoff_topology: MatrixHandoffTopology,
    pub fault_model: MatrixFaultModel,
    pub verifier: MatrixVerifier,
    pub disposition: MatrixCellDisposition,
    pub claim_ids: Vec<String>,
    pub workflow_binding_ids: Vec<String>,
    pub evidence_boundary: String,
    pub non_claims: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixClaimRequirement {
    pub claim_id: String,
    pub required_cells: Vec<String>,
    pub supporting_cells: Vec<String>,
    pub minimum_required_runs_per_cell: u32,
    pub minimum_supporting_runs_per_cell: u32,
    pub requires_clean_git: bool,
    pub requires_relocated_verification: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrix {
    pub schema_version: String,
    pub cells: Vec<EvidenceMatrixCell>,
    pub claim_requirements: Vec<EvidenceMatrixClaimRequirement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixValidationReport {
    pub ok: bool,
    pub matrix_sha256: Option<String>,
    pub cell_count: usize,
    pub claim_count: usize,
    pub findings: Vec<EvidenceMatrixFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixArtifactReference {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixVerifierIdentity {
    pub name: String,
    pub version: String,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixCoordinates {
    pub source: MatrixEndpoint,
    pub destination: MatrixEndpoint,
    pub resource_profile: MatrixResourceProfile,
    pub handoff_topology: MatrixHandoffTopology,
    pub fault_model: MatrixFaultModel,
    pub verifier: MatrixVerifier,
}

impl From<&EvidenceMatrixCell> for EvidenceMatrixCoordinates {
    fn from(cell: &EvidenceMatrixCell) -> Self {
        Self {
            source: cell.source.clone(),
            destination: cell.destination.clone(),
            resource_profile: cell.resource_profile,
            handoff_topology: cell.handoff_topology,
            fault_model: cell.fault_model,
            verifier: cell.verifier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixCellReceipt {
    pub cell_id: String,
    pub run_ordinal: u32,
    pub coordinates: EvidenceMatrixCoordinates,
    pub evidence_bundle: EvidenceMatrixArtifactReference,
    pub validation_report: EvidenceMatrixArtifactReference,
    pub environment: EvidenceMatrixArtifactReference,
    pub verifier_identity: EvidenceMatrixVerifierIdentity,
    pub expected_semantic_outcome: EvidenceMatrixSemanticOutcome,
    pub observed_semantic_outcome: EvidenceMatrixSemanticOutcome,
    pub relocated_verification: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixRun {
    pub schema_version: String,
    pub matrix_sha256: String,
    pub git_sha: String,
    pub git_dirty: bool,
    pub run_id: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub claim_ids: Vec<String>,
    pub receipts: Vec<EvidenceMatrixCellReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixClaimClosure {
    pub claim_id: String,
    pub closed: bool,
    pub missing_required_cells: Vec<String>,
    pub missing_supporting_cells: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatrixRunValidationReport {
    pub ok: bool,
    pub matrix_sha256: Option<String>,
    pub git_sha: Option<String>,
    pub claim_closures: Vec<EvidenceMatrixClaimClosure>,
    pub findings: Vec<EvidenceMatrixFinding>,
}

pub fn parse_evidence_matrix_json(bytes: &[u8]) -> Result<EvidenceMatrix, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn validate_evidence_matrix_json(bytes: &[u8]) -> EvidenceMatrixValidationReport {
    let matrix = match parse_evidence_matrix_json(bytes) {
        Ok(matrix) => matrix,
        Err(detail) => {
            return EvidenceMatrixValidationReport {
                ok: false,
                matrix_sha256: None,
                cell_count: 0,
                claim_count: 0,
                findings: vec![EvidenceMatrixFinding {
                    code: "invalid-evidence-matrix-json".to_owned(),
                    detail,
                }],
            };
        }
    };
    validate_evidence_matrix(&matrix)
}

pub fn validate_evidence_matrix(matrix: &EvidenceMatrix) -> EvidenceMatrixValidationReport {
    let mut findings = Vec::new();
    if matrix.schema_version != EVIDENCE_MATRIX_SCHEMA_VERSION {
        finding(
            &mut findings,
            "unknown-evidence-matrix-schema",
            format!("expected {EVIDENCE_MATRIX_SCHEMA_VERSION}, found {}", matrix.schema_version),
        );
    }
    if matrix.cells.is_empty() {
        finding(&mut findings, "empty-evidence-matrix", "the matrix has no cells");
    }
    if matrix.claim_requirements.is_empty() {
        finding(&mut findings, "empty-evidence-claims", "the matrix has no claim requirements");
    }

    let mut cells = BTreeMap::new();
    let mut cell_order = Vec::new();
    let mut coordinates = BTreeSet::new();
    for cell in &matrix.cells {
        cell_order.push(cell.id.as_str());
        if !valid_id(&cell.id) {
            finding(
                &mut findings,
                "invalid-evidence-cell-id",
                format!("invalid cell ID {:?}", cell.id),
            );
        }
        if cells.insert(cell.id.as_str(), cell).is_some() {
            finding(
                &mut findings,
                "duplicate-evidence-cell-id",
                format!("duplicate cell ID {}", cell.id),
            );
        }
        require_sorted_unique(&cell.claim_ids, &format!("{} claim_ids", cell.id), &mut findings);
        require_sorted_unique(
            &cell.workflow_binding_ids,
            &format!("{} workflow_binding_ids", cell.id),
            &mut findings,
        );
        require_sorted_unique(&cell.non_claims, &format!("{} non_claims", cell.id), &mut findings);
        if cell.evidence_boundary.trim().is_empty() || cell.non_claims.is_empty() {
            finding(
                &mut findings,
                "incomplete-evidence-cell-boundary",
                format!("{} must state an evidence boundary and at least one non-claim", cell.id),
            );
        }
        match cell.disposition {
            MatrixCellDisposition::DeclaredGap => {
                if !cell.claim_ids.is_empty() || !cell.workflow_binding_ids.is_empty() {
                    finding(
                        &mut findings,
                        "declared-gap-has-evidence-binding",
                        format!("{} is a gap but binds a claim or workflow", cell.id),
                    );
                }
            }
            MatrixCellDisposition::Candidate | MatrixCellDisposition::Qualified => {
                if cell.claim_ids.is_empty() || cell.workflow_binding_ids.is_empty() {
                    finding(
                        &mut findings,
                        "unbound-evidence-cell",
                        format!("{} must bind at least one claim and workflow", cell.id),
                    );
                }
            }
        }
        validate_endpoint(&cell.id, "source", &cell.source, &mut findings);
        validate_endpoint(&cell.id, "destination", &cell.destination, &mut findings);
        let coordinate = (
            cell.source.clone(),
            cell.destination.clone(),
            cell.resource_profile,
            cell.handoff_topology,
            cell.fault_model,
            cell.verifier,
        );
        if !coordinates.insert(coordinate) {
            finding(
                &mut findings,
                "duplicate-evidence-coordinate",
                format!("{} duplicates an existing six-dimensional coordinate", cell.id),
            );
        }
    }
    if cell_order.windows(2).any(|pair| pair[0] >= pair[1]) {
        finding(
            &mut findings,
            "unsorted-evidence-cells",
            "evidence cells must be strictly sorted by ID",
        );
    }

    let mut requirements = BTreeMap::new();
    let mut requirement_order = Vec::new();
    let mut referenced_cells = BTreeSet::new();
    for requirement in &matrix.claim_requirements {
        requirement_order.push(requirement.claim_id.as_str());
        if !valid_id(&requirement.claim_id) {
            finding(
                &mut findings,
                "invalid-evidence-claim-id",
                format!("invalid claim ID {:?}", requirement.claim_id),
            );
        }
        if requirements.insert(requirement.claim_id.as_str(), requirement).is_some() {
            finding(
                &mut findings,
                "duplicate-evidence-claim-id",
                format!("duplicate claim requirement {}", requirement.claim_id),
            );
        }
        require_sorted_unique(
            &requirement.required_cells,
            &format!("{} required_cells", requirement.claim_id),
            &mut findings,
        );
        require_sorted_unique(
            &requirement.supporting_cells,
            &format!("{} supporting_cells", requirement.claim_id),
            &mut findings,
        );
        if requirement.required_cells.is_empty() {
            finding(
                &mut findings,
                "claim-without-required-evidence",
                format!("{} has no required cells", requirement.claim_id),
            );
        }
        if requirement.minimum_required_runs_per_cell == 0
            || requirement.minimum_supporting_runs_per_cell == 0
        {
            finding(
                &mut findings,
                "invalid-evidence-stability-policy",
                format!("{} requires a nonzero run count", requirement.claim_id),
            );
        }
        for cell_id in requirement.required_cells.iter().chain(&requirement.supporting_cells) {
            referenced_cells.insert(cell_id.as_str());
            match cells.get(cell_id.as_str()) {
                None => finding(
                    &mut findings,
                    "unknown-claim-evidence-cell",
                    format!("{} references unknown cell {cell_id}", requirement.claim_id),
                ),
                Some(cell) if cell.disposition == MatrixCellDisposition::DeclaredGap => finding(
                    &mut findings,
                    "claim-requires-declared-gap",
                    format!("{} references declared gap {cell_id}", requirement.claim_id),
                ),
                Some(cell) if !cell.claim_ids.iter().any(|id| id == &requirement.claim_id) => {
                    finding(
                        &mut findings,
                        "asymmetric-claim-cell-binding",
                        format!("{cell_id} does not bind claim {}", requirement.claim_id),
                    )
                }
                Some(_) => {}
            }
        }
        let overlap = requirement
            .required_cells
            .iter()
            .filter(|cell| requirement.supporting_cells.contains(cell))
            .collect::<Vec<_>>();
        if !overlap.is_empty() {
            finding(
                &mut findings,
                "overlapping-required-and-supporting-cells",
                format!("{} repeats cells in both sets: {overlap:?}", requirement.claim_id),
            );
        }
    }
    if requirement_order.windows(2).any(|pair| pair[0] >= pair[1]) {
        finding(
            &mut findings,
            "unsorted-evidence-claims",
            "claim requirements must be strictly sorted by claim ID",
        );
    }

    for cell in
        matrix.cells.iter().filter(|cell| cell.disposition != MatrixCellDisposition::DeclaredGap)
    {
        if !referenced_cells.contains(cell.id.as_str()) {
            finding(
                &mut findings,
                "orphaned-evidence-cell",
                format!("{} is not required or supporting evidence for any claim", cell.id),
            );
        }
        for claim_id in &cell.claim_ids {
            let symmetric = requirements.get(claim_id.as_str()).is_some_and(|requirement| {
                requirement.required_cells.contains(&cell.id)
                    || requirement.supporting_cells.contains(&cell.id)
            });
            if !symmetric {
                finding(
                    &mut findings,
                    "asymmetric-cell-claim-binding",
                    format!(
                        "{} binds {claim_id}, but the claim does not reference the cell",
                        cell.id
                    ),
                );
            }
        }
    }

    let matrix_sha256 =
        serde_json::to_vec(matrix).ok().map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    EvidenceMatrixValidationReport {
        ok: findings.is_empty(),
        matrix_sha256,
        cell_count: matrix.cells.len(),
        claim_count: matrix.claim_requirements.len(),
        findings,
    }
}

pub fn parse_evidence_matrix_run_json(bytes: &[u8]) -> Result<EvidenceMatrixRun, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn evidence_matrix_sha256(matrix: &EvidenceMatrix) -> Result<String, String> {
    serde_json::to_vec(matrix)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| error.to_string())
}

pub fn validate_evidence_matrix_run_json(
    matrix_bytes: &[u8],
    run_bytes: &[u8],
    artifact_root: &Path,
) -> EvidenceMatrixRunValidationReport {
    let matrix = match parse_evidence_matrix_json(matrix_bytes) {
        Ok(matrix) => matrix,
        Err(detail) => {
            return run_load_failure("invalid-evidence-matrix-json", detail);
        }
    };
    let matrix_report = validate_evidence_matrix(&matrix);
    if !matrix_report.ok {
        return EvidenceMatrixRunValidationReport {
            ok: false,
            matrix_sha256: matrix_report.matrix_sha256,
            git_sha: None,
            claim_closures: Vec::new(),
            findings: matrix_report.findings,
        };
    }
    let run = match parse_evidence_matrix_run_json(run_bytes) {
        Ok(run) => run,
        Err(detail) => return run_load_failure("invalid-evidence-matrix-run-json", detail),
    };
    validate_evidence_matrix_run(&matrix, &run, artifact_root)
}

pub fn validate_evidence_matrix_run(
    matrix: &EvidenceMatrix,
    run: &EvidenceMatrixRun,
    artifact_root: &Path,
) -> EvidenceMatrixRunValidationReport {
    let mut findings = Vec::new();
    let secure_artifact_root = match SecureArtifactRoot::open(artifact_root) {
        Ok(root) => Some(root),
        Err(error) => {
            finding(&mut findings, "invalid-evidence-matrix-artifact-root", error.to_string());
            None
        }
    };
    let matrix_sha256 = evidence_matrix_sha256(matrix).ok();
    if run.schema_version != EVIDENCE_MATRIX_RUN_SCHEMA_VERSION {
        finding(
            &mut findings,
            "unknown-evidence-matrix-run-schema",
            format!("expected {EVIDENCE_MATRIX_RUN_SCHEMA_VERSION}, found {}", run.schema_version),
        );
    }
    if matrix_sha256.as_deref() != Some(run.matrix_sha256.as_str()) {
        finding(
            &mut findings,
            "evidence-matrix-run-digest-mismatch",
            "run does not bind the supplied canonical matrix",
        );
    }
    if !lower_hex(&run.git_sha, 40) {
        finding(
            &mut findings,
            "invalid-evidence-matrix-git-sha",
            "run Git revision must be one exact lowercase SHA",
        );
    }
    if !valid_id(&run.run_id) || run.finished_at_unix_ms < run.started_at_unix_ms {
        finding(
            &mut findings,
            "invalid-evidence-matrix-run-identity",
            "run ID or timestamps are invalid",
        );
    }
    require_sorted_unique(&run.claim_ids, "matrix run claim_ids", &mut findings);

    let cells =
        matrix.cells.iter().map(|cell| (cell.id.as_str(), cell)).collect::<BTreeMap<_, _>>();
    let requirements = matrix
        .claim_requirements
        .iter()
        .map(|requirement| (requirement.claim_id.as_str(), requirement))
        .collect::<BTreeMap<_, _>>();
    for claim_id in &run.claim_ids {
        if !requirements.contains_key(claim_id.as_str()) {
            finding(
                &mut findings,
                "unknown-evidence-matrix-run-claim",
                format!("run requests unknown claim {claim_id}"),
            );
        }
    }

    let mut receipt_keys = BTreeSet::new();
    let mut previous_key: Option<(&str, u32)> = None;
    let mut successful_runs: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
    let mut relocated_runs: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
    for receipt in &run.receipts {
        let receipt_findings = findings.len();
        let key = (receipt.cell_id.as_str(), receipt.run_ordinal);
        if previous_key.is_some_and(|previous| previous >= key) {
            finding(
                &mut findings,
                "unsorted-evidence-matrix-receipts",
                "cell receipts must be strictly sorted by cell ID and run ordinal",
            );
        }
        previous_key = Some(key);
        if !receipt_keys.insert(key) {
            finding(
                &mut findings,
                "duplicate-evidence-matrix-receipt",
                format!("duplicate receipt {} run {}", receipt.cell_id, receipt.run_ordinal),
            );
        }
        if receipt.run_ordinal == 0 {
            finding(
                &mut findings,
                "invalid-evidence-matrix-run-ordinal",
                format!("{} has run ordinal zero", receipt.cell_id),
            );
        }
        let Some(cell) = cells.get(receipt.cell_id.as_str()) else {
            finding(
                &mut findings,
                "unknown-evidence-matrix-receipt-cell",
                format!("receipt references unknown cell {}", receipt.cell_id),
            );
            continue;
        };
        if cell.disposition == MatrixCellDisposition::DeclaredGap {
            finding(
                &mut findings,
                "receipt-for-declared-gap",
                format!("{} is a declared gap", receipt.cell_id),
            );
        }
        if receipt.coordinates != EvidenceMatrixCoordinates::from(*cell) {
            finding(
                &mut findings,
                "evidence-matrix-receipt-coordinate-mismatch",
                format!("{} does not reproduce its six-dimensional coordinate", receipt.cell_id),
            );
        }
        let evidence_bundle = validate_matrix_artifact(
            &receipt.cell_id,
            "evidence bundle",
            &receipt.evidence_bundle,
            secure_artifact_root.as_ref(),
            &mut findings,
        );
        let validation_report = validate_matrix_artifact(
            &receipt.cell_id,
            "validation report",
            &receipt.validation_report,
            secure_artifact_root.as_ref(),
            &mut findings,
        );
        let environment = validate_matrix_artifact(
            &receipt.cell_id,
            "environment",
            &receipt.environment,
            secure_artifact_root.as_ref(),
            &mut findings,
        );
        if receipt.verifier_identity.name.trim().is_empty()
            || receipt.verifier_identity.version.trim().is_empty()
            || !lower_hex(&receipt.verifier_identity.executable_sha256, 64)
        {
            finding(
                &mut findings,
                "invalid-evidence-matrix-verifier-identity",
                format!("{} has an invalid verifier identity", receipt.cell_id),
            );
        }
        let canonical_expected = expected_semantic_outcome(cell);
        let wanco_cell = matches!(
            cell.handoff_topology,
            MatrixHandoffTopology::WancoCarrierOnly | MatrixHandoffTopology::VisaPlusWancoCarrier
        );
        if wanco_cell && let Some(bytes) = evidence_bundle.as_deref() {
            validate_wanco_evidence_bundle(
                secure_artifact_root.as_ref(),
                &receipt.cell_id,
                receipt.run_ordinal,
                canonical_expected,
                bytes,
                &mut findings,
            );
        }
        if receipt.relocated_verification
            && wanco_cell
            && let Some(bytes) = environment.as_deref()
        {
            validate_wanco_relocation_environment(
                artifact_root,
                &receipt.cell_id,
                receipt.run_ordinal,
                bytes,
                &mut findings,
            );
        }
        if receipt.expected_semantic_outcome != canonical_expected {
            finding(
                &mut findings,
                "evidence-matrix-expected-outcome-mismatch",
                format!(
                    "{} declares {:?}, but its matrix coordinate requires {:?}",
                    receipt.cell_id, receipt.expected_semantic_outcome, canonical_expected
                ),
            );
        }
        let independently_observed = validation_report.as_deref().and_then(|bytes| {
            observe_semantic_outcome(cell, bytes, canonical_expected, &mut findings)
        });
        if independently_observed != Some(receipt.observed_semantic_outcome) {
            finding(
                &mut findings,
                "evidence-matrix-observed-outcome-mismatch",
                format!(
                    "{} receipt reports {:?}, independently derived outcome is {:?}",
                    receipt.cell_id, receipt.observed_semantic_outcome, independently_observed
                ),
            );
        }
        if receipt.observed_semantic_outcome != receipt.expected_semantic_outcome {
            finding(
                &mut findings,
                "failed-evidence-matrix-cell",
                format!(
                    "{} run {} observed {:?}, expected {:?}",
                    receipt.cell_id,
                    receipt.run_ordinal,
                    receipt.observed_semantic_outcome,
                    receipt.expected_semantic_outcome
                ),
            );
        }
        if findings.len() == receipt_findings {
            successful_runs
                .entry(receipt.cell_id.as_str())
                .or_default()
                .insert(receipt.run_ordinal);
            if receipt.relocated_verification {
                relocated_runs
                    .entry(receipt.cell_id.as_str())
                    .or_default()
                    .insert(receipt.run_ordinal);
            }
        }
    }

    let mut claim_closures = Vec::new();
    for claim_id in &run.claim_ids {
        let Some(requirement) = requirements.get(claim_id.as_str()) else { continue };
        let missing_required_cells = missing_cells(
            &requirement.required_cells,
            requirement.minimum_required_runs_per_cell,
            requirement.requires_relocated_verification,
            &successful_runs,
            &relocated_runs,
        );
        let missing_supporting_cells = missing_cells(
            &requirement.supporting_cells,
            requirement.minimum_supporting_runs_per_cell,
            false,
            &successful_runs,
            &relocated_runs,
        );
        if requirement.requires_clean_git && run.git_dirty {
            finding(
                &mut findings,
                "dirty-evidence-matrix-run",
                format!("{claim_id} requires a clean exact-SHA run"),
            );
        }
        let closed = missing_required_cells.is_empty()
            && missing_supporting_cells.is_empty()
            && (!requirement.requires_clean_git || !run.git_dirty);
        if !closed {
            finding(
                &mut findings,
                "incomplete-evidence-matrix-claim",
                format!("{claim_id} lacks its required matrix closure"),
            );
        }
        claim_closures.push(EvidenceMatrixClaimClosure {
            claim_id: claim_id.clone(),
            closed,
            missing_required_cells,
            missing_supporting_cells,
        });
    }

    EvidenceMatrixRunValidationReport {
        ok: findings.is_empty() && claim_closures.iter().all(|claim| claim.closed),
        matrix_sha256,
        git_sha: Some(run.git_sha.clone()),
        claim_closures,
        findings,
    }
}

fn missing_cells(
    cell_ids: &[String],
    minimum_runs: u32,
    relocation_required: bool,
    successful_runs: &BTreeMap<&str, BTreeSet<u32>>,
    relocated_runs: &BTreeMap<&str, BTreeSet<u32>>,
) -> Vec<String> {
    cell_ids
        .iter()
        .filter(|cell_id| {
            let successful = successful_runs.get(cell_id.as_str()).map_or(0, BTreeSet::len);
            let relocated = relocated_runs.get(cell_id.as_str()).map_or(0, BTreeSet::len);
            successful < minimum_runs as usize
                || (relocation_required && relocated < minimum_runs as usize)
        })
        .cloned()
        .collect()
}

fn validate_matrix_artifact(
    cell_id: &str,
    label: &str,
    artifact: &EvidenceMatrixArtifactReference,
    root: Option<&SecureArtifactRoot>,
    findings: &mut Vec<EvidenceMatrixFinding>,
) -> Option<Vec<u8>> {
    if !safe_relative_uri(&artifact.uri) || !lower_hex(&artifact.sha256, 64) || artifact.size == 0 {
        finding(
            findings,
            "invalid-evidence-matrix-artifact",
            format!("{cell_id} has an invalid {label} reference"),
        );
        return None;
    }
    let root = root?;
    let bytes = match root.read_single_link_regular(&artifact.uri, 256 * 1024 * 1024) {
        Ok(artifact) => artifact.bytes,
        Err(error) => {
            finding(
                findings,
                "unreadable-evidence-matrix-artifact",
                format!("{cell_id} {label} {}: {error}", artifact.uri),
            );
            return None;
        }
    };
    if bytes.len() as u64 != artifact.size {
        finding(
            findings,
            "evidence-matrix-artifact-size-mismatch",
            format!(
                "{cell_id} {label} {} declares {} bytes, found {}",
                artifact.uri,
                artifact.size,
                bytes.len()
            ),
        );
        return None;
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != artifact.sha256 {
        finding(
            findings,
            "evidence-matrix-artifact-digest-mismatch",
            format!(
                "{cell_id} {label} {} declares {}, found {digest}",
                artifact.uri, artifact.sha256
            ),
        );
        return None;
    }
    Some(bytes)
}

fn expected_semantic_outcome(cell: &EvidenceMatrixCell) -> EvidenceMatrixSemanticOutcome {
    if cell.handoff_topology == MatrixHandoffTopology::WancoCarrierOnly {
        EvidenceMatrixSemanticOutcome::Rejected
    } else {
        EvidenceMatrixSemanticOutcome::Accepted
    }
}

fn validate_wanco_evidence_bundle(
    root: Option<&SecureArtifactRoot>,
    cell_id: &str,
    run_ordinal: u32,
    expected: EvidenceMatrixSemanticOutcome,
    bytes: &[u8],
    findings: &mut Vec<EvidenceMatrixFinding>,
) {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            finding(
                findings,
                "invalid-wanco-canonical-evidence-bundle",
                format!("{cell_id} evidence bundle is not JSON: {error}"),
            );
            return;
        }
    };
    let expected_wire = match expected {
        EvidenceMatrixSemanticOutcome::Accepted => "accepted",
        EvidenceMatrixSemanticOutcome::Rejected => "rejected",
    };
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("visa-wanco-carrier-paired-evidence-v1")
        || value.get("cell_id").and_then(serde_json::Value::as_str) != Some(cell_id)
        || value.get("run_ordinal").and_then(serde_json::Value::as_u64)
            != Some(u64::from(run_ordinal))
        || value.get("expected_oracle_outcome").and_then(serde_json::Value::as_str)
            != Some(expected_wire)
    {
        finding(
            findings,
            "invalid-wanco-canonical-evidence-bundle",
            format!("{cell_id} run {run_ordinal} evidence metadata does not bind its receipt"),
        );
    }
    let mut references = Vec::new();
    collect_embedded_artifact_references(&value, &mut references, findings, cell_id);
    if references.is_empty() {
        finding(
            findings,
            "empty-wanco-canonical-evidence-bundle",
            format!("{cell_id} run {run_ordinal} has no retained evidence references"),
        );
    }
    for reference in references {
        validate_matrix_artifact(cell_id, "embedded evidence", &reference, root, findings);
    }
}

fn collect_embedded_artifact_references(
    value: &serde_json::Value,
    output: &mut Vec<EvidenceMatrixArtifactReference>,
    findings: &mut Vec<EvidenceMatrixFinding>,
    cell_id: &str,
) {
    match value {
        serde_json::Value::Object(object)
            if object.contains_key("uri")
                || object.contains_key("sha256")
                || object.contains_key("size") =>
        {
            if object.len() != 3
                || !object.contains_key("uri")
                || !object.contains_key("sha256")
                || !object.contains_key("size")
            {
                finding(
                    findings,
                    "invalid-embedded-evidence-matrix-artifact",
                    format!("{cell_id} contains a partial or extended artifact reference"),
                );
                return;
            }
            match serde_json::from_value::<EvidenceMatrixArtifactReference>(value.clone()) {
                Ok(reference) => output.push(reference),
                Err(error) => finding(
                    findings,
                    "invalid-embedded-evidence-matrix-artifact",
                    format!("{cell_id} contains an invalid artifact reference: {error}"),
                ),
            }
        }
        serde_json::Value::Object(object) => {
            for nested in object.values() {
                collect_embedded_artifact_references(nested, output, findings, cell_id);
            }
        }
        serde_json::Value::Array(array) => {
            for nested in array {
                collect_embedded_artifact_references(nested, output, findings, cell_id);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOracleReport {
    schema_version: String,
    accepted: bool,
    #[allow(dead_code)]
    control_bundle_id: Option<String>,
    #[allow(dead_code)]
    candidate_bundle_id: Option<String>,
    control_validation: CanonicalOracleBundle,
    candidate_validation: CanonicalOracleBundle,
    cases: Vec<CanonicalOracleCase>,
    findings: Vec<CanonicalOracleFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOracleBundle {
    schema_version: String,
    #[allow(dead_code)]
    bundle_id: Option<String>,
    route_mode: Option<String>,
    accepted: bool,
    #[allow(dead_code)]
    cases: Vec<serde_json::Value>,
    #[allow(dead_code)]
    findings: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOracleCase {
    case_id: String,
    equivalent: bool,
    control_projection: Option<serde_json::Value>,
    candidate_projection: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOracleFinding {
    code: String,
    case_id: Option<String>,
    #[allow(dead_code)]
    detail: String,
}

fn observe_semantic_outcome(
    cell: &EvidenceMatrixCell,
    bytes: &[u8],
    expected: EvidenceMatrixSemanticOutcome,
    findings: &mut Vec<EvidenceMatrixFinding>,
) -> Option<EvidenceMatrixSemanticOutcome> {
    if cell.handoff_topology == MatrixHandoffTopology::WancoCarrierOnly
        || cell.handoff_topology == MatrixHandoffTopology::VisaPlusWancoCarrier
    {
        return observe_wanco_oracle(bytes, cell, expected, findings);
    }
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            finding(
                findings,
                "invalid-evidence-matrix-validation-report",
                format!("{} validation report is not JSON: {error}", cell.id),
            );
            return None;
        }
    };
    let observed = value
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .or_else(|| value.get("accepted").and_then(serde_json::Value::as_bool));
    match observed {
        Some(true) => Some(EvidenceMatrixSemanticOutcome::Accepted),
        Some(false) => Some(EvidenceMatrixSemanticOutcome::Rejected),
        None => {
            finding(
                findings,
                "missing-evidence-matrix-semantic-outcome",
                format!("{} validation report has no boolean ok/accepted outcome", cell.id),
            );
            None
        }
    }
}

fn observe_wanco_oracle(
    bytes: &[u8],
    cell: &EvidenceMatrixCell,
    expected: EvidenceMatrixSemanticOutcome,
    findings: &mut Vec<EvidenceMatrixFinding>,
) -> Option<EvidenceMatrixSemanticOutcome> {
    let report: CanonicalOracleReport = match serde_json::from_slice(bytes) {
        Ok(report) => report,
        Err(error) => {
            finding(
                findings,
                "invalid-wanco-oracle-report",
                format!("{} validation report is not a canonical oracle report: {error}", cell.id),
            );
            return None;
        }
    };
    let expected_route = match cell.handoff_topology {
        MatrixHandoffTopology::WancoCarrierOnly => "carrier_only",
        MatrixHandoffTopology::VisaPlusWancoCarrier => "visa_plus_carrier",
        _ => unreachable!("observe_wanco_oracle only accepts Wanco topologies"),
    };
    let case_ids = BTreeSet::from(["read-write-offset".to_owned(), "append-continuity".to_owned()]);
    let observed = if report.schema_version
        != visa_regular_file_oracle::EQUIVALENCE_REPORT_SCHEMA_VERSION
        || report.control_validation.schema_version
            != visa_regular_file_oracle::ORACLE_REPORT_SCHEMA_VERSION
        || report.candidate_validation.schema_version
            != visa_regular_file_oracle::ORACLE_REPORT_SCHEMA_VERSION
        || report.control_validation.route_mode.as_deref() != Some("uninterrupted_control")
        || report.candidate_validation.route_mode.as_deref() != Some(expected_route)
        || !report.control_validation.accepted
        || report.cases.len() != case_ids.len()
        || report.cases.iter().map(|case| case.case_id.as_str()).collect::<BTreeSet<_>>()
            != case_ids.iter().map(String::as_str).collect::<BTreeSet<_>>()
        || report
            .cases
            .iter()
            .any(|case| case.control_projection.is_none() || case.candidate_projection.is_none())
    {
        finding(
            findings,
            "invalid-wanco-oracle-semantics",
            format!("{} Wanco report does not contain the fixed two-case oracle shape", cell.id),
        );
        return None;
    } else if expected == EvidenceMatrixSemanticOutcome::Rejected {
        let expected_findings = BTreeSet::from([
            ("read-write-offset".to_owned(), "observable-projection-mismatch".to_owned()),
            ("append-continuity".to_owned(), "observable-projection-mismatch".to_owned()),
        ]);
        let actual_findings = report
            .findings
            .iter()
            .filter_map(|finding| {
                finding.case_id.clone().map(|case_id| (case_id, finding.code.clone()))
            })
            .collect::<BTreeSet<_>>();
        if report.accepted
            || report.candidate_validation.accepted
            || report.cases.iter().any(|case| case.equivalent)
            || report.findings.len() != case_ids.len()
            || actual_findings != expected_findings
        {
            finding(
                findings,
                "invalid-wanco-negative-oracle-semantics",
                format!(
                    "{} negative cell did not produce exactly the two expected mismatches",
                    cell.id
                ),
            );
            return None;
        }
        EvidenceMatrixSemanticOutcome::Rejected
    } else {
        if !report.accepted
            || !report.candidate_validation.accepted
            || !report.findings.is_empty()
            || report.cases.iter().any(|case| !case.equivalent)
        {
            finding(
                findings,
                "invalid-wanco-positive-oracle-semantics",
                format!(
                    "{} positive cell did not produce an accepted two-case equivalence",
                    cell.id
                ),
            );
            return None;
        }
        EvidenceMatrixSemanticOutcome::Accepted
    };
    Some(observed)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WancoCanonicalEnvironment {
    schema: String,
    cell_id: String,
    run_ordinal: u32,
    #[allow(dead_code)]
    coordinates: serde_json::Value,
    #[allow(dead_code)]
    git_sha: String,
    #[allow(dead_code)]
    git_dirty: bool,
    #[allow(dead_code)]
    host: serde_json::Value,
    #[allow(dead_code)]
    wanco: serde_json::Value,
    #[allow(dead_code)]
    producer_sha256: String,
    #[allow(dead_code)]
    standalone_oracle_sha256: String,
    container_security: WancoContainerSecurityEnvironment,
    relocation: WancoRelocationEnvironment,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WancoContainerSecurityEnvironment {
    docker_process_label: String,
    reason: String,
    privileged: bool,
    host_network: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WancoRelocationEnvironment {
    original_root_name: String,
    publication_root_name: String,
    original_root_absent: bool,
}

fn validate_wanco_relocation_environment(
    artifact_root: &Path,
    cell_id: &str,
    run_ordinal: u32,
    bytes: &[u8],
    findings: &mut Vec<EvidenceMatrixFinding>,
) {
    let environment: WancoCanonicalEnvironment = match serde_json::from_slice(bytes) {
        Ok(environment) => environment,
        Err(error) => {
            finding(
                findings,
                "invalid-wanco-relocation-environment",
                format!("{cell_id} environment is not canonical JSON: {error}"),
            );
            return;
        }
    };
    let publication_name = artifact_root.file_name().and_then(|name| name.to_str());
    let original_name = Path::new(&environment.relocation.original_root_name);
    let original_is_one_normal_component = original_name.components().count() == 1
        && original_name
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
    let original_absent = artifact_root
        .parent()
        .filter(|_| original_is_one_normal_component)
        .map(|parent| !parent.join(original_name).exists())
        .unwrap_or(false);
    if environment.container_security.docker_process_label != "disabled"
        || environment.container_security.reason != "same-host canonical Unix-socket peer"
        || environment.container_security.privileged
        || environment.container_security.host_network
    {
        finding(
            findings,
            "unproven-wanco-container-security",
            format!("{cell_id} run {run_ordinal} has an unexpected container security boundary"),
        );
    }
    if environment.schema != "visa-wanco-carrier-environment-v1"
        || environment.cell_id != cell_id
        || environment.run_ordinal != run_ordinal
        || !environment.relocation.original_root_absent
        || !original_absent
        || publication_name != Some(environment.relocation.publication_root_name.as_str())
        || environment.relocation.original_root_name == environment.relocation.publication_root_name
    {
        finding(
            findings,
            "unproven-wanco-relocation",
            format!("{cell_id} run {run_ordinal} does not prove validation after relocation"),
        );
    }
}

fn safe_relative_uri(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.as_bytes().contains(&0)
        && value.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn run_load_failure(code: &str, detail: String) -> EvidenceMatrixRunValidationReport {
    EvidenceMatrixRunValidationReport {
        ok: false,
        matrix_sha256: None,
        git_sha: None,
        claim_closures: Vec::new(),
        findings: vec![EvidenceMatrixFinding { code: code.to_owned(), detail }],
    }
}

fn validate_endpoint(
    cell_id: &str,
    role: &str,
    endpoint: &MatrixEndpoint,
    findings: &mut Vec<EvidenceMatrixFinding>,
) {
    let runtime_absent = endpoint.runtime == MatrixRuntime::NotApplicable;
    let isa_absent = endpoint.isa == MatrixIsa::NotApplicable;
    if runtime_absent != isa_absent {
        finding(
            findings,
            "inconsistent-evidence-endpoint",
            format!("{cell_id} {role} runtime and ISA applicability disagree"),
        );
    }
    if endpoint.substrate == MatrixSubstrate::NeutralModel && !runtime_absent {
        finding(
            findings,
            "inconsistent-neutral-model-endpoint",
            format!("{cell_id} {role} neutral-model substrate cannot name a runtime"),
        );
    }
}

fn require_sorted_unique(
    values: &[String],
    label: &str,
    findings: &mut Vec<EvidenceMatrixFinding>,
) {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        finding(
            findings,
            "unsorted-or-duplicate-evidence-values",
            format!("{label} must be strictly sorted and unique"),
        );
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
}

fn finding(
    findings: &mut Vec<EvidenceMatrixFinding>,
    code: impl Into<String>,
    detail: impl Into<String>,
) {
    findings.push(EvidenceMatrixFinding { code: code.into(), detail: detail.into() });
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{Stage2ClaimSet, Stage3Profile, required_stage4_claims, stage2_cell_descriptors};

    const COMMITTED_MATRIX: &[u8] = include_bytes!("../../../../claims/evidence-matrix.json");

    #[test]
    fn committed_matrix_is_valid() {
        let report = validate_evidence_matrix_json(COMMITTED_MATRIX);
        assert!(report.ok, "{:#?}", report.findings);
    }

    #[test]
    fn matrix_matches_compiled_stage_catalog_sizes() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let requirement = |claim_id: &str| {
            matrix
                .claim_requirements
                .iter()
                .find(|requirement| requirement.claim_id == claim_id)
                .unwrap()
        };
        assert_eq!(
            requirement("cross-execution-path-portability").required_cells.len(),
            stage2_cell_descriptors(Stage2ClaimSet::CrossExecutionPathPortability).count()
        );
        assert_eq!(
            requirement("strict-cross-runtime-continuity").required_cells.len(),
            stage2_cell_descriptors(Stage2ClaimSet::StrictCrossRuntimeContinuity).count()
        );
        assert_eq!(requirement("bounded-regular-file-continuity").required_cells.len(), 1);
        assert_eq!(Stage3Profile::RegularFile.cases().len(), 12);
        assert_eq!(Stage3Profile::LogicalRequest.cases().len(), 14);
        let sqlite = matrix
            .cells
            .iter()
            .find(|cell| cell.id == "stock-sqlite.wanco-rollback-journal")
            .unwrap();
        assert_eq!(sqlite.resource_profile, MatrixResourceProfile::SqliteRollbackJournal);
        assert_eq!(
            sqlite.handoff_topology,
            MatrixHandoffTopology::VisaPlusWancoCarrierWithProviderHandoff
        );
        assert_eq!(sqlite.fault_model, MatrixFaultModel::SqliteRollbackEightCutPlusProcessCrash);
        assert_eq!(sqlite.verifier, MatrixVerifier::SqliteNamespaceNativeOracle);
        for claim in required_stage4_claims() {
            assert_eq!(
                requirement(claim.claim_id.as_str()).required_cells.len(),
                claim.required_cells.len()
            );
        }
    }

    #[test]
    fn regular_file_successor_requires_the_full_four_direction_matrix() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let requirement = matrix
            .claim_requirements
            .iter()
            .find(|requirement| requirement.claim_id == "cross-runtime-regular-file-continuity-v1")
            .unwrap();
        assert_eq!(requirement.required_cells.len(), 4);
        let directions = requirement
            .required_cells
            .iter()
            .map(|id| matrix.cells.iter().find(|cell| &cell.id == id).unwrap())
            .map(|cell| (cell.source.runtime, cell.destination.runtime))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            directions,
            BTreeSet::from([
                (MatrixRuntime::Wasmtime, MatrixRuntime::Wasmtime),
                (MatrixRuntime::Wasmtime, MatrixRuntime::SourceLockedWacogo),
                (MatrixRuntime::SourceLockedWacogo, MatrixRuntime::Wasmtime),
                (MatrixRuntime::SourceLockedWacogo, MatrixRuntime::SourceLockedWacogo,),
            ])
        );
    }

    #[test]
    fn regular_file_successor_run_requires_three_relocated_passes_per_direction() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("regular-file-successor");
        let run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert!(report.ok, "{:#?}", report.findings);
        assert_eq!(report.claim_closures.len(), 1);
        assert!(report.claim_closures[0].closed);

        let mut incomplete = run.clone();
        incomplete.receipts.retain(|receipt| {
            receipt.cell_id != "s3a.cross.wasmtime-to-wacogo.regular-file"
                || receipt.run_ordinal != 3
        });
        let report = validate_evidence_matrix_run(&matrix, &incomplete, root.path());
        assert!(!report.ok);
        assert_eq!(
            report.claim_closures[0].missing_required_cells,
            ["s3a.cross.wasmtime-to-wacogo.regular-file"]
        );
    }

    #[test]
    fn matrix_run_rejects_coordinate_drift_and_dirty_candidate_evidence() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("coordinate-drift");
        let mut run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        run.git_dirty = true;
        run.receipts[0].coordinates.destination.runtime = MatrixRuntime::Wasmtime;
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "evidence-matrix-receipt-coordinate-mismatch")
        );
        assert!(report.findings.iter().any(|finding| finding.code == "dirty-evidence-matrix-run"));
    }

    #[test]
    fn stage3a_verifier_layers_are_explicit() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let baseline = matrix
            .cells
            .iter()
            .find(|cell| cell.id == "s3a.wasmtime-to-wasmtime.regular-file")
            .unwrap();
        assert_eq!(baseline.verifier, MatrixVerifier::RegularFileRawObservableOracle);
        let cross = matrix
            .cells
            .iter()
            .filter(|cell| cell.id.starts_with("s3a.cross."))
            .collect::<Vec<_>>();
        assert_eq!(cross.len(), 4);
        assert!(
            cross.iter().all(|cell| {
                cell.verifier == MatrixVerifier::Stage3aCrossRuntimeOuterAndRawOracle
            })
        );
    }

    #[test]
    fn wanco_claim_requires_negative_and_positive_three_run_cells() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let claim_id = "bounded-wanco-regular-file-carrier-composition-v1";
        let requirement = matrix
            .claim_requirements
            .iter()
            .find(|requirement| requirement.claim_id == claim_id)
            .unwrap();
        assert_eq!(
            requirement.required_cells,
            ["wanco.carrier-only.regular-file", "wanco.visa-plus-carrier.regular-file",]
        );
        assert_eq!(requirement.minimum_required_runs_per_cell, 3);
        assert!(requirement.requires_clean_git);
        assert!(requirement.requires_relocated_verification);

        let cells = requirement
            .required_cells
            .iter()
            .map(|id| matrix.cells.iter().find(|cell| &cell.id == id).unwrap())
            .collect::<Vec<_>>();
        assert!(cells.iter().all(|cell| {
            cell.source.runtime == MatrixRuntime::WancoAot
                && cell.destination.runtime == MatrixRuntime::WancoAot
                && cell.fault_model == MatrixFaultModel::WancoRegularFileTwoCase
                && cell.verifier == MatrixVerifier::RegularFileRawObservableOracle
                && cell.disposition == MatrixCellDisposition::Qualified
        }));
        assert_eq!(
            cells.iter().map(|cell| cell.handoff_topology).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                MatrixHandoffTopology::VisaPlusWancoCarrier,
                MatrixHandoffTopology::WancoCarrierOnly,
            ])
        );
        assert!(cells[0].evidence_boundary.contains("required oracle rejection"));

        let root = TestArtifactRoot::new("wanco-closure");
        let run = claim_matrix_run(&matrix, claim_id, root.path());
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert!(report.ok, "{:#?}", report.findings);
        assert_eq!(report.claim_closures.len(), 1);
        assert!(report.claim_closures[0].closed);

        let mut incomplete = run;
        incomplete.receipts.retain(|receipt| {
            receipt.cell_id != "wanco.carrier-only.regular-file" || receipt.run_ordinal != 3
        });
        let report = validate_evidence_matrix_run(&matrix, &incomplete, root.path());
        assert!(!report.ok);
        assert_eq!(
            report.claim_closures[0].missing_required_cells,
            ["wanco.carrier-only.regular-file"]
        );
    }

    #[test]
    fn matrix_run_rejects_a_missing_referenced_artifact() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("missing-artifact");
        let run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        fs::remove_file(root.path().join(&run.receipts[0].evidence_bundle.uri)).unwrap();
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&report, "unreadable-evidence-matrix-artifact");
    }

    #[test]
    fn matrix_run_rejects_same_size_artifact_tampering() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("tampered-artifact");
        let run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        let reference = &run.receipts[0].evidence_bundle;
        fs::write(
            root.path().join(&reference.uri),
            vec![b'x'; usize::try_from(reference.size).unwrap()],
        )
        .unwrap();
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&report, "evidence-matrix-artifact-digest-mismatch");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn matrix_run_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("symlinked-artifact");
        let run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        let referenced = root.path().join(&run.receipts[0].evidence_bundle.uri);
        let target = root.path().join("symlink-target.json");
        fs::write(&target, fs::read(&referenced).unwrap()).unwrap();
        fs::remove_file(&referenced).unwrap();
        symlink(&target, &referenced).unwrap();
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&report, "unreadable-evidence-matrix-artifact");
    }

    #[test]
    fn matrix_run_rejects_a_fake_artifact_sha() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("fake-sha");
        let mut run =
            claim_matrix_run(&matrix, "cross-runtime-regular-file-continuity-v1", root.path());
        run.receipts[0].evidence_bundle.sha256 = "f".repeat(64);
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&report, "evidence-matrix-artifact-digest-mismatch");
    }

    #[test]
    fn wanco_matrix_run_rejects_polarity_swapped_reports() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("polarity-swap");
        let mut run = claim_matrix_run(
            &matrix,
            "bounded-wanco-regular-file-carrier-composition-v1",
            root.path(),
        );
        let negative = run
            .receipts
            .iter()
            .position(|receipt| {
                receipt.cell_id == "wanco.carrier-only.regular-file" && receipt.run_ordinal == 1
            })
            .unwrap();
        let positive = run
            .receipts
            .iter()
            .position(|receipt| {
                receipt.cell_id == "wanco.visa-plus-carrier.regular-file"
                    && receipt.run_ordinal == 1
            })
            .unwrap();
        let positive_report = run.receipts[positive].validation_report.clone();
        run.receipts[positive].validation_report = run.receipts[negative].validation_report.clone();
        run.receipts[negative].validation_report = positive_report;
        let report = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&report, "invalid-wanco-oracle-semantics");
        assert_finding(&report, "evidence-matrix-observed-outcome-mismatch");
    }

    #[test]
    fn wanco_negative_run_requires_two_false_cases_and_only_expected_mismatches() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("negative-semantics");
        let mut run = claim_matrix_run(
            &matrix,
            "bounded-wanco-regular-file-carrier-composition-v1",
            root.path(),
        );
        let receipt = run
            .receipts
            .iter_mut()
            .find(|receipt| receipt.cell_id == "wanco.carrier-only.regular-file")
            .unwrap();
        let mut report = wanco_report(EvidenceMatrixSemanticOutcome::Rejected);
        report["cases"][0]["equivalent"] = serde_json::Value::Bool(true);
        report["findings"].as_array_mut().unwrap().push(serde_json::json!({
            "code": "unexpected-finding",
            "case_id": "read-write-offset",
            "detail": "must not be counted as the expected negative"
        }));
        rewrite_json_reference(root.path(), &mut receipt.validation_report, &report);
        let validation = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&validation, "invalid-wanco-negative-oracle-semantics");
    }

    #[test]
    fn wanco_matrix_run_rejects_a_missing_embedded_artifact() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("missing-embedded-artifact");
        let run = claim_matrix_run(
            &matrix,
            "bounded-wanco-regular-file-carrier-composition-v1",
            root.path(),
        );
        let evidence = &run.receipts[0].evidence_bundle;
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(&evidence.uri)).unwrap()).unwrap();
        let embedded = value["retained"][0]["uri"].as_str().unwrap();
        fs::remove_file(root.path().join(embedded)).unwrap();
        let validation = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&validation, "unreadable-evidence-matrix-artifact");
    }

    #[test]
    fn wanco_matrix_run_rejects_a_privileged_container_environment() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let root = TestArtifactRoot::new("privileged-container");
        let mut run = claim_matrix_run(
            &matrix,
            "bounded-wanco-regular-file-carrier-composition-v1",
            root.path(),
        );
        let receipt = run
            .receipts
            .iter_mut()
            .find(|receipt| receipt.cell_id == "wanco.visa-plus-carrier.regular-file")
            .unwrap();
        let mut environment: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(&receipt.environment.uri)).unwrap())
                .unwrap();
        environment["container_security"]["privileged"] = serde_json::Value::Bool(true);
        rewrite_json_reference(root.path(), &mut receipt.environment, &environment);
        let validation = validate_evidence_matrix_run(&matrix, &run, root.path());
        assert_finding(&validation, "unproven-wanco-container-security");
    }

    fn claim_matrix_run(
        matrix: &EvidenceMatrix,
        claim_id: &str,
        artifact_root: &Path,
    ) -> EvidenceMatrixRun {
        let requirement = matrix
            .claim_requirements
            .iter()
            .find(|requirement| requirement.claim_id == claim_id)
            .unwrap();
        let matrix_sha256 = evidence_matrix_sha256(matrix).unwrap();
        let mut receipts = Vec::new();
        for cell_id in &requirement.required_cells {
            let cell = matrix.cells.iter().find(|cell| &cell.id == cell_id).unwrap();
            for run_ordinal in 1..=requirement.minimum_required_runs_per_cell {
                receipts.push(receipt(cell, run_ordinal, true, artifact_root));
            }
        }
        for cell_id in &requirement.supporting_cells {
            let cell = matrix.cells.iter().find(|cell| &cell.id == cell_id).unwrap();
            for run_ordinal in 1..=requirement.minimum_supporting_runs_per_cell {
                receipts.push(receipt(cell, run_ordinal, false, artifact_root));
            }
        }
        receipts.sort_by(|left, right| {
            (&left.cell_id, left.run_ordinal).cmp(&(&right.cell_id, right.run_ordinal))
        });
        EvidenceMatrixRun {
            schema_version: EVIDENCE_MATRIX_RUN_SCHEMA_VERSION.to_owned(),
            matrix_sha256,
            git_sha: "a".repeat(40),
            git_dirty: false,
            run_id: format!("{claim_id}-test-run"),
            started_at_unix_ms: 1,
            finished_at_unix_ms: 2,
            claim_ids: vec![claim_id.to_owned()],
            receipts,
        }
    }

    fn receipt(
        cell: &EvidenceMatrixCell,
        run_ordinal: u32,
        relocated_verification: bool,
        artifact_root: &Path,
    ) -> EvidenceMatrixCellReceipt {
        let base = format!("runs/{}/{run_ordinal}", cell.id);
        let expected = expected_semantic_outcome(cell);
        let wanco_cell = matches!(
            cell.handoff_topology,
            MatrixHandoffTopology::WancoCarrierOnly | MatrixHandoffTopology::VisaPlusWancoCarrier
        );
        let evidence = if wanco_cell {
            let retained = write_json_reference(
                artifact_root,
                &format!("{base}/retained-observation.json"),
                &serde_json::json!({"schema": "test-observation-v1"}),
            );
            serde_json::json!({
                "schema": "visa-wanco-carrier-paired-evidence-v1",
                "cell_id": cell.id,
                "run_ordinal": run_ordinal,
                "expected_oracle_outcome": if expected == EvidenceMatrixSemanticOutcome::Accepted {
                    "accepted"
                } else {
                    "rejected"
                },
                "retained": [retained]
            })
        } else {
            serde_json::json!({"schema": "test-evidence-v1"})
        };
        let evidence_bundle =
            write_json_reference(artifact_root, &format!("{base}/evidence.json"), &evidence);
        let report = if wanco_cell {
            wanco_report(expected)
        } else {
            serde_json::json!({"ok": expected == EvidenceMatrixSemanticOutcome::Accepted})
        };
        let validation_report =
            write_json_reference(artifact_root, &format!("{base}/validation.json"), &report);
        let environment = if wanco_cell {
            let publication_root_name = artifact_root.file_name().unwrap().to_str().unwrap();
            serde_json::json!({
                "schema": "visa-wanco-carrier-environment-v1",
                "cell_id": cell.id,
                "run_ordinal": run_ordinal,
                "coordinates": EvidenceMatrixCoordinates::from(cell),
                "git_sha": "a".repeat(40),
                "git_dirty": false,
                "host": {},
                "wanco": {},
                "producer_sha256": "b".repeat(64),
                "standalone_oracle_sha256": "c".repeat(64),
                "container_security": {
                    "docker_process_label": "disabled",
                    "reason": "same-host canonical Unix-socket peer",
                    "privileged": false,
                    "host_network": false
                },
                "relocation": {
                    "original_root_name": format!("{publication_root_name}-original"),
                    "publication_root_name": publication_root_name,
                    "original_root_absent": true
                }
            })
        } else {
            serde_json::json!({"schema": "test-environment-v1"})
        };
        let environment =
            write_json_reference(artifact_root, &format!("{base}/environment.json"), &environment);
        EvidenceMatrixCellReceipt {
            cell_id: cell.id.clone(),
            run_ordinal,
            coordinates: EvidenceMatrixCoordinates::from(cell),
            evidence_bundle,
            validation_report,
            environment,
            verifier_identity: EvidenceMatrixVerifierIdentity {
                name: "visa-conformance".to_owned(),
                version: "0.2.0".to_owned(),
                executable_sha256: "c".repeat(64),
            },
            expected_semantic_outcome: expected,
            observed_semantic_outcome: expected,
            relocated_verification,
        }
    }

    fn wanco_report(outcome: EvidenceMatrixSemanticOutcome) -> serde_json::Value {
        let accepted = outcome == EvidenceMatrixSemanticOutcome::Accepted;
        let route = if accepted { "visa_plus_carrier" } else { "carrier_only" };
        let cases = ["read-write-offset", "append-continuity"]
            .into_iter()
            .map(|case_id| {
                serde_json::json!({
                    "case_id": case_id,
                    "equivalent": accepted,
                    "control_projection": {},
                    "candidate_projection": {}
                })
            })
            .collect::<Vec<_>>();
        let findings = if accepted {
            Vec::new()
        } else {
            ["read-write-offset", "append-continuity"]
                .into_iter()
                .map(|case_id| {
                    serde_json::json!({
                        "code": "observable-projection-mismatch",
                        "case_id": case_id,
                        "detail": "test mismatch"
                    })
                })
                .collect::<Vec<_>>()
        };
        serde_json::json!({
            "schema_version": visa_regular_file_oracle::EQUIVALENCE_REPORT_SCHEMA_VERSION,
            "accepted": accepted,
            "control_bundle_id": "control",
            "candidate_bundle_id": "candidate",
            "control_validation": {
                "schema_version": visa_regular_file_oracle::ORACLE_REPORT_SCHEMA_VERSION,
                "bundle_id": "control",
                "route_mode": "uninterrupted_control",
                "accepted": true,
                "cases": [],
                "findings": []
            },
            "candidate_validation": {
                "schema_version": visa_regular_file_oracle::ORACLE_REPORT_SCHEMA_VERSION,
                "bundle_id": "candidate",
                "route_mode": route,
                "accepted": accepted,
                "cases": [],
                "findings": []
            },
            "cases": cases,
            "findings": findings
        })
    }

    fn write_json_reference(
        root: &Path,
        uri: &str,
        value: &serde_json::Value,
    ) -> EvidenceMatrixArtifactReference {
        let bytes = serde_json::to_vec(value).unwrap();
        let path = root.join(uri);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();
        EvidenceMatrixArtifactReference {
            uri: uri.to_owned(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size: bytes.len() as u64,
        }
    }

    fn rewrite_json_reference(
        root: &Path,
        reference: &mut EvidenceMatrixArtifactReference,
        value: &serde_json::Value,
    ) {
        *reference = write_json_reference(root, &reference.uri, value);
    }

    fn assert_finding(report: &EvidenceMatrixRunValidationReport, code: &str) {
        assert!(!report.ok);
        assert!(
            report.findings.iter().any(|finding| finding.code == code),
            "missing finding {code}: {:#?}",
            report.findings
        );
    }

    struct TestArtifactRoot {
        path: PathBuf,
    }

    impl TestArtifactRoot {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let path = std::env::temp_dir().join(format!(
                "visa-evidence-matrix-{label}-{}-{}-relocated",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestArtifactRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
