use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const EVIDENCE_MATRIX_SCHEMA_VERSION: &str = "visa.evidence-matrix.v1";
pub const EVIDENCE_MATRIX_RUN_SCHEMA_VERSION: &str = "visa.evidence-matrix-run.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixRuntime {
    JcoNode,
    NotApplicable,
    SourceLockedWacogo,
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
    TimerKv,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixVerifier {
    JointAdmissionArtifactStatic,
    JointArtifactStatic,
    JointNeutralOracle,
    Stage1ArtifactSemantic,
    Stage2OuterNormalized,
    Stage2StrictOuterNormalized,
    Stage3Structural,
    Stage3aCrossRuntimeNormalized,
    Stage4ReconstructedNormalized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatrixCellDisposition {
    Candidate,
    DeclaredGap,
    Qualified,
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
    pub passed: bool,
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
    validate_evidence_matrix_run(&matrix, &run)
}

pub fn validate_evidence_matrix_run(
    matrix: &EvidenceMatrix,
    run: &EvidenceMatrixRun,
) -> EvidenceMatrixRunValidationReport {
    let mut findings = Vec::new();
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
        validate_matrix_artifact(
            &receipt.cell_id,
            "evidence bundle",
            &receipt.evidence_bundle,
            &mut findings,
        );
        validate_matrix_artifact(
            &receipt.cell_id,
            "validation report",
            &receipt.validation_report,
            &mut findings,
        );
        validate_matrix_artifact(
            &receipt.cell_id,
            "environment",
            &receipt.environment,
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
        if receipt.passed {
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
        } else {
            finding(
                &mut findings,
                "failed-evidence-matrix-cell",
                format!("{} run {} did not pass", receipt.cell_id, receipt.run_ordinal),
            );
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
    findings: &mut Vec<EvidenceMatrixFinding>,
) {
    if !safe_relative_uri(&artifact.uri) || !lower_hex(&artifact.sha256, 64) || artifact.size == 0 {
        finding(
            findings,
            "invalid-evidence-matrix-artifact",
            format!("{cell_id} has an invalid {label} reference"),
        );
    }
}

fn safe_relative_uri(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
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
        let run = regular_file_matrix_run(&matrix);
        let report = validate_evidence_matrix_run(&matrix, &run);
        assert!(report.ok, "{:#?}", report.findings);
        assert_eq!(report.claim_closures.len(), 1);
        assert!(report.claim_closures[0].closed);

        let mut incomplete = run.clone();
        incomplete.receipts.retain(|receipt| {
            receipt.cell_id != "s3a.cross.wasmtime-to-wacogo.regular-file"
                || receipt.run_ordinal != 3
        });
        let report = validate_evidence_matrix_run(&matrix, &incomplete);
        assert!(!report.ok);
        assert_eq!(
            report.claim_closures[0].missing_required_cells,
            ["s3a.cross.wasmtime-to-wacogo.regular-file"]
        );
    }

    #[test]
    fn matrix_run_rejects_coordinate_drift_and_dirty_candidate_evidence() {
        let matrix = parse_evidence_matrix_json(COMMITTED_MATRIX).unwrap();
        let mut run = regular_file_matrix_run(&matrix);
        run.git_dirty = true;
        run.receipts[0].coordinates.destination.runtime = MatrixRuntime::Wasmtime;
        let report = validate_evidence_matrix_run(&matrix, &run);
        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "evidence-matrix-receipt-coordinate-mismatch")
        );
        assert!(report.findings.iter().any(|finding| finding.code == "dirty-evidence-matrix-run"));
    }

    fn regular_file_matrix_run(matrix: &EvidenceMatrix) -> EvidenceMatrixRun {
        let claim_id = "cross-runtime-regular-file-continuity-v1";
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
                receipts.push(receipt(cell, run_ordinal, true));
            }
        }
        for cell_id in &requirement.supporting_cells {
            let cell = matrix.cells.iter().find(|cell| &cell.id == cell_id).unwrap();
            for run_ordinal in 1..=requirement.minimum_supporting_runs_per_cell {
                receipts.push(receipt(cell, run_ordinal, false));
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
            run_id: "regular-file-paper-run-1".to_owned(),
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
    ) -> EvidenceMatrixCellReceipt {
        let artifact = |kind: &str| EvidenceMatrixArtifactReference {
            uri: format!("runs/{}/{run_ordinal}/{kind}.json", cell.id),
            sha256: "b".repeat(64),
            size: 1,
        };
        EvidenceMatrixCellReceipt {
            cell_id: cell.id.clone(),
            run_ordinal,
            coordinates: EvidenceMatrixCoordinates::from(cell),
            evidence_bundle: artifact("evidence"),
            validation_report: artifact("validation"),
            environment: artifact("environment"),
            verifier_identity: EvidenceMatrixVerifierIdentity {
                name: "visa-conformance".to_owned(),
                version: "0.2.0".to_owned(),
                executable_sha256: "c".repeat(64),
            },
            passed: true,
            relocated_verification,
        }
    }
}
