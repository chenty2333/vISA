use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    catalog::full_catalog,
    types::{
        Boundary, ClaimKind, EvidenceArtifactKind, TestSpec, ValidationFinding, ValidationReport,
    },
};

pub const EVIDENCE_MATRIX_SCHEMA_VERSION: &str = "visa-evidence-matrix-v0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceMatrix {
    pub schema_version: String,
    pub entries: Vec<EvidenceMatrixEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceMatrixEntry {
    pub claim_id: String,
    pub title: String,
    pub claim_kind: ClaimKind,
    pub evidence_boundary: Boundary,
    pub report_suite: String,
    pub report_gate: String,
    pub artifact_gate: String,
    pub required_artifacts: Vec<EvidenceArtifactKind>,
    pub profile_rule: String,
    pub proving_spec_ids: Vec<String>,
    pub proving_tests: Vec<String>,
    pub known_risks: Vec<String>,
}

pub fn minimum_mature_evidence_matrix() -> EvidenceMatrix {
    let catalog = full_catalog();
    let specs = catalog.iter().map(|spec| (spec.id.as_str(), spec)).collect::<BTreeMap<_, _>>();

    let semantic_specs = ["visa.wait.trap.cleanup"];
    let portable_specs = [
        "visa.artifact.load",
        "visa.capability.hostcall",
        "visa.snapshot.restore",
        "visa.native.full-hostcall-abi",
    ];
    let real_target_specs = [
        "substrate.p0.semantic.harness",
        "substrate.p1.console.timer.event",
        "substrate.p2.memory.dmw",
        "substrate.p3.mmio.dma.irq",
        "substrate.p4.snapshot.replay",
    ];

    EvidenceMatrix {
        schema_version: EVIDENCE_MATRIX_SCHEMA_VERSION.to_string(),
        entries: vec![
            EvidenceMatrixEntry {
                claim_id: "mature.semantic-model".to_string(),
                title: "Semantic model and contract graph invariants".to_string(),
                claim_kind: ClaimKind::VisaSemanticConformance,
                evidence_boundary: Boundary::SemanticModel,
                report_suite: "visa-layered-conformance".to_string(),
                report_gate:
                    "cargo run -p visa-conformance -- validate-report <report.json>"
                        .to_string(),
                artifact_gate:
                    "cargo run -p visa-conformance -- validate-artifacts <report.json> <artifact-root>"
                        .to_string(),
                required_artifacts: vec![EvidenceArtifactKind::ContractGraphSnapshot],
                profile_rule:
                    "Profile 0 semantic-harness semantics only; no substrate authority claim"
                        .to_string(),
                proving_spec_ids: strings(&semantic_specs),
                proving_tests: runners_for(&specs, &semantic_specs),
                known_risks: vec![
                    "Does not prove artifact runtime execution, Linux/WASI personality compatibility, performance, or real target substrate authority"
                        .to_string(),
                    "Snapshot artifact proves contract graph shape and identity/generation evidence, not hardware enforcement"
                        .to_string(),
                ],
            },
            EvidenceMatrixEntry {
                claim_id: "mature.portable-artifact-execution".to_string(),
                title: "Portable vISA artifact execution through target-runtime objects"
                    .to_string(),
                claim_kind: ClaimKind::VisaSemanticConformance,
                evidence_boundary: Boundary::PortableArtifactExecution,
                report_suite: "visa-layered-conformance".to_string(),
                report_gate:
                    "cargo run -p visa-conformance -- validate-report <report.json>"
                        .to_string(),
                artifact_gate:
                    "cargo run -p visa-conformance -- validate-report-with-artifacts <report.json> <artifact-root>"
                        .to_string(),
                required_artifacts: vec![EvidenceArtifactKind::ContractGraphSnapshot],
                profile_rule:
                    "Each result must satisfy its catalog profile; the minimum mature portable set includes minimal-bare-metal, device-capable, and snapshot-replay-capable vISA-native specs"
                        .to_string(),
                proving_spec_ids: strings(&portable_specs),
                proving_tests: runners_for(&specs, &portable_specs),
                known_risks: vec![
                    "Does not prove Linux personality compatibility unless Linux personality results with raw logs and traces are also reported"
                        .to_string(),
                    "Does not prove real target substrate execution; host-side or Wasmtime-backed portable execution can still bypass target hardware authority"
                        .to_string(),
                    "Contract graph snapshots must not claim a stronger boundary than the result observed"
                        .to_string(),
                ],
            },
            EvidenceMatrixEntry {
                claim_id: "mature.real-target-substrate-execution".to_string(),
                title:
                    "Real target substrate execution with machine-authority extraction evidence"
                        .to_string(),
                claim_kind: ClaimKind::SubstrateProfileConformance,
                evidence_boundary: Boundary::RealTargetSubstrate,
                report_suite: "visa-substrate-profile-conformance".to_string(),
                report_gate:
                    "cargo run -p visa-conformance -- validate-report <report.json>"
                        .to_string(),
                artifact_gate:
                    "cargo run -p visa-conformance -- validate-report-with-artifacts <report.json> <artifact-root>"
                        .to_string(),
                required_artifacts: vec![
                    EvidenceArtifactKind::SubstrateExtractionTrace,
                    EvidenceArtifactKind::DeviceTrace,
                ],
                profile_rule:
                    "Report the actual target profile from substrate capability discovery; every claimed profile spec up to that level must pass, and device/snapshot claims require device-capable or snapshot-replay-capable evidence respectively"
                        .to_string(),
                proving_spec_ids: strings(&real_target_specs),
                proving_tests: vec![
                    "real target or QEMU substrate runner emits visa-substrate-profile-conformance with observed_boundary=real-target-substrate"
                        .to_string(),
                    "cargo run -p visa-conformance -- validate-report-with-artifacts <report.json> <artifact-root>"
                        .to_string(),
                    "local guard tests: substrate_bridge_does_not_overclaim_real_target_without_context, artifact_gate_validates_real_target_extraction_trace_files, artifact_gate_validates_real_target_device_trace_context"
                        .to_string(),
                ],
                known_risks: vec![
                    "Local semantic, host-side substrate, or portable artifact tests alone do not prove this claim"
                        .to_string(),
                    "Trace artifacts must include target_arch and target_board context and must bind operations to event_id/event_epoch"
                        .to_string(),
                    "Linux personality compatibility and performance remain separate claims even when collected on the same target"
                        .to_string(),
                ],
            },
        ],
    }
}

pub fn validate_evidence_matrix(matrix: &EvidenceMatrix, catalog: &[TestSpec]) -> ValidationReport {
    let mut findings = Vec::new();
    if matrix.schema_version != EVIDENCE_MATRIX_SCHEMA_VERSION {
        findings.push(finding(
            "unsupported-evidence-matrix-schema",
            format!("unsupported evidence matrix schema {}", matrix.schema_version),
        ));
    }
    if matrix.entries.is_empty() {
        findings.push(finding("empty-evidence-matrix", "evidence matrix contains no entries"));
    }

    let catalog_ids = catalog.iter().map(|spec| spec.id.as_str()).collect::<BTreeSet<_>>();
    let mut claim_ids = BTreeSet::new();
    for entry in &matrix.entries {
        validate_matrix_entry(entry, &catalog_ids, &mut claim_ids, &mut findings);
    }

    for required in [
        "mature.semantic-model",
        "mature.portable-artifact-execution",
        "mature.real-target-substrate-execution",
    ] {
        if !claim_ids.contains(required) {
            findings.push(finding(
                "missing-required-evidence-claim",
                format!("minimum mature evidence matrix omits {required}"),
            ));
        }
    }

    ValidationReport::new(findings)
}

fn validate_matrix_entry(
    entry: &EvidenceMatrixEntry,
    catalog_ids: &BTreeSet<&str>,
    claim_ids: &mut BTreeSet<String>,
    findings: &mut Vec<ValidationFinding>,
) {
    if entry.claim_id.trim().is_empty() {
        findings.push(finding("empty-evidence-claim-id", "evidence matrix claim id is empty"));
    } else if !claim_ids.insert(entry.claim_id.clone()) {
        findings.push(finding(
            "duplicate-evidence-claim-id",
            format!("duplicate evidence matrix claim id {}", entry.claim_id),
        ));
    }

    for (code, label, value) in [
        ("empty-evidence-title", "title", entry.title.as_str()),
        ("empty-evidence-report-suite", "report_suite", entry.report_suite.as_str()),
        ("empty-evidence-report-gate", "report_gate", entry.report_gate.as_str()),
        ("empty-evidence-artifact-gate", "artifact_gate", entry.artifact_gate.as_str()),
        ("empty-evidence-profile-rule", "profile_rule", entry.profile_rule.as_str()),
    ] {
        if value.trim().is_empty() {
            findings.push(finding(code, format!("{} has empty {label}", entry.claim_id)));
        }
    }

    if entry.required_artifacts.is_empty() {
        findings.push(finding(
            "missing-evidence-artifact-requirement",
            format!("{} does not name required artifact kinds", entry.claim_id),
        ));
    }
    if entry.proving_spec_ids.is_empty() {
        findings.push(finding(
            "missing-evidence-proving-specs",
            format!("{} does not name proving specs", entry.claim_id),
        ));
    }
    if entry.proving_tests.is_empty() {
        findings.push(finding(
            "missing-evidence-proving-tests",
            format!("{} does not name proving tests or gates", entry.claim_id),
        ));
    }
    if entry.known_risks.is_empty() {
        findings.push(finding(
            "missing-evidence-known-risks",
            format!("{} does not name known risks", entry.claim_id),
        ));
    }

    for spec_id in &entry.proving_spec_ids {
        if !catalog_ids.contains(spec_id.as_str()) {
            findings.push(finding(
                "unknown-evidence-proving-spec",
                format!("{} references unknown spec {}", entry.claim_id, spec_id),
            ));
        }
    }
}

fn runners_for(specs: &BTreeMap<&str, &TestSpec>, ids: &[&str]) -> Vec<String> {
    ids.iter().filter_map(|id| specs.get(id).map(|spec| format!("{id}: {}", spec.runner))).collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn finding(code: &str, detail: impl Into<String>) -> ValidationFinding {
    ValidationFinding { code: code.to_string(), detail: detail.into() }
}
