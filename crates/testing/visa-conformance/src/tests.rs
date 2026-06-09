use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use contract_core::CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION;
use substrate_api::conformance::{
    ConformanceCheck, ConformanceEvidenceContext, ConformanceStatus, SubstrateConformanceReport,
};
use visa_profile::{SubstrateCapabilitySet, SubstrateProfile};

use super::*;
use crate::{artifacts::write_file_with_sha256, performance::CRITERION_METRIC_SOURCES};

#[test]
fn full_catalog_is_valid_and_has_unique_ids() {
    let catalog = full_catalog();
    let report = validate_catalog(&catalog);
    assert!(report.ok, "{:#?}", report.findings);
    assert!(catalog.len() >= 15);
}

#[test]
fn ltp_specs_are_linux_personality_compatibility_not_visa_conformance() {
    for spec in linux_ltp_catalog() {
        assert_eq!(spec.claim, ClaimKind::PersonalityCompatibility);
        assert_eq!(spec.personality, Some(Personality::Linux));
        assert!(spec.does_not_prove.iter().any(|item| item.contains("vISA semantic completeness")));
        assert_ne!(spec.claim, ClaimKind::VisaSemanticConformance);
    }
}

#[test]
fn visa_native_full_hostcall_spec_is_primary_visa_conformance() {
    let spec = visa_core_catalog()
        .into_iter()
        .find(|spec| spec.id == "visa.native.full-hostcall-abi")
        .expect("native vISA spec");

    assert_eq!(spec.claim, ClaimKind::VisaSemanticConformance);
    assert_eq!(spec.personality, Some(Personality::VisaNative));
    assert_eq!(spec.minimum_boundary, Boundary::PortableArtifactExecution);
    assert!(spec.runner.contains("visa_wasmtime"));
    assert!(spec.does_not_prove.iter().any(|item| item.contains("Linux personality")));
}

#[test]
fn minimum_mature_evidence_matrix_is_valid_and_layered() {
    let catalog = full_catalog();
    let matrix = minimum_mature_evidence_matrix();
    let validation = validate_evidence_matrix(&matrix, &catalog);

    assert!(validation.ok, "{:#?}", validation.findings);
    assert_eq!(matrix.schema_version, EVIDENCE_MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.entries.len(), 3);

    let semantic = matrix
        .entries
        .iter()
        .find(|entry| entry.claim_id == "mature.semantic-model")
        .expect("semantic model matrix entry");
    assert_eq!(semantic.evidence_boundary, Boundary::SemanticModel);
    assert_eq!(semantic.claim_kind, ClaimKind::VisaSemanticConformance);
    assert_eq!(semantic.required_artifacts, vec![EvidenceArtifactKind::ContractGraphSnapshot]);
    assert!(semantic.profile_rule.contains("semantic-harness"));
    assert!(semantic.known_risks.iter().any(|risk| risk.contains("Does not prove artifact")));

    let portable = matrix
        .entries
        .iter()
        .find(|entry| entry.claim_id == "mature.portable-artifact-execution")
        .expect("portable artifact execution matrix entry");
    assert_eq!(portable.evidence_boundary, Boundary::PortableArtifactExecution);
    assert_eq!(portable.claim_kind, ClaimKind::VisaSemanticConformance);
    assert!(portable.proving_spec_ids.iter().any(|id| id == "visa.artifact.load"));
    assert!(portable.proving_spec_ids.iter().any(|id| id == "visa.native.full-hostcall-abi"));
    assert_eq!(portable.required_artifacts, vec![EvidenceArtifactKind::ContractGraphSnapshot]);
    assert!(portable.known_risks.iter().any(|risk| risk.contains("real target")));

    let real_target = matrix
        .entries
        .iter()
        .find(|entry| entry.claim_id == "mature.real-target-substrate-execution")
        .expect("real target substrate matrix entry");
    assert_eq!(real_target.evidence_boundary, Boundary::RealTargetSubstrate);
    assert_eq!(real_target.claim_kind, ClaimKind::SubstrateProfileConformance);
    assert_eq!(real_target.report_suite, "visa-substrate-profile-conformance");
    assert!(
        real_target.required_artifacts.contains(&EvidenceArtifactKind::SubstrateExtractionTrace)
    );
    assert!(real_target.required_artifacts.contains(&EvidenceArtifactKind::DeviceTrace));
    assert!(real_target.profile_rule.contains("actual target profile"));
    assert!(real_target.known_risks.iter().any(|risk| risk.contains("Local semantic")));
}

#[test]
fn evidence_matrix_rejects_unknown_or_incomplete_claim_entries() {
    let catalog = full_catalog();
    let mut matrix = minimum_mature_evidence_matrix();
    matrix.entries[0].proving_spec_ids.push("missing.spec".to_string());
    matrix.entries[1].known_risks.clear();
    matrix.entries[2].required_artifacts.clear();

    let validation = validate_evidence_matrix(&matrix, &catalog);

    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "unknown-evidence-proving-spec")
    );
    assert!(
        validation.findings.iter().any(|finding| finding.code == "missing-evidence-known-risks")
    );
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "missing-evidence-artifact-requirement")
    );
}

#[test]
fn substrate_conformance_report_maps_to_unified_report() {
    let substrate_report = passing_substrate_report(SubstrateProfile::SemanticHarness);
    let report = substrate_report_from_conformance(
        "unit-substrate",
        "unit-test",
        Boundary::SemanticModel,
        &substrate_report,
        ConformanceEvidenceContext::host_side(),
    );
    let validation = validate_report(&report, &substrate_profile_catalog());

    assert!(validation.ok, "{:#?}", validation.findings);
    assert_eq!(report.suite_id, "visa-substrate-profile-conformance");
    assert_eq!(report.results[0].spec_id, "substrate.p0.semantic.harness");
    assert_eq!(report.results[0].outcome, Outcome::Pass);
    assert_eq!(report.results[0].metrics["required_checks"], 1.0);
    assert_eq!(report.results[0].metrics["passed_required_checks"], 1.0);
    assert!(report.results[0].remaining_uncertainty.contains("host-side"));
}

#[test]
fn substrate_bridge_does_not_overclaim_real_target_without_context() {
    let substrate_report = passing_substrate_report(SubstrateProfile::DeviceCapable);

    let host_side = substrate_result_from_conformance(
        &substrate_report,
        Boundary::RealTargetSubstrate,
        ConformanceEvidenceContext::host_side(),
    );
    let real_target = substrate_result_from_conformance(
        &substrate_report,
        Boundary::RealTargetSubstrate,
        ConformanceEvidenceContext::real_target_with_extraction_event_count("riscv64", 3),
    );
    let real_target_with_artifact = substrate_result_from_conformance_with_artifacts(
        &substrate_report,
        Boundary::RealTargetSubstrate,
        ConformanceEvidenceContext::real_target_with_extraction_event_count("riscv64", 3),
        vec![real_target_extraction_artifact()],
    );
    let unified_real_target_report = substrate_report_from_conformance_with_artifacts(
        "unit-substrate",
        "unit-test",
        Boundary::RealTargetSubstrate,
        &substrate_report,
        ConformanceEvidenceContext::real_target_with_extraction_event_count("riscv64", 3),
        vec![real_target_extraction_artifact()],
    );

    assert_eq!(host_side.outcome, Outcome::Fail);
    assert!(host_side.remaining_uncertainty.contains("did not include"));
    assert_eq!(real_target.outcome, Outcome::Fail);
    assert!(real_target.remaining_uncertainty.contains("no linked"));
    assert_eq!(real_target.metrics["real_target_extraction_event_count"], 3.0);
    assert_eq!(real_target_with_artifact.outcome, Outcome::Pass);
    assert_eq!(real_target_with_artifact.metrics["real_target_extraction_event_count"], 3.0);
    let validation = validate_report(&unified_real_target_report, &substrate_profile_catalog());
    assert!(validation.ok, "{:#?}", validation.findings);
}

#[test]
fn sample_report_validates_against_full_catalog() {
    let catalog = full_catalog();
    let report = sample_report(&catalog);
    let validation = validate_report(&report, &catalog);
    assert!(validation.ok, "{:#?}", validation.findings);
}

#[test]
fn report_rejects_unknown_spec_id() {
    let catalog = full_catalog();
    let mut report = sample_report(&catalog);
    report.results[0].spec_id = "missing.spec".to_string();

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "unknown-spec-id"));
}

#[test]
fn report_rejects_unknown_suite_id() {
    let catalog = linux_ltp_catalog();
    let mut report = sample_ltp_report();
    report.suite_id = "custom-suite".to_string();

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "unknown-suite-id"));
}

#[test]
fn report_rejects_known_spec_in_wrong_suite() {
    let catalog = full_catalog();
    let mut report = sample_ltp_report();
    let visa_spec = catalog.iter().find(|spec| spec.id == "visa.artifact.load").unwrap();
    report.results.push(TestResult {
        spec_id: visa_spec.id.clone(),
        outcome: Outcome::NotRun,
        observed_boundary: visa_spec.minimum_boundary,
        observed_profile: visa_spec.required_profile.clone(),
        evidence: "known spec intentionally placed in wrong suite".to_string(),
        remaining_uncertainty: "suite membership should reject this result".to_string(),
        metrics: BTreeMap::new(),
        evidence_artifacts: Vec::new(),
    });

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "unexpected-suite-result"));
}

#[test]
fn report_rejects_missing_suite_results() {
    let catalog = linux_ltp_catalog();
    let spec = catalog.iter().find(|spec| spec.id == LtpSubset::FsBasic.spec_id()).unwrap();
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "visa-linux-ltp-personality-compatibility".to_string(),
        target: "unit-test".to_string(),
        generated_by: "unit-test".to_string(),
        results: vec![TestResult {
            spec_id: spec.id.clone(),
            outcome: Outcome::Pass,
            observed_boundary: spec.minimum_boundary,
            observed_profile: spec.required_profile.clone(),
            evidence: "only one passing LTP subset was reported".to_string(),
            remaining_uncertainty: "other LTP subsets were omitted".to_string(),
            metrics: BTreeMap::new(),
            evidence_artifacts: Vec::new(),
        }],
    };

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-suite-result"));
}

#[test]
fn report_rejects_empty_result_set() {
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "test".to_string(),
        target: "test".to_string(),
        generated_by: "unit-test".to_string(),
        results: Vec::new(),
    };

    let validation = validate_report(&report, &full_catalog());
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "empty-report"));
}

#[test]
fn report_rejects_empty_metadata() {
    let catalog = full_catalog();
    let mut report = sample_report(&catalog);
    report.suite_id.clear();
    report.target = "  ".to_string();
    report.generated_by.clear();

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-report-suite-id"));
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-report-target"));
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-report-generator"));
}

#[test]
fn report_rejects_duplicate_result_ids() {
    let catalog = full_catalog();
    let spec = catalog.iter().find(|spec| spec.id == "visa.artifact.load").unwrap();
    let mut report = sample_report(&catalog);
    report.results = vec![
        TestResult {
            spec_id: spec.id.clone(),
            outcome: Outcome::NotRun,
            observed_boundary: spec.minimum_boundary,
            observed_profile: spec.required_profile.clone(),
            evidence: "not run".to_string(),
            remaining_uncertainty: "duplicate test fixture".to_string(),
            metrics: BTreeMap::new(),
            evidence_artifacts: Vec::new(),
        },
        TestResult {
            spec_id: spec.id.clone(),
            outcome: Outcome::NotRun,
            observed_boundary: spec.minimum_boundary,
            observed_profile: spec.required_profile.clone(),
            evidence: "not run".to_string(),
            remaining_uncertainty: "duplicate test fixture".to_string(),
            metrics: BTreeMap::new(),
            evidence_artifacts: Vec::new(),
        },
    ];

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "duplicate-result-spec-id"));
}

#[test]
fn report_rejects_insufficient_boundary() {
    let catalog = full_catalog();
    let mut report = sample_report(&catalog);
    let ltp = catalog.iter().find(|spec| spec.id == "linux-ltp.fs.basic").unwrap();
    report.results = vec![TestResult {
        spec_id: ltp.id.clone(),
        outcome: Outcome::Pass,
        observed_boundary: Boundary::SemanticModel,
        observed_profile: ltp.required_profile.clone(),
        evidence: "LTP fs subset passed in a semantic-only harness".to_string(),
        remaining_uncertainty: "portable artifact execution was not observed".to_string(),
        metrics: BTreeMap::new(),
        evidence_artifacts: Vec::new(),
    }];

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "insufficient-evidence-boundary")
    );
}

#[test]
fn report_rejects_real_target_claim_without_extraction_artifact() {
    let catalog = linux_ltp_catalog();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "missing-real-target-extraction-artifact")
    );
}

#[test]
fn report_accepts_real_target_claim_with_extraction_artifact() {
    let catalog = linux_ltp_catalog();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;
    let attached = attach_evidence_artifact(
        &mut report,
        LtpSubset::FsBasic.spec_id(),
        real_target_extraction_artifact(),
    );

    let validation = validate_report(&report, &catalog);

    assert_eq!(attached, 1);
    assert!(validation.ok, "{:#?}", validation.findings);
}

#[test]
fn report_rejects_portable_visa_semantic_claim_without_snapshot_artifact() {
    let catalog = full_catalog();
    let mut report = sample_report(&catalog);
    let result =
        report.results.iter_mut().find(|result| result.spec_id == "visa.artifact.load").unwrap();
    result.outcome = Outcome::Pass;
    result.observed_boundary = Boundary::PortableArtifactExecution;
    result.evidence = "artifact load path completed through visa_runtime".to_string();
    result.remaining_uncertainty = "unit fixture omits the snapshot artifact".to_string();
    result.evidence_artifacts.clear();

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    let missing_snapshot = validation
        .findings
        .iter()
        .any(|finding| finding.code == "missing-contract-graph-snapshot-artifact");
    assert!(missing_snapshot);
}

#[test]
fn report_accepts_portable_visa_semantic_claim_with_snapshot_artifact() {
    let catalog = full_catalog();
    let mut report = sample_report(&catalog);
    let result =
        report.results.iter_mut().find(|result| result.spec_id == "visa.artifact.load").unwrap();
    result.outcome = Outcome::Pass;
    result.observed_boundary = Boundary::PortableArtifactExecution;
    result.evidence = "artifact load path completed through visa_runtime".to_string();
    result.remaining_uncertainty = "unit fixture validates report metadata only".to_string();
    result.evidence_artifacts.push(contract_graph_snapshot_artifact());

    let validation = validate_report(&report, &catalog);

    assert!(validation.ok, "{:#?}", validation.findings);
}

#[test]
fn attach_evidence_artifact_can_target_all_results() {
    let mut report = sample_ltp_report();
    let attached = attach_evidence_artifact(&mut report, "*", real_target_extraction_artifact());

    assert_eq!(attached, LtpSubset::ALL.len());
    assert!(report.results.iter().all(|result| result.evidence_artifacts.len() == 3));
}

#[test]
fn evidence_artifact_kind_parse_is_stable() {
    assert_eq!(
        EvidenceArtifactKind::parse("substrate-extraction-trace"),
        Some(EvidenceArtifactKind::SubstrateExtractionTrace)
    );
    assert_eq!(EvidenceArtifactKind::DeviceTrace.as_str(), "device-trace");
    assert_eq!(
        EvidenceArtifactKind::parse("linux-personality-trace"),
        Some(EvidenceArtifactKind::LinuxPersonalityTrace)
    );
    assert_eq!(EvidenceArtifactKind::parse("unknown"), None);
}

#[test]
fn evidence_artifact_uri_must_be_bundle_relative() {
    assert!(artifact_uri_is_bundle_relative("logs/linux-ltp.fs.basic.log"));
    assert!(artifact_uri_is_bundle_relative("criterion/bench/base/estimates.json"));
    assert!(!artifact_uri_is_bundle_relative(""));
    assert!(!artifact_uri_is_bundle_relative("../escape.log"));
    assert!(!artifact_uri_is_bundle_relative("/tmp/absolute.log"));
    assert!(!artifact_uri_is_bundle_relative("file:///tmp/absolute.log"));
}

#[test]
fn report_rejects_malformed_evidence_artifacts() {
    let catalog = linux_ltp_catalog();
    let mut report = sample_ltp_report();
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::SubstrateExtractionTrace,
        uri: String::new(),
        sha256: "not-a-sha".to_string(),
        description: String::new(),
    });

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| {
        finding.code == "empty-evidence-artifact-uri"
            || finding.code == "invalid-evidence-artifact-sha256"
            || finding.code == "empty-evidence-artifact-description"
    }));
}

#[test]
fn report_rejects_non_bundle_relative_evidence_artifact_uri() {
    let catalog = linux_ltp_catalog();
    let mut report = sample_ltp_report();
    report.results[0].evidence_artifacts.clear();
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::LtpRawLog,
        uri: "/tmp/linux-ltp.fs.basic.log".to_string(),
        sha256: "a".repeat(64),
        description: "absolute artifact path should fail report contract".to_string(),
    });

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| {
        finding.code == "non-bundle-relative-evidence-artifact-uri"
            && finding.detail.contains("linux-ltp.fs.basic")
    }));
}

#[test]
fn artifact_gate_validates_real_target_extraction_trace_files() {
    let root = temp_criterion_dir("real-target-artifact");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("substrate-extraction.jsonl");
    let sha256 = write_file_with_sha256(
        &trace,
        br#"{"event_id":1,"event_epoch":1,"authority":"ConsoleAuthority","operation":"console_write","target_arch":"riscv64","target_board":"qemu-virt"}
"#,
    )
    .unwrap();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::SubstrateExtractionTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "real target substrate authority extraction trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(validation.ok, "{:#?}", validation.findings);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_real_target_extraction_trace_without_target_context() {
    let root = temp_criterion_dir("real-target-artifact-missing-context");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("substrate-extraction.jsonl");
    let sha256 = write_file_with_sha256(
        &trace,
        br#"{"event_id":1,"event_epoch":1,"authority":"ConsoleAuthority","operation":"console_write"}
"#,
    )
    .unwrap();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::SubstrateExtractionTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "generic substrate authority extraction trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "evidence-artifact-boundary-overclaim")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_validates_device_trace_event_identity() {
    let root = temp_criterion_dir("device-trace-artifact");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("device.jsonl");
    let sha256 = write_file_with_sha256(
        &trace,
        br#"{"event_id":7,"event_epoch":2,"device":"virtio-net0","operation":"irq_ack"}
"#,
    )
    .unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::DeviceTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "real target device trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(validation.ok, "{:#?}", validation.findings);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_validates_real_target_device_trace_context() {
    let root = temp_criterion_dir("real-target-device-trace-artifact");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("device.jsonl");
    let sha256 = write_file_with_sha256(
        &trace,
        br#"{"event_id":7,"event_epoch":2,"device":"virtio-net0","operation":"irq_ack","target_arch":"riscv64","target_board":"qemu-virt"}
"#,
    )
    .unwrap();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::DeviceTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "real target device trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(validation.ok, "{:#?}", validation.findings);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_real_target_device_trace_without_target_context() {
    let root = temp_criterion_dir("real-target-device-trace-missing-context");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("device.jsonl");
    let sha256 = write_file_with_sha256(
        &trace,
        br#"{"event_id":7,"event_epoch":2,"device":"virtio-net0","operation":"irq_ack"}
"#,
    )
    .unwrap();
    let mut report = sample_ltp_report();
    report.results[0].observed_boundary = Boundary::RealTargetSubstrate;
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::DeviceTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "generic device trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "evidence-artifact-boundary-overclaim")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_validates_contract_graph_snapshot_schema() {
    let root = temp_criterion_dir("contract-graph-snapshot-artifact");
    fs::create_dir_all(&root).unwrap();
    let snapshot = root.join("contract-graph-snapshot.json");
    let snapshot_json = contract_graph_snapshot_json("portable-artifact-execution");
    let sha256 = write_file_with_sha256(&snapshot, snapshot_json.as_bytes()).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::ContractGraphSnapshot,
        uri: snapshot.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "portable artifact contract graph snapshot".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(validation.ok, "{:#?}", validation.findings);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_contract_graph_snapshot_boundary_overclaim() {
    let root = temp_criterion_dir("contract-graph-snapshot-overclaim-artifact");
    fs::create_dir_all(&root).unwrap();
    let snapshot = root.join("contract-graph-snapshot.json");
    let snapshot_json = contract_graph_snapshot_json("real-target-substrate");
    let sha256 = write_file_with_sha256(&snapshot, snapshot_json.as_bytes()).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].observed_boundary = Boundary::PortableArtifactExecution;
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::ContractGraphSnapshot,
        uri: snapshot.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "overclaimed contract graph snapshot".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "evidence-artifact-boundary-overclaim")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_empty_contract_graph_snapshot_artifact() {
    let root = temp_criterion_dir("empty-contract-graph-snapshot-artifact");
    fs::create_dir_all(&root).unwrap();
    let snapshot = root.join("contract-graph-snapshot.json");
    let sha256 = write_file_with_sha256(&snapshot, br#"{}"#).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::ContractGraphSnapshot,
        uri: snapshot.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "empty contract graph snapshot".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-evidence-artifact-content")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_malformed_contract_graph_snapshot_identities() {
    let root = temp_criterion_dir("malformed-contract-graph-snapshot-identities");
    fs::create_dir_all(&root).unwrap();

    let cases = [
        (
            "zero-artifact-id",
            contract_graph_snapshot_json("portable-artifact-execution")
                .replace("\"artifacts\": []", "\"artifacts\": [{\"id\":0,\"generation\":1}]"),
        ),
        (
            "zero-tombstone-generation",
            contract_graph_snapshot_json("portable-artifact-execution").replace(
                "\"tombstones\": []",
                "\"tombstones\": [{\"kind\":\"store\",\"id\":1,\"generation\":0}]",
            ),
        ),
        (
            "zero-external-ref-id",
            contract_graph_snapshot_json("portable-artifact-execution").replace(
                "\"external_objects\": []",
                "\"external_objects\": [{\"object\":{\"kind\":\"external-object\",\"id\":0,\"generation\":0},\"provider\":\"pci\",\"class\":\"device\"}]",
            ),
        ),
        (
            "zero-internal-edge-generation",
            contract_graph_snapshot_json("portable-artifact-execution").replace(
                "\"explicit_edges\": []",
                "\"explicit_edges\": [{\"from\":{\"kind\":\"store\",\"id\":1,\"generation\":1},\"to\":{\"kind\":\"task\",\"id\":2,\"generation\":0},\"mode\":\"live\",\"evidence_level\":\"portable-artifact-execution\",\"epoch\":1}]",
            ),
        ),
    ];

    for (name, snapshot_json) in cases {
        let snapshot = root.join(format!("{name}.json"));
        let sha256 = write_file_with_sha256(&snapshot, snapshot_json.as_bytes()).unwrap();
        let mut report = sample_ltp_report();
        for result in &mut report.results {
            result.evidence_artifacts.clear();
        }
        report.results[0].evidence_artifacts.push(EvidenceArtifact {
            kind: EvidenceArtifactKind::ContractGraphSnapshot,
            uri: snapshot.file_name().unwrap().to_string_lossy().into_owned(),
            sha256,
            description: format!("malformed contract graph snapshot {name}"),
        });

        let validation = validate_report_artifacts(&report, &root);

        assert!(!validation.ok, "{name} should fail");
        assert!(
            validation
                .findings
                .iter()
                .any(|finding| finding.code == "invalid-evidence-artifact-content"),
            "{name} should report invalid snapshot content: {:#?}",
            validation.findings
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_unknown_contract_graph_snapshot_schema_version() {
    let root = temp_criterion_dir("unknown-contract-graph-snapshot-schema");
    fs::create_dir_all(&root).unwrap();
    let snapshot = root.join("contract-graph-snapshot.json");
    let snapshot_json = contract_graph_snapshot_json_with_schema(
        "contract-graph-snapshot-v9.9",
        "portable-artifact-execution",
    );
    let sha256 = write_file_with_sha256(&snapshot, snapshot_json.as_bytes()).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::ContractGraphSnapshot,
        uri: snapshot.file_name().unwrap().to_string_lossy().into_owned(),
        sha256,
        description: "unknown contract graph snapshot schema".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-evidence-artifact-content")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_sha_mismatch_and_invalid_structured_content() {
    let root = temp_criterion_dir("bad-artifact");
    fs::create_dir_all(&root).unwrap();
    let trace = root.join("substrate-extraction.jsonl");
    fs::write(&trace, br#"{"authority":"","operation":""}"#).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::SubstrateExtractionTrace,
        uri: trace.file_name().unwrap().to_string_lossy().into_owned(),
        sha256: "c".repeat(64),
        description: "bad trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "evidence-artifact-sha256-mismatch")
    );
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-evidence-artifact-content")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_relative_path_escape() {
    let root = temp_criterion_dir("path-escape-artifact");
    fs::create_dir_all(&root).unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::LtpRawLog,
        uri: "../outside-root.log".to_string(),
        sha256: "d".repeat(64),
        description: "path escape should be rejected before reading".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "evidence-artifact-path-escape")
    );
    assert!(
        !validation.findings.iter().any(|finding| finding.code == "missing-evidence-artifact-file")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_rejects_absolute_artifact_paths() {
    let root = temp_criterion_dir("absolute-path-artifact");
    fs::create_dir_all(&root).unwrap();
    let artifact = root.join("absolute.log");
    let sha256 = write_file_with_sha256(&artifact, b"open01 1 TPASS : open succeeded\n").unwrap();
    let mut report = sample_ltp_report();
    for result in &mut report.results {
        result.evidence_artifacts.clear();
    }
    report.results[0].evidence_artifacts.push(EvidenceArtifact {
        kind: EvidenceArtifactKind::LtpRawLog,
        uri: artifact.display().to_string(),
        sha256,
        description: "absolute paths must not bypass the artifact root".to_string(),
    });

    let validation = validate_report_artifacts(&report, &root);

    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "evidence-artifact-path-escape")
    );
    assert!(
        !validation.findings.iter().any(|finding| finding.code == "missing-evidence-artifact-file")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn passing_results_must_record_confidence_and_risk() {
    let catalog = full_catalog();
    let spec = catalog.iter().find(|spec| spec.id == "visa.artifact.load").unwrap();
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "test".to_string(),
        target: "test".to_string(),
        generated_by: "unit-test".to_string(),
        results: vec![TestResult {
            spec_id: spec.id.clone(),
            outcome: Outcome::Pass,
            observed_boundary: spec.minimum_boundary,
            observed_profile: spec.required_profile.clone(),
            evidence: String::new(),
            remaining_uncertainty: String::new(),
            metrics: BTreeMap::new(),
            evidence_artifacts: Vec::new(),
        }],
    };

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-evidence"));
    assert!(
        validation.findings.iter().any(|finding| finding.code == "missing-remaining-uncertainty")
    );
}

#[test]
fn gate_report_json_accepts_all_pass_sample_report() {
    let catalog = linux_ltp_catalog();
    let sample = sample_ltp_report();
    let bytes = serde_json::to_vec(&sample).unwrap();
    let gate = gate_report_json(&bytes, &catalog);

    assert!(gate.ok, "{gate:#?}");
    assert!(gate.load_error.is_none());
    assert!(gate.validation.unwrap().ok);
    assert!(gate.outcome_findings.is_empty());
}

#[test]
fn gate_report_json_rejects_not_run_or_failed_outcomes() {
    let catalog = full_catalog();
    let sample = sample_report(&catalog);
    let bytes = serde_json::to_vec(&sample).unwrap();
    let gate = gate_report_json(&bytes, &catalog);

    assert!(!gate.ok);
    assert!(gate.validation.unwrap().ok);
    assert!(gate.outcome_findings.iter().any(|finding| finding.code == "result-not-run"));
}

#[test]
fn performance_report_requires_metrics_for_pass_or_fail_results() {
    let catalog = performance_catalog();
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "visa-performance-benchmark".to_string(),
        target: "unit-test".to_string(),
        generated_by: "unit-test".to_string(),
        results: catalog
            .iter()
            .map(|spec| TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::Pass,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "benchmark completed".to_string(),
                remaining_uncertainty: "metrics were accidentally omitted".to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: Vec::new(),
            })
            .collect(),
    };

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "missing-performance-metrics")
    );
}

#[test]
fn performance_report_requires_spec_specific_metric_keys() {
    let catalog = performance_catalog();
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "visa-performance-benchmark".to_string(),
        target: "unit-test".to_string(),
        generated_by: "unit-test".to_string(),
        results: catalog
            .iter()
            .map(|spec| {
                let mut metrics = BTreeMap::new();
                metrics.insert("sample_value".to_string(), 1.0);
                TestResult {
                    spec_id: spec.id.clone(),
                    outcome: Outcome::Pass,
                    observed_boundary: spec.minimum_boundary,
                    observed_profile: spec.required_profile.clone(),
                    evidence: "benchmark completed".to_string(),
                    remaining_uncertainty: "wrong metric key was reported".to_string(),
                    metrics,
                    evidence_artifacts: Vec::new(),
                }
            })
            .collect(),
    };

    let validation = validate_report(&report, &catalog);
    assert!(!validation.ok);
    assert!(validation.findings.iter().any(|finding| finding.code == "missing-performance-metric"));
}

#[test]
fn performance_report_requires_raw_benchmark_artifacts() {
    let catalog = performance_catalog();
    let report = ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "visa-performance-benchmark".to_string(),
        target: "unit-test".to_string(),
        generated_by: "unit-test".to_string(),
        results: catalog
            .iter()
            .map(|spec| {
                let mut metrics = BTreeMap::new();
                for metric in required_performance_metrics(&spec.id) {
                    metrics.insert((*metric).to_string(), 1.0);
                }
                TestResult {
                    spec_id: spec.id.clone(),
                    outcome: Outcome::Pass,
                    observed_boundary: spec.minimum_boundary,
                    observed_profile: spec.required_profile.clone(),
                    evidence: "benchmark completed".to_string(),
                    remaining_uncertainty: "raw Criterion output was accidentally omitted"
                        .to_string(),
                    metrics,
                    evidence_artifacts: Vec::new(),
                }
            })
            .collect(),
    };

    let validation = validate_report(&report, &catalog);

    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "missing-performance-evidence-artifact")
    );
}

#[test]
fn performance_report_rejects_negative_or_non_finite_metrics() {
    let catalog = performance_catalog();
    let mut report = sample_performance_report();
    report.results[0].metrics.insert("latency_ns".to_string(), -1.0);
    report.results[1].metrics.insert("latency_ns".to_string(), f64::INFINITY);

    let validation = validate_report(&report, &catalog);
    let invalid_metric_count = validation
        .findings
        .iter()
        .filter(|finding| finding.code == "invalid-performance-metric")
        .count();

    assert!(!validation.ok);
    assert_eq!(invalid_metric_count, 2);
}

#[test]
fn sample_performance_report_validates_and_gates() {
    let catalog = performance_catalog();
    let report = sample_performance_report();
    let validation = validate_report(&report, &catalog);
    let gate = gate_report_json(&serde_json::to_vec(&report).unwrap(), &catalog);

    assert!(validation.ok, "{:#?}", validation.findings);
    assert!(gate.ok, "{gate:#?}");
    assert!(report.results.iter().all(|result| {
        required_performance_metrics(&result.spec_id)
            .iter()
            .all(|metric| result.metrics.contains_key(*metric))
    }));
}

#[test]
fn criterion_performance_plan_entries_match_metric_sources() {
    let entries = criterion_performance_plan_entries("target/criterion");
    let catalog_ids = performance_catalog().into_iter().map(|spec| spec.id).collect::<Vec<_>>();

    assert_eq!(entries.len(), CRITERION_METRIC_SOURCES.len());
    assert_eq!(entries[0].spec_id, "bench.hostcall.latency");
    assert_eq!(entries[0].benchmark_id, "hostcall_dispatch_latency");
    assert_eq!(entries[0].metric, "latency_ns");
    assert_eq!(
        entries[0].estimate_path,
        "target/criterion/hostcall_dispatch_latency/base/estimates.json"
    );
    for source in CRITERION_METRIC_SOURCES {
        assert!(entries.iter().any(|entry| {
            entry.spec_id == source.spec_id
                && entry.benchmark_id == source.benchmark_id
                && entry.metric == source.metric
        }));
        assert!(catalog_ids.iter().any(|id| id == source.spec_id));
    }
    assert!(entries.iter().any(|entry| entry.benchmark_id == "preemption_latency_mutation"));
    assert!(entries.iter().any(|entry| entry.benchmark_id == "simd_vector_state_record_mutation"));
    assert!(entries.iter().any(|entry| entry.benchmark_id == "simd_speedup_mutation"));
    assert!(entries.iter().any(|entry| entry.benchmark_id == "display_record_mutation"));
}

#[test]
fn criterion_performance_report_defaults_to_per_spec_boundaries() {
    let root = temp_criterion_dir("per-spec-boundary");
    for source in CRITERION_METRIC_SOURCES {
        write_criterion_estimate(&root, source.benchmark_id, 1_000.0);
    }

    let report = criterion_performance_report_from_estimates_dir_with_boundary(
        "unit-target",
        "unit-test",
        None,
        None,
        &root,
    );
    let hostcall =
        report.results.iter().find(|result| result.spec_id == "bench.hostcall.latency").unwrap();
    let block_network =
        report.results.iter().find(|result| result.spec_id == "bench.block.network").unwrap();
    let preemption = report
        .results
        .iter()
        .find(|result| result.spec_id == "bench.scheduler.preemption")
        .unwrap();

    assert_eq!(hostcall.observed_boundary, Boundary::PortableArtifactExecution);
    assert_eq!(block_network.observed_boundary, Boundary::SemanticModel);
    assert_eq!(preemption.observed_boundary, Boundary::SemanticModel);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn criterion_performance_report_maps_estimates_to_required_metrics() {
    let root = temp_criterion_dir("all-pass");
    for source in CRITERION_METRIC_SOURCES {
        write_criterion_estimate(&root, source.benchmark_id, 1_000.0);
    }

    let catalog = performance_catalog();
    let report = criterion_performance_report_from_estimates_dir(
        "unit-target",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    );
    let validation = validate_report(&report, &catalog);
    let gate = gate_report_json(&serde_json::to_vec(&report).unwrap(), &catalog);

    assert!(validation.ok, "{:#?}", validation.findings);
    assert!(gate.ok, "{gate:#?}");
    assert!(report.results.iter().all(|result| result.outcome == Outcome::Pass));
    let block_network =
        report.results.iter().find(|result| result.spec_id == "bench.block.network").unwrap();
    assert_eq!(block_network.metrics["block_iops"], 64_000_000.0);
    assert_eq!(block_network.metrics["network_packets_per_sec"], 1_000_000.0);
    assert_eq!(block_network.evidence_artifacts.len(), 2);
    assert!(report.results.iter().all(|result| {
        !result.evidence_artifacts.is_empty()
            && result.evidence_artifacts.iter().all(|artifact| {
                artifact.kind == EvidenceArtifactKind::BenchmarkRawOutput
                    && artifact.sha256.len() == 64
                    && artifact.uri.ends_with("estimates.json")
            })
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_gate_accepts_ltp_and_criterion_raw_outputs() {
    let ltp_root = temp_criterion_dir("ltp-artifact-gate");
    fs::create_dir_all(&ltp_root).unwrap();
    for subset in LtpSubset::ALL {
        fs::write(
            ltp_root.join(format!("{}.log", subset.spec_id())),
            format!("{}_case01 1 TPASS : passed\n", subset.spec_id().replace('.', "_")),
        )
        .unwrap();
        write_ltp_trace(
            &ltp_root,
            subset,
            &format!("{}_case01", subset.spec_id().replace('.', "_")),
        );
    }
    let ltp_report = ltp_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &ltp_root,
    )
    .unwrap();
    let ltp_artifact_validation = validate_report_artifacts(&ltp_report, &ltp_root);
    assert!(ltp_artifact_validation.ok, "{:#?}", ltp_artifact_validation.findings);

    let criterion_root = temp_criterion_dir("criterion-artifact-gate");
    for source in CRITERION_METRIC_SOURCES {
        write_criterion_estimate(&criterion_root, source.benchmark_id, 1_000.0);
    }
    let performance_report = criterion_performance_report_from_estimates_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &criterion_root,
    );
    let performance_artifact_validation =
        validate_report_artifacts(&performance_report, &criterion_root);
    assert!(performance_artifact_validation.ok, "{:#?}", performance_artifact_validation.findings);

    let _ = fs::remove_dir_all(ltp_root);
    let _ = fs::remove_dir_all(criterion_root);
}

#[test]
fn criterion_performance_report_marks_missing_estimates_not_run() {
    let root = temp_criterion_dir("missing");
    fs::create_dir_all(&root).unwrap();

    let catalog = performance_catalog();
    let report = criterion_performance_report_from_estimates_dir(
        "unit-target",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    );
    let gate = gate_report_json(&serde_json::to_vec(&report).unwrap(), &catalog);

    assert!(report.results.iter().all(|result| result.outcome == Outcome::NotRun));
    assert!(!gate.ok);
    assert!(gate.outcome_findings.iter().any(|finding| finding.code == "result-not-run"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn criterion_performance_report_fails_partial_or_invalid_estimates() {
    let root = temp_criterion_dir("partial-invalid");
    write_criterion_estimate(&root, "block_request_submit_mutation_64", 1_000.0);
    write_criterion_estimate(&root, "network_adapter_record_mutation", 0.0);

    let report = criterion_performance_report_from_estimates_dir(
        "unit-target",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    );
    let block_network =
        report.results.iter().find(|result| result.spec_id == "bench.block.network").unwrap();

    assert_eq!(block_network.outcome, Outcome::Fail);
    assert!(block_network.metrics.contains_key("block_iops"));
    assert!(!block_network.metrics.contains_key("network_packets_per_sec"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn gate_report_json_rejects_malformed_json() {
    let gate = gate_report_json(b"{not-json", &full_catalog());

    assert!(!gate.ok);
    assert_eq!(gate.load_error.unwrap().code, "invalid-report-json");
    assert!(gate.validation.is_none());
    assert!(gate.outcome_findings.is_empty());
}

#[test]
fn ltp_invocation_maps_subsets_to_runltp_commands() {
    let plan = LtpInvocation::default_plan("target/ltp");

    assert_eq!(plan.subsets, LtpSubset::ALL);
    assert_eq!(
        plan.command_for(LtpSubset::FsBasic),
        vec![
            "runltp".to_string(),
            "-f".to_string(),
            "fs".to_string(),
            "-o".to_string(),
            "target/ltp/linux-ltp.fs.basic.log".to_string(),
        ]
    );
    assert_eq!(
        plan.command_for(LtpSubset::NetSocket),
        vec![
            "runltp".to_string(),
            "-f".to_string(),
            "net.ipv4,net.tcp_cmds".to_string(),
            "-o".to_string(),
            "target/ltp/linux-ltp.net.socket.log".to_string(),
        ]
    );
    let entries = plan.plan_entries();
    assert_eq!(entries.len(), LtpSubset::ALL.len());
    assert_eq!(entries[0].spec_id, LtpSubset::FsBasic.spec_id());
    assert_eq!(entries[0].scenario_arg, LtpSubset::FsBasic.scenario_arg());
    assert_eq!(entries[0].output_log, "target/ltp/linux-ltp.fs.basic.log");
}

#[test]
fn ltp_parser_maps_common_status_lines() {
    let serial = format!(
        "
open01 1 TPASS : open succeeded
rename01 1 TFAIL : rename failed
mmap01 1 TCONF : unsupported configuration
{esc}[1;33meventfd06{esc}[0m 1 {esc}[1;33mTCONF{esc}[0m : libaio is not available
",
        esc = '\u{1b}'
    );
    let cases = parse_ltp_results(&serial);

    assert_eq!(cases.len(), 4);
    assert_eq!(cases[0].case_id, "open01");
    assert_eq!(cases[0].outcome, Outcome::Pass);
    assert_eq!(cases[1].outcome, Outcome::Fail);
    assert_eq!(cases[2].outcome, Outcome::Skip);
    assert_eq!(cases[3].case_id, "eventfd06");
    assert_eq!(cases[3].outcome, Outcome::Skip);
}

#[test]
fn ltp_subset_result_uses_failures_as_compatibility_failure() {
    let spec = linux_ltp_catalog()
        .into_iter()
        .find(|spec| spec.id == LtpSubset::FsBasic.spec_id())
        .unwrap();
    let cases = parse_ltp_results(
        r#"
open01 1 TPASS : open succeeded
rename01 1 TFAIL : rename failed
"#,
    );
    let result = ltp_subset_result(
        &spec,
        &cases,
        Boundary::PortableArtifactExecution,
        spec.required_profile.clone(),
    );

    assert_eq!(result.outcome, Outcome::Fail);
    assert_eq!(result.metrics["ltp_cases_passed"], 1.0);
    assert_eq!(result.metrics["ltp_cases_failed"], 1.0);
    assert!(result.remaining_uncertainty.contains("vISA semantic completeness"));
}

#[test]
fn ltp_report_from_subset_logs_marks_missing_subsets_not_run() {
    let report = ltp_report_from_subset_logs(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        [(LtpSubset::FsBasic, "open01 1 TPASS : open succeeded")],
    );

    let validation = validate_report(&report, &linux_ltp_catalog());
    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "missing-ltp-raw-log-artifact")
    );
    assert_eq!(report.results.len(), LtpSubset::ALL.len());
    assert_eq!(report.results[0].spec_id, LtpSubset::FsBasic.spec_id());
    assert_eq!(report.results[0].outcome, Outcome::Pass);
    assert!(report.results.iter().filter(|result| result.outcome == Outcome::NotRun).count() >= 1);
}

#[test]
fn ltp_report_from_subset_logs_preserves_failures_and_profile_override() {
    let report = ltp_report_from_subset_logs(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        Some("snapshot-replay-capable".to_string()),
        [(
            LtpSubset::NetSocket,
            "socket01 1 TPASS : socket opened\nsocket02 1 TFAIL : connect failed",
        )],
    );

    let socket = report
        .results
        .iter()
        .find(|result| result.spec_id == LtpSubset::NetSocket.spec_id())
        .unwrap();
    assert_eq!(socket.outcome, Outcome::Fail);
    assert_eq!(socket.observed_boundary, Boundary::PortableArtifactExecution);
    assert_eq!(socket.observed_profile.as_deref(), Some("snapshot-replay-capable"));
    assert_eq!(socket.metrics["ltp_cases_failed"], 1.0);
    let validation = validate_report(&report, &linux_ltp_catalog());
    assert!(!validation.ok);
    assert!(
        validation.findings.iter().any(|finding| finding.code == "missing-ltp-raw-log-artifact")
    );
}

#[test]
fn ltp_report_from_log_dir_attaches_raw_log_artifacts() {
    let root = temp_criterion_dir("ltp-raw-artifacts");
    fs::create_dir_all(&root).unwrap();
    for subset in LtpSubset::ALL {
        fs::write(
            root.join(format!("{}.log", subset.spec_id())),
            format!("{}_case01 1 TPASS : passed\n", subset.spec_id().replace('.', "_")),
        )
        .unwrap();
        write_ltp_trace(&root, subset, &format!("{}_case01", subset.spec_id().replace('.', "_")));
    }

    let report = ltp_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    )
    .unwrap();
    let validation = validate_report(&report, &linux_ltp_catalog());

    assert!(validation.ok, "{:#?}", validation.findings);
    assert_eq!(report.results.len(), LtpSubset::ALL.len());
    assert!(report.results.iter().all(|result| {
        result.evidence_artifacts.len() == 2
            && result.evidence_artifacts.iter().any(|artifact| {
                artifact.kind == EvidenceArtifactKind::LtpRawLog
                    && artifact.sha256.len() == 64
                    && artifact.uri.ends_with(&format!("{}.log", result.spec_id))
            })
            && result.evidence_artifacts.iter().any(|artifact| {
                artifact.kind == EvidenceArtifactKind::LinuxPersonalityTrace
                    && artifact.sha256.len() == 64
                    && artifact.uri.ends_with(&format!("{}.visa-trace.jsonl", result.spec_id))
            })
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn visa_ltp_subset_report_requires_visa_trace_for_portable_claims() {
    let root = temp_criterion_dir("visa-ltp-missing-trace");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("linux-ltp.fs.basic.log"), "open01 1 TPASS : passed\n").unwrap();

    let report = ltp_visa_subset_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    )
    .unwrap();
    let validation = validate_report(&report, &linux_ltp_catalog());

    assert_eq!(report.suite_id, LTP_VISA_SUBSET_SUITE_ID);
    assert_eq!(report.results.len(), 1);
    assert!(!validation.ok);
    assert!(
        validation
            .findings
            .iter()
            .any(|finding| finding.code == "missing-linux-personality-trace-artifact")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn visa_ltp_subset_report_gates_with_raw_log_and_execution_trace() {
    let root = temp_criterion_dir("visa-ltp-subset");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("linux-ltp.fs.basic.log"), "open01 1 TPASS : passed\n").unwrap();
    write_ltp_trace(&root, LtpSubset::FsBasic, "open01");

    let report = ltp_visa_subset_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    )
    .unwrap();
    let validation = validate_report(&report, &linux_ltp_catalog());
    let artifact_validation = validate_report_artifacts(&report, &root);
    let gate = gate_report_json(&serde_json::to_vec(&report).unwrap(), &linux_ltp_catalog());

    assert!(validation.ok, "{:#?}", validation.findings);
    assert!(artifact_validation.ok, "{:#?}", artifact_validation.findings);
    assert!(gate.ok, "{gate:#?}");
    assert_eq!(report.suite_id, LTP_VISA_SUBSET_SUITE_ID);
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].spec_id, LtpSubset::FsBasic.spec_id());
    assert_eq!(report.results[0].evidence_artifacts.len(), 2);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn visa_ltp_subset_report_aggregates_per_case_logs() {
    let root = temp_criterion_dir("visa-ltp-per-case");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("linux-ltp.syscalls.core.getpid01.log"),
        "getpid01 1 TPASS : getpid passed\n",
    )
    .unwrap();
    fs::write(root.join("linux-ltp.syscalls.core.uname01.log"), "uname01 1 TPASS : uname passed\n")
        .unwrap();
    write_ltp_trace_file(
        &root,
        LtpSubset::SyscallsCore,
        "getpid01",
        "linux-ltp.syscalls.core.getpid01.visa-trace.jsonl",
        "linux-ltp.syscalls.core.getpid01.log",
        "linux-ltp.syscalls.core.getpid01.serial.log",
    );
    write_ltp_trace_file(
        &root,
        LtpSubset::SyscallsCore,
        "uname01",
        "linux-ltp.syscalls.core.uname01.visa-trace.jsonl",
        "linux-ltp.syscalls.core.uname01.log",
        "linux-ltp.syscalls.core.uname01.serial.log",
    );

    let report = ltp_visa_subset_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    )
    .unwrap();
    let validation = validate_report(&report, &linux_ltp_catalog());
    let artifact_validation = validate_report_artifacts(&report, &root);

    assert!(validation.ok, "{:#?}", validation.findings);
    assert!(artifact_validation.ok, "{:#?}", artifact_validation.findings);
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].spec_id, LtpSubset::SyscallsCore.spec_id());
    assert_eq!(report.results[0].metrics["ltp_cases_passed"], 2.0);
    assert_eq!(report.results[0].evidence_artifacts.len(), 4);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn ltp_report_ignores_host_runltp_transport_logs_as_raw_results() {
    let root = temp_criterion_dir("ltp-host-transport-logs");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("linux-ltp.fs.basic.log"), "open01 1 TPASS : passed\n").unwrap();
    fs::write(root.join("linux-ltp.fs.basic.host-runltp.log"), "host wrapper stdout only\n")
        .unwrap();

    let report = ltp_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &root,
    )
    .unwrap();
    let fs_result = report
        .results
        .iter()
        .find(|result| result.spec_id == LtpSubset::FsBasic.spec_id())
        .unwrap();

    assert_eq!(fs_result.metrics["ltp_cases_passed"], 1.0);
    assert_eq!(fs_result.evidence_artifacts.len(), 1);
    assert_eq!(fs_result.evidence_artifacts[0].uri, "linux-ltp.fs.basic.log");
    let artifact_validation = validate_report_artifacts(&report, &root);
    assert!(artifact_validation.ok, "{:#?}", artifact_validation.findings);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn visa_ltp_plan_uses_expanded_stable_fs_mm_syscall_timer_socket_cases() {
    let plan = default_visa_ltp_plan("target/visa-ltp", "target/ltp-bins");

    assert_eq!(plan.len(), 12);
    assert_eq!(plan[0].spec_id, LtpSubset::FsBasic.spec_id());
    assert_eq!(plan[0].case_id, "open01");
    assert_eq!(plan[1].spec_id, LtpSubset::MmMapping.spec_id());
    assert_eq!(plan[1].case_id, "mmap01");
    assert!(plan.iter().any(|entry| entry.case_id == "brk01"));
    assert!(plan.iter().any(|entry| entry.case_id == "getpid01"));
    assert!(plan.iter().any(|entry| entry.case_id == "uname01"));
    assert!(plan.iter().any(|entry| entry.case_id == "getuid01"));
    assert!(plan.iter().any(|entry| entry.case_id == "gettid01"));
    assert!(plan.iter().any(|entry| entry.case_id == "read01"));
    assert!(plan.iter().any(|entry| entry.case_id == "write01"));
    assert!(plan.iter().any(|entry| entry.case_id == "clock_gettime01"));
    assert!(plan.iter().any(|entry| entry.case_id == "nanosleep01"));
    assert!(plan.iter().any(|entry| entry.case_id == "socket01"));
    assert!(plan.iter().all(|entry| entry.output_log.contains(&entry.case_id)));
    assert!(plan.iter().all(|entry| entry.trace_log.contains(&entry.case_id)));
    assert!(plan.iter().all(|entry| entry.serial_log.contains(&entry.case_id)));
    assert!(plan.iter().all(|entry| entry.output_log.ends_with(".log")));
    assert!(plan.iter().all(|entry| entry.trace_log.ends_with(".visa-trace.jsonl")));
    assert!(plan.iter().all(|entry| entry.serial_log.ends_with(".serial.log")));
}

#[test]
fn visa_ltp_manifest_plan_accepts_large_candidate_entries() {
    let manifest = "\
# spec_id\tcase_id\trelative_binary\tsource
linux-ltp.syscalls.core\taccept01\taccept01\ttestcases/kernel/syscalls/accept/accept01
linux-ltp.syscalls.core\topenat201\tsyscalls/openat201\ttestcases/kernel/syscalls/openat2/openat201
linux-ltp.mm.mapping\tmmap01\tmmap01\ttestcases/kernel/syscalls/mmap/mmap01
";
    let plan =
        visa_ltp_manifest_plan("target/visa-ltp-large", "target/ltp-bins", manifest).unwrap();

    assert_eq!(plan.len(), 3);
    assert_eq!(plan[0].spec_id, LtpSubset::SyscallsCore.spec_id());
    assert_eq!(plan[0].case_id, "accept01");
    assert_eq!(plan[0].binary_path, "target/ltp-bins/accept01");
    assert_eq!(plan[1].binary_path, "target/ltp-bins/syscalls/openat201");
    assert!(plan[1].output_log.ends_with("linux-ltp.syscalls.core.openat201.log"));
    assert!(plan[1].trace_log.ends_with("linux-ltp.syscalls.core.openat201.visa-trace.jsonl"));
    assert!(plan[1].serial_log.ends_with("linux-ltp.syscalls.core.openat201.serial.log"));
    assert_eq!(plan[2].spec_id, LtpSubset::MmMapping.spec_id());
}

#[test]
fn visa_ltp_manifest_plan_rejects_unsafe_entries() {
    assert!(
        visa_ltp_manifest_plan("target/out", "target/bins", "linux-ltp.unknown\tcase01\tcase01")
            .unwrap_err()
            .contains("unknown LTP spec id")
    );
    assert!(
        visa_ltp_manifest_plan(
            "target/out",
            "target/bins",
            "linux-ltp.syscalls.core\t../bad\tcase01"
        )
        .unwrap_err()
        .contains("not safe")
    );
    assert!(
        visa_ltp_manifest_plan(
            "target/out",
            "target/bins",
            "linux-ltp.syscalls.core\tcase01\t../case01"
        )
        .unwrap_err()
        .contains("must not contain")
    );
    assert!(
        visa_ltp_manifest_plan(
            "target/out",
            "target/bins",
            "linux-ltp.syscalls.core\tcase01\t/tmp/case01"
        )
        .unwrap_err()
        .contains("must be relative")
    );
}

#[test]
fn visa_ltp_serial_helpers_preserve_ltp_output_and_trace_execution_path() {
    let serial = "== ring3 real ELF demo ==\nopen01 1 TPASS : passed\nHostcallEntered label=ring3_openat class=immediate-privileged-op subject=linux_syscall object=vfs_service op=lookup\nvisa: demo completed\n";
    let raw = ltp_raw_log_from_serial("open01", serial, 0);
    let trace = ltp_visa_trace_from_serial(
        LtpSubset::FsBasic.spec_id(),
        "open01",
        "target/ltp-bins/open01",
        "linux-ltp.fs.basic.log",
        "linux-ltp.fs.basic.serial.log",
        serial,
        0,
    );

    assert_eq!(raw, "open01 1 TPASS : passed\n");
    assert_eq!(trace["schema_version"], LTP_VISA_TRACE_SCHEMA_VERSION);
    assert_eq!(trace["entered_visa_execution"], true);
    assert_eq!(trace["linux_personality_dispatch"], true);
    assert_eq!(trace["syscalls_observed"], 1);
    assert!(trace["service_syscalls_observed"].as_u64().unwrap() >= 1);
}

#[test]
fn sample_ltp_report_validates_against_ltp_catalog() {
    let catalog = linux_ltp_catalog();
    let report = sample_ltp_report();
    let validation = validate_report(&report, &catalog);

    assert!(validation.ok, "{:#?}", validation.findings);
    assert!(report.results.iter().all(|result| {
        result.observed_boundary == Boundary::PortableArtifactExecution
            && matches!(result.outcome, Outcome::Pass)
            && result
                .evidence_artifacts
                .iter()
                .any(|artifact| artifact.kind == EvidenceArtifactKind::LtpRawLog)
            && result
                .evidence_artifacts
                .iter()
                .any(|artifact| artifact.kind == EvidenceArtifactKind::LinuxPersonalityTrace)
    }));
}

fn write_ltp_trace(root: &Path, subset: LtpSubset, case_id: &str) {
    write_ltp_trace_file(
        root,
        subset,
        case_id,
        &format!("{}.visa-trace.jsonl", subset.spec_id()),
        &format!("{}.log", subset.spec_id()),
        &format!("{}.serial.log", subset.spec_id()),
    );
}

fn write_ltp_trace_file(
    root: &Path,
    subset: LtpSubset,
    case_id: &str,
    trace_name: &str,
    raw_name: &str,
    serial_name: &str,
) {
    let trace = format!(
        "{{\"schema_version\":\"{}\",\"spec_id\":\"{}\",\"case_id\":\"{}\",\"test_binary\":\"target/ltp-bins/{}\",\"runner\":\"visa-linux-personality\",\"entered_visa_execution\":true,\"linux_personality_dispatch\":true,\"syscalls_observed\":1,\"service_syscalls_observed\":1,\"exit_status\":0,\"runner_status\":0,\"raw_log_uri\":\"{}\",\"serial_log_uri\":\"{}\"}}\n",
        LTP_VISA_TRACE_SCHEMA_VERSION,
        subset.spec_id(),
        case_id,
        case_id,
        raw_name,
        serial_name
    );
    fs::write(root.join(trace_name), trace).unwrap();
}

fn temp_criterion_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("visa-conformance-{name}-{}-{nonce}", std::process::id()))
}

fn write_criterion_estimate(root: &Path, benchmark_id: &str, mean_ns: f64) {
    let dir = root.join(benchmark_id).join("base");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("estimates.json"),
        format!(
            r#"{{
  "mean": {{
    "confidence_interval": {{
      "confidence_level": 0.95,
      "lower_bound": {mean_ns},
      "upper_bound": {mean_ns}
    }},
    "point_estimate": {mean_ns},
    "standard_error": 0.0
  }}
}}"#
        ),
    )
    .unwrap();
}

fn real_target_extraction_artifact() -> EvidenceArtifact {
    EvidenceArtifact {
        kind: EvidenceArtifactKind::SubstrateExtractionTrace,
        uri: "target/evidence/substrate-extraction.jsonl".to_string(),
        sha256: "a".repeat(64),
        description: "real target substrate authority extraction trace".to_string(),
    }
}

fn contract_graph_snapshot_artifact() -> EvidenceArtifact {
    EvidenceArtifact {
        kind: EvidenceArtifactKind::ContractGraphSnapshot,
        uri: "target/evidence/contract-graph-snapshot.json".to_string(),
        sha256: "b".repeat(64),
        description: "contract graph snapshot for portable vISA semantic evidence".to_string(),
    }
}

fn contract_graph_snapshot_json(claimed_boundary: &str) -> String {
    contract_graph_snapshot_json_with_schema(
        CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION,
        claimed_boundary,
    )
}

fn contract_graph_snapshot_json_with_schema(
    schema_version: &str,
    claimed_boundary: &str,
) -> String {
    format!(
        r#"{{
  "schema_version": "{schema_version}",
  "claimed_evidence_level": "{claimed_boundary}",
  "artifacts": [],
  "code_objects": [],
  "stores": [],
  "activations": [],
  "hostcalls": [],
  "traps": [],
  "capabilities": [],
  "waits": [],
  "cleanup_transactions": [],
  "tombstones": [],
  "external_objects": [],
  "explicit_edges": []
}}"#
    )
}

fn passing_substrate_report(profile: SubstrateProfile) -> SubstrateConformanceReport {
    let capabilities = SubstrateCapabilitySet::for_profile(profile);
    SubstrateConformanceReport {
        profile,
        capabilities,
        compatibility: capabilities.check_profile(profile),
        checks: vec![ConformanceCheck {
            check: "unit-required-check",
            required: true,
            status: ConformanceStatus::Passed,
            detail: "ok",
        }],
        ok: true,
    }
}
