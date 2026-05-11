use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
    assert!(spec.runner.contains("vms_wasmtime"));
    assert!(spec.does_not_prove.iter().any(|item| item.contains("Linux personality")));
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
    assert_eq!(report.suite_id, "vmos-substrate-profile-conformance");
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
        suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
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
fn attach_evidence_artifact_can_target_all_results() {
    let mut report = sample_ltp_report();
    let attached = attach_evidence_artifact(&mut report, "*", real_target_extraction_artifact());

    assert_eq!(attached, LtpSubset::ALL.len());
    assert!(report.results.iter().all(|result| result.evidence_artifacts.len() == 2));
}

#[test]
fn evidence_artifact_kind_parse_is_stable() {
    assert_eq!(
        EvidenceArtifactKind::parse("substrate-extraction-trace"),
        Some(EvidenceArtifactKind::SubstrateExtractionTrace)
    );
    assert_eq!(EvidenceArtifactKind::DeviceTrace.as_str(), "device-trace");
    assert_eq!(EvidenceArtifactKind::parse("unknown"), None);
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
fn artifact_gate_validates_real_target_extraction_trace_files() {
    let root = temp_criterion_dir("real-target-artifact");
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
        uri: trace.display().to_string(),
        sha256,
        description: "real target substrate authority extraction trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, ".");

    assert!(validation.ok, "{:#?}", validation.findings);
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
        uri: trace.display().to_string(),
        sha256,
        description: "real target device trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, ".");

    assert!(validation.ok, "{:#?}", validation.findings);
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
        uri: trace.display().to_string(),
        sha256: "c".repeat(64),
        description: "bad trace".to_string(),
    });

    let validation = validate_report_artifacts(&report, ".");

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
        suite_id: "vmos-performance-benchmark".to_string(),
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
        suite_id: "vmos-performance-benchmark".to_string(),
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
        suite_id: "vmos-performance-benchmark".to_string(),
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
    }
    let ltp_report = ltp_report_from_log_dir(
        "unit-test",
        "unit-test",
        Boundary::PortableArtifactExecution,
        None,
        &ltp_root,
    )
    .unwrap();
    let ltp_artifact_validation = validate_report_artifacts(&ltp_report, ".");
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
    let performance_artifact_validation = validate_report_artifacts(&performance_report, ".");
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
    let cases = parse_ltp_results(
        r#"
open01 1 TPASS : open succeeded
rename01 1 TFAIL : rename failed
mmap01 1 TCONF : unsupported configuration
"#,
    );

    assert_eq!(cases.len(), 3);
    assert_eq!(cases[0].case_id, "open01");
    assert_eq!(cases[0].outcome, Outcome::Pass);
    assert_eq!(cases[1].outcome, Outcome::Fail);
    assert_eq!(cases[2].outcome, Outcome::Skip);
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
        result.evidence_artifacts.len() == 1
            && result.evidence_artifacts[0].kind == EvidenceArtifactKind::LtpRawLog
            && result.evidence_artifacts[0].sha256.len() == 64
            && result.evidence_artifacts[0].uri.ends_with(&format!("{}.log", result.spec_id))
    }));

    let _ = fs::remove_dir_all(root);
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
            && result.evidence_artifacts.len() == 1
            && result.evidence_artifacts[0].kind == EvidenceArtifactKind::LtpRawLog
    }));
}

fn temp_criterion_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("vmos-conformance-{name}-{}-{nonce}", std::process::id()))
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
