use std::collections::BTreeMap;

use crate::{
    catalog::{linux_ltp_catalog, performance_catalog},
    hash::sha256_hex,
    ltp::ltp_subset_result,
    performance::required_performance_metrics,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, LtpCaseResult,
        Outcome, REPORT_SCHEMA_VERSION, TestResult, TestSpec,
    },
};

pub fn sample_report(catalog: &[TestSpec]) -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-layered-conformance".to_string(),
        target: "catalog-only".to_string(),
        generated_by: "vmos-conformance sample-report".to_string(),
        results: catalog
            .iter()
            .map(|spec| TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::NotRun,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "catalog entry not executed".to_string(),
                remaining_uncertainty: "no executable result has been collected".to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: Vec::new(),
            })
            .collect(),
    }
}

pub fn sample_ltp_report() -> ConformanceReport {
    let catalog = linux_ltp_catalog();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
        target: "ltp-parser-sample".to_string(),
        generated_by: "vmos-conformance sample-ltp-report".to_string(),
        results: catalog
            .iter()
            .map(|spec| {
                let raw_log = format!(
                    "{case_prefix}_smoke_01 1 TPASS : sample LTP case passed\n{case_prefix}_smoke_02 1 TCONF : sample LTP case skipped by configuration\n",
                    case_prefix = spec.id.replace('.', "_")
                );
                let cases = [
                    LtpCaseResult {
                        case_id: format!("{}_smoke_01", spec.id.replace('.', "_")),
                        outcome: Outcome::Pass,
                        raw_status: "TPASS".to_string(),
                        detail: "sample LTP case passed".to_string(),
                    },
                    LtpCaseResult {
                        case_id: format!("{}_smoke_02", spec.id.replace('.', "_")),
                        outcome: Outcome::Skip,
                        raw_status: "TCONF".to_string(),
                        detail: "sample LTP case skipped by configuration".to_string(),
                    },
                ];
                let mut result = ltp_subset_result(
                    spec,
                    &cases,
                    Boundary::PortableArtifactExecution,
                    spec.required_profile.clone(),
                );
                result.evidence_artifacts.push(EvidenceArtifact {
                    kind: EvidenceArtifactKind::LtpRawLog,
                    uri: format!("samples/{}.log", spec.id),
                    sha256: sha256_hex(raw_log.as_bytes()),
                    description: "synthetic raw LTP log metadata for schema validation"
                        .to_string(),
                });
                result
            })
            .collect(),
    }
}

pub fn sample_performance_report() -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-performance-benchmark".to_string(),
        target: "performance-parser-sample".to_string(),
        generated_by: "vmos-conformance sample-performance-report".to_string(),
        results: performance_catalog()
            .into_iter()
            .map(|spec| {
                let mut metrics = BTreeMap::new();
                for metric in required_performance_metrics(&spec.id) {
                    metrics.insert((*metric).to_string(), 1.0);
                }
                let artifact_uri = format!("sample://{}", spec.id);
                TestResult {
                    spec_id: spec.id,
                    outcome: Outcome::Pass,
                    observed_boundary: spec.minimum_boundary,
                    observed_profile: spec.required_profile,
                    evidence: "synthetic performance metric recorded".to_string(),
                    remaining_uncertainty:
                        "sample report validates schema only; it is not a real benchmark run"
                            .to_string(),
                    metrics,
                    evidence_artifacts: vec![EvidenceArtifact {
                        kind: EvidenceArtifactKind::BenchmarkRawOutput,
                        uri: artifact_uri,
                        sha256: "b".repeat(64),
                        description: "synthetic benchmark artifact for schema validation"
                            .to_string(),
                    }],
                }
            })
            .collect(),
    }
}
