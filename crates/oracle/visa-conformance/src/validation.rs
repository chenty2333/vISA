use std::collections::{BTreeMap, BTreeSet};

use visa_profile::SubstrateProfile;

use crate::{
    artifacts::artifact_uri_is_bundle_relative,
    catalog::{linux_ltp_catalog, performance_catalog, substrate_profile_catalog},
    ltp::{LTP_FULL_SUITE_ID, LTP_VISA_SUBSET_SUITE_ID},
    performance::required_performance_metrics,
    types::{
        Boundary, ClaimKind, ConformanceReport, EvidenceArtifactKind, Outcome, Personality,
        REPORT_SCHEMA_VERSION, ReportGateResult, ReportLoadError, TestResult, TestSpec,
        ValidationFinding, ValidationReport,
    },
};

pub fn validate_catalog(specs: &[TestSpec]) -> ValidationReport {
    let mut findings = Vec::new();
    let mut ids = BTreeSet::new();
    for spec in specs {
        if !ids.insert(spec.id.as_str()) {
            findings.push(finding("duplicate-spec-id", format!("duplicate spec id {}", spec.id)));
        }
        validate_spec(spec, &mut findings);
    }
    ValidationReport::new(findings)
}

pub fn validate_report(report: &ConformanceReport, catalog: &[TestSpec]) -> ValidationReport {
    let mut findings = Vec::new();
    if report.schema_version != REPORT_SCHEMA_VERSION {
        findings.push(finding(
            "unsupported-report-schema",
            format!("unsupported schema {}", report.schema_version),
        ));
    }
    if report.suite_id.trim().is_empty() {
        findings.push(finding("missing-report-suite-id", "report suite id is empty"));
    }
    if report.target.trim().is_empty() {
        findings.push(finding("missing-report-target", "report target is empty"));
    }
    if report.generated_by.trim().is_empty() {
        findings.push(finding("missing-report-generator", "report generator is empty"));
    }
    if report.results.is_empty() {
        findings.push(finding("empty-report", "report contains no results"));
    }
    let spec_by_id =
        catalog.iter().map(|spec| (spec.id.as_str(), spec)).collect::<BTreeMap<_, _>>();
    let allowed_suite_ids = suite_allowed_result_ids(&report.suite_id, catalog);
    let mut result_ids = BTreeSet::new();
    for result in &report.results {
        if !result_ids.insert(result.spec_id.as_str()) {
            findings.push(finding(
                "duplicate-result-spec-id",
                format!("duplicate result for spec id {}", result.spec_id),
            ));
        }
        let Some(spec) = spec_by_id.get(result.spec_id.as_str()) else {
            findings
                .push(finding("unknown-spec-id", format!("unknown spec id {}", result.spec_id)));
            continue;
        };
        if let Some(allowed_suite_ids) = &allowed_suite_ids
            && !allowed_suite_ids.contains(result.spec_id.as_str())
        {
            findings.push(finding(
                "unexpected-suite-result",
                format!("{} does not belong to suite {}", result.spec_id, report.suite_id),
            ));
        }
        if !result.observed_boundary.can_claim(spec.minimum_boundary) {
            findings.push(finding(
                "insufficient-evidence-boundary",
                format!(
                    "{} observed {} but requires {}",
                    result.spec_id,
                    result.observed_boundary.as_str(),
                    spec.minimum_boundary.as_str()
                ),
            ));
        }
        validate_result_profile(spec, result, &mut findings);
        validate_evidence_artifacts(result, &mut findings);
        if is_linux_ltp_spec(spec)
            && !matches!(result.outcome, Outcome::NotRun)
            && !has_ltp_raw_log_artifact(result)
        {
            findings.push(finding(
                "missing-ltp-raw-log-artifact",
                format!("{} reports LTP execution without a raw log artifact", result.spec_id),
            ));
        }
        if is_linux_ltp_spec(spec)
            && matches!(result.outcome, Outcome::Pass | Outcome::Fail)
            && result.observed_boundary.can_claim(Boundary::PortableArtifactExecution)
            && !has_linux_personality_trace_artifact(result)
        {
            findings.push(finding(
                "missing-linux-personality-trace-artifact",
                format!(
                    "{} claims vISA-backed Linux personality execution without a Linux personality trace artifact",
                    result.spec_id
                ),
            ));
        }
        if matches!(result.outcome, Outcome::Pass | Outcome::Fail) {
            if result.evidence.trim().is_empty() {
                findings.push(finding(
                    "missing-evidence",
                    format!("{} has no evidence text", result.spec_id),
                ));
            }
            if result.remaining_uncertainty.trim().is_empty() {
                findings.push(finding(
                    "missing-remaining-uncertainty",
                    format!("{} has no remaining uncertainty text", result.spec_id),
                ));
            }
            if spec.claim == ClaimKind::PerformanceBenchmark {
                validate_performance_metrics(result, &mut findings);
            }
            if spec.claim == ClaimKind::VisaSemanticConformance
                && result.observed_boundary.can_claim(Boundary::PortableArtifactExecution)
                && !has_contract_graph_snapshot_artifact(result)
            {
                findings.push(finding(
                    "missing-contract-graph-snapshot-artifact",
                    format!(
                        "{} claims portable vISA semantic execution without a contract graph snapshot artifact",
                        result.spec_id
                    ),
                ));
            }
            if profile_gate_event_count(result) > 0.0 && !has_profile_gate_trace_artifact(result) {
                findings.push(finding(
                    "missing-profile-gate-trace-artifact",
                    format!(
                        "{} reports profile gate events without a profile gate trace artifact",
                        result.spec_id
                    ),
                ));
            }
            if unsupported_substrate_event_count(result) > 0.0
                && !has_substrate_event_trace_artifact(result)
            {
                findings.push(finding(
                    "missing-substrate-event-trace-artifact",
                    format!(
                        "{} reports unsupported substrate events without a substrate event trace artifact",
                        result.spec_id
                    ),
                ));
            }
            if denied_substrate_event_count(result) > 0.0
                && !has_substrate_event_trace_artifact(result)
            {
                findings.push(finding(
                    "missing-substrate-event-trace-artifact",
                    format!(
                        "{} reports denied substrate events without a substrate event trace artifact",
                        result.spec_id
                    ),
                ));
            }
            if authority_extraction_event_count(result) > 0.0
                && !has_substrate_event_trace_artifact(result)
                && !has_substrate_extraction_trace_artifact(result)
            {
                findings.push(finding(
                    "missing-substrate-event-trace-artifact",
                    format!(
                        "{} reports substrate authority extraction events without a substrate event or extraction trace artifact",
                        result.spec_id
                    ),
                ));
            }
            if result.observed_boundary == Boundary::RealTargetSubstrate
                && !has_real_target_extraction_artifact(result)
            {
                findings.push(finding(
                    "missing-real-target-extraction-artifact",
                    format!(
                        "{} claims real-target-substrate without substrate extraction or device trace artifact",
                        result.spec_id
                    ),
                ));
            }
        }
    }
    validate_suite_coverage(report, &result_ids, catalog, &mut findings);
    ValidationReport::new(findings)
}

fn validate_evidence_artifacts(result: &TestResult, findings: &mut Vec<ValidationFinding>) {
    let mut artifact_keys = BTreeSet::new();
    for artifact in &result.evidence_artifacts {
        if artifact.uri.trim().is_empty() {
            findings.push(finding(
                "empty-evidence-artifact-uri",
                format!("{} has evidence artifact without uri", result.spec_id),
            ));
        } else if !artifact_uri_is_bundle_relative(&artifact.uri) {
            findings.push(finding(
                "non-bundle-relative-evidence-artifact-uri",
                format!(
                    "{} evidence artifact uri {} must be relative to the artifact root",
                    result.spec_id, artifact.uri
                ),
            ));
        }
        if artifact.description.trim().is_empty() {
            findings.push(finding(
                "empty-evidence-artifact-description",
                format!("{} has evidence artifact without description", result.spec_id),
            ));
        }
        if !is_sha256_hex(&artifact.sha256) {
            findings.push(finding(
                "invalid-evidence-artifact-sha256",
                format!("{} has evidence artifact with invalid sha256", result.spec_id),
            ));
        }
        let key = (artifact.kind, artifact.uri.as_str());
        if !artifact_keys.insert(key) {
            findings.push(finding(
                "duplicate-evidence-artifact",
                format!("{} repeats evidence artifact {}", result.spec_id, artifact.uri),
            ));
        }
    }
}

fn validate_result_profile(
    spec: &TestSpec,
    result: &TestResult,
    findings: &mut Vec<ValidationFinding>,
) {
    let observed = match result.observed_profile.as_deref() {
        Some(profile) => match SubstrateProfile::parse(profile) {
            Some(profile) => Some(profile),
            None => {
                findings.push(finding(
                    "unknown-observed-profile",
                    format!("{} observed unknown profile {}", result.spec_id, profile),
                ));
                None
            }
        },
        None => None,
    };
    let required = spec.required_profile.as_deref().and_then(SubstrateProfile::parse);
    let Some(required) = required else {
        return;
    };
    if !matches!(result.outcome, Outcome::Pass | Outcome::Fail) {
        return;
    }
    if observed.is_none() {
        findings.push(finding(
            "missing-observed-profile",
            format!(
                "{} requires profile {} but result has no observed profile",
                result.spec_id,
                required.as_str()
            ),
        ));
        return;
    }
    if let Some(observed) = observed
        && !observed.satisfies(required)
    {
        findings.push(finding(
            "insufficient-observed-profile",
            format!(
                "{} observed profile {} but requires {}",
                result.spec_id,
                observed.as_str(),
                required.as_str()
            ),
        ));
    }
}

fn has_real_target_extraction_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        matches!(
            artifact.kind,
            EvidenceArtifactKind::SubstrateExtractionTrace | EvidenceArtifactKind::DeviceTrace
        ) && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_profile_gate_trace_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::ProfileGateTrace
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_substrate_event_trace_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::SubstrateEventTrace
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_substrate_extraction_trace_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::SubstrateExtractionTrace
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_contract_graph_snapshot_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::ContractGraphSnapshot
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_ltp_raw_log_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::LtpRawLog
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn has_linux_personality_trace_artifact(result: &TestResult) -> bool {
    result.evidence_artifacts.iter().any(|artifact| {
        artifact.kind == EvidenceArtifactKind::LinuxPersonalityTrace
            && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn profile_gate_event_count(result: &TestResult) -> f64 {
    metric_value(result, "profile_gate_event_count")
        + metric_value(result, "profile_gate_rejection_count")
        + metric_value(result, "profile_gate_degradation_count")
}

fn unsupported_substrate_event_count(result: &TestResult) -> f64 {
    metric_value(result, "unsupported_substrate_event_count")
}

fn denied_substrate_event_count(result: &TestResult) -> f64 {
    metric_value(result, "denied_substrate_event_count")
        .max(metric_value(result, "capability_denied_substrate_event_count"))
}

fn authority_extraction_event_count(result: &TestResult) -> f64 {
    metric_value(result, "authority_extraction_event_count")
        .max(metric_value(result, "substrate_authority_extraction_count"))
}

fn metric_value(result: &TestResult, name: &str) -> f64 {
    result.metrics.get(name).copied().filter(|value| *value > 0.0).unwrap_or(0.0)
}

fn is_linux_ltp_spec(spec: &TestSpec) -> bool {
    spec.claim == ClaimKind::PersonalityCompatibility
        && spec.personality == Some(Personality::Linux)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_performance_metrics(result: &TestResult, findings: &mut Vec<ValidationFinding>) {
    if result.metrics.is_empty() {
        findings.push(finding(
            "missing-performance-metrics",
            format!("{} is a performance result without metrics", result.spec_id),
        ));
        return;
    }

    for metric in required_performance_metrics(&result.spec_id) {
        if !result.metrics.contains_key(*metric) {
            findings.push(finding(
                "missing-performance-metric",
                format!("{} is missing required metric {}", result.spec_id, metric),
            ));
        }
    }

    if !result
        .evidence_artifacts
        .iter()
        .any(|artifact| artifact.kind == EvidenceArtifactKind::BenchmarkRawOutput)
    {
        findings.push(finding(
            "missing-performance-evidence-artifact",
            format!("{} is missing benchmark raw output artifact", result.spec_id),
        ));
    }

    for (name, value) in &result.metrics {
        if !value.is_finite() {
            findings.push(finding(
                "invalid-performance-metric",
                format!("{} metric {} is not finite", result.spec_id, name),
            ));
        } else if *value < 0.0 {
            findings.push(finding(
                "invalid-performance-metric",
                format!("{} metric {} is negative", result.spec_id, name),
            ));
        }
    }
}

pub fn parse_report_json(bytes: &[u8]) -> Result<ConformanceReport, ReportLoadError> {
    serde_json::from_slice(bytes).map_err(|error| ReportLoadError {
        code: "invalid-report-json".to_string(),
        detail: error.to_string(),
    })
}

pub fn gate_report_json(bytes: &[u8], catalog: &[TestSpec]) -> ReportGateResult {
    match parse_report_json(bytes) {
        Ok(report) => {
            let validation = validate_report(&report, catalog);
            let outcome_findings = report_outcome_findings(&report);
            ReportGateResult {
                ok: validation.ok && outcome_findings.is_empty(),
                load_error: None,
                validation: Some(validation),
                outcome_findings,
            }
        }
        Err(error) => ReportGateResult {
            ok: false,
            load_error: Some(error),
            validation: None,
            outcome_findings: Vec::new(),
        },
    }
}

pub fn report_outcome_findings(report: &ConformanceReport) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    for result in &report.results {
        let code = match result.outcome {
            Outcome::Pass => continue,
            Outcome::Fail => "result-failed",
            Outcome::Skip => "result-skipped",
            Outcome::NotRun => "result-not-run",
        };
        findings.push(finding(
            code,
            format!("{} reported outcome {:?}", result.spec_id, result.outcome),
        ));
    }
    findings
}

fn validate_suite_coverage(
    report: &ConformanceReport,
    result_ids: &BTreeSet<&str>,
    catalog: &[TestSpec],
    findings: &mut Vec<ValidationFinding>,
) {
    let required_ids: Vec<String> = match report.suite_id.as_str() {
        "visa-layered-conformance" => catalog.iter().map(|spec| spec.id.clone()).collect(),
        LTP_FULL_SUITE_ID => linux_ltp_catalog().into_iter().map(|spec| spec.id).collect(),
        LTP_VISA_SUBSET_SUITE_ID => return validate_ltp_subset_suite(result_ids, findings),
        "visa-substrate-profile-conformance" => {
            report.results.iter().map(|result| result.spec_id.clone()).collect()
        }
        "visa-performance-benchmark" => {
            performance_catalog().into_iter().map(|spec| spec.id).collect()
        }
        suite_id => {
            findings.push(finding("unknown-suite-id", format!("unknown suite id {suite_id}")));
            return;
        }
    };
    for spec_id in required_ids {
        if !result_ids.contains(spec_id.as_str()) {
            findings.push(finding(
                "missing-suite-result",
                format!("{} omits required result {}", report.suite_id, spec_id),
            ));
        }
    }
}

fn validate_ltp_subset_suite(result_ids: &BTreeSet<&str>, findings: &mut Vec<ValidationFinding>) {
    if result_ids.is_empty() {
        findings.push(finding(
            "empty-ltp-subset-suite",
            "vISA-backed LTP subset suite must contain at least one result",
        ));
    }
}

fn validate_spec(spec: &TestSpec, findings: &mut Vec<ValidationFinding>) {
    if spec.id.trim().is_empty() {
        findings.push(finding("empty-spec-id", "spec id is empty"));
    }
    if spec.runner.trim().is_empty() {
        findings.push(finding("empty-runner", format!("{} has no runner", spec.id)));
    }
    if let Some(profile) = &spec.required_profile
        && SubstrateProfile::parse(profile).is_none()
    {
        findings.push(finding(
            "unknown-required-profile",
            format!("{} requires unknown profile {}", spec.id, profile),
        ));
    }
    if spec.claim == ClaimKind::PersonalityCompatibility && spec.personality.is_none() {
        findings.push(finding(
            "personality-claim-missing-personality",
            format!("{} is a personality claim without a personality", spec.id),
        ));
    }
    if spec.id.starts_with("linux-ltp.") {
        if spec.claim != ClaimKind::PersonalityCompatibility
            || spec.personality != Some(Personality::Linux)
        {
            findings.push(finding(
                "ltp-boundary-misclassified",
                format!("{} must be Linux personality compatibility", spec.id),
            ));
        }
        if !spec.does_not_prove.iter().any(|item| item.contains("vISA semantic completeness")) {
            findings.push(finding(
                "ltp-missing-non-proof",
                format!(
                    "{} must state that LTP does not prove vISA semantic completeness",
                    spec.id
                ),
            ));
        }
    }
}

fn suite_allowed_result_ids(suite_id: &str, catalog: &[TestSpec]) -> Option<BTreeSet<String>> {
    match suite_id {
        "visa-layered-conformance" => Some(catalog.iter().map(|spec| spec.id.clone()).collect()),
        LTP_FULL_SUITE_ID | LTP_VISA_SUBSET_SUITE_ID => {
            Some(linux_ltp_catalog().into_iter().map(|spec| spec.id).collect())
        }
        "visa-substrate-profile-conformance" => {
            Some(substrate_profile_catalog().into_iter().map(|spec| spec.id).collect())
        }
        "visa-performance-benchmark" => {
            Some(performance_catalog().into_iter().map(|spec| spec.id).collect())
        }
        _ => None,
    }
}

fn finding(code: &str, detail: impl Into<String>) -> ValidationFinding {
    ValidationFinding { code: code.to_string(), detail: detail.into() }
}
