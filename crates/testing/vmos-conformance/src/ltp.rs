use std::{collections::BTreeMap, fs, io, path::Path};

use crate::{
    catalog::linux_ltp_catalog,
    hash::sha256_hex,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, LtpCaseResult,
        LtpSubset, Outcome, REPORT_SCHEMA_VERSION, TestResult, TestSpec,
    },
};

pub fn parse_ltp_results(text: &str) -> Vec<LtpCaseResult> {
    text.lines().filter_map(parse_ltp_result_line).collect()
}

pub fn parse_ltp_result_line(line: &str) -> Option<LtpCaseResult> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut case_id = trimmed.split_whitespace().next()?.trim_end_matches(':').to_string();
    let (raw_status, outcome) = trimmed.split_whitespace().find_map(|token| {
        normalize_ltp_status(token).map(|outcome| (token.to_string(), outcome))
    })?;
    if matches!(case_id.as_str(), "PASS" | "FAIL" | "TPASS" | "TFAIL" | "SKIP" | "CONF") {
        case_id = "unknown".to_string();
    }
    Some(LtpCaseResult { case_id, outcome, raw_status, detail: trimmed.to_string() })
}

pub fn ltp_subset_result(
    spec: &TestSpec,
    cases: &[LtpCaseResult],
    observed_boundary: Boundary,
    observed_profile: Option<String>,
) -> TestResult {
    let passed = cases.iter().filter(|case| case.outcome == Outcome::Pass).count();
    let failed = cases.iter().filter(|case| case.outcome == Outcome::Fail).count();
    let skipped = cases.iter().filter(|case| case.outcome == Outcome::Skip).count();
    let outcome = if failed > 0 {
        Outcome::Fail
    } else if passed > 0 {
        Outcome::Pass
    } else if skipped > 0 {
        Outcome::Skip
    } else {
        Outcome::NotRun
    };
    let mut metrics = BTreeMap::new();
    metrics.insert("ltp_cases_passed".to_string(), passed as f64);
    metrics.insert("ltp_cases_failed".to_string(), failed as f64);
    metrics.insert("ltp_cases_skipped".to_string(), skipped as f64);
    TestResult {
        spec_id: spec.id.clone(),
        outcome,
        observed_boundary,
        observed_profile,
        evidence: format!(
            "LTP subset {} parsed {} cases: {passed} passed, {failed} failed, {skipped} skipped",
            spec.id,
            cases.len()
        ),
        remaining_uncertainty: "LTP compatibility does not prove vISA semantic completeness, substrate profile conformance, or real target substrate execution unless separately claimed with matching evidence".to_string(),
        metrics,
        evidence_artifacts: Vec::new(),
    }
}

pub fn ltp_report_from_subset_logs<'a>(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    logs: impl IntoIterator<Item = (LtpSubset, &'a str)>,
) -> ConformanceReport {
    let logs = logs.into_iter().collect::<BTreeMap<_, _>>();
    let results = linux_ltp_catalog()
        .into_iter()
        .map(|spec| {
            let subset = LtpSubset::from_spec_id(&spec.id).expect("linux_ltp_catalog id mismatch");
            let observed_profile =
                observed_profile_override.clone().or_else(|| spec.required_profile.clone());
            match logs.get(&subset) {
                Some(text) => {
                    let cases = parse_ltp_results(text);
                    ltp_subset_result(&spec, &cases, observed_boundary, observed_profile)
                }
                None => TestResult {
                    spec_id: spec.id,
                    outcome: Outcome::NotRun,
                    observed_boundary,
                    observed_profile,
                    evidence: "LTP subset log was not provided".to_string(),
                    remaining_uncertainty:
                        "subset was not executed or the runner did not collect its log".to_string(),
                    metrics: BTreeMap::new(),
                    evidence_artifacts: Vec::new(),
                },
            }
        })
        .collect();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results,
    }
}

pub fn ltp_report_from_log_dir(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    log_dir: impl AsRef<Path>,
) -> io::Result<ConformanceReport> {
    let log_dir = log_dir.as_ref();
    let mut logs = Vec::new();
    for subset in LtpSubset::ALL {
        let path = log_dir.join(format!("{}.log", subset.spec_id()));
        match fs::read(&path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let artifact = EvidenceArtifact {
                    kind: EvidenceArtifactKind::LtpRawLog,
                    uri: path.display().to_string(),
                    sha256: sha256_hex(&bytes),
                    description: format!("raw LTP result log for {}", subset.spec_id()),
                };
                logs.push((subset, text, artifact));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let mut report = ltp_report_from_subset_logs(
        target,
        generated_by,
        observed_boundary,
        observed_profile_override,
        logs.iter().map(|(subset, text, _artifact)| (*subset, text.as_str())),
    );
    for result in &mut report.results {
        if let Some((_subset, _text, artifact)) =
            logs.iter().find(|(subset, _text, _artifact)| subset.spec_id() == result.spec_id)
        {
            result.evidence_artifacts.push(artifact.clone());
        }
    }
    Ok(report)
}

fn normalize_ltp_status(token: &str) -> Option<Outcome> {
    let status = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()).to_ascii_uppercase();
    match status.as_str() {
        "PASS" | "TPASS" => Some(Outcome::Pass),
        "FAIL" | "TFAIL" | "BROK" | "TBROK" => Some(Outcome::Fail),
        "CONF" | "TCONF" | "NA" | "SKIP" | "TSKIP" => Some(Outcome::Skip),
        _ => None,
    }
}
