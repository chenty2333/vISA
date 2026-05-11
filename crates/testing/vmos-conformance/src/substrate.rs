use std::collections::BTreeMap;

use substrate_api::conformance::{
    ConformanceEvidenceContext, ConformanceStatus, SubstrateConformanceReport,
};
use visa_profile::SubstrateProfile;

use crate::types::{Boundary, ConformanceReport, Outcome, REPORT_SCHEMA_VERSION, TestResult};

pub fn substrate_profile_spec_id(profile: SubstrateProfile) -> &'static str {
    match profile {
        SubstrateProfile::SemanticHarness => "substrate.p0.semantic.harness",
        SubstrateProfile::MinimalBareMetal => "substrate.p1.console.timer.event",
        SubstrateProfile::GuestFrontend => "substrate.p2.memory.dmw",
        SubstrateProfile::DeviceCapable => "substrate.p3.mmio.dma.irq",
        SubstrateProfile::SnapshotReplayCapable => "substrate.p4.snapshot.replay",
    }
}

pub fn substrate_report_from_conformance(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    report: &SubstrateConformanceReport,
    context: ConformanceEvidenceContext,
) -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-substrate-profile-conformance".to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results: vec![substrate_result_from_conformance(report, observed_boundary, context)],
    }
}

pub fn substrate_result_from_conformance(
    report: &SubstrateConformanceReport,
    observed_boundary: Boundary,
    context: ConformanceEvidenceContext,
) -> TestResult {
    let evidence_summary = report.evidence_summary(context);
    let failed_checks =
        report.checks.iter().filter(|check| check.status == ConformanceStatus::Failed).count();
    let passed_required = report
        .checks
        .iter()
        .filter(|check| check.required && check.status == ConformanceStatus::Passed)
        .count();
    let required_checks = report.checks.iter().filter(|check| check.required).count();
    let real_target_boundary_ok = observed_boundary != Boundary::RealTargetSubstrate
        || evidence_summary.can_claim_real_target_substrate;
    let outcome = if report.ok && real_target_boundary_ok { Outcome::Pass } else { Outcome::Fail };
    let mut metrics = BTreeMap::new();
    metrics.insert("total_checks".to_string(), report.checks.len() as f64);
    metrics.insert("required_checks".to_string(), required_checks as f64);
    metrics.insert("passed_required_checks".to_string(), passed_required as f64);
    metrics.insert("failed_checks".to_string(), failed_checks as f64);
    metrics.insert(
        "real_target_extraction_event_count".to_string(),
        evidence_summary.real_target_extraction_event_count as f64,
    );
    TestResult {
        spec_id: substrate_profile_spec_id(report.profile).to_string(),
        outcome,
        observed_boundary,
        observed_profile: Some(report.profile.as_str().to_string()),
        evidence: format!(
            "substrate profile {} checks: {}/{} required passed, {} failed, strongest={}",
            report.profile.as_str(),
            passed_required,
            required_checks,
            failed_checks,
            evidence_summary.strongest_profile.map(SubstrateProfile::as_str).unwrap_or("none")
        ),
        remaining_uncertainty: remaining_uncertainty(observed_boundary, real_target_boundary_ok),
        metrics,
        evidence_artifacts: Vec::new(),
    }
}

fn remaining_uncertainty(observed_boundary: Boundary, real_target_boundary_ok: bool) -> String {
    if observed_boundary == Boundary::RealTargetSubstrate && !real_target_boundary_ok {
        "report requested real-target-substrate, but the substrate conformance context did not include a supported concrete arch with extraction events".to_string()
    } else if observed_boundary == Boundary::RealTargetSubstrate {
        "real target substrate claim still requires a linked extraction or device trace artifact in the outer conformance report".to_string()
    } else {
        "host-side substrate conformance does not prove real target substrate execution".to_string()
    }
}
