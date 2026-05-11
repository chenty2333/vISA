use std::collections::BTreeMap;

use substrate_api::conformance::{
    ConformanceEvidenceContext, ConformanceStatus, SubstrateConformanceReport,
};
use visa_profile::SubstrateProfile;

use crate::types::{
    Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, Outcome,
    REPORT_SCHEMA_VERSION, TestResult,
};

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
    substrate_report_from_conformance_with_artifacts(
        target,
        generated_by,
        observed_boundary,
        report,
        context,
        Vec::new(),
    )
}

pub fn substrate_report_from_conformance_with_artifacts(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    report: &SubstrateConformanceReport,
    context: ConformanceEvidenceContext,
    evidence_artifacts: Vec<EvidenceArtifact>,
) -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-substrate-profile-conformance".to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results: vec![substrate_result_from_conformance_with_artifacts(
            report,
            observed_boundary,
            context,
            evidence_artifacts,
        )],
    }
}

pub fn substrate_result_from_conformance(
    report: &SubstrateConformanceReport,
    observed_boundary: Boundary,
    context: ConformanceEvidenceContext,
) -> TestResult {
    substrate_result_from_conformance_with_artifacts(report, observed_boundary, context, Vec::new())
}

pub fn substrate_result_from_conformance_with_artifacts(
    report: &SubstrateConformanceReport,
    observed_boundary: Boundary,
    context: ConformanceEvidenceContext,
    evidence_artifacts: Vec<EvidenceArtifact>,
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
    let real_target_artifact_ok = observed_boundary != Boundary::RealTargetSubstrate
        || has_real_target_evidence_artifact(&evidence_artifacts);
    let outcome = if report.ok && real_target_boundary_ok && real_target_artifact_ok {
        Outcome::Pass
    } else {
        Outcome::Fail
    };
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
        remaining_uncertainty: remaining_uncertainty(
            observed_boundary,
            real_target_boundary_ok,
            real_target_artifact_ok,
        ),
        metrics,
        evidence_artifacts,
    }
}

fn remaining_uncertainty(
    observed_boundary: Boundary,
    real_target_boundary_ok: bool,
    real_target_artifact_ok: bool,
) -> String {
    if observed_boundary == Boundary::RealTargetSubstrate && !real_target_boundary_ok {
        "report requested real-target-substrate, but the substrate conformance context did not include a supported concrete arch with extraction events".to_string()
    } else if observed_boundary == Boundary::RealTargetSubstrate && !real_target_artifact_ok {
        "report requested real-target-substrate, but no linked substrate extraction or device trace artifact was attached".to_string()
    } else if observed_boundary == Boundary::RealTargetSubstrate {
        "real target substrate claim is linked to extraction evidence; remaining risk is target-specific runner reproducibility".to_string()
    } else {
        "host-side substrate conformance does not prove real target substrate execution".to_string()
    }
}

fn has_real_target_evidence_artifact(evidence_artifacts: &[EvidenceArtifact]) -> bool {
    evidence_artifacts.iter().any(|artifact| {
        matches!(
            artifact.kind,
            EvidenceArtifactKind::SubstrateExtractionTrace | EvidenceArtifactKind::DeviceTrace
        ) && !artifact.uri.trim().is_empty()
            && is_sha256_hex(&artifact.sha256)
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
