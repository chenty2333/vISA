mod artifacts;
mod catalog;
mod hash;
mod ltp;
mod performance;
mod report;
mod samples;
mod substrate;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use artifacts::{artifact_uri_is_bundle_relative, validate_report_artifacts};
pub use catalog::{
    full_catalog, linux_ltp_catalog, performance_catalog, substrate_profile_catalog,
    visa_core_catalog, wasi_personality_catalog,
};
pub use ltp::{
    LTP_FULL_SUITE_ID, LTP_VISA_SUBSET_SUITE_ID, LTP_VISA_TRACE_SCHEMA_VERSION,
    default_visa_ltp_plan, ltp_raw_log_from_serial, ltp_report_from_log_dir,
    ltp_report_from_subset_logs, ltp_subset_report_from_present_logs, ltp_subset_result,
    ltp_visa_subset_report_from_log_dir, ltp_visa_trace_from_serial, parse_ltp_result_line,
    parse_ltp_results, visa_ltp_manifest_plan,
};
pub use performance::{
    PerformancePlanEntry, criterion_performance_plan_entries,
    criterion_performance_report_from_estimates_dir,
    criterion_performance_report_from_estimates_dir_with_boundary, required_performance_metrics,
};
pub use report::attach_evidence_artifact;
pub use samples::{sample_ltp_report, sample_performance_report, sample_report};
pub use substrate::{
    substrate_profile_spec_id, substrate_report_from_conformance,
    substrate_report_from_conformance_with_artifacts, substrate_result_from_conformance,
    substrate_result_from_conformance_with_artifacts,
};
pub use types::{
    Boundary, CapabilityDomain, ClaimKind, ConformanceReport, EvidenceArtifact,
    EvidenceArtifactKind, LtpCaseResult, LtpInvocation, LtpPlanEntry, LtpSubset, Outcome,
    Personality, REPORT_SCHEMA_VERSION, ReportGateResult, ReportLoadError, TestResult, TestSpec,
    ValidationFinding, ValidationReport,
};
pub use validation::{
    gate_report_json, parse_report_json, report_outcome_findings, validate_catalog, validate_report,
};
