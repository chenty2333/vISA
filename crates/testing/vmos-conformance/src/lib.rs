mod catalog;
mod ltp;
mod performance;
mod report;
mod samples;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use catalog::{
    full_catalog, linux_ltp_catalog, performance_catalog, substrate_profile_catalog,
    visa_core_catalog, wasi_personality_catalog,
};
pub use ltp::{
    ltp_report_from_log_dir, ltp_report_from_subset_logs, ltp_subset_result, parse_ltp_result_line,
    parse_ltp_results,
};
pub use performance::{
    criterion_performance_report_from_estimates_dir, required_performance_metrics,
};
pub use report::attach_evidence_artifact;
pub use samples::{sample_ltp_report, sample_performance_report, sample_report};
pub use types::{
    Boundary, CapabilityDomain, ClaimKind, ConformanceReport, EvidenceArtifact,
    EvidenceArtifactKind, LtpCaseResult, LtpInvocation, LtpSubset, Outcome, Personality,
    REPORT_SCHEMA_VERSION, ReportGateResult, ReportLoadError, TestResult, TestSpec,
    ValidationFinding, ValidationReport,
};
pub use validation::{
    gate_report_json, parse_report_json, report_outcome_findings, validate_catalog, validate_report,
};
