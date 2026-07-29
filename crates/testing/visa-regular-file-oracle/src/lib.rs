//! Independent semantic oracle for regular-file continuity observations.
//!
//! The oracle owns its decoder, registry, validation rules, projections, and
//! equivalence comparison. Its Cargo graph intentionally contains no vISA
//! workspace path dependency.

mod wire;

#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use wire::{
    CaseObservation, CleanupObservation, DestinationBindingState, ErrorCode,
    FileDurabilityObservation, FileEntryObservation, FileLockStateObservation, GenericCallResult,
    ObservationActor, ObservationBundle, ObservationPhase, OperationCallResult,
    OperationOutcomeObservation, OsAction, ProtocolAction, RawObservationEvent, RegularFileCase,
    RegularFileOperationObservation, RegularFileOutputObservation, RouteMode,
};

pub const ORACLE_REPORT_SCHEMA_VERSION: &str = "regular-file-oracle-report-v2";
pub const EQUIVALENCE_REPORT_SCHEMA_VERSION: &str = "regular-file-equivalence-oracle-report-v2";
const CARRIER_PROBE_CASES: [RegularFileCase; 2] =
    [RegularFileCase::ReadWriteOffset, RegularFileCase::AppendContinuity];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    CompleteRegistry,
    CarrierProbe,
    AnySubset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierProbeRoute {
    Restart,
    CarrierOnly,
    NaiveReopen,
    VisaPlusCarrier,
}

impl CarrierProbeRoute {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "restart" => Ok(Self::Restart),
            "carrier-only" => Ok(Self::CarrierOnly),
            "naive-reopen" => Ok(Self::NaiveReopen),
            "visa-plus-carrier" => Ok(Self::VisaPlusCarrier),
            other => Err(format!("unsupported carrier probe route {other:?}")),
        }
    }

    const fn wire(self) -> RouteMode {
        match self {
            Self::Restart => RouteMode::Restart,
            Self::CarrierOnly => RouteMode::CarrierOnly,
            Self::NaiveReopen => RouteMode::NaiveReopen,
            Self::VisaPlusCarrier => RouteMode::VisaPlusCarrier,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::CarrierOnly => "carrier_only",
            Self::NaiveReopen => "naive_reopen",
            Self::VisaPlusCarrier => "visa_plus_carrier",
        }
    }

    const fn uses_checkpoint_carrier(self) -> bool {
        !matches!(self, Self::Restart)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CarrierProbeExpectation<'a> {
    pub route: CarrierProbeRoute,
    pub artifact_root: &'a Path,
    pub carrier_revision: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage3aEndpointExpectation {
    pub instance_id: String,
    pub runtime: String,
    pub runtime_version: String,
    pub operating_system: String,
    pub isa: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage3aTopologyExpectation {
    pub source: Stage3aEndpointExpectation,
    pub destination: Stage3aEndpointExpectation,
    pub candidate_execution_boundary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleFinding {
    pub code: String,
    pub case_id: Option<String>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedTerminal {
    UninterruptedCompleted,
    ExecutionBlocked,
    HandoffCommitted,
    HandoffBlocked,
    ProfileRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedAssertion {
    pub name: String,
    pub passed: bool,
    pub supporting_sequences: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleBundleReport {
    pub schema_version: String,
    pub bundle_id: Option<String>,
    pub route_mode: Option<String>,
    pub accepted: bool,
    pub cases: Vec<OracleCaseReport>,
    pub findings: Vec<OracleFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCaseReport {
    pub case_id: String,
    pub accepted: bool,
    pub terminal: Option<DerivedTerminal>,
    pub assertions: Vec<DerivedAssertion>,
    pub projection: Option<ObservableProjection>,
    pub findings: Vec<OracleFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableProjection {
    pub case_id: String,
    pub initial_file: ObservableFile,
    pub final_files: Vec<ObservableFile>,
    pub operation_calls: Vec<ObservableOperationCall>,
    pub final_profile_state: Option<ObservableProfileState>,
    pub client_outputs: Vec<ObservableClientOutput>,
    pub process_exit: Option<ObservableProcessExit>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableFile {
    pub path: Vec<u8>,
    pub state: ObservableFileState,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservableFileState {
    Missing,
    File { size: u64, sha256: String },
    ProbeError { code: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableOperationCall {
    pub operation: ObservableOperation,
    pub result: ObservableOperationResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservableOperation {
    Read { max_bytes: u32 },
    Write { bytes_sha256: String, bytes_len: u64, durability: String },
    Append { bytes_sha256: String, bytes_len: u64, durability: String },
    Truncate { size: u64, durability: String },
    Rename { relative_path: Vec<u8> },
    Sync { durability: String },
    AcquireLock,
    ReleaseLock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservableOperationResult {
    Read {
        bytes_sha256: String,
        bytes_len: u64,
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest_hex: String,
    },
    Mutated {
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest_hex: String,
        durability: String,
    },
    Renamed {
        relative_path: Vec<u8>,
        version: u64,
        content_digest_hex: String,
    },
    Synced {
        version: u64,
        durability: String,
    },
    Lock {
        state: String,
    },
    Error {
        domain: String,
        code: String,
        errno: Option<i32>,
        retryable: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableProfileState {
    pub relative_path: Vec<u8>,
    pub logical_offset: u64,
    pub version: u64,
    pub size: u64,
    pub content_digest_hex: String,
    pub durability: String,
    pub lock_state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableClientOutput {
    pub channel: String,
    pub bytes_sha256: String,
    pub bytes_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquivalenceReport {
    pub schema_version: String,
    pub accepted: bool,
    pub control_bundle_id: Option<String>,
    pub candidate_bundle_id: Option<String>,
    pub control_validation: OracleBundleReport,
    pub candidate_validation: OracleBundleReport,
    pub cases: Vec<CaseEquivalence>,
    pub findings: Vec<OracleFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEquivalence {
    pub case_id: String,
    pub equivalent: bool,
    pub control_projection: Option<ObservableProjection>,
    pub candidate_projection: Option<ObservableProjection>,
}

pub fn evaluate_json(bytes: &[u8], coverage: Coverage) -> OracleBundleReport {
    let bundle = match parse_bundle(bytes) {
        Ok(bundle) => bundle,
        Err(detail) => {
            return OracleBundleReport {
                schema_version: ORACLE_REPORT_SCHEMA_VERSION.to_owned(),
                bundle_id: None,
                route_mode: None,
                accepted: false,
                cases: Vec::new(),
                findings: vec![OracleFinding {
                    code: "invalid-observation-json".to_owned(),
                    case_id: None,
                    detail,
                }],
            };
        }
    };
    evaluate_bundle(&bundle, coverage)
}

/// Production paired gate. Both inputs must be full 12-case bundles; the
/// first must be an exact uninterrupted control and the second an exact
/// non-carrier handoff. Runtime-lineage callers should use
/// [`evaluate_stage3a_equivalence`] to bind the raw endpoints to their typed
/// runtime scope.
pub fn evaluate_equivalence(control_json: &[u8], candidate_json: &[u8]) -> EquivalenceReport {
    let mut report = evaluate_equivalence_with_coverage(
        control_json,
        candidate_json,
        Coverage::CompleteRegistry,
    );
    if let Ok(control) = parse_bundle(control_json) {
        validate_stage3a_control_topology(&control, &mut report.findings);
    }
    if let Ok(candidate) = parse_bundle(candidate_json) {
        validate_stage3a_candidate_topology(&candidate, &mut report.findings);
    }
    report.accepted = report.accepted && report.findings.is_empty();
    report
}

/// Complete Stage 3A gate. In addition to deriving all regular-file semantics
/// from raw observations, this binds the raw route, runtime implementation,
/// implementation version, OS, ISA, role-specific instance, and execution
/// boundary to the separately validated Stage 3 runtime scope. `host_id`
/// remains an explicitly unattested observation boundary.
pub fn evaluate_stage3a_equivalence(
    control_json: &[u8],
    candidate_json: &[u8],
    expectation: &Stage3aTopologyExpectation,
) -> EquivalenceReport {
    evaluate_stage3a_equivalence_with_coverage(
        control_json,
        candidate_json,
        expectation,
        Coverage::CompleteRegistry,
    )
}

fn evaluate_stage3a_equivalence_with_coverage(
    control_json: &[u8],
    candidate_json: &[u8],
    expectation: &Stage3aTopologyExpectation,
    coverage: Coverage,
) -> EquivalenceReport {
    let mut report = evaluate_equivalence_with_coverage(control_json, candidate_json, coverage);
    if let Ok(control) = parse_bundle(control_json) {
        validate_stage3a_control_topology(&control, &mut report.findings);
        validate_stage3a_endpoint(
            &control.route.source,
            &expectation.source,
            "control source",
            &mut report.findings,
        );
    }
    if let Ok(candidate) = parse_bundle(candidate_json) {
        validate_stage3a_candidate_topology(&candidate, &mut report.findings);
        validate_stage3a_endpoint(
            &candidate.route.source,
            &expectation.source,
            "candidate source",
            &mut report.findings,
        );
        if let Some(destination) = &candidate.route.destination {
            validate_stage3a_endpoint(
                destination,
                &expectation.destination,
                "candidate destination",
                &mut report.findings,
            );
        }
        if candidate.route.execution_boundary != expectation.candidate_execution_boundary {
            finding(
                &mut report.findings,
                "stage3a-execution-boundary-mismatch",
                None,
                "candidate execution boundary does not match the typed Stage 3 runtime scope",
            );
        }
    }
    report.accepted = report.accepted && report.findings.is_empty();
    report
}

fn evaluate_carrier_subset(control_json: &[u8], candidate_json: &[u8]) -> EquivalenceReport {
    evaluate_equivalence_with_coverage(control_json, candidate_json, Coverage::CarrierProbe)
}

/// Exact Wanco carrier gate used by the canonical matrix. In addition to
/// semantic recomputation, this binds the candidate to one named topology and
/// rehashes the real checkpoint artifact beneath the supplied publication
/// root.
pub fn evaluate_carrier_probe(
    control_json: &[u8],
    candidate_json: &[u8],
    expectation: CarrierProbeExpectation<'_>,
) -> EquivalenceReport {
    let mut report = evaluate_carrier_subset(control_json, candidate_json);
    let control = parse_bundle(control_json);
    let candidate = parse_bundle(candidate_json);
    if let Ok(control) = &control {
        validate_wanco_control_topology(control, expectation, &mut report.findings);
    }
    if let Ok(candidate) = &candidate {
        validate_wanco_candidate_topology(candidate, expectation, &mut report.findings);
    }
    if let (Ok(control), Ok(candidate)) = (&control, &candidate)
        && let Some(destination) = &candidate.route.destination
        && (control.route.source.host_id != candidate.route.source.host_id
            || candidate.route.source.host_id != destination.host_id)
    {
        finding(
            &mut report.findings,
            "wanco-same-host-observation-mismatch",
            None,
            "control, candidate source, and candidate destination do not report one same-host topology",
        );
    }
    report.accepted = report.accepted && report.findings.is_empty();
    report
}

/// Development-only paired evaluator. Production callers and the CLI use
/// [`evaluate_equivalence`], which always requires the complete registry.
pub fn evaluate_equivalence_with_coverage(
    control_json: &[u8],
    candidate_json: &[u8],
    coverage: Coverage,
) -> EquivalenceReport {
    let control = parse_bundle(control_json);
    let candidate = parse_bundle(candidate_json);
    let control_report = control
        .as_ref()
        .map_or_else(|detail| load_failure(detail), |bundle| evaluate_bundle(bundle, coverage));
    let candidate_report = candidate
        .as_ref()
        .map_or_else(|detail| load_failure(detail), |bundle| evaluate_bundle(bundle, coverage));

    let mut findings = Vec::new();
    if let Ok(bundle) = &control
        && bundle.route.mode != RouteMode::UninterruptedControl
    {
        finding(
            &mut findings,
            "control-route-mode",
            None,
            "the control bundle route mode is not uninterrupted_control",
        );
    }
    if let Ok(bundle) = &candidate
        && bundle.route.mode == RouteMode::UninterruptedControl
    {
        finding(
            &mut findings,
            "candidate-route-mode",
            None,
            "the candidate bundle must use a non-control route mode",
        );
    }

    let mut cases = Vec::new();
    if let (Ok(control_bundle), Ok(candidate_bundle)) = (&control, &candidate) {
        let control_by_case = reports_by_case(&control_report);
        let candidate_by_case = reports_by_case(&candidate_report);
        let candidate_wire_by_case = candidate_bundle
            .cases
            .iter()
            .map(|case| (case.case_id, case))
            .collect::<BTreeMap<_, _>>();
        let control_set =
            control_bundle.cases.iter().map(|case| case.case_id).collect::<BTreeSet<_>>();
        let candidate_set =
            candidate_bundle.cases.iter().map(|case| case.case_id).collect::<BTreeSet<_>>();
        if control_set != candidate_set {
            finding(
                &mut findings,
                "paired-case-set-mismatch",
                None,
                "control and candidate do not contain the same case set",
            );
        }
        for control_case in &control_bundle.cases {
            let case_id = control_case.case_id;
            let control_case_report = control_by_case.get(case_id.as_str()).copied();
            let candidate_case_report = candidate_by_case.get(case_id.as_str()).copied();
            let candidate_case = candidate_wire_by_case.get(&case_id).copied();
            if let Some(candidate_case) = candidate_case {
                if control_case.schedule_id != candidate_case.schedule_id
                    || control_case.schedule_sha256 != candidate_case.schedule_sha256
                {
                    finding(
                        &mut findings,
                        "schedule-mismatch",
                        Some(case_id.as_str()),
                        "control and candidate do not identify the same execution schedule",
                    );
                }
                if control_case.subject.resource_id != candidate_case.subject.resource_id
                    || control_case.subject.initial_path != candidate_case.subject.initial_path
                {
                    finding(
                        &mut findings,
                        "resource-subject-mismatch",
                        Some(case_id.as_str()),
                        "control and candidate observe different resource subjects",
                    );
                }
            }
            let control_projection =
                control_case_report.and_then(|report| report.projection.clone());
            let candidate_projection =
                candidate_case_report.and_then(|report| report.projection.clone());
            let equivalent = control_projection.is_some()
                && control_projection == candidate_projection
                && candidate_case.is_some();
            if !equivalent {
                finding(
                    &mut findings,
                    "observable-projection-mismatch",
                    Some(case_id.as_str()),
                    "candidate observable projection differs from uninterrupted control",
                );
            }
            cases.push(CaseEquivalence {
                case_id: case_id.as_str().to_owned(),
                equivalent,
                control_projection,
                candidate_projection,
            });
        }
    }

    let accepted = control_report.accepted
        && candidate_report.accepted
        && findings.is_empty()
        && !cases.is_empty()
        && match coverage {
            Coverage::CompleteRegistry => cases.len() == RegularFileCase::ALL.len(),
            Coverage::CarrierProbe => cases.len() == CARRIER_PROBE_CASES.len(),
            Coverage::AnySubset => true,
        }
        && cases.iter().all(|case| case.equivalent);
    EquivalenceReport {
        schema_version: EQUIVALENCE_REPORT_SCHEMA_VERSION.to_owned(),
        accepted,
        control_bundle_id: control_report.bundle_id.clone(),
        candidate_bundle_id: candidate_report.bundle_id.clone(),
        control_validation: control_report,
        candidate_validation: candidate_report,
        cases,
        findings,
    }
}

fn parse_bundle(bytes: &[u8]) -> Result<ObservationBundle, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

fn load_failure(detail: &str) -> OracleBundleReport {
    OracleBundleReport {
        schema_version: ORACLE_REPORT_SCHEMA_VERSION.to_owned(),
        bundle_id: None,
        route_mode: None,
        accepted: false,
        cases: Vec::new(),
        findings: vec![OracleFinding {
            code: "invalid-observation-json".to_owned(),
            case_id: None,
            detail: detail.to_owned(),
        }],
    }
}

fn reports_by_case(report: &OracleBundleReport) -> BTreeMap<&str, &OracleCaseReport> {
    report.cases.iter().map(|case| (case.case_id.as_str(), case)).collect()
}

fn evaluate_bundle(bundle: &ObservationBundle, coverage: Coverage) -> OracleBundleReport {
    let mut findings = validate_bundle_structure(bundle, coverage);
    let mut cases = Vec::with_capacity(bundle.cases.len());
    for case in &bundle.cases {
        let report = evaluate_case(bundle.route.mode, case);
        findings.extend(report.findings.iter().cloned());
        cases.push(report);
    }
    let accepted = findings.is_empty() && cases.iter().all(|case| case.accepted);
    OracleBundleReport {
        schema_version: ORACLE_REPORT_SCHEMA_VERSION.to_owned(),
        bundle_id: Some(bundle.bundle_id.clone()),
        route_mode: Some(route_mode_name(bundle.route.mode).to_owned()),
        accepted,
        cases,
        findings,
    }
}

fn validate_bundle_structure(bundle: &ObservationBundle, coverage: Coverage) -> Vec<OracleFinding> {
    let mut findings = Vec::new();
    if bundle.bundle_id.is_empty() {
        finding(&mut findings, "empty-bundle-id", None, "bundle_id must not be empty");
    }
    validate_endpoint(&bundle.route.source, "source", &mut findings);
    if bundle.route.mode != RouteMode::UninterruptedControl && bundle.route.destination.is_none() {
        finding(
            &mut findings,
            "missing-destination-endpoint",
            None,
            "non-control routes require a destination endpoint",
        );
    }
    if let Some(destination) = &bundle.route.destination {
        validate_endpoint(destination, "destination", &mut findings);
    }
    if bundle.route.execution_boundary.is_empty() {
        finding(
            &mut findings,
            "empty-execution-boundary",
            None,
            "route execution_boundary must not be empty",
        );
    }
    if matches!(bundle.route.mode, RouteMode::CarrierOnly | RouteMode::VisaPlusCarrier)
        && bundle.route.carrier.is_none()
    {
        finding(
            &mut findings,
            "missing-carrier-identity",
            None,
            "carrier route lacks a carrier identity",
        );
    }
    if let Some(carrier) = &bundle.route.carrier
        && (carrier.implementation.is_empty()
            || carrier.implementation_version.is_empty()
            || carrier.mode.is_empty())
    {
        finding(
            &mut findings,
            "incomplete-carrier-identity",
            None,
            "carrier identity fields must not be empty",
        );
    }

    let mut seen = BTreeSet::new();
    for case in &bundle.cases {
        let case_id = case.case_id.as_str();
        if !seen.insert(case.case_id) {
            finding(&mut findings, "duplicate-case", Some(case_id), "case occurs more than once");
        }
        validate_case_structure(case, &mut findings);
    }
    match coverage {
        Coverage::CompleteRegistry
            if seen.len() != RegularFileCase::ALL.len()
                || RegularFileCase::ALL.iter().any(|case| !seen.contains(case)) =>
        {
            finding(
                &mut findings,
                "incomplete-case-registry",
                None,
                "production input must contain the independent oracle's exact 12-case registry",
            );
        }
        Coverage::CarrierProbe
            if seen.len() != CARRIER_PROBE_CASES.len()
                || CARRIER_PROBE_CASES.iter().any(|case| !seen.contains(case)) =>
        {
            finding(
                &mut findings,
                "invalid-carrier-probe-registry",
                None,
                "carrier probe must contain exactly read-write-offset and append-continuity",
            );
        }
        Coverage::AnySubset if seen.is_empty() => {
            finding(
                &mut findings,
                "empty-case-subset",
                None,
                "development subset must contain at least one case",
            );
        }
        _ => {}
    }
    findings
}

fn validate_stage3a_control_topology(
    bundle: &ObservationBundle,
    findings: &mut Vec<OracleFinding>,
) {
    if bundle.route.mode != RouteMode::UninterruptedControl
        || bundle.route.destination.is_some()
        || bundle.route.carrier.is_some()
        || bundle.route.execution_boundary != "single-runtime-instance-uninterrupted-control"
    {
        finding(
            findings,
            "invalid-stage3a-control-topology",
            None,
            "Stage 3A control must be one uninterrupted source, the fixed control boundary, no destination, and no carrier",
        );
    }
}

fn validate_stage3a_candidate_topology(
    bundle: &ObservationBundle,
    findings: &mut Vec<OracleFinding>,
) {
    if bundle.route.mode != RouteMode::Handoff
        || bundle.route.destination.is_none()
        || bundle.route.carrier.is_some()
    {
        finding(
            findings,
            "invalid-stage3a-candidate-topology",
            None,
            "Stage 3A candidate must be one source-to-destination handoff with no compute carrier",
        );
    }
}

fn validate_stage3a_endpoint(
    endpoint: &wire::EndpointObservation,
    expected: &Stage3aEndpointExpectation,
    role: &str,
    findings: &mut Vec<OracleFinding>,
) {
    if endpoint.instance_id != expected.instance_id
        || endpoint.runtime != expected.runtime
        || endpoint.runtime_version != expected.runtime_version
        || endpoint.operating_system != expected.operating_system
        || endpoint.isa != expected.isa
    {
        finding(
            findings,
            "stage3a-endpoint-scope-mismatch",
            None,
            format!("{role} does not match the typed Stage 3 runtime scope"),
        );
    }
}

fn validate_wanco_control_topology(
    bundle: &ObservationBundle,
    expectation: CarrierProbeExpectation<'_>,
    findings: &mut Vec<OracleFinding>,
) {
    if bundle.route.mode != RouteMode::UninterruptedControl
        || bundle.route.destination.is_some()
        || bundle.route.carrier.is_some()
        || bundle.route.execution_boundary != "same-process-uninterrupted"
    {
        finding(
            findings,
            "invalid-wanco-control-topology",
            None,
            "Wanco carrier control must be one same-process uninterrupted source with no destination or carrier",
        );
    }
    validate_wanco_endpoint(
        &bundle.route.source,
        "control source",
        "wanco-aot-uninterrupted-source",
        expectation.carrier_revision,
        findings,
    );
    for case in &bundle.cases {
        if case
            .events
            .iter()
            .any(|event| matches!(event.body, RawObservationEvent::CarrierCall { .. }))
        {
            finding(
                findings,
                "carrier-call-in-wanco-control",
                Some(case.case_id.as_str()),
                "uninterrupted Wanco control contains a carrier call",
            );
        }
    }
}

fn validate_wanco_candidate_topology(
    bundle: &ObservationBundle,
    expectation: CarrierProbeExpectation<'_>,
    findings: &mut Vec<OracleFinding>,
) {
    if expectation.carrier_revision.len() != 40
        || !expectation
            .carrier_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        finding(
            findings,
            "invalid-expected-wanco-revision",
            None,
            "expected Wanco revision must be one exact lowercase 40-hex Git SHA",
        );
    }
    if bundle.route.mode != expectation.route.wire() {
        finding(
            findings,
            "unexpected-wanco-carrier-route",
            None,
            format!(
                "expected {}, observed {}",
                expectation.route.name(),
                route_mode_name(bundle.route.mode)
            ),
        );
    }
    if bundle.route.execution_boundary != "same-host-fresh-process-and-node-local-storage" {
        finding(
            findings,
            "unexpected-wanco-execution-boundary",
            None,
            "Wanco carrier candidate must cross one fresh process and node-local storage boundary",
        );
    }
    let expected_source = wanco_instance_id(expectation.route, "source");
    let expected_destination = wanco_instance_id(expectation.route, "destination");
    validate_wanco_endpoint(
        &bundle.route.source,
        "candidate source",
        &expected_source,
        expectation.carrier_revision,
        findings,
    );
    match &bundle.route.destination {
        Some(destination) => {
            validate_wanco_endpoint(
                destination,
                "candidate destination",
                &expected_destination,
                expectation.carrier_revision,
                findings,
            );
            if destination.instance_id == bundle.route.source.instance_id {
                finding(
                    findings,
                    "aliased-wanco-endpoint-instance",
                    None,
                    "Wanco source and destination must be distinct process instances",
                );
            }
        }
        None => finding(
            findings,
            "missing-wanco-destination",
            None,
            "Wanco carrier candidate lacks a destination endpoint",
        ),
    }
    if expectation.route.uses_checkpoint_carrier() {
        match &bundle.route.carrier {
            Some(carrier)
                if carrier.implementation == "tamaroning/wanco"
                    && carrier.implementation_version == expectation.carrier_revision
                    && carrier.mode == "signal-triggered-llvm-stackmap-protobuf" => {}
            Some(_) => finding(
                findings,
                "unexpected-wanco-carrier-identity",
                None,
                "candidate carrier identity does not match the exact source-locked Wanco carrier",
            ),
            None => finding(
                findings,
                "missing-wanco-carrier-identity",
                None,
                "candidate lacks the required Wanco carrier identity",
            ),
        }
        for case in &bundle.cases {
            validate_wanco_carrier_lifecycle(case, expectation.artifact_root, findings);
        }
    } else {
        if bundle.route.carrier.is_some() {
            finding(
                findings,
                "unexpected-wanco-carrier-identity",
                None,
                "restart diagnostic must not claim a checkpoint carrier",
            );
        }
        for case in &bundle.cases {
            if case
                .events
                .iter()
                .any(|event| matches!(event.body, RawObservationEvent::CarrierCall { .. }))
            {
                finding(
                    findings,
                    "unexpected-wanco-carrier-call",
                    Some(case.case_id.as_str()),
                    "restart diagnostic contains a checkpoint carrier call",
                );
            }
        }
    }
}

fn validate_wanco_endpoint(
    endpoint: &wire::EndpointObservation,
    role: &str,
    expected_instance_id: &str,
    revision: &str,
    findings: &mut Vec<OracleFinding>,
) {
    if endpoint.instance_id != expected_instance_id
        || endpoint.runtime != "tamaroning/wanco-aot"
        || endpoint.runtime_version != revision
        || endpoint.operating_system != "linux"
        || endpoint.isa != "x86_64"
    {
        finding(
            findings,
            "unexpected-wanco-endpoint-identity",
            None,
            format!(
                "{role} does not match the exact role-specific x86_64 Linux Wanco AOT endpoint"
            ),
        );
    }
}

fn wanco_instance_id(route: CarrierProbeRoute, role: &str) -> String {
    let route = match route {
        CarrierProbeRoute::Restart => "restart",
        CarrierProbeRoute::CarrierOnly => "carrier-only",
        CarrierProbeRoute::NaiveReopen => "naive-reopen",
        CarrierProbeRoute::VisaPlusCarrier => "visa-plus-carrier",
    };
    format!("wanco-aot-{route}-{role}")
}

fn validate_wanco_carrier_lifecycle(
    case: &CaseObservation,
    artifact_root: &Path,
    findings: &mut Vec<OracleFinding>,
) {
    use wire::{CarrierAction, CarrierCallResult, CarrierPayloadObservation};

    let case_id = case.case_id.as_str();
    let calls = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::CarrierCall { action, result } => {
                Some((event.sequence, event.phase, event.actor, action, result))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if calls.len() != 3 {
        finding(
            findings,
            "invalid-wanco-carrier-call-count",
            Some(case_id),
            format!(
                "expected capture, restore, and resume exactly once; observed {} calls",
                calls.len()
            ),
        );
        return;
    }
    let (capture_sequence, capture_phase, capture_actor, capture_id, captured_payload) =
        match calls[0] {
            (
                sequence,
                phase,
                actor,
                CarrierAction::Capture { capture_id },
                CarrierCallResult::Captured { payload },
            ) => (sequence, phase, actor, capture_id, payload),
            _ => {
                finding(
                    findings,
                    "invalid-wanco-capture-call",
                    Some(case_id),
                    "first carrier call is not a successful checkpoint capture",
                );
                return;
            }
        };
    let (restore_sequence, restore_phase, restore_actor, restore_id, restored_payload) =
        match calls[1] {
            (
                sequence,
                phase,
                actor,
                CarrierAction::Restore { capture_id, payload },
                CarrierCallResult::Returned { .. },
            ) => (sequence, phase, actor, capture_id, payload),
            _ => {
                finding(
                    findings,
                    "invalid-wanco-restore-call",
                    Some(case_id),
                    "second carrier call is not a successful checkpoint restore",
                );
                return;
            }
        };
    let (resume_sequence, resume_phase, resume_actor) = match calls[2] {
        (sequence, phase, actor, CarrierAction::Resume, CarrierCallResult::Returned { .. }) => {
            (sequence, phase, actor)
        }
        _ => {
            finding(
                findings,
                "invalid-wanco-resume-call",
                Some(case_id),
                "third carrier call is not a successful destination resume",
            );
            return;
        }
    };
    if capture_id.is_empty()
        || capture_id != restore_id
        || captured_payload != restored_payload
        || !(capture_sequence < restore_sequence && restore_sequence < resume_sequence)
        || capture_phase != ObservationPhase::CarrierCapture
        || restore_phase != ObservationPhase::CarrierRestore
        || resume_phase != ObservationPhase::CarrierRestore
        || capture_actor != ObservationActor::Carrier
        || restore_actor != ObservationActor::Carrier
        || resume_actor != ObservationActor::Carrier
    {
        finding(
            findings,
            "invalid-wanco-carrier-lifecycle",
            Some(case_id),
            "capture, restore, and resume are not one ordered identity-bound Wanco lifecycle",
        );
    }
    match captured_payload {
        CarrierPayloadObservation::Artifact { reference } => {
            validate_carrier_artifact(reference, artifact_root, case_id, findings)
        }
        CarrierPayloadObservation::Inline { .. } => finding(
            findings,
            "inline-wanco-checkpoint",
            Some(case_id),
            "canonical Wanco carrier evidence requires a rehashable checkpoint artifact",
        ),
    }
}

fn validate_carrier_artifact(
    reference: &wire::ArtifactReferenceObservation,
    artifact_root: &Path,
    case_id: &str,
    findings: &mut Vec<OracleFinding>,
) {
    let relative = Path::new(&reference.uri);
    if reference.uri.is_empty()
        || reference.uri.starts_with('/')
        || reference.uri.contains('\\')
        || reference
            .uri
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || relative.is_absolute()
        || relative.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        finding(
            findings,
            "unsafe-wanco-checkpoint-uri",
            Some(case_id),
            "checkpoint artifact URI is not one safe relative path",
        );
        return;
    }
    let root = match fs::canonicalize(artifact_root) {
        Ok(root) => root,
        Err(error) => {
            finding(
                findings,
                "unavailable-wanco-artifact-root",
                Some(case_id),
                format!("cannot resolve checkpoint artifact root: {error}"),
            );
            return;
        }
    };
    let mut path = root.clone();
    let components = reference.uri.split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                finding(
                    findings,
                    "missing-wanco-checkpoint-artifact",
                    Some(case_id),
                    format!("cannot inspect checkpoint artifact: {error}"),
                );
                return;
            }
        };
        if metadata.file_type().is_symlink() {
            finding(
                findings,
                "symlinked-wanco-checkpoint-artifact",
                Some(case_id),
                "checkpoint artifact path must not contain symbolic links",
            );
            return;
        }
        let final_component = index + 1 == components.len();
        if (!final_component && !metadata.is_dir()) || (final_component && !metadata.is_file()) {
            finding(
                findings,
                "invalid-wanco-checkpoint-artifact-type",
                Some(case_id),
                "checkpoint artifact path does not resolve to one regular file",
            );
            return;
        }
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            finding(
                findings,
                "unreadable-wanco-checkpoint-artifact",
                Some(case_id),
                format!("cannot read checkpoint artifact: {error}"),
            );
            return;
        }
    };
    if bytes.len() as u64 != reference.size || sha256_hex(&bytes) != reference.sha256 {
        finding(
            findings,
            "wanco-checkpoint-artifact-mismatch",
            Some(case_id),
            "checkpoint artifact bytes do not match the recorded size and SHA-256",
        );
    }
}

fn validate_endpoint(
    endpoint: &wire::EndpointObservation,
    role: &str,
    findings: &mut Vec<OracleFinding>,
) {
    if endpoint.instance_id.is_empty()
        || endpoint.runtime.is_empty()
        || endpoint.runtime_version.is_empty()
        || endpoint.host_id.is_empty()
        || endpoint.operating_system.is_empty()
        || endpoint.isa.is_empty()
    {
        finding(
            findings,
            "incomplete-endpoint-identity",
            None,
            format!("{role} endpoint identity is incomplete"),
        );
    }
}

fn validate_case_structure(case: &CaseObservation, findings: &mut Vec<OracleFinding>) {
    let case_id = case.case_id.as_str();
    if case.observation_id.is_empty()
        || case.schedule_id.is_empty()
        || case.subject.resource_id.is_empty()
        || case.subject.initial_path.is_empty()
    {
        finding(
            findings,
            "incomplete-case-identity",
            Some(case_id),
            "observation, schedule, and resource identity fields must not be empty",
        );
    }
    if !is_lower_hex_sha256(&case.schedule_sha256) {
        finding(
            findings,
            "invalid-schedule-digest",
            Some(case_id),
            "schedule_sha256 must be a lowercase SHA-256 value",
        );
    }
    if case.events.is_empty() {
        finding(
            findings,
            "empty-event-stream",
            Some(case_id),
            "case has no raw observation events",
        );
    }

    let mut attempts = BTreeMap::<&str, BTreeSet<u32>>::new();
    for (expected, event) in case.events.iter().enumerate() {
        if event.sequence != expected as u64 {
            finding(
                findings,
                "noncontiguous-event-sequence",
                Some(case_id),
                format!("expected event sequence {expected}, observed {}", event.sequence),
            );
        }
        match &event.body {
            RawObservationEvent::FileProbe { entry, .. } => {
                if event.actor != ObservationActor::ExternalObserver {
                    finding(
                        findings,
                        "nonexternal-file-probe",
                        Some(case_id),
                        format!(
                            "file probe at sequence {} was not made by external_observer",
                            event.sequence
                        ),
                    );
                }
                validate_file_entry(case_id, event.sequence, entry, findings);
            }
            RawObservationEvent::OperationCall {
                operation_id, attempt, operation, result, ..
            } => {
                if operation_id.is_empty() {
                    finding(
                        findings,
                        "empty-operation-id",
                        Some(case_id),
                        format!("operation call at sequence {} has an empty id", event.sequence),
                    );
                }
                if !matches!(
                    event.actor,
                    ObservationActor::SourceRuntime | ObservationActor::DestinationRuntime
                ) {
                    finding(
                        findings,
                        "invalid-operation-actor",
                        Some(case_id),
                        format!("operation at sequence {} has a non-runtime actor", event.sequence),
                    );
                }
                if !attempts.entry(operation_id).or_default().insert(*attempt) {
                    finding(
                        findings,
                        "duplicate-operation-attempt",
                        Some(case_id),
                        format!("operation {operation_id} repeats attempt {attempt}"),
                    );
                }
                validate_operation_result(case_id, event.sequence, operation, result, findings);
            }
            RawObservationEvent::ProtocolCall { action, .. } => {
                if !valid_protocol_context(action, event.phase, event.actor) {
                    finding(
                        findings,
                        "invalid-protocol-observation-context",
                        Some(case_id),
                        format!(
                            "protocol action at sequence {} has an actor or phase inconsistent with its lifecycle role",
                            event.sequence
                        ),
                    );
                }
                validate_protocol_action_identity(case_id, event.sequence, action, findings);
            }
            RawObservationEvent::CarrierCall { action, result } => {
                validate_carrier_call(case_id, event.sequence, action, result, findings);
            }
            _ => {}
        }
    }
    for (operation_id, observed) in attempts {
        for expected in 0..observed.len() as u32 {
            if !observed.contains(&expected) {
                finding(
                    findings,
                    "noncontiguous-operation-attempts",
                    Some(case_id),
                    format!("operation {operation_id} is missing attempt {expected}"),
                );
            }
        }
    }
    validate_content_digest_recomputation(case, findings);
}

fn valid_protocol_context(
    action: &ProtocolAction,
    phase: ObservationPhase,
    actor: ObservationActor,
) -> bool {
    match action {
        ProtocolAction::BeginQuiesce { .. } | ProtocolAction::PrepareSafePoint { .. } => {
            phase == ObservationPhase::Quiesce
                && matches!(actor, ObservationActor::SourceRuntime | ObservationActor::Controller)
        }
        ProtocolAction::FreezeRuntime { .. } | ProtocolAction::CommitSafePoint { .. } => {
            matches!(
                (phase, actor),
                (ObservationPhase::CarrierCapture, ObservationActor::SourceRuntime)
                    | (ObservationPhase::Quiesce, ObservationActor::Controller)
            )
        }
        ProtocolAction::ExportSnapshot { .. } => {
            phase == ObservationPhase::Transfer
                && matches!(actor, ObservationActor::SourceRuntime | ObservationActor::Controller)
        }
        ProtocolAction::PrepareDestination { .. } | ProtocolAction::CommitHandoff { .. } => {
            phase == ObservationPhase::DestinationPrepare
                && matches!(actor, ObservationActor::Provider | ObservationActor::Controller)
        }
        ProtocolAction::RestoreRuntime { .. } => {
            phase == ObservationPhase::CarrierRestore
                && matches!(
                    actor,
                    ObservationActor::DestinationRuntime | ObservationActor::Controller
                )
        }
        ProtocolAction::ResumeDestination { .. } => {
            phase == ObservationPhase::DestinationExecution
                && matches!(
                    actor,
                    ObservationActor::DestinationRuntime | ObservationActor::Controller
                )
        }
        ProtocolAction::CleanupOperation { .. } => {
            phase == ObservationPhase::Cleanup
                && matches!(actor, ObservationActor::Provider | ObservationActor::Controller)
        }
    }
}

fn validate_protocol_action_identity(
    case_id: &str,
    sequence: u64,
    action: &ProtocolAction,
    findings: &mut Vec<OracleFinding>,
) {
    let complete = match action {
        ProtocolAction::BeginQuiesce { command_id, authority_id } => {
            !command_id.is_empty() && !authority_id.is_empty()
        }
        ProtocolAction::PrepareSafePoint { safe_point_id }
        | ProtocolAction::FreezeRuntime { safe_point_id } => !safe_point_id.is_empty(),
        ProtocolAction::CommitSafePoint { command_id, safe_point_id } => {
            !command_id.is_empty() && !safe_point_id.is_empty()
        }
        ProtocolAction::ExportSnapshot { command_id, snapshot_id } => {
            !command_id.is_empty() && !snapshot_id.is_empty()
        }
        ProtocolAction::PrepareDestination { command_id }
        | ProtocolAction::ResumeDestination { command_id } => !command_id.is_empty(),
        ProtocolAction::CommitHandoff { command_id, operation_id } => {
            !command_id.is_empty() && !operation_id.is_empty()
        }
        ProtocolAction::RestoreRuntime { snapshot_id } => !snapshot_id.is_empty(),
        ProtocolAction::CleanupOperation { command_id, operation_id, evidence_id } => {
            !command_id.is_empty() && !operation_id.is_empty() && !evidence_id.is_empty()
        }
    };
    if !complete {
        finding(
            findings,
            "incomplete-protocol-action-identity",
            Some(case_id),
            format!("protocol action at sequence {sequence} has an empty identity field"),
        );
    }
}

fn validate_file_entry(
    case_id: &str,
    sequence: u64,
    entry: &FileEntryObservation,
    findings: &mut Vec<OracleFinding>,
) {
    if let FileEntryObservation::File { bytes, size, sha256, metadata } = entry {
        if *size != bytes.len() as u64 {
            finding(
                findings,
                "file-probe-size-mismatch",
                Some(case_id),
                format!("file probe at sequence {sequence} has size inconsistent with raw bytes"),
            );
        }
        if !is_lower_hex_sha256(sha256) || *sha256 != sha256_hex(bytes) {
            finding(
                findings,
                "file-probe-digest-mismatch",
                Some(case_id),
                format!(
                    "file probe at sequence {sequence} has a SHA-256 value not derived from raw bytes"
                ),
            );
        }
        if metadata.link_count == 0 {
            finding(
                findings,
                "invalid-file-metadata",
                Some(case_id),
                format!("file probe at sequence {sequence} reports zero links"),
            );
        }
    }
}

fn validate_operation_result(
    case_id: &str,
    sequence: u64,
    operation: &RegularFileOperationObservation,
    result: &OperationCallResult,
    findings: &mut Vec<OracleFinding>,
) {
    let matches = matches!(
        (operation, result),
        (_, OperationCallResult::Error { .. })
            | (
                RegularFileOperationObservation::Read { .. },
                OperationCallResult::Returned { output: RegularFileOutputObservation::Read { .. } },
            )
            | (
                RegularFileOperationObservation::Write { .. }
                    | RegularFileOperationObservation::Append { .. }
                    | RegularFileOperationObservation::Truncate { .. },
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Mutated { .. }
                },
            )
            | (
                RegularFileOperationObservation::Rename { .. },
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Renamed { .. }
                },
            )
            | (
                RegularFileOperationObservation::Sync { .. },
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Synced { .. }
                },
            )
            | (
                RegularFileOperationObservation::AcquireLock
                    | RegularFileOperationObservation::ReleaseLock,
                OperationCallResult::Returned { output: RegularFileOutputObservation::Lock { .. } },
            )
    );
    if !matches {
        finding(
            findings,
            "operation-result-kind-mismatch",
            Some(case_id),
            format!("operation call at sequence {sequence} returned an incompatible output kind"),
        );
    }
    let content_digest = match result {
        OperationCallResult::Returned {
            output:
                RegularFileOutputObservation::Read { content_digest, .. }
                | RegularFileOutputObservation::Mutated { content_digest, .. }
                | RegularFileOutputObservation::Renamed { content_digest, .. },
        } => Some(content_digest),
        _ => None,
    };
    if content_digest.is_some_and(|digest| digest.len() != 32) {
        finding(
            findings,
            "invalid-operation-content-digest",
            Some(case_id),
            format!("operation call at sequence {sequence} has a non-32-byte content digest"),
        );
    }
}

fn validate_content_digest_recomputation(
    case: &CaseObservation,
    findings: &mut Vec<OracleFinding>,
) {
    let case_id = case.case_id.as_str();
    let Some((mut current_path, mut current_bytes)) =
        case.events.iter().find_map(|event| match &event.body {
            RawObservationEvent::FileProbe {
                path,
                entry: FileEntryObservation::File { bytes, .. },
            } if event.phase == ObservationPhase::Setup && path == &case.subject.initial_path => {
                Some((path.clone(), bytes.clone()))
            }
            _ => None,
        })
    else {
        return;
    };
    let mut logical_offset = case
        .events
        .iter()
        .find_map(|event| match &event.body {
            RawObservationEvent::ProfileStateProbe { state }
                if event.phase == ObservationPhase::Setup
                    && state.relative_path == case.subject.initial_path =>
            {
                Some(state.logical_offset)
            }
            _ => None,
        })
        .unwrap_or(0);
    let mut reconciled_operations = BTreeSet::new();
    let mut state_known = true;

    for event in &case.events {
        match &event.body {
            RawObservationEvent::OperationCall {
                result: OperationCallResult::Error { error },
                ..
            } => {
                if matches!(error.code, ErrorCode::Indeterminate | ErrorCode::IndeterminateEffect) {
                    state_known = false;
                }
            }
            RawObservationEvent::OperationCall {
                operation_id,
                operation,
                result: OperationCallResult::Returned { output },
                ..
            } => {
                let first_success = reconciled_operations.insert(operation_id.clone());
                if first_success {
                    match operation {
                        RegularFileOperationObservation::Read { .. } => {
                            if let RegularFileOutputObservation::Read {
                                logical_offset: observed_offset,
                                ..
                            } = output
                            {
                                logical_offset = *observed_offset;
                            }
                        }
                        RegularFileOperationObservation::Write { bytes, .. } => {
                            let start = usize::try_from(logical_offset).unwrap_or(usize::MAX);
                            if start <= current_bytes.len() {
                                let end = start.saturating_add(bytes.len());
                                if end > current_bytes.len() {
                                    current_bytes.resize(end, 0);
                                }
                                current_bytes[start..end].copy_from_slice(bytes);
                                logical_offset = end as u64;
                                state_known = true;
                            } else {
                                state_known = false;
                            }
                        }
                        RegularFileOperationObservation::Append { bytes, .. } => {
                            current_bytes.extend_from_slice(bytes);
                            logical_offset = current_bytes.len() as u64;
                            state_known = true;
                        }
                        RegularFileOperationObservation::Truncate { size, .. } => {
                            if let Ok(size) = usize::try_from(*size) {
                                current_bytes.resize(size, 0);
                                state_known = true;
                            } else {
                                state_known = false;
                            }
                        }
                        RegularFileOperationObservation::Rename { relative_path } => {
                            current_path.clone_from(relative_path);
                        }
                        RegularFileOperationObservation::Sync { .. }
                        | RegularFileOperationObservation::AcquireLock
                        | RegularFileOperationObservation::ReleaseLock => {}
                    }
                }
                if state_known
                    && let Some(observed_digest) = output_content_digest(output)
                    && *observed_digest != canonical_byte_vector_digest(&current_bytes)
                {
                    finding(
                        findings,
                        "operation-content-digest-mismatch",
                        Some(case_id),
                        format!(
                            "operation call at sequence {} has a content digest not independently derived from raw file bytes and operations",
                            event.sequence
                        ),
                    );
                }
            }
            RawObservationEvent::ProfileStateProbe { state } => {
                if state.content_digest.len() != 32 {
                    finding(
                        findings,
                        "invalid-profile-content-digest",
                        Some(case_id),
                        format!(
                            "profile state at sequence {} has a non-32-byte content digest",
                            event.sequence
                        ),
                    );
                }
                if state_known
                    && state.relative_path == current_path
                    && state.size == current_bytes.len() as u64
                    && state.content_digest != canonical_byte_vector_digest(&current_bytes)
                {
                    finding(
                        findings,
                        "profile-content-digest-mismatch",
                        Some(case_id),
                        format!(
                            "profile state at sequence {} has a content digest not independently derived from raw file bytes and operations",
                            event.sequence
                        ),
                    );
                }
            }
            _ => {}
        }
    }
}

fn output_content_digest(output: &RegularFileOutputObservation) -> Option<&Vec<u8>> {
    match output {
        RegularFileOutputObservation::Read { content_digest, .. }
        | RegularFileOutputObservation::Mutated { content_digest, .. }
        | RegularFileOutputObservation::Renamed { content_digest, .. } => Some(content_digest),
        RegularFileOutputObservation::Synced { .. } | RegularFileOutputObservation::Lock { .. } => {
            None
        }
    }
}

fn validate_carrier_call(
    case_id: &str,
    sequence: u64,
    action: &wire::CarrierAction,
    result: &wire::CarrierCallResult,
    findings: &mut Vec<OracleFinding>,
) {
    use wire::{CarrierAction, CarrierCallResult, CarrierPayloadObservation};
    let payloads = match (action, result) {
        (CarrierAction::Capture { capture_id }, CarrierCallResult::Captured { payload }) => {
            if capture_id.is_empty() {
                finding(
                    findings,
                    "empty-carrier-capture-id",
                    Some(case_id),
                    format!("carrier call at sequence {sequence} has an empty capture id"),
                );
            }
            vec![payload]
        }
        (CarrierAction::Restore { capture_id, payload }, _) => {
            if capture_id.is_empty() {
                finding(
                    findings,
                    "empty-carrier-capture-id",
                    Some(case_id),
                    format!("carrier call at sequence {sequence} has an empty capture id"),
                );
            }
            vec![payload]
        }
        _ => Vec::new(),
    };
    for payload in payloads {
        match payload {
            CarrierPayloadObservation::Inline { bytes, sha256 } => {
                if !is_lower_hex_sha256(sha256) || *sha256 != sha256_hex(bytes) {
                    finding(
                        findings,
                        "carrier-payload-digest-mismatch",
                        Some(case_id),
                        format!(
                            "carrier payload at sequence {sequence} is not bound to its raw bytes"
                        ),
                    );
                }
            }
            CarrierPayloadObservation::Artifact { reference } => {
                if reference.uri.is_empty()
                    || reference.size == 0
                    || !is_lower_hex_sha256(&reference.sha256)
                {
                    finding(
                        findings,
                        "invalid-carrier-artifact-reference",
                        Some(case_id),
                        format!("carrier artifact at sequence {sequence} is incomplete"),
                    );
                }
            }
        }
    }
}

fn evaluate_case(route_mode: RouteMode, case: &CaseObservation) -> OracleCaseReport {
    let mut findings = Vec::new();
    let projection = derive_projection(case, &mut findings);
    let expected_terminal = if route_mode == RouteMode::UninterruptedControl {
        None
    } else {
        Some(expected_candidate_terminal(case.case_id))
    };
    let committed_lifecycle = (expected_terminal == Some(DerivedTerminal::HandoffCommitted))
        .then(|| validate_committed_lifecycle(case, &mut findings))
        .flatten();
    if let Some(lifecycle) = &committed_lifecycle {
        validate_committed_destination_execution(case, lifecycle, &mut findings);
    }
    let terminal = derive_terminal(route_mode, case, committed_lifecycle.is_some());
    let assertions = if route_mode == RouteMode::UninterruptedControl {
        Vec::new()
    } else {
        derive_assertions(case, terminal)
    };
    if let Some(expected) = expected_terminal {
        if terminal != Some(expected) {
            finding(
                &mut findings,
                "unexpected-derived-terminal",
                Some(case.case_id.as_str()),
                format!("expected {expected:?}, independently derived {terminal:?}"),
            );
        }
    } else if terminal.is_none() {
        finding(
            &mut findings,
            "missing-control-terminal",
            Some(case.case_id.as_str()),
            "could not derive a control execution terminal from raw events",
        );
    }
    if route_mode != RouteMode::UninterruptedControl
        && (assertions.is_empty() || assertions.iter().any(|assertion| !assertion.passed))
    {
        finding(
            &mut findings,
            "semantic-assertion-failed",
            Some(case.case_id.as_str()),
            "one or more independently derived semantic assertions failed",
        );
    }
    let accepted = findings.is_empty() && projection.is_some();
    OracleCaseReport {
        case_id: case.case_id.as_str().to_owned(),
        accepted,
        terminal,
        assertions,
        projection,
        findings,
    }
}

fn derive_terminal(
    route_mode: RouteMode,
    case: &CaseObservation,
    committed_lifecycle: bool,
) -> Option<DerivedTerminal> {
    if matches!(
        case.case_id,
        RegularFileCase::ReplacementRejected | RegularFileCase::ExternalMutationRejected
    ) && operation_error(case, ErrorCode::Conflict).is_some()
    {
        return Some(DerivedTerminal::ProfileRejected);
    }
    if route_mode == RouteMode::UninterruptedControl {
        if operation_error(case, ErrorCode::Indeterminate).is_some() {
            return Some(DerivedTerminal::ExecutionBlocked);
        }
        return Some(DerivedTerminal::UninterruptedCompleted);
    }
    if protocol_error(
        case,
        |action| matches!(action, ProtocolAction::CommitSafePoint { .. }),
        ErrorCode::IndeterminateEffect,
    )
    .is_some()
        || protocol_error(
            case,
            |action| matches!(action, ProtocolAction::PrepareDestination { .. }),
            ErrorCode::ProviderDenied,
        )
        .is_some()
    {
        return Some(DerivedTerminal::HandoffBlocked);
    }
    if committed_lifecycle {
        return Some(DerivedTerminal::HandoffCommitted);
    }
    None
}

fn expected_candidate_terminal(case: RegularFileCase) -> DerivedTerminal {
    match case {
        RegularFileCase::ReplacementRejected | RegularFileCase::ExternalMutationRejected => {
            DerivedTerminal::ProfileRejected
        }
        RegularFileCase::IndeterminateWriteBlocksHandoff
        | RegularFileCase::DestinationReauthorizationDenied => DerivedTerminal::HandoffBlocked,
        _ => DerivedTerminal::HandoffCommitted,
    }
}

fn derive_projection(
    case: &CaseObservation,
    findings: &mut Vec<OracleFinding>,
) -> Option<ObservableProjection> {
    let initial_probe = case.events.iter().find_map(|event| match &event.body {
        RawObservationEvent::FileProbe { path, entry }
            if event.phase == ObservationPhase::Setup && path == &case.subject.initial_path =>
        {
            Some((path, entry))
        }
        _ => None,
    });
    let Some((initial_path, initial_entry)) = initial_probe else {
        finding(
            findings,
            "missing-initial-file-probe",
            Some(case.case_id.as_str()),
            "no setup-phase external probe exists for the subject path",
        );
        return None;
    };
    let initial_file = project_file(initial_path, initial_entry);

    let mut final_by_path = BTreeMap::<Vec<u8>, &FileEntryObservation>::new();
    for event in &case.events {
        if event.phase == ObservationPhase::FinalObservation
            && let RawObservationEvent::FileProbe { path, entry } = &event.body
            && final_by_path.insert(path.clone(), entry).is_some()
        {
            finding(
                findings,
                "duplicate-final-file-probe",
                Some(case.case_id.as_str()),
                "a final-observation path must have exactly one raw file probe",
            );
            return None;
        }
    }
    if final_by_path.is_empty() {
        finding(
            findings,
            "missing-final-file-probe",
            Some(case.case_id.as_str()),
            "case has no final-phase external file probes",
        );
        return None;
    }
    let final_files =
        final_by_path.into_iter().map(|(path, entry)| project_file(&path, entry)).collect();

    let operation_calls = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::OperationCall { operation, result, .. } => {
                Some(project_operation_call(operation, result))
            }
            _ => None,
        })
        .collect();
    let final_profile_state = case.events.iter().rev().find_map(|event| match &event.body {
        RawObservationEvent::ProfileStateProbe { state } => Some(ObservableProfileState {
            relative_path: state.relative_path.clone(),
            logical_offset: state.logical_offset,
            version: state.version,
            size: state.size,
            content_digest_hex: hex_bytes(&state.content_digest),
            durability: durability_name(state.durable_through).to_owned(),
            lock_state: lock_state_name(state.lock_state).to_owned(),
        }),
        _ => None,
    });
    let client_outputs = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::ClientOutput { channel, bytes } => Some(ObservableClientOutput {
                channel: format!("{channel:?}").to_lowercase(),
                bytes_sha256: sha256_hex(bytes),
                bytes_len: bytes.len() as u64,
            }),
            _ => None,
        })
        .collect();
    let process_exit = case.events.iter().rev().find_map(|event| match event.body {
        RawObservationEvent::ProcessExit { code, signal } => {
            Some(ObservableProcessExit { code, signal })
        }
        _ => None,
    });
    Some(ObservableProjection {
        case_id: case.case_id.as_str().to_owned(),
        initial_file,
        final_files,
        operation_calls,
        final_profile_state,
        client_outputs,
        process_exit,
    })
}

fn project_file(path: &[u8], entry: &FileEntryObservation) -> ObservableFile {
    let state = match entry {
        FileEntryObservation::Missing => ObservableFileState::Missing,
        FileEntryObservation::File { size, sha256, .. } => {
            ObservableFileState::File { size: *size, sha256: sha256.clone() }
        }
        FileEntryObservation::ProbeError { error } => {
            ObservableFileState::ProbeError { code: error_code_name(error.code).to_owned() }
        }
    };
    ObservableFile { path: path.to_vec(), state }
}

fn project_operation_call(
    operation: &RegularFileOperationObservation,
    result: &OperationCallResult,
) -> ObservableOperationCall {
    let operation = match operation {
        RegularFileOperationObservation::Read { max_bytes } => {
            ObservableOperation::Read { max_bytes: *max_bytes }
        }
        RegularFileOperationObservation::Write { bytes, durability } => {
            ObservableOperation::Write {
                bytes_sha256: sha256_hex(bytes),
                bytes_len: bytes.len() as u64,
                durability: durability_name(*durability).to_owned(),
            }
        }
        RegularFileOperationObservation::Append { bytes, durability } => {
            ObservableOperation::Append {
                bytes_sha256: sha256_hex(bytes),
                bytes_len: bytes.len() as u64,
                durability: durability_name(*durability).to_owned(),
            }
        }
        RegularFileOperationObservation::Truncate { size, durability } => {
            ObservableOperation::Truncate {
                size: *size,
                durability: durability_name(*durability).to_owned(),
            }
        }
        RegularFileOperationObservation::Rename { relative_path } => {
            ObservableOperation::Rename { relative_path: relative_path.clone() }
        }
        RegularFileOperationObservation::Sync { durability } => {
            ObservableOperation::Sync { durability: durability_name(*durability).to_owned() }
        }
        RegularFileOperationObservation::AcquireLock => ObservableOperation::AcquireLock,
        RegularFileOperationObservation::ReleaseLock => ObservableOperation::ReleaseLock,
    };
    let result = match result {
        OperationCallResult::Returned { output } => match output {
            RegularFileOutputObservation::Read {
                bytes,
                logical_offset,
                version,
                size,
                content_digest,
            } => ObservableOperationResult::Read {
                bytes_sha256: sha256_hex(bytes),
                bytes_len: bytes.len() as u64,
                logical_offset: *logical_offset,
                version: *version,
                size: *size,
                content_digest_hex: hex_bytes(content_digest),
            },
            RegularFileOutputObservation::Mutated {
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
            } => ObservableOperationResult::Mutated {
                logical_offset: *logical_offset,
                version: *version,
                size: *size,
                content_digest_hex: hex_bytes(content_digest),
                durability: durability_name(*durable_through).to_owned(),
            },
            RegularFileOutputObservation::Renamed { relative_path, version, content_digest } => {
                ObservableOperationResult::Renamed {
                    relative_path: relative_path.clone(),
                    version: *version,
                    content_digest_hex: hex_bytes(content_digest),
                }
            }
            RegularFileOutputObservation::Synced { version, durable_through } => {
                ObservableOperationResult::Synced {
                    version: *version,
                    durability: durability_name(*durable_through).to_owned(),
                }
            }
            RegularFileOutputObservation::Lock { state } => {
                ObservableOperationResult::Lock { state: lock_state_name(*state).to_owned() }
            }
        },
        OperationCallResult::Error { error } => ObservableOperationResult::Error {
            domain: format!("{:?}", error.domain).to_lowercase(),
            code: error_code_name(error.code).to_owned(),
            errno: error.errno,
            retryable: error.retryable,
        },
    };
    ObservableOperationCall { operation, result }
}

fn finding(
    findings: &mut Vec<OracleFinding>,
    code: &str,
    case_id: Option<&str>,
    detail: impl Into<String>,
) {
    findings.push(OracleFinding {
        code: code.to_owned(),
        case_id: case_id.map(str::to_owned),
        detail: detail.into(),
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn canonical_byte_vector_digest(bytes: &[u8]) -> Vec<u8> {
    let mut encoded_length = Vec::with_capacity(10);
    let mut remaining = bytes.len() as u64;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        encoded_length.push(byte);
        if remaining == 0 {
            break;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(encoded_length);
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn route_mode_name(mode: RouteMode) -> &'static str {
    match mode {
        RouteMode::UninterruptedControl => "uninterrupted_control",
        RouteMode::Handoff => "handoff",
        RouteMode::Restart => "restart",
        RouteMode::CarrierOnly => "carrier_only",
        RouteMode::NaiveReopen => "naive_reopen",
        RouteMode::VisaPlusCarrier => "visa_plus_carrier",
    }
}

fn durability_name(value: FileDurabilityObservation) -> &'static str {
    match value {
        FileDurabilityObservation::Visible => "visible",
        FileDurabilityObservation::Data => "data",
        FileDurabilityObservation::DataAndMetadata => "data_and_metadata",
    }
}

fn lock_state_name(value: FileLockStateObservation) -> &'static str {
    match value {
        FileLockStateObservation::Unlocked => "unlocked",
        FileLockStateObservation::Held => "held",
    }
}

fn error_code_name(value: ErrorCode) -> &'static str {
    match value {
        ErrorCode::Unavailable => "unavailable",
        ErrorCode::Conflict => "conflict",
        ErrorCode::Indeterminate => "indeterminate",
        ErrorCode::SafePointUnavailable => "safe_point_unavailable",
        ErrorCode::ProviderDenied => "provider_denied",
        ErrorCode::StaleEpoch => "stale_epoch",
        ErrorCode::IndeterminateEffect => "indeterminate_effect",
        ErrorCode::WouldBlock => "would_block",
        ErrorCode::NotFound => "not_found",
        ErrorCode::AlreadyExists => "already_exists",
        ErrorCode::Invalid => "invalid",
        ErrorCode::Io => "io",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::Other => "other",
    }
}

#[derive(Clone, Copy)]
struct OperationEvent<'a> {
    sequence: u64,
    phase: ObservationPhase,
    actor: ObservationActor,
    operation_id: &'a str,
    attempt: u32,
    idempotency_key: Option<&'a str>,
    operation: &'a RegularFileOperationObservation,
    result: &'a OperationCallResult,
}

#[derive(Clone, Copy)]
struct FileEvent<'a> {
    sequence: u64,
    phase: ObservationPhase,
    path: &'a [u8],
    entry: &'a FileEntryObservation,
}

#[derive(Clone, Copy)]
struct ProtocolEvent<'a> {
    sequence: u64,
    phase: ObservationPhase,
    actor: ObservationActor,
    action: &'a ProtocolAction,
    result: &'a GenericCallResult,
}

fn operation_events(case: &CaseObservation) -> Vec<OperationEvent<'_>> {
    case.events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::OperationCall {
                operation_id,
                attempt,
                idempotency_key,
                operation,
                result,
            } => Some(OperationEvent {
                sequence: event.sequence,
                phase: event.phase,
                actor: event.actor,
                operation_id,
                attempt: *attempt,
                idempotency_key: idempotency_key.as_deref(),
                operation,
                result,
            }),
            _ => None,
        })
        .collect()
}

fn file_events(case: &CaseObservation) -> Vec<FileEvent<'_>> {
    case.events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::FileProbe { path, entry } => {
                Some(FileEvent { sequence: event.sequence, phase: event.phase, path, entry })
            }
            _ => None,
        })
        .collect()
}

fn protocol_events(case: &CaseObservation) -> Vec<ProtocolEvent<'_>> {
    case.events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::ProtocolCall { action, result } => Some(ProtocolEvent {
                sequence: event.sequence,
                phase: event.phase,
                actor: event.actor,
                action,
                result,
            }),
            _ => None,
        })
        .collect()
}

fn profile_states(case: &CaseObservation) -> Vec<(u64, &wire::ProfileStateObservation)> {
    case.events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::ProfileStateProbe { state } => Some((event.sequence, state)),
            _ => None,
        })
        .collect()
}

fn lease_probes(case: &CaseObservation) -> Vec<(u64, &str, Option<&str>, u64)> {
    case.events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::LeaseProbe { resource_id, owner, epoch } => {
                Some((event.sequence, resource_id.as_str(), owner.as_deref(), *epoch))
            }
            _ => None,
        })
        .collect()
}

fn file_bytes(entry: &FileEntryObservation) -> Option<&[u8]> {
    match entry {
        FileEntryObservation::File { bytes, .. } => Some(bytes),
        _ => None,
    }
}

fn file_metadata(entry: &FileEntryObservation) -> Option<&wire::FileMetadataObservation> {
    match entry {
        FileEntryObservation::File { metadata, .. } => Some(metadata),
        _ => None,
    }
}

fn first_setup_file<'a>(case: &'a CaseObservation, path: &[u8]) -> Option<FileEvent<'a>> {
    file_events(case)
        .into_iter()
        .find(|probe| probe.phase == ObservationPhase::Setup && probe.path == path)
}

fn last_file_before<'a>(
    case: &'a CaseObservation,
    path: &[u8],
    sequence: u64,
) -> Option<FileEvent<'a>> {
    file_events(case)
        .into_iter()
        .rev()
        .find(|probe| probe.sequence < sequence && probe.path == path)
}

fn final_file<'a>(case: &'a CaseObservation, path: &[u8]) -> Option<FileEvent<'a>> {
    file_events(case)
        .into_iter()
        .rev()
        .find(|probe| probe.phase == ObservationPhase::FinalObservation && probe.path == path)
}

fn returned(result: &GenericCallResult) -> bool {
    matches!(result, GenericCallResult::Returned { .. })
}

fn generic_error(result: &GenericCallResult, code: ErrorCode) -> bool {
    matches!(result, GenericCallResult::Error { error } if error.code == code)
}

fn operation_error(case: &CaseObservation, code: ErrorCode) -> Option<u64> {
    operation_events(case).into_iter().find_map(|event| {
        matches!(event.result, OperationCallResult::Error { error } if error.code == code)
            .then_some(event.sequence)
    })
}

fn protocol_error(
    case: &CaseObservation,
    predicate: impl Fn(&ProtocolAction) -> bool,
    code: ErrorCode,
) -> Option<u64> {
    protocol_events(case).into_iter().find_map(|event| {
        (predicate(event.action) && generic_error(event.result, code)).then_some(event.sequence)
    })
}

struct CommittedLifecycle {
    commit_handoff_sequence: u64,
    resume_sequence: u64,
}

fn validate_committed_lifecycle(
    case: &CaseObservation,
    findings: &mut Vec<OracleFinding>,
) -> Option<CommittedLifecycle> {
    type Predicate = fn(&ProtocolAction) -> bool;
    let events = protocol_events(case);
    let required: [(&str, Predicate); 9] = [
        ("begin_quiesce", |action| matches!(action, ProtocolAction::BeginQuiesce { .. })),
        ("prepare_safe_point", |action| matches!(action, ProtocolAction::PrepareSafePoint { .. })),
        ("freeze_runtime", |action| matches!(action, ProtocolAction::FreezeRuntime { .. })),
        ("commit_safe_point", |action| matches!(action, ProtocolAction::CommitSafePoint { .. })),
        ("export_snapshot", |action| matches!(action, ProtocolAction::ExportSnapshot { .. })),
        ("prepare_destination", |action| {
            matches!(action, ProtocolAction::PrepareDestination { .. })
        }),
        ("commit_handoff", |action| matches!(action, ProtocolAction::CommitHandoff { .. })),
        ("restore_runtime", |action| matches!(action, ProtocolAction::RestoreRuntime { .. })),
        ("resume_destination", |action| matches!(action, ProtocolAction::ResumeDestination { .. })),
    ];
    let mut lifecycle = Vec::with_capacity(required.len());
    for (name, predicate) in required {
        let matching = events
            .iter()
            .copied()
            .filter(|event| predicate(event.action) && returned(event.result))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            finding(
                findings,
                "invalid-committed-handoff-lifecycle",
                Some(case.case_id.as_str()),
                format!(
                    "committed handoff requires exactly one successful {name}; observed {}",
                    matching.len()
                ),
            );
            return None;
        }
        lifecycle.push(matching[0]);
    }

    if lifecycle.iter().any(|event| !valid_protocol_context(event.action, event.phase, event.actor))
        || !lifecycle.windows(2).all(|pair| pair[0].sequence < pair[1].sequence)
    {
        finding(
            findings,
            "invalid-committed-handoff-lifecycle",
            Some(case.case_id.as_str()),
            "successful handoff actions do not form one ordered actor/phase-bound lifecycle",
        );
        return None;
    }

    let prepare_safe_point = match lifecycle[1].action {
        ProtocolAction::PrepareSafePoint { safe_point_id } => safe_point_id,
        _ => unreachable!("lifecycle index is type checked"),
    };
    let freeze_safe_point = match lifecycle[2].action {
        ProtocolAction::FreezeRuntime { safe_point_id } => safe_point_id,
        _ => unreachable!("lifecycle index is type checked"),
    };
    let commit_safe_point = match lifecycle[3].action {
        ProtocolAction::CommitSafePoint { safe_point_id, .. } => safe_point_id,
        _ => unreachable!("lifecycle index is type checked"),
    };
    if prepare_safe_point.is_empty()
        || prepare_safe_point != freeze_safe_point
        || prepare_safe_point != commit_safe_point
    {
        finding(
            findings,
            "handoff-safe-point-identity-mismatch",
            Some(case.case_id.as_str()),
            "prepare, freeze, and commit do not bind one identical nonempty safe-point id",
        );
        return None;
    }

    let exported_snapshot = match lifecycle[4].action {
        ProtocolAction::ExportSnapshot { snapshot_id, .. } => snapshot_id,
        _ => unreachable!("lifecycle index is type checked"),
    };
    let restored_snapshot = match lifecycle[7].action {
        ProtocolAction::RestoreRuntime { snapshot_id } => snapshot_id,
        _ => unreachable!("lifecycle index is type checked"),
    };
    if exported_snapshot.is_empty() || exported_snapshot != restored_snapshot {
        finding(
            findings,
            "handoff-snapshot-identity-mismatch",
            Some(case.case_id.as_str()),
            "export and restore do not bind one identical nonempty snapshot id",
        );
        return None;
    }

    Some(CommittedLifecycle {
        commit_handoff_sequence: lifecycle[6].sequence,
        resume_sequence: lifecycle[8].sequence,
    })
}

fn validate_committed_destination_execution(
    case: &CaseObservation,
    lifecycle: &CommittedLifecycle,
    findings: &mut Vec<OracleFinding>,
) {
    for operation in operation_events(case) {
        if operation.actor == ObservationActor::DestinationRuntime
            && (operation.sequence <= lifecycle.resume_sequence
                || operation.phase != ObservationPhase::DestinationExecution)
        {
            finding(
                findings,
                "invalid-destination-operation-context",
                Some(case.case_id.as_str()),
                format!(
                    "destination operation {} is not after ResumeDestination in destination_execution",
                    operation.operation_id
                ),
            );
            continue;
        }
        if operation.sequence <= lifecycle.commit_handoff_sequence {
            continue;
        }
        let explicit_stale_source_negative = case.case_id == RegularFileCase::StaleSourceFenced
            && operation.actor == ObservationActor::SourceRuntime
            && operation.phase == ObservationPhase::DestinationExecution
            && operation.sequence > lifecycle.resume_sequence
            && matches!(
                operation.result,
                OperationCallResult::Error { error }
                    if error.code == ErrorCode::StaleEpoch && !error.retryable
            );
        let destination_execution = operation.actor == ObservationActor::DestinationRuntime
            && operation.phase == ObservationPhase::DestinationExecution
            && operation.sequence > lifecycle.resume_sequence;
        if !destination_execution && !explicit_stale_source_negative {
            finding(
                findings,
                "invalid-post-commit-operation-context",
                Some(case.case_id.as_str()),
                format!(
                    "operation {} after CommitHandoff is neither resumed destination work nor the explicit stale-source negative",
                    operation.operation_id
                ),
            );
        }
    }
}

fn assertion(name: &str, passed: bool, supporting_sequences: Vec<u64>) -> DerivedAssertion {
    DerivedAssertion { name: name.to_owned(), passed, supporting_sequences }
}

fn derive_assertions(
    case: &CaseObservation,
    terminal: Option<DerivedTerminal>,
) -> Vec<DerivedAssertion> {
    match case.case_id {
        RegularFileCase::ReadWriteOffset => assertions_read_write_offset(case),
        RegularFileCase::AppendContinuity => assertions_append_continuity(case),
        RegularFileCase::TruncateVersion => assertions_truncate_version(case),
        RegularFileCase::RenameObjectIdentity => assertions_rename_identity(case),
        RegularFileCase::ReplacementRejected => assertions_replacement_rejected(case),
        RegularFileCase::ExternalMutationRejected => assertions_external_mutation(case),
        RegularFileCase::LockConflict => assertions_lock_conflict(case),
        RegularFileCase::DurabilityReconciled => assertions_durability_reconciled(case),
        RegularFileCase::StaleSourceFenced => assertions_stale_source_fenced(case),
        RegularFileCase::CleanupIdempotent => assertions_cleanup_idempotent(case),
        RegularFileCase::IndeterminateWriteBlocksHandoff => {
            assertions_indeterminate_blocks(case, terminal)
        }
        RegularFileCase::DestinationReauthorizationDenied => {
            assertions_destination_denied(case, terminal)
        }
    }
}

fn assertions_read_write_offset(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let operations = operation_events(case);
    let reads = operations
        .iter()
        .copied()
        .filter(|event| matches!(event.operation, RegularFileOperationObservation::Read { .. }))
        .collect::<Vec<_>>();
    let writes = operations
        .iter()
        .copied()
        .filter(|event| matches!(event.operation, RegularFileOperationObservation::Write { .. }))
        .collect::<Vec<_>>();
    let unavailable = reads.iter().copied().find(|event| {
        matches!(
            event.result,
            OperationCallResult::Error { error }
                if error.code == ErrorCode::Unavailable && error.retryable
        )
    });
    let retried = unavailable.and_then(|failed| {
        reads.iter().copied().find(|event| {
            event.operation_id == failed.operation_id
                && event.attempt > failed.attempt
                && matches!(
                    event.result,
                    OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Read { .. }
                    }
                )
        })
    });
    let returned_reads = reads
        .iter()
        .copied()
        .filter(|event| {
            matches!(
                event.result,
                OperationCallResult::Returned { output: RegularFileOutputObservation::Read { .. } }
            )
        })
        .collect::<Vec<_>>();
    let initial = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let successful_write = writes
        .iter()
        .copied()
        .filter(|event| {
            matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Mutated { .. }
                }
            )
        })
        .collect::<Vec<_>>();

    let mut bytes_preserved = false;
    let mut offset_preserved = false;
    let mut write_once = false;
    let mut basis = Vec::new();
    if let (Some(initial), Some(final_probe), Some(first_read), Some(last_read), [write]) = (
        initial,
        final_probe,
        returned_reads.first().copied(),
        returned_reads.last().copied(),
        successful_write.as_slice(),
    ) {
        let initial_bytes = file_bytes(initial.entry);
        let final_bytes = file_bytes(final_probe.entry);
        if let (
            Some(initial_bytes),
            Some(final_bytes),
            RegularFileOperationObservation::Read { max_bytes: first_max },
            OperationCallResult::Returned {
                output:
                    RegularFileOutputObservation::Read {
                        bytes: first_bytes,
                        logical_offset: first_offset,
                        ..
                    },
            },
            RegularFileOperationObservation::Write { bytes: write_bytes, .. },
            OperationCallResult::Returned {
                output:
                    RegularFileOutputObservation::Mutated {
                        logical_offset: write_offset,
                        version: write_version,
                        ..
                    },
            },
            RegularFileOperationObservation::Read { max_bytes: last_max },
            OperationCallResult::Returned {
                output:
                    RegularFileOutputObservation::Read {
                        bytes: last_bytes,
                        logical_offset: last_offset,
                        version: last_version,
                        size: last_size,
                        ..
                    },
            },
        ) = (
            initial_bytes,
            final_bytes,
            first_read.operation,
            first_read.result,
            write.operation,
            write.result,
            last_read.operation,
            last_read.result,
        ) {
            let first_len =
                usize::try_from(*first_max).unwrap_or(usize::MAX).min(initial_bytes.len());
            let first_ok = first_bytes == &initial_bytes[..first_len]
                && *first_offset == first_bytes.len() as u64;
            let write_start = *first_offset as usize;
            let mut expected = initial_bytes.to_vec();
            if write_start <= expected.len() {
                let replace_end = write_start.saturating_add(write_bytes.len()).min(expected.len());
                expected.splice(write_start..replace_end, write_bytes.iter().copied());
            }
            let expected_write_offset = first_offset.saturating_add(write_bytes.len() as u64);
            let read_start = expected_write_offset as usize;
            let read_end = read_start
                .saturating_add(usize::try_from(*last_max).unwrap_or(usize::MAX))
                .min(expected.len());
            let expected_last = expected.get(read_start..read_end).unwrap_or_default();
            bytes_preserved = first_ok && final_bytes == expected && last_bytes == expected_last;
            offset_preserved = *write_offset == expected_write_offset
                && *last_offset == expected_write_offset + last_bytes.len() as u64
                && *last_size == expected.len() as u64
                && *last_version == *write_version
                && profile_states(case).last().is_some_and(|(_, state)| {
                    state.logical_offset == *last_offset
                        && state.size == expected.len() as u64
                        && state.version == *last_version
                });
            write_once = successful_write.len() == 1 && final_bytes == expected;
            basis.extend([
                initial.sequence,
                first_read.sequence,
                write.sequence,
                last_read.sequence,
                final_probe.sequence,
            ]);
        }
    }
    let transient = unavailable.zip(retried).is_some_and(|(failed, retry)| {
        failed.operation_id == retry.operation_id
            && failed.idempotency_key == retry.idempotency_key
            && retry.attempt == failed.attempt + 1
    });
    let transient_basis =
        unavailable.into_iter().chain(retried).map(|event| event.sequence).collect();
    vec![
        assertion("transient_observe_retried", transient, transient_basis),
        assertion("bytes_preserved", bytes_preserved, basis.clone()),
        assertion("logical_offset_preserved", offset_preserved, basis.clone()),
        assertion("write_once", write_once, basis),
    ]
}

fn assertions_append_continuity(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let appends = operation_events(case)
        .into_iter()
        .filter(|event| {
            matches!(event.operation, RegularFileOperationObservation::Append { .. })
                && matches!(
                    event.result,
                    OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Mutated { .. }
                    }
                )
        })
        .collect::<Vec<_>>();
    let initial = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let mut expected = initial
        .and_then(|probe| file_bytes(probe.entry))
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let mut unique = BTreeMap::<&str, (&RegularFileOperationObservation, Option<&str>)>::new();
    let mut replay_consistent = true;
    for event in &appends {
        if let Some((prior_operation, prior_key)) = unique.get(event.operation_id) {
            replay_consistent &=
                *prior_operation == event.operation && *prior_key == event.idempotency_key;
        } else {
            unique.insert(event.operation_id, (event.operation, event.idempotency_key));
            if let RegularFileOperationObservation::Append { bytes, .. } = event.operation {
                expected.extend_from_slice(bytes);
            }
        }
    }
    let final_bytes = final_probe.and_then(|probe| file_bytes(probe.entry));
    let profile = profile_states(case);
    let first_state = profile.first().map(|(_, state)| *state);
    let last_state = profile.last().map(|(_, state)| *state);
    let append_once = appends.len() == 3
        && unique.len() == 2
        && appends.len() > unique.len()
        && replay_consistent
        && final_bytes == Some(expected.as_slice())
        && first_state
            .zip(last_state)
            .is_some_and(|(first, last)| last.version == first.version + unique.len() as u64);
    let size_preserved = final_bytes.is_some_and(|bytes| {
        last_state.is_some_and(|state| {
            state.size == bytes.len() as u64 && state.logical_offset == bytes.len() as u64
        })
    });
    let digest_preserved = final_probe.is_some_and(|probe| match probe.entry {
        FileEntryObservation::File { bytes, sha256, .. } => *sha256 == sha256_hex(bytes),
        _ => false,
    });
    let basis = appends
        .iter()
        .map(|event| event.sequence)
        .chain(initial.into_iter().chain(final_probe).map(|probe| probe.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("append_once", append_once, basis.clone()),
        assertion("size_preserved", size_preserved, basis.clone()),
        assertion("digest_preserved", digest_preserved, basis),
    ]
}

fn assertions_truncate_version(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let truncates = operation_events(case)
        .into_iter()
        .filter(|event| {
            matches!(event.operation, RegularFileOperationObservation::Truncate { .. })
                && matches!(
                    event.result,
                    OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Mutated { .. }
                    }
                )
        })
        .collect::<Vec<_>>();
    let initial = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let profile = profile_states(case);
    let first_state = profile.first().map(|(_, state)| *state);
    let last_state = profile.last().map(|(_, state)| *state);
    let size_preserved = truncates.as_slice().first().is_some_and(|truncate| {
        if let RegularFileOperationObservation::Truncate { size, .. } = truncate.operation {
            initial
                .and_then(|probe| file_bytes(probe.entry))
                .zip(final_probe.and_then(|probe| file_bytes(probe.entry)))
                .is_some_and(|(before, after)| {
                    let expected_len =
                        usize::try_from(*size).unwrap_or(usize::MAX).min(before.len());
                    after == &before[..expected_len]
                        && last_state.is_some_and(|state| state.size == *size)
                })
        } else {
            false
        }
    }) && truncates.len() == 1;
    let version_advanced =
        first_state.zip(last_state).is_some_and(|(first, last)| last.version == first.version + 1);
    let digest_preserved = final_probe.is_some_and(|probe| match probe.entry {
        FileEntryObservation::File { bytes, sha256, .. } => *sha256 == sha256_hex(bytes),
        _ => false,
    });
    let basis = truncates
        .iter()
        .map(|event| event.sequence)
        .chain(initial.into_iter().chain(final_probe).map(|probe| probe.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("size_preserved", size_preserved, basis.clone()),
        assertion("version_advanced", version_advanced, basis.clone()),
        assertion("digest_preserved", digest_preserved, basis),
    ]
}

fn assertions_rename_identity(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let renames = operation_events(case)
        .into_iter()
        .filter(|event| matches!(event.operation, RegularFileOperationObservation::Rename { .. }))
        .collect::<Vec<_>>();
    let conflict = renames.iter().copied().find(|event| {
        matches!(
            event.result,
            OperationCallResult::Error { error } if error.code == ErrorCode::Conflict
        )
    });
    let successful = renames.iter().copied().find(|event| {
        matches!(
            event.result,
            OperationCallResult::Returned { output: RegularFileOutputObservation::Renamed { .. } }
        )
    });
    let initial = first_setup_file(case, &case.subject.initial_path);
    let target_path = successful.and_then(|event| match event.operation {
        RegularFileOperationObservation::Rename { relative_path } => Some(relative_path.as_slice()),
        _ => None,
    });
    let occupied_path = conflict.and_then(|event| match event.operation {
        RegularFileOperationObservation::Rename { relative_path } => Some(relative_path.as_slice()),
        _ => None,
    });
    let target_final = target_path.and_then(|path| final_file(case, path));
    let old_final = final_file(case, &case.subject.initial_path);
    let occupied_initial = conflict.and_then(|event| {
        occupied_path.and_then(|path| last_file_before(case, path, event.sequence))
    });
    let occupied_final = occupied_path.and_then(|path| final_file(case, path));
    let profile_final = profile_states(case).last().map(|(_, state)| *state);

    let path_rebound = target_path.zip(profile_final).is_some_and(|(path, state)| {
        state.relative_path == path
            && matches!(
                successful.map(|event| event.result),
                Some(OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Renamed { relative_path, .. }
                }) if relative_path == path
            )
    });
    let object_identity_preserved = initial
        .and_then(|probe| file_metadata(probe.entry))
        .zip(target_final.and_then(|probe| file_metadata(probe.entry)))
        .is_some_and(|(before, after)| {
            before.device == after.device
                && before.inode == after.inode
                && before.generation == after.generation
        });
    let existing_target_preserved = conflict.is_some()
        && occupied_initial
            .and_then(|probe| file_bytes(probe.entry))
            .zip(occupied_final.and_then(|probe| file_bytes(probe.entry)))
            .is_some_and(|(before, after)| before == after)
        && initial
            .and_then(|probe| file_bytes(probe.entry))
            .zip(target_final.and_then(|probe| file_bytes(probe.entry)))
            .is_some_and(|(before, after)| before == after);
    let old_path_absent =
        old_final.is_some_and(|probe| matches!(probe.entry, FileEntryObservation::Missing));
    let basis = renames
        .iter()
        .map(|event| event.sequence)
        .chain(
            initial
                .into_iter()
                .chain(target_final)
                .chain(old_final)
                .chain(occupied_initial)
                .chain(occupied_final)
                .map(|probe| probe.sequence),
        )
        .collect::<Vec<_>>();
    vec![
        assertion("path_rebound", path_rebound, basis.clone()),
        assertion("object_identity_preserved", object_identity_preserved, basis.clone()),
        assertion("existing_target_preserved", existing_target_preserved, basis.clone()),
        assertion("old_path_absent", old_path_absent, basis),
    ]
}

fn assertions_replacement_rejected(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let initial = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let replacement = case.events.iter().find_map(|event| match &event.body {
        RawObservationEvent::OsCall {
            action: OsAction::ReplacePath { destination, .. },
            result,
        } if destination == &case.subject.initial_path && returned(result) => Some(event.sequence),
        _ => None,
    });
    let conflict = operation_error(case, ErrorCode::Conflict);
    let identity_changed = initial
        .and_then(|probe| file_metadata(probe.entry))
        .zip(final_probe.and_then(|probe| file_metadata(probe.entry)))
        .is_some_and(|(before, after)| {
            before.device != after.device
                || before.inode != after.inode
                || before.generation != after.generation
        });
    let same_bytes = initial
        .and_then(|probe| file_bytes(probe.entry))
        .zip(final_probe.and_then(|probe| file_bytes(probe.entry)))
        .is_some_and(|(before, after)| before == after);
    let states = profile_states(case);
    let state_unchanged =
        states.first().zip(states.last()).is_some_and(|(before, after)| before.1 == after.1);
    let replacement_detected = replacement.is_some() && conflict.is_some() && identity_changed;
    let same_content_not_accepted = replacement_detected && same_bytes && state_unchanged;
    let basis = replacement
        .into_iter()
        .chain(conflict)
        .chain(initial.into_iter().chain(final_probe).map(|probe| probe.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("replacement_detected", replacement_detected, basis.clone()),
        assertion("same_content_not_accepted", same_content_not_accepted, basis),
    ]
}

fn assertions_external_mutation(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let external_write = case.events.iter().find_map(|event| match &event.body {
        RawObservationEvent::OsCall { action: OsAction::WriteWhole { path, bytes }, result }
            if path == &case.subject.initial_path && returned(result) =>
        {
            Some((event.sequence, bytes.as_slice()))
        }
        _ => None,
    });
    let conflict = operation_error(case, ErrorCode::Conflict);
    let final_probe = final_file(case, &case.subject.initial_path);
    let external_bytes_visible = external_write
        .map(|(_, bytes)| bytes)
        .zip(final_probe.and_then(|probe| file_bytes(probe.entry)))
        .is_some_and(|(written, observed)| written == observed);
    let states = profile_states(case);
    let state_unchanged =
        states.first().zip(states.last()).is_some_and(|(before, after)| before.1 == after.1);
    let basis = external_write
        .map(|(sequence, _)| sequence)
        .into_iter()
        .chain(conflict)
        .chain(final_probe.into_iter().map(|probe| probe.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion(
            "version_conflict_detected",
            external_write.is_some() && external_bytes_visible && conflict.is_some(),
            basis.clone(),
        ),
        assertion("canonical_state_unchanged", state_unchanged, basis),
    ]
}

fn assertions_lock_conflict(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let operations = operation_events(case);
    let source_acquire = operations.iter().copied().find(|event| {
        event.actor == ObservationActor::SourceRuntime
            && matches!(event.operation, RegularFileOperationObservation::AcquireLock)
            && matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Lock {
                        state: FileLockStateObservation::Held
                    }
                }
            )
    });
    let source_release = operations.iter().copied().find(|event| {
        event.actor == ObservationActor::SourceRuntime
            && matches!(event.operation, RegularFileOperationObservation::ReleaseLock)
            && matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Lock {
                        state: FileLockStateObservation::Unlocked
                    }
                }
            )
    });
    let destination_acquire = operations.iter().copied().find(|event| {
        event.actor == ObservationActor::DestinationRuntime
            && matches!(event.operation, RegularFileOperationObservation::AcquireLock)
            && matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Lock {
                        state: FileLockStateObservation::Held
                    }
                }
            )
    });
    let destination_release = operations.iter().copied().find(|event| {
        event.actor == ObservationActor::DestinationRuntime
            && matches!(event.operation, RegularFileOperationObservation::ReleaseLock)
            && matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Lock {
                        state: FileLockStateObservation::Unlocked
                    }
                }
            )
    });
    let competing = case.events.iter().find_map(|event| match &event.body {
        RawObservationEvent::OsCall {
            action: OsAction::TryExclusiveLock { path },
            result: GenericCallResult::Error { error },
        } if path == &case.subject.initial_path && error.code == ErrorCode::WouldBlock => {
            Some(event.sequence)
        }
        _ => None,
    });
    let live_freeze_rejected = protocol_error(
        case,
        |action| matches!(action, ProtocolAction::FreezeRuntime { .. }),
        ErrorCode::SafePointUnavailable,
    );
    let final_unlocked = profile_states(case)
        .last()
        .is_some_and(|(_, state)| state.lock_state == FileLockStateObservation::Unlocked);
    let exclusive_lock_enforced = source_acquire.is_some()
        && competing.is_some()
        && source_release.is_some()
        && source_acquire.is_some_and(|acquire| {
            source_release.is_some_and(|release| acquire.sequence < release.sequence)
                && competing.is_some_and(|sequence| {
                    acquire.sequence < sequence && sequence < source_release.unwrap().sequence
                })
        });
    let lock_not_snapshotted_live = live_freeze_rejected.is_some()
        && source_release.is_some_and(|release| {
            live_freeze_rejected.is_some_and(|sequence| sequence < release.sequence)
        })
        && final_unlocked;
    let reacquired = destination_acquire.is_some_and(|acquire| {
        destination_release.is_some_and(|release| acquire.sequence < release.sequence)
    });
    let basis = source_acquire
        .into_iter()
        .chain(source_release)
        .chain(destination_acquire)
        .chain(destination_release)
        .map(|event| event.sequence)
        .chain(competing)
        .chain(live_freeze_rejected)
        .collect::<Vec<_>>();
    vec![
        assertion("exclusive_lock_enforced", exclusive_lock_enforced, basis.clone()),
        assertion("lock_not_snapshotted_live", lock_not_snapshotted_live, basis.clone()),
        assertion("reacquired", reacquired, basis),
    ]
}

fn assertions_durability_reconciled(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let appends = operation_events(case)
        .into_iter()
        .filter(|event| matches!(event.operation, RegularFileOperationObservation::Append { .. }))
        .collect::<Vec<_>>();
    let indeterminate = appends.iter().copied().find(|event| {
        matches!(
            event.result,
            OperationCallResult::Error { error } if error.code == ErrorCode::Indeterminate
        )
    });
    let reconciled = indeterminate.and_then(|failed| {
        appends.iter().copied().find(|event| {
            event.operation_id == failed.operation_id
                && event.attempt == failed.attempt + 1
                && event.idempotency_key == failed.idempotency_key
                && matches!(
                    event.result,
                    OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Mutated { .. }
                    }
                )
        })
    });
    let initial = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let expected = initial.and_then(|probe| file_bytes(probe.entry)).zip(indeterminate).and_then(
        |(before, event)| match event.operation {
            RegularFileOperationObservation::Append { bytes, .. } => {
                let mut expected = before.to_vec();
                expected.extend_from_slice(bytes);
                Some(expected)
            }
            _ => None,
        },
    );
    let post_fault_probe = indeterminate.zip(reconciled).and_then(|(failed, retry)| {
        file_events(case).into_iter().find(|probe| {
            failed.sequence < probe.sequence
                && probe.sequence < retry.sequence
                && probe.path == case.subject.initial_path
        })
    });
    let mutation_once = expected.as_deref().is_some_and(|expected| {
        post_fault_probe.and_then(|probe| file_bytes(probe.entry)) == Some(expected)
            && final_probe.and_then(|probe| file_bytes(probe.entry)) == Some(expected)
    });
    let final_state = profile_states(case).last().map(|(_, state)| *state);
    let durability_met = final_state
        .is_some_and(|state| state.durable_through == FileDurabilityObservation::DataAndMetadata);
    let ledger_applied = indeterminate.is_some_and(|failed| {
        case.events.iter().rev().find_map(|event| match &event.body {
            RawObservationEvent::OperationLedgerProbe { records } => {
                records.iter().find(|record| record.operation_id == failed.operation_id).map(
                    |record| matches!(record.outcome, OperationOutcomeObservation::Applied { .. }),
                )
            }
            _ => None,
        }) == Some(true)
    });
    let lost_ack_reconciled = indeterminate.zip(reconciled).is_some() && ledger_applied;
    let basis = appends
        .iter()
        .map(|event| event.sequence)
        .chain(
            initial
                .into_iter()
                .chain(post_fault_probe)
                .chain(final_probe)
                .map(|probe| probe.sequence),
        )
        .collect::<Vec<_>>();
    vec![
        assertion("durability_met", durability_met, basis.clone()),
        assertion("lost_ack_reconciled", lost_ack_reconciled, basis.clone()),
        assertion("mutation_not_repeated", mutation_once, basis),
    ]
}

fn assertions_stale_source_fenced(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let lease_checks = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::LeaseCheck { resource_id, owner, epoch, result }
                if resource_id == &case.subject.resource_id =>
            {
                Some((event.sequence, owner.as_str(), *epoch, result))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let stale_check = lease_checks
        .iter()
        .copied()
        .find(|(_, _, _, result)| generic_error(result, ErrorCode::StaleEpoch));
    let leases = lease_probes(case)
        .into_iter()
        .filter(|(_, resource, _, _)| *resource == case.subject.resource_id)
        .collect::<Vec<_>>();
    let initial_lease = leases.first().copied();
    let final_lease = leases.last().copied();
    let epoch_advanced = initial_lease.zip(final_lease).is_some_and(
        |((_, _, initial_owner, initial_epoch), (_, _, final_owner, final_epoch))| {
            initial_owner.is_some()
                && final_owner.is_some()
                && initial_owner != final_owner
                && final_epoch > initial_epoch
        },
    );
    let source_denied = stale_check.zip(initial_lease).is_some_and(
        |((_, owner, epoch, _), (_, _, initial_owner, initial_epoch))| {
            Some(owner) == initial_owner && epoch == initial_epoch
        },
    );
    let destination_append = operation_events(case).into_iter().find(|event| {
        event.actor == ObservationActor::DestinationRuntime
            && matches!(event.operation, RegularFileOperationObservation::Append { .. })
            && matches!(
                event.result,
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Mutated { .. }
                }
            )
    });
    let initial_file = first_setup_file(case, &case.subject.initial_path);
    let final_probe = final_file(case, &case.subject.initial_path);
    let destination_write_succeeded = destination_append.is_some_and(|append| {
        let expected =
            initial_file.and_then(|probe| file_bytes(probe.entry)).and_then(|before| match append
                .operation
            {
                RegularFileOperationObservation::Append { bytes, .. } => {
                    let mut expected = before.to_vec();
                    expected.extend_from_slice(bytes);
                    Some(expected)
                }
                _ => None,
            });
        expected.as_deref() == final_probe.and_then(|probe| file_bytes(probe.entry))
            && profile_states(case).last().is_some_and(|(_, state)| {
                matches!(
                    append.result,
                    OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Mutated { version, .. }
                    } if state.version == *version
                )
            })
    });
    let basis = leases
        .iter()
        .map(|(sequence, _, _, _)| *sequence)
        .chain(stale_check.map(|(sequence, _, _, _)| sequence))
        .chain(destination_append.map(|event| event.sequence))
        .chain(initial_file.into_iter().chain(final_probe).map(|probe| probe.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("destination_epoch_advanced", epoch_advanced, basis.clone()),
        assertion("source_write_denied", source_denied, basis.clone()),
        assertion("destination_write_succeeded", destination_write_succeeded, basis),
    ]
}

fn assertions_cleanup_idempotent(case: &CaseObservation) -> Vec<DerivedAssertion> {
    let successful_effect = operation_events(case).into_iter().find(|event| {
        matches!(
            event.operation,
            RegularFileOperationObservation::Write { .. }
                | RegularFileOperationObservation::Append { .. }
                | RegularFileOperationObservation::Truncate { .. }
                | RegularFileOperationObservation::Rename { .. }
        ) && matches!(event.result, OperationCallResult::Returned { .. })
    });
    let cleanup_calls = protocol_events(case)
        .into_iter()
        .filter_map(|event| match event.action {
            ProtocolAction::CleanupOperation { operation_id, .. } if returned(event.result) => {
                Some((event.sequence, operation_id.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let matching_cleanup_calls = successful_effect.map_or_else(Vec::new, |effect| {
        cleanup_calls
            .iter()
            .copied()
            .filter(|(_, operation)| *operation == effect.operation_id)
            .collect::<Vec<_>>()
    });
    let ledgers = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::OperationLedgerProbe { records } => {
                Some((event.sequence, records.as_slice()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let ledger_after = |sequence: u64| {
        ledgers.iter().copied().find(|(probe_sequence, _)| *probe_sequence > sequence)
    };
    let first_record = matching_cleanup_calls.first().and_then(|(sequence, operation)| {
        ledger_after(*sequence).and_then(|(_, records)| {
            let matching = records
                .iter()
                .filter(|record| record.operation_id == *operation)
                .collect::<Vec<_>>();
            (matching.len() == 1).then_some(matching[0])
        })
    });
    let second_record = matching_cleanup_calls.get(1).and_then(|(sequence, operation)| {
        ledger_after(*sequence).and_then(|(_, records)| {
            let matching = records
                .iter()
                .filter(|record| record.operation_id == *operation)
                .collect::<Vec<_>>();
            (matching.len() == 1).then_some(matching[0])
        })
    });
    let cleanup_repeated = matching_cleanup_calls.len() == 2
        && first_record.is_some_and(|record| record.cleanup == CleanupObservation::Cleaned)
        && second_record.is_some_and(|record| record.cleanup == CleanupObservation::Cleaned);
    let operation_truth_retained =
        first_record.zip(second_record).is_some_and(|(first, second)| {
            matches!(first.outcome, OperationOutcomeObservation::Applied { .. })
                && first.outcome == second.outcome
                && first.request_digest == second.request_digest
        });
    let basis = matching_cleanup_calls
        .iter()
        .map(|(sequence, _)| *sequence)
        .chain(ledgers.iter().map(|(sequence, _)| *sequence))
        .chain(successful_effect.map(|event| event.sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("cleanup_repeated", cleanup_repeated, basis.clone()),
        assertion("operation_truth_retained", operation_truth_retained, basis),
    ]
}

fn assertions_indeterminate_blocks(
    case: &CaseObservation,
    terminal: Option<DerivedTerminal>,
) -> Vec<DerivedAssertion> {
    let indeterminate = operation_events(case).into_iter().find(|event| {
        matches!(
            event.result,
            OperationCallResult::Error { error } if error.code == ErrorCode::Indeterminate
        )
    });
    let ledger_unknown = indeterminate.is_some_and(|operation| {
        case.events.iter().rev().find_map(|event| match &event.body {
            RawObservationEvent::OperationLedgerProbe { records } => records
                .iter()
                .find(|record| record.operation_id == operation.operation_id)
                .map(|record| record.outcome == OperationOutcomeObservation::Indeterminate),
            _ => None,
        }) == Some(true)
    });
    let freeze_rejected = protocol_error(
        case,
        |action| matches!(action, ProtocolAction::CommitSafePoint { .. }),
        ErrorCode::IndeterminateEffect,
    );
    let leases = lease_probes(case)
        .into_iter()
        .filter(|(_, resource, _, _)| *resource == case.subject.resource_id)
        .collect::<Vec<_>>();
    let no_transfer =
        leases.first().zip(leases.last()).is_some_and(|(first, last)| {
            first.2.is_some() && first.2 == last.2 && first.3 == last.3
        }) && !protocol_events(case).into_iter().any(|event| {
            matches!(
                event.action,
                ProtocolAction::PrepareDestination { .. }
                    | ProtocolAction::CommitHandoff { .. }
                    | ProtocolAction::ResumeDestination { .. }
            ) && returned(event.result)
        });
    let basis = indeterminate
        .map(|event| event.sequence)
        .into_iter()
        .chain(freeze_rejected)
        .chain(leases.iter().map(|(sequence, _, _, _)| *sequence))
        .collect::<Vec<_>>();
    vec![
        assertion("unknown_outcome_recorded", ledger_unknown, basis.clone()),
        assertion(
            "freeze_rejected",
            freeze_rejected.is_some() && terminal == Some(DerivedTerminal::HandoffBlocked),
            basis.clone(),
        ),
        assertion("no_lease_transfer", no_transfer, basis),
    ]
}

fn assertions_destination_denied(
    case: &CaseObservation,
    terminal: Option<DerivedTerminal>,
) -> Vec<DerivedAssertion> {
    let prepare_denied = protocol_error(
        case,
        |action| matches!(action, ProtocolAction::PrepareDestination { .. }),
        ErrorCode::ProviderDenied,
    );
    let binding_probes = case
        .events
        .iter()
        .filter_map(|event| match &event.body {
            RawObservationEvent::DestinationBindingProbe { bindings } => {
                Some((event.sequence, bindings.as_slice()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let binding_absent = binding_probes.last().is_some_and(|(_, bindings)| {
        let matching = bindings
            .iter()
            .filter(|binding| binding.resource_id == case.subject.resource_id)
            .collect::<Vec<_>>();
        matching.is_empty()
            || (matching.len() == 1
                && matching[0].state == DestinationBindingState::Absent
                && matching[0].owner.is_none()
                && matching[0].epoch.is_none())
    });
    let leases = lease_probes(case)
        .into_iter()
        .filter(|(_, resource, _, _)| *resource == case.subject.resource_id)
        .collect::<Vec<_>>();
    let source_retained = leases
        .first()
        .zip(leases.last())
        .is_some_and(|(first, last)| first.2.is_some() && first.2 == last.2 && first.3 == last.3);
    let no_commit = !protocol_events(case).into_iter().any(|event| {
        matches!(
            event.action,
            ProtocolAction::CommitHandoff { .. } | ProtocolAction::ResumeDestination { .. }
        ) && returned(event.result)
    });
    let basis = prepare_denied
        .into_iter()
        .chain(binding_probes.iter().map(|(sequence, _)| *sequence))
        .chain(leases.iter().map(|(sequence, _, _, _)| *sequence))
        .collect::<Vec<_>>();
    vec![
        assertion(
            "destination_policy_denied",
            prepare_denied.is_some() && terminal == Some(DerivedTerminal::HandoffBlocked),
            basis.clone(),
        ),
        assertion("binding_not_published", binding_absent && no_commit, basis.clone()),
        assertion("source_lease_retained", source_retained, basis),
    ]
}
