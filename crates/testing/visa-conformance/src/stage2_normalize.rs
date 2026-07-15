use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::path::Path;

use contract_core::{
    BindingReceipt, CanonicalState, Digest, EffectFailure, EffectOutcome, EffectRequest,
    EffectResult, EventKind, EvidenceRef, LogicalDurationNanos, OperationRecord,
    PreparationCleanup, PreparedDestination, SnapshotEnvelope, TimerDisposition, TimerStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub use crate::stage2::{
    ProtocolCommandKind as Stage2WorkerCommandKind, ProtocolResultKind as Stage2WorkerResultKind,
};
use crate::{
    Stage1ArtifactReference, Stage1CaseEvidence, Stage1FaultSchedule, Stage1PerformanceMetric,
    Stage1ResourceKind, Stage1SemanticTraceArtifact, Stage1TraceRole, VerifiedStage1Artifacts,
    stage2::{
        ProtocolRequestProjection, ProtocolResponseProjection, project_request_command,
        project_response, success_result_matches,
    },
};

pub const STAGE2_NORMALIZED_TRACE_SCHEMA_VERSION: &str =
    "visa-stage2-normalized-observable-trace-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2TimerEquivalenceProfile {
    PausedDurationZeroVsPositiveV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2DerivedIntegrityEquivalenceProfile {
    Stage1VerifiedDerivedDigestsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedCellV1 {
    pub schema_version: String,
    pub timer_equivalence: Stage2TimerEquivalenceProfile,
    pub derived_integrity_equivalence: Stage2DerivedIntegrityEquivalenceProfile,
    pub cases: Vec<Stage2NormalizedCaseV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedCaseV1 {
    pub case_id: String,
    pub execution_id: String,
    pub handoff_id: String,
    pub snapshot_id: String,
    pub case_config_sha256: String,
    pub case_policy_sha256: String,
    pub outcome: crate::Stage1CaseOutcome,
    pub exit_status: i32,
    pub fault_schedule: Stage1FaultSchedule,
    pub authority: crate::Stage1AuthorityEvidence,
    pub snapshot: Option<SnapshotEnvelope>,
    pub semantic_traces: Vec<Stage1SemanticTraceArtifact>,
    pub binding_receipts: Vec<Stage2NormalizedBindingReceipt>,
    pub assertion_names: Vec<String>,
    pub worker_protocol_observations: Vec<Stage2NormalizedWorkerProtocolObservation>,
    pub worker_errors: Vec<Stage2NormalizedWorkerError>,
    pub state: Stage2NormalizedStateEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedWorkerProtocolObservation {
    pub role: Stage1TraceRole,
    pub worker_scope: String,
    pub observation_index: u64,
    pub worker_request_index: u64,
    pub command_occurrence: u64,
    pub command: Stage2WorkerCommandKind,
    pub response: Stage2NormalizedWorkerResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Stage2NormalizedWorkerResponse {
    Success { result: Stage2WorkerResultKind },
    Error,
    NoResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage2WorkerErrorCode {
    Protocol,
    InvalidState,
    Fixture,
    Provider,
    Runtime,
    Adapter,
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage2AdapterFailureKind {
    IncompatibleProfile,
    ProfileEncoding,
    ProfileDigestMismatch,
    ComponentDigestMismatch,
    Engine,
    InvalidComponent,
    Link,
    UnsupportedRuntimeFeature,
    Instantiation,
    GuestTrap,
    Workload,
    ResourceBinding,
    LiveResourcesAtSafePoint,
    SafePointStateMismatch,
    PortableStateMismatch,
    PortableState,
    Coordinator,
    SafePointRollback,
    SafePointGuestRollback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage2WorkloadFailureKind {
    AlreadyActive,
    InvalidState,
    WrongTimer,
    SafePointUnavailable,
    KeyValueDenied,
    KeyValueConflict,
    KeyValueStaleBinding,
    KeyValueIndeterminate,
    KeyValueUnavailable,
    TimerDenied,
    TimerStaleBinding,
    TimerNotPending,
    TimerUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Stage2ProviderFailureKind {
    InvalidRequest,
    Unsupported,
    NotFound,
    Conflict,
    StaleGeneration,
    StaleEpoch,
    Denied,
    Revoked,
    Integrity,
    Unavailable,
    OutcomeUnknown,
    Storage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedWorkerError {
    pub role: Stage1TraceRole,
    pub observation_index: u64,
    pub code: Stage2WorkerErrorCode,
    pub retryable: Option<bool>,
    pub provider_kind: Option<Stage2ProviderFailureKind>,
    pub adapter_kind: Option<Stage2AdapterFailureKind>,
    pub workload_kind: Option<Stage2WorkloadFailureKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedBindingReceipt {
    pub resource: Stage1ResourceKind,
    pub receipt_id: String,
    pub receipt: BindingReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2NormalizedStateEvidence {
    pub final_state_sha256: String,
    pub replay_state_sha256: String,
    pub snapshot_sha256: Option<String>,
    pub semantic_trace_sha256s: Vec<String>,
    pub normalized_snapshot_size_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2NormalizationError {
    pub code: String,
    pub detail: String,
}

impl std::fmt::Display for Stage2NormalizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Stage2NormalizationError {}

pub(crate) fn normalize_stage2_cell(
    bundle: &crate::Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
) -> Result<Stage2NormalizedCellV1, Stage2NormalizationError> {
    let mut cases = Vec::with_capacity(bundle.cases.len());
    for case in &bundle.cases {
        cases.push(normalize_stage2_case(bundle, case, artifacts)?);
    }
    Ok(Stage2NormalizedCellV1 {
        schema_version: STAGE2_NORMALIZED_TRACE_SCHEMA_VERSION.to_owned(),
        timer_equivalence: Stage2TimerEquivalenceProfile::PausedDurationZeroVsPositiveV1,
        derived_integrity_equivalence:
            Stage2DerivedIntegrityEquivalenceProfile::Stage1VerifiedDerivedDigestsV1,
        cases,
    })
}

fn normalize_stage2_case(
    bundle: &crate::Stage1EvidenceBundle,
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
) -> Result<Stage2NormalizedCaseV1, Stage2NormalizationError> {
    validate_canonical_raw_artifacts(case)?;
    let snapshot = case
        .artifacts
        .snapshot
        .as_ref()
        .map(|reference| read_captured_typed_artifact::<SnapshotEnvelope>(artifacts, reference))
        .transpose()?
        .map(normalize_snapshot);

    let mut semantic_traces = Vec::with_capacity(case.artifacts.semantic_traces.len());
    for reference in &case.artifacts.semantic_traces {
        let trace =
            read_captured_typed_artifact::<Stage1SemanticTraceArtifact>(artifacts, reference)?;
        semantic_traces.push(normalize_trace(trace));
    }

    let mut binding_receipts = Vec::with_capacity(case.artifacts.binding_receipts.len());
    for reference in &case.artifacts.binding_receipts {
        let receipt =
            read_captured_typed_artifact::<BindingReceipt>(artifacts, &reference.artifact)?;
        binding_receipts.push(Stage2NormalizedBindingReceipt {
            resource: reference.resource,
            receipt_id: reference.receipt_id.clone(),
            receipt: normalize_binding_receipt(receipt),
        });
    }

    let assertion_names = read_assertion_names(case, artifacts)?;
    let worker_protocol_observations = read_worker_protocol_observations(case, artifacts)?;
    let worker_errors = read_worker_errors(case, artifacts)?;
    let semantic_trace_sha256s =
        semantic_traces.iter().map(canonical_stage2_sha256).collect::<Result<Vec<_>, _>>()?;
    let snapshot_bytes = snapshot.as_ref().map(canonical_stage2_json_bytes).transpose()?;
    let snapshot_sha256 = snapshot_bytes.as_ref().map(|bytes| sha256_hex(bytes));
    let normalized_snapshot_size_bytes =
        snapshot_bytes.as_ref().map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    let final_trace = select_final_trace(case, &semantic_traces)?;
    let final_state_sha256 = canonical_stage2_sha256(&final_trace.final_state)?;

    if case.case_id == "performance-observations"
        && !bundle.performance_observations.iter().any(|observation| {
            observation.metric == Stage1PerformanceMetric::SnapshotSize
                && observation.execution_id == case.execution_id
        })
    {
        return Err(error(
            "missing-stage2-snapshot-size-observation",
            format!("{} has no verified Stage 1 snapshot-size observation", case.case_id),
        ));
    }

    Ok(Stage2NormalizedCaseV1 {
        case_id: case.case_id.clone(),
        execution_id: case.execution_id.clone(),
        handoff_id: case.handoff_id.clone(),
        snapshot_id: case.snapshot_id.clone(),
        case_config_sha256: case.case_config_sha256.clone(),
        case_policy_sha256: case.case_policy_sha256.clone(),
        outcome: case.outcome,
        exit_status: case.exit_status,
        fault_schedule: case.fault_schedule.clone(),
        authority: case.authority.clone(),
        snapshot,
        semantic_traces,
        binding_receipts,
        assertion_names,
        worker_protocol_observations,
        worker_errors,
        state: Stage2NormalizedStateEvidence {
            final_state_sha256: final_state_sha256.clone(),
            replay_state_sha256: final_state_sha256,
            snapshot_sha256,
            semantic_trace_sha256s,
            normalized_snapshot_size_bytes,
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawTranscriptStream {
    ParentRequest,
    WorkerResponse,
    WorkerStderr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTranscriptLine {
    worker: String,
    pid: u32,
    sequence: u64,
    stream: RawTranscriptStream,
    line: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkerError {
    code: Stage2WorkerErrorCode,
    message: String,
    retryable: Option<bool>,
    provider_kind: Option<Stage2ProviderFailureKind>,
    adapter_kind: Option<Stage2AdapterFailureKind>,
    workload_kind: Option<Stage2WorkloadFailureKind>,
}

struct PendingWorkerProtocolObservation {
    observation: Stage2NormalizedWorkerProtocolObservation,
    response: Option<Stage2NormalizedWorkerResponse>,
    permits_no_response: bool,
    forbids_response: bool,
}

pub(crate) fn read_worker_protocol_observations(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
) -> Result<Vec<Stage2NormalizedWorkerProtocolObservation>, Stage2NormalizationError> {
    validate_canonical_raw_artifacts(case)?;
    let mut observations = Vec::new();
    for (file_name, role) in [
        ("source.jsonl", Stage1TraceRole::Source),
        ("destination.jsonl", Stage1TraceRole::Destination),
    ] {
        let uri = canonical_raw_uri(&case.case_id, file_name);
        let reference =
            case.artifacts.raw_execution.iter().find(|reference| reference.uri == uri).ok_or_else(
                || {
                    error(
                        "missing-stage2-worker-transcript",
                        format!("{} has no {file_name}", case.case_id),
                    )
                },
            )?;
        let bytes = read_artifact_bytes(artifacts, reference)?;
        observations.extend(project_worker_protocol_observations(
            &case.case_id,
            file_name,
            role,
            bytes,
        )?);
    }
    Ok(observations)
}

pub(crate) fn project_worker_protocol_observations(
    case_id: &str,
    file_name: &str,
    role: Stage1TraceRole,
    bytes: &[u8],
) -> Result<Vec<Stage2NormalizedWorkerProtocolObservation>, Stage2NormalizationError> {
    let mut pending = Vec::<PendingWorkerProtocolObservation>::new();
    let mut requests = BTreeMap::<(String, String), usize>::new();
    let mut worker_processes = BTreeMap::<String, (u32, u64, u64)>::new();
    let mut command_occurrences = BTreeMap::<(String, Stage2WorkerCommandKind), u64>::new();
    for (line_index, line) in
        bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
    {
        let transcript: RawTranscriptLine = serde_json::from_slice(line).map_err(|source| {
            error(
                "invalid-stage2-worker-transcript",
                format!("{case_id} {file_name} line {}: {source}", line_index + 1),
            )
        })?;
        let worker_scope = normalized_worker_scope(case_id, file_name, &transcript.worker)?;
        if transcript.pid == 0 || transcript.sequence == 0 {
            return Err(error(
                "invalid-stage2-worker-transcript",
                format!("{case_id} {file_name} contains an invalid envelope"),
            ));
        }
        let worker_facts =
            worker_processes.entry(worker_scope.clone()).or_insert((transcript.pid, 0, 0));
        if worker_facts.0 != transcript.pid
            || worker_facts.1.checked_add(1) != Some(transcript.sequence)
        {
            return Err(error(
                "invalid-stage2-worker-transcript-order",
                format!(
                    "{case_id} {file_name} worker {worker_scope} changed pid or used a non-contiguous sequence"
                ),
            ));
        }
        worker_facts.1 = transcript.sequence;
        if transcript.stream == RawTranscriptStream::WorkerStderr {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&transcript.line).map_err(|source| {
                error(
                    "invalid-stage2-worker-protocol-json",
                    format!("{case_id} {file_name}: {source}"),
                )
            })?;
        let request_id =
            value.get("id").and_then(serde_json::Value::as_str).unwrap_or_default().to_owned();
        let key = (worker_scope.clone(), request_id);
        match transcript.stream {
            RawTranscriptStream::ParentRequest => {
                let ProtocolRequestProjection {
                    kind: command,
                    permits_no_response,
                    forbids_response,
                } = project_request_command(&value).map_err(|detail| {
                    error(
                        "invalid-stage2-worker-protocol-request",
                        format!("{case_id} {file_name}: {detail}"),
                    )
                })?;
                if requests.contains_key(&key) {
                    return Err(error(
                        "duplicate-stage2-worker-protocol-request",
                        format!("{case_id} {file_name} repeats a worker request"),
                    ));
                }
                worker_facts.2 = checked_increment(
                    worker_facts.2,
                    "stage2-worker-request-count-overflow",
                    case_id,
                    file_name,
                )?;
                let occurrence =
                    command_occurrences.entry((worker_scope.clone(), command)).or_default();
                *occurrence = checked_increment(
                    *occurrence,
                    "stage2-worker-command-count-overflow",
                    case_id,
                    file_name,
                )?;
                let observation_index = u64::try_from(pending.len())
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            "stage2-worker-observation-count-overflow",
                            format!("{case_id} {file_name} has too many observations"),
                        )
                    })?;
                requests.insert(key, pending.len());
                pending.push(PendingWorkerProtocolObservation {
                    observation: Stage2NormalizedWorkerProtocolObservation {
                        role,
                        worker_scope,
                        observation_index,
                        worker_request_index: worker_facts.2,
                        command_occurrence: *occurrence,
                        command,
                        response: Stage2NormalizedWorkerResponse::NoResponse,
                    },
                    response: None,
                    permits_no_response,
                    forbids_response,
                });
            }
            RawTranscriptStream::WorkerResponse => {
                let response_projection = project_response(&value).map_err(|detail| {
                    error(
                        "invalid-stage2-worker-protocol-response",
                        format!("{case_id} {file_name}: {detail}"),
                    )
                })?;
                let response = match response_projection {
                    ProtocolResponseProjection::Success(result) => {
                        Stage2NormalizedWorkerResponse::Success { result }
                    }
                    ProtocolResponseProjection::Error => Stage2NormalizedWorkerResponse::Error,
                };
                let index = requests.get(&key).copied().ok_or_else(|| {
                    error(
                        "unmatched-stage2-worker-protocol-response",
                        format!("{case_id} {file_name} response has no preceding request"),
                    )
                })?;
                let observation = &mut pending[index];
                if observation.forbids_response {
                    return Err(error(
                        "forbidden-stage2-worker-protocol-response",
                        format!(
                            "{case_id} {file_name} immediate crash request unexpectedly has a response"
                        ),
                    ));
                }
                if let ProtocolResponseProjection::Success(result) = response_projection
                    && !success_result_matches(observation.observation.command, result)
                {
                    return Err(error(
                        "incompatible-stage2-worker-protocol-result",
                        format!(
                            "{case_id} {file_name} result {result:?} is impossible for {:?}",
                            observation.observation.command
                        ),
                    ));
                }
                if observation.response.replace(response).is_some() {
                    return Err(error(
                        "duplicate-stage2-worker-protocol-response",
                        format!("{case_id} {file_name} repeats a worker response"),
                    ));
                }
            }
            RawTranscriptStream::WorkerStderr => unreachable!(),
        }
    }
    pending
        .into_iter()
        .map(|mut pending| {
            match pending.response {
                Some(response) => pending.observation.response = response,
                None if pending.permits_no_response => {}
                None => {
                    return Err(error(
                        "missing-stage2-worker-protocol-response",
                        format!(
                            "{case_id} {file_name} {:?} request has no response",
                            pending.observation.command
                        ),
                    ));
                }
            }
            Ok(pending.observation)
        })
        .collect()
}

fn normalized_worker_scope(
    case_id: &str,
    file_name: &str,
    worker: &str,
) -> Result<String, Stage2NormalizationError> {
    let prefix = format!("{case_id}-");
    let scope = worker.strip_prefix(&prefix).unwrap_or_default();
    if scope.is_empty()
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(error(
            "invalid-stage2-worker-scope",
            format!("{case_id} {file_name} has invalid worker identity {worker:?}"),
        ));
    }
    Ok(scope.to_owned())
}

fn checked_increment(
    value: u64,
    code: &'static str,
    case_id: &str,
    file_name: &str,
) -> Result<u64, Stage2NormalizationError> {
    value.checked_add(1).ok_or_else(|| {
        error(code, format!("{case_id} {file_name} has too many protocol observations"))
    })
}

pub(crate) fn read_worker_errors(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
) -> Result<Vec<Stage2NormalizedWorkerError>, Stage2NormalizationError> {
    validate_canonical_raw_artifacts(case)?;
    let mut errors = Vec::new();
    for (file_name, role) in [
        ("source.jsonl", Stage1TraceRole::Source),
        ("destination.jsonl", Stage1TraceRole::Destination),
    ] {
        let reference = case
            .artifacts
            .raw_execution
            .iter()
            .find(|reference| reference.uri == canonical_raw_uri(&case.case_id, file_name))
            .ok_or_else(|| {
                error(
                    "missing-stage2-worker-transcript",
                    format!("{} has no {file_name}", case.case_id),
                )
            })?;
        let bytes = read_artifact_bytes(artifacts, reference)?;
        let mut observation_index = 0_u64;
        for (line_index, line) in
            bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
        {
            let transcript: RawTranscriptLine = serde_json::from_slice(line).map_err(|source| {
                error(
                    "invalid-stage2-worker-transcript",
                    format!("{} {file_name} line {}: {source}", case.case_id, line_index + 1),
                )
            })?;
            if transcript.worker.is_empty() || transcript.pid == 0 || transcript.sequence == 0 {
                return Err(error(
                    "invalid-stage2-worker-transcript",
                    format!("{} {file_name} contains an invalid envelope", case.case_id),
                ));
            }
            if transcript.stream != RawTranscriptStream::WorkerResponse {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(&transcript.line).map_err(|source| {
                    error(
                        "invalid-stage2-worker-protocol-json",
                        format!("{} {file_name}: {source}", case.case_id),
                    )
                })?;
            if value.pointer("/outcome/status").and_then(serde_json::Value::as_str) != Some("error")
            {
                continue;
            }
            let raw = value.pointer("/outcome/error").cloned().ok_or_else(|| {
                error(
                    "invalid-stage2-worker-error",
                    format!("{} {file_name} error response has no typed error", case.case_id),
                )
            })?;
            let raw: RawWorkerError = serde_json::from_value(raw).map_err(|source| {
                error(
                    "invalid-stage2-worker-error",
                    format!("{} {file_name}: {source}", case.case_id),
                )
            })?;
            if raw.message.trim().is_empty() {
                return Err(error(
                    "invalid-stage2-worker-error",
                    format!("{} {file_name} contains an empty diagnostic", case.case_id),
                ));
            }
            observation_index = observation_index.checked_add(1).ok_or_else(|| {
                error(
                    "stage2-worker-error-count-overflow",
                    format!("{} {file_name} has too many errors", case.case_id),
                )
            })?;
            errors.push(Stage2NormalizedWorkerError {
                role,
                observation_index,
                code: raw.code,
                retryable: raw.retryable,
                provider_kind: raw.provider_kind,
                adapter_kind: raw.adapter_kind,
                workload_kind: raw.workload_kind,
            });
        }
    }
    Ok(errors)
}

fn select_final_trace<'a>(
    case: &Stage1CaseEvidence,
    traces: &'a [Stage1SemanticTraceArtifact],
) -> Result<&'a Stage1SemanticTraceArtifact, Stage2NormalizationError> {
    let preferred = match crate::stage1_expected_ownership(case.outcome) {
        crate::Stage1ExpectedOwnership::SourceRetained => Stage1TraceRole::Source,
        crate::Stage1ExpectedOwnership::DestinationCommitted
        | crate::Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            Stage1TraceRole::Destination
        }
    };
    traces.iter().find(|trace| trace.role == preferred).ok_or_else(|| {
        error(
            "missing-stage2-final-semantic-trace",
            format!("{} has no {preferred:?} final trace", case.case_id),
        )
    })
}

fn read_assertion_names(
    case: &Stage1CaseEvidence,
    artifacts: &VerifiedStage1Artifacts,
) -> Result<Vec<String>, Stage2NormalizationError> {
    validate_canonical_raw_artifacts(case)?;
    let expected = canonical_raw_uri(&case.case_id, "assertions.jsonl");
    let reference = case
        .artifacts
        .raw_execution
        .iter()
        .find(|reference| reference.uri == expected)
        .ok_or_else(|| {
            error(
                "missing-stage2-assertion-artifact",
                format!("{} has no assertions.jsonl", case.case_id),
            )
        })?;
    let bytes = read_artifact_bytes(artifacts, reference)?;
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();
    for (index, line) in
        bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
    {
        let value: serde_json::Value = serde_json::from_slice(line).map_err(|source| {
            error(
                "invalid-stage2-assertion-artifact",
                format!("{} assertion line {}: {source}", case.case_id, index + 1),
            )
        })?;
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                error(
                    "invalid-stage2-assertion-artifact",
                    format!("{} assertion line {} has no name", case.case_id, index + 1),
                )
            })?;
        if !seen.insert(name.to_owned()) {
            return Err(error(
                "duplicate-stage2-assertion-name",
                format!("{} repeats assertion {name}", case.case_id),
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

pub(crate) fn validate_canonical_raw_artifacts(
    case: &Stage1CaseEvidence,
) -> Result<(), Stage2NormalizationError> {
    let mut expected = vec![
        canonical_raw_uri(&case.case_id, "source.jsonl"),
        canonical_raw_uri(&case.case_id, "destination.jsonl"),
        canonical_raw_uri(&case.case_id, "assertions.jsonl"),
    ];
    if case.case_id == "performance-observations" {
        expected.push(canonical_raw_uri(&case.case_id, "performance.json"));
    }
    let observed = case
        .artifacts
        .raw_execution
        .iter()
        .map(|reference| reference.uri.as_str())
        .collect::<Vec<_>>();
    if observed.len() != expected.len()
        || observed.iter().zip(&expected).any(|(observed, expected)| *observed != expected)
    {
        return Err(error(
            "noncanonical-stage2-raw-artifact-set",
            format!("{} raw artifacts must be exactly {}", case.case_id, expected.join(", ")),
        ));
    }
    Ok(())
}

fn canonical_raw_uri(case_id: &str, file_name: &str) -> String {
    format!("cases/{case_id}/raw/{file_name}")
}

fn read_captured_typed_artifact<T>(
    artifacts: &VerifiedStage1Artifacts,
    reference: &Stage1ArtifactReference,
) -> Result<T, Stage2NormalizationError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = read_artifact_bytes(artifacts, reference)?;
    decode_typed_artifact(bytes, &reference.uri)
}

#[cfg(test)]
pub(crate) fn read_typed_artifact<T>(
    artifact_root: &Path,
    uri: &str,
) -> Result<T, Stage2NormalizationError>
where
    T: for<'de> Deserialize<'de>,
{
    let root = crate::artifact_io::SecureArtifactRoot::open(artifact_root)
        .map_err(|source| error("invalid-stage2-normalizer-artifact-root", source.to_string()))?;
    let bytes = root
        .read_regular(uri)
        .map_err(|source| error("unreadable-stage2-normalizer-artifact", source.to_string()))?;
    decode_typed_artifact(&bytes, uri)
}

fn decode_typed_artifact<T>(bytes: &[u8], uri: &str) -> Result<T, Stage2NormalizationError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut ignored = Vec::new();
    let value = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored.push(path.to_string());
    })
    .map_err(|source| {
        error(
            "invalid-stage2-normalizer-input",
            format!("cannot decode typed artifact {uri}: {source}"),
        )
    })?;
    deserializer.end().map_err(|source| {
        error(
            "invalid-stage2-normalizer-input",
            format!("typed artifact {uri} has trailing data: {source}"),
        )
    })?;
    if !ignored.is_empty() {
        return Err(error(
            "unknown-stage2-normalizer-input-field",
            format!("typed artifact {uri} contains ignored fields: {}", ignored.join(", ")),
        ));
    }
    Ok(value)
}

fn read_artifact_bytes<'a>(
    artifacts: &'a VerifiedStage1Artifacts,
    reference: &Stage1ArtifactReference,
) -> Result<&'a [u8], Stage2NormalizationError> {
    artifacts.bytes(&reference.uri).ok_or_else(|| {
        error(
            "missing-stage2-captured-artifact",
            format!("artifact {} was not retained in the stable Stage 1 view", reference.uri),
        )
    })
}

pub(crate) fn normalize_trace(
    mut trace: Stage1SemanticTraceArtifact,
) -> Stage1SemanticTraceArtifact {
    normalize_state(&mut trace.base_state, trace.role);
    for entry in &mut trace.entries {
        entry.input_state = Digest::ZERO;
        entry.output_state = Digest::ZERO;
        normalize_event(&mut entry.event.kind, trace.role);
    }
    normalize_state(&mut trace.final_state, trace.role);
    trace
}

fn normalize_snapshot(mut snapshot: SnapshotEnvelope) -> SnapshotEnvelope {
    snapshot.integrity = Digest::ZERO;
    normalize_snapshot_record(&mut snapshot.body.snapshot);
    normalize_timer_disposition(&mut snapshot.body.timer);
    for operation in &mut snapshot.body.operations {
        normalize_operation(operation, Stage1TraceRole::Source);
    }
    snapshot
}

fn normalize_state(state: &mut CanonicalState, role: Stage1TraceRole) {
    normalize_timer_status(&mut state.timer.status);
    for operation in &mut state.operations {
        normalize_operation(operation, role);
    }
    if let Some(snapshot) = &mut state.exported_snapshot {
        normalize_snapshot_record(snapshot);
    }
    if let Some(prepared) = &mut state.prepared_destination {
        normalize_prepared(prepared);
    }
    if let Some(cleanup) = &mut state.preparation_cleanup {
        normalize_cleanup(cleanup);
    }
    for evidence in &mut state.evidence {
        normalize_evidence(evidence);
    }
}

fn normalize_event(event: &mut EventKind, role: Stage1TraceRole) {
    match event {
        EventKind::EffectPrepared { request } => normalize_request(request, role),
        EventKind::EffectResolved { outcome, .. } | EventKind::EffectReconciled { outcome, .. } => {
            normalize_outcome(outcome, role)
        }
        EventKind::OperationCleaned { evidence, .. }
        | EventKind::TimerCompleted { evidence, .. } => normalize_evidence(evidence),
        EventKind::Frozen { timer, .. } => normalize_timer_disposition(timer),
        EventKind::SnapshotExported { snapshot } => normalize_snapshot_record(snapshot),
        EventKind::DestinationPrepared { prepared } => normalize_prepared(prepared),
        EventKind::HandoffCommitted { outcome, .. } => normalize_outcome(outcome, role),
        EventKind::HandoffAborted { evidence } => normalize_optional_evidence(evidence),
        EventKind::PreparationCleaned { cleanup } => normalize_cleanup(cleanup),
        EventKind::JointDestinationResumed { activation_record_digest } => {
            *activation_record_digest = Digest::ZERO;
        }
        EventKind::Activated { .. }
        | EventKind::AuthorityAttenuated { .. }
        | EventKind::AuthorityRevoked { .. }
        | EventKind::HandoffStarted
        | EventKind::SourceResumed
        | EventKind::DestinationResumed => {}
    }
}

fn normalize_operation(operation: &mut OperationRecord, role: Stage1TraceRole) {
    normalize_request(&mut operation.request, role);
    if let Some(outcome) = &mut operation.outcome {
        normalize_outcome(outcome, role);
    }
}

fn normalize_request(request: &mut EffectRequest, role: Stage1TraceRole) {
    request.request_digest = Digest::ZERO;
    if role == Stage1TraceRole::Destination
        && let contract_core::EffectKind::TimerArm { remaining } = &mut request.kind
    {
        normalize_duration(remaining);
    }
}

fn normalize_outcome(outcome: &mut EffectOutcome, role: Stage1TraceRole) {
    match outcome {
        EffectOutcome::Succeeded { result, evidence } => {
            if role == Stage1TraceRole::Destination
                && let EffectResult::TimerArmed { remaining } = result
            {
                normalize_duration(remaining);
            }
            if let EffectResult::LeaseAdvanced { source_fence, .. } = result {
                normalize_evidence(source_fence);
            }
            normalize_evidence(evidence);
        }
        EffectOutcome::Failed(EffectFailure { evidence, .. })
        | EffectOutcome::Cancelled { evidence }
        | EffectOutcome::Unsupported { evidence }
        | EffectOutcome::Indeterminate { evidence } => normalize_optional_evidence(evidence),
    }
}

fn normalize_timer_status(status: &mut TimerStatus) {
    match status {
        TimerStatus::Armed { remaining } => normalize_duration(remaining),
        TimerStatus::Frozen(disposition) => normalize_timer_disposition(disposition),
        TimerStatus::Idle
        | TimerStatus::Completed
        | TimerStatus::Cancelled
        | TimerStatus::Cleaned => {}
    }
}

fn normalize_timer_disposition(disposition: &mut TimerDisposition) {
    if let TimerDisposition::Pending { remaining, .. } = disposition {
        normalize_duration(remaining);
    }
}

fn normalize_duration(duration: &mut LogicalDurationNanos) {
    duration.0 = u64::from(duration.0 > 0);
}

fn normalize_snapshot_record(snapshot: &mut contract_core::SnapshotRecord) {
    normalize_evidence(&mut snapshot.evidence);
}

fn normalize_prepared(prepared: &mut PreparedDestination) {
    for binding in &mut prepared.bindings {
        normalize_binding_receipt_in_place(binding);
    }
}

fn normalize_cleanup(cleanup: &mut PreparationCleanup) {
    normalize_optional_evidence(&mut cleanup.evidence);
}

fn normalize_binding_receipt(mut receipt: BindingReceipt) -> BindingReceipt {
    normalize_binding_receipt_in_place(&mut receipt);
    receipt
}

fn normalize_binding_receipt_in_place(receipt: &mut BindingReceipt) {
    normalize_evidence(&mut receipt.evidence);
}

fn normalize_optional_evidence(evidence: &mut Option<EvidenceRef>) {
    if let Some(evidence) = evidence {
        normalize_evidence(evidence);
    }
}

fn normalize_evidence(evidence: &mut EvidenceRef) {
    evidence.digest = Digest::ZERO;
}

pub fn canonical_stage2_json_bytes<T>(value: &T) -> Result<Vec<u8>, Stage2NormalizationError>
where
    T: Serialize,
{
    serde_json::to_vec(value).map_err(|source| {
        error(
            "stage2-canonical-json-encoding-failed",
            format!("cannot encode canonical Stage 2 JSON: {source}"),
        )
    })
}

pub fn canonical_stage2_sha256<T>(value: &T) -> Result<String, Stage2NormalizationError>
where
    T: Serialize,
{
    canonical_stage2_json_bytes(value).map(|bytes| sha256_hex(&bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> Stage2NormalizationError {
    Stage2NormalizationError { code: code.into(), detail: detail.into() }
}

#[cfg(test)]
#[path = "stage2_worker_observation_tests.rs"]
mod worker_observation_tests;
