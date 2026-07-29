//! Verdict-free wire types for externally observed regular-file executions.
//!
//! This crate deliberately contains no semantic registry, reducer, normalizer,
//! or correctness predicate. Its fixed case catalog is only a wire-level
//! coverage contract. Producers may use these types to serialize raw
//! observations. The independent oracle implements its own wire decoder from
//! the written JSON contract and does not depend on this crate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const REGULAR_FILE_CONTROL_OBSERVATION_FILE: &str =
    "observations/regular-file-observation-control-v2.json";
pub const REGULAR_FILE_CANDIDATE_OBSERVATION_FILE: &str =
    "observations/regular-file-observation-candidate-v2.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationSchemaVersion {
    #[serde(rename = "regular-file-observation-v2")]
    V2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularFileObservationBundle {
    pub schema_version: ObservationSchemaVersion,
    pub bundle_id: String,
    pub route: RouteObservation,
    pub cases: Vec<RegularFileCaseObservation>,
}

impl RegularFileObservationBundle {
    pub fn new(
        bundle_id: impl Into<String>,
        route: RouteObservation,
        cases: Vec<RegularFileCaseObservation>,
    ) -> Self {
        Self {
            schema_version: ObservationSchemaVersion::V2,
            bundle_id: bundle_id.into(),
            route,
            cases,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingCoverage {
    CompleteRegistry,
    AnySubset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordingValidationFinding {
    pub code: &'static str,
    pub detail: String,
}

/// Performs producer-side structural checks before a raw bundle is published.
///
/// The independent oracle intentionally reimplements all checks and never
/// calls this function.
pub fn validate_recording_bundle(
    bundle: &RegularFileObservationBundle,
    coverage: RecordingCoverage,
) -> Result<(), Vec<RecordingValidationFinding>> {
    let mut findings = Vec::new();
    if bundle.bundle_id.is_empty() {
        recording_finding(&mut findings, "empty-bundle-id", "bundle_id must not be empty");
    }
    if bundle.route.source.instance_id.is_empty()
        || bundle.route.source.runtime.is_empty()
        || bundle.route.source.host_id.is_empty()
        || bundle.route.source.isa.is_empty()
    {
        recording_finding(
            &mut findings,
            "incomplete-source-endpoint",
            "source endpoint identity must be complete",
        );
    }
    if bundle.route.mode != RouteMode::UninterruptedControl && bundle.route.destination.is_none() {
        recording_finding(
            &mut findings,
            "missing-destination-endpoint",
            "non-control routes require a destination endpoint",
        );
    }
    if matches!(bundle.route.mode, RouteMode::CarrierOnly | RouteMode::VisaPlusCarrier)
        && bundle.route.carrier.is_none()
    {
        recording_finding(
            &mut findings,
            "missing-carrier-identity",
            "carrier routes require a carrier identity",
        );
    }

    let mut seen = BTreeSet::new();
    for case in &bundle.cases {
        if !seen.insert(case.case_id) {
            recording_finding(
                &mut findings,
                "duplicate-case",
                format!("case {:?} occurs more than once", case.case_id),
            );
        }
        if case.observation_id.is_empty()
            || case.schedule_id.is_empty()
            || case.subject.resource_id.is_empty()
            || case.subject.initial_path.is_empty()
        {
            recording_finding(
                &mut findings,
                "incomplete-case-identity",
                format!("case {:?} has incomplete identity fields", case.case_id),
            );
        }
        if !is_lower_hex_sha256(&case.schedule_sha256) {
            recording_finding(
                &mut findings,
                "invalid-schedule-digest",
                format!("case {:?} schedule_sha256 is not lowercase SHA-256", case.case_id),
            );
        }
        if case.events.is_empty() {
            recording_finding(
                &mut findings,
                "empty-event-stream",
                format!("case {:?} has no raw events", case.case_id),
            );
        }
        for (expected, event) in case.events.iter().enumerate() {
            if event.sequence != expected as u64 {
                recording_finding(
                    &mut findings,
                    "noncontiguous-event-sequence",
                    format!(
                        "case {:?} expected event sequence {expected}, observed {}",
                        case.case_id, event.sequence
                    ),
                );
            }
        }
    }
    if coverage == RecordingCoverage::CompleteRegistry
        && (seen.len() != RegularFileCase::ALL.len()
            || RegularFileCase::ALL.iter().any(|case| !seen.contains(case)))
    {
        recording_finding(
            &mut findings,
            "incomplete-case-registry",
            "complete recording must contain each of the 12 cases exactly once",
        );
    }
    if findings.is_empty() { Ok(()) } else { Err(findings) }
}

fn recording_finding(
    findings: &mut Vec<RecordingValidationFinding>,
    code: &'static str,
    detail: impl Into<String>,
) {
    findings.push(RecordingValidationFinding { code, detail: detail.into() });
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteObservation {
    pub mode: RouteMode,
    pub source: EndpointObservation,
    pub destination: Option<EndpointObservation>,
    pub execution_boundary: String,
    pub carrier: Option<CarrierIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    UninterruptedControl,
    Handoff,
    Restart,
    CarrierOnly,
    NaiveReopen,
    VisaPlusCarrier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub instance_id: String,
    pub runtime: String,
    pub runtime_version: String,
    pub host_id: String,
    pub operating_system: String,
    pub isa: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularFileCaseObservation {
    pub observation_id: String,
    pub case_id: RegularFileCase,
    pub schedule_id: String,
    pub schedule_sha256: String,
    pub subject: ResourceSubject,
    pub events: Vec<ObservedEvent>,
}

impl RegularFileCaseObservation {
    pub fn new(
        observation_id: impl Into<String>,
        case_id: RegularFileCase,
        schedule_id: impl Into<String>,
        schedule_sha256: impl Into<String>,
        subject: ResourceSubject,
        events: Vec<ObservedEvent>,
    ) -> Self {
        Self {
            observation_id: observation_id.into(),
            case_id,
            schedule_id: schedule_id.into(),
            schedule_sha256: schedule_sha256.into(),
            subject,
            events,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegularFileCase {
    ReadWriteOffset,
    AppendContinuity,
    TruncateVersion,
    RenameObjectIdentity,
    ReplacementRejected,
    ExternalMutationRejected,
    LockConflict,
    DurabilityReconciled,
    StaleSourceFenced,
    CleanupIdempotent,
    IndeterminateWriteBlocksHandoff,
    DestinationReauthorizationDenied,
}

impl RegularFileCase {
    pub const ALL: [Self; 12] = [
        Self::ReadWriteOffset,
        Self::AppendContinuity,
        Self::TruncateVersion,
        Self::RenameObjectIdentity,
        Self::ReplacementRejected,
        Self::ExternalMutationRejected,
        Self::LockConflict,
        Self::DurabilityReconciled,
        Self::StaleSourceFenced,
        Self::CleanupIdempotent,
        Self::IndeterminateWriteBlocksHandoff,
        Self::DestinationReauthorizationDenied,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSubject {
    pub resource_id: String,
    pub initial_path: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEvent {
    pub sequence: u64,
    pub phase: ObservationPhase,
    pub actor: ObservationActor,
    pub body: RawObservationEvent,
}

impl ObservedEvent {
    pub const fn new(
        sequence: u64,
        phase: ObservationPhase,
        actor: ObservationActor,
        body: RawObservationEvent,
    ) -> Self {
        Self { sequence, phase, actor, body }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationPhase {
    Setup,
    SourceExecution,
    CarrierCapture,
    Quiesce,
    Transfer,
    DestinationPrepare,
    CarrierRestore,
    DestinationExecution,
    Cleanup,
    FinalObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationActor {
    ExternalObserver,
    Controller,
    SourceRuntime,
    DestinationRuntime,
    Provider,
    Carrier,
    CompetingProcess,
    ExternalMutator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawObservationEvent {
    FileProbe {
        path: Vec<u8>,
        entry: FileEntryObservation,
    },
    OperationCall {
        operation_id: String,
        attempt: u32,
        idempotency_key: Option<String>,
        operation: RegularFileOperationObservation,
        result: OperationCallResult,
    },
    OsCall {
        action: OsAction,
        result: GenericCallResult,
    },
    ProtocolCall {
        action: ProtocolAction,
        result: GenericCallResult,
    },
    ProfileStateProbe {
        state: ProfileStateObservation,
    },
    CoordinatorStateProbe {
        state: CoordinatorStateObservation,
    },
    LeaseProbe {
        resource_id: String,
        owner: Option<String>,
        epoch: u64,
    },
    LeaseCheck {
        resource_id: String,
        owner: String,
        epoch: u64,
        result: GenericCallResult,
    },
    OperationLedgerProbe {
        records: Vec<OperationRecordObservation>,
    },
    DestinationBindingProbe {
        bindings: Vec<DestinationBindingObservation>,
    },
    ClientOutput {
        channel: OutputChannel,
        bytes: Vec<u8>,
    },
    ProcessExit {
        code: Option<i32>,
        signal: Option<i32>,
    },
    CarrierCall {
        action: CarrierAction,
        result: CarrierCallResult,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileEntryObservation {
    Missing,
    File { bytes: Vec<u8>, size: u64, sha256: String, metadata: FileMetadataObservation },
    ProbeError { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadataObservation {
    pub device: u64,
    pub inode: u64,
    pub generation: Option<u64>,
    pub birth_time_unix_ns: Option<i64>,
    pub mode: u32,
    pub link_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegularFileOperationObservation {
    Read { max_bytes: u32 },
    Write { bytes: Vec<u8>, durability: FileDurabilityObservation },
    Append { bytes: Vec<u8>, durability: FileDurabilityObservation },
    Truncate { size: u64, durability: FileDurabilityObservation },
    Rename { relative_path: Vec<u8> },
    Sync { durability: FileDurabilityObservation },
    AcquireLock,
    ReleaseLock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationCallResult {
    Returned { output: RegularFileOutputObservation },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegularFileOutputObservation {
    Read {
        bytes: Vec<u8>,
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest: Vec<u8>,
    },
    Mutated {
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest: Vec<u8>,
        durable_through: FileDurabilityObservation,
    },
    Renamed {
        relative_path: Vec<u8>,
        version: u64,
        content_digest: Vec<u8>,
    },
    Synced {
        version: u64,
        durable_through: FileDurabilityObservation,
    },
    Lock {
        state: FileLockStateObservation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDurabilityObservation {
    Visible,
    Data,
    DataAndMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileLockStateObservation {
    Unlocked,
    Held,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawErrorObservation {
    pub domain: ErrorDomain,
    pub code: ErrorCode,
    pub errno: Option<i32>,
    pub retryable: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDomain {
    OperatingSystem,
    RegularFileProfile,
    Provider,
    Runtime,
    Carrier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unavailable,
    Conflict,
    Indeterminate,
    SafePointUnavailable,
    ProviderDenied,
    StaleEpoch,
    IndeterminateEffect,
    WouldBlock,
    NotFound,
    AlreadyExists,
    Invalid,
    Io,
    Unsupported,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsAction {
    WriteWhole { path: Vec<u8>, bytes: Vec<u8> },
    RenameNoReplace { source: Vec<u8>, destination: Vec<u8> },
    ReplacePath { source: Vec<u8>, destination: Vec<u8> },
    TryExclusiveLock { path: Vec<u8> },
    Unlock { path: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenericCallResult {
    Returned { bytes: Vec<u8> },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolAction {
    BeginQuiesce { command_id: String, authority_id: String },
    PrepareSafePoint { safe_point_id: String },
    FreezeRuntime { safe_point_id: String },
    CommitSafePoint { command_id: String, safe_point_id: String },
    ExportSnapshot { command_id: String, snapshot_id: String },
    PrepareDestination { command_id: String },
    CommitHandoff { command_id: String, operation_id: String },
    RestoreRuntime { snapshot_id: String },
    ResumeDestination { command_id: String },
    CleanupOperation { command_id: String, operation_id: String, evidence_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStateObservation {
    pub relative_path: Vec<u8>,
    pub object_binding: Vec<u8>,
    pub logical_offset: u64,
    pub version: u64,
    pub size: u64,
    pub content_digest: Vec<u8>,
    pub durable_through: FileDurabilityObservation,
    pub lock_state: FileLockStateObservation,
    pub disposition: ContinuityDispositionObservation,
    pub last_operation: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityDispositionObservation {
    Revalidate,
    Reconnect,
    Replay,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStateObservation {
    pub phase: CoordinatorPhaseObservation,
    pub activation: ActivationObservation,
    pub owner: Option<String>,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorPhaseObservation {
    Inactive,
    Active,
    Quiescing,
    Frozen,
    Exported,
    Restoring,
    PreparedDestination,
    Committed,
    ResumedDestination,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationObservation {
    Inactive,
    Source,
    SourceFenced,
    DestinationPrepared,
    DestinationActive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecordObservation {
    pub operation_id: String,
    pub request_digest: Vec<u8>,
    pub outcome: OperationOutcomeObservation,
    pub cleanup: CleanupObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationOutcomeObservation {
    Pending,
    Applied { result_digest: Vec<u8> },
    Indeterminate,
    Rejected { error: RawErrorObservation },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupObservation {
    Required,
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationBindingObservation {
    pub resource_id: String,
    pub state: DestinationBindingState,
    pub owner: Option<String>,
    pub epoch: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationBindingState {
    Absent,
    Prepared,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputChannel {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierAction {
    Capture { capture_id: String },
    Restore { capture_id: String, payload: CarrierPayloadObservation },
    Resume,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierCallResult {
    Captured { payload: CarrierPayloadObservation },
    Returned { bytes: Vec<u8> },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "storage", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierPayloadObservation {
    Inline { bytes: Vec<u8>, sha256: String },
    Artifact { reference: ArtifactReferenceObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReferenceObservation {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const FORBIDDEN_DECISION_KEYS: [&str; 8] = [
        "verdict",
        "passed",
        "expected",
        "assertions",
        "normalized",
        "terminal",
        "semantic_projection",
        "producer_claim",
    ];

    fn complete_bundle() -> RegularFileObservationBundle {
        let cases = RegularFileCase::ALL
            .into_iter()
            .enumerate()
            .map(|(index, case_id)| {
                RegularFileCaseObservation::new(
                    format!("observation-{index}"),
                    case_id,
                    format!("schedule-{index}"),
                    "0".repeat(64),
                    ResourceSubject {
                        resource_id: "file:1".to_owned(),
                        initial_path: b"data.bin".to_vec(),
                    },
                    vec![ObservedEvent::new(
                        0,
                        ObservationPhase::FinalObservation,
                        ObservationActor::ExternalObserver,
                        RawObservationEvent::ProcessExit { code: Some(0), signal: None },
                    )],
                )
            })
            .collect();
        RegularFileObservationBundle::new(
            "complete-wire-bundle",
            RouteObservation {
                mode: RouteMode::UninterruptedControl,
                source: EndpointObservation {
                    instance_id: "source-1".to_owned(),
                    runtime: "test-runtime".to_owned(),
                    runtime_version: "1".to_owned(),
                    host_id: "host-1".to_owned(),
                    operating_system: "linux".to_owned(),
                    isa: "x86_64".to_owned(),
                },
                destination: None,
                execution_boundary: "same-process".to_owned(),
                carrier: None,
            },
            cases,
        )
    }

    fn assert_no_decision_keys(value: &Value) {
        match value {
            Value::Object(object) => {
                for key in object.keys() {
                    assert!(
                        !FORBIDDEN_DECISION_KEYS.contains(&key.as_str()),
                        "serialized observation contains forbidden producer decision key {key:?}"
                    );
                }
                object.values().for_each(assert_no_decision_keys);
            }
            Value::Array(values) => values.iter().for_each(assert_no_decision_keys),
            _ => {}
        }
    }

    #[test]
    fn complete_wire_catalog_is_structurally_valid_and_verdict_free() {
        let bundle = complete_bundle();
        validate_recording_bundle(&bundle, RecordingCoverage::CompleteRegistry)
            .expect("the exact 12-case wire catalog must be structurally valid");
        let value = serde_json::to_value(bundle).expect("bundle serializes");
        assert_no_decision_keys(&value);
    }

    #[test]
    fn unknown_producer_verdict_is_rejected() {
        let mut value = serde_json::to_value(complete_bundle()).expect("bundle serializes");
        value
            .as_object_mut()
            .expect("bundle is an object")
            .insert("verdict".to_owned(), Value::Bool(true));
        let error = serde_json::from_value::<RegularFileObservationBundle>(value)
            .expect_err("strict observation decoding must reject a producer verdict");
        assert!(error.to_string().contains("unknown field `verdict`"));
    }

    #[test]
    fn wire_case_names_are_exact_and_stable() {
        let names = RegularFileCase::ALL
            .into_iter()
            .map(|case| serde_json::to_value(case).expect("case serializes"))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "read-write-offset",
                "append-continuity",
                "truncate-version",
                "rename-object-identity",
                "replacement-rejected",
                "external-mutation-rejected",
                "lock-conflict",
                "durability-reconciled",
                "stale-source-fenced",
                "cleanup-idempotent",
                "indeterminate-write-blocks-handoff",
                "destination-reauthorization-denied",
            ]
            .map(Value::from)
        );
    }
}
