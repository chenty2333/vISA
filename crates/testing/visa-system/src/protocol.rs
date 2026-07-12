use contract_core::{
    AuthorityGrant, BindingReceipt, CanonicalState, Digest, EffectOutcome, EntityRef, EvidenceRef,
    ExtensionSupport, HandoffPhase, Identity, JournalEntry, JournalPosition, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, SchemaVersion, SnapshotEnvelope, VersionedValue,
};
use serde::{Deserialize, Serialize};

use crate::fixture::FixtureOptions;

pub const PROTOCOL_VERSION: u64 = visa_conformance::STAGE1_WORKER_PROTOCOL_VERSION;
pub const INVALID_REQUEST_ID: &str = "<invalid>";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeImplementation {
    Wasmtime,
    JcoNode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentityView {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
    pub translation_provenance: Option<TranslationProvenanceView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationProvenanceView {
    pub jco_version: String,
    pub js_component_bindgen_version: String,
    pub translator: String,
    pub translator_version: String,
    pub translation_options: String,
    pub node_executable_path: String,
    pub node_executable_sha256: String,
    pub node_version: String,
    pub v8_version: String,
    pub rpc_protocol_version: u32,
    pub execution_carrier: String,
    pub generated_sha256: String,
    pub driver_sha256: String,
    pub core_module_sha256s: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultPointSpec {
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    AfterKvCommit,
}

impl From<FaultPointSpec> for substrate_host::FaultPoint {
    fn from(value: FaultPointSpec) -> Self {
        match value {
            FaultPointSpec::BeforeJournalWrite => Self::BeforeJournalWrite,
            FaultPointSpec::AfterJournalWrite => Self::AfterJournalWrite,
            FaultPointSpec::BeforeActivationBundle => Self::BeforeActivationBundle,
            FaultPointSpec::AfterActivationBundle => Self::AfterActivationBundle,
            FaultPointSpec::BeforeCommitBundle => Self::BeforeCommitBundle,
            FaultPointSpec::AfterCommitBundle => Self::AfterCommitBundle,
            FaultPointSpec::AfterKvCommit => Self::AfterKvCommit,
        }
    }
}

impl From<substrate_host::FaultPoint> for FaultPointSpec {
    fn from(value: substrate_host::FaultPoint) -> Self {
        match value {
            substrate_host::FaultPoint::BeforeJournalWrite => Self::BeforeJournalWrite,
            substrate_host::FaultPoint::AfterJournalWrite => Self::AfterJournalWrite,
            substrate_host::FaultPoint::BeforeActivationBundle => Self::BeforeActivationBundle,
            substrate_host::FaultPoint::AfterActivationBundle => Self::AfterActivationBundle,
            substrate_host::FaultPoint::BeforeCommitBundle => Self::BeforeCommitBundle,
            substrate_host::FaultPoint::AfterCommitBundle => Self::AfterCommitBundle,
            substrate_host::FaultPoint::AfterKvCommit => Self::AfterKvCommit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultObservationView {
    pub point: FaultPointSpec,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashMode {
    AfterResponse,
    Immediate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAuthority {
    Handoff,
    Timer,
    KeyValue,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationSupportMode {
    #[default]
    Compatible,
    TimerSemanticsUnsupported,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotExpectationOverrides {
    pub component_digest: Option<Digest>,
    pub profile_digest: Option<Digest>,
    pub profile_version: Option<SchemaVersion>,
    pub supported_extensions: Option<Vec<ExtensionSupport>>,
    pub destination: Option<NodeIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecordView {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub version: u64,
    pub id: String,
    pub command: WorkerCommand,
}

impl RequestEnvelope {
    pub fn new(id: impl Into<String>, command: WorkerCommand) -> Self {
        Self { version: PROTOCOL_VERSION, id: id.into(), command }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerCommand {
    Initialize {
        role: WorkerRole,
        runtime: RuntimeImplementation,
        database_path: String,
        options: FixtureOptions,
        fault: Option<FaultPointSpec>,
    },
    BootstrapSource,
    Read,
    BeginQuiesce,
    FreezeSource,
    ExportSourceSnapshot,
    AbortSource,
    ThawSource,
    CancelPending,
    CleanupPendingTimer,
    InjectUnsupportedLiveResource,
    ClearUnsupportedLiveResource,
    RevokeRequiredAuthority {
        authority: RequiredAuthority,
    },
    StaleSourceKvProbe,
    AdversarialStaleKvWriteProbe,
    DuplicateCompletionKvProbe,
    ValidateDestination {
        envelope: SnapshotEnvelope,
        expectations: SnapshotExpectationOverrides,
        support: DestinationSupportMode,
    },
    LoadDestination {
        envelope: SnapshotEnvelope,
        component_state: Vec<u8>,
    },
    PrepareDestination,
    CommitDestination,
    ResumeDestination,
    PollTimer {
        deliver: bool,
    },
    Dump,
    Crash {
        mode: CrashMode,
        exit_code: i32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub version: u64,
    pub id: String,
    pub outcome: ResponseOutcome,
}

impl ResponseEnvelope {
    pub fn success(id: impl Into<String>, result: WorkerResult) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id: id.into(),
            outcome: ResponseOutcome::Success { result: Box::new(result) },
        }
    }

    pub fn error(id: impl Into<String>, error: WorkerError) -> Self {
        Self { version: PROTOCOL_VERSION, id: id.into(), outcome: ResponseOutcome::Error { error } }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseOutcome {
    Success { result: Box<WorkerResult> },
    Error { error: WorkerError },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerResult {
    Ack,
    Initialized {
        role: WorkerRole,
        case_id: String,
        runtime: RuntimeIdentityView,
    },
    State {
        view: StateView,
    },
    SafePoint {
        component_state: Vec<u8>,
        timer: SafePointTimerView,
        view: StateView,
    },
    Snapshot {
        envelope: Box<SnapshotEnvelope>,
        component_state: Vec<u8>,
        view: StateView,
    },
    Timer {
        poll: TimerPollView,
        delivered: bool,
        view: StateView,
    },
    EffectProbe {
        operation: Identity,
        outcome: Option<EffectOutcome>,
        replayed: bool,
        view: StateView,
    },
    Dump {
        canonical_state: Box<CanonicalState>,
        state_digest: Digest,
        journal: Vec<JournalEntry>,
        leases: Vec<LeaseRecordView>,
        authority_grants: Vec<AuthorityGrant>,
        binding_receipts: Vec<BindingReceipt>,
        fault_observation: Option<FaultObservationView>,
        key_value_entry: Option<VersionedValue>,
        component_instantiated: bool,
        component: Option<ComponentStatusView>,
        portable_component_state: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateView {
    pub role: WorkerRole,
    pub canonical_phase: HandoffPhase,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
    pub component_instantiated: bool,
    pub component: Option<ComponentStatusView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentStatusView {
    pub session_id: String,
    pub key: String,
    pub expected_version: u64,
    pub completion_value: Vec<u8>,
    pub timer_operation_id: String,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
    pub phase: WorkloadPhaseView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPhaseView {
    Armed,
    Frozen,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafePointTimerView {
    Idle,
    Pending { remaining: LogicalDurationNanos, arm_operation: Identity },
    Completed { arm_operation: Option<Identity> },
    Cancelled,
    Cleaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TimerPollView {
    Idle,
    Pending { arm_operation: Identity, remaining: LogicalDurationNanos },
    Fired { arm_operation: Identity, evidence: EvidenceRef },
    Completed,
    Cancelled,
    CancelledObserved { arm_operation: Identity, evidence: EvidenceRef },
    Cleaned,
    Absent { arm_operation: Identity },
    Frozen { disposition: contract_core::TimerDisposition },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
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
pub enum AdapterFailureKindView {
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
pub enum WorkloadFailureKindView {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerError {
    pub code: WorkerErrorCode,
    pub message: String,
    pub retryable: Option<bool>,
    pub provider_kind: Option<String>,
    pub adapter_kind: Option<AdapterFailureKindView>,
    pub workload_kind: Option<WorkloadFailureKindView>,
}

impl WorkerError {
    pub fn new(code: WorkerErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: None,
            provider_kind: None,
            adapter_kind: None,
            workload_kind: None,
        }
    }

    pub fn provider(message: impl Into<String>, error: substrate_api::ProviderError) -> Self {
        Self {
            code: WorkerErrorCode::Provider,
            message: message.into(),
            retryable: Some(error.retryable),
            provider_kind: Some(format!("{:?}", error.kind)),
            adapter_kind: None,
            workload_kind: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_round_trip_as_tagged_json() {
        let request = RequestEnvelope::new(
            "initialize-1",
            WorkerCommand::Initialize {
                role: WorkerRole::Source,
                runtime: RuntimeImplementation::Wasmtime,
                database_path: "/tmp/visa-system-protocol.sqlite3".to_owned(),
                options: FixtureOptions::new("protocol-round-trip"),
                fault: Some(FaultPointSpec::AfterActivationBundle),
            },
        );
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["version"], PROTOCOL_VERSION);
        assert_eq!(encoded["id"], "initialize-1");
        assert_eq!(encoded["command"]["kind"], "initialize");
        assert_eq!(serde_json::from_value::<RequestEnvelope>(encoded).unwrap(), request);

        let response = ResponseEnvelope::success("initialize-1", WorkerResult::Ack);
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(encoded["outcome"]["status"], "success");
        assert_eq!(encoded["outcome"]["result"]["kind"], "ack");
        assert_eq!(serde_json::from_value::<ResponseEnvelope>(encoded).unwrap(), response);
    }

    #[test]
    fn unknown_fields_on_structured_commands_are_rejected() {
        let encoded = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "id": "strict-request",
            "command": {
                "kind": "poll_timer",
                "deliver": true,
                "unexpected": true
            }
        });
        assert!(serde_json::from_value::<RequestEnvelope>(encoded).is_err());
    }

    #[test]
    fn initialize_requires_an_explicit_runtime_selector() {
        let encoded = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "id": "missing-runtime",
            "command": {
                "kind": "initialize",
                "role": "source",
                "database_path": "/tmp/visa-system-missing-runtime.sqlite3",
                "options": FixtureOptions::new("missing-runtime"),
                "fault": null
            }
        });
        assert!(serde_json::from_value::<RequestEnvelope>(encoded).is_err());
    }
}
