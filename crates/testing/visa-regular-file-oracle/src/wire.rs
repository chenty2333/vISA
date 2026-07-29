use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum ObservationSchemaVersion {
    #[serde(rename = "regular-file-observation-v2")]
    V2,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationBundle {
    pub schema_version: ObservationSchemaVersion,
    pub bundle_id: String,
    pub route: RouteObservation,
    pub cases: Vec<CaseObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteObservation {
    pub mode: RouteMode,
    pub source: EndpointObservation,
    pub destination: Option<EndpointObservation>,
    pub execution_boundary: String,
    pub carrier: Option<CarrierIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    UninterruptedControl,
    Handoff,
    Restart,
    CarrierOnly,
    NaiveReopen,
    VisaPlusCarrier,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub instance_id: String,
    pub runtime: String,
    pub runtime_version: String,
    pub host_id: String,
    pub operating_system: String,
    pub isa: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseObservation {
    pub observation_id: String,
    pub case_id: RegularFileCase,
    pub schedule_id: String,
    pub schedule_sha256: String,
    pub subject: ResourceSubject,
    pub events: Vec<ObservedEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWriteOffset => "read-write-offset",
            Self::AppendContinuity => "append-continuity",
            Self::TruncateVersion => "truncate-version",
            Self::RenameObjectIdentity => "rename-object-identity",
            Self::ReplacementRejected => "replacement-rejected",
            Self::ExternalMutationRejected => "external-mutation-rejected",
            Self::LockConflict => "lock-conflict",
            Self::DurabilityReconciled => "durability-reconciled",
            Self::StaleSourceFenced => "stale-source-fenced",
            Self::CleanupIdempotent => "cleanup-idempotent",
            Self::IndeterminateWriteBlocksHandoff => "indeterminate-write-blocks-handoff",
            Self::DestinationReauthorizationDenied => "destination-reauthorization-denied",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSubject {
    pub resource_id: String,
    pub initial_path: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEvent {
    pub sequence: u64,
    pub phase: ObservationPhase,
    pub actor: ObservationActor,
    pub body: RawObservationEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileEntryObservation {
    Missing,
    File { bytes: Vec<u8>, size: u64, sha256: String, metadata: FileMetadataObservation },
    ProbeError { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadataObservation {
    pub device: u64,
    pub inode: u64,
    pub generation: Option<u64>,
    pub birth_time_unix_ns: Option<i64>,
    pub mode: u32,
    pub link_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationCallResult {
    Returned { output: RegularFileOutputObservation },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDurabilityObservation {
    Visible,
    Data,
    DataAndMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileLockStateObservation {
    Unlocked,
    Held,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawErrorObservation {
    pub domain: ErrorDomain,
    pub code: ErrorCode,
    pub errno: Option<i32>,
    pub retryable: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDomain {
    OperatingSystem,
    RegularFileProfile,
    Provider,
    Runtime,
    Carrier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsAction {
    WriteWhole { path: Vec<u8>, bytes: Vec<u8> },
    RenameNoReplace { source: Vec<u8>, destination: Vec<u8> },
    ReplacePath { source: Vec<u8>, destination: Vec<u8> },
    TryExclusiveLock { path: Vec<u8> },
    Unlock { path: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum GenericCallResult {
    Returned { bytes: Vec<u8> },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityDispositionObservation {
    Revalidate,
    Reconnect,
    Replay,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStateObservation {
    pub phase: CoordinatorPhaseObservation,
    pub activation: ActivationObservation,
    pub owner: Option<String>,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationObservation {
    Inactive,
    Source,
    SourceFenced,
    DestinationPrepared,
    DestinationActive,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecordObservation {
    pub operation_id: String,
    pub request_digest: Vec<u8>,
    pub outcome: OperationOutcomeObservation,
    pub cleanup: CleanupObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationOutcomeObservation {
    Pending,
    Applied { result_digest: Vec<u8> },
    Indeterminate,
    Rejected { error: RawErrorObservation },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupObservation {
    Required,
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationBindingObservation {
    pub resource_id: String,
    pub state: DestinationBindingState,
    pub owner: Option<String>,
    pub epoch: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationBindingState {
    Absent,
    Prepared,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputChannel {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierAction {
    Capture { capture_id: String },
    Restore { capture_id: String, payload: CarrierPayloadObservation },
    Resume,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierCallResult {
    Captured { payload: CarrierPayloadObservation },
    Returned { bytes: Vec<u8> },
    Error { error: RawErrorObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "storage", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum CarrierPayloadObservation {
    Inline { bytes: Vec<u8>, sha256: String },
    Artifact { reference: ArtifactReferenceObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReferenceObservation {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}
