use contract_core::{
    AuthorityGrant, BindingReceipt, Digest, EffectOutcome, EffectRequest, EntityRef, EvidenceRef,
    Extension, IdempotencyKey, Identity, JournalEntry, JournalPosition, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, Rights, VersionedValue,
};
use serde::{Deserialize, Serialize};
use substrate_api::{
    ActivationBundle, AuthorityPolicy, BindingKind, BindingRequest, CommitBundle,
    EffectRequestBinding, JournalScope, LeaseRecord, LeaseTransition, OperationObservation,
    PreparedLeaseTransitions, ProfileDispatchAuthorization, ProviderError, ProviderErrorKind,
    ReauthorizationRequest, TimerObservation, TimerRecovery,
};
use substrate_host::{FaultObservation, FaultPoint};

use super::PROVIDER_RPC_SCHEMA_VERSION;

pub(super) const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestEnvelope {
    pub schema_version: String,
    pub request_id: u64,
    pub request: Request,
}

impl RequestEnvelope {
    pub fn new(request_id: u64, request: Request) -> Self {
        Self { schema_version: PROVIDER_RPC_SCHEMA_VERSION.to_owned(), request_id, request }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseEnvelope {
    pub schema_version: String,
    pub request_id: u64,
    pub outcome: ResponseOutcome,
}

impl ResponseEnvelope {
    pub fn ok(request_id: u64, value: Value) -> Self {
        Self {
            schema_version: PROVIDER_RPC_SCHEMA_VERSION.to_owned(),
            request_id,
            outcome: ResponseOutcome::Ok { value: Box::new(value) },
        }
    }

    pub fn provider_error(request_id: u64, error: ProviderError) -> Self {
        Self {
            schema_version: PROVIDER_RPC_SCHEMA_VERSION.to_owned(),
            request_id,
            outcome: ResponseOutcome::ProviderError { error: error.into() },
        }
    }

    pub fn protocol_error(request_id: u64, detail: impl Into<String>) -> Self {
        Self {
            schema_version: PROVIDER_RPC_SCHEMA_VERSION.to_owned(),
            request_id,
            outcome: ResponseOutcome::ProtocolError { detail: detail.into() },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", deny_unknown_fields)]
pub(super) enum ResponseOutcome {
    Ok { value: Box<Value> },
    ProviderError { error: WireProviderError },
    ProtocolError { detail: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub(super) enum Request {
    Ping,
    Open { database_id: String, scope: WireJournalScope },
    InjectFailure { point: WireFaultPoint },
    FaultObservation,
    InspectKeyValue { resource: EntityRef, key: Vec<u8> },
    ProvisionKeyValueNamespace { resource: EntityRef, namespace: Identity },
    ProvisionKeyValueNamespaceAvailability { node: NodeIdentity, namespace: Identity },
    AppendEntry { entry: JournalEntry },
    CommitActivation { bundle: WireActivationBundle },
    CommitBundle { bundle: WireCommitBundle },
    Entry { position: JournalPosition },
    Operation { operation: Identity },
    Idempotency { key: IdempotencyKey },
    ReplayFrom { after: Option<JournalPosition> },
    KvRead { request: EffectRequest },
    KvCompareAndSet { request: EffectRequest },
    KvQueryOperation { operation: Identity, idempotency_key: IdempotencyKey },
    TimerArm { request: EffectRequest },
    TimerCancel { request: EffectRequest },
    TimerRestoreBinding { request: EffectRequest, recovery: WireTimerRecovery },
    TimerObserve { operation: Identity },
    TimerSuspend { operation: Identity },
    TimerResume { operation: Identity },
    TimerCleanup { operation: Identity },
    InstallPolicy { policy: WireAuthorityPolicy },
    InstallGrant { grant: AuthorityGrant },
    Attenuate { handoff: Identity, snapshot: Identity, parent: EntityRef, derived: AuthorityGrant },
    Revoke { authority: EntityRef },
    Reauthorize { request: WireReauthorizationRequest },
    AuthorizeEffect { request: EffectRequest, required_rights: Rights },
    RevokePrepared { snapshot: Identity },
    InitializeLease { lease: WireLeaseRecord },
    PrepareTransitions { request: EffectRequest, resources: Vec<EntityRef> },
    CurrentLease { resource: EntityRef },
    CheckLease { resource: EntityRef, owner: NodeIdentity, epoch: LeaseEpoch },
    PrepareBinding { request: WireBindingRequest },
    Binding { snapshot: Identity, claim: EntityRef },
    CleanupBinding { snapshot: Identity, claim: EntityRef },
    RequireProfileDispatchAuthorization { profile: Identity },
    ArmProfileDispatch { authorization: WireProfileDispatchAuthorization },
    FinishProfileDispatch { binding: WireEffectRequestBinding },
    ExecuteProfile { request: EffectRequest, extension: Extension },
    QueryProfileOperation { operation: Identity, idempotency_key: IdempotencyKey },
    ReconcileProfileOperation { request: EffectRequest, extension: Extension },
    CleanupProfileOperation { request: EffectRequest },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub(super) enum Value {
    Unit,
    Bool(bool),
    Rights(Rights),
    EffectOutcome(EffectOutcome),
    OptionalEffectOutcome(Option<EffectOutcome>),
    OptionalJournalEntry(Option<JournalEntry>),
    OptionalOperationObservation(Option<WireOperationObservation>),
    JournalEntries(Vec<JournalEntry>),
    TimerObservation(WireTimerObservation),
    AuthorityGrant(AuthorityGrant),
    PreparedLeaseTransitions(WirePreparedLeaseTransitions),
    OptionalLeaseRecord(Option<WireLeaseRecord>),
    BindingReceipt(BindingReceipt),
    OptionalBindingReceipt(Option<BindingReceipt>),
    VersionedValueOption(Option<VersionedValue>),
    OptionalFaultObservation(Option<WireFaultObservation>),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WireProviderErrorKind {
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireProviderError {
    pub kind: WireProviderErrorKind,
    pub retryable: bool,
}

impl From<ProviderError> for WireProviderError {
    fn from(value: ProviderError) -> Self {
        Self { kind: value.kind.into(), retryable: value.retryable }
    }
}

impl From<WireProviderError> for ProviderError {
    fn from(value: WireProviderError) -> Self {
        Self::new(value.kind.into(), value.retryable)
    }
}

impl From<ProviderErrorKind> for WireProviderErrorKind {
    fn from(value: ProviderErrorKind) -> Self {
        match value {
            ProviderErrorKind::InvalidRequest => Self::InvalidRequest,
            ProviderErrorKind::Unsupported => Self::Unsupported,
            ProviderErrorKind::NotFound => Self::NotFound,
            ProviderErrorKind::Conflict => Self::Conflict,
            ProviderErrorKind::StaleGeneration => Self::StaleGeneration,
            ProviderErrorKind::StaleEpoch => Self::StaleEpoch,
            ProviderErrorKind::Denied => Self::Denied,
            ProviderErrorKind::Revoked => Self::Revoked,
            ProviderErrorKind::Integrity => Self::Integrity,
            ProviderErrorKind::Unavailable => Self::Unavailable,
            ProviderErrorKind::OutcomeUnknown => Self::OutcomeUnknown,
            ProviderErrorKind::Storage => Self::Storage,
        }
    }
}

impl From<WireProviderErrorKind> for ProviderErrorKind {
    fn from(value: WireProviderErrorKind) -> Self {
        match value {
            WireProviderErrorKind::InvalidRequest => Self::InvalidRequest,
            WireProviderErrorKind::Unsupported => Self::Unsupported,
            WireProviderErrorKind::NotFound => Self::NotFound,
            WireProviderErrorKind::Conflict => Self::Conflict,
            WireProviderErrorKind::StaleGeneration => Self::StaleGeneration,
            WireProviderErrorKind::StaleEpoch => Self::StaleEpoch,
            WireProviderErrorKind::Denied => Self::Denied,
            WireProviderErrorKind::Revoked => Self::Revoked,
            WireProviderErrorKind::Integrity => Self::Integrity,
            WireProviderErrorKind::Unavailable => Self::Unavailable,
            WireProviderErrorKind::OutcomeUnknown => Self::OutcomeUnknown,
            WireProviderErrorKind::Storage => Self::Storage,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireJournalScope {
    pub node: NodeIdentity,
    pub component: Identity,
}

impl From<JournalScope> for WireJournalScope {
    fn from(value: JournalScope) -> Self {
        Self { node: value.node, component: value.component }
    }
}

impl From<WireJournalScope> for JournalScope {
    fn from(value: WireJournalScope) -> Self {
        Self { node: value.node, component: value.component }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireActivationBundle {
    pub entry: JournalEntry,
    pub initial_leases: Vec<WireLeaseRecord>,
}

impl From<&ActivationBundle> for WireActivationBundle {
    fn from(value: &ActivationBundle) -> Self {
        Self {
            entry: value.entry.clone(),
            initial_leases: value.initial_leases.iter().copied().map(Into::into).collect(),
        }
    }
}

impl From<WireActivationBundle> for ActivationBundle {
    fn from(value: WireActivationBundle) -> Self {
        Self {
            entry: value.entry,
            initial_leases: value.initial_leases.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireCommitBundle {
    pub entry: JournalEntry,
    pub lease_transitions: Vec<WireLeaseTransition>,
    pub final_authorities: Vec<EntityRef>,
}

impl From<&CommitBundle> for WireCommitBundle {
    fn from(value: &CommitBundle) -> Self {
        Self {
            entry: value.entry.clone(),
            lease_transitions: value.lease_transitions.iter().copied().map(Into::into).collect(),
            final_authorities: value.final_authorities.clone(),
        }
    }
}

impl From<WireCommitBundle> for CommitBundle {
    fn from(value: WireCommitBundle) -> Self {
        Self {
            entry: value.entry,
            lease_transitions: value.lease_transitions.into_iter().map(Into::into).collect(),
            final_authorities: value.final_authorities,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireLeaseTransition {
    pub resource: EntityRef,
    pub expected_owner: NodeIdentity,
    pub next_owner: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub next_epoch: LeaseEpoch,
}

impl From<LeaseTransition> for WireLeaseTransition {
    fn from(value: LeaseTransition) -> Self {
        Self {
            resource: value.resource,
            expected_owner: value.expected_owner,
            next_owner: value.next_owner,
            expected_epoch: value.expected_epoch,
            next_epoch: value.next_epoch,
        }
    }
}

impl From<WireLeaseTransition> for LeaseTransition {
    fn from(value: WireLeaseTransition) -> Self {
        Self {
            resource: value.resource,
            expected_owner: value.expected_owner,
            next_owner: value.next_owner,
            expected_epoch: value.expected_epoch,
            next_epoch: value.next_epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireLeaseRecord {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

impl From<LeaseRecord> for WireLeaseRecord {
    fn from(value: LeaseRecord) -> Self {
        Self { resource: value.resource, owner: value.owner, epoch: value.epoch }
    }
}

impl From<WireLeaseRecord> for LeaseRecord {
    fn from(value: WireLeaseRecord) -> Self {
        Self { resource: value.resource, owner: value.owner, epoch: value.epoch }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WirePreparedLeaseTransitions {
    pub transitions: Vec<WireLeaseTransition>,
    pub outcome: EffectOutcome,
}

impl From<PreparedLeaseTransitions> for WirePreparedLeaseTransitions {
    fn from(value: PreparedLeaseTransitions) -> Self {
        Self {
            transitions: value.transitions.into_iter().map(Into::into).collect(),
            outcome: value.outcome,
        }
    }
}

impl From<WirePreparedLeaseTransitions> for PreparedLeaseTransitions {
    fn from(value: WirePreparedLeaseTransitions) -> Self {
        Self {
            transitions: value.transitions.into_iter().map(Into::into).collect(),
            outcome: value.outcome,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub(super) enum WireTimerRecovery {
    Running { remaining: LogicalDurationNanos },
    Suspended { remaining: LogicalDurationNanos },
}

impl From<TimerRecovery> for WireTimerRecovery {
    fn from(value: TimerRecovery) -> Self {
        match value {
            TimerRecovery::Running { remaining } => Self::Running { remaining },
            TimerRecovery::Suspended { remaining } => Self::Suspended { remaining },
        }
    }
}

impl From<WireTimerRecovery> for TimerRecovery {
    fn from(value: WireTimerRecovery) -> Self {
        match value {
            WireTimerRecovery::Running { remaining } => Self::Running { remaining },
            WireTimerRecovery::Suspended { remaining } => Self::Suspended { remaining },
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub(super) enum WireTimerObservation {
    Pending { remaining: LogicalDurationNanos },
    Completed { evidence: EvidenceRef },
    Cancelled { evidence: EvidenceRef },
    Absent,
}

impl From<TimerObservation> for WireTimerObservation {
    fn from(value: TimerObservation) -> Self {
        match value {
            TimerObservation::Pending(remaining) => Self::Pending { remaining },
            TimerObservation::Completed { evidence } => Self::Completed { evidence },
            TimerObservation::Cancelled { evidence } => Self::Cancelled { evidence },
            TimerObservation::Absent => Self::Absent,
        }
    }
}

impl From<WireTimerObservation> for TimerObservation {
    fn from(value: WireTimerObservation) -> Self {
        match value {
            WireTimerObservation::Pending { remaining } => Self::Pending(remaining),
            WireTimerObservation::Completed { evidence } => Self::Completed { evidence },
            WireTimerObservation::Cancelled { evidence } => Self::Cancelled { evidence },
            WireTimerObservation::Absent => Self::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAuthorityPolicy {
    pub subject: EntityRef,
    pub resource: EntityRef,
    pub allowed_rights: Rights,
}

impl From<AuthorityPolicy> for WireAuthorityPolicy {
    fn from(value: AuthorityPolicy) -> Self {
        Self {
            subject: value.subject,
            resource: value.resource,
            allowed_rights: value.allowed_rights,
        }
    }
}

impl From<WireAuthorityPolicy> for AuthorityPolicy {
    fn from(value: WireAuthorityPolicy) -> Self {
        Self {
            subject: value.subject,
            resource: value.resource,
            allowed_rights: value.allowed_rights,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireReauthorizationRequest {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub source_authority: EntityRef,
    pub destination_authority: EntityRef,
    pub destination_subject: EntityRef,
    pub resource: EntityRef,
    pub required_rights: Rights,
}

impl From<ReauthorizationRequest> for WireReauthorizationRequest {
    fn from(value: ReauthorizationRequest) -> Self {
        Self {
            handoff: value.handoff,
            snapshot: value.snapshot,
            source_authority: value.source_authority,
            destination_authority: value.destination_authority,
            destination_subject: value.destination_subject,
            resource: value.resource,
            required_rights: value.required_rights,
        }
    }
}

impl From<WireReauthorizationRequest> for ReauthorizationRequest {
    fn from(value: WireReauthorizationRequest) -> Self {
        Self {
            handoff: value.handoff,
            snapshot: value.snapshot,
            source_authority: value.source_authority,
            destination_authority: value.destination_authority,
            destination_subject: value.destination_subject,
            resource: value.resource,
            required_rights: value.required_rights,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub(super) enum WireBindingKind {
    PausedDurationTimer,
    KeyValueNamespace { namespace: Identity },
    Profile { profile: Identity },
}

impl From<BindingKind> for WireBindingKind {
    fn from(value: BindingKind) -> Self {
        match value {
            BindingKind::PausedDurationTimer => Self::PausedDurationTimer,
            BindingKind::KeyValueNamespace { namespace } => Self::KeyValueNamespace { namespace },
            BindingKind::Profile { profile } => Self::Profile { profile },
        }
    }
}

impl From<WireBindingKind> for BindingKind {
    fn from(value: WireBindingKind) -> Self {
        match value {
            WireBindingKind::PausedDurationTimer => Self::PausedDurationTimer,
            WireBindingKind::KeyValueNamespace { namespace } => {
                Self::KeyValueNamespace { namespace }
            }
            WireBindingKind::Profile { profile } => Self::Profile { profile },
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireBindingRequest {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub claim: EntityRef,
    pub authority: EntityRef,
    pub exposed_rights: Rights,
    pub expected_owner: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub candidate_owner: NodeIdentity,
    pub candidate_epoch: LeaseEpoch,
    pub kind: WireBindingKind,
}

impl From<BindingRequest> for WireBindingRequest {
    fn from(value: BindingRequest) -> Self {
        Self {
            handoff: value.handoff,
            snapshot: value.snapshot,
            claim: value.claim,
            authority: value.authority,
            exposed_rights: value.exposed_rights,
            expected_owner: value.expected_owner,
            expected_epoch: value.expected_epoch,
            candidate_owner: value.candidate_owner,
            candidate_epoch: value.candidate_epoch,
            kind: value.kind.into(),
        }
    }
}

impl From<WireBindingRequest> for BindingRequest {
    fn from(value: WireBindingRequest) -> Self {
        Self {
            handoff: value.handoff,
            snapshot: value.snapshot,
            claim: value.claim,
            authority: value.authority,
            exposed_rights: value.exposed_rights,
            expected_owner: value.expected_owner,
            expected_epoch: value.expected_epoch,
            candidate_owner: value.candidate_owner,
            candidate_epoch: value.candidate_epoch,
            kind: value.kind.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOperationObservation {
    pub record: contract_core::OperationRecord,
}

impl From<OperationObservation> for WireOperationObservation {
    fn from(value: OperationObservation) -> Self {
        Self { record: value.record }
    }
}

impl From<WireOperationObservation> for OperationObservation {
    fn from(value: WireOperationObservation) -> Self {
        Self { record: value.record }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireEffectRequestBinding {
    pub operation: Identity,
    pub idempotency_key: IdempotencyKey,
    pub canonical_digest: Digest,
}

impl From<EffectRequestBinding> for WireEffectRequestBinding {
    fn from(value: EffectRequestBinding) -> Self {
        Self {
            operation: value.operation,
            idempotency_key: value.idempotency_key,
            canonical_digest: value.canonical_digest,
        }
    }
}

impl From<WireEffectRequestBinding> for EffectRequestBinding {
    fn from(value: WireEffectRequestBinding) -> Self {
        Self {
            operation: value.operation,
            idempotency_key: value.idempotency_key,
            canonical_digest: value.canonical_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireProfileDispatchAuthorization {
    pub profile: Identity,
    pub binding: WireEffectRequestBinding,
}

impl From<&ProfileDispatchAuthorization> for WireProfileDispatchAuthorization {
    fn from(value: &ProfileDispatchAuthorization) -> Self {
        Self { profile: value.profile(), binding: value.binding().into() }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WireFaultPoint {
    SkipJournalAppend,
    SkipSourceFence,
    DropTimerCancel,
    DuplicateCleanupApply,
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    BeforeExternalSourceFence,
    AfterExternalSourceFence,
    AfterKvCommit,
    BeforeProfileEffect,
    AfterProfileEffect,
    AfterProfileCommit,
    BeforeLogicalRequestIo,
    AfterRegularFileMutation,
    AfterLogicalRequestSend,
    AfterLogicalRequestCommit,
    AfterLogicalCancelSend,
}

impl From<FaultPoint> for WireFaultPoint {
    fn from(value: FaultPoint) -> Self {
        match value {
            FaultPoint::SkipJournalAppend => Self::SkipJournalAppend,
            FaultPoint::SkipSourceFence => Self::SkipSourceFence,
            FaultPoint::DropTimerCancel => Self::DropTimerCancel,
            FaultPoint::DuplicateCleanupApply => Self::DuplicateCleanupApply,
            FaultPoint::BeforeJournalWrite => Self::BeforeJournalWrite,
            FaultPoint::AfterJournalWrite => Self::AfterJournalWrite,
            FaultPoint::BeforeActivationBundle => Self::BeforeActivationBundle,
            FaultPoint::AfterActivationBundle => Self::AfterActivationBundle,
            FaultPoint::BeforeCommitBundle => Self::BeforeCommitBundle,
            FaultPoint::AfterCommitBundle => Self::AfterCommitBundle,
            FaultPoint::BeforeExternalSourceFence => Self::BeforeExternalSourceFence,
            FaultPoint::AfterExternalSourceFence => Self::AfterExternalSourceFence,
            FaultPoint::AfterKvCommit => Self::AfterKvCommit,
            FaultPoint::BeforeProfileEffect => Self::BeforeProfileEffect,
            FaultPoint::AfterProfileEffect => Self::AfterProfileEffect,
            FaultPoint::AfterProfileCommit => Self::AfterProfileCommit,
            FaultPoint::BeforeLogicalRequestIo => Self::BeforeLogicalRequestIo,
            FaultPoint::AfterRegularFileMutation => Self::AfterRegularFileMutation,
            FaultPoint::AfterLogicalRequestSend => Self::AfterLogicalRequestSend,
            FaultPoint::AfterLogicalRequestCommit => Self::AfterLogicalRequestCommit,
            FaultPoint::AfterLogicalCancelSend => Self::AfterLogicalCancelSend,
        }
    }
}

impl From<WireFaultPoint> for FaultPoint {
    fn from(value: WireFaultPoint) -> Self {
        match value {
            WireFaultPoint::SkipJournalAppend => Self::SkipJournalAppend,
            WireFaultPoint::SkipSourceFence => Self::SkipSourceFence,
            WireFaultPoint::DropTimerCancel => Self::DropTimerCancel,
            WireFaultPoint::DuplicateCleanupApply => Self::DuplicateCleanupApply,
            WireFaultPoint::BeforeJournalWrite => Self::BeforeJournalWrite,
            WireFaultPoint::AfterJournalWrite => Self::AfterJournalWrite,
            WireFaultPoint::BeforeActivationBundle => Self::BeforeActivationBundle,
            WireFaultPoint::AfterActivationBundle => Self::AfterActivationBundle,
            WireFaultPoint::BeforeCommitBundle => Self::BeforeCommitBundle,
            WireFaultPoint::AfterCommitBundle => Self::AfterCommitBundle,
            WireFaultPoint::BeforeExternalSourceFence => Self::BeforeExternalSourceFence,
            WireFaultPoint::AfterExternalSourceFence => Self::AfterExternalSourceFence,
            WireFaultPoint::AfterKvCommit => Self::AfterKvCommit,
            WireFaultPoint::BeforeProfileEffect => Self::BeforeProfileEffect,
            WireFaultPoint::AfterProfileEffect => Self::AfterProfileEffect,
            WireFaultPoint::AfterProfileCommit => Self::AfterProfileCommit,
            WireFaultPoint::BeforeLogicalRequestIo => Self::BeforeLogicalRequestIo,
            WireFaultPoint::AfterRegularFileMutation => Self::AfterRegularFileMutation,
            WireFaultPoint::AfterLogicalRequestSend => Self::AfterLogicalRequestSend,
            WireFaultPoint::AfterLogicalRequestCommit => Self::AfterLogicalRequestCommit,
            WireFaultPoint::AfterLogicalCancelSend => Self::AfterLogicalCancelSend,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireFaultObservation {
    pub point: WireFaultPoint,
    pub count: u64,
}

impl From<FaultObservation> for WireFaultObservation {
    fn from(value: FaultObservation) -> Self {
        Self { point: value.point.into(), count: value.count }
    }
}

impl From<WireFaultObservation> for FaultObservation {
    fn from(value: WireFaultObservation) -> Self {
        Self { point: value.point.into(), count: value.count }
    }
}
