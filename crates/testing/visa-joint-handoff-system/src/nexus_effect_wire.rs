use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA: &str = "nexus.effect-peer.request.v1";
pub const RESPONSE_SCHEMA: &str = "nexus.effect-peer.response.v1";
pub const RECEIPT_SCHEMA: &str = "nexus.effect-peer.native-receipt.v1";
pub const AUTHENTICATION_BOUNDARY: &str = "sha256-integrity-only-not-authenticity";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRequest {
    pub schema: String,
    pub request_id: u64,
    pub command: PeerCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "kebab-case")]
pub enum PeerCommand {
    Initialize(PeerConfig),
    Register(RegisterEffect),
    Prepare(EffectSelector),
    Commit(CommitEffect),
    Complete(CompleteEffect),
    AcknowledgePublication(EffectSelector),
    CrashService(CrashService),
    RebindService(RebindService),
    Freeze(NativePrepareIntent),
    AbortUncommitted,
    Thaw(NativeOwnershipDecision),
    CloseStep(NativeOwnershipDecision),
    Query,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub task_id: u64,
    pub task_generation: u64,
    pub credit_class: u16,
    pub credit_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterEffect {
    pub client_effect: u64,
    pub operation_class: u32,
    pub syscall_number: u64,
    pub syscall_arguments: [u64; 6],
    pub credit_units: u64,
    pub publication_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSelector {
    pub client_effect: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitEffect {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub result: i64,
    pub domain_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteEffect {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub result: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashService {
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebindService {
    pub crashed_binding_epoch: u64,
    pub replacement_supervisor_id: u64,
    pub replacement_supervisor_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrepareIntent {
    pub handoff_id: u64,
    pub log_identity: u64,
    pub intent_position: u64,
    pub service_incarnation: u64,
    pub key_identity: u64,
    pub request_digest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnershipDecision {
    pub handoff_id: u64,
    pub freeze_generation: u64,
    pub log_identity: u64,
    pub decision_position: u64,
    pub service_incarnation: u64,
    pub key_identity: u64,
    pub request_digest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseStatus {
    Ok,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerResponse {
    pub schema: String,
    pub request_id: u64,
    pub status: ResponseStatus,
    pub receipt: Option<NativeReceipt>,
    pub error: Option<NativeError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReceipt {
    pub schema: String,
    pub sequence: u64,
    pub kind: NativeReceiptKind,
    pub request_sha256: String,
    pub previous_receipt_sha256: Option<String>,
    pub payload_sha256: String,
    pub authentication_boundary: String,
    pub payload: NativeReceiptPayload,
    pub receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReceiptKind {
    Initialized,
    EffectRegistered,
    EffectPrepared,
    EffectCommitted,
    EffectCompleted,
    PublicationAcknowledged,
    ServiceCrashed,
    ServiceRebound,
    AdmissionFrozen,
    UncommittedAborted,
    AdmissionThawed,
    ClosureProgress,
    HandoffQuery,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum NativeReceiptPayload {
    Initialized(InitializedPayload),
    EffectRegistered(RegisteredPayload),
    EffectPrepared(EffectSelector),
    EffectCommitted(CommittedPayload),
    EffectCompleted(CompletedPayload),
    PublicationAcknowledged(EffectSelector),
    ServiceCrashed(ServiceCrashedPayload),
    ServiceRebound(ServiceReboundPayload),
    AdmissionFrozen(FreezePayload),
    UncommittedAborted(AbortProgressPayload),
    AdmissionThawed(ThawPayload),
    ClosureProgress(HandoffProgressPayload),
    HandoffQuery(HandoffProgressPayload),
    Shutdown,
}

impl NativeReceiptPayload {
    pub const fn receipt_kind(&self) -> NativeReceiptKind {
        match self {
            Self::Initialized(_) => NativeReceiptKind::Initialized,
            Self::EffectRegistered(_) => NativeReceiptKind::EffectRegistered,
            Self::EffectPrepared(_) => NativeReceiptKind::EffectPrepared,
            Self::EffectCommitted(_) => NativeReceiptKind::EffectCommitted,
            Self::EffectCompleted(_) => NativeReceiptKind::EffectCompleted,
            Self::PublicationAcknowledged(_) => NativeReceiptKind::PublicationAcknowledged,
            Self::ServiceCrashed(_) => NativeReceiptKind::ServiceCrashed,
            Self::ServiceRebound(_) => NativeReceiptKind::ServiceRebound,
            Self::AdmissionFrozen(_) => NativeReceiptKind::AdmissionFrozen,
            Self::UncommittedAborted(_) => NativeReceiptKind::UncommittedAborted,
            Self::AdmissionThawed(_) => NativeReceiptKind::AdmissionThawed,
            Self::ClosureProgress(_) => NativeReceiptKind::ClosureProgress,
            Self::HandoffQuery(_) => NativeReceiptKind::HandoffQuery,
            Self::Shutdown => NativeReceiptKind::Shutdown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializedPayload {
    pub process_id: u32,
    pub boot_incarnation: u64,
    pub config: PeerConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub binding_epoch: u64,
    pub commit_sequence: u64,
    pub result: i64,
    pub domain_revision: u64,
    pub registry_replay: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPayload {
    pub client_effect: u64,
    pub binding_epoch: u64,
    pub terminal_sequence: u64,
    pub publication_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashedEffectPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCrashedPayload {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub previous_binding_epoch: u64,
    pub crashed_binding_epoch: u64,
    pub cohort: Vec<CrashedEffectPayload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedEffectPayload {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub previous_binding_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReboundPayload {
    pub scope_id: u64,
    pub scope_generation: u64,
    pub supervisor_id: u64,
    pub supervisor_generation: u64,
    pub binding_epoch: u64,
    pub adopted: Vec<AdoptedEffectPayload>,
    pub recovery_remaining: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeReadiness {
    ReadyToCommit,
    NeedsAbort,
    PublicationPending,
    BlockedRetained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezePayload {
    pub handoff_id: u64,
    pub registry_instance: u64,
    pub boot_incarnation: u64,
    pub scope_id: u64,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub frozen_scope_revision: u64,
    pub freeze_generation: u64,
    pub cohort_digest: u64,
    pub classification_digest: u64,
    pub cohort_size: usize,
    pub committed_at_freeze: usize,
    pub readiness: NativeReadiness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortProgressPayload {
    pub aborted: usize,
    pub publication_effects: Vec<u64>,
    pub readiness: NativeReadiness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThawPayload {
    pub handoff_id: u64,
    pub freeze_generation: u64,
    pub decision_position: u64,
    pub source_recovery_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeHandoffStatus {
    Frozen,
    Aborted,
    Closing,
    Retained,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffProgressPayload {
    pub status: NativeHandoffStatus,
    pub readiness: Option<NativeReadiness>,
    pub freeze_generation: u64,
    pub scope_revision: u64,
    pub authority_epoch: u64,
    pub binding_epoch: u64,
    pub live_effects: usize,
    pub pending_publications: usize,
    pub native_effect: Option<u64>,
    pub publication_pending: bool,
    pub terminal_manifest_digest: Option<u64>,
}

#[derive(Serialize)]
pub struct ReceiptDigestInput<'a> {
    pub schema: &'static str,
    pub sequence: u64,
    pub kind: NativeReceiptKind,
    pub request_sha256: &'a str,
    pub previous_receipt_sha256: Option<&'a str>,
    pub payload_sha256: &'a str,
    pub authentication_boundary: &'static str,
    pub payload: &'a NativeReceiptPayload,
}
