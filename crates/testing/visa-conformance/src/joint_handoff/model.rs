use contract_core::{
    CanonicalState, Digest, EntityRef, IdempotencyKey, Identity, JournalEntry, JournalPosition,
    LeaseEpoch, NodeIdentity, SnapshotEnvelope,
};
use serde::{Deserialize, Serialize};

pub const JOINT_HANDOFF_EVIDENCE_SCHEMA_VERSION: &str = "visa-joint-handoff-evidence-v2";
pub const JOINT_HANDOFF_RAW_TRACE_SCHEMA_VERSION: &str = "visa-joint-handoff-raw-trace-v1";
pub const JOINT_HANDOFF_MAPPING_SCHEMA_VERSION: &str = "visa-joint-handoff-mapping-v1";
pub const JOINT_HANDOFF_EFFECT_MANIFEST_SCHEMA_VERSION: &str =
    "visa-joint-handoff-effect-cohort-v1";
pub const JOINT_HANDOFF_CLAIM_ID: &str = "bounded-joint-handoff-refinement-v1";
pub const JOINT_HANDOFF_CASE_COUNT: usize = 16;
pub const JOINT_REFERENCE_CELL_SCHEMA_VERSION: &str = "visa-joint-reference-peer-cell-v1";
pub const JOINT_REFERENCE_CELL_SUPPLEMENTAL_CASE_ID: &str =
    "supplemental-postcommit-retained-tombstone";
pub const JOINT_REFERENCE_CELL_SCENARIO_COUNT: usize = JOINT_HANDOFF_CASE_COUNT + 1;
pub const JOINT_REFERENCE_CELL_VISA_MODE: &str =
    "synthetic-visa-freeze-and-destination-prepared-references";
pub const JOINT_DURABLE_PROJECTION_CELL_SCHEMA_VERSION: &str =
    "visa.joint-handoff.durable-projection-cell.v2";
pub const JOINT_HOST_SUBSTRATE_CELL_SCHEMA_VERSION: &str =
    "visa.joint-handoff.host-substrate-cell.v2";
pub const JOINT_HOST_SUBSTRATE_AUTHENTICATION_SCHEME: &str =
    "visa-host-substrate-cell-sha256-v1-same-boot-reference-only";
/// Deterministic checksum scheme used only by the bounded reference artifact.
/// It is independently recomputable and is not a signature, MAC, or production
/// native-receipt authentication mechanism.
pub const JOINT_REFERENCE_AUTHENTICATION_SCHEME: &str =
    "visa-reference-sha256-v1-not-cryptographic";
pub const JOINT_UNPUBLISHED_BUNDLE_ID: &str = "unpublished";
pub const JOINT_VISA_REPOSITORY: &str = "https://github.com/chenty2333/vISA";
pub const JOINT_NEXUS_REPOSITORY: &str = "https://github.com/chenty2333/Nexus";
pub const JOINT_NEUTRAL_REPOSITORY: &str = "https://github.com/chenty2333/visa-nexus-handoff";

// Updated only after an explicit case ID, terminal, and assertion review.
// The verifier recomputes the catalog digest and requires both values to match.
pub const JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256: &str =
    "4bc9c66bd88659a59407e1d296d8df101c0ada14598e759c66713583501d7485";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointReferenceCellReport {
    pub schema_version: String,
    pub fixed_case_count: usize,
    pub scenario_count: usize,
    pub all_passed: bool,
    pub ownership_effect_peers_observed: bool,
    pub runtime_projection_observed: bool,
    pub visa_reference_mode: String,
    pub traces: Vec<JointReferenceCellTrace>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointDurableProjectionCellReport {
    pub schema: String,
    pub key: JointHandoffKey,
    pub issuer_set: JointIssuerSet,
    pub pre_reopen: JointDurableProjectionTranscript,
    pub post_reopen: JointDurableProjectionTranscript,
    pub abort_probe: JointDurableAbortProbe,
    pub execution_observation: JointDurableExecutionObservation,
    pub record_count: u64,
    pub recovered_phase: String,
    pub recovered_authentication_count: u64,
    pub abort_probe_authentication_count: u64,
    pub unknown_effect_freeze_retained: bool,
    pub abort_blocked_while_unknown: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointDurableProjectionTranscript {
    pub head: JointProjectionLogHead,
    pub canonical_record_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointDurableAbortProbe {
    pub command: Identity,
    pub request_bytes: Vec<u8>,
    pub envelope_bytes: Vec<u8>,
    pub payload_bytes: Vec<u8>,
    pub claimed_rejection: String,
    pub head_before: JointProjectionLogHead,
    pub head_after: JointProjectionLogHead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointDurableExecutionObservation {
    pub backend: String,
    pub close_observed: bool,
    pub reopen_observed: bool,
    pub same_boot_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProjectionLogVersion {
    pub major: u16,
    pub minor: u16,
}

impl JointProjectionLogVersion {
    pub const V1: Self = Self { major: 1, minor: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProjectionLogHead {
    pub version: JointProjectionLogVersion,
    pub key: JointHandoffKey,
    pub issuer_set_digest: Digest,
    pub sequence: u64,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostSubstrateCellReport {
    pub schema: String,
    pub lifecycle: Vec<String>,
    pub receipt_chain: Vec<String>,
    pub authenticated_receipt_count: usize,
    pub joint_phase: String,
    pub source_reopened: bool,
    pub source_phase: String,
    pub source_activation: String,
    pub source_owner_is_destination: bool,
    pub destination_phase: String,
    pub destination_activation: String,
    pub destination_owner_is_destination: bool,
    pub source_component_generation: u64,
    pub destination_component_generation: u64,
    pub source_journal_position: JournalPosition,
    pub destination_journal_position: JournalPosition,
    pub source_state_digest: Digest,
    pub destination_state_digest: Digest,
    pub snapshot_integrity: Digest,
    pub prepared_destination_digest: Digest,
    pub lease_commit_request_digest: Digest,
    pub independent_source_destination_databases: bool,
    pub same_boot_only: bool,
    pub exclusive_trusted_coordinator_api: bool,
    pub authentication_scheme: String,
    pub authentication_key: [u8; 32],
    pub native_receipts: Vec<JointHostNativeReceiptMaterial>,
    pub source_initial_state: CanonicalState,
    pub snapshot: SnapshotEnvelope,
    pub snapshot_cursor: JournalPosition,
    pub destination_restored_state: CanonicalState,
    pub source_terminal_state: CanonicalState,
    pub destination_terminal_state: CanonicalState,
    pub source_journal: Vec<JournalEntry>,
    pub destination_journal: Vec<JournalEntry>,
    pub source_leases: Vec<JointHostLeaseRecordMaterial>,
    pub destination_leases: Vec<JointHostLeaseRecordMaterial>,
    pub durable_projection: JointHostDurableProjectionEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostNativeReceiptMaterial {
    pub kind: String,
    pub issuance_request: Vec<u8>,
    pub peer_invocation: Option<Vec<u8>>,
    pub envelope: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostLeaseRecordMaterial {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostProjectionTranscript {
    pub head: JointProjectionLogHead,
    pub canonical_record_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostProjectionWindowObservation {
    pub conflict_head_before: JointProjectionLogHead,
    pub conflict_head_after: JointProjectionLogHead,
    pub attempt_head: JointProjectionLogHead,
    pub reopened_attempt_head: JointProjectionLogHead,
    pub completion_head: JointProjectionLogHead,
    pub reopened_completion_head: JointProjectionLogHead,
    pub local_before_position: JournalPosition,
    pub local_before_digest: Digest,
    pub local_after_position: JournalPosition,
    pub local_after_digest: Digest,
    pub reopened_local_after_position: JournalPosition,
    pub reopened_local_after_digest: Digest,
    pub conflicts_left_local_unchanged: bool,
    pub completion_append_ack_lost: bool,
    pub exposure_blocked_before_completion: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostAbortProjectionEvidence {
    pub transcript: JointHostProjectionTranscript,
    pub observation: JointHostProjectionWindowObservation,
    pub issuer_set: JointIssuerSet,
    pub authentication_key: [u8; 32],
    pub native_receipts: Vec<JointHostNativeReceiptMaterial>,
    pub initial_state: CanonicalState,
    pub terminal_state: CanonicalState,
    pub journal: Vec<JournalEntry>,
    pub leases: Vec<JointHostLeaseRecordMaterial>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostDurableProjectionEvidence {
    pub commit_transcript: JointHostProjectionTranscript,
    pub source_abort: JointHostAbortProjectionEvidence,
    pub source_fence: JointHostProjectionWindowObservation,
    pub destination_activation: JointHostProjectionWindowObservation,
    pub destination_checkpoint: JointHostDestinationActivationCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHostDestinationActivationCheckpoint {
    pub joint_completion_head: JointProjectionLogHead,
    pub activation_completion_record_digest: Digest,
    pub local_state: CanonicalState,
    pub local_journal: Vec<JournalEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointReferenceCellTrace {
    pub case_id: String,
    pub handoff: Identity,
    pub ownership_log_id: Identity,
    pub effect_log_id: Identity,
    pub events: Vec<JointReferenceCellEvent>,
    pub terminal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointReferenceCellEvent {
    pub step: String,
    pub outcome: String,
    pub receipt_kind: Option<String>,
    pub receipt: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_record: Option<JointEffectRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl JointProtocolVersion {
    pub const V1: Self = Self { major: 1, minor: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHandoffKey {
    pub continuity_unit: EntityRef,
    pub handoff: Identity,
    pub source: NodeIdentity,
    pub destination: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub next_epoch: LeaseEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipVersion {
    pub service_id: Identity,
    pub service_incarnation: Identity,
    pub log_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScopeVersion {
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptKind {
    PrepareIntent,
    VisaFreeze,
    NexusFreeze,
    DestinationPrepared,
    OwnershipPrepared,
    OwnershipAbort,
    OwnershipCommit,
    NexusThaw,
    ClosureProgress,
    Closure,
    RetainedTombstone,
    VisaSourceFence,
    VisaSourceResume,
    VisaDestinationActivation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIssuerRole {
    Ownership,
    VisaSource,
    VisaDestination,
    EffectClosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIssuerIdentity {
    pub issuer: Identity,
    pub issuer_incarnation: Identity,
    pub key_id: Identity,
    pub log_id: Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointIssuerSet {
    pub ownership: ReceiptIssuerIdentity,
    pub visa_source: ReceiptIssuerIdentity,
    pub visa_destination: ReceiptIssuerIdentity,
    pub effect_closure: ReceiptIssuerIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptHeader {
    pub version: JointProtocolVersion,
    pub kind: ReceiptKind,
    pub issuer: Identity,
    pub issuer_incarnation: Identity,
    pub key_id: Identity,
    pub log_id: Identity,
    pub sequence: u64,
    pub previous_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRef {
    pub version: JointProtocolVersion,
    pub kind: ReceiptKind,
    pub handoff: Identity,
    pub issuer: Identity,
    pub issuer_incarnation: Identity,
    pub key_id: Identity,
    pub log_id: Identity,
    pub sequence: u64,
    pub digest: Digest,
}

/// Independent mirror of the response-derived receipt issuance/authentication
/// binding. It is not an ownership/effect peer invocation; those are retained
/// separately as `peer_invocation` bytes in HostSubstrate evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRequest {
    pub version: JointProtocolVersion,
    pub kind: ReceiptKind,
    pub key: JointHandoffKey,
    pub operation: Identity,
    pub expected_state_sequence: u64,
    pub expected_previous_receipt_digest: Option<Digest>,
    pub parameters: ReceiptRequestParameters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRequestBinding {
    pub version: JointProtocolVersion,
    pub kind: ReceiptKind,
    pub key: JointHandoffKey,
    pub operation: Identity,
    pub expected_state_sequence: u64,
    pub expected_previous_receipt_digest: Option<Digest>,
    pub parameters_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptRequestParameters {
    PrepareIntent {
        ownership_service: Identity,
        service_incarnation: Identity,
        reservation: Identity,
        intent_revision: u64,
        service_request_digest: Digest,
    },
    VisaFreeze {
        intent: ReceiptRef,
    },
    NexusFreeze {
        intent: ReceiptRef,
        registry_instance: Identity,
        scope_id: Identity,
        scope_generation: u64,
        authority_epoch: u64,
        freeze_generation: u64,
        domain_bindings_digest: Digest,
        effect_cohort_digest: Digest,
    },
    DestinationPrepared {
        intent: ReceiptRef,
        visa_freeze: ReceiptRef,
        nexus_freeze: ReceiptRef,
        snapshot: SnapshotBinding,
        joint_mapping_manifest_digest: Digest,
        lease_commit_operation: Identity,
        lease_commit_idempotency: IdempotencyKey,
        lease_commit_request_digest: Digest,
    },
    OwnershipPrepared {
        reservation: Identity,
        intent: ReceiptRef,
        visa_freeze: ReceiptRef,
        nexus_freeze: ReceiptRef,
        destination_prepared: ReceiptRef,
        bindings: Box<PreparedBindings>,
        prepared_revision: u64,
    },
    OwnershipAbort {
        reservation: Identity,
        basis: ReceiptRef,
        basis_revision: u64,
        decision_sequence: u64,
    },
    OwnershipCommit {
        reservation: Identity,
        prepared: ReceiptRef,
        prepared_revision: u64,
        decision_sequence: u64,
    },
    NexusThaw {
        abort: ReceiptRef,
        nexus_freeze: ReceiptRef,
        thaw_generation: u64,
    },
    ClosureProgress {
        commit: ReceiptRef,
        nexus_freeze: ReceiptRef,
        closure_revision: u64,
    },
    Closure {
        commit: ReceiptRef,
        nexus_freeze: ReceiptRef,
        closure_revision: u64,
        effect_manifest_digest: Digest,
        closed_authority_epoch: u64,
    },
    RetainedTombstone {
        commit: ReceiptRef,
        nexus_freeze: ReceiptRef,
        closure_revision: u64,
    },
    VisaSourceFence {
        commit: ReceiptRef,
        closure: ReceiptRef,
    },
    VisaSourceResume {
        abort: ReceiptRef,
        thaw: Option<ReceiptRef>,
    },
    VisaDestinationActivation {
        commit: ReceiptRef,
        closure: ReceiptRef,
        source_fence: ReceiptRef,
        activation_command: Identity,
        resume_command: Identity,
        activation_attempt_record_digest: Digest,
    },
}

impl ReceiptRequestParameters {
    pub const fn kind(&self) -> ReceiptKind {
        match self {
            Self::PrepareIntent { .. } => ReceiptKind::PrepareIntent,
            Self::VisaFreeze { .. } => ReceiptKind::VisaFreeze,
            Self::NexusFreeze { .. } => ReceiptKind::NexusFreeze,
            Self::DestinationPrepared { .. } => ReceiptKind::DestinationPrepared,
            Self::OwnershipPrepared { .. } => ReceiptKind::OwnershipPrepared,
            Self::OwnershipAbort { .. } => ReceiptKind::OwnershipAbort,
            Self::OwnershipCommit { .. } => ReceiptKind::OwnershipCommit,
            Self::NexusThaw { .. } => ReceiptKind::NexusThaw,
            Self::ClosureProgress { .. } => ReceiptKind::ClosureProgress,
            Self::Closure { .. } => ReceiptKind::Closure,
            Self::RetainedTombstone { .. } => ReceiptKind::RetainedTombstone,
            Self::VisaSourceFence { .. } => ReceiptKind::VisaSourceFence,
            Self::VisaSourceResume { .. } => ReceiptKind::VisaSourceResume,
            Self::VisaDestinationActivation { .. } => ReceiptKind::VisaDestinationActivation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    pub schema: JointProtocolVersion,
    pub issuer: Identity,
    pub issuer_incarnation: Identity,
    pub kind: ReceiptKind,
    pub handoff: Identity,
    pub request_digest: Digest,
    pub state_sequence: u64,
    pub payload_digest: Digest,
    pub previous_receipt_digest: Option<Digest>,
    /// `JOINT_REFERENCE_AUTHENTICATION_SCHEME || sha256(projection)` in the
    /// reference artifact. Production adapters must replace this with their
    /// pinned native verifier and must never treat these bytes as a signature.
    pub authentication: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareIntentReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub ownership_service: Identity,
    pub service_incarnation: Identity,
    pub reservation: Identity,
    pub intent_revision: u64,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisaFreezeReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub intent: ReceiptRef,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
    pub portable_state_digest: Digest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationCounts {
    pub registered: u64,
    pub committed: u64,
    pub aborted: u64,
    pub unresolved: u64,
    pub tombstones: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeDisposition {
    ReadyToCommit,
    Blocked { blocker_digest: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusFreezeReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub intent: ReceiptRef,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub domain_bindings_digest: Digest,
    pub effect_cohort_digest: Digest,
    pub classification_root: Digest,
    pub counts: ClassificationCounts,
    pub disposition: FreezeDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBinding {
    pub snapshot: Identity,
    pub integrity: Digest,
    pub body_digest: Digest,
    pub source_journal_position: JournalPosition,
    pub component_digest: Digest,
    pub profile_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationPreparedReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub intent: ReceiptRef,
    pub visa_freeze: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub snapshot: SnapshotBinding,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
    pub prepared_destination_digest: Digest,
    pub authorities_digest: Digest,
    pub bindings_digest: Digest,
    pub joint_mapping_manifest_digest: Digest,
    pub lease_commit_operation: Identity,
    pub lease_commit_idempotency: IdempotencyKey,
    pub lease_commit_request_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipPreparedReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub intent: ReceiptRef,
    pub visa_freeze: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub destination_prepared: ReceiptRef,
    pub bindings: PreparedBindings,
    pub prepared_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipAbortReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub basis: ReceiptRef,
    pub basis_revision: u64,
    pub decision_sequence: u64,
    pub non_equivocation_root: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipCommitReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub prepared: ReceiptRef,
    pub prepared_revision: u64,
    pub decision_sequence: u64,
    pub non_equivocation_root: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusThawReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub abort: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub thaw_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureProgressReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub commit: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub closure_revision: u64,
    pub remaining_effects: u64,
    pub retained_tombstones: u64,
    pub progress_root: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub commit: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub closure_revision: u64,
    pub effect_manifest_digest: Digest,
    pub closed_authority_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedTombstoneReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub commit: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub closure_revision: u64,
    pub tombstone_count: u64,
    pub tombstone_manifest_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisaSourceFenceReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub commit: ReceiptRef,
    pub closure: ReceiptRef,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisaSourceResumeReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub abort: ReceiptRef,
    pub thaw: Option<ReceiptRef>,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisaDestinationActivationReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub commit: ReceiptRef,
    pub closure: ReceiptRef,
    pub source_fence: ReceiptRef,
    pub activation_command: Identity,
    pub resume_command: Identity,
    pub activation_attempt_record_digest: Digest,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
}

pub type EffectFreezeReceipt = NexusFreezeReceipt;
pub type EffectThawReceipt = NexusThawReceipt;
pub type EffectClosureProgressReceipt = ClosureProgressReceipt;
pub type EffectClosureReceipt = ClosureReceipt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JointReceipt {
    PrepareIntent(PrepareIntentReceipt),
    VisaFreeze(VisaFreezeReceipt),
    EffectFreeze(EffectFreezeReceipt),
    DestinationPrepared(Box<DestinationPreparedReceipt>),
    OwnershipPrepared(Box<OwnershipPreparedReceipt>),
    OwnershipAbort(OwnershipAbortReceipt),
    OwnershipCommit(OwnershipCommitReceipt),
    EffectThaw(EffectThawReceipt),
    ClosureProgress(EffectClosureProgressReceipt),
    Closure(EffectClosureReceipt),
    RetainedTombstone(RetainedTombstoneReceipt),
    VisaSourceFence(VisaSourceFenceReceipt),
    VisaSourceResume(VisaSourceResumeReceipt),
    VisaDestinationActivation(VisaDestinationActivationReceipt),
}

impl JointReceipt {
    pub const fn kind(&self) -> ReceiptKind {
        match self {
            Self::PrepareIntent(_) => ReceiptKind::PrepareIntent,
            Self::VisaFreeze(_) => ReceiptKind::VisaFreeze,
            Self::EffectFreeze(_) => ReceiptKind::NexusFreeze,
            Self::DestinationPrepared(_) => ReceiptKind::DestinationPrepared,
            Self::OwnershipPrepared(_) => ReceiptKind::OwnershipPrepared,
            Self::OwnershipAbort(_) => ReceiptKind::OwnershipAbort,
            Self::OwnershipCommit(_) => ReceiptKind::OwnershipCommit,
            Self::EffectThaw(_) => ReceiptKind::NexusThaw,
            Self::ClosureProgress(_) => ReceiptKind::ClosureProgress,
            Self::Closure(_) => ReceiptKind::Closure,
            Self::RetainedTombstone(_) => ReceiptKind::RetainedTombstone,
            Self::VisaSourceFence(_) => ReceiptKind::VisaSourceFence,
            Self::VisaSourceResume(_) => ReceiptKind::VisaSourceResume,
            Self::VisaDestinationActivation(_) => ReceiptKind::VisaDestinationActivation,
        }
    }

    pub const fn header(&self) -> &ReceiptHeader {
        match self {
            Self::PrepareIntent(value) => &value.header,
            Self::VisaFreeze(value) => &value.header,
            Self::EffectFreeze(value) => &value.header,
            Self::DestinationPrepared(value) => &value.header,
            Self::OwnershipPrepared(value) => &value.header,
            Self::OwnershipAbort(value) => &value.header,
            Self::OwnershipCommit(value) => &value.header,
            Self::EffectThaw(value) => &value.header,
            Self::ClosureProgress(value) => &value.header,
            Self::Closure(value) => &value.header,
            Self::RetainedTombstone(value) => &value.header,
            Self::VisaSourceFence(value) => &value.header,
            Self::VisaSourceResume(value) => &value.header,
            Self::VisaDestinationActivation(value) => &value.header,
        }
    }

    pub const fn key(&self) -> JointHandoffKey {
        match self {
            Self::PrepareIntent(value) => value.key,
            Self::VisaFreeze(value) => value.key,
            Self::EffectFreeze(value) => value.key,
            Self::DestinationPrepared(value) => value.key,
            Self::OwnershipPrepared(value) => value.key,
            Self::OwnershipAbort(value) => value.key,
            Self::OwnershipCommit(value) => value.key,
            Self::EffectThaw(value) => value.key,
            Self::ClosureProgress(value) => value.key,
            Self::Closure(value) => value.key,
            Self::RetainedTombstone(value) => value.key,
            Self::VisaSourceFence(value) => value.key,
            Self::VisaSourceResume(value) => value.key,
            Self::VisaDestinationActivation(value) => value.key,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JointEffectClassification {
    Registered,
    Committed,
    Aborted,
    ResolvedTombstone,
    UnresolvedTombstone,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEffectRecord {
    pub effect: Identity,
    pub operation: Identity,
    pub domain: Identity,
    pub binding_generation: u64,
    pub classification: JointEffectClassification,
    pub outcome_digest: Option<Digest>,
    pub tombstone_digest: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEffectCohortManifest {
    pub schema_version: String,
    pub key: JointHandoffKey,
    pub effects: Vec<JointEffectRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointMappingManifest {
    pub version: JointProtocolVersion,
    pub key: JointHandoffKey,
    pub visa_operation_cohort_digest: Digest,
    pub effect_scope: EffectScopeVersion,
    pub effect_cohort_digest: Digest,
    pub domain_bindings_manifest_digest: Digest,
    pub ownership_service: OwnershipVersion,
    pub protocol_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBindings {
    pub prepare_intent_receipt_digest: Digest,
    pub visa_freeze_receipt_digest: Digest,
    pub effect_freeze_receipt_digest: Digest,
    pub snapshot: Identity,
    pub snapshot_integrity_digest: Digest,
    pub source_journal_position: JournalPosition,
    pub source_state_digest: Digest,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub destination_prepared_receipt_digest: Digest,
    pub destination_state_digest: Digest,
    pub prepared_authorities_digest: Digest,
    pub prepared_bindings_digest: Digest,
    pub effect_cohort_manifest_digest: Digest,
    pub joint_mapping_manifest_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointPreparedInput {
    pub snapshot: SnapshotBinding,
    pub destination_journal_position: JournalPosition,
    pub destination_state_digest: Digest,
    pub prepared_destination_digest: Digest,
    pub prepared_authorities_digest: Digest,
    pub prepared_bindings_digest: Digest,
    pub lease_commit_operation: Identity,
    pub lease_commit_idempotency: IdempotencyKey,
    pub lease_commit_request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JointActor {
    Coordinator,
    Source,
    Destination,
    OwnershipService,
    NexusService,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum JointExternalFault {
    DestinationPreparationFailed,
    CommitAcknowledgementLost { durable_commit: Box<OwnershipCommitObservation> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnershipQueryResult {
    Unavailable,
    Reserved,
    Prepared,
    AbortDecided { observation: OwnershipAbortObservation },
    CommitDecided { observation: OwnershipCommitObservation },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipAbortObservation {
    pub request: ReceiptRequest,
    pub envelope: ReceiptEnvelope,
    pub receipt: OwnershipAbortReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipCommitObservation {
    pub request: ReceiptRequest,
    pub envelope: ReceiptEnvelope,
    pub receipt: OwnershipCommitReceipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleRejection {
    UnsupportedVersion,
    InvalidIdentity,
    InvalidHandoffKey,
    InvalidReceiptHeader,
    InvalidReceiptKind,
    HandoffMismatch,
    IssuerMismatch,
    StaleIssuerIncarnation,
    StaleSequence,
    CausalChainMismatch,
    InvalidDigest,
    InvalidRevision,
    InvalidPhase,
    MissingPrerequisite,
    ReceiptMismatch,
    ConflictingReceipt,
    DecisionConflict,
    ClosureBlocked,
    EffectCohortMismatch,
    EffectGateClosed,
    StaleScope,
    StaleEpoch,
    StaleFreezeGeneration,
    CompetingDestination,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum JointRawEventKind {
    ReceiptAccepted {
        request: ReceiptRequest,
        envelope: ReceiptEnvelope,
        receipt: JointReceipt,
    },
    ReceiptRejected {
        request: ReceiptRequest,
        envelope: ReceiptEnvelope,
        receipt: JointReceipt,
        rejection: OracleRejection,
        state_before_sha256: String,
        state_after_sha256: String,
    },
    EffectPublication {
        record: JointEffectRecord,
        source_epoch: LeaseEpoch,
        scope_generation: u64,
        accepted: bool,
        rejection: Option<OracleRejection>,
    },
    OwnershipQuery {
        result: OwnershipQueryResult,
    },
    ExternalFault {
        fault: JointExternalFault,
        state_before_sha256: String,
        state_after_sha256: String,
    },
    ActorCrashed {
        actor: JointActor,
    },
    ActorRestarted {
        actor: JointActor,
    },
    NexusServiceRebound {
        previous: ReceiptIssuerIdentity,
        current: ReceiptIssuerIdentity,
        previous_scope: EffectScopeVersion,
        current_scope: EffectScopeVersion,
        domain_bindings_manifest_digest: Digest,
    },
    DestinationActivationStarted {
        commit: ReceiptRef,
        closure: ReceiptRef,
        activation_command: Identity,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointRawEvent {
    pub index: u64,
    pub event: JointRawEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointRawTrace {
    pub schema_version: String,
    pub case_id: String,
    pub protocol_version: JointProtocolVersion,
    pub key: JointHandoffKey,
    pub issuers: JointIssuerSet,
    pub initial_scope: EffectScopeVersion,
    pub mapping: JointMappingManifest,
    pub prepared_input: JointPreparedInput,
    pub events: Vec<JointRawEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JointTerminal {
    SourceActive,
    PreparedFrozen,
    CommitBlocked,
    DestinationActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JointAssertion {
    ReceiptChainRecomputed,
    EffectCohortRecomputed,
    FreezeSerializedPublication,
    DestinationPreparedBound,
    PreparedBindingsComplete,
    SingleTerminalDecision,
    UnknownDecisionRemainedFrozen,
    AbortAuthorizedThaw,
    CommitAuthorizedClosure,
    ClosurePrecededActivation,
    SourceFencedAfterCommit,
    StaleInputHadNoEffect,
    CrashRecoveryFailedClosed,
    UnresolvedTombstoneBlockedSeal,
    RebindRejectedStaleIssuer,
    SingleDestinationSelected,
    DuplicateReceiptIdempotent,
    ReorderedReceiptRejected,
    PrecommitAbortPreservedRegisteredEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JointCaseDefinition {
    pub id: &'static str,
    pub terminal: JointTerminal,
    pub required_assertions: &'static [JointAssertion],
}

pub const JOINT_HANDOFF_CASE_DEFINITIONS: &[JointCaseDefinition] = &[
    JointCaseDefinition {
        id: "freeze-wins-effect-commit",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::FreezeSerializedPublication,
            JointAssertion::ClosurePrecededActivation,
        ],
    },
    JointCaseDefinition {
        id: "effect-commit-wins-freeze",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::FreezeSerializedPublication,
            JointAssertion::EffectCohortRecomputed,
        ],
    },
    JointCaseDefinition {
        id: "destination-prepare-fails-abort-thaw",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[
            JointAssertion::AbortAuthorizedThaw,
            JointAssertion::StaleInputHadNoEffect,
        ],
    },
    JointCaseDefinition {
        id: "commit-ack-lost-query-close",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::UnknownDecisionRemainedFrozen,
            JointAssertion::CommitAuthorizedClosure,
        ],
    },
    JointCaseDefinition {
        id: "frozen-service-crash-rebind",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::CrashRecoveryFailedClosed,
            JointAssertion::RebindRejectedStaleIssuer,
        ],
    },
    JointCaseDefinition {
        id: "unresolved-tombstone-blocks-seal",
        terminal: JointTerminal::CommitBlocked,
        required_assertions: &[JointAssertion::UnresolvedTombstoneBlockedSeal],
    },
    JointCaseDefinition {
        id: "stale-token-scope-epoch-probes",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[JointAssertion::StaleInputHadNoEffect],
    },
    JointCaseDefinition {
        id: "abort-commit-race-abort-wins",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[
            JointAssertion::SingleTerminalDecision,
            JointAssertion::AbortAuthorizedThaw,
        ],
    },
    JointCaseDefinition {
        id: "abort-commit-race-commit-wins",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::SingleTerminalDecision,
            JointAssertion::CommitAuthorizedClosure,
        ],
    },
    JointCaseDefinition {
        id: "source-crash-after-commit-before-close",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::CrashRecoveryFailedClosed,
            JointAssertion::SourceFencedAfterCommit,
        ],
    },
    JointCaseDefinition {
        id: "destination-crash-before-activation",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::CrashRecoveryFailedClosed,
            JointAssertion::ClosurePrecededActivation,
        ],
    },
    JointCaseDefinition {
        id: "concurrent-two-destinations",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[JointAssertion::SingleDestinationSelected],
    },
    JointCaseDefinition {
        id: "crash-after-freeze-before-seal",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[
            JointAssertion::CrashRecoveryFailedClosed,
            JointAssertion::AbortAuthorizedThaw,
        ],
    },
    JointCaseDefinition {
        id: "stale-destination-prepared-receipt",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[
            JointAssertion::DestinationPreparedBound,
            JointAssertion::StaleInputHadNoEffect,
        ],
    },
    JointCaseDefinition {
        id: "duplicate-reordered-receipts",
        terminal: JointTerminal::DestinationActive,
        required_assertions: &[
            JointAssertion::DuplicateReceiptIdempotent,
            JointAssertion::ReorderedReceiptRejected,
            JointAssertion::ReceiptChainRecomputed,
        ],
    },
    JointCaseDefinition {
        id: "precommit-abort-preserves-uncommitted-effect",
        terminal: JointTerminal::SourceActive,
        required_assertions: &[JointAssertion::PrecommitAbortPreservedRegisteredEffect],
    },
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointCaseEvidence {
    pub case_id: String,
    pub trace_sha256: String,
    pub claimed_terminal: JointTerminal,
    pub claimed_assertions: Vec<JointAssertion>,
    pub trace: JointRawTrace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointSourceRevision {
    pub repository: String,
    pub git_sha: String,
    pub role: JointSourceRole,
    pub checkout_clean: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JointSourceRole {
    ExecutedCheckout,
    SourceLockOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEvidenceExpectations {
    pub visa_git_sha: String,
    pub nexus_git_sha: String,
    pub neutral_git_sha: String,
    pub neutral_tree: String,
    pub neutral_bundle_sha256: String,
    pub source_lock_sha256: String,
    pub protocol_schema_sha256: String,
    pub machine_contract_sha256: String,
    pub refinement_map_sha256: String,
    pub abstract_registry_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointTcbDeclaration {
    pub ownership_log_non_equivocating: bool,
    pub ownership_log_not_rolled_back: bool,
    pub native_receipt_verifiers_pinned: bool,
    pub exclusive_trusted_coordinator_api: bool,
    pub crash_stable_freeze_marker: bool,
    pub fail_closed_recovery: bool,
    pub same_boot_only: bool,
    pub hostile_storage_rollback_covered: bool,
    pub host_reboot_covered: bool,
    pub confidential_transport_covered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEvidenceBundle {
    pub schema_version: String,
    pub claim_id: String,
    pub bundle_id: String,
    pub source_lock_sha256: String,
    pub neutral_tree: String,
    pub neutral_bundle_sha256: String,
    pub registry_sha256: String,
    pub protocol_schema_sha256: String,
    pub machine_contract_sha256: String,
    pub refinement_map_sha256: String,
    pub abstract_registry_sha256: String,
    pub visa: JointSourceRevision,
    pub nexus: JointSourceRevision,
    pub neutral: JointSourceRevision,
    pub tcb: JointTcbDeclaration,
    /// Filled by the artifact publisher after the production replay and
    /// reference-cell report are serialized. In-memory prepublication bundles
    /// intentionally leave this unset.
    pub production_replay_sha256: Option<String>,
    pub cases: Vec<JointCaseEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointValidationFinding {
    pub code: String,
    pub case_id: Option<String>,
    pub event_index: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointValidationReport {
    pub ok: bool,
    pub findings: Vec<JointValidationFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointEvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<JointEvidenceLoadError>,
    pub validation: Option<JointValidationReport>,
}
