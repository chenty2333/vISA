use alloc::{boxed::Box, vec::Vec};

pub use contract_core::{
    Digest, EntityRef, IdempotencyKey, Identity, JournalPosition, LeaseEpoch, NodeIdentity,
};
use serde::{Deserialize, Serialize};

use crate::{EncodeError, canonical_digest, receipt_digest, receipt_request_digest};

pub const JOINT_PROTOCOL_VERSION: JointProtocolVersion = JointProtocolVersion::new(1, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl JointProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn is_supported(self) -> bool {
        self.major == JOINT_PROTOCOL_VERSION.major && self.minor == JOINT_PROTOCOL_VERSION.minor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointHandoffKey {
    pub continuity_unit: EntityRef,
    pub handoff: Identity,
    pub source: NodeIdentity,
    pub destination: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub next_epoch: LeaseEpoch,
}

impl JointHandoffKey {
    pub fn is_well_formed(self) -> bool {
        !self.continuity_unit.identity.is_zero()
            && !self.handoff.is_zero()
            && !self.source.is_zero()
            && !self.destination.is_zero()
            && self.source != self.destination
            && self.expected_epoch.next() == Some(self.next_epoch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptKind {
    PrepareIntent = 0,
    VisaFreeze = 1,
    NexusFreeze = 2,
    DestinationPrepared = 3,
    OwnershipPrepared = 4,
    OwnershipAbort = 5,
    OwnershipCommit = 6,
    NexusThaw = 7,
    ClosureProgress = 8,
    Closure = 9,
    RetainedTombstone = 10,
    VisaSourceFence = 11,
    VisaSourceResume = 12,
    VisaDestinationActivation = 13,
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

/// Response-derived binding retained for receipt issuance and authentication.
/// It names the completion operation, expected issuer state, and typed receipt
/// inputs, while response observations remain in the receipt payload.
///
/// This is not the request sent to an ownership or effect peer. Qualification
/// of a real peer call requires separately retained canonical pre-call
/// invocation bytes; [`ReceiptRequest::for_receipt`] cannot provide that proof.
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

impl ReceiptRequest {
    /// Derive the receipt-issuance/authentication binding from a completed
    /// typed response. This helper must not be used as peer-invocation evidence.
    pub fn for_receipt<T: TypedReceipt>(operation: Identity, receipt: &T) -> Self {
        let header = receipt.header();
        Self {
            version: header.version,
            kind: T::KIND,
            key: receipt.key(),
            operation,
            expected_state_sequence: header.sequence,
            expected_previous_receipt_digest: header.previous_digest,
            parameters: receipt.request_parameters(),
        }
    }

    pub fn matches<T: TypedReceipt>(&self, receipt: &T) -> bool {
        let header = receipt.header();
        self.version == header.version
            && self.version.is_supported()
            && self.kind == T::KIND
            && self.key == receipt.key()
            && !self.operation.is_zero()
            && self.expected_state_sequence == header.sequence
            && self.expected_previous_receipt_digest == header.previous_digest
            && self.parameters == receipt.request_parameters()
            && self.parameters.kind() == self.kind
    }

    pub fn digest(&self) -> Result<Digest, EncodeError> {
        receipt_request_digest(self)
    }
}

/// The exact compact issuance projection covered by
/// `ReceiptEnvelope.request_digest`.
/// `parameters_digest` is separately domain bound so the envelope commits to
/// typed request parameters without treating response bytes as a request.
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

/// Native receipt envelope retained and authenticated by an issuer-specific
/// verifier. The reducer consumes the strictly decoded typed payload only
/// after this envelope has been checked by the integration layer.
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
    pub authentication: Vec<u8>,
}

impl ReceiptEnvelope {
    pub fn matches<T: TypedReceipt>(&self, payload: &T) -> Result<bool, EncodeError> {
        let header = payload.header();
        Ok(self.schema == header.version
            && self.schema.is_supported()
            && self.issuer == header.issuer
            && self.issuer_incarnation == header.issuer_incarnation
            && self.kind == T::KIND
            && self.handoff == payload.key().handoff
            && self.state_sequence == header.sequence
            && self.previous_receipt_digest == header.previous_digest
            && nonzero_digest(self.request_digest)
            && self.payload_digest == canonical_digest(payload)?
            && !self.authentication.is_empty())
    }

    pub fn matches_request<T: TypedReceipt>(
        &self,
        request: &ReceiptRequest,
        payload: &T,
    ) -> Result<bool, EncodeError> {
        Ok(self.matches(payload)?
            && request.matches(payload)
            && self.request_digest == request.digest()?)
    }
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

/// Exact immutable values sealed by the ownership service at PreparedFrozen.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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

pub trait TypedReceipt: Serialize {
    const KIND: ReceiptKind;

    fn header(&self) -> &ReceiptHeader;
    fn key(&self) -> JointHandoffKey;
    fn request_parameters(&self) -> ReceiptRequestParameters;

    fn receipt_ref(&self) -> Result<ReceiptRef, EncodeError> {
        let header = self.header();
        Ok(ReceiptRef {
            version: header.version,
            kind: Self::KIND,
            handoff: self.key().handoff,
            issuer: header.issuer,
            issuer_incarnation: header.issuer_incarnation,
            key_id: header.key_id,
            log_id: header.log_id,
            sequence: header.sequence,
            digest: receipt_digest(Self::KIND, self)?,
        })
    }
}

macro_rules! impl_typed_receipt {
    ($type:ty, $kind:ident, |$value:ident| $parameters:expr) => {
        impl TypedReceipt for $type {
            const KIND: ReceiptKind = ReceiptKind::$kind;

            fn header(&self) -> &ReceiptHeader {
                &self.header
            }

            fn key(&self) -> JointHandoffKey {
                self.key
            }

            fn request_parameters(&self) -> ReceiptRequestParameters {
                let $value = self;
                $parameters
            }
        }
    };
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
impl_typed_receipt!(PrepareIntentReceipt, PrepareIntent, |value| {
    ReceiptRequestParameters::PrepareIntent {
        ownership_service: value.ownership_service,
        service_incarnation: value.service_incarnation,
        reservation: value.reservation,
        intent_revision: value.intent_revision,
        service_request_digest: value.request_digest,
    }
});

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
impl_typed_receipt!(VisaFreezeReceipt, VisaFreeze, |value| {
    ReceiptRequestParameters::VisaFreeze { intent: value.intent }
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationCounts {
    pub registered: u64,
    pub committed: u64,
    pub aborted: u64,
    pub unresolved: u64,
    pub tombstones: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
impl_typed_receipt!(NexusFreezeReceipt, NexusFreeze, |value| {
    ReceiptRequestParameters::NexusFreeze {
        intent: value.intent,
        registry_instance: value.registry_instance,
        scope_id: value.scope_id,
        scope_generation: value.scope_generation,
        authority_epoch: value.authority_epoch,
        freeze_generation: value.freeze_generation,
        domain_bindings_digest: value.domain_bindings_digest,
        effect_cohort_digest: value.effect_cohort_digest,
    }
});

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
impl_typed_receipt!(DestinationPreparedReceipt, DestinationPrepared, |value| {
    ReceiptRequestParameters::DestinationPrepared {
        intent: value.intent,
        visa_freeze: value.visa_freeze,
        nexus_freeze: value.nexus_freeze,
        snapshot: value.snapshot,
        joint_mapping_manifest_digest: value.joint_mapping_manifest_digest,
        lease_commit_operation: value.lease_commit_operation,
        lease_commit_idempotency: value.lease_commit_idempotency,
        lease_commit_request_digest: value.lease_commit_request_digest,
    }
});

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
impl_typed_receipt!(OwnershipPreparedReceipt, OwnershipPrepared, |value| {
    ReceiptRequestParameters::OwnershipPrepared {
        reservation: value.reservation,
        intent: value.intent,
        visa_freeze: value.visa_freeze,
        nexus_freeze: value.nexus_freeze,
        destination_prepared: value.destination_prepared,
        bindings: Box::new(value.bindings),
        prepared_revision: value.prepared_revision,
    }
});

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
impl_typed_receipt!(OwnershipAbortReceipt, OwnershipAbort, |value| {
    ReceiptRequestParameters::OwnershipAbort {
        reservation: value.reservation,
        basis: value.basis,
        basis_revision: value.basis_revision,
        decision_sequence: value.decision_sequence,
    }
});

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
impl_typed_receipt!(OwnershipCommitReceipt, OwnershipCommit, |value| {
    ReceiptRequestParameters::OwnershipCommit {
        reservation: value.reservation,
        prepared: value.prepared,
        prepared_revision: value.prepared_revision,
        decision_sequence: value.decision_sequence,
    }
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusThawReceipt {
    pub header: ReceiptHeader,
    pub key: JointHandoffKey,
    pub abort: ReceiptRef,
    pub nexus_freeze: ReceiptRef,
    pub thaw_generation: u64,
}
impl_typed_receipt!(NexusThawReceipt, NexusThaw, |value| {
    ReceiptRequestParameters::NexusThaw {
        abort: value.abort,
        nexus_freeze: value.nexus_freeze,
        thaw_generation: value.thaw_generation,
    }
});

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
impl_typed_receipt!(ClosureProgressReceipt, ClosureProgress, |value| {
    ReceiptRequestParameters::ClosureProgress {
        commit: value.commit,
        nexus_freeze: value.nexus_freeze,
        closure_revision: value.closure_revision,
    }
});

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
impl_typed_receipt!(ClosureReceipt, Closure, |value| {
    ReceiptRequestParameters::Closure {
        commit: value.commit,
        nexus_freeze: value.nexus_freeze,
        closure_revision: value.closure_revision,
        effect_manifest_digest: value.effect_manifest_digest,
        closed_authority_epoch: value.closed_authority_epoch,
    }
});

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
impl_typed_receipt!(RetainedTombstoneReceipt, RetainedTombstone, |value| {
    ReceiptRequestParameters::RetainedTombstone {
        commit: value.commit,
        nexus_freeze: value.nexus_freeze,
        closure_revision: value.closure_revision,
    }
});

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
impl_typed_receipt!(VisaSourceFenceReceipt, VisaSourceFence, |value| {
    ReceiptRequestParameters::VisaSourceFence { commit: value.commit, closure: value.closure }
});

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
impl_typed_receipt!(VisaSourceResumeReceipt, VisaSourceResume, |value| {
    ReceiptRequestParameters::VisaSourceResume { abort: value.abort, thaw: value.thaw }
});

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
impl_typed_receipt!(VisaDestinationActivationReceipt, VisaDestinationActivation, |value| {
    ReceiptRequestParameters::VisaDestinationActivation {
        commit: value.commit,
        closure: value.closure,
        source_fence: value.source_fence,
        activation_command: value.activation_command,
        resume_command: value.resume_command,
        activation_attempt_record_digest: value.activation_attempt_record_digest,
    }
});

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JointPhase {
    SourceOwned,
    PrepareIntent,
    FrozenUnsealed,
    PreparedFrozen,
    AbortDecided,
    SourceThawPending,
    SourceActive,
    CommitDecided,
    ClosurePending,
    SourceClosed,
    DestinationActivationPending,
    DestinationActive,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnershipDecision {
    Undecided,
    Abort(ReceiptRef),
    Commit(ReceiptRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosureStatus {
    NotStarted,
    Pending { receipt: ReceiptRef, revision: u64 },
    Closed { receipt: ReceiptRef, revision: u64 },
    RetainedTombstone { receipt: ReceiptRef, revision: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointState {
    pub version: JointProtocolVersion,
    pub key: JointHandoffKey,
    pub revision: u64,
    pub phase: JointPhase,
    pub reservation: Option<Identity>,
    pub intent: Option<ReceiptRef>,
    pub intent_revision: Option<u64>,
    pub visa_freeze: Option<ReceiptRef>,
    pub source_journal_position: Option<JournalPosition>,
    pub source_state_digest: Option<Digest>,
    pub nexus_freeze: Option<ReceiptRef>,
    pub effect_cohort_digest: Option<Digest>,
    pub freeze_disposition: Option<FreezeDisposition>,
    pub freeze_counts: Option<ClassificationCounts>,
    pub destination_prepared: Option<ReceiptRef>,
    pub pending_bindings: Option<PreparedBindings>,
    pub prepared: Option<ReceiptRef>,
    pub prepared_revision: Option<u64>,
    pub decision: OwnershipDecision,
    pub thaw: Option<ReceiptRef>,
    pub closure: ClosureStatus,
    pub source_fence: Option<ReceiptRef>,
    pub source_resume: Option<ReceiptRef>,
    pub destination_activation_command: Option<Identity>,
    pub destination_activation: Option<ReceiptRef>,
}

impl JointState {
    pub fn new(key: JointHandoffKey) -> Result<Self, Rejection> {
        if !key.is_well_formed() {
            return Err(Rejection::InvalidHandoffKey);
        }
        Ok(Self {
            version: JOINT_PROTOCOL_VERSION,
            key,
            revision: 0,
            phase: JointPhase::SourceOwned,
            reservation: None,
            intent: None,
            intent_revision: None,
            visa_freeze: None,
            source_journal_position: None,
            source_state_digest: None,
            nexus_freeze: None,
            effect_cohort_digest: None,
            freeze_disposition: None,
            freeze_counts: None,
            destination_prepared: None,
            pending_bindings: None,
            prepared: None,
            prepared_revision: None,
            decision: OwnershipDecision::Undecided,
            thaw: None,
            closure: ClosureStatus::NotStarted,
            source_fence: None,
            source_resume: None,
            destination_activation_command: None,
            destination_activation: None,
        })
    }
}

pub type JointProjectionState = JointState;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub version: JointProtocolVersion,
    pub identity: Identity,
    pub kind: CommandKind,
}

impl Command {
    pub const fn new(identity: Identity, kind: CommandKind) -> Self {
        Self { version: JOINT_PROTOCOL_VERSION, identity, kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandKind {
    RecordPrepareIntent(PrepareIntentReceipt),
    RecordVisaFreeze(VisaFreezeReceipt),
    RecordNexusFreeze(NexusFreezeReceipt),
    RecordDestinationPrepared(Box<DestinationPreparedReceipt>),
    SealPreparedFrozen(Box<OwnershipPreparedReceipt>),
    RecordAbortDecision(OwnershipAbortReceipt),
    RecordThaw(NexusThawReceipt),
    RecordSourceResume(VisaSourceResumeReceipt),
    RecordCommitDecision(OwnershipCommitReceipt),
    RecordClosureProgress(ClosureProgressReceipt),
    RecordClosure(ClosureReceipt),
    RecordRetainedTombstone(RetainedTombstoneReceipt),
    RecordSourceFence(VisaSourceFenceReceipt),
    BeginDestinationActivation { commit: ReceiptRef, closure: ReceiptRef },
    RecordDestinationActivation(VisaDestinationActivationReceipt),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: JointProtocolVersion,
    pub identity: Identity,
    pub kind: EventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    PrepareIntentRecorded(PrepareIntentReceipt),
    VisaFreezeRecorded(VisaFreezeReceipt),
    NexusFreezeRecorded(NexusFreezeReceipt),
    DestinationPreparedRecorded(Box<DestinationPreparedReceipt>),
    PreparedFrozenSealed(Box<OwnershipPreparedReceipt>),
    AbortDecisionRecorded(OwnershipAbortReceipt),
    ThawRecorded(NexusThawReceipt),
    SourceResumeRecorded(VisaSourceResumeReceipt),
    CommitDecisionRecorded(OwnershipCommitReceipt),
    ClosureProgressRecorded(ClosureProgressReceipt),
    ClosureRecorded(ClosureReceipt),
    RetainedTombstoneRecorded(RetainedTombstoneReceipt),
    SourceFenceRecorded(VisaSourceFenceReceipt),
    DestinationActivationStarted { commit: ReceiptRef, closure: ReceiptRef },
    DestinationActivationRecorded(VisaDestinationActivationReceipt),
}

impl From<CommandKind> for EventKind {
    fn from(value: CommandKind) -> Self {
        match value {
            CommandKind::RecordPrepareIntent(value) => Self::PrepareIntentRecorded(value),
            CommandKind::RecordVisaFreeze(value) => Self::VisaFreezeRecorded(value),
            CommandKind::RecordNexusFreeze(value) => Self::NexusFreezeRecorded(value),
            CommandKind::RecordDestinationPrepared(value) => {
                Self::DestinationPreparedRecorded(value)
            }
            CommandKind::SealPreparedFrozen(value) => Self::PreparedFrozenSealed(value),
            CommandKind::RecordAbortDecision(value) => Self::AbortDecisionRecorded(value),
            CommandKind::RecordThaw(value) => Self::ThawRecorded(value),
            CommandKind::RecordSourceResume(value) => Self::SourceResumeRecorded(value),
            CommandKind::RecordCommitDecision(value) => Self::CommitDecisionRecorded(value),
            CommandKind::RecordClosureProgress(value) => Self::ClosureProgressRecorded(value),
            CommandKind::RecordClosure(value) => Self::ClosureRecorded(value),
            CommandKind::RecordRetainedTombstone(value) => Self::RetainedTombstoneRecorded(value),
            CommandKind::RecordSourceFence(value) => Self::SourceFenceRecorded(value),
            CommandKind::BeginDestinationActivation { commit, closure } => {
                Self::DestinationActivationStarted { commit, closure }
            }
            CommandKind::RecordDestinationActivation(value) => {
                Self::DestinationActivationRecorded(value)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Replay {
    NoChange,
    Receipt(ReceiptRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Commit(Box<Event>),
    Replay(Replay),
    Reject(Rejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    Applied(JointState),
    Replay(JointState, Replay),
}

impl ApplyResult {
    pub fn state(&self) -> &JointState {
        match self {
            Self::Applied(state) | Self::Replay(state, _) => state,
        }
    }

    pub fn into_state(self) -> JointState {
        match self {
            Self::Applied(state) | Self::Replay(state, _) => state,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Rejection {
    UnsupportedVersion,
    InvalidIdentity,
    InvalidHandoffKey,
    InvalidReceiptHeader,
    InvalidReceiptKind,
    HandoffMismatch,
    InvalidDigest,
    InvalidRevision,
    RevisionExhausted,
    InvalidPhase { actual: JointPhase },
    MissingPrerequisite,
    ReceiptMismatch,
    ConflictingReceipt,
    DecisionConflict,
    StaleRevision,
    ClosureBlocked,
    EventNotApplicable,
    Encoding,
}

pub(crate) fn nonzero_digest(digest: Digest) -> bool {
    digest != Digest::ZERO
}

pub(crate) fn valid_header(header: &ReceiptHeader, expected: ReceiptKind) -> bool {
    header.version.is_supported()
        && header.kind == expected
        && !header.issuer.is_zero()
        && !header.issuer_incarnation.is_zero()
        && !header.key_id.is_zero()
        && !header.log_id.is_zero()
        && header.sequence > 0
        && header.previous_digest.is_none_or(nonzero_digest)
}

pub(crate) fn receipt_reference<T: TypedReceipt>(receipt: &T) -> Result<ReceiptRef, Rejection> {
    if !valid_header(receipt.header(), T::KIND) {
        return Err(Rejection::InvalidReceiptHeader);
    }
    receipt.receipt_ref().map_err(|_| Rejection::Encoding)
}

pub(crate) fn refs_are_distinct(refs: &[ReceiptRef]) -> bool {
    refs.iter().enumerate().all(|(index, item)| refs[..index].iter().all(|other| other != item))
}

pub(crate) fn all_digests_nonzero(digests: &[Digest]) -> bool {
    digests.iter().copied().all(nonzero_digest)
}

pub(crate) fn no_duplicate_receipts(receipts: Vec<ReceiptRef>) -> bool {
    refs_are_distinct(&receipts)
}
