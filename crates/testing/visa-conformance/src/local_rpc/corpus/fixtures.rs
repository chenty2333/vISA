use serde::Serialize;
use visa_local_rpc::common::{
    AgentBinding, AgentRole, ArtifactRoot, AuthorityRole, AuthorityServiceBinding, BootId,
    CanonicalPayload, CohortId, ContinuityUnitId, ControllerBinding, EntityRefWire, HandoffId,
    InternalFailure, IssuerId, IssuerKeyId, IssuerLogId, JointHandoffKeyWire, LogicalIncarnation,
    NodeId, OperationId, PRODUCT_VERSION, PayloadSchema, ProcessNonce, ReceiptArtifact,
    ReceiptKindWire, ReceiptRefWire, RegistryInstanceId, RequestId, RuntimeSessionId,
    SecureArtifactRef, ServiceIncarnation, Sha256Digest, joint_receipt_digest,
};

#[derive(Clone, Copy)]
pub(super) struct Context {
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
}

impl Context {
    pub fn new(seed: u128) -> Self {
        Self {
            cohort: CohortId::from_u128(seed + 1),
            boot: BootId::from_u128(seed + 2),
            runtime_session: RuntimeSessionId::from_u128(seed + 3),
        }
    }

    pub fn controller(self, seed: u128) -> ControllerBinding {
        ControllerBinding {
            product_version: PRODUCT_VERSION,
            cohort: self.cohort,
            boot: self.boot,
            runtime_session: self.runtime_session,
            process_nonce: ProcessNonce::from_u128(seed + 1),
            process_generation: 1,
        }
    }

    pub fn agent(self, role: AgentRole, seed: u128) -> AgentBinding {
        AgentBinding {
            product_version: PRODUCT_VERSION,
            cohort: self.cohort,
            boot: self.boot,
            runtime_session: self.runtime_session,
            role,
            logical_incarnation: LogicalIncarnation::from_u128(seed + 1),
            process_nonce: ProcessNonce::from_u128(seed + 2),
            process_generation: 1,
        }
    }

    pub fn authority(self, role: AuthorityRole, seed: u128) -> AuthorityServiceBinding {
        AuthorityServiceBinding {
            product_version: PRODUCT_VERSION,
            cohort: self.cohort,
            boot: self.boot,
            runtime_session: self.runtime_session,
            role,
            service_incarnation: ServiceIncarnation::from_u128(seed + 1),
            process_nonce: ProcessNonce::from_u128(seed + 2),
            process_generation: 1,
        }
    }
}

pub(super) fn request_id(seed: u128) -> RequestId {
    RequestId::from_u128(seed)
}

pub(super) fn operation_id(seed: u128) -> OperationId {
    OperationId::from_u128(seed)
}

pub(super) fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of(label.as_bytes())
}

pub(super) fn payload(schema_id: [u8; 16], label: &str) -> CanonicalPayload {
    CanonicalPayload::new(
        PayloadSchema { id: schema_id, major: 1, minor: 0 },
        label.as_bytes().to_vec(),
    )
    .expect("fixture payload is valid")
}

pub(super) fn payload_with_len(schema_id: [u8; 16], len: usize) -> CanonicalPayload {
    CanonicalPayload::new(PayloadSchema { id: schema_id, major: 1, minor: 0 }, vec![0xa5; len])
        .expect("fixture payload length is valid")
}

pub(super) fn artifact(
    root: ArtifactRoot,
    relative_path: impl Into<String>,
    label: &str,
) -> SecureArtifactRef {
    let relative_path = relative_path.into();
    SecureArtifactRef { root, relative_path, size: label.len() as u64, sha256: digest(label) }
}

pub(super) fn entity(seed: u128) -> EntityRefWire {
    EntityRefWire { identity: ContinuityUnitId::from_u128(seed), generation: 1 }
}

pub(super) fn handoff_key(seed: u128) -> JointHandoffKeyWire {
    JointHandoffKeyWire {
        continuity_unit: entity(seed + 1),
        handoff: HandoffId::from_u128(seed + 2),
        source: NodeId::from_u128(seed + 3),
        destination: NodeId::from_u128(seed + 4),
        expected_epoch: 7,
        next_epoch: 8,
    }
}

pub(super) fn receipt(kind: ReceiptKindWire, seed: u128) -> ReceiptArtifact {
    receipt_for_handoff(kind, HandoffId::from_u128(seed + 1), seed)
}

pub(super) fn receipt_for_handoff(
    kind: ReceiptKindWire,
    handoff: HandoffId,
    seed: u128,
) -> ReceiptArtifact {
    let issuer = IssuerId::from_u128(seed + 2);
    let issuer_incarnation = ServiceIncarnation::from_u128(seed + 3);
    let key_id = IssuerKeyId::from_u128(seed + 4);
    let log_id = IssuerLogId::from_u128(seed + 5);
    let sequence = u64::try_from(seed).unwrap_or(u64::MAX).max(1);
    let mut key = handoff_key(seed + 10);
    key.handoff = handoff;
    let body = ReceiptCarrierFixture {
        protocol_major: 1,
        protocol_minor: 0,
        kind,
        key,
        issuer,
        issuer_incarnation,
        key_id,
        log_id,
        sequence,
        request_binding_digest: digest(&format!("receipt-request-{seed}")),
    };
    let bytes = postcard::to_allocvec(&body).expect("receipt carrier fixture must encode");
    let reference = ReceiptRefWire {
        protocol_major: 1,
        protocol_minor: 0,
        kind,
        handoff,
        issuer,
        issuer_incarnation,
        key_id,
        log_id,
        sequence,
        digest: joint_receipt_digest(kind, &bytes),
    };
    ReceiptArtifact::new(reference, bytes).expect("receipt carrier fixture must be self-consistent")
}

/// Test-only shape used to make the development corpus carrier internally
/// coherent. It is not a neutral typed receipt and must never be accepted as
/// service/readiness evidence without the later joint_handoff_core verifier.
#[derive(Serialize)]
struct ReceiptCarrierFixture {
    protocol_major: u16,
    protocol_minor: u16,
    kind: ReceiptKindWire,
    key: JointHandoffKeyWire,
    issuer: IssuerId,
    issuer_incarnation: ServiceIncarnation,
    key_id: IssuerKeyId,
    log_id: IssuerLogId,
    sequence: u64,
    request_binding_digest: Sha256Digest,
}

pub(super) fn internal_failure(seed: u128) -> InternalFailure {
    InternalFailure { failure_id: operation_id(seed), retryable: seed.is_multiple_of(2) }
}

pub(super) fn registry(seed: u128) -> RegistryInstanceId {
    RegistryInstanceId::from_u128(seed)
}

pub(super) fn nonminimal_header_major(canonical: &[u8]) -> Vec<u8> {
    assert_eq!(canonical[16], 1, "wire header major must be the first varint after family ID");
    let mut bytes = Vec::with_capacity(canonical.len() + 1);
    bytes.extend_from_slice(&canonical[..16]);
    bytes.extend_from_slice(&[0x81, 0x00]);
    bytes.extend_from_slice(&canonical[17..]);
    bytes
}

pub(super) fn all_receipt_kinds() -> [ReceiptKindWire; 14] {
    [
        ReceiptKindWire::PrepareIntent,
        ReceiptKindWire::VisaFreeze,
        ReceiptKindWire::NexusFreeze,
        ReceiptKindWire::DestinationPrepared,
        ReceiptKindWire::OwnershipPrepared,
        ReceiptKindWire::OwnershipAbort,
        ReceiptKindWire::OwnershipCommit,
        ReceiptKindWire::NexusThaw,
        ReceiptKindWire::ClosureProgress,
        ReceiptKindWire::Closure,
        ReceiptKindWire::RetainedTombstone,
        ReceiptKindWire::VisaSourceFence,
        ReceiptKindWire::VisaSourceResume,
        ReceiptKindWire::VisaDestinationActivation,
    ]
}

pub(super) fn receipt_kind_name(kind: ReceiptKindWire) -> &'static str {
    match kind {
        ReceiptKindWire::PrepareIntent => "PrepareIntent",
        ReceiptKindWire::VisaFreeze => "VisaFreeze",
        ReceiptKindWire::NexusFreeze => "NexusFreeze",
        ReceiptKindWire::DestinationPrepared => "DestinationPrepared",
        ReceiptKindWire::OwnershipPrepared => "OwnershipPrepared",
        ReceiptKindWire::OwnershipAbort => "OwnershipAbort",
        ReceiptKindWire::OwnershipCommit => "OwnershipCommit",
        ReceiptKindWire::NexusThaw => "NexusThaw",
        ReceiptKindWire::ClosureProgress => "ClosureProgress",
        ReceiptKindWire::Closure => "Closure",
        ReceiptKindWire::RetainedTombstone => "RetainedTombstone",
        ReceiptKindWire::VisaSourceFence => "VisaSourceFence",
        ReceiptKindWire::VisaSourceResume => "VisaSourceResume",
        ReceiptKindWire::VisaDestinationActivation => "VisaDestinationActivation",
    }
}
