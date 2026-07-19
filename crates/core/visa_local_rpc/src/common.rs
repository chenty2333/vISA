use postcard_schema::Schema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const PRODUCT_VERSION: ProductVersion = ProductVersion { major: 0, minor: 1, patch: 0 };
pub const MAX_CANONICAL_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_SECURE_RELATIVE_PATH_BYTES: usize = 4_096;
pub const JOINT_RECEIPT_DIGEST_DOMAIN: &[u8] = b"vISA/joint-handoff/receipt/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireValidationError {
    WrongFamily,
    UnsupportedVersion,
    ZeroIdentity,
    InvalidGeneration,
    InvalidRole,
    InvalidSequence,
    InvalidDigest,
    EmptyPayload,
    PayloadTooLarge,
    InvalidPath,
    InvalidArtifact,
    InvalidBinding,
    InvalidOperation,
}

pub trait WireValidation {
    fn validate(&self) -> Result<(), WireValidationError>;
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Schema,
)]
pub struct ProductVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl WireValidation for ProductVersion {
    fn validate(&self) -> Result<(), WireValidationError> {
        if *self == PRODUCT_VERSION { Ok(()) } else { Err(WireValidationError::UnsupportedVersion) }
    }
}

macro_rules! identity_type {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
            Schema,
        )]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub const ZERO: Self = Self([0; 16]);

            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn from_u128(value: u128) -> Self {
                Self(value.to_be_bytes())
            }

            pub fn is_zero(self) -> bool {
                self == Self::ZERO
            }
        }

        impl WireValidation for $name {
            fn validate(&self) -> Result<(), WireValidationError> {
                if self.is_zero() { Err(WireValidationError::ZeroIdentity) } else { Ok(()) }
            }
        }
    };
}

identity_type!(RequestId);
identity_type!(CohortId);
identity_type!(BootId);
identity_type!(RuntimeSessionId);
identity_type!(ProcessNonce);
identity_type!(LogicalIncarnation);
identity_type!(ServiceIncarnation);
identity_type!(OperationId);
identity_type!(IdempotencyId);
identity_type!(ContinuityUnitId);
identity_type!(HandoffId);
identity_type!(NodeId);
identity_type!(ReservationId);
identity_type!(GrantId);
identity_type!(RegistryInstanceId);
identity_type!(IssuerId);
identity_type!(IssuerKeyId);
identity_type!(IssuerLogId);

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Schema,
)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub const ZERO: Self = Self([0; 32]);

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

impl WireValidation for Sha256Digest {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.is_zero() { Err(WireValidationError::InvalidDigest) } else { Ok(()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct WireHeader {
    pub family: [u8; 16],
    pub major: u16,
    pub minor: u16,
}

impl WireHeader {
    pub const fn new(family: [u8; 16]) -> Self {
        Self { family, major: 1, minor: 0 }
    }

    pub fn validate_family(&self, expected: [u8; 16]) -> Result<(), WireValidationError> {
        if self.family != expected {
            return Err(WireValidationError::WrongFamily);
        }
        if self.major != 1 || self.minor != 0 {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum AgentRole {
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ControllerBinding {
    pub product_version: ProductVersion,
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
    pub process_nonce: ProcessNonce,
    pub process_generation: u64,
}

impl WireValidation for ControllerBinding {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.product_version.validate()?;
        self.cohort.validate()?;
        self.boot.validate()?;
        self.runtime_session.validate()?;
        self.process_nonce.validate()?;
        require_nonzero_generation(self.process_generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct AgentBinding {
    pub product_version: ProductVersion,
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
    pub role: AgentRole,
    pub logical_incarnation: LogicalIncarnation,
    pub process_nonce: ProcessNonce,
    pub process_generation: u64,
}

impl WireValidation for AgentBinding {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.product_version.validate()?;
        self.cohort.validate()?;
        self.boot.validate()?;
        self.runtime_session.validate()?;
        self.logical_incarnation.validate()?;
        self.process_nonce.validate()?;
        require_nonzero_generation(self.process_generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum AuthorityRole {
    Ownership,
    NexusAdapter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct AuthorityServiceBinding {
    pub product_version: ProductVersion,
    pub cohort: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
    pub role: AuthorityRole,
    pub service_incarnation: ServiceIncarnation,
    pub process_nonce: ProcessNonce,
    pub process_generation: u64,
}

impl WireValidation for AuthorityServiceBinding {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.product_version.validate()?;
        self.cohort.validate()?;
        self.boot.validate()?;
        self.runtime_session.validate()?;
        self.service_incarnation.validate()?;
        self.process_nonce.validate()?;
        require_nonzero_generation(self.process_generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct PayloadSchema {
    pub id: [u8; 16],
    pub major: u16,
    pub minor: u16,
}

impl WireValidation for PayloadSchema {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.id == [0; 16] {
            return Err(WireValidationError::ZeroIdentity);
        }
        if self.major == 0 {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct CanonicalPayload {
    pub schema: PayloadSchema,
    pub bytes: Vec<u8>,
    pub sha256: Sha256Digest,
}

impl CanonicalPayload {
    pub fn new(schema: PayloadSchema, bytes: Vec<u8>) -> Result<Self, WireValidationError> {
        let value = Self { schema, sha256: Sha256Digest::of(&bytes), bytes };
        value.validate()?;
        Ok(value)
    }
}

impl WireValidation for CanonicalPayload {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.schema.validate()?;
        if self.bytes.is_empty() {
            return Err(WireValidationError::EmptyPayload);
        }
        if self.bytes.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(WireValidationError::PayloadTooLarge);
        }
        if self.sha256 != Sha256Digest::of(&self.bytes) {
            return Err(WireValidationError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum ArtifactRoot {
    Runtime,
    State,
    Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct SecureArtifactRef {
    pub root: ArtifactRoot,
    pub relative_path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
}

impl WireValidation for SecureArtifactRef {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.sha256.validate()?;
        validate_secure_relative_path(&self.relative_path)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct EntityRefWire {
    pub identity: ContinuityUnitId,
    pub generation: u64,
}

impl WireValidation for EntityRefWire {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.identity.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct JointHandoffKeyWire {
    pub continuity_unit: EntityRefWire,
    pub handoff: HandoffId,
    pub source: NodeId,
    pub destination: NodeId,
    pub expected_epoch: u64,
    pub next_epoch: u64,
}

impl WireValidation for JointHandoffKeyWire {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.continuity_unit.validate()?;
        self.handoff.validate()?;
        self.source.validate()?;
        self.destination.validate()?;
        if self.source == self.destination
            || self.expected_epoch.checked_add(1) != Some(self.next_epoch)
        {
            return Err(WireValidationError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum ReceiptKindWire {
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

impl ReceiptKindWire {
    /// Exact `joint_handoff_core::ReceiptKind` v1 discriminant used by the
    /// neutral receipt digest. This explicit match must remain exhaustive.
    pub const fn neutral_tag(self) -> u8 {
        match self {
            Self::PrepareIntent => 0,
            Self::VisaFreeze => 1,
            Self::NexusFreeze => 2,
            Self::DestinationPrepared => 3,
            Self::OwnershipPrepared => 4,
            Self::OwnershipAbort => 5,
            Self::OwnershipCommit => 6,
            Self::NexusThaw => 7,
            Self::ClosureProgress => 8,
            Self::Closure => 9,
            Self::RetainedTombstone => 10,
            Self::VisaSourceFence => 11,
            Self::VisaSourceResume => 12,
            Self::VisaDestinationActivation => 13,
        }
    }

    /// Content type for the exact canonical neutral receipt bytes carried by a
    /// [`ReceiptArtifact`]. Distinct IDs prevent a receipt-kind substitution
    /// from being hidden behind a generic opaque-payload schema.
    pub const fn payload_schema(self) -> PayloadSchema {
        let id = match self {
            Self::PrepareIntent => *b"joint-rcpt-00-v1",
            Self::VisaFreeze => *b"joint-rcpt-01-v1",
            Self::NexusFreeze => *b"joint-rcpt-02-v1",
            Self::DestinationPrepared => *b"joint-rcpt-03-v1",
            Self::OwnershipPrepared => *b"joint-rcpt-04-v1",
            Self::OwnershipAbort => *b"joint-rcpt-05-v1",
            Self::OwnershipCommit => *b"joint-rcpt-06-v1",
            Self::NexusThaw => *b"joint-rcpt-07-v1",
            Self::ClosureProgress => *b"joint-rcpt-08-v1",
            Self::Closure => *b"joint-rcpt-09-v1",
            Self::RetainedTombstone => *b"joint-rcpt-10-v1",
            Self::VisaSourceFence => *b"joint-rcpt-11-v1",
            Self::VisaSourceResume => *b"joint-rcpt-12-v1",
            Self::VisaDestinationActivation => *b"joint-rcpt-13-v1",
        };
        PayloadSchema { id, major: 1, minor: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ReceiptRefWire {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub kind: ReceiptKindWire,
    pub handoff: HandoffId,
    pub issuer: IssuerId,
    pub issuer_incarnation: ServiceIncarnation,
    pub key_id: IssuerKeyId,
    pub log_id: IssuerLogId,
    pub sequence: u64,
    pub digest: Sha256Digest,
}

impl WireValidation for ReceiptRefWire {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.protocol_major != 1 || self.protocol_minor != 0 {
            return Err(WireValidationError::UnsupportedVersion);
        }
        self.handoff.validate()?;
        self.issuer.validate()?;
        self.issuer_incarnation.validate()?;
        self.key_id.validate()?;
        self.log_id.validate()?;
        if self.sequence == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.digest.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ReceiptArtifact {
    pub reference: ReceiptRefWire,
    pub payload: CanonicalPayload,
}

impl ReceiptArtifact {
    pub fn new(reference: ReceiptRefWire, bytes: Vec<u8>) -> Result<Self, WireValidationError> {
        let payload = CanonicalPayload::new(reference.kind.payload_schema(), bytes)?;
        let value = Self { reference, payload };
        value.validate()?;
        Ok(value)
    }
}

impl WireValidation for ReceiptArtifact {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.reference.validate()?;
        self.payload.validate()?;
        if self.payload.schema != self.reference.kind.payload_schema() {
            return Err(WireValidationError::UnsupportedVersion);
        }
        if self.reference.digest != joint_receipt_digest(self.reference.kind, &self.payload.bytes) {
            return Err(WireValidationError::InvalidDigest);
        }
        Ok(())
    }
}

/// Recompute the neutral v1 receipt reference digest over exact typed receipt
/// bytes. This proves carrier/reference byte consistency only. A service must
/// still decode the bytes as the selected neutral receipt type, require exact
/// re-encoding, verify its header/key/request binding, and authenticate it
/// before adopting the receipt or mutating authority state.
pub fn joint_receipt_digest(
    kind: ReceiptKindWire,
    canonical_typed_receipt_bytes: &[u8],
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(JOINT_RECEIPT_DIGEST_DOMAIN);
    digest.update([kind.neutral_tag()]);
    digest.update((canonical_typed_receipt_bytes.len() as u64).to_be_bytes());
    digest.update(canonical_typed_receipt_bytes);
    Sha256Digest(digest.finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct OperationEvidence {
    pub operation: OperationId,
    pub sequence: u64,
    pub state_digest: Sha256Digest,
    pub evidence: Option<SecureArtifactRef>,
}

impl WireValidation for OperationEvidence {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()?;
        if self.sequence == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.state_digest.validate()?;
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct InternalFailure {
    pub failure_id: OperationId,
    pub retryable: bool,
}

impl WireValidation for InternalFailure {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.failure_id.validate()
    }
}

pub fn require_nonzero_generation(value: u64) -> Result<(), WireValidationError> {
    if value == 0 { Err(WireValidationError::InvalidGeneration) } else { Ok(()) }
}

pub fn validate_secure_relative_path(path: &str) -> Result<(), WireValidationError> {
    if path.is_empty()
        || path.len() > MAX_SECURE_RELATIVE_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.bytes().any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        || path.split('/').any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        Err(WireValidationError::InvalidPath)
    } else {
        Ok(())
    }
}
