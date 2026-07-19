use joint_handoff_core::{
    Digest, JointHandoffKey, JointIssuerSet, JointProtocolVersion, ReceiptIssuerIdentity,
    ReceiptIssuerRole, ReceiptKind, ReceiptRef, TypedReceipt, canonical_bytes, canonical_digest,
    canonical_from_bytes,
};
use serde::{Serialize, de::DeserializeOwned};
use visa_local_rpc::{
    WireValidation,
    common::{
        HandoffId, IssuerId, IssuerKeyId, IssuerLogId, ReceiptArtifact, ReceiptKindWire,
        ReceiptRefWire, ServiceIncarnation, Sha256Digest,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptAdmissionError {
    Carrier,
    Decode,
    NonCanonical,
    WrongKind,
    WrongKey,
    WrongReference,
    InvalidReference,
    Authentication,
}

pub trait LocalReceiptAuthenticator {
    fn authenticate(
        &self,
        expected_role: ReceiptIssuerRole,
        reference: ReceiptRef,
        canonical_receipt_bytes: &[u8],
    ) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedLocalReceiptAuthenticator {
    issuers: JointIssuerSet,
    policy_digest: Digest,
}

impl PinnedLocalReceiptAuthenticator {
    pub fn new(issuers: JointIssuerSet) -> Option<Self> {
        let values = [
            issuers.ownership,
            issuers.visa_source,
            issuers.visa_destination,
            issuers.effect_closure,
        ];
        let valid = values.iter().all(|issuer| well_formed_issuer(*issuer))
            && values
                .iter()
                .enumerate()
                .all(|(index, issuer)| values[..index].iter().all(|other| other != issuer));
        let policy_digest =
            canonical_digest(&(b"vISA/ownership/local-receipt-policy/v1\0".as_slice(), issuers))
                .ok()?;
        (valid && policy_digest != Digest::ZERO).then_some(Self { issuers, policy_digest })
    }

    pub const fn policy_digest(self) -> Digest {
        self.policy_digest
    }

    pub const fn ownership_namespace(self) -> ReceiptIssuerIdentity {
        self.issuers.ownership
    }
}

impl LocalReceiptAuthenticator for PinnedLocalReceiptAuthenticator {
    fn authenticate(
        &self,
        expected_role: ReceiptIssuerRole,
        reference: ReceiptRef,
        _canonical_receipt_bytes: &[u8],
    ) -> bool {
        let expected = match expected_role {
            ReceiptIssuerRole::Ownership => {
                ownership_issuer_for_handoff(self.issuers.ownership, reference.handoff)
            }
            ReceiptIssuerRole::VisaSource => Some(self.issuers.visa_source),
            ReceiptIssuerRole::VisaDestination => Some(self.issuers.visa_destination),
            ReceiptIssuerRole::EffectClosure => Some(self.issuers.effect_closure),
        };
        expected == Some(issuer_from_ref(reference))
    }
}

pub struct AdmittedReceipt<T> {
    receipt: T,
    reference: ReceiptRef,
}

impl<T> AdmittedReceipt<T> {
    pub const fn receipt(&self) -> &T {
        &self.receipt
    }

    pub const fn reference(&self) -> ReceiptRef {
        self.reference
    }
}

pub fn admit_receipt<T, A>(
    artifact: &ReceiptArtifact,
    key: JointHandoffKey,
    expected_role: ReceiptIssuerRole,
    authenticator: &A,
) -> Result<AdmittedReceipt<T>, ReceiptAdmissionError>
where
    T: TypedReceipt + Serialize + DeserializeOwned,
    A: LocalReceiptAuthenticator,
{
    artifact.validate().map_err(|_| ReceiptAdmissionError::Carrier)?;
    if wire_kind(T::KIND) != artifact.reference.kind {
        return Err(ReceiptAdmissionError::WrongKind);
    }
    let receipt: T =
        canonical_from_bytes(&artifact.payload.bytes).map_err(|_| ReceiptAdmissionError::Decode)?;
    if canonical_bytes(&receipt).ok().as_deref() != Some(artifact.payload.bytes.as_slice()) {
        return Err(ReceiptAdmissionError::NonCanonical);
    }
    let header = receipt.header();
    if header.kind != T::KIND {
        return Err(ReceiptAdmissionError::WrongKind);
    }
    if receipt.key() != key {
        return Err(ReceiptAdmissionError::WrongKey);
    }
    if !valid_header_reference(header.version, header.sequence, header.previous_digest) {
        return Err(ReceiptAdmissionError::InvalidReference);
    }
    let reference = receipt.receipt_ref().map_err(|_| ReceiptAdmissionError::InvalidReference)?;
    if reference.digest == Digest::ZERO || joint_ref_to_wire(reference) != artifact.reference {
        return Err(ReceiptAdmissionError::WrongReference);
    }
    if !authenticator.authenticate(expected_role, reference, &artifact.payload.bytes) {
        return Err(ReceiptAdmissionError::Authentication);
    }
    Ok(AdmittedReceipt { receipt, reference })
}

pub fn receipt_artifact<T>(receipt: &T) -> Result<ReceiptArtifact, ReceiptAdmissionError>
where
    T: TypedReceipt + Serialize,
{
    let reference = receipt.receipt_ref().map_err(|_| ReceiptAdmissionError::InvalidReference)?;
    let bytes = canonical_bytes(receipt).map_err(|_| ReceiptAdmissionError::NonCanonical)?;
    ReceiptArtifact::new(joint_ref_to_wire(reference), bytes)
        .map_err(|_| ReceiptAdmissionError::Carrier)
}

pub(crate) fn joint_ref_to_wire(reference: ReceiptRef) -> ReceiptRefWire {
    ReceiptRefWire {
        protocol_major: reference.version.major,
        protocol_minor: reference.version.minor,
        kind: wire_kind(reference.kind),
        handoff: HandoffId::from_bytes(reference.handoff.0),
        issuer: IssuerId::from_bytes(reference.issuer.0),
        issuer_incarnation: ServiceIncarnation::from_bytes(reference.issuer_incarnation.0),
        key_id: IssuerKeyId::from_bytes(reference.key_id.0),
        log_id: IssuerLogId::from_bytes(reference.log_id.0),
        sequence: reference.sequence,
        digest: Sha256Digest(reference.digest.0),
    }
}

pub(crate) const fn wire_kind(kind: ReceiptKind) -> ReceiptKindWire {
    match kind {
        ReceiptKind::PrepareIntent => ReceiptKindWire::PrepareIntent,
        ReceiptKind::VisaFreeze => ReceiptKindWire::VisaFreeze,
        ReceiptKind::NexusFreeze => ReceiptKindWire::NexusFreeze,
        ReceiptKind::DestinationPrepared => ReceiptKindWire::DestinationPrepared,
        ReceiptKind::OwnershipPrepared => ReceiptKindWire::OwnershipPrepared,
        ReceiptKind::OwnershipAbort => ReceiptKindWire::OwnershipAbort,
        ReceiptKind::OwnershipCommit => ReceiptKindWire::OwnershipCommit,
        ReceiptKind::NexusThaw => ReceiptKindWire::NexusThaw,
        ReceiptKind::ClosureProgress => ReceiptKindWire::ClosureProgress,
        ReceiptKind::Closure => ReceiptKindWire::Closure,
        ReceiptKind::RetainedTombstone => ReceiptKindWire::RetainedTombstone,
        ReceiptKind::VisaSourceFence => ReceiptKindWire::VisaSourceFence,
        ReceiptKind::VisaSourceResume => ReceiptKindWire::VisaSourceResume,
        ReceiptKind::VisaDestinationActivation => ReceiptKindWire::VisaDestinationActivation,
    }
}

fn valid_header_reference(
    version: JointProtocolVersion,
    sequence: u64,
    previous_digest: Option<Digest>,
) -> bool {
    version.is_supported() && sequence > 0 && previous_digest != Some(Digest::ZERO)
}

fn well_formed_issuer(issuer: ReceiptIssuerIdentity) -> bool {
    !issuer.issuer.is_zero()
        && !issuer.issuer_incarnation.is_zero()
        && !issuer.key_id.is_zero()
        && !issuer.log_id.is_zero()
}

pub(crate) fn ownership_issuer_for_handoff(
    namespace: ReceiptIssuerIdentity,
    handoff: joint_handoff_core::Identity,
) -> Option<ReceiptIssuerIdentity> {
    if !well_formed_issuer(namespace) || handoff.is_zero() {
        return None;
    }
    let digest = canonical_digest(&(
        b"vISA/ownership/handoff-log/v1\0".as_slice(),
        &(namespace.log_id, handoff),
    ))
    .ok()?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let log_id = joint_handoff_core::Identity::from_bytes(bytes);
    (!log_id.is_zero()).then_some(ReceiptIssuerIdentity { log_id, ..namespace })
}

fn issuer_from_ref(reference: ReceiptRef) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: reference.issuer,
        issuer_incarnation: reference.issuer_incarnation,
        key_id: reference.key_id,
        log_id: reference.log_id,
    }
}
