use alloc::{collections::BTreeSet, vec::Vec};
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

macro_rules! id_type {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            #[must_use]
            pub const fn from_u128(value: u128) -> Self { Self(value.to_be_bytes()) }
        }
    )+};
}

id_type!(
    ContinuationId,
    OperationId,
    ScopeId,
    LineageId,
    SnapshotId,
    ProfileId,
    SemanticDomainId,
    SchemaId,
    RequirementId,
    AuthorityId
);

/// Bytes whose meaning belongs to the identified schema or profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpaqueBytes(pub Vec<u8>);

/// Exact external locator; possession is not an authority grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExternalCoordinate {
    pub authority: AuthorityId,
    pub value: OpaqueBytes,
}

/// Profile/runtime-defined position at which the portable state was captured.
/// It identifies a semantic boundary, not a wall-clock time or native address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticCut {
    pub sequence: u64,
    /// Exact runtime safe-point receipt material.
    pub safe_point_digest: Digest,
    /// Exact source provider/admission closure material. A runtime safe point
    /// alone is not a source semantic fence.
    pub admission_digest: Digest,
}

/// A content digest. It is neither a signature nor a capability.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest(")?;
        for byte in &self.0[..6] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Hash a canonical postcard representation.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<Digest, ContractError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ContractError::Encoding)?;
    Ok(Digest::of_bytes(&bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDomainRef {
    pub id: SemanticDomainId,
    pub contract_digest: Digest,
    pub artifact_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineagePoint {
    pub semantic_domain: SemanticDomainRef,
    pub lineage: LineageId,
    pub generation: u64,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageAdvance {
    pub parent: LineagePoint,
    pub successor_generation: u64,
    pub successor_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub id: SchemaId,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub id: ProfileId,
    pub version: ProfileVersion,
    pub contract_digest: Digest,
    pub state_schema: SchemaRef,
}

/// A profile-defined finite set of logical permissions.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Rights(pub u64);

impl Rights {
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// A logical resource which must be satisfied by the destination profile.
/// It never contains a native binding, handle, or capability grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirement {
    pub id: RequirementId,
    pub schema: SchemaRef,
    pub logical_name: OpaqueBytes,
    pub required_rights: Rights,
    pub disposition: RebindDisposition,
    pub profile_data: OpaqueBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebindDisposition {
    Recreate,
    Reconnect,
    Reattach,
    Proxy,
    ReplayIfAuthorized,
    RetainOld,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectClosure {
    Empty,
    Unsupported,
}

pub const MAX_PORTABLE_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RESOURCE_REQUIREMENTS: usize = 1_024;
pub const MAX_RESOURCE_FIELD_BYTES: usize = 1024 * 1024;
pub const MAX_RESOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EXTERNAL_COORDINATE_BYTES: usize = 4 * 1024;

/// The portable semantic state transported across a continuation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableSnapshot {
    pub snapshot: SnapshotId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub semantic_domain: SemanticDomainRef,
    pub lineage: LineageAdvance,
    pub profile: ProfileRef,
    pub source: ExternalCoordinate,
    pub semantic_cut: SemanticCut,
    pub state: OpaqueBytes,
    pub state_digest: Digest,
    pub resources: Vec<ResourceRequirement>,
    pub effect_closure: EffectClosure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnvelope {
    pub body: PortableSnapshot,
    pub body_digest: Digest,
}

impl SnapshotEnvelope {
    pub fn seal(mut body: PortableSnapshot) -> Result<Self, ContractError> {
        validate_snapshot_contract(&body)?;
        body.state_digest = Digest::of_bytes(&body.state.0);
        body.lineage.successor_digest = Digest::ZERO;
        body.lineage.successor_digest = successor_digest(&body)?;
        Ok(Self { body_digest: canonical_digest(&body)?, body })
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        validate_snapshot_contract(&self.body)?;
        if Digest::of_bytes(&self.body.state.0) != self.body.state_digest {
            return Err(ContractError::StateDigestMismatch);
        }
        if successor_digest(&self.body)? != self.body.lineage.successor_digest {
            return Err(ContractError::SuccessorDigestMismatch);
        }
        if canonical_digest(&self.body)? != self.body_digest {
            return Err(ContractError::EnvelopeDigestMismatch);
        }
        Ok(())
    }

    /// The only lineage point this verified snapshot can propose as its
    /// successor. Persistence still needs an external atomic lineage update.
    pub fn successor_point(&self) -> Result<LineagePoint, ContractError> {
        self.verify()?;
        Ok(LineagePoint {
            semantic_domain: self.body.semantic_domain,
            lineage: self.body.lineage.parent.lineage,
            generation: self.body.lineage.successor_generation,
            state_digest: self.body.lineage.successor_digest,
        })
    }
}

fn successor_digest(body: &PortableSnapshot) -> Result<Digest, ContractError> {
    let mut material = body.clone();
    material.lineage.successor_digest = Digest::ZERO;
    canonical_digest(&material)
}

/// A canonical statement that a durable capture authority holds this exact
/// snapshot for this exact operation. It does not grant access to either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReceipt {
    pub operation: OperationId,
    pub request_digest: Digest,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub lineage: LineageAdvance,
    pub profile: ProfileRef,
    pub source: ExternalCoordinate,
    pub semantic_cut: SemanticCut,
    pub receipt_digest: Digest,
}

impl SnapshotReceipt {
    pub fn seal(mut self) -> Result<Self, ContractError> {
        self.receipt_digest = Digest::ZERO;
        self.receipt_digest = canonical_digest(&self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        let mut material = self.clone();
        let claimed = material.receipt_digest;
        material.receipt_digest = Digest::ZERO;
        if canonical_digest(&material)? == claimed {
            Ok(())
        } else {
            Err(ContractError::ReceiptDigestMismatch)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingGrant {
    pub requirement: RequirementId,
    pub disposition: RebindDisposition,
    pub provider: ExternalCoordinate,
    pub provider_generation: u64,
    pub binding: ExternalCoordinate,
    pub granted_rights: Rights,
}

macro_rules! exact_receipt {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name { $(pub $field: $ty,)+ pub request_digest: Digest, pub receipt_digest: Digest }
        impl $name {
            pub fn seal(mut self) -> Result<Self, ContractError> {
                self.receipt_digest = Digest::ZERO;
                self.receipt_digest = canonical_digest(&self)?;
                Ok(self)
            }
            pub fn verify(&self) -> Result<(), ContractError> {
                let mut material = self.clone(); let claimed = material.receipt_digest;
                material.receipt_digest = Digest::ZERO;
                if canonical_digest(&material)? == claimed { Ok(()) } else { Err(ContractError::ReceiptDigestMismatch) }
            }
        }
    };
}

exact_receipt!(BindingPreparationReceipt {
    operation: OperationId, continuation: ContinuationId, snapshot: SnapshotId,
    snapshot_digest: Digest, destination: ExternalCoordinate, grants: Vec<BindingGrant>
});

impl BindingPreparationReceipt {
    /// Validate that one exact authority receipt closes every resource
    /// requirement without silently changing its rights.
    pub fn validate_for(&self, snapshot: &SnapshotEnvelope) -> Result<(), ContractError> {
        snapshot.verify()?;
        if self.grants.len() > MAX_RESOURCE_REQUIREMENTS {
            return Err(ContractError::TooManyBindingGrants);
        }
        for grant in &self.grants {
            validate_coordinate(&grant.provider)?;
            validate_coordinate(&grant.binding)?;
        }
        self.verify()?;
        if self.continuation != snapshot.body.continuation
            || self.snapshot != snapshot.body.snapshot
            || self.snapshot_digest != snapshot.body_digest
        {
            return Err(ContractError::BindingMismatch);
        }

        let mut grant_ids = BTreeSet::new();
        for grant in &self.grants {
            if !grant_ids.insert(grant.requirement) {
                return Err(ContractError::DuplicateBindingGrant);
            }
        }
        for requirement in &snapshot.body.resources {
            match requirement.disposition {
                RebindDisposition::Reject => return Err(ContractError::RejectedResource),
                RebindDisposition::ReplayIfAuthorized | RebindDisposition::RetainOld => {
                    return Err(ContractError::UnsupportedRebindDisposition);
                }
                RebindDisposition::Recreate
                | RebindDisposition::Reconnect
                | RebindDisposition::Reattach
                | RebindDisposition::Proxy => {}
            }
            let grant = self
                .grants
                .iter()
                .find(|grant| grant.requirement == requirement.id)
                .ok_or(ContractError::MissingBindingGrant)?;
            if grant.disposition != requirement.disposition
                || grant.granted_rights != requirement.required_rights
            {
                return Err(ContractError::BindingMismatch);
            }
        }
        if self.grants.len() != snapshot.body.resources.len() {
            return Err(ContractError::UnexpectedBindingGrant);
        }
        Ok(())
    }
}

exact_receipt!(RuntimePreparationReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    destination: ExternalCoordinate,
    binding_receipt_digest: Digest
});

exact_receipt!(AuthorityCommitReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    source: ExternalCoordinate,
    destination: ExternalCoordinate,
    binding_receipt_digest: Digest,
    source_fence_epoch: u64,
    execution_epoch: u64
});

exact_receipt!(DestinationRestoreReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    destination: ExternalCoordinate,
    preparation_receipt_digest: Digest
});

// Authority permit: it enables a destination provider but not the runtime's
// local dispatch gate.
exact_receipt!(ActivationPermitReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    destination: ExternalCoordinate,
    authority_commit_digest: Digest,
    execution_epoch: u64
});

// Runtime proof that its fresh destination instance opened local dispatch with
// one exact authority permit.
exact_receipt!(RuntimeActivationReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    destination: ExternalCoordinate,
    activation_permit_digest: Digest
});

exact_receipt!(AbortPreparationReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    source: ExternalCoordinate,
    destination: ExternalCoordinate,
    preparation_receipt_digest: Digest
});

exact_receipt!(SourceRestorationReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    source: ExternalCoordinate,
    execution_epoch: u64
});

exact_receipt!(RetirementReceipt {
    operation: OperationId,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    snapshot_digest: Digest,
    source: ExternalCoordinate,
    runtime_activation_receipt_digest: Digest
});

fn validate_snapshot_contract(snapshot: &PortableSnapshot) -> Result<(), ContractError> {
    validate_lineage(&snapshot.lineage, snapshot.semantic_domain)?;
    validate_resources(&snapshot.resources)?;
    if snapshot.state.0.len() > MAX_PORTABLE_STATE_BYTES {
        return Err(ContractError::PortableStateTooLarge);
    }
    validate_coordinate(&snapshot.source)?;
    if snapshot.effect_closure != EffectClosure::Empty {
        return Err(ContractError::UnsupportedEffectClosure);
    }
    if snapshot.semantic_domain.contract_digest == Digest::ZERO
        || snapshot.semantic_domain.artifact_digest == Digest::ZERO
    {
        return Err(ContractError::IncompleteSemanticDomain);
    }
    if snapshot.semantic_cut.safe_point_digest == Digest::ZERO
        || snapshot.semantic_cut.admission_digest == Digest::ZERO
    {
        return Err(ContractError::IncompleteSemanticCut);
    }
    Ok(())
}

fn validate_coordinate(coordinate: &ExternalCoordinate) -> Result<(), ContractError> {
    if coordinate.value.0.len() > MAX_EXTERNAL_COORDINATE_BYTES {
        Err(ContractError::ExternalCoordinateTooLarge)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_lineage(
    lineage: &LineageAdvance,
    semantic_domain: SemanticDomainRef,
) -> Result<(), ContractError> {
    if lineage.parent.generation.checked_add(1) != Some(lineage.successor_generation) {
        return Err(ContractError::InvalidLineageAdvance);
    }
    if lineage.parent.semantic_domain != semantic_domain {
        return Err(ContractError::SemanticDomainMismatch);
    }
    Ok(())
}

fn validate_resources(resources: &[ResourceRequirement]) -> Result<(), ContractError> {
    if resources.len() > MAX_RESOURCE_REQUIREMENTS {
        return Err(ContractError::TooManyResourceRequirements);
    }
    let mut ids = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for requirement in resources {
        if !ids.insert(requirement.id) {
            return Err(ContractError::DuplicateResourceRequirement);
        }
        if requirement.logical_name.0.len() > MAX_RESOURCE_FIELD_BYTES
            || requirement.profile_data.0.len() > MAX_RESOURCE_FIELD_BYTES
        {
            return Err(ContractError::ResourceFieldTooLarge);
        }
        total_bytes = total_bytes
            .checked_add(requirement.logical_name.0.len())
            .and_then(|size| size.checked_add(requirement.profile_data.0.len()))
            .ok_or(ContractError::ResourceBytesOverflow)?;
        if total_bytes > MAX_RESOURCE_BYTES {
            return Err(ContractError::ResourceBytesTooLarge);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    Encoding,
    InvalidLineageAdvance,
    SemanticDomainMismatch,
    SuccessorDigestMismatch,
    DuplicateResourceRequirement,
    TooManyResourceRequirements,
    ResourceFieldTooLarge,
    ResourceBytesOverflow,
    ResourceBytesTooLarge,
    PortableStateTooLarge,
    UnsupportedEffectClosure,
    IncompleteSemanticDomain,
    IncompleteSemanticCut,
    StateDigestMismatch,
    EnvelopeDigestMismatch,
    ReceiptDigestMismatch,
    MissingRecord,
    RecordAlreadyExists,
    InvalidPhase,
    SnapshotMismatch,
    CaptureMismatch,
    RevisionOverflow,
    TooManyBindingGrants,
    DuplicateBindingGrant,
    MissingBindingGrant,
    UnexpectedBindingGrant,
    BindingMismatch,
    RejectedResource,
    UnsupportedRebindDisposition,
    ExternalCoordinateTooLarge,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
