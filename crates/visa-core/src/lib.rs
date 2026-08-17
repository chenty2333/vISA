//! Portable contracts and pure state transitions for semantic continuation.
//!
//! This crate deliberately has no runtime, provider, operating-system, or
//! persistence dependency. External coordinates and receipts identify facts
//! owned by another authority; they never confer that authority.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

macro_rules! id_type {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            /// Construct a deterministic identifier from a small integer.
            /// This is convenient for embeddings and tests; allocation policy
            /// remains outside vISA.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self(value.to_be_bytes())
            }
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
    SchemaId,
    RequirementId,
    EffectId,
    AuthorityId,
);

/// A content digest, not a signature or grant.
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

/// Hash a canonical postcard encoding.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<Digest, ContractError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ContractError::Encoding)?;
    Ok(Digest::of_bytes(&bytes))
}

/// An exact locator allocated by an external authority.
///
/// Possession does not grant access to the located object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExternalCoordinate {
    pub authority: AuthorityId,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineagePoint {
    pub lineage: LineageId,
    pub generation: u64,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageAdvance {
    pub parent: LineagePoint,
    pub successor_generation: u64,
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

/// A profile-defined finite right set.
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

/// A portable logical requirement. It contains no native binding or grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirement {
    pub id: RequirementId,
    pub kind: Vec<u8>,
    pub logical_name: Vec<u8>,
    pub required_rights: Rights,
    pub disposition: RebindDisposition,
    pub profile_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredEffectResolution {
    Settled,
    RetainedBySource,
    ReplayAuthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectRef {
    pub authority: AuthorityId,
    pub effect: EffectId,
    pub required_resolution: RequiredEffectResolution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSemanticCut {
    pub runtime: ExternalCoordinate,
    pub cut_sequence: u64,
    pub receipt_digest: Digest,
}

/// The complete portable state carried across a continuation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableSnapshot {
    pub snapshot: SnapshotId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub lineage: LineageAdvance,
    pub profile: ProfileRef,
    pub source_cut: SourceSemanticCut,
    pub state: Vec<u8>,
    pub state_digest: Digest,
    pub resources: Vec<ResourceRequirement>,
    pub effects: Vec<EffectRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnvelope {
    pub body: PortableSnapshot,
    pub body_digest: Digest,
}

impl SnapshotEnvelope {
    pub fn seal(mut body: PortableSnapshot) -> Result<Self, ContractError> {
        validate_lineage(&body.lineage)?;
        body.state_digest = Digest::of_bytes(&body.state);
        let body_digest = canonical_digest(&body)?;
        Ok(Self { body, body_digest })
    }

    pub fn verify(&self) -> Result<(), ContractError> {
        validate_lineage(&self.body.lineage)?;
        if Digest::of_bytes(&self.body.state) != self.body.state_digest {
            return Err(ContractError::StateDigestMismatch);
        }
        if canonical_digest(&self.body)? != self.body_digest {
            return Err(ContractError::EnvelopeDigestMismatch);
        }
        Ok(())
    }
}

fn validate_lineage(lineage: &LineageAdvance) -> Result<(), ContractError> {
    if lineage.parent.generation.checked_add(1) != Some(lineage.successor_generation) {
        return Err(ContractError::InvalidLineageAdvance);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafePointReceipt {
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub runtime: ExternalCoordinate,
    pub cut_sequence: u64,
    pub portable_state_digest: Digest,
    pub receipt_digest: Digest,
}

impl SafePointReceipt {
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

/// Canonical proof that a runtime or capture authority accepted one exact
/// portable source capture.  This is a content receipt, not a capability.
/// Every field that can change the continuation is repeated here so an exact
/// query can never be mistaken for a receipt for a different cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureReceipt {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub snapshot: SnapshotId,
    pub source: ExternalCoordinate,
    pub profile: ProfileRef,
    pub lineage: LineageAdvance,
    pub state_digest: Digest,
    pub snapshot_digest: Digest,
    pub safe_point_digest: Digest,
    pub receipt_digest: Digest,
}

impl CaptureReceipt {
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
    pub provider: ExternalCoordinate,
    pub provider_generation: u64,
    pub binding: ExternalCoordinate,
    pub granted_rights: Rights,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingPreparationReceipt {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub destination: ExternalCoordinate,
    pub grants: Vec<BindingGrant>,
    pub receipt_digest: Digest,
}

impl BindingPreparationReceipt {
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

/// Canonical proof that an exact prepared destination was discarded without
/// transferring authority away from the source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortPreparationReceipt {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub preparation_receipt_digest: Digest,
    pub receipt_digest: Digest,
}

impl AbortPreparationReceipt {
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
pub struct AuthorityCommitReceipt {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub source: ExternalCoordinate,
    pub source_fence_epoch: u64,
    pub destination: ExternalCoordinate,
    pub binding_receipt_digest: Digest,
    pub execution_epoch: u64,
    pub receipt_digest: Digest,
}

impl AuthorityCommitReceipt {
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
pub enum EffectResolution {
    Settled { outcome_digest: Digest },
    RetainedBySource,
    ReplayAuthorized { authorization: ExternalCoordinate },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectClosureReceipt {
    pub effect: EffectId,
    pub authority: AuthorityId,
    pub resolution: EffectResolution,
    pub receipt_digest: Digest,
}

impl EffectClosureReceipt {
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
pub struct ActivationReceipt {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub destination: ExternalCoordinate,
    pub authority_commit_digest: Digest,
    pub execution_epoch: u64,
    pub receipt_digest: Digest,
}

impl ActivationReceipt {
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
pub struct SourceRestorationReceipt {
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub snapshot_digest: Digest,
    pub source: ExternalCoordinate,
    pub execution_epoch: u64,
    pub receipt_digest: Digest,
}

impl SourceRestorationReceipt {
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
pub struct ContinuationIntent {
    pub id: ContinuationId,
    pub scope: ScopeId,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub lineage_parent: LineagePoint,
    pub profile: ProfileRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
    Preparing,
    Frozen,
    DestinationPrepared,
    Committed,
    Activated,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryCause {
    ExternalOutcomeUnknown { authority: AuthorityId, operation: OperationId },
    CaptureOutcomeUnknown { operation: OperationId },
    CaptureReceiptMismatch { operation: OperationId },
    CaptureDurabilityUnavailable { operation: OperationId },
    ProcessLocalCaptureDualCrashRisk { operation: OperationId },
    CaptureRejected { operation: OperationId },
    MissingPreparedRuntime,
    ReceiptConflict,
    StoreConflict,
    SourceRestorationUnknown,
    RuntimePreparationUnknown { operation: OperationId },
    RuntimeRestoreUnknown { operation: OperationId },
    RuntimeActivationUnknown { operation: OperationId },
    UnresolvedEffects,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuationPhase {
    Progress(Progress),
    RecoveryRequired { last_known: Progress, cause: RecoveryCause },
}

impl ContinuationPhase {
    #[must_use]
    pub const fn last_known(&self) -> Progress {
        match self {
            Self::Progress(progress) | Self::RecoveryRequired { last_known: progress, .. } => {
                *progress
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalOperationKind {
    CaptureSource,
    PrepareBindings,
    CommitAuthority,
    AbortPreparation,
    ActivateRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExternal {
    pub operation: OperationId,
    pub kind: ExternalOperationKind,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationRecord {
    pub revision: u64,
    pub intent: ContinuationIntent,
    pub phase: ContinuationPhase,
    pub pending: Option<PendingExternal>,
    pub snapshot: Option<SnapshotEnvelope>,
    /// Present only when the source runtime returned an authority-durable
    /// capture receipt. `None` is an explicit process-local capture outcome.
    pub capture_receipt: Option<CaptureReceipt>,
    pub binding_preparation: Option<BindingPreparationReceipt>,
    pub effect_closures: Vec<EffectClosureReceipt>,
    pub authority_commit: Option<AuthorityCommitReceipt>,
    pub activation: Option<ActivationReceipt>,
    pub abort_receipt: Option<AbortPreparationReceipt>,
    pub source_restoration: Option<SourceRestorationReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    Rejected,
    OperatorRequested,
    DestinationUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Begin(ContinuationIntent),
    RecordSnapshot {
        snapshot: SnapshotEnvelope,
        safe_point: SafePointReceipt,
    },
    RecordCapture {
        snapshot: SnapshotEnvelope,
        safe_point: SafePointReceipt,
        receipt: CaptureReceipt,
    },
    ArmExternal(PendingExternal),
    ObserveExternalRejection(PendingExternal),
    ObserveBindingPreparation(BindingPreparationReceipt),
    ObserveEffectClosure(EffectClosureReceipt),
    ObserveAuthorityCommit(AuthorityCommitReceipt),
    ObserveActivation(ActivationReceipt),
    ObserveSourceRestoration(SourceRestorationReceipt),
    MarkRecoveryRequired(RecoveryCause),
    AbortConfirmed {
        operation: OperationId,
        receipt: Option<AbortPreparationReceipt>,
        reason: AbortReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Begun(ContinuationIntent),
    SnapshotRecorded {
        snapshot: SnapshotEnvelope,
        safe_point: SafePointReceipt,
    },
    CaptureRecorded {
        snapshot: SnapshotEnvelope,
        safe_point: SafePointReceipt,
        receipt: CaptureReceipt,
    },
    ExternalArmed(PendingExternal),
    ExternalRejected(PendingExternal),
    BindingPreparationRecorded(BindingPreparationReceipt),
    EffectClosureRecorded(EffectClosureReceipt),
    AuthorityCommitted(AuthorityCommitReceipt),
    Activated(ActivationReceipt),
    SourceRestored(SourceRestorationReceipt),
    RecoveryRequired(RecoveryCause),
    Aborted {
        operation: OperationId,
        receipt: Option<AbortPreparationReceipt>,
        reason: AbortReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Decision {
    Apply(Event),
    AlreadyApplied,
    Reject(ContractError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    Encoding,
    MissingRecord,
    RecordAlreadyExists,
    InvalidPhase,
    InvalidLineageAdvance,
    StateDigestMismatch,
    EnvelopeDigestMismatch,
    SnapshotMismatch,
    CaptureMismatch,
    RejectedResource,
    SafePointMismatch,
    PendingOperationExists,
    PendingOperationMismatch,
    MissingSnapshot,
    MissingBindingPreparation,
    MissingAbortReceipt,
    MissingGrant,
    ExtraGrant,
    RightsMismatch,
    ReceiptConflict,
    ReceiptDigestMismatch,
    UnresolvedEffect,
    ActivationMismatch,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

fn capture_request_digest(
    record: &ContinuationRecord,
    operation: OperationId,
) -> Result<Digest, ContractError> {
    let successor_generation = record
        .intent
        .lineage_parent
        .generation
        .checked_add(1)
        .ok_or(ContractError::InvalidLineageAdvance)?;
    canonical_digest(&(
        operation,
        record.intent.id,
        record.intent.scope,
        &record.intent.source,
        &record.intent.profile,
        LineageAdvance { parent: record.intent.lineage_parent.clone(), successor_generation },
    ))
}

/// Validate a command without changing state or invoking an external system.
#[must_use]
pub fn preflight(record: Option<&ContinuationRecord>, command: &Command) -> Decision {
    match (record, command) {
        (None, Command::Begin(intent)) => Decision::Apply(Event::Begun(intent.clone())),
        (Some(_), Command::Begin(_)) => Decision::Reject(ContractError::RecordAlreadyExists),
        (None, _) => Decision::Reject(ContractError::MissingRecord),
        (Some(record), command) => preflight_existing(record, command),
    }
}

fn preflight_existing(record: &ContinuationRecord, command: &Command) -> Decision {
    match command {
        Command::Begin(_) => Decision::Reject(ContractError::RecordAlreadyExists),
        Command::RecordSnapshot { snapshot, safe_point } => {
            if record.phase != ContinuationPhase::Progress(Progress::Preparing)
                || record.snapshot.is_some()
            {
                return Decision::Reject(ContractError::InvalidPhase);
            }
            if let Err(error) = snapshot.verify() {
                return Decision::Reject(error);
            }
            let body = &snapshot.body;
            if body.continuation != record.intent.id
                || body.scope != record.intent.scope
                || body.profile != record.intent.profile
                || body.lineage.parent != record.intent.lineage_parent
            {
                return Decision::Reject(ContractError::SnapshotMismatch);
            }
            if let Err(error) = safe_point.verify() {
                return Decision::Reject(error);
            }
            if safe_point.continuation != body.continuation
                || safe_point.scope != body.scope
                || safe_point.runtime != body.source_cut.runtime
                || safe_point.cut_sequence != body.source_cut.cut_sequence
                || safe_point.portable_state_digest != body.state_digest
                || safe_point.receipt_digest != body.source_cut.receipt_digest
            {
                return Decision::Reject(ContractError::SafePointMismatch);
            }
            if record
                .pending
                .as_ref()
                .is_some_and(|pending| pending.kind != ExternalOperationKind::CaptureSource)
            {
                return Decision::Reject(ContractError::PendingOperationMismatch);
            }
            Decision::Apply(Event::SnapshotRecorded {
                snapshot: snapshot.clone(),
                safe_point: safe_point.clone(),
            })
        }
        Command::RecordCapture { snapshot, safe_point, receipt } => {
            let Some(pending) = &record.pending else {
                return Decision::Reject(ContractError::InvalidPhase);
            };
            let capture_phase = match &record.phase {
                ContinuationPhase::Progress(Progress::Preparing) => true,
                ContinuationPhase::RecoveryRequired {
                    last_known: Progress::Preparing,
                    cause: RecoveryCause::CaptureOutcomeUnknown { operation },
                } => *operation == pending.operation,
                _ => false,
            };
            if !capture_phase || record.snapshot.is_some() {
                return Decision::Reject(ContractError::InvalidPhase);
            }
            if let Err(error) = snapshot.verify() {
                return Decision::Reject(error);
            }
            let body = &snapshot.body;
            if body.continuation != record.intent.id
                || body.scope != record.intent.scope
                || body.profile != record.intent.profile
                || body.lineage.parent != record.intent.lineage_parent
            {
                return Decision::Reject(ContractError::SnapshotMismatch);
            }
            if let Err(error) = safe_point.verify() {
                return Decision::Reject(error);
            }
            if safe_point.continuation != body.continuation
                || safe_point.scope != body.scope
                || safe_point.runtime != body.source_cut.runtime
                || safe_point.cut_sequence != body.source_cut.cut_sequence
                || safe_point.portable_state_digest != body.state_digest
                || safe_point.receipt_digest != body.source_cut.receipt_digest
            {
                return Decision::Reject(ContractError::SafePointMismatch);
            }
            if let Err(error) = receipt.verify() {
                return Decision::Reject(error);
            }
            if pending.kind != ExternalOperationKind::CaptureSource
                || pending.operation != receipt.operation
            {
                return Decision::Reject(ContractError::PendingOperationMismatch);
            }
            match capture_request_digest(record, pending.operation) {
                Ok(digest) if digest == pending.request_digest => {}
                Ok(_) => return Decision::Reject(ContractError::PendingOperationMismatch),
                Err(error) => return Decision::Reject(error),
            }
            if receipt.continuation != body.continuation
                || receipt.scope != body.scope
                || receipt.snapshot != body.snapshot
                || receipt.source != record.intent.source
                || receipt.profile != body.profile
                || receipt.lineage != body.lineage
                || receipt.state_digest != body.state_digest
                || receipt.snapshot_digest != snapshot.body_digest
                || receipt.safe_point_digest != safe_point.receipt_digest
            {
                return Decision::Reject(ContractError::CaptureMismatch);
            }
            Decision::Apply(Event::CaptureRecorded {
                snapshot: snapshot.clone(),
                safe_point: safe_point.clone(),
                receipt: receipt.clone(),
            })
        }
        Command::ArmExternal(pending) => {
            let progress = match &record.phase {
                ContinuationPhase::Progress(progress) => *progress,
                ContinuationPhase::RecoveryRequired {
                    last_known: Progress::Committed,
                    cause:
                        RecoveryCause::RuntimePreparationUnknown { operation }
                        | RecoveryCause::RuntimeRestoreUnknown { operation },
                } if pending.kind == ExternalOperationKind::ActivateRuntime
                    && *operation == pending.operation =>
                {
                    Progress::Committed
                }
                _ => return Decision::Reject(ContractError::InvalidPhase),
            };
            if let Some(existing) = &record.pending {
                return if existing == pending {
                    Decision::AlreadyApplied
                } else {
                    Decision::Reject(ContractError::PendingOperationExists)
                };
            }
            if !operation_allowed(progress, pending.kind)
                || (pending.kind == ExternalOperationKind::AbortPreparation
                    && record.binding_preparation.is_none())
            {
                return Decision::Reject(ContractError::InvalidPhase);
            }
            if pending.kind == ExternalOperationKind::CaptureSource {
                match capture_request_digest(record, pending.operation) {
                    Ok(digest) if digest == pending.request_digest => {}
                    Ok(_) => return Decision::Reject(ContractError::PendingOperationMismatch),
                    Err(error) => return Decision::Reject(error),
                }
            }
            Decision::Apply(Event::ExternalArmed(pending.clone()))
        }
        Command::ObserveExternalRejection(pending) => {
            if record.pending.as_ref() == Some(pending) {
                Decision::Apply(Event::ExternalRejected(pending.clone()))
            } else {
                Decision::Reject(ContractError::PendingOperationMismatch)
            }
        }
        Command::ObserveBindingPreparation(receipt) => observe_preparation(record, receipt),
        Command::ObserveEffectClosure(receipt) => observe_effect(record, receipt),
        Command::ObserveAuthorityCommit(receipt) => observe_commit(record, receipt),
        Command::ObserveActivation(receipt) => observe_activation(record, receipt),
        Command::ObserveSourceRestoration(receipt) => observe_source_restoration(record, receipt),
        Command::MarkRecoveryRequired(cause) => {
            if record.phase.last_known() == Progress::Activated
                || (record.phase.last_known() == Progress::Aborted
                    && (record.snapshot.is_none() || record.source_restoration.is_some()))
            {
                Decision::Reject(ContractError::InvalidPhase)
            } else if let ContinuationPhase::RecoveryRequired { cause: current, .. } = &record.phase
            {
                if current == cause {
                    Decision::AlreadyApplied
                } else if !recovery_cause_is_fatal(current) && recovery_cause_is_fatal(cause) {
                    Decision::Apply(Event::RecoveryRequired(cause.clone()))
                } else {
                    Decision::Reject(ContractError::InvalidPhase)
                }
            } else {
                Decision::Apply(Event::RecoveryRequired(cause.clone()))
            }
        }
        Command::AbortConfirmed { operation, receipt, reason } => {
            if matches!(
                record.phase.last_known(),
                Progress::Committed | Progress::Activated | Progress::Aborted
            ) {
                return Decision::Reject(ContractError::InvalidPhase);
            }
            match &record.binding_preparation {
                Some(preparation) => {
                    if !pending_matches(record, *operation, ExternalOperationKind::AbortPreparation)
                    {
                        return Decision::Reject(ContractError::PendingOperationMismatch);
                    }
                    let Some(receipt) = receipt else {
                        return Decision::Reject(ContractError::MissingAbortReceipt);
                    };
                    if let Err(error) = receipt.verify() {
                        return Decision::Reject(error);
                    }
                    let Some(snapshot) = &record.snapshot else {
                        return Decision::Reject(ContractError::MissingSnapshot);
                    };
                    if receipt.operation != *operation
                        || receipt.continuation != record.intent.id
                        || receipt.snapshot != snapshot.body.snapshot
                        || receipt.snapshot_digest != snapshot.body_digest
                        || receipt.source != record.intent.source
                        || receipt.destination != record.intent.destination
                        || receipt.preparation_receipt_digest != preparation.receipt_digest
                    {
                        return Decision::Reject(ContractError::ReceiptConflict);
                    }
                }
                None => {
                    if receipt.is_some() {
                        return Decision::Reject(ContractError::ReceiptConflict);
                    }
                    if record.pending.is_some()
                        && !pending_matches(
                            record,
                            *operation,
                            ExternalOperationKind::AbortPreparation,
                        )
                    {
                        return Decision::Reject(ContractError::PendingOperationMismatch);
                    }
                }
            }
            Decision::Apply(Event::Aborted {
                operation: *operation,
                receipt: receipt.clone(),
                reason: *reason,
            })
        }
    }
}

const fn operation_allowed(progress: Progress, kind: ExternalOperationKind) -> bool {
    matches!(
        (progress, kind),
        (Progress::Preparing, ExternalOperationKind::CaptureSource)
            | (Progress::Frozen, ExternalOperationKind::PrepareBindings)
            | (Progress::DestinationPrepared, ExternalOperationKind::CommitAuthority)
            | (Progress::Committed, ExternalOperationKind::ActivateRuntime)
            | (Progress::DestinationPrepared, ExternalOperationKind::AbortPreparation)
    )
}

fn recovery_cause_is_fatal(cause: &RecoveryCause) -> bool {
    matches!(
        cause,
        RecoveryCause::CaptureReceiptMismatch { .. }
            | RecoveryCause::ReceiptConflict
            | RecoveryCause::StoreConflict
    )
}

fn pending_matches(
    record: &ContinuationRecord,
    operation: OperationId,
    kind: ExternalOperationKind,
) -> bool {
    matches!(&record.pending, Some(pending) if pending.operation == operation && pending.kind == kind)
}

fn observe_preparation(
    record: &ContinuationRecord,
    receipt: &BindingPreparationReceipt,
) -> Decision {
    if let Err(error) = receipt.verify() {
        return Decision::Reject(error);
    }
    if let Some(existing) = &record.binding_preparation {
        return duplicate_or_conflict(existing.operation, existing == receipt, receipt.operation);
    }
    if record.phase.last_known() != Progress::Frozen
        || !pending_matches(record, receipt.operation, ExternalOperationKind::PrepareBindings)
    {
        return Decision::Reject(ContractError::PendingOperationMismatch);
    }
    let Some(snapshot) = &record.snapshot else {
        return Decision::Reject(ContractError::MissingSnapshot);
    };
    if receipt.continuation != record.intent.id
        || receipt.snapshot != snapshot.body.snapshot
        || receipt.snapshot_digest != snapshot.body_digest
        || receipt.destination != record.intent.destination
    {
        return Decision::Reject(ContractError::SnapshotMismatch);
    }
    if snapshot
        .body
        .resources
        .iter()
        .any(|requirement| requirement.disposition == RebindDisposition::Reject)
    {
        return Decision::Reject(ContractError::RejectedResource);
    }
    for requirement in snapshot
        .body
        .resources
        .iter()
        .filter(|requirement| requirement.disposition != RebindDisposition::RetainOld)
    {
        let matches: Vec<_> =
            receipt.grants.iter().filter(|grant| grant.requirement == requirement.id).collect();
        if matches.is_empty() {
            return Decision::Reject(ContractError::MissingGrant);
        }
        if matches.len() != 1 || matches[0].granted_rights != requirement.required_rights {
            return Decision::Reject(ContractError::RightsMismatch);
        }
    }
    if receipt.grants.iter().any(|grant| {
        !snapshot.body.resources.iter().any(|requirement| {
            requirement.id == grant.requirement
                && requirement.disposition != RebindDisposition::RetainOld
        })
    }) {
        return Decision::Reject(ContractError::ExtraGrant);
    }
    Decision::Apply(Event::BindingPreparationRecorded(receipt.clone()))
}

fn observe_effect(record: &ContinuationRecord, receipt: &EffectClosureReceipt) -> Decision {
    if let Err(error) = receipt.verify() {
        return Decision::Reject(error);
    }
    if let Some(existing) = record.effect_closures.iter().find(|item| item.effect == receipt.effect)
    {
        return duplicate_or_conflict(receipt.effect.0, existing == receipt, receipt.effect.0);
    }
    if matches!(record.phase.last_known(), Progress::Activated | Progress::Aborted) {
        return Decision::Reject(ContractError::InvalidPhase);
    }
    let Some(snapshot) = &record.snapshot else {
        return Decision::Reject(ContractError::MissingSnapshot);
    };
    let Some(required) =
        snapshot.body.effects.iter().find(|effect| {
            effect.effect == receipt.effect && effect.authority == receipt.authority
        })
    else {
        return Decision::Reject(ContractError::UnresolvedEffect);
    };
    if !resolution_satisfies(required.required_resolution, &receipt.resolution) {
        return Decision::Reject(ContractError::UnresolvedEffect);
    }
    Decision::Apply(Event::EffectClosureRecorded(receipt.clone()))
}

fn resolution_satisfies(required: RequiredEffectResolution, actual: &EffectResolution) -> bool {
    matches!(
        (required, actual),
        (RequiredEffectResolution::Settled, EffectResolution::Settled { .. })
            | (RequiredEffectResolution::RetainedBySource, EffectResolution::RetainedBySource)
            | (
                RequiredEffectResolution::ReplayAuthorized,
                EffectResolution::ReplayAuthorized { .. }
            )
    )
}

fn observe_commit(record: &ContinuationRecord, receipt: &AuthorityCommitReceipt) -> Decision {
    if let Err(error) = receipt.verify() {
        return Decision::Reject(error);
    }
    if let Some(existing) = &record.authority_commit {
        return duplicate_or_conflict(existing.operation, existing == receipt, receipt.operation);
    }
    if record.phase.last_known() != Progress::DestinationPrepared
        || !pending_matches(record, receipt.operation, ExternalOperationKind::CommitAuthority)
    {
        return Decision::Reject(ContractError::PendingOperationMismatch);
    }
    let (Some(snapshot), Some(preparation)) = (&record.snapshot, &record.binding_preparation)
    else {
        return Decision::Reject(ContractError::MissingBindingPreparation);
    };
    if receipt.continuation != record.intent.id
        || receipt.snapshot != snapshot.body.snapshot
        || receipt.snapshot_digest != snapshot.body_digest
        || receipt.source != record.intent.source
        || receipt.destination != record.intent.destination
        || receipt.binding_receipt_digest != preparation.receipt_digest
    {
        return Decision::Reject(ContractError::SnapshotMismatch);
    }
    for effect in &snapshot.body.effects {
        let Some(closure) = record.effect_closures.iter().find(|closure| {
            closure.effect == effect.effect && closure.authority == effect.authority
        }) else {
            return Decision::Reject(ContractError::UnresolvedEffect);
        };
        if !resolution_satisfies(effect.required_resolution, &closure.resolution) {
            return Decision::Reject(ContractError::UnresolvedEffect);
        }
    }
    Decision::Apply(Event::AuthorityCommitted(receipt.clone()))
}

fn observe_activation(record: &ContinuationRecord, receipt: &ActivationReceipt) -> Decision {
    if let Err(error) = receipt.verify() {
        return Decision::Reject(error);
    }
    if let Some(existing) = &record.activation {
        return duplicate_or_conflict(existing.operation, existing == receipt, receipt.operation);
    }
    if record.phase.last_known() != Progress::Committed
        || !pending_matches(record, receipt.operation, ExternalOperationKind::ActivateRuntime)
    {
        return Decision::Reject(ContractError::PendingOperationMismatch);
    }
    let (Some(snapshot), Some(commit)) = (&record.snapshot, &record.authority_commit) else {
        return Decision::Reject(ContractError::ActivationMismatch);
    };
    if receipt.continuation != record.intent.id
        || receipt.snapshot != snapshot.body.snapshot
        || receipt.snapshot_digest != snapshot.body_digest
        || receipt.destination != record.intent.destination
        || receipt.authority_commit_digest != commit.receipt_digest
        || receipt.execution_epoch != commit.execution_epoch
    {
        return Decision::Reject(ContractError::ActivationMismatch);
    }
    Decision::Apply(Event::Activated(receipt.clone()))
}

fn observe_source_restoration(
    record: &ContinuationRecord,
    receipt: &SourceRestorationReceipt,
) -> Decision {
    if let Err(error) = receipt.verify() {
        return Decision::Reject(error);
    }
    if let Some(existing) = &record.source_restoration {
        return if existing == receipt {
            Decision::AlreadyApplied
        } else {
            Decision::Reject(ContractError::ReceiptConflict)
        };
    }
    let Some(snapshot) = &record.snapshot else {
        return Decision::Reject(ContractError::MissingSnapshot);
    };
    if record.phase.last_known() != Progress::Aborted
        || receipt.continuation != record.intent.id
        || receipt.snapshot != snapshot.body.snapshot
        || receipt.snapshot_digest != snapshot.body_digest
        || receipt.source != record.intent.source
    {
        return Decision::Reject(ContractError::ActivationMismatch);
    }
    Decision::Apply(Event::SourceRestored(receipt.clone()))
}

fn duplicate_or_conflict<T: PartialEq>(
    existing_operation: T,
    exact: bool,
    operation: T,
) -> Decision {
    if existing_operation == operation && exact {
        Decision::AlreadyApplied
    } else {
        Decision::Reject(ContractError::ReceiptConflict)
    }
}

/// Apply an event after re-validating it against the current record.
pub fn apply(
    record: Option<ContinuationRecord>,
    event: &Event,
) -> Result<ContinuationRecord, ContractError> {
    let command = command_for_event(event);
    match preflight(record.as_ref(), &command) {
        Decision::Apply(expected) if &expected == event => apply_validated(record, event),
        Decision::AlreadyApplied => record.ok_or(ContractError::MissingRecord),
        Decision::Reject(error) => Err(error),
        Decision::Apply(_) => Err(ContractError::ReceiptConflict),
    }
}

fn command_for_event(event: &Event) -> Command {
    match event {
        Event::Begun(value) => Command::Begin(value.clone()),
        Event::SnapshotRecorded { snapshot, safe_point } => {
            Command::RecordSnapshot { safe_point: safe_point.clone(), snapshot: snapshot.clone() }
        }
        Event::CaptureRecorded { snapshot, safe_point, receipt } => Command::RecordCapture {
            snapshot: snapshot.clone(),
            safe_point: safe_point.clone(),
            receipt: receipt.clone(),
        },
        Event::ExternalArmed(value) => Command::ArmExternal(value.clone()),
        Event::ExternalRejected(value) => Command::ObserveExternalRejection(value.clone()),
        Event::BindingPreparationRecorded(value) => {
            Command::ObserveBindingPreparation(value.clone())
        }
        Event::EffectClosureRecorded(value) => Command::ObserveEffectClosure(value.clone()),
        Event::AuthorityCommitted(value) => Command::ObserveAuthorityCommit(value.clone()),
        Event::Activated(value) => Command::ObserveActivation(value.clone()),
        Event::SourceRestored(value) => Command::ObserveSourceRestoration(value.clone()),
        Event::RecoveryRequired(value) => Command::MarkRecoveryRequired(value.clone()),
        Event::Aborted { operation, receipt, reason } => Command::AbortConfirmed {
            operation: *operation,
            receipt: receipt.clone(),
            reason: *reason,
        },
    }
}

fn apply_validated(
    record: Option<ContinuationRecord>,
    event: &Event,
) -> Result<ContinuationRecord, ContractError> {
    if let Event::Begun(intent) = event {
        return Ok(ContinuationRecord {
            revision: 0,
            intent: intent.clone(),
            phase: ContinuationPhase::Progress(Progress::Preparing),
            pending: None,
            snapshot: None,
            capture_receipt: None,
            binding_preparation: None,
            effect_closures: Vec::new(),
            authority_commit: None,
            activation: None,
            abort_receipt: None,
            source_restoration: None,
        });
    }
    let mut record = record.ok_or(ContractError::MissingRecord)?;
    record.revision = record.revision.checked_add(1).ok_or(ContractError::InvalidPhase)?;
    match event {
        Event::Begun(_) => return Err(ContractError::RecordAlreadyExists),
        Event::SnapshotRecorded { snapshot, .. } => {
            record.snapshot = Some(snapshot.clone());
            record.capture_receipt = None;
            if record
                .pending
                .as_ref()
                .is_some_and(|pending| pending.kind == ExternalOperationKind::CaptureSource)
            {
                record.pending = None;
            }
            record.phase = ContinuationPhase::Progress(Progress::Frozen);
        }
        Event::CaptureRecorded { snapshot, receipt, .. } => {
            record.snapshot = Some(snapshot.clone());
            record.capture_receipt = Some(receipt.clone());
            record.pending = None;
            record.phase = ContinuationPhase::Progress(Progress::Frozen);
        }
        Event::ExternalArmed(pending) => record.pending = Some(pending.clone()),
        Event::ExternalRejected(_) => record.pending = None,
        Event::BindingPreparationRecorded(receipt) => {
            record.binding_preparation = Some(receipt.clone());
            record.pending = None;
            record.phase = ContinuationPhase::Progress(Progress::DestinationPrepared);
        }
        Event::EffectClosureRecorded(receipt) => record.effect_closures.push(receipt.clone()),
        Event::AuthorityCommitted(receipt) => {
            record.authority_commit = Some(receipt.clone());
            record.pending = None;
            record.phase = ContinuationPhase::Progress(Progress::Committed);
        }
        Event::Activated(receipt) => {
            record.activation = Some(receipt.clone());
            record.pending = None;
            record.phase = ContinuationPhase::Progress(Progress::Activated);
        }
        Event::SourceRestored(receipt) => {
            record.source_restoration = Some(receipt.clone());
        }
        Event::RecoveryRequired(cause) => {
            record.phase = ContinuationPhase::RecoveryRequired {
                last_known: record.phase.last_known(),
                cause: cause.clone(),
            };
        }
        Event::Aborted { receipt, .. } => {
            record.abort_receipt = receipt.clone();
            record.pending = None;
            record.phase = ContinuationPhase::Progress(Progress::Aborted);
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn id(value: u128) -> [u8; 16] {
        value.to_be_bytes()
    }

    fn coordinate(value: u8) -> ExternalCoordinate {
        ExternalCoordinate { authority: AuthorityId(id(90)), value: vec![value] }
    }

    fn profile() -> ProfileRef {
        ProfileRef {
            id: ProfileId(id(3)),
            version: ProfileVersion { major: 1, minor: 0 },
            contract_digest: Digest::of_bytes(b"profile"),
            state_schema: SchemaRef { id: SchemaId(id(4)), version: 1 },
        }
    }

    fn intent() -> ContinuationIntent {
        ContinuationIntent {
            id: ContinuationId(id(1)),
            scope: ScopeId(id(2)),
            source: coordinate(1),
            destination: coordinate(2),
            lineage_parent: LineagePoint {
                lineage: LineageId(id(5)),
                generation: 0,
                state_digest: Digest::of_bytes(b"old"),
            },
            profile: profile(),
        }
    }

    fn snapshot() -> (SnapshotEnvelope, SafePointReceipt) {
        let intent = intent();
        let state = vec![10, 20];
        let safe = SafePointReceipt {
            continuation: intent.id,
            scope: intent.scope,
            runtime: coordinate(1),
            cut_sequence: 7,
            portable_state_digest: Digest::of_bytes(&state),
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let body = PortableSnapshot {
            snapshot: SnapshotId(id(6)),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance { parent: intent.lineage_parent, successor_generation: 1 },
            profile: intent.profile,
            source_cut: SourceSemanticCut {
                runtime: coordinate(1),
                cut_sequence: 7,
                receipt_digest: safe.receipt_digest,
            },
            state,
            state_digest: Digest::ZERO,
            resources: vec![ResourceRequirement {
                id: RequirementId(id(7)),
                kind: b"kv".to_vec(),
                logical_name: b"s".to_vec(),
                required_rights: Rights(3),
                disposition: RebindDisposition::Reconnect,
                profile_data: vec![],
            }],
            effects: vec![],
        };
        let envelope = SnapshotEnvelope::seal(body).unwrap();
        (envelope, safe)
    }

    fn begun() -> ContinuationRecord {
        apply(None, &Event::Begun(intent())).unwrap()
    }

    fn capture_receipt(
        operation: OperationId,
        snapshot: &SnapshotEnvelope,
        safe_point: &SafePointReceipt,
    ) -> CaptureReceipt {
        CaptureReceipt {
            operation,
            continuation: intent().id,
            scope: intent().scope,
            snapshot: snapshot.body.snapshot,
            source: intent().source,
            profile: snapshot.body.profile.clone(),
            lineage: snapshot.body.lineage.clone(),
            state_digest: snapshot.body.state_digest,
            snapshot_digest: snapshot.body_digest,
            safe_point_digest: safe_point.receipt_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn rejected_transition_does_not_mutate_record() {
        let record = begun();
        let before = record.clone();
        let command = Command::ObserveActivation(ActivationReceipt {
            operation: OperationId(id(9)),
            continuation: intent().id,
            snapshot: SnapshotId(id(6)),
            snapshot_digest: Digest::ZERO,
            destination: intent().destination,
            authority_commit_digest: Digest::ZERO,
            execution_epoch: 2,
            receipt_digest: Digest::ZERO,
        });
        assert!(matches!(preflight(Some(&record), &command), Decision::Reject(_)));
        assert_eq!(record, before);
    }

    #[test]
    fn snapshot_integrity_and_profile_are_checked() {
        let mut record = begun();
        let (mut envelope, safe) = snapshot();
        envelope.body.state.push(1);
        assert_eq!(
            preflight(
                Some(&record),
                &Command::RecordSnapshot { snapshot: envelope, safe_point: safe }
            ),
            Decision::Reject(ContractError::StateDigestMismatch)
        );
        let (mut envelope, safe) = snapshot();
        envelope.body.profile.id = ProfileId(id(99));
        envelope.body_digest = canonical_digest(&envelope.body).unwrap();
        assert_eq!(
            preflight(
                Some(&record),
                &Command::RecordSnapshot { snapshot: envelope, safe_point: safe }
            ),
            Decision::Reject(ContractError::SnapshotMismatch)
        );
        let (envelope, safe) = snapshot();
        let mut changed_safe = safe.clone();
        changed_safe.cut_sequence += 1;
        assert_eq!(
            preflight(
                Some(&record),
                &Command::RecordSnapshot { snapshot: envelope.clone(), safe_point: changed_safe }
            ),
            Decision::Reject(ContractError::ReceiptDigestMismatch)
        );
        let Decision::Apply(event) = preflight(
            Some(&record),
            &Command::RecordSnapshot { snapshot: envelope, safe_point: safe },
        ) else {
            panic!()
        };
        record = apply(Some(record), &event).unwrap();
        assert_eq!(record.phase.last_known(), Progress::Frozen);
    }

    #[test]
    fn grants_are_exact_and_commit_is_one_way() {
        let mut record = begun();
        let (envelope, safe) = snapshot();
        let Decision::Apply(event) = preflight(
            Some(&record),
            &Command::RecordSnapshot { snapshot: envelope.clone(), safe_point: safe },
        ) else {
            panic!()
        };
        record = apply(Some(record), &event).unwrap();
        let pending = PendingExternal {
            operation: OperationId(id(10)),
            kind: ExternalOperationKind::PrepareBindings,
            request_digest: Digest::of_bytes(b"p"),
        };
        record = apply(Some(record), &Event::ExternalArmed(pending.clone())).unwrap();
        let mut preparation = BindingPreparationReceipt {
            operation: pending.operation,
            continuation: intent().id,
            snapshot: envelope.body.snapshot,
            snapshot_digest: envelope.body_digest,
            destination: intent().destination.clone(),
            grants: vec![BindingGrant {
                requirement: RequirementId(id(7)),
                provider: coordinate(3),
                provider_generation: 1,
                binding: coordinate(4),
                granted_rights: Rights(7),
            }],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::ObserveBindingPreparation(preparation.clone())),
            Decision::Reject(ContractError::RightsMismatch)
        );
        preparation.receipt_digest = Digest::ZERO;
        assert_eq!(
            preflight(Some(&record), &Command::ObserveBindingPreparation(preparation.clone())),
            Decision::Reject(ContractError::ReceiptDigestMismatch)
        );
        preparation.grants[0].granted_rights = Rights(3);
        preparation = preparation.seal().unwrap();
        record =
            apply(Some(record), &Event::BindingPreparationRecorded(preparation.clone())).unwrap();
        assert_eq!(
            preflight(
                Some(&record),
                &Command::AbortConfirmed {
                    operation: OperationId(id(99)),
                    receipt: None,
                    reason: AbortReason::OperatorRequested,
                }
            ),
            Decision::Reject(ContractError::PendingOperationMismatch)
        );
        let abort_operation = OperationId(id(13));
        let abort_pending = PendingExternal {
            operation: abort_operation,
            kind: ExternalOperationKind::AbortPreparation,
            request_digest: Digest::of_bytes(b"a"),
        };
        let aborting = apply(Some(record.clone()), &Event::ExternalArmed(abort_pending)).unwrap();
        assert_eq!(
            preflight(
                Some(&aborting),
                &Command::AbortConfirmed {
                    operation: abort_operation,
                    receipt: None,
                    reason: AbortReason::OperatorRequested,
                }
            ),
            Decision::Reject(ContractError::MissingAbortReceipt)
        );
        let abort_receipt = AbortPreparationReceipt {
            operation: abort_operation,
            continuation: intent().id,
            snapshot: envelope.body.snapshot,
            snapshot_digest: envelope.body_digest,
            source: intent().source.clone(),
            destination: intent().destination.clone(),
            preparation_receipt_digest: preparation.receipt_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let mut corrupt_abort = abort_receipt.clone();
        corrupt_abort.snapshot = SnapshotId(id(88));
        assert_eq!(
            preflight(
                Some(&aborting),
                &Command::AbortConfirmed {
                    operation: abort_operation,
                    receipt: Some(corrupt_abort),
                    reason: AbortReason::OperatorRequested,
                }
            ),
            Decision::Reject(ContractError::ReceiptDigestMismatch)
        );
        let aborted = apply(
            Some(aborting),
            &Event::Aborted {
                operation: abort_operation,
                receipt: Some(abort_receipt.clone()),
                reason: AbortReason::OperatorRequested,
            },
        )
        .unwrap();
        assert_eq!(aborted.abort_receipt, Some(abort_receipt));
        let commit_op = OperationId(id(11));
        record = apply(
            Some(record),
            &Event::ExternalArmed(PendingExternal {
                operation: commit_op,
                kind: ExternalOperationKind::CommitAuthority,
                request_digest: Digest::of_bytes(b"c"),
            }),
        )
        .unwrap();
        let commit = AuthorityCommitReceipt {
            operation: commit_op,
            continuation: intent().id,
            snapshot: envelope.body.snapshot,
            snapshot_digest: envelope.body_digest,
            source: intent().source.clone(),
            source_fence_epoch: 1,
            destination: intent().destination.clone(),
            binding_receipt_digest: preparation.receipt_digest,
            execution_epoch: 2,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        record = apply(Some(record), &Event::AuthorityCommitted(commit.clone())).unwrap();
        assert_eq!(
            preflight(
                Some(&record),
                &Command::AbortConfirmed {
                    operation: OperationId(id(12)),
                    receipt: None,
                    reason: AbortReason::OperatorRequested
                }
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
        let activation_operation = OperationId(id(14));
        record = apply(
            Some(record),
            &Event::ExternalArmed(PendingExternal {
                operation: activation_operation,
                kind: ExternalOperationKind::ActivateRuntime,
                request_digest: Digest::of_bytes(b"activation"),
            }),
        )
        .unwrap();
        let wrong_activation = ActivationReceipt {
            operation: activation_operation,
            continuation: intent().id,
            snapshot: envelope.body.snapshot,
            snapshot_digest: envelope.body_digest,
            destination: coordinate(99),
            authority_commit_digest: commit.receipt_digest,
            execution_epoch: commit.execution_epoch,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::ObserveActivation(wrong_activation)),
            Decision::Reject(ContractError::ActivationMismatch)
        );
    }

    #[test]
    fn exact_duplicate_is_replay_but_conflict_is_rejected() {
        let mut record = begun();
        let (envelope, safe) = snapshot();
        let Decision::Apply(event) = preflight(
            Some(&record),
            &Command::RecordSnapshot { snapshot: envelope.clone(), safe_point: safe },
        ) else {
            panic!()
        };
        record = apply(Some(record), &event).unwrap();
        let pending = PendingExternal {
            operation: OperationId(id(10)),
            kind: ExternalOperationKind::PrepareBindings,
            request_digest: Digest::of_bytes(b"p"),
        };
        record = apply(Some(record), &Event::ExternalArmed(pending.clone())).unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::ArmExternal(pending.clone())),
            Decision::AlreadyApplied
        );
        let different =
            PendingExternal { request_digest: Digest::of_bytes(b"different"), ..pending };
        assert_eq!(
            preflight(Some(&record), &Command::ArmExternal(different)),
            Decision::Reject(ContractError::PendingOperationExists)
        );
    }

    #[test]
    fn only_exact_capture_receipt_can_close_unknown_durable_capture() {
        let mut record = begun();
        let operation = OperationId(id(21));
        let pending = PendingExternal {
            operation,
            kind: ExternalOperationKind::CaptureSource,
            request_digest: capture_request_digest(&record, operation).unwrap(),
        };
        record = apply(Some(record), &Event::ExternalArmed(pending)).unwrap();
        record = apply(
            Some(record),
            &Event::RecoveryRequired(RecoveryCause::CaptureOutcomeUnknown { operation }),
        )
        .unwrap();
        let (snapshot, safe_point) = snapshot();
        assert_eq!(
            preflight(
                Some(&record),
                &Command::RecordSnapshot {
                    snapshot: snapshot.clone(),
                    safe_point: safe_point.clone(),
                },
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
        let receipt = capture_receipt(operation, &snapshot, &safe_point);
        record = apply(
            Some(record),
            &Event::CaptureRecorded {
                snapshot: snapshot.clone(),
                safe_point: safe_point.clone(),
                receipt: receipt.clone(),
            },
        )
        .unwrap();
        assert_eq!(record.capture_receipt, Some(receipt));
        assert_eq!(record.phase, ContinuationPhase::Progress(Progress::Frozen));

        let mut wrong = begun();
        let request_digest = capture_request_digest(&wrong, operation).unwrap();
        wrong = apply(
            Some(wrong),
            &Event::ExternalArmed(PendingExternal {
                operation,
                kind: ExternalOperationKind::CaptureSource,
                request_digest,
            }),
        )
        .unwrap();
        let mut mismatched = capture_receipt(operation, &snapshot, &safe_point);
        mismatched.source = coordinate(99);
        mismatched = mismatched.seal().unwrap();
        assert_eq!(
            preflight(
                Some(&wrong),
                &Command::RecordCapture { snapshot, safe_point, receipt: mismatched.clone() },
            ),
            Decision::Reject(ContractError::CaptureMismatch)
        );
        mismatched.receipt_digest = Digest::ZERO;
        assert_eq!(mismatched.verify(), Err(ContractError::ReceiptDigestMismatch));
    }

    #[test]
    fn capture_cannot_clear_unrelated_recovery_cause() {
        let operation = OperationId(id(22));
        let mut record = begun();
        let pending = PendingExternal {
            operation,
            kind: ExternalOperationKind::CaptureSource,
            request_digest: capture_request_digest(&record, operation).unwrap(),
        };
        record = apply(Some(record), &Event::ExternalArmed(pending)).unwrap();
        record =
            apply(Some(record), &Event::RecoveryRequired(RecoveryCause::StoreConflict)).unwrap();
        let (snapshot, safe_point) = snapshot();
        assert_eq!(
            preflight(
                Some(&record),
                &Command::RecordCapture {
                    snapshot: snapshot.clone(),
                    safe_point: safe_point.clone(),
                    receipt: capture_receipt(operation, &snapshot, &safe_point),
                },
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
    }

    #[test]
    fn recovery_causes_are_monotonic() {
        let operation = OperationId(id(23));
        let soft = RecoveryCause::CaptureOutcomeUnknown { operation };
        let mut record = apply(Some(begun()), &Event::RecoveryRequired(soft.clone())).unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::MarkRecoveryRequired(soft.clone())),
            Decision::AlreadyApplied
        );
        assert_eq!(
            preflight(
                Some(&record),
                &Command::MarkRecoveryRequired(RecoveryCause::CaptureRejected { operation }),
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
        let fatal = RecoveryCause::StoreConflict;
        let Decision::Apply(event) =
            preflight(Some(&record), &Command::MarkRecoveryRequired(fatal.clone()))
        else {
            panic!()
        };
        record = apply(Some(record), &event).unwrap();
        assert_eq!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                last_known: Progress::Preparing,
                cause: fatal.clone(),
            }
        );
        assert_eq!(
            preflight(
                Some(&record),
                &Command::MarkRecoveryRequired(RecoveryCause::CaptureReceiptMismatch { operation }),
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
        assert_eq!(
            preflight(Some(&record), &Command::MarkRecoveryRequired(soft)),
            Decision::Reject(ContractError::InvalidPhase)
        );
        assert_eq!(
            preflight(Some(&record), &Command::MarkRecoveryRequired(fatal)),
            Decision::AlreadyApplied
        );
    }

    #[test]
    fn external_operations_and_rejected_resources_fail_closed() {
        let capture = PendingExternal {
            operation: OperationId(id(25)),
            kind: ExternalOperationKind::CaptureSource,
            request_digest: Digest::of_bytes(b"forged request"),
        };
        assert_eq!(
            preflight(Some(&begun()), &Command::ArmExternal(capture)),
            Decision::Reject(ContractError::PendingOperationMismatch)
        );

        let activation_operation = OperationId(id(26));
        let mut recovering = begun();
        recovering.phase = ContinuationPhase::RecoveryRequired {
            last_known: Progress::Committed,
            cause: RecoveryCause::RuntimeRestoreUnknown { operation: activation_operation },
        };
        let activation = PendingExternal {
            operation: activation_operation,
            kind: ExternalOperationKind::ActivateRuntime,
            request_digest: Digest::of_bytes(b"activation"),
        };
        assert!(matches!(
            preflight(Some(&recovering), &Command::ArmExternal(activation)),
            Decision::Apply(Event::ExternalArmed(_))
        ));
        let wrong_activation = PendingExternal {
            operation: OperationId(id(27)),
            kind: ExternalOperationKind::ActivateRuntime,
            request_digest: Digest::of_bytes(b"activation"),
        };
        assert_eq!(
            preflight(Some(&recovering), &Command::ArmExternal(wrong_activation)),
            Decision::Reject(ContractError::InvalidPhase)
        );

        let abort = PendingExternal {
            operation: OperationId(id(24)),
            kind: ExternalOperationKind::AbortPreparation,
            request_digest: Digest::of_bytes(b"abort"),
        };
        let record = begun();
        assert_eq!(
            preflight(Some(&record), &Command::ArmExternal(abort.clone())),
            Decision::Reject(ContractError::InvalidPhase)
        );

        let (envelope, safe_point) = snapshot();
        let record = apply(
            Some(record),
            &Event::SnapshotRecorded { snapshot: envelope.clone(), safe_point },
        )
        .unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::ArmExternal(abort)),
            Decision::Reject(ContractError::InvalidPhase)
        );

        let (mut rejected, safe_point) = snapshot();
        rejected.body.resources[0].disposition = RebindDisposition::Reject;
        let rejected = SnapshotEnvelope::seal(rejected.body).unwrap();
        let mut record = begun();
        record = apply(
            Some(record),
            &Event::SnapshotRecorded { snapshot: rejected.clone(), safe_point },
        )
        .unwrap();
        let pending = PendingExternal {
            operation: OperationId(id(25)),
            kind: ExternalOperationKind::PrepareBindings,
            request_digest: Digest::of_bytes(b"prepare"),
        };
        record = apply(Some(record), &Event::ExternalArmed(pending.clone())).unwrap();
        let receipt = BindingPreparationReceipt {
            operation: pending.operation,
            continuation: intent().id,
            snapshot: rejected.body.snapshot,
            snapshot_digest: rejected.body_digest,
            destination: intent().destination,
            grants: vec![BindingGrant {
                requirement: RequirementId(id(7)),
                provider: coordinate(3),
                provider_generation: 1,
                binding: coordinate(4),
                granted_rights: Rights(3),
            }],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        assert_eq!(
            preflight(Some(&record), &Command::ObserveBindingPreparation(receipt)),
            Decision::Reject(ContractError::RejectedResource)
        );
    }

    #[test]
    fn terminal_records_reject_new_effect_facts() {
        let (mut snapshot, _) = snapshot();
        let effect = EffectRef {
            authority: AuthorityId(id(30)),
            effect: EffectId(id(31)),
            required_resolution: RequiredEffectResolution::Settled,
        };
        snapshot.body.effects.push(effect.clone());
        snapshot = SnapshotEnvelope::seal(snapshot.body).unwrap();
        let closure = EffectClosureReceipt {
            effect: effect.effect,
            authority: effect.authority,
            resolution: EffectResolution::Settled { outcome_digest: Digest::of_bytes(b"done") },
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        for progress in [Progress::Activated, Progress::Aborted] {
            let mut record = begun();
            record.snapshot = Some(snapshot.clone());
            record.phase = ContinuationPhase::Progress(progress);
            if progress == Progress::Aborted {
                record.source_restoration = Some(SourceRestorationReceipt {
                    continuation: record.intent.id,
                    snapshot: snapshot.body.snapshot,
                    snapshot_digest: snapshot.body_digest,
                    source: record.intent.source.clone(),
                    execution_epoch: 1,
                    receipt_digest: Digest::ZERO,
                });
            }
            assert_eq!(
                preflight(Some(&record), &Command::ObserveEffectClosure(closure.clone())),
                Decision::Reject(ContractError::InvalidPhase)
            );
            if progress == Progress::Activated {
                assert_eq!(
                    preflight(
                        Some(&record),
                        &Command::MarkRecoveryRequired(RecoveryCause::StoreConflict)
                    ),
                    Decision::Reject(ContractError::InvalidPhase)
                );
            }
        }
    }

    #[test]
    fn aborted_record_can_require_recovery_until_source_restoration_is_durable() {
        let (snapshot, _) = snapshot();
        let mut record = begun();
        record.phase = ContinuationPhase::Progress(Progress::Aborted);
        record.snapshot = Some(snapshot.clone());
        let cause = RecoveryCause::SourceRestorationUnknown;

        assert_eq!(
            preflight(Some(&record), &Command::MarkRecoveryRequired(cause.clone())),
            Decision::Apply(Event::RecoveryRequired(cause.clone()))
        );

        record.source_restoration = Some(
            SourceRestorationReceipt {
                continuation: record.intent.id,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: record.intent.source.clone(),
                execution_epoch: 1,
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .unwrap(),
        );
        assert_eq!(
            preflight(Some(&record), &Command::MarkRecoveryRequired(cause)),
            Decision::Reject(ContractError::InvalidPhase)
        );

        let mut never_frozen = begun();
        never_frozen.phase = ContinuationPhase::Progress(Progress::Aborted);
        assert_eq!(
            preflight(
                Some(&never_frozen),
                &Command::MarkRecoveryRequired(RecoveryCause::StoreConflict)
            ),
            Decision::Reject(ContractError::InvalidPhase)
        );
    }
}
