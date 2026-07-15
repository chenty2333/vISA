use alloc::boxed::Box;

use joint_handoff_core::{
    ApplyResult, ClosureProgressReceipt, ClosureReceipt, ClosureStatus, Command, CommandKind,
    Decision, DecodeError, DestinationPreparedReceipt, Digest, IdempotencyKey, Identity,
    JointHandoffKey, JointIssuerSet, JointState, NexusFreezeReceipt, NexusThawReceipt,
    OwnershipAbortReceipt, OwnershipCommitReceipt, OwnershipDecision, OwnershipPreparedReceipt,
    PrepareIntentReceipt, ReceiptEnvelope, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef,
    Rejection, RetainedTombstoneReceipt, TypedReceipt, VisaDestinationActivationReceipt,
    VisaFreezeReceipt, VisaSourceFenceReceipt, VisaSourceResumeReceipt, apply, canonical_bytes,
    canonical_from_bytes, preflight,
};
use serde::de::DeserializeOwned;

pub trait NativeReceiptAuthenticator {
    type Error;

    /// Authenticate exact canonical bytes against a pinned issuer policy.
    /// Success does not establish freshness; non-equivocation remains a
    /// separate ownership-log TCB property.
    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptVerificationError<E> {
    EnvelopeDecode,
    PayloadDecode,
    NonCanonicalEnvelope,
    NonCanonicalPayload,
    EnvelopeMismatch,
    MissingAuthentication,
    InvalidReference,
    Authentication(E),
}

/// A typed receipt created only by [`verify_native_receipt`].
pub struct VerifiedReceipt<T> {
    receipt: T,
    reference: ReceiptRef,
}

/// Joint reducer state whose receipt-bearing transitions were admitted only
/// through authenticated [`VerifiedReceipt`] values.
///
/// The inner state is intentionally not deserializable or directly
/// constructible. Recovery must replay the retained native receipts instead of
/// trusting a serialized projection snapshot as authority evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedJointState {
    state: JointState,
    issuers: JointIssuerSet,
    destination_commit: Option<VerifiedDestinationCommit>,
}

impl VerifiedJointState {
    pub fn new(key: JointHandoffKey, issuers: JointIssuerSet) -> Result<Self, Rejection> {
        if !valid_issuer_set(issuers) {
            return Err(Rejection::InvalidIdentity);
        }
        JointState::new(key).map(|state| Self { state, issuers, destination_commit: None })
    }

    pub const fn state(&self) -> &JointState {
        &self.state
    }

    pub const fn issuers(&self) -> JointIssuerSet {
        self.issuers
    }

    pub const fn destination_commit(&self) -> Option<VerifiedDestinationCommit> {
        self.destination_commit
    }

    /// Enter the local activation-attempt phase after the authenticated commit,
    /// closure, and source-fence receipts have all been replayed.
    pub fn begin_destination_activation(
        &self,
        command_identity: joint_handoff_core::Identity,
    ) -> Result<Self, ReceiptRecordError> {
        let OwnershipDecision::Commit(commit) = self.state.decision else {
            return Err(ReceiptRecordError::Rejected(Rejection::MissingPrerequisite));
        };
        let ClosureStatus::Closed { receipt: closure, .. } = self.state.closure else {
            return Err(ReceiptRecordError::Rejected(Rejection::MissingPrerequisite));
        };
        apply_verified_command(
            self,
            Command::new(
                command_identity,
                CommandKind::BeginDestinationActivation { commit, closure },
            ),
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) const fn from_replayed_for_test(
        state: JointState,
        issuers: JointIssuerSet,
        destination_commit: Option<VerifiedDestinationCommit>,
    ) -> Self {
        Self { state, issuers, destination_commit }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedDestinationCommit {
    pub operation: Identity,
    pub idempotency: IdempotencyKey,
    pub request_digest: Digest,
}

impl<T> VerifiedReceipt<T> {
    pub const fn receipt(&self) -> &T {
        &self.receipt
    }

    pub const fn receipt_ref(&self) -> ReceiptRef {
        self.reference
    }
}

pub fn verify_native_receipt<T, A>(
    envelope_bytes: &[u8],
    payload_bytes: &[u8],
    authenticator: &A,
) -> Result<VerifiedReceipt<T>, ReceiptVerificationError<A::Error>>
where
    T: TypedReceipt + DeserializeOwned,
    A: NativeReceiptAuthenticator,
{
    let envelope: ReceiptEnvelope = match canonical_from_bytes(envelope_bytes) {
        Ok(envelope) => envelope,
        Err(DecodeError::TrailingBytes) => {
            return Err(ReceiptVerificationError::NonCanonicalEnvelope);
        }
        Err(DecodeError::Codec) => return Err(ReceiptVerificationError::EnvelopeDecode),
    };
    let receipt: T = match canonical_from_bytes(payload_bytes) {
        Ok(receipt) => receipt,
        Err(DecodeError::TrailingBytes) => {
            return Err(ReceiptVerificationError::NonCanonicalPayload);
        }
        Err(DecodeError::Codec) => return Err(ReceiptVerificationError::PayloadDecode),
    };
    if canonical_bytes(&envelope).ok().as_deref() != Some(envelope_bytes) {
        return Err(ReceiptVerificationError::NonCanonicalEnvelope);
    }
    if canonical_bytes(&receipt).ok().as_deref() != Some(payload_bytes) {
        return Err(ReceiptVerificationError::NonCanonicalPayload);
    }
    if envelope.authentication.is_empty() {
        return Err(ReceiptVerificationError::MissingAuthentication);
    }
    if !envelope.matches(&receipt).map_err(|_| ReceiptVerificationError::EnvelopeMismatch)? {
        return Err(ReceiptVerificationError::EnvelopeMismatch);
    }
    let reference = validate_reference(&receipt)?;
    authenticator
        .authenticate(&envelope, envelope_bytes, payload_bytes)
        .map_err(ReceiptVerificationError::Authentication)?;
    Ok(VerifiedReceipt { receipt, reference })
}

fn validate_reference<T, E>(receipt: &T) -> Result<ReceiptRef, ReceiptVerificationError<E>>
where
    T: TypedReceipt,
{
    let header = receipt.header();
    if !header.version.is_supported()
        || header.kind != T::KIND
        || header.issuer.is_zero()
        || header.issuer_incarnation.is_zero()
        || header.key_id.is_zero()
        || header.log_id.is_zero()
        || header.sequence == 0
        || header.previous_digest == Some(Digest::ZERO)
        || !receipt.key().is_well_formed()
    {
        return Err(ReceiptVerificationError::InvalidReference);
    }
    let reference =
        receipt.receipt_ref().map_err(|_| ReceiptVerificationError::InvalidReference)?;
    if reference.digest == Digest::ZERO {
        return Err(ReceiptVerificationError::InvalidReference);
    }
    Ok(reference)
}

pub trait VerifiedCommandReceipt: TypedReceipt + Clone {
    fn command_kind(self) -> CommandKind;

    fn destination_commit(&self) -> Option<VerifiedDestinationCommit> {
        None
    }
}

macro_rules! command_receipt {
    ($type:ty, $variant:ident) => {
        impl VerifiedCommandReceipt for $type {
            fn command_kind(self) -> CommandKind {
                CommandKind::$variant(self)
            }
        }
    };
    ($type:ty, $variant:ident, boxed) => {
        impl VerifiedCommandReceipt for $type {
            fn command_kind(self) -> CommandKind {
                CommandKind::$variant(Box::new(self))
            }
        }
    };
}

command_receipt!(PrepareIntentReceipt, RecordPrepareIntent);
command_receipt!(VisaFreezeReceipt, RecordVisaFreeze);
command_receipt!(NexusFreezeReceipt, RecordNexusFreeze);
impl VerifiedCommandReceipt for DestinationPreparedReceipt {
    fn command_kind(self) -> CommandKind {
        CommandKind::RecordDestinationPrepared(Box::new(self))
    }

    fn destination_commit(&self) -> Option<VerifiedDestinationCommit> {
        Some(VerifiedDestinationCommit {
            operation: self.lease_commit_operation,
            idempotency: self.lease_commit_idempotency,
            request_digest: self.lease_commit_request_digest,
        })
    }
}
command_receipt!(OwnershipPreparedReceipt, SealPreparedFrozen, boxed);
command_receipt!(OwnershipAbortReceipt, RecordAbortDecision);
command_receipt!(NexusThawReceipt, RecordThaw);
command_receipt!(VisaSourceResumeReceipt, RecordSourceResume);
command_receipt!(OwnershipCommitReceipt, RecordCommitDecision);
command_receipt!(ClosureProgressReceipt, RecordClosureProgress);
command_receipt!(ClosureReceipt, RecordClosure);
command_receipt!(RetainedTombstoneReceipt, RecordRetainedTombstone);
command_receipt!(VisaSourceFenceReceipt, RecordSourceFence);
command_receipt!(VisaDestinationActivationReceipt, RecordDestinationActivation);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRecordError {
    Rejected(Rejection),
    WrongIssuerRole,
    UnexpectedReplay,
    ProjectionMismatch,
}

pub fn record_verified_receipt<T>(
    state: &VerifiedJointState,
    command_identity: joint_handoff_core::Identity,
    verified: &VerifiedReceipt<T>,
) -> Result<VerifiedJointState, ReceiptRecordError>
where
    T: VerifiedCommandReceipt,
{
    if issuer_for_kind(&state.issuers, verified.reference.kind)
        != issuer_from_ref(verified.reference)
    {
        return Err(ReceiptRecordError::WrongIssuerRole);
    }
    let destination_commit = verified.receipt.destination_commit();
    let command = Command::new(command_identity, verified.receipt.clone().command_kind());
    apply_verified_command(state, command, Some(verified.reference), destination_commit)
}

fn apply_verified_command(
    state: &VerifiedJointState,
    command: Command,
    expected_receipt: Option<ReceiptRef>,
    destination_commit: Option<VerifiedDestinationCommit>,
) -> Result<VerifiedJointState, ReceiptRecordError> {
    match preflight(&state.state, &command) {
        Decision::Commit(event) => match apply(&state.state, &event) {
            Ok(ApplyResult::Applied(next))
                if expected_receipt.is_none_or(|receipt| records_reference(&next, receipt)) =>
            {
                if state.destination_commit.is_some()
                    && destination_commit.is_some()
                    && state.destination_commit != destination_commit
                {
                    return Err(ReceiptRecordError::ProjectionMismatch);
                }
                Ok(VerifiedJointState {
                    state: next,
                    issuers: state.issuers,
                    destination_commit: destination_commit.or(state.destination_commit),
                })
            }
            Ok(ApplyResult::Applied(_)) => Err(ReceiptRecordError::ProjectionMismatch),
            Ok(ApplyResult::Replay(_, _)) => Err(ReceiptRecordError::UnexpectedReplay),
            Err(rejection) => Err(ReceiptRecordError::Rejected(rejection)),
        },
        Decision::Replay(_)
            if expected_receipt.is_none_or(|receipt| records_reference(&state.state, receipt))
                && destination_commit
                    .is_none_or(|binding| state.destination_commit == Some(binding)) =>
        {
            Ok(state.clone())
        }
        Decision::Replay(_) => Err(ReceiptRecordError::ProjectionMismatch),
        Decision::Reject(rejection) => Err(ReceiptRecordError::Rejected(rejection)),
    }
}

fn valid_issuer_set(issuers: JointIssuerSet) -> bool {
    let values =
        [issuers.ownership, issuers.visa_source, issuers.visa_destination, issuers.effect_closure];
    values.iter().all(|issuer| {
        !issuer.issuer.is_zero()
            && !issuer.issuer_incarnation.is_zero()
            && !issuer.key_id.is_zero()
            && !issuer.log_id.is_zero()
    }) && values
        .iter()
        .enumerate()
        .all(|(index, issuer)| values[..index].iter().all(|other| other != issuer))
}

fn issuer_for_kind(issuers: &JointIssuerSet, kind: ReceiptKind) -> ReceiptIssuerIdentity {
    match kind {
        ReceiptKind::PrepareIntent
        | ReceiptKind::OwnershipPrepared
        | ReceiptKind::OwnershipAbort
        | ReceiptKind::OwnershipCommit => issuers.ownership,
        ReceiptKind::VisaFreeze | ReceiptKind::VisaSourceFence | ReceiptKind::VisaSourceResume => {
            issuers.visa_source
        }
        ReceiptKind::DestinationPrepared | ReceiptKind::VisaDestinationActivation => {
            issuers.visa_destination
        }
        ReceiptKind::NexusFreeze
        | ReceiptKind::NexusThaw
        | ReceiptKind::ClosureProgress
        | ReceiptKind::Closure
        | ReceiptKind::RetainedTombstone => issuers.effect_closure,
    }
}

fn issuer_from_ref(reference: ReceiptRef) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: reference.issuer,
        issuer_incarnation: reference.issuer_incarnation,
        key_id: reference.key_id,
        log_id: reference.log_id,
    }
}

fn records_reference(state: &JointState, reference: ReceiptRef) -> bool {
    match reference.kind {
        ReceiptKind::PrepareIntent => state.intent == Some(reference),
        ReceiptKind::VisaFreeze => state.visa_freeze == Some(reference),
        ReceiptKind::NexusFreeze => state.nexus_freeze == Some(reference),
        ReceiptKind::DestinationPrepared => state.destination_prepared == Some(reference),
        ReceiptKind::OwnershipPrepared => state.prepared == Some(reference),
        ReceiptKind::OwnershipAbort => state.decision == OwnershipDecision::Abort(reference),
        ReceiptKind::OwnershipCommit => state.decision == OwnershipDecision::Commit(reference),
        ReceiptKind::NexusThaw => state.thaw == Some(reference),
        ReceiptKind::ClosureProgress => matches!(
            state.closure,
            ClosureStatus::Pending { receipt, .. } if receipt == reference
        ),
        ReceiptKind::Closure => matches!(
            state.closure,
            ClosureStatus::Closed { receipt, .. } if receipt == reference
        ),
        ReceiptKind::RetainedTombstone => matches!(
            state.closure,
            ClosureStatus::RetainedTombstone { receipt, .. } if receipt == reference
        ),
        ReceiptKind::VisaSourceFence => state.source_fence == Some(reference),
        ReceiptKind::VisaSourceResume => state.source_resume == Some(reference),
        ReceiptKind::VisaDestinationActivation => state.destination_activation == Some(reference),
    }
}
