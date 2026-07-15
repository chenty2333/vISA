use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData};

use joint_handoff_core::{
    ClosureProgressReceipt, ClosureReceipt, ClosureStatus, DecodeError, DestinationPreparedReceipt,
    Digest, IdempotencyKey, Identity, JointHandoffKey, JointIssuerSet, JointPhase, JournalPosition,
    NexusFreezeReceipt, NexusThawReceipt, OwnershipAbortReceipt, OwnershipCommitReceipt,
    OwnershipDecision, OwnershipPreparedReceipt, PrepareIntentReceipt, ReceiptEnvelope,
    ReceiptKind, ReceiptRef, ReceiptRequest, RetainedTombstoneReceipt, TypedReceipt,
    VisaDestinationActivationReceipt, VisaFreezeReceipt, VisaSourceFenceReceipt,
    VisaSourceResumeReceipt, canonical_bytes, canonical_digest, canonical_from_bytes,
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor},
};

use crate::{
    NativeReceiptAuthenticator, ReceiptRecordError, ReceiptVerificationError,
    VerifiedCommandReceipt, VerifiedJointState, record_verified_receipt, verify_native_receipt,
};

pub const JOINT_PROJECTION_LOG_VERSION: JointProjectionLogVersion =
    JointProjectionLogVersion { major: 1, minor: 0 };
pub const MAX_JOINT_PROJECTION_RECORDS: u64 = 64;
pub const MAX_NATIVE_ENVELOPE_BYTES: usize = 8 * 1024;
pub const MAX_NATIVE_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_NATIVE_PAYLOAD_BYTES: usize = 64 * 1024;
pub const SOURCE_ABORT_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.source-abort-attempt.v1";
pub const SOURCE_FENCE_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.source-fence-attempt.v1";
pub const DESTINATION_ACTIVATION_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.destination-activation-attempt.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProjectionLogVersion {
    pub major: u16,
    pub minor: u16,
}

impl JointProjectionLogVersion {
    pub const fn is_supported(self) -> bool {
        self.major == JOINT_PROJECTION_LOG_VERSION.major
            && self.minor == JOINT_PROJECTION_LOG_VERSION.minor
    }
}

/// Opaque bytes with a limit enforced both at construction and deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub fn new(bytes: &[u8]) -> Result<Self, ProjectionRecordRejection> {
        if bytes.is_empty() {
            return Err(ProjectionRecordRejection::EmptyNativeBytes);
        }
        if bytes.len() > MAX {
            return Err(ProjectionRecordRejection::NativeBytesTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct BoundedBytesVisitor<const MAX: usize>(PhantomData<[u8; MAX]>);

impl<'de, const MAX: usize> Visitor<'de> for BoundedBytesVisitor<MAX> {
    type Value = BoundedBytes<MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "between 1 and {MAX} bytes")
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bytes(value)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.is_empty() || value.len() > MAX {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(BoundedBytes(value.to_vec()))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
        while let Some(byte) = sequence.next_element()? {
            if bytes.len() == MAX {
                return Err(serde::de::Error::invalid_length(MAX + 1, &self));
            }
            bytes.push(byte);
        }
        if bytes.is_empty() {
            return Err(serde::de::Error::invalid_length(0, &self));
        }
        Ok(BoundedBytes(bytes))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BoundedBytesVisitor(PhantomData))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReceiptRecord {
    pub kind: ReceiptKind,
    pub command_identity: Identity,
    pub request: BoundedBytes<MAX_NATIVE_REQUEST_BYTES>,
    pub envelope: BoundedBytes<MAX_NATIVE_ENVELOPE_BYTES>,
    pub payload: BoundedBytes<MAX_NATIVE_PAYLOAD_BYTES>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFreezeInvocation {
    pub key: JointHandoffKey,
    pub intent: PrepareIntentReceipt,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFreezeAttempt {
    pub attempt: Identity,
    /// Exact canonical bytes passed to the effect peer `freeze` invocation.
    pub invocation: BoundedBytes<MAX_NATIVE_REQUEST_BYTES>,
    pub invocation_digest: Digest,
}

impl EffectFreezeAttempt {
    pub fn new(
        attempt: Identity,
        invocation_bytes: &[u8],
    ) -> Result<Self, ProjectionRecordRejection> {
        let invocation: EffectFreezeInvocation = canonical_from_bytes(invocation_bytes)
            .map_err(|_| ProjectionRecordRejection::Decode)?;
        if canonical_bytes(&invocation).ok().as_deref() != Some(invocation_bytes) {
            return Err(ProjectionRecordRejection::NonCanonical);
        }
        let value = Self {
            attempt,
            invocation: BoundedBytes::new(invocation_bytes)?,
            invocation_digest: canonical_digest(&invocation)
                .map_err(|_| ProjectionRecordRejection::Encoding)?,
        };
        value.validate_integrity()?;
        Ok(value)
    }

    pub fn decoded_invocation(&self) -> Result<EffectFreezeInvocation, ProjectionRecordRejection> {
        let invocation: EffectFreezeInvocation = canonical_from_bytes(self.invocation.as_slice())
            .map_err(|_| ProjectionRecordRejection::Decode)?;
        if canonical_bytes(&invocation).ok().as_deref() != Some(self.invocation.as_slice()) {
            return Err(ProjectionRecordRejection::NonCanonical);
        }
        Ok(invocation)
    }

    fn validate_integrity(&self) -> Result<(), ProjectionRecordRejection> {
        let invocation = self.decoded_invocation()?;
        if self.attempt.is_zero()
            || self.invocation_digest == Digest::ZERO
            || canonical_digest(&invocation).map_err(|_| ProjectionRecordRejection::Encoding)?
                != self.invocation_digest
            || !invocation.key.is_well_formed()
            || invocation.registry_instance.is_zero()
            || invocation.scope_id.is_zero()
            || invocation.scope_generation == 0
            || invocation.authority_epoch == 0
            || invocation.freeze_generation == 0
        {
            return Err(ProjectionRecordRejection::InvalidLocalRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAbortAttempt {
    pub joint_revision: u64,
    pub ownership_abort: ReceiptRef,
    pub nexus_thaw: Option<ReceiptRef>,
    pub abort_command: Identity,
    pub resume_command: Identity,
    pub expected_pre_state_digest: Digest,
    pub expected_pre_journal_position: JournalPosition,
    /// Digest of the canonical `VisaSourceResume` receipt-issuance binding. This is
    /// distinct from `request_digest`, which seals this write-ahead attempt.
    pub completion_request_digest: Digest,
    pub request_digest: Digest,
}

impl SourceAbortAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        joint_revision: u64,
        ownership_abort: ReceiptRef,
        nexus_thaw: Option<ReceiptRef>,
        abort_command: Identity,
        resume_command: Identity,
        expected_pre_state_digest: Digest,
        expected_pre_journal_position: JournalPosition,
        completion_request_digest: Digest,
    ) -> Result<Self, ProjectionRecordRejection> {
        let mut attempt = Self {
            joint_revision,
            ownership_abort,
            nexus_thaw,
            abort_command,
            resume_command,
            expected_pre_state_digest,
            expected_pre_journal_position,
            completion_request_digest,
            request_digest: Digest::ZERO,
        };
        attempt.request_digest = attempt.derived_request_digest()?;
        attempt.validate_integrity()?;
        Ok(attempt)
    }

    pub fn derived_request_digest(self) -> Result<Digest, ProjectionRecordRejection> {
        canonical_digest(&SourceAbortAttemptDigestInput {
            domain: SOURCE_ABORT_ATTEMPT_DOMAIN,
            joint_revision: self.joint_revision,
            ownership_abort: self.ownership_abort,
            nexus_thaw: self.nexus_thaw,
            abort_command: self.abort_command,
            resume_command: self.resume_command,
            expected_pre_state_digest: self.expected_pre_state_digest,
            expected_pre_journal_position: self.expected_pre_journal_position,
            completion_request_digest: self.completion_request_digest,
        })
        .map_err(|_| ProjectionRecordRejection::Encoding)
    }

    fn validate_integrity(self) -> Result<(), ProjectionRecordRejection> {
        if self.joint_revision == 0
            || self.abort_command.is_zero()
            || self.resume_command.is_zero()
            || self.abort_command == self.resume_command
            || self.expected_pre_state_digest == Digest::ZERO
            || self.completion_request_digest == Digest::ZERO
        {
            return Err(ProjectionRecordRejection::InvalidLocalRecord);
        }
        if self.request_digest != self.derived_request_digest()? {
            return Err(ProjectionRecordRejection::LocalAttemptRequestMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct SourceAbortAttemptDigestInput {
    domain: &'static str,
    joint_revision: u64,
    ownership_abort: ReceiptRef,
    nexus_thaw: Option<ReceiptRef>,
    abort_command: Identity,
    resume_command: Identity,
    expected_pre_state_digest: Digest,
    expected_pre_journal_position: JournalPosition,
    completion_request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFenceAttempt {
    pub joint_revision: u64,
    pub ownership_commit: ReceiptRef,
    pub closure: ReceiptRef,
    pub fence_command: Identity,
    pub fence_operation: Identity,
    pub expected_pre_state_digest: Digest,
    pub expected_pre_journal_position: JournalPosition,
    /// Digest of the canonical `VisaSourceFence` receipt-issuance binding.
    pub completion_request_digest: Digest,
    pub request_digest: Digest,
}

impl SourceFenceAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        joint_revision: u64,
        ownership_commit: ReceiptRef,
        closure: ReceiptRef,
        fence_command: Identity,
        fence_operation: Identity,
        expected_pre_state_digest: Digest,
        expected_pre_journal_position: JournalPosition,
        completion_request_digest: Digest,
    ) -> Result<Self, ProjectionRecordRejection> {
        let mut attempt = Self {
            joint_revision,
            ownership_commit,
            closure,
            fence_command,
            fence_operation,
            expected_pre_state_digest,
            expected_pre_journal_position,
            completion_request_digest,
            request_digest: Digest::ZERO,
        };
        attempt.request_digest = attempt.derived_request_digest()?;
        attempt.validate_integrity()?;
        Ok(attempt)
    }

    pub fn derived_request_digest(self) -> Result<Digest, ProjectionRecordRejection> {
        canonical_digest(&SourceFenceAttemptDigestInput {
            domain: SOURCE_FENCE_ATTEMPT_DOMAIN,
            joint_revision: self.joint_revision,
            ownership_commit: self.ownership_commit,
            closure: self.closure,
            fence_command: self.fence_command,
            fence_operation: self.fence_operation,
            expected_pre_state_digest: self.expected_pre_state_digest,
            expected_pre_journal_position: self.expected_pre_journal_position,
            completion_request_digest: self.completion_request_digest,
        })
        .map_err(|_| ProjectionRecordRejection::Encoding)
    }

    fn validate_integrity(self) -> Result<(), ProjectionRecordRejection> {
        if self.joint_revision == 0
            || self.fence_command.is_zero()
            || self.fence_operation.is_zero()
            || self.fence_command == self.fence_operation
            || self.expected_pre_state_digest == Digest::ZERO
            || self.completion_request_digest == Digest::ZERO
        {
            return Err(ProjectionRecordRejection::InvalidLocalRecord);
        }
        if self.request_digest != self.derived_request_digest()? {
            return Err(ProjectionRecordRejection::LocalAttemptRequestMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct SourceFenceAttemptDigestInput {
    domain: &'static str,
    joint_revision: u64,
    ownership_commit: ReceiptRef,
    closure: ReceiptRef,
    fence_command: Identity,
    fence_operation: Identity,
    expected_pre_state_digest: Digest,
    expected_pre_journal_position: JournalPosition,
    completion_request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationActivationAttempt {
    pub joint_revision: u64,
    pub ownership_commit: ReceiptRef,
    pub closure: ReceiptRef,
    pub source_fence: ReceiptRef,
    pub joint_command: Identity,
    pub commit_command: Identity,
    pub commit_operation: Identity,
    pub commit_idempotency: IdempotencyKey,
    pub commit_request_digest: Digest,
    pub resume_command: Identity,
    pub expected_pre_state_digest: Digest,
    pub expected_pre_journal_position: JournalPosition,
    pub request_digest: Digest,
}

impl DestinationActivationAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        joint_revision: u64,
        ownership_commit: ReceiptRef,
        closure: ReceiptRef,
        source_fence: ReceiptRef,
        joint_command: Identity,
        commit_command: Identity,
        commit_operation: Identity,
        commit_idempotency: IdempotencyKey,
        commit_request_digest: Digest,
        resume_command: Identity,
        expected_pre_state_digest: Digest,
        expected_pre_journal_position: JournalPosition,
    ) -> Result<Self, ProjectionRecordRejection> {
        let mut attempt = Self {
            joint_revision,
            ownership_commit,
            closure,
            source_fence,
            joint_command,
            commit_command,
            commit_operation,
            commit_idempotency,
            commit_request_digest,
            resume_command,
            expected_pre_state_digest,
            expected_pre_journal_position,
            request_digest: Digest::ZERO,
        };
        attempt.request_digest = attempt.derived_request_digest()?;
        attempt.validate_integrity()?;
        Ok(attempt)
    }

    pub fn derived_request_digest(self) -> Result<Digest, ProjectionRecordRejection> {
        canonical_digest(&DestinationActivationAttemptDigestInput {
            domain: DESTINATION_ACTIVATION_ATTEMPT_DOMAIN,
            joint_revision: self.joint_revision,
            ownership_commit: self.ownership_commit,
            closure: self.closure,
            source_fence: self.source_fence,
            joint_command: self.joint_command,
            commit_command: self.commit_command,
            commit_operation: self.commit_operation,
            commit_idempotency: self.commit_idempotency,
            commit_request_digest: self.commit_request_digest,
            resume_command: self.resume_command,
            expected_pre_state_digest: self.expected_pre_state_digest,
            expected_pre_journal_position: self.expected_pre_journal_position,
        })
        .map_err(|_| ProjectionRecordRejection::Encoding)
    }

    fn validate_integrity(self) -> Result<(), ProjectionRecordRejection> {
        let commands =
            [self.joint_command, self.commit_command, self.commit_operation, self.resume_command];
        if self.joint_revision == 0
            || commands.iter().any(|identity| identity.is_zero())
            || commands
                .iter()
                .enumerate()
                .any(|(index, identity)| commands[..index].contains(identity))
            || self.commit_idempotency.0 == [0; 16]
            || self.commit_request_digest == Digest::ZERO
            || self.expected_pre_state_digest == Digest::ZERO
        {
            return Err(ProjectionRecordRejection::InvalidLocalRecord);
        }
        if self.request_digest != self.derived_request_digest()? {
            return Err(ProjectionRecordRejection::LocalAttemptRequestMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DestinationActivationAttemptDigestInput {
    domain: &'static str,
    joint_revision: u64,
    ownership_commit: ReceiptRef,
    closure: ReceiptRef,
    source_fence: ReceiptRef,
    joint_command: Identity,
    commit_command: Identity,
    commit_operation: Identity,
    commit_idempotency: IdempotencyKey,
    commit_request_digest: Digest,
    resume_command: Identity,
    expected_pre_state_digest: Digest,
    expected_pre_journal_position: JournalPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProjectionObserved {
    /// Canonical digest of the exact write-ahead attempt record that preceded
    /// the local runtime invocation.
    pub attempt_record_digest: Digest,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
}

impl LocalProjectionObserved {
    fn validate(self) -> Result<(), ProjectionRecordRejection> {
        if self.attempt_record_digest == Digest::ZERO || self.state_digest == Digest::ZERO {
            Err(ProjectionRecordRejection::InvalidLocalRecord)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JointProjectionRecordKind {
    NativeReceipt(NativeReceiptRecord),
    /// Legacy pre-publication record retained only so recovery can reject it
    /// explicitly instead of mis-decoding an old log.
    BeginDestinationActivation {
        command_identity: Identity,
    },
    EffectFreezeAttempt(EffectFreezeAttempt),
    SourceAbortAttempt(Box<SourceAbortAttempt>),
    SourceAbortObserved(LocalProjectionObserved),
    SourceFenceAttempt(Box<SourceFenceAttempt>),
    SourceFenceObserved(LocalProjectionObserved),
    DestinationActivationAttempt(Box<DestinationActivationAttempt>),
    DestinationActivationPreviewObserved(LocalProjectionObserved),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointProjectionRecord {
    pub version: JointProjectionLogVersion,
    pub key: JointHandoffKey,
    pub issuer_set_digest: Digest,
    pub sequence: u64,
    pub previous_record_digest: Option<Digest>,
    pub kind: JointProjectionRecordKind,
}

impl JointProjectionRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProjectionRecordRejection> {
        canonical_bytes(self).map_err(|_| ProjectionRecordRejection::Encoding)
    }

    pub fn canonical_digest(&self) -> Result<Digest, ProjectionRecordRejection> {
        canonical_digest(self).map_err(|_| ProjectionRecordRejection::Encoding)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProjectionRecordRejection> {
        let record: Self = match canonical_from_bytes(bytes) {
            Ok(record) => record,
            Err(DecodeError::Codec) => return Err(ProjectionRecordRejection::Decode),
            Err(DecodeError::TrailingBytes) => {
                return Err(ProjectionRecordRejection::NonCanonical);
            }
        };
        if record.canonical_bytes()?.as_slice() != bytes {
            return Err(ProjectionRecordRejection::NonCanonical);
        }
        Ok(record)
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointProjectionAppendOutcome {
    Appended,
    ExactReplay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JointProjectionAppendError<E> {
    Conflict,
    Backend(E),
}

/// Durable, single-writer append-only projection log.
///
/// `append` must atomically compare `expected_head`, persist `record`, and
/// advance the head. If the exact record already occupies the next position it
/// returns `ExactReplay`; any other occupant or head is `Conflict`. A backend
/// error may mean that the append committed but its acknowledgement was lost.
/// The head and records must share one crash-stable durability boundary;
/// rollback of both to an older valid prefix is an explicit storage-TCB concern.
pub trait JointProjectionLog {
    type Error;

    fn head(&self) -> Result<Option<JointProjectionLogHead>, Self::Error>;

    fn read(&self, sequence: u64) -> Result<Option<JointProjectionRecord>, Self::Error>;

    fn append(
        &mut self,
        expected_head: Option<JointProjectionLogHead>,
        record: &JointProjectionRecord,
    ) -> Result<JointProjectionAppendOutcome, JointProjectionAppendError<Self::Error>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectFreezeObligation {
    NotAttempted,
    OutcomeUnknown(EffectFreezeAttempt),
    ReceiptObserved { attempt: EffectFreezeAttempt, receipt: ReceiptRef },
}

impl EffectFreezeObligation {
    pub fn unresolved(&self) -> Option<EffectFreezeAttempt> {
        match self {
            Self::OutcomeUnknown(attempt) => Some(attempt.clone()),
            Self::NotAttempted | Self::ReceiptObserved { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalProjectionObligation<T> {
    NotAttempted,
    OutcomeUnknown(T),
    ReceiptObserved { attempt: T, receipt: ReceiptRef },
}

impl<T> LocalProjectionObligation<T>
where
    T: Copy,
{
    pub const fn attempt(self) -> Option<T> {
        match self {
            Self::NotAttempted => None,
            Self::OutcomeUnknown(attempt) | Self::ReceiptObserved { attempt, .. } => Some(attempt),
        }
    }

    pub const fn unresolved(self) -> Option<T> {
        match self {
            Self::OutcomeUnknown(attempt) => Some(attempt),
            Self::NotAttempted | Self::ReceiptObserved { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableRecordOutcome {
    Appended,
    ExactReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionRecordRejection {
    UnsupportedVersion,
    InvalidHandoffKey,
    HandoffMismatch,
    IssuerPinMismatch,
    InvalidSequence,
    PreviousDigestMismatch,
    InvalidHead,
    HeadMismatch,
    MissingRecord,
    UnexpectedRecord,
    RecordLimitExceeded,
    EmptyNativeBytes,
    NativeBytesTooLarge,
    Decode,
    NonCanonical,
    Encoding,
    InvalidLocalRecord,
    ReceiptKindMismatch,
    RequestDecode,
    NonCanonicalRequest,
    ReceiptRequestMismatch,
    DuplicateRecord,
    ConflictingReplay,
    MissingEffectFreezeAttempt,
    EffectFreezeAttemptConflict,
    EffectFreezeRequestMismatch,
    EffectFreezeOutcomeUnknown,
    LegacyLocalAttemptUnsupported,
    MissingSourceAbortAttempt,
    MissingSourceFenceAttempt,
    MissingDestinationActivationAttempt,
    SourceAbortAttemptConflict,
    SourceFenceAttemptConflict,
    DestinationActivationAttemptConflict,
    LocalAttemptRequestMismatch,
    MissingLocalProjectionObservation,
    LocalProjectionObservationConflict,
    LocalProjectionObservationMismatch,
    LocalProjectionOutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableJointSessionError<LogError, AuthError> {
    LogRead(LogError),
    LogAppend(LogError),
    LogConflict,
    Poisoned,
    PendingAppendConflict,
    Record(ProjectionRecordRejection),
    Verification(ReceiptVerificationError<AuthError>),
    Receipt(ReceiptRecordError),
}

struct VerifiedTransition {
    state: VerifiedJointState,
    reference: ReceiptRef,
}

/// Crash-recoverable host composition state. The authoritative projection is
/// rebuilt exclusively from authenticated native receipt bytes plus the local
/// write-ahead attempt records in [`JointProjectionRecordKind`].
pub struct DurableJointSession<L, A> {
    log: L,
    authenticator: A,
    state: VerifiedJointState,
    head: Option<JointProjectionLogHead>,
    records: Vec<JointProjectionRecord>,
    effect_freeze: EffectFreezeObligation,
    source_abort: LocalProjectionObligation<SourceAbortAttempt>,
    source_abort_attempt_digest: Option<Digest>,
    source_abort_observed: Option<LocalProjectionObserved>,
    source_fence: LocalProjectionObligation<SourceFenceAttempt>,
    source_fence_attempt_digest: Option<Digest>,
    source_fence_observed: Option<LocalProjectionObserved>,
    destination_activation: LocalProjectionObligation<DestinationActivationAttempt>,
    destination_activation_attempt_digest: Option<Digest>,
    destination_activation_observed: Option<LocalProjectionObserved>,
    pending_append: Option<JointProjectionRecord>,
    poisoned: bool,
}

impl<L, A> DurableJointSession<L, A>
where
    L: JointProjectionLog,
    A: NativeReceiptAuthenticator,
{
    pub fn recover(
        log: L,
        authenticator: A,
        key: JointHandoffKey,
        issuers: JointIssuerSet,
    ) -> Result<Self, DurableJointSessionError<L::Error, A::Error>> {
        let issuer_set_digest = canonical_digest(&issuers)
            .map_err(|_| DurableJointSessionError::Record(ProjectionRecordRejection::Encoding))?;
        let mut state = VerifiedJointState::new(key, issuers).map_err(|rejection| {
            DurableJointSessionError::Receipt(ReceiptRecordError::Rejected(rejection))
        })?;
        let head = log.head().map_err(DurableJointSessionError::LogRead)?;
        let mut records = Vec::new();
        let mut effect_freeze = EffectFreezeObligation::NotAttempted;
        let mut source_abort = LocalProjectionObligation::NotAttempted;
        let mut source_abort_attempt_digest = None;
        let mut source_abort_observed = None;
        let mut source_fence = LocalProjectionObligation::NotAttempted;
        let mut source_fence_attempt_digest = None;
        let mut source_fence_observed = None;
        let mut destination_activation = LocalProjectionObligation::NotAttempted;
        let mut destination_activation_attempt_digest = None;
        let mut destination_activation_observed = None;
        let mut previous_digest = None;

        if let Some(log_head) = head {
            validate_head(log_head, key, issuer_set_digest)?;
            for sequence in 1..=log_head.sequence {
                let record = log.read(sequence).map_err(DurableJointSessionError::LogRead)?.ok_or(
                    DurableJointSessionError::Record(ProjectionRecordRejection::MissingRecord),
                )?;
                validate_record(&record, key, issuer_set_digest, sequence, previous_digest)?;
                let next_digest =
                    record.canonical_digest().map_err(DurableJointSessionError::Record)?;
                replay_record(
                    &mut state,
                    &authenticator,
                    &mut effect_freeze,
                    &mut source_abort,
                    &mut source_abort_attempt_digest,
                    &mut source_abort_observed,
                    &mut source_fence,
                    &mut source_fence_attempt_digest,
                    &mut source_fence_observed,
                    &mut destination_activation,
                    &mut destination_activation_attempt_digest,
                    &mut destination_activation_observed,
                    next_digest,
                    &record,
                )?;
                previous_digest = Some(next_digest);
                records.push(record);
            }
            if previous_digest != Some(log_head.record_digest) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::HeadMismatch,
                ));
            }
            if log.read(log_head.sequence + 1).map_err(DurableJointSessionError::LogRead)?.is_some()
            {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::UnexpectedRecord,
                ));
            }
        } else if log.read(1).map_err(DurableJointSessionError::LogRead)?.is_some() {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::UnexpectedRecord,
            ));
        }

        Ok(Self {
            log,
            authenticator,
            state,
            head,
            records,
            effect_freeze,
            source_abort,
            source_abort_attempt_digest,
            source_abort_observed,
            source_fence,
            source_fence_attempt_digest,
            source_fence_observed,
            destination_activation,
            destination_activation_attempt_digest,
            destination_activation_observed,
            pending_append: None,
            poisoned: false,
        })
    }

    pub const fn state(&self) -> &VerifiedJointState {
        &self.state
    }

    pub const fn head(&self) -> Option<JointProjectionLogHead> {
        self.head
    }

    pub const fn log(&self) -> &L {
        &self.log
    }

    pub fn effect_freeze_obligation(&self) -> EffectFreezeObligation {
        self.effect_freeze.clone()
    }

    pub fn unresolved_effect_freeze(&self) -> Option<EffectFreezeAttempt> {
        self.effect_freeze.unresolved()
    }

    pub const fn source_abort_obligation(&self) -> LocalProjectionObligation<SourceAbortAttempt> {
        self.source_abort
    }

    pub const fn source_abort_attempt(&self) -> Option<SourceAbortAttempt> {
        self.source_abort.attempt()
    }

    pub const fn source_abort_observed(&self) -> Option<LocalProjectionObserved> {
        self.source_abort_observed
    }

    /// Exact persisted input to replay after a crash. `None` means either no
    /// side effect was authorized or its authenticated completion was observed.
    pub const fn replay_source_abort_attempt(&self) -> Option<SourceAbortAttempt> {
        self.source_abort.unresolved()
    }

    pub const fn source_fence_obligation(&self) -> LocalProjectionObligation<SourceFenceAttempt> {
        self.source_fence
    }

    pub const fn source_fence_attempt(&self) -> Option<SourceFenceAttempt> {
        self.source_fence.attempt()
    }

    pub const fn source_fence_observed(&self) -> Option<LocalProjectionObserved> {
        self.source_fence_observed
    }

    pub const fn replay_source_fence_attempt(&self) -> Option<SourceFenceAttempt> {
        self.source_fence.unresolved()
    }

    pub const fn destination_activation_obligation(
        &self,
    ) -> LocalProjectionObligation<DestinationActivationAttempt> {
        self.destination_activation
    }

    pub const fn destination_activation_attempt(&self) -> Option<DestinationActivationAttempt> {
        self.destination_activation.attempt()
    }

    pub const fn replay_destination_activation_attempt(
        &self,
    ) -> Option<DestinationActivationAttempt> {
        self.destination_activation.unresolved()
    }

    pub fn destination_activation_attempt_record_digest(&self) -> Option<Digest> {
        self.destination_activation_attempt_digest
    }

    pub const fn destination_activation_preview_observed(&self) -> Option<LocalProjectionObserved> {
        self.destination_activation_observed
    }

    pub fn destination_activation_completion_record_digest(&self) -> Option<Digest> {
        if !matches!(self.destination_activation, LocalProjectionObligation::ReceiptObserved { .. })
        {
            return None;
        }
        self.records.iter().rev().find_map(|record| {
            if matches!(
                &record.kind,
                JointProjectionRecordKind::NativeReceipt(native)
                    if native.kind == ReceiptKind::VisaDestinationActivation
            ) {
                record.canonical_digest().ok()
            } else {
                None
            }
        })
    }

    /// Return the already authenticated activation payload retained in the
    /// durable log. Recovery has verified its canonical bytes, issuer, typed
    /// request, and reducer transition before this accessor can succeed.
    pub fn destination_activation_receipt(&self) -> Option<VisaDestinationActivationReceipt> {
        if !matches!(self.destination_activation, LocalProjectionObligation::ReceiptObserved { .. })
        {
            return None;
        }
        self.records.iter().rev().find_map(|record| {
            let JointProjectionRecordKind::NativeReceipt(native) = &record.kind else {
                return None;
            };
            if native.kind != ReceiptKind::VisaDestinationActivation {
                return None;
            }
            canonical_from_bytes(native.payload.as_slice()).ok()
        })
    }

    pub const fn has_indeterminate_append(&self) -> bool {
        self.pending_append.is_some()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn into_parts(self) -> (L, A) {
        (self.log, self.authenticator)
    }

    pub fn record_effect_freeze_attempt(
        &mut self,
        attempt: Identity,
        invocation_bytes: &[u8],
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        let attempt = EffectFreezeAttempt::new(attempt, invocation_bytes)
            .map_err(DurableJointSessionError::Record)?;
        let record_kind = JointProjectionRecordKind::EffectFreezeAttempt(attempt.clone());
        self.ensure_pending_kind(&record_kind)?;
        match &self.effect_freeze {
            EffectFreezeObligation::NotAttempted => {}
            EffectFreezeObligation::OutcomeUnknown(existing)
            | EffectFreezeObligation::ReceiptObserved { attempt: existing, .. }
                if existing == &attempt =>
            {
                if self.pending_append.is_none() {
                    return Ok(DurableRecordOutcome::ExactReplay);
                }
            }
            EffectFreezeObligation::OutcomeUnknown(_)
            | EffectFreezeObligation::ReceiptObserved { .. } => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::EffectFreezeAttemptConflict,
                ));
            }
        }
        validate_effect_freeze_attempt(&self.state, &attempt)
            .map_err(DurableJointSessionError::Record)?;
        let record = self.next_record(record_kind)?;
        let outcome = self.append_record(record)?;
        self.effect_freeze = EffectFreezeObligation::OutcomeUnknown(attempt);
        Ok(outcome)
    }

    /// Persist the complete source-abort invocation before calling the source
    /// runtime. A successful return is the write-ahead authorization boundary;
    /// recovery exposes the exact same value through
    /// [`Self::replay_source_abort_attempt`] until the resume receipt is stored.
    pub fn begin_source_abort(
        &mut self,
        attempt: SourceAbortAttempt,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        let kind = JointProjectionRecordKind::SourceAbortAttempt(Box::new(attempt));
        self.ensure_pending_kind(&kind)?;
        match self.source_abort {
            LocalProjectionObligation::NotAttempted => {}
            LocalProjectionObligation::OutcomeUnknown(existing)
            | LocalProjectionObligation::ReceiptObserved { attempt: existing, .. }
                if existing == attempt =>
            {
                if self.pending_append.is_none() {
                    return Ok(DurableRecordOutcome::ExactReplay);
                }
            }
            LocalProjectionObligation::OutcomeUnknown(_)
            | LocalProjectionObligation::ReceiptObserved { .. } => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::SourceAbortAttemptConflict,
                ));
            }
        }
        self.ensure_no_unresolved_local_projection()?;
        validate_source_abort_attempt(&self.state, attempt)
            .map_err(DurableJointSessionError::Record)?;
        let record = self.next_record(kind)?;
        let attempt_record_digest =
            record.canonical_digest().map_err(DurableJointSessionError::Record)?;
        let outcome = self.append_record(record)?;
        self.source_abort = LocalProjectionObligation::OutcomeUnknown(attempt);
        self.source_abort_attempt_digest = Some(attempt_record_digest);
        Ok(outcome)
    }

    /// Persist the complete source-fence invocation before calling the source
    /// runtime. Conflicting retries never replace the stored invocation.
    pub fn begin_source_fence(
        &mut self,
        attempt: SourceFenceAttempt,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        let kind = JointProjectionRecordKind::SourceFenceAttempt(Box::new(attempt));
        self.ensure_pending_kind(&kind)?;
        match self.source_fence {
            LocalProjectionObligation::NotAttempted => {}
            LocalProjectionObligation::OutcomeUnknown(existing)
            | LocalProjectionObligation::ReceiptObserved { attempt: existing, .. }
                if existing == attempt =>
            {
                if self.pending_append.is_none() {
                    return Ok(DurableRecordOutcome::ExactReplay);
                }
            }
            LocalProjectionObligation::OutcomeUnknown(_)
            | LocalProjectionObligation::ReceiptObserved { .. } => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::SourceFenceAttemptConflict,
                ));
            }
        }
        self.ensure_no_unresolved_local_projection()?;
        validate_source_fence_attempt(&self.state, attempt)
            .map_err(DurableJointSessionError::Record)?;
        let record = self.next_record(kind)?;
        let attempt_record_digest =
            record.canonical_digest().map_err(DurableJointSessionError::Record)?;
        let outcome = self.append_record(record)?;
        self.source_fence = LocalProjectionObligation::OutcomeUnknown(attempt);
        self.source_fence_attempt_digest = Some(attempt_record_digest);
        Ok(outcome)
    }

    /// Persist the exact terminal local source-abort projection before its
    /// authenticated completion receipt can clear the retry obligation.
    pub fn record_source_abort_observed(
        &mut self,
        journal_position: JournalPosition,
        state_digest: Digest,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        let attempt = self.source_abort.attempt().ok_or(DurableJointSessionError::Record(
            ProjectionRecordRejection::MissingSourceAbortAttempt,
        ))?;
        let observed = LocalProjectionObserved {
            attempt_record_digest: self.source_abort_attempt_digest.ok_or(
                DurableJointSessionError::Record(
                    ProjectionRecordRejection::MissingSourceAbortAttempt,
                ),
            )?,
            journal_position,
            state_digest,
        };
        self.record_source_abort_observation(attempt, observed)
    }

    fn record_source_abort_observation(
        &mut self,
        attempt: SourceAbortAttempt,
        observed: LocalProjectionObserved,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        validate_local_projection_observed(
            observed,
            self.source_abort_attempt_digest,
            attempt.expected_pre_journal_position,
            attempt.expected_pre_state_digest,
        )
        .map_err(DurableJointSessionError::Record)?;
        let kind = JointProjectionRecordKind::SourceAbortObserved(observed);
        self.ensure_pending_kind(&kind)?;
        match self.source_abort_observed {
            Some(existing) if existing == observed && self.pending_append.is_none() => {
                return Ok(DurableRecordOutcome::ExactReplay);
            }
            Some(existing) if existing != observed => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            _ => {}
        }
        if !matches!(self.source_abort, LocalProjectionObligation::OutcomeUnknown(_)) {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::MissingLocalProjectionObservation,
            ));
        }
        let record = self.next_record(kind)?;
        let outcome = self.append_record(record)?;
        self.source_abort_observed = Some(observed);
        Ok(outcome)
    }

    /// Persist the exact terminal local source-fence projection before its
    /// authenticated completion receipt can clear the retry obligation.
    pub fn record_source_fence_observed(
        &mut self,
        journal_position: JournalPosition,
        state_digest: Digest,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        let attempt = self.source_fence.attempt().ok_or(DurableJointSessionError::Record(
            ProjectionRecordRejection::MissingSourceFenceAttempt,
        ))?;
        let observed = LocalProjectionObserved {
            attempt_record_digest: self.source_fence_attempt_digest.ok_or(
                DurableJointSessionError::Record(
                    ProjectionRecordRejection::MissingSourceFenceAttempt,
                ),
            )?,
            journal_position,
            state_digest,
        };
        self.record_source_fence_observation(attempt, observed)
    }

    fn record_source_fence_observation(
        &mut self,
        attempt: SourceFenceAttempt,
        observed: LocalProjectionObserved,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        validate_local_projection_observed(
            observed,
            self.source_fence_attempt_digest,
            attempt.expected_pre_journal_position,
            attempt.expected_pre_state_digest,
        )
        .map_err(DurableJointSessionError::Record)?;
        let kind = JointProjectionRecordKind::SourceFenceObserved(observed);
        self.ensure_pending_kind(&kind)?;
        match self.source_fence_observed {
            Some(existing) if existing == observed && self.pending_append.is_none() => {
                return Ok(DurableRecordOutcome::ExactReplay);
            }
            Some(existing) if existing != observed => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            _ => {}
        }
        if !matches!(self.source_fence, LocalProjectionObligation::OutcomeUnknown(_)) {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::MissingLocalProjectionObservation,
            ));
        }
        let record = self.next_record(kind)?;
        let outcome = self.append_record(record)?;
        self.source_fence_observed = Some(observed);
        Ok(outcome)
    }

    /// Persist the deterministic destination resume preview while the local
    /// runtime remains `Committed` and workload admission is still closed.
    pub fn record_destination_activation_preview_observed(
        &mut self,
        journal_position: JournalPosition,
        state_digest: Digest,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        let attempt =
            self.destination_activation.attempt().ok_or(DurableJointSessionError::Record(
                ProjectionRecordRejection::MissingDestinationActivationAttempt,
            ))?;
        let observed = LocalProjectionObserved {
            attempt_record_digest: self.destination_activation_attempt_digest.ok_or(
                DurableJointSessionError::Record(
                    ProjectionRecordRejection::MissingDestinationActivationAttempt,
                ),
            )?,
            journal_position,
            state_digest,
        };
        self.ensure_operable()?;
        validate_local_projection_observed(
            observed,
            self.destination_activation_attempt_digest,
            attempt.expected_pre_journal_position,
            attempt.expected_pre_state_digest,
        )
        .map_err(DurableJointSessionError::Record)?;
        let kind = JointProjectionRecordKind::DestinationActivationPreviewObserved(observed);
        self.ensure_pending_kind(&kind)?;
        match self.destination_activation_observed {
            Some(existing) if existing == observed && self.pending_append.is_none() => {
                return Ok(DurableRecordOutcome::ExactReplay);
            }
            Some(existing) if existing != observed => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            _ => {}
        }
        if !matches!(self.destination_activation, LocalProjectionObligation::OutcomeUnknown(_)) {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::MissingLocalProjectionObservation,
            ));
        }
        let record = self.next_record(kind)?;
        let outcome = self.append_record(record)?;
        self.destination_activation_observed = Some(observed);
        Ok(outcome)
    }

    /// Retain the exact request/envelope/payload triple. The canonical request
    /// and its command binding are checked before issuer authentication.
    pub fn record_native_receipt(
        &mut self,
        command_identity: Identity,
        request_bytes: &[u8],
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        let request = decode_request(request_bytes)?;
        if request.operation != command_identity {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::ReceiptRequestMismatch,
            ));
        }
        let envelope = decode_envelope(envelope_bytes)?;
        let native = NativeReceiptRecord {
            kind: envelope.kind,
            command_identity,
            request: BoundedBytes::new(request_bytes).map_err(DurableJointSessionError::Record)?,
            envelope: BoundedBytes::new(envelope_bytes)
                .map_err(DurableJointSessionError::Record)?,
            payload: BoundedBytes::new(payload_bytes).map_err(DurableJointSessionError::Record)?,
        };
        let record_kind = JointProjectionRecordKind::NativeReceipt(native);
        self.ensure_pending_kind(&record_kind)?;
        let transition = verify_transition(
            &self.state,
            command_identity,
            envelope.kind,
            &request,
            &envelope,
            envelope_bytes,
            payload_bytes,
            &self.authenticator,
        )?;

        if transition.state == self.state {
            if self.records.iter().any(|record| record.kind == record_kind) {
                return Ok(DurableRecordOutcome::ExactReplay);
            }
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::ConflictingReplay,
            ));
        }

        if matches!(self.effect_freeze, EffectFreezeObligation::OutcomeUnknown(_))
            && envelope.kind != ReceiptKind::NexusFreeze
        {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::EffectFreezeOutcomeUnknown,
            ));
        }

        let next_effect_freeze = match (envelope.kind, &self.effect_freeze) {
            (ReceiptKind::NexusFreeze, EffectFreezeObligation::OutcomeUnknown(attempt)) => {
                validate_effect_freeze_completion(attempt, payload_bytes)
                    .map_err(DurableJointSessionError::Record)?;
                EffectFreezeObligation::ReceiptObserved {
                    attempt: attempt.clone(),
                    receipt: transition.reference,
                }
            }
            (ReceiptKind::NexusFreeze, _) => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::MissingEffectFreezeAttempt,
                ));
            }
            (_, obligation) => obligation.clone(),
        };
        let next_source_abort = advance_local_projection_obligation(
            envelope.kind,
            ReceiptKind::VisaSourceResume,
            envelope.request_digest,
            transition.reference,
            payload_bytes,
            self.source_abort,
            self.source_abort_observed,
            self.source_abort_attempt_digest,
            |attempt| attempt.completion_request_digest,
            decode_source_resume_projection,
            ProjectionRecordRejection::MissingSourceAbortAttempt,
        )
        .map_err(DurableJointSessionError::Record)?;
        let next_source_fence = advance_local_projection_obligation(
            envelope.kind,
            ReceiptKind::VisaSourceFence,
            envelope.request_digest,
            transition.reference,
            payload_bytes,
            self.source_fence,
            self.source_fence_observed,
            self.source_fence_attempt_digest,
            |attempt| attempt.completion_request_digest,
            decode_source_fence_projection,
            ProjectionRecordRejection::MissingSourceFenceAttempt,
        )
        .map_err(DurableJointSessionError::Record)?;
        let next_destination_activation = advance_destination_activation_obligation(
            envelope.kind,
            transition.reference,
            payload_bytes,
            self.destination_activation,
            self.destination_activation_attempt_digest,
            self.destination_activation_observed,
        )
        .map_err(DurableJointSessionError::Record)?;

        let record = self.next_record(record_kind)?;
        let outcome = self.append_record(record)?;
        self.state = transition.state;
        self.effect_freeze = next_effect_freeze;
        self.source_abort = next_source_abort;
        self.source_fence = next_source_fence;
        self.destination_activation = next_destination_activation;
        Ok(outcome)
    }

    /// Persist all destination commit/resume inputs and enter the joint
    /// activation-pending phase before calling the destination runtime.
    pub fn begin_destination_activation(
        &mut self,
        attempt: DestinationActivationAttempt,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.ensure_operable()?;
        if matches!(self.effect_freeze, EffectFreezeObligation::OutcomeUnknown(_)) {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::EffectFreezeOutcomeUnknown,
            ));
        }
        let kind = JointProjectionRecordKind::DestinationActivationAttempt(Box::new(attempt));
        self.ensure_pending_kind(&kind)?;
        match self.destination_activation {
            LocalProjectionObligation::NotAttempted => {}
            LocalProjectionObligation::OutcomeUnknown(existing)
            | LocalProjectionObligation::ReceiptObserved { attempt: existing, .. }
                if existing == attempt =>
            {
                if self.pending_append.is_none() {
                    return Ok(DurableRecordOutcome::ExactReplay);
                }
            }
            LocalProjectionObligation::OutcomeUnknown(_)
            | LocalProjectionObligation::ReceiptObserved { .. } => {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DestinationActivationAttemptConflict,
                ));
            }
        }
        self.ensure_no_unresolved_local_projection()?;
        validate_destination_activation_attempt(&self.state, attempt)
            .map_err(DurableJointSessionError::Record)?;
        let next = self
            .state
            .begin_destination_activation(attempt.joint_command)
            .map_err(DurableJointSessionError::Receipt)?;
        if next == self.state {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::ConflictingReplay,
            ));
        }
        let record = self.next_record(kind)?;
        let attempt_record_digest =
            record.canonical_digest().map_err(DurableJointSessionError::Record)?;
        let outcome = self.append_record(record)?;
        self.state = next;
        self.destination_activation = LocalProjectionObligation::OutcomeUnknown(attempt);
        self.destination_activation_attempt_digest = Some(attempt_record_digest);
        Ok(outcome)
    }

    fn ensure_operable(&self) -> Result<(), DurableJointSessionError<L::Error, A::Error>> {
        if self.poisoned { Err(DurableJointSessionError::Poisoned) } else { Ok(()) }
    }

    fn ensure_pending_kind(
        &self,
        kind: &JointProjectionRecordKind,
    ) -> Result<(), DurableJointSessionError<L::Error, A::Error>> {
        if self.pending_append.as_ref().is_some_and(|pending| &pending.kind != kind) {
            Err(DurableJointSessionError::PendingAppendConflict)
        } else {
            Ok(())
        }
    }

    fn ensure_no_unresolved_local_projection(
        &self,
    ) -> Result<(), DurableJointSessionError<L::Error, A::Error>> {
        if self.source_abort.unresolved().is_some()
            || self.source_fence.unresolved().is_some()
            || self.destination_activation.unresolved().is_some()
        {
            Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::LocalProjectionOutcomeUnknown,
            ))
        } else {
            Ok(())
        }
    }

    fn next_record(
        &self,
        kind: JointProjectionRecordKind,
    ) -> Result<JointProjectionRecord, DurableJointSessionError<L::Error, A::Error>> {
        let sequence = self.head.map_or(1, |head| head.sequence.saturating_add(1));
        if sequence == 0 || sequence > MAX_JOINT_PROJECTION_RECORDS {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::RecordLimitExceeded,
            ));
        }
        let issuer_set_digest = canonical_digest(&self.state.issuers())
            .map_err(|_| DurableJointSessionError::Record(ProjectionRecordRejection::Encoding))?;
        Ok(JointProjectionRecord {
            version: JOINT_PROJECTION_LOG_VERSION,
            key: self.state.state().key,
            issuer_set_digest,
            sequence,
            previous_record_digest: self.head.map(|head| head.record_digest),
            kind,
        })
    }

    fn append_record(
        &mut self,
        record: JointProjectionRecord,
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        if let Some(pending) = &self.pending_append
            && pending != &record
        {
            return Err(DurableJointSessionError::PendingAppendConflict);
        }
        self.pending_append = Some(record.clone());
        let digest = record.canonical_digest().map_err(DurableJointSessionError::Record)?;
        let expected_result_head = JointProjectionLogHead {
            version: JOINT_PROJECTION_LOG_VERSION,
            key: record.key,
            issuer_set_digest: record.issuer_set_digest,
            sequence: record.sequence,
            record_digest: digest,
        };
        let append_outcome = match self.log.append(self.head, &record) {
            Ok(outcome) => outcome,
            Err(JointProjectionAppendError::Backend(error)) => {
                return Err(DurableJointSessionError::LogAppend(error));
            }
            Err(JointProjectionAppendError::Conflict) => {
                self.poisoned = true;
                return Err(DurableJointSessionError::LogConflict);
            }
        };
        let stored = match self.log.read(record.sequence) {
            Ok(Some(stored)) if stored == record => stored,
            Ok(_) => {
                self.poisoned = true;
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::HeadMismatch,
                ));
            }
            Err(error) => return Err(DurableJointSessionError::LogRead(error)),
        };
        let observed_head = match self.log.head() {
            Ok(head) => head,
            Err(error) => return Err(DurableJointSessionError::LogRead(error)),
        };
        if observed_head != Some(expected_result_head)
            || stored.canonical_digest().map_err(DurableJointSessionError::Record)? != digest
        {
            self.poisoned = true;
            return Err(DurableJointSessionError::Record(ProjectionRecordRejection::HeadMismatch));
        }
        self.head = Some(expected_result_head);
        self.records.push(record);
        self.pending_append = None;
        Ok(match append_outcome {
            JointProjectionAppendOutcome::Appended => DurableRecordOutcome::Appended,
            JointProjectionAppendOutcome::ExactReplay => DurableRecordOutcome::ExactReplay,
        })
    }
}

fn validate_head<LogError, AuthError>(
    head: JointProjectionLogHead,
    key: JointHandoffKey,
    issuer_set_digest: Digest,
) -> Result<(), DurableJointSessionError<LogError, AuthError>> {
    if !head.version.is_supported() {
        return Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::UnsupportedVersion,
        ));
    }
    if !head.key.is_well_formed() {
        return Err(DurableJointSessionError::Record(ProjectionRecordRejection::InvalidHandoffKey));
    }
    if head.key != key {
        return Err(DurableJointSessionError::Record(ProjectionRecordRejection::HandoffMismatch));
    }
    if head.issuer_set_digest != issuer_set_digest {
        return Err(DurableJointSessionError::Record(ProjectionRecordRejection::IssuerPinMismatch));
    }
    if head.sequence == 0
        || head.sequence > MAX_JOINT_PROJECTION_RECORDS
        || head.record_digest == Digest::ZERO
    {
        return Err(DurableJointSessionError::Record(ProjectionRecordRejection::InvalidHead));
    }
    Ok(())
}

fn validate_record<LogError, AuthError>(
    record: &JointProjectionRecord,
    key: JointHandoffKey,
    issuer_set_digest: Digest,
    expected_sequence: u64,
    expected_previous: Option<Digest>,
) -> Result<(), DurableJointSessionError<LogError, AuthError>> {
    let rejection = if !record.version.is_supported() {
        Some(ProjectionRecordRejection::UnsupportedVersion)
    } else if !record.key.is_well_formed() {
        Some(ProjectionRecordRejection::InvalidHandoffKey)
    } else if record.key != key {
        Some(ProjectionRecordRejection::HandoffMismatch)
    } else if record.issuer_set_digest != issuer_set_digest {
        Some(ProjectionRecordRejection::IssuerPinMismatch)
    } else if record.sequence != expected_sequence
        || record.sequence == 0
        || record.sequence > MAX_JOINT_PROJECTION_RECORDS
    {
        Some(ProjectionRecordRejection::InvalidSequence)
    } else if record.previous_record_digest != expected_previous {
        Some(ProjectionRecordRejection::PreviousDigestMismatch)
    } else {
        None
    };
    if let Some(rejection) = rejection {
        return Err(DurableJointSessionError::Record(rejection));
    }
    let local_validation = match &record.kind {
        JointProjectionRecordKind::NativeReceipt(native)
            if native.command_identity.is_zero()
                || native.request.as_slice().is_empty()
                || native.envelope.as_slice().is_empty()
                || native.payload.as_slice().is_empty() =>
        {
            Err(ProjectionRecordRejection::InvalidLocalRecord)
        }
        JointProjectionRecordKind::BeginDestinationActivation { command_identity }
            if command_identity.is_zero() =>
        {
            Err(ProjectionRecordRejection::InvalidLocalRecord)
        }
        JointProjectionRecordKind::EffectFreezeAttempt(attempt) => attempt.validate_integrity(),
        JointProjectionRecordKind::SourceAbortAttempt(attempt) => {
            attempt.as_ref().validate_integrity()
        }
        JointProjectionRecordKind::SourceFenceAttempt(attempt) => {
            attempt.as_ref().validate_integrity()
        }
        JointProjectionRecordKind::DestinationActivationAttempt(attempt) => {
            attempt.as_ref().validate_integrity()
        }
        JointProjectionRecordKind::SourceAbortObserved(observed)
        | JointProjectionRecordKind::SourceFenceObserved(observed)
        | JointProjectionRecordKind::DestinationActivationPreviewObserved(observed) => {
            observed.validate()
        }
        _ => Ok(()),
    };
    local_validation.map_err(DurableJointSessionError::Record)
}

fn validate_effect_freeze_attempt(
    state: &VerifiedJointState,
    attempt: &EffectFreezeAttempt,
) -> Result<(), ProjectionRecordRejection> {
    attempt.validate_integrity()?;
    let invocation = attempt.decoded_invocation()?;
    let projection = state.state();
    if projection.phase != JointPhase::FrozenUnsealed
        || projection.visa_freeze.is_none()
        || projection.nexus_freeze.is_some()
        || !matches!(projection.decision, OwnershipDecision::Undecided)
        || invocation.key != projection.key
        || invocation.intent.receipt_ref().ok() != projection.intent
        || invocation.intent.key != projection.key
        || Some(invocation.intent.reservation) != projection.reservation
        || Some(invocation.intent.intent_revision) != projection.intent_revision
    {
        return Err(ProjectionRecordRejection::EffectFreezeAttemptConflict);
    }
    Ok(())
}

fn validate_effect_freeze_completion(
    attempt: &EffectFreezeAttempt,
    payload: &[u8],
) -> Result<(), ProjectionRecordRejection> {
    let invocation = attempt.decoded_invocation()?;
    let receipt: NexusFreezeReceipt =
        canonical_from_bytes(payload).map_err(|_| ProjectionRecordRejection::Decode)?;
    let intent = invocation
        .intent
        .receipt_ref()
        .map_err(|_| ProjectionRecordRejection::InvalidLocalRecord)?;
    if receipt.key != invocation.key
        || receipt.intent != intent
        || receipt.registry_instance != invocation.registry_instance
        || receipt.scope_id != invocation.scope_id
        || receipt.scope_generation != invocation.scope_generation
        || receipt.authority_epoch != invocation.authority_epoch
        || receipt.freeze_generation != invocation.freeze_generation
    {
        return Err(ProjectionRecordRejection::EffectFreezeRequestMismatch);
    }
    Ok(())
}

fn validate_source_abort_attempt(
    state: &VerifiedJointState,
    attempt: SourceAbortAttempt,
) -> Result<(), ProjectionRecordRejection> {
    attempt.validate_integrity()?;
    let projection = state.state();
    let OwnershipDecision::Abort(ownership_abort) = projection.decision else {
        return Err(ProjectionRecordRejection::SourceAbortAttemptConflict);
    };
    let valid_phase = match projection.phase {
        JointPhase::AbortDecided => {
            projection.visa_freeze.is_none()
                && projection.nexus_freeze.is_none()
                && projection.thaw.is_none()
                && attempt.nexus_thaw.is_none()
        }
        JointPhase::SourceThawPending => {
            projection.visa_freeze.is_some()
                && projection.nexus_freeze.is_some()
                && projection.thaw.is_some()
                && attempt.nexus_thaw == projection.thaw
        }
        _ => false,
    };
    if attempt.joint_revision != projection.revision
        || attempt.ownership_abort != ownership_abort
        || projection.source_resume.is_some()
        || !valid_phase
    {
        return Err(ProjectionRecordRejection::SourceAbortAttemptConflict);
    }
    Ok(())
}

fn validate_source_fence_attempt(
    state: &VerifiedJointState,
    attempt: SourceFenceAttempt,
) -> Result<(), ProjectionRecordRejection> {
    attempt.validate_integrity()?;
    let projection = state.state();
    let OwnershipDecision::Commit(ownership_commit) = projection.decision else {
        return Err(ProjectionRecordRejection::SourceFenceAttemptConflict);
    };
    let ClosureStatus::Closed { receipt: closure, .. } = projection.closure else {
        return Err(ProjectionRecordRejection::SourceFenceAttemptConflict);
    };
    if attempt.joint_revision != projection.revision
        || attempt.ownership_commit != ownership_commit
        || attempt.closure != closure
        || projection.phase != JointPhase::SourceClosed
        || projection.source_fence.is_some()
    {
        return Err(ProjectionRecordRejection::SourceFenceAttemptConflict);
    }
    Ok(())
}

fn validate_destination_activation_attempt(
    state: &VerifiedJointState,
    attempt: DestinationActivationAttempt,
) -> Result<(), ProjectionRecordRejection> {
    attempt.validate_integrity()?;
    let projection = state.state();
    let OwnershipDecision::Commit(ownership_commit) = projection.decision else {
        return Err(ProjectionRecordRejection::DestinationActivationAttemptConflict);
    };
    let ClosureStatus::Closed { receipt: closure, .. } = projection.closure else {
        return Err(ProjectionRecordRejection::DestinationActivationAttemptConflict);
    };
    let Some(source_fence) = projection.source_fence else {
        return Err(ProjectionRecordRejection::DestinationActivationAttemptConflict);
    };
    let Some(destination_commit) = state.destination_commit() else {
        return Err(ProjectionRecordRejection::DestinationActivationAttemptConflict);
    };
    if attempt.joint_revision != projection.revision
        || attempt.ownership_commit != ownership_commit
        || attempt.closure != closure
        || attempt.source_fence != source_fence
        || attempt.commit_operation != destination_commit.operation
        || attempt.commit_idempotency != destination_commit.idempotency
        || attempt.commit_request_digest != destination_commit.request_digest
        || projection.phase != JointPhase::SourceClosed
        || projection.destination_activation.is_some()
    {
        return Err(ProjectionRecordRejection::DestinationActivationAttemptConflict);
    }
    Ok(())
}

fn validate_local_projection_observed(
    observed: LocalProjectionObserved,
    expected_attempt_record_digest: Option<Digest>,
    expected_pre_journal_position: JournalPosition,
    expected_pre_state_digest: Digest,
) -> Result<(), ProjectionRecordRejection> {
    observed.validate()?;
    if Some(observed.attempt_record_digest) != expected_attempt_record_digest
        || observed.journal_position.0 <= expected_pre_journal_position.0
        || observed.state_digest == expected_pre_state_digest
    {
        return Err(ProjectionRecordRejection::LocalProjectionObservationMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn advance_local_projection_obligation<T, F, P>(
    actual_kind: ReceiptKind,
    completion_kind: ReceiptKind,
    actual_request_digest: Digest,
    receipt: ReceiptRef,
    payload: &[u8],
    obligation: LocalProjectionObligation<T>,
    observed: Option<LocalProjectionObserved>,
    expected_attempt_record_digest: Option<Digest>,
    request_digest: F,
    decode_projection: P,
    missing: ProjectionRecordRejection,
) -> Result<LocalProjectionObligation<T>, ProjectionRecordRejection>
where
    T: Copy,
    F: FnOnce(T) -> Digest,
    P: FnOnce(&[u8]) -> Result<(JournalPosition, Digest), ProjectionRecordRejection>,
{
    match obligation {
        LocalProjectionObligation::OutcomeUnknown(attempt) => {
            if actual_kind != completion_kind {
                return Err(ProjectionRecordRejection::LocalProjectionOutcomeUnknown);
            }
            if request_digest(attempt) != actual_request_digest {
                return Err(ProjectionRecordRejection::LocalAttemptRequestMismatch);
            }
            let observed =
                observed.ok_or(ProjectionRecordRejection::MissingLocalProjectionObservation)?;
            if Some(observed.attempt_record_digest) != expected_attempt_record_digest {
                return Err(ProjectionRecordRejection::LocalProjectionObservationMismatch);
            }
            let (journal_position, state_digest) = decode_projection(payload)?;
            if observed.journal_position != journal_position
                || observed.state_digest != state_digest
            {
                return Err(ProjectionRecordRejection::LocalProjectionObservationMismatch);
            }
            Ok(LocalProjectionObligation::ReceiptObserved { attempt, receipt })
        }
        LocalProjectionObligation::NotAttempted if actual_kind == completion_kind => Err(missing),
        LocalProjectionObligation::ReceiptObserved { .. } if actual_kind == completion_kind => {
            Err(ProjectionRecordRejection::ConflictingReplay)
        }
        obligation => Ok(obligation),
    }
}

fn advance_destination_activation_obligation(
    actual_kind: ReceiptKind,
    receipt_reference: ReceiptRef,
    payload: &[u8],
    obligation: LocalProjectionObligation<DestinationActivationAttempt>,
    expected_attempt_record_digest: Option<Digest>,
    observed: Option<LocalProjectionObserved>,
) -> Result<LocalProjectionObligation<DestinationActivationAttempt>, ProjectionRecordRejection> {
    match obligation {
        LocalProjectionObligation::OutcomeUnknown(attempt) => {
            if actual_kind != ReceiptKind::VisaDestinationActivation {
                return Err(ProjectionRecordRejection::LocalProjectionOutcomeUnknown);
            }
            let receipt: VisaDestinationActivationReceipt =
                canonical_from_bytes(payload).map_err(|_| ProjectionRecordRejection::Decode)?;
            if canonical_bytes(&receipt).ok().as_deref() != Some(payload) {
                return Err(ProjectionRecordRejection::NonCanonical);
            }
            if receipt.source_fence != attempt.source_fence
                || receipt.activation_command != attempt.joint_command
                || receipt.resume_command != attempt.resume_command
                || Some(receipt.activation_attempt_record_digest) != expected_attempt_record_digest
            {
                return Err(ProjectionRecordRejection::LocalAttemptRequestMismatch);
            }
            let observed =
                observed.ok_or(ProjectionRecordRejection::MissingLocalProjectionObservation)?;
            if Some(observed.attempt_record_digest) != expected_attempt_record_digest
                || observed.journal_position != receipt.journal_position
                || observed.state_digest != receipt.state_digest
            {
                return Err(ProjectionRecordRejection::LocalProjectionObservationMismatch);
            }
            Ok(LocalProjectionObligation::ReceiptObserved { attempt, receipt: receipt_reference })
        }
        LocalProjectionObligation::NotAttempted
            if actual_kind == ReceiptKind::VisaDestinationActivation =>
        {
            Err(ProjectionRecordRejection::MissingDestinationActivationAttempt)
        }
        LocalProjectionObligation::ReceiptObserved { .. }
            if actual_kind == ReceiptKind::VisaDestinationActivation =>
        {
            Err(ProjectionRecordRejection::ConflictingReplay)
        }
        obligation => Ok(obligation),
    }
}

fn decode_source_resume_projection(
    payload: &[u8],
) -> Result<(JournalPosition, Digest), ProjectionRecordRejection> {
    let receipt: VisaSourceResumeReceipt =
        canonical_from_bytes(payload).map_err(|_| ProjectionRecordRejection::Decode)?;
    Ok((receipt.journal_position, receipt.state_digest))
}

fn decode_source_fence_projection(
    payload: &[u8],
) -> Result<(JournalPosition, Digest), ProjectionRecordRejection> {
    let receipt: VisaSourceFenceReceipt =
        canonical_from_bytes(payload).map_err(|_| ProjectionRecordRejection::Decode)?;
    Ok((receipt.journal_position, receipt.state_digest))
}

fn decode_request<LogError, AuthError>(
    bytes: &[u8],
) -> Result<ReceiptRequest, DurableJointSessionError<LogError, AuthError>> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err(DurableJointSessionError::Record(if bytes.is_empty() {
            ProjectionRecordRejection::EmptyNativeBytes
        } else {
            ProjectionRecordRejection::NativeBytesTooLarge
        }));
    }
    let request: ReceiptRequest = match canonical_from_bytes(bytes) {
        Ok(request) => request,
        Err(DecodeError::Codec) => {
            return Err(DurableJointSessionError::Record(ProjectionRecordRejection::RequestDecode));
        }
        Err(DecodeError::TrailingBytes) => {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::NonCanonicalRequest,
            ));
        }
    };
    if canonical_bytes(&request).ok().as_deref() != Some(bytes) {
        return Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::NonCanonicalRequest,
        ));
    }
    Ok(request)
}

fn decode_envelope<LogError, AuthError>(
    bytes: &[u8],
) -> Result<ReceiptEnvelope, DurableJointSessionError<LogError, AuthError>> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_ENVELOPE_BYTES {
        return Err(DurableJointSessionError::Record(if bytes.is_empty() {
            ProjectionRecordRejection::EmptyNativeBytes
        } else {
            ProjectionRecordRejection::NativeBytesTooLarge
        }));
    }
    let envelope: ReceiptEnvelope = match canonical_from_bytes(bytes) {
        Ok(envelope) => envelope,
        Err(DecodeError::Codec) => {
            return Err(DurableJointSessionError::Verification(
                ReceiptVerificationError::EnvelopeDecode,
            ));
        }
        Err(DecodeError::TrailingBytes) => {
            return Err(DurableJointSessionError::Verification(
                ReceiptVerificationError::NonCanonicalEnvelope,
            ));
        }
    };
    if canonical_bytes(&envelope).ok().as_deref() != Some(bytes) {
        return Err(DurableJointSessionError::Verification(
            ReceiptVerificationError::NonCanonicalEnvelope,
        ));
    }
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
fn verify_transition<A, LogError>(
    state: &VerifiedJointState,
    command_identity: Identity,
    kind: ReceiptKind,
    request: &ReceiptRequest,
    decoded_envelope: &ReceiptEnvelope,
    envelope_bytes: &[u8],
    payload: &[u8],
    authenticator: &A,
) -> Result<VerifiedTransition, DurableJointSessionError<LogError, A::Error>>
where
    A: NativeReceiptAuthenticator,
{
    if payload.is_empty() || payload.len() > MAX_NATIVE_PAYLOAD_BYTES {
        return Err(DurableJointSessionError::Record(if payload.is_empty() {
            ProjectionRecordRejection::EmptyNativeBytes
        } else {
            ProjectionRecordRejection::NativeBytesTooLarge
        }));
    }
    macro_rules! verify {
        ($receipt:ty) => {{
            verify_typed_transition::<$receipt, A, LogError>(
                state,
                command_identity,
                request,
                decoded_envelope,
                envelope_bytes,
                payload,
                authenticator,
            )
        }};
    }
    match kind {
        ReceiptKind::PrepareIntent => verify!(PrepareIntentReceipt),
        ReceiptKind::VisaFreeze => verify!(VisaFreezeReceipt),
        ReceiptKind::NexusFreeze => verify!(NexusFreezeReceipt),
        ReceiptKind::DestinationPrepared => verify!(DestinationPreparedReceipt),
        ReceiptKind::OwnershipPrepared => verify!(OwnershipPreparedReceipt),
        ReceiptKind::OwnershipAbort => verify!(OwnershipAbortReceipt),
        ReceiptKind::OwnershipCommit => verify!(OwnershipCommitReceipt),
        ReceiptKind::NexusThaw => verify!(NexusThawReceipt),
        ReceiptKind::ClosureProgress => verify!(ClosureProgressReceipt),
        ReceiptKind::Closure => verify!(ClosureReceipt),
        ReceiptKind::RetainedTombstone => verify!(RetainedTombstoneReceipt),
        ReceiptKind::VisaSourceFence => verify!(VisaSourceFenceReceipt),
        ReceiptKind::VisaSourceResume => verify!(VisaSourceResumeReceipt),
        ReceiptKind::VisaDestinationActivation => verify!(VisaDestinationActivationReceipt),
    }
}

fn verify_typed_transition<T, A, LogError>(
    state: &VerifiedJointState,
    command_identity: Identity,
    request: &ReceiptRequest,
    decoded_envelope: &ReceiptEnvelope,
    envelope_bytes: &[u8],
    payload: &[u8],
    authenticator: &A,
) -> Result<VerifiedTransition, DurableJointSessionError<LogError, A::Error>>
where
    T: VerifiedCommandReceipt + serde::de::DeserializeOwned,
    A: NativeReceiptAuthenticator,
{
    let typed_payload: T = match canonical_from_bytes(payload) {
        Ok(receipt) => receipt,
        Err(DecodeError::Codec) => {
            return Err(DurableJointSessionError::Verification(
                ReceiptVerificationError::PayloadDecode,
            ));
        }
        Err(DecodeError::TrailingBytes) => {
            return Err(DurableJointSessionError::Verification(
                ReceiptVerificationError::NonCanonicalPayload,
            ));
        }
    };
    if canonical_bytes(&typed_payload).ok().as_deref() != Some(payload) {
        return Err(DurableJointSessionError::Verification(
            ReceiptVerificationError::NonCanonicalPayload,
        ));
    }
    let request_matches = decoded_envelope
        .matches_request(request, &typed_payload)
        .map_err(|_| DurableJointSessionError::Record(ProjectionRecordRejection::Encoding))?;
    if !request_matches || request.operation != command_identity {
        return Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::ReceiptRequestMismatch,
        ));
    }
    let verified = verify_native_receipt::<T, A>(envelope_bytes, payload, authenticator)
        .map_err(DurableJointSessionError::Verification)?;
    let reference = verified.receipt_ref();
    let state = record_verified_receipt(state, command_identity, &verified)
        .map_err(DurableJointSessionError::Receipt)?;
    Ok(VerifiedTransition { state, reference })
}

#[allow(clippy::too_many_arguments)]
fn replay_record<A, LogError>(
    state: &mut VerifiedJointState,
    authenticator: &A,
    effect_freeze: &mut EffectFreezeObligation,
    source_abort: &mut LocalProjectionObligation<SourceAbortAttempt>,
    source_abort_attempt_digest: &mut Option<Digest>,
    source_abort_observed: &mut Option<LocalProjectionObserved>,
    source_fence: &mut LocalProjectionObligation<SourceFenceAttempt>,
    source_fence_attempt_digest: &mut Option<Digest>,
    source_fence_observed: &mut Option<LocalProjectionObserved>,
    destination_activation: &mut LocalProjectionObligation<DestinationActivationAttempt>,
    destination_activation_attempt_digest: &mut Option<Digest>,
    destination_activation_observed: &mut Option<LocalProjectionObserved>,
    record_digest: Digest,
    record: &JointProjectionRecord,
) -> Result<(), DurableJointSessionError<LogError, A::Error>>
where
    A: NativeReceiptAuthenticator,
{
    match &record.kind {
        JointProjectionRecordKind::EffectFreezeAttempt(attempt) => {
            if !matches!(effect_freeze, EffectFreezeObligation::NotAttempted) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            validate_effect_freeze_attempt(state, attempt)
                .map_err(DurableJointSessionError::Record)?;
            *effect_freeze = EffectFreezeObligation::OutcomeUnknown(attempt.clone());
        }
        JointProjectionRecordKind::BeginDestinationActivation { .. } => {
            return Err(DurableJointSessionError::Record(
                ProjectionRecordRejection::LegacyLocalAttemptUnsupported,
            ));
        }
        JointProjectionRecordKind::SourceAbortAttempt(attempt) => {
            if !matches!(source_abort, LocalProjectionObligation::NotAttempted) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            ensure_replay_has_no_unresolved_local_projection(
                *source_abort,
                *source_fence,
                *destination_activation,
            )?;
            validate_source_abort_attempt(state, **attempt)
                .map_err(DurableJointSessionError::Record)?;
            *source_abort = LocalProjectionObligation::OutcomeUnknown(**attempt);
            *source_abort_attempt_digest = Some(record_digest);
        }
        JointProjectionRecordKind::SourceAbortObserved(observed) => {
            let attempt = match *source_abort {
                LocalProjectionObligation::OutcomeUnknown(attempt) => attempt,
                LocalProjectionObligation::NotAttempted => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::MissingSourceAbortAttempt,
                    ));
                }
                LocalProjectionObligation::ReceiptObserved { .. } => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::LocalProjectionObservationConflict,
                    ));
                }
            };
            if source_abort_observed.is_some() {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            validate_local_projection_observed(
                *observed,
                *source_abort_attempt_digest,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )
            .map_err(DurableJointSessionError::Record)?;
            *source_abort_observed = Some(*observed);
        }
        JointProjectionRecordKind::SourceFenceAttempt(attempt) => {
            if !matches!(source_fence, LocalProjectionObligation::NotAttempted) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            ensure_replay_has_no_unresolved_local_projection(
                *source_abort,
                *source_fence,
                *destination_activation,
            )?;
            validate_source_fence_attempt(state, **attempt)
                .map_err(DurableJointSessionError::Record)?;
            *source_fence = LocalProjectionObligation::OutcomeUnknown(**attempt);
            *source_fence_attempt_digest = Some(record_digest);
        }
        JointProjectionRecordKind::SourceFenceObserved(observed) => {
            let attempt = match *source_fence {
                LocalProjectionObligation::OutcomeUnknown(attempt) => attempt,
                LocalProjectionObligation::NotAttempted => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::MissingSourceFenceAttempt,
                    ));
                }
                LocalProjectionObligation::ReceiptObserved { .. } => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::LocalProjectionObservationConflict,
                    ));
                }
            };
            if source_fence_observed.is_some() {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            validate_local_projection_observed(
                *observed,
                *source_fence_attempt_digest,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )
            .map_err(DurableJointSessionError::Record)?;
            *source_fence_observed = Some(*observed);
        }
        JointProjectionRecordKind::DestinationActivationAttempt(attempt) => {
            if !matches!(destination_activation, LocalProjectionObligation::NotAttempted) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            if matches!(effect_freeze, EffectFreezeObligation::OutcomeUnknown(_)) {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::EffectFreezeOutcomeUnknown,
                ));
            }
            ensure_replay_has_no_unresolved_local_projection(
                *source_abort,
                *source_fence,
                *destination_activation,
            )?;
            validate_destination_activation_attempt(state, **attempt)
                .map_err(DurableJointSessionError::Record)?;
            let next = state
                .begin_destination_activation(attempt.joint_command)
                .map_err(DurableJointSessionError::Receipt)?;
            if next == *state {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            *state = next;
            *destination_activation = LocalProjectionObligation::OutcomeUnknown(**attempt);
            *destination_activation_attempt_digest = Some(record_digest);
        }
        JointProjectionRecordKind::DestinationActivationPreviewObserved(observed) => {
            let attempt = match *destination_activation {
                LocalProjectionObligation::OutcomeUnknown(attempt) => attempt,
                LocalProjectionObligation::NotAttempted => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::MissingDestinationActivationAttempt,
                    ));
                }
                LocalProjectionObligation::ReceiptObserved { .. } => {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::LocalProjectionObservationConflict,
                    ));
                }
            };
            if destination_activation_observed.is_some() {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::LocalProjectionObservationConflict,
                ));
            }
            validate_local_projection_observed(
                *observed,
                *destination_activation_attempt_digest,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )
            .map_err(DurableJointSessionError::Record)?;
            *destination_activation_observed = Some(*observed);
        }
        JointProjectionRecordKind::NativeReceipt(native) => {
            let request = decode_request(native.request.as_slice())?;
            if request.operation != native.command_identity {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::ReceiptRequestMismatch,
                ));
            }
            let envelope = decode_envelope(native.envelope.as_slice())?;
            if envelope.kind != native.kind {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::ReceiptKindMismatch,
                ));
            }
            let transition = verify_transition(
                state,
                native.command_identity,
                native.kind,
                &request,
                &envelope,
                native.envelope.as_slice(),
                native.payload.as_slice(),
                authenticator,
            )?;
            if transition.state == *state {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::DuplicateRecord,
                ));
            }
            if matches!(effect_freeze, EffectFreezeObligation::OutcomeUnknown(_))
                && native.kind != ReceiptKind::NexusFreeze
            {
                return Err(DurableJointSessionError::Record(
                    ProjectionRecordRejection::EffectFreezeOutcomeUnknown,
                ));
            }
            let next_effect_freeze = if native.kind == ReceiptKind::NexusFreeze {
                let EffectFreezeObligation::OutcomeUnknown(attempt) = effect_freeze else {
                    return Err(DurableJointSessionError::Record(
                        ProjectionRecordRejection::MissingEffectFreezeAttempt,
                    ));
                };
                validate_effect_freeze_completion(attempt, native.payload.as_slice())
                    .map_err(DurableJointSessionError::Record)?;
                EffectFreezeObligation::ReceiptObserved {
                    attempt: attempt.clone(),
                    receipt: transition.reference,
                }
            } else {
                effect_freeze.clone()
            };
            let next_source_abort = advance_local_projection_obligation(
                native.kind,
                ReceiptKind::VisaSourceResume,
                envelope.request_digest,
                transition.reference,
                native.payload.as_slice(),
                *source_abort,
                *source_abort_observed,
                *source_abort_attempt_digest,
                |attempt| attempt.completion_request_digest,
                decode_source_resume_projection,
                ProjectionRecordRejection::MissingSourceAbortAttempt,
            )
            .map_err(DurableJointSessionError::Record)?;
            let next_source_fence = advance_local_projection_obligation(
                native.kind,
                ReceiptKind::VisaSourceFence,
                envelope.request_digest,
                transition.reference,
                native.payload.as_slice(),
                *source_fence,
                *source_fence_observed,
                *source_fence_attempt_digest,
                |attempt| attempt.completion_request_digest,
                decode_source_fence_projection,
                ProjectionRecordRejection::MissingSourceFenceAttempt,
            )
            .map_err(DurableJointSessionError::Record)?;
            let next_destination_activation = advance_destination_activation_obligation(
                native.kind,
                transition.reference,
                native.payload.as_slice(),
                *destination_activation,
                *destination_activation_attempt_digest,
                *destination_activation_observed,
            )
            .map_err(DurableJointSessionError::Record)?;
            *state = transition.state;
            *effect_freeze = next_effect_freeze;
            *source_abort = next_source_abort;
            *source_fence = next_source_fence;
            *destination_activation = next_destination_activation;
        }
    }
    Ok(())
}

fn ensure_replay_has_no_unresolved_local_projection<LogError, AuthError>(
    source_abort: LocalProjectionObligation<SourceAbortAttempt>,
    source_fence: LocalProjectionObligation<SourceFenceAttempt>,
    destination_activation: LocalProjectionObligation<DestinationActivationAttempt>,
) -> Result<(), DurableJointSessionError<LogError, AuthError>> {
    if source_abort.unresolved().is_some()
        || source_fence.unresolved().is_some()
        || destination_activation.unresolved().is_some()
    {
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::LocalProjectionOutcomeUnknown,
        ))
    } else {
        Ok(())
    }
}
