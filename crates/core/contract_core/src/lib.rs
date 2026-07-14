//! Canonical portable contract for vISA state continuity.
//!
//! This crate contains the portable data vocabulary and its canonical wire
//! codec. Runtime engines, providers, host bindings, and scenario-specific
//! policy belong in adapters above this layer.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

mod codec;

pub use codec::{
    CANONICAL_ENCODING, DIGEST_ALGORITHM, DecodeError, EncodeError, canonical_bytes,
    canonical_digest, canonical_from_bytes, snapshot_integrity, state_digest,
};

/// The only schema version accepted by this implementation.
pub const CONTRACT_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Explicit wire/schema version carried by every command, event, and snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
}

impl SchemaVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn is_supported(self) -> bool {
        self.major == CONTRACT_VERSION.major && self.minor == CONTRACT_VERSION.minor
    }
}

/// Stable, portable identity. It is never a native handle or runtime object ID.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Identity(pub [u8; 16]);

impl Identity {
    pub const ZERO: Self = Self([0; 16]);

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 16]
    }
}

/// Generation attached to a portable identity to reject stale references.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Generation(pub u64);

impl Generation {
    pub const INITIAL: Self = Self(0);

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// An identity coupled to the generation at which it is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    pub identity: Identity,
    pub generation: Generation,
}

impl EntityRef {
    pub const fn new(identity: Identity, generation: Generation) -> Self {
        Self { identity, generation }
    }

    pub const fn initial(identity: Identity) -> Self {
        Self::new(identity, Generation::INITIAL)
    }
}

/// Epoch enforced at the external-effect boundary to fence an old owner.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct LeaseEpoch(pub u64);

impl LeaseEpoch {
    pub const INITIAL: Self = Self(0);

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// Position of a committed entry in the authoritative journal.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct JournalPosition(pub u64);

impl JournalPosition {
    pub const ORIGIN: Self = Self(0);

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// Digest produced by the selected canonical encoder and digest algorithm.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Stable identity of one execution node participating in a handoff.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct NodeIdentity(pub Identity);

impl NodeIdentity {
    pub const fn new(identity: Identity) -> Self {
        Self(identity)
    }

    pub fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}

/// Typed, versioned snapshot extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extension {
    pub id: Identity,
    pub version: SchemaVersion,
    pub required: bool,
    pub payload: Vec<u8>,
}

/// Extension version understood by a destination implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionSupport {
    pub id: Identity,
    pub version: SchemaVersion,
}

/// Identity used to deduplicate an externally visible operation.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct IdempotencyKey(pub [u8; 16]);

impl IdempotencyKey {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }
}

/// Rights understood by the Stage 1 canonical contract.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Rights(u16);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const TIMER_ARM: Self = Self(1 << 0);
    pub const TIMER_CANCEL: Self = Self(1 << 1);
    pub const KV_READ: Self = Self(1 << 2);
    pub const KV_WRITE: Self = Self(1 << 3);
    pub const REBIND: Self = Self(1 << 4);
    pub const HANDOFF: Self = Self(1 << 5);
    /// Profile-scoped observation. The profile defines the typed operation;
    /// the canonical core only enforces the authority class.
    pub const PROFILE_READ: Self = Self(1 << 6);
    /// Profile-scoped mutation.
    pub const PROFILE_WRITE: Self = Self(1 << 7);
    /// Profile-scoped lifecycle control such as sync, lock, or cancellation.
    pub const PROFILE_CONTROL: Self = Self(1 << 8);

    const KNOWN: u16 = Self::TIMER_ARM.0
        | Self::TIMER_CANCEL.0
        | Self::KV_READ.0
        | Self::KV_WRITE.0
        | Self::REBIND.0
        | Self::HANDOFF.0
        | Self::PROFILE_READ.0
        | Self::PROFILE_WRITE.0
        | Self::PROFILE_CONTROL.0;
    pub const ALL: Self = Self(Self::KNOWN);

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::KNOWN == 0 { Some(Self(bits)) } else { None }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn is_subset_of(self, other: Self) -> bool {
        other.contains(self)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Active,
    Revoked,
}

/// One node in an explicit authority provenance chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    pub authority: EntityRef,
    pub parent: Option<EntityRef>,
    pub subject: EntityRef,
    pub resource: EntityRef,
    pub rights: Rights,
    pub status: AuthorityStatus,
}

impl AuthorityGrant {
    pub fn active_root(
        authority: EntityRef,
        subject: EntityRef,
        resource: EntityRef,
        rights: Rights,
    ) -> Self {
        Self { authority, parent: None, subject, resource, rights, status: AuthorityStatus::Active }
    }
}

/// Portable duration for the Stage 1 paused monotonic-duration profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogicalDurationNanos(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerClock {
    PausedMonotonicDuration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerClaim {
    pub resource: EntityRef,
    pub clock: TimerClock,
    pub required_rights: Rights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPolicy {
    Deduplicated,
    AtMostOnce,
    AtLeastOnce,
    NonRecoverable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyValueClaim {
    pub resource: EntityRef,
    pub namespace: Identity,
    pub required_rights: Rights,
    pub delivery: DeliveryPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceClaims {
    pub timer: TimerClaim,
    pub key_value: KeyValueClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerDisposition {
    Idle,
    Pending { remaining: LogicalDurationNanos, arm_operation: Identity },
    Completed,
    Cancelled,
    Cleaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerStatus {
    Idle,
    Armed { remaining: LogicalDurationNanos },
    Completed,
    Cancelled,
    Cleaned,
    Frozen(TimerDisposition),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimerState {
    pub claim: TimerClaim,
    pub status: TimerStatus,
    pub active_operation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyValueState {
    pub claim: KeyValueClaim,
    pub last_version: Option<u64>,
    pub last_operation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedValue {
    pub value: Vec<u8>,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    AuthorityDecision,
    EffectOutcome,
    SnapshotIntegrity,
    Binding,
    LeaseCommit,
    SourceFence,
    Cleanup,
}

/// Authority class for an operation whose typed semantics live in a versioned
/// profile extension. This keeps file, request, and provider verbs out of the
/// canonical effect vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileAccess {
    Read,
    Write,
    Control,
}

impl ProfileAccess {
    pub const fn required_rights(self) -> Rights {
        match self {
            Self::Read => Rights::PROFILE_READ,
            Self::Write => Rights::PROFILE_WRITE,
            Self::Control => Rights::PROFILE_CONTROL,
        }
    }
}

/// Portable reference to evidence; evidence bytes and storage remain external.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub identity: Identity,
    pub kind: EvidenceKind,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    TimerArm {
        remaining: LogicalDurationNanos,
    },
    TimerCancel {
        target_operation: Identity,
    },
    KeyValueRead {
        key: Vec<u8>,
    },
    KeyValueCompareAndSet {
        key: Vec<u8>,
        expected_version: Option<u64>,
        value: Vec<u8>,
    },
    /// A typed resource-profile operation. `payload` is interpreted only by
    /// the named profile; providers and runtimes may not redefine it.
    Profile {
        profile: Identity,
        access: ProfileAccess,
        payload: Vec<u8>,
    },
    LeaseCommit {
        handoff: Identity,
        snapshot: Identity,
        destination: NodeIdentity,
        expected_epoch: LeaseEpoch,
        next_epoch: LeaseEpoch,
    },
}

/// Fully authorized, provider-neutral request for one external effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub operation: Identity,
    pub idempotency_key: IdempotencyKey,
    pub causal_parent: Option<Identity>,
    pub node: NodeIdentity,
    pub subject: EntityRef,
    pub resource: EntityRef,
    pub authority: EntityRef,
    pub lease_epoch: LeaseEpoch,
    pub request_digest: Digest,
    pub kind: EffectKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectResult {
    TimerArmed { remaining: LogicalDurationNanos },
    TimerCancelled,
    KeyValueRead { value: Option<VersionedValue> },
    KeyValue { version: u64, applied: bool },
    Profile { profile: Identity, payload: Vec<u8> },
    LeaseAdvanced { owner: NodeIdentity, epoch: LeaseEpoch, source_fence: EvidenceRef },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Denied,
    Conflict,
    Unavailable,
    Integrity,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFailure {
    pub class: FailureClass,
    pub retryable: bool,
    pub evidence: Option<EvidenceRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcome {
    Succeeded { result: EffectResult, evidence: EvidenceRef },
    Failed(EffectFailure),
    Cancelled { evidence: Option<EvidenceRef> },
    Unsupported { evidence: Option<EvidenceRef> },
    Indeterminate { evidence: Option<EvidenceRef> },
}

impl EffectOutcome {
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Pending,
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub request: EffectRequest,
    pub outcome: Option<EffectOutcome>,
    pub cleanup: CleanupStatus,
}

impl OperationRecord {
    pub fn prepared(request: EffectRequest) -> Self {
        Self { request, outcome: None, cleanup: CleanupStatus::Pending }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffPhase {
    Dormant,
    Running,
    Quiescing,
    Frozen,
    Exported,
    DestinationPrepared,
    Committed,
    Aborted,
}

/// Global ownership truth committed atomically with the fencing epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub owner: Option<NodeIdentity>,
    pub epoch: LeaseEpoch,
}

impl Ownership {
    pub const fn unowned(last_epoch: LeaseEpoch) -> Self {
        Self { owner: None, epoch: last_epoch }
    }

    pub const fn owned(owner: NodeIdentity, epoch: LeaseEpoch) -> Self {
        Self { owner: Some(owner), epoch }
    }

    pub const fn epoch(self) -> LeaseEpoch {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationRole {
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Inactive,
    Active,
    Prepared,
    Fenced,
}

/// Local projection of the globally committed ownership decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub node: NodeIdentity,
    pub role: ActivationRole,
    pub status: ActivationStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub journal_position: JournalPosition,
    pub evidence: EvidenceRef,
}

/// Portable snapshot projection. Native bindings and credentials cannot appear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBody {
    pub version: SchemaVersion,
    pub profile_version: SchemaVersion,
    pub snapshot: SnapshotRecord,
    pub source_node: NodeIdentity,
    pub component: EntityRef,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub source_lease_epoch: LeaseEpoch,
    pub portable_state: Vec<u8>,
    pub claims: ResourceClaims,
    pub timer: TimerDisposition,
    pub key_value_last_version: Option<u64>,
    pub key_value_last_operation: Option<Identity>,
    pub extensions: Vec<Extension>,
    pub authorities: Vec<AuthorityGrant>,
    pub operations: Vec<OperationRecord>,
}

/// Integrity-protected transport envelope for a portable snapshot body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {
    pub version: SchemaVersion,
    pub body: SnapshotBody,
    pub integrity: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingReceipt {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub claim: EntityRef,
    pub binding: EntityRef,
    pub node: NodeIdentity,
    pub authority: EntityRef,
    pub exposed_rights: Rights,
    pub lease_epoch: LeaseEpoch,
    pub evidence: EvidenceRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDestination {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub destination: NodeIdentity,
    pub component_generation: Generation,
    pub expected_epoch: LeaseEpoch,
    pub next_epoch: LeaseEpoch,
    pub authorities: Vec<AuthorityGrant>,
    pub bindings: Vec<BindingReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCleanup {
    pub snapshot: Identity,
    pub evidence: Option<EvidenceRef>,
}

/// Compact committed truth for the Stage 1 capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalState {
    pub version: SchemaVersion,
    pub profile_version: SchemaVersion,
    pub component: EntityRef,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub phase: HandoffPhase,
    pub activation: Activation,
    pub ownership: Ownership,
    pub portable_state: Vec<u8>,
    pub timer: TimerState,
    pub key_value: KeyValueState,
    pub extensions: Vec<Extension>,
    pub authorities: Vec<AuthorityGrant>,
    pub operations: Vec<OperationRecord>,
    pub exported_snapshot: Option<SnapshotRecord>,
    pub prepared_destination: Option<PreparedDestination>,
    pub preparation_cleanup: Option<PreparationCleanup>,
    pub evidence: Vec<EvidenceRef>,
}

impl CanonicalState {
    pub fn dormant(
        component: EntityRef,
        node: NodeIdentity,
        component_digest: Digest,
        profile_digest: Digest,
        profile_version: SchemaVersion,
        claims: ResourceClaims,
        authorities: Vec<AuthorityGrant>,
    ) -> Self {
        Self::dormant_with_extensions(
            component,
            node,
            component_digest,
            profile_digest,
            profile_version,
            claims,
            authorities,
            Vec::new(),
        )
    }

    /// Construct a dormant activation with profile-owned canonical state.
    /// Extension payloads must already be validated by the selected profile.
    #[allow(clippy::too_many_arguments)]
    pub fn dormant_with_extensions(
        component: EntityRef,
        node: NodeIdentity,
        component_digest: Digest,
        profile_digest: Digest,
        profile_version: SchemaVersion,
        claims: ResourceClaims,
        authorities: Vec<AuthorityGrant>,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            version: CONTRACT_VERSION,
            profile_version,
            component,
            component_digest,
            profile_digest,
            phase: HandoffPhase::Dormant,
            activation: Activation {
                node,
                role: ActivationRole::Source,
                status: ActivationStatus::Inactive,
            },
            ownership: Ownership::unowned(LeaseEpoch::INITIAL),
            portable_state: Vec::new(),
            timer: TimerState {
                claim: claims.timer,
                status: TimerStatus::Idle,
                active_operation: None,
            },
            key_value: KeyValueState {
                claim: claims.key_value,
                last_version: None,
                last_operation: None,
            },
            extensions,
            authorities,
            operations: Vec::new(),
            exported_snapshot: None,
            prepared_destination: None,
            preparation_cleanup: None,
            evidence: Vec::new(),
        }
    }

    pub fn claims(&self) -> ResourceClaims {
        ResourceClaims { timer: self.timer.claim.clone(), key_value: self.key_value.claim.clone() }
    }

    pub fn snapshot_body(&self) -> Option<SnapshotBody> {
        let snapshot = self.exported_snapshot.clone()?;
        let timer = match self.timer.status {
            TimerStatus::Frozen(disposition) => disposition,
            _ => return None,
        };
        let source_node = self.ownership.owner?;
        let source_lease_epoch = self.ownership.epoch;

        Some(SnapshotBody {
            version: CONTRACT_VERSION,
            profile_version: self.profile_version,
            snapshot,
            source_node,
            component: self.component,
            component_digest: self.component_digest,
            profile_digest: self.profile_digest,
            source_lease_epoch,
            portable_state: self.portable_state.clone(),
            claims: self.claims(),
            timer,
            key_value_last_version: self.key_value.last_version,
            key_value_last_operation: self.key_value.last_operation,
            extensions: self.extensions.clone(),
            authorities: self.authorities.clone(),
            operations: self.operations.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub version: SchemaVersion,
    pub identity: Identity,
    pub kind: CommandKind,
}

impl Command {
    pub const fn new(identity: Identity, kind: CommandKind) -> Self {
        Self { version: CONTRACT_VERSION, identity, kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Activate {
        authority: EntityRef,
        lease_epoch: LeaseEpoch,
    },
    AttenuateAuthority {
        parent: EntityRef,
        derived: AuthorityGrant,
    },
    RevokeAuthority {
        authority: EntityRef,
    },
    RequestEffect(EffectRequest),
    ResolveEffect {
        operation: Identity,
        outcome: EffectOutcome,
    },
    ReconcileEffect {
        operation: Identity,
        outcome: EffectOutcome,
    },
    CleanupOperation {
        operation: Identity,
        evidence: EvidenceRef,
    },
    TimerCompleted {
        timer: EntityRef,
        arm_operation: Identity,
        lease_epoch: LeaseEpoch,
        evidence: EvidenceRef,
    },
    BeginHandoff {
        authority: EntityRef,
    },
    Freeze {
        portable_state: Vec<u8>,
        timer: TimerDisposition,
    },
    ExportSnapshot {
        snapshot: SnapshotRecord,
    },
    PrepareDestination(PreparedDestination),
    AbortHandoff {
        evidence: Option<EvidenceRef>,
    },
    CleanupPreparation {
        snapshot: Identity,
        evidence: Option<EvidenceRef>,
    },
    ResumeSource,
    ResumeDestination,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: SchemaVersion,
    pub identity: Identity,
    pub kind: EventKind,
}

impl Event {
    pub const fn new(identity: Identity, kind: EventKind) -> Self {
        Self { version: CONTRACT_VERSION, identity, kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Activated {
        lease_epoch: LeaseEpoch,
    },
    AuthorityAttenuated {
        grant: AuthorityGrant,
    },
    AuthorityRevoked {
        authority: EntityRef,
        revoked_generation: Generation,
    },
    EffectPrepared {
        request: EffectRequest,
    },
    EffectResolved {
        operation: Identity,
        outcome: EffectOutcome,
    },
    EffectReconciled {
        operation: Identity,
        outcome: EffectOutcome,
    },
    OperationCleaned {
        operation: Identity,
        evidence: EvidenceRef,
    },
    TimerCompleted {
        timer: EntityRef,
        arm_operation: Identity,
        evidence: EvidenceRef,
    },
    HandoffStarted,
    Frozen {
        portable_state: Vec<u8>,
        timer: TimerDisposition,
    },
    SnapshotExported {
        snapshot: SnapshotRecord,
    },
    DestinationPrepared {
        prepared: PreparedDestination,
    },
    HandoffCommitted {
        operation: Identity,
        handoff: Identity,
        snapshot: Identity,
        source: NodeIdentity,
        destination: NodeIdentity,
        previous_epoch: LeaseEpoch,
        new_epoch: LeaseEpoch,
        outcome: EffectOutcome,
    },
    HandoffAborted {
        evidence: Option<EvidenceRef>,
    },
    PreparationCleaned {
        cleanup: PreparationCleanup,
    },
    SourceResumed,
    DestinationResumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Replay {
    Operation(OperationRecord),
    Event(Event),
    NoChange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Commit(Event),
    Execute { intent: Event, request: EffectRequest },
    Replay(Replay),
    Reject(Rejection),
}

impl Decision {
    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Reject(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    UnsupportedVersion { found: SchemaVersion },
    InvalidIdentity,
    InvalidRights,
    StaleGeneration { identity: Identity, expected: Generation, actual: Generation },
    UnknownAuthority { authority: EntityRef },
    AuthorityRevoked { authority: EntityRef },
    AuthorityAmplification { requested: Rights, available: Rights },
    InsufficientAuthority { required: Rights, granted: Rights },
    AuthoritySubjectMismatch,
    AuthorityResourceMismatch,
    InvalidPhase { actual: HandoffPhase },
    LeaseEpochMismatch { expected: LeaseEpoch, actual: LeaseEpoch },
    NodeMismatch { expected: NodeIdentity, actual: NodeIdentity },
    LeaseEpochExhausted,
    GenerationExhausted,
    DuplicateOperation { operation: Identity },
    IdempotencyConflict { key: IdempotencyKey },
    UnknownOperation { operation: Identity },
    OperationAlreadyResolved { operation: Identity },
    OutcomeMismatch,
    InFlightEffect { operation: Identity },
    IndeterminateEffect { operation: Identity },
    CleanupBlocked { operation: Identity },
    TimerStateConflict,
    SnapshotMismatch,
    SnapshotIntegrityMismatch,
    ProfileMismatch,
    UnsupportedExtension { id: Identity, version: SchemaVersion },
    UnknownProfile { id: Identity },
    InvalidProfilePayload { id: Identity },
    SnapshotUnavailable,
    SnapshotAlreadyExported,
    InvalidBinding { claim: EntityRef },
    MissingBinding { claim: EntityRef },
    EventNotApplicable,
}

/// Digest-bound event persisted by the authoritative journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub version: SchemaVersion,
    pub position: JournalPosition,
    pub input_state: Digest,
    pub output_state: Digest,
    pub event: Event,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_only_construct_known_bits_and_intersect_monotonically() {
        let timer = Rights::TIMER_ARM.union(Rights::TIMER_CANCEL);
        let narrowed = timer.intersection(Rights::TIMER_ARM);

        assert_eq!(narrowed, Rights::TIMER_ARM);
        assert!(narrowed.is_subset_of(timer));
        assert!(Rights::from_bits(1 << 15).is_none());
    }

    #[test]
    fn generation_and_epoch_never_wrap() {
        assert_eq!(Generation(u64::MAX).next(), None);
        assert_eq!(LeaseEpoch(u64::MAX).next(), None);
        assert_eq!(JournalPosition(u64::MAX).next(), None);
    }
}
