//! Narrow, provider-neutral ports for vISA state continuity.
//!
//! These traits expose mechanisms. They do not grant authority and they do not
//! define a second command, event, identity, or outcome vocabulary.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

mod effect_closure;
use contract_core::{
    AuthorityGrant, BindingReceipt, Digest, EffectOutcome, EffectRequest, EntityRef, EvidenceRef,
    Extension, IdempotencyKey, Identity, JournalEntry, JournalPosition, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, OperationRecord, Rights,
};
pub use effect_closure::*;

/// Provider-neutral failure categories. Canonical effect outcomes remain in
/// [`contract_core::EffectOutcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unsupported,
    NotFound,
    Conflict,
    StaleGeneration,
    StaleEpoch,
    Denied,
    Revoked,
    Integrity,
    Unavailable,
    OutcomeUnknown,
    Storage,
}

/// A failure to execute or durably observe a provider operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub retryable: bool,
}

impl ProviderError {
    pub const fn new(kind: ProviderErrorKind, retryable: bool) -> Self {
        Self { kind, retryable }
    }
}

/// Provider-side observation used for effect reconciliation. This is not a
/// canonical journal entry and cannot advance canonical state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationObservation {
    pub record: OperationRecord,
}

/// Canonical journal routing scope for one local activation stream.
///
/// Source and destination coordinators bind distinct scopes while sharing the
/// same provider transaction domain for leases and external resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalScope {
    pub node: NodeIdentity,
    pub component: Identity,
}

/// Ownership change committed together with its canonical journal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseTransition {
    pub resource: EntityRef,
    pub expected_owner: NodeIdentity,
    pub next_owner: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub next_epoch: LeaseEpoch,
}

/// Provider-validated handoff transition and enforcement evidence. It remains
/// inactive until supplied to [`JournalPort::commit_bundle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLeaseTransitions {
    pub transitions: Vec<LeaseTransition>,
    pub outcome: EffectOutcome,
}

/// One durable journal resolution, optionally coupled to an ownership change.
///
/// A successful `LeaseCommit` must carry a transition. Providers commit the
/// journal outcome and that transition in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBundle {
    pub entry: JournalEntry,
    pub lease_transitions: Vec<LeaseTransition>,
    pub final_authorities: Vec<EntityRef>,
}

/// A local, crash-stable projection of an externally authoritative handoff
/// decision onto the source journal and provider leases.
///
/// The external ownership service remains the decision authority. This bundle
/// contains only the already-validated canonical event and the local lease
/// transitions needed to make the old source unusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalSourceFenceBundle {
    pub entry: JournalEntry,
    pub lease_transitions: Vec<LeaseTransition>,
    pub decision_digest: Digest,
    pub closure_digest: Digest,
}

/// Exact source-side abort/resume projection requested by the joint-handoff
/// runtime. The request is also used to reconcile a local commit whose joint
/// receipt was not recorded before a process crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAbortProjectionRequest {
    pub handoff: Identity,
    pub snapshot: Option<Identity>,
    pub local_freeze_recorded: bool,
    pub abort_command: Identity,
    pub resume_command: Identity,
    pub abort_evidence: EvidenceRef,
    pub thaw_evidence: Option<EvidenceRef>,
}

/// Exact destination-side lease-commit/resume projection requested by the
/// joint-handoff runtime. `request_digest` binds the request prepared by the
/// neutral protocol before any local effect is executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationActivationProjectionRequest {
    pub handoff: Identity,
    pub commit_command: Identity,
    pub commit_operation: Identity,
    pub commit_idempotency: IdempotencyKey,
    pub request_digest: Digest,
    pub resume_command: Identity,
}

/// Provider transaction used only by the joint-handoff composition profile.
pub trait ExternalHandoffProjectionPort {
    /// Atomically append the source `HandoffCommitted` projection and advance
    /// every local resource lease. Replaying the exact bundle is idempotent;
    /// any conflicting event or transition fails closed.
    fn commit_external_source_fence(
        &mut self,
        bundle: &ExternalSourceFenceBundle,
    ) -> Result<(), ProviderError>;
}

/// Source activation entry and all initial profiled resource leases. Providers
/// commit these in one transaction before the source is published active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationBundle {
    pub entry: JournalEntry,
    pub initial_leases: Vec<LeaseRecord>,
}

/// Canonical journal persistence plus provider operation reconciliation.
pub trait JournalPort {
    /// Append an entry already constructed by the coordinator and reducer.
    /// `EffectPrepared` also creates the provider operation intent; resolved
    /// and cleanup events update only the matching provider observation.
    fn append_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError>;

    fn commit_activation(&mut self, bundle: &ActivationBundle) -> Result<(), ProviderError>;

    fn commit_bundle(&mut self, bundle: &CommitBundle) -> Result<(), ProviderError>;

    fn entry(&self, position: JournalPosition) -> Result<Option<JournalEntry>, ProviderError>;

    fn operation(&self, operation: Identity)
    -> Result<Option<OperationObservation>, ProviderError>;

    fn idempotency(
        &self,
        key: IdempotencyKey,
    ) -> Result<Option<OperationObservation>, ProviderError>;

    fn replay_from(
        &self,
        after: Option<JournalPosition>,
    ) -> Result<Vec<JournalEntry>, ProviderError>;
}

/// Versioned and deduplicated conditional key-value effects.
pub trait KvPort {
    /// Execute a canonical `KeyValueRead` request and durably retain the
    /// observed versioned value for reconciliation.
    fn read(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError>;

    /// Execute a canonical `KeyValueCompareAndSet` request. The key-value
    /// mutation and its operation/idempotency outcome are one transaction.
    fn compare_and_set(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError>;

    /// Reconcile a possibly lost acknowledgement by both identities.
    fn query_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError>;
}

/// Mechanism port for versioned resource-profile operations. The canonical
/// request identifies the profile and carries its typed payload; implementations
/// may not reinterpret an unknown profile.
pub trait ProfilePort {
    /// Permanently harden one profile on this provider instance. There is no
    /// downgrade operation: reopening the legacy path requires a new provider
    /// instance and therefore a new runtime admission decision.
    fn require_profile_dispatch_authorization(
        &mut self,
        _profile: Identity,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::new(ProviderErrorKind::Unsupported, false))
    }

    /// Arm the mechanism provider with one authorization minted by a consumed
    /// closure-provider commit. Implementations must consume the value even on
    /// a later request-binding mismatch.
    fn arm_profile_dispatch(
        &mut self,
        _authorization: ProfileDispatchAuthorization,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::new(ProviderErrorKind::Unsupported, false))
    }

    /// Close or cancel the currently armed gate and report whether the exact
    /// binding was consumed by the profile execution sink.
    ///
    /// Before returning either `Ok` or `Err`, an implementation must
    /// irreversibly discard every armed or consumed gate selected by this
    /// finish attempt. In particular, a binding mismatch may report an error
    /// but may not leave the authorization reusable. Providers which cannot
    /// meet this rule are not safe for admitted execution.
    fn finish_profile_dispatch(
        &mut self,
        _binding: EffectRequestBinding,
    ) -> Result<bool, ProviderError> {
        Err(ProviderError::new(ProviderErrorKind::Unsupported, false))
    }

    fn execute_profile(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError>;

    /// Reconcile an operation whose completion acknowledgement may have been
    /// lost. Both identities must select the same durable operation.
    fn query_profile_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError>;

    /// Reconcile provider-owned durable state for an operation whose outcome
    /// is indeterminate. Providers with a redo plan may complete it here;
    /// providers whose truth is already queryable can use the default path.
    fn reconcile_profile_operation(
        &mut self,
        request: &EffectRequest,
        _extension: &Extension,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        self.query_profile_operation(request.operation, request.idempotency_key)
    }

    fn cleanup_profile_operation(&mut self, request: &EffectRequest) -> Result<(), ProviderError>;
}

/// Provider observation of a live host timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerObservation {
    Pending(LogicalDurationNanos),
    Completed { evidence: contract_core::EvidenceRef },
    Cancelled { evidence: contract_core::EvidenceRef },
    Absent,
}

/// Canonical timer disposition used to rebuild a process-local host binding
/// after crash recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerRecovery {
    Running { remaining: LogicalDurationNanos },
    Suspended { remaining: LogicalDurationNanos },
}

/// Paused-remaining-duration timer effects and host-local observation.
pub trait TimerPort {
    fn arm(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError>;

    fn cancel(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError>;

    fn restore_timer_binding(
        &mut self,
        arm_request: &EffectRequest,
        recovery: TimerRecovery,
    ) -> Result<(), ProviderError>;

    fn observe(&mut self, arm_operation: Identity) -> Result<TimerObservation, ProviderError>;

    /// Stop a pending timer and return its fixed remaining logical duration.
    /// Repeating suspension returns the same duration.
    fn suspend_timer(&mut self, arm_operation: Identity)
    -> Result<TimerObservation, ProviderError>;

    /// Restart a suspended timer from its recorded remaining duration.
    /// Repeating resume never resets an already running deadline.
    fn resume_suspended(&mut self, arm_operation: Identity) -> Result<(), ProviderError>;

    fn cleanup_timer(&mut self, arm_operation: Identity) -> Result<(), ProviderError>;
}

/// Host authorization policy used while reauthorizing a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityPolicy {
    pub subject: EntityRef,
    pub resource: EntityRef,
    pub allowed_rights: Rights,
}

/// Request to derive fresh destination authority from a live source chain and
/// destination policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReauthorizationRequest {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub source_authority: EntityRef,
    pub destination_authority: EntityRef,
    pub destination_subject: EntityRef,
    pub resource: EntityRef,
    pub required_rights: Rights,
}

/// Durable policy, attenuation, revocation, and effect authorization.
pub trait AuthorityPort {
    fn install_policy(&mut self, policy: AuthorityPolicy) -> Result<(), ProviderError>;

    fn install_grant(&mut self, grant: &AuthorityGrant) -> Result<(), ProviderError>;

    fn attenuate(
        &mut self,
        handoff: Identity,
        snapshot: Identity,
        parent: EntityRef,
        derived: &AuthorityGrant,
    ) -> Result<AuthorityGrant, ProviderError>;

    fn revoke(&mut self, authority: EntityRef) -> Result<(), ProviderError>;

    fn reauthorize(
        &mut self,
        request: ReauthorizationRequest,
    ) -> Result<AuthorityGrant, ProviderError>;

    fn authorize_effect(
        &self,
        request: &EffectRequest,
        required_rights: Rights,
    ) -> Result<Rights, ProviderError>;

    /// Revoke every still-pending grant created for a prepared snapshot.
    /// Repeating cleanup is idempotent.
    fn revoke_prepared(&mut self, snapshot: Identity) -> Result<(), ProviderError>;
}

/// Durable current ownership record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseRecord {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

/// Ownership initialization and fencing checks. Handoff commit is deliberately
/// on [`JournalPort::commit_bundle`] so it cannot be split from journal truth.
pub trait LeasePort {
    fn initialize_lease(&mut self, lease: LeaseRecord) -> Result<(), ProviderError>;

    /// Validate a canonical `LeaseCommit` request and produce evidence without
    /// changing ownership. The only ownership write remains
    /// [`JournalPort::commit_bundle`].
    fn prepare_transitions(
        &mut self,
        request: &EffectRequest,
        resources: &[EntityRef],
    ) -> Result<PreparedLeaseTransitions, ProviderError>;

    fn current_lease(&self, resource: EntityRef) -> Result<Option<LeaseRecord>, ProviderError>;

    fn check_lease(
        &self,
        resource: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), ProviderError>;
}

/// Resource-specific data needed to create a fresh host binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingKind {
    PausedDurationTimer,
    KeyValueNamespace { namespace: Identity },
    Profile { profile: Identity },
}

/// Provider-neutral destination binding preparation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingRequest {
    pub handoff: Identity,
    pub snapshot: Identity,
    pub claim: EntityRef,
    pub authority: EntityRef,
    pub exposed_rights: Rights,
    pub expected_owner: NodeIdentity,
    pub expected_epoch: LeaseEpoch,
    pub candidate_owner: NodeIdentity,
    pub candidate_epoch: LeaseEpoch,
    pub kind: BindingKind,
}

/// Fresh binding receipts and idempotent cleanup.
pub trait BindingPort {
    fn prepare_binding(&mut self, request: BindingRequest)
    -> Result<BindingReceipt, ProviderError>;

    fn binding(
        &self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<Option<BindingReceipt>, ProviderError>;

    fn cleanup_binding(
        &mut self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<(), ProviderError>;
}
