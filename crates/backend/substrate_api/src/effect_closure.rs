use alloc::boxed::Box;
use core::ptr;

use contract_core::{
    Digest, EffectOutcome, EffectRequest, EncodeError, IdempotencyKey, Identity,
    canonical_digest,
};

/// Preview protocol family for the provider-neutral effect-closure SPI.
///
/// This version is independent from the accepted joint-handoff wire v1. It
/// describes runtime/provider compatibility and does not reinterpret any v1
/// receipt or state-machine transition.
pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR: u16 = 2;
pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR: u16 = 0;

/// Whether one runtime/provider instance permits legacy effect bypasses.
///
/// `Compatibility` preserves the pre-admission Stage 3 entrypoints and is not
/// an enforcement boundary. `AdmissionRequired` is the bounded v0.1 profile:
/// every externally dispatched Start must consume a provider-validated commit
/// fence, and legacy raw publication/dispatch entrypoints must reject it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EffectAdmissionProfile {
    #[default]
    Compatibility,
    AdmissionRequired,
}

impl EffectAdmissionProfile {
    pub const fn satisfies(self, required: Self) -> bool {
        matches!(required, Self::Compatibility) || matches!(self, Self::AdmissionRequired)
    }
}

/// Stable identity for one complete canonical [`EffectRequest`].
///
/// The explicit operation and idempotency identities support provider lookup;
/// `canonical_digest` binds every remaining request field without extending or
/// reinterpreting the frozen joint-handoff wire v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectRequestBinding {
    pub operation: Identity,
    pub idempotency_key: IdempotencyKey,
    pub canonical_digest: Digest,
}

impl EffectRequestBinding {
    pub fn from_effect(effect: &EffectRequest) -> Result<Self, EncodeError> {
        Ok(Self {
            operation: effect.operation,
            idempotency_key: effect.idempotency_key,
            canonical_digest: canonical_digest(effect)?,
        })
    }

    pub fn matches(self, effect: &EffectRequest) -> Result<bool, EncodeError> {
        Ok(self == Self::from_effect(effect)?)
    }
}

/// Inclusive protocol range implemented by one provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureProtocolRange {
    pub major: u16,
    pub min_minor: u16,
    pub max_minor: u16,
}

impl EffectClosureProtocolRange {
    pub const fn v2_preview() -> Self {
        Self {
            major: EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR,
            min_minor: EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR,
            max_minor: EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR,
        }
    }

    pub const fn is_well_formed(self) -> bool {
        self.major != 0 && self.min_minor <= self.max_minor
    }

    pub const fn supports(self, major: u16, minor: u16) -> bool {
        self.is_well_formed()
            && self.major == major
            && self.min_minor <= minor
            && minor <= self.max_minor
    }
}

/// Independently qualified provider capabilities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectClosureCapabilities {
    pub effect_admission: bool,
    pub outcome_recording: bool,
    pub effect_completion: bool,
    pub session_query: bool,
    pub freeze_thaw: bool,
    pub commit_close: bool,
    pub crash_rebind: bool,
    pub retained_device: bool,
    pub persistent_query: bool,
}

impl EffectClosureCapabilities {
    pub const fn contains(self, required: Self) -> bool {
        (!required.effect_admission || self.effect_admission)
            && (!required.outcome_recording || self.outcome_recording)
            && (!required.effect_completion || self.effect_completion)
            && (!required.session_query || self.session_query)
            && (!required.freeze_thaw || self.freeze_thaw)
            && (!required.commit_close || self.commit_close)
            && (!required.crash_rebind || self.crash_rebind)
            && (!required.retained_device || self.retained_device)
            && (!required.persistent_query || self.persistent_query)
    }
}

/// Authentication strength independently reported by a provider adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClosureAuthenticationProfile {
    None,
    IntegrityOnly,
    AuthenticatedSameBoot,
    AuthenticatedFresh,
}

impl EffectClosureAuthenticationProfile {
    const fn strength(self) -> u8 {
        match self {
            Self::None => 0,
            Self::IntegrityOnly => 1,
            Self::AuthenticatedSameBoot => 2,
            Self::AuthenticatedFresh => 3,
        }
    }

    pub const fn satisfies(self, minimum: Self) -> bool {
        self.strength() >= minimum.strength()
    }
}

/// Hard resource and framing limits for one provider instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderLimits {
    pub max_scopes: u64,
    pub max_effects_per_scope: u64,
    pub max_inflight_mutations: u64,
    pub max_request_bytes: u64,
    pub max_receipt_bytes: u64,
}

impl EffectClosureProviderLimits {
    pub const fn is_well_formed(self) -> bool {
        self.max_scopes != 0
            && self.max_effects_per_scope != 0
            && self.max_inflight_mutations != 0
            && self.max_request_bytes != 0
            && self.max_receipt_bytes != 0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.max_scopes >= required.max_scopes
            && self.max_effects_per_scope >= required.max_effects_per_scope
            && self.max_inflight_mutations >= required.max_inflight_mutations
            && self.max_request_bytes >= required.max_request_bytes
            && self.max_receipt_bytes >= required.max_receipt_bytes
    }
}

/// Minimum compatibility contract requested by one runtime profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderRequirements {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub admission_profile: EffectAdmissionProfile,
    pub capabilities: EffectClosureCapabilities,
    pub minimum_authentication: EffectClosureAuthenticationProfile,
    pub minimum_limits: EffectClosureProviderLimits,
}

impl EffectClosureProviderRequirements {
    pub const fn v2_preview(
        capabilities: EffectClosureCapabilities,
        minimum_authentication: EffectClosureAuthenticationProfile,
        minimum_limits: EffectClosureProviderLimits,
    ) -> Self {
        Self {
            protocol_major: EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR,
            protocol_minor: EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR,
            admission_profile: EffectAdmissionProfile::Compatibility,
            capabilities,
            minimum_authentication,
            minimum_limits,
        }
    }

    pub const fn is_well_formed(self) -> bool {
        self.protocol_major != 0 && self.minimum_limits.is_well_formed()
    }

    pub const fn require_admission(mut self) -> Self {
        self.admission_profile = EffectAdmissionProfile::AdmissionRequired;
        self
    }
}

/// Capability and compatibility description returned by one live provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderDescriptor {
    pub protocol: EffectClosureProtocolRange,
    pub admission_profile: EffectAdmissionProfile,
    pub capabilities: EffectClosureCapabilities,
    pub authentication: EffectClosureAuthenticationProfile,
    pub limits: EffectClosureProviderLimits,
}

impl EffectClosureProviderDescriptor {
    pub const fn is_well_formed(self) -> bool {
        self.protocol.is_well_formed()
            && self.limits.is_well_formed()
            && self.capabilities.effect_admission
            && (!self.capabilities.effect_completion || self.capabilities.outcome_recording)
            && (!self.capabilities.persistent_query || self.capabilities.session_query)
    }

    pub const fn supports_v2_preview(self, required: EffectClosureCapabilities) -> bool {
        self.satisfies(EffectClosureProviderRequirements::v2_preview(
            required,
            EffectClosureAuthenticationProfile::None,
            EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 1,
                max_inflight_mutations: 1,
                max_request_bytes: 1,
                max_receipt_bytes: 1,
            },
        ))
    }

    pub const fn satisfies(self, requirements: EffectClosureProviderRequirements) -> bool {
        self.is_well_formed()
            && requirements.is_well_formed()
            && self.protocol.supports(requirements.protocol_major, requirements.protocol_minor)
            && self.admission_profile.satisfies(requirements.admission_profile)
            && self.capabilities.contains(requirements.capabilities)
            && self.authentication.satisfies(requirements.minimum_authentication)
            && self.limits.contains(requirements.minimum_limits)
    }
}

/// Minimal staged effect-admission surface shared by closure providers.
///
/// Freeze, thaw, and close remain on the accepted joint-handoff contract in
/// this first extraction. The descriptor advertises those independently
/// qualified capabilities without copying their receipt vocabulary here.
pub trait EffectClosureProvider: Send + Sync {
    type RegistrationRequest;
    type Registered;
    type Prepared;
    type CommitMetadata;
    type CommitEvidence;
    type DispatchFence;
    type OutcomeEvidence;
    type CompletionRequest;
    type CompletionEvidence;
    type QueryObservation;
    type Error;

    fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, Self::Error>;

    fn register_effect(
        &self,
        effect: &EffectRequest,
        request: &Self::RegistrationRequest,
    ) -> Result<Self::Registered, Self::Error>;

    fn prepare_effect(
        &self,
        effect: &EffectRequest,
        registered: &Self::Registered,
    ) -> Result<Self::Prepared, Self::Error>;

    fn commit_effect(
        &self,
        effect: &EffectRequest,
        prepared: &Self::Prepared,
        metadata: &Self::CommitMetadata,
    ) -> Result<Self::CommitEvidence, Self::Error>;

    /// Atomically validate and consume one committed dispatch authorization.
    ///
    /// Implementations must compare the complete canonical effect binding,
    /// current provider generation/incarnation, revocation state, and prior
    /// consumption state before returning a fence. A successful call is a
    /// one-way transition: dropping the returned fence or losing its outcome
    /// acknowledgement remains fail closed and must never re-open dispatch.
    fn consume_committed_effect(
        &self,
        effect: &EffectRequest,
        evidence: &Self::CommitEvidence,
    ) -> Result<Self::DispatchFence, Self::Error>;

    /// Record the bounded runtime outcome of one already-consumed dispatch.
    ///
    /// This closes only the local provider admission fence around the guest
    /// call. It does not replace the canonical outcome transition below.
    fn finish_effect_dispatch(
        &self,
        effect: &EffectRequest,
        fence: &Self::DispatchFence,
        outcome: EffectDispatchOutcome,
    ) -> Result<(), Self::Error>;

    /// Record the canonical provider outcome without implying that the native
    /// effect has completed or left the closure cohort. Admission-required
    /// providers must reject a first outcome until the dispatch fence has been
    /// consumed and successfully closed.
    fn record_effect_outcome(
        &self,
        effect: &EffectRequest,
        committed: &Self::CommitEvidence,
        outcome: &EffectOutcome,
    ) -> Result<Self::OutcomeEvidence, Self::Error>;

    /// Explicitly advance provider-local completion after an outcome exists.
    /// Handoff profiles may defer this transition to cohort closure.
    fn complete_effect(
        &self,
        effect: &EffectRequest,
        request: &Self::CompletionRequest,
    ) -> Result<Self::CompletionEvidence, Self::Error>;

    /// Query only the live provider session selected by this object. A result
    /// is not crash-stable recovery evidence unless `persistent_query` was
    /// independently advertised and qualified.
    fn query_effect(
        &self,
        effect: &EffectRequest,
    ) -> Result<Option<Self::QueryObservation>, Self::Error>;
}

/// Bounded result of entering the guest after a provider commit was consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectDispatchOutcome {
    GuestReturned,
    GuestFailed,
}

/// Failure to turn a committed permit into a provider-consumed dispatch fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectDispatchAcquireError<E> {
    BindingMismatch,
    Provider(E),
}

/// One provider-side consumed authorization awaiting a guest outcome.
///
/// There is deliberately no retry/clone surface. If this value is dropped or
/// `finish` fails, provider state remains consumed and recovery must reconcile
/// it out of band; a second local dispatch is forbidden.
pub struct ConsumedEffectDispatch<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    commit_evidence: P::CommitEvidence,
    fence: P::DispatchFence,
}

impl<'a, P> ConsumedEffectDispatch<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn provider_fence(&self) -> &P::DispatchFence {
        &self.fence
    }

    pub fn finish(
        self,
        outcome: EffectDispatchOutcome,
    ) -> Result<CommittedEffectPermit<'a, P>, P::Error> {
        self.provider.finish_effect_dispatch(&self.effect, &self.fence, outcome)?;
        Ok(CommittedEffectPermit {
            provider: self.provider,
            effect: self.effect,
            commit_evidence: self.commit_evidence,
        })
    }
}

/// Registered provider state bound to one exact canonical effect request and
/// the provider instance which accepted it.
pub struct RegisteredEffect<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    provider_state: P::Registered,
}

impl<'a, P> RegisteredEffect<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn provider_state(&self) -> &P::Registered {
        &self.provider_state
    }

    pub fn prepare(self) -> Result<PreparedEffect<'a, P>, EffectPrepareFailure<'a, P>> {
        match self.provider.prepare_effect(&self.effect, &self.provider_state) {
            Ok(provider_state) => {
                Ok(PreparedEffect { provider: self.provider, effect: self.effect, provider_state })
            }
            Err(error) => Err(EffectPrepareFailure {
                inner: Box::new(EffectPrepareFailureInner { error, registered: self }),
            }),
        }
    }
}

/// Registration failure bound to the provider instance which observed it,
/// with every consumed input retained for exact acknowledgement-loss recovery
/// without requiring either input to be Clone.
pub struct EffectRegisterFailure<'a, P>
where
    P: EffectClosureProvider,
{
    inner: Box<EffectRegisterFailureInner<'a, P>>,
}

struct EffectRegisterFailureInner<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    error: P::Error,
    effect: EffectRequest,
    request: P::RegistrationRequest,
}

impl<'a, P> EffectRegisterFailure<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn provider(&self) -> &'a P {
        self.inner.provider
    }

    pub const fn error(&self) -> &P::Error {
        &self.inner.error
    }

    pub const fn effect(&self) -> &EffectRequest {
        &self.inner.effect
    }

    pub const fn request(&self) -> &P::RegistrationRequest {
        &self.inner.request
    }

    pub fn retry(self) -> Result<RegisteredEffect<'a, P>, Self> {
        let EffectRegisterFailureInner { provider, effect, request, .. } = *self.inner;
        match provider.register_effect(&effect, &request) {
            Ok(provider_state) => Ok(RegisteredEffect { provider, effect, provider_state }),
            Err(error) => Err(Self {
                inner: Box::new(EffectRegisterFailureInner { provider, error, effect, request }),
            }),
        }
    }

    pub fn into_parts(self) -> (P::Error, &'a P, EffectRequest, P::RegistrationRequest) {
        let inner = *self.inner;
        (inner.error, inner.provider, inner.effect, inner.request)
    }
}

/// Prepared provider state bound to one exact canonical effect request and
/// the provider instance which prepared it.
pub struct PreparedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    provider_state: P::Prepared,
}

impl<'a, P> PreparedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn provider_state(&self) -> &P::Prepared {
        &self.provider_state
    }

    pub fn commit(
        self,
        metadata: P::CommitMetadata,
    ) -> Result<CommittedEffectPermit<'a, P>, EffectCommitFailure<'a, P>> {
        match self.provider.commit_effect(&self.effect, &self.provider_state, &metadata) {
            Ok(commit_evidence) => Ok(CommittedEffectPermit {
                provider: self.provider,
                effect: self.effect,
                commit_evidence,
            }),
            Err(error) => Err(EffectCommitFailure {
                inner: Box::new(EffectCommitFailureInner { error, prepared: self, metadata }),
            }),
        }
    }
}

/// Failed Prepare transition with the still-owned Registered state returned
/// for exact retry or fail-closed retention.
pub struct EffectPrepareFailure<'a, P>
where
    P: EffectClosureProvider,
{
    inner: Box<EffectPrepareFailureInner<'a, P>>,
}

struct EffectPrepareFailureInner<'a, P>
where
    P: EffectClosureProvider,
{
    error: P::Error,
    registered: RegisteredEffect<'a, P>,
}

impl<'a, P> EffectPrepareFailure<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn error(&self) -> &P::Error {
        &self.inner.error
    }

    pub const fn registered(&self) -> &RegisteredEffect<'a, P> {
        &self.inner.registered
    }

    pub fn into_parts(self) -> (P::Error, RegisteredEffect<'a, P>) {
        let inner = *self.inner;
        (inner.error, inner.registered)
    }
}

/// Non-cloneable authorization to dispatch one exact effect after provider
/// commit.
///
/// The private fields prevent callers from fabricating a permit, and an
/// admitted runtime entry consumes each returned value before external
/// dispatch. An idempotent provider may issue another permit while recovering
/// a lost Commit acknowledgement, so this type establishes exact-effect
/// commit-before-dispatch, not global exactly-once execution. Dispatchers must
/// preserve the canonical idempotency identity across such recovery.
///
/// A dispatch API must take the permit by value; attempting to execute twice
/// with one authority value is rejected by the type system:
///
/// ```compile_fail
/// use substrate_api::{CommittedEffectPermit, EffectClosureProvider};
///
/// fn execute<P: EffectClosureProvider>(_permit: CommittedEffectPermit<'_, P>) {}
///
/// fn execute_twice<P: EffectClosureProvider>(permit: CommittedEffectPermit<'_, P>) {
///     execute(permit);
///     execute(permit);
/// }
/// ```
pub struct CommittedEffectPermit<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    commit_evidence: P::CommitEvidence,
}

impl<'a, P> CommittedEffectPermit<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn commit_evidence(&self) -> &P::CommitEvidence {
        &self.commit_evidence
    }

    /// Consume this local permit only after the provider revalidates its live
    /// state and mints a one-way dispatch fence.
    pub fn consume(
        self,
        provider: &'a P,
        effect: &EffectRequest,
    ) -> Result<ConsumedEffectDispatch<'a, P>, EffectDispatchAcquireError<P::Error>> {
        if !ptr::eq(self.provider, provider) || self.effect != *effect {
            return Err(EffectDispatchAcquireError::BindingMismatch);
        }
        let fence = provider
            .consume_committed_effect(&self.effect, &self.commit_evidence)
            .map_err(EffectDispatchAcquireError::Provider)?;
        Ok(ConsumedEffectDispatch {
            provider,
            effect: self.effect,
            commit_evidence: self.commit_evidence,
            fence,
        })
    }

    pub fn record_outcome(
        self,
        outcome: EffectOutcome,
    ) -> Result<OutcomeRecordedEffect<'a, P>, EffectOutcomeFailure<'a, P>> {
        match self.provider.record_effect_outcome(&self.effect, &self.commit_evidence, &outcome) {
            Ok(outcome_evidence) => Ok(OutcomeRecordedEffect {
                provider: self.provider,
                effect: self.effect,
                commit_evidence: self.commit_evidence,
                outcome,
                outcome_evidence,
            }),
            Err(error) => Err(EffectOutcomeFailure {
                inner: Box::new(EffectOutcomeFailureInner { error, committed: self, outcome }),
            }),
        }
    }
}

/// Provider state after the canonical outcome has been recorded. Completion
/// remains explicit because a handoff may retain the committed effect for
/// cohort closure instead of completing it before freeze.
pub struct OutcomeRecordedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    commit_evidence: P::CommitEvidence,
    outcome: EffectOutcome,
    outcome_evidence: P::OutcomeEvidence,
}

impl<'a, P> OutcomeRecordedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn commit_evidence(&self) -> &P::CommitEvidence {
        &self.commit_evidence
    }

    pub const fn outcome(&self) -> &EffectOutcome {
        &self.outcome
    }

    pub const fn outcome_evidence(&self) -> &P::OutcomeEvidence {
        &self.outcome_evidence
    }

    pub fn complete(
        self,
        request: P::CompletionRequest,
    ) -> Result<CompletedEffect<'a, P>, EffectCompletionFailure<'a, P>> {
        match self.provider.complete_effect(&self.effect, &request) {
            Ok(completion_evidence) => Ok(CompletedEffect {
                provider: self.provider,
                effect: self.effect,
                commit_evidence: self.commit_evidence,
                outcome: self.outcome,
                outcome_evidence: self.outcome_evidence,
                completion_evidence,
            }),
            Err(error) => Err(EffectCompletionFailure {
                inner: Box::new(EffectCompletionFailureInner {
                    error,
                    outcome_recorded: self,
                    request,
                }),
            }),
        }
    }
}

/// Terminal provider evidence after an explicit effect completion.
pub struct CompletedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
    effect: EffectRequest,
    commit_evidence: P::CommitEvidence,
    outcome: EffectOutcome,
    outcome_evidence: P::OutcomeEvidence,
    completion_evidence: P::CompletionEvidence,
}

impl<'a, P> CompletedEffect<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn provider(&self) -> &'a P {
        self.provider
    }

    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    pub const fn commit_evidence(&self) -> &P::CommitEvidence {
        &self.commit_evidence
    }

    pub const fn outcome(&self) -> &EffectOutcome {
        &self.outcome
    }

    pub const fn outcome_evidence(&self) -> &P::OutcomeEvidence {
        &self.outcome_evidence
    }

    pub const fn completion_evidence(&self) -> &P::CompletionEvidence {
        &self.completion_evidence
    }
}

/// Failed canonical outcome recording with the committed permit and exact
/// outcome returned for retry or fail-closed retention.
pub struct EffectOutcomeFailure<'a, P>
where
    P: EffectClosureProvider,
{
    inner: Box<EffectOutcomeFailureInner<'a, P>>,
}

struct EffectOutcomeFailureInner<'a, P>
where
    P: EffectClosureProvider,
{
    error: P::Error,
    committed: CommittedEffectPermit<'a, P>,
    outcome: EffectOutcome,
}

impl<'a, P> EffectOutcomeFailure<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn error(&self) -> &P::Error {
        &self.inner.error
    }

    pub const fn committed(&self) -> &CommittedEffectPermit<'a, P> {
        &self.inner.committed
    }

    pub const fn outcome(&self) -> &EffectOutcome {
        &self.inner.outcome
    }

    pub fn retry(self) -> Result<OutcomeRecordedEffect<'a, P>, Self> {
        let inner = *self.inner;
        inner.committed.record_outcome(inner.outcome)
    }

    pub fn into_parts(self) -> (P::Error, CommittedEffectPermit<'a, P>, EffectOutcome) {
        let inner = *self.inner;
        (inner.error, inner.committed, inner.outcome)
    }
}

/// Failed explicit completion with the outcome-recorded state and exact
/// completion request retained for retry.
pub struct EffectCompletionFailure<'a, P>
where
    P: EffectClosureProvider,
{
    inner: Box<EffectCompletionFailureInner<'a, P>>,
}

struct EffectCompletionFailureInner<'a, P>
where
    P: EffectClosureProvider,
{
    error: P::Error,
    outcome_recorded: OutcomeRecordedEffect<'a, P>,
    request: P::CompletionRequest,
}

impl<'a, P> EffectCompletionFailure<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn error(&self) -> &P::Error {
        &self.inner.error
    }

    pub const fn outcome_recorded(&self) -> &OutcomeRecordedEffect<'a, P> {
        &self.inner.outcome_recorded
    }

    pub const fn request(&self) -> &P::CompletionRequest {
        &self.inner.request
    }

    pub fn retry(self) -> Result<CompletedEffect<'a, P>, Self> {
        let inner = *self.inner;
        inner.outcome_recorded.complete(inner.request)
    }

    pub fn into_parts(self) -> (P::Error, OutcomeRecordedEffect<'a, P>, P::CompletionRequest) {
        let inner = *self.inner;
        (inner.error, inner.outcome_recorded, inner.request)
    }
}

/// Failed Commit transition with the still-owned Prepared state returned for
/// exact acknowledgement-loss recovery. A successful Commit returns only a
/// provider-typed [`CommittedEffectPermit`].
pub struct EffectCommitFailure<'a, P>
where
    P: EffectClosureProvider,
{
    inner: Box<EffectCommitFailureInner<'a, P>>,
}

struct EffectCommitFailureInner<'a, P>
where
    P: EffectClosureProvider,
{
    error: P::Error,
    prepared: PreparedEffect<'a, P>,
    metadata: P::CommitMetadata,
}

impl<'a, P> EffectCommitFailure<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn error(&self) -> &P::Error {
        &self.inner.error
    }

    pub const fn prepared(&self) -> &PreparedEffect<'a, P> {
        &self.inner.prepared
    }

    pub const fn metadata(&self) -> &P::CommitMetadata {
        &self.inner.metadata
    }

    pub fn into_parts(self) -> (P::Error, PreparedEffect<'a, P>, P::CommitMetadata) {
        let inner = *self.inner;
        (inner.error, inner.prepared, inner.metadata)
    }
}

/// Type-state driver that is the only public path which can mint a committed
/// dispatch permit.
pub struct EffectAdmissionSession<'a, P>
where
    P: EffectClosureProvider,
{
    provider: &'a P,
}

impl<'a, P> EffectAdmissionSession<'a, P>
where
    P: EffectClosureProvider,
{
    pub const fn new(provider: &'a P) -> Self {
        Self { provider }
    }

    pub fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, P::Error> {
        self.provider.descriptor()
    }

    pub fn register(
        &self,
        effect: EffectRequest,
        request: P::RegistrationRequest,
    ) -> Result<RegisteredEffect<'a, P>, EffectRegisterFailure<'a, P>> {
        match self.provider.register_effect(&effect, &request) {
            Ok(provider_state) => {
                Ok(RegisteredEffect { provider: self.provider, effect, provider_state })
            }
            Err(error) => Err(EffectRegisterFailure {
                inner: Box::new(EffectRegisterFailureInner {
                    provider: self.provider,
                    error,
                    effect,
                    request,
                }),
            }),
        }
    }

    pub fn query_effect(
        &self,
        effect: &EffectRequest,
    ) -> Result<Option<P::QueryObservation>, P::Error> {
        self.provider.query_effect(effect)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use contract_core::{
        Digest, EffectKind, EntityRef, IdempotencyKey, Identity, LeaseEpoch, NodeIdentity,
        ProfileAccess,
    };

    use super::*;

    struct FakeProvider {
        registration_attempts: AtomicUsize,
        commit_attempts: AtomicUsize,
        dispatch_state: AtomicUsize,
        outcome_attempts: AtomicUsize,
        completion_attempts: AtomicUsize,
    }

    impl FakeProvider {
        const fn new() -> Self {
            Self {
                registration_attempts: AtomicUsize::new(0),
                commit_attempts: AtomicUsize::new(0),
                dispatch_state: AtomicUsize::new(0),
                outcome_attempts: AtomicUsize::new(0),
                completion_attempts: AtomicUsize::new(0),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeCommitEvidence {
        value: u64,
        binding: EffectRequestBinding,
        generation: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeDispatchFence {
        binding: EffectRequestBinding,
        generation: u64,
    }

    impl EffectClosureProvider for FakeProvider {
        type RegistrationRequest = u64;
        type Registered = u64;
        type Prepared = u64;
        type CommitMetadata = String;
        type CommitEvidence = FakeCommitEvidence;
        type DispatchFence = FakeDispatchFence;
        type OutcomeEvidence = bool;
        type CompletionRequest = u64;
        type CompletionEvidence = bool;
        type QueryObservation = u64;
        type Error = &'static str;

        fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, Self::Error> {
            Ok(descriptor())
        }

        fn register_effect(
            &self,
            _effect: &EffectRequest,
            request: &Self::RegistrationRequest,
        ) -> Result<Self::Registered, Self::Error> {
            if *request == 0 && self.registration_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                Err("register-acknowledgement-lost")
            } else {
                Ok(request + 1)
            }
        }

        fn prepare_effect(
            &self,
            _effect: &EffectRequest,
            registered: &Self::Registered,
        ) -> Result<Self::Prepared, Self::Error> {
            Ok(registered + 1)
        }

        fn commit_effect(
            &self,
            effect: &EffectRequest,
            prepared: &Self::Prepared,
            metadata: &Self::CommitMetadata,
        ) -> Result<Self::CommitEvidence, Self::Error> {
            if self.commit_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                Err("acknowledgement-lost")
            } else {
                Ok(FakeCommitEvidence {
                    value: prepared + metadata.parse::<u64>().map_err(|_| "invalid-metadata")?,
                    binding: EffectRequestBinding::from_effect(effect)
                        .map_err(|_| "invalid-effect")?,
                    generation: 1,
                })
            }
        }

        fn consume_committed_effect(
            &self,
            effect: &EffectRequest,
            evidence: &Self::CommitEvidence,
        ) -> Result<Self::DispatchFence, Self::Error> {
            if !evidence.binding.matches(effect).map_err(|_| "invalid-effect")?
                || evidence.generation != 1
            {
                return Err("stale-or-mismatched");
            }
            self.dispatch_state
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| "consumed-or-revoked")?;
            Ok(FakeDispatchFence { binding: evidence.binding, generation: evidence.generation })
        }

        fn finish_effect_dispatch(
            &self,
            effect: &EffectRequest,
            fence: &Self::DispatchFence,
            outcome: EffectDispatchOutcome,
        ) -> Result<(), Self::Error> {
            if !fence.binding.matches(effect).map_err(|_| "invalid-effect")?
                || fence.generation != 1
            {
                return Err("stale-or-mismatched");
            }
            let terminal = match outcome {
                EffectDispatchOutcome::GuestReturned => 2,
                EffectDispatchOutcome::GuestFailed => 3,
            };
            self.dispatch_state
                .compare_exchange(1, terminal, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| "not-consumed")?;
            Ok(())
        }

        fn record_effect_outcome(
            &self,
            effect: &EffectRequest,
            committed: &Self::CommitEvidence,
            _outcome: &EffectOutcome,
        ) -> Result<Self::OutcomeEvidence, Self::Error> {
            if !committed.binding.matches(effect).map_err(|_| "invalid-effect")?
                || self.dispatch_state.load(Ordering::SeqCst) != 2
            {
                return Err("dispatch-not-successfully-closed");
            }
            if self.outcome_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                Err("outcome-acknowledgement-lost")
            } else {
                Ok(false)
            }
        }

        fn complete_effect(
            &self,
            _effect: &EffectRequest,
            _request: &Self::CompletionRequest,
        ) -> Result<Self::CompletionEvidence, Self::Error> {
            if self.completion_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                Err("completion-acknowledgement-lost")
            } else {
                Ok(false)
            }
        }

        fn query_effect(
            &self,
            _effect: &EffectRequest,
        ) -> Result<Option<Self::QueryObservation>, Self::Error> {
            Ok(None)
        }
    }

    const fn descriptor() -> EffectClosureProviderDescriptor {
        EffectClosureProviderDescriptor {
            protocol: EffectClosureProtocolRange::v2_preview(),
            admission_profile: EffectAdmissionProfile::AdmissionRequired,
            capabilities: EffectClosureCapabilities {
                effect_admission: true,
                outcome_recording: true,
                effect_completion: true,
                session_query: true,
                freeze_thaw: true,
                commit_close: true,
                crash_rebind: false,
                retained_device: false,
                persistent_query: false,
            },
            authentication: EffectClosureAuthenticationProfile::IntegrityOnly,
            limits: EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 8,
                max_inflight_mutations: 1,
                max_request_bytes: 1024,
                max_receipt_bytes: 4096,
            },
        }
    }

    fn effect(operation: u128) -> EffectRequest {
        EffectRequest {
            operation: Identity::from_u128(operation),
            idempotency_key: IdempotencyKey::from_u128(2),
            causal_parent: None,
            node: NodeIdentity::new(Identity::from_u128(3)),
            subject: EntityRef::initial(Identity::from_u128(4)),
            resource: EntityRef::initial(Identity::from_u128(5)),
            authority: EntityRef::initial(Identity::from_u128(6)),
            lease_epoch: LeaseEpoch(1),
            request_digest: Digest::from_bytes([7; 32]),
            kind: EffectKind::Profile {
                profile: Identity::from_u128(8),
                access: ProfileAccess::Write,
                payload: vec![9],
            },
        }
    }

    #[test]
    fn descriptor_requires_the_preview_protocol_and_capabilities() {
        let descriptor = descriptor();
        let capabilities = EffectClosureCapabilities {
            effect_admission: true,
            outcome_recording: true,
            effect_completion: true,
            session_query: true,
            freeze_thaw: true,
            commit_close: true,
            ..EffectClosureCapabilities::default()
        };
        assert!(descriptor.supports_v2_preview(capabilities));
        assert!(!descriptor.supports_v2_preview(EffectClosureCapabilities {
            retained_device: true,
            ..EffectClosureCapabilities::default()
        }));
        assert!(!descriptor.satisfies(EffectClosureProviderRequirements::v2_preview(
            capabilities,
            EffectClosureAuthenticationProfile::AuthenticatedSameBoot,
            EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 1,
                max_inflight_mutations: 1,
                max_request_bytes: 1,
                max_receipt_bytes: 1,
            },
        )));
        assert!(!descriptor.satisfies(EffectClosureProviderRequirements::v2_preview(
            capabilities,
            EffectClosureAuthenticationProfile::IntegrityOnly,
            EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 9,
                max_inflight_mutations: 1,
                max_request_bytes: 1,
                max_receipt_bytes: 1,
            },
        )));
        assert!(!descriptor.satisfies(EffectClosureProviderRequirements::v2_preview(
            capabilities,
            EffectClosureAuthenticationProfile::IntegrityOnly,
            EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 1,
                max_inflight_mutations: 1,
                max_request_bytes: 0,
                max_receipt_bytes: 1,
            },
        )));
    }

    #[test]
    fn committed_permit_binds_the_exact_effect_after_staged_commit() {
        let provider = FakeProvider::new();
        let other_provider = FakeProvider::new();
        let admission = EffectAdmissionSession::new(&provider);
        let request = effect(1);
        let registered = match admission.register(request.clone(), 10) {
            Ok(registered) => registered,
            Err(_) => panic!("register unexpectedly failed"),
        };
        let prepared = match registered.prepare() {
            Ok(prepared) => prepared,
            Err(_) => panic!("prepare unexpectedly failed"),
        };
        let failure = match prepared.commit(String::from("20")) {
            Ok(_) => panic!("the injected acknowledgement loss unexpectedly committed"),
            Err(failure) => failure,
        };
        assert_eq!(*failure.error(), "acknowledgement-lost");
        assert_eq!(failure.metadata(), "20");
        let (_, prepared, metadata) = failure.into_parts();
        let permit = match prepared.commit(metadata) {
            Ok(permit) => permit,
            Err(_) => panic!("exact commit retry unexpectedly failed"),
        };

        assert_eq!(permit.commit_evidence().value, 32);
        let dispatch = match permit.consume(&provider, &request) {
            Ok(dispatch) => dispatch,
            Err(_) => panic!("provider unexpectedly rejected the committed dispatch"),
        };
        assert_eq!(provider.dispatch_state.load(Ordering::SeqCst), 1);
        assert!(dispatch.finish(EffectDispatchOutcome::GuestReturned).is_ok());
        assert_eq!(provider.dispatch_state.load(Ordering::SeqCst), 2);
        assert_eq!(other_provider.commit_attempts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn registration_failure_returns_the_exact_nonclone_contract_inputs() {
        let provider = FakeProvider::new();
        let admission = EffectAdmissionSession::new(&provider);
        let effect = effect(11);
        let failure = match admission.register(effect.clone(), 0) {
            Ok(_) => panic!("the injected registration acknowledgement loss unexpectedly passed"),
            Err(failure) => failure,
        };
        assert_eq!(*failure.error(), "register-acknowledgement-lost");
        assert_eq!(failure.effect(), &effect);
        assert_eq!(*failure.request(), 0);
        assert!(ptr::eq(failure.provider(), &provider));
        let (error, recovered_provider, recovered_effect, recovered_request) = failure.into_parts();
        assert_eq!(error, "register-acknowledgement-lost");
        assert!(ptr::eq(recovered_provider, &provider));
        assert_eq!(recovered_effect, effect);
        assert_eq!(recovered_request, 0);

        let retry_provider = FakeProvider::new();
        let retry_admission = EffectAdmissionSession::new(&retry_provider);
        let failure = match retry_admission.register(effect.clone(), 0) {
            Ok(_) => panic!("the retry fixture unexpectedly registered on its first attempt"),
            Err(failure) => failure,
        };
        let registered = match failure.retry() {
            Ok(registered) => registered,
            Err(_) => panic!("exact registration retry unexpectedly failed"),
        };
        assert_eq!(registered.effect(), &effect);
        assert_eq!(*registered.provider_state(), 1);
    }

    #[test]
    fn outcome_and_completion_failures_retain_exact_type_state_for_retry() {
        let provider = FakeProvider::new();
        let request = effect(21);
        let registered = EffectAdmissionSession::new(&provider)
            .register(request.clone(), 10)
            .unwrap_or_else(|_| panic!("register unexpectedly failed"));
        let prepared =
            registered.prepare().unwrap_or_else(|_| panic!("prepare unexpectedly failed"));
        let commit_failure = match prepared.commit(String::from("20")) {
            Ok(_) => panic!("the injected Commit acknowledgement loss unexpectedly succeeded"),
            Err(failure) => failure,
        };
        let (_, prepared, metadata) = commit_failure.into_parts();
        let committed = prepared
            .commit(metadata)
            .unwrap_or_else(|_| panic!("exact Commit retry unexpectedly failed"));

        let outcome = EffectOutcome::Indeterminate { evidence: None };
        let committed = committed
            .consume(&provider, &request)
            .unwrap_or_else(|_| panic!("provider unexpectedly rejected dispatch"))
            .finish(EffectDispatchOutcome::GuestReturned)
            .unwrap_or_else(|_| panic!("provider unexpectedly rejected dispatch outcome"));
        let outcome_failure = match committed.record_outcome(outcome.clone()) {
            Ok(_) => panic!("the injected outcome acknowledgement loss unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(*outcome_failure.error(), "outcome-acknowledgement-lost");
        assert!(outcome_failure.committed().authorizes(&provider, &request));
        assert_eq!(outcome_failure.outcome(), &outcome);
        let outcome_recorded = outcome_failure
            .retry()
            .unwrap_or_else(|_| panic!("exact outcome retry unexpectedly failed"));
        assert_eq!(outcome_recorded.effect(), &request);
        assert_eq!(outcome_recorded.outcome(), &outcome);

        let completion_failure = match outcome_recorded.complete(44) {
            Ok(_) => {
                panic!("the injected completion acknowledgement loss unexpectedly succeeded")
            }
            Err(failure) => failure,
        };
        assert_eq!(*completion_failure.error(), "completion-acknowledgement-lost");
        assert_eq!(*completion_failure.request(), 44);
        assert_eq!(completion_failure.outcome_recorded().effect(), &request);
        assert_eq!(completion_failure.outcome_recorded().outcome(), &outcome);
        let completed = completion_failure
            .retry()
            .unwrap_or_else(|_| panic!("exact completion retry unexpectedly failed"));
        assert!(core::ptr::eq(completed.provider(), &provider));
        assert_eq!(completed.effect(), &request);
        assert_eq!(completed.outcome(), &outcome);
        assert!(!completed.completion_evidence());
    }
}
