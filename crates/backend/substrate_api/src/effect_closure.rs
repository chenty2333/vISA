use alloc::boxed::Box;
use core::ptr;

use contract_core::EffectRequest;

/// Preview protocol family for the provider-neutral effect-closure SPI.
///
/// This version is independent from the accepted joint-handoff wire v1. It
/// describes runtime/provider compatibility and does not reinterpret any v1
/// receipt or state-machine transition.
pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR: u16 = 2;
pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR: u16 = 0;

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
    pub freeze_thaw: bool,
    pub commit_close: bool,
    pub crash_rebind: bool,
    pub retained_device: bool,
    pub persistent_query: bool,
}

impl EffectClosureCapabilities {
    pub const fn contains(self, required: Self) -> bool {
        (!required.effect_admission || self.effect_admission)
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
            capabilities,
            minimum_authentication,
            minimum_limits,
        }
    }

    pub const fn is_well_formed(self) -> bool {
        self.protocol_major != 0 && self.minimum_limits.is_well_formed()
    }
}

/// Capability and compatibility description returned by one live provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderDescriptor {
    pub protocol: EffectClosureProtocolRange,
    pub capabilities: EffectClosureCapabilities,
    pub authentication: EffectClosureAuthenticationProfile,
    pub limits: EffectClosureProviderLimits,
}

impl EffectClosureProviderDescriptor {
    pub const fn is_well_formed(self) -> bool {
        self.protocol.is_well_formed()
            && self.limits.is_well_formed()
            && self.capabilities.effect_admission
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

    pub fn authorizes(&self, provider: &P, effect: &EffectRequest) -> bool {
        ptr::eq(self.provider, provider) && self.effect == *effect
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
    }

    impl FakeProvider {
        const fn new() -> Self {
            Self {
                registration_attempts: AtomicUsize::new(0),
                commit_attempts: AtomicUsize::new(0),
            }
        }
    }

    impl EffectClosureProvider for FakeProvider {
        type RegistrationRequest = u64;
        type Registered = u64;
        type Prepared = u64;
        type CommitMetadata = String;
        type CommitEvidence = u64;
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
            _effect: &EffectRequest,
            prepared: &Self::Prepared,
            metadata: &Self::CommitMetadata,
        ) -> Result<Self::CommitEvidence, Self::Error> {
            if self.commit_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                Err("acknowledgement-lost")
            } else {
                Ok(prepared + metadata.parse::<u64>().map_err(|_| "invalid-metadata")?)
            }
        }
    }

    const fn descriptor() -> EffectClosureProviderDescriptor {
        EffectClosureProviderDescriptor {
            protocol: EffectClosureProtocolRange::v2_preview(),
            capabilities: EffectClosureCapabilities {
                effect_admission: true,
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

        assert_eq!(*permit.commit_evidence(), 32);
        assert!(permit.authorizes(&provider, &request));
        assert!(!permit.authorizes(&other_provider, &request));
        assert!(!permit.authorizes(&provider, &effect(9)));
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
}
