use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EntityRef, IdempotencyKey, Identity,
    ProfileAccess,
};
use substrate_api::{
    CommittedEffectPermit, EffectAdmissionProfile, EffectAdmissionSession,
    EffectClosureAuthenticationProfile, EffectClosureCapabilities, EffectClosureProtocolRange,
    EffectClosureProvider, EffectClosureProviderDescriptor, EffectClosureProviderLimits,
    EffectClosureProviderRequirements, EffectDispatchAcquireError, EffectDispatchOutcome,
};

use crate::effect_closure_replay::{
    EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX, EffectClosureContractExpectation, EffectClosureFaultCase,
    EffectClosureProviderContractReport,
};

pub const EFFECT_CLOSURE_CORE_CAPABILITIES: EffectClosureCapabilities = EffectClosureCapabilities {
    effect_admission: true,
    outcome_recording: true,
    effect_completion: true,
    session_query: true,
    freeze_thaw: true,
    commit_close: true,
    crash_rebind: false,
    retained_device: false,
    persistent_query: false,
};

pub const EFFECT_CLOSURE_MINIMUM_LIMITS: EffectClosureProviderLimits =
    EffectClosureProviderLimits {
        max_scopes: 1,
        max_effects_per_scope: 1,
        max_inflight_mutations: 1,
        max_request_bytes: 1,
        max_receipt_bytes: 1,
    };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectClosureDescriptorContractVector {
    pub case_id: &'static str,
    pub descriptor: EffectClosureProviderDescriptor,
    pub requirements: EffectClosureProviderRequirements,
    pub expected_match: bool,
}

pub fn effect_closure_descriptor_contract_vectors() -> Vec<EffectClosureDescriptorContractVector> {
    let exact = EffectClosureProviderDescriptor {
        protocol: EffectClosureProtocolRange::v2_preview(),
        admission_profile: EffectAdmissionProfile::AdmissionRequired,
        capabilities: EFFECT_CLOSURE_CORE_CAPABILITIES,
        authentication: EffectClosureAuthenticationProfile::IntegrityOnly,
        limits: EffectClosureProviderLimits {
            max_scopes: 1,
            max_effects_per_scope: 8,
            max_inflight_mutations: 1,
            max_request_bytes: 4096,
            max_receipt_bytes: 8192,
        },
    };
    let exact_requirements = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EFFECT_CLOSURE_MINIMUM_LIMITS,
    )
    .require_admission();

    let mut superset = exact;
    superset.capabilities.crash_rebind = true;
    superset.capabilities.persistent_query = true;
    superset.authentication = EffectClosureAuthenticationProfile::AuthenticatedFresh;

    let mut wrong_major = exact;
    wrong_major.protocol.major += 1;

    let mut missing_capability = exact;
    missing_capability.capabilities.freeze_thaw = false;

    let mut weak_authentication = exact;
    weak_authentication.authentication = EffectClosureAuthenticationProfile::None;

    let mut compatibility_only = exact;
    compatibility_only.admission_profile = EffectAdmissionProfile::Compatibility;

    let mut malformed_limits = exact;
    malformed_limits.limits.max_request_bytes = 0;

    let mut insufficient_limits = exact;
    insufficient_limits.limits.max_request_bytes = 64;
    let larger_request = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 65, ..EFFECT_CLOSURE_MINIMUM_LIMITS },
    )
    .require_admission();

    let future_minor =
        EffectClosureProviderRequirements { protocol_minor: 1, ..exact_requirements };
    let malformed_minimum = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 0, ..EFFECT_CLOSURE_MINIMUM_LIMITS },
    )
    .require_admission();
    let mut completion_without_outcome = exact;
    completion_without_outcome.capabilities.outcome_recording = false;
    let mut persistent_without_session_query = exact;
    persistent_without_session_query.capabilities.session_query = false;
    persistent_without_session_query.capabilities.persistent_query = true;

    vec![
        EffectClosureDescriptorContractVector {
            case_id: "exact-v2-preview",
            descriptor: exact,
            requirements: exact_requirements,
            expected_match: true,
        },
        EffectClosureDescriptorContractVector {
            case_id: "capability-auth-and-limit-superset",
            descriptor: superset,
            requirements: exact_requirements,
            expected_match: true,
        },
        EffectClosureDescriptorContractVector {
            case_id: "wrong-protocol-major",
            descriptor: wrong_major,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "missing-required-capability",
            descriptor: missing_capability,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "authentication-below-minimum",
            descriptor: weak_authentication,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "compatibility-profile-cannot-satisfy-admission-required",
            descriptor: compatibility_only,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "malformed-zero-limit",
            descriptor: malformed_limits,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "limit-below-minimum",
            descriptor: insufficient_limits,
            requirements: larger_request,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "unsupported-future-minor",
            descriptor: exact,
            requirements: future_minor,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "malformed-zero-minimum",
            descriptor: exact,
            requirements: malformed_minimum,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "completion-without-outcome-recording",
            descriptor: completion_without_outcome,
            requirements: exact_requirements,
            expected_match: false,
        },
        EffectClosureDescriptorContractVector {
            case_id: "persistent-query-without-session-query",
            descriptor: persistent_without_session_query,
            requirements: exact_requirements,
            expected_match: false,
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRequestContractVector {
    pub case_id: &'static str,
    pub request: EffectRequest,
}

pub fn effect_request_contract_vectors(effect: &EffectRequest) -> Vec<EffectRequestContractVector> {
    let mut vectors = Vec::new();
    let mut push = |case_id, mutate: fn(&mut EffectRequest)| {
        let mut request = effect.clone();
        mutate(&mut request);
        vectors.push(EffectRequestContractVector { case_id, request });
    };
    push("idempotency-key", |request| {
        request.idempotency_key = IdempotencyKey::from_u128(90_001);
    });
    push("request-digest", |request| {
        request.request_digest = Digest::from_bytes([0x44; 32]);
    });
    push("kind", |request| {
        request.kind = EffectKind::Profile {
            profile: Identity::from_u128(90_002),
            access: ProfileAccess::Write,
            payload: vec![0xaa],
        };
    });
    push("subject", |request| {
        request.subject = EntityRef::initial(Identity::from_u128(90_003));
    });
    push("resource", |request| {
        request.resource = EntityRef::initial(Identity::from_u128(90_004));
    });
    push("authority", |request| {
        request.authority = EntityRef::initial(Identity::from_u128(90_005));
    });
    push("causal-parent", |request| {
        request.causal_parent =
            if request.causal_parent.is_some() { None } else { Some(Identity::from_u128(90_006)) };
    });
    vectors
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClosureRegistrationCase {
    Exact,
    Stale,
    Conflicting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClosureCompletionCase {
    Exact,
    Conflicting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClosureConformanceErrorKind {
    StaleSelector,
    Conflict,
    InvalidTransition,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClosureObservedState {
    Committed,
    OutcomeRecorded,
    Completed,
}

pub trait EffectClosureConformanceFixture<P>
where
    P: EffectClosureProvider,
{
    fn effect(&self) -> EffectRequest;
    fn registration(&self, case: EffectClosureRegistrationCase) -> P::RegistrationRequest;
    fn commit_metadata(&self) -> P::CommitMetadata;
    fn conflicting_commit_metadata(&self) -> P::CommitMetadata;
    fn outcome(&self) -> EffectOutcome;
    fn conflicting_outcome(&self) -> EffectOutcome;
    fn completion(&self, case: EffectClosureCompletionCase) -> P::CompletionRequest;
    fn minimum_authentication(&self) -> EffectClosureAuthenticationProfile;
    fn classify_error(&self, error: &P::Error) -> EffectClosureConformanceErrorKind;
    fn registration_is_replay(&self, registered: &P::Registered) -> bool;
    fn commit_is_replay(&self, evidence: &P::CommitEvidence) -> bool;
    fn outcome_is_replay(&self, evidence: &P::OutcomeEvidence) -> bool;
    fn completion_is_replay(&self, evidence: &P::CompletionEvidence) -> bool;
    fn observed_state(&self, observation: &P::QueryObservation) -> EffectClosureObservedState;
    fn observed_outcome<'a>(
        &self,
        observation: &'a P::QueryObservation,
    ) -> Option<&'a EffectOutcome>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectClosureConformanceFailure {
    pub case_id: &'static str,
    pub detail: String,
}

pub fn run_effect_closure_provider_contract<P, F>(
    provider: &P,
    other_provider: &P,
    fixture: &F,
) -> Result<EffectClosureProviderContractReport, EffectClosureConformanceFailure>
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    let mut observations = Vec::with_capacity(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.len());
    let effect = fixture.effect();
    let admission = EffectAdmissionSession::new(provider);
    let descriptor =
        admission.descriptor().map_err(|error| provider_error("descriptor", fixture, &error))?;
    let requirements = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        fixture.minimum_authentication(),
        EFFECT_CLOSURE_MINIMUM_LIMITS,
    )
    .require_admission();
    require(
        "descriptor",
        descriptor.satisfies(requirements),
        "provider did not satisfy the core v2-preview contract",
    )?;
    require(
        "descriptor",
        !descriptor.capabilities.persistent_query,
        "first-tranche provider must not claim persistent query",
    )?;
    observe_case(&mut observations, "descriptor", EffectClosureContractExpectation::Accepted)?;

    let mut absent = effect.clone();
    absent.operation = Identity::from_u128(95_001);
    absent.idempotency_key = IdempotencyKey::from_u128(95_002);
    require(
        "query-absent",
        admission
            .query_effect(&absent)
            .map_err(|error| provider_error("query-absent", fixture, &error))?
            .is_none(),
        "absent effect query returned an observation",
    )?;
    observe_case(&mut observations, "query-absent", EffectClosureContractExpectation::Absent)?;

    match admission
        .register(effect.clone(), fixture.registration(EffectClosureRegistrationCase::Stale))
    {
        Err(failure) => require_error(
            "stale-selector",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::StaleSelector,
        )?,
        Ok(_) => return fail("stale-selector", "stale registration was accepted"),
    }
    observe_case(
        &mut observations,
        "stale-selector",
        EffectClosureContractExpectation::RejectedStaleSelector,
    )?;

    let permit = exact_permit(provider, fixture, &effect, false)?;
    observe_case(
        &mut observations,
        "initial-admission",
        EffectClosureContractExpectation::Applied,
    )?;
    expect_observation(
        "query-committed",
        provider,
        fixture,
        &effect,
        EffectClosureObservedState::Committed,
        None,
    )?;
    observe_case(
        &mut observations,
        "query-committed",
        EffectClosureContractExpectation::ObservedCommitted,
    )?;
    require(
        "permit-exact-effect",
        permit.authorizes(provider, &effect),
        "committed permit did not authorize its provider and exact effect",
    )?;
    observe_case(
        &mut observations,
        "permit-exact-effect",
        EffectClosureContractExpectation::Authorized,
    )?;
    require(
        "permit-other-provider",
        !permit.authorizes(other_provider, &effect),
        "committed permit authorized another provider instance",
    )?;
    observe_case(
        &mut observations,
        "permit-other-provider",
        EffectClosureContractExpectation::Denied,
    )?;
    let different_effect = effect_request_contract_vectors(&effect)
        .into_iter()
        .next()
        .ok_or_else(|| failure("permit-mutated-effect", "mutation registry was empty"))?
        .request;
    require(
        "permit-mutated-effect",
        !permit.authorizes(provider, &different_effect),
        "committed permit authorized a mutated effect",
    )?;
    observe_case(
        &mut observations,
        "permit-mutated-effect",
        EffectClosureContractExpectation::Denied,
    )?;
    match exact_permit(provider, fixture, &effect, true)?.consume(other_provider, &effect) {
        Err(EffectDispatchAcquireError::BindingMismatch) => {}
        Err(EffectDispatchAcquireError::Provider(error)) => {
            return Err(provider_error("dispatch-other-provider", fixture, &error));
        }
        Ok(_) => return fail("dispatch-other-provider", "another provider accepted the permit"),
    }
    observe_case(
        &mut observations,
        "dispatch-other-provider",
        EffectClosureContractExpectation::Denied,
    )?;
    match exact_permit(provider, fixture, &effect, true)?.consume(provider, &different_effect) {
        Err(EffectDispatchAcquireError::BindingMismatch) => {}
        Err(EffectDispatchAcquireError::Provider(error)) => {
            return Err(provider_error("dispatch-mutated-effect", fixture, &error));
        }
        Ok(_) => return fail("dispatch-mutated-effect", "a mutated effect consumed the permit"),
    }
    observe_case(
        &mut observations,
        "dispatch-mutated-effect",
        EffectClosureContractExpectation::Denied,
    )?;

    let _replayed_permit = exact_permit(provider, fixture, &effect, true)?;
    observe_case(
        &mut observations,
        "exact-admission-replay",
        EffectClosureContractExpectation::ExactReplay,
    )?;

    for vector in effect_request_contract_vectors(&effect) {
        let case_id = vector.case_id;
        match admission
            .register(vector.request, fixture.registration(EffectClosureRegistrationCase::Exact))
        {
            Err(failure) => require_error(
                vector.case_id,
                fixture.classify_error(failure.error()),
                EffectClosureConformanceErrorKind::Conflict,
            )?,
            Ok(_) => return fail(vector.case_id, "mutated canonical effect was accepted"),
        }
        observe_case(
            &mut observations,
            case_id,
            EffectClosureContractExpectation::RejectedConflict,
        )?;
    }
    match admission
        .register(effect.clone(), fixture.registration(EffectClosureRegistrationCase::Conflicting))
    {
        Err(failure) => require_error(
            "conflicting-registration",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::Conflict,
        )?,
        Ok(_) => return fail("conflicting-registration", "conflicting registration was accepted"),
    }
    observe_case(
        &mut observations,
        "conflicting-registration",
        EffectClosureContractExpectation::RejectedConflict,
    )?;

    let conflicting_commit = admission
        .register(effect.clone(), fixture.registration(EffectClosureRegistrationCase::Exact))
        .map_err(|failure| provider_error("prepare-conflicting-commit", fixture, failure.error()))?
        .prepare()
        .map_err(|failure| {
            provider_error("prepare-conflicting-commit", fixture, failure.error())
        })?;
    match conflicting_commit.commit(fixture.conflicting_commit_metadata()) {
        Err(failure) => require_error(
            "conflicting-commit",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Ok(_) => return fail("conflicting-commit", "conflicting Commit replay was accepted"),
    }
    observe_case(
        &mut observations,
        "conflicting-commit",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    )?;

    match provider.complete_effect(&effect, &fixture.completion(EffectClosureCompletionCase::Exact))
    {
        Err(error) => require_error(
            "complete-before-outcome",
            fixture.classify_error(&error),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Ok(_) => return fail("complete-before-outcome", "completion succeeded before outcome"),
    }
    observe_case(
        &mut observations,
        "complete-before-outcome",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    )?;

    let canonical_outcome = fixture.outcome();
    match exact_permit(provider, fixture, &effect, true)?.record_outcome(canonical_outcome.clone()) {
        Err(failure) => require_error(
            "outcome-before-dispatch",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Ok(_) => return fail("outcome-before-dispatch", "outcome succeeded before dispatch"),
    }
    observe_case(
        &mut observations,
        "outcome-before-dispatch",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    )?;

    let dispatch = permit.consume(provider, &effect).map_err(|error| match error {
        EffectDispatchAcquireError::BindingMismatch => {
            failure("dispatch", "exact permit reported a binding mismatch")
        }
        EffectDispatchAcquireError::Provider(error) => provider_error("dispatch", fixture, &error),
    })?;
    let permit = dispatch
        .finish(EffectDispatchOutcome::GuestReturned)
        .map_err(|error| provider_error("finish-dispatch", fixture, &error))?;
    observe_case(
        &mut observations,
        "dispatch-gate-consumes-permit",
        EffectClosureContractExpectation::PermitConsumed,
    )?;

    match exact_permit(provider, fixture, &effect, true)?.consume(provider, &effect) {
        Err(EffectDispatchAcquireError::Provider(error)) => require_error(
            "duplicate-dispatch",
            fixture.classify_error(&error),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Err(EffectDispatchAcquireError::BindingMismatch) => {
            return fail("duplicate-dispatch", "duplicate permit reported a binding mismatch");
        }
        Ok(_) => return fail("duplicate-dispatch", "duplicate dispatch was accepted"),
    }
    observe_case(
        &mut observations,
        "duplicate-dispatch",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    )?;

    let outcome_recorded = permit
        .record_outcome(canonical_outcome.clone())
        .map_err(|failure| provider_error("record-outcome", fixture, failure.error()))?;
    require(
        "record-outcome",
        !fixture.outcome_is_replay(outcome_recorded.outcome_evidence()),
        "first outcome recording was marked as replay",
    )?;
    observe_case(&mut observations, "record-outcome", EffectClosureContractExpectation::Applied)?;
    expect_observation(
        "query-outcome-recorded",
        provider,
        fixture,
        &effect,
        EffectClosureObservedState::OutcomeRecorded,
        Some(&canonical_outcome),
    )?;
    observe_case(
        &mut observations,
        "query-outcome-recorded",
        EffectClosureContractExpectation::ObservedOutcomeRecorded,
    )?;

    let replay_outcome = exact_permit(provider, fixture, &effect, true)?
        .record_outcome(fixture.outcome())
        .map_err(|failure| provider_error("replay-outcome", fixture, failure.error()))?;
    require(
        "replay-outcome",
        fixture.outcome_is_replay(replay_outcome.outcome_evidence()),
        "exact outcome replay was not reported as replay",
    )?;
    observe_case(
        &mut observations,
        "replay-outcome",
        EffectClosureContractExpectation::ExactReplay,
    )?;

    match exact_permit(provider, fixture, &effect, true)?
        .record_outcome(fixture.conflicting_outcome())
    {
        Err(failure) => require_error(
            "conflicting-outcome",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::Conflict,
        )?,
        Ok(_) => return fail("conflicting-outcome", "conflicting outcome was accepted"),
    }
    observe_case(
        &mut observations,
        "conflicting-outcome",
        EffectClosureContractExpectation::RejectedConflict,
    )?;

    let completed = outcome_recorded
        .complete(fixture.completion(EffectClosureCompletionCase::Exact))
        .map_err(|failure| provider_error("complete", fixture, failure.error()))?;
    require(
        "complete",
        !fixture.completion_is_replay(completed.completion_evidence()),
        "first completion was marked as replay",
    )?;
    observe_case(&mut observations, "complete", EffectClosureContractExpectation::Applied)?;
    expect_observation(
        "query-completed",
        provider,
        fixture,
        &effect,
        EffectClosureObservedState::Completed,
        Some(&canonical_outcome),
    )?;
    observe_case(
        &mut observations,
        "query-completed",
        EffectClosureContractExpectation::ObservedCompleted,
    )?;

    let replay_completed = replay_outcome
        .complete(fixture.completion(EffectClosureCompletionCase::Exact))
        .map_err(|failure| provider_error("replay-complete", fixture, failure.error()))?;
    require(
        "replay-complete",
        fixture.completion_is_replay(replay_completed.completion_evidence()),
        "exact completion replay was not reported as replay",
    )?;
    observe_case(
        &mut observations,
        "replay-complete",
        EffectClosureContractExpectation::ExactReplay,
    )?;

    let conflicting_completion =
        exact_permit(provider, fixture, &effect, true)?.record_outcome(fixture.outcome()).map_err(
            |failure| provider_error("prepare-conflicting-complete", fixture, failure.error()),
        )?;
    match conflicting_completion
        .complete(fixture.completion(EffectClosureCompletionCase::Conflicting))
    {
        Err(failure) => require_error(
            "conflicting-complete",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::Conflict,
        )?,
        Ok(_) => return fail("conflicting-complete", "conflicting completion was accepted"),
    }
    observe_case(
        &mut observations,
        "conflicting-complete",
        EffectClosureContractExpectation::RejectedConflict,
    )?;

    let failed_dispatch = exact_permit(other_provider, fixture, &effect, false)?
        .consume(other_provider, &effect)
        .map_err(|error| match error {
            EffectDispatchAcquireError::BindingMismatch => {
                failure("failed-dispatch", "exact permit reported a binding mismatch")
            }
            EffectDispatchAcquireError::Provider(error) => {
                provider_error("failed-dispatch", fixture, &error)
            }
        })?
        .finish(EffectDispatchOutcome::GuestFailed)
        .map_err(|error| provider_error("finish-failed-dispatch", fixture, &error))?;
    observe_case(
        &mut observations,
        "failed-dispatch",
        EffectClosureContractExpectation::PermitConsumed,
    )?;
    match failed_dispatch.record_outcome(fixture.outcome()) {
        Err(failure) => require_error(
            "failed-dispatch-canonical-outcome",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Ok(_) => {
            return fail(
                "failed-dispatch-canonical-outcome",
                "GuestFailed was accepted as a canonical effect outcome",
            );
        }
    }
    observe_case(
        &mut observations,
        "failed-dispatch-canonical-outcome",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    )?;
    expect_observation(
        "query-failed-dispatch",
        other_provider,
        fixture,
        &effect,
        EffectClosureObservedState::Committed,
        None,
    )?;
    observe_case(
        &mut observations,
        "query-failed-dispatch",
        EffectClosureContractExpectation::ObservedCommitted,
    )?;

    EffectClosureProviderContractReport::new(observations)
        .map_err(|detail| failure("fault-matrix", detail))
}

fn exact_permit<'a, P, F>(
    provider: &'a P,
    fixture: &F,
    effect: &EffectRequest,
    expected_replay: bool,
) -> Result<CommittedEffectPermit<'a, P>, EffectClosureConformanceFailure>
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    let registered = EffectAdmissionSession::new(provider)
        .register(effect.clone(), fixture.registration(EffectClosureRegistrationCase::Exact))
        .map_err(|failure| provider_error("register", fixture, failure.error()))?;
    require(
        "register",
        fixture.registration_is_replay(registered.provider_state()) == expected_replay,
        "exact registration returned the wrong replay disposition",
    )?;
    let prepared = registered
        .prepare()
        .map_err(|failure| provider_error("prepare", fixture, failure.error()))?;
    let permit = prepared
        .commit(fixture.commit_metadata())
        .map_err(|failure| provider_error("commit", fixture, failure.error()))?;
    require(
        "commit",
        fixture.commit_is_replay(permit.commit_evidence()) == expected_replay,
        "exact Commit returned the wrong replay disposition",
    )?;
    Ok(permit)
}

fn expect_observation<P, F>(
    case_id: &'static str,
    provider: &P,
    fixture: &F,
    effect: &EffectRequest,
    expected: EffectClosureObservedState,
    expected_outcome: Option<&EffectOutcome>,
) -> Result<(), EffectClosureConformanceFailure>
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    let observed = provider
        .query_effect(effect)
        .map_err(|error| provider_error(case_id, fixture, &error))?
        .ok_or_else(|| failure(case_id, "known effect query returned absent"))?;
    require(
        case_id,
        fixture.observed_state(&observed) == expected,
        "query returned the wrong session-local state",
    )?;
    require(
        case_id,
        fixture.observed_outcome(&observed) == expected_outcome,
        "query returned the wrong canonical outcome",
    )
}

fn observe_case(
    observations: &mut Vec<EffectClosureFaultCase>,
    case_id: &'static str,
    expectation: EffectClosureContractExpectation,
) -> Result<(), EffectClosureConformanceFailure> {
    let observed = EffectClosureFaultCase { case_id, expectation };
    let index = observations.len();
    require(
        case_id,
        EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.get(index) == Some(&observed),
        format!("fault-matrix order drifted at index {index}"),
    )?;
    observations.push(observed);
    Ok(())
}

fn require_error(
    case_id: &'static str,
    actual: EffectClosureConformanceErrorKind,
    expected: EffectClosureConformanceErrorKind,
) -> Result<(), EffectClosureConformanceFailure> {
    require(case_id, actual == expected, "provider returned the wrong error class")
}

fn provider_error<P, F>(
    case_id: &'static str,
    fixture: &F,
    error: &P::Error,
) -> EffectClosureConformanceFailure
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    failure(case_id, format!("provider returned {:?}", fixture.classify_error(error)))
}

fn require(
    case_id: &'static str,
    condition: bool,
    detail: impl Into<String>,
) -> Result<(), EffectClosureConformanceFailure> {
    if condition { Ok(()) } else { fail(case_id, detail) }
}

fn fail<T>(
    case_id: &'static str,
    detail: impl Into<String>,
) -> Result<T, EffectClosureConformanceFailure> {
    Err(failure(case_id, detail))
}

fn failure(case_id: &'static str, detail: impl Into<String>) -> EffectClosureConformanceFailure {
    EffectClosureConformanceFailure { case_id, detail: detail.into() }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use contract_core::{EffectKind, EntityRef, LeaseEpoch, NodeIdentity};

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeError {
        Stale,
        Conflict,
        InvalidTransition,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeRegistration {
        generation: u64,
        selector: u64,
    }

    #[derive(Clone, Debug)]
    struct FakeState {
        effect: EffectRequest,
        registration: FakeRegistration,
        dispatch: FakeDispatchPhase,
        phase: EffectClosureObservedState,
        outcome: Option<EffectOutcome>,
        completion: Option<u64>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeDispatchPhase {
        Available,
        Consumed,
        GuestReturned,
        GuestFailed,
    }

    #[derive(Default)]
    struct FakeProvider {
        effects: Mutex<BTreeMap<Identity, FakeState>>,
    }

    #[derive(Clone, Debug)]
    struct FakeBoundState {
        effect: EffectRequest,
        replay: bool,
    }

    #[derive(Clone, Debug)]
    struct FakeCommitEvidence {
        effect: EffectRequest,
        replay: bool,
    }

    #[derive(Clone, Debug)]
    struct FakeDispatchFence {
        effect: EffectRequest,
    }

    #[derive(Clone, Copy, Debug)]
    struct FakeReplayEvidence {
        replay: bool,
    }

    #[derive(Clone, Debug)]
    struct FakeQueryObservation {
        phase: EffectClosureObservedState,
        outcome: Option<EffectOutcome>,
    }

    impl EffectClosureProvider for FakeProvider {
        type RegistrationRequest = FakeRegistration;
        type Registered = FakeBoundState;
        type Prepared = FakeBoundState;
        type CommitMetadata = u64;
        type CommitEvidence = FakeCommitEvidence;
        type DispatchFence = FakeDispatchFence;
        type OutcomeEvidence = FakeReplayEvidence;
        type CompletionRequest = u64;
        type CompletionEvidence = FakeReplayEvidence;
        type QueryObservation = FakeQueryObservation;
        type Error = FakeError;

        fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, Self::Error> {
            Ok(EffectClosureProviderDescriptor {
                protocol: EffectClosureProtocolRange::v2_preview(),
                admission_profile: EffectAdmissionProfile::AdmissionRequired,
                capabilities: EFFECT_CLOSURE_CORE_CAPABILITIES,
                authentication: EffectClosureAuthenticationProfile::None,
                limits: EffectClosureProviderLimits {
                    max_scopes: 1,
                    max_effects_per_scope: 8,
                    max_inflight_mutations: 1,
                    max_request_bytes: 4096,
                    max_receipt_bytes: 8192,
                },
            })
        }

        fn register_effect(
            &self,
            effect: &EffectRequest,
            request: &Self::RegistrationRequest,
        ) -> Result<Self::Registered, Self::Error> {
            if request.generation != 1 {
                return Err(FakeError::Stale);
            }
            let mut effects = self.effects.lock().unwrap();
            if let Some(existing) = effects.get(&effect.operation) {
                if existing.effect == *effect && existing.registration == *request {
                    return Ok(FakeBoundState { effect: effect.clone(), replay: true });
                }
                return Err(FakeError::Conflict);
            }
            effects.insert(
                effect.operation,
                FakeState {
                    effect: effect.clone(),
                    registration: request.clone(),
                    dispatch: FakeDispatchPhase::Available,
                    phase: EffectClosureObservedState::Committed,
                    outcome: None,
                    completion: None,
                },
            );
            Ok(FakeBoundState { effect: effect.clone(), replay: false })
        }

        fn prepare_effect(
            &self,
            effect: &EffectRequest,
            registered: &Self::Registered,
        ) -> Result<Self::Prepared, Self::Error> {
            if registered.effect != *effect {
                return Err(FakeError::Conflict);
            }
            Ok(registered.clone())
        }

        fn commit_effect(
            &self,
            effect: &EffectRequest,
            prepared: &Self::Prepared,
            metadata: &Self::CommitMetadata,
        ) -> Result<Self::CommitEvidence, Self::Error> {
            if prepared.effect != *effect {
                return Err(FakeError::Conflict);
            }
            if *metadata != 7 {
                return Err(FakeError::InvalidTransition);
            }
            Ok(FakeCommitEvidence { effect: effect.clone(), replay: prepared.replay })
        }

        fn consume_committed_effect(
            &self,
            effect: &EffectRequest,
            committed: &Self::CommitEvidence,
        ) -> Result<Self::DispatchFence, Self::Error> {
            if committed.effect != *effect {
                return Err(FakeError::Conflict);
            }
            let mut effects = self.effects.lock().unwrap();
            let state = effects.get_mut(&effect.operation).ok_or(FakeError::Conflict)?;
            if state.effect != *effect {
                return Err(FakeError::Conflict);
            }
            if state.dispatch != FakeDispatchPhase::Available {
                return Err(FakeError::InvalidTransition);
            }
            state.dispatch = FakeDispatchPhase::Consumed;
            Ok(FakeDispatchFence { effect: effect.clone() })
        }

        fn finish_effect_dispatch(
            &self,
            effect: &EffectRequest,
            fence: &Self::DispatchFence,
            outcome: EffectDispatchOutcome,
        ) -> Result<(), Self::Error> {
            if fence.effect != *effect {
                return Err(FakeError::Conflict);
            }
            let mut effects = self.effects.lock().unwrap();
            let state = effects.get_mut(&effect.operation).ok_or(FakeError::Conflict)?;
            if state.effect != *effect {
                return Err(FakeError::Conflict);
            }
            if state.dispatch != FakeDispatchPhase::Consumed {
                return Err(FakeError::InvalidTransition);
            }
            state.dispatch = match outcome {
                EffectDispatchOutcome::GuestReturned => FakeDispatchPhase::GuestReturned,
                EffectDispatchOutcome::GuestFailed => FakeDispatchPhase::GuestFailed,
            };
            Ok(())
        }

        fn record_effect_outcome(
            &self,
            effect: &EffectRequest,
            committed: &Self::CommitEvidence,
            outcome: &EffectOutcome,
        ) -> Result<Self::OutcomeEvidence, Self::Error> {
            if committed.effect != *effect {
                return Err(FakeError::Conflict);
            }
            let mut effects = self.effects.lock().unwrap();
            let state = effects.get_mut(&effect.operation).ok_or(FakeError::Conflict)?;
            if state.effect != *effect {
                return Err(FakeError::Conflict);
            }
            if let Some(existing) = &state.outcome {
                return if existing == outcome {
                    Ok(FakeReplayEvidence { replay: true })
                } else {
                    Err(FakeError::Conflict)
                };
            }
            if state.dispatch != FakeDispatchPhase::GuestReturned {
                return Err(FakeError::InvalidTransition);
            }
            state.outcome = Some(outcome.clone());
            state.phase = EffectClosureObservedState::OutcomeRecorded;
            Ok(FakeReplayEvidence { replay: false })
        }

        fn complete_effect(
            &self,
            effect: &EffectRequest,
            request: &Self::CompletionRequest,
        ) -> Result<Self::CompletionEvidence, Self::Error> {
            let mut effects = self.effects.lock().unwrap();
            let state = effects.get_mut(&effect.operation).ok_or(FakeError::Conflict)?;
            if state.effect != *effect {
                return Err(FakeError::Conflict);
            }
            if state.outcome.is_none() {
                return Err(FakeError::InvalidTransition);
            }
            if let Some(existing) = state.completion {
                return if existing == *request {
                    Ok(FakeReplayEvidence { replay: true })
                } else {
                    Err(FakeError::Conflict)
                };
            }
            state.completion = Some(*request);
            state.phase = EffectClosureObservedState::Completed;
            Ok(FakeReplayEvidence { replay: false })
        }

        fn query_effect(
            &self,
            effect: &EffectRequest,
        ) -> Result<Option<Self::QueryObservation>, Self::Error> {
            let effects = self.effects.lock().unwrap();
            Ok(effects.get(&effect.operation).filter(|state| state.effect == *effect).map(
                |state| FakeQueryObservation { phase: state.phase, outcome: state.outcome.clone() },
            ))
        }
    }

    struct FakeFixture;

    impl EffectClosureConformanceFixture<FakeProvider> for FakeFixture {
        fn effect(&self) -> EffectRequest {
            EffectRequest {
                operation: Identity::from_u128(1),
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

        fn registration(&self, case: EffectClosureRegistrationCase) -> FakeRegistration {
            match case {
                EffectClosureRegistrationCase::Exact => {
                    FakeRegistration { generation: 1, selector: 1 }
                }
                EffectClosureRegistrationCase::Stale => {
                    FakeRegistration { generation: 2, selector: 1 }
                }
                EffectClosureRegistrationCase::Conflicting => {
                    FakeRegistration { generation: 1, selector: 2 }
                }
            }
        }

        fn commit_metadata(&self) -> u64 {
            7
        }

        fn conflicting_commit_metadata(&self) -> u64 {
            8
        }

        fn outcome(&self) -> EffectOutcome {
            EffectOutcome::Indeterminate { evidence: None }
        }

        fn conflicting_outcome(&self) -> EffectOutcome {
            EffectOutcome::Cancelled { evidence: None }
        }

        fn completion(&self, case: EffectClosureCompletionCase) -> u64 {
            match case {
                EffectClosureCompletionCase::Exact => 11,
                EffectClosureCompletionCase::Conflicting => 12,
            }
        }

        fn minimum_authentication(&self) -> EffectClosureAuthenticationProfile {
            EffectClosureAuthenticationProfile::None
        }

        fn classify_error(&self, error: &FakeError) -> EffectClosureConformanceErrorKind {
            match error {
                FakeError::Stale => EffectClosureConformanceErrorKind::StaleSelector,
                FakeError::Conflict => EffectClosureConformanceErrorKind::Conflict,
                FakeError::InvalidTransition => {
                    EffectClosureConformanceErrorKind::InvalidTransition
                }
            }
        }

        fn registration_is_replay(&self, registered: &FakeBoundState) -> bool {
            registered.replay
        }

        fn commit_is_replay(&self, evidence: &FakeCommitEvidence) -> bool {
            evidence.replay
        }

        fn outcome_is_replay(&self, evidence: &FakeReplayEvidence) -> bool {
            evidence.replay
        }

        fn completion_is_replay(&self, evidence: &FakeReplayEvidence) -> bool {
            evidence.replay
        }

        fn observed_state(&self, observation: &FakeQueryObservation) -> EffectClosureObservedState {
            observation.phase
        }

        fn observed_outcome<'a>(
            &self,
            observation: &'a FakeQueryObservation,
        ) -> Option<&'a EffectOutcome> {
            observation.outcome.as_ref()
        }
    }

    #[test]
    fn descriptor_vectors_are_fixed_and_provider_neutral() {
        let vectors = effect_closure_descriptor_contract_vectors();
        assert_eq!(
            vectors.iter().map(|vector| vector.case_id).collect::<Vec<_>>(),
            [
                "exact-v2-preview",
                "capability-auth-and-limit-superset",
                "wrong-protocol-major",
                "missing-required-capability",
                "authentication-below-minimum",
                "compatibility-profile-cannot-satisfy-admission-required",
                "malformed-zero-limit",
                "limit-below-minimum",
                "unsupported-future-minor",
                "malformed-zero-minimum",
                "completion-without-outcome-recording",
                "persistent-query-without-session-query",
            ]
        );
        for vector in vectors {
            assert_eq!(
                vector.descriptor.satisfies(vector.requirements),
                vector.expected_match,
                "{}",
                vector.case_id
            );
        }
    }

    #[test]
    fn generic_fake_provider_passes_the_full_lifecycle_contract() {
        let provider = FakeProvider::default();
        let other_provider = FakeProvider::default();
        let report =
            run_effect_closure_provider_contract(&provider, &other_provider, &FakeFixture).unwrap();
        assert_eq!(report.observations(), EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX);
    }
}
