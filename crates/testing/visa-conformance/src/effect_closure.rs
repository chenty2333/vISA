use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EntityRef, IdempotencyKey, Identity,
    ProfileAccess,
};
use substrate_api::{
    CommittedEffectPermit, EffectAdmissionSession, EffectClosureAuthenticationProfile,
    EffectClosureCapabilities, EffectClosureProtocolRange, EffectClosureProvider,
    EffectClosureProviderDescriptor, EffectClosureProviderLimits,
    EffectClosureProviderRequirements,
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
    );

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

    let mut malformed_limits = exact;
    malformed_limits.limits.max_request_bytes = 0;

    let mut insufficient_limits = exact;
    insufficient_limits.limits.max_request_bytes = 64;
    let larger_request = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 65, ..EFFECT_CLOSURE_MINIMUM_LIMITS },
    );

    let future_minor =
        EffectClosureProviderRequirements { protocol_minor: 1, ..exact_requirements };
    let malformed_minimum = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 0, ..EFFECT_CLOSURE_MINIMUM_LIMITS },
    );
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
) -> Result<(), EffectClosureConformanceFailure>
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    let effect = fixture.effect();
    let admission = EffectAdmissionSession::new(provider);
    let descriptor =
        admission.descriptor().map_err(|error| provider_error("descriptor", fixture, &error))?;
    let requirements = EffectClosureProviderRequirements::v2_preview(
        EFFECT_CLOSURE_CORE_CAPABILITIES,
        fixture.minimum_authentication(),
        EFFECT_CLOSURE_MINIMUM_LIMITS,
    );
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

    let permit = exact_permit(provider, fixture, &effect)?;
    expect_observation(provider, fixture, &effect, EffectClosureObservedState::Committed, None)?;
    require(
        "permit-exact-effect",
        permit.authorizes(provider, &effect),
        "committed permit did not authorize its provider and exact effect",
    )?;
    require(
        "permit-other-provider",
        !permit.authorizes(other_provider, &effect),
        "committed permit authorized another provider instance",
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

    for vector in effect_request_contract_vectors(&effect) {
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

    match provider.complete_effect(&effect, &fixture.completion(EffectClosureCompletionCase::Exact))
    {
        Err(error) => require_error(
            "complete-before-outcome",
            fixture.classify_error(&error),
            EffectClosureConformanceErrorKind::InvalidTransition,
        )?,
        Ok(_) => return fail("complete-before-outcome", "completion succeeded before outcome"),
    }

    let canonical_outcome = fixture.outcome();
    let outcome_recorded = permit
        .record_outcome(canonical_outcome.clone())
        .map_err(|failure| provider_error("record-outcome", fixture, failure.error()))?;
    require(
        "record-outcome",
        !fixture.outcome_is_replay(outcome_recorded.outcome_evidence()),
        "first outcome recording was marked as replay",
    )?;
    expect_observation(
        provider,
        fixture,
        &effect,
        EffectClosureObservedState::OutcomeRecorded,
        Some(&canonical_outcome),
    )?;

    let replay_outcome = exact_permit(provider, fixture, &effect)?
        .record_outcome(fixture.outcome())
        .map_err(|failure| provider_error("replay-outcome", fixture, failure.error()))?;
    require(
        "replay-outcome",
        fixture.outcome_is_replay(replay_outcome.outcome_evidence()),
        "exact outcome replay was not reported as replay",
    )?;

    match exact_permit(provider, fixture, &effect)?.record_outcome(fixture.conflicting_outcome()) {
        Err(failure) => require_error(
            "conflicting-outcome",
            fixture.classify_error(failure.error()),
            EffectClosureConformanceErrorKind::Conflict,
        )?,
        Ok(_) => return fail("conflicting-outcome", "conflicting outcome was accepted"),
    }

    let completed = outcome_recorded
        .complete(fixture.completion(EffectClosureCompletionCase::Exact))
        .map_err(|failure| provider_error("complete", fixture, failure.error()))?;
    require(
        "complete",
        !fixture.completion_is_replay(completed.completion_evidence()),
        "first completion was marked as replay",
    )?;
    expect_observation(
        provider,
        fixture,
        &effect,
        EffectClosureObservedState::Completed,
        Some(&canonical_outcome),
    )?;

    let replay_completed = replay_outcome
        .complete(fixture.completion(EffectClosureCompletionCase::Exact))
        .map_err(|failure| provider_error("replay-complete", fixture, failure.error()))?;
    require(
        "replay-complete",
        fixture.completion_is_replay(replay_completed.completion_evidence()),
        "exact completion replay was not reported as replay",
    )?;

    let conflicting_completion =
        exact_permit(provider, fixture, &effect)?.record_outcome(fixture.outcome()).map_err(
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

    Ok(())
}

fn exact_permit<'a, P, F>(
    provider: &'a P,
    fixture: &F,
    effect: &EffectRequest,
) -> Result<CommittedEffectPermit<'a, P>, EffectClosureConformanceFailure>
where
    P: EffectClosureProvider,
    F: EffectClosureConformanceFixture<P>,
{
    let registered = EffectAdmissionSession::new(provider)
        .register(effect.clone(), fixture.registration(EffectClosureRegistrationCase::Exact))
        .map_err(|failure| provider_error("register", fixture, failure.error()))?;
    let prepared = registered
        .prepare()
        .map_err(|failure| provider_error("prepare", fixture, failure.error()))?;
    prepared
        .commit(fixture.commit_metadata())
        .map_err(|failure| provider_error("commit", fixture, failure.error()))
}

fn expect_observation<P, F>(
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
        .map_err(|error| provider_error("query-effect", fixture, &error))?
        .ok_or_else(|| failure("query-effect", "known effect query returned absent"))?;
    require(
        "query-effect",
        fixture.observed_state(&observed) == expected,
        "query returned the wrong session-local state",
    )?;
    require(
        "query-effect",
        fixture.observed_outcome(&observed) == expected_outcome,
        "query returned the wrong canonical outcome",
    )
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
        phase: EffectClosureObservedState,
        outcome: Option<EffectOutcome>,
        completion: Option<u64>,
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
        type OutcomeEvidence = FakeReplayEvidence;
        type CompletionRequest = u64;
        type CompletionEvidence = FakeReplayEvidence;
        type QueryObservation = FakeQueryObservation;
        type Error = FakeError;

        fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, Self::Error> {
            Ok(EffectClosureProviderDescriptor {
                protocol: EffectClosureProtocolRange::v2_preview(),
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
            let _ = prepared.replay;
            Ok(FakeCommitEvidence { effect: effect.clone() })
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
        run_effect_closure_provider_contract(&provider, &other_provider, &FakeFixture).unwrap();
    }
}
