use std::{env, path::PathBuf};

use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EntityRef, Generation, IdempotencyKey,
    Identity, LeaseEpoch, NodeIdentity, ProfileAccess,
};
use joint_handoff_core::{JointHandoffKey, ReceiptIssuerIdentity};
use substrate_api::{
    CommittedEffectPermit, EffectAdmissionProfile, EffectAdmissionSession,
    EffectClosureAuthenticationProfile, EffectClosureProvider, EffectDispatchAcquireError,
    EffectDispatchOutcome,
};
use visa_conformance::{
    EffectClosureCompletionCase, EffectClosureConformanceErrorKind,
    EffectClosureConformanceFixture, EffectClosureObservedState, EffectClosureRegistrationCase,
    JointEffectClassification, JointEffectRecord, RECORDED_NATIVE_EFFECT_REPLAY_SCHEMA,
    RecordedNativeEffectExchange, RecordedNativeEffectOperation, RecordedNativeEffectReplay,
    RecordedNativeExactReplay, effect_closure_descriptor_contract_vectors,
    run_effect_closure_provider_contract, validate_recorded_native_effect_replay,
};

use crate::{
    EffectAdmissionRegistration, EffectPeer, EffectPeerConfig, EffectPeerError,
    EffectPublicationRequest, ProcessEffectCompletionEvidence, ProcessEffectCompletionRequest,
    ProcessEffectPeer, ProcessEffectPeerLaunch, ProcessEffectQueryObservation,
    ProcessEffectQueryPhase, ProcessLiveEffectAdvance, ProcessLiveEffectCommitMetadata,
    ReferenceEffectCommitMetadata, ReferenceEffectCompletionEvidence,
    ReferenceEffectCompletionRequest, ReferenceEffectOutcomeEvidence, ReferenceEffectPeer,
    ReferenceEffectQueryObservation, ReferenceEffectQueryPhase, effect_receipt_issuer,
    ownership_receipt_issuer,
};

struct SharedProviderFixture {
    config: EffectPeerConfig,
    effect: EffectRequest,
    registration: EffectPublicationRequest,
}

fn shared_fixture(seed: u128) -> SharedProviderFixture {
    let key = JointHandoffKey {
        continuity_unit: EntityRef {
            identity: Identity::from_u128(seed + 1),
            generation: Generation(1),
        },
        handoff: Identity::from_u128(seed + 2),
        source: NodeIdentity::new(Identity::from_u128(seed + 3)),
        destination: NodeIdentity::new(Identity::from_u128(seed + 4)),
        expected_epoch: LeaseEpoch(7),
        next_epoch: LeaseEpoch(8),
    };
    let ownership_namespace = issuer(seed + 20);
    let config = EffectPeerConfig {
        key,
        issuer: effect_receipt_issuer(issuer(seed + 30), key).unwrap(),
        ownership_issuer: ownership_receipt_issuer(ownership_namespace, key).unwrap(),
        registry_instance: Identity::from_u128(seed + 40),
        scope_id: Identity::from_u128(seed + 41),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 1,
        domain_bindings_digest: Digest::from_bytes([4; 32]),
    };
    let operation = Identity::from_u128(seed + 51);
    let effect = EffectRequest {
        operation,
        idempotency_key: IdempotencyKey::from_u128(seed + 52),
        causal_parent: None,
        node: key.source,
        subject: EntityRef::initial(Identity::from_u128(seed + 53)),
        resource: EntityRef::initial(Identity::from_u128(seed + 54)),
        authority: EntityRef::initial(Identity::from_u128(seed + 55)),
        lease_epoch: key.expected_epoch,
        request_digest: Digest::from_bytes([7; 32]),
        kind: EffectKind::Profile {
            profile: Identity::from_u128(seed + 56),
            access: ProfileAccess::Write,
            payload: vec![9, 10],
        },
    };
    let registration = EffectPublicationRequest {
        key,
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        source_epoch: key.expected_epoch,
        record: JointEffectRecord {
            effect: Identity::from_u128(seed + 50),
            operation,
            domain: Identity::from_u128(seed + 57),
            binding_generation: config.scope_generation,
            classification: JointEffectClassification::Registered,
            outcome_digest: None,
            tombstone_digest: None,
        },
    };
    SharedProviderFixture { config, effect, registration }
}

fn issuer(seed: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: Identity::from_u128(seed),
        issuer_incarnation: Identity::from_u128(seed + 1),
        key_id: Identity::from_u128(seed + 2),
        log_id: Identity::from_u128(seed + 3),
    }
}

fn registration(
    fixture: &SharedProviderFixture,
    case: EffectClosureRegistrationCase,
) -> EffectPublicationRequest {
    let mut request = fixture.registration.clone();
    match case {
        EffectClosureRegistrationCase::Exact => {}
        EffectClosureRegistrationCase::Stale => {
            request.scope_generation += 1;
            request.record.binding_generation = request.scope_generation;
        }
        EffectClosureRegistrationCase::Conflicting => {
            request.record.domain = Identity::from_u128(99_001);
        }
    }
    request
}

fn outcome() -> EffectOutcome {
    EffectOutcome::Indeterminate { evidence: None }
}

fn conflicting_outcome() -> EffectOutcome {
    EffectOutcome::Cancelled { evidence: None }
}

fn classify_error(error: &EffectPeerError) -> EffectClosureConformanceErrorKind {
    match error {
        EffectPeerError::StaleRegistry
        | EffectPeerError::StaleScope
        | EffectPeerError::StaleEpoch
        | EffectPeerError::StaleFreezeGeneration => {
            EffectClosureConformanceErrorKind::StaleSelector
        }
        EffectPeerError::InvalidRequest | EffectPeerError::PublicationConflict => {
            EffectClosureConformanceErrorKind::Conflict
        }
        EffectPeerError::StepConflict => EffectClosureConformanceErrorKind::InvalidTransition,
        _ => EffectClosureConformanceErrorKind::Other,
    }
}

struct ReferenceFixture<'a>(&'a SharedProviderFixture);

impl EffectClosureConformanceFixture<ReferenceEffectPeer> for ReferenceFixture<'_> {
    fn effect(&self) -> EffectRequest {
        self.0.effect.clone()
    }

    fn registration(&self, case: EffectClosureRegistrationCase) -> EffectAdmissionRegistration {
        EffectAdmissionRegistration::new(&self.0.effect, registration(self.0, case)).unwrap()
    }

    fn commit_metadata(&self) -> ReferenceEffectCommitMetadata {
        ReferenceEffectCommitMetadata {
            result: 17,
            domain_revision: self.0.config.scope_generation,
        }
    }

    fn conflicting_commit_metadata(&self) -> ReferenceEffectCommitMetadata {
        ReferenceEffectCommitMetadata {
            result: 18,
            domain_revision: self.0.config.scope_generation,
        }
    }

    fn outcome(&self) -> EffectOutcome {
        outcome()
    }

    fn conflicting_outcome(&self) -> EffectOutcome {
        conflicting_outcome()
    }

    fn completion(&self, case: EffectClosureCompletionCase) -> ReferenceEffectCompletionRequest {
        ReferenceEffectCompletionRequest {
            result: match case {
                EffectClosureCompletionCase::Exact => 17,
                EffectClosureCompletionCase::Conflicting => 18,
            },
        }
    }

    fn minimum_authentication(&self) -> EffectClosureAuthenticationProfile {
        EffectClosureAuthenticationProfile::None
    }

    fn classify_error(&self, error: &EffectPeerError) -> EffectClosureConformanceErrorKind {
        classify_error(error)
    }

    fn registration_is_replay(&self, registered: &crate::ReferenceRegisteredEffect) -> bool {
        registered.is_replay()
    }

    fn commit_is_replay(&self, evidence: &crate::ReferenceEffectCommitEvidence) -> bool {
        evidence.replay
    }

    fn outcome_is_replay(&self, evidence: &ReferenceEffectOutcomeEvidence) -> bool {
        evidence.is_replay()
    }

    fn completion_is_replay(&self, evidence: &ReferenceEffectCompletionEvidence) -> bool {
        evidence.is_replay()
    }

    fn observed_state(
        &self,
        observation: &ReferenceEffectQueryObservation,
    ) -> EffectClosureObservedState {
        match observation.phase() {
            ReferenceEffectQueryPhase::Committed => EffectClosureObservedState::Committed,
            ReferenceEffectQueryPhase::OutcomeRecorded => {
                EffectClosureObservedState::OutcomeRecorded
            }
            ReferenceEffectQueryPhase::Completed => EffectClosureObservedState::Completed,
            ReferenceEffectQueryPhase::Registered | ReferenceEffectQueryPhase::Prepared => {
                panic!("conformance queried the reference provider before Commit")
            }
        }
    }

    fn observed_outcome<'a>(
        &self,
        observation: &'a ReferenceEffectQueryObservation,
    ) -> Option<&'a EffectOutcome> {
        observation.outcome()
    }
}

struct ProcessFixture<'a>(&'a SharedProviderFixture);

impl EffectClosureConformanceFixture<ProcessEffectPeer> for ProcessFixture<'_> {
    fn effect(&self) -> EffectRequest {
        self.0.effect.clone()
    }

    fn registration(&self, case: EffectClosureRegistrationCase) -> EffectAdmissionRegistration {
        EffectAdmissionRegistration::new(&self.0.effect, registration(self.0, case)).unwrap()
    }

    fn commit_metadata(&self) -> ProcessLiveEffectCommitMetadata {
        ProcessLiveEffectCommitMetadata {
            result: 17,
            domain_revision: self.0.config.scope_generation,
        }
    }

    fn conflicting_commit_metadata(&self) -> ProcessLiveEffectCommitMetadata {
        ProcessLiveEffectCommitMetadata {
            result: 18,
            domain_revision: self.0.config.scope_generation,
        }
    }

    fn outcome(&self) -> EffectOutcome {
        outcome()
    }

    fn conflicting_outcome(&self) -> EffectOutcome {
        conflicting_outcome()
    }

    fn completion(&self, case: EffectClosureCompletionCase) -> ProcessEffectCompletionRequest {
        ProcessEffectCompletionRequest {
            result: match case {
                EffectClosureCompletionCase::Exact => 17,
                EffectClosureCompletionCase::Conflicting => 18,
            },
        }
    }

    fn minimum_authentication(&self) -> EffectClosureAuthenticationProfile {
        EffectClosureAuthenticationProfile::IntegrityOnly
    }

    fn classify_error(&self, error: &EffectPeerError) -> EffectClosureConformanceErrorKind {
        classify_error(error)
    }

    fn registration_is_replay(&self, registered: &ProcessLiveEffectAdvance) -> bool {
        registered.is_replay()
    }

    fn commit_is_replay(&self, evidence: &ProcessLiveEffectAdvance) -> bool {
        evidence.is_replay()
    }

    fn outcome_is_replay(&self, evidence: &ProcessLiveEffectAdvance) -> bool {
        evidence.is_replay()
    }

    fn completion_is_replay(&self, evidence: &ProcessEffectCompletionEvidence) -> bool {
        evidence.is_replay()
    }

    fn observed_state(
        &self,
        observation: &ProcessEffectQueryObservation,
    ) -> EffectClosureObservedState {
        match observation.phase() {
            ProcessEffectQueryPhase::Committed => EffectClosureObservedState::Committed,
            ProcessEffectQueryPhase::OutcomeRecorded => EffectClosureObservedState::OutcomeRecorded,
            ProcessEffectQueryPhase::Completed => EffectClosureObservedState::Completed,
            ProcessEffectQueryPhase::Registered | ProcessEffectQueryPhase::Prepared => {
                panic!("conformance queried the process provider before Commit")
            }
        }
    }

    fn observed_outcome<'a>(
        &self,
        observation: &'a ProcessEffectQueryObservation,
    ) -> Option<&'a EffectOutcome> {
        observation.outcome()
    }
}

fn reference_permit<'a>(
    peer: &'a ReferenceEffectPeer,
    fixture: &SharedProviderFixture,
) -> CommittedEffectPermit<'a, ReferenceEffectPeer> {
    EffectAdmissionSession::new(peer)
        .register(
            fixture.effect.clone(),
            EffectAdmissionRegistration::new(&fixture.effect, fixture.registration.clone())
                .unwrap(),
        )
        .unwrap_or_else(|failure| panic!("register failed: {:?}", failure.error()))
        .prepare()
        .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()))
        .commit(ReferenceEffectCommitMetadata {
            result: 17,
            domain_revision: fixture.config.scope_generation,
        })
        .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()))
}

#[test]
fn provider_descriptor_contract_vectors_are_fixed_and_provider_neutral() {
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
            "descriptor vector {}",
            vector.case_id
        );
    }
}

#[test]
fn compatibility_publication_remains_available_but_required_profile_rejects_the_bypass() {
    let fixture = shared_fixture(12_000);
    let compatibility = ReferenceEffectPeer::new(fixture.config).unwrap();
    assert_eq!(
        compatibility.descriptor().unwrap().admission_profile,
        EffectAdmissionProfile::Compatibility
    );
    assert_eq!(
        EffectPeer::publish(&compatibility, fixture.registration.clone()).unwrap(),
        crate::EffectPublicationResult::Published
    );

    let required = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    assert_eq!(
        required.descriptor().unwrap().admission_profile,
        EffectAdmissionProfile::AdmissionRequired
    );
    assert!(matches!(
        EffectPeer::publish(&required, fixture.registration.clone()),
        Err(EffectPeerError::Unsupported(_))
    ));
}

#[test]
fn provider_revocation_between_commit_and_dispatch_fails_closed() {
    let fixture = shared_fixture(13_000);
    let peer = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let permit = reference_permit(&peer, &fixture);
    peer.revoke_effect_dispatch(fixture.registration.record.effect).unwrap();
    assert!(matches!(
        permit.consume(&peer, &fixture.effect),
        Err(EffectDispatchAcquireError::Provider(EffectPeerError::Revoked))
    ));
}

#[test]
fn generation_change_and_duplicate_permit_consumption_are_rejected() {
    let stale_fixture = shared_fixture(14_000);
    let stale_peer = ReferenceEffectPeer::new_admission_required(stale_fixture.config).unwrap();
    let stale = reference_permit(&stale_peer, &stale_fixture);
    EffectPeer::rebind(&stale_peer, Identity::from_u128(14_999)).unwrap();
    assert!(matches!(
        stale.consume(&stale_peer, &stale_fixture.effect),
        Err(EffectDispatchAcquireError::Provider(EffectPeerError::StaleScope))
    ));

    let fixture = shared_fixture(14_500);
    let peer = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let first = reference_permit(&peer, &fixture);
    let duplicate = reference_permit(&peer, &fixture);
    first
        .consume(&peer, &fixture.effect)
        .unwrap()
        .finish(EffectDispatchOutcome::GuestReturned)
        .unwrap();
    assert!(matches!(
        duplicate.consume(&peer, &fixture.effect),
        Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
    ));
}

#[test]
fn reference_permit_is_bound_to_one_concrete_provider_instance() {
    let fixture = shared_fixture(15_000);
    let first = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let second = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let permit = reference_permit(&first, &fixture);
    assert!(matches!(
        permit.consume(&second, &fixture.effect),
        Err(EffectDispatchAcquireError::BindingMismatch)
    ));
}

#[test]
fn reference_effect_peer_passes_the_shared_provider_harness() {
    let fixture = shared_fixture(10_000);
    let peer = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let other = ReferenceEffectPeer::new_admission_required(fixture.config).unwrap();
    let report =
        run_effect_closure_provider_contract(&peer, &other, &ReferenceFixture(&fixture)).unwrap();
    assert_eq!(report.observations(), visa_conformance::EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX);
    let query = crate::EffectPeer::query(&peer).unwrap();
    assert!(query.gate_open);
    assert_eq!(query.effect_count, 1);
}

#[test]
#[ignore = "requires an explicitly pinned, separately built nexus-effect-peer binary"]
fn process_effect_peer_passes_the_shared_provider_harness() {
    let fixture = shared_fixture(20_000);
    let peer =
        ProcessEffectPeer::spawn_admission_required(process_launch(), fixture.config).unwrap();
    let other =
        ProcessEffectPeer::spawn_admission_required(process_launch(), fixture.config).unwrap();
    assert!(matches!(
        EffectPeer::publish(&peer, fixture.registration.clone()),
        Err(EffectPeerError::Unsupported(_))
    ));
    assert!(matches!(
        peer.register_live_effect(fixture.registration.clone()),
        Err(EffectPeerError::Unsupported(_))
    ));
    let process_report =
        run_effect_closure_provider_contract(&peer, &other, &ProcessFixture(&fixture)).unwrap();

    let reference_fixture = shared_fixture(30_000);
    let reference = ReferenceEffectPeer::new_admission_required(reference_fixture.config).unwrap();
    let other_reference =
        ReferenceEffectPeer::new_admission_required(reference_fixture.config).unwrap();
    let reference_report = run_effect_closure_provider_contract(
        &reference,
        &other_reference,
        &ReferenceFixture(&reference_fixture),
    )
    .unwrap();
    assert_eq!(process_report, reference_report);

    let before_replay = peer.native_transcript().unwrap();
    let replay_response_jsonl =
        String::from_utf8(peer.replay_last_native_request().unwrap()).unwrap();
    let after_replay = peer.native_transcript().unwrap();
    assert_eq!(before_replay, after_replay);
    let last = before_replay.last().unwrap();
    let recorded = RecordedNativeEffectReplay {
        schema: RECORDED_NATIVE_EFFECT_REPLAY_SCHEMA.to_owned(),
        exchanges: before_replay.iter().map(recorded_exchange).collect(),
        exact_replay: RecordedNativeExactReplay {
            request_id: last.request_id,
            original_response_jsonl: last.response_jsonl.clone(),
            replay_response_jsonl,
            accepted_chain_length_before: before_replay.len(),
            accepted_chain_length_after: after_replay.len(),
        },
    };
    validate_recorded_native_effect_replay(&recorded).unwrap();

    let commands = before_replay
        .iter()
        .map(|exchange| {
            serde_json::from_str::<crate::nexus_effect_wire::PeerRequest>(
                exchange.request_jsonl.strip_suffix('\n').unwrap(),
            )
            .unwrap()
            .command
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        commands.as_slice(),
        [
            crate::nexus_effect_wire::PeerCommand::Initialize(_),
            crate::nexus_effect_wire::PeerCommand::Register(_),
            crate::nexus_effect_wire::PeerCommand::Prepare(_),
            crate::nexus_effect_wire::PeerCommand::Commit(_),
            crate::nexus_effect_wire::PeerCommand::Complete(_),
        ]
    ));
    peer.shutdown().unwrap();
    other.shutdown().unwrap();
}

fn recorded_exchange(exchange: &crate::NativeJsonlExchange) -> RecordedNativeEffectExchange {
    let request = serde_json::from_str::<crate::nexus_effect_wire::PeerRequest>(
        exchange.request_jsonl.strip_suffix('\n').unwrap(),
    )
    .unwrap();
    let operation = match request.command {
        crate::nexus_effect_wire::PeerCommand::Initialize(_) => {
            RecordedNativeEffectOperation::Initialize
        }
        crate::nexus_effect_wire::PeerCommand::Register(_) => {
            RecordedNativeEffectOperation::Register
        }
        crate::nexus_effect_wire::PeerCommand::Prepare(_) => RecordedNativeEffectOperation::Prepare,
        crate::nexus_effect_wire::PeerCommand::Commit(_) => RecordedNativeEffectOperation::Commit,
        crate::nexus_effect_wire::PeerCommand::Complete(_) => {
            RecordedNativeEffectOperation::Complete
        }
        _ => panic!("provider lifecycle transcript contained an unrelated native command"),
    };
    RecordedNativeEffectExchange {
        operation,
        request_id: exchange.request_id,
        request_jsonl: exchange.request_jsonl.clone(),
        response_jsonl: exchange.response_jsonl.clone(),
        receipt_sequence: exchange.receipt_sequence,
        request_sha256: exchange.request_sha256.clone(),
        previous_receipt_sha256: exchange.previous_receipt_sha256.clone(),
        receipt_sha256: exchange.receipt_sha256.clone(),
    }
}

fn process_launch() -> ProcessEffectPeerLaunch {
    let executable = env::var_os("NEXUS_EFFECT_PEER_BIN")
        .map(PathBuf::from)
        .expect("NEXUS_EFFECT_PEER_BIN must name the built Nexus peer");
    ProcessEffectPeerLaunch::new(
        executable,
        env::var("NEXUS_EFFECT_PEER_SHA256")
            .expect("NEXUS_EFFECT_PEER_SHA256 must pin the exact executable"),
        env::var("NEXUS_EFFECT_PEER_REVISION")
            .expect("NEXUS_EFFECT_PEER_REVISION must pin the Nexus source revision"),
    )
}
