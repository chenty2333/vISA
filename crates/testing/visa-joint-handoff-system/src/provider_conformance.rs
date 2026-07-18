use std::{env, path::PathBuf};

use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EntityRef, Generation, IdempotencyKey,
    Identity, LeaseEpoch, NodeIdentity, ProfileAccess,
};
use joint_handoff_core::{JointHandoffKey, ReceiptIssuerIdentity};
use substrate_api::EffectClosureAuthenticationProfile;
use visa_conformance::{
    EffectClosureCompletionCase, EffectClosureConformanceErrorKind,
    EffectClosureConformanceFixture, EffectClosureObservedState, EffectClosureRegistrationCase,
    JointEffectClassification, JointEffectRecord, effect_closure_descriptor_contract_vectors,
    run_effect_closure_provider_contract,
};

use crate::{
    EffectPeerConfig, EffectPeerError, EffectPublicationRequest, ProcessEffectCompletionEvidence,
    ProcessEffectCompletionRequest, ProcessEffectPeer, ProcessEffectPeerLaunch,
    ProcessEffectQueryObservation, ProcessEffectQueryPhase, ProcessLiveEffectAdvance,
    ProcessLiveEffectCommitMetadata, ReferenceEffectCommitMetadata,
    ReferenceEffectCompletionEvidence, ReferenceEffectCompletionRequest,
    ReferenceEffectOutcomeEvidence, ReferenceEffectPeer, ReferenceEffectQueryObservation,
    ReferenceEffectQueryPhase, effect_receipt_issuer, ownership_receipt_issuer,
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
        EffectPeerError::PublicationConflict => EffectClosureConformanceErrorKind::Conflict,
        EffectPeerError::StepConflict => EffectClosureConformanceErrorKind::InvalidTransition,
        _ => EffectClosureConformanceErrorKind::Other,
    }
}

struct ReferenceFixture<'a>(&'a SharedProviderFixture);

impl EffectClosureConformanceFixture<ReferenceEffectPeer> for ReferenceFixture<'_> {
    fn effect(&self) -> EffectRequest {
        self.0.effect.clone()
    }

    fn registration(&self, case: EffectClosureRegistrationCase) -> EffectPublicationRequest {
        registration(self.0, case)
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

    fn registration(&self, case: EffectClosureRegistrationCase) -> EffectPublicationRequest {
        registration(self.0, case)
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
fn reference_effect_peer_passes_the_shared_provider_harness() {
    let fixture = shared_fixture(10_000);
    let peer = ReferenceEffectPeer::new(fixture.config).unwrap();
    let other = ReferenceEffectPeer::new(fixture.config).unwrap();
    run_effect_closure_provider_contract(&peer, &other, &ReferenceFixture(&fixture)).unwrap();
    let query = crate::EffectPeer::query(&peer).unwrap();
    assert!(query.gate_open);
    assert_eq!(query.effect_count, 1);
}

#[test]
#[ignore = "requires an explicitly pinned, separately built nexus-effect-peer binary"]
fn process_effect_peer_passes_the_shared_provider_harness() {
    let fixture = shared_fixture(20_000);
    let peer = ProcessEffectPeer::spawn(process_launch(), fixture.config).unwrap();
    let other = ProcessEffectPeer::spawn(process_launch(), fixture.config).unwrap();
    run_effect_closure_provider_contract(&peer, &other, &ProcessFixture(&fixture)).unwrap();

    let commands = peer
        .native_transcript()
        .unwrap()
        .into_iter()
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
