use std::{env, path::PathBuf};

use contract_core::{
    Digest, EffectKind, EffectRequest, EntityRef, Generation, IdempotencyKey, Identity, LeaseEpoch,
    NodeIdentity, ProfileAccess,
};
use joint_handoff_core::{JointHandoffKey, ReceiptIssuerIdentity};
use substrate_api::{
    EffectAdmissionSession, EffectClosureAuthenticationProfile, EffectClosureCapabilities,
    EffectClosureProtocolRange, EffectClosureProvider, EffectClosureProviderDescriptor,
    EffectClosureProviderLimits, EffectClosureProviderRequirements,
};
use visa_conformance::{JointEffectClassification, JointEffectRecord};

use crate::{
    EffectPeerConfig, EffectPeerError, EffectPublicationRequest, ProcessEffectPeer,
    ProcessEffectPeerLaunch, ProcessLiveEffectCommitMetadata, ReferenceEffectCommitMetadata,
    ReferenceEffectPeer, effect_receipt_issuer, ownership_receipt_issuer,
};

const CORE_CAPABILITIES: EffectClosureCapabilities = EffectClosureCapabilities {
    effect_admission: true,
    freeze_thaw: true,
    commit_close: true,
    crash_rebind: false,
    retained_device: false,
    persistent_query: false,
};

const MINIMUM_LIMITS: EffectClosureProviderLimits = EffectClosureProviderLimits {
    max_scopes: 1,
    max_effects_per_scope: 1,
    max_inflight_mutations: 1,
    max_request_bytes: 1,
    max_receipt_bytes: 1,
};

#[derive(Clone, Copy)]
struct DescriptorContractVector {
    case_id: &'static str,
    descriptor: EffectClosureProviderDescriptor,
    requirements: EffectClosureProviderRequirements,
    expected_match: bool,
}

fn descriptor_contract_vectors() -> Vec<DescriptorContractVector> {
    let exact = EffectClosureProviderDescriptor {
        protocol: EffectClosureProtocolRange::v2_preview(),
        capabilities: CORE_CAPABILITIES,
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
        CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        MINIMUM_LIMITS,
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
        CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 65, ..MINIMUM_LIMITS },
    );

    let future_minor =
        EffectClosureProviderRequirements { protocol_minor: 1, ..exact_requirements };
    let malformed_minimum = EffectClosureProviderRequirements::v2_preview(
        CORE_CAPABILITIES,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        EffectClosureProviderLimits { max_request_bytes: 0, ..MINIMUM_LIMITS },
    );

    vec![
        DescriptorContractVector {
            case_id: "exact-v2-preview",
            descriptor: exact,
            requirements: exact_requirements,
            expected_match: true,
        },
        DescriptorContractVector {
            case_id: "capability-auth-and-limit-superset",
            descriptor: superset,
            requirements: exact_requirements,
            expected_match: true,
        },
        DescriptorContractVector {
            case_id: "wrong-protocol-major",
            descriptor: wrong_major,
            requirements: exact_requirements,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "missing-required-capability",
            descriptor: missing_capability,
            requirements: exact_requirements,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "authentication-below-minimum",
            descriptor: weak_authentication,
            requirements: exact_requirements,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "malformed-zero-limit",
            descriptor: malformed_limits,
            requirements: exact_requirements,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "limit-below-minimum",
            descriptor: insufficient_limits,
            requirements: larger_request,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "unsupported-future-minor",
            descriptor: exact,
            requirements: future_minor,
            expected_match: false,
        },
        DescriptorContractVector {
            case_id: "malformed-zero-minimum",
            descriptor: exact,
            requirements: malformed_minimum,
            expected_match: false,
        },
    ]
}

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

fn run_shared_provider_harness<P>(
    provider: &P,
    fixture: &SharedProviderFixture,
    minimum_authentication: EffectClosureAuthenticationProfile,
    metadata: P::CommitMetadata,
) where
    P: EffectClosureProvider<
            RegistrationRequest = EffectPublicationRequest,
            Error = EffectPeerError,
        >,
{
    let admission = EffectAdmissionSession::new(provider);
    let requirements = EffectClosureProviderRequirements::v2_preview(
        CORE_CAPABILITIES,
        minimum_authentication,
        MINIMUM_LIMITS,
    );
    let descriptor = admission.descriptor().unwrap();
    assert!(descriptor.satisfies(requirements));

    let mut stale = fixture.registration.clone();
    stale.scope_generation += 1;
    stale.record.binding_generation = stale.scope_generation;
    match admission.register(fixture.effect.clone(), stale) {
        Err(failure) if matches!(failure.error(), EffectPeerError::StaleScope) => {}
        Err(failure) => panic!("stale selector returned {:?}", failure.error()),
        Ok(_) => panic!("stale selector was accepted"),
    }

    let registered = admission
        .register(fixture.effect.clone(), fixture.registration.clone())
        .unwrap_or_else(|failure| panic!("register failed: {:?}", failure.error()));
    admission.register(fixture.effect.clone(), fixture.registration.clone()).unwrap_or_else(
        |failure| panic!("exact registration replay failed: {:?}", failure.error()),
    );

    for (field, mutated_effect) in conflicting_effect_mutations(&fixture.effect) {
        match admission.register(mutated_effect.clone(), fixture.registration.clone()) {
            Err(failure) if matches!(failure.error(), EffectPeerError::PublicationConflict) => {
                let (_, recovered_provider, recovered_effect, recovered_registration) =
                    failure.into_parts();
                assert!(core::ptr::eq(recovered_provider, provider), "{field}");
                assert_eq!(recovered_effect, mutated_effect, "{field}");
                assert_eq!(recovered_registration, fixture.registration, "{field}");
            }
            Err(failure) => {
                panic!("conflicting {field} returned {:?}", failure.error())
            }
            Ok(_) => panic!("conflicting {field} was accepted"),
        }
    }

    let mut conflicting = fixture.registration.clone();
    conflicting.record.domain = Identity::from_u128(99_001);
    match admission.register(fixture.effect.clone(), conflicting) {
        Err(failure) if matches!(failure.error(), EffectPeerError::PublicationConflict) => {}
        Err(failure) => panic!("conflicting selector returned {:?}", failure.error()),
        Ok(_) => panic!("conflicting selector was accepted"),
    }

    let prepared = registered
        .prepare()
        .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()));
    let permit = prepared
        .commit(metadata)
        .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()));
    assert!(permit.authorizes(provider, &fixture.effect));
    let mut different_effect = fixture.effect.clone();
    different_effect.request_digest = Digest::from_bytes([0x55; 32]);
    assert!(!permit.authorizes(provider, &different_effect));
}

fn conflicting_effect_mutations(effect: &EffectRequest) -> Vec<(&'static str, EffectRequest)> {
    let mut mutations = Vec::new();
    let mut push = |field, mutate: fn(&mut EffectRequest)| {
        let mut candidate = effect.clone();
        mutate(&mut candidate);
        mutations.push((field, candidate));
    };
    push("idempotency_key", |candidate| {
        candidate.idempotency_key = IdempotencyKey::from_u128(90_001);
    });
    push("request_digest", |candidate| {
        candidate.request_digest = Digest::from_bytes([0x44; 32]);
    });
    push("kind", |candidate| {
        candidate.kind = EffectKind::Profile {
            profile: Identity::from_u128(90_002),
            access: ProfileAccess::Write,
            payload: vec![0xaa],
        };
    });
    push("subject", |candidate| {
        candidate.subject = EntityRef::initial(Identity::from_u128(90_003));
    });
    push("resource", |candidate| {
        candidate.resource = EntityRef::initial(Identity::from_u128(90_004));
    });
    push("authority", |candidate| {
        candidate.authority = EntityRef::initial(Identity::from_u128(90_005));
    });
    push("causal_parent", |candidate| {
        candidate.causal_parent = Some(Identity::from_u128(90_006));
    });
    mutations
}

#[test]
fn provider_descriptor_contract_vectors_are_fixed_and_provider_neutral() {
    let vectors = descriptor_contract_vectors();
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
    run_shared_provider_harness(
        &peer,
        &fixture,
        EffectClosureAuthenticationProfile::None,
        ReferenceEffectCommitMetadata {
            result: 17,
            domain_revision: fixture.config.scope_generation,
        },
    );
    let query = crate::EffectPeer::query(&peer).unwrap();
    assert!(query.gate_open);
    assert_eq!(query.effect_count, 1);
}

#[test]
fn reference_permit_is_bound_to_one_concrete_provider_instance() {
    let fixture = shared_fixture(15_000);
    let first = ReferenceEffectPeer::new(fixture.config).unwrap();
    let second = ReferenceEffectPeer::new(fixture.config).unwrap();
    let admission = EffectAdmissionSession::new(&first);
    let registered = admission
        .register(fixture.effect.clone(), fixture.registration.clone())
        .unwrap_or_else(|failure| panic!("register failed: {:?}", failure.error()));
    let prepared = registered
        .prepare()
        .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()));
    let permit = prepared
        .commit(ReferenceEffectCommitMetadata {
            result: 17,
            domain_revision: fixture.config.scope_generation,
        })
        .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()));
    assert!(permit.authorizes(&first, &fixture.effect));
    assert!(!permit.authorizes(&second, &fixture.effect));
}

#[test]
#[ignore = "requires an explicitly pinned, separately built nexus-effect-peer binary"]
fn process_effect_peer_passes_the_shared_provider_harness() {
    let fixture = shared_fixture(20_000);
    let peer = ProcessEffectPeer::spawn(process_launch(), fixture.config).unwrap();
    run_shared_provider_harness(
        &peer,
        &fixture,
        EffectClosureAuthenticationProfile::IntegrityOnly,
        ProcessLiveEffectCommitMetadata {
            result: 17,
            domain_revision: fixture.config.scope_generation,
        },
    );

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
        ]
    ));
    peer.shutdown().unwrap();
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
