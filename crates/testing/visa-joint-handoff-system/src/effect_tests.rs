use std::sync::{Arc, Barrier};

use contract_core::{
    Digest, EffectKind, EffectRequest, EntityRef, IdempotencyKey, Identity, LeaseEpoch,
    NodeIdentity, ProfileAccess,
};
use joint_handoff_core::{
    JointHandoffKey, PreparedBindings, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
};
use substrate_api::{CommittedEffectPermit, EffectAdmissionSession, EffectDispatchOutcome};
use visa_conformance::{JointEffectClassification, JointEffectRecord};

use crate::{
    EffectAdmissionRegistration, EffectCloseRequest, EffectCloseResult, EffectFreezeRequest,
    EffectPeerConfig, EffectPeerError, EffectPublicationRequest, EffectPublicationResult,
    EffectThawRequest, OwnershipAbortRequest, OwnershipCommitRequest, OwnershipReserveRequest,
    OwnershipSealRequest, ReferenceEffectCommitMetadata, ReferenceEffectPeer,
    ReferenceOwnershipLog, effect_receipt_issuer, ownership_receipt_issuer,
};

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
    }
}

fn key() -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: EntityRef::initial(id(1)),
        handoff: id(2),
        source: NodeIdentity::new(id(3)),
        destination: NodeIdentity::new(id(4)),
        expected_epoch: LeaseEpoch(7),
        next_epoch: LeaseEpoch(8),
    }
}

fn config() -> EffectPeerConfig {
    EffectPeerConfig {
        key: key(),
        issuer: effect_receipt_issuer(issuer(200), key()).unwrap(),
        ownership_issuer: ownership_receipt_issuer(issuer(100), key()).unwrap(),
        registry_instance: id(210),
        scope_id: id(211),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
        domain_bindings_digest: digest(4),
    }
}

fn reference(kind: ReceiptKind, base: u128) -> ReceiptRef {
    ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: key().handoff,
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
        sequence: 1,
        digest: digest(u8::try_from(base).unwrap_or(250)),
    }
}

fn bindings(
    intent: ReceiptRef,
    visa: ReceiptRef,
    effect: ReceiptRef,
    destination: ReceiptRef,
    cohort: Digest,
) -> PreparedBindings {
    PreparedBindings {
        prepare_intent_receipt_digest: intent.digest,
        visa_freeze_receipt_digest: visa.digest,
        effect_freeze_receipt_digest: effect.digest,
        snapshot: id(40),
        snapshot_integrity_digest: digest(41),
        source_journal_position: contract_core::JournalPosition(42),
        source_state_digest: digest(43),
        component_digest: digest(44),
        profile_digest: digest(45),
        destination_prepared_receipt_digest: destination.digest,
        destination_state_digest: digest(46),
        prepared_authorities_digest: digest(47),
        prepared_bindings_digest: digest(48),
        effect_cohort_manifest_digest: cohort,
        joint_mapping_manifest_digest: digest(50),
    }
}

fn ownership() -> ReferenceOwnershipLog {
    ReferenceOwnershipLog::open(":memory:", issuer(100)).unwrap()
}

fn reserve(log: &mut ReferenceOwnershipLog) -> joint_handoff_core::PrepareIntentReceipt {
    log.initialize_unit(key().continuity_unit, key().source, key().expected_epoch).unwrap();
    log.reserve(OwnershipReserveRequest { key: key(), expected_state_sequence: 0 }).unwrap()
}

fn freeze_request(intent: joint_handoff_core::PrepareIntentReceipt) -> EffectFreezeRequest {
    let config = config();
    EffectFreezeRequest {
        key: key(),
        intent,
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        authority_epoch: config.authority_epoch,
        freeze_generation: config.freeze_generation,
    }
}

fn effect(value: u128, classification: JointEffectClassification) -> JointEffectRecord {
    let (outcome_digest, tombstone_digest) = match classification {
        JointEffectClassification::Registered | JointEffectClassification::Aborted => (None, None),
        JointEffectClassification::Committed => (Some(digest(value as u8)), None),
        JointEffectClassification::ResolvedTombstone => {
            (Some(digest(value as u8)), Some(digest(240)))
        }
        JointEffectClassification::UnresolvedTombstone => (None, Some(digest(241))),
    };
    JointEffectRecord {
        effect: id(value),
        operation: id(value + 1),
        domain: id(value + 2),
        binding_generation: 1,
        classification,
        outcome_digest,
        tombstone_digest,
    }
}

fn publication(record: JointEffectRecord) -> EffectPublicationRequest {
    let config = config();
    EffectPublicationRequest {
        key: key(),
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        source_epoch: key().expected_epoch,
        record,
    }
}

fn admission_effect(value: u128) -> EffectRequest {
    EffectRequest {
        operation: id(value + 1),
        idempotency_key: IdempotencyKey::from_u128(value + 10),
        causal_parent: None,
        node: key().source,
        subject: EntityRef::initial(id(value + 11)),
        resource: EntityRef::initial(id(value + 12)),
        authority: EntityRef::initial(id(value + 13)),
        lease_epoch: key().expected_epoch,
        request_digest: digest(7),
        kind: EffectKind::Profile {
            profile: id(value + 2),
            access: ProfileAccess::Write,
            payload: vec![1, 2, 3],
        },
    }
}

fn admitted_permit<'a>(
    peer: &'a ReferenceEffectPeer,
    effect: &EffectRequest,
    registration: &EffectPublicationRequest,
) -> CommittedEffectPermit<'a, ReferenceEffectPeer> {
    EffectAdmissionSession::new(peer)
        .register(
            effect.clone(),
            EffectAdmissionRegistration::new(effect, registration.clone()).unwrap(),
        )
        .unwrap_or_else(|failure| panic!("registration failed: {:?}", failure.error()))
        .prepare()
        .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()))
        .commit(ReferenceEffectCommitMetadata { result: 17, domain_revision: 1 })
        .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()))
}

fn seal_and_commit(
    log: &mut ReferenceOwnershipLog,
    intent: &joint_handoff_core::PrepareIntentReceipt,
    freeze: &joint_handoff_core::NexusFreezeReceipt,
) -> joint_handoff_core::OwnershipCommitReceipt {
    let intent_ref = intent.receipt_ref().unwrap();
    let effect_ref = freeze.receipt_ref().unwrap();
    let visa = reference(ReceiptKind::VisaFreeze, 60);
    let destination = reference(ReceiptKind::DestinationPrepared, 80);
    let prepared = log
        .seal(OwnershipSealRequest {
            key: key(),
            reservation: intent.reservation,
            intent: intent_ref,
            visa_freeze: visa,
            effect_freeze: effect_ref,
            destination_prepared: destination,
            bindings: bindings(
                intent_ref,
                visa,
                effect_ref,
                destination,
                freeze.effect_cohort_digest,
            ),
            expected_state_sequence: 1,
        })
        .unwrap();
    log.commit(OwnershipCommitRequest {
        key: key(),
        reservation: intent.reservation,
        prepared: prepared.receipt_ref().unwrap(),
        expected_state_sequence: 2,
    })
    .unwrap()
}

#[test]
fn publication_before_freeze_is_in_cohort_and_exact_retry_survives_closed_gate() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let request = publication(effect(20, JointEffectClassification::Committed));
    assert_eq!(peer.publish(request.clone()).unwrap(), EffectPublicationResult::Published);
    let frozen = peer.freeze(freeze_request(intent)).unwrap();
    assert_eq!(frozen.receipt.counts.registered, 1);
    assert_eq!(peer.publish(request).unwrap(), EffectPublicationResult::Replay);
    assert_eq!(
        peer.publish(publication(effect(30, JointEffectClassification::Committed))),
        Err(EffectPeerError::GateClosed)
    );
}

#[test]
fn admitted_reference_outcome_makes_the_exact_effect_ready_to_commit() {
    let peer = ReferenceEffectPeer::new_admission_required(config()).unwrap();
    let request = admission_effect(20);
    let registration = publication(effect(20, JointEffectClassification::Registered));
    let permit = admitted_permit(&peer, &request, &registration);
    let evidence = *permit.commit_evidence();
    permit.consume(&peer, &request).unwrap().finish(EffectDispatchOutcome::GuestReturned).unwrap();
    let outcome = publication(effect(20, JointEffectClassification::Committed));
    assert_eq!(
        peer.record_effect_outcome(&request, &evidence, outcome.clone()).unwrap(),
        EffectPublicationResult::Published
    );
    assert_eq!(
        peer.record_effect_outcome(&request, &evidence, outcome).unwrap(),
        EffectPublicationResult::Replay
    );

    let mut ownership = ownership();
    let frozen = peer.freeze(freeze_request(reserve(&mut ownership))).unwrap();
    assert_eq!(frozen.receipt.counts.registered, 1);
    assert_eq!(frozen.receipt.counts.committed, 1);
    assert_eq!(frozen.receipt.disposition, joint_handoff_core::FreezeDisposition::ReadyToCommit);
}

#[test]
fn missing_or_guest_failed_reference_outcome_remains_blocked() {
    for (value, outcome) in
        [(30, EffectDispatchOutcome::GuestReturned), (40, EffectDispatchOutcome::GuestFailed)]
    {
        let peer = ReferenceEffectPeer::new_admission_required(config()).unwrap();
        let request = admission_effect(value);
        let registration = publication(effect(value, JointEffectClassification::Registered));
        let permit = admitted_permit(&peer, &request, &registration);
        let evidence = *permit.commit_evidence();
        permit.consume(&peer, &request).unwrap().finish(outcome).unwrap();
        if outcome == EffectDispatchOutcome::GuestFailed {
            assert_eq!(
                peer.record_effect_outcome(
                    &request,
                    &evidence,
                    publication(effect(value, JointEffectClassification::Committed)),
                ),
                Err(EffectPeerError::StepConflict)
            );
        }
        let mut ownership = ownership();
        let frozen = peer.freeze(freeze_request(reserve(&mut ownership))).unwrap();
        assert!(matches!(
            frozen.receipt.disposition,
            joint_handoff_core::FreezeDisposition::Blocked { .. }
        ));
        assert_eq!(frozen.receipt.counts.committed, 0);
    }
}

#[test]
fn reference_outcome_rejects_binding_identity_and_zero_digest_mutations() {
    let peer = ReferenceEffectPeer::new_admission_required(config()).unwrap();
    let request = admission_effect(50);
    let registration = publication(effect(50, JointEffectClassification::Registered));
    let permit = admitted_permit(&peer, &request, &registration);
    let evidence = *permit.commit_evidence();
    permit.consume(&peer, &request).unwrap().finish(EffectDispatchOutcome::GuestReturned).unwrap();

    let mut mutated_request = request.clone();
    mutated_request.request_digest = digest(99);
    assert_eq!(
        peer.record_effect_outcome(
            &mutated_request,
            &evidence,
            publication(effect(50, JointEffectClassification::Committed)),
        ),
        Err(EffectPeerError::PublicationConflict)
    );
    let mut mutated_identity = publication(effect(50, JointEffectClassification::Committed));
    mutated_identity.record.operation = id(999);
    assert_eq!(
        peer.record_effect_outcome(&request, &evidence, mutated_identity),
        Err(EffectPeerError::PublicationConflict)
    );
    let mut zero_outcome = publication(effect(50, JointEffectClassification::Committed));
    zero_outcome.record.outcome_digest = Some(Digest::ZERO);
    assert_eq!(
        peer.record_effect_outcome(&request, &evidence, zero_outcome),
        Err(EffectPeerError::InvalidRequest)
    );

    let mut ownership = ownership();
    let frozen = peer.freeze(freeze_request(reserve(&mut ownership))).unwrap();
    assert!(matches!(
        frozen.receipt.disposition,
        joint_handoff_core::FreezeDisposition::Blocked { .. }
    ));
}

#[test]
fn freeze_winning_the_gate_rejects_first_publication() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let frozen = peer.freeze(freeze_request(intent)).unwrap();
    assert_eq!(frozen.receipt.counts.registered, 0);
    assert_eq!(
        peer.publish(publication(effect(20, JointEffectClassification::Committed))),
        Err(EffectPeerError::GateClosed)
    );
}

#[test]
fn freeze_rejects_structurally_valid_but_unpinned_ownership_issuer() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let mut intent = reserve(&mut ownership);
    intent.header.issuer = id(900);
    intent.header.issuer_incarnation = id(901);
    intent.header.key_id = id(902);
    intent.header.log_id = id(903);
    intent.ownership_service = id(900);
    intent.service_incarnation = id(901);
    assert_eq!(peer.freeze(freeze_request(intent)), Err(EffectPeerError::InvalidRequest));
}

#[test]
fn freeze_and_first_publication_share_one_linearization_gate() {
    let peer = Arc::new(ReferenceEffectPeer::new(config()).unwrap());
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let barrier = Arc::new(Barrier::new(3));
    let freeze_peer = Arc::clone(&peer);
    let freeze_barrier = Arc::clone(&barrier);
    let freeze_thread = std::thread::spawn(move || {
        freeze_barrier.wait();
        freeze_peer.freeze(freeze_request(intent)).unwrap()
    });
    let publish_peer = Arc::clone(&peer);
    let publish_barrier = Arc::clone(&barrier);
    let publish_thread = std::thread::spawn(move || {
        publish_barrier.wait();
        publish_peer.publish(publication(effect(20, JointEffectClassification::Committed)))
    });
    barrier.wait();
    let frozen = freeze_thread.join().unwrap();
    let published = publish_thread.join().unwrap();
    match published {
        Ok(EffectPublicationResult::Published) => assert_eq!(frozen.receipt.counts.registered, 1),
        Err(EffectPeerError::GateClosed) => assert_eq!(frozen.receipt.counts.registered, 0),
        other => panic!("unexpected publication result: {other:?}"),
    }
}

#[test]
fn unresolved_tombstone_blocks_commit_authorized_close() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    peer.publish(publication(effect(20, JointEffectClassification::UnresolvedTombstone))).unwrap();
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    assert!(matches!(
        frozen.receipt.disposition,
        joint_handoff_core::FreezeDisposition::Blocked { .. }
    ));
    let prepared_ref = reference(ReceiptKind::OwnershipPrepared, 100);
    let commit = joint_handoff_core::OwnershipCommitReceipt {
        header: joint_handoff_core::ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::OwnershipCommit,
            issuer: id(100),
            issuer_incarnation: id(101),
            key_id: id(102),
            log_id: id(103),
            sequence: 3,
            previous_digest: Some(prepared_ref.digest),
        },
        key: key(),
        reservation: intent.reservation,
        prepared: ReceiptRef { sequence: 2, ..prepared_ref },
        prepared_revision: 2,
        decision_sequence: 3,
        non_equivocation_root: digest(90),
    };
    assert_eq!(
        peer.close(EffectCloseRequest {
            token: frozen.token,
            commit,
            expected_closure_revision: 0,
        }),
        Err(EffectPeerError::FreezeBlocked)
    );
}

#[test]
fn thaw_requires_exact_abort_receipt_and_excludes_close() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    let intent_ref = intent.receipt_ref().unwrap();
    let abort = ownership
        .abort(OwnershipAbortRequest {
            key: key(),
            reservation: intent.reservation,
            basis: intent_ref,
            expected_state_sequence: 1,
        })
        .unwrap();
    let mut wrong_kind = abort.clone();
    wrong_kind.header.kind = ReceiptKind::OwnershipCommit;
    assert_eq!(
        peer.thaw(EffectThawRequest { token: frozen.token, abort: wrong_kind }),
        Err(EffectPeerError::InvalidRequest)
    );
    let request = EffectThawRequest { token: frozen.token, abort };
    let thaw = peer.thaw(request.clone()).unwrap();
    assert_eq!(thaw.header.previous_digest, Some(frozen.token.freeze.digest));
    assert_eq!(peer.thaw(request).unwrap(), thaw);
    assert!(peer.query().unwrap().gate_open);

    let mut bad_token = frozen.token;
    bad_token.freeze_generation += 1;
    assert_eq!(
        peer.thaw(EffectThawRequest {
            token: bad_token,
            abort: ownership
                .query(key().handoff)
                .unwrap()
                .and_then(|value| match value {
                    crate::OwnershipQuery::AbortDecided(receipt) => Some(receipt),
                    _ => None,
                })
                .unwrap(),
        }),
        Err(EffectPeerError::TokenMismatch)
    );
}

#[test]
fn authoritative_thaw_commits_only_the_exact_frozen_registered_effect() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let registered = effect(20, JointEffectClassification::Registered);
    assert_eq!(
        peer.publish(publication(registered.clone())).unwrap(),
        EffectPublicationResult::Published
    );
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    assert_eq!(frozen.receipt.counts.registered, 1);
    assert_eq!(frozen.receipt.counts.committed, 0);
    assert!(matches!(
        frozen.receipt.disposition,
        joint_handoff_core::FreezeDisposition::Blocked { .. }
    ));

    let committed = effect(20, JointEffectClassification::Committed);
    assert_eq!(
        peer.publish(publication(committed.clone())),
        Err(EffectPeerError::PublicationConflict)
    );
    let abort = ownership
        .abort(OwnershipAbortRequest {
            key: key(),
            reservation: intent.reservation,
            basis: intent.receipt_ref().unwrap(),
            expected_state_sequence: 1,
        })
        .unwrap();
    peer.thaw(EffectThawRequest { token: frozen.token, abort }).unwrap();

    for mutation in [
        JointEffectRecord { operation: id(90), ..committed.clone() },
        JointEffectRecord { domain: id(91), ..committed.clone() },
    ] {
        assert_eq!(peer.publish(publication(mutation)), Err(EffectPeerError::PublicationConflict));
    }
    let mut stale_binding = publication(committed.clone());
    stale_binding.record.binding_generation = 2;
    assert_eq!(peer.publish(stale_binding), Err(EffectPeerError::InvalidRequest));

    let post_thaw_registered = effect(30, JointEffectClassification::Registered);
    assert_eq!(
        peer.publish(publication(post_thaw_registered)).unwrap(),
        EffectPublicationResult::Published
    );
    assert_eq!(
        peer.publish(publication(effect(30, JointEffectClassification::Committed))),
        Err(EffectPeerError::PublicationConflict),
        "a new post-thaw registration is not part of the frozen recovery cohort"
    );

    assert_eq!(
        peer.publish(publication(committed.clone())).unwrap(),
        EffectPublicationResult::Published
    );
    assert_eq!(peer.publish(publication(committed)).unwrap(), EffectPublicationResult::Replay);
    assert_eq!(peer.query().unwrap().effect_count, 2);
}

#[test]
fn committed_close_keeps_cross_cohort_publication_fenced() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    let commit = seal_and_commit(&mut ownership, &intent, &frozen.receipt);
    let closed = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 0 })
        .unwrap();
    assert!(matches!(closed, EffectCloseResult::Closed(_)));
    assert_eq!(
        peer.publish(publication(effect(20, JointEffectClassification::Committed))),
        Err(EffectPeerError::GateClosed)
    );
}

#[test]
fn close_progress_is_revisioned_idempotent_and_excludes_thaw() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    for value in [20, 30] {
        peer.publish(publication(effect(value, JointEffectClassification::Committed))).unwrap();
    }
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    let commit = seal_and_commit(&mut ownership, &intent, &frozen.receipt);
    let mut wrong_kind = commit.clone();
    wrong_kind.header.kind = ReceiptKind::OwnershipAbort;
    assert_eq!(
        peer.close(EffectCloseRequest {
            token: frozen.token,
            commit: wrong_kind,
            expected_closure_revision: 0,
        }),
        Err(EffectPeerError::InvalidRequest)
    );
    let first_request = EffectCloseRequest {
        token: frozen.token,
        commit: commit.clone(),
        expected_closure_revision: 0,
    };
    let first = peer.close(first_request.clone()).unwrap();
    let EffectCloseResult::Progress(progress) = &first else {
        panic!("two effects must produce a progress receipt")
    };
    assert_eq!(progress.remaining_effects, 1);
    assert_eq!(progress.header.previous_digest, Some(frozen.token.freeze.digest));
    assert_eq!(peer.close(first_request).unwrap(), first);
    assert_eq!(
        peer.close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 9,
        }),
        Err(EffectPeerError::StaleRevision { expected: 9, actual: 1 })
    );
    let terminal = peer
        .close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 1,
        })
        .unwrap();
    let EffectCloseResult::Closed(closed) = terminal else {
        panic!("second close step must finish the cohort")
    };
    assert_eq!(closed.closure_revision, 2);
    assert_eq!(closed.header.previous_digest, Some(progress.receipt_ref().unwrap().digest));
    assert!(matches!(
        peer.close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 2,
        }),
        Err(EffectPeerError::ExistingCommit(_))
    ));
    let intent_ref = intent.receipt_ref().unwrap();
    let abort = joint_handoff_core::OwnershipAbortReceipt {
        header: joint_handoff_core::ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::OwnershipAbort,
            issuer: id(100),
            issuer_incarnation: id(101),
            key_id: id(102),
            log_id: id(103),
            sequence: 4,
            previous_digest: Some(intent_ref.digest),
        },
        key: key(),
        reservation: intent.reservation,
        basis: intent_ref,
        basis_revision: 1,
        decision_sequence: 4,
        non_equivocation_root: digest(91),
    };
    assert!(matches!(
        peer.thaw(EffectThawRequest { token: frozen.token, abort }),
        Err(EffectPeerError::ExistingCommit(_))
    ));
}

#[test]
fn retained_tombstone_requires_fresh_higher_revision_closure() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    peer.publish(publication(effect(20, JointEffectClassification::ResolvedTombstone))).unwrap();
    let frozen = peer.freeze(freeze_request(intent.clone())).unwrap();
    let commit = seal_and_commit(&mut ownership, &intent, &frozen.receipt);
    let result = peer
        .close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 0,
        })
        .unwrap();
    let EffectCloseResult::RetainedTombstone(receipt) = result else {
        panic!("resolved tombstone must remain an explicit cleanup obligation")
    };
    assert_eq!(receipt.tombstone_count, 1);
    let retained_ref = receipt.receipt_ref().unwrap();
    let recovered = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 1 })
        .unwrap();
    let EffectCloseResult::Closed(closure) = recovered else {
        panic!("retained tombstone recovery must advance to closure")
    };
    assert_eq!(closure.closure_revision, 2);
    assert_eq!(closure.header.previous_digest, Some(retained_ref.digest));
}

#[test]
fn rebind_advances_scope_lineage_and_rejects_stale_scope() {
    let peer = ReferenceEffectPeer::new(config()).unwrap();
    let mut ownership = ownership();
    let intent = reserve(&mut ownership);
    let stale = freeze_request(intent.clone());
    let scope = peer.rebind(id(299)).unwrap();
    assert_eq!(scope.scope_generation, 2);
    assert_eq!(scope.freeze_generation, 7);
    assert_eq!(peer.freeze(stale), Err(EffectPeerError::StaleRegistry));
    let mut current = freeze_request(intent);
    current.scope_generation = scope.scope_generation;
    current.freeze_generation = scope.freeze_generation;
    current.registry_instance = scope.registry_instance;
    let frozen = peer.freeze(current).unwrap();
    assert_eq!(frozen.receipt.header.issuer_incarnation, id(201));
    assert_eq!(frozen.receipt.registry_instance, id(299));
    assert_eq!(frozen.receipt.header.sequence, 1);
}
