use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    JointHandoffKey, PreparedBindings, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
};

use crate::{
    OwnershipAbortRequest, OwnershipCommitRequest, OwnershipLogError, OwnershipQuery,
    OwnershipReserveRequest, OwnershipSealRequest, ReferenceOwnershipLog,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

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

fn key(handoff: u128, destination: u128) -> JointHandoffKey {
    key_at(handoff, 3, destination, 7)
}

fn key_at(handoff: u128, source: u128, destination: u128, epoch: u64) -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: EntityRef::initial(id(1)),
        handoff: id(handoff),
        source: NodeIdentity::new(id(source)),
        destination: NodeIdentity::new(id(destination)),
        expected_epoch: LeaseEpoch(epoch),
        next_epoch: LeaseEpoch(epoch + 1),
    }
}

fn reference(kind: ReceiptKind, key: JointHandoffKey, base: u128) -> ReceiptRef {
    ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: key.handoff,
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
        effect_cohort_manifest_digest: digest(49),
        joint_mapping_manifest_digest: digest(50),
    }
}

fn db_path(label: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir()
        .join(format!("visa-joint-ownership-{label}-{}-{sequence}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root.join("ownership.sqlite")
}

fn reserve(
    log: &mut ReferenceOwnershipLog,
    key: JointHandoffKey,
) -> joint_handoff_core::PrepareIntentReceipt {
    log.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).unwrap();
    log.reserve(OwnershipReserveRequest { key, expected_state_sequence: 0 }).unwrap()
}

fn seal_request(
    key: JointHandoffKey,
    intent: &joint_handoff_core::PrepareIntentReceipt,
) -> OwnershipSealRequest {
    let intent_ref = intent.receipt_ref().unwrap();
    let visa = reference(ReceiptKind::VisaFreeze, key, 60);
    let effect = reference(ReceiptKind::NexusFreeze, key, 70);
    let destination = reference(ReceiptKind::DestinationPrepared, key, 80);
    OwnershipSealRequest {
        key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa,
        effect_freeze: effect,
        destination_prepared: destination,
        bindings: bindings(intent_ref, visa, effect, destination),
        expected_state_sequence: 1,
    }
}

#[test]
fn file_log_uses_wal_and_full_synchronous_durability() {
    let path = db_path("durability");
    let log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    assert_eq!(log.durability_settings().unwrap(), ("wal".to_owned(), 2));
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn reserve_is_exactly_idempotent_and_conflicts_on_changed_request() {
    let path = db_path("reserve-idempotency");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    let original_key = key(2, 4);
    log.initialize_unit(
        original_key.continuity_unit,
        original_key.source,
        original_key.expected_epoch,
    )
    .unwrap();
    let request = OwnershipReserveRequest { key: original_key, expected_state_sequence: 0 };
    let first = log.reserve(request).unwrap();
    assert_eq!(log.reserve(request).unwrap(), first);

    let changed = OwnershipReserveRequest { key: key(2, 5), expected_state_sequence: 0 };
    assert_eq!(log.reserve(changed), Err(OwnershipLogError::Conflict));
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn one_epoch_cannot_be_reserved_for_two_destinations() {
    let path = db_path("epoch-conflict");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    reserve(&mut log, key(2, 4));
    assert_eq!(
        log.reserve(OwnershipReserveRequest { key: key(9, 5), expected_state_sequence: 0 }),
        Err(OwnershipLogError::Conflict)
    );
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn seal_is_idempotent_and_rejects_stale_sequence_or_changed_step() {
    let path = db_path("seal");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    let key = key(2, 4);
    let intent = reserve(&mut log, key);
    let request = seal_request(key, &intent);
    let mut stale = request;
    stale.expected_state_sequence = 0;
    assert_eq!(log.seal(stale), Err(OwnershipLogError::StaleSequence { expected: 0, actual: 1 }));
    let first = log.seal(request).unwrap();
    assert_eq!(log.seal(request).unwrap(), first);
    let mut changed = request;
    changed.bindings.profile_digest = digest(99);
    assert_eq!(log.seal(changed), Err(OwnershipLogError::Conflict));
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn commit_ack_loss_recovers_exact_terminal_receipt_after_reopen() {
    let path = db_path("commit-reopen");
    let ownership_issuer = issuer(100);
    let key = key(2, 4);
    let request = {
        let mut log = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
        let intent = reserve(&mut log, key);
        let prepared = log.seal(seal_request(key, &intent)).unwrap();
        let request = OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().unwrap(),
            expected_state_sequence: 2,
        };
        log.arm_next_commit_ack_loss().unwrap();
        assert_eq!(log.commit(request), Err(OwnershipLogError::AcknowledgementLost));
        request
    };

    let mut reopened = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
    let Some(OwnershipQuery::CommitDecided(committed)) = reopened.query(key.handoff).unwrap()
    else {
        panic!("durable commit disappeared after acknowledgement loss");
    };
    assert_eq!(reopened.commit(request).unwrap(), committed);
    drop(reopened);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn terminal_commit_rejects_abort_and_survives_reopen() {
    let path = db_path("commit-terminal");
    let ownership_issuer = issuer(100);
    let key = key(2, 4);
    let committed = {
        let mut log = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
        let intent = reserve(&mut log, key);
        let prepared = log.seal(seal_request(key, &intent)).unwrap();
        let committed = log
            .commit(OwnershipCommitRequest {
                key,
                reservation: intent.reservation,
                prepared: prepared.receipt_ref().unwrap(),
                expected_state_sequence: 2,
            })
            .unwrap();
        assert_eq!(
            log.abort(OwnershipAbortRequest {
                key,
                reservation: intent.reservation,
                basis: prepared.receipt_ref().unwrap(),
                expected_state_sequence: 3,
            }),
            Err(OwnershipLogError::ExistingCommit(Box::new(committed.clone())))
        );
        committed
    };
    let reopened = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
    assert_eq!(
        reopened.query(key.handoff).unwrap(),
        Some(OwnershipQuery::CommitDecided(committed))
    );
    drop(reopened);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn terminal_abort_rejects_commit_and_can_start_from_reserved() {
    let path = db_path("abort-reserved");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    let key = key(2, 4);
    let intent = reserve(&mut log, key);
    let intent_ref = intent.receipt_ref().unwrap();
    let aborted = log
        .abort(OwnershipAbortRequest {
            key,
            reservation: intent.reservation,
            basis: intent_ref,
            expected_state_sequence: 1,
        })
        .unwrap();
    assert_eq!(
        log.commit(OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: reference(ReceiptKind::OwnershipPrepared, key, 100),
            expected_state_sequence: 2,
        }),
        Err(OwnershipLogError::ExistingAbort(Box::new(aborted.clone())))
    );
    assert_eq!(log.query(key.handoff).unwrap(), Some(OwnershipQuery::AbortDecided(aborted)));
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn abort_from_prepared_is_exactly_idempotent_and_durable() {
    let path = db_path("abort-prepared");
    let ownership_issuer = issuer(100);
    let key = key(2, 4);
    let (request, aborted) = {
        let mut log = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
        let intent = reserve(&mut log, key);
        let prepared = log.seal(seal_request(key, &intent)).unwrap();
        let request = OwnershipAbortRequest {
            key,
            reservation: intent.reservation,
            basis: prepared.receipt_ref().unwrap(),
            expected_state_sequence: 2,
        };
        let aborted = log.abort(request).unwrap();
        assert_eq!(log.abort(request).unwrap(), aborted);
        (request, aborted)
    };
    let mut reopened = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
    assert_eq!(reopened.abort(request).unwrap(), aborted);
    drop(reopened);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn abort_releases_epoch_for_new_handoff_and_preserves_both_histories() {
    let path = db_path("abort-new-handoff");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    let first_key = key(2, 4);
    let first = reserve(&mut log, first_key);
    let first_ref = first.receipt_ref().unwrap();
    let abort = log
        .abort(OwnershipAbortRequest {
            key: first_key,
            reservation: first.reservation,
            basis: first_ref,
            expected_state_sequence: 1,
        })
        .unwrap();

    let second_key = key(9, 5);
    let second = log
        .reserve(OwnershipReserveRequest { key: second_key, expected_state_sequence: 0 })
        .unwrap();
    assert_ne!(first.header.log_id, second.header.log_id);
    assert_eq!(log.query(first_key.handoff).unwrap(), Some(OwnershipQuery::AbortDecided(abort)));
    assert_eq!(
        log.query(second_key.handoff).unwrap(),
        Some(OwnershipQuery::Reserved(second.clone()))
    );
    let unit = log.query_unit(first_key.continuity_unit).unwrap().unwrap();
    assert_eq!(unit.owner, first_key.source);
    assert_eq!(unit.epoch, first_key.expected_epoch);
    assert_eq!(unit.active_handoff, Some(second_key.handoff));
    assert_eq!(unit.active_reservation, Some(second.reservation));
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn commit_advances_authoritative_owner_and_rejects_stale_epoch() {
    let path = db_path("commit-owner-cas");
    let mut log = ReferenceOwnershipLog::open(&path, issuer(100)).unwrap();
    let first_key = key(2, 4);
    let intent = reserve(&mut log, first_key);
    let prepared = log.seal(seal_request(first_key, &intent)).unwrap();
    log.commit(OwnershipCommitRequest {
        key: first_key,
        reservation: intent.reservation,
        prepared: prepared.receipt_ref().unwrap(),
        expected_state_sequence: 2,
    })
    .unwrap();

    let unit = log.query_unit(first_key.continuity_unit).unwrap().unwrap();
    assert_eq!(unit.owner, first_key.destination);
    assert_eq!(unit.epoch, first_key.next_epoch);
    assert_eq!(unit.active_handoff, None);
    assert_eq!(unit.active_reservation, None);
    assert_eq!(
        log.reserve(OwnershipReserveRequest { key: key(9, 5), expected_state_sequence: 0 }),
        Err(OwnershipLogError::OwnershipMismatch {
            owner: first_key.destination,
            epoch: first_key.next_epoch,
        })
    );

    let next_key = key_at(10, 4, 5, 8);
    assert!(
        log.reserve(OwnershipReserveRequest { key: next_key, expected_state_sequence: 0 }).is_ok()
    );
    drop(log);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn concurrent_reservations_have_one_linearized_winner() {
    let path = db_path("concurrent-reserve");
    let ownership_issuer = issuer(100);
    let initial = key(2, 4);
    {
        let mut log = ReferenceOwnershipLog::open(&path, ownership_issuer).unwrap();
        log.initialize_unit(initial.continuity_unit, initial.source, initial.expected_epoch)
            .unwrap();
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let spawn = |candidate: JointHandoffKey| {
        let path = path.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut log = ReferenceOwnershipLog::open(path, ownership_issuer).unwrap();
            barrier.wait();
            log.reserve(OwnershipReserveRequest { key: candidate, expected_state_sequence: 0 })
        })
    };
    let first = spawn(key(2, 4));
    let second = spawn(key(9, 5));
    barrier.wait();
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| matches!(result, Err(OwnershipLogError::Conflict))).count(),
        1
    );
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
