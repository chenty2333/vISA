use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    FreezeDisposition, JointHandoffKey, OwnershipPreparedReceipt, PrepareIntentReceipt,
    PreparedBindings, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
};
use serde::Serialize;
use visa_conformance::{JointEffectClassification, JointEffectRecord};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectFreezeResult,
    EffectPeerConfig, EffectPeerError, EffectPublicationRequest, EffectPublicationResult,
    EffectThawRequest, OwnershipAbortRequest, OwnershipCommitRequest, OwnershipLogError,
    OwnershipQuery, OwnershipReserveRequest, OwnershipSealRequest, ReferenceCellEvent,
    ReferenceCellTrace, ReferenceEffectPeer, ReferenceOwnershipLog, effect_receipt_issuer,
    ownership_receipt_issuer,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(10_000);

pub(crate) fn run_extra_reference_cases() -> Result<Vec<ReferenceCellTrace>, String> {
    Ok(vec![
        destination_prepare_failure()?,
        stale_scope_epoch_token_probes()?,
        abort_commit_abort_wins()?,
        abort_commit_commit_wins()?,
        source_crash_after_commit()?,
        destination_crash_before_activation()?,
        concurrent_two_destinations()?,
        crash_after_freeze_before_seal()?,
        stale_destination_prepared()?,
        duplicate_and_reordered_requests()?,
        precommit_abort_preserves_uncommitted_effect()?,
        postcommit_retained_tombstone()?,
    ])
}

fn destination_prepare_failure() -> Result<ReferenceCellTrace, String> {
    let (key, mut log, peer, intent, frozen, mut trace) =
        frozen_setup("destination-prepare-fails-abort-thaw", 200)?;
    outcome(&mut trace, "destination-prepare", "failed-before-seal");
    abort_reserved_and_thaw(&mut trace, &mut log, &peer, key, &intent, frozen)?;
    trace.terminal = "source-thawed".to_owned();
    Ok(trace)
}

fn stale_scope_epoch_token_probes() -> Result<ReferenceCellTrace, String> {
    let key = key(230);
    let mut log = memory_log(key)?;
    let config = peer_config(key);
    let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
    let intent = reserve(&mut log, key)?;
    let mut trace = trace("stale-token-scope-epoch-probes", key)?;
    receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;

    let mut stale = freeze_request(key, config, intent.clone());
    stale.registry_instance = id(900);
    expect_error(peer.freeze(stale), EffectPeerError::StaleRegistry)?;
    outcome(&mut trace, "stale-registry-freeze", "rejected-no-effect");
    let mut stale = freeze_request(key, config, intent.clone());
    stale.scope_generation += 1;
    expect_error(peer.freeze(stale), EffectPeerError::StaleScope)?;
    outcome(&mut trace, "stale-scope-freeze", "rejected-no-effect");
    let mut stale = freeze_request(key, config, intent.clone());
    stale.freeze_generation += 1;
    expect_error(peer.freeze(stale), EffectPeerError::StaleFreezeGeneration)?;
    outcome(&mut trace, "stale-freeze-generation", "rejected-no-effect");
    let mut stale_publication = publication(key, config, committed_effect(240, 1));
    stale_publication.source_epoch = LeaseEpoch(6);
    expect_error(peer.publish(stale_publication), EffectPeerError::StaleEpoch)?;
    outcome(&mut trace, "stale-source-epoch", "rejected-no-effect");

    let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
    receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    let intent_ref = intent.receipt_ref().map_err(debug)?;
    let abort = log
        .abort(OwnershipAbortRequest {
            key,
            reservation: intent.reservation,
            basis: intent_ref,
            expected_state_sequence: 1,
        })
        .map_err(debug)?;
    let mut stale_token = frozen.token;
    stale_token.freeze_generation += 1;
    expect_error(
        peer.thaw(EffectThawRequest { token: stale_token, abort: abort.clone() }),
        EffectPeerError::TokenMismatch,
    )?;
    outcome(&mut trace, "stale-thaw-token", "rejected-no-effect");
    let thaw = peer.thaw(EffectThawRequest { token: frozen.token, abort }).map_err(debug)?;
    receipt(&mut trace, "effect-thaw", ReceiptKind::NexusThaw, &thaw)?;
    trace.terminal = "source-thawed".to_owned();
    Ok(trace)
}

fn abort_commit_abort_wins() -> Result<ReferenceCellTrace, String> {
    let (key, mut log, peer, intent, frozen, mut trace) =
        frozen_setup("abort-commit-race-abort-wins", 260)?;
    let prepared = seal(&mut log, key, &intent, &frozen.receipt)?;
    receipt(&mut trace, "ownership-prepared", ReceiptKind::OwnershipPrepared, &prepared)?;
    let prepared_ref = prepared.receipt_ref().map_err(debug)?;
    let abort = log
        .abort(OwnershipAbortRequest {
            key,
            reservation: intent.reservation,
            basis: prepared_ref,
            expected_state_sequence: 2,
        })
        .map_err(debug)?;
    receipt(&mut trace, "ownership-abort-winner", ReceiptKind::OwnershipAbort, &abort)?;
    let losing_commit = log.commit(OwnershipCommitRequest {
        key,
        reservation: intent.reservation,
        prepared: prepared_ref,
        expected_state_sequence: 3,
    });
    if !matches!(losing_commit, Err(OwnershipLogError::ExistingAbort(_))) {
        return Err(format!("commit did not lose immutable race: {losing_commit:?}"));
    }
    outcome(&mut trace, "commit-racer", "existing-abort");
    let thaw = peer.thaw(EffectThawRequest { token: frozen.token, abort }).map_err(debug)?;
    receipt(&mut trace, "effect-thaw", ReceiptKind::NexusThaw, &thaw)?;
    trace.terminal = "abort-terminal".to_owned();
    Ok(trace)
}

fn abort_commit_commit_wins() -> Result<ReferenceCellTrace, String> {
    let (key, mut log, peer, intent, frozen, mut trace) =
        frozen_setup("abort-commit-race-commit-wins", 290)?;
    let prepared = seal(&mut log, key, &intent, &frozen.receipt)?;
    let prepared_ref = prepared.receipt_ref().map_err(debug)?;
    let commit = log
        .commit(OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared_ref,
            expected_state_sequence: 2,
        })
        .map_err(debug)?;
    receipt(&mut trace, "ownership-commit-winner", ReceiptKind::OwnershipCommit, &commit)?;
    let losing_abort = log.abort(OwnershipAbortRequest {
        key,
        reservation: intent.reservation,
        basis: prepared_ref,
        expected_state_sequence: 3,
    });
    if !matches!(losing_abort, Err(OwnershipLogError::ExistingCommit(_))) {
        return Err(format!("abort did not lose immutable race: {losing_abort:?}"));
    }
    outcome(&mut trace, "abort-racer", "existing-commit");
    close_empty(&mut trace, &peer, frozen, commit)?;
    trace.terminal = "commit-terminal-source-closed".to_owned();
    Ok(trace)
}

fn source_crash_after_commit() -> Result<ReferenceCellTrace, String> {
    let key = key(320);
    let path = durable_path("source-crash");
    let result = (|| {
        let mut log = file_log(&path, key)?;
        let config = peer_config(key);
        let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
        let intent = reserve(&mut log, key)?;
        let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
        let prepared = seal(&mut log, key, &intent, &frozen.receipt)?;
        let request = OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        };
        let commit = log.commit(request).map_err(debug)?;
        let mut trace = trace("source-crash-after-commit-before-close", key)?;
        receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
        receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
        receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
        drop(log);
        outcome(&mut trace, "source-process", "crashed-before-close");
        let reopened = ReferenceOwnershipLog::open(&path, ownership_namespace()).map_err(debug)?;
        let Some(OwnershipQuery::CommitDecided(queried)) =
            reopened.query(key.handoff).map_err(debug)?
        else {
            return Err("source restart did not recover commit".to_owned());
        };
        if queried != commit {
            return Err("source restart recovered a different commit".to_owned());
        }
        receipt(&mut trace, "query-after-restart", ReceiptKind::OwnershipCommit, &queried)?;
        close_empty(&mut trace, &peer, frozen, queried)?;
        trace.terminal = "source-closed-after-restart".to_owned();
        Ok(trace)
    })();
    cleanup(&path);
    result
}

fn destination_crash_before_activation() -> Result<ReferenceCellTrace, String> {
    let (key, mut log, peer, intent, frozen, mut trace) =
        frozen_setup("destination-crash-before-activation", 350)?;
    let prepared = seal(&mut log, key, &intent, &frozen.receipt)?;
    let commit = log
        .commit(OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        })
        .map_err(debug)?;
    receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    close_empty(&mut trace, &peer, frozen, commit)?;
    outcome(&mut trace, "destination-process", "restart-remained-inactive-until-closure");
    trace.terminal = "source-closed-destination-prepared".to_owned();
    Ok(trace)
}

fn concurrent_two_destinations() -> Result<ReferenceCellTrace, String> {
    let first_key = key(380);
    let second_key =
        JointHandoffKey { handoff: id(399), destination: NodeIdentity::new(id(400)), ..first_key };
    let path = durable_path("concurrent-destinations");
    let result = (|| {
        file_log(&path, first_key)?;
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |candidate: JointHandoffKey| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut log = ReferenceOwnershipLog::open(path, ownership_namespace())?;
                barrier.wait();
                log.reserve(OwnershipReserveRequest { key: candidate, expected_state_sequence: 0 })
            })
        };
        let first = spawn(first_key);
        let second = spawn(second_key);
        barrier.wait();
        let results = [
            first.join().map_err(|_| "reserve thread panicked".to_owned())?,
            second.join().map_err(|_| "reserve thread panicked".to_owned())?,
        ];
        let winner = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .cloned()
            .ok_or_else(|| "concurrent reserve had no winner".to_owned())?;
        if results.iter().filter(|result| result.is_ok()).count() != 1
            || results
                .iter()
                .filter(|result| matches!(result, Err(OwnershipLogError::Conflict)))
                .count()
                != 1
        {
            return Err(format!("concurrent reserve was not single-winner: {results:?}"));
        }
        let mut trace = trace("concurrent-two-destinations", winner.key)?;
        receipt(&mut trace, "winning-reservation", ReceiptKind::PrepareIntent, &winner)?;
        outcome(&mut trace, "competing-reservation", "conflict-no-second-owner");
        let mut log = ReferenceOwnershipLog::open(&path, ownership_namespace()).map_err(debug)?;
        let config = peer_config(winner.key);
        let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
        let frozen =
            peer.freeze(freeze_request(winner.key, config, winner.clone())).map_err(debug)?;
        receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
        let prepared = seal(&mut log, winner.key, &winner, &frozen.receipt)?;
        let commit = log
            .commit(OwnershipCommitRequest {
                key: winner.key,
                reservation: winner.reservation,
                prepared: prepared.receipt_ref().map_err(debug)?,
                expected_state_sequence: 2,
            })
            .map_err(debug)?;
        receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
        close_empty(&mut trace, &peer, frozen, commit)?;
        trace.terminal = "single-destination-source-closed".to_owned();
        Ok(trace)
    })();
    cleanup(&path);
    result
}

fn crash_after_freeze_before_seal() -> Result<ReferenceCellTrace, String> {
    let key = key(410);
    let path = durable_path("crash-before-seal");
    let result = (|| {
        let mut log = file_log(&path, key)?;
        let config = peer_config(key);
        let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
        let intent = reserve(&mut log, key)?;
        let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
        let mut trace = trace("crash-after-freeze-before-seal", key)?;
        receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
        receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
        drop(log);
        outcome(&mut trace, "coordinator", "crashed-before-seal");
        let mut reopened =
            ReferenceOwnershipLog::open(&path, ownership_namespace()).map_err(debug)?;
        if !matches!(reopened.query(key.handoff).map_err(debug)?, Some(OwnershipQuery::Reserved(_)))
        {
            return Err("crash before seal did not recover reservation".to_owned());
        }
        abort_reserved_and_thaw(&mut trace, &mut reopened, &peer, key, &intent, frozen)?;
        trace.terminal = "source-thawed-after-restart".to_owned();
        Ok(trace)
    })();
    cleanup(&path);
    result
}

fn stale_destination_prepared() -> Result<ReferenceCellTrace, String> {
    let (key, mut log, peer, intent, frozen, mut trace) =
        frozen_setup("stale-destination-prepared-receipt", 440)?;
    let mut request = seal_request(key, &intent, &frozen.receipt)?;
    request.destination_prepared.digest = digest(231);
    if log.seal(request) != Err(OwnershipLogError::InvalidRequest) {
        return Err("substituted destination receipt was not rejected".to_owned());
    }
    outcome(&mut trace, "substituted-destination-prepared", "rejected-no-seal");
    abort_reserved_and_thaw(&mut trace, &mut log, &peer, key, &intent, frozen)?;
    trace.terminal = "source-thawed-no-seal".to_owned();
    Ok(trace)
}

fn duplicate_and_reordered_requests() -> Result<ReferenceCellTrace, String> {
    let key = key(470);
    let mut log = memory_log(key)?;
    let config = peer_config(key);
    let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
    let intent = reserve(&mut log, key)?;
    let request = freeze_request(key, config, intent.clone());
    let first = peer.freeze(request.clone()).map_err(debug)?;
    let duplicate = peer.freeze(request).map_err(debug)?;
    if first != duplicate {
        return Err("duplicate freeze did not replay exact receipt/token".to_owned());
    }
    let mut trace = trace("duplicate-reordered-receipts", key)?;
    receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &first.receipt)?;
    receipt(&mut trace, "effect-freeze-duplicate", ReceiptKind::NexusFreeze, &duplicate.receipt)?;
    let mut reordered = seal_request(key, &intent, &first.receipt)?;
    reordered.expected_state_sequence = 0;
    if log.seal(reordered) != Err(OwnershipLogError::StaleSequence { expected: 0, actual: 1 }) {
        return Err("reordered seal was not rejected at stale sequence".to_owned());
    }
    outcome(&mut trace, "reordered-seal", "stale-sequence-no-effect");
    let prepared = seal(&mut log, key, &intent, &first.receipt)?;
    let commit = log
        .commit(OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        })
        .map_err(debug)?;
    receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    close_empty(&mut trace, &peer, first, commit)?;
    trace.terminal = "duplicate-idempotent-source-closed".to_owned();
    Ok(trace)
}

fn precommit_abort_preserves_uncommitted_effect() -> Result<ReferenceCellTrace, String> {
    let key = key(500);
    let mut log = memory_log(key)?;
    let config = peer_config(key);
    let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
    let registered = registered_effect(510, config.scope_generation);
    expect_published(peer.publish(publication(key, config, registered.clone())).map_err(debug)?)?;

    let mut trace = trace("precommit-abort-preserves-uncommitted-effect", key)?;
    effect_event(&mut trace, "registered-effect-before-freeze", "published", &registered);
    let intent = reserve(&mut log, key)?;
    receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
    if frozen.receipt.counts.registered != 1
        || frozen.receipt.counts.committed != 0
        || !matches!(frozen.receipt.disposition, FreezeDisposition::Blocked { .. })
    {
        return Err(
            "registered source-local effect was not retained as the freeze blocker".to_owned()
        );
    }
    receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    outcome(&mut trace, "destination-prepare", "failed-before-seal");
    abort_reserved_and_thaw(&mut trace, &mut log, &peer, key, &intent, frozen)?;

    let committed = committed_effect(510, config.scope_generation);
    expect_published(peer.publish(publication(key, config, committed.clone())).map_err(debug)?)?;
    if peer.publish(publication(key, config, committed.clone())).map_err(debug)?
        != EffectPublicationResult::Replay
    {
        return Err(
            "completed registered-effect retry did not replay exact committed identity".to_owned()
        );
    }
    let query = peer.query().map_err(debug)?;
    if !query.gate_open || query.effect_count != 1 {
        return Err("authoritative thaw did not resume exactly one frozen effect".to_owned());
    }
    effect_event(&mut trace, "registered-effect-committed-after-thaw", "published", &committed);
    trace.terminal = "source-thawed-registered-effect-committed".to_owned();
    Ok(trace)
}

fn postcommit_retained_tombstone() -> Result<ReferenceCellTrace, String> {
    let key = key(540);
    let mut log = memory_log(key)?;
    let config = peer_config(key);
    let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
    let intent = reserve(&mut log, key)?;
    expect_published(
        peer.publish(publication(key, config, resolved_tombstone(550, 1))).map_err(debug)?,
    )?;
    let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
    let prepared = seal(&mut log, key, &intent, &frozen.receipt)?;
    let commit = log
        .commit(OwnershipCommitRequest {
            key,
            reservation: intent.reservation,
            prepared: prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        })
        .map_err(debug)?;
    let mut trace = trace("supplemental-postcommit-retained-tombstone", key)?;
    receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    let result = peer
        .close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 0,
        })
        .map_err(debug)?;
    let EffectCloseResult::RetainedTombstone(retained) = result else {
        return Err("postcommit tombstone did not produce retained terminal".to_owned());
    };
    receipt(&mut trace, "retained-tombstone", ReceiptKind::RetainedTombstone, &retained)?;
    outcome(&mut trace, "destination-activation", "blocked-recovery-required");
    let retained_ref = retained.receipt_ref().map_err(debug)?;
    let recovered = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 1 })
        .map_err(debug)?;
    let EffectCloseResult::Closed(closure) = recovered else {
        return Err("retained cleanup did not advance to fresh closure".to_owned());
    };
    if closure.header.previous_digest != Some(retained_ref.digest) {
        return Err("recovery closure did not descend from retained receipt".to_owned());
    }
    receipt(&mut trace, "recovery-closure", ReceiptKind::Closure, &closure)?;
    trace.terminal = "source-closed-after-tombstone-recovery".to_owned();
    Ok(trace)
}

fn frozen_setup(
    case_id: &str,
    seed: u128,
) -> Result<
    (
        JointHandoffKey,
        ReferenceOwnershipLog,
        ReferenceEffectPeer,
        PrepareIntentReceipt,
        EffectFreezeResult,
        ReferenceCellTrace,
    ),
    String,
> {
    let key = key(seed);
    let mut log = memory_log(key)?;
    let config = peer_config(key);
    let peer = ReferenceEffectPeer::new(config).map_err(debug)?;
    let intent = reserve(&mut log, key)?;
    let frozen = peer.freeze(freeze_request(key, config, intent.clone())).map_err(debug)?;
    let mut trace = trace(case_id, key)?;
    receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    Ok((key, log, peer, intent, frozen, trace))
}

fn abort_reserved_and_thaw(
    trace: &mut ReferenceCellTrace,
    log: &mut ReferenceOwnershipLog,
    peer: &ReferenceEffectPeer,
    key: JointHandoffKey,
    intent: &PrepareIntentReceipt,
    frozen: EffectFreezeResult,
) -> Result<(), String> {
    let abort = log
        .abort(OwnershipAbortRequest {
            key,
            reservation: intent.reservation,
            basis: intent.receipt_ref().map_err(debug)?,
            expected_state_sequence: 1,
        })
        .map_err(debug)?;
    receipt(trace, "ownership-abort", ReceiptKind::OwnershipAbort, &abort)?;
    let thaw = peer.thaw(EffectThawRequest { token: frozen.token, abort }).map_err(debug)?;
    receipt(trace, "effect-thaw", ReceiptKind::NexusThaw, &thaw)
}

fn close_empty(
    trace: &mut ReferenceCellTrace,
    peer: &ReferenceEffectPeer,
    frozen: EffectFreezeResult,
    commit: joint_handoff_core::OwnershipCommitReceipt,
) -> Result<(), String> {
    let result = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 0 })
        .map_err(debug)?;
    let EffectCloseResult::Closed(closure) = result else {
        return Err("empty cohort did not close in one step".to_owned());
    };
    receipt(trace, "effect-closure", ReceiptKind::Closure, &closure)
}

fn seal(
    log: &mut ReferenceOwnershipLog,
    key: JointHandoffKey,
    intent: &PrepareIntentReceipt,
    freeze: &joint_handoff_core::NexusFreezeReceipt,
) -> Result<OwnershipPreparedReceipt, String> {
    log.seal(seal_request(key, intent, freeze)?).map_err(debug)
}

fn seal_request(
    key: JointHandoffKey,
    intent: &PrepareIntentReceipt,
    freeze: &joint_handoff_core::NexusFreezeReceipt,
) -> Result<OwnershipSealRequest, String> {
    let intent_ref = intent.receipt_ref().map_err(debug)?;
    let effect_ref = freeze.receipt_ref().map_err(debug)?;
    let visa = external_ref(key, ReceiptKind::VisaFreeze, 60);
    let destination = external_ref(key, ReceiptKind::DestinationPrepared, 80);
    Ok(OwnershipSealRequest {
        key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa,
        effect_freeze: effect_ref,
        destination_prepared: destination,
        bindings: bindings(intent_ref, visa, effect_ref, destination, freeze.effect_cohort_digest),
        expected_state_sequence: 1,
    })
}

fn memory_log(key: JointHandoffKey) -> Result<ReferenceOwnershipLog, String> {
    let mut log = ReferenceOwnershipLog::open(":memory:", ownership_namespace()).map_err(debug)?;
    log.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).map_err(debug)?;
    Ok(log)
}

fn file_log(path: &PathBuf, key: JointHandoffKey) -> Result<ReferenceOwnershipLog, String> {
    let mut log = ReferenceOwnershipLog::open(path, ownership_namespace()).map_err(debug)?;
    log.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).map_err(debug)?;
    Ok(log)
}

fn reserve(
    log: &mut ReferenceOwnershipLog,
    key: JointHandoffKey,
) -> Result<PrepareIntentReceipt, String> {
    log.reserve(OwnershipReserveRequest { key, expected_state_sequence: 0 }).map_err(debug)
}

fn freeze_request(
    key: JointHandoffKey,
    config: EffectPeerConfig,
    intent: PrepareIntentReceipt,
) -> EffectFreezeRequest {
    EffectFreezeRequest {
        key,
        intent,
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        authority_epoch: config.authority_epoch,
        freeze_generation: config.freeze_generation,
    }
}

fn publication(
    key: JointHandoffKey,
    config: EffectPeerConfig,
    record: JointEffectRecord,
) -> EffectPublicationRequest {
    EffectPublicationRequest {
        key,
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        source_epoch: key.expected_epoch,
        record,
    }
}

fn committed_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: id(value),
        operation: id(value + 1),
        domain: id(value + 2),
        binding_generation,
        classification: JointEffectClassification::Committed,
        outcome_digest: Some(digest(value as u8)),
        tombstone_digest: None,
    }
}

fn registered_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: id(value),
        operation: id(value + 1),
        domain: id(value + 2),
        binding_generation,
        classification: JointEffectClassification::Registered,
        outcome_digest: None,
        tombstone_digest: None,
    }
}

fn resolved_tombstone(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: id(value),
        operation: id(value + 1),
        domain: id(value + 2),
        binding_generation,
        classification: JointEffectClassification::ResolvedTombstone,
        outcome_digest: Some(digest(value as u8)),
        tombstone_digest: Some(digest(241)),
    }
}

fn expect_published(result: EffectPublicationResult) -> Result<(), String> {
    if result == EffectPublicationResult::Published {
        Ok(())
    } else {
        Err("first publication unexpectedly replayed".to_owned())
    }
}

fn expect_error<T>(
    result: Result<T, EffectPeerError>,
    expected: EffectPeerError,
) -> Result<(), String> {
    match result {
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => {
            Err(format!("wrong effect rejection: expected {expected:?}, got {actual:?}"))
        }
        Ok(_) => Err(format!("effect request unexpectedly succeeded; expected {expected:?}")),
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
        snapshot: id(700),
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

fn key(seed: u128) -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: EntityRef::initial(id(seed + 1)),
        handoff: id(seed + 2),
        source: NodeIdentity::new(id(seed + 3)),
        destination: NodeIdentity::new(id(seed + 4)),
        expected_epoch: LeaseEpoch(7),
        next_epoch: LeaseEpoch(8),
    }
}

fn peer_config(key: JointHandoffKey) -> EffectPeerConfig {
    EffectPeerConfig {
        key,
        issuer: effect_receipt_issuer(effect_namespace(), key).expect("valid effect issuer"),
        ownership_issuer: ownership_receipt_issuer(ownership_namespace(), key)
            .expect("valid ownership issuer"),
        registry_instance: id(710),
        scope_id: id(711),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
        domain_bindings_digest: digest(4),
    }
}

fn ownership_namespace() -> ReceiptIssuerIdentity {
    issuer(600)
}

fn effect_namespace() -> ReceiptIssuerIdentity {
    issuer(650)
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
    }
}

fn external_ref(key: JointHandoffKey, kind: ReceiptKind, base: u128) -> ReceiptRef {
    ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: key.handoff,
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
        sequence: 1,
        digest: digest(base as u8),
    }
}

fn trace(case_id: &str, key: JointHandoffKey) -> Result<ReferenceCellTrace, String> {
    Ok(ReferenceCellTrace {
        case_id: case_id.to_owned(),
        handoff: key.handoff,
        ownership_log_id: ownership_receipt_issuer(ownership_namespace(), key)
            .map_err(debug)?
            .log_id,
        effect_log_id: effect_receipt_issuer(effect_namespace(), key).map_err(debug)?.log_id,
        events: Vec::new(),
        terminal: "incomplete".to_owned(),
    })
}

fn receipt(
    trace: &mut ReferenceCellTrace,
    step: &str,
    kind: ReceiptKind,
    value: &impl Serialize,
) -> Result<(), String> {
    trace.events.push(ReferenceCellEvent {
        step: step.to_owned(),
        outcome: "accepted".to_owned(),
        receipt_kind: Some(format!("{kind:?}")),
        receipt: Some(serde_json::to_value(value).map_err(|error| error.to_string())?),
        effect_record: None,
    });
    Ok(())
}

fn outcome(trace: &mut ReferenceCellTrace, step: &str, value: &str) {
    trace.events.push(ReferenceCellEvent {
        step: step.to_owned(),
        outcome: value.to_owned(),
        receipt_kind: None,
        receipt: None,
        effect_record: None,
    });
}

fn effect_event(
    trace: &mut ReferenceCellTrace,
    step: &str,
    outcome: &str,
    record: &JointEffectRecord,
) {
    trace.events.push(ReferenceCellEvent {
        step: step.to_owned(),
        outcome: outcome.to_owned(),
        receipt_kind: None,
        receipt: None,
        effect_record: Some(record.clone()),
    });
}

fn durable_path(label: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir()
        .join(format!("visa-joint-reference-extra-{label}-{}-{sequence}", std::process::id()));
    fs::create_dir_all(&root).expect("reference scenario temp directory");
    root.join("ownership.sqlite")
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path.parent().unwrap_or(path));
}

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
