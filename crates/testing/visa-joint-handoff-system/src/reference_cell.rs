use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    FreezeDisposition, JointHandoffKey, OwnershipCommitReceipt, PrepareIntentReceipt,
    PreparedBindings, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
};
use serde::{Deserialize, Serialize};
use visa_conformance::{JointEffectClassification, JointEffectRecord};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectPeerConfig, EffectPeerError,
    EffectPublicationRequest, EffectPublicationResult, OwnershipCommitRequest, OwnershipQuery,
    OwnershipReserveRequest, OwnershipSealRequest, ReferenceEffectPeer, ReferenceOwnershipLog,
    effect_receipt_issuer, ownership_receipt_issuer,
};

const REFERENCE_CELL_SCHEMA: &str = "visa-joint-reference-peer-cell-v1";
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceCellReport {
    pub schema_version: String,
    pub fixed_case_count: usize,
    pub scenario_count: usize,
    pub all_passed: bool,
    pub ownership_effect_peers_observed: bool,
    pub runtime_projection_observed: bool,
    pub visa_reference_mode: String,
    pub traces: Vec<ReferenceCellTrace>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceCellTrace {
    pub case_id: String,
    pub handoff: Identity,
    pub ownership_log_id: Identity,
    pub effect_log_id: Identity,
    pub events: Vec<ReferenceCellEvent>,
    pub terminal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceCellEvent {
    pub step: String,
    pub outcome: String,
    pub receipt_kind: Option<String>,
    pub receipt: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_record: Option<JointEffectRecord>,
}

pub fn run_reference_peer_cell() -> Result<ReferenceCellReport, String> {
    let mut traces = vec![
        publication_wins_then_revisioned_close()?,
        freeze_wins_then_abort_thaw()?,
        commit_ack_loss_reopen_query_close()?,
        service_binding_rebind_rejects_stale_publication()?,
        unresolved_tombstone_blocks_commit()?,
    ];
    traces.extend(crate::reference_cell_extra::run_extra_reference_cases()?);
    validate_trace_log_isolation(&traces)?;
    validate_fixed_case_coverage(&traces)?;
    Ok(ReferenceCellReport {
        schema_version: REFERENCE_CELL_SCHEMA.to_owned(),
        fixed_case_count: visa_conformance::JOINT_HANDOFF_CASE_COUNT,
        scenario_count: traces.len(),
        all_passed: true,
        ownership_effect_peers_observed: true,
        runtime_projection_observed: false,
        visa_reference_mode: "synthetic-visa-freeze-and-destination-prepared-references".to_owned(),
        traces,
    })
}

fn publication_wins_then_revisioned_close() -> Result<ReferenceCellTrace, String> {
    let key = key(10);
    let mut log = memory_log(key)?;
    let peer = ReferenceEffectPeer::new(peer_config(key)).map_err(debug)?;
    let mut trace = trace("effect-commit-wins-freeze", key)?;
    let intent = reserve(&mut log, key)?;
    push_receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    for value in [20, 30] {
        expect_publication(
            peer.publish(publication(key, peer_config(key), committed_effect(value, 1)))
                .map_err(debug)?,
        )?;
        push_outcome(&mut trace, "effect-publication", "published");
    }
    let frozen =
        peer.freeze(freeze_request(key, peer_config(key), intent.clone())).map_err(debug)?;
    push_receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    let (commit_request, commit) = seal_commit(&mut log, key, &intent, &frozen.receipt)?;
    push_receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    let first = peer
        .close(EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: 0,
        })
        .map_err(debug)?;
    let EffectCloseResult::Progress(progress) = first else {
        return Err("reference close did not emit progress for two effects".to_owned());
    };
    push_receipt(&mut trace, "closure-progress", ReceiptKind::ClosureProgress, &progress)?;
    let terminal = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 1 })
        .map_err(debug)?;
    let EffectCloseResult::Closed(closure) = terminal else {
        return Err("reference close did not produce terminal closure".to_owned());
    };
    push_receipt(&mut trace, "effect-closure", ReceiptKind::Closure, &closure)?;
    if log.commit(commit_request).map_err(debug)? != closure_commit(&closure, &log, key)? {
        return Err("ownership commit retry did not return exact receipt".to_owned());
    }
    trace.terminal = "source-closed".to_owned();
    Ok(trace)
}

fn freeze_wins_then_abort_thaw() -> Result<ReferenceCellTrace, String> {
    let key = key(40);
    let mut log = memory_log(key)?;
    let peer = ReferenceEffectPeer::new(peer_config(key)).map_err(debug)?;
    let mut trace = trace("freeze-wins-effect-commit", key)?;
    let intent = reserve(&mut log, key)?;
    push_receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    let frozen =
        peer.freeze(freeze_request(key, peer_config(key), intent.clone())).map_err(debug)?;
    push_receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    let publication = peer.publish(publication(key, peer_config(key), committed_effect(50, 1)));
    if publication != Err(EffectPeerError::GateClosed) {
        return Err(format!("post-freeze publication was not rejected: {publication:?}"));
    }
    push_outcome(&mut trace, "effect-publication", "gate-closed");
    let (_, commit) = seal_commit(&mut log, key, &intent, &frozen.receipt)?;
    push_receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    let closed = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 0 })
        .map_err(debug)?;
    let EffectCloseResult::Closed(closure) = closed else {
        return Err("freeze-winning empty cohort did not close".to_owned());
    };
    push_receipt(&mut trace, "effect-closure", ReceiptKind::Closure, &closure)?;
    trace.terminal = "source-closed".to_owned();
    Ok(trace)
}

fn commit_ack_loss_reopen_query_close() -> Result<ReferenceCellTrace, String> {
    let key = key(70);
    let path = durable_path();
    let result = (|| {
        let mut log = ReferenceOwnershipLog::open(&path, ownership_issuer()).map_err(debug)?;
        log.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).map_err(debug)?;
        let peer = ReferenceEffectPeer::new(peer_config(key)).map_err(debug)?;
        let mut trace = trace("commit-ack-lost-query-close", key)?;
        let intent = reserve(&mut log, key)?;
        push_receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
        let frozen =
            peer.freeze(freeze_request(key, peer_config(key), intent.clone())).map_err(debug)?;
        push_receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
        let (commit_request, committed) = seal_commit(&mut log, key, &intent, &frozen.receipt)?;
        push_receipt(
            &mut trace,
            "ownership-commit-ack-lost",
            ReceiptKind::OwnershipCommit,
            &committed,
        )?;
        drop(log);
        let mut reopened = ReferenceOwnershipLog::open(&path, ownership_issuer()).map_err(debug)?;
        let Some(OwnershipQuery::CommitDecided(queried)) =
            reopened.query(key.handoff).map_err(debug)?
        else {
            return Err("reopened ownership log did not return commit".to_owned());
        };
        if queried != committed || reopened.commit(commit_request).map_err(debug)? != committed {
            return Err("lost-ack query/retry changed terminal commit receipt".to_owned());
        }
        push_receipt(
            &mut trace,
            "ownership-query-after-reopen",
            ReceiptKind::OwnershipCommit,
            &queried,
        )?;
        let closed = peer
            .close(EffectCloseRequest {
                token: frozen.token,
                commit: queried,
                expected_closure_revision: 0,
            })
            .map_err(debug)?;
        let EffectCloseResult::Closed(closure) = closed else {
            return Err("empty frozen cohort did not close in one step".to_owned());
        };
        push_receipt(&mut trace, "effect-closure", ReceiptKind::Closure, &closure)?;
        trace.terminal = "source-closed-after-recovery".to_owned();
        Ok(trace)
    })();
    let _ = fs::remove_dir_all(path.parent().unwrap_or(path.as_path()));
    result
}

fn service_binding_rebind_rejects_stale_publication() -> Result<ReferenceCellTrace, String> {
    let key = key(100);
    let mut log = memory_log(key)?;
    let peer = ReferenceEffectPeer::new(peer_config(key)).map_err(debug)?;
    let mut trace = trace("frozen-service-crash-rebind", key)?;
    let intent = reserve(&mut log, key)?;
    push_receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    let old_config = peer_config(key);
    let scope = peer.rebind(id(230)).map_err(debug)?;
    let stale = peer.publish(publication(key, old_config, committed_effect(110, 1)));
    if stale != Err(EffectPeerError::StaleRegistry) {
        return Err(format!("stale binding publication was not rejected: {stale:?}"));
    }
    push_outcome(&mut trace, "stale-binding-publication", "stale-registry");
    let current = EffectPeerConfig {
        registry_instance: scope.registry_instance,
        scope_generation: scope.scope_generation,
        freeze_generation: scope.freeze_generation,
        ..old_config
    };
    expect_publication(
        peer.publish(publication(key, current, committed_effect(120, scope.scope_generation)))
            .map_err(debug)?,
    )?;
    push_outcome(&mut trace, "current-binding-publication", "published");
    let frozen = peer.freeze(freeze_request(key, current, intent.clone())).map_err(debug)?;
    if frozen.receipt.header.issuer_incarnation != old_config.issuer.issuer_incarnation {
        return Err("service rebind changed pinned receipt authority".to_owned());
    }
    push_receipt(&mut trace, "effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    let (_, commit) = seal_commit(&mut log, key, &intent, &frozen.receipt)?;
    push_receipt(&mut trace, "ownership-commit", ReceiptKind::OwnershipCommit, &commit)?;
    let closed = peer
        .close(EffectCloseRequest { token: frozen.token, commit, expected_closure_revision: 0 })
        .map_err(debug)?;
    let EffectCloseResult::Closed(closure) = closed else {
        return Err("rebound cohort did not close".to_owned());
    };
    push_receipt(&mut trace, "effect-closure", ReceiptKind::Closure, &closure)?;
    trace.terminal = "source-closed-after-rebind".to_owned();
    Ok(trace)
}

fn unresolved_tombstone_blocks_commit() -> Result<ReferenceCellTrace, String> {
    let key = key(130);
    let mut log = memory_log(key)?;
    let peer = ReferenceEffectPeer::new(peer_config(key)).map_err(debug)?;
    let mut trace = trace("unresolved-tombstone-blocks-seal", key)?;
    let intent = reserve(&mut log, key)?;
    push_receipt(&mut trace, "reserve", ReceiptKind::PrepareIntent, &intent)?;
    expect_publication(
        peer.publish(publication(key, peer_config(key), unresolved_effect(140, 1)))
            .map_err(debug)?,
    )?;
    push_outcome(&mut trace, "unresolved-effect-publication", "published");
    let frozen =
        peer.freeze(freeze_request(key, peer_config(key), intent.clone())).map_err(debug)?;
    if !matches!(frozen.receipt.disposition, FreezeDisposition::Blocked { .. }) {
        return Err("unresolved tombstone did not block freeze".to_owned());
    }
    push_receipt(&mut trace, "blocked-effect-freeze", ReceiptKind::NexusFreeze, &frozen.receipt)?;
    if !matches!(log.query(key.handoff).map_err(debug)?, Some(OwnershipQuery::Reserved(_))) {
        return Err("blocked freeze advanced ownership reservation".to_owned());
    }
    trace.terminal = "commit-blocked-frozen".to_owned();
    Ok(trace)
}

fn memory_log(key: JointHandoffKey) -> Result<ReferenceOwnershipLog, String> {
    let mut log = ReferenceOwnershipLog::open(":memory:", ownership_issuer()).map_err(debug)?;
    log.initialize_unit(key.continuity_unit, key.source, key.expected_epoch).map_err(debug)?;
    Ok(log)
}

fn reserve(
    log: &mut ReferenceOwnershipLog,
    key: JointHandoffKey,
) -> Result<PrepareIntentReceipt, String> {
    log.reserve(OwnershipReserveRequest { key, expected_state_sequence: 0 }).map_err(debug)
}

fn seal_commit(
    log: &mut ReferenceOwnershipLog,
    key: JointHandoffKey,
    intent: &PrepareIntentReceipt,
    freeze: &joint_handoff_core::NexusFreezeReceipt,
) -> Result<(OwnershipCommitRequest, OwnershipCommitReceipt), String> {
    let intent_ref = intent.receipt_ref().map_err(debug)?;
    let effect_ref = freeze.receipt_ref().map_err(debug)?;
    let visa = external_ref(key, ReceiptKind::VisaFreeze, 60);
    let destination = external_ref(key, ReceiptKind::DestinationPrepared, 80);
    let prepared = log
        .seal(OwnershipSealRequest {
            key,
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
        .map_err(debug)?;
    let request = OwnershipCommitRequest {
        key,
        reservation: intent.reservation,
        prepared: prepared.receipt_ref().map_err(debug)?,
        expected_state_sequence: 2,
    };
    let commit = log.commit(request).map_err(debug)?;
    Ok((request, commit))
}

fn closure_commit(
    closure: &joint_handoff_core::ClosureReceipt,
    log: &ReferenceOwnershipLog,
    key: JointHandoffKey,
) -> Result<OwnershipCommitReceipt, String> {
    let Some(OwnershipQuery::CommitDecided(commit)) = log.query(key.handoff).map_err(debug)? else {
        return Err("ownership query lost committed decision".to_owned());
    };
    if closure.commit != commit.receipt_ref().map_err(debug)? {
        return Err("closure was not bound to queried commit".to_owned());
    }
    Ok(commit)
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
        snapshot: id(240),
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

fn unresolved_effect(value: u128, binding_generation: u64) -> JointEffectRecord {
    JointEffectRecord {
        effect: id(value),
        operation: id(value + 1),
        domain: id(value + 2),
        binding_generation,
        classification: JointEffectClassification::UnresolvedTombstone,
        outcome_digest: None,
        tombstone_digest: Some(digest(241)),
    }
}

fn expect_publication(result: EffectPublicationResult) -> Result<(), String> {
    if result == EffectPublicationResult::Published {
        Ok(())
    } else {
        Err("first publication unexpectedly replayed".to_owned())
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
        issuer: effect_receipt_issuer(effect_issuer(), key)
            .expect("well-formed reference effect issuer"),
        ownership_issuer: ownership_receipt_issuer(ownership_issuer(), key)
            .expect("well-formed reference ownership issuer"),
        registry_instance: id(210),
        scope_id: id(211),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
        domain_bindings_digest: digest(4),
    }
}

fn ownership_issuer() -> ReceiptIssuerIdentity {
    issuer(160)
}

fn effect_issuer() -> ReceiptIssuerIdentity {
    issuer(200)
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

fn durable_path() -> PathBuf {
    let run = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir()
        .join(format!("visa-joint-reference-cell-{}-{run}", std::process::id()));
    fs::create_dir_all(&root).expect("reference cell temp directory");
    root.join("ownership.sqlite")
}

fn trace(case_id: &str, key: JointHandoffKey) -> Result<ReferenceCellTrace, String> {
    Ok(ReferenceCellTrace {
        case_id: case_id.to_owned(),
        handoff: key.handoff,
        ownership_log_id: ownership_receipt_issuer(ownership_issuer(), key).map_err(debug)?.log_id,
        effect_log_id: effect_receipt_issuer(effect_issuer(), key).map_err(debug)?.log_id,
        events: Vec::new(),
        terminal: "incomplete".to_owned(),
    })
}

fn validate_trace_log_isolation(traces: &[ReferenceCellTrace]) -> Result<(), String> {
    let mut handoffs = BTreeSet::new();
    let mut ownership_logs = BTreeSet::new();
    let mut effect_logs = BTreeSet::new();
    for trace in traces {
        if !handoffs.insert(trace.handoff)
            || !ownership_logs.insert(trace.ownership_log_id)
            || !effect_logs.insert(trace.effect_log_id)
        {
            return Err("reference scenarios reused a handoff or native log identity".to_owned());
        }
    }
    Ok(())
}

fn validate_fixed_case_coverage(traces: &[ReferenceCellTrace]) -> Result<(), String> {
    let expected: BTreeSet<_> =
        visa_conformance::JOINT_HANDOFF_CASE_DEFINITIONS.iter().map(|case| case.id).collect();
    let observed: BTreeSet<_> = traces.iter().map(|trace| trace.case_id.as_str()).collect();
    if expected.len() != visa_conformance::JOINT_HANDOFF_CASE_COUNT
        || !expected.iter().all(|case| observed.contains(case))
    {
        return Err("reference peer cell does not cover the fixed case registry".to_owned());
    }
    Ok(())
}

fn push_outcome(trace: &mut ReferenceCellTrace, step: &str, outcome: &str) {
    trace.events.push(ReferenceCellEvent {
        step: step.to_owned(),
        outcome: outcome.to_owned(),
        receipt_kind: None,
        receipt: None,
        effect_record: None,
    });
}

fn push_receipt(
    trace: &mut ReferenceCellTrace,
    step: &str,
    kind: ReceiptKind,
    receipt: &impl Serialize,
) -> Result<(), String> {
    trace.events.push(ReferenceCellEvent {
        step: step.to_owned(),
        outcome: "accepted".to_owned(),
        receipt_kind: Some(format!("{kind:?}")),
        receipt: Some(serde_json::to_value(receipt).map_err(|error| error.to_string())?),
        effect_record: None,
    });
    Ok(())
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
