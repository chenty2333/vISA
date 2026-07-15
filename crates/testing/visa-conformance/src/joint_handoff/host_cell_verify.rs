use std::collections::BTreeMap;

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityStatus, CanonicalState, Digest, EffectKind,
    EffectOutcome, EffectRequest, EffectResult, EntityRef, EventKind, EvidenceKind, HandoffPhase,
    Identity, JournalEntry, Rights, TimerDisposition, TimerStatus, canonical_bytes,
    canonical_digest,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use super::{
    durable_cell_verify::{
        ProjectionDestinationActivationAttempt, ProjectionEffectFreezeAttempt,
        ProjectionEffectFreezeInvocation, ProjectionLocalProjectionObserved, ProjectionRecord,
        ProjectionRecordKind, ProjectionSourceAbortAttempt, ProjectionSourceFenceAttempt,
        replay_projection_transcript, validate_effect_freeze_invocation,
    },
    model::*,
    verify::{
        joint_classification_root, joint_effect_cohort_digest, joint_receipt_payload_digest,
        joint_receipt_ref, joint_receipt_request_digest, joint_receipt_request_matches,
    },
};

const HOST_AUTHENTICATION_DOMAIN: &[u8] =
    b"vISA/joint-handoff/coordinator-cell/authentication/v1/same-boot-only\0";
const RECEIPT_KINDS: [(ReceiptKind, &str); 9] = [
    (ReceiptKind::PrepareIntent, "prepare-intent"),
    (ReceiptKind::VisaFreeze, "visa-freeze"),
    (ReceiptKind::NexusFreeze, "nexus-freeze"),
    (ReceiptKind::DestinationPrepared, "destination-prepared"),
    (ReceiptKind::OwnershipPrepared, "ownership-prepared"),
    (ReceiptKind::OwnershipCommit, "ownership-commit"),
    (ReceiptKind::Closure, "closure"),
    (ReceiptKind::VisaSourceFence, "visa-source-fence"),
    (ReceiptKind::VisaDestinationActivation, "visa-destination-activation"),
];
const ABORT_RECEIPT_KINDS: [(ReceiptKind, &str); 6] = [
    (ReceiptKind::PrepareIntent, "prepare-intent"),
    (ReceiptKind::VisaFreeze, "visa-freeze"),
    (ReceiptKind::NexusFreeze, "nexus-freeze"),
    (ReceiptKind::OwnershipAbort, "ownership-abort"),
    (ReceiptKind::NexusThaw, "nexus-thaw"),
    (ReceiptKind::VisaSourceResume, "visa-source-resume"),
];

struct DecodedHostReceipt {
    request: ReceiptRequest,
    envelope: ReceiptEnvelope,
    receipt: JointReceipt,
    reference: ReceiptRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOwnershipReserveInvocation {
    key: JointHandoffKey,
    expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOwnershipSealInvocation {
    key: JointHandoffKey,
    reservation: Identity,
    intent: ReceiptRef,
    visa_freeze: ReceiptRef,
    effect_freeze: ReceiptRef,
    destination_prepared: ReceiptRef,
    bindings: PreparedBindings,
    expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOwnershipAbortInvocation {
    key: JointHandoffKey,
    reservation: Identity,
    basis: ReceiptRef,
    expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostOwnershipCommitInvocation {
    key: JointHandoffKey,
    reservation: Identity,
    prepared: ReceiptRef,
    expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEffectFreezeToken {
    key: JointHandoffKey,
    reservation: Identity,
    registry_instance: Identity,
    scope_id: Identity,
    scope_generation: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    freeze: ReceiptRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEffectThawInvocation {
    token: HostEffectFreezeToken,
    abort: OwnershipAbortReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEffectCloseInvocation {
    token: HostEffectFreezeToken,
    commit: OwnershipCommitReceipt,
    expected_closure_revision: u64,
}

pub(super) fn validate_host_substrate_raw_material(
    report: &JointHostSubstrateCellReport,
) -> Result<(), String> {
    if report.schema != JOINT_HOST_SUBSTRATE_CELL_SCHEMA_VERSION
        || report.authentication_scheme != JOINT_HOST_SUBSTRATE_AUTHENTICATION_SCHEME
        || report.authentication_key == [0; 32]
        || report.native_receipts.len() != 9
        || report.source_journal.len() != 5
        || report.destination_journal.len() != 4
        || report.source_leases.len() != 2
        || report.destination_leases.len() != 2
        || !report.same_boot_only
        || !report.independent_source_destination_databases
        || !report.exclusive_trusted_coordinator_api
    {
        return Err("HostSubstrate raw-material inventory is incomplete".to_owned());
    }

    let receipts = decode_native_receipts(report)?;
    validate_peer_invocations(&report.native_receipts, &receipts)?;
    validate_receipt_chain(&receipts)?;
    validate_host_projection_transcript(report, &receipts)?;
    require_event_shapes(&report.source_journal, &report.destination_journal)?;
    let source =
        semantic_core::replay(&report.source_initial_state, &report.source_journal, state_digest)
            .map_err(|error| format!("source journal replay failed: {error:?}"))?;
    let destination = semantic_core::replay_from(
        &report.destination_restored_state,
        report.snapshot_cursor,
        &report.destination_journal,
        state_digest,
    )
    .map_err(|error| format!("destination journal replay failed: {error:?}"))?;
    let destination_committed = semantic_core::replay_from(
        &report.destination_restored_state,
        report.snapshot_cursor,
        &report.destination_journal[..3],
        state_digest,
    )
    .map_err(|error| format!("destination committed checkpoint replay failed: {error:?}"))?;
    let destination_from_completion = semantic_core::replay_from(
        &destination_committed,
        report.destination_journal[2].position,
        &report.destination_journal[3..],
        state_digest,
    )
    .map_err(|error| format!("destination activation replay failed: {error:?}"))?;

    if source != report.source_terminal_state
        || destination != report.destination_terminal_state
        || destination_from_completion != destination
        || source.phase != HandoffPhase::Committed
        || source.activation.role != ActivationRole::Source
        || source.activation.status != ActivationStatus::Fenced
        || destination.phase != HandoffPhase::Running
        || destination_committed.phase != HandoffPhase::Committed
        || destination_committed.activation.role != ActivationRole::Destination
        || destination_committed.activation.status != ActivationStatus::Active
        || destination.activation.role != ActivationRole::Destination
        || destination.activation.status != ActivationStatus::Active
        || source.ownership.owner != Some(destination.activation.node)
        || destination.ownership.owner != Some(destination.activation.node)
        || source.ownership.epoch != destination.ownership.epoch
    {
        return Err("HostSubstrate journal replay did not derive the claimed terminals".to_owned());
    }
    validate_state_and_receipt_bindings(report, &receipts, &source, &destination)?;
    validate_lease_material(report, &source, &destination)?;
    Ok(())
}

fn decode_native_receipts(
    report: &JointHostSubstrateCellReport,
) -> Result<Vec<DecodedHostReceipt>, String> {
    decode_receipt_materials(&report.native_receipts, &RECEIPT_KINDS, &report.authentication_key)
}

fn decode_receipt_materials(
    materials: &[JointHostNativeReceiptMaterial],
    expected_kinds: &[(ReceiptKind, &str)],
    authentication_key: &[u8; 32],
) -> Result<Vec<DecodedHostReceipt>, String> {
    if materials.len() != expected_kinds.len() {
        return Err(format!(
            "native receipt inventory mismatch: expected {}, observed {}",
            expected_kinds.len(),
            materials.len(),
        ));
    }
    materials
        .iter()
        .zip(expected_kinds.iter().copied())
        .map(|(material, (expected_kind, expected_name))| {
            if material.kind != expected_name {
                return Err(format!(
                    "native receipt order mismatch: expected {expected_name}, observed {}",
                    material.kind
                ));
            }
            let request: ReceiptRequest =
                strict_decode(&material.issuance_request, "receipt issuance request")?;
            let envelope: ReceiptEnvelope = strict_decode(&material.envelope, "receipt envelope")?;
            let receipt = decode_typed_receipt(expected_kind, &material.payload)?;
            if envelope.kind != expected_kind || receipt.kind() != expected_kind {
                return Err(format!("native receipt kind mismatch for {expected_name}"));
            }
            validate_native_envelope(
                &request,
                &envelope,
                &receipt,
                &material.payload,
                authentication_key,
            )?;
            let reference = joint_receipt_ref(&receipt)?;
            Ok(DecodedHostReceipt { request, envelope, receipt, reference })
        })
        .collect()
}

fn validate_peer_invocations(
    materials: &[JointHostNativeReceiptMaterial],
    receipts: &[DecodedHostReceipt],
) -> Result<(), String> {
    if materials.len() != receipts.len() {
        return Err("peer invocation inventory differs from receipt inventory".to_owned());
    }
    for (material, decoded) in materials.iter().zip(receipts) {
        match &decoded.receipt {
            JointReceipt::PrepareIntent(receipt) => {
                let invocation: HostOwnershipReserveInvocation =
                    decode_peer_invocation(material, "ownership reserve")?;
                if invocation.key != receipt.key
                    || invocation.expected_state_sequence != 0
                    || receipt.header.sequence != 1
                    || receipt.intent_revision != 1
                    || receipt.request_digest
                        != canonical_digest(&invocation)
                            .map_err(|_| "cannot hash ownership reserve invocation".to_owned())?
                {
                    return Err(
                        "ownership reserve response does not refine its pre-call invocation"
                            .to_owned(),
                    );
                }
            }
            JointReceipt::EffectFreeze(receipt) => {
                let invocation: ProjectionEffectFreezeInvocation =
                    decode_peer_invocation(material, "effect freeze")?;
                let expected_intent = receipts
                    .iter()
                    .find_map(|decoded| match &decoded.receipt {
                        JointReceipt::PrepareIntent(intent) => Some(intent),
                        _ => None,
                    })
                    .ok_or_else(|| "effect freeze invocation lacks PrepareIntent".to_owned())?;
                let intent =
                    joint_receipt_ref(&JointReceipt::PrepareIntent(invocation.intent.clone()))?;
                if invocation.key != receipt.key
                    || invocation.intent != *expected_intent
                    || intent != receipt.intent
                    || invocation.registry_instance != receipt.registry_instance
                    || invocation.scope_id != receipt.scope_id
                    || invocation.scope_generation != receipt.scope_generation
                    || invocation.authority_epoch != receipt.authority_epoch
                    || invocation.freeze_generation != receipt.freeze_generation
                {
                    return Err(
                        "effect freeze response does not refine its pre-call invocation".to_owned()
                    );
                }
            }
            JointReceipt::OwnershipPrepared(receipt) => {
                let invocation: HostOwnershipSealInvocation =
                    decode_peer_invocation(material, "ownership seal")?;
                if invocation.key != receipt.key
                    || invocation.reservation != receipt.reservation
                    || invocation.intent != receipt.intent
                    || invocation.visa_freeze != receipt.visa_freeze
                    || invocation.effect_freeze != receipt.nexus_freeze
                    || invocation.destination_prepared != receipt.destination_prepared
                    || invocation.bindings != receipt.bindings
                    || invocation.expected_state_sequence != 1
                    || receipt.prepared_revision != 2
                {
                    return Err("ownership seal response does not refine its pre-call invocation"
                        .to_owned());
                }
            }
            JointReceipt::OwnershipCommit(receipt) => {
                let invocation: HostOwnershipCommitInvocation =
                    decode_peer_invocation(material, "ownership commit")?;
                if invocation.key != receipt.key
                    || invocation.reservation != receipt.reservation
                    || invocation.prepared != receipt.prepared
                    || invocation.expected_state_sequence != receipt.prepared_revision
                    || receipt.decision_sequence
                        != invocation
                            .expected_state_sequence
                            .checked_add(1)
                            .ok_or_else(|| "ownership commit sequence overflowed".to_owned())?
                {
                    return Err(
                        "ownership commit response does not refine its pre-call invocation"
                            .to_owned(),
                    );
                }
            }
            JointReceipt::OwnershipAbort(receipt) => {
                let invocation: HostOwnershipAbortInvocation =
                    decode_peer_invocation(material, "ownership abort")?;
                if invocation.key != receipt.key
                    || invocation.reservation != receipt.reservation
                    || invocation.basis != receipt.basis
                    || invocation.expected_state_sequence != receipt.basis_revision
                    || receipt.decision_sequence
                        != invocation
                            .expected_state_sequence
                            .checked_add(1)
                            .ok_or_else(|| "ownership abort sequence overflowed".to_owned())?
                {
                    return Err("ownership abort response does not refine its pre-call invocation"
                        .to_owned());
                }
            }
            JointReceipt::EffectThaw(receipt) => {
                let invocation: HostEffectThawInvocation =
                    decode_peer_invocation(material, "effect thaw")?;
                let abort =
                    joint_receipt_ref(&JointReceipt::OwnershipAbort(invocation.abort.clone()))?;
                let expected_abort = receipts
                    .iter()
                    .find_map(|decoded| match &decoded.receipt {
                        JointReceipt::OwnershipAbort(abort) => Some(abort),
                        _ => None,
                    })
                    .ok_or_else(|| "effect thaw invocation lacks OwnershipAbort".to_owned())?;
                if invocation.abort != *expected_abort
                    || !effect_token_matches_freeze(&invocation.token, receipts)?
                    || invocation.token.key != receipt.key
                    || abort != receipt.abort
                    || invocation.token.freeze != receipt.nexus_freeze
                    || invocation.token.freeze_generation.checked_add(1)
                        != Some(receipt.thaw_generation)
                {
                    return Err(
                        "effect thaw response does not refine its pre-call invocation".to_owned()
                    );
                }
            }
            JointReceipt::Closure(receipt) => {
                let invocation: HostEffectCloseInvocation =
                    decode_peer_invocation(material, "effect close")?;
                let commit =
                    joint_receipt_ref(&JointReceipt::OwnershipCommit(invocation.commit.clone()))?;
                let expected_commit = receipts
                    .iter()
                    .find_map(|decoded| match &decoded.receipt {
                        JointReceipt::OwnershipCommit(commit) => Some(commit),
                        _ => None,
                    })
                    .ok_or_else(|| "effect close invocation lacks OwnershipCommit".to_owned())?;
                if invocation.commit != *expected_commit
                    || !effect_token_matches_freeze(&invocation.token, receipts)?
                    || invocation.token.key != receipt.key
                    || commit != receipt.commit
                    || invocation.token.freeze != receipt.nexus_freeze
                    || invocation.expected_closure_revision != 0
                    || receipt.closure_revision != 1
                    || invocation.token.authority_epoch != receipt.closed_authority_epoch
                {
                    return Err(
                        "effect close response does not refine its pre-call invocation".to_owned()
                    );
                }
            }
            JointReceipt::VisaFreeze(_)
            | JointReceipt::DestinationPrepared(_)
            | JointReceipt::VisaSourceFence(_)
            | JointReceipt::VisaSourceResume(_)
            | JointReceipt::VisaDestinationActivation(_) => {
                if material.peer_invocation.is_some() {
                    return Err(format!(
                        "local vISA receipt {} must not claim a peer invocation",
                        material.kind
                    ));
                }
            }
            JointReceipt::ClosureProgress(_) | JointReceipt::RetainedTombstone(_) => {
                return Err("unsupported peer invocation receipt in HostSubstrate cell".to_owned());
            }
        }
    }
    Ok(())
}

fn effect_token_matches_freeze(
    token: &HostEffectFreezeToken,
    receipts: &[DecodedHostReceipt],
) -> Result<bool, String> {
    let intent = receipts
        .iter()
        .find_map(|receipt| match &receipt.receipt {
            JointReceipt::PrepareIntent(intent) => Some(intent),
            _ => None,
        })
        .ok_or_else(|| "peer invocation inventory lacks PrepareIntent".to_owned())?;
    let freeze = receipts
        .iter()
        .find_map(|receipt| match &receipt.receipt {
            JointReceipt::EffectFreeze(freeze) => Some(freeze),
            _ => None,
        })
        .ok_or_else(|| "peer invocation inventory lacks NexusFreeze".to_owned())?;
    let freeze_ref = joint_receipt_ref(&JointReceipt::EffectFreeze(freeze.clone()))?;
    Ok(token.key == freeze.key
        && token.reservation == intent.reservation
        && token.registry_instance == freeze.registry_instance
        && token.scope_id == freeze.scope_id
        && token.scope_generation == freeze.scope_generation
        && token.authority_epoch == freeze.authority_epoch
        && token.freeze_generation == freeze.freeze_generation
        && token.freeze == freeze_ref)
}

fn decode_peer_invocation<T>(
    material: &JointHostNativeReceiptMaterial,
    label: &str,
) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = material
        .peer_invocation
        .as_deref()
        .ok_or_else(|| format!("{label} is missing its pre-call peer invocation"))?;
    strict_decode(bytes, &format!("{label} peer invocation"))
}

fn validate_host_projection_transcript(
    report: &JointHostSubstrateCellReport,
    receipts: &[DecodedHostReceipt],
) -> Result<(), String> {
    let first =
        receipts.first().ok_or_else(|| "HostSubstrate receipt inventory is empty".to_owned())?;
    let key = first.receipt.key();
    let issuers = host_issuer_set(receipts)?;
    let issuer_set_digest = canonical_digest(&issuers)
        .map_err(|_| "cannot hash HostSubstrate projection issuer set".to_owned())?;
    let transcript = &report.durable_projection.commit_transcript;
    let records = replay_projection_transcript(
        transcript.head,
        &transcript.canonical_record_bytes,
        key,
        issuer_set_digest,
        "HostSubstrate commit projection",
    )?;

    let native_records = records
        .iter()
        .filter_map(|record| match &record.kind {
            ProjectionRecordKind::NativeReceipt(native) => Some(native),
            _ => None,
        })
        .collect::<Vec<_>>();
    if native_records.len() != report.native_receipts.len()
        || native_records.len() != receipts.len()
    {
        return Err(
            "HostSubstrate projection transcript does not retain every native receipt".to_owned()
        );
    }
    let mut commands = BTreeMap::new();
    for (index, ((native, material), receipt)) in
        native_records.iter().zip(&report.native_receipts).zip(receipts).enumerate()
    {
        if native.kind != receipt.receipt.kind()
            || native.command_identity != receipt.request.operation
            || native.request != material.issuance_request
            || native.envelope != material.envelope
            || native.payload != material.payload
            || commands.insert(native.command_identity, index).is_some()
        {
            return Err(format!(
                "HostSubstrate projection native receipt {index} differs from authenticated raw material"
            ));
        }
    }
    validate_commit_projection_records(report, receipts, &records)?;
    validate_abort_projection_evidence(&report.durable_projection.source_abort)
}

fn validate_commit_projection_records(
    report: &JointHostSubstrateCellReport,
    receipts: &[DecodedHostReceipt],
    records: &[ProjectionRecord],
) -> Result<(), String> {
    let [
        intent,
        visa_freeze,
        effect_attempt,
        nexus_freeze,
        destination_prepared,
        ownership_prepared,
        ownership_commit,
        closure,
        source_attempt_record,
        source_observed_record,
        source_fence,
        destination_attempt_record,
        destination_observed_record,
        destination_activation,
    ] = records
    else {
        return Err(
            "HostSubstrate commit projection does not contain exactly 14 records".to_owned()
        );
    };
    for (record, kind) in [
        (intent, ReceiptKind::PrepareIntent),
        (visa_freeze, ReceiptKind::VisaFreeze),
        (nexus_freeze, ReceiptKind::NexusFreeze),
        (destination_prepared, ReceiptKind::DestinationPrepared),
        (ownership_prepared, ReceiptKind::OwnershipPrepared),
        (ownership_commit, ReceiptKind::OwnershipCommit),
        (closure, ReceiptKind::Closure),
        (source_fence, ReceiptKind::VisaSourceFence),
        (destination_activation, ReceiptKind::VisaDestinationActivation),
    ] {
        require_projection_native_kind(record, kind)?;
    }
    let ProjectionRecordKind::EffectFreezeAttempt(effect_attempt) = &effect_attempt.kind else {
        return Err("HostSubstrate record 3 is not an effect-freeze invocation WAL".to_owned());
    };
    validate_host_effect_freeze_invocation(effect_attempt, &report.native_receipts[2], receipts)?;
    if report.native_receipts[2].peer_invocation.as_deref()
        != Some(effect_attempt.invocation.as_slice())
    {
        return Err(
            "HostSubstrate effect-freeze WAL differs from the exact peer invocation".to_owned()
        );
    }
    let ProjectionRecordKind::SourceFenceAttempt(source_attempt) = &source_attempt_record.kind
    else {
        return Err("HostSubstrate record 9 is not a source-fence attempt".to_owned());
    };
    let ProjectionRecordKind::SourceFenceObserved(source_observed) = &source_observed_record.kind
    else {
        return Err("HostSubstrate record 10 is not a source-fence observation".to_owned());
    };
    let ProjectionRecordKind::DestinationActivationAttempt(destination_attempt) =
        &destination_attempt_record.kind
    else {
        return Err("HostSubstrate record 12 is not a destination activation attempt".to_owned());
    };
    let ProjectionRecordKind::DestinationActivationPreviewObserved(destination_observed) =
        &destination_observed_record.kind
    else {
        return Err("HostSubstrate record 13 is not a destination activation preview observation"
            .to_owned());
    };

    validate_source_fence_projection(
        report,
        receipts,
        records,
        source_attempt,
        source_attempt_record,
        source_observed,
    )?;
    validate_destination_activation_projection(
        report,
        receipts,
        records,
        destination_attempt,
        destination_attempt_record,
        destination_observed,
        destination_activation,
    )
}

fn validate_source_fence_projection(
    report: &JointHostSubstrateCellReport,
    receipts: &[DecodedHostReceipt],
    records: &[ProjectionRecord],
    attempt: &ProjectionSourceFenceAttempt,
    attempt_record: &ProjectionRecord,
    observed: &ProjectionLocalProjectionObserved,
) -> Result<(), String> {
    let window = &report.durable_projection.source_fence;
    let attempt_record_digest = projection_record_digest(attempt_record)?;
    let JointReceipt::VisaSourceFence(source_fence) = &receipts[7].receipt else {
        return Err("HostSubstrate receipt 8 is not VisaSourceFence".to_owned());
    };
    if attempt.joint_revision != 7
        || attempt.ownership_commit != receipts[5].reference
        || attempt.closure != receipts[6].reference
        || attempt.fence_command.is_zero()
        || attempt.fence_operation.is_zero()
        || attempt.fence_command == attempt.fence_operation
        || attempt.fence_command == receipts[7].request.operation
        || attempt.fence_operation == receipts[7].request.operation
        || attempt.expected_pre_state_digest == Digest::ZERO
        || attempt.completion_request_digest != receipts[7].envelope.request_digest
        || attempt.request_digest != source_fence_attempt_request_digest(attempt)?
        || observed.attempt_record_digest != attempt_record_digest
        || observed.journal_position != source_fence.journal_position
        || observed.state_digest != source_fence.state_digest
        || attempt.expected_pre_journal_position != report.source_journal[3].position
        || attempt.expected_pre_state_digest != report.source_journal[3].output_state
        || observed.journal_position != report.source_journal[4].position
        || observed.state_digest != report.source_journal[4].output_state
        || attempt.fence_command != report.source_journal[4].event.identity
        || !matches!(
            &report.source_journal[4].event.kind,
            EventKind::HandoffCommitted { operation, .. }
                if *operation == attempt.fence_operation
        )
    {
        return Err("HostSubstrate source-fence WAL lineage is inconsistent".to_owned());
    }
    validate_window_heads(window, records, 7, 8, 10, "source fence")?;
    if window.local_before_position != attempt.expected_pre_journal_position
        || window.local_before_digest != attempt.expected_pre_state_digest
        || window.local_after_position != observed.journal_position
        || window.local_after_digest != observed.state_digest
        || window.reopened_local_after_position != observed.journal_position
        || window.reopened_local_after_digest != observed.state_digest
        || !window.conflicts_left_local_unchanged
        || !window.completion_append_ack_lost
        || window.exposure_blocked_before_completion
    {
        return Err("HostSubstrate source-fence checkpoints do not refine the WAL".to_owned());
    }
    Ok(())
}

fn validate_host_effect_freeze_invocation(
    attempt: &ProjectionEffectFreezeAttempt,
    material: &JointHostNativeReceiptMaterial,
    receipts: &[DecodedHostReceipt],
) -> Result<(), String> {
    let JointReceipt::PrepareIntent(intent) = &receipts[0].receipt else {
        return Err("HostSubstrate effect invocation lacks PrepareIntent".to_owned());
    };
    let JointReceipt::EffectFreeze(freeze) = &receipts[2].receipt else {
        return Err("HostSubstrate effect invocation lacks NexusFreeze".to_owned());
    };
    let invocation = validate_effect_freeze_invocation(attempt, intent.key, intent)?;
    if material.peer_invocation.as_deref() != Some(attempt.invocation.as_slice())
        || receipts.iter().any(|receipt| receipt.request.operation == attempt.attempt)
        || invocation.registry_instance != freeze.registry_instance
        || invocation.scope_id != freeze.scope_id
        || invocation.scope_generation != freeze.scope_generation
        || invocation.authority_epoch != freeze.authority_epoch
        || invocation.freeze_generation != freeze.freeze_generation
        || freeze.intent != receipts[0].reference
    {
        return Err("HostSubstrate NexusFreeze completion does not match the persisted invocation"
            .to_owned());
    }
    Ok(())
}

fn validate_destination_activation_projection(
    report: &JointHostSubstrateCellReport,
    receipts: &[DecodedHostReceipt],
    records: &[ProjectionRecord],
    attempt: &ProjectionDestinationActivationAttempt,
    attempt_record: &ProjectionRecord,
    observed: &ProjectionLocalProjectionObserved,
    completion_record: &ProjectionRecord,
) -> Result<(), String> {
    let window = &report.durable_projection.destination_activation;
    let attempt_record_digest = projection_record_digest(attempt_record)?;
    let completion_record_digest = projection_record_digest(completion_record)?;
    let JointReceipt::DestinationPrepared(destination_prepared) = &receipts[3].receipt else {
        return Err("HostSubstrate receipt 4 is not DestinationPrepared".to_owned());
    };
    let JointReceipt::VisaDestinationActivation(activation) = &receipts[8].receipt else {
        return Err("HostSubstrate receipt 9 is not VisaDestinationActivation".to_owned());
    };
    if attempt.joint_revision != 8
        || attempt.ownership_commit != receipts[5].reference
        || attempt.closure != receipts[6].reference
        || attempt.source_fence != receipts[7].reference
        || attempt.joint_command != activation.activation_command
        || attempt.commit_operation != destination_prepared.lease_commit_operation
        || attempt.commit_idempotency != destination_prepared.lease_commit_idempotency
        || attempt.commit_request_digest != destination_prepared.lease_commit_request_digest
        || attempt.resume_command != activation.resume_command
        || attempt.joint_command == receipts[8].request.operation
        || attempt.resume_command == receipts[8].request.operation
        || attempt.expected_pre_state_digest == Digest::ZERO
        || attempt.request_digest != destination_activation_attempt_request_digest(attempt)?
        || activation.activation_attempt_record_digest != attempt_record_digest
        || observed.attempt_record_digest != attempt_record_digest
        || observed.journal_position != activation.journal_position
        || observed.state_digest != activation.state_digest
        || attempt.expected_pre_journal_position != report.destination_journal[0].position
        || attempt.expected_pre_state_digest != report.destination_journal[0].output_state
        || observed.journal_position != report.destination_journal[3].position
        || observed.state_digest != report.destination_journal[3].output_state
        || attempt.commit_command != report.destination_journal[1].event.identity
        || attempt.resume_command != report.destination_journal[3].event.identity
    {
        return Err("HostSubstrate destination-activation WAL lineage is inconsistent".to_owned());
    }
    validate_window_heads(window, records, 10, 11, 13, "destination activation")?;
    let destination_commit = &report.destination_journal[2];
    if window.local_before_position != attempt.expected_pre_journal_position
        || window.local_before_digest != attempt.expected_pre_state_digest
        || window.local_after_position != observed.journal_position
        || window.local_after_digest != observed.state_digest
        || window.reopened_local_after_position != destination_commit.position
        || window.reopened_local_after_digest != destination_commit.output_state
        || !window.conflicts_left_local_unchanged
        || !window.completion_append_ack_lost
        || !window.exposure_blocked_before_completion
    {
        return Err(
            "HostSubstrate destination preview checkpoints do not refine the WAL".to_owned()
        );
    }
    let EventKind::JointDestinationResumed { activation_record_digest } =
        report.destination_journal[3].event.kind
    else {
        return Err("destination terminal is not a joint-authorized resume".to_owned());
    };
    if activation_record_digest != completion_record_digest {
        return Err(
            "destination resume event is not bound to the activation completion record".to_owned()
        );
    }
    let checkpoint = &report.durable_projection.destination_checkpoint;
    let completion_head = projection_head_at(records, 13)?;
    if checkpoint.joint_completion_head != completion_head
        || checkpoint.activation_completion_record_digest != completion_record_digest
        || checkpoint.local_journal.as_slice() != &report.destination_journal[..3]
        || checkpoint
            .local_journal
            .iter()
            .any(|entry| matches!(entry.event.kind, EventKind::JointDestinationResumed { .. }))
        || checkpoint.local_state.phase != HandoffPhase::Committed
        || checkpoint.local_state.activation.role != ActivationRole::Destination
        || checkpoint.local_state.activation.status != ActivationStatus::Active
        || checkpoint.local_state.timer.status != TimerStatus::Frozen(TimerDisposition::Idle)
        || checkpoint.local_journal.last().map(|entry| entry.position)
            != Some(window.reopened_local_after_position)
        || canonical_digest(&checkpoint.local_state)
            .map_err(|_| "cannot hash destination pre-resume checkpoint".to_owned())?
            != window.reopened_local_after_digest
    {
        return Err(
            "destination pre-resume checkpoint does not prove admission remained closed".to_owned()
        );
    }
    let checkpoint_state = semantic_core::replay_from(
        &report.destination_restored_state,
        report.snapshot_cursor,
        &checkpoint.local_journal,
        state_digest,
    )
    .map_err(|error| format!("destination checkpoint replay failed: {error:?}"))?;
    if checkpoint_state != checkpoint.local_state {
        return Err("destination checkpoint state is not derived from its local journal".to_owned());
    }
    Ok(())
}

fn validate_abort_projection_evidence(
    evidence: &JointHostAbortProjectionEvidence,
) -> Result<(), String> {
    if evidence.authentication_key == [0; 32]
        || evidence.native_receipts.len() != ABORT_RECEIPT_KINDS.len()
        || evidence.journal.len() != 5
        || evidence.leases.len() != 2
    {
        return Err("HostSubstrate abort projection inventory is incomplete".to_owned());
    }
    let issuers = evidence.issuer_set;
    let issuer_list =
        [issuers.ownership, issuers.visa_source, issuers.visa_destination, issuers.effect_closure];
    if issuer_list.iter().any(|issuer| !well_formed_issuer(*issuer))
        || issuer_list
            .iter()
            .enumerate()
            .any(|(index, issuer)| issuer_list[..index].contains(issuer))
    {
        return Err("HostSubstrate abort projection issuer set is invalid".to_owned());
    }
    let receipts = decode_abort_receipts(evidence)?;
    validate_peer_invocations(&evidence.native_receipts, &receipts)?;
    validate_abort_receipt_chain(&receipts, issuers)?;
    let key = receipts[0].receipt.key();
    let issuer_set_digest = canonical_digest(&issuers)
        .map_err(|_| "cannot hash abort projection issuer set".to_owned())?;
    let records = replay_projection_transcript(
        evidence.transcript.head,
        &evidence.transcript.canonical_record_bytes,
        key,
        issuer_set_digest,
        "HostSubstrate abort projection",
    )?;
    validate_abort_projection_records(evidence, &receipts, &records)?;

    if !matches!(evidence.journal[0].event.kind, EventKind::Activated { .. })
        || !matches!(evidence.journal[1].event.kind, EventKind::HandoffStarted)
        || !matches!(evidence.journal[2].event.kind, EventKind::Frozen { .. })
        || !matches!(evidence.journal[3].event.kind, EventKind::HandoffAborted { .. })
        || !matches!(evidence.journal[4].event.kind, EventKind::SourceResumed)
    {
        return Err("HostSubstrate abort journal order is not canonical".to_owned());
    }
    let terminal = semantic_core::replay(&evidence.initial_state, &evidence.journal, state_digest)
        .map_err(|error| format!("abort journal replay failed: {error:?}"))?;
    if terminal != evidence.terminal_state
        || terminal.phase != HandoffPhase::Running
        || terminal.activation.role != ActivationRole::Source
        || terminal.activation.status != ActivationStatus::Active
        || terminal.ownership.owner != Some(key.source)
        || terminal.ownership.epoch != key.expected_epoch
    {
        return Err("HostSubstrate abort journal did not restore the exact source".to_owned());
    }
    let resources = [terminal.timer.claim.resource, terminal.key_value.claim.resource];
    for (lease, resource) in evidence.leases.iter().zip(resources) {
        if lease.resource != resource
            || lease.owner != key.source
            || lease.epoch != key.expected_epoch
        {
            return Err(
                "HostSubstrate abort projection changed provider lease ownership".to_owned()
            );
        }
    }
    Ok(())
}

fn decode_abort_receipts(
    evidence: &JointHostAbortProjectionEvidence,
) -> Result<Vec<DecodedHostReceipt>, String> {
    decode_receipt_materials(
        &evidence.native_receipts,
        &ABORT_RECEIPT_KINDS,
        &evidence.authentication_key,
    )
}

fn validate_abort_receipt_chain(
    receipts: &[DecodedHostReceipt],
    issuers: JointIssuerSet,
) -> Result<(), String> {
    let JointReceipt::PrepareIntent(intent) = &receipts[0].receipt else {
        return Err("abort receipt 1 is not PrepareIntent".to_owned());
    };
    let JointReceipt::VisaFreeze(visa_freeze) = &receipts[1].receipt else {
        return Err("abort receipt 2 is not VisaFreeze".to_owned());
    };
    let JointReceipt::EffectFreeze(nexus_freeze) = &receipts[2].receipt else {
        return Err("abort receipt 3 is not NexusFreeze".to_owned());
    };
    let JointReceipt::OwnershipAbort(abort) = &receipts[3].receipt else {
        return Err("abort receipt 4 is not OwnershipAbort".to_owned());
    };
    let JointReceipt::EffectThaw(thaw) = &receipts[4].receipt else {
        return Err("abort receipt 5 is not NexusThaw".to_owned());
    };
    let JointReceipt::VisaSourceResume(resume) = &receipts[5].receipt else {
        return Err("abort receipt 6 is not VisaSourceResume".to_owned());
    };
    let key = intent.key;
    let expected_previous = [
        None,
        None,
        None,
        Some(receipts[0].reference.digest),
        Some(receipts[2].reference.digest),
        Some(receipts[1].reference.digest),
    ];
    let expected_sequences = [1_u64, 1, 1, 2, 2, 2];
    for (index, receipt) in receipts.iter().enumerate() {
        let header = receipt.receipt.header();
        if receipt.request.operation.is_zero()
            || header.kind != receipt.receipt.kind()
            || issuer_from_header(header) != issuer_for_kind(issuers, receipt.receipt.kind())
            || header.sequence != expected_sequences[index]
            || header.previous_digest != expected_previous[index]
            || receipt.envelope.previous_receipt_digest != expected_previous[index]
        {
            return Err(format!(
                "HostSubstrate abort receipt header chain failed at index {index}"
            ));
        }
    }
    let empty_effects = Vec::<JointEffectRecord>::new();
    let expected_thaw_generation = nexus_freeze
        .freeze_generation
        .checked_add(1)
        .ok_or_else(|| "HostSubstrate abort thaw generation overflowed".to_owned())?;
    if !well_formed_key(key)
        || receipts.iter().any(|receipt| receipt.receipt.key() != key)
        || issuer_from_header(&intent.header) != issuers.ownership
        || issuer_from_header(&visa_freeze.header) != issuers.visa_source
        || issuer_from_header(&nexus_freeze.header) != issuers.effect_closure
        || issuer_from_header(&abort.header) != issuers.ownership
        || issuer_from_header(&thaw.header) != issuers.effect_closure
        || issuer_from_header(&resume.header) != issuers.visa_source
        || visa_freeze.intent != receipts[0].reference
        || nexus_freeze.intent != receipts[0].reference
        || abort.basis != receipts[0].reference
        || abort.reservation != intent.reservation
        || thaw.abort != receipts[3].reference
        || thaw.nexus_freeze != receipts[2].reference
        || resume.abort != receipts[3].reference
        || resume.thaw != Some(receipts[4].reference)
        || intent.ownership_service != issuers.ownership.issuer
        || intent.service_incarnation != issuers.ownership.issuer_incarnation
        || intent.intent_revision != intent.header.sequence
        || intent.reservation.is_zero()
        || intent.request_digest == Digest::ZERO
        || visa_freeze.state_digest == Digest::ZERO
        || visa_freeze.portable_state_digest == Digest::ZERO
        || nexus_freeze.counts != ClassificationCounts::default()
        || nexus_freeze.disposition != FreezeDisposition::ReadyToCommit
        || nexus_freeze.effect_cohort_digest
            != joint_effect_cohort_digest(key, empty_effects.clone())?
        || nexus_freeze.classification_root != joint_classification_root(key, empty_effects)?
        || nexus_freeze.registry_instance.is_zero()
        || nexus_freeze.scope_id.is_zero()
        || nexus_freeze.scope_generation == 0
        || nexus_freeze.authority_epoch == 0
        || nexus_freeze.freeze_generation == 0
        || nexus_freeze.domain_bindings_digest == Digest::ZERO
        || abort.basis_revision != intent.intent_revision
        || abort.decision_sequence != abort.header.sequence
        || abort.non_equivocation_root == Digest::ZERO
        || thaw.thaw_generation != expected_thaw_generation
        || resume.state_digest == Digest::ZERO
    {
        return Err("HostSubstrate abort receipt parent graph is inconsistent".to_owned());
    }
    Ok(())
}

fn validate_abort_projection_records(
    evidence: &JointHostAbortProjectionEvidence,
    receipts: &[DecodedHostReceipt],
    records: &[ProjectionRecord],
) -> Result<(), String> {
    let [
        intent,
        visa_freeze,
        effect_attempt,
        nexus_freeze,
        abort,
        thaw,
        attempt_record,
        observed_record,
        resume,
    ] = records
    else {
        return Err("HostSubstrate abort projection does not contain exactly 9 records".to_owned());
    };
    for (record, kind) in [
        (intent, ReceiptKind::PrepareIntent),
        (visa_freeze, ReceiptKind::VisaFreeze),
        (nexus_freeze, ReceiptKind::NexusFreeze),
        (abort, ReceiptKind::OwnershipAbort),
        (thaw, ReceiptKind::NexusThaw),
        (resume, ReceiptKind::VisaSourceResume),
    ] {
        require_projection_native_kind(record, kind)?;
    }
    let ProjectionRecordKind::EffectFreezeAttempt(effect_attempt) = &effect_attempt.kind else {
        return Err(
            "HostSubstrate abort record 3 is not an effect-freeze invocation WAL".to_owned()
        );
    };
    validate_host_effect_freeze_invocation(effect_attempt, &evidence.native_receipts[2], receipts)?;
    if evidence.native_receipts[2].peer_invocation.as_deref()
        != Some(effect_attempt.invocation.as_slice())
    {
        return Err("HostSubstrate abort effect-freeze WAL differs from the exact peer invocation"
            .to_owned());
    }
    let ProjectionRecordKind::SourceAbortAttempt(attempt) = &attempt_record.kind else {
        return Err("HostSubstrate abort record 7 is not a source-abort attempt".to_owned());
    };
    let ProjectionRecordKind::SourceAbortObserved(observed) = &observed_record.kind else {
        return Err("HostSubstrate abort record 8 is not a source-abort observation".to_owned());
    };
    let native_records = records
        .iter()
        .filter_map(|record| match &record.kind {
            ProjectionRecordKind::NativeReceipt(native) => Some(native),
            _ => None,
        })
        .collect::<Vec<_>>();
    if native_records.len() != evidence.native_receipts.len() {
        return Err("HostSubstrate abort transcript omits native receipts".to_owned());
    }
    let mut commands = BTreeMap::new();
    for ((native, material), receipt) in
        native_records.iter().zip(&evidence.native_receipts).zip(receipts)
    {
        if native.kind != receipt.receipt.kind()
            || native.command_identity != receipt.request.operation
            || native.request != material.issuance_request
            || native.envelope != material.envelope
            || native.payload != material.payload
            || commands.insert(native.command_identity, ()).is_some()
        {
            return Err("HostSubstrate abort transcript native material differs".to_owned());
        }
    }
    let attempt_digest = projection_record_digest(attempt_record)?;
    let JointReceipt::VisaSourceResume(completion) = &receipts[5].receipt else {
        return Err("HostSubstrate abort completion is not VisaSourceResume".to_owned());
    };
    let abort_evidence_matches = matches!(
        &evidence.journal[3].event.kind,
        EventKind::HandoffAborted {
            evidence: Some(abort_evidence),
        } if abort_evidence.kind == EvidenceKind::AuthorityDecision
            && abort_evidence.digest == receipts[3].reference.digest
    );
    if attempt.joint_revision != 5
        || attempt.ownership_abort != receipts[3].reference
        || attempt.nexus_thaw != Some(receipts[4].reference)
        || attempt.abort_command == receipts[5].request.operation
        || attempt.resume_command == receipts[5].request.operation
        || attempt.completion_request_digest != receipts[5].envelope.request_digest
        || attempt.request_digest != source_abort_attempt_request_digest(attempt)?
        || attempt.abort_command.is_zero()
        || attempt.resume_command.is_zero()
        || attempt.abort_command == attempt.resume_command
        || commands.contains_key(&attempt.abort_command)
        || commands.contains_key(&attempt.resume_command)
        || attempt.expected_pre_journal_position != evidence.journal[2].position
        || attempt.expected_pre_state_digest != evidence.journal[2].output_state
        || observed.attempt_record_digest != attempt_digest
        || observed.journal_position != completion.journal_position
        || observed.state_digest != completion.state_digest
        || observed.journal_position != evidence.journal[4].position
        || observed.state_digest != evidence.journal[4].output_state
        || attempt.abort_command != evidence.journal[3].event.identity
        || attempt.resume_command != evidence.journal[4].event.identity
        || !abort_evidence_matches
    {
        return Err("HostSubstrate abort WAL lineage is inconsistent".to_owned());
    }
    validate_window_heads(&evidence.observation, records, 5, 6, 8, "source abort")?;
    let window = &evidence.observation;
    if window.local_before_position != attempt.expected_pre_journal_position
        || window.local_before_digest != attempt.expected_pre_state_digest
        || window.local_after_position != observed.journal_position
        || window.local_after_digest != observed.state_digest
        || window.reopened_local_after_position != observed.journal_position
        || window.reopened_local_after_digest != observed.state_digest
        || !window.conflicts_left_local_unchanged
        || !window.completion_append_ack_lost
        || window.exposure_blocked_before_completion
    {
        return Err("HostSubstrate abort checkpoints do not refine the WAL".to_owned());
    }
    Ok(())
}

fn validate_window_heads(
    window: &JointHostProjectionWindowObservation,
    records: &[ProjectionRecord],
    conflict_prefix_index: usize,
    attempt_index: usize,
    completion_index: usize,
    label: &str,
) -> Result<(), String> {
    let conflict = projection_head_at(records, conflict_prefix_index)?;
    let attempt = projection_head_at(records, attempt_index)?;
    let completion = projection_head_at(records, completion_index)?;
    if window.conflict_head_before != conflict
        || window.conflict_head_after != conflict
        || window.attempt_head != attempt
        || window.reopened_attempt_head != attempt
        || window.completion_head != completion
        || window.reopened_completion_head != completion
        || conflict.sequence.checked_add(1) != Some(attempt.sequence)
        || attempt.sequence.checked_add(2) != Some(completion.sequence)
    {
        return Err(format!("HostSubstrate {label} head checkpoints are not exact WAL prefixes"));
    }
    Ok(())
}

fn projection_head_at(
    records: &[ProjectionRecord],
    index: usize,
) -> Result<JointProjectionLogHead, String> {
    let record =
        records.get(index).ok_or_else(|| format!("projection head index {index} is absent"))?;
    Ok(JointProjectionLogHead {
        version: record.version,
        key: record.key,
        issuer_set_digest: record.issuer_set_digest,
        sequence: record.sequence,
        record_digest: projection_record_digest(record)?,
    })
}

fn projection_record_digest(record: &ProjectionRecord) -> Result<Digest, String> {
    canonical_digest(record).map_err(|_| "cannot hash projection record".to_owned())
}

fn require_projection_native_kind(
    record: &ProjectionRecord,
    expected: ReceiptKind,
) -> Result<(), String> {
    if matches!(&record.kind, ProjectionRecordKind::NativeReceipt(native) if native.kind == expected)
    {
        Ok(())
    } else {
        Err(format!("HostSubstrate projection expected native {expected:?}"))
    }
}

const SOURCE_ABORT_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.source-abort-attempt.v1";
const SOURCE_FENCE_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.source-fence-attempt.v1";
const DESTINATION_ACTIVATION_ATTEMPT_DOMAIN: &str =
    "visa.joint-handoff.local-projection.destination-activation-attempt.v1";

fn source_fence_attempt_request_digest(
    attempt: &ProjectionSourceFenceAttempt,
) -> Result<Digest, String> {
    canonical_digest(&(
        SOURCE_FENCE_ATTEMPT_DOMAIN,
        attempt.joint_revision,
        attempt.ownership_commit,
        attempt.closure,
        attempt.fence_command,
        attempt.fence_operation,
        attempt.expected_pre_state_digest,
        attempt.expected_pre_journal_position,
        attempt.completion_request_digest,
    ))
    .map_err(|_| "cannot hash source-fence attempt request".to_owned())
}

fn source_abort_attempt_request_digest(
    attempt: &ProjectionSourceAbortAttempt,
) -> Result<Digest, String> {
    canonical_digest(&(
        SOURCE_ABORT_ATTEMPT_DOMAIN,
        attempt.joint_revision,
        attempt.ownership_abort,
        attempt.nexus_thaw,
        attempt.abort_command,
        attempt.resume_command,
        attempt.expected_pre_state_digest,
        attempt.expected_pre_journal_position,
        attempt.completion_request_digest,
    ))
    .map_err(|_| "cannot hash source-abort attempt request".to_owned())
}

fn destination_activation_attempt_request_digest(
    attempt: &ProjectionDestinationActivationAttempt,
) -> Result<Digest, String> {
    canonical_digest(&(
        DESTINATION_ACTIVATION_ATTEMPT_DOMAIN,
        attempt.joint_revision,
        attempt.ownership_commit,
        attempt.closure,
        attempt.source_fence,
        attempt.joint_command,
        attempt.commit_command,
        attempt.commit_operation,
        attempt.commit_idempotency,
        attempt.commit_request_digest,
        attempt.resume_command,
        attempt.expected_pre_state_digest,
        attempt.expected_pre_journal_position,
    ))
    .map_err(|_| "cannot hash destination-activation attempt request".to_owned())
}

fn host_issuer_set(receipts: &[DecodedHostReceipt]) -> Result<JointIssuerSet, String> {
    let intent = receipts
        .iter()
        .find(|receipt| receipt.receipt.kind() == ReceiptKind::PrepareIntent)
        .ok_or_else(|| "HostSubstrate transcript lacks PrepareIntent".to_owned())?;
    let visa_source = receipts
        .iter()
        .find(|receipt| receipt.receipt.kind() == ReceiptKind::VisaFreeze)
        .ok_or_else(|| "HostSubstrate transcript lacks VisaFreeze".to_owned())?;
    let visa_destination = receipts
        .iter()
        .find(|receipt| receipt.receipt.kind() == ReceiptKind::DestinationPrepared)
        .ok_or_else(|| "HostSubstrate transcript lacks DestinationPrepared".to_owned())?;
    let effect = receipts
        .iter()
        .find(|receipt| receipt.receipt.kind() == ReceiptKind::NexusFreeze)
        .ok_or_else(|| "HostSubstrate transcript lacks NexusFreeze".to_owned())?;
    Ok(JointIssuerSet {
        ownership: issuer_from_header(intent.receipt.header()),
        visa_source: issuer_from_header(visa_source.receipt.header()),
        visa_destination: issuer_from_header(visa_destination.receipt.header()),
        effect_closure: issuer_from_header(effect.receipt.header()),
    })
}

pub(super) fn strict_decode<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let (value, remaining) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|error| format!("cannot decode canonical {label}: {error}"))?;
    if !remaining.is_empty() {
        return Err(format!("canonical {label} contains trailing bytes"));
    }
    let reencoded =
        canonical_bytes(&value).map_err(|_| format!("cannot re-encode canonical {label}"))?;
    if reencoded != bytes {
        return Err(format!("{label} is not canonically encoded"));
    }
    Ok(value)
}

fn decode_typed_receipt(kind: ReceiptKind, bytes: &[u8]) -> Result<JointReceipt, String> {
    macro_rules! decode {
        ($type:ty, $variant:ident) => {
            strict_decode::<$type>(bytes, "receipt payload").map(JointReceipt::$variant)
        };
    }
    match kind {
        ReceiptKind::PrepareIntent => decode!(PrepareIntentReceipt, PrepareIntent),
        ReceiptKind::VisaFreeze => decode!(VisaFreezeReceipt, VisaFreeze),
        ReceiptKind::NexusFreeze => decode!(NexusFreezeReceipt, EffectFreeze),
        ReceiptKind::DestinationPrepared => {
            strict_decode::<DestinationPreparedReceipt>(bytes, "receipt payload")
                .map(|receipt| JointReceipt::DestinationPrepared(Box::new(receipt)))
        }
        ReceiptKind::OwnershipPrepared => {
            strict_decode::<OwnershipPreparedReceipt>(bytes, "receipt payload")
                .map(|receipt| JointReceipt::OwnershipPrepared(Box::new(receipt)))
        }
        ReceiptKind::OwnershipAbort => decode!(OwnershipAbortReceipt, OwnershipAbort),
        ReceiptKind::OwnershipCommit => decode!(OwnershipCommitReceipt, OwnershipCommit),
        ReceiptKind::NexusThaw => decode!(NexusThawReceipt, EffectThaw),
        ReceiptKind::Closure => decode!(ClosureReceipt, Closure),
        ReceiptKind::VisaSourceFence => decode!(VisaSourceFenceReceipt, VisaSourceFence),
        ReceiptKind::VisaSourceResume => decode!(VisaSourceResumeReceipt, VisaSourceResume),
        ReceiptKind::VisaDestinationActivation => {
            decode!(VisaDestinationActivationReceipt, VisaDestinationActivation)
        }
        _ => Err(format!("unsupported HostSubstrate receipt kind {kind:?}")),
    }
}

fn validate_native_envelope(
    request: &ReceiptRequest,
    envelope: &ReceiptEnvelope,
    receipt: &JointReceipt,
    payload: &[u8],
    authentication_key: &[u8; 32],
) -> Result<(), String> {
    let header = receipt.header();
    let payload_digest = joint_receipt_payload_digest(receipt)?;
    let request_digest = joint_receipt_request_digest(request)?;
    let authentication = host_authentication(envelope, payload, authentication_key)?;
    if envelope.schema != JointProtocolVersion::V1
        || envelope.schema != header.version
        || envelope.issuer != header.issuer
        || envelope.issuer_incarnation != header.issuer_incarnation
        || envelope.kind != receipt.kind()
        || envelope.handoff != receipt.key().handoff
        || !joint_receipt_request_matches(request, receipt)
        || envelope.request_digest != request_digest
        || envelope.state_sequence != header.sequence
        || envelope.payload_digest != payload_digest
        || envelope.previous_receipt_digest != header.previous_digest
        || envelope.authentication != authentication
    {
        return Err(format!(
            "native {:?} envelope mismatch: schema={}, header_schema={}, issuer={}, incarnation={}, kind={}, handoff={}, typed_request={}, request_digest={}, sequence={}, payload={}, previous={}, authentication={}",
            receipt.kind(),
            envelope.schema == JointProtocolVersion::V1,
            envelope.schema == header.version,
            envelope.issuer == header.issuer,
            envelope.issuer_incarnation == header.issuer_incarnation,
            envelope.kind == receipt.kind(),
            envelope.handoff == receipt.key().handoff,
            joint_receipt_request_matches(request, receipt),
            envelope.request_digest == request_digest,
            envelope.state_sequence == header.sequence,
            envelope.payload_digest == payload_digest,
            envelope.previous_receipt_digest == header.previous_digest,
            envelope.authentication == authentication,
        ));
    }
    Ok(())
}

fn host_authentication(
    envelope: &ReceiptEnvelope,
    payload: &[u8],
    authentication_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // This exactly mirrors the bounded same-boot reference authenticator. The
    // disclosed key makes it a recomputable consistency tag, not a signature.
    let projection = canonical_bytes(&(
        envelope.schema,
        envelope.issuer,
        envelope.issuer_incarnation,
        envelope.kind,
        envelope.handoff,
        envelope.request_digest,
        envelope.state_sequence,
        envelope.payload_digest,
        envelope.previous_receipt_digest,
    ))
    .map_err(|_| "cannot encode native authentication projection".to_owned())?;
    let projection_length = u64::try_from(projection.len())
        .map_err(|_| "native authentication projection is too large".to_owned())?;
    let payload_length = u64::try_from(payload.len())
        .map_err(|_| "native receipt payload is too large".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(HOST_AUTHENTICATION_DOMAIN);
    digest.update(authentication_key);
    digest.update(projection_length.to_be_bytes());
    digest.update(projection);
    digest.update(payload_length.to_be_bytes());
    digest.update(payload);
    Ok(digest.finalize().to_vec())
}

fn validate_receipt_chain(receipts: &[DecodedHostReceipt]) -> Result<(), String> {
    let JointReceipt::PrepareIntent(intent) = &receipts[0].receipt else {
        return Err("receipt 0 is not PrepareIntent".to_owned());
    };
    let JointReceipt::VisaFreeze(visa_freeze) = &receipts[1].receipt else {
        return Err("receipt 1 is not VisaFreeze".to_owned());
    };
    let JointReceipt::EffectFreeze(nexus_freeze) = &receipts[2].receipt else {
        return Err("receipt 2 is not NexusFreeze".to_owned());
    };
    let JointReceipt::DestinationPrepared(destination_prepared) = &receipts[3].receipt else {
        return Err("receipt 3 is not DestinationPrepared".to_owned());
    };
    let JointReceipt::OwnershipPrepared(ownership_prepared) = &receipts[4].receipt else {
        return Err("receipt 4 is not OwnershipPrepared".to_owned());
    };
    let JointReceipt::OwnershipCommit(ownership_commit) = &receipts[5].receipt else {
        return Err("receipt 5 is not OwnershipCommit".to_owned());
    };
    let JointReceipt::Closure(closure) = &receipts[6].receipt else {
        return Err("receipt 6 is not Closure".to_owned());
    };
    let JointReceipt::VisaSourceFence(source_fence) = &receipts[7].receipt else {
        return Err("receipt 7 is not VisaSourceFence".to_owned());
    };
    let JointReceipt::VisaDestinationActivation(destination_activation) = &receipts[8].receipt
    else {
        return Err("receipt 8 is not VisaDestinationActivation".to_owned());
    };

    let key = intent.key;
    if !well_formed_key(key) || receipts.iter().any(|item| item.receipt.key() != key) {
        return Err("native receipt chain does not use one well-formed handoff key".to_owned());
    }
    let issuers = JointIssuerSet {
        ownership: issuer_from_header(&intent.header),
        visa_source: issuer_from_header(&visa_freeze.header),
        visa_destination: issuer_from_header(&destination_prepared.header),
        effect_closure: issuer_from_header(&nexus_freeze.header),
    };
    let issuer_list =
        [issuers.ownership, issuers.visa_source, issuers.visa_destination, issuers.effect_closure];
    if issuer_list.iter().any(|issuer| !well_formed_issuer(*issuer))
        || issuer_list
            .iter()
            .enumerate()
            .any(|(index, issuer)| issuer_list[..index].contains(issuer))
    {
        return Err("native receipt roles do not have four distinct pinned issuers".to_owned());
    }

    let expected_previous = [
        None,
        None,
        None,
        None,
        Some(receipts[0].reference.digest),
        Some(receipts[4].reference.digest),
        Some(receipts[2].reference.digest),
        Some(receipts[1].reference.digest),
        Some(receipts[3].reference.digest),
    ];
    let mut sequences = BTreeMap::new();
    for (index, item) in receipts.iter().enumerate() {
        let header = item.receipt.header();
        let expected_issuer = issuer_for_kind(issuers, item.receipt.kind());
        let sequence_key = (header.issuer, header.issuer_incarnation, header.log_id);
        let expected_sequence = sequences
            .get(&sequence_key)
            .copied()
            .unwrap_or(0_u64)
            .checked_add(1)
            .ok_or_else(|| "native issuer sequence overflowed".to_owned())?;
        if header.kind != item.receipt.kind()
            || issuer_from_header(header) != expected_issuer
            || header.sequence != expected_sequence
            || header.previous_digest != expected_previous[index]
            || item.envelope.previous_receipt_digest != expected_previous[index]
        {
            return Err(format!("native receipt header chain failed at index {index}"));
        }
        sequences.insert(sequence_key, header.sequence);
    }

    let references: Vec<_> = receipts.iter().map(|item| item.reference).collect();
    if visa_freeze.intent != references[0]
        || nexus_freeze.intent != references[0]
        || destination_prepared.intent != references[0]
        || destination_prepared.visa_freeze != references[1]
        || destination_prepared.nexus_freeze != references[2]
        || ownership_prepared.intent != references[0]
        || ownership_prepared.visa_freeze != references[1]
        || ownership_prepared.nexus_freeze != references[2]
        || ownership_prepared.destination_prepared != references[3]
        || ownership_commit.prepared != references[4]
        || closure.commit != references[5]
        || closure.nexus_freeze != references[2]
        || source_fence.commit != references[5]
        || source_fence.closure != references[6]
        || destination_activation.commit != references[5]
        || destination_activation.closure != references[6]
        || destination_activation.source_fence != references[7]
        || destination_activation.activation_attempt_record_digest == Digest::ZERO
    {
        return Err("native receipt parent graph is not exact".to_owned());
    }
    if intent.ownership_service != issuers.ownership.issuer
        || intent.service_incarnation != issuers.ownership.issuer_incarnation
        || intent.intent_revision != 1
        || intent.reservation.is_zero()
        || intent.request_digest == Digest::ZERO
        || ownership_prepared.reservation != intent.reservation
        || ownership_prepared.prepared_revision != ownership_prepared.header.sequence
        || ownership_commit.reservation != intent.reservation
        || ownership_commit.prepared_revision != ownership_prepared.prepared_revision
        || ownership_commit.decision_sequence != ownership_commit.header.sequence
        || ownership_commit.non_equivocation_root == Digest::ZERO
    {
        return Err("ownership receipt lineage is inconsistent".to_owned());
    }
    let bindings = ownership_prepared.bindings;
    if bindings.prepare_intent_receipt_digest != references[0].digest
        || bindings.visa_freeze_receipt_digest != references[1].digest
        || bindings.effect_freeze_receipt_digest != references[2].digest
        || bindings.destination_prepared_receipt_digest != references[3].digest
    {
        return Err("Prepared ownership does not seal the exact receipt chain".to_owned());
    }

    let empty_effects = Vec::<JointEffectRecord>::new();
    if nexus_freeze.counts != ClassificationCounts::default()
        || nexus_freeze.disposition != FreezeDisposition::ReadyToCommit
        || nexus_freeze.effect_cohort_digest
            != joint_effect_cohort_digest(key, empty_effects.clone())?
        || nexus_freeze.classification_root != joint_classification_root(key, empty_effects)?
        || nexus_freeze.registry_instance.is_zero()
        || nexus_freeze.scope_id.is_zero()
        || nexus_freeze.scope_generation == 0
        || nexus_freeze.authority_epoch == 0
        || nexus_freeze.freeze_generation == 0
        || nexus_freeze.domain_bindings_digest == Digest::ZERO
        || closure.closure_revision != 1
        || closure.effect_manifest_digest != nexus_freeze.effect_cohort_digest
        || closure.closed_authority_epoch != nexus_freeze.authority_epoch
    {
        return Err(
            "effect freeze/closure receipts do not describe the empty closed cohort".to_owned()
        );
    }
    Ok(())
}

fn validate_state_and_receipt_bindings(
    report: &JointHostSubstrateCellReport,
    receipts: &[DecodedHostReceipt],
    source_terminal: &CanonicalState,
    destination_terminal: &CanonicalState,
) -> Result<(), String> {
    let JointReceipt::PrepareIntent(intent) = &receipts[0].receipt else {
        return Err("receipt 0 is not PrepareIntent".to_owned());
    };
    let JointReceipt::VisaFreeze(visa_freeze) = &receipts[1].receipt else {
        return Err("receipt 1 is not VisaFreeze".to_owned());
    };
    let JointReceipt::EffectFreeze(nexus_freeze) = &receipts[2].receipt else {
        return Err("receipt 2 is not NexusFreeze".to_owned());
    };
    let JointReceipt::DestinationPrepared(destination_prepared) = &receipts[3].receipt else {
        return Err("receipt 3 is not DestinationPrepared".to_owned());
    };
    let JointReceipt::OwnershipPrepared(ownership_prepared) = &receipts[4].receipt else {
        return Err("receipt 4 is not OwnershipPrepared".to_owned());
    };
    let JointReceipt::VisaSourceFence(source_fence) = &receipts[7].receipt else {
        return Err("receipt 7 is not VisaSourceFence".to_owned());
    };
    let JointReceipt::VisaDestinationActivation(destination_activation) = &receipts[8].receipt
    else {
        return Err("receipt 8 is not VisaDestinationActivation".to_owned());
    };
    let key = intent.key;

    if !report.snapshot.body.extensions.is_empty() {
        return Err("HostSubstrate reference snapshot unexpectedly contains extensions".to_owned());
    }
    let snapshot_integrity = canonical_digest(&report.snapshot.body)
        .map_err(|_| "cannot recompute snapshot integrity".to_owned())?;
    if report.snapshot.integrity != snapshot_integrity
        || report.snapshot.integrity != report.snapshot_integrity
        || report.snapshot_cursor != report.snapshot.body.snapshot.journal_position
        || report.snapshot_cursor != report.source_journal[3].position
        || report.snapshot.body.snapshot.handoff != key.handoff
        || report.snapshot.body.source_node != key.source
        || report.snapshot.body.component != key.continuity_unit
        || report.snapshot.body.source_lease_epoch != key.expected_epoch
    {
        return Err("snapshot raw material is not bound to the joint handoff".to_owned());
    }
    let restored = semantic_core::restore(
        &report.snapshot,
        snapshot_integrity,
        report.snapshot.body.component_digest,
        report.snapshot.body.profile_digest,
        report.snapshot.body.profile_version,
        &[],
        key.destination,
    )
    .map_err(|error| format!("snapshot restore failed in verifier: {error:?}"))?;
    if restored != report.destination_restored_state {
        return Err(
            "reported destination restored state is not derived from the snapshot".to_owned()
        );
    }

    let source_exported = semantic_core::replay(
        &report.source_initial_state,
        &report.source_journal[..4],
        state_digest,
    )
    .map_err(|error| format!("source pre-fence replay failed: {error:?}"))?;
    let destination_prepared_state = semantic_core::replay_from(
        &restored,
        report.snapshot_cursor,
        &report.destination_journal[..1],
        state_digest,
    )
    .map_err(|error| format!("destination prepare replay failed: {error:?}"))?;
    let prepared = destination_prepared_state
        .prepared_destination
        .as_ref()
        .ok_or_else(|| "destination prepare journal did not produce prepared state".to_owned())?;
    let prepared_destination_digest = canonical_digest(prepared)
        .map_err(|_| "cannot recompute prepared destination digest".to_owned())?;
    let prepared_authorities_digest = canonical_digest(&prepared.authorities)
        .map_err(|_| "cannot recompute prepared authorities digest".to_owned())?;
    let prepared_bindings_digest = canonical_digest(&prepared.bindings)
        .map_err(|_| "cannot recompute prepared bindings digest".to_owned())?;
    let source_state_digest = canonical_digest(&source_exported)
        .map_err(|_| "cannot recompute exported source state digest".to_owned())?;
    let destination_prepared_state_digest = canonical_digest(&destination_prepared_state)
        .map_err(|_| "cannot recompute destination prepared state digest".to_owned())?;
    let portable_state_digest = canonical_digest(&report.snapshot.body.portable_state)
        .map_err(|_| "cannot recompute portable-state digest".to_owned())?;
    let snapshot_body_digest = canonical_digest(&report.snapshot.body)
        .map_err(|_| "cannot recompute snapshot-body digest".to_owned())?;

    let mapping = JointMappingManifest {
        version: JointProtocolVersion::V1,
        key,
        visa_operation_cohort_digest: canonical_digest(&source_exported.operations)
            .map_err(|_| "cannot recompute vISA operation cohort digest".to_owned())?,
        effect_scope: EffectScopeVersion {
            registry_instance: nexus_freeze.registry_instance,
            scope_id: nexus_freeze.scope_id,
            scope_generation: nexus_freeze.scope_generation,
            authority_epoch: nexus_freeze.authority_epoch,
            freeze_generation: nexus_freeze.freeze_generation,
        },
        effect_cohort_digest: nexus_freeze.effect_cohort_digest,
        domain_bindings_manifest_digest: nexus_freeze.domain_bindings_digest,
        ownership_service: OwnershipVersion {
            service_id: intent.header.issuer,
            service_incarnation: intent.header.issuer_incarnation,
            log_sequence: intent.header.sequence,
        },
        protocol_revision: 1,
    };
    let mapping_digest = canonical_digest(&mapping)
        .map_err(|_| "cannot recompute joint mapping manifest digest".to_owned())?;
    let snapshot_binding = SnapshotBinding {
        snapshot: report.snapshot.body.snapshot.snapshot,
        integrity: report.snapshot.integrity,
        body_digest: snapshot_body_digest,
        source_journal_position: report.snapshot_cursor,
        component_digest: report.snapshot.body.component_digest,
        profile_digest: report.snapshot.body.profile_digest,
    };
    if visa_freeze.journal_position != report.snapshot_cursor
        || visa_freeze.state_digest != source_state_digest
        || visa_freeze.portable_state_digest != portable_state_digest
        || source_exported.exported_snapshot.as_ref() != Some(&report.snapshot.body.snapshot)
        || source_exported.portable_state != report.snapshot.body.portable_state
        || destination_prepared.snapshot != snapshot_binding
        || destination_prepared.journal_position != report.destination_journal[0].position
        || destination_prepared.state_digest != destination_prepared_state_digest
        || destination_prepared.prepared_destination_digest != prepared_destination_digest
        || destination_prepared.authorities_digest != prepared_authorities_digest
        || destination_prepared.bindings_digest != prepared_bindings_digest
        || destination_prepared.joint_mapping_manifest_digest != mapping_digest
    {
        return Err("freeze/destination-prepared receipts do not match replayed state".to_owned());
    }

    let expected_request = expected_lease_commit_request(
        &destination_prepared_state,
        destination_prepared.lease_commit_operation,
        destination_prepared.lease_commit_idempotency,
        destination_activation.resume_command,
    )?;
    if destination_prepared.lease_commit_request_digest != expected_request.request_digest
        || report.lease_commit_request_digest != expected_request.request_digest
    {
        return Err(
            "destination lease-commit request digest is not independently derived".to_owned()
        );
    }
    let EventKind::EffectPrepared { request } = &report.destination_journal[1].event.kind else {
        return Err("destination journal lacks EffectPrepared".to_owned());
    };
    if request != &expected_request {
        return Err("destination EffectPrepared request differs from the sealed request".to_owned());
    }

    let expected_bindings = PreparedBindings {
        prepare_intent_receipt_digest: receipts[0].reference.digest,
        visa_freeze_receipt_digest: receipts[1].reference.digest,
        effect_freeze_receipt_digest: receipts[2].reference.digest,
        snapshot: snapshot_binding.snapshot,
        snapshot_integrity_digest: snapshot_binding.integrity,
        source_journal_position: report.snapshot_cursor,
        source_state_digest,
        component_digest: snapshot_binding.component_digest,
        profile_digest: snapshot_binding.profile_digest,
        destination_prepared_receipt_digest: receipts[3].reference.digest,
        destination_state_digest: destination_prepared_state_digest,
        prepared_authorities_digest,
        prepared_bindings_digest,
        effect_cohort_manifest_digest: nexus_freeze.effect_cohort_digest,
        joint_mapping_manifest_digest: mapping_digest,
    };
    if ownership_prepared.bindings != expected_bindings {
        return Err(
            "ownership Prepared receipt does not seal replayed state and mapping".to_owned()
        );
    }

    validate_handoff_commit_event(
        &report.source_journal[4],
        key,
        None,
        Some((receipts[5].reference.digest, receipts[6].reference.digest)),
    )?;
    validate_handoff_commit_event(
        &report.destination_journal[2],
        key,
        Some(destination_prepared.lease_commit_operation),
        None,
    )?;
    let source_terminal_digest = canonical_digest(source_terminal)
        .map_err(|_| "cannot recompute source terminal digest".to_owned())?;
    let destination_terminal_digest = canonical_digest(destination_terminal)
        .map_err(|_| "cannot recompute destination terminal digest".to_owned())?;
    if source_fence.journal_position != report.source_journal[4].position
        || source_fence.state_digest != source_terminal_digest
        || destination_activation.journal_position != report.destination_journal[3].position
        || destination_activation.state_digest != destination_terminal_digest
    {
        return Err("terminal vISA receipts do not match replayed journal terminals".to_owned());
    }

    validate_summary(
        report,
        key,
        source_terminal,
        destination_terminal,
        source_terminal_digest,
        destination_terminal_digest,
        prepared_destination_digest,
        expected_request.request_digest,
    )
}

fn expected_lease_commit_request(
    prepared_state: &CanonicalState,
    operation: contract_core::Identity,
    idempotency_key: contract_core::IdempotencyKey,
    resume_guard: contract_core::Identity,
) -> Result<EffectRequest, String> {
    if resume_guard.is_zero() || resume_guard == operation {
        return Err("destination lease-commit resume guard is invalid".to_owned());
    }
    let prepared = prepared_state
        .prepared_destination
        .as_ref()
        .ok_or_else(|| "prepared destination is absent".to_owned())?;
    let subject = EntityRef::new(prepared_state.component.identity, prepared.component_generation);
    let mut authorities = prepared.authorities.iter().filter(|grant| {
        grant.subject == subject
            && grant.resource == subject
            && grant.status == AuthorityStatus::Active
            && grant.rights.contains(Rights::HANDOFF)
    });
    let authority = authorities
        .next()
        .ok_or_else(|| "prepared destination lacks one handoff authority".to_owned())?
        .authority;
    if authorities.next().is_some() {
        return Err("prepared destination has ambiguous handoff authorities".to_owned());
    }
    let kind = EffectKind::LeaseCommit {
        handoff: prepared.handoff,
        snapshot: prepared.snapshot,
        destination: prepared.destination,
        expected_epoch: prepared.expected_epoch,
        next_epoch: prepared.next_epoch,
    };
    let request_digest = canonical_digest(&(
        operation,
        idempotency_key,
        Some(resume_guard),
        prepared.destination,
        subject,
        authority,
        kind.clone(),
    ))
    .map_err(|_| "cannot recompute lease-commit request".to_owned())?;
    Ok(EffectRequest {
        operation,
        idempotency_key,
        causal_parent: Some(resume_guard),
        node: prepared.destination,
        subject,
        resource: subject,
        authority,
        lease_epoch: prepared.expected_epoch,
        request_digest,
        kind,
    })
}

fn validate_handoff_commit_event(
    entry: &JournalEntry,
    key: JointHandoffKey,
    expected_operation: Option<contract_core::Identity>,
    receipt_evidence: Option<(Digest, Digest)>,
) -> Result<(), String> {
    let EventKind::HandoffCommitted {
        operation,
        handoff,
        snapshot,
        source,
        destination,
        previous_epoch,
        new_epoch,
        outcome,
    } = &entry.event.kind
    else {
        return Err("journal terminal is not HandoffCommitted".to_owned());
    };
    if expected_operation.is_some_and(|expected| expected != *operation)
        || *handoff != key.handoff
        || *source != key.source
        || *destination != key.destination
        || *previous_epoch != key.expected_epoch
        || *new_epoch != key.next_epoch
        || snapshot.is_zero()
    {
        return Err("HandoffCommitted journal event does not match the joint key".to_owned());
    }
    let EffectOutcome::Succeeded {
        result: EffectResult::LeaseAdvanced { owner, epoch, source_fence },
        evidence,
    } = outcome
    else {
        return Err("HandoffCommitted outcome is not a successful lease advance".to_owned());
    };
    if *owner != key.destination || *epoch != key.next_epoch {
        return Err("HandoffCommitted outcome advances the wrong owner or epoch".to_owned());
    }
    if let Some((decision_digest, closure_digest)) = receipt_evidence
        && (evidence.kind != EvidenceKind::AuthorityDecision
            || evidence.digest != decision_digest
            || source_fence.kind != EvidenceKind::SourceFence
            || source_fence.digest != closure_digest)
    {
        return Err("source fence event is not bound to ownership and closure receipts".to_owned());
    }
    Ok(())
}

fn validate_lease_material(
    report: &JointHostSubstrateCellReport,
    source: &CanonicalState,
    destination: &CanonicalState,
) -> Result<(), String> {
    let resources = [source.timer.claim.resource, source.key_value.claim.resource];
    if destination.timer.claim.resource != resources[0]
        || destination.key_value.claim.resource != resources[1]
    {
        return Err("source and destination resource claims diverge".to_owned());
    }
    for leases in [&report.source_leases, &report.destination_leases] {
        for (lease, resource) in leases.iter().zip(resources) {
            if lease.resource != resource
                || lease.owner != destination.activation.node
                || lease.epoch != destination.ownership.epoch
            {
                return Err(
                    "provider lease material does not project destination ownership".to_owned()
                );
            }
        }
    }
    if report.source_leases != report.destination_leases {
        return Err("source and destination providers disagree on final resource leases".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_summary(
    report: &JointHostSubstrateCellReport,
    key: JointHandoffKey,
    source: &CanonicalState,
    destination: &CanonicalState,
    source_digest: Digest,
    destination_digest: Digest,
    prepared_destination_digest: Digest,
    lease_commit_request_digest: Digest,
) -> Result<(), String> {
    let expected_lifecycle = [
        "source-activated",
        "source-quiescing",
        "source-frozen",
        "source-exported",
        "destination-restored",
        "destination-prepared",
        "source-committed-fenced",
        "destination-committed",
        "destination-running-active",
        "source-reopened-committed-fenced",
    ];
    let lifecycle = report.lifecycle.iter().map(String::as_str).collect::<Vec<_>>();
    let receipt_chain = report.receipt_chain.iter().map(String::as_str).collect::<Vec<_>>();
    let source_position =
        report.source_journal.last().ok_or_else(|| "source journal is empty".to_owned())?.position;
    let destination_position = report
        .destination_journal
        .last()
        .ok_or_else(|| "destination journal is empty".to_owned())?
        .position;
    let destination_generation = key
        .continuity_unit
        .generation
        .next()
        .ok_or_else(|| "continuity generation exhausted".to_owned())?;
    if lifecycle != expected_lifecycle
        || receipt_chain != RECEIPT_KINDS.map(|(_, name)| name)
        || report.authenticated_receipt_count != report.native_receipts.len()
        || report.joint_phase != "destination-active"
        || !report.source_reopened
        || report.source_phase != "committed"
        || report.source_activation != "fenced"
        || !report.source_owner_is_destination
        || report.destination_phase != "running"
        || report.destination_activation != "active"
        || !report.destination_owner_is_destination
        || report.source_component_generation != key.continuity_unit.generation.0
        || report.destination_component_generation != destination_generation.0
        || source.component != key.continuity_unit
        || destination.component
            != EntityRef::new(key.continuity_unit.identity, destination_generation)
        || report.source_journal_position != source_position
        || report.destination_journal_position != destination_position
        || report.source_state_digest != source_digest
        || report.destination_state_digest != destination_digest
        || report.prepared_destination_digest != prepared_destination_digest
        || report.lease_commit_request_digest != lease_commit_request_digest
        || source_digest == destination_digest
    {
        return Err("HostSubstrate scalar summary differs from recomputed raw material".to_owned());
    }
    Ok(())
}

const fn issuer_from_header(header: &ReceiptHeader) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        key_id: header.key_id,
        log_id: header.log_id,
    }
}

const fn issuer_for_kind(issuers: JointIssuerSet, kind: ReceiptKind) -> ReceiptIssuerIdentity {
    match kind {
        ReceiptKind::PrepareIntent
        | ReceiptKind::OwnershipPrepared
        | ReceiptKind::OwnershipAbort
        | ReceiptKind::OwnershipCommit => issuers.ownership,
        ReceiptKind::VisaFreeze | ReceiptKind::VisaSourceFence | ReceiptKind::VisaSourceResume => {
            issuers.visa_source
        }
        ReceiptKind::DestinationPrepared | ReceiptKind::VisaDestinationActivation => {
            issuers.visa_destination
        }
        ReceiptKind::NexusFreeze
        | ReceiptKind::NexusThaw
        | ReceiptKind::ClosureProgress
        | ReceiptKind::Closure
        | ReceiptKind::RetainedTombstone => issuers.effect_closure,
    }
}

fn well_formed_key(key: JointHandoffKey) -> bool {
    !key.continuity_unit.identity.is_zero()
        && !key.handoff.is_zero()
        && !key.source.is_zero()
        && !key.destination.is_zero()
        && key.source != key.destination
        && key.expected_epoch.next() == Some(key.next_epoch)
}

fn well_formed_issuer(issuer: ReceiptIssuerIdentity) -> bool {
    [issuer.issuer, issuer.issuer_incarnation, issuer.key_id, issuer.log_id]
        .into_iter()
        .all(|identity| !identity.is_zero())
}

fn state_digest(state: &CanonicalState) -> Digest {
    canonical_digest(state).unwrap_or(Digest::ZERO)
}

fn require_event_shapes(
    source: &[JournalEntry],
    destination: &[JournalEntry],
) -> Result<(), String> {
    use contract_core::EventKind;

    let source_matches = matches!(source[0].event.kind, EventKind::Activated { .. })
        && matches!(source[1].event.kind, EventKind::HandoffStarted)
        && matches!(source[2].event.kind, EventKind::Frozen { .. })
        && matches!(source[3].event.kind, EventKind::SnapshotExported { .. })
        && matches!(source[4].event.kind, EventKind::HandoffCommitted { .. });
    let destination_matches =
        matches!(destination[0].event.kind, EventKind::DestinationPrepared { .. })
            && matches!(destination[1].event.kind, EventKind::EffectPrepared { .. })
            && matches!(destination[2].event.kind, EventKind::HandoffCommitted { .. })
            && matches!(
                destination[3].event.kind,
                EventKind::JointDestinationResumed {
                    activation_record_digest
                } if activation_record_digest != Digest::ZERO
            );
    if source_matches && destination_matches {
        Ok(())
    } else {
        Err("HostSubstrate journal event order is not canonical".to_owned())
    }
}
