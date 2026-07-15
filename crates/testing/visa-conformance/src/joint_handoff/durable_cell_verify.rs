use contract_core::{
    Digest, IdempotencyKey, Identity, JournalPosition, canonical_bytes, canonical_digest,
};
use serde::{Deserialize, Serialize};

use super::{
    host_cell_verify::strict_decode,
    model::*,
    verify::{
        joint_receipt_payload_digest, joint_receipt_ref, joint_receipt_request_digest,
        joint_receipt_request_matches,
    },
};

const MAX_NATIVE_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_NATIVE_REQUEST_BYTES: usize = 64 * 1024;
const MAX_NATIVE_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_PROJECTION_RECORDS: usize = 64;
const EFFECT_FREEZE_OUTCOME_UNKNOWN: &str = "effect-freeze-outcome-unknown";
const SQLITE_BACKEND: &str = "sqlite-wal-synchronous-full";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionRecord {
    pub(super) version: JointProjectionLogVersion,
    pub(super) key: JointHandoffKey,
    pub(super) issuer_set_digest: Digest,
    pub(super) sequence: u64,
    pub(super) previous_record_digest: Option<Digest>,
    pub(super) kind: ProjectionRecordKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProjectionRecordKind {
    NativeReceipt(ProjectionNativeReceipt),
    BeginDestinationActivation { command_identity: Identity },
    EffectFreezeAttempt(ProjectionEffectFreezeAttempt),
    SourceAbortAttempt(Box<ProjectionSourceAbortAttempt>),
    SourceAbortObserved(ProjectionLocalProjectionObserved),
    SourceFenceAttempt(Box<ProjectionSourceFenceAttempt>),
    SourceFenceObserved(ProjectionLocalProjectionObserved),
    DestinationActivationAttempt(Box<ProjectionDestinationActivationAttempt>),
    DestinationActivationPreviewObserved(ProjectionLocalProjectionObserved),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionNativeReceipt {
    pub(super) kind: ReceiptKind,
    pub(super) command_identity: Identity,
    pub(super) request: Vec<u8>,
    pub(super) envelope: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionEffectFreezeAttempt {
    pub(super) attempt: Identity,
    pub(super) invocation: Vec<u8>,
    pub(super) invocation_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionEffectFreezeInvocation {
    pub(super) key: JointHandoffKey,
    pub(super) intent: PrepareIntentReceipt,
    pub(super) registry_instance: Identity,
    pub(super) scope_id: Identity,
    pub(super) scope_generation: u64,
    pub(super) authority_epoch: u64,
    pub(super) freeze_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionSourceAbortAttempt {
    pub(super) joint_revision: u64,
    pub(super) ownership_abort: ReceiptRef,
    pub(super) nexus_thaw: Option<ReceiptRef>,
    pub(super) abort_command: Identity,
    pub(super) resume_command: Identity,
    pub(super) expected_pre_state_digest: Digest,
    pub(super) expected_pre_journal_position: JournalPosition,
    pub(super) completion_request_digest: Digest,
    pub(super) request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionSourceFenceAttempt {
    pub(super) joint_revision: u64,
    pub(super) ownership_commit: ReceiptRef,
    pub(super) closure: ReceiptRef,
    pub(super) fence_command: Identity,
    pub(super) fence_operation: Identity,
    pub(super) expected_pre_state_digest: Digest,
    pub(super) expected_pre_journal_position: JournalPosition,
    pub(super) completion_request_digest: Digest,
    pub(super) request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionDestinationActivationAttempt {
    pub(super) joint_revision: u64,
    pub(super) ownership_commit: ReceiptRef,
    pub(super) closure: ReceiptRef,
    pub(super) source_fence: ReceiptRef,
    pub(super) joint_command: Identity,
    pub(super) commit_command: Identity,
    pub(super) commit_operation: Identity,
    pub(super) commit_idempotency: IdempotencyKey,
    pub(super) commit_request_digest: Digest,
    pub(super) resume_command: Identity,
    pub(super) expected_pre_state_digest: Digest,
    pub(super) expected_pre_journal_position: JournalPosition,
    pub(super) request_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionLocalProjectionObserved {
    pub(super) attempt_record_digest: Digest,
    pub(super) journal_position: JournalPosition,
    pub(super) state_digest: Digest,
}

pub(super) fn validate_durable_projection_raw_material(
    report: &JointDurableProjectionCellReport,
) -> Result<(), String> {
    validate_inventory(report)?;
    if report.pre_reopen != report.post_reopen {
        return Err("SQLite reopen changed the retained projection transcript".to_owned());
    }
    if report.abort_probe.head_before != report.post_reopen.head
        || report.abort_probe.head_after != report.abort_probe.head_before
    {
        return Err("abort probe changed the retained projection head".to_owned());
    }

    let issuer_set_digest = canonical_digest(&report.issuer_set)
        .map_err(|_| "cannot recompute durable issuer-set digest".to_owned())?;
    let records = validate_transcript(report, issuer_set_digest)?;
    let [first, second, third] = records.as_slice() else {
        return Err("durable projection transcript does not contain exactly 3 records".to_owned());
    };

    let ProjectionRecordKind::NativeReceipt(first_native) = &first.kind else {
        return Err("durable record 1 is not the prepare-intent receipt".to_owned());
    };
    let intent_receipt = validate_native_receipt(
        first_native,
        ReceiptKind::PrepareIntent,
        report.key,
        report.issuer_set.ownership,
    )?;
    let JointReceipt::PrepareIntent(intent) = &intent_receipt else {
        return Err("durable record 1 payload is not a prepare intent".to_owned());
    };
    validate_intent(intent, report.issuer_set.ownership)?;
    let intent_reference = joint_receipt_ref(&intent_receipt)?;

    let ProjectionRecordKind::NativeReceipt(second_native) = &second.kind else {
        return Err("durable record 2 is not the vISA freeze receipt".to_owned());
    };
    if second_native.command_identity == first_native.command_identity {
        return Err("durable native receipt commands are not unique".to_owned());
    }
    let freeze_receipt = validate_native_receipt(
        second_native,
        ReceiptKind::VisaFreeze,
        report.key,
        report.issuer_set.visa_source,
    )?;
    let JointReceipt::VisaFreeze(freeze) = &freeze_receipt else {
        return Err("durable record 2 payload is not a vISA freeze".to_owned());
    };
    validate_visa_freeze(freeze, intent_reference)?;

    let ProjectionRecordKind::EffectFreezeAttempt(attempt) = &third.kind else {
        return Err("durable record 3 is not an effect-freeze attempt".to_owned());
    };
    validate_effect_freeze_invocation(attempt, report.key, intent)?;

    validate_abort_probe(
        report,
        intent,
        intent_reference,
        [first_native.command_identity, second_native.command_identity],
        attempt,
    )?;
    Ok(())
}

fn validate_inventory(report: &JointDurableProjectionCellReport) -> Result<(), String> {
    if report.schema != JOINT_DURABLE_PROJECTION_CELL_SCHEMA_VERSION
        || !well_formed_key(report.key)
        || !well_formed_issuer_set(report.issuer_set)
        || report.record_count != 3
        || report.recovered_phase != "frozen-unsealed"
        || report.recovered_authentication_count != 2
        || report.abort_probe_authentication_count != 1
        || !report.unknown_effect_freeze_retained
        || !report.abort_blocked_while_unknown
        || report.abort_probe.claimed_rejection != EFFECT_FREEZE_OUTCOME_UNKNOWN
        || report.execution_observation.backend != SQLITE_BACKEND
        || !report.execution_observation.close_observed
        || !report.execution_observation.reopen_observed
        || !report.execution_observation.same_boot_only
    {
        return Err("durable projection raw-material inventory is incomplete".to_owned());
    }
    Ok(())
}

fn validate_transcript(
    report: &JointDurableProjectionCellReport,
    issuer_set_digest: Digest,
) -> Result<Vec<ProjectionRecord>, String> {
    let transcript = &report.pre_reopen;
    if transcript.head.sequence != report.record_count {
        return Err("durable projection head does not bind the retained transcript".to_owned());
    }
    replay_projection_transcript(
        transcript.head,
        &transcript.canonical_record_bytes,
        report.key,
        issuer_set_digest,
        "durable projection",
    )
}

pub(super) fn replay_projection_transcript(
    head: JointProjectionLogHead,
    canonical_record_bytes: &[Vec<u8>],
    key: JointHandoffKey,
    issuer_set_digest: Digest,
    label: &str,
) -> Result<Vec<ProjectionRecord>, String> {
    if head.version != JointProjectionLogVersion::V1
        || head.key != key
        || head.issuer_set_digest != issuer_set_digest
        || head.record_digest == Digest::ZERO
        || issuer_set_digest == Digest::ZERO
        || canonical_record_bytes.is_empty()
        || canonical_record_bytes.len() > MAX_PROJECTION_RECORDS
        || usize::try_from(head.sequence).ok() != Some(canonical_record_bytes.len())
    {
        return Err(format!("{label} head does not bind the retained transcript"));
    }

    let mut records = Vec::with_capacity(canonical_record_bytes.len());
    let mut previous_digest = None;
    for (index, bytes) in canonical_record_bytes.iter().enumerate() {
        let record: ProjectionRecord = strict_decode(bytes, &format!("{label} record"))?;
        let sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| format!("{label} sequence overflowed"))?;
        if record.version != JointProjectionLogVersion::V1
            || record.key != key
            || record.issuer_set_digest != issuer_set_digest
            || record.sequence != sequence
            || record.previous_record_digest != previous_digest
        {
            return Err(format!("{label} record {sequence} breaks the log chain"));
        }
        previous_digest = Some(
            canonical_digest(&record)
                .map_err(|_| format!("cannot hash {label} record {sequence}"))?,
        );
        records.push(record);
    }
    if previous_digest != Some(head.record_digest) {
        return Err(format!("{label} head digest does not match its final record"));
    }
    Ok(records)
}

fn validate_native_receipt(
    native: &ProjectionNativeReceipt,
    expected_kind: ReceiptKind,
    key: JointHandoffKey,
    expected_issuer: ReceiptIssuerIdentity,
) -> Result<JointReceipt, String> {
    if native.kind != expected_kind
        || native.command_identity.is_zero()
        || native.request.is_empty()
        || native.request.len() > MAX_NATIVE_REQUEST_BYTES
        || native.envelope.is_empty()
        || native.envelope.len() > MAX_NATIVE_ENVELOPE_BYTES
        || native.payload.is_empty()
        || native.payload.len() > MAX_NATIVE_PAYLOAD_BYTES
    {
        return Err(format!("durable {expected_kind:?} native record is malformed"));
    }
    let request: ReceiptRequest =
        strict_decode(&native.request, "durable receipt issuance binding")?;
    let envelope: ReceiptEnvelope = strict_decode(&native.envelope, "durable receipt envelope")?;
    let receipt = match expected_kind {
        ReceiptKind::PrepareIntent => {
            strict_decode::<PrepareIntentReceipt>(&native.payload, "durable prepare-intent payload")
                .map(JointReceipt::PrepareIntent)?
        }
        ReceiptKind::VisaFreeze => {
            strict_decode::<VisaFreezeReceipt>(&native.payload, "durable vISA-freeze payload")
                .map(JointReceipt::VisaFreeze)?
        }
        _ => return Err(format!("unsupported durable native receipt {expected_kind:?}")),
    };
    if request.operation != native.command_identity {
        return Err(format!("durable {expected_kind:?} request command is mismatched"));
    }
    validate_native_envelope(&request, &envelope, &receipt, &native.payload, key, expected_issuer)?;
    Ok(receipt)
}

fn validate_native_envelope(
    request: &ReceiptRequest,
    envelope: &ReceiptEnvelope,
    receipt: &JointReceipt,
    payload: &[u8],
    key: JointHandoffKey,
    expected_issuer: ReceiptIssuerIdentity,
) -> Result<(), String> {
    let header = receipt.header();
    let expected_authentication = [0xa5, receipt.kind() as u8];
    let expected_payload = canonical_receipt_payload(receipt)?;
    if receipt.key() != key
        || envelope.schema != JointProtocolVersion::V1
        || header.version != JointProtocolVersion::V1
        || header.kind != receipt.kind()
        || !header_matches_issuer(header, expected_issuer)
        || envelope.issuer != header.issuer
        || envelope.issuer_incarnation != header.issuer_incarnation
        || envelope.kind != receipt.kind()
        || envelope.handoff != key.handoff
        || !joint_receipt_request_matches(request, receipt)
        || envelope.request_digest != joint_receipt_request_digest(request)?
        || envelope.state_sequence != header.sequence
        || envelope.payload_digest != joint_receipt_payload_digest(receipt)?
        || envelope.previous_receipt_digest != header.previous_digest
        || envelope.authentication.as_slice() != expected_authentication
        || expected_payload != payload
    {
        return Err(format!("durable {:?} native envelope or payload mismatch", receipt.kind()));
    }
    Ok(())
}

fn canonical_receipt_payload(receipt: &JointReceipt) -> Result<Vec<u8>, String> {
    let encoded = match receipt {
        JointReceipt::PrepareIntent(value) => canonical_bytes(value),
        JointReceipt::VisaFreeze(value) => canonical_bytes(value),
        JointReceipt::OwnershipAbort(value) => canonical_bytes(value),
        _ => return Err("unsupported durable receipt payload".to_owned()),
    };
    encoded.map_err(|_| "cannot encode durable native payload".to_owned())
}

fn validate_intent(
    intent: &PrepareIntentReceipt,
    ownership: ReceiptIssuerIdentity,
) -> Result<(), String> {
    if intent.header.previous_digest.is_some()
        || intent.ownership_service != ownership.issuer
        || intent.service_incarnation != ownership.issuer_incarnation
        || intent.reservation.is_zero()
        || intent.intent_revision == 0
        || intent.request_digest == Digest::ZERO
    {
        return Err("durable prepare intent is not a valid root receipt".to_owned());
    }
    Ok(())
}

fn validate_visa_freeze(
    freeze: &VisaFreezeReceipt,
    intent_reference: ReceiptRef,
) -> Result<(), String> {
    if freeze.header.previous_digest.is_some()
        || freeze.intent != intent_reference
        || freeze.journal_position.0 == 0
        || freeze.state_digest == Digest::ZERO
        || freeze.portable_state_digest == Digest::ZERO
    {
        return Err("durable vISA freeze does not derive FrozenUnsealed".to_owned());
    }
    Ok(())
}

fn validate_abort_probe(
    report: &JointDurableProjectionCellReport,
    intent: &PrepareIntentReceipt,
    intent_reference: ReceiptRef,
    recorded_commands: [Identity; 2],
    unknown_attempt: &ProjectionEffectFreezeAttempt,
) -> Result<(), String> {
    let probe = &report.abort_probe;
    if probe.command.is_zero() || recorded_commands.contains(&probe.command) {
        return Err("durable abort probe command is invalid or reused".to_owned());
    }
    let envelope: ReceiptEnvelope = strict_decode(&probe.envelope_bytes, "abort probe envelope")?;
    let request: ReceiptRequest =
        strict_decode(&probe.request_bytes, "abort probe receipt issuance binding")?;
    let abort: OwnershipAbortReceipt = strict_decode(&probe.payload_bytes, "abort probe payload")?;
    let receipt = JointReceipt::OwnershipAbort(abort.clone());
    validate_native_envelope(
        &request,
        &envelope,
        &receipt,
        &probe.payload_bytes,
        report.key,
        report.issuer_set.ownership,
    )?;
    if request.operation != probe.command
        || abort.basis != intent_reference
        || abort.header.previous_digest != Some(intent_reference.digest)
        || abort.reservation != intent.reservation
        || abort.basis_revision != intent.intent_revision
        || abort.decision_sequence <= abort.basis_revision
        || abort.header.sequence != abort.decision_sequence
        || abort.non_equivocation_root == Digest::ZERO
    {
        return Err("abort probe is not a valid FrozenUnsealed abort transition".to_owned());
    }
    if unknown_attempt.attempt.is_zero()
        || unknown_attempt.invocation_digest == Digest::ZERO
        || envelope.kind == ReceiptKind::NexusFreeze
        || probe.claimed_rejection != EFFECT_FREEZE_OUTCOME_UNKNOWN
    {
        return Err("abort probe did not derive EffectFreezeOutcomeUnknown".to_owned());
    }
    Ok(())
}

pub(super) fn validate_effect_freeze_invocation(
    attempt: &ProjectionEffectFreezeAttempt,
    key: JointHandoffKey,
    expected_intent: &PrepareIntentReceipt,
) -> Result<ProjectionEffectFreezeInvocation, String> {
    if attempt.attempt.is_zero()
        || attempt.invocation.is_empty()
        || attempt.invocation.len() > MAX_NATIVE_REQUEST_BYTES
        || attempt.invocation_digest == Digest::ZERO
    {
        return Err("durable effect-freeze invocation WAL is malformed".to_owned());
    }
    let invocation: ProjectionEffectFreezeInvocation =
        strict_decode(&attempt.invocation, "effect-freeze invocation")?;
    let invocation_digest = canonical_digest(&invocation)
        .map_err(|_| "cannot hash effect-freeze invocation".to_owned())?;
    if invocation.key != key
        || invocation.intent != *expected_intent
        || invocation.registry_instance.is_zero()
        || invocation.scope_id.is_zero()
        || invocation.scope_generation == 0
        || invocation.authority_epoch == 0
        || invocation.freeze_generation == 0
        || attempt.invocation_digest != invocation_digest
    {
        return Err("durable effect-freeze invocation WAL does not bind its inputs".to_owned());
    }
    Ok(invocation)
}

fn header_matches_issuer(header: &ReceiptHeader, issuer: ReceiptIssuerIdentity) -> bool {
    header.issuer == issuer.issuer
        && header.issuer_incarnation == issuer.issuer_incarnation
        && header.key_id == issuer.key_id
        && header.log_id == issuer.log_id
        && header.sequence > 0
}

fn well_formed_key(key: JointHandoffKey) -> bool {
    !key.continuity_unit.identity.is_zero()
        && !key.handoff.is_zero()
        && !key.source.is_zero()
        && !key.destination.is_zero()
        && key.source != key.destination
        && key.expected_epoch.next() == Some(key.next_epoch)
}

fn well_formed_issuer_set(issuers: JointIssuerSet) -> bool {
    let values =
        [issuers.ownership, issuers.visa_source, issuers.visa_destination, issuers.effect_closure];
    values.iter().all(|issuer| {
        !issuer.issuer.is_zero()
            && !issuer.issuer_incarnation.is_zero()
            && !issuer.key_id.is_zero()
            && !issuer.log_id.is_zero()
    }) && values
        .iter()
        .enumerate()
        .all(|(index, issuer)| values[..index].iter().all(|other| other != issuer))
}
