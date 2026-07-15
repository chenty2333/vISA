use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use contract_core::{Digest, EntityRef, Identity, JournalPosition, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    JointHandoffKey, JointIssuerSet, JointPhase, OwnershipAbortReceipt, PrepareIntentReceipt,
    ReceiptEnvelope, ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, ReceiptRequest,
    TypedReceipt, VisaFreezeReceipt, canonical_bytes, canonical_digest,
};
use serde::{Deserialize, Serialize};
use visa_joint_handoff::{
    DurableJointSession, DurableJointSessionError, EffectFreezeAttempt, EffectFreezeInvocation,
    JointProjectionLog, JointProjectionLogHead, NativeReceiptAuthenticator,
    ProjectionRecordRejection,
};

use crate::SqliteJointProjectionLog;

const DURABLE_CELL_SCHEMA: &str = "visa.joint-handoff.durable-projection-cell.v2";
const ABORT_PROBE_REJECTION: &str = "effect-freeze-outcome-unknown";
type EncodedNativeReceipt = (Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableProjectionTranscript {
    pub head: JointProjectionLogHead,
    pub canonical_record_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableAbortProbe {
    pub command: Identity,
    pub request_bytes: Vec<u8>,
    pub envelope_bytes: Vec<u8>,
    pub payload_bytes: Vec<u8>,
    pub claimed_rejection: String,
    pub head_before: JointProjectionLogHead,
    pub head_after: JointProjectionLogHead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableExecutionObservation {
    pub backend: String,
    pub close_observed: bool,
    pub reopen_observed: bool,
    pub same_boot_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableProjectionCellReport {
    pub schema: String,
    pub key: JointHandoffKey,
    pub issuer_set: JointIssuerSet,
    pub pre_reopen: DurableProjectionTranscript,
    pub post_reopen: DurableProjectionTranscript,
    pub abort_probe: DurableAbortProbe,
    pub execution_observation: DurableExecutionObservation,
    pub record_count: u64,
    pub recovered_phase: String,
    pub recovered_authentication_count: u64,
    pub abort_probe_authentication_count: u64,
    pub unknown_effect_freeze_retained: bool,
    pub abort_blocked_while_unknown: bool,
}

#[derive(Clone)]
struct PinnedCellAuthenticator {
    issuers: JointIssuerSet,
    accepted: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CellAuthenticationError {
    WrongIssuer,
    WrongAuthentication,
}

impl NativeReceiptAuthenticator for PinnedCellAuthenticator {
    type Error = CellAuthenticationError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        _envelope_bytes: &[u8],
        _payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let expected = match envelope.kind {
            ReceiptKind::PrepareIntent
            | ReceiptKind::OwnershipPrepared
            | ReceiptKind::OwnershipAbort
            | ReceiptKind::OwnershipCommit => self.issuers.ownership,
            ReceiptKind::VisaFreeze
            | ReceiptKind::VisaSourceFence
            | ReceiptKind::VisaSourceResume => self.issuers.visa_source,
            ReceiptKind::DestinationPrepared | ReceiptKind::VisaDestinationActivation => {
                self.issuers.visa_destination
            }
            ReceiptKind::NexusFreeze
            | ReceiptKind::NexusThaw
            | ReceiptKind::ClosureProgress
            | ReceiptKind::Closure
            | ReceiptKind::RetainedTombstone => self.issuers.effect_closure,
        };
        if envelope.issuer != expected.issuer
            || envelope.issuer_incarnation != expected.issuer_incarnation
            || envelope.authentication != [0xa5, envelope.kind as u8]
        {
            return Err(if envelope.authentication != [0xa5, envelope.kind as u8] {
                CellAuthenticationError::WrongAuthentication
            } else {
                CellAuthenticationError::WrongIssuer
            });
        }
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub fn run_durable_projection_cell(
    database_path: impl AsRef<std::path::Path>,
) -> Result<DurableProjectionCellReport, String> {
    let database_path = database_path.as_ref();
    let key = cell_key();
    let issuers = cell_issuers();
    let first_counter = Arc::new(AtomicU64::new(0));
    let authenticator = PinnedCellAuthenticator { issuers, accepted: Arc::clone(&first_counter) };
    let log = SqliteJointProjectionLog::open(database_path).map_err(debug)?;
    let mut session =
        DurableJointSession::recover(log, authenticator, key, issuers).map_err(debug)?;

    let intent = intent_receipt(key, issuers.ownership);
    let intent_ref = intent.receipt_ref().map_err(debug)?;
    let visa_freeze = visa_freeze_receipt(key, issuers.visa_source, intent_ref);
    record(&mut session, id(1_000), &intent)?;
    record(&mut session, id(1_001), &visa_freeze)?;
    let invocation = EffectFreezeInvocation {
        key,
        intent: intent.clone(),
        registry_instance: id(910),
        scope_id: id(911),
        scope_generation: 1,
        authority_epoch: 1,
        freeze_generation: 1,
    };
    let invocation_bytes = canonical_bytes(&invocation).map_err(debug)?;
    let attempt = EffectFreezeAttempt::new(id(900), &invocation_bytes).map_err(debug)?;
    session.record_effect_freeze_attempt(attempt.attempt, &invocation_bytes).map_err(debug)?;
    if first_counter.load(Ordering::Relaxed) != 2 {
        return Err(
            "initial durable projection did not authenticate both native receipts".to_owned()
        );
    }
    let head = session.head().ok_or_else(|| "durable projection head is absent".to_owned())?;
    if head.sequence != 3 {
        return Err(format!("durable projection expected 3 records, observed {}", head.sequence));
    }
    let pre_reopen = projection_transcript(session.log(), head)?;
    let (log, _) = session.into_parts();
    drop(log);
    let close_observed = true;

    let recovery_counter = Arc::new(AtomicU64::new(0));
    let recovered_authenticator =
        PinnedCellAuthenticator { issuers, accepted: Arc::clone(&recovery_counter) };
    let reopened = SqliteJointProjectionLog::open(database_path).map_err(debug)?;
    let mut recovered =
        DurableJointSession::recover(reopened, recovered_authenticator, key, issuers)
            .map_err(debug)?;
    let recovered_authentication_count = recovery_counter.load(Ordering::Relaxed);
    if recovered_authentication_count != 2 {
        return Err(format!(
            "durable projection recovery expected 2 replay authentications, observed {recovered_authentication_count}"
        ));
    }
    let recovered_head =
        recovered.head().ok_or_else(|| "recovered durable projection head is absent".to_owned())?;
    let post_reopen = projection_transcript(recovered.log(), recovered_head)?;
    if pre_reopen != post_reopen {
        return Err("SQLite reopen changed the canonical projection transcript".to_owned());
    }
    let recovered_phase = recovered.state().state().phase;
    let unknown_effect_freeze_retained = recovered.unresolved_effect_freeze() == Some(attempt);

    let abort_command = id(1_002);
    let abort = abort_receipt(key, issuers.ownership, intent_ref);
    let (abort_request, abort_envelope, abort_payload) = encoded(&abort, abort_command)?;
    let abort_head_before = recovered
        .head()
        .ok_or_else(|| "durable projection head is absent before abort probe".to_owned())?;
    let abort_blocked_while_unknown = matches!(
        recovered.record_native_receipt(
            abort_command,
            &abort_request,
            &abort_envelope,
            &abort_payload,
        ),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::EffectFreezeOutcomeUnknown
        ))
    );
    let abort_head_after = recovered
        .head()
        .ok_or_else(|| "durable projection head is absent after abort probe".to_owned())?;
    let abort_probe_authentication_count = recovery_counter
        .load(Ordering::Relaxed)
        .checked_sub(recovered_authentication_count)
        .ok_or_else(|| "abort probe authentication counter regressed".to_owned())?;
    if recovered_phase != JointPhase::FrozenUnsealed
        || !unknown_effect_freeze_retained
        || !abort_blocked_while_unknown
        || abort_head_before != head
        || abort_head_after != abort_head_before
        || abort_probe_authentication_count != 1
    {
        return Err(
            "SQLite recovery did not preserve the fail-closed effect-freeze obligation".to_owned()
        );
    }

    Ok(DurableProjectionCellReport {
        schema: DURABLE_CELL_SCHEMA.to_owned(),
        key,
        issuer_set: issuers,
        pre_reopen,
        post_reopen,
        abort_probe: DurableAbortProbe {
            command: abort_command,
            request_bytes: abort_request,
            envelope_bytes: abort_envelope,
            payload_bytes: abort_payload,
            claimed_rejection: ABORT_PROBE_REJECTION.to_owned(),
            head_before: abort_head_before,
            head_after: abort_head_after,
        },
        execution_observation: DurableExecutionObservation {
            backend: "sqlite-wal-synchronous-full".to_owned(),
            close_observed,
            reopen_observed: true,
            same_boot_only: true,
        },
        record_count: head.sequence,
        recovered_phase: "frozen-unsealed".to_owned(),
        recovered_authentication_count,
        abort_probe_authentication_count,
        unknown_effect_freeze_retained,
        abort_blocked_while_unknown,
    })
}

fn projection_transcript<L>(
    log: &L,
    head: JointProjectionLogHead,
) -> Result<DurableProjectionTranscript, String>
where
    L: JointProjectionLog,
    L::Error: std::fmt::Debug,
{
    if log.head().map_err(debug)? != Some(head) {
        return Err("projection transcript head changed while it was read".to_owned());
    }
    let mut canonical_record_bytes = Vec::new();
    for sequence in 1..=head.sequence {
        let record = log
            .read(sequence)
            .map_err(debug)?
            .ok_or_else(|| format!("projection transcript record {sequence} is absent"))?;
        canonical_record_bytes.push(record.canonical_bytes().map_err(debug)?);
    }
    if log.head().map_err(debug)? != Some(head) {
        return Err("projection transcript head changed while it was read".to_owned());
    }
    Ok(DurableProjectionTranscript { head, canonical_record_bytes })
}

fn record<L, A, T>(
    session: &mut DurableJointSession<L, A>,
    command: Identity,
    receipt: &T,
) -> Result<(), String>
where
    L: visa_joint_handoff::JointProjectionLog,
    A: NativeReceiptAuthenticator,
    L::Error: std::fmt::Debug,
    A::Error: std::fmt::Debug,
    T: TypedReceipt + Serialize,
{
    let (request, envelope, payload) = encoded(receipt, command)?;
    session.record_native_receipt(command, &request, &envelope, &payload).map(|_| ()).map_err(debug)
}

fn encoded<T>(receipt: &T, command: Identity) -> Result<EncodedNativeReceipt, String>
where
    T: TypedReceipt + Serialize,
{
    let request = ReceiptRequest::for_receipt(command, receipt);
    let request_digest = request.digest().map_err(debug)?;
    let payload = canonical_bytes(receipt).map_err(debug)?;
    let header = receipt.header();
    let envelope = ReceiptEnvelope {
        schema: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        kind: T::KIND,
        handoff: receipt.key().handoff,
        request_digest,
        state_sequence: header.sequence,
        payload_digest: canonical_digest(receipt).map_err(debug)?,
        previous_receipt_digest: header.previous_digest,
        authentication: vec![0xa5, T::KIND as u8],
    };
    Ok((
        canonical_bytes(&request).map_err(debug)?,
        canonical_bytes(&envelope).map_err(debug)?,
        payload,
    ))
}

fn intent_receipt(key: JointHandoffKey, issuer: ReceiptIssuerIdentity) -> PrepareIntentReceipt {
    PrepareIntentReceipt {
        header: header(ReceiptKind::PrepareIntent, issuer, 10, None),
        key,
        ownership_service: issuer.issuer,
        service_incarnation: issuer.issuer_incarnation,
        reservation: id(104),
        intent_revision: 10,
        request_digest: digest(1),
    }
}

fn visa_freeze_receipt(
    key: JointHandoffKey,
    issuer: ReceiptIssuerIdentity,
    intent: ReceiptRef,
) -> VisaFreezeReceipt {
    VisaFreezeReceipt {
        header: header(ReceiptKind::VisaFreeze, issuer, 1, None),
        key,
        intent,
        journal_position: JournalPosition(20),
        state_digest: digest(2),
        portable_state_digest: digest(3),
    }
}

fn abort_receipt(
    key: JointHandoffKey,
    issuer: ReceiptIssuerIdentity,
    intent: ReceiptRef,
) -> OwnershipAbortReceipt {
    OwnershipAbortReceipt {
        header: header(ReceiptKind::OwnershipAbort, issuer, 20, Some(intent)),
        key,
        reservation: id(104),
        basis: intent,
        basis_revision: 10,
        decision_sequence: 20,
        non_equivocation_root: digest(4),
    }
}

fn header(
    kind: ReceiptKind,
    issuer: ReceiptIssuerIdentity,
    sequence: u64,
    previous: Option<ReceiptRef>,
) -> ReceiptHeader {
    ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: issuer.issuer,
        issuer_incarnation: issuer.issuer_incarnation,
        key_id: issuer.key_id,
        log_id: issuer.log_id,
        sequence,
        previous_digest: previous.map(|receipt| receipt.digest),
    }
}

fn cell_key() -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: EntityRef::initial(id(1)),
        handoff: id(2),
        source: NodeIdentity::new(id(3)),
        destination: NodeIdentity::new(id(4)),
        expected_epoch: LeaseEpoch(7),
        next_epoch: LeaseEpoch(8),
    }
}

fn cell_issuers() -> JointIssuerSet {
    JointIssuerSet {
        ownership: issuer(100),
        effect_closure: issuer(200),
        visa_source: issuer(300),
        visa_destination: issuer(400),
    }
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
    }
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_DB: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn sqlite_reopen_reauthenticates_and_retains_unknown_effect_freeze() {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("visa-joint-durable-cell-{}-{sequence}.sqlite3", std::process::id()));
        let _ = fs::remove_file(&path);
        let report = run_durable_projection_cell(&path).unwrap();
        assert_eq!(report.record_count, 3);
        assert_eq!(report.recovered_authentication_count, 2);
        assert_eq!(report.abort_probe_authentication_count, 1);
        assert!(report.unknown_effect_freeze_retained);
        assert!(report.abort_blocked_while_unknown);
        assert_eq!(report.pre_reopen.head, report.post_reopen.head);
        assert_eq!(
            report.pre_reopen.canonical_record_bytes,
            report.post_reopen.canonical_record_bytes
        );
        assert_eq!(report.pre_reopen.canonical_record_bytes.len(), 3);
        assert_eq!(report.abort_probe.head_before, report.abort_probe.head_after);
        assert_eq!(report.abort_probe.head_before, report.post_reopen.head);
        assert_eq!(report.abort_probe.claimed_rejection, ABORT_PROBE_REJECTION);
        assert_eq!(report.execution_observation.backend, "sqlite-wal-synchronous-full");
        assert!(report.execution_observation.close_observed);
        assert!(report.execution_observation.reopen_observed);
        assert!(report.execution_observation.same_boot_only);
        drop(report);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }
}
