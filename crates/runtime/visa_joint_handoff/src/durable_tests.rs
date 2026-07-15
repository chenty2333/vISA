extern crate std;

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec,
    vec::Vec,
};

use joint_handoff_core::{
    ClassificationCounts, ClosureProgressReceipt, ClosureReceipt, DestinationPreparedReceipt,
    Digest, EffectScopeVersion, EntityRef, FreezeDisposition, IdempotencyKey, Identity,
    JointHandoffKey, JointIssuerSet, JointMappingManifest, JointPhase, JournalPosition, LeaseEpoch,
    NexusFreezeReceipt, NexusThawReceipt, NodeIdentity, OwnershipAbortReceipt,
    OwnershipCommitReceipt, OwnershipPreparedReceipt, OwnershipVersion, PrepareIntentReceipt,
    PreparedBindings, ReceiptEnvelope, ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind,
    ReceiptRef, ReceiptRequest, RetainedTombstoneReceipt, SnapshotBinding, TypedReceipt,
    VisaDestinationActivationReceipt, VisaFreezeReceipt, VisaSourceFenceReceipt,
    VisaSourceResumeReceipt, canonical_bytes, canonical_digest,
};
use serde::Serialize;

use super::*;

const OWNERSHIP_ISSUER: u128 = 100;
const OWNERSHIP_INCARNATION: u128 = 101;
const OWNERSHIP_KEY: u128 = 102;
const OWNERSHIP_LOG: u128 = 103;
const EFFECT_ISSUER: u128 = 200;
const EFFECT_INCARNATION: u128 = 201;
const EFFECT_KEY: u128 = 202;
const EFFECT_LOG: u128 = 203;
const VISA_SOURCE_ISSUER: u128 = 300;
const VISA_SOURCE_INCARNATION: u128 = 301;
const VISA_SOURCE_KEY: u128 = 302;
const VISA_SOURCE_LOG: u128 = 303;
const VISA_DESTINATION_ISSUER: u128 = 400;
const VISA_DESTINATION_INCARNATION: u128 = 401;
const VISA_DESTINATION_KEY: u128 = 402;
const VISA_DESTINATION_LOG: u128 = 403;

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
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

fn issuer(issuer: u128, incarnation: u128, key_id: u128, log_id: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(issuer),
        issuer_incarnation: id(incarnation),
        key_id: id(key_id),
        log_id: id(log_id),
    }
}

fn issuers() -> JointIssuerSet {
    JointIssuerSet {
        ownership: issuer(OWNERSHIP_ISSUER, OWNERSHIP_INCARNATION, OWNERSHIP_KEY, OWNERSHIP_LOG),
        visa_source: issuer(
            VISA_SOURCE_ISSUER,
            VISA_SOURCE_INCARNATION,
            VISA_SOURCE_KEY,
            VISA_SOURCE_LOG,
        ),
        visa_destination: issuer(
            VISA_DESTINATION_ISSUER,
            VISA_DESTINATION_INCARNATION,
            VISA_DESTINATION_KEY,
            VISA_DESTINATION_LOG,
        ),
        effect_closure: issuer(EFFECT_ISSUER, EFFECT_INCARNATION, EFFECT_KEY, EFFECT_LOG),
    }
}

fn header(
    kind: ReceiptKind,
    issuer: ReceiptIssuerIdentity,
    sequence: u64,
    parent: Option<ReceiptRef>,
) -> ReceiptHeader {
    ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: issuer.issuer,
        issuer_incarnation: issuer.issuer_incarnation,
        key_id: issuer.key_id,
        log_id: issuer.log_id,
        sequence,
        previous_digest: parent.map(|receipt| receipt.digest),
    }
}

fn intent() -> PrepareIntentReceipt {
    PrepareIntentReceipt {
        header: header(ReceiptKind::PrepareIntent, issuers().ownership, 10, None),
        key: key(),
        ownership_service: id(OWNERSHIP_ISSUER),
        service_incarnation: id(OWNERSHIP_INCARNATION),
        reservation: id(104),
        intent_revision: 10,
        request_digest: digest(1),
    }
}

fn visa_freeze(intent: ReceiptRef) -> VisaFreezeReceipt {
    VisaFreezeReceipt {
        header: header(ReceiptKind::VisaFreeze, issuers().visa_source, 1, None),
        key: key(),
        intent,
        journal_position: JournalPosition(20),
        state_digest: digest(2),
        portable_state_digest: digest(3),
    }
}

fn effect_freeze(intent: ReceiptRef) -> NexusFreezeReceipt {
    NexusFreezeReceipt {
        header: header(ReceiptKind::NexusFreeze, issuers().effect_closure, 20, None),
        key: key(),
        intent,
        registry_instance: id(210),
        scope_id: id(211),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
        domain_bindings_digest: digest(4),
        effect_cohort_digest: digest(5),
        classification_root: digest(6),
        counts: ClassificationCounts {
            registered: 5,
            committed: 5,
            aborted: 0,
            unresolved: 0,
            tombstones: 0,
        },
        disposition: FreezeDisposition::ReadyToCommit,
    }
}

fn destination_prepared(
    intent: ReceiptRef,
    visa_freeze: ReceiptRef,
    effect_freeze: ReceiptRef,
) -> DestinationPreparedReceipt {
    DestinationPreparedReceipt {
        header: header(ReceiptKind::DestinationPrepared, issuers().visa_destination, 1, None),
        key: key(),
        intent,
        visa_freeze,
        nexus_freeze: effect_freeze,
        snapshot: SnapshotBinding {
            snapshot: id(20),
            integrity: digest(7),
            body_digest: digest(8),
            source_journal_position: JournalPosition(20),
            component_digest: digest(9),
            profile_digest: digest(10),
        },
        journal_position: JournalPosition(21),
        state_digest: digest(11),
        prepared_destination_digest: digest(12),
        authorities_digest: digest(13),
        bindings_digest: digest(14),
        joint_mapping_manifest_digest: digest(16),
        lease_commit_operation: id(21),
        lease_commit_idempotency: IdempotencyKey::from_bytes([22; 16]),
        lease_commit_request_digest: digest(15),
    }
}

fn prepared_bindings(
    intent: ReceiptRef,
    visa: &VisaFreezeReceipt,
    effect: &NexusFreezeReceipt,
    destination: &DestinationPreparedReceipt,
) -> PreparedBindings {
    PreparedBindings {
        prepare_intent_receipt_digest: intent.digest,
        visa_freeze_receipt_digest: visa.receipt_ref().unwrap().digest,
        effect_freeze_receipt_digest: effect.receipt_ref().unwrap().digest,
        snapshot: destination.snapshot.snapshot,
        snapshot_integrity_digest: destination.snapshot.integrity,
        source_journal_position: visa.journal_position,
        source_state_digest: visa.state_digest,
        component_digest: destination.snapshot.component_digest,
        profile_digest: destination.snapshot.profile_digest,
        destination_prepared_receipt_digest: destination.receipt_ref().unwrap().digest,
        destination_state_digest: destination.state_digest,
        prepared_authorities_digest: destination.authorities_digest,
        prepared_bindings_digest: destination.bindings_digest,
        effect_cohort_manifest_digest: effect.effect_cohort_digest,
        joint_mapping_manifest_digest: destination.joint_mapping_manifest_digest,
    }
}

fn ownership_prepared(
    intent: ReceiptRef,
    visa: &VisaFreezeReceipt,
    effect: &NexusFreezeReceipt,
    destination: &DestinationPreparedReceipt,
) -> OwnershipPreparedReceipt {
    OwnershipPreparedReceipt {
        header: header(ReceiptKind::OwnershipPrepared, issuers().ownership, 30, Some(intent)),
        key: key(),
        reservation: id(104),
        intent,
        visa_freeze: visa.receipt_ref().unwrap(),
        nexus_freeze: effect.receipt_ref().unwrap(),
        destination_prepared: destination.receipt_ref().unwrap(),
        bindings: prepared_bindings(intent, visa, effect, destination),
        prepared_revision: 30,
    }
}

fn ownership_commit(prepared: ReceiptRef) -> OwnershipCommitReceipt {
    OwnershipCommitReceipt {
        header: header(ReceiptKind::OwnershipCommit, issuers().ownership, 40, Some(prepared)),
        key: key(),
        reservation: id(104),
        prepared,
        prepared_revision: 30,
        decision_sequence: 40,
        non_equivocation_root: digest(17),
    }
}

fn ownership_abort(basis: ReceiptRef, basis_revision: u64) -> OwnershipAbortReceipt {
    OwnershipAbortReceipt {
        header: header(ReceiptKind::OwnershipAbort, issuers().ownership, 40, Some(basis)),
        key: key(),
        reservation: id(104),
        basis,
        basis_revision,
        decision_sequence: 40,
        non_equivocation_root: digest(80),
    }
}

fn thaw(abort: ReceiptRef, freeze: ReceiptRef) -> NexusThawReceipt {
    NexusThawReceipt {
        header: header(ReceiptKind::NexusThaw, issuers().effect_closure, 21, Some(freeze)),
        key: key(),
        abort,
        nexus_freeze: freeze,
        thaw_generation: 7,
    }
}

fn source_resume(
    abort: ReceiptRef,
    thaw: Option<ReceiptRef>,
    visa_freeze: ReceiptRef,
) -> VisaSourceResumeReceipt {
    VisaSourceResumeReceipt {
        header: header(ReceiptKind::VisaSourceResume, issuers().visa_source, 2, Some(visa_freeze)),
        key: key(),
        abort,
        thaw,
        journal_position: JournalPosition(24),
        state_digest: digest(81),
    }
}

fn progress(commit: ReceiptRef, freeze: ReceiptRef) -> ClosureProgressReceipt {
    ClosureProgressReceipt {
        header: header(ReceiptKind::ClosureProgress, issuers().effect_closure, 21, Some(freeze)),
        key: key(),
        commit,
        nexus_freeze: freeze,
        closure_revision: 1,
        remaining_effects: 2,
        retained_tombstones: 0,
        progress_root: digest(18),
    }
}

fn closure(commit: ReceiptRef, freeze: ReceiptRef, progress: ReceiptRef) -> ClosureReceipt {
    ClosureReceipt {
        header: header(ReceiptKind::Closure, issuers().effect_closure, 22, Some(progress)),
        key: key(),
        commit,
        nexus_freeze: freeze,
        closure_revision: 2,
        effect_manifest_digest: digest(19),
        closed_authority_epoch: 6,
    }
}

fn tombstone(commit: ReceiptRef, freeze: ReceiptRef) -> RetainedTombstoneReceipt {
    RetainedTombstoneReceipt {
        header: header(ReceiptKind::RetainedTombstone, issuers().effect_closure, 21, Some(freeze)),
        key: key(),
        commit,
        nexus_freeze: freeze,
        closure_revision: 1,
        tombstone_count: 1,
        tombstone_manifest_digest: digest(82),
    }
}

fn source_fence(
    commit: ReceiptRef,
    closure: ReceiptRef,
    visa_freeze: ReceiptRef,
) -> VisaSourceFenceReceipt {
    VisaSourceFenceReceipt {
        header: header(ReceiptKind::VisaSourceFence, issuers().visa_source, 2, Some(visa_freeze)),
        key: key(),
        commit,
        closure,
        journal_position: JournalPosition(22),
        state_digest: digest(20),
    }
}

fn activation(
    commit: ReceiptRef,
    closure: ReceiptRef,
    source_fence: ReceiptRef,
    destination: ReceiptRef,
    activation_attempt_record_digest: Digest,
) -> VisaDestinationActivationReceipt {
    VisaDestinationActivationReceipt {
        header: header(
            ReceiptKind::VisaDestinationActivation,
            issuers().visa_destination,
            2,
            Some(destination),
        ),
        key: key(),
        commit,
        closure,
        source_fence,
        activation_command: id(1_009),
        resume_command: id(7_202),
        activation_attempt_record_digest,
        journal_position: JournalPosition(23),
        state_digest: digest(21),
    }
}

fn source_abort_wal(
    joint_revision: u64,
    ownership_abort: ReceiptRef,
    nexus_thaw: Option<ReceiptRef>,
    completion_request_digest: Digest,
) -> SourceAbortAttempt {
    SourceAbortAttempt::new(
        joint_revision,
        ownership_abort,
        nexus_thaw,
        id(7_001),
        id(7_002),
        digest(91),
        JournalPosition(20),
        completion_request_digest,
    )
    .unwrap()
}

fn source_fence_wal(
    ownership_commit: ReceiptRef,
    closure: ReceiptRef,
    completion_request_digest: Digest,
) -> SourceFenceAttempt {
    SourceFenceAttempt::new(
        8,
        ownership_commit,
        closure,
        id(7_101),
        id(7_102),
        digest(92),
        JournalPosition(20),
        completion_request_digest,
    )
    .unwrap()
}

fn destination_activation_wal(
    ownership_commit: ReceiptRef,
    closure: ReceiptRef,
    source_fence: ReceiptRef,
) -> DestinationActivationAttempt {
    DestinationActivationAttempt::new(
        9,
        ownership_commit,
        closure,
        source_fence,
        id(1_009),
        id(7_201),
        id(21),
        IdempotencyKey::from_bytes([22; 16]),
        digest(15),
        id(7_202),
        digest(11),
        JournalPosition(21),
    )
    .unwrap()
}

fn mapping_manifest() -> JointMappingManifest {
    JointMappingManifest {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        key: key(),
        visa_operation_cohort_digest: digest(70),
        effect_scope: EffectScopeVersion {
            registry_instance: id(210),
            scope_id: id(211),
            scope_generation: 1,
            authority_epoch: 5,
            freeze_generation: 6,
        },
        effect_cohort_digest: digest(5),
        domain_bindings_manifest_digest: digest(71),
        ownership_service: OwnershipVersion {
            service_id: id(OWNERSHIP_ISSUER),
            service_incarnation: id(OWNERSHIP_INCARNATION),
            log_sequence: 10,
        },
        protocol_revision: 1,
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum Step {
    Receipt { command: Identity, request: Vec<u8>, envelope: Vec<u8>, payload: Vec<u8> },
    EffectAttempt { attempt: Identity, invocation: Vec<u8> },
    SourceAbortAttempt(SourceAbortAttempt),
    SourceAbortObserved { journal_position: JournalPosition, state_digest: Digest },
    SourceFenceAttempt(SourceFenceAttempt),
    SourceFenceObserved { journal_position: JournalPosition, state_digest: Digest },
    DestinationActivationAttempt(DestinationActivationAttempt),
    DestinationActivationPreviewObserved { journal_position: JournalPosition, state_digest: Digest },
}

fn effect_freeze_invocation(intent: PrepareIntentReceipt) -> EffectFreezeInvocation {
    EffectFreezeInvocation {
        key: key(),
        intent,
        registry_instance: id(210),
        scope_id: id(211),
        scope_generation: 1,
        authority_epoch: 5,
        freeze_generation: 6,
    }
}

fn encoded<T>(command: Identity, receipt: &T) -> (Vec<u8>, Vec<u8>, Vec<u8>)
where
    T: TypedReceipt + Serialize,
{
    let request = ReceiptRequest::for_receipt(command, receipt);
    let payload = canonical_bytes(receipt).unwrap();
    let header = receipt.header();
    let envelope = ReceiptEnvelope {
        schema: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        kind: T::KIND,
        handoff: receipt.key().handoff,
        request_digest: request.digest().unwrap(),
        state_sequence: header.sequence,
        payload_digest: canonical_digest(receipt).unwrap(),
        previous_receipt_digest: header.previous_digest,
        authentication: vec![0xa5, T::KIND as u8],
    };
    (canonical_bytes(&request).unwrap(), canonical_bytes(&envelope).unwrap(), payload)
}

fn receipt_step<T>(command: u128, receipt: &T) -> Step
where
    T: TypedReceipt + Serialize,
{
    let command = id(command);
    let (request, envelope, payload) = encoded(command, receipt);
    Step::Receipt { command, request, envelope, payload }
}

fn canonical_receipt_request_digest<T>(command: u128, receipt: &T) -> Digest
where
    T: TypedReceipt,
{
    ReceiptRequest::for_receipt(id(command), receipt).digest().unwrap()
}

fn full_steps() -> Vec<Step> {
    let intent = intent();
    let intent_ref = intent.receipt_ref().unwrap();
    let visa = visa_freeze(intent_ref);
    let visa_ref = visa.receipt_ref().unwrap();
    let effect = effect_freeze(intent_ref);
    let effect_ref = effect.receipt_ref().unwrap();
    let destination = destination_prepared(intent_ref, visa_ref, effect_ref);
    let destination_ref = destination.receipt_ref().unwrap();
    let prepared = ownership_prepared(intent_ref, &visa, &effect, &destination);
    let prepared_ref = prepared.receipt_ref().unwrap();
    let commit = ownership_commit(prepared_ref);
    let commit_ref = commit.receipt_ref().unwrap();
    let progress = progress(commit_ref, effect_ref);
    let progress_ref = progress.receipt_ref().unwrap();
    let closure = closure(commit_ref, effect_ref, progress_ref);
    let closure_ref = closure.receipt_ref().unwrap();
    let source_fence = source_fence(commit_ref, closure_ref, visa_ref);
    let source_fence_ref = source_fence.receipt_ref().unwrap();
    let source_fence_wal = source_fence_wal(
        commit_ref,
        closure_ref,
        canonical_receipt_request_digest(1_008, &source_fence),
    );
    let destination_activation_wal =
        destination_activation_wal(commit_ref, closure_ref, source_fence_ref);

    let mut steps = vec![
        receipt_step(1_000, &intent),
        receipt_step(1_001, &visa),
        Step::EffectAttempt {
            attempt: id(900),
            invocation: canonical_bytes(&effect_freeze_invocation(intent.clone())).unwrap(),
        },
        receipt_step(1_002, &effect),
        receipt_step(1_003, &destination),
        receipt_step(1_004, &prepared),
        receipt_step(1_005, &commit),
        receipt_step(1_006, &progress),
        receipt_step(1_007, &closure),
        Step::SourceFenceAttempt(source_fence_wal),
        Step::SourceFenceObserved {
            journal_position: source_fence.journal_position,
            state_digest: source_fence.state_digest,
        },
        receipt_step(1_008, &source_fence),
        Step::DestinationActivationAttempt(destination_activation_wal),
        Step::DestinationActivationPreviewObserved {
            journal_position: JournalPosition(23),
            state_digest: digest(21),
        },
    ];
    let mut session = empty_session();
    for step in &steps {
        apply_step(&mut session, step).unwrap();
    }
    let activation = activation(
        commit_ref,
        closure_ref,
        source_fence_ref,
        destination_ref,
        session.destination_activation_attempt_record_digest().unwrap(),
    );
    steps.push(receipt_step(1_010, &activation));
    steps
}

fn abort_steps() -> Vec<Step> {
    let commit_steps = full_steps();
    let intent = intent();
    let visa = visa_freeze(intent.receipt_ref().unwrap());
    let effect = effect_freeze(intent.receipt_ref().unwrap());
    let abort = ownership_abort(intent.receipt_ref().unwrap(), intent.intent_revision);
    let thaw = thaw(abort.receipt_ref().unwrap(), effect.receipt_ref().unwrap());
    let resume = source_resume(
        abort.receipt_ref().unwrap(),
        Some(thaw.receipt_ref().unwrap()),
        visa.receipt_ref().unwrap(),
    );
    let abort_wal = source_abort_wal(
        5,
        abort.receipt_ref().unwrap(),
        Some(thaw.receipt_ref().unwrap()),
        canonical_receipt_request_digest(2_002, &resume),
    );
    let mut steps = commit_steps[..4].to_vec();
    steps.extend([
        receipt_step(2_000, &abort),
        receipt_step(2_001, &thaw),
        Step::SourceAbortAttempt(abort_wal),
        Step::SourceAbortObserved {
            journal_position: resume.journal_position,
            state_digest: resume.state_digest,
        },
        receipt_step(2_002, &resume),
    ]);
    steps
}

fn tombstone_steps() -> Vec<Step> {
    let commit_steps = full_steps();
    let intent_ref = intent().receipt_ref().unwrap();
    let effect_ref = effect_freeze(intent_ref).receipt_ref().unwrap();
    let visa = visa_freeze(intent_ref);
    let effect = effect_freeze(intent_ref);
    let destination = destination_prepared(intent_ref, visa.receipt_ref().unwrap(), effect_ref);
    let prepared = ownership_prepared(intent_ref, &visa, &effect, &destination);
    let commit = ownership_commit(prepared.receipt_ref().unwrap());
    let retained = tombstone(commit.receipt_ref().unwrap(), effect_ref);
    let mut steps = commit_steps[..7].to_vec();
    steps.push(receipt_step(3_000, &retained));
    steps
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthError {
    Rejected,
    InvalidBytes,
}

#[derive(Clone)]
struct Authenticator {
    calls: Rc<Cell<usize>>,
    reject: bool,
}

impl Authenticator {
    fn accepting() -> Self {
        Self { calls: Rc::new(Cell::new(0)), reject: false }
    }

    fn rejecting() -> Self {
        Self { calls: Rc::new(Cell::new(0)), reject: true }
    }
}

impl NativeReceiptAuthenticator for Authenticator {
    type Error = AuthError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.reject {
            return Err(AuthError::Rejected);
        }
        if canonical_bytes(envelope).ok().as_deref() != Some(envelope_bytes)
            || payload_bytes.is_empty()
            || envelope.authentication.is_empty()
        {
            return Err(AuthError::InvalidBytes);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    DropAppend,
    LoseAppendAck,
    FailReadConfirmation,
    FailHeadConfirmation,
    Conflict,
}

#[derive(Clone, Default)]
struct MemoryLog {
    inner: Rc<RefCell<MemoryLogInner>>,
}

#[derive(Default)]
struct MemoryLogInner {
    records: Vec<JointProjectionRecord>,
    head: Option<JointProjectionLogHead>,
    fault: Option<Fault>,
    fail_next_read: bool,
    fail_next_head: bool,
}

impl MemoryLog {
    fn arm(&self, fault: Fault) {
        self.inner.borrow_mut().fault = Some(fault);
    }

    fn truncate_tail_keep_head(&self) {
        self.inner.borrow_mut().records.pop();
    }

    fn reorder_first_two(&self) {
        self.inner.borrow_mut().records.swap(0, 1);
    }

    fn append_physical_duplicate(&self) {
        let mut inner = self.inner.borrow_mut();
        let mut duplicate = inner.records.last().unwrap().clone();
        let old_head = inner.head.unwrap();
        duplicate.sequence = old_head.sequence + 1;
        duplicate.previous_record_digest = Some(old_head.record_digest);
        let record_digest = duplicate.canonical_digest().unwrap();
        inner.records.push(duplicate);
        inner.head = Some(JointProjectionLogHead {
            sequence: old_head.sequence + 1,
            record_digest,
            ..old_head
        });
    }
}

impl JointProjectionLog for MemoryLog {
    type Error = &'static str;

    fn head(&self) -> Result<Option<JointProjectionLogHead>, Self::Error> {
        let mut inner = self.inner.borrow_mut();
        if inner.fail_next_head {
            inner.fail_next_head = false;
            Err("head confirmation unavailable")
        } else {
            Ok(inner.head)
        }
    }

    fn read(&self, sequence: u64) -> Result<Option<JointProjectionRecord>, Self::Error> {
        let mut inner = self.inner.borrow_mut();
        if inner.fail_next_read {
            inner.fail_next_read = false;
            return Err("read confirmation unavailable");
        }
        let index = usize::try_from(sequence.saturating_sub(1)).map_err(|_| "bad sequence")?;
        Ok(inner.records.get(index).cloned())
    }

    fn append(
        &mut self,
        expected_head: Option<JointProjectionLogHead>,
        record: &JointProjectionRecord,
    ) -> Result<JointProjectionAppendOutcome, JointProjectionAppendError<Self::Error>> {
        let mut inner = self.inner.borrow_mut();
        let fault = inner.fault.take().unwrap_or(Fault::None);
        if fault == Fault::Conflict {
            return Err(JointProjectionAppendError::Conflict);
        }
        if fault == Fault::DropAppend {
            return Err(JointProjectionAppendError::Backend("append unavailable"));
        }
        let digest = record
            .canonical_digest()
            .map_err(|_| JointProjectionAppendError::Backend("record encoding failed"))?;
        let candidate_head = JointProjectionLogHead {
            version: JOINT_PROJECTION_LOG_VERSION,
            key: record.key,
            issuer_set_digest: record.issuer_set_digest,
            sequence: record.sequence,
            record_digest: digest,
        };
        if inner.head == expected_head {
            inner.records.push(record.clone());
            inner.head = Some(candidate_head);
            inner.fail_next_read = fault == Fault::FailReadConfirmation;
            inner.fail_next_head = fault == Fault::FailHeadConfirmation;
            if fault == Fault::LoseAppendAck {
                Err(JointProjectionAppendError::Backend("append ack lost"))
            } else {
                Ok(JointProjectionAppendOutcome::Appended)
            }
        } else if inner.head == Some(candidate_head)
            && inner.records.get(record.sequence.saturating_sub(1) as usize) == Some(record)
        {
            Ok(JointProjectionAppendOutcome::ExactReplay)
        } else {
            Err(JointProjectionAppendError::Conflict)
        }
    }
}

type Session = DurableJointSession<MemoryLog, Authenticator>;
type SessionError = DurableJointSessionError<&'static str, AuthError>;

fn empty_session() -> Session {
    Session::recover(MemoryLog::default(), Authenticator::accepting(), key(), issuers()).unwrap()
}

fn apply_step(session: &mut Session, step: &Step) -> Result<DurableRecordOutcome, SessionError> {
    match step {
        Step::Receipt { command, request, envelope, payload } => {
            session.record_native_receipt(*command, request, envelope, payload)
        }
        Step::EffectAttempt { attempt, invocation } => {
            session.record_effect_freeze_attempt(*attempt, invocation)
        }
        Step::SourceAbortAttempt(attempt) => session.begin_source_abort(*attempt),
        Step::SourceAbortObserved { journal_position, state_digest } => {
            session.record_source_abort_observed(*journal_position, *state_digest)
        }
        Step::SourceFenceAttempt(attempt) => session.begin_source_fence(*attempt),
        Step::SourceFenceObserved { journal_position, state_digest } => {
            session.record_source_fence_observed(*journal_position, *state_digest)
        }
        Step::DestinationActivationAttempt(attempt) => {
            session.begin_destination_activation(*attempt)
        }
        Step::DestinationActivationPreviewObserved { journal_position, state_digest } => {
            session.record_destination_activation_preview_observed(*journal_position, *state_digest)
        }
    }
}

fn full_log() -> MemoryLog {
    let mut session = empty_session();
    for step in full_steps() {
        assert_eq!(apply_step(&mut session, &step), Ok(DurableRecordOutcome::Appended));
    }
    session.into_parts().0
}

#[test]
fn recovery_replays_and_reauthenticates_every_intermediate_record() {
    let mut session = empty_session();
    let mut receipt_count = 0;
    for (index, step) in full_steps().iter().enumerate() {
        assert_eq!(apply_step(&mut session, step), Ok(DurableRecordOutcome::Appended));
        if matches!(step, Step::Receipt { .. }) {
            receipt_count += 1;
        }
        let expected_state = session.state().clone();
        let expected_obligation = session.effect_freeze_obligation();
        let authenticator = Authenticator::accepting();
        let calls = authenticator.calls.clone();
        let recovered = Session::recover(session.log().clone(), authenticator, key(), issuers())
            .unwrap_or_else(|error| panic!("recovery failed after step {index}: {error:?}"));
        assert_eq!(recovered.state(), &expected_state);
        assert_eq!(recovered.effect_freeze_obligation(), expected_obligation);
        assert_eq!(calls.get(), receipt_count);
    }
    assert_eq!(session.state().state().phase, JointPhase::DestinationActive);
}

#[test]
fn abort_thaw_resume_and_tombstone_branches_recover_fail_closed() {
    let mut abort_session = empty_session();
    for (index, step) in abort_steps().iter().enumerate() {
        apply_step(&mut abort_session, step).unwrap();
        let recovered = Session::recover(
            abort_session.log().clone(),
            Authenticator::accepting(),
            key(),
            issuers(),
        )
        .unwrap_or_else(|error| panic!("abort recovery failed at {index}: {error:?}"));
        assert_eq!(recovered.state(), abort_session.state());
    }
    assert_eq!(abort_session.state().state().phase, JointPhase::SourceActive);

    let mut tombstone_session = empty_session();
    for (index, step) in tombstone_steps().iter().enumerate() {
        apply_step(&mut tombstone_session, step).unwrap();
        let recovered = Session::recover(
            tombstone_session.log().clone(),
            Authenticator::accepting(),
            key(),
            issuers(),
        )
        .unwrap_or_else(|error| panic!("tombstone recovery failed at {index}: {error:?}"));
        assert_eq!(recovered.state(), tombstone_session.state());
    }
    assert_eq!(tombstone_session.state().state().phase, JointPhase::RecoveryRequired);
    let full = full_steps();
    let Step::DestinationActivationAttempt(activation_attempt) = &full[12] else {
        unreachable!();
    };
    assert!(matches!(
        tombstone_session.begin_destination_activation(*activation_attempt),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::DestinationActivationAttemptConflict
        ))
    ));
}

#[test]
fn every_append_point_survives_lost_ack_by_exact_replay() {
    let steps = full_steps();
    for fault_index in 0..steps.len() {
        let mut session = empty_session();
        for step in &steps[..fault_index] {
            apply_step(&mut session, step).unwrap();
        }
        let state_before = session.state().clone();
        session.log().arm(Fault::LoseAppendAck);
        assert_eq!(
            apply_step(&mut session, &steps[fault_index]),
            Err(DurableJointSessionError::LogAppend("append ack lost")),
            "fault index {fault_index}"
        );
        assert_eq!(session.state(), &state_before);
        assert!(session.has_indeterminate_append());
        assert_eq!(
            apply_step(&mut session, &steps[fault_index]),
            Ok(DurableRecordOutcome::ExactReplay),
            "retry index {fault_index}"
        );
        assert!(!session.has_indeterminate_append());
        Session::recover(session.log().clone(), Authenticator::accepting(), key(), issuers())
            .unwrap();
    }
}

#[test]
fn every_append_point_keeps_memory_behind_durability_across_confirmation_faults() {
    let steps = full_steps();
    for fault in [Fault::DropAppend, Fault::FailReadConfirmation, Fault::FailHeadConfirmation] {
        for fault_index in 0..steps.len() {
            let mut session = empty_session();
            for step in &steps[..fault_index] {
                apply_step(&mut session, step).unwrap();
            }
            let state_before = session.state().clone();
            session.log().arm(fault);
            assert!(matches!(
                apply_step(&mut session, &steps[fault_index]),
                Err(DurableJointSessionError::LogAppend(_))
                    | Err(DurableJointSessionError::LogRead(_))
            ));
            assert_eq!(session.state(), &state_before);
            assert!(session.has_indeterminate_append());

            let retry = apply_step(&mut session, &steps[fault_index]).unwrap();
            let expected = if fault == Fault::DropAppend {
                DurableRecordOutcome::Appended
            } else {
                DurableRecordOutcome::ExactReplay
            };
            assert_eq!(retry, expected, "fault {fault:?} at index {fault_index}");
            assert!(!session.has_indeterminate_append());
        }
    }
}

#[test]
fn recovery_rejects_truncation_reordering_and_physical_duplicates() {
    let truncated = full_log();
    truncated.truncate_tail_keep_head();
    assert!(matches!(
        Session::recover(truncated, Authenticator::accepting(), key(), issuers()),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::MissingRecord))
    ));

    let reordered = full_log();
    reordered.reorder_first_two();
    assert!(matches!(
        Session::recover(reordered, Authenticator::accepting(), key(), issuers()),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::InvalidSequence))
    ));

    let duplicated = full_log();
    duplicated.append_physical_duplicate();
    assert!(matches!(
        Session::recover(duplicated, Authenticator::accepting(), key(), issuers()),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::DuplicateRecord))
    ));
}

#[test]
fn log_conflict_poisoning_and_pending_append_conflicts_fail_closed() {
    let steps = full_steps();
    let mut conflicted = empty_session();
    conflicted.log().arm(Fault::Conflict);
    assert_eq!(apply_step(&mut conflicted, &steps[0]), Err(DurableJointSessionError::LogConflict));
    assert!(conflicted.is_poisoned());
    assert_eq!(apply_step(&mut conflicted, &steps[0]), Err(DurableJointSessionError::Poisoned));

    let mut pending = empty_session();
    pending.log().arm(Fault::LoseAppendAck);
    assert!(matches!(
        apply_step(&mut pending, &steps[0]),
        Err(DurableJointSessionError::LogAppend(_))
    ));
    assert_eq!(
        apply_step(&mut pending, &steps[1]),
        Err(DurableJointSessionError::PendingAppendConflict)
    );
    assert!(pending.has_indeterminate_append());
}

#[test]
fn crash_recovery_exposes_unknown_effect_freeze_and_blocks_abort_progress() {
    let steps = full_steps();
    let mut session = empty_session();
    for step in &steps[..3] {
        apply_step(&mut session, step).unwrap();
    }
    let log = session.into_parts().0;
    let mut recovered =
        Session::recover(log, Authenticator::accepting(), key(), issuers()).unwrap();
    let Step::EffectAttempt { attempt, invocation } = &steps[2] else {
        unreachable!();
    };
    assert_eq!(
        recovered.unresolved_effect_freeze(),
        Some(EffectFreezeAttempt::new(*attempt, invocation).unwrap())
    );

    let intent = intent();
    let abort = ownership_abort(intent.receipt_ref().unwrap(), intent.intent_revision);
    let abort_step = receipt_step(2_000, &abort);
    assert_eq!(
        apply_step(&mut recovered, &abort_step),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::EffectFreezeOutcomeUnknown
        ))
    );
    assert_eq!(apply_step(&mut recovered, &steps[1]), Ok(DurableRecordOutcome::ExactReplay));
}

#[test]
fn local_projection_attempts_are_durable_before_side_effect_and_replay_exactly() {
    let cases = [(abort_steps(), 6), (full_steps(), 9), (full_steps(), 12)];
    for (steps, attempt_index) in cases {
        let mut session = empty_session();
        for step in &steps[..attempt_index] {
            apply_step(&mut session, step).unwrap();
        }

        assert_eq!(
            apply_step(&mut session, &steps[attempt_index]),
            Ok(DurableRecordOutcome::Appended)
        );
        let recovered =
            Session::recover(session.into_parts().0, Authenticator::accepting(), key(), issuers())
                .unwrap();

        match &steps[attempt_index] {
            Step::SourceAbortAttempt(attempt) => {
                assert_eq!(recovered.source_abort_attempt(), Some(*attempt));
                assert_eq!(recovered.replay_source_abort_attempt(), Some(*attempt));
            }
            Step::SourceFenceAttempt(attempt) => {
                assert_eq!(recovered.source_fence_attempt(), Some(*attempt));
                assert_eq!(recovered.replay_source_fence_attempt(), Some(*attempt));
            }
            Step::DestinationActivationAttempt(attempt) => {
                assert_eq!(recovered.destination_activation_attempt(), Some(*attempt));
                assert_eq!(recovered.replay_destination_activation_attempt(), Some(*attempt));
                assert_eq!(
                    recovered.state().state().phase,
                    JointPhase::DestinationActivationPending
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn local_projection_attempt_retries_are_exact_or_fail_closed_on_conflict() {
    let mut abort_session = empty_session();
    let abort_steps = abort_steps();
    for step in &abort_steps[..=6] {
        apply_step(&mut abort_session, step).unwrap();
    }
    let Step::SourceAbortAttempt(abort_attempt) = &abort_steps[6] else {
        unreachable!();
    };
    assert_eq!(
        abort_session.begin_source_abort(*abort_attempt),
        Ok(DurableRecordOutcome::ExactReplay)
    );
    let mut conflicting_abort = *abort_attempt;
    conflicting_abort.resume_command = id(70_002);
    conflicting_abort.request_digest = conflicting_abort.derived_request_digest().unwrap();
    assert_eq!(
        abort_session.begin_source_abort(conflicting_abort),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::SourceAbortAttemptConflict
        ))
    );

    let full_steps = full_steps();
    let mut fence_session = empty_session();
    for step in &full_steps[..=9] {
        apply_step(&mut fence_session, step).unwrap();
    }
    let Step::SourceFenceAttempt(fence_attempt) = &full_steps[9] else {
        unreachable!();
    };
    assert_eq!(
        fence_session.begin_source_fence(*fence_attempt),
        Ok(DurableRecordOutcome::ExactReplay)
    );
    let mut conflicting_fence = *fence_attempt;
    conflicting_fence.fence_operation = id(70_102);
    conflicting_fence.request_digest = conflicting_fence.derived_request_digest().unwrap();
    assert_eq!(
        fence_session.begin_source_fence(conflicting_fence),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::SourceFenceAttemptConflict
        ))
    );

    let mut activation_session = empty_session();
    for step in &full_steps[..=12] {
        apply_step(&mut activation_session, step).unwrap();
    }
    let Step::DestinationActivationAttempt(activation_attempt) = &full_steps[12] else {
        unreachable!();
    };
    assert_eq!(
        activation_session.begin_destination_activation(*activation_attempt),
        Ok(DurableRecordOutcome::ExactReplay)
    );
    let mut conflicting_activation = *activation_attempt;
    conflicting_activation.resume_command = id(70_202);
    conflicting_activation.request_digest =
        conflicting_activation.derived_request_digest().unwrap();
    assert_eq!(
        activation_session.begin_destination_activation(conflicting_activation),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::DestinationActivationAttemptConflict
        ))
    );
}

#[test]
fn local_projection_attempt_seals_and_completion_receipts_are_bound() {
    let steps = full_steps();
    let mut session = empty_session();
    for step in &steps[..9] {
        apply_step(&mut session, step).unwrap();
    }
    let Step::SourceFenceAttempt(attempt) = &steps[9] else {
        unreachable!();
    };
    let mut attempt = *attempt;
    attempt.fence_command = id(71_001);
    assert_eq!(
        session.begin_source_fence(attempt),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::LocalAttemptRequestMismatch
        ))
    );

    let Step::SourceFenceAttempt(attempt) = &steps[9] else {
        unreachable!();
    };
    let attempt = *attempt;
    let mut wrong_completion_session = empty_session();
    for step in &steps[..9] {
        apply_step(&mut wrong_completion_session, step).unwrap();
    }
    let mut wrong_completion = attempt;
    wrong_completion.completion_request_digest = digest(98);
    wrong_completion.request_digest = wrong_completion.derived_request_digest().unwrap();
    wrong_completion_session.begin_source_fence(wrong_completion).unwrap();
    let Step::SourceFenceObserved { journal_position, state_digest } = &steps[10] else {
        unreachable!();
    };
    wrong_completion_session
        .record_source_fence_observed(*journal_position, *state_digest)
        .unwrap();
    assert_eq!(
        apply_step(&mut wrong_completion_session, &steps[11]),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::LocalAttemptRequestMismatch
        ))
    );

    session.begin_source_fence(attempt).unwrap();
    apply_step(&mut session, &steps[10]).unwrap();
    let Step::Receipt { command, request, envelope, payload } = &steps[11] else {
        unreachable!();
    };
    let mut wrong_envelope: ReceiptEnvelope =
        joint_handoff_core::canonical_from_bytes(envelope).unwrap();
    wrong_envelope.request_digest = digest(99);
    let wrong_envelope = canonical_bytes(&wrong_envelope).unwrap();
    assert_eq!(
        session.record_native_receipt(*command, request, &wrong_envelope, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::ReceiptRequestMismatch))
    );
    assert_eq!(session.replay_source_fence_attempt(), Some(attempt));
    assert_eq!(apply_step(&mut session, &steps[11]), Ok(DurableRecordOutcome::Appended));
    assert_eq!(session.replay_source_fence_attempt(), None);
    assert!(matches!(
        session.source_fence_obligation(),
        LocalProjectionObligation::ReceiptObserved { attempt: observed, .. } if observed == attempt
    ));
}

#[test]
fn local_projection_completion_without_write_ahead_attempt_is_rejected() {
    let full = full_steps();
    let mut fence_session = empty_session();
    for step in &full[..9] {
        apply_step(&mut fence_session, step).unwrap();
    }
    assert_eq!(
        apply_step(&mut fence_session, &full[10]),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::MissingSourceFenceAttempt))
    );

    let abort = abort_steps();
    let mut abort_session = empty_session();
    for step in &abort[..6] {
        apply_step(&mut abort_session, step).unwrap();
    }
    assert_eq!(
        apply_step(&mut abort_session, &abort[7]),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::MissingSourceAbortAttempt))
    );
}

#[test]
fn legacy_destination_activation_marker_fails_closed_during_recovery() {
    let issuer_set_digest = canonical_digest(&issuers()).unwrap();
    let record = JointProjectionRecord {
        version: JOINT_PROJECTION_LOG_VERSION,
        key: key(),
        issuer_set_digest,
        sequence: 1,
        previous_record_digest: None,
        kind: JointProjectionRecordKind::BeginDestinationActivation {
            command_identity: id(99_001),
        },
    };
    let mut log = MemoryLog::default();
    assert_eq!(log.append(None, &record), Ok(JointProjectionAppendOutcome::Appended));
    assert!(matches!(
        Session::recover(log, Authenticator::accepting(), key(), issuers()),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::LegacyLocalAttemptUnsupported
        ))
    ));
}

#[test]
fn effect_freeze_receipt_requires_the_exact_durable_attempt_request() {
    let steps = full_steps();
    let mut wrong_attempt_session = empty_session();
    for step in &steps[..2] {
        apply_step(&mut wrong_attempt_session, step).unwrap();
    }
    let mut wrong_invocation = effect_freeze_invocation(intent());
    wrong_invocation.scope_id = id(999);
    let wrong_invocation = canonical_bytes(&wrong_invocation).unwrap();
    wrong_attempt_session.record_effect_freeze_attempt(id(900), &wrong_invocation).unwrap();
    assert_eq!(
        apply_step(&mut wrong_attempt_session, &steps[3]),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::EffectFreezeRequestMismatch
        ))
    );

    let mut session = empty_session();
    for step in &steps[..2] {
        apply_step(&mut session, step).unwrap();
    }
    assert_eq!(
        apply_step(&mut session, &steps[3]),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::MissingEffectFreezeAttempt
        ))
    );
    apply_step(&mut session, &steps[2]).unwrap();
    let Step::EffectAttempt { invocation, .. } = &steps[2] else {
        unreachable!();
    };
    assert_eq!(
        session.record_effect_freeze_attempt(id(901), invocation),
        Err(DurableJointSessionError::Record(
            ProjectionRecordRejection::EffectFreezeAttemptConflict
        ))
    );
    let Step::Receipt { command, request, envelope, payload } = &steps[3] else {
        unreachable!();
    };
    let mut wrong_envelope: ReceiptEnvelope =
        joint_handoff_core::canonical_from_bytes(envelope).unwrap();
    wrong_envelope.request_digest = digest(99);
    let wrong_envelope = canonical_bytes(&wrong_envelope).unwrap();
    assert_eq!(
        session.record_native_receipt(*command, request, &wrong_envelope, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::ReceiptRequestMismatch))
    );
    assert!(session.unresolved_effect_freeze().is_some());
    assert_eq!(apply_step(&mut session, &steps[3]), Ok(DurableRecordOutcome::Appended));
    assert!(matches!(
        session.effect_freeze_obligation(),
        EffectFreezeObligation::ReceiptObserved { .. }
    ));
}

#[test]
fn native_receipt_exact_replay_requires_identical_raw_request_envelope_and_command() {
    let steps = full_steps();
    let mut session = empty_session();
    apply_step(&mut session, &steps[0]).unwrap();
    assert_eq!(apply_step(&mut session, &steps[0]), Ok(DurableRecordOutcome::ExactReplay));

    let Step::Receipt { command, request, envelope, payload } = &steps[0] else {
        unreachable!();
    };
    let mut changed: ReceiptEnvelope = joint_handoff_core::canonical_from_bytes(envelope).unwrap();
    changed.authentication.push(0x55);
    let changed = canonical_bytes(&changed).unwrap();
    assert_eq!(
        session.record_native_receipt(*command, request, &changed, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::ConflictingReplay))
    );
    assert_eq!(
        session.record_native_receipt(id(9_999), request, envelope, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::ReceiptRequestMismatch))
    );
}

#[test]
fn native_receipt_request_is_strictly_canonical_and_checked_before_authentication() {
    let steps = full_steps();
    let Step::Receipt { command, request, envelope, payload } = &steps[0] else {
        unreachable!();
    };
    let authenticator = Authenticator::accepting();
    let calls = authenticator.calls.clone();
    let mut session =
        Session::recover(MemoryLog::default(), authenticator, key(), issuers()).unwrap();

    let mut trailing = request.clone();
    trailing.push(0);
    assert_eq!(
        session.record_native_receipt(*command, &trailing, envelope, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::NonCanonicalRequest))
    );
    assert_eq!(calls.get(), 0);

    let mut mismatched: ReceiptRequest = joint_handoff_core::canonical_from_bytes(request).unwrap();
    mismatched.operation = id(88_001);
    let mismatched = canonical_bytes(&mismatched).unwrap();
    assert_eq!(
        session.record_native_receipt(*command, &mismatched, envelope, payload),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::ReceiptRequestMismatch))
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn recovery_rechecks_authenticator_and_issuer_pins() {
    let log = full_log();
    assert!(matches!(
        Session::recover(log.clone(), Authenticator::rejecting(), key(), issuers()),
        Err(DurableJointSessionError::Verification(ReceiptVerificationError::Authentication(
            AuthError::Rejected
        )))
    ));

    let mut wrong_issuers = issuers();
    wrong_issuers.effect_closure = issuer(500, 501, 502, 503);
    assert!(matches!(
        Session::recover(log, Authenticator::accepting(), key(), wrong_issuers),
        Err(DurableJointSessionError::Record(ProjectionRecordRejection::IssuerPinMismatch))
    ));
}

#[test]
fn bounded_record_codec_rejects_oversize_and_noncanonical_input() {
    assert_eq!(
        BoundedBytes::<2>::new(&[1, 2, 3]),
        Err(ProjectionRecordRejection::NativeBytesTooLarge)
    );
    assert_eq!(BoundedBytes::<2>::new(&[]), Err(ProjectionRecordRejection::EmptyNativeBytes));

    let log = full_log();
    let record = log.read(1).unwrap().unwrap();
    let mut encoded = record.canonical_bytes().unwrap();
    encoded.push(0);
    assert_eq!(
        JointProjectionRecord::from_canonical_bytes(&encoded),
        Err(ProjectionRecordRejection::NonCanonical)
    );

    let manifest = mapping_manifest();
    assert_ne!(canonical_digest(&manifest).unwrap(), Digest::ZERO);
}
