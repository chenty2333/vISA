extern crate std;

use contract_core::{
    Activation, ActivationRole, ActivationStatus, Digest, EntityRef, EvidenceKind, EvidenceRef,
    Generation, HandoffPhase, IdempotencyKey, Identity, JournalPosition, LeaseEpoch, NodeIdentity,
    Ownership, PreparedDestination, SnapshotRecord,
};
use joint_handoff_core::{
    ClosureStatus, JointHandoffKey, JointIssuerSet, JointPhase, JointState, OwnershipDecision,
    PrepareIntentReceipt, PreparedBindings, ReceiptEnvelope, ReceiptHeader, ReceiptIssuerIdentity,
    ReceiptKind, ReceiptRef, TypedReceipt, canonical_bytes, canonical_digest,
};

use super::*;

struct FakeSource {
    aborts: usize,
    fences: usize,
    binding: VisaRuntimeBinding,
}

impl FakeSource {
    fn running() -> Self {
        Self { aborts: 0, fences: 0, binding: source_running_binding() }
    }

    fn exported() -> Self {
        Self { aborts: 0, fences: 0, binding: source_exported_binding() }
    }

    fn frozen(state_digest: Digest) -> Self {
        let mut binding = base_runtime_binding();
        binding.phase = HandoffPhase::Frozen;
        binding.state_digest = state_digest;
        Self { aborts: 0, fences: 0, binding }
    }
}

impl VisaSourceRuntime for FakeSource {
    type Error = &'static str;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        Ok(self.binding.clone())
    }

    fn abort_and_resume(
        &mut self,
        _handoff: Identity,
        _snapshot: Option<Identity>,
        _local_freeze_recorded: bool,
        _commands: SourceAbortCommands,
        abort_evidence: EvidenceRef,
        thaw_evidence: Option<EvidenceRef>,
    ) -> Result<LocalProjection, Self::Error> {
        assert_eq!(abort_evidence.kind, EvidenceKind::AuthorityDecision);
        if let Some(thaw_evidence) = thaw_evidence {
            assert_eq!(thaw_evidence.kind, EvidenceKind::Cleanup);
        }
        self.aborts += 1;
        self.binding = source_running_binding();
        Ok(projection())
    }

    fn project_source_fence(
        &mut self,
        _command: SourceFenceCommand,
        _destination: NodeIdentity,
        _next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<LocalProjection, Self::Error> {
        assert_eq!(decision_evidence.kind, EvidenceKind::AuthorityDecision);
        assert_eq!(closure_evidence.kind, EvidenceKind::SourceFence);
        self.fences += 1;
        self.binding = source_closed_binding();
        Ok(projection())
    }
}

struct FakeDestination {
    activations: usize,
    binding: VisaRuntimeBinding,
}

impl FakeDestination {
    fn prepared() -> Self {
        Self { activations: 0, binding: destination_prepared_binding() }
    }

    fn active() -> Self {
        Self { activations: 0, binding: destination_active_binding() }
    }
}

impl VisaDestinationRuntime for FakeDestination {
    type Error = &'static str;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        Ok(self.binding.clone())
    }

    fn destination_commit_request_digest(
        &self,
        _operation: Identity,
        _idempotency: IdempotencyKey,
        _resume_guard: Identity,
    ) -> Result<Digest, Self::Error> {
        Ok(digest(90))
    }

    fn commit_for_activation(
        &mut self,
        _handoff: Identity,
        _request_digest: Digest,
        _commands: DestinationActivationCommands,
    ) -> Result<(), Self::Error> {
        self.activations += 1;
        self.binding = destination_committed_binding();
        Ok(())
    }

    fn preview_activation_resume(
        &self,
        _handoff: Identity,
        _request_digest: Digest,
        _commands: DestinationActivationCommands,
        activation_record_digest: Digest,
    ) -> Result<LocalProjection, Self::Error> {
        Ok(destination_projection(activation_record_digest))
    }

    fn resume_after_activation_receipt(
        &mut self,
        _handoff: Identity,
        _request_digest: Digest,
        _commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: LocalProjection,
    ) -> Result<LocalProjection, Self::Error> {
        assert_eq!(expected, destination_projection(activation_record_digest));
        self.binding = destination_active_binding();
        Ok(expected)
    }
}

fn projection() -> LocalProjection {
    LocalProjection {
        journal_position: JournalPosition(9),
        state_digest: digest(9),
        authorization_record_digest: None,
    }
}

fn destination_projection(activation_record_digest: Digest) -> LocalProjection {
    LocalProjection { authorization_record_digest: Some(activation_record_digest), ..projection() }
}

fn prepared_bindings() -> PreparedBindings {
    PreparedBindings {
        prepare_intent_receipt_digest: digest(10),
        visa_freeze_receipt_digest: digest(11),
        effect_freeze_receipt_digest: digest(12),
        snapshot: identity(500),
        snapshot_integrity_digest: digest(13),
        source_journal_position: JournalPosition(6),
        source_state_digest: digest(14),
        component_digest: digest(15),
        profile_digest: digest(16),
        destination_prepared_receipt_digest: digest(17),
        destination_state_digest: digest(18),
        prepared_authorities_digest: digest(19),
        prepared_bindings_digest: digest(20),
        effect_cohort_manifest_digest: digest(21),
        joint_mapping_manifest_digest: digest(22),
    }
}

fn base_runtime_binding() -> VisaRuntimeBinding {
    let key = state().key;
    VisaRuntimeBinding {
        component: key.continuity_unit,
        component_digest: prepared_bindings().component_digest,
        profile_digest: prepared_bindings().profile_digest,
        phase: HandoffPhase::Running,
        activation: Activation {
            node: key.source,
            role: ActivationRole::Source,
            status: ActivationStatus::Active,
        },
        ownership: Ownership::owned(key.source, key.expected_epoch),
        exported_snapshot: None,
        prepared_destination: None,
        journal_position: JournalPosition(0),
        state_digest: digest(9),
    }
}

fn source_running_binding() -> VisaRuntimeBinding {
    base_runtime_binding()
}

fn source_exported_binding() -> VisaRuntimeBinding {
    let key = state().key;
    VisaRuntimeBinding {
        phase: HandoffPhase::Exported,
        exported_snapshot: Some(SnapshotRecord {
            handoff: key.handoff,
            snapshot: prepared_bindings().snapshot,
            journal_position: prepared_bindings().source_journal_position,
            evidence: EvidenceRef {
                identity: identity(501),
                kind: EvidenceKind::SnapshotIntegrity,
                digest: digest(23),
            },
        }),
        journal_position: prepared_bindings().source_journal_position,
        ..base_runtime_binding()
    }
}

fn source_closed_binding() -> VisaRuntimeBinding {
    let key = state().key;
    VisaRuntimeBinding {
        phase: HandoffPhase::Committed,
        activation: Activation {
            node: key.source,
            role: ActivationRole::Source,
            status: ActivationStatus::Fenced,
        },
        ownership: Ownership::owned(key.destination, key.next_epoch),
        ..source_exported_binding()
    }
}

fn destination_prepared_binding() -> VisaRuntimeBinding {
    let key = state().key;
    let destination_generation = Generation(key.continuity_unit.generation.0 + 1);
    VisaRuntimeBinding {
        phase: HandoffPhase::DestinationPrepared,
        activation: Activation {
            node: key.destination,
            role: ActivationRole::Destination,
            status: ActivationStatus::Prepared,
        },
        prepared_destination: Some(PreparedDestination {
            handoff: key.handoff,
            snapshot: prepared_bindings().snapshot,
            destination: key.destination,
            component_generation: destination_generation,
            expected_epoch: key.expected_epoch,
            next_epoch: key.next_epoch,
            authorities: std::vec![],
            bindings: std::vec![],
        }),
        state_digest: prepared_bindings().destination_state_digest,
        ..base_runtime_binding()
    }
}

fn destination_active_binding() -> VisaRuntimeBinding {
    let key = state().key;
    let component = EntityRef::new(
        key.continuity_unit.identity,
        Generation(key.continuity_unit.generation.0 + 1),
    );
    VisaRuntimeBinding {
        component,
        phase: HandoffPhase::Running,
        activation: Activation {
            node: key.destination,
            role: ActivationRole::Destination,
            status: ActivationStatus::Active,
        },
        ownership: Ownership::owned(key.destination, key.next_epoch),
        ..destination_prepared_binding()
    }
}

fn destination_committed_binding() -> VisaRuntimeBinding {
    VisaRuntimeBinding { phase: HandoffPhase::Committed, ..destination_active_binding() }
}

fn identity(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn receipt(kind: ReceiptKind, value: u8) -> ReceiptRef {
    ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: identity(10),
        issuer: identity(20 + u128::from(value)),
        issuer_incarnation: identity(30 + u128::from(value)),
        key_id: identity(35 + u128::from(value)),
        log_id: identity(40 + u128::from(value)),
        sequence: u64::from(value),
        digest: digest(value),
    }
}

fn state() -> JointState {
    JointState::new(JointHandoffKey {
        continuity_unit: EntityRef::new(identity(1), Generation::INITIAL),
        handoff: identity(10),
        source: NodeIdentity::new(identity(2)),
        destination: NodeIdentity::new(identity(3)),
        expected_epoch: LeaseEpoch(4),
        next_epoch: LeaseEpoch(5),
    })
    .unwrap()
}

fn issuer_identity(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: identity(base),
        issuer_incarnation: identity(base + 1),
        key_id: identity(base + 2),
        log_id: identity(base + 3),
    }
}

fn issuers() -> JointIssuerSet {
    JointIssuerSet {
        ownership: issuer_identity(100),
        visa_source: issuer_identity(200),
        visa_destination: issuer_identity(300),
        effect_closure: issuer_identity(400),
    }
}

fn verified_state(state: JointState) -> VerifiedJointState {
    VerifiedJointState::from_replayed_for_test(state, issuers(), None)
}

fn verified_destination_state(
    state: JointState,
    operation: Identity,
    idempotency: IdempotencyKey,
) -> VerifiedJointState {
    VerifiedJointState::from_replayed_for_test(
        state,
        issuers(),
        Some(VerifiedDestinationCommit { operation, idempotency, request_digest: digest(90) }),
    )
}

fn intent_receipt() -> PrepareIntentReceipt {
    PrepareIntentReceipt {
        header: ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::PrepareIntent,
            issuer: identity(100),
            issuer_incarnation: identity(101),
            key_id: identity(102),
            log_id: identity(103),
            sequence: 1,
            previous_digest: None,
        },
        key: state().key,
        ownership_service: identity(100),
        service_incarnation: identity(101),
        reservation: identity(104),
        intent_revision: 1,
        request_digest: digest(10),
    }
}

fn encoded_intent(
    receipt: &PrepareIntentReceipt,
    authentication: std::vec::Vec<u8>,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let payload = canonical_bytes(receipt).unwrap();
    let envelope = ReceiptEnvelope {
        schema: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        issuer: receipt.header.issuer,
        issuer_incarnation: receipt.header.issuer_incarnation,
        kind: ReceiptKind::PrepareIntent,
        handoff: receipt.key.handoff,
        request_digest: receipt.request_digest,
        state_sequence: receipt.header.sequence,
        payload_digest: canonical_digest(receipt).unwrap(),
        previous_receipt_digest: receipt.header.previous_digest,
        authentication,
    };
    (canonical_bytes(&envelope).unwrap(), payload)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthError {
    Rejected,
    NonCanonicalInput,
}

struct ExactAuthenticator {
    reject: bool,
}

impl NativeReceiptAuthenticator for ExactAuthenticator {
    type Error = AuthError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        if self.reject {
            return Err(AuthError::Rejected);
        }
        if canonical_bytes(envelope).ok().as_deref() != Some(envelope_bytes)
            || payload_bytes.is_empty()
            || envelope.authentication != [0xa5, 0x5a]
        {
            return Err(AuthError::NonCanonicalInput);
        }
        Ok(())
    }
}

fn abort_state() -> JointState {
    let mut state = state();
    state.revision = 1;
    state.phase = JointPhase::SourceThawPending;
    state.decision = OwnershipDecision::Abort(receipt(ReceiptKind::OwnershipAbort, 5));
    state.nexus_freeze = Some(receipt(ReceiptKind::NexusFreeze, 4));
    state.thaw = Some(receipt(ReceiptKind::NexusThaw, 6));
    state
}

fn early_abort_state() -> JointState {
    let mut state = state();
    state.revision = 1;
    state.phase = JointPhase::AbortDecided;
    state.decision = OwnershipDecision::Abort(receipt(ReceiptKind::OwnershipAbort, 5));
    state
}

fn closed_state() -> JointState {
    let mut state = state();
    state.revision = 1;
    state.phase = JointPhase::SourceClosed;
    state.decision = OwnershipDecision::Commit(receipt(ReceiptKind::OwnershipCommit, 7));
    state.closure =
        ClosureStatus::Closed { receipt: receipt(ReceiptKind::Closure, 8), revision: 8 };
    state.pending_bindings = Some(prepared_bindings());
    state
}

#[test]
fn canonical_authenticated_receipt_is_the_only_path_to_a_verified_token() {
    let receipt = intent_receipt();
    let (envelope, payload) = encoded_intent(&receipt, std::vec![0xa5, 0x5a]);
    let verified = verify_native_receipt::<PrepareIntentReceipt, _>(
        &envelope,
        &payload,
        &ExactAuthenticator { reject: false },
    )
    .unwrap();
    assert_eq!(verified.receipt(), &receipt);
    assert_eq!(verified.receipt_ref(), receipt.receipt_ref().unwrap());
}

#[test]
fn authentication_failure_missing_authentication_and_envelope_mismatch_fail_closed() {
    let receipt = intent_receipt();
    let (envelope, payload) = encoded_intent(&receipt, std::vec![0xa5, 0x5a]);
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &envelope,
            &payload,
            &ExactAuthenticator { reject: true },
        ),
        Err(ReceiptVerificationError::Authentication(AuthError::Rejected))
    ));

    let (missing, payload) = encoded_intent(&receipt, std::vec![]);
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &missing,
            &payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::MissingAuthentication)
    ));

    let envelope_value: ReceiptEnvelope =
        joint_handoff_core::canonical_from_bytes(&envelope).unwrap();
    let mut mismatched = envelope_value;
    mismatched.payload_digest = digest(99);
    let mismatched = canonical_bytes(&mismatched).unwrap();
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &mismatched,
            &payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::EnvelopeMismatch)
    ));
}

#[test]
fn noncanonical_and_malformed_envelope_or_payload_are_distinguished() {
    let receipt = intent_receipt();
    let (envelope, payload) = encoded_intent(&receipt, std::vec![0xa5, 0x5a]);

    let mut trailing_envelope = envelope.clone();
    trailing_envelope.push(0);
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &trailing_envelope,
            &payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::NonCanonicalEnvelope)
    ));

    let mut trailing_payload = payload.clone();
    trailing_payload.push(0);
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &envelope,
            &trailing_payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::NonCanonicalPayload)
    ));

    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &[0xff],
            &payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::EnvelopeDecode)
    ));
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &envelope,
            &[0xff],
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::PayloadDecode)
    ));
}

#[test]
fn structurally_invalid_typed_header_cannot_be_authenticated_into_a_token() {
    let mut receipt = intent_receipt();
    receipt.header.sequence = 0;
    receipt.intent_revision = 1;
    let (envelope, payload) = encoded_intent(&receipt, std::vec![0xa5, 0x5a]);
    assert!(matches!(
        verify_native_receipt::<PrepareIntentReceipt, _>(
            &envelope,
            &payload,
            &ExactAuthenticator { reject: false },
        ),
        Err(ReceiptVerificationError::InvalidReference)
    ));
}

#[test]
fn record_verified_receipt_records_exact_digest_and_replays_idempotently() {
    let receipt = intent_receipt();
    let (envelope, payload) = encoded_intent(&receipt, std::vec![0xa5, 0x5a]);
    let verified = verify_native_receipt::<PrepareIntentReceipt, _>(
        &envelope,
        &payload,
        &ExactAuthenticator { reject: false },
    )
    .unwrap();
    let initial = VerifiedJointState::new(state().key, issuers()).unwrap();
    let recorded = record_verified_receipt(&initial, identity(500), &verified).unwrap();
    assert_eq!(recorded.state().phase, JointPhase::PrepareIntent);
    assert_eq!(recorded.state().intent, Some(verified.receipt_ref()));
    assert_eq!(recorded.state().revision, 1);

    let replay = record_verified_receipt(&recorded, identity(500), &verified).unwrap();
    assert_eq!(replay, recorded);

    let mut different = state();
    different.key.handoff = identity(999);
    let different = verified_state(different);
    assert!(matches!(
        record_verified_receipt(&different, identity(501), &verified),
        Err(ReceiptRecordError::Rejected(joint_handoff_core::Rejection::HandoffMismatch))
    ));

    let mut wrong_issuers = issuers();
    wrong_issuers.ownership = issuer_identity(500);
    let wrong_issuer_state = VerifiedJointState::new(state().key, wrong_issuers).unwrap();
    assert_eq!(
        record_verified_receipt(&wrong_issuer_state, identity(502), &verified),
        Err(ReceiptRecordError::WrongIssuerRole)
    );

    let mut duplicate_issuers = issuers();
    duplicate_issuers.effect_closure = duplicate_issuers.ownership;
    assert_eq!(
        VerifiedJointState::new(state().key, duplicate_issuers),
        Err(joint_handoff_core::Rejection::InvalidIdentity)
    );
}

#[test]
fn source_abort_requires_exact_abort_and_thaw_state() {
    let mut source = JointSource::new(FakeSource::running());
    let commands = SourceAbortCommands { abort: identity(50), resume: identity(51) };
    assert_eq!(
        source.project_abort(&verified_state(state()), commands),
        Err(ProjectionError::InvalidJointPhase { actual: JointPhase::SourceOwned })
    );
    assert_eq!(source.project_abort(&verified_state(abort_state()), commands), Ok(projection()));
    assert_eq!(
        source.project_abort(&verified_state(early_abort_state()), commands),
        Ok(projection())
    );

    let mut unknown_effect_freeze = early_abort_state();
    unknown_effect_freeze.visa_freeze = Some(receipt(ReceiptKind::VisaFreeze, 4));
    unknown_effect_freeze.source_state_digest = Some(digest(24));
    let mut frozen_source = JointSource::new(FakeSource::frozen(digest(24)));
    assert_eq!(
        frozen_source.project_abort(&verified_state(unknown_effect_freeze), commands),
        Err(ProjectionError::EffectFreezeOutcomeUnknown)
    );

    let mut exported_abort = abort_state();
    exported_abort.visa_freeze = Some(receipt(ReceiptKind::VisaFreeze, 4));
    exported_abort.source_journal_position = Some(prepared_bindings().source_journal_position);
    let mut exported_source = JointSource::new(FakeSource::exported());
    assert_eq!(
        exported_source.project_abort(&verified_state(exported_abort), commands),
        Ok(projection())
    );
}

#[test]
fn destination_cannot_activate_before_source_fence_projection() {
    let commands = DestinationActivationCommands {
        commit_command: identity(60),
        commit_operation: identity(61),
        commit_idempotency: IdempotencyKey::from_u128(62),
        resume_command: identity(63),
    };
    let mut destination = JointDestination::new(FakeDestination::prepared());
    let mut state = closed_state();
    state.phase = JointPhase::DestinationActivationPending;
    assert_eq!(
        destination.project_activation(&verified_state(state.clone()), commands, digest(200)),
        Err(ProjectionError::InvalidJointPhase {
            actual: JointPhase::DestinationActivationPending,
        })
    );
    state.source_fence = Some(receipt(ReceiptKind::VisaSourceFence, 9));
    let verified =
        verified_destination_state(state, commands.commit_operation, commands.commit_idempotency);
    assert_eq!(
        destination.project_activation(&verified, commands, digest(200)),
        Ok(destination_projection(digest(200)))
    );
    assert_eq!(
        destination.project_activation(&verified, commands, digest(200)),
        Ok(destination_projection(digest(200)))
    );
}

#[test]
fn activation_attempt_can_only_be_derived_from_verified_terminal_receipts() {
    let mut closed = closed_state();
    closed.source_fence = Some(receipt(ReceiptKind::VisaSourceFence, 9));
    let verified = verified_state(closed);

    let pending = verified.begin_destination_activation(identity(64)).unwrap();
    assert_eq!(pending.state().phase, JointPhase::DestinationActivationPending);
    assert_eq!(pending.state().decision, verified.state().decision);
    assert_eq!(pending.state().closure, verified.state().closure);
    assert_eq!(pending.begin_destination_activation(identity(64)).unwrap(), pending);
    assert!(matches!(
        pending.begin_destination_activation(identity(65)),
        Err(ReceiptRecordError::Rejected(joint_handoff_core::Rejection::ConflictingReceipt))
    ));

    assert!(matches!(
        VerifiedJointState::new(state().key, issuers())
            .unwrap()
            .begin_destination_activation(identity(66)),
        Err(ReceiptRecordError::Rejected(joint_handoff_core::Rejection::MissingPrerequisite))
    ));
}

#[test]
fn source_fence_rejects_duplicate_command_identities() {
    let mut source = JointSource::new(FakeSource::exported());
    let command = SourceFenceCommand { command: identity(70), operation: identity(70) };
    assert_eq!(
        source.project_commit_fence(&verified_state(closed_state()), command),
        Err(ProjectionError::InvalidCommand)
    );
}

#[test]
fn source_projection_rejects_a_different_component_generation() {
    let mut runtime = FakeSource::exported();
    runtime.binding.component.generation = Generation(1);
    let mut source = JointSource::new(runtime);
    assert_eq!(
        source.project_commit_fence(
            &verified_state(closed_state()),
            SourceFenceCommand { command: identity(70), operation: identity(71) },
        ),
        Err(ProjectionError::ReceiptMismatch)
    );
}

#[test]
fn projection_rejects_wrong_receipt_kind_handoff_and_unreplayed_state() {
    let mut source = JointSource::new(FakeSource::exported());
    let command = SourceFenceCommand { command: identity(70), operation: identity(71) };

    let mut wrong_kind = closed_state();
    wrong_kind.closure =
        ClosureStatus::Closed { receipt: receipt(ReceiptKind::NexusThaw, 8), revision: 8 };
    assert_eq!(
        source.project_commit_fence(&verified_state(wrong_kind), command),
        Err(ProjectionError::ReceiptMismatch)
    );

    let mut wrong_handoff = closed_state();
    let ClosureStatus::Closed { receipt: mut closure, revision } = wrong_handoff.closure else {
        unreachable!();
    };
    closure.handoff = identity(999);
    wrong_handoff.closure = ClosureStatus::Closed { receipt: closure, revision };
    assert_eq!(
        source.project_commit_fence(&verified_state(wrong_handoff), command),
        Err(ProjectionError::ReceiptMismatch)
    );

    let mut unreplayed = closed_state();
    unreplayed.revision = 0;
    assert_eq!(
        source.project_commit_fence(&verified_state(unreplayed), command),
        Err(ProjectionError::ReceiptMismatch)
    );
}

#[test]
fn destination_projection_rejects_wrong_source_fence_and_zero_idempotency() {
    let mut state = closed_state();
    state.phase = JointPhase::DestinationActivationPending;
    state.source_fence = Some(receipt(ReceiptKind::NexusThaw, 9));
    let commands = DestinationActivationCommands {
        commit_command: identity(80),
        commit_operation: identity(81),
        commit_idempotency: IdempotencyKey::from_u128(82),
        resume_command: identity(83),
    };
    let mut destination = JointDestination::new(FakeDestination::prepared());
    assert_eq!(
        destination.project_activation(&verified_state(state.clone()), commands, digest(200)),
        Err(ProjectionError::ReceiptMismatch)
    );

    state.source_fence = Some(receipt(ReceiptKind::VisaSourceFence, 9));
    let wrong_binding =
        verified_destination_state(state.clone(), identity(999), commands.commit_idempotency);
    assert_eq!(
        destination.project_activation(&wrong_binding, commands, digest(200)),
        Err(ProjectionError::ReceiptMismatch)
    );
    let zero = DestinationActivationCommands {
        commit_idempotency: IdempotencyKey::from_u128(0),
        ..commands
    };
    assert_eq!(
        destination.project_activation(&verified_state(state), zero, digest(200)),
        Err(ProjectionError::InvalidCommand)
    );
}

#[test]
fn destination_prepared_projection_rejects_state_digest_drift() {
    let mut state = closed_state();
    state.phase = JointPhase::DestinationActivationPending;
    state.source_fence = Some(receipt(ReceiptKind::VisaSourceFence, 9));
    let commands = DestinationActivationCommands {
        commit_command: identity(80),
        commit_operation: identity(81),
        commit_idempotency: IdempotencyKey::from_u128(82),
        resume_command: identity(83),
    };
    let mut runtime = FakeDestination::prepared();
    runtime.binding.state_digest = digest(99);
    let mut destination = JointDestination::new(runtime);
    assert_eq!(
        destination.project_activation(
            &verified_destination_state(
                state,
                commands.commit_operation,
                commands.commit_idempotency,
            ),
            commands,
            digest(200),
        ),
        Err(ProjectionError::ReceiptMismatch)
    );
}

#[test]
fn runtime_handles_release_only_after_exact_terminal_projection_receipts() {
    let mut source_state = early_abort_state();
    source_state.phase = JointPhase::SourceActive;
    source_state.source_resume = Some(receipt(ReceiptKind::VisaSourceResume, 6));
    assert!(
        JointSource::new(FakeSource::running())
            .into_source_active(&verified_state(source_state))
            .is_ok()
    );

    let mut destination_state = closed_state();
    destination_state.phase = JointPhase::DestinationActive;
    destination_state.source_fence = Some(receipt(ReceiptKind::VisaSourceFence, 9));
    destination_state.destination_activation =
        Some(receipt(ReceiptKind::VisaDestinationActivation, 10));
    assert!(
        JointDestination::new(FakeDestination::active())
            .into_active(&verified_state(destination_state.clone()))
            .is_ok()
    );

    destination_state.destination_activation = Some(receipt(ReceiptKind::NexusThaw, 10));
    assert!(matches!(
        JointDestination::new(FakeDestination::active())
            .into_active(&verified_state(destination_state)),
        Err(ProjectionError::ReceiptMismatch)
    ));
}
