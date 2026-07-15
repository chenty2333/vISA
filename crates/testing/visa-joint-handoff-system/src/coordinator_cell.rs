use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::{
    ActivationStatus, AuthorityGrant, CONTRACT_VERSION, CanonicalState, DeliveryPolicy, Digest,
    EntityRef, EvidenceKind, EvidenceRef, Generation, HandoffPhase, IdempotencyKey, Identity,
    JournalEntry, KeyValueClaim, LeaseEpoch, NodeIdentity, ResourceClaims, Rights,
    SnapshotEnvelope, TimerClaim, TimerClock, canonical_digest as contract_digest,
};
use joint_handoff_core::{
    DestinationPreparedReceipt, EffectScopeVersion, JointHandoffKey, JointIssuerSet,
    JointMappingManifest, OwnershipVersion, PreparedBindings, ReceiptEnvelope, ReceiptHeader,
    ReceiptIssuerIdentity, ReceiptKind, ReceiptRequest, SnapshotBinding, TypedReceipt,
    VisaDestinationActivationReceipt, VisaFreezeReceipt, VisaSourceFenceReceipt,
    VisaSourceResumeReceipt, canonical_bytes as joint_bytes, canonical_digest as joint_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use substrate_api::{AuthorityPolicy, AuthorityPort, JournalPort, JournalScope, LeasePort};
use substrate_host::SqliteProvider;
use visa_joint_handoff::{
    DestinationActivationAttempt, DurableDestinationGuard, DurableJointSession,
    DurableJointSessionError, DurableProjectionDriver, JointProjectionLog, JointSource,
    NativeReceiptAuthenticator, SourceAbortAttempt, SourceFenceAttempt, VerifiedCommandReceipt,
};
use visa_runtime::{AuthorityPlan, Coordinator, SnapshotExpectations, validate_snapshot};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectPeerConfig,
    EffectThawRequest, LostAckProjectionLog, LostAckProjectionLogError, OwnershipAbortRequest,
    OwnershipCommitRequest, OwnershipReserveRequest, OwnershipSealRequest, ReferenceEffectPeer,
    ReferenceOwnershipLog, SqliteJointProjectionLog, effect_receipt_issuer,
    ownership_receipt_issuer,
};

const AUTHENTICATION_DOMAIN: &[u8] =
    b"vISA/joint-handoff/coordinator-cell/authentication/v1/same-boot-only\0";
pub const HOST_SUBSTRATE_CELL_SCHEMA: &str = "visa.joint-handoff.host-substrate-cell.v2";
pub const HOST_SUBSTRATE_AUTHENTICATION_SCHEME: &str =
    "visa-host-substrate-cell-sha256-v1-same-boot-reference-only";
const INITIAL_EPOCH: LeaseEpoch = LeaseEpoch(1);
static NEXT_CELL: AtomicU64 = AtomicU64::new(1);

type HostJointLog = LostAckProjectionLog<SqliteJointProjectionLog>;
type HostJointSession = DurableJointSession<HostJointLog, CellAuthenticator>;
type EncodedNativeMaterial = (Vec<u8>, Vec<u8>, Vec<u8>, HostNativeReceiptMaterial);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNativeReceiptMaterial {
    pub kind: String,
    /// Canonical typed request used only for receipt issuance/authentication.
    pub issuance_request: Vec<u8>,
    /// Canonical request bytes actually passed to an ownership/effect peer.
    /// Local vISA projection receipts have no peer invocation.
    pub peer_invocation: Option<Vec<u8>>,
    pub envelope: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLeaseRecordMaterial {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJointProjectionTranscript {
    pub head: visa_joint_handoff::JointProjectionLogHead,
    pub canonical_record_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProjectionWindowObservation {
    pub conflict_head_before: visa_joint_handoff::JointProjectionLogHead,
    pub conflict_head_after: visa_joint_handoff::JointProjectionLogHead,
    pub attempt_head: visa_joint_handoff::JointProjectionLogHead,
    pub reopened_attempt_head: visa_joint_handoff::JointProjectionLogHead,
    pub completion_head: visa_joint_handoff::JointProjectionLogHead,
    pub reopened_completion_head: visa_joint_handoff::JointProjectionLogHead,
    pub local_before_position: contract_core::JournalPosition,
    pub local_before_digest: Digest,
    pub local_after_position: contract_core::JournalPosition,
    pub local_after_digest: Digest,
    pub reopened_local_after_position: contract_core::JournalPosition,
    pub reopened_local_after_digest: Digest,
    pub conflicts_left_local_unchanged: bool,
    pub completion_append_ack_lost: bool,
    pub exposure_blocked_before_completion: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAbortProjectionEvidence {
    pub transcript: HostJointProjectionTranscript,
    pub observation: HostProjectionWindowObservation,
    pub issuer_set: JointIssuerSet,
    pub authentication_key: [u8; 32],
    pub native_receipts: Vec<HostNativeReceiptMaterial>,
    pub initial_state: CanonicalState,
    pub terminal_state: CanonicalState,
    pub journal: Vec<JournalEntry>,
    pub leases: Vec<HostLeaseRecordMaterial>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDurableProjectionEvidence {
    pub commit_transcript: HostJointProjectionTranscript,
    pub source_abort: HostAbortProjectionEvidence,
    pub source_fence: HostProjectionWindowObservation,
    pub destination_activation: HostProjectionWindowObservation,
    pub destination_checkpoint: HostDestinationActivationCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDestinationActivationCheckpoint {
    pub joint_completion_head: visa_joint_handoff::JointProjectionLogHead,
    pub activation_completion_record_digest: Digest,
    pub local_state: CanonicalState,
    pub local_journal: Vec<JournalEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorVerticalCellReport {
    pub schema: String,
    pub lifecycle: Vec<String>,
    pub receipt_chain: Vec<String>,
    pub authenticated_receipt_count: usize,
    pub joint_phase: String,
    pub source_reopened: bool,
    pub source_phase: String,
    pub source_activation: String,
    pub source_owner_is_destination: bool,
    pub destination_phase: String,
    pub destination_activation: String,
    pub destination_owner_is_destination: bool,
    pub source_component_generation: u64,
    pub destination_component_generation: u64,
    pub source_journal_position: contract_core::JournalPosition,
    pub destination_journal_position: contract_core::JournalPosition,
    pub source_state_digest: Digest,
    pub destination_state_digest: Digest,
    pub snapshot_integrity: Digest,
    pub prepared_destination_digest: Digest,
    pub lease_commit_request_digest: Digest,
    pub independent_source_destination_databases: bool,
    pub same_boot_only: bool,
    pub exclusive_trusted_coordinator_api: bool,
    pub authentication_scheme: String,
    pub authentication_key: [u8; 32],
    pub native_receipts: Vec<HostNativeReceiptMaterial>,
    pub source_initial_state: CanonicalState,
    pub snapshot: SnapshotEnvelope,
    pub snapshot_cursor: contract_core::JournalPosition,
    pub destination_restored_state: CanonicalState,
    pub source_terminal_state: CanonicalState,
    pub destination_terminal_state: CanonicalState,
    pub source_journal: Vec<JournalEntry>,
    pub destination_journal: Vec<JournalEntry>,
    pub source_leases: Vec<HostLeaseRecordMaterial>,
    pub destination_leases: Vec<HostLeaseRecordMaterial>,
    pub durable_projection: HostDurableProjectionEvidence,
}

pub fn run_coordinator_vertical_cell() -> Result<CoordinatorVerticalCellReport, String> {
    let source_abort_evidence = run_source_abort_recovery_probe()?;
    let paths = CellPaths::new()?;
    let fixture = Fixture::new();
    let initial = fixture.initial_state();

    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    source.activate(id(100), fixture.source_handoff_authority, INITIAL_EPOCH).map_err(debug)?;

    let key = JointHandoffKey {
        continuity_unit: fixture.source_component,
        handoff: fixture.handoff,
        source: fixture.source_node,
        destination: fixture.destination_node,
        expected_epoch: INITIAL_EPOCH,
        next_epoch: INITIAL_EPOCH.next().ok_or("lease epoch exhausted")?,
    };
    let ownership_namespace = issuer(1_000);
    let effect_namespace = issuer(1_100);
    let ownership_issuer = ownership_receipt_issuer(ownership_namespace, key).map_err(debug)?;
    let effect_issuer = effect_receipt_issuer(effect_namespace, key).map_err(debug)?;
    let issuers = JointIssuerSet {
        ownership: ownership_issuer,
        visa_source: issuer(1_200),
        visa_destination: issuer(1_300),
        effect_closure: effect_issuer,
    };
    let authenticator = CellAuthenticator { key, issuers, secret: [0x5a; 32] };

    let mut ownership =
        ReferenceOwnershipLog::open(&paths.ownership, ownership_namespace).map_err(debug)?;
    ownership
        .initialize_unit(key.continuity_unit, key.source, key.expected_epoch)
        .map_err(debug)?;
    let projection_log =
        HostJointLog::new(SqliteJointProjectionLog::open(&paths.projection).map_err(debug)?);
    let mut joint =
        DurableJointSession::recover(projection_log, authenticator.clone(), key, issuers)
            .map_err(debug)?;
    let mut native_receipts = Vec::new();
    let mut receipt_count = 0_usize;

    let reserve_invocation = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_invocation_bytes = joint_bytes(&reserve_invocation).map_err(debug)?;
    let intent = ownership.reserve(reserve_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &intent,
        id(200),
        &authenticator,
        &mut native_receipts,
        reserve_invocation_bytes,
    )?;
    receipt_count += 1;
    let intent_ref = intent.receipt_ref().map_err(debug)?;

    source.begin_quiesce(id(101), fixture.source_handoff_authority).map_err(debug)?;
    let safe_point = source.prepare_safe_point().map_err(debug)?;
    source
        .commit_safe_point(id(102), b"coordinator-vertical-state".to_vec(), safe_point)
        .map_err(debug)?;
    let (_, snapshot) = source
        .export_snapshot(
            id(103),
            fixture.handoff,
            fixture.snapshot,
            EvidenceRef {
                identity: id(104),
                kind: EvidenceKind::SnapshotIntegrity,
                digest: source.state_digest().map_err(debug)?,
            },
        )
        .map_err(debug)?;
    require(source.state().phase == HandoffPhase::Exported, "source did not export")?;
    let visa_freeze = VisaFreezeReceipt {
        header: header(issuers.visa_source, ReceiptKind::VisaFreeze, 1, None),
        key,
        intent: intent_ref,
        journal_position: snapshot.body.snapshot.journal_position,
        state_digest: source.state_digest().map_err(debug)?,
        portable_state_digest: contract_digest(&snapshot.body.portable_state).map_err(debug)?,
    };
    let visa_freeze_ref = visa_freeze.receipt_ref().map_err(debug)?;
    record(&mut joint, &visa_freeze, id(201), &authenticator, &mut native_receipts)?;
    receipt_count += 1;

    let effect_config = EffectPeerConfig {
        key,
        issuer: effect_issuer,
        ownership_issuer,
        registry_instance: id(1_400),
        scope_id: id(1_401),
        scope_generation: 1,
        authority_epoch: 1,
        freeze_generation: 1,
        domain_bindings_digest: digest(40),
    };
    let effect_peer = ReferenceEffectPeer::new(effect_config).map_err(debug)?;
    let effect_freeze_invocation = EffectFreezeRequest {
        key,
        intent: intent.clone(),
        registry_instance: effect_config.registry_instance,
        scope_id: effect_config.scope_id,
        scope_generation: effect_config.scope_generation,
        authority_epoch: effect_config.authority_epoch,
        freeze_generation: effect_config.freeze_generation,
    };
    let effect_freeze_invocation_bytes = joint_bytes(&effect_freeze_invocation).map_err(debug)?;
    joint
        .record_effect_freeze_attempt(id(2_202), &effect_freeze_invocation_bytes)
        .map_err(debug)?;
    let frozen = effect_peer.freeze(effect_freeze_invocation.clone()).map_err(debug)?;
    let effect_freeze_ref = frozen.receipt.receipt_ref().map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &frozen.receipt,
        id(202),
        &authenticator,
        &mut native_receipts,
        effect_freeze_invocation_bytes,
    )?;
    receipt_count += 1;

    fixture.seed_destination_ownership(&paths.destination, &initial)?;
    let destination_provider = fixture.destination_provider(&paths.destination)?;
    let validated = validate_snapshot(
        &snapshot,
        &SnapshotExpectations {
            component_digest: fixture.component_digest,
            profile_digest: fixture.profile_digest,
            profile_version: CONTRACT_VERSION,
            supported_extensions: Vec::new(),
            destination: fixture.destination_node,
        },
    )
    .map_err(debug)?;
    let mut destination =
        Coordinator::restore(validated.clone(), destination_provider).map_err(debug)?;
    let destination_restored_state = destination.state().clone();
    let snapshot_cursor = snapshot.body.snapshot.journal_position;
    destination
        .prepare_destination(
            id(110),
            fixture.handoff_plan(),
            fixture.timer_plan(),
            fixture.key_value_plan(),
        )
        .map_err(debug)?;
    require(
        destination.state().phase == HandoffPhase::DestinationPrepared,
        "destination did not prepare",
    )?;

    let commit_operation = id(120);
    let commit_idempotency = IdempotencyKey::from_u128(121);
    let destination_resume_command = id(141);
    let commit_request_digest = destination
        .guarded_handoff_commit_request_digest(
            commit_operation,
            commit_idempotency,
            destination_resume_command,
        )
        .map_err(debug)?;
    let prepared = destination
        .state()
        .prepared_destination
        .as_ref()
        .ok_or("destination prepared state is absent")?;
    let prepared_destination_digest = contract_digest(prepared).map_err(debug)?;
    let authorities_digest = contract_digest(&prepared.authorities).map_err(debug)?;
    let bindings_digest = contract_digest(&prepared.bindings).map_err(debug)?;
    let mapping = JointMappingManifest {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        key,
        visa_operation_cohort_digest: contract_digest(&source.state().operations).map_err(debug)?,
        effect_scope: EffectScopeVersion {
            registry_instance: effect_config.registry_instance,
            scope_id: effect_config.scope_id,
            scope_generation: effect_config.scope_generation,
            authority_epoch: effect_config.authority_epoch,
            freeze_generation: effect_config.freeze_generation,
        },
        effect_cohort_digest: frozen.receipt.effect_cohort_digest,
        domain_bindings_manifest_digest: effect_config.domain_bindings_digest,
        ownership_service: OwnershipVersion {
            service_id: ownership_issuer.issuer,
            service_incarnation: ownership_issuer.issuer_incarnation,
            log_sequence: intent.header.sequence,
        },
        protocol_revision: 1,
    };
    let destination_prepared = DestinationPreparedReceipt {
        header: header(issuers.visa_destination, ReceiptKind::DestinationPrepared, 1, None),
        key,
        intent: intent_ref,
        visa_freeze: visa_freeze_ref,
        nexus_freeze: effect_freeze_ref,
        snapshot: SnapshotBinding {
            snapshot: snapshot.body.snapshot.snapshot,
            integrity: snapshot.integrity,
            body_digest: contract_digest(&snapshot.body).map_err(debug)?,
            source_journal_position: snapshot.body.snapshot.journal_position,
            component_digest: snapshot.body.component_digest,
            profile_digest: snapshot.body.profile_digest,
        },
        journal_position: destination.journal_position(),
        state_digest: destination.state_digest().map_err(debug)?,
        prepared_destination_digest,
        authorities_digest,
        bindings_digest,
        joint_mapping_manifest_digest: joint_digest(&mapping).map_err(debug)?,
        lease_commit_operation: commit_operation,
        lease_commit_idempotency: commit_idempotency,
        lease_commit_request_digest: commit_request_digest,
    };
    let destination_prepared_ref = destination_prepared.receipt_ref().map_err(debug)?;
    record(&mut joint, &destination_prepared, id(203), &authenticator, &mut native_receipts)?;
    receipt_count += 1;
    let sealed_bindings = PreparedBindings {
        prepare_intent_receipt_digest: intent_ref.digest,
        visa_freeze_receipt_digest: visa_freeze_ref.digest,
        effect_freeze_receipt_digest: effect_freeze_ref.digest,
        snapshot: destination_prepared.snapshot.snapshot,
        snapshot_integrity_digest: destination_prepared.snapshot.integrity,
        source_journal_position: destination_prepared.snapshot.source_journal_position,
        source_state_digest: visa_freeze.state_digest,
        component_digest: destination_prepared.snapshot.component_digest,
        profile_digest: destination_prepared.snapshot.profile_digest,
        destination_prepared_receipt_digest: destination_prepared_ref.digest,
        destination_state_digest: destination_prepared.state_digest,
        prepared_authorities_digest: destination_prepared.authorities_digest,
        prepared_bindings_digest: destination_prepared.bindings_digest,
        effect_cohort_manifest_digest: frozen.receipt.effect_cohort_digest,
        joint_mapping_manifest_digest: destination_prepared.joint_mapping_manifest_digest,
    };
    let seal_invocation = OwnershipSealRequest {
        key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa_freeze_ref,
        effect_freeze: effect_freeze_ref,
        destination_prepared: destination_prepared_ref,
        bindings: sealed_bindings,
        expected_state_sequence: 1,
    };
    let seal_invocation_bytes = joint_bytes(&seal_invocation).map_err(debug)?;
    let ownership_prepared = ownership.seal(seal_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &ownership_prepared,
        id(204),
        &authenticator,
        &mut native_receipts,
        seal_invocation_bytes,
    )?;
    receipt_count += 1;
    let ownership_prepared_ref = ownership_prepared.receipt_ref().map_err(debug)?;
    let commit_invocation = OwnershipCommitRequest {
        key,
        reservation: intent.reservation,
        prepared: ownership_prepared_ref,
        expected_state_sequence: 2,
    };
    let commit_invocation_bytes = joint_bytes(&commit_invocation).map_err(debug)?;
    let ownership_commit = ownership.commit(commit_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &ownership_commit,
        id(205),
        &authenticator,
        &mut native_receipts,
        commit_invocation_bytes,
    )?;
    receipt_count += 1;
    let close_invocation = EffectCloseRequest {
        token: frozen.token,
        commit: ownership_commit.clone(),
        expected_closure_revision: 0,
    };
    let close_invocation_bytes = joint_bytes(&close_invocation).map_err(debug)?;
    let EffectCloseResult::Closed(closure) = effect_peer.close(close_invocation).map_err(debug)?
    else {
        return Err("empty effect cohort did not close in one step".to_owned());
    };
    record_with_peer_invocation(
        &mut joint,
        &closure,
        id(206),
        &authenticator,
        &mut native_receipts,
        close_invocation_bytes,
    )?;
    receipt_count += 1;

    let commit_ref = ownership_commit.receipt_ref().map_err(debug)?;
    let closure_ref = closure.receipt_ref().map_err(debug)?;
    let source_fence_header =
        header(issuers.visa_source, ReceiptKind::VisaSourceFence, 2, Some(visa_freeze_ref.digest));
    let source_fence_template = VisaSourceFenceReceipt {
        header: source_fence_header,
        key,
        commit: commit_ref,
        closure: closure_ref,
        journal_position: contract_core::JournalPosition::ORIGIN,
        state_digest: Digest::ZERO,
    };
    let source_completion_command = id(207);
    let source_completion_digest =
        ReceiptRequest::for_receipt(source_completion_command, &source_fence_template)
            .digest()
            .map_err(debug)?;
    let source_attempt = SourceFenceAttempt::new(
        joint.state().state().revision,
        commit_ref,
        closure_ref,
        id(130),
        id(131),
        source.state_digest().map_err(debug)?,
        source.journal_position(),
        source_completion_digest,
    )
    .map_err(debug)?;
    let source_before_attempt_conflicts =
        (source.journal_position(), source.state_digest().map_err(debug)?);
    let source_conflict_head_before =
        joint.head().ok_or_else(|| "source conflict probe has no head".to_owned())?;

    let mut wrong_source_handoff = source_attempt;
    wrong_source_handoff.closure.handoff = id(9_050);
    wrong_source_handoff.request_digest =
        wrong_source_handoff.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_fence(wrong_source_handoff),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceFenceAttemptConflict
            ))
        ),
        "wrong source handoff reference was not rejected before provider projection",
    )?;
    let mut wrong_source_evidence = source_attempt;
    wrong_source_evidence.closure.digest = digest(99);
    wrong_source_evidence.request_digest =
        wrong_source_evidence.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_fence(wrong_source_evidence),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceFenceAttemptConflict
            ))
        ),
        "wrong source evidence reference was not rejected before provider projection",
    )?;
    let source_conflict_head_after =
        joint.head().ok_or_else(|| "source conflict probe lost its head".to_owned())?;
    joint.begin_source_fence(source_attempt).map_err(debug)?;
    let source_attempt_head =
        joint.head().ok_or_else(|| "source fence attempt has no head".to_owned())?;
    let mut wrong_source_operation = source_attempt;
    wrong_source_operation.fence_operation = id(9_131);
    wrong_source_operation.request_digest =
        wrong_source_operation.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_fence(wrong_source_operation),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceFenceAttemptConflict
            ))
        ),
        "conflicting source operation replaced a persisted projection attempt",
    )?;
    require(
        (source.journal_position(), source.state_digest().map_err(debug)?)
            == source_before_attempt_conflicts,
        "rejected source attempts changed the provider projection",
    )?;
    require(
        joint.head() == Some(source_attempt_head),
        "conflicting source operation changed the attempt head",
    )?;
    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let source_reopened_attempt_head =
        joint.head().ok_or_else(|| "reopened source fence attempt has no head".to_owned())?;
    let source_projection = {
        let mut driver = DurableProjectionDriver::new(&mut joint);
        let execution = driver
            .project_source_fence(&mut source, source_attempt)
            .map_err(|error| format!("source projection failed after attempt reopen: {error:?}"))?;
        require(
            execution.write_ahead == visa_joint_handoff::DurableRecordOutcome::ExactReplay,
            "source attempt was not replayed from the durable joint log",
        )?;
        execution.local
    };

    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let source_reopened_local_after =
        (source.journal_position(), source.state_digest().map_err(debug)?);
    let reconciled_source_projection = {
        let mut driver = DurableProjectionDriver::new(&mut joint);
        driver
            .project_source_fence(&mut source, source_attempt)
            .map_err(|error| format!("source projection reconciliation failed: {error:?}"))?
            .local
    };
    require(
        reconciled_source_projection == source_projection,
        "source projection changed across provider-commit recovery",
    )?;
    let source_fence = VisaSourceFenceReceipt {
        header: source_fence_header,
        key,
        commit: commit_ref,
        closure: closure_ref,
        journal_position: source_projection.journal_position,
        state_digest: source_projection.state_digest,
    };
    require(
        source_fence.journal_position == source_projection.journal_position
            && source_fence.state_digest == source_projection.state_digest,
        "source fence receipt does not match the local projection",
    )?;
    let (source_request, source_envelope, source_payload, source_material) =
        encode_native_material(&source_fence, source_completion_command, &authenticator)?;
    joint.log().arm_append_ack_loss();
    require(
        matches!(
            joint.record_native_receipt(
                source_completion_command,
                &source_request,
                &source_envelope,
                &source_payload,
            ),
            Err(DurableJointSessionError::LogAppend(
                LostAckProjectionLogError::AcknowledgementLost
            ))
        ),
        "source completion append did not lose its acknowledgement after durable commit",
    )?;
    let source_completion_head = joint
        .log()
        .inner()
        .head()
        .map_err(debug)?
        .ok_or_else(|| "source completion append did not create a head".to_owned())?;
    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let source_reopened_completion_head =
        joint.head().ok_or_else(|| "reopened source completion has no head".to_owned())?;
    require(
        joint.replay_source_fence_attempt().is_none(),
        "source completion receipt was not recovered after append acknowledgement loss",
    )?;
    native_receipts.push(source_material);
    receipt_count += 1;
    let joint_source = JointSource::new(source);
    joint_source
        .close(joint.state())
        .map_err(|error| format!("source close validation failed: {error:?}"))?;

    let local_prepared = destination
        .state()
        .prepared_destination
        .as_ref()
        .ok_or("destination lost its prepared projection")?;
    require(
        destination.state().component.identity == key.continuity_unit.identity,
        "destination continuity identity differs from joint key",
    )?;
    require(
        destination.state().component.generation.next()
            == Some(local_prepared.component_generation),
        "destination prepared generation is not the successor continuity generation",
    )?;
    require(
        destination.state_digest().map_err(debug)? == sealed_bindings.destination_state_digest,
        "destination prepared state digest drifted before projection",
    )?;
    require(
        destination
            .guarded_handoff_commit_request_digest(
                commit_operation,
                commit_idempotency,
                destination_resume_command,
            )
            .map_err(debug)?
            == commit_request_digest,
        "destination commit request digest drifted before projection",
    )?;
    let source_fence_ref = source_fence.receipt_ref().map_err(debug)?;
    let destination_activation_header = header(
        issuers.visa_destination,
        ReceiptKind::VisaDestinationActivation,
        2,
        Some(destination_prepared_ref.digest),
    );
    let destination_completion_command = id(209);
    let destination_attempt = DestinationActivationAttempt::new(
        joint.state().state().revision,
        commit_ref,
        closure_ref,
        source_fence_ref,
        id(208),
        id(140),
        commit_operation,
        commit_idempotency,
        commit_request_digest,
        destination_resume_command,
        destination.state_digest().map_err(debug)?,
        destination.journal_position(),
    )
    .map_err(debug)?;
    let destination_before_attempt =
        (destination.journal_position(), destination.state_digest().map_err(debug)?);
    let destination_conflict_head_before =
        joint.head().ok_or_else(|| "destination conflict probe has no head".to_owned())?;
    joint.begin_destination_activation(destination_attempt).map_err(debug)?;
    let destination_activation_attempt_record_digest = joint
        .destination_activation_attempt_record_digest()
        .ok_or_else(|| "destination activation attempt record has no digest".to_owned())?;
    let destination_attempt_head =
        joint.head().ok_or_else(|| "destination attempt has no head".to_owned())?;
    let mut wrong_destination_operation = destination_attempt;
    wrong_destination_operation.commit_operation = id(9_120);
    wrong_destination_operation.request_digest =
        wrong_destination_operation.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_destination_activation(wrong_destination_operation),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::DestinationActivationAttemptConflict
            ))
        ),
        "conflicting destination operation replaced a persisted attempt",
    )?;
    require(
        (destination.journal_position(), destination.state_digest().map_err(debug)?)
            == destination_before_attempt,
        "conflicting destination attempt reached the provider",
    )?;
    require(
        joint.head() == Some(destination_attempt_head),
        "conflicting destination operation changed the attempt head",
    )?;
    let destination_conflict_head_after = destination_conflict_head_before;

    drop(destination);
    drop(joint);
    let destination_provider = fixture.destination_provider(&paths.destination)?;
    let destination =
        Coordinator::restore(validated.clone(), destination_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let destination_reopened_attempt_head =
        joint.head().ok_or_else(|| "reopened destination attempt has no head".to_owned())?;
    let destination_projection = {
        let mut guard = DurableDestinationGuard::new(&mut joint, destination);
        let execution = guard
            .project(destination_attempt)
            .map_err(|error| format!("destination projection failed: {error:?}"))?;
        require(
            matches!(
                guard.check_release(),
                Err(visa_joint_handoff::DurableProjectionError::CompletionPending)
            ),
            "destination workload exposure opened before its receipt was durable",
        )?;
        execution.local
    };

    drop(joint);
    let destination_provider = fixture.destination_provider(&paths.destination)?;
    let destination =
        Coordinator::restore(validated.clone(), destination_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let destination_reopened_local_after =
        (destination.journal_position(), destination.state_digest().map_err(debug)?);
    let destination_activation = VisaDestinationActivationReceipt {
        header: destination_activation_header,
        key,
        commit: commit_ref,
        closure: closure_ref,
        source_fence: source_fence_ref,
        activation_command: id(208),
        resume_command: destination_resume_command,
        activation_attempt_record_digest: destination_activation_attempt_record_digest,
        journal_position: destination_projection.journal_position,
        state_digest: destination_projection.state_digest,
    };
    require(
        destination_activation.journal_position == destination_projection.journal_position
            && destination_activation.state_digest == destination_projection.state_digest,
        "destination activation receipt does not match the local projection",
    )?;
    let (destination_request, destination_envelope, destination_payload, destination_material) =
        encode_native_material(
            &destination_activation,
            destination_completion_command,
            &authenticator,
        )?;
    joint.log().arm_append_ack_loss();
    let mut guard = DurableDestinationGuard::new(&mut joint, destination);
    let reconciled_destination_projection = guard
        .project(destination_attempt)
        .map_err(|error| format!("destination projection reconciliation failed: {error:?}"))?
        .local;
    require(
        reconciled_destination_projection == destination_projection
            && matches!(
                guard.check_release(),
                Err(visa_joint_handoff::DurableProjectionError::CompletionPending)
            ),
        "reopened destination projection changed or became publishable before receipt recovery",
    )?;
    require(
        matches!(
            guard.record_completion(
                destination_completion_command,
                &destination_request,
                &destination_envelope,
                &destination_payload,
            ),
            Err(visa_joint_handoff::DurableProjectionError::Durable(
                DurableJointSessionError::LogAppend(LostAckProjectionLogError::AcknowledgementLost)
            ))
        ),
        "destination completion did not exercise append acknowledgement loss",
    )?;
    drop(guard);
    let destination_completion_head = joint
        .log()
        .inner()
        .head()
        .map_err(debug)?
        .ok_or_else(|| "destination completion append did not create a head".to_owned())?;
    drop(joint);

    let destination_provider = fixture.destination_provider(&paths.destination)?;
    let destination =
        Coordinator::restore(validated.clone(), destination_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let destination_reopened_completion_head =
        joint.head().ok_or_else(|| "reopened destination completion has no head".to_owned())?;
    let activation_completion_record_digest = joint
        .destination_activation_completion_record_digest()
        .ok_or_else(|| "reopened destination completion has no record digest".to_owned())?;
    let checkpoint_state = destination.state().clone();
    let checkpoint_journal =
        destination.provider().replay_from(Some(snapshot_cursor)).map_err(debug)?;
    require(
        checkpoint_state.phase == HandoffPhase::Committed
            && checkpoint_state.activation.role == contract_core::ActivationRole::Destination
            && checkpoint_state.activation.status == ActivationStatus::Active
            && checkpoint_state.timer.status
                == contract_core::TimerStatus::Frozen(contract_core::TimerDisposition::Idle),
        "destination checkpoint was not Committed/Active/Frozen(Idle)",
    )?;
    require(
        checkpoint_journal.iter().all(|entry| {
            !matches!(entry.event.kind, contract_core::EventKind::JointDestinationResumed { .. })
        }),
        "destination checkpoint already exposed a joint resume event",
    )?;
    let destination_checkpoint = HostDestinationActivationCheckpoint {
        joint_completion_head: destination_reopened_completion_head,
        activation_completion_record_digest,
        local_state: checkpoint_state,
        local_journal: checkpoint_journal,
    };
    native_receipts.push(destination_material);
    receipt_count += 1;
    let destination = DurableDestinationGuard::new(&mut joint, destination)
        .release()
        .map_err(|error| format!("destination active validation failed: {error:?}"))?;

    let source_provider = SqliteProvider::open(
        &paths.source,
        JournalScope { node: fixture.source_node, component: fixture.source_component.identity },
    )
    .map_err(debug)?;
    let source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    require(
        source.state().phase == HandoffPhase::Committed
            && source.state().activation.status == ActivationStatus::Fenced,
        "source did not recover Committed/Fenced",
    )?;
    require(
        destination.state().phase == HandoffPhase::Running
            && destination.state().activation.status == ActivationStatus::Active,
        "destination did not reach Running/Active",
    )?;
    require(
        joint.state().state().phase == joint_handoff_core::JointPhase::DestinationActive,
        "joint state did not reach DestinationActive",
    )?;

    let source_journal = source.provider().replay_from(None).map_err(debug)?;
    let destination_journal =
        destination.provider().replay_from(Some(snapshot_cursor)).map_err(debug)?;
    require(
        source_journal.last().is_some_and(|entry| {
            entry.event.identity == source_attempt.fence_command
                && matches!(
                    entry.event.kind,
                    contract_core::EventKind::HandoffCommitted { operation, .. }
                        if operation == source_attempt.fence_operation
                )
        }),
        "source fence attempt command/operation do not bind the terminal source journal event",
    )?;
    require(
        destination_journal.get(1).is_some_and(|entry| {
            entry.event.identity == destination_attempt.commit_command
                && matches!(entry.event.kind, contract_core::EventKind::EffectPrepared { .. })
        }) && destination_journal.last().is_some_and(|entry| {
            entry.event.identity == destination_attempt.resume_command
                && matches!(
                    entry.event.kind,
                    contract_core::EventKind::JointDestinationResumed {
                        activation_record_digest,
                    } if activation_record_digest == activation_completion_record_digest
                )
        }),
        "destination activation attempt commands do not bind the intent/resume journal events",
    )?;
    let source_leases = lease_material(source.provider(), [fixture.timer, fixture.key_value])?;
    let destination_leases =
        lease_material(destination.provider(), [fixture.timer, fixture.key_value])?;
    let source_terminal_state = source.state().clone();
    let destination_terminal_state = destination.state().clone();
    let commit_transcript = host_projection_transcript(joint.log())?;
    let durable_projection = HostDurableProjectionEvidence {
        commit_transcript,
        source_abort: source_abort_evidence,
        source_fence: HostProjectionWindowObservation {
            conflict_head_before: source_conflict_head_before,
            conflict_head_after: source_conflict_head_after,
            attempt_head: source_attempt_head,
            reopened_attempt_head: source_reopened_attempt_head,
            completion_head: source_completion_head,
            reopened_completion_head: source_reopened_completion_head,
            local_before_position: source_before_attempt_conflicts.0,
            local_before_digest: source_before_attempt_conflicts.1,
            local_after_position: source_projection.journal_position,
            local_after_digest: source_projection.state_digest,
            reopened_local_after_position: source_reopened_local_after.0,
            reopened_local_after_digest: source_reopened_local_after.1,
            conflicts_left_local_unchanged: true,
            completion_append_ack_lost: true,
            exposure_blocked_before_completion: false,
        },
        destination_activation: HostProjectionWindowObservation {
            conflict_head_before: destination_conflict_head_before,
            conflict_head_after: destination_conflict_head_after,
            attempt_head: destination_attempt_head,
            reopened_attempt_head: destination_reopened_attempt_head,
            completion_head: destination_completion_head,
            reopened_completion_head: destination_reopened_completion_head,
            local_before_position: destination_before_attempt.0,
            local_before_digest: destination_before_attempt.1,
            local_after_position: destination_projection.journal_position,
            local_after_digest: destination_projection.state_digest,
            reopened_local_after_position: destination_reopened_local_after.0,
            reopened_local_after_digest: destination_reopened_local_after.1,
            conflicts_left_local_unchanged: true,
            completion_append_ack_lost: true,
            exposure_blocked_before_completion: true,
        },
        destination_checkpoint,
    };

    Ok(CoordinatorVerticalCellReport {
        schema: HOST_SUBSTRATE_CELL_SCHEMA.to_owned(),
        lifecycle: [
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
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        receipt_chain: [
            "prepare-intent",
            "visa-freeze",
            "nexus-freeze",
            "destination-prepared",
            "ownership-prepared",
            "ownership-commit",
            "closure",
            "visa-source-fence",
            "visa-destination-activation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        authenticated_receipt_count: receipt_count,
        joint_phase: "destination-active".to_owned(),
        source_reopened: true,
        source_phase: "committed".to_owned(),
        source_activation: "fenced".to_owned(),
        source_owner_is_destination: source.state().ownership.owner
            == Some(fixture.destination_node),
        destination_phase: "running".to_owned(),
        destination_activation: "active".to_owned(),
        destination_owner_is_destination: destination.state().ownership.owner
            == Some(fixture.destination_node),
        source_component_generation: source.state().component.generation.0,
        destination_component_generation: destination.state().component.generation.0,
        source_journal_position: source.journal_position(),
        destination_journal_position: destination.journal_position(),
        source_state_digest: source.state_digest().map_err(debug)?,
        destination_state_digest: destination.state_digest().map_err(debug)?,
        snapshot_integrity: snapshot.integrity,
        prepared_destination_digest,
        lease_commit_request_digest: commit_request_digest,
        independent_source_destination_databases: paths.source != paths.destination,
        same_boot_only: true,
        exclusive_trusted_coordinator_api: true,
        authentication_scheme: HOST_SUBSTRATE_AUTHENTICATION_SCHEME.to_owned(),
        authentication_key: authenticator.secret,
        native_receipts,
        source_initial_state: initial,
        snapshot,
        snapshot_cursor,
        destination_restored_state,
        source_terminal_state,
        destination_terminal_state,
        source_journal,
        destination_journal,
        source_leases,
        destination_leases,
        durable_projection,
    })
}

fn run_source_abort_recovery_probe() -> Result<HostAbortProjectionEvidence, String> {
    let paths = CellPaths::new()?;
    let fixture = Fixture::new();
    let initial = fixture.initial_state();
    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    source.activate(id(3_100), fixture.source_handoff_authority, INITIAL_EPOCH).map_err(debug)?;

    let key = JointHandoffKey {
        continuity_unit: fixture.source_component,
        handoff: fixture.handoff,
        source: fixture.source_node,
        destination: fixture.destination_node,
        expected_epoch: INITIAL_EPOCH,
        next_epoch: INITIAL_EPOCH.next().ok_or("lease epoch exhausted")?,
    };
    let ownership_namespace = issuer(3_500);
    let effect_namespace = issuer(3_600);
    let ownership_issuer = ownership_receipt_issuer(ownership_namespace, key).map_err(debug)?;
    let effect_issuer = effect_receipt_issuer(effect_namespace, key).map_err(debug)?;
    let issuers = JointIssuerSet {
        ownership: ownership_issuer,
        visa_source: issuer(3_700),
        visa_destination: issuer(3_800),
        effect_closure: effect_issuer,
    };
    let authenticator = CellAuthenticator { key, issuers, secret: [0x6b; 32] };
    let mut ownership =
        ReferenceOwnershipLog::open(&paths.ownership, ownership_namespace).map_err(debug)?;
    ownership
        .initialize_unit(key.continuity_unit, key.source, key.expected_epoch)
        .map_err(debug)?;
    let log = HostJointLog::new(SqliteJointProjectionLog::open(&paths.projection).map_err(debug)?);
    let mut joint =
        DurableJointSession::recover(log, authenticator.clone(), key, issuers).map_err(debug)?;
    let mut native_receipts = Vec::new();
    let reserve_invocation = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_invocation_bytes = joint_bytes(&reserve_invocation).map_err(debug)?;
    let intent = ownership.reserve(reserve_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &intent,
        id(3_200),
        &authenticator,
        &mut native_receipts,
        reserve_invocation_bytes.clone(),
    )?;
    let intent_ref = intent.receipt_ref().map_err(debug)?;

    source.begin_quiesce(id(3_101), fixture.source_handoff_authority).map_err(debug)?;
    let safe_point = source.prepare_safe_point().map_err(debug)?;
    source
        .commit_safe_point(id(3_102), b"abort-recovery-state".to_vec(), safe_point)
        .map_err(debug)?;
    require(source.state().phase == HandoffPhase::Frozen, "abort probe source did not freeze")?;
    let visa_freeze = VisaFreezeReceipt {
        header: header(issuers.visa_source, ReceiptKind::VisaFreeze, 1, None),
        key,
        intent: intent_ref,
        journal_position: source.journal_position(),
        state_digest: source.state_digest().map_err(debug)?,
        portable_state_digest: digest(71),
    };
    let visa_freeze_ref = visa_freeze.receipt_ref().map_err(debug)?;
    record(&mut joint, &visa_freeze, id(3_201), &authenticator, &mut native_receipts)?;
    let effect_config = EffectPeerConfig {
        key,
        issuer: effect_issuer,
        ownership_issuer,
        registry_instance: id(3_900),
        scope_id: id(3_901),
        scope_generation: 1,
        authority_epoch: 1,
        freeze_generation: 1,
        domain_bindings_digest: digest(72),
    };
    let effect_peer = ReferenceEffectPeer::new(effect_config).map_err(debug)?;
    let effect_freeze_invocation = EffectFreezeRequest {
        key,
        intent: intent.clone(),
        registry_instance: effect_config.registry_instance,
        scope_id: effect_config.scope_id,
        scope_generation: effect_config.scope_generation,
        authority_epoch: effect_config.authority_epoch,
        freeze_generation: effect_config.freeze_generation,
    };
    let effect_freeze_invocation_bytes = joint_bytes(&effect_freeze_invocation).map_err(debug)?;
    joint
        .record_effect_freeze_attempt(id(3_250), &effect_freeze_invocation_bytes)
        .map_err(debug)?;
    let frozen = effect_peer.freeze(effect_freeze_invocation.clone()).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &frozen.receipt,
        id(3_202),
        &authenticator,
        &mut native_receipts,
        effect_freeze_invocation_bytes,
    )?;
    let abort_invocation = OwnershipAbortRequest {
        key,
        reservation: intent.reservation,
        basis: intent_ref,
        expected_state_sequence: 1,
    };
    let abort_invocation_bytes = joint_bytes(&abort_invocation).map_err(debug)?;
    let abort = ownership.abort(abort_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &abort,
        id(3_203),
        &authenticator,
        &mut native_receipts,
        abort_invocation_bytes,
    )?;
    let abort_ref = abort.receipt_ref().map_err(debug)?;
    let thaw_invocation = EffectThawRequest { token: frozen.token, abort: abort.clone() };
    let thaw_invocation_bytes = joint_bytes(&thaw_invocation).map_err(debug)?;
    let thaw = effect_peer.thaw(thaw_invocation).map_err(debug)?;
    record_with_peer_invocation(
        &mut joint,
        &thaw,
        id(3_204),
        &authenticator,
        &mut native_receipts,
        thaw_invocation_bytes,
    )?;
    let thaw_ref = thaw.receipt_ref().map_err(debug)?;

    let completion_command = id(3_205);
    let completion_header =
        header(issuers.visa_source, ReceiptKind::VisaSourceResume, 2, Some(visa_freeze_ref.digest));
    let completion_template = VisaSourceResumeReceipt {
        header: completion_header,
        key,
        abort: abort_ref,
        thaw: Some(thaw_ref),
        journal_position: contract_core::JournalPosition::ORIGIN,
        state_digest: Digest::ZERO,
    };
    let completion_digest = ReceiptRequest::for_receipt(completion_command, &completion_template)
        .digest()
        .map_err(debug)?;
    let attempt = SourceAbortAttempt::new(
        joint.state().state().revision,
        abort_ref,
        Some(thaw_ref),
        id(3_130),
        id(3_131),
        source.state_digest().map_err(debug)?,
        source.journal_position(),
        completion_digest,
    )
    .map_err(debug)?;
    let local_before_conflicts = (source.journal_position(), source.state_digest().map_err(debug)?);
    let conflict_head_before =
        joint.head().ok_or_else(|| "abort conflict probe has no durable head".to_owned())?;
    let mut wrong_handoff = attempt;
    wrong_handoff.ownership_abort.handoff = id(3_999);
    wrong_handoff.request_digest = wrong_handoff.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_abort(wrong_handoff),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceAbortAttemptConflict
            ))
        ),
        "abort attempt accepted a wrong handoff reference",
    )?;
    let mut wrong_evidence = attempt;
    wrong_evidence.nexus_thaw =
        Some(joint_handoff_core::ReceiptRef { digest: digest(98), ..thaw_ref });
    wrong_evidence.request_digest = wrong_evidence.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_abort(wrong_evidence),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceAbortAttemptConflict
            ))
        ),
        "abort attempt accepted conflicting thaw evidence",
    )?;
    require(
        joint.head() == Some(conflict_head_before)
            && (source.journal_position(), source.state_digest().map_err(debug)?)
                == local_before_conflicts,
        "rejected abort attempts changed durable or provider state",
    )?;
    let conflict_head_after =
        joint.head().ok_or_else(|| "abort conflict probe lost its durable head".to_owned())?;

    joint.begin_source_abort(attempt).map_err(debug)?;
    let attempt_head =
        joint.head().ok_or_else(|| "abort attempt has no durable head".to_owned())?;
    let mut wrong_operation = attempt;
    wrong_operation.resume_command = id(3_998);
    wrong_operation.request_digest = wrong_operation.derived_request_digest().map_err(debug)?;
    require(
        matches!(
            joint.begin_source_abort(wrong_operation),
            Err(DurableJointSessionError::Record(
                visa_joint_handoff::ProjectionRecordRejection::SourceAbortAttemptConflict
            ))
        ) && (source.journal_position(), source.state_digest().map_err(debug)?)
            == local_before_conflicts,
        "conflicting abort operation replaced the durable attempt or reached the provider",
    )?;
    require(
        joint.head() == Some(attempt_head),
        "conflicting abort operation changed the attempt head",
    )?;

    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let reopened_attempt_head =
        joint.head().ok_or_else(|| "reopened abort attempt has no head".to_owned())?;
    let projection = DurableProjectionDriver::new(&mut joint)
        .project_source_abort(&mut source, attempt)
        .map_err(|error| format!("abort projection after attempt reopen failed: {error:?}"))?
        .local;
    let local_after = (projection.journal_position, projection.state_digest);

    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let mut source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let mut joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let reopened_local_after = (source.journal_position(), source.state_digest().map_err(debug)?);
    let reconciled = DurableProjectionDriver::new(&mut joint)
        .project_source_abort(&mut source, attempt)
        .map_err(|error| format!("abort provider reconciliation failed: {error:?}"))?
        .local;
    require(reconciled == projection, "abort projection changed after provider reopen")?;
    let completion = VisaSourceResumeReceipt {
        header: completion_header,
        key,
        abort: abort_ref,
        thaw: Some(thaw_ref),
        journal_position: projection.journal_position,
        state_digest: projection.state_digest,
    };
    let (request, envelope, payload, completion_material) =
        encode_native_material(&completion, completion_command, &authenticator)?;
    joint.log().arm_append_ack_loss();
    require(
        matches!(
            joint.record_native_receipt(completion_command, &request, &envelope, &payload),
            Err(DurableJointSessionError::LogAppend(
                LostAckProjectionLogError::AcknowledgementLost
            ))
        ),
        "abort completion did not exercise append acknowledgement loss",
    )?;
    let completion_head = joint
        .log()
        .inner()
        .head()
        .map_err(debug)?
        .ok_or_else(|| "abort completion append did not create a head".to_owned())?;
    native_receipts.push(completion_material);

    drop(source);
    drop(joint);
    let source_provider = fixture.source_provider(&paths.source)?;
    let source = Coordinator::recover(initial.clone(), source_provider).map_err(debug)?;
    let joint = reopen_joint(&paths.projection, &authenticator, key, issuers)?;
    let reopened_completion_head =
        joint.head().ok_or_else(|| "reopened abort completion has no head".to_owned())?;
    require(
        joint.replay_source_abort_attempt().is_none(),
        "abort completion receipt was not recovered after append acknowledgement loss",
    )?;
    let source = JointSource::new(source)
        .into_source_active(joint.state())
        .map_err(|error| format!("abort source release failed: {error:?}"))?;
    require(
        source.state().phase == HandoffPhase::Running
            && source.state().activation.status == ActivationStatus::Active
            && source.journal_position() == projection.journal_position
            && source.state_digest().map_err(debug)? == projection.state_digest,
        "abort source did not recover the exact Running/Active projection",
    )?;
    let journal = source.provider().replay_from(None).map_err(debug)?;
    let leases = lease_material(source.provider(), [fixture.timer, fixture.key_value])?;
    let terminal_state = source.state().clone();
    let transcript = host_projection_transcript(joint.log())?;
    Ok(HostAbortProjectionEvidence {
        transcript,
        observation: HostProjectionWindowObservation {
            conflict_head_before,
            conflict_head_after,
            attempt_head,
            reopened_attempt_head,
            completion_head,
            reopened_completion_head,
            local_before_position: local_before_conflicts.0,
            local_before_digest: local_before_conflicts.1,
            local_after_position: local_after.0,
            local_after_digest: local_after.1,
            reopened_local_after_position: reopened_local_after.0,
            reopened_local_after_digest: reopened_local_after.1,
            conflicts_left_local_unchanged: true,
            completion_append_ack_lost: true,
            exposure_blocked_before_completion: false,
        },
        issuer_set: issuers,
        authentication_key: authenticator.secret,
        native_receipts,
        initial_state: initial,
        terminal_state,
        journal,
        leases,
    })
}

fn record<T>(
    state: &mut HostJointSession,
    receipt: &T,
    command: Identity,
    authenticator: &CellAuthenticator,
    materials: &mut Vec<HostNativeReceiptMaterial>,
) -> Result<(), String>
where
    T: VerifiedCommandReceipt + Serialize,
{
    let (request, envelope, payload, material) =
        encode_native_material(receipt, command, authenticator)?;
    state
        .record_native_receipt(command, &request, &envelope, &payload)
        .map_err(|error| format!("record {:?} failed: {error:?}", T::KIND))?;
    materials.push(material);
    Ok(())
}

fn record_with_peer_invocation<T>(
    state: &mut HostJointSession,
    receipt: &T,
    command: Identity,
    authenticator: &CellAuthenticator,
    materials: &mut Vec<HostNativeReceiptMaterial>,
    peer_invocation: Vec<u8>,
) -> Result<(), String>
where
    T: VerifiedCommandReceipt + Serialize,
{
    require(!peer_invocation.is_empty(), "peer invocation bytes are empty")?;
    record(state, receipt, command, authenticator, materials)?;
    let material =
        materials.last_mut().ok_or_else(|| "peer receipt material was not retained".to_owned())?;
    material.peer_invocation = Some(peer_invocation);
    Ok(())
}

fn encode_native_material<T>(
    receipt: &T,
    command: Identity,
    authenticator: &CellAuthenticator,
) -> Result<EncodedNativeMaterial, String>
where
    T: TypedReceipt + Serialize,
{
    let payload = joint_bytes(receipt).map_err(debug)?;
    let request = ReceiptRequest::for_receipt(command, receipt);
    let request_bytes = joint_bytes(&request).map_err(debug)?;
    let envelope = authenticator.envelope(receipt, &request, &payload)?;
    require(
        envelope.matches_request(&request, receipt).map_err(debug)?,
        "native envelope does not bind the typed request",
    )?;
    let envelope = joint_bytes(&envelope).map_err(debug)?;
    let material = HostNativeReceiptMaterial {
        kind: receipt_kind_name(T::KIND).to_owned(),
        issuance_request: request_bytes.clone(),
        peer_invocation: None,
        envelope: envelope.clone(),
        payload: payload.clone(),
    };
    Ok((request_bytes, envelope, payload, material))
}

fn reopen_joint(
    path: &Path,
    authenticator: &CellAuthenticator,
    key: JointHandoffKey,
    issuers: JointIssuerSet,
) -> Result<HostJointSession, String> {
    let log = HostJointLog::new(SqliteJointProjectionLog::open(path).map_err(debug)?);
    DurableJointSession::recover(log, authenticator.clone(), key, issuers).map_err(debug)
}

fn host_projection_transcript<L>(log: &L) -> Result<HostJointProjectionTranscript, String>
where
    L: JointProjectionLog,
    L::Error: std::fmt::Debug,
{
    let head =
        log.head().map_err(debug)?.ok_or_else(|| "joint projection head is absent".to_owned())?;
    let mut canonical_record_bytes = Vec::new();
    for sequence in 1..=head.sequence {
        let record = log
            .read(sequence)
            .map_err(debug)?
            .ok_or_else(|| format!("joint projection record {sequence} is absent"))?;
        canonical_record_bytes.push(record.canonical_bytes().map_err(debug)?);
    }
    require(
        log.head().map_err(debug)? == Some(head),
        "joint projection head changed while transcript was read",
    )?;
    Ok(HostJointProjectionTranscript { head, canonical_record_bytes })
}

fn lease_material(
    provider: &SqliteProvider,
    resources: [EntityRef; 2],
) -> Result<Vec<HostLeaseRecordMaterial>, String> {
    resources
        .into_iter()
        .map(|resource| {
            provider
                .current_lease(resource)
                .map_err(debug)?
                .map(|lease| HostLeaseRecordMaterial {
                    resource: lease.resource,
                    owner: lease.owner,
                    epoch: lease.epoch,
                })
                .ok_or_else(|| format!("lease for {resource:?} is absent"))
        })
        .collect()
}

const fn receipt_kind_name(kind: ReceiptKind) -> &'static str {
    match kind {
        ReceiptKind::PrepareIntent => "prepare-intent",
        ReceiptKind::VisaFreeze => "visa-freeze",
        ReceiptKind::NexusFreeze => "nexus-freeze",
        ReceiptKind::DestinationPrepared => "destination-prepared",
        ReceiptKind::OwnershipPrepared => "ownership-prepared",
        ReceiptKind::OwnershipAbort => "ownership-abort",
        ReceiptKind::OwnershipCommit => "ownership-commit",
        ReceiptKind::NexusThaw => "nexus-thaw",
        ReceiptKind::ClosureProgress => "closure-progress",
        ReceiptKind::Closure => "closure",
        ReceiptKind::RetainedTombstone => "retained-tombstone",
        ReceiptKind::VisaSourceFence => "visa-source-fence",
        ReceiptKind::VisaSourceResume => "visa-source-resume",
        ReceiptKind::VisaDestinationActivation => "visa-destination-activation",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticationError {
    WrongHandoff,
    WrongIssuer,
    InvalidTag,
    Encoding,
}

#[derive(Clone)]
struct CellAuthenticator {
    key: JointHandoffKey,
    issuers: JointIssuerSet,
    secret: [u8; 32],
}

impl CellAuthenticator {
    fn envelope<T: TypedReceipt>(
        &self,
        receipt: &T,
        request: &ReceiptRequest,
        payload: &[u8],
    ) -> Result<ReceiptEnvelope, String> {
        let header = receipt.header();
        let mut envelope = ReceiptEnvelope {
            schema: header.version,
            issuer: header.issuer,
            issuer_incarnation: header.issuer_incarnation,
            kind: T::KIND,
            handoff: receipt.key().handoff,
            request_digest: request.digest().map_err(debug)?,
            state_sequence: header.sequence,
            payload_digest: joint_digest(receipt).map_err(debug)?,
            previous_receipt_digest: header.previous_digest,
            authentication: Vec::new(),
        };
        envelope.authentication = self.authentication(&envelope, payload).map_err(debug)?;
        Ok(envelope)
    }

    fn authentication(
        &self,
        envelope: &ReceiptEnvelope,
        payload: &[u8],
    ) -> Result<Vec<u8>, AuthenticationError> {
        let projection = joint_bytes(&(
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
        .map_err(|_| AuthenticationError::Encoding)?;
        let mut digest = Sha256::new();
        digest.update(AUTHENTICATION_DOMAIN);
        digest.update(self.secret);
        digest.update((projection.len() as u64).to_be_bytes());
        digest.update(projection);
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);
        Ok(digest.finalize().to_vec())
    }
}

impl NativeReceiptAuthenticator for CellAuthenticator {
    type Error = AuthenticationError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        _envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        if envelope.handoff != self.key.handoff {
            return Err(AuthenticationError::WrongHandoff);
        }
        let expected = expected_issuer(self.issuers, envelope.kind);
        if envelope.issuer != expected.issuer
            || envelope.issuer_incarnation != expected.issuer_incarnation
        {
            return Err(AuthenticationError::WrongIssuer);
        }
        if envelope.authentication != self.authentication(envelope, payload_bytes)? {
            return Err(AuthenticationError::InvalidTag);
        }
        Ok(())
    }
}

fn expected_issuer(issuers: JointIssuerSet, kind: ReceiptKind) -> ReceiptIssuerIdentity {
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

fn header(
    issuer: ReceiptIssuerIdentity,
    kind: ReceiptKind,
    sequence: u64,
    previous_digest: Option<Digest>,
) -> ReceiptHeader {
    ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: issuer.issuer,
        issuer_incarnation: issuer.issuer_incarnation,
        key_id: issuer.key_id,
        log_id: issuer.log_id,
        sequence,
        previous_digest,
    }
}

#[derive(Clone)]
struct Fixture {
    source_node: NodeIdentity,
    destination_node: NodeIdentity,
    source_component: EntityRef,
    destination_component: EntityRef,
    timer: EntityRef,
    key_value: EntityRef,
    namespace: Identity,
    source_handoff_authority: EntityRef,
    source_timer_authority: EntityRef,
    source_key_value_authority: EntityRef,
    destination_handoff_authority: EntityRef,
    destination_timer_authority: EntityRef,
    destination_key_value_authority: EntityRef,
    attenuated_handoff_authority: EntityRef,
    attenuated_timer_authority: EntityRef,
    attenuated_key_value_authority: EntityRef,
    handoff: Identity,
    snapshot: Identity,
    component_digest: Digest,
    profile_digest: Digest,
}

impl Fixture {
    fn new() -> Self {
        let source_component = entity(1);
        Self {
            source_node: NodeIdentity::new(id(10)),
            destination_node: NodeIdentity::new(id(11)),
            source_component,
            destination_component: EntityRef::new(source_component.identity, Generation(1)),
            timer: entity(2),
            key_value: entity(3),
            namespace: id(4),
            source_handoff_authority: entity(20),
            source_timer_authority: entity(21),
            source_key_value_authority: entity(22),
            destination_handoff_authority: entity(30),
            destination_timer_authority: entity(31),
            destination_key_value_authority: entity(32),
            attenuated_handoff_authority: entity(40),
            attenuated_timer_authority: entity(41),
            attenuated_key_value_authority: entity(42),
            handoff: id(50),
            snapshot: id(51),
            component_digest: digest(1),
            profile_digest: digest(2),
        }
    }

    fn initial_state(&self) -> CanonicalState {
        CanonicalState::dormant(
            self.source_component,
            self.source_node,
            self.component_digest,
            self.profile_digest,
            CONTRACT_VERSION,
            ResourceClaims {
                timer: TimerClaim {
                    resource: self.timer,
                    clock: TimerClock::PausedMonotonicDuration,
                    required_rights: timer_rights(),
                },
                key_value: KeyValueClaim {
                    resource: self.key_value,
                    namespace: self.namespace,
                    required_rights: key_value_rights(),
                    delivery: DeliveryPolicy::Deduplicated,
                },
            },
            self.source_grants(),
        )
    }

    fn source_grants(&self) -> Vec<AuthorityGrant> {
        vec![
            AuthorityGrant::active_root(
                self.source_handoff_authority,
                self.source_component,
                self.source_component,
                Rights::HANDOFF,
            ),
            AuthorityGrant::active_root(
                self.source_timer_authority,
                self.source_component,
                self.timer,
                timer_rights(),
            ),
            AuthorityGrant::active_root(
                self.source_key_value_authority,
                self.source_component,
                self.key_value,
                key_value_rights(),
            ),
        ]
    }

    fn source_provider(&self, path: &Path) -> Result<SqliteProvider, String> {
        let mut provider = SqliteProvider::open(
            path,
            JournalScope { node: self.source_node, component: self.source_component.identity },
        )
        .map_err(debug)?;
        self.configure_source(&mut provider)?;
        Ok(provider)
    }

    fn destination_provider(&self, path: &Path) -> Result<SqliteProvider, String> {
        let mut provider = SqliteProvider::open(
            path,
            JournalScope {
                node: self.destination_node,
                component: self.destination_component.identity,
            },
        )
        .map_err(debug)?;
        for (resource, rights) in [
            (self.destination_component, Rights::HANDOFF),
            (self.timer, timer_rights()),
            (self.key_value, key_value_rights()),
        ] {
            provider
                .install_policy(AuthorityPolicy {
                    subject: self.destination_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(debug)?;
        }
        provider
            .provision_key_value_namespace_availability(self.destination_node, self.namespace)
            .map_err(debug)?;
        Ok(provider)
    }

    fn seed_destination_ownership(
        &self,
        path: &Path,
        initial: &CanonicalState,
    ) -> Result<(), String> {
        let mut provider = SqliteProvider::open(
            path,
            JournalScope { node: self.source_node, component: self.source_component.identity },
        )
        .map_err(debug)?;
        self.configure_source(&mut provider)?;
        let mut coordinator = Coordinator::recover(initial.clone(), provider).map_err(debug)?;
        coordinator
            .activate(id(105), self.source_handoff_authority, INITIAL_EPOCH)
            .map_err(debug)?;
        Ok(())
    }

    fn configure_source(&self, provider: &mut SqliteProvider) -> Result<(), String> {
        for (resource, rights) in [
            (self.source_component, Rights::HANDOFF),
            (self.timer, timer_rights()),
            (self.key_value, key_value_rights()),
        ] {
            provider
                .install_policy(AuthorityPolicy {
                    subject: self.source_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(debug)?;
        }
        for grant in self.source_grants() {
            provider.install_grant(&grant).map_err(debug)?;
        }
        provider.provision_key_value_namespace(self.key_value, self.namespace).map_err(debug)
    }

    fn handoff_plan(&self) -> AuthorityPlan {
        AuthorityPlan {
            source_authority: self.source_handoff_authority,
            destination_authority: self.destination_handoff_authority,
            attenuated_authority: self.attenuated_handoff_authority,
        }
    }

    fn timer_plan(&self) -> AuthorityPlan {
        AuthorityPlan {
            source_authority: self.source_timer_authority,
            destination_authority: self.destination_timer_authority,
            attenuated_authority: self.attenuated_timer_authority,
        }
    }

    fn key_value_plan(&self) -> AuthorityPlan {
        AuthorityPlan {
            source_authority: self.source_key_value_authority,
            destination_authority: self.destination_key_value_authority,
            attenuated_authority: self.attenuated_key_value_authority,
        }
    }
}

struct CellPaths {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    ownership: PathBuf,
    projection: PathBuf,
}

impl CellPaths {
    fn new() -> Result<Self, String> {
        let sequence = NEXT_CELL.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .join(format!("visa-joint-coordinator-cell-{}-{sequence}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).map_err(debug)?;
        }
        fs::create_dir_all(&root).map_err(debug)?;
        Ok(Self {
            source: root.join("source.sqlite"),
            destination: root.join("destination.sqlite"),
            ownership: root.join("ownership.sqlite"),
            projection: root.join("joint-projection.sqlite"),
            root,
        })
    }
}

impl Drop for CellPaths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const fn timer_rights() -> Rights {
    Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
}

const fn key_value_rights() -> Rights {
    Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: id(base),
        issuer_incarnation: id(base + 1),
        key_id: id(base + 2),
        log_id: id(base + 3),
    }
}

fn entity(value: u128) -> EntityRef {
    EntityRef::initial(id(value))
}

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn require(condition: bool, detail: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(detail.to_owned()) }
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use contract_core::EventKind;
    use visa_conformance::{
        JointHostProjectionTranscript, JointHostSubstrateCellReport,
        validate_joint_host_substrate_raw_material,
    };
    use visa_joint_handoff::{JointProjectionRecord, JointProjectionRecordKind};

    use super::*;

    #[test]
    fn real_sqlite_coordinators_complete_authenticated_joint_projection() {
        let report = run_coordinator_vertical_cell().unwrap();
        assert_eq!(report.schema, HOST_SUBSTRATE_CELL_SCHEMA);
        assert_eq!(report.authenticated_receipt_count, 9);
        assert_eq!(report.source_phase, "committed");
        assert_eq!(report.source_activation, "fenced");
        assert_eq!(report.destination_phase, "running");
        assert_eq!(report.destination_activation, "active");
        assert!(report.source_reopened);
        assert!(report.source_owner_is_destination);
        assert!(report.destination_owner_is_destination);
        assert_eq!(report.destination_component_generation, report.source_component_generation + 1);
        assert!(report.independent_source_destination_databases);
        assert!(report.same_boot_only);
        assert!(report.exclusive_trusted_coordinator_api);
        assert_eq!(report.authentication_scheme, HOST_SUBSTRATE_AUTHENTICATION_SCHEME);
        assert_eq!(report.native_receipts.len(), 9);
        assert_eq!(report.source_journal.len(), 5);
        assert_eq!(report.destination_journal.len(), 4);
        assert_eq!(report.source_leases.len(), 2);
        assert_eq!(report.destination_leases.len(), 2);
        assert_eq!(report.source_terminal_state.phase, HandoffPhase::Committed);
        assert_eq!(report.destination_terminal_state.phase, HandoffPhase::Running);
        assert_ne!(report.snapshot_integrity, Digest::ZERO);
        assert_ne!(report.prepared_destination_digest, Digest::ZERO);
        assert_ne!(report.lease_commit_request_digest, Digest::ZERO);
    }

    #[test]
    fn conformance_recomputes_the_host_cell_from_raw_material() {
        let report = conformance_report();
        validate_joint_host_substrate_raw_material(&report).unwrap();
    }

    #[test]
    fn host_raw_verifier_rejects_rehashed_lineage_and_checkpoint_mutations() {
        let baseline = conformance_report();
        validate_joint_host_substrate_raw_material(&baseline).unwrap();

        let mut peer = baseline.clone();
        let bytes = peer.native_receipts[0].peer_invocation.as_deref().unwrap();
        let mut invocation: OwnershipReserveRequest =
            joint_handoff_core::canonical_from_bytes(bytes).unwrap();
        invocation.expected_state_sequence = 1;
        peer.native_receipts[0].peer_invocation = Some(joint_bytes(&invocation).unwrap());
        assert_raw_rejected("canonical peer invocation substitution", &peer);

        let mut source_observed = baseline.clone();
        let mut records = decode_projection(&source_observed.durable_projection.commit_transcript);
        let JointProjectionRecordKind::SourceFenceObserved(observed) = &mut records[9].kind else {
            panic!("record 10 is not SourceFenceObserved")
        };
        observed.state_digest = digest(0xe1);
        let heads = reseal_projection(
            &mut source_observed.durable_projection.commit_transcript,
            &mut records,
        );
        sync_commit_heads(&mut source_observed, &heads);
        assert_raw_rejected("rehashed source observation", &source_observed);

        let mut destination_parent = baseline.clone();
        let mut records =
            decode_projection(&destination_parent.durable_projection.commit_transcript);
        let JointProjectionRecordKind::DestinationActivationAttempt(attempt) =
            &mut records[11].kind
        else {
            panic!("record 12 is not DestinationActivationAttempt")
        };
        attempt.source_fence.digest = digest(0xe2);
        attempt.request_digest = attempt.derived_request_digest().unwrap();
        let heads = reseal_projection(
            &mut destination_parent.durable_projection.commit_transcript,
            &mut records,
        );
        sync_commit_heads(&mut destination_parent, &heads);
        assert_raw_rejected("rehashed destination parent", &destination_parent);

        let mut abort_observed = baseline.clone();
        let mut records =
            decode_projection(&abort_observed.durable_projection.source_abort.transcript);
        let JointProjectionRecordKind::SourceAbortObserved(observed) = &mut records[7].kind else {
            panic!("abort record 8 is not SourceAbortObserved")
        };
        observed.state_digest = digest(0xe3);
        let heads = reseal_projection(
            &mut abort_observed.durable_projection.source_abort.transcript,
            &mut records,
        );
        sync_abort_heads(&mut abort_observed, &heads);
        assert_raw_rejected("rehashed abort observation", &abort_observed);

        let mut checkpoint = baseline.clone();
        checkpoint.durable_projection.destination_checkpoint.local_state =
            checkpoint.destination_terminal_state.clone();
        checkpoint.durable_projection.destination_checkpoint.local_journal =
            checkpoint.destination_journal.clone();
        assert_raw_rejected("post-resume state substituted for checkpoint", &checkpoint);

        let mut event_digest = baseline.clone();
        let EventKind::JointDestinationResumed { activation_record_digest } =
            &mut event_digest.destination_journal[3].event.kind
        else {
            panic!("destination terminal is not JointDestinationResumed")
        };
        *activation_record_digest = digest(0xe4);
        assert_raw_rejected("activation event digest substitution", &event_digest);

        let mut prefix = baseline.clone();
        let mut records = decode_projection(&prefix.durable_projection.commit_transcript);
        records.pop();
        reseal_projection(&mut prefix.durable_projection.commit_transcript, &mut records);
        assert_raw_rejected("shorter valid projection prefix", &prefix);
    }

    fn conformance_report() -> JointHostSubstrateCellReport {
        serde_json::from_value(
            serde_json::to_value(run_coordinator_vertical_cell().unwrap()).unwrap(),
        )
        .unwrap()
    }

    fn assert_raw_rejected(label: &str, report: &JointHostSubstrateCellReport) {
        assert!(
            validate_joint_host_substrate_raw_material(report).is_err(),
            "raw HostSubstrate verifier accepted {label}",
        );
    }

    fn decode_projection(transcript: &JointHostProjectionTranscript) -> Vec<JointProjectionRecord> {
        transcript
            .canonical_record_bytes
            .iter()
            .map(|bytes| JointProjectionRecord::from_canonical_bytes(bytes).unwrap())
            .collect()
    }

    fn reseal_projection(
        transcript: &mut JointHostProjectionTranscript,
        records: &mut [JointProjectionRecord],
    ) -> Vec<visa_conformance::JointProjectionLogHead> {
        let mut previous = None;
        let mut heads = Vec::with_capacity(records.len());
        transcript.canonical_record_bytes.clear();
        for (index, record) in records.iter_mut().enumerate() {
            record.sequence = u64::try_from(index).unwrap() + 1;
            record.previous_record_digest = previous;
            let record_digest = record.canonical_digest().unwrap();
            transcript.canonical_record_bytes.push(record.canonical_bytes().unwrap());
            let mut head = transcript.head;
            head.sequence = record.sequence;
            head.record_digest = record_digest;
            heads.push(head);
            previous = Some(record_digest);
        }
        transcript.head = *heads.last().unwrap();
        heads
    }

    fn sync_commit_heads(
        report: &mut JointHostSubstrateCellReport,
        heads: &[visa_conformance::JointProjectionLogHead],
    ) {
        let source = &mut report.durable_projection.source_fence;
        source.conflict_head_before = heads[7];
        source.conflict_head_after = heads[7];
        source.attempt_head = heads[8];
        source.reopened_attempt_head = heads[8];
        source.completion_head = heads[10];
        source.reopened_completion_head = heads[10];
        let destination = &mut report.durable_projection.destination_activation;
        destination.conflict_head_before = heads[10];
        destination.conflict_head_after = heads[10];
        destination.attempt_head = heads[11];
        destination.reopened_attempt_head = heads[11];
        destination.completion_head = heads[13];
        destination.reopened_completion_head = heads[13];
        report.durable_projection.destination_checkpoint.joint_completion_head = heads[13];
        report.durable_projection.destination_checkpoint.activation_completion_record_digest =
            heads[13].record_digest;
        let EventKind::JointDestinationResumed { activation_record_digest } =
            &mut report.destination_journal[3].event.kind
        else {
            panic!("destination terminal is not JointDestinationResumed")
        };
        *activation_record_digest = heads[13].record_digest;
    }

    fn sync_abort_heads(
        report: &mut JointHostSubstrateCellReport,
        heads: &[visa_conformance::JointProjectionLogHead],
    ) {
        let window = &mut report.durable_projection.source_abort.observation;
        window.conflict_head_before = heads[5];
        window.conflict_head_after = heads[5];
        window.attempt_head = heads[6];
        window.reopened_attempt_head = heads[6];
        window.completion_head = heads[8];
        window.reopened_completion_head = heads[8];
    }
}
