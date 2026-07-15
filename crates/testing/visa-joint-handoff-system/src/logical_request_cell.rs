use std::{fs, path::Path};

use contract_core::{
    AuthorityGrant, CONTRACT_VERSION, DeliveryPolicy, Digest, EffectKind, EffectOutcome,
    EffectRequest, EffectResult, EntityRef, Event, EventKind, Extension, IdempotencyKey, Identity,
    JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, ProfileAccess, Rights, SchemaVersion,
    canonical_bytes, canonical_digest, canonical_from_bytes,
};
use joint_handoff_core::{
    ClosureReceipt, FreezeDisposition, JointHandoffKey, NexusFreezeReceipt, OwnershipCommitReceipt,
    OwnershipPreparedReceipt, PrepareIntentReceipt, PreparedBindings, ReceiptIssuerIdentity,
    ReceiptKind, ReceiptRef, TypedReceipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, JournalPort, JournalScope, LeasePort, LeaseRecord, ProfilePort,
    ProviderErrorKind,
};
use substrate_host::{
    FaultPoint, LoopbackLogicalPeer, LoopbackLogicalPeerBehavior, SqliteProvider,
};
use visa_conformance::{JointEffectClassification, JointEffectRecord, joint_effect_cohort_digest};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectPeer, EffectPeerConfig,
    EffectPeerError, EffectPublicationRequest, EffectPublicationResult, NativeJsonlExchange,
    NativeResponseLossObservation, NexusProcessQualificationInputs, OwnershipCommitRequest,
    OwnershipQuery, OwnershipReserveRequest, OwnershipSealRequest, ProcessEffectPeer,
    ProcessEffectPeerIdentity, ReferenceOwnershipLog, effect_receipt_issuer,
    nexus_effect_wire::{
        NativeHandoffStatus, NativeReceiptPayload, PeerCommand, PeerRequest, PeerResponse,
    },
    ownership_receipt_issuer,
};

pub const LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA: &str = "visa.logical-request-dual-lost-ack-cell.v1";
pub const LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT: &str = "logical-request-dual-lost-ack.json";

const PROVIDER_DATABASE: &str = "logical-request-provider.sqlite3";
const OWNERSHIP_DATABASE: &str = "logical-request-ownership.sqlite3";
const SAME_BOOT_BOUNDARY: &str =
    "same-boot-real-logical-request-provider-plus-sqlite-ownership-plus-nexus-process";
const LOGICAL_REQUEST_PROFILE_ID: Identity = Identity::from_bytes(*b"visa:req:v1\0\0\0\0\0");
const LOGICAL_REQUEST_PROFILE_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

// Exact canonical v1 shapes consumed by substrate_host's production
// visa_profile decoder. Keeping the experiment on the existing allowed
// dependency edge avoids making this system crate a second profile owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestTransportWire {
    Reconnectable,
    RawLiveTcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestReplayWire {
    Never,
    BeforeSend,
    IfIdempotent,
    WithOperationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestIdempotencyWire {
    NonIdempotent,
    Idempotent,
    OperationIdDeduplicated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestPhaseWire {
    Ready,
    Pending,
    PartialResponse,
    UnknownCompletion,
    Reconciling,
    Replaying,
    Cancelling,
    Completed,
    TimedOut,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestRejectionWire {
    PeerMismatch,
    CredentialDenied,
    UnsafeReplay,
    UnsupportedTransport,
    PolicyDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum ContinuityDispositionWire {
    Revalidate,
    Reconnect,
    Replay,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalRequestClaimWire {
    resource: EntityRef,
    peer_identity: Vec<u8>,
    credential_reference: Identity,
    required_rights: Rights,
    transport: LogicalRequestTransportWire,
    delivery: DeliveryPolicy,
    replay: LogicalRequestReplayWire,
    idempotency: LogicalRequestIdempotencyWire,
    timeout_millis: u64,
    max_request_size: u32,
    max_response_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalResponseMetadataWire {
    size: u32,
    digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalRequestStateWire {
    claim: LogicalRequestClaimWire,
    operation_id: Identity,
    request_size: u32,
    request_digest: Digest,
    phase: LogicalRequestPhaseWire,
    response_cursor: u32,
    response: Option<LogicalResponseMetadataWire>,
    rejection: Option<LogicalRequestRejectionWire>,
    disposition: ContinuityDispositionWire,
    last_operation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestOperationWire {
    Start { request: Vec<u8> },
    Observe { max_bytes: u32 },
    Reconcile,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalRequestObservationWire {
    phase: LogicalRequestPhaseWire,
    response: Option<LogicalResponseMetadataWire>,
    rejection: Option<LogicalRequestRejectionWire>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum LogicalRequestResultWire {
    Started { observation: LogicalRequestObservationWire },
    Observed { observation: LogicalRequestObservationWire, bytes: Vec<u8>, response_cursor: u32 },
    Reconciled { observation: LogicalRequestObservationWire },
    Cancelled { observation: LogicalRequestObservationWire },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestDualLostAckInputs {
    pub run_identity: Identity,
    pub nexus: NexusProcessQualificationInputs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestDualLostAckReport {
    pub schema: String,
    pub all_passed: bool,
    pub boundary: String,
    pub same_boot_only: bool,
    pub cross_reboot_claimed: bool,
    pub process_backed_nexus: bool,
    pub reference_effect_peer_used: bool,
    pub run_identity: Identity,
    pub logical_request: LogicalRequestProviderEvidence,
    pub binding: LogicalRequestNexusBindingEvidence,
    pub ownership_commit_ack_loss: OwnershipCommitAckLossEvidence,
    pub nexus_terminal_response_loss: NexusTerminalResponseLossEvidence,
    pub terminal: LogicalRequestTerminalEvidence,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBoundaryExchange {
    pub boundary: String,
    pub operation: String,
    pub request_json: String,
    pub response_json: String,
    pub request_sha256: String,
    pub response_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestProviderEvidence {
    pub provider_database: String,
    pub operation_id: Identity,
    pub canonical_effect_operation: Identity,
    pub resource: EntityRef,
    pub request_digest: Digest,
    pub completed_state_digest: Digest,
    pub outcome_digest: Digest,
    pub fault_point: String,
    pub fault_was_injected_after_durable_commit: bool,
    pub initial_return: String,
    pub durable_query_exact: bool,
    pub exact_retry: bool,
    pub reopen_query_exact: bool,
    pub remote_execution_count: u64,
    pub remote_request_count: u64,
    pub application_request_present_on_wire: bool,
    pub credential_present_on_wire: bool,
    pub tcp_raw_frame_capture_available: bool,
    pub exchange: CanonicalBoundaryExchange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestNexusBindingEvidence {
    pub logical_operation_id: Identity,
    pub nexus_effect: JointEffectRecord,
    pub logical_operation_is_nexus_effect_identity: bool,
    pub canonical_effect_operation_matches: bool,
    pub recomputed_effect_cohort_digest: Digest,
    pub freeze: NexusFreezeReceipt,
    pub ownership_prepared: OwnershipPreparedReceipt,
    pub ownership_commit: OwnershipCommitReceipt,
    pub closure: ClosureReceipt,
    pub cohort_bound_into_prepared: bool,
    pub prepared_bound_into_commit: bool,
    pub commit_and_freeze_bound_into_closure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipCommitAckLossEvidence {
    pub database: String,
    pub journal_mode: String,
    pub synchronous: i64,
    pub transport_fault_injection_available: bool,
    pub loss_model: String,
    pub commit_exchange: CanonicalBoundaryExchange,
    pub query_exchange: CanonicalBoundaryExchange,
    pub retry_exchange: CanonicalBoundaryExchange,
    pub query_after_reopen_exact: bool,
    pub retry_exact: bool,
    pub owner_advanced_to_destination: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExactReplayEvidence {
    pub request_id: u64,
    pub command: String,
    pub original_request_jsonl: String,
    pub original_response_jsonl: String,
    pub replay_response_jsonl: String,
    pub byte_identical: bool,
    pub accepted_chain_length_before: usize,
    pub accepted_chain_length_after: usize,
    pub accepted_chain_grew_once: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NexusTerminalResponseLossEvidence {
    pub process: ProcessEffectPeerIdentity,
    pub transport_fault_injection_available: bool,
    pub loss_model: String,
    pub publication_first: String,
    pub duplicate_publication: String,
    pub duplicate_publication_extended_native_chain: bool,
    pub close_steps: u64,
    pub terminal_query_recovered_exact: bool,
    pub exact_replay: NativeExactReplayEvidence,
    pub native_chain: Vec<NativeJsonlExchange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestTerminalEvidence {
    pub logical_request_completed: bool,
    pub remote_execution_count: u64,
    pub ownership_owner: NodeIdentity,
    pub ownership_epoch: LeaseEpoch,
    pub nexus_gate_open: bool,
    pub nexus_effect_count: usize,
    pub native_register_count: usize,
    pub native_prepare_count: usize,
    pub native_commit_count: usize,
    pub source_closed: bool,
    pub no_duplicate_external_execution: bool,
    pub no_duplicate_nexus_publication: bool,
}

#[derive(Clone)]
struct ExperimentFixture {
    key: JointHandoffKey,
    ownership_namespace: ReceiptIssuerIdentity,
    effect_config: EffectPeerConfig,
    logical_resource: EntityRef,
    logical_authority: EntityRef,
    logical_operation: Identity,
    canonical_effect_operation: Identity,
    idempotency: IdempotencyKey,
    credential_reference: Identity,
    peer_identity: Vec<u8>,
    credential: Vec<u8>,
    request: Vec<u8>,
    response: Vec<u8>,
}

struct ProviderRun {
    completed: LogicalRequestStateWire,
    outcome: EffectOutcome,
    evidence: LogicalRequestProviderEvidence,
}

/// Runs one bounded same-boot experiment and retains its two SQLite databases
/// plus a strict JSON report under `root`.
///
/// The provider fault is a real post-commit fault. The ownership and Nexus
/// boundaries currently expose no drop-after-write transport hook, so their
/// loss models are deliberately recorded as discard-and-reconcile equivalents.
pub fn run_logical_request_dual_lost_ack_cell(
    root: impl AsRef<Path>,
    inputs: LogicalRequestDualLostAckInputs,
) -> Result<LogicalRequestDualLostAckReport, String> {
    require(!inputs.run_identity.is_zero(), "run identity must be nonzero")?;
    let root = root.as_ref();
    fs::create_dir_all(root).map_err(debug)?;
    let provider_path = root.join(PROVIDER_DATABASE);
    let ownership_path = root.join(OWNERSHIP_DATABASE);
    let report_path = root.join(LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT);
    for path in [&provider_path, &ownership_path, &report_path] {
        require(!path.exists(), "experiment output path already exists")?;
    }

    let fixture = ExperimentFixture::new(inputs.run_identity)?;
    let provider = run_provider_request(&provider_path, &fixture)?;
    let outcome_digest = canonical_digest(&provider.outcome).map_err(debug)?;
    let effect = JointEffectRecord {
        effect: provider.completed.operation_id,
        operation: fixture.canonical_effect_operation,
        domain: LOGICAL_REQUEST_PROFILE_ID,
        binding_generation: fixture.effect_config.scope_generation,
        classification: JointEffectClassification::Committed,
        outcome_digest: Some(outcome_digest),
        tombstone_digest: None,
    };

    let peer = ProcessEffectPeer::spawn(inputs.nexus.launch(), fixture.effect_config)
        .map_err(|error| format!("spawn Nexus process peer: {error:?}"))?;
    let process = peer
        .process_identity()
        .map_err(|error| format!("observe Nexus process identity: {error:?}"))?;
    let publication = publication_request(&fixture, effect.clone());
    require(
        peer.publish(publication.clone())
            .map_err(|error| format!("publish logical request to Nexus: {error:?}"))?
            == EffectPublicationResult::Published,
        "first Nexus logical-request publication was not new",
    )?;
    let native_after_first_publication = peer.native_transcript().map_err(debug)?;
    require(
        peer.publish(publication)
            .map_err(|error| format!("replay logical request publication: {error:?}"))?
            == EffectPublicationResult::Replay,
        "duplicate Nexus logical-request publication was not an exact replay",
    )?;
    let native_after_duplicate = peer.native_transcript().map_err(debug)?;
    require(
        native_after_first_publication == native_after_duplicate,
        "portable publication replay emitted another native operation",
    )?;

    let mut ownership =
        ReferenceOwnershipLog::open(&ownership_path, fixture.ownership_namespace).map_err(debug)?;
    ownership
        .initialize_unit(
            fixture.key.continuity_unit,
            fixture.key.source,
            fixture.key.expected_epoch,
        )
        .map_err(debug)?;
    let (journal_mode, synchronous) = ownership.durability_settings().map_err(debug)?;
    require(journal_mode.eq_ignore_ascii_case("wal"), "ownership log did not enable WAL")?;
    require(synchronous == 2, "ownership log did not retain synchronous=FULL")?;

    let reserve_request = OwnershipReserveRequest { key: fixture.key, expected_state_sequence: 0 };
    let intent = ownership.reserve(reserve_request).map_err(debug)?;
    let frozen = peer
        .freeze(EffectFreezeRequest {
            key: fixture.key,
            intent: intent.clone(),
            registry_instance: fixture.effect_config.registry_instance,
            scope_id: fixture.effect_config.scope_id,
            scope_generation: fixture.effect_config.scope_generation,
            authority_epoch: fixture.effect_config.authority_epoch,
            freeze_generation: fixture.effect_config.freeze_generation,
        })
        .map_err(|error| format!("freeze Nexus logical-request cohort: {error:?}"))?;
    require(
        frozen.receipt.disposition == FreezeDisposition::ReadyToCommit,
        "committed logical request did not freeze ready-to-commit",
    )?;
    let recomputed_effect_cohort_digest =
        joint_effect_cohort_digest(conformance_key(fixture.key)?, [effect.clone()])
            .map_err(debug)?;
    require(
        frozen.receipt.effect_cohort_digest == recomputed_effect_cohort_digest,
        "Nexus freeze did not bind the logical-request effect cohort",
    )?;

    let (seal_request, expected_prepared) =
        seal_request(&fixture, &provider.completed, &intent, &frozen.receipt)?;
    let prepared = ownership.seal(seal_request).map_err(debug)?;
    require(
        prepared == expected_prepared,
        "ownership seal result diverged from the exact prepared binding preview",
    )?;
    let commit_request = OwnershipCommitRequest {
        key: fixture.key,
        reservation: intent.reservation,
        prepared: prepared.receipt_ref().map_err(debug)?,
        expected_state_sequence: 2,
    };
    ownership.arm_next_commit_ack_loss().map_err(debug)?;
    let commit_error = match ownership.commit(commit_request) {
        Err(error) => error,
        Ok(_) => {
            return Err("armed ownership commit returned an acknowledgement after durable commit"
                .to_owned());
        }
    };
    require(
        commit_error == crate::OwnershipLogError::AcknowledgementLost,
        "ownership fault did not report AcknowledgementLost after commit",
    )?;
    let commit_exchange = exchange(
        "in-process-sqlite-ownership-api",
        "ownership.commit",
        &commit_request,
        &AcknowledgementLostCapture {
            error: "acknowledgement_lost",
            durable_write_completed: true,
        },
    )?;
    drop(ownership);

    let mut reopened =
        ReferenceOwnershipLog::open(&ownership_path, fixture.ownership_namespace).map_err(debug)?;
    let query_request = OwnershipQueryCapture { handoff: fixture.key.handoff };
    let Some(OwnershipQuery::CommitDecided(queried_commit)) =
        reopened.query(fixture.key.handoff).map_err(debug)?
    else {
        return Err("reopened ownership log did not recover the committed decision".to_owned());
    };
    let query_exchange = exchange(
        "in-process-sqlite-ownership-api",
        "ownership.query",
        &query_request,
        &queried_commit,
    )?;
    let retried_commit = reopened.commit(commit_request).map_err(debug)?;
    let retry_exchange = exchange(
        "in-process-sqlite-ownership-api",
        "ownership.commit-retry",
        &commit_request,
        &retried_commit,
    )?;
    require(retried_commit == queried_commit, "ownership retry changed the terminal decision")?;
    let unit = reopened
        .query_unit(fixture.key.continuity_unit)
        .map_err(debug)?
        .ok_or_else(|| "ownership unit disappeared after commit".to_owned())?;
    require(
        unit.owner == fixture.key.destination && unit.epoch == fixture.key.next_epoch,
        "ownership unit did not advance to the destination",
    )?;

    let (closure, close_steps, exact_replay) =
        close_and_replay_terminal(&peer, frozen.token, queried_commit.clone())?;
    let terminal_query =
        peer.query().map_err(|error| format!("query terminal Nexus state: {error:?}"))?;
    require(
        terminal_query.latest_close == Some(EffectCloseResult::Closed(closure.clone())),
        "Nexus query did not recover the discarded terminal close result",
    )?;
    require(
        !terminal_query.gate_open && terminal_query.effect_count == 1,
        "terminal Nexus query did not retain one closed logical-request effect",
    )?;
    peer.shutdown().map_err(|error| format!("shutdown Nexus process peer: {error:?}"))?;
    let native_chain = peer.native_transcript().map_err(debug)?;
    let (native_register_count, native_prepare_count, native_commit_count) =
        native_effect_command_counts(&native_chain)?;
    require(
        native_register_count == 1 && native_prepare_count == 1 && native_commit_count == 1,
        "logical request was published more than once into the Nexus process",
    )?;

    let commit_ref = queried_commit.receipt_ref().map_err(debug)?;
    let freeze_ref = frozen.receipt.receipt_ref().map_err(debug)?;
    let binding = LogicalRequestNexusBindingEvidence {
        logical_operation_id: provider.completed.operation_id,
        nexus_effect: effect.clone(),
        logical_operation_is_nexus_effect_identity: effect.effect
            == provider.completed.operation_id,
        canonical_effect_operation_matches: effect.operation == fixture.canonical_effect_operation,
        recomputed_effect_cohort_digest,
        freeze: frozen.receipt.clone(),
        ownership_prepared: prepared.clone(),
        ownership_commit: queried_commit.clone(),
        closure: closure.clone(),
        cohort_bound_into_prepared: prepared.bindings.effect_cohort_manifest_digest
            == recomputed_effect_cohort_digest,
        prepared_bound_into_commit: queried_commit.prepared
            == prepared.receipt_ref().map_err(debug)?,
        commit_and_freeze_bound_into_closure: closure.commit == commit_ref
            && closure.nexus_freeze == freeze_ref,
    };
    let terminal = LogicalRequestTerminalEvidence {
        logical_request_completed: provider.completed.phase == LogicalRequestPhaseWire::Completed,
        remote_execution_count: provider.evidence.remote_execution_count,
        ownership_owner: unit.owner,
        ownership_epoch: unit.epoch,
        nexus_gate_open: terminal_query.gate_open,
        nexus_effect_count: terminal_query.effect_count,
        native_register_count,
        native_prepare_count,
        native_commit_count,
        source_closed: matches!(terminal_query.latest_close, Some(EffectCloseResult::Closed(_))),
        no_duplicate_external_execution: provider.evidence.remote_execution_count == 1,
        no_duplicate_nexus_publication: native_register_count == 1
            && native_prepare_count == 1
            && native_commit_count == 1,
    };
    let report = LogicalRequestDualLostAckReport {
        schema: LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA.to_owned(),
        all_passed: true,
        boundary: SAME_BOOT_BOUNDARY.to_owned(),
        same_boot_only: true,
        cross_reboot_claimed: false,
        process_backed_nexus: true,
        reference_effect_peer_used: false,
        run_identity: inputs.run_identity,
        logical_request: provider.evidence,
        binding,
        ownership_commit_ack_loss: OwnershipCommitAckLossEvidence {
            database: OWNERSHIP_DATABASE.to_owned(),
            journal_mode,
            synchronous,
            transport_fault_injection_available: true,
            loss_model: "the ownership fault hook committed the SQLite transaction with WAL/FULL durability, suppressed the typed acknowledgement as AcknowledgementLost, then recovery dropped and reopened the connection, queried, and retried the exact request"
                .to_owned(),
            commit_exchange,
            query_exchange,
            retry_exchange,
            query_after_reopen_exact: true,
            retry_exact: retried_commit == queried_commit,
            owner_advanced_to_destination: unit.owner == fixture.key.destination
                && unit.epoch == fixture.key.next_epoch,
        },
        nexus_terminal_response_loss: NexusTerminalResponseLossEvidence {
            process,
            transport_fault_injection_available: true,
            loss_model: "the response-loss hook sent a real terminal close-step to the Nexus child, read and discarded its first JSONL response before adapter acceptance, then the identical close retry reused the exact request-id and admitted only the child's byte-identical replay"
                .to_owned(),
            publication_first: "published".to_owned(),
            duplicate_publication: "exact-replay".to_owned(),
            duplicate_publication_extended_native_chain: false,
            close_steps,
            terminal_query_recovered_exact: true,
            exact_replay,
            native_chain,
        },
        terminal,
        limitations: vec![
            "same boot only; the Nexus Registry and process receipt chain are not restored after host reboot"
                .to_owned(),
            "the logical-request peer exposes authenticated execution counters but not retained raw TCP frame bytes; the report retains the exact typed provider request/outcome and all raw Nexus JSONL"
                .to_owned(),
        ],
    };
    validate_report(&report)?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(debug)?;
    fs::write(report_path, &bytes).map_err(debug)?;
    let decoded: LogicalRequestDualLostAckReport = serde_json::from_slice(&bytes).map_err(debug)?;
    require(decoded == report, "logical-request report did not round-trip exactly")?;
    Ok(report)
}

impl ExperimentFixture {
    fn new(run: Identity) -> Result<Self, String> {
        let key = JointHandoffKey {
            continuity_unit: EntityRef::initial(derived_identity(run, b"continuity-unit")?),
            handoff: derived_identity(run, b"handoff")?,
            source: NodeIdentity::new(derived_identity(run, b"source-node")?),
            destination: NodeIdentity::new(derived_identity(run, b"destination-node")?),
            expected_epoch: LeaseEpoch(1),
            next_epoch: LeaseEpoch(2),
        };
        let ownership_namespace = issuer(run, b"ownership")?;
        let effect_config = EffectPeerConfig {
            key,
            issuer: effect_receipt_issuer(issuer(run, b"effect")?, key).map_err(debug)?,
            ownership_issuer: ownership_receipt_issuer(ownership_namespace, key).map_err(debug)?,
            registry_instance: derived_identity(run, b"registry-instance")?,
            scope_id: derived_identity(run, b"scope")?,
            scope_generation: 1,
            authority_epoch: 1,
            freeze_generation: 1,
            domain_bindings_digest: derived_digest(run, b"domain-bindings")?,
        };
        let idempotency =
            IdempotencyKey::from_bytes(derived_identity(run, b"provider-idempotency")?.0);
        Ok(Self {
            key,
            ownership_namespace,
            effect_config,
            logical_resource: EntityRef::initial(derived_identity(run, b"logical-resource")?),
            logical_authority: EntityRef::initial(derived_identity(run, b"logical-authority")?),
            logical_operation: derived_identity(run, b"logical-operation")?,
            canonical_effect_operation: derived_identity(run, b"logical-start-effect")?,
            idempotency,
            credential_reference: derived_identity(run, b"credential-reference")?,
            peer_identity: b"visa-joint-logical-request-peer-v1".to_vec(),
            credential: derived_digest(run, b"credential-material")?.0.to_vec(),
            request: b"visa-nexus-same-boot-logical-request-v1".to_vec(),
            response: b"logical-request-completed-once".to_vec(),
        })
    }
}

fn run_provider_request(path: &Path, fixture: &ExperimentFixture) -> Result<ProviderRun, String> {
    let peer = LoopbackLogicalPeer::spawn(
        fixture.peer_identity.clone(),
        fixture.credential.clone(),
        LoopbackLogicalPeerBehavior::Static(fixture.response.clone()),
    )
    .map_err(debug)?;
    let rights = Rights::PROFILE_READ
        .union(Rights::PROFILE_WRITE)
        .union(Rights::PROFILE_CONTROL)
        .union(Rights::REBIND);
    let state = LogicalRequestStateWire {
        claim: LogicalRequestClaimWire {
            resource: fixture.logical_resource,
            peer_identity: fixture.peer_identity.clone(),
            credential_reference: fixture.credential_reference,
            required_rights: rights,
            transport: LogicalRequestTransportWire::Reconnectable,
            delivery: DeliveryPolicy::Deduplicated,
            replay: LogicalRequestReplayWire::WithOperationId,
            idempotency: LogicalRequestIdempotencyWire::OperationIdDeduplicated,
            timeout_millis: 1_000,
            max_request_size: 4_096,
            max_response_size: 4_096,
        },
        operation_id: fixture.logical_operation,
        request_size: u32::try_from(fixture.request.len()).map_err(debug)?,
        request_digest: canonical_digest(fixture.request.as_slice()).map_err(debug)?,
        phase: LogicalRequestPhaseWire::Ready,
        response_cursor: 0,
        response: None,
        rejection: None,
        disposition: ContinuityDispositionWire::Revalidate,
        last_operation: None,
    };
    let scope =
        JournalScope { node: fixture.key.source, component: fixture.key.continuity_unit.identity };
    let mut provider = SqliteProvider::open(path, scope).map_err(debug)?;
    provider
        .install_policy(AuthorityPolicy {
            subject: fixture.key.continuity_unit,
            resource: fixture.logical_resource,
            allowed_rights: rights,
        })
        .map_err(debug)?;
    provider
        .install_grant(&AuthorityGrant::active_root(
            fixture.logical_authority,
            fixture.key.continuity_unit,
            fixture.logical_resource,
            rights,
        ))
        .map_err(debug)?;
    provider
        .initialize_lease(LeaseRecord {
            resource: fixture.logical_resource,
            owner: fixture.key.source,
            epoch: fixture.key.expected_epoch,
        })
        .map_err(debug)?;
    let state_bytes = canonical_bytes(&state).map_err(debug)?;
    let decoded_state = canonical_from_bytes(&state_bytes).map_err(debug)?;
    // Type inference here deliberately selects substrate_host's production
    // visa_profile::LogicalRequestState without adding a second dependency
    // edge to this experiment crate.
    provider
        .provision_logical_request(&decoded_state, peer.address(), &fixture.credential)
        .map_err(debug)?;
    let request = EffectRequest {
        operation: fixture.canonical_effect_operation,
        idempotency_key: fixture.idempotency,
        causal_parent: None,
        node: fixture.key.source,
        subject: fixture.key.continuity_unit,
        resource: fixture.logical_resource,
        authority: fixture.logical_authority,
        lease_epoch: fixture.key.expected_epoch,
        request_digest: state.request_digest,
        kind: EffectKind::Profile {
            profile: LOGICAL_REQUEST_PROFILE_ID,
            access: ProfileAccess::Write,
            payload: canonical_bytes(&LogicalRequestOperationWire::Start {
                request: fixture.request.clone(),
            })
            .map_err(debug)?,
        },
    };
    provider
        .append_entry(&JournalEntry {
            version: CONTRACT_VERSION,
            position: JournalPosition(1),
            input_state: derived_digest(fixture.logical_operation, b"input-state")?,
            output_state: derived_digest(fixture.logical_operation, b"prepared-state")?,
            event: Event::new(
                derived_identity(fixture.logical_operation, b"prepared-event")?,
                EventKind::EffectPrepared { request: request.clone() },
            ),
        })
        .map_err(debug)?;
    let extension = Extension {
        id: LOGICAL_REQUEST_PROFILE_ID,
        version: LOGICAL_REQUEST_PROFILE_VERSION,
        required: true,
        payload: state_bytes,
    };
    provider.inject_failure_once(FaultPoint::AfterLogicalRequestCommit);
    let initial_error = match provider.execute_profile(&request, &extension) {
        Err(error) => error,
        Ok(_) => {
            return Err(
                "logical-request test-control fault did not fire after provider commit".to_owned()
            );
        }
    };
    require(
        initial_error.kind == ProviderErrorKind::OutcomeUnknown,
        "logical-request post-commit fault did not report OutcomeUnknown",
    )?;
    let queried = provider
        .query_profile_operation(request.operation, request.idempotency_key)
        .map_err(debug)?
        .ok_or_else(|| "logical-request durable query lost the committed outcome".to_owned())?;
    let retried = provider.execute_profile(&request, &extension).map_err(debug)?;
    require(queried == retried, "logical-request exact retry changed its outcome")?;
    let EffectOutcome::Succeeded { result, .. } = &queried else {
        return Err("logical request did not complete successfully".to_owned());
    };
    let EffectResult::Profile { profile, payload } = result else {
        return Err("logical request returned a non-profile result".to_owned());
    };
    require(*profile == LOGICAL_REQUEST_PROFILE_ID, "logical request returned the wrong profile")?;
    let result: LogicalRequestResultWire = canonical_from_bytes(payload).map_err(debug)?;
    let LogicalRequestResultWire::Started { observation } = result else {
        return Err("logical request start returned the wrong result variant".to_owned());
    };
    require(
        observation.phase == LogicalRequestPhaseWire::Completed
            && observation.response.is_some()
            && observation.rejection.is_none(),
        "logical request did not return a completed observation",
    )?;
    let completed = LogicalRequestStateWire {
        phase: observation.phase,
        response: observation.response,
        rejection: observation.rejection,
        disposition: ContinuityDispositionWire::Revalidate,
        last_operation: Some(request.operation),
        ..state.clone()
    };
    require(
        completed.operation_id == state.operation_id
            && completed.phase == LogicalRequestPhaseWire::Completed,
        "logical request did not retain its stable operation ID through completion",
    )?;
    let execution_count = peer.execution_count();
    let request_count = peer.request_count();
    require(
        execution_count == 1 && request_count == 1,
        "logical request executed more than once after lost acknowledgement",
    )?;
    let request_on_wire = peer.received_wire_contains(&fixture.request);
    let credential_on_wire = peer.received_wire_contains(&fixture.credential);
    require(request_on_wire, "logical application request never reached the real peer")?;
    require(!credential_on_wire, "credential material appeared on the logical-request wire")?;
    let exchange = exchange(
        "typed-substrate-profile-api-canonical-json-capture",
        "logical-request.start-query-retry",
        &request,
        &queried,
    )?;
    let completed_state_digest = canonical_digest(&completed).map_err(debug)?;
    let outcome_digest = canonical_digest(&queried).map_err(debug)?;
    drop(provider);
    let reopened = SqliteProvider::open(path, scope).map_err(debug)?;
    let reopened_outcome = reopened
        .query_profile_operation(request.operation, request.idempotency_key)
        .map_err(debug)?
        .ok_or_else(|| "reopened logical-request provider lost its outcome".to_owned())?;
    require(reopened_outcome == queried, "reopened provider changed the logical outcome")?;
    Ok(ProviderRun {
        completed,
        outcome: queried,
        evidence: LogicalRequestProviderEvidence {
            provider_database: PROVIDER_DATABASE.to_owned(),
            operation_id: state.operation_id,
            canonical_effect_operation: request.operation,
            resource: state.claim.resource,
            request_digest: state.request_digest,
            completed_state_digest,
            outcome_digest,
            fault_point: "after-logical-request-commit".to_owned(),
            fault_was_injected_after_durable_commit: true,
            initial_return: "outcome-unknown".to_owned(),
            durable_query_exact: true,
            exact_retry: retried == reopened_outcome,
            reopen_query_exact: true,
            remote_execution_count: execution_count,
            remote_request_count: request_count,
            application_request_present_on_wire: request_on_wire,
            credential_present_on_wire: credential_on_wire,
            tcp_raw_frame_capture_available: false,
            exchange,
        },
    })
}

fn seal_request(
    fixture: &ExperimentFixture,
    completed: &LogicalRequestStateWire,
    intent: &PrepareIntentReceipt,
    freeze: &NexusFreezeReceipt,
) -> Result<(OwnershipSealRequest, OwnershipPreparedReceipt), String> {
    let intent_ref = intent.receipt_ref().map_err(debug)?;
    let effect_ref = freeze.receipt_ref().map_err(debug)?;
    let state_digest = canonical_digest(completed).map_err(debug)?;
    let visa = external_ref(fixture, ReceiptKind::VisaFreeze, b"visa-freeze", state_digest)?;
    let destination = external_ref(
        fixture,
        ReceiptKind::DestinationPrepared,
        b"destination-prepared",
        derived_digest(fixture.logical_operation, b"destination-state")?,
    )?;
    let request = OwnershipSealRequest {
        key: fixture.key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa,
        effect_freeze: effect_ref,
        destination_prepared: destination,
        bindings: PreparedBindings {
            prepare_intent_receipt_digest: intent_ref.digest,
            visa_freeze_receipt_digest: visa.digest,
            effect_freeze_receipt_digest: effect_ref.digest,
            snapshot: derived_identity(fixture.logical_operation, b"snapshot")?,
            snapshot_integrity_digest: derived_digest(
                fixture.logical_operation,
                b"snapshot-integrity",
            )?,
            source_journal_position: JournalPosition(1),
            source_state_digest: state_digest,
            component_digest: derived_digest(fixture.logical_operation, b"component")?,
            profile_digest: canonical_digest(&LOGICAL_REQUEST_PROFILE_ID).map_err(debug)?,
            destination_prepared_receipt_digest: destination.digest,
            destination_state_digest: derived_digest(
                fixture.logical_operation,
                b"destination-state",
            )?,
            prepared_authorities_digest: derived_digest(fixture.logical_operation, b"authorities")?,
            prepared_bindings_digest: derived_digest(fixture.logical_operation, b"bindings")?,
            effect_cohort_manifest_digest: freeze.effect_cohort_digest,
            joint_mapping_manifest_digest: derived_digest(
                fixture.logical_operation,
                b"joint-mapping",
            )?,
        },
        expected_state_sequence: 1,
    };
    // The caller executes the real seal. Returning this typed preview keeps
    // construction and later binding checks explicit without another write.
    let preview = OwnershipPreparedReceipt {
        header: joint_handoff_core::ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::OwnershipPrepared,
            issuer: fixture.effect_config.ownership_issuer.issuer,
            issuer_incarnation: fixture.effect_config.ownership_issuer.issuer_incarnation,
            key_id: fixture.effect_config.ownership_issuer.key_id,
            log_id: fixture.effect_config.ownership_issuer.log_id,
            sequence: 2,
            previous_digest: Some(intent_ref.digest),
        },
        key: fixture.key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa,
        nexus_freeze: effect_ref,
        destination_prepared: destination,
        bindings: request.bindings,
        prepared_revision: 2,
    };
    Ok((request, preview))
}

fn close_and_replay_terminal(
    peer: &ProcessEffectPeer,
    token: crate::EffectFreezeToken,
    commit: OwnershipCommitReceipt,
) -> Result<(ClosureReceipt, u64, NativeExactReplayEvidence), String> {
    let mut revision = 0;
    let mut arm_terminal_loss = false;
    let mut exact_replay = None;
    for step in 1..=16 {
        let request = EffectCloseRequest {
            token,
            commit: commit.clone(),
            expected_closure_revision: revision,
        };
        let result = if arm_terminal_loss {
            peer.arm_next_response_loss()
                .map_err(|error| format!("arm Nexus close response loss: {error:?}"))?;
            let lost_request_id = match peer.close(request.clone()) {
                Err(EffectPeerError::AcknowledgementLost { request_id }) => request_id,
                other => {
                    return Err(format!(
                        "armed Nexus close did not lose its real response: {other:?}"
                    ));
                }
            };
            let recovered = peer
                .close(request)
                .map_err(|error| format!("recover lost Nexus close response: {error:?}"))?;
            let observations = peer.response_loss_observations().map_err(debug)?;
            let observation = observations
                .last()
                .ok_or_else(|| "Nexus response-loss hook omitted its observation".to_owned())?;
            require(
                observation.request_id == lost_request_id,
                "Nexus response-loss observation changed request identity",
            )?;
            validate_lost_close_response(observation)?;
            exact_replay = Some(NativeExactReplayEvidence {
                request_id: observation.request_id,
                command: "close-step".to_owned(),
                original_request_jsonl: observation.request_jsonl.clone(),
                original_response_jsonl: observation.discarded_response_jsonl.clone(),
                replay_response_jsonl: observation.replay_response_jsonl.clone(),
                byte_identical: observation.byte_identical,
                accepted_chain_length_before: observation.accepted_chain_length_before,
                accepted_chain_length_after: observation.accepted_chain_length_after,
                accepted_chain_grew_once: observation.accepted_chain_length_before.checked_add(1)
                    == Some(observation.accepted_chain_length_after),
            });
            recovered
        } else {
            peer.close(request).map_err(|error| format!("Nexus close step {step}: {error:?}"))?
        };
        revision = result.closure_revision();
        match result {
            EffectCloseResult::Progress(progress) => {
                if progress.remaining_effects == 0 {
                    arm_terminal_loss = true;
                }
            }
            EffectCloseResult::RetainedTombstone(_) => {
                return Err("logical request unexpectedly retained a tombstone".to_owned());
            }
            EffectCloseResult::Closed(closure) => {
                let exact_replay = exact_replay.ok_or_else(|| {
                    "Nexus closed before the real response-loss hook was exercised".to_owned()
                })?;
                return Ok((closure, step, exact_replay));
            }
        }
    }
    Err("Nexus did not close the logical request within 16 steps".to_owned())
}

fn validate_lost_close_response(observation: &NativeResponseLossObservation) -> Result<(), String> {
    require(
        observation.byte_identical
            && observation.accepted_chain_length_before.checked_add(1)
                == Some(observation.accepted_chain_length_after),
        "lost Nexus response did not replay byte-identically into one accepted chain entry",
    )?;
    let request: PeerRequest =
        serde_json::from_str(observation.request_jsonl.trim_end_matches('\n')).map_err(debug)?;
    require(
        matches!(request.command, PeerCommand::CloseStep(_)),
        "Nexus response-loss hook did not target close-step",
    )?;
    let response: PeerResponse =
        serde_json::from_str(observation.replay_response_jsonl.trim_end_matches('\n'))
            .map_err(debug)?;
    let payload = response
        .receipt
        .ok_or_else(|| "replayed close response omitted its receipt".to_owned())?
        .payload;
    require(
        matches!(
            payload,
            NativeReceiptPayload::ClosureProgress(value)
                if value.status == NativeHandoffStatus::Closed
        ),
        "replayed close response was not terminal Closed",
    )
}

fn publication_request(
    fixture: &ExperimentFixture,
    record: JointEffectRecord,
) -> EffectPublicationRequest {
    EffectPublicationRequest {
        key: fixture.key,
        registry_instance: fixture.effect_config.registry_instance,
        scope_id: fixture.effect_config.scope_id,
        scope_generation: fixture.effect_config.scope_generation,
        source_epoch: fixture.key.expected_epoch,
        record,
    }
}

fn conformance_key(key: JointHandoffKey) -> Result<visa_conformance::JointHandoffKey, String> {
    let value = serde_json::to_value(key).map_err(debug)?;
    serde_json::from_value(value).map_err(debug)
}

fn native_effect_command_counts(
    chain: &[NativeJsonlExchange],
) -> Result<(usize, usize, usize), String> {
    let mut register = 0;
    let mut prepare = 0;
    let mut commit = 0;
    for exchange in chain {
        let request: PeerRequest =
            serde_json::from_str(exchange.request_jsonl.trim_end_matches('\n')).map_err(debug)?;
        match request.command {
            PeerCommand::Register(_) => register += 1,
            PeerCommand::Prepare(_) => prepare += 1,
            PeerCommand::Commit(_) => commit += 1,
            _ => {}
        }
    }
    Ok((register, prepare, commit))
}

fn validate_report(report: &LogicalRequestDualLostAckReport) -> Result<(), String> {
    require(report.schema == LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA, "wrong report schema")?;
    require(
        report.all_passed
            && report.same_boot_only
            && !report.cross_reboot_claimed
            && report.process_backed_nexus
            && !report.reference_effect_peer_used,
        "experiment boundary was overstated or not process-backed",
    )?;
    require(
        report.logical_request.fault_was_injected_after_durable_commit
            && report.logical_request.initial_return == "outcome-unknown"
            && report.logical_request.durable_query_exact
            && report.logical_request.exact_retry
            && report.logical_request.reopen_query_exact
            && report.logical_request.remote_execution_count == 1
            && report.logical_request.remote_request_count == 1
            && report.logical_request.application_request_present_on_wire
            && !report.logical_request.credential_present_on_wire,
        "logical-request provider evidence did not prove one recovered execution",
    )?;
    require(
        report.binding.logical_operation_is_nexus_effect_identity
            && report.binding.canonical_effect_operation_matches
            && report.binding.cohort_bound_into_prepared
            && report.binding.prepared_bound_into_commit
            && report.binding.commit_and_freeze_bound_into_closure,
        "logical-request identity was not bound through the Nexus/ownership receipts",
    )?;
    require(
        report.ownership_commit_ack_loss.transport_fault_injection_available
            && report.ownership_commit_ack_loss.query_after_reopen_exact
            && report.ownership_commit_ack_loss.retry_exact
            && report.ownership_commit_ack_loss.owner_advanced_to_destination,
        "ownership recovery evidence was incomplete",
    )?;
    require(
        report.nexus_terminal_response_loss.transport_fault_injection_available
            && report.nexus_terminal_response_loss.terminal_query_recovered_exact
            && report.nexus_terminal_response_loss.exact_replay.byte_identical
            && report.nexus_terminal_response_loss.exact_replay.accepted_chain_grew_once
            && !report.nexus_terminal_response_loss.duplicate_publication_extended_native_chain,
        "Nexus response-loss equivalent did not replay exactly",
    )?;
    require(
        report.terminal.logical_request_completed
            && report.terminal.remote_execution_count == 1
            && report.terminal.ownership_epoch == LeaseEpoch(2)
            && !report.terminal.nexus_gate_open
            && report.terminal.nexus_effect_count == 1
            && report.terminal.source_closed
            && report.terminal.no_duplicate_external_execution
            && report.terminal.no_duplicate_nexus_publication,
        "terminal state did not prove single execution and source closure",
    )
}

#[derive(Serialize)]
struct OwnershipQueryCapture {
    handoff: Identity,
}

#[derive(Serialize)]
struct AcknowledgementLostCapture {
    error: &'static str,
    durable_write_completed: bool,
}

fn exchange(
    boundary: &str,
    operation: &str,
    request: &impl Serialize,
    response: &impl Serialize,
) -> Result<CanonicalBoundaryExchange, String> {
    let request_json = serde_json::to_string(request).map_err(debug)?;
    let response_json = serde_json::to_string(response).map_err(debug)?;
    Ok(CanonicalBoundaryExchange {
        boundary: boundary.to_owned(),
        operation: operation.to_owned(),
        request_sha256: sha256_hex(request_json.as_bytes()),
        response_sha256: sha256_hex(response_json.as_bytes()),
        request_json,
        response_json,
    })
}

fn external_ref(
    fixture: &ExperimentFixture,
    kind: ReceiptKind,
    label: &[u8],
    digest: Digest,
) -> Result<ReceiptRef, String> {
    Ok(ReceiptRef {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        handoff: fixture.key.handoff,
        issuer: derived_identity(fixture.logical_operation, &[label, b"-issuer"].concat())?,
        issuer_incarnation: derived_identity(
            fixture.logical_operation,
            &[label, b"-incarnation"].concat(),
        )?,
        key_id: derived_identity(fixture.logical_operation, &[label, b"-key"].concat())?,
        log_id: derived_identity(fixture.logical_operation, &[label, b"-log"].concat())?,
        sequence: 1,
        digest,
    })
}

fn issuer(run: Identity, label: &[u8]) -> Result<ReceiptIssuerIdentity, String> {
    Ok(ReceiptIssuerIdentity {
        issuer: derived_identity(run, &[label, b"-issuer"].concat())?,
        issuer_incarnation: derived_identity(run, &[label, b"-incarnation"].concat())?,
        key_id: derived_identity(run, &[label, b"-key"].concat())?,
        log_id: derived_identity(run, &[label, b"-log"].concat())?,
    })
}

fn derived_identity(parent: Identity, label: &[u8]) -> Result<Identity, String> {
    let digest = derived_digest(parent, label)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(bytes);
    require(!identity.is_zero(), "derived identity was zero")?;
    Ok(identity)
}

fn derived_digest(parent: Identity, label: &[u8]) -> Result<Digest, String> {
    let digest = canonical_digest(&(
        b"vISA logical-request dual lost-ack cell v1".as_slice(),
        parent,
        label,
    ))
    .map_err(debug)?;
    require(digest != Digest::ZERO, "derived digest was zero")?;
    Ok(digest)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-joint-logical-request-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn real_logical_request_provider_commit_fault_queries_and_retries_once() {
        let root = TestRoot::new("provider");
        let fixture = ExperimentFixture::new(Identity::from_u128(1)).unwrap();
        let run = run_provider_request(&root.0.join(PROVIDER_DATABASE), &fixture).unwrap();
        assert_eq!(run.completed.operation_id, fixture.logical_operation);
        assert_eq!(run.completed.phase, LogicalRequestPhaseWire::Completed);
        assert!(run.evidence.fault_was_injected_after_durable_commit);
        assert!(run.evidence.durable_query_exact && run.evidence.reopen_query_exact);
        assert_eq!(run.evidence.remote_execution_count, 1);
        assert!(run.evidence.application_request_present_on_wire);
        assert!(!run.evidence.credential_present_on_wire);
    }

    #[test]
    fn derived_logical_request_identity_is_domain_separated() {
        let run = Identity::from_u128(9);
        assert_ne!(
            derived_identity(run, b"logical-operation").unwrap(),
            derived_identity(run, b"logical-start-effect").unwrap()
        );
        assert_ne!(
            derived_identity(run, b"logical-operation").unwrap(),
            derived_identity(Identity::from_u128(10), b"logical-operation").unwrap()
        );
    }

    #[test]
    #[ignore = "requires an explicitly identified, separately built nexus-effect-peer binary"]
    fn real_same_boot_logical_request_dual_lost_ack_cell() {
        let root = TestRoot::new("full");
        let inputs = LogicalRequestDualLostAckInputs {
            run_identity: Identity::from_u128(0x4c52_2d4e_4558_5553),
            nexus: NexusProcessQualificationInputs {
                executable: std::env::var_os("NEXUS_EFFECT_PEER_BIN")
                    .map(PathBuf::from)
                    .expect("NEXUS_EFFECT_PEER_BIN must name the built Nexus peer"),
                executable_sha256: std::env::var("NEXUS_EFFECT_PEER_SHA256")
                    .expect("NEXUS_EFFECT_PEER_SHA256 must pin the exact executable"),
                nexus_revision: std::env::var("NEXUS_EFFECT_PEER_REVISION")
                    .expect("NEXUS_EFFECT_PEER_REVISION must pin the Nexus revision"),
            },
        };
        let report = run_logical_request_dual_lost_ack_cell(&root.0, inputs).unwrap();
        assert!(report.all_passed && report.same_boot_only);
        assert!(!report.cross_reboot_claimed && !report.reference_effect_peer_used);
        assert_eq!(report.logical_request.remote_execution_count, 1);
        assert!(report.binding.logical_operation_is_nexus_effect_identity);
        assert!(report.ownership_commit_ack_loss.query_after_reopen_exact);
        assert!(report.nexus_terminal_response_loss.exact_replay.byte_identical);
        assert!(root.0.join(LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT).is_file());
    }
}
