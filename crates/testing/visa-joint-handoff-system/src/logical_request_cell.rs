use std::{fs, path::Path};

use contract_core::{
    AuthorityGrant, CONTRACT_VERSION, DeliveryPolicy, Digest, EffectKind, EffectOutcome,
    EffectRequest, EffectResult, EntityRef, Event, EventKind, Extension, IdempotencyKey, Identity,
    JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, ProfileAccess, Rights, SchemaVersion,
    canonical_bytes, canonical_digest, canonical_from_bytes,
};
use joint_handoff_core::{
    ClosureProgressReceipt, ClosureReceipt, FreezeDisposition, JointHandoffKey, NexusFreezeReceipt,
    OwnershipCommitReceipt, OwnershipPreparedReceipt, PrepareIntentReceipt, PreparedBindings,
    ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, TypedReceipt,
    canonical_digest as joint_canonical_digest,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, JournalPort, JournalScope, LeasePort, LeaseRecord, ProfilePort,
    ProviderErrorKind,
};
use substrate_host::{
    FaultPoint, LoopbackLogicalPeer, LoopbackLogicalPeerBehavior, SqliteProvider,
};
use visa_conformance::{
    JointEffectClassification, JointEffectRecord, joint_classification_counts,
    joint_classification_root, joint_effect_cohort_digest,
};

use crate::{
    EffectCloseRequest, EffectCloseResult, EffectFreezeRequest, EffectPeer, EffectPeerConfig,
    EffectPeerError, EffectPublicationRequest, EffectPublicationResult, NativeJsonlExchange,
    NativeResponseLossObservation, NexusProcessQualificationInputs, OwnershipCommitRequest,
    OwnershipQuery, OwnershipReserveRequest, OwnershipSealRequest, ProcessEffectPeer,
    ProcessEffectPeerIdentity, ReferenceOwnershipLog, effect_receipt_issuer,
    nexus_effect_wire::{
        CommitEffect, CommittedPayload, EffectSelector, FreezePayload, HandoffProgressPayload,
        InitializedPayload, NativeHandoffStatus, NativeOwnershipDecision, NativePrepareIntent,
        NativeReadiness, NativeReceiptPayload, PeerCommand, PeerConfig, PeerRequest, PeerResponse,
        RegisterEffect, RegisteredPayload,
    },
    ownership_receipt_issuer,
    process_effect_peer::{
        compact_digest, compact_identity, mapped_native_digest, mapped_u64_digest,
        validate_native_jsonl_chain,
    },
};

pub const LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA: &str = "visa.logical-request-dual-lost-ack-cell.v1";
pub const LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT: &str = "logical-request-dual-lost-ack.json";
pub const LOGICAL_REQUEST_PROVIDER_DATABASE: &str = "logical-request-provider.sqlite3";
pub const LOGICAL_REQUEST_OWNERSHIP_DATABASE: &str = "logical-request-ownership.sqlite3";
const SAME_BOOT_BOUNDARY: &str =
    "same-boot-real-logical-request-provider-plus-sqlite-ownership-plus-nexus-process";
const OWNERSHIP_LOSS_MODEL: &str = "the ownership fault hook committed the SQLite transaction with WAL/FULL durability, suppressed the typed acknowledgement as AcknowledgementLost, then recovery dropped and reopened the connection, queried, and retried the exact request";
const NEXUS_LOSS_MODEL: &str = "the response-loss hook sent a real terminal close-step to the Nexus child, read and discarded its first JSONL response before adapter acceptance, then the identical close retry reused the exact request-id and admitted only the child's byte-identical replay";
const REPORT_LIMITATIONS: [&str; 2] = [
    "same boot only; the Nexus Registry and process receipt chain are not restored after host reboot",
    "the logical-request peer exposes authenticated execution counters but not retained raw TCP frame bytes; the report retains the exact typed provider request/outcome and all raw Nexus JSONL",
];
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
/// All three fault legs use active post-commit acknowledgement-loss hooks: the
/// provider and ownership stores suppress their acknowledgements after durable
/// SQLite commits, while the Nexus adapter discards the child's terminal JSONL
/// response before accepting it and then replays the identical request ID.
pub fn run_logical_request_dual_lost_ack_cell(
    root: impl AsRef<Path>,
    inputs: LogicalRequestDualLostAckInputs,
) -> Result<LogicalRequestDualLostAckReport, String> {
    require(!inputs.run_identity.is_zero(), "run identity must be nonzero")?;
    let root = root.as_ref();
    fs::create_dir_all(root).map_err(debug)?;
    let provider_path = root.join(LOGICAL_REQUEST_PROVIDER_DATABASE);
    let ownership_path = root.join(LOGICAL_REQUEST_OWNERSHIP_DATABASE);
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
            error: "acknowledgement_lost".to_owned(),
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
            database: LOGICAL_REQUEST_OWNERSHIP_DATABASE.to_owned(),
            journal_mode,
            synchronous,
            transport_fault_injection_available: true,
            loss_model: OWNERSHIP_LOSS_MODEL.to_owned(),
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
            loss_model: NEXUS_LOSS_MODEL.to_owned(),
            publication_first: "published".to_owned(),
            duplicate_publication: "exact-replay".to_owned(),
            duplicate_publication_extended_native_chain: false,
            close_steps,
            terminal_query_recovered_exact: true,
            exact_replay,
            native_chain,
        },
        terminal,
        limitations: REPORT_LIMITATIONS.map(str::to_owned).to_vec(),
    };
    validate_logical_request_dual_lost_ack_report(&report)?;
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
            provider_database: LOGICAL_REQUEST_PROVIDER_DATABASE.to_owned(),
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
    let (visa, destination, bindings) = logical_request_prepared_material(
        fixture,
        state_digest,
        intent_ref,
        effect_ref,
        freeze.effect_cohort_digest,
    )?;
    let request = OwnershipSealRequest {
        key: fixture.key,
        reservation: intent.reservation,
        intent: intent_ref,
        visa_freeze: visa,
        effect_freeze: effect_ref,
        destination_prepared: destination,
        bindings,
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

fn logical_request_prepared_material(
    fixture: &ExperimentFixture,
    source_state_digest: Digest,
    intent: ReceiptRef,
    nexus_freeze: ReceiptRef,
    effect_cohort_digest: Digest,
) -> Result<(ReceiptRef, ReceiptRef, PreparedBindings), String> {
    let visa_freeze =
        external_ref(fixture, ReceiptKind::VisaFreeze, b"visa-freeze", source_state_digest)?;
    let destination_state_digest = derived_digest(fixture.logical_operation, b"destination-state")?;
    let destination_prepared = external_ref(
        fixture,
        ReceiptKind::DestinationPrepared,
        b"destination-prepared",
        destination_state_digest,
    )?;
    let bindings = PreparedBindings {
        prepare_intent_receipt_digest: intent.digest,
        visa_freeze_receipt_digest: visa_freeze.digest,
        effect_freeze_receipt_digest: nexus_freeze.digest,
        snapshot: derived_identity(fixture.logical_operation, b"snapshot")?,
        snapshot_integrity_digest: derived_digest(
            fixture.logical_operation,
            b"snapshot-integrity",
        )?,
        source_journal_position: JournalPosition(1),
        source_state_digest,
        component_digest: derived_digest(fixture.logical_operation, b"component")?,
        profile_digest: canonical_digest(&LOGICAL_REQUEST_PROFILE_ID).map_err(debug)?,
        destination_prepared_receipt_digest: destination_prepared.digest,
        destination_state_digest,
        prepared_authorities_digest: derived_digest(fixture.logical_operation, b"authorities")?,
        prepared_bindings_digest: derived_digest(fixture.logical_operation, b"bindings")?,
        effect_cohort_manifest_digest: effect_cohort_digest,
        joint_mapping_manifest_digest: derived_digest(fixture.logical_operation, b"joint-mapping")?,
    };
    Ok((visa_freeze, destination_prepared, bindings))
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

#[derive(Clone, Copy)]
struct DecodedNativeCloseStep<'a> {
    exchange: &'a NativeJsonlExchange,
    decision: NativeOwnershipDecision,
    payload: HandoffProgressPayload,
}

#[derive(Clone, Copy)]
struct DecodedNativePublication {
    register_request_id: u64,
    register: RegisterEffect,
    registered: RegisteredPayload,
    prepare_request_id: u64,
    prepare: EffectSelector,
    prepared: EffectSelector,
    commit_request_id: u64,
    commit: CommitEffect,
    committed: CommittedPayload,
}

#[derive(Clone, Copy)]
struct NativePublicationMapping {
    client_effect: u64,
    binding_epoch: u64,
}

#[derive(Clone, Copy)]
struct DecodedNativeTranscript<'a> {
    initialize: PeerConfig,
    initialized: InitializedPayload,
    publication: DecodedNativePublication,
    freeze: NativePrepareIntent,
    frozen: FreezePayload,
    first_close: DecodedNativeCloseStep<'a>,
    acknowledge: EffectSelector,
    acknowledged: EffectSelector,
    terminal_close: DecodedNativeCloseStep<'a>,
    query: HandoffProgressPayload,
}

fn decode_native_exchange(
    exchange: &NativeJsonlExchange,
) -> Result<(PeerRequest, NativeReceiptPayload), String> {
    let request_json = exchange
        .request_jsonl
        .strip_suffix('\n')
        .ok_or_else(|| "native request was not LF terminated".to_owned())?;
    let request: PeerRequest = serde_json::from_str(request_json).map_err(debug)?;
    let response_json = exchange
        .response_jsonl
        .strip_suffix('\n')
        .ok_or_else(|| "native response was not LF terminated".to_owned())?;
    let response: PeerResponse = serde_json::from_str(response_json).map_err(debug)?;
    let payload =
        response.receipt.ok_or_else(|| "native response omitted its receipt".to_owned())?.payload;
    Ok((request, payload))
}

fn decode_exact_native_transcript(
    chain: &[NativeJsonlExchange],
) -> Result<DecodedNativeTranscript<'_>, String> {
    const COMMANDS: usize = 10;

    validate_native_jsonl_chain(chain).map_err(debug)?;
    require(
        chain.len() == COMMANDS,
        "logical-request native transcript did not contain exactly ten commands",
    )?;
    for (index, exchange) in chain.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(debug)?
            .checked_add(1)
            .ok_or_else(|| "native transcript request ID overflowed".to_owned())?;
        require(
            exchange.request_id == expected && exchange.receipt_sequence == expected,
            "logical-request native transcript command IDs were not exactly 1 through 10",
        )?;
    }

    let (request, payload) = decode_native_exchange(&chain[0])?;
    let PeerCommand::Initialize(initialize) = request.command else {
        return Err("native command 1 was not Initialize".to_owned());
    };
    let NativeReceiptPayload::Initialized(initialized) = payload else {
        return Err("native command 1 did not return Initialized".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[1])?;
    let PeerCommand::Register(register) = request.command else {
        return Err("native command 2 was not Register".to_owned());
    };
    let NativeReceiptPayload::EffectRegistered(registered) = payload else {
        return Err("native command 2 did not return EffectRegistered".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[2])?;
    let PeerCommand::Prepare(prepare) = request.command else {
        return Err("native command 3 was not Prepare".to_owned());
    };
    let NativeReceiptPayload::EffectPrepared(prepared) = payload else {
        return Err("native command 3 did not return EffectPrepared".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[3])?;
    let PeerCommand::Commit(commit) = request.command else {
        return Err("native command 4 was not Commit".to_owned());
    };
    let NativeReceiptPayload::EffectCommitted(committed) = payload else {
        return Err("native command 4 did not return EffectCommitted".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[4])?;
    let PeerCommand::Freeze(freeze) = request.command else {
        return Err("native command 5 was not Freeze".to_owned());
    };
    let NativeReceiptPayload::AdmissionFrozen(frozen) = payload else {
        return Err("native command 5 did not return AdmissionFrozen".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[5])?;
    let PeerCommand::CloseStep(first_decision) = request.command else {
        return Err("native command 6 was not CloseStep".to_owned());
    };
    let NativeReceiptPayload::ClosureProgress(first_payload) = payload else {
        return Err("native command 6 did not return ClosureProgress".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[6])?;
    let PeerCommand::AcknowledgePublication(acknowledge) = request.command else {
        return Err("native command 7 was not AcknowledgePublication".to_owned());
    };
    let NativeReceiptPayload::PublicationAcknowledged(acknowledged) = payload else {
        return Err("native command 7 did not return PublicationAcknowledged".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[7])?;
    let PeerCommand::CloseStep(terminal_decision) = request.command else {
        return Err("native command 8 was not CloseStep".to_owned());
    };
    let NativeReceiptPayload::ClosureProgress(terminal_payload) = payload else {
        return Err("native command 8 did not return ClosureProgress".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[8])?;
    if !matches!(request.command, PeerCommand::Query) {
        return Err("native command 9 was not Query".to_owned());
    }
    let NativeReceiptPayload::HandoffQuery(query) = payload else {
        return Err("native command 9 did not return HandoffQuery".to_owned());
    };

    let (request, payload) = decode_native_exchange(&chain[9])?;
    if !matches!(request.command, PeerCommand::Shutdown) {
        return Err("native command 10 was not Shutdown".to_owned());
    }
    if !matches!(payload, NativeReceiptPayload::Shutdown) {
        return Err("native command 10 did not return Shutdown".to_owned());
    }

    Ok(DecodedNativeTranscript {
        initialize,
        initialized,
        publication: DecodedNativePublication {
            register_request_id: chain[1].request_id,
            register,
            registered,
            prepare_request_id: chain[2].request_id,
            prepare,
            prepared,
            commit_request_id: chain[3].request_id,
            commit,
            committed,
        },
        freeze,
        frozen,
        first_close: DecodedNativeCloseStep {
            exchange: &chain[5],
            decision: first_decision,
            payload: first_payload,
        },
        acknowledge,
        acknowledged,
        terminal_close: DecodedNativeCloseStep {
            exchange: &chain[7],
            decision: terminal_decision,
            payload: terminal_payload,
        },
        query,
    })
}

fn validate_native_publication_projection(
    binding: &LogicalRequestNexusBindingEvidence,
    publication: DecodedNativePublication,
) -> Result<NativePublicationMapping, String> {
    let record = &binding.nexus_effect;
    let key = binding.freeze.key;
    let outcome = record
        .outcome_digest
        .ok_or_else(|| "committed logical-request effect omitted its outcome digest".to_owned())?;
    let client_effect = compact_identity(b"client-effect", record.effect);
    let binding_epoch = binding.freeze.scope_generation;
    let expected_register = RegisterEffect {
        client_effect,
        operation_class: compact_identity(b"operation-class", record.domain) as u32,
        syscall_number: compact_identity(b"operation", record.operation),
        syscall_arguments: [
            record.binding_generation,
            compact_identity(b"handoff", key.handoff),
            compact_identity(b"source", key.source.0),
            compact_identity(b"destination", key.destination.0),
            0,
            0,
        ],
        credit_units: 1,
        publication_required: true,
    };
    let expected_selector = EffectSelector { client_effect, binding_epoch };
    let expected_commit = CommitEffect {
        client_effect,
        binding_epoch,
        result: i64::from_be_bytes(outcome.0[..8].try_into().map_err(debug)?),
        domain_revision: record.binding_generation,
    };
    require(
        publication.register_request_id.checked_add(1) == Some(publication.prepare_request_id)
            && publication.prepare_request_id.checked_add(1) == Some(publication.commit_request_id)
            && publication.register == expected_register
            && publication.prepare == expected_selector
            && publication.prepared == expected_selector
            && publication.commit == expected_commit,
        "native Register/Prepare/Commit requests did not match the exact logical effect projection",
    )?;
    require(
        publication.registered.client_effect == client_effect
            && publication.registered.native_effect_id != 0
            && publication.registered.native_effect_generation != 0
            && publication.registered.authority_epoch == binding.freeze.authority_epoch
            && publication.registered.binding_epoch == binding_epoch
            && publication.committed.client_effect == client_effect
            && publication.committed.native_effect_id == publication.registered.native_effect_id
            && publication.committed.binding_epoch == binding_epoch
            && publication.committed.commit_sequence == 1
            && publication.committed.result == expected_commit.result
            && publication.committed.domain_revision == expected_commit.domain_revision
            && !publication.committed.registry_replay,
        "native publication receipts did not bind one exact client-to-native committed effect",
    )?;
    Ok(NativePublicationMapping { client_effect, binding_epoch })
}

fn expected_native_peer_config(
    binding: &LogicalRequestNexusBindingEvidence,
) -> Result<PeerConfig, String> {
    let key = binding.freeze.key;
    let task_generation = key
        .continuity_unit
        .generation
        .0
        .checked_add(1)
        .ok_or_else(|| "native task generation overflowed".to_owned())?;
    Ok(PeerConfig {
        scope_id: compact_identity(b"scope", binding.freeze.scope_id),
        scope_generation: binding.freeze.scope_generation,
        authority_epoch: binding.freeze.authority_epoch,
        binding_epoch: binding.freeze.scope_generation,
        supervisor_id: compact_identity(b"supervisor", key.source.0),
        supervisor_generation: binding.freeze.scope_generation,
        task_id: compact_identity(b"task", key.continuity_unit.identity),
        task_generation,
        credit_class: 1,
        credit_limit: 1_000_000,
    })
}

fn expected_native_prepare_intent(
    binding: &LogicalRequestNexusBindingEvidence,
) -> Result<NativePrepareIntent, String> {
    let key = binding.freeze.key;
    let intent = binding.freeze.intent;
    let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_request_digest = joint_canonical_digest(&reserve_request).map_err(debug)?;
    Ok(NativePrepareIntent {
        handoff_id: compact_identity(b"handoff", key.handoff),
        log_identity: compact_identity(b"ownership-log", intent.log_id),
        intent_position: intent.sequence,
        service_incarnation: compact_identity(b"ownership-incarnation", intent.issuer_incarnation),
        key_identity: compact_identity(b"ownership-key", intent.key_id),
        request_digest: compact_digest(b"intent-request", reserve_request_digest),
    })
}

fn expected_native_commit_decision(
    binding: &LogicalRequestNexusBindingEvidence,
) -> Result<NativeOwnershipDecision, String> {
    let intent = expected_native_prepare_intent(binding)?;
    let commit = &binding.ownership_commit.header;
    Ok(NativeOwnershipDecision {
        handoff_id: intent.handoff_id,
        freeze_generation: binding.freeze.freeze_generation,
        log_identity: compact_identity(b"ownership-log", commit.log_id),
        decision_position: commit.sequence,
        service_incarnation: compact_identity(b"ownership-incarnation", commit.issuer_incarnation),
        key_identity: compact_identity(b"ownership-key", commit.key_id),
        request_digest: intent.request_digest,
    })
}

fn validate_native_initialize_and_freeze(
    binding: &LogicalRequestNexusBindingEvidence,
    nexus: &NexusTerminalResponseLossEvidence,
    transcript: &DecodedNativeTranscript<'_>,
    publication: NativePublicationMapping,
) -> Result<(), String> {
    let expected_config = expected_native_peer_config(binding)?;
    let expected_intent = expected_native_prepare_intent(binding)?;
    let frozen = transcript.frozen;
    require(
        transcript.initialize == expected_config
            && transcript.initialized.config == expected_config
            && transcript.initialized.process_id == nexus.process.process_id
            && transcript.initialized.boot_incarnation != 0,
        "native Initialize did not bind the exact process and effect-scope configuration",
    )?;
    require(
        transcript.freeze == expected_intent
            && frozen.handoff_id == expected_intent.handoff_id
            && frozen.registry_instance != 0
            && frozen.boot_incarnation == transcript.initialized.boot_incarnation
            && frozen.scope_id == expected_config.scope_id
            && frozen.scope_generation == binding.freeze.scope_generation
            && frozen.authority_epoch == binding.freeze.authority_epoch
            && frozen.binding_epoch == publication.binding_epoch
            && frozen.frozen_scope_revision != 0
            && frozen.frozen_scope_revision < transcript.first_close.payload.scope_revision
            && frozen.freeze_generation == binding.freeze.freeze_generation
            && frozen.cohort_digest != 0
            && frozen.classification_digest != 0
            && frozen.cohort_size
                == usize::try_from(binding.freeze.counts.registered).map_err(debug)?
            && frozen.committed_at_freeze
                == usize::try_from(binding.freeze.counts.committed).map_err(debug)?
            && frozen.readiness == NativeReadiness::ReadyToCommit
            && binding.freeze.disposition == FreezeDisposition::ReadyToCommit,
        "native Freeze/AdmissionFrozen did not refine the exact neutral freeze and cohort",
    )
}

fn expected_native_closure_receipts(
    binding: &LogicalRequestNexusBindingEvidence,
    first: HandoffProgressPayload,
    terminal: HandoffProgressPayload,
) -> Result<(ClosureProgressReceipt, ClosureReceipt), String> {
    let freeze = &binding.freeze;
    let freeze_ref = freeze.receipt_ref().map_err(debug)?;
    let commit_ref = binding.ownership_commit.receipt_ref().map_err(debug)?;
    let authority_epoch = freeze
        .authority_epoch
        .checked_add(1)
        .ok_or_else(|| "native closure authority epoch overflowed".to_owned())?;
    require(
        first.status == NativeHandoffStatus::Closing
            && first.readiness.is_none()
            && first.freeze_generation == freeze.freeze_generation
            && first.scope_revision != 0
            && first.authority_epoch == authority_epoch
            && first.binding_epoch == freeze.scope_generation
            && first.live_effects == 0
            && first.pending_publications == 1
            && first.native_effect.is_some_and(|effect| effect != 0)
            && first.publication_pending
            && first.terminal_manifest_digest.is_none(),
        "first native CloseStep did not prove one pending publication after local closure",
    )?;
    let terminal_manifest = terminal
        .terminal_manifest_digest
        .ok_or_else(|| "terminal native CloseStep omitted its manifest digest".to_owned())?;
    require(
        terminal.status == NativeHandoffStatus::Closed
            && terminal.readiness.is_none()
            && terminal.freeze_generation == freeze.freeze_generation
            && terminal.scope_revision > first.scope_revision
            && terminal.authority_epoch == authority_epoch
            && terminal.binding_epoch == freeze.scope_generation
            && terminal.live_effects == 0
            && terminal.pending_publications == 0
            && terminal.native_effect.is_none()
            && !terminal.publication_pending
            && terminal_manifest != 0,
        "terminal native CloseStep did not prove a fully drained Closed state",
    )?;

    let progress_sequence = freeze
        .header
        .sequence
        .checked_add(1)
        .ok_or_else(|| "native closure progress sequence overflowed".to_owned())?;
    let progress = ClosureProgressReceipt {
        header: ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::ClosureProgress,
            issuer: freeze.header.issuer,
            issuer_incarnation: freeze.header.issuer_incarnation,
            key_id: freeze.header.key_id,
            log_id: freeze.header.log_id,
            sequence: progress_sequence,
            previous_digest: Some(freeze_ref.digest),
        },
        key: freeze.key,
        commit: commit_ref,
        nexus_freeze: freeze_ref,
        closure_revision: 1,
        remaining_effects: u64::try_from(first.live_effects).map_err(debug)?,
        retained_tombstones: 0,
        progress_root: mapped_native_digest(b"closure-progress", &first),
    };
    let progress_ref = progress.receipt_ref().map_err(debug)?;
    let closure = ClosureReceipt {
        header: ReceiptHeader {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind: ReceiptKind::Closure,
            issuer: freeze.header.issuer,
            issuer_incarnation: freeze.header.issuer_incarnation,
            key_id: freeze.header.key_id,
            log_id: freeze.header.log_id,
            sequence: progress_sequence
                .checked_add(1)
                .ok_or_else(|| "native closure sequence overflowed".to_owned())?,
            previous_digest: Some(progress_ref.digest),
        },
        key: freeze.key,
        commit: commit_ref,
        nexus_freeze: freeze_ref,
        closure_revision: 2,
        effect_manifest_digest: mapped_u64_digest(b"terminal-manifest", terminal_manifest),
        closed_authority_epoch: terminal.authority_epoch,
    };
    Ok((progress, closure))
}

fn validate_terminal_replay_binding(
    replay: &NativeExactReplayEvidence,
    terminal: &NativeJsonlExchange,
) -> Result<(), String> {
    let accepted_before = replay
        .request_id
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "terminal replay request ID was not a positive usize".to_owned())?;
    let accepted_after = usize::try_from(replay.request_id).map_err(debug)?;
    require(
        replay.command == "close-step"
            && replay.request_id == terminal.request_id
            && replay.original_request_jsonl == terminal.request_jsonl
            && replay.original_response_jsonl == terminal.response_jsonl
            && replay.replay_response_jsonl == terminal.response_jsonl
            && replay.byte_identical
            && replay.accepted_chain_length_before == accepted_before
            && replay.accepted_chain_length_after == accepted_after
            && replay.accepted_chain_grew_once,
        "terminal response-loss replay did not bind the exact accepted CloseStep position",
    )
}

fn validate_native_closure_payload_refinement(
    binding: &LogicalRequestNexusBindingEvidence,
    first: HandoffProgressPayload,
    terminal: HandoffProgressPayload,
) -> Result<(), String> {
    let (_, expected_closure) = expected_native_closure_receipts(binding, first, terminal)?;
    require(
        binding.closure == expected_closure,
        "neutral Closure receipt did not exactly refine the two native CloseStep payloads",
    )
}

fn validate_native_closure_refinement(
    binding: &LogicalRequestNexusBindingEvidence,
    nexus: &NexusTerminalResponseLossEvidence,
) -> Result<(), String> {
    let transcript = decode_exact_native_transcript(&nexus.native_chain)?;
    let publication = validate_native_publication_projection(binding, transcript.publication)?;
    validate_native_initialize_and_freeze(binding, nexus, &transcript, publication)?;
    let first = transcript.first_close;
    let terminal = transcript.terminal_close;
    let expected_decision = expected_native_commit_decision(binding)?;
    require(
        first.decision == expected_decision && terminal.decision == expected_decision,
        "native CloseSteps did not retain one decision around one publication acknowledgement",
    )?;
    require(
        first.payload.native_effect == Some(publication.client_effect)
            && transcript.acknowledge.client_effect == publication.client_effect
            && transcript.acknowledge.binding_epoch == publication.binding_epoch
            && transcript.acknowledge.binding_epoch == first.payload.binding_epoch
            && transcript.acknowledged == transcript.acknowledge,
        "native publication acknowledgement did not name the Closing payload effect",
    )?;
    require(
        transcript.query == terminal.payload,
        "native terminal Query did not replay the exact Closed handoff projection",
    )?;
    validate_native_closure_payload_refinement(binding, first.payload, terminal.payload)?;
    validate_terminal_replay_binding(&nexus.exact_replay, terminal.exchange)
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

/// Validates the exact joint receipt lineage that binds one logical request to
/// its Nexus effect and ownership decision.
pub fn validate_logical_request_joint_binding_lineage(
    run_identity: Identity,
    logical_request: &LogicalRequestProviderEvidence,
    binding: &LogicalRequestNexusBindingEvidence,
    close_steps: u64,
) -> Result<(), String> {
    let fixture = ExperimentFixture::new(run_identity)?;
    let key = fixture.key;
    let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reservation = ownership_reservation(&reserve_request)?;
    let intent = binding.freeze.intent;
    let freeze_ref = binding.freeze.receipt_ref().map_err(debug)?;
    let prepared_ref = binding.ownership_prepared.receipt_ref().map_err(debug)?;
    let commit_ref = binding.ownership_commit.receipt_ref().map_err(debug)?;
    let recomputed_cohort =
        joint_effect_cohort_digest(conformance_key(key)?, [binding.nexus_effect.clone()])
            .map_err(debug)?;
    let classification_root =
        joint_classification_root(conformance_key(key)?, [binding.nexus_effect.clone()])
            .map_err(debug)?;
    let counts = joint_classification_counts([binding.nexus_effect.clone()]);
    let (visa_freeze, destination_prepared, expected_bindings) = logical_request_prepared_material(
        &fixture,
        logical_request.completed_state_digest,
        intent,
        freeze_ref,
        recomputed_cohort,
    )?;
    let expected_commit_root = ownership_commit_root(key, reservation, 3)?;
    let closure_sequence = binding
        .freeze
        .header
        .sequence
        .checked_add(close_steps)
        .ok_or_else(|| "logical-request closure header sequence overflowed".to_owned())?;
    let closed_authority_epoch = binding
        .freeze
        .authority_epoch
        .checked_add(1)
        .ok_or_else(|| "logical-request closed authority epoch overflowed".to_owned())?;

    require(
        key.is_well_formed()
            && binding.freeze.key == key
            && binding.ownership_prepared.key == key
            && binding.ownership_commit.key == key
            && binding.closure.key == key
            && binding.logical_operation_id == fixture.logical_operation
            && binding.logical_operation_id == logical_request.operation_id
            && logical_request.canonical_effect_operation == fixture.canonical_effect_operation
            && logical_request.resource == fixture.logical_resource,
        "logical-request joint lineage did not retain one exact key and operation identity",
    )?;
    require(
        binding.nexus_effect.effect == fixture.logical_operation
            && binding.nexus_effect.operation == fixture.canonical_effect_operation
            && binding.nexus_effect.domain == LOGICAL_REQUEST_PROFILE_ID
            && binding.nexus_effect.binding_generation == fixture.effect_config.scope_generation
            && binding.nexus_effect.classification == JointEffectClassification::Committed
            && binding.nexus_effect.outcome_digest == Some(logical_request.outcome_digest)
            && binding.nexus_effect.tombstone_digest.is_none(),
        "logical-request Nexus effect record was substituted",
    )?;
    require(
        reference_matches(
            intent,
            fixture.effect_config.ownership_issuer,
            ReceiptKind::PrepareIntent,
            key.handoff,
            1,
        ) && binding.ownership_prepared.intent == intent
            && binding.ownership_prepared.reservation == reservation
            && binding.ownership_commit.reservation == reservation,
        "logical-request ownership intent or reservation lineage drifted",
    )?;
    require(
        header_matches(
            &binding.freeze.header,
            fixture.effect_config.issuer,
            ReceiptKind::NexusFreeze,
            1,
            None,
        ) && binding.freeze.intent == intent
            && binding.freeze.registry_instance == fixture.effect_config.registry_instance
            && binding.freeze.scope_id == fixture.effect_config.scope_id
            && binding.freeze.scope_generation == fixture.effect_config.scope_generation
            && binding.freeze.authority_epoch == fixture.effect_config.authority_epoch
            && binding.freeze.freeze_generation == fixture.effect_config.freeze_generation
            && binding.freeze.domain_bindings_digest
                == fixture.effect_config.domain_bindings_digest
            && binding.freeze.effect_cohort_digest == recomputed_cohort
            && binding.recomputed_effect_cohort_digest == recomputed_cohort
            && binding.freeze.classification_root == classification_root
            && binding.freeze.counts.registered == counts.registered
            && binding.freeze.counts.committed == counts.committed
            && binding.freeze.counts.aborted == counts.aborted
            && binding.freeze.counts.unresolved == counts.unresolved
            && binding.freeze.counts.tombstones == counts.tombstones
            && binding.freeze.counts.registered == 1
            && binding.freeze.counts.committed == 1
            && binding.freeze.counts.aborted == 0
            && binding.freeze.counts.unresolved == 0
            && binding.freeze.counts.tombstones == 0
            && binding.freeze.disposition == FreezeDisposition::ReadyToCommit,
        "logical-request Nexus freeze did not bind the exact cohort and scope",
    )?;
    require(
        header_matches(
            &binding.ownership_prepared.header,
            fixture.effect_config.ownership_issuer,
            ReceiptKind::OwnershipPrepared,
            2,
            Some(intent.digest),
        ) && binding.ownership_prepared.intent == intent
            && binding.ownership_prepared.visa_freeze == visa_freeze
            && binding.ownership_prepared.nexus_freeze == freeze_ref
            && binding.ownership_prepared.destination_prepared == destination_prepared
            && binding.ownership_prepared.bindings == expected_bindings
            && binding.ownership_prepared.prepared_revision == 2,
        "logical-request ownership Prepared receipt did not seal exact source and effect inputs",
    )?;
    require(
        header_matches(
            &binding.ownership_commit.header,
            fixture.effect_config.ownership_issuer,
            ReceiptKind::OwnershipCommit,
            3,
            Some(prepared_ref.digest),
        ) && binding.ownership_commit.prepared == prepared_ref
            && binding.ownership_commit.prepared_revision == 2
            && binding.ownership_commit.decision_sequence == 3
            && binding.ownership_commit.non_equivocation_root == expected_commit_root,
        "logical-request ownership Commit receipt did not extend exact Prepared lineage",
    )?;
    require(
        close_steps == 2
            && header_matches(
                &binding.closure.header,
                fixture.effect_config.issuer,
                ReceiptKind::Closure,
                closure_sequence,
                binding.closure.header.previous_digest,
            )
            && binding.closure.header.previous_digest.is_some_and(|digest| digest != Digest::ZERO)
            && binding.closure.commit == commit_ref
            && binding.closure.nexus_freeze == freeze_ref
            && binding.closure.closure_revision == close_steps
            && binding.closure.effect_manifest_digest != Digest::ZERO
            && binding.closure.closed_authority_epoch == closed_authority_epoch,
        "logical-request closure did not extend the exact commit/freeze lineage",
    )?;
    require(
        expected_bindings.source_state_digest == logical_request.completed_state_digest
            && expected_bindings.effect_cohort_manifest_digest == recomputed_cohort
            && binding.logical_operation_is_nexus_effect_identity
            && binding.canonical_effect_operation_matches
            && binding.cohort_bound_into_prepared
            && binding.prepared_bound_into_commit
            && binding.commit_and_freeze_bound_into_closure,
        "logical-request joint lineage summary flags or sealed digests drifted",
    )
}

/// Strictly validates the bounded same-boot dual-lost-ACK evidence contract.
pub fn validate_logical_request_dual_lost_ack_report(
    report: &LogicalRequestDualLostAckReport,
) -> Result<(), String> {
    require(report.schema == LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA, "wrong report schema")?;
    require(
        report.all_passed
            && report.boundary == SAME_BOOT_BOUNDARY
            && report.same_boot_only
            && !report.cross_reboot_claimed
            && report.process_backed_nexus
            && !report.reference_effect_peer_used
            && !report.run_identity.is_zero()
            && report.limitations == REPORT_LIMITATIONS.map(str::to_owned),
        "experiment boundary was overstated or not process-backed",
    )?;
    let (provider_request, provider_outcome) =
        decode_boundary_exchange::<EffectRequest, EffectOutcome>(
            &report.logical_request.exchange,
            "typed-substrate-profile-api-canonical-json-capture",
            "logical-request.start-query-retry",
        )?;
    let completed_state_digest = completed_logical_request_state_digest(
        report.run_identity,
        &provider_request,
        &provider_outcome,
    )?;
    require(
        report.logical_request.provider_database == LOGICAL_REQUEST_PROVIDER_DATABASE
            && report.logical_request.fault_point == "after-logical-request-commit"
            && report.logical_request.fault_was_injected_after_durable_commit
            && report.logical_request.initial_return == "outcome-unknown"
            && report.logical_request.durable_query_exact
            && report.logical_request.exact_retry
            && report.logical_request.reopen_query_exact
            && report.logical_request.remote_execution_count == 1
            && report.logical_request.remote_request_count == 1
            && report.logical_request.application_request_present_on_wire
            && !report.logical_request.credential_present_on_wire
            && !report.logical_request.tcp_raw_frame_capture_available
            && provider_request.operation == report.logical_request.canonical_effect_operation
            && provider_request.resource == report.logical_request.resource
            && provider_request.request_digest == report.logical_request.request_digest
            && completed_state_digest == report.logical_request.completed_state_digest
            && canonical_digest(&provider_outcome).map_err(debug)?
                == report.logical_request.outcome_digest,
        "logical-request provider evidence did not prove one recovered execution",
    )?;
    validate_logical_request_joint_binding_lineage(
        report.run_identity,
        &report.logical_request,
        &report.binding,
        report.nexus_terminal_response_loss.close_steps,
    )?;
    let expected_commit_request = OwnershipCommitRequest {
        key: report.binding.ownership_commit.key,
        reservation: report.binding.ownership_commit.reservation,
        prepared: report.binding.ownership_commit.prepared,
        expected_state_sequence: 2,
    };
    let (commit_request, acknowledgement_loss) =
        decode_boundary_exchange::<OwnershipCommitRequest, AcknowledgementLostCapture>(
            &report.ownership_commit_ack_loss.commit_exchange,
            "in-process-sqlite-ownership-api",
            "ownership.commit",
        )?;
    let (query_request, queried_commit) =
        decode_boundary_exchange::<OwnershipQueryCapture, OwnershipCommitReceipt>(
            &report.ownership_commit_ack_loss.query_exchange,
            "in-process-sqlite-ownership-api",
            "ownership.query",
        )?;
    let (retry_request, retried_commit) =
        decode_boundary_exchange::<OwnershipCommitRequest, OwnershipCommitReceipt>(
            &report.ownership_commit_ack_loss.retry_exchange,
            "in-process-sqlite-ownership-api",
            "ownership.commit-retry",
        )?;
    require(
        report.ownership_commit_ack_loss.database == LOGICAL_REQUEST_OWNERSHIP_DATABASE
            && report.ownership_commit_ack_loss.journal_mode.eq_ignore_ascii_case("wal")
            && report.ownership_commit_ack_loss.synchronous == 2
            && report.ownership_commit_ack_loss.transport_fault_injection_available
            && report.ownership_commit_ack_loss.loss_model == OWNERSHIP_LOSS_MODEL
            && report.ownership_commit_ack_loss.query_after_reopen_exact
            && report.ownership_commit_ack_loss.retry_exact
            && report.ownership_commit_ack_loss.owner_advanced_to_destination
            && commit_request == expected_commit_request
            && retry_request == expected_commit_request
            && report.ownership_commit_ack_loss.commit_exchange.request_json
                == report.ownership_commit_ack_loss.retry_exchange.request_json
            && acknowledgement_loss
                == (AcknowledgementLostCapture {
                    error: "acknowledgement_lost".to_owned(),
                    durable_write_completed: true,
                })
            && query_request.handoff == report.binding.ownership_commit.key.handoff
            && queried_commit == report.binding.ownership_commit
            && retried_commit == report.binding.ownership_commit,
        "ownership recovery evidence was incomplete",
    )?;
    let replay = &report.nexus_terminal_response_loss.exact_replay;
    validate_native_jsonl_chain(&report.nexus_terminal_response_loss.native_chain)
        .map_err(debug)?;
    validate_native_closure_refinement(&report.binding, &report.nexus_terminal_response_loss)?;
    validate_lost_close_response(&NativeResponseLossObservation {
        request_id: replay.request_id,
        request_jsonl: replay.original_request_jsonl.clone(),
        discarded_response_jsonl: replay.original_response_jsonl.clone(),
        replay_response_jsonl: replay.replay_response_jsonl.clone(),
        byte_identical: replay.byte_identical,
        accepted_chain_length_before: replay.accepted_chain_length_before,
        accepted_chain_length_after: replay.accepted_chain_length_after,
    })?;
    let (native_register_count, native_prepare_count, native_commit_count) =
        native_effect_command_counts(&report.nexus_terminal_response_loss.native_chain)?;
    let replay_is_in_accepted_chain =
        report.nexus_terminal_response_loss.native_chain.iter().any(|exchange| {
            exchange.request_id == replay.request_id
                && exchange.request_jsonl == replay.original_request_jsonl
                && exchange.response_jsonl == replay.replay_response_jsonl
        });
    let process = &report.nexus_terminal_response_loss.process;
    require(
        process.process_id != 0
            && process.start_time_ticks != 0
            && process.executable_path.is_absolute()
            && is_lower_hex(&process.executable_sha256, 64)
            && is_lower_hex(&process.nexus_revision, 40)
            && report.nexus_terminal_response_loss.transport_fault_injection_available
            && report.nexus_terminal_response_loss.loss_model == NEXUS_LOSS_MODEL
            && report.nexus_terminal_response_loss.publication_first == "published"
            && report.nexus_terminal_response_loss.duplicate_publication == "exact-replay"
            && report.nexus_terminal_response_loss.terminal_query_recovered_exact
            && replay.byte_identical
            && replay.accepted_chain_grew_once
            && replay.original_response_jsonl == replay.replay_response_jsonl
            && replay_is_in_accepted_chain
            && !report.nexus_terminal_response_loss.duplicate_publication_extended_native_chain
            && native_register_count == 1
            && native_prepare_count == 1
            && native_commit_count == 1,
        "Nexus response-loss evidence did not replay exactly",
    )?;
    require(
        report.terminal.logical_request_completed
            && report.terminal.remote_execution_count == 1
            && report.terminal.ownership_owner == report.binding.ownership_commit.key.destination
            && report.terminal.ownership_epoch == LeaseEpoch(2)
            && report.terminal.ownership_epoch == report.binding.ownership_commit.key.next_epoch
            && !report.terminal.nexus_gate_open
            && report.terminal.nexus_effect_count == 1
            && report.terminal.native_register_count == native_register_count
            && report.terminal.native_prepare_count == native_prepare_count
            && report.terminal.native_commit_count == native_commit_count
            && report.terminal.source_closed
            && report.terminal.no_duplicate_external_execution
            && report.terminal.no_duplicate_nexus_publication,
        "terminal state did not prove single execution and source closure",
    )
}

fn decode_boundary_exchange<Request, Response>(
    exchange: &CanonicalBoundaryExchange,
    expected_boundary: &str,
    expected_operation: &str,
) -> Result<(Request, Response), String>
where
    Request: DeserializeOwned + Serialize,
    Response: DeserializeOwned + Serialize,
{
    require(
        exchange.boundary == expected_boundary
            && exchange.operation == expected_operation
            && !exchange.request_json.is_empty()
            && !exchange.response_json.is_empty()
            && exchange.request_sha256 == sha256_hex(exchange.request_json.as_bytes())
            && exchange.response_sha256 == sha256_hex(exchange.response_json.as_bytes()),
        "captured boundary exchange digest or identity drifted",
    )?;
    let request: Request = serde_json::from_str(&exchange.request_json).map_err(debug)?;
    let response: Response = serde_json::from_str(&exchange.response_json).map_err(debug)?;
    require(
        serde_json::to_string(&request).map_err(debug)? == exchange.request_json
            && serde_json::to_string(&response).map_err(debug)? == exchange.response_json,
        "captured boundary exchange is not canonical compact JSON",
    )?;
    Ok((request, response))
}

fn completed_logical_request_state_digest(
    run_identity: Identity,
    request: &EffectRequest,
    outcome: &EffectOutcome,
) -> Result<Digest, String> {
    let fixture = ExperimentFixture::new(run_identity)?;
    let EffectKind::Profile { profile, access, payload } = &request.kind else {
        return Err("captured logical request is not a profile operation".to_owned());
    };
    require(
        *profile == LOGICAL_REQUEST_PROFILE_ID && *access == ProfileAccess::Write,
        "captured logical request used the wrong profile or access",
    )?;
    let operation: LogicalRequestOperationWire = canonical_from_bytes(payload).map_err(debug)?;
    require(
        canonical_bytes(&operation).map_err(debug)?.as_slice() == payload.as_slice()
            && operation
                == (LogicalRequestOperationWire::Start { request: fixture.request.clone() }),
        "captured logical-request operation payload was not the exact canonical Start",
    )?;
    let rights = Rights::PROFILE_READ
        .union(Rights::PROFILE_WRITE)
        .union(Rights::PROFILE_CONTROL)
        .union(Rights::REBIND);
    let initial = LogicalRequestStateWire {
        claim: LogicalRequestClaimWire {
            resource: fixture.logical_resource,
            peer_identity: fixture.peer_identity,
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
    require(
        request.operation == fixture.canonical_effect_operation
            && request.idempotency_key == fixture.idempotency
            && request.causal_parent.is_none()
            && request.node == fixture.key.source
            && request.subject == fixture.key.continuity_unit
            && request.resource == fixture.logical_resource
            && request.authority == fixture.logical_authority
            && request.lease_epoch == fixture.key.expected_epoch
            && request.request_digest == initial.request_digest,
        "captured logical request did not match its run-derived canonical request",
    )?;
    let EffectOutcome::Succeeded { result: EffectResult::Profile { profile, payload }, .. } =
        outcome
    else {
        return Err(
            "captured logical request outcome is not a successful profile result".to_owned()
        );
    };
    require(
        *profile == LOGICAL_REQUEST_PROFILE_ID,
        "captured logical request outcome used the wrong profile",
    )?;
    let result: LogicalRequestResultWire = canonical_from_bytes(payload).map_err(debug)?;
    require(
        canonical_bytes(&result).map_err(debug)?.as_slice() == payload.as_slice(),
        "captured logical request result payload was not canonical",
    )?;
    let LogicalRequestResultWire::Started { observation } = result else {
        return Err("captured logical request outcome was not Start completion".to_owned());
    };
    require(
        observation.phase == LogicalRequestPhaseWire::Completed
            && observation.response.is_some()
            && observation.rejection.is_none(),
        "captured logical request outcome was not terminal Completed",
    )?;
    let completed = LogicalRequestStateWire {
        phase: observation.phase,
        response: observation.response,
        rejection: observation.rejection,
        disposition: ContinuityDispositionWire::Revalidate,
        last_operation: Some(request.operation),
        ..initial
    };
    canonical_digest(&completed).map_err(debug)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipQueryCapture {
    handoff: Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgementLostCapture {
    error: String,
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

fn ownership_reservation(request: &OwnershipReserveRequest) -> Result<Identity, String> {
    let digest =
        joint_canonical_digest(&(b"ownership-reservation".as_slice(), request)).map_err(debug)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let reservation = Identity::from_bytes(bytes);
    require(!reservation.is_zero(), "derived ownership reservation was zero")?;
    Ok(reservation)
}

fn ownership_commit_root(
    key: JointHandoffKey,
    reservation: Identity,
    sequence: u64,
) -> Result<Digest, String> {
    joint_canonical_digest(&(
        b"vISA reference ownership decision v1".as_slice(),
        key,
        reservation,
        b"commit".as_slice(),
        sequence,
    ))
    .map_err(debug)
}

fn reference_matches(
    reference: ReceiptRef,
    issuer: ReceiptIssuerIdentity,
    kind: ReceiptKind,
    handoff: Identity,
    sequence: u64,
) -> bool {
    reference.version == joint_handoff_core::JOINT_PROTOCOL_VERSION
        && reference.kind == kind
        && reference.handoff == handoff
        && reference.issuer == issuer.issuer
        && reference.issuer_incarnation == issuer.issuer_incarnation
        && reference.key_id == issuer.key_id
        && reference.log_id == issuer.log_id
        && reference.sequence == sequence
        && reference.digest != Digest::ZERO
}

fn header_matches(
    header: &ReceiptHeader,
    issuer: ReceiptIssuerIdentity,
    kind: ReceiptKind,
    sequence: u64,
    previous_digest: Option<Digest>,
) -> bool {
    header.version == joint_handoff_core::JOINT_PROTOCOL_VERSION
        && header.kind == kind
        && header.issuer == issuer.issuer
        && header.issuer_incarnation == issuer.issuer_incarnation
        && header.key_id == issuer.key_id
        && header.log_id == issuer.log_id
        && header.sequence == sequence
        && header.previous_digest == previous_digest
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
    use crate::nexus_effect_wire::{
        AUTHENTICATION_BOUNDARY, NativeReceipt, RECEIPT_SCHEMA, REQUEST_SCHEMA, RESPONSE_SCHEMA,
        ReceiptDigestInput, ResponseStatus,
    };

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
        let run = run_provider_request(&root.0.join(LOGICAL_REQUEST_PROVIDER_DATABASE), &fixture)
            .unwrap();
        assert_eq!(run.completed.operation_id, fixture.logical_operation);
        assert_eq!(run.completed.phase, LogicalRequestPhaseWire::Completed);
        assert!(run.evidence.fault_was_injected_after_durable_commit);
        assert!(run.evidence.durable_query_exact && run.evidence.reopen_query_exact);
        assert_eq!(run.evidence.remote_execution_count, 1);
        assert!(run.evidence.application_request_present_on_wire);
        assert!(!run.evidence.credential_present_on_wire);
        let (request, outcome) = decode_boundary_exchange::<EffectRequest, EffectOutcome>(
            &run.evidence.exchange,
            "typed-substrate-profile-api-canonical-json-capture",
            "logical-request.start-query-retry",
        )
        .unwrap();
        assert_eq!(
            completed_logical_request_state_digest(Identity::from_u128(1), &request, &outcome,)
                .unwrap(),
            run.evidence.completed_state_digest
        );
        let mut changed = request;
        changed.request_digest = Digest::ZERO;
        assert!(
            completed_logical_request_state_digest(Identity::from_u128(1), &changed, &outcome,)
                .is_err()
        );
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

    fn strict_lineage_fixture()
    -> (Identity, LogicalRequestProviderEvidence, LogicalRequestNexusBindingEvidence, u64) {
        let run = Identity::from_u128(0x4c49_4e45_4147_455f_5445_5354);
        let fixture = ExperimentFixture::new(run).unwrap();
        let completed_state_digest = derived_digest(run, b"completed-state").unwrap();
        let outcome_digest = derived_digest(run, b"outcome").unwrap();
        let logical = LogicalRequestProviderEvidence {
            provider_database: LOGICAL_REQUEST_PROVIDER_DATABASE.to_owned(),
            operation_id: fixture.logical_operation,
            canonical_effect_operation: fixture.canonical_effect_operation,
            resource: fixture.logical_resource,
            request_digest: derived_digest(run, b"request").unwrap(),
            completed_state_digest,
            outcome_digest,
            fault_point: "after-logical-request-commit".to_owned(),
            fault_was_injected_after_durable_commit: true,
            initial_return: "outcome-unknown".to_owned(),
            durable_query_exact: true,
            exact_retry: true,
            reopen_query_exact: true,
            remote_execution_count: 1,
            remote_request_count: 1,
            application_request_present_on_wire: true,
            credential_present_on_wire: false,
            tcp_raw_frame_capture_available: false,
            exchange: CanonicalBoundaryExchange {
                boundary: String::new(),
                operation: String::new(),
                request_json: String::new(),
                response_json: String::new(),
                request_sha256: String::new(),
                response_sha256: String::new(),
            },
        };
        let effect = JointEffectRecord {
            effect: fixture.logical_operation,
            operation: fixture.canonical_effect_operation,
            domain: LOGICAL_REQUEST_PROFILE_ID,
            binding_generation: fixture.effect_config.scope_generation,
            classification: JointEffectClassification::Committed,
            outcome_digest: Some(outcome_digest),
            tombstone_digest: None,
        };
        let reserve_request =
            OwnershipReserveRequest { key: fixture.key, expected_state_sequence: 0 };
        let reservation = ownership_reservation(&reserve_request).unwrap();
        let intent = PrepareIntentReceipt {
            header: ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::PrepareIntent,
                issuer: fixture.effect_config.ownership_issuer.issuer,
                issuer_incarnation: fixture.effect_config.ownership_issuer.issuer_incarnation,
                key_id: fixture.effect_config.ownership_issuer.key_id,
                log_id: fixture.effect_config.ownership_issuer.log_id,
                sequence: 1,
                previous_digest: None,
            },
            key: fixture.key,
            ownership_service: fixture.effect_config.ownership_issuer.issuer,
            service_incarnation: fixture.effect_config.ownership_issuer.issuer_incarnation,
            reservation,
            intent_revision: 1,
            request_digest: joint_canonical_digest(&reserve_request).unwrap(),
        };
        let intent_ref = intent.receipt_ref().unwrap();
        let cohort =
            joint_effect_cohort_digest(conformance_key(fixture.key).unwrap(), [effect.clone()])
                .unwrap();
        let classification =
            joint_classification_root(conformance_key(fixture.key).unwrap(), [effect.clone()])
                .unwrap();
        let counts = joint_classification_counts([effect.clone()]);
        let freeze = NexusFreezeReceipt {
            header: ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::NexusFreeze,
                issuer: fixture.effect_config.issuer.issuer,
                issuer_incarnation: fixture.effect_config.issuer.issuer_incarnation,
                key_id: fixture.effect_config.issuer.key_id,
                log_id: fixture.effect_config.issuer.log_id,
                sequence: 1,
                previous_digest: None,
            },
            key: fixture.key,
            intent: intent_ref,
            registry_instance: fixture.effect_config.registry_instance,
            scope_id: fixture.effect_config.scope_id,
            scope_generation: fixture.effect_config.scope_generation,
            authority_epoch: fixture.effect_config.authority_epoch,
            freeze_generation: fixture.effect_config.freeze_generation,
            domain_bindings_digest: fixture.effect_config.domain_bindings_digest,
            effect_cohort_digest: cohort,
            classification_root: classification,
            counts: joint_handoff_core::ClassificationCounts {
                registered: counts.registered,
                committed: counts.committed,
                aborted: counts.aborted,
                unresolved: counts.unresolved,
                tombstones: counts.tombstones,
            },
            disposition: FreezeDisposition::ReadyToCommit,
        };
        let freeze_ref = freeze.receipt_ref().unwrap();
        let (visa_freeze, destination_prepared, bindings) = logical_request_prepared_material(
            &fixture,
            completed_state_digest,
            intent_ref,
            freeze_ref,
            cohort,
        )
        .unwrap();
        let prepared = OwnershipPreparedReceipt {
            header: ReceiptHeader {
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
            reservation,
            intent: intent_ref,
            visa_freeze,
            nexus_freeze: freeze_ref,
            destination_prepared,
            bindings,
            prepared_revision: 2,
        };
        let prepared_ref = prepared.receipt_ref().unwrap();
        let commit = OwnershipCommitReceipt {
            header: ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::OwnershipCommit,
                issuer: fixture.effect_config.ownership_issuer.issuer,
                issuer_incarnation: fixture.effect_config.ownership_issuer.issuer_incarnation,
                key_id: fixture.effect_config.ownership_issuer.key_id,
                log_id: fixture.effect_config.ownership_issuer.log_id,
                sequence: 3,
                previous_digest: Some(prepared_ref.digest),
            },
            key: fixture.key,
            reservation,
            prepared: prepared_ref,
            prepared_revision: 2,
            decision_sequence: 3,
            non_equivocation_root: ownership_commit_root(fixture.key, reservation, 3).unwrap(),
        };
        let commit_ref = commit.receipt_ref().unwrap();
        let closure = ClosureReceipt {
            header: ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::Closure,
                issuer: fixture.effect_config.issuer.issuer,
                issuer_incarnation: fixture.effect_config.issuer.issuer_incarnation,
                key_id: fixture.effect_config.issuer.key_id,
                log_id: fixture.effect_config.issuer.log_id,
                sequence: 3,
                previous_digest: Some(derived_digest(run, b"closure-progress").unwrap()),
            },
            key: fixture.key,
            commit: commit_ref,
            nexus_freeze: freeze_ref,
            closure_revision: 2,
            effect_manifest_digest: derived_digest(run, b"effect-manifest").unwrap(),
            closed_authority_epoch: 2,
        };
        let binding = LogicalRequestNexusBindingEvidence {
            logical_operation_id: fixture.logical_operation,
            nexus_effect: effect,
            logical_operation_is_nexus_effect_identity: true,
            canonical_effect_operation_matches: true,
            recomputed_effect_cohort_digest: cohort,
            freeze,
            ownership_prepared: prepared,
            ownership_commit: commit,
            closure,
            cohort_bound_into_prepared: true,
            prepared_bound_into_commit: true,
            commit_and_freeze_bound_into_closure: true,
        };
        (run, logical, binding, 2)
    }

    #[test]
    fn strict_joint_lineage_rejects_identity_and_parent_mutations() {
        let (run, logical, binding, close_steps) = strict_lineage_fixture();
        assert_eq!(
            validate_logical_request_joint_binding_lineage(run, &logical, &binding, close_steps,),
            Ok(())
        );
        let rejects = |candidate: &LogicalRequestNexusBindingEvidence| {
            assert!(
                validate_logical_request_joint_binding_lineage(
                    run,
                    &logical,
                    candidate,
                    close_steps,
                )
                .is_err()
            );
        };

        let mut changed = binding.clone();
        changed.closure.key = ExperimentFixture::new(Identity::from_u128(77)).unwrap().key;
        rejects(&changed);
        let mut changed = binding.clone();
        changed.ownership_commit.reservation = Identity::from_u128(78);
        rejects(&changed);
        let mut changed = binding.clone();
        changed.ownership_prepared.intent.digest = Digest::ZERO;
        rejects(&changed);
        let mut changed = binding.clone();
        changed.ownership_prepared.nexus_freeze.digest = Digest::ZERO;
        rejects(&changed);
        let mut changed = binding.clone();
        changed.ownership_commit.prepared.digest = Digest::ZERO;
        rejects(&changed);
        let mut changed = binding;
        changed.closure.commit.digest = Digest::ZERO;
        rejects(&changed);
    }

    #[test]
    fn strict_joint_lineage_rejects_state_cohort_count_and_header_mutations() {
        let (run, logical, binding, close_steps) = strict_lineage_fixture();
        let rejects = |logical: &LogicalRequestProviderEvidence,
                       candidate: &LogicalRequestNexusBindingEvidence| {
            assert!(
                validate_logical_request_joint_binding_lineage(
                    run,
                    logical,
                    candidate,
                    close_steps,
                )
                .is_err()
            );
        };

        let mut changed = binding.clone();
        changed.ownership_prepared.bindings.source_state_digest = Digest::ZERO;
        rejects(&logical, &changed);
        let mut changed = binding.clone();
        changed.freeze.effect_cohort_digest = Digest::ZERO;
        rejects(&logical, &changed);
        let mut changed = binding.clone();
        changed.freeze.counts.committed = 0;
        rejects(&logical, &changed);
        let mut changed = binding.clone();
        changed.freeze.header.kind = ReceiptKind::NexusThaw;
        rejects(&logical, &changed);
        let mut changed = binding.clone();
        changed.closure.closed_authority_epoch = 1;
        rejects(&logical, &changed);
        let mut changed_logical = logical;
        changed_logical.completed_state_digest = Digest::ZERO;
        rejects(&changed_logical, &binding);
    }

    fn native_closure_payload_fixture()
    -> (LogicalRequestNexusBindingEvidence, HandoffProgressPayload, HandoffProgressPayload) {
        let (_, _, mut binding, _) = strict_lineage_fixture();
        let authority_epoch = binding.freeze.authority_epoch + 1;
        let first = HandoffProgressPayload {
            status: NativeHandoffStatus::Closing,
            readiness: None,
            freeze_generation: binding.freeze.freeze_generation,
            scope_revision: 5,
            authority_epoch,
            binding_epoch: binding.freeze.scope_generation,
            live_effects: 0,
            pending_publications: 1,
            native_effect: Some(compact_identity(b"client-effect", binding.nexus_effect.effect)),
            publication_pending: true,
            terminal_manifest_digest: None,
        };
        let terminal = HandoffProgressPayload {
            status: NativeHandoffStatus::Closed,
            readiness: None,
            freeze_generation: binding.freeze.freeze_generation,
            scope_revision: 7,
            authority_epoch,
            binding_epoch: binding.freeze.scope_generation,
            live_effects: 0,
            pending_publications: 0,
            native_effect: None,
            publication_pending: false,
            terminal_manifest_digest: Some(93),
        };
        let (_, closure) = expected_native_closure_receipts(&binding, first, terminal).unwrap();
        binding.closure = closure;
        (binding, first, terminal)
    }

    fn native_publication_fixture(
        binding: &LogicalRequestNexusBindingEvidence,
    ) -> DecodedNativePublication {
        let record = &binding.nexus_effect;
        let key = binding.freeze.key;
        let client_effect = compact_identity(b"client-effect", record.effect);
        let binding_epoch = binding.freeze.scope_generation;
        let register = RegisterEffect {
            client_effect,
            operation_class: compact_identity(b"operation-class", record.domain) as u32,
            syscall_number: compact_identity(b"operation", record.operation),
            syscall_arguments: [
                record.binding_generation,
                compact_identity(b"handoff", key.handoff),
                compact_identity(b"source", key.source.0),
                compact_identity(b"destination", key.destination.0),
                0,
                0,
            ],
            credit_units: 1,
            publication_required: true,
        };
        let selector = EffectSelector { client_effect, binding_epoch };
        let outcome = record.outcome_digest.unwrap();
        let commit = CommitEffect {
            client_effect,
            binding_epoch,
            result: i64::from_be_bytes(outcome.0[..8].try_into().unwrap()),
            domain_revision: record.binding_generation,
        };
        DecodedNativePublication {
            register_request_id: 2,
            register,
            registered: RegisteredPayload {
                client_effect,
                native_effect_id: 17,
                native_effect_generation: 1,
                authority_epoch: binding.freeze.authority_epoch,
                binding_epoch,
            },
            prepare_request_id: 3,
            prepare: selector,
            prepared: selector,
            commit_request_id: 4,
            commit,
            committed: CommittedPayload {
                client_effect,
                native_effect_id: 17,
                binding_epoch,
                commit_sequence: 1,
                result: commit.result,
                domain_revision: commit.domain_revision,
                registry_replay: false,
            },
        }
    }

    fn build_native_chain(
        entries: &[(PeerCommand, NativeReceiptPayload)],
    ) -> Vec<NativeJsonlExchange> {
        let mut previous = None;
        let mut chain = Vec::with_capacity(entries.len());
        for (index, (command, payload)) in entries.iter().cloned().enumerate() {
            let request_id = u64::try_from(index).unwrap() + 1;
            let request = PeerRequest { schema: REQUEST_SCHEMA.to_owned(), request_id, command };
            let request_bytes = serde_json::to_vec(&request).unwrap();
            let request_sha256 = sha256_hex(&request_bytes);
            let payload_sha256 = sha256_hex(&serde_json::to_vec(&payload).unwrap());
            let kind = payload.receipt_kind();
            let digest_input = ReceiptDigestInput {
                schema: RECEIPT_SCHEMA,
                sequence: request_id,
                kind,
                request_sha256: &request_sha256,
                previous_receipt_sha256: previous.as_deref(),
                payload_sha256: &payload_sha256,
                authentication_boundary: AUTHENTICATION_BOUNDARY,
                payload: &payload,
            };
            let receipt_sha256 = sha256_hex(&serde_json::to_vec(&digest_input).unwrap());
            let receipt = NativeReceipt {
                schema: RECEIPT_SCHEMA.to_owned(),
                sequence: request_id,
                kind,
                request_sha256: request_sha256.clone(),
                previous_receipt_sha256: previous.clone(),
                payload_sha256,
                authentication_boundary: AUTHENTICATION_BOUNDARY.to_owned(),
                payload,
                receipt_sha256: receipt_sha256.clone(),
            };
            let response = PeerResponse {
                schema: RESPONSE_SCHEMA.to_owned(),
                request_id,
                status: ResponseStatus::Ok,
                receipt: Some(receipt.clone()),
                error: None,
            };
            let receipt_kind = serde_json::to_value(kind).unwrap().as_str().unwrap().to_owned();
            chain.push(NativeJsonlExchange {
                request_id,
                request_jsonl: format!("{}\n", String::from_utf8(request_bytes).unwrap()),
                response_jsonl: format!("{}\n", serde_json::to_string(&response).unwrap()),
                receipt_sequence: request_id,
                receipt_kind,
                request_sha256,
                previous_receipt_sha256: receipt.previous_receipt_sha256.clone(),
                receipt_sha256,
            });
            previous = Some(receipt.receipt_sha256);
        }
        chain
    }

    fn native_transcript_entries(
        binding: &LogicalRequestNexusBindingEvidence,
        first: HandoffProgressPayload,
        terminal: HandoffProgressPayload,
    ) -> Vec<(PeerCommand, NativeReceiptPayload)> {
        let publication = native_publication_fixture(binding);
        let config = expected_native_peer_config(binding).unwrap();
        let intent = expected_native_prepare_intent(binding).unwrap();
        let decision = expected_native_commit_decision(binding).unwrap();
        vec![
            (
                PeerCommand::Initialize(config),
                NativeReceiptPayload::Initialized(InitializedPayload {
                    process_id: 4_242,
                    boot_incarnation: 1,
                    config,
                }),
            ),
            (
                PeerCommand::Register(publication.register),
                NativeReceiptPayload::EffectRegistered(publication.registered),
            ),
            (
                PeerCommand::Prepare(publication.prepare),
                NativeReceiptPayload::EffectPrepared(publication.prepared),
            ),
            (
                PeerCommand::Commit(publication.commit),
                NativeReceiptPayload::EffectCommitted(publication.committed),
            ),
            (
                PeerCommand::Freeze(intent),
                NativeReceiptPayload::AdmissionFrozen(FreezePayload {
                    handoff_id: intent.handoff_id,
                    registry_instance: 31,
                    boot_incarnation: 1,
                    scope_id: config.scope_id,
                    scope_generation: config.scope_generation,
                    authority_epoch: config.authority_epoch,
                    binding_epoch: config.binding_epoch,
                    frozen_scope_revision: first.scope_revision - 1,
                    freeze_generation: binding.freeze.freeze_generation,
                    cohort_digest: 32,
                    classification_digest: 33,
                    cohort_size: 1,
                    committed_at_freeze: 1,
                    readiness: NativeReadiness::ReadyToCommit,
                }),
            ),
            (PeerCommand::CloseStep(decision), NativeReceiptPayload::ClosureProgress(first)),
            (
                PeerCommand::AcknowledgePublication(publication.prepare),
                NativeReceiptPayload::PublicationAcknowledged(publication.prepare),
            ),
            (PeerCommand::CloseStep(decision), NativeReceiptPayload::ClosureProgress(terminal)),
            (PeerCommand::Query, NativeReceiptPayload::HandoffQuery(terminal)),
            (PeerCommand::Shutdown, NativeReceiptPayload::Shutdown),
        ]
    }

    fn nexus_evidence_with_chain(
        chain: Vec<NativeJsonlExchange>,
    ) -> NexusTerminalResponseLossEvidence {
        let terminal = &chain[7];
        NexusTerminalResponseLossEvidence {
            process: ProcessEffectPeerIdentity {
                process_id: 4_242,
                executable_path: PathBuf::from("/tmp/nexus-effect-peer"),
                executable_sha256: "1".repeat(64),
                nexus_revision: "2".repeat(40),
                start_time_ticks: 3,
            },
            transport_fault_injection_available: true,
            loss_model: NEXUS_LOSS_MODEL.to_owned(),
            publication_first: "published".to_owned(),
            duplicate_publication: "exact-replay".to_owned(),
            duplicate_publication_extended_native_chain: false,
            close_steps: 2,
            terminal_query_recovered_exact: true,
            exact_replay: NativeExactReplayEvidence {
                request_id: terminal.request_id,
                command: "close-step".to_owned(),
                original_request_jsonl: terminal.request_jsonl.clone(),
                original_response_jsonl: terminal.response_jsonl.clone(),
                replay_response_jsonl: terminal.response_jsonl.clone(),
                byte_identical: true,
                accepted_chain_length_before: 7,
                accepted_chain_length_after: 8,
                accepted_chain_grew_once: true,
            },
            native_chain: chain,
        }
    }

    fn assert_rehashed_native_transcript_rejected(
        binding: &LogicalRequestNexusBindingEvidence,
        entries: &[(PeerCommand, NativeReceiptPayload)],
    ) {
        let chain = build_native_chain(entries);
        assert_eq!(validate_native_jsonl_chain(&chain), Ok(()));
        let nexus = nexus_evidence_with_chain(chain);
        assert!(validate_native_closure_refinement(binding, &nexus).is_err());
    }

    #[test]
    fn native_publication_refinement_rejects_rehashed_operation_mutations() {
        let (_, _, binding, _) = strict_lineage_fixture();
        let publication = native_publication_fixture(&binding);
        assert!(validate_native_publication_projection(&binding, publication).is_ok());

        let mut changed = publication;
        changed.register.syscall_number ^= 1;
        assert!(validate_native_publication_projection(&binding, changed).is_err());
        let mut changed = publication;
        changed.prepare.binding_epoch += 1;
        assert!(validate_native_publication_projection(&binding, changed).is_err());
        let mut changed = publication;
        changed.commit.result ^= 1;
        assert!(validate_native_publication_projection(&binding, changed).is_err());
        let mut changed = publication;
        changed.committed.native_effect_id += 1;
        assert!(validate_native_publication_projection(&binding, changed).is_err());
    }

    #[test]
    fn exact_native_transcript_accepts_the_ten_command_semantic_refinement() {
        let (binding, first, terminal) = native_closure_payload_fixture();
        let entries = native_transcript_entries(&binding, first, terminal);
        let chain = build_native_chain(&entries);
        assert_eq!(validate_native_jsonl_chain(&chain), Ok(()));
        let nexus = nexus_evidence_with_chain(chain);
        assert_eq!(validate_native_closure_refinement(&binding, &nexus), Ok(()));
    }

    #[test]
    fn exact_native_transcript_rejects_rehashed_extra_and_reordered_commands() {
        let (binding, first, terminal) = native_closure_payload_fixture();
        let entries = native_transcript_entries(&binding, first, terminal);

        let mut extra = entries.clone();
        let extra_query = extra[8].clone();
        extra.insert(9, extra_query);
        assert_rehashed_native_transcript_rejected(&binding, &extra);

        let mut reordered = entries;
        reordered.swap(3, 4);
        assert_rehashed_native_transcript_rejected(&binding, &reordered);
    }

    #[test]
    fn exact_native_transcript_rejects_rehashed_freeze_and_query_payload_mutations() {
        let (binding, first, terminal) = native_closure_payload_fixture();
        let entries = native_transcript_entries(&binding, first, terminal);

        let mut changed_freeze = entries.clone();
        let NativeReceiptPayload::AdmissionFrozen(frozen) = &mut changed_freeze[4].1 else {
            panic!("fixture command 5 must be AdmissionFrozen");
        };
        frozen.cohort_size += 1;
        assert_rehashed_native_transcript_rejected(&binding, &changed_freeze);

        let mut changed_query = entries;
        let NativeReceiptPayload::HandoffQuery(query) = &mut changed_query[8].1 else {
            panic!("fixture command 9 must be HandoffQuery");
        };
        query.scope_revision += 1;
        assert_rehashed_native_transcript_rejected(&binding, &changed_query);
    }

    #[test]
    fn native_closure_refinement_rejects_rehashed_report_field_mutations() {
        let (binding, first, terminal) = native_closure_payload_fixture();
        assert_eq!(validate_native_closure_payload_refinement(&binding, first, terminal), Ok(()));

        let rejects = |candidate: &LogicalRequestNexusBindingEvidence,
                       first: HandoffProgressPayload,
                       terminal: HandoffProgressPayload| {
            assert!(
                validate_native_closure_payload_refinement(candidate, first, terminal).is_err()
            );
        };
        let mut changed = binding.clone();
        changed.closure.effect_manifest_digest = Digest::from_bytes([0x41; 32]);
        rejects(&changed, first, terminal);
        let mut changed = binding.clone();
        changed.closure.header.previous_digest = Some(Digest::from_bytes([0x42; 32]));
        rejects(&changed, first, terminal);
        let mut changed_terminal = terminal;
        changed_terminal.terminal_manifest_digest = Some(94);
        rejects(&binding, first, changed_terminal);
        let mut changed_terminal = terminal;
        changed_terminal.authority_epoch += 1;
        rejects(&binding, first, changed_terminal);
        let mut changed_first = first;
        changed_first.live_effects = 1;
        rejects(&binding, changed_first, terminal);
        let mut changed_first = first;
        changed_first.publication_pending = false;
        rejects(&binding, changed_first, terminal);
    }

    #[test]
    fn terminal_replay_binding_rejects_rehashed_metadata_mutations() {
        let exchange = NativeJsonlExchange {
            request_id: 8,
            request_jsonl: "terminal-close-request\n".to_owned(),
            response_jsonl: "terminal-close-response\n".to_owned(),
            receipt_sequence: 8,
            receipt_kind: "closure-progress".to_owned(),
            request_sha256: "1".repeat(64),
            previous_receipt_sha256: Some("2".repeat(64)),
            receipt_sha256: "3".repeat(64),
        };
        let replay = NativeExactReplayEvidence {
            request_id: 8,
            command: "close-step".to_owned(),
            original_request_jsonl: exchange.request_jsonl.clone(),
            original_response_jsonl: exchange.response_jsonl.clone(),
            replay_response_jsonl: exchange.response_jsonl.clone(),
            byte_identical: true,
            accepted_chain_length_before: 7,
            accepted_chain_length_after: 8,
            accepted_chain_grew_once: true,
        };
        assert_eq!(validate_terminal_replay_binding(&replay, &exchange), Ok(()));

        let mut changed = replay.clone();
        changed.command = "query".to_owned();
        assert!(validate_terminal_replay_binding(&changed, &exchange).is_err());
        let mut changed = replay.clone();
        changed.accepted_chain_length_before = 6;
        assert!(validate_terminal_replay_binding(&changed, &exchange).is_err());
        let mut changed = replay;
        changed.request_id = 7;
        assert!(validate_terminal_replay_binding(&changed, &exchange).is_err());
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
