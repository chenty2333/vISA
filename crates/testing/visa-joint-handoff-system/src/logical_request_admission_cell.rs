use std::{
    fmt, fs,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, CanonicalState, DeliveryPolicy, Digest,
    EffectOutcome, EffectRequest, EffectResult, EntityRef, EvidenceKind, EvidenceRef,
    ExtensionSupport, Generation, HandoffPhase, IdempotencyKey, Identity, JournalPosition,
    KeyValueClaim, LeaseEpoch, NodeIdentity, ResourceClaims, Rights, SchemaVersion,
    SnapshotEnvelope, TimerClaim, TimerClock, canonical_digest,
};
use joint_handoff_core::{
    ClassificationCounts, ClosureReceipt, DestinationPreparedReceipt, EffectScopeVersion,
    FreezeDisposition, JointIssuerSet, JointMappingManifest, NexusFreezeReceipt,
    OwnershipCommitReceipt, OwnershipPreparedReceipt, OwnershipVersion, PrepareIntentReceipt,
    PreparedBindings, ReceiptEnvelope, ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind,
    ReceiptRequest, SnapshotBinding, TypedReceipt, VisaDestinationActivationReceipt,
    VisaFreezeReceipt, VisaSourceFenceReceipt, canonical_bytes as joint_bytes,
    canonical_digest as joint_digest,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, EffectAdmissionProfile, EffectAdmissionSession,
    EffectClosureAuthenticationProfile, EffectClosureCapabilities, EffectClosureProviderLimits,
    EffectClosureProviderRequirements, JournalScope,
};
use substrate_host::{
    FaultPoint, LoopbackLogicalPeer, LoopbackLogicalPeerBehavior, SqliteProvider,
};
use visa_conformance::{JointEffectClassification, JointEffectRecord};
use visa_joint_handoff::{
    DestinationActivationAttempt, DestinationActivationCommands, DurableDestinationGuard,
    DurableJointSession, DurableProjectionDriver, DurableProjectionError, JointProjectionLog,
    JointProjectionLogHead, NativeReceiptAuthenticator, SourceFenceAttempt, VerifiedCommandReceipt,
    VisaDestinationRuntime, VisaRuntimeBinding,
};
use visa_profile::{
    ContinuityDisposition, CooperativeHandoffProfile, LOGICAL_REQUEST_EXTENSION_ID,
    LOGICAL_REQUEST_EXTENSION_VERSION, LogicalRequestClaim, LogicalRequestIdempotency,
    LogicalRequestPhase, LogicalRequestReplay, LogicalRequestResult, LogicalRequestState,
    LogicalRequestTransport, logical_request_extension, logical_request_state,
};
use visa_runtime::{
    AuthorityPlan, Coordinator, ProfileAuthorityPlan, RuntimeError, SnapshotExpectations,
    validate_snapshot,
};
use visa_wasmtime::{
    LogicalRequestAdapter, LogicalRequestAdapterError, PortableLogicalRequestState,
    PreparedLogicalRequestStart,
};

use crate::{
    EffectAdmissionRegistration, EffectCloseRequest, EffectCloseResult, EffectFreezeRequest,
    EffectFreezeResult, EffectPeer, EffectPeerConfig, EffectPeerError, EffectPublicationRequest,
    LostAckProjectionLog, NativeJsonlExchange, NativeResponseLossObservation,
    NexusProcessQualificationInputs, OwnershipCommitRequest, OwnershipLogError, OwnershipQuery,
    OwnershipReserveRequest, OwnershipSealRequest, ProcessEffectPeer, ProcessEffectPeerIdentity,
    ProcessLiveEffectAdvance, ProcessLiveEffectCommitMetadata, ProcessLiveEffectPhase,
    ReferenceOwnershipLog, SqliteJointProjectionLog, admission_component, effect_receipt_issuer,
    nexus_effect_wire::{PeerCommand, PeerRequest},
    ownership_receipt_issuer,
    process_effect_peer::validate_native_jsonl_chain,
};

pub const LOGICAL_REQUEST_ADMISSION_SCHEMA: &str = "visa.logical-request-admission-ordered-cell.v1";
pub const LOGICAL_REQUEST_ADMISSION_REPORT: &str = "logical-request-admission-report.json";
pub const SOURCE_DATABASE: &str = "source.sqlite3";
pub const DESTINATION_DATABASE: &str = "destination.sqlite3";
pub const OWNERSHIP_DATABASE: &str = "ownership.sqlite3";
pub const JOINT_PROJECTION_DATABASE: &str = "joint-projection.sqlite3";

#[allow(dead_code)]
const ADMISSION_AUTHENTICATION_DOMAIN: &[u8] =
    b"vISA/logical-request-admission/authentication/v1/same-boot-only\0";
const ADMISSION_ID_DOMAIN: &[u8] = b"vISA/logical-request-admission/fixture/v1\0";
const INITIAL_EPOCH: LeaseEpoch = LeaseEpoch(1);
const LOGICAL_PEER_IDENTITY: &[u8] = b"visa-admission-logical-peer-v1";
const LOGICAL_PEER_CREDENTIAL: &[u8] = b"visa-admission-logical-credential-v1";
const LOGICAL_REQUEST_BYTES: &[u8] = b"visa-admission-ordered-request-v1";
const LOGICAL_RESPONSE_BYTES: &[u8] = b"visa-admission-ordered-response-v1";
pub(crate) const ADMISSION_LIMITATIONS: [&str; 6] = [
    "same boot and one host only; no host-reboot recovery or cross-host transport is claimed",
    "the Nexus boundary is a real host process backed by the production Registry mapping, not real OSTD execution",
    "IRQ, SMP, device DMA, retained tombstones, and hardware reset paths are outside this cell",
    "the receipt authenticator is a deterministic same-boot evidence key, not a cryptographic freshness or anti-rollback root",
    "the exactly-once observation is bounded to one operation-id-deduplicated logical request and is not a general exactly-once claim",
    "source and destination use independent SQLite stores on the same filesystem and process lifetime",
];

type AdmissionJointLog = LostAckProjectionLog<SqliteJointProjectionLog>;
type AdmissionJointSession = DurableJointSession<AdmissionJointLog, AdmissionAuthenticator>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestAdmissionInputs {
    pub run_identity: Identity,
    pub nexus: NexusProcessQualificationInputs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestAdmissionExpectations {
    pub run_identity: Identity,
    pub nexus_process: ProcessEffectPeerIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestAdmissionClaims {
    pub same_boot: bool,
    pub host_process: bool,
    pub production_registry_admitted: bool,
    pub real_wasmtime: bool,
    pub independent_source_destination_sqlite: bool,
    pub real_ostd_execution: bool,
    pub irq_smp: bool,
    pub cross_host: bool,
    pub host_reboot_recovery: bool,
    pub cryptographic_freshness: bool,
    pub retained_tombstone_path: bool,
    pub general_exactly_once: bool,
}

impl LogicalRequestAdmissionClaims {
    pub const fn bounded() -> Self {
        Self {
            same_boot: true,
            host_process: true,
            production_registry_admitted: true,
            real_wasmtime: true,
            independent_source_destination_sqlite: true,
            real_ostd_execution: false,
            irq_smp: false,
            cross_host: false,
            host_reboot_recovery: false,
            cryptographic_freshness: false,
            retained_tombstone_path: false,
            general_exactly_once: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDatabaseEvidence {
    pub path: String,
    pub user_version: u32,
    pub device: u64,
    pub inode: u64,
    pub hard_link_count: u64,
    pub regular_file: bool,
    pub symlink: bool,
    pub integrity_check: String,
    pub foreign_key_violations: usize,
    pub runtime_journal_mode: String,
    pub wal_checkpoint_busy: u32,
    pub wal_log_frames: u32,
    pub wal_checkpointed_frames: u32,
    pub archive_journal_mode: String,
    pub sidecars_absent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDatabaseSetEvidence {
    pub source: AdmissionDatabaseEvidence,
    pub destination: AdmissionDatabaseEvidence,
    pub ownership: AdmissionDatabaseEvidence,
    pub joint_projection: AdmissionDatabaseEvidence,
    pub all_device_inode_pairs_distinct: bool,
    pub source_destination_paths_distinct: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceiptMaterial {
    pub kind: String,
    pub issuance_request: Vec<u8>,
    pub peer_invocation: Option<Vec<u8>>,
    pub envelope: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStagedAdvanceEvidence {
    pub phase: String,
    pub advance: u64,
    pub replay: bool,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub native_sequence: Option<u64>,
    pub native_request_sha256: Option<String>,
    pub native_receipt_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionVerifiedCommitEvidence {
    pub client_effect: u64,
    pub native_effect_id: u64,
    pub native_effect_generation: u64,
    pub binding_epoch: u64,
    pub commit_sequence: u64,
    pub result: i64,
    pub domain_revision: u64,
    pub registry_replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionJointProjectionEvidence {
    pub head: JointProjectionLogHead,
    pub canonical_record_bytes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSourceEvidence {
    pub logical_operation: Identity,
    pub preview: EffectRequest,
    pub source_start_outcome: EffectOutcome,
    pub source_start_state: CanonicalState,
    pub source_start_phase: String,
    pub source_start_effect: Identity,
    pub source_journal_position: JournalPosition,
    pub source_state_digest: Digest,
    pub source_ledger_revision: u64,
    pub source_ledger_retained_request: bool,
    pub source_start_provider_row_present: bool,
    pub source_start_effect_mapping_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionNexusEvidence {
    pub process: ProcessEffectPeerIdentity,
    pub registration: EffectPublicationRequest,
    pub final_publication: EffectPublicationRequest,
    pub register: AdmissionStagedAdvanceEvidence,
    pub prepare: AdmissionStagedAdvanceEvidence,
    pub commit: AdmissionStagedAdvanceEvidence,
    pub outcome: AdmissionStagedAdvanceEvidence,
    pub verified_commit: AdmissionVerifiedCommitEvidence,
    pub commit_metadata_result: i64,
    pub commit_metadata_meaning: String,
    pub commit_domain_revision: u64,
    pub commit_ack_loss: NativeResponseLossObservation,
    pub freeze: NexusFreezeReceipt,
    pub frozen_counts: ClassificationCounts,
    pub closure: ClosureReceipt,
    pub native_complete_count: usize,
    pub native_chain: Vec<NativeJsonlExchange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionOwnershipEvidence {
    pub intent: PrepareIntentReceipt,
    pub prepared: OwnershipPreparedReceipt,
    pub commit: OwnershipCommitReceipt,
    pub commit_request: OwnershipCommitRequest,
    pub queried_commit: OwnershipCommitReceipt,
    pub retried_commit: OwnershipCommitReceipt,
    pub journal_mode: String,
    pub synchronous: i64,
    pub acknowledgement_error: String,
    pub commit_ack_lost_after_durable_write: bool,
    pub reopened_query_exact: bool,
    pub exact_retry: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRuntimeEvidence {
    pub issuer_set: JointIssuerSet,
    pub authentication_secret: [u8; 32],
    pub snapshot: SnapshotEnvelope,
    pub visa_freeze: VisaFreezeReceipt,
    pub destination_prepared: DestinationPreparedReceipt,
    pub source_fence: VisaSourceFenceReceipt,
    pub destination_activation: VisaDestinationActivationReceipt,
    pub destination_guest_restored_before_activation_receipt: bool,
    pub destination_release_blocked_before_completion: bool,
    pub source_terminal_state: CanonicalState,
    pub destination_prepared_state: CanonicalState,
    pub destination_activation_state: CanonicalState,
    pub destination_terminal_state: CanonicalState,
    pub receipt_material: Vec<AdmissionReceiptMaterial>,
    pub joint_projection: AdmissionJointProjectionEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDestinationEvidence {
    pub source_start_absent_before_reconcile: bool,
    pub logical_ledger_absent_before_reconcile: bool,
    pub portable_source_operation_present_before_reconcile: bool,
    pub reconcile_effect: Identity,
    pub reconcile_effect_differs_from_source_start: bool,
    pub reconcile_provider_row_present: bool,
    pub destination_ledger_revision: u64,
    pub destination_ledger_retained_request: bool,
    pub terminal_phase: String,
    pub remote_request_count: u64,
    pub remote_execution_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSequenceEvidence {
    pub steps: Vec<String>,
    pub external_requests_before_nexus_commit: u64,
    pub external_executions_before_nexus_commit: u64,
    pub external_executions_after_source_start: u64,
    pub external_executions_after_destination_reconcile: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestAdmissionReport {
    pub schema: String,
    pub all_passed: bool,
    pub run_identity: Identity,
    pub claims: LogicalRequestAdmissionClaims,
    pub sequence: AdmissionSequenceEvidence,
    pub source: AdmissionSourceEvidence,
    pub nexus: AdmissionNexusEvidence,
    pub ownership: AdmissionOwnershipEvidence,
    pub runtime: AdmissionRuntimeEvidence,
    pub destination: AdmissionDestinationEvidence,
    pub databases: AdmissionDatabaseSetEvidence,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionDatabasePaths {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub ownership: PathBuf,
    pub joint_projection: PathBuf,
    pub report: PathBuf,
}

impl AdmissionDatabasePaths {
    pub fn new(root: &Path) -> Self {
        Self {
            source: root.join(SOURCE_DATABASE),
            destination: root.join(DESTINATION_DATABASE),
            ownership: root.join(OWNERSHIP_DATABASE),
            joint_projection: root.join(JOINT_PROJECTION_DATABASE),
            report: root.join(LOGICAL_REQUEST_ADMISSION_REPORT),
        }
    }

    pub fn databases(&self) -> [&Path; 4] {
        [
            self.source.as_path(),
            self.destination.as_path(),
            self.ownership.as_path(),
            self.joint_projection.as_path(),
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionFixtureIds {
    source_node: NodeIdentity,
    destination_node: NodeIdentity,
    source_component: EntityRef,
    destination_component: EntityRef,
    timer: EntityRef,
    key_value: EntityRef,
    key_value_namespace: Identity,
    request: EntityRef,
    credential_reference: Identity,
    logical_operation: Identity,
    source_handoff_authority: EntityRef,
    destination_handoff_authority: EntityRef,
    attenuated_handoff_authority: EntityRef,
    source_timer_authority: EntityRef,
    destination_timer_authority: EntityRef,
    attenuated_timer_authority: EntityRef,
    source_key_value_authority: EntityRef,
    destination_key_value_authority: EntityRef,
    attenuated_key_value_authority: EntityRef,
    source_request_authority: EntityRef,
    destination_request_authority: EntityRef,
    attenuated_request_authority: EntityRef,
    activate: Identity,
    handoff: Identity,
    snapshot: Identity,
}

impl AdmissionFixtureIds {
    fn for_run(run: Identity) -> Result<Self, String> {
        let component = derived_identity(run, b"component")?;
        Ok(Self {
            source_node: NodeIdentity::new(derived_identity(run, b"source-node")?),
            destination_node: NodeIdentity::new(derived_identity(run, b"destination-node")?),
            source_component: EntityRef::initial(component),
            destination_component: EntityRef::new(component, Generation(1)),
            timer: derived_entity(run, b"timer")?,
            key_value: derived_entity(run, b"key-value")?,
            key_value_namespace: derived_identity(run, b"key-value-namespace")?,
            request: derived_entity(run, b"logical-request")?,
            credential_reference: derived_identity(run, b"credential-reference")?,
            logical_operation: derived_identity(run, b"logical-operation")?,
            source_handoff_authority: derived_entity(run, b"source-handoff-authority")?,
            destination_handoff_authority: derived_entity(run, b"destination-handoff-authority")?,
            attenuated_handoff_authority: derived_entity(run, b"attenuated-handoff-authority")?,
            source_timer_authority: derived_entity(run, b"source-timer-authority")?,
            destination_timer_authority: derived_entity(run, b"destination-timer-authority")?,
            attenuated_timer_authority: derived_entity(run, b"attenuated-timer-authority")?,
            source_key_value_authority: derived_entity(run, b"source-key-value-authority")?,
            destination_key_value_authority: derived_entity(
                run,
                b"destination-key-value-authority",
            )?,
            attenuated_key_value_authority: derived_entity(run, b"attenuated-key-value-authority")?,
            source_request_authority: derived_entity(run, b"source-request-authority")?,
            destination_request_authority: derived_entity(run, b"destination-request-authority")?,
            attenuated_request_authority: derived_entity(run, b"attenuated-request-authority")?,
            activate: derived_identity(run, b"source-activate")?,
            handoff: derived_identity(run, b"handoff")?,
            snapshot: derived_identity(run, b"snapshot")?,
        })
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct AdmissionFixture {
    run_identity: Identity,
    paths: AdmissionDatabasePaths,
    ids: AdmissionFixtureIds,
    key: joint_handoff_core::JointHandoffKey,
    effect_config: EffectPeerConfig,
    source_initial_state: CanonicalState,
    profile_digest: Digest,
    logical_request: LogicalRequestState,
    handoff_authority: AuthorityPlan,
    timer_authority: AuthorityPlan,
    key_value_authority: AuthorityPlan,
    request_authority: ProfileAuthorityPlan,
    request: Vec<u8>,
}

struct AdmissionSetup {
    fixture: AdmissionFixture,
    source_provider: SqliteProvider,
    destination_provider: SqliteProvider,
    logical_peer: LoopbackLogicalPeer,
}

impl AdmissionSetup {
    fn create(root: &Path, run: Identity) -> Result<Self, String> {
        Self::create_with_optional_source_fault(
            root,
            run,
            Some(FaultPoint::AfterLogicalRequestSend),
        )
    }

    #[cfg(test)]
    fn create_with_source_fault(
        root: &Path,
        run: Identity,
        source_fault: FaultPoint,
    ) -> Result<Self, String> {
        Self::create_with_optional_source_fault(root, run, Some(source_fault))
    }

    #[cfg(test)]
    fn create_without_source_fault(root: &Path, run: Identity) -> Result<Self, String> {
        Self::create_with_optional_source_fault(root, run, None)
    }

    fn create_with_optional_source_fault(
        root: &Path,
        run: Identity,
        source_fault: Option<FaultPoint>,
    ) -> Result<Self, String> {
        if run.is_zero() {
            return Err("admission fixture run identity is zero".to_owned());
        }
        fs::create_dir_all(root).map_err(debug)?;
        let paths = AdmissionDatabasePaths::new(root);
        for path in paths.databases().into_iter().chain([paths.report.as_path()]) {
            if path_entry_exists(path)? {
                return Err(format!("admission output already exists: {}", path.display()));
            }
        }
        for database in paths.databases() {
            for sidecar in sqlite_sidecars(database) {
                if path_entry_exists(&sidecar)? {
                    return Err(format!(
                        "admission SQLite sidecar already exists: {}",
                        sidecar.display()
                    ));
                }
            }
        }

        let ids = AdmissionFixtureIds::for_run(run)?;
        let key = joint_handoff_core::JointHandoffKey {
            continuity_unit: ids.source_component,
            handoff: ids.handoff,
            source: ids.source_node,
            destination: ids.destination_node,
            expected_epoch: INITIAL_EPOCH,
            next_epoch: INITIAL_EPOCH.next().ok_or("admission lease epoch exhausted")?,
        };
        let expected_authenticator = expected_admission_authenticator(run, key)?;
        let effect_config = EffectPeerConfig {
            key,
            issuer: expected_authenticator.issuers.effect_closure,
            ownership_issuer: expected_authenticator.issuers.ownership,
            registry_instance: derived_identity(run, b"registry-instance")?,
            scope_id: derived_identity(run, b"scope")?,
            scope_generation: 1,
            authority_epoch: 1,
            freeze_generation: 1,
            domain_bindings_digest: derived_digest(run, b"domain-bindings")?,
        };

        let request = LOGICAL_REQUEST_BYTES.to_vec();
        let request_rights = profile_rights();
        let logical_request = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: ids.request,
                peer_identity: LOGICAL_PEER_IDENTITY.to_vec(),
                credential_reference: ids.credential_reference,
                required_rights: request_rights,
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 1_000,
                max_request_size: visa_profile::MAX_LOGICAL_REQUEST_BYTES,
                max_response_size: visa_profile::MAX_LOGICAL_RESPONSE_BYTES,
            },
            operation_id: ids.logical_operation,
            request_size: u32::try_from(request.len())
                .map_err(|_| "admission request is too large")?,
            request_digest: canonical_digest(request.as_slice()).map_err(debug)?,
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let extension = logical_request_extension(&logical_request).map_err(debug)?;
        let profile = CooperativeHandoffProfile::v1(vec![ExtensionSupport {
            id: LOGICAL_REQUEST_EXTENSION_ID,
            version: LOGICAL_REQUEST_EXTENSION_VERSION,
        }]);
        let profile_digest = canonical_digest(&profile).map_err(debug)?;
        let claims = ResourceClaims {
            timer: TimerClaim {
                resource: ids.timer,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: timer_rights(),
            },
            key_value: KeyValueClaim {
                resource: ids.key_value,
                namespace: ids.key_value_namespace,
                required_rights: key_value_rights(),
                delivery: DeliveryPolicy::Deduplicated,
            },
        };
        let source_roots = vec![
            AuthorityGrant::active_root(
                ids.source_handoff_authority,
                ids.source_component,
                ids.source_component,
                Rights::HANDOFF,
            ),
            AuthorityGrant::active_root(
                ids.source_timer_authority,
                ids.source_component,
                ids.timer,
                timer_rights(),
            ),
            AuthorityGrant::active_root(
                ids.source_key_value_authority,
                ids.source_component,
                ids.key_value,
                key_value_rights(),
            ),
            AuthorityGrant::active_root(
                ids.source_request_authority,
                ids.source_component,
                ids.request,
                request_rights,
            ),
        ];
        let source_initial_state = CanonicalState::dormant_with_extensions(
            ids.source_component,
            ids.source_node,
            admission_component::digest(),
            profile_digest,
            SchemaVersion::new(profile.version.major, profile.version.minor),
            claims,
            source_roots.clone(),
            vec![extension],
        );
        let source_scope =
            JournalScope { node: ids.source_node, component: ids.source_component.identity };
        let mut source_provider =
            SqliteProvider::open(&paths.source, source_scope).map_err(debug)?;
        for (resource, rights) in [
            (ids.source_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.request, request_rights),
        ] {
            source_provider
                .install_policy(AuthorityPolicy {
                    subject: ids.source_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(debug)?;
        }
        for grant in &source_roots {
            source_provider.install_grant(grant).map_err(debug)?;
        }

        // Seed the independent destination database with only the initial
        // source ownership/lease provenance. This happens before the real
        // source Start below, so no source provider outcome or logical-request
        // ledger row can be copied into the destination store.
        let mut destination_seed = SqliteProvider::open(
            &paths.destination,
            JournalScope { node: ids.source_node, component: ids.source_component.identity },
        )
        .map_err(debug)?;
        for (resource, rights) in [
            (ids.source_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.request, request_rights),
        ] {
            destination_seed
                .install_policy(AuthorityPolicy {
                    subject: ids.source_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(debug)?;
        }
        for grant in &source_roots {
            destination_seed.install_grant(grant).map_err(debug)?;
        }
        destination_seed
            .provision_key_value_namespace(ids.key_value, ids.key_value_namespace)
            .map_err(debug)?;
        let mut destination_seed =
            Coordinator::recover(source_initial_state.clone(), destination_seed).map_err(debug)?;
        destination_seed
            .activate(ids.activate, ids.source_handoff_authority, INITIAL_EPOCH)
            .map_err(debug)?;
        drop(destination_seed);

        let mut destination_provider = SqliteProvider::open(
            &paths.destination,
            JournalScope {
                node: ids.destination_node,
                component: ids.destination_component.identity,
            },
        )
        .map_err(debug)?;
        for (resource, rights) in [
            (ids.destination_component, Rights::HANDOFF),
            (ids.timer, timer_rights()),
            (ids.key_value, key_value_rights()),
            (ids.request, request_rights),
        ] {
            destination_provider
                .install_policy(AuthorityPolicy {
                    subject: ids.destination_component,
                    resource,
                    allowed_rights: rights,
                })
                .map_err(debug)?;
        }

        let logical_peer = LoopbackLogicalPeer::spawn(
            LOGICAL_PEER_IDENTITY.to_vec(),
            LOGICAL_PEER_CREDENTIAL.to_vec(),
            LoopbackLogicalPeerBehavior::Static(LOGICAL_RESPONSE_BYTES.to_vec()),
        )
        .map_err(debug)?;
        source_provider
            .provision_key_value_namespace(ids.key_value, ids.key_value_namespace)
            .map_err(debug)?;
        source_provider
            .provision_logical_request(
                &logical_request,
                logical_peer.address(),
                LOGICAL_PEER_CREDENTIAL,
            )
            .map_err(debug)?;
        destination_provider
            .provision_key_value_namespace_availability(
                ids.destination_node,
                ids.key_value_namespace,
            )
            .map_err(debug)?;
        destination_provider
            .provision_logical_request(
                &logical_request,
                logical_peer.address(),
                LOGICAL_PEER_CREDENTIAL,
            )
            .map_err(debug)?;
        if let Some(source_fault) = source_fault {
            source_provider.inject_failure_once(source_fault);
        }

        let fixture = AdmissionFixture {
            run_identity: run,
            paths,
            ids,
            key,
            effect_config,
            source_initial_state,
            profile_digest,
            logical_request,
            handoff_authority: authority_plan(
                ids.source_handoff_authority,
                ids.destination_handoff_authority,
                ids.attenuated_handoff_authority,
            ),
            timer_authority: authority_plan(
                ids.source_timer_authority,
                ids.destination_timer_authority,
                ids.attenuated_timer_authority,
            ),
            key_value_authority: authority_plan(
                ids.source_key_value_authority,
                ids.destination_key_value_authority,
                ids.attenuated_key_value_authority,
            ),
            request_authority: ProfileAuthorityPlan {
                profile: LOGICAL_REQUEST_EXTENSION_ID,
                resource: ids.request,
                authority: authority_plan(
                    ids.source_request_authority,
                    ids.destination_request_authority,
                    ids.attenuated_request_authority,
                ),
            },
            request,
        };
        Ok(Self { fixture, source_provider, destination_provider, logical_peer })
    }

    fn into_active_source(
        self,
    ) -> Result<
        (
            AdmissionFixture,
            LogicalRequestAdapter<SqliteProvider>,
            SqliteProvider,
            LoopbackLogicalPeer,
        ),
        String,
    > {
        self.into_active_source_with_session("logical-request-admission:source-session")
    }

    fn into_active_source_with_session(
        self,
        session_id: &str,
    ) -> Result<
        (
            AdmissionFixture,
            LogicalRequestAdapter<SqliteProvider>,
            SqliteProvider,
            LoopbackLogicalPeer,
        ),
        String,
    > {
        let mut coordinator =
            Coordinator::recover(self.fixture.source_initial_state.clone(), self.source_provider)
                .map_err(debug)?;
        coordinator
            .activate(
                self.fixture.ids.activate,
                self.fixture.ids.source_handoff_authority,
                INITIAL_EPOCH,
            )
            .map_err(debug)?;
        let mut source = LogicalRequestAdapter::instantiate_with_profile(
            admission_component::bytes(),
            coordinator,
            EffectAdmissionProfile::AdmissionRequired,
        )
        .map_err(debug)?;
        source.activate(session_id).map_err(debug)?;
        Ok((self.fixture, source, self.destination_provider, self.logical_peer))
    }
}

fn authority_plan(
    source_authority: EntityRef,
    destination_authority: EntityRef,
    attenuated_authority: EntityRef,
) -> AuthorityPlan {
    AuthorityPlan { source_authority, destination_authority, attenuated_authority }
}

#[allow(dead_code)]
enum AdmissionDestinationState {
    Prepared(Box<Coordinator<SqliteProvider>>),
    GuestRestored(Box<LogicalRequestAdapter<SqliteProvider>>),
}

/// Testing-only destination projection wrapper. The restored Wasmtime adapter
/// remains owned by the durable activation guard; callers cannot obtain it
/// until the guard has persisted and verified the activation completion.
#[allow(dead_code)]
pub(crate) struct AdmissionDestinationRuntime {
    state: Option<AdmissionDestinationState>,
    portable: PortableLogicalRequestState,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum AdmissionDestinationRuntimeError {
    Runtime(RuntimeError),
    Adapter(LogicalRequestAdapterError),
    InvalidState,
}

impl fmt::Display for AdmissionDestinationRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AdmissionDestinationRuntimeError {}

#[allow(dead_code)]
impl AdmissionDestinationRuntime {
    pub(crate) fn new(
        coordinator: Coordinator<SqliteProvider>,
        portable: PortableLogicalRequestState,
    ) -> Self {
        Self { state: Some(AdmissionDestinationState::Prepared(Box::new(coordinator))), portable }
    }

    fn coordinator(
        &self,
    ) -> Result<&Coordinator<SqliteProvider>, AdmissionDestinationRuntimeError> {
        match self.state.as_ref() {
            Some(AdmissionDestinationState::Prepared(coordinator)) => Ok(coordinator.as_ref()),
            Some(AdmissionDestinationState::GuestRestored(adapter)) => Ok(adapter.coordinator()),
            None => Err(AdmissionDestinationRuntimeError::InvalidState),
        }
    }

    fn coordinator_mut(
        &mut self,
    ) -> Result<&mut Coordinator<SqliteProvider>, AdmissionDestinationRuntimeError> {
        match self.state.as_mut() {
            Some(AdmissionDestinationState::Prepared(coordinator)) => Ok(coordinator.as_mut()),
            Some(AdmissionDestinationState::GuestRestored(adapter)) => {
                Ok(adapter.coordinator_mut())
            }
            None => Err(AdmissionDestinationRuntimeError::InvalidState),
        }
    }

    pub(crate) fn into_adapter(
        mut self,
    ) -> Result<LogicalRequestAdapter<SqliteProvider>, AdmissionDestinationRuntimeError> {
        let state = self.state.take().ok_or(AdmissionDestinationRuntimeError::InvalidState)?;
        let AdmissionDestinationState::GuestRestored(adapter) = state else {
            return Err(AdmissionDestinationRuntimeError::InvalidState);
        };
        let canonical = adapter.coordinator().state();
        if canonical.phase != HandoffPhase::Running
            || canonical.activation.role != ActivationRole::Destination
            || canonical.activation.status != ActivationStatus::Active
        {
            return Err(AdmissionDestinationRuntimeError::InvalidState);
        }
        Ok(*adapter)
    }
}

impl VisaDestinationRuntime for AdmissionDestinationRuntime {
    type Error = AdmissionDestinationRuntimeError;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        <Coordinator<SqliteProvider> as VisaDestinationRuntime>::joint_runtime_binding(
            self.coordinator()?,
        )
        .map_err(AdmissionDestinationRuntimeError::Runtime)
    }

    fn destination_commit_request_digest(
        &self,
        operation: Identity,
        idempotency: contract_core::IdempotencyKey,
        resume_guard: Identity,
    ) -> Result<Digest, Self::Error> {
        <Coordinator<SqliteProvider> as VisaDestinationRuntime>::destination_commit_request_digest(
            self.coordinator()?,
            operation,
            idempotency,
            resume_guard,
        )
        .map_err(AdmissionDestinationRuntimeError::Runtime)
    }

    fn commit_for_activation(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
    ) -> Result<(), Self::Error> {
        <Coordinator<SqliteProvider> as VisaDestinationRuntime>::commit_for_activation(
            self.coordinator_mut()?,
            handoff,
            request_digest,
            commands,
        )
        .map_err(AdmissionDestinationRuntimeError::Runtime)?;

        if matches!(self.state, Some(AdmissionDestinationState::Prepared(_))) {
            let state = self.state.take().ok_or(AdmissionDestinationRuntimeError::InvalidState)?;
            let AdmissionDestinationState::Prepared(coordinator) = state else {
                return Err(AdmissionDestinationRuntimeError::InvalidState);
            };
            let mut adapter = match LogicalRequestAdapter::instantiate_recoverable_with_profile(
                admission_component::bytes(),
                *coordinator,
                EffectAdmissionProfile::AdmissionRequired,
            ) {
                Ok(adapter) => adapter,
                Err(failure) => {
                    let (error, coordinator) = *failure;
                    self.state = Some(AdmissionDestinationState::Prepared(Box::new(coordinator)));
                    return Err(AdmissionDestinationRuntimeError::Adapter(error));
                }
            };
            if let Err(error) = adapter.restore(&self.portable) {
                let coordinator = adapter.into_coordinator();
                self.state = Some(AdmissionDestinationState::Prepared(Box::new(coordinator)));
                return Err(AdmissionDestinationRuntimeError::Adapter(error));
            }
            self.state = Some(AdmissionDestinationState::GuestRestored(Box::new(adapter)));
        }
        Ok(())
    }

    fn preview_activation_resume(
        &self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
    ) -> Result<visa_joint_handoff::LocalProjection, Self::Error> {
        <Coordinator<SqliteProvider> as VisaDestinationRuntime>::preview_activation_resume(
            self.coordinator()?,
            handoff,
            request_digest,
            commands,
            activation_record_digest,
        )
        .map_err(AdmissionDestinationRuntimeError::Runtime)
    }

    fn resume_after_activation_receipt(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: visa_joint_handoff::LocalProjection,
    ) -> Result<visa_joint_handoff::LocalProjection, Self::Error> {
        <Coordinator<SqliteProvider> as VisaDestinationRuntime>::resume_after_activation_receipt(
            self.coordinator_mut()?,
            handoff,
            request_digest,
            commands,
            activation_record_digest,
            expected,
        )
        .map_err(AdmissionDestinationRuntimeError::Runtime)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum AdmissionAuthenticationError {
    WrongHandoff,
    WrongIssuer,
    InvalidTag,
    Encoding,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct AdmissionAuthenticator {
    pub(crate) key: joint_handoff_core::JointHandoffKey,
    pub(crate) issuers: JointIssuerSet,
    pub(crate) secret: [u8; 32],
}

#[allow(dead_code)]
impl AdmissionAuthenticator {
    pub(crate) fn envelope<T: TypedReceipt>(
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
    ) -> Result<Vec<u8>, AdmissionAuthenticationError> {
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
        .map_err(|_| AdmissionAuthenticationError::Encoding)?;
        let mut digest = Sha256::new();
        digest.update(ADMISSION_AUTHENTICATION_DOMAIN);
        digest.update(self.secret);
        digest.update((projection.len() as u64).to_be_bytes());
        digest.update(projection);
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);
        Ok(digest.finalize().to_vec())
    }
}

impl NativeReceiptAuthenticator for AdmissionAuthenticator {
    type Error = AdmissionAuthenticationError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        _envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        if envelope.handoff != self.key.handoff {
            return Err(AdmissionAuthenticationError::WrongHandoff);
        }
        let expected = expected_issuer(self.issuers, envelope.kind);
        if envelope.issuer != expected.issuer
            || envelope.issuer_incarnation != expected.issuer_incarnation
        {
            return Err(AdmissionAuthenticationError::WrongIssuer);
        }
        if envelope.authentication != self.authentication(envelope, payload_bytes)? {
            return Err(AdmissionAuthenticationError::InvalidTag);
        }
        Ok(())
    }
}

#[allow(dead_code)]
type EncodedAdmissionReceiptMaterial = (Vec<u8>, Vec<u8>, Vec<u8>, AdmissionReceiptMaterial);

#[allow(dead_code)]
pub(crate) fn encode_receipt_material<T>(
    receipt: &T,
    command: Identity,
    authenticator: &AdmissionAuthenticator,
) -> Result<EncodedAdmissionReceiptMaterial, String>
where
    T: TypedReceipt + Serialize,
{
    let payload = joint_bytes(receipt).map_err(debug)?;
    let request = ReceiptRequest::for_receipt(command, receipt);
    let request_bytes = joint_bytes(&request).map_err(debug)?;
    let envelope = authenticator.envelope(receipt, &request, &payload)?;
    if !envelope.matches_request(&request, receipt).map_err(debug)? {
        return Err("receipt envelope did not bind its typed request".to_owned());
    }
    let envelope_bytes = joint_bytes(&envelope).map_err(debug)?;
    let material = AdmissionReceiptMaterial {
        kind: receipt_kind_name(T::KIND).to_owned(),
        issuance_request: request_bytes.clone(),
        peer_invocation: None,
        envelope: envelope_bytes.clone(),
        payload: payload.clone(),
    };
    Ok((request_bytes, envelope_bytes, payload, material))
}

#[allow(dead_code)]
pub(crate) struct AdmissionPrefix {
    fixture: AdmissionFixture,
    source: LogicalRequestAdapter<SqliteProvider>,
    destination_provider: SqliteProvider,
    logical_peer: LoopbackLogicalPeer,
    process_peer: ProcessEffectPeer,
    process_identity: ProcessEffectPeerIdentity,
    prepared_start: PreparedLogicalRequestStart,
    registration: EffectPublicationRequest,
    final_publication: EffectPublicationRequest,
    registered: ProcessLiveEffectAdvance,
    prepared: ProcessLiveEffectAdvance,
    committed: ProcessLiveEffectAdvance,
    outcome_recorded: ProcessLiveEffectAdvance,
    commit_ack_loss: NativeResponseLossObservation,
    source_outcome: EffectOutcome,
    source_logical_state: LogicalRequestState,
    source_start_state: CanonicalState,
    source_start_journal_position: JournalPosition,
    source_start_state_digest: Digest,
}

impl AdmissionPrefix {
    fn run(root: &Path, inputs: &LogicalRequestAdmissionInputs) -> Result<Self, String> {
        let setup = AdmissionSetup::create(root, inputs.run_identity)?;
        let (fixture, mut source, destination_provider, logical_peer) =
            setup.into_active_source()?;
        let prepared_start = source.prepare_start(fixture.request.clone()).map_err(debug)?;
        if prepared_start.effect_request().operation.is_zero()
            || prepared_start.effect_request().node != fixture.ids.source_node
            || prepared_start.effect_request().subject != fixture.ids.source_component
            || prepared_start.effect_request().resource != fixture.ids.request
            || prepared_start.effect_request().authority != fixture.ids.source_request_authority
            || prepared_start.effect_request().lease_epoch != INITIAL_EPOCH
        {
            return Err("Wasmtime preview did not retain the fixture authority identity".to_owned());
        }

        let registered_record = JointEffectRecord {
            effect: fixture.logical_request.operation_id,
            operation: prepared_start.effect_request().operation,
            domain: LOGICAL_REQUEST_EXTENSION_ID,
            binding_generation: fixture.effect_config.scope_generation,
            classification: JointEffectClassification::Registered,
            outcome_digest: None,
            tombstone_digest: None,
        };
        let registration = publication(&fixture, registered_record);
        let process_peer = ProcessEffectPeer::spawn_admission_required(
            inputs.nexus.launch(),
            fixture.effect_config,
        )
        .map_err(|error| format!("spawn admission Nexus process peer: {error:?}"))?;
        let process_identity = process_peer.process_identity().map_err(debug)?;
        let admission = EffectAdmissionSession::new(&process_peer);
        let required_capabilities = EffectClosureCapabilities {
            effect_admission: true,
            freeze_thaw: true,
            commit_close: true,
            ..EffectClosureCapabilities::default()
        };
        let requirements = EffectClosureProviderRequirements::v2_preview(
            required_capabilities,
            EffectClosureAuthenticationProfile::IntegrityOnly,
            EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 1,
                max_inflight_mutations: 1,
                max_request_bytes: 1,
                max_receipt_bytes: 1,
            },
        )
        .require_admission();
        let descriptor = admission.descriptor().map_err(debug)?;
        if !descriptor.satisfies(requirements) {
            return Err(
                "Nexus provider did not advertise the bounded v2-preview profile".to_owned()
            );
        }
        let admission_registration =
            EffectAdmissionRegistration::new(prepared_start.effect_request(), registration.clone())
                .map_err(debug)?;
        let registered_admission = admission
            .register(prepared_start.effect_request().clone(), admission_registration)
            .map_err(|failure| format!("register admission effect: {:?}", failure.error()))?;
        let registered = registered_admission.provider_state().clone();
        require_advance(&registered, ProcessLiveEffectPhase::Registered, 1, false)?;
        let prepared_admission = registered_admission
            .prepare()
            .map_err(|failure| format!("prepare admission effect: {:?}", failure.error()))?;
        let prepared = prepared_admission.provider_state().clone();
        require_advance(&prepared, ProcessLiveEffectPhase::Prepared, 2, false)?;

        let metadata = ProcessLiveEffectCommitMetadata {
            result: 0,
            domain_revision: fixture.effect_config.scope_generation,
        };
        process_peer.arm_next_response_loss().map_err(debug)?;
        let (commit_error, prepared_admission, retry_metadata) =
            match prepared_admission.commit(metadata) {
                Err(failure) => failure.into_parts(),
                Ok(_) => {
                    return Err(
                        "armed admission Commit returned a token before ACK recovery".to_owned()
                    );
                }
            };
        let lost_request_id = match commit_error {
            EffectPeerError::AcknowledgementLost { request_id } => request_id,
            error => return Err(format!("armed admission Commit failed unexpectedly: {error:?}")),
        };
        let committed_permit = match prepared_admission.commit(retry_metadata) {
            Ok(permit) => permit,
            Err(failure) => {
                return Err(format!("recover exact admission Commit: {:?}", failure.error()));
            }
        };
        let committed = committed_permit.commit_evidence().clone();
        require_advance(&committed, ProcessLiveEffectPhase::CommittedAwaitingOutcome, 3, false)?;
        let verified = committed
            .verified_commit()
            .ok_or("recovered admission Commit omitted verified metadata")?;
        if verified.result() != 0
            || verified.domain_revision() != fixture.effect_config.scope_generation
            || verified.native_effect_id() != registered.native_effect_id()
            || verified.native_effect_generation() != registered.native_effect_generation()
            || verified.commit_sequence() != 1
            || verified.registry_replay()
        {
            return Err("recovered admission Commit metadata changed".to_owned());
        }
        let observations = process_peer.response_loss_observations().map_err(debug)?;
        let commit_ack_loss = observations
            .into_iter()
            .next()
            .ok_or("admission Commit ACK-loss observation is absent")?;
        if commit_ack_loss.request_id != lost_request_id
            || !commit_ack_loss.byte_identical
            || commit_ack_loss.discarded_response_jsonl != commit_ack_loss.replay_response_jsonl
            || commit_ack_loss.accepted_chain_length_before.checked_add(1)
                != Some(commit_ack_loss.accepted_chain_length_after)
        {
            return Err("admission Commit ACK-loss recovery was not byte-exact".to_owned());
        }
        if logical_peer.request_count() != 0 || logical_peer.execution_count() != 0 {
            return Err("external request ran before Nexus admission Commit".to_owned());
        }

        let started = source
            .start_admitted(&prepared_start, &process_peer, committed_permit)
            .map_err(debug)?;
        if started.effect_operation_id.is_empty() {
            return Err("prepared source start omitted its effect identity".to_owned());
        }
        let source_logical_state = canonical_logical_request(source.coordinator().state())?;
        if source_logical_state.operation_id != fixture.logical_request.operation_id
            || source_logical_state.phase != LogicalRequestPhase::UnknownCompletion
            || source_logical_state.last_operation
                != Some(prepared_start.effect_request().operation)
        {
            return Err("source did not retain canonical UnknownCompletion".to_owned());
        }
        if logical_peer.request_count() != 1 || logical_peer.execution_count() != 1 {
            return Err("source logical request did not execute exactly once".to_owned());
        }
        let source_record = source
            .coordinator()
            .state()
            .operations
            .iter()
            .find(|record| record.request.operation == prepared_start.effect_request().operation)
            .ok_or("source canonical operations omitted the previewed Start")?;
        if source_record.request != *prepared_start.effect_request() {
            return Err("source Start request diverged from its admitted preview".to_owned());
        }
        let source_outcome =
            source_record.outcome.clone().ok_or("source Start omitted its provider outcome")?;
        require_unknown_start_outcome(&source_outcome)?;
        let source_start_state = source.coordinator().state().clone();
        let source_start_journal_position = source.coordinator().journal_position();
        let source_start_state_digest = source.coordinator().state_digest().map_err(debug)?;

        let final_record = JointEffectRecord {
            classification: JointEffectClassification::Committed,
            outcome_digest: Some(canonical_digest(&source_outcome).map_err(debug)?),
            ..registration.record.clone()
        };
        let final_publication = publication(&fixture, final_record);
        let before_outcome = process_peer.native_transcript().map_err(debug)?;
        let outcome_recorded = process_peer
            .record_live_effect_outcome(committed.token(), final_publication.clone())
            .map_err(|error| format!("record admission provider outcome: {error:?}"))?;
        require_advance(&outcome_recorded, ProcessLiveEffectPhase::OutcomeRecorded, 4, false)?;
        if outcome_recorded.native_sequence().is_some()
            || outcome_recorded.native_request_sha256().is_some()
            || outcome_recorded.native_receipt_sha256().is_some()
        {
            return Err("adapter-only outcome recording emitted native receipt metadata".to_owned());
        }
        let after_outcome = process_peer.native_transcript().map_err(debug)?;
        if before_outcome != after_outcome {
            return Err("adapter-only outcome recording extended the native transcript".to_owned());
        }
        validate_native_jsonl_chain(&after_outcome).map_err(debug)?;
        if native_command_count(&after_outcome, |command| {
            matches!(command, PeerCommand::Complete(_))
        })? != 0
        {
            return Err("source outcome incorrectly issued native Complete".to_owned());
        }

        Ok(Self {
            fixture,
            source,
            destination_provider,
            logical_peer,
            process_peer,
            process_identity,
            prepared_start,
            registration,
            final_publication,
            registered,
            prepared,
            committed,
            outcome_recorded,
            commit_ack_loss,
            source_outcome,
            source_logical_state,
            source_start_state,
            source_start_journal_position,
            source_start_state_digest,
        })
    }

    #[cfg(test)]
    fn shutdown(&self) -> Result<(), String> {
        self.process_peer
            .shutdown()
            .map_err(|error| format!("shutdown admission Nexus process peer: {error:?}"))
    }
}

#[allow(dead_code)]
struct AdmissionCommittedHandoff {
    fixture: AdmissionFixture,
    source: Coordinator<SqliteProvider>,
    destination: Option<AdmissionDestinationRuntime>,
    destination_adapter: Option<LogicalRequestAdapter<SqliteProvider>>,
    logical_peer: LoopbackLogicalPeer,
    process_identity: ProcessEffectPeerIdentity,
    prepared_start: PreparedLogicalRequestStart,
    registration: EffectPublicationRequest,
    final_publication: EffectPublicationRequest,
    registered: ProcessLiveEffectAdvance,
    prepared: ProcessLiveEffectAdvance,
    committed: ProcessLiveEffectAdvance,
    outcome_recorded: ProcessLiveEffectAdvance,
    commit_ack_loss: NativeResponseLossObservation,
    source_outcome: EffectOutcome,
    source_logical_state: LogicalRequestState,
    source_start_state: CanonicalState,
    source_start_journal_position: JournalPosition,
    source_start_state_digest: Digest,
    snapshot: SnapshotEnvelope,
    visa_freeze: VisaFreezeReceipt,
    frozen: EffectFreezeResult,
    destination_prepared_state: CanonicalState,
    destination_prepared: DestinationPreparedReceipt,
    source_fence: Option<VisaSourceFenceReceipt>,
    destination_activation: Option<VisaDestinationActivationReceipt>,
    ownership_intent: PrepareIntentReceipt,
    ownership_prepared: OwnershipPreparedReceipt,
    ownership_commit: OwnershipCommitReceipt,
    ownership_commit_request: OwnershipCommitRequest,
    ownership_retried_commit: OwnershipCommitReceipt,
    ownership_journal_mode: String,
    ownership_synchronous: i64,
    closure: ClosureReceipt,
    ownership_commit_ack_lost_after_durable_write: bool,
    ownership_reopened_query_exact: bool,
    ownership_exact_retry: bool,
    destination_guest_restored_before_activation_receipt: bool,
    destination_release_blocked_before_completion: bool,
    source_start_provider_row_present: bool,
    source_start_effect_mapping_present: bool,
    source_ledger_revision: u64,
    source_ledger_retained_request: bool,
    destination_source_start_absent_before_reconcile: bool,
    destination_logical_ledger_absent_before_reconcile: bool,
    destination_portable_source_operation_present_before_reconcile: bool,
    destination_reconcile_effect: Option<Identity>,
    destination_reconcile_provider_row_present: bool,
    destination_ledger_revision: u64,
    destination_ledger_retained_request: bool,
    destination_logical_state: Option<LogicalRequestState>,
    destination_activation_state: Option<CanonicalState>,
    destination_commit_operation: Identity,
    destination_commit_idempotency: IdempotencyKey,
    destination_resume_command: Identity,
    receipt_material: Vec<AdmissionReceiptMaterial>,
    native_chain: Vec<NativeJsonlExchange>,
    sequence: Vec<String>,
    authenticator: AdmissionAuthenticator,
    joint: AdmissionJointSession,
}

impl AdmissionCommittedHandoff {
    fn run(prefix: AdmissionPrefix) -> Result<Self, String> {
        let AdmissionPrefix {
            fixture,
            mut source,
            destination_provider,
            logical_peer,
            process_peer,
            process_identity,
            prepared_start,
            registration,
            final_publication,
            registered,
            prepared,
            committed,
            outcome_recorded,
            commit_ack_loss,
            source_outcome,
            source_logical_state,
            source_start_state,
            source_start_journal_position,
            source_start_state_digest,
        } = prefix;
        let run = fixture.run_identity;
        let key = fixture.key;
        let ownership_namespace = derived_issuer(run, b"ownership")?;
        let authenticator = expected_admission_authenticator(run, key)?;
        let issuers = authenticator.issuers;
        if issuers.ownership != fixture.effect_config.ownership_issuer
            || issuers.effect_closure != fixture.effect_config.issuer
        {
            return Err("admission issuer derivation drifted after setup".to_owned());
        }

        let mut ownership =
            ReferenceOwnershipLog::open(&fixture.paths.ownership, ownership_namespace)
                .map_err(debug)?;
        ownership
            .initialize_unit(key.continuity_unit, key.source, key.expected_epoch)
            .map_err(debug)?;
        let (journal_mode, synchronous) = ownership.durability_settings().map_err(debug)?;
        if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err("ownership log did not retain WAL/FULL durability".to_owned());
        }
        let projection_log = AdmissionJointLog::new(
            SqliteJointProjectionLog::open(&fixture.paths.joint_projection).map_err(debug)?,
        );
        let mut joint =
            DurableJointSession::recover(projection_log, authenticator.clone(), key, issuers)
                .map_err(debug)?;
        let mut receipt_material = Vec::new();

        let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
        let reserve_invocation = joint_bytes(&reserve_request).map_err(debug)?;
        let ownership_intent = ownership.reserve(reserve_request).map_err(debug)?;
        record_admission_receipt(
            &mut joint,
            &ownership_intent,
            derived_identity(run, b"record-prepare-intent")?,
            &authenticator,
            &mut receipt_material,
            Some(reserve_invocation),
        )?;
        let intent_ref = ownership_intent.receipt_ref().map_err(debug)?;

        source
            .coordinator_mut()
            .begin_quiesce(
                derived_identity(run, b"source-begin-quiesce")?,
                fixture.ids.source_handoff_authority,
            )
            .map_err(|error| format!("source begin_quiesce failed: {error:?}"))?;
        let safe_point = source
            .coordinator_mut()
            .prepare_safe_point()
            .map_err(|error| format!("source prepare_safe_point failed: {error:?}"))?;
        let portable =
            source.freeze().map_err(|error| format!("Wasmtime guest freeze failed: {error:?}"))?;
        source
            .coordinator_mut()
            .commit_safe_point(
                derived_identity(run, b"source-commit-safe-point")?,
                portable.as_bytes().to_vec(),
                safe_point,
            )
            .map_err(|error| format!("source commit_safe_point failed: {error:?}"))?;
        let pre_export_digest = source.coordinator().state_digest().map_err(debug)?;
        let (_, snapshot) = source
            .coordinator_mut()
            .export_snapshot(
                derived_identity(run, b"source-export-snapshot")?,
                fixture.ids.handoff,
                fixture.ids.snapshot,
                EvidenceRef {
                    identity: derived_identity(run, b"snapshot-integrity-evidence")?,
                    kind: EvidenceKind::SnapshotIntegrity,
                    digest: pre_export_digest,
                },
            )
            .map_err(|error| format!("source export_snapshot failed: {error:?}"))?;
        if source.coordinator().state().phase != HandoffPhase::Exported {
            return Err("source did not reach Exported after the Wasmtime safe point".to_owned());
        }
        let visa_freeze = VisaFreezeReceipt {
            header: admission_header(issuers.visa_source, ReceiptKind::VisaFreeze, 1, None),
            key,
            intent: intent_ref,
            journal_position: snapshot.body.snapshot.journal_position,
            state_digest: source.coordinator().state_digest().map_err(debug)?,
            portable_state_digest: canonical_digest(&snapshot.body.portable_state)
                .map_err(debug)?,
        };
        record_admission_receipt(
            &mut joint,
            &visa_freeze,
            derived_identity(run, b"record-visa-freeze")?,
            &authenticator,
            &mut receipt_material,
            None,
        )?;
        let visa_freeze_ref = visa_freeze.receipt_ref().map_err(debug)?;

        let validated = validate_snapshot(
            &snapshot,
            &SnapshotExpectations {
                component_digest: admission_component::digest(),
                profile_digest: fixture.profile_digest,
                profile_version: SchemaVersion::new(1, 0),
                supported_extensions: vec![ExtensionSupport {
                    id: LOGICAL_REQUEST_EXTENSION_ID,
                    version: LOGICAL_REQUEST_EXTENSION_VERSION,
                }],
                destination: fixture.ids.destination_node,
            },
        )
        .map_err(|error| format!("destination snapshot validation failed: {error:?}"))?;
        let mut destination = Coordinator::restore(validated, destination_provider)
            .map_err(|error| format!("destination Coordinator restore failed: {error:?}"))?;
        destination
            .prepare_destination_with_profiles(
                derived_identity(run, b"destination-local-prepare")?,
                fixture.handoff_authority,
                fixture.timer_authority,
                fixture.key_value_authority,
                std::slice::from_ref(&fixture.request_authority),
            )
            .map_err(|error| format!("destination local prepare failed: {error:?}"))?;
        if destination.state().phase != HandoffPhase::DestinationPrepared {
            return Err("destination did not reach the local prepared state".to_owned());
        }
        let destination_prepared_state = destination.state().clone();

        let freeze_request = EffectFreezeRequest {
            key,
            intent: ownership_intent.clone(),
            registry_instance: fixture.effect_config.registry_instance,
            scope_id: fixture.effect_config.scope_id,
            scope_generation: fixture.effect_config.scope_generation,
            authority_epoch: fixture.effect_config.authority_epoch,
            freeze_generation: fixture.effect_config.freeze_generation,
        };
        let freeze_invocation = joint_bytes(&freeze_request).map_err(debug)?;
        joint
            .record_effect_freeze_attempt(
                derived_identity(run, b"attempt-nexus-freeze")?,
                &freeze_invocation,
            )
            .map_err(debug)?;
        let frozen = process_peer
            .freeze(freeze_request)
            .map_err(|error| format!("freeze admission Nexus cohort: {error:?}"))?;
        if frozen.receipt.disposition != FreezeDisposition::ReadyToCommit
            || frozen.receipt.counts.registered != 1
            || frozen.receipt.counts.committed != 1
            || frozen.receipt.counts.aborted != 0
            || frozen.receipt.counts.unresolved != 0
            || frozen.receipt.counts.tombstones != 0
        {
            return Err(
                "Nexus freeze did not bind one outcome-recorded committed effect".to_owned()
            );
        }
        record_admission_receipt(
            &mut joint,
            &frozen.receipt,
            derived_identity(run, b"record-nexus-freeze")?,
            &authenticator,
            &mut receipt_material,
            Some(freeze_invocation),
        )?;
        let nexus_freeze_ref = frozen.receipt.receipt_ref().map_err(debug)?;

        let destination_commit_operation =
            derived_identity(run, b"destination-lease-commit-operation")?;
        let destination_commit_idempotency = IdempotencyKey::from_bytes(
            derived_identity(run, b"destination-lease-commit-idempotency")?.0,
        );
        let destination_resume_command =
            derived_identity(run, b"destination-resume-after-activation")?;
        let destination_commit_request_digest = destination
            .guarded_handoff_commit_request_digest(
                destination_commit_operation,
                destination_commit_idempotency,
                destination_resume_command,
            )
            .map_err(debug)?;
        let prepared_destination = destination
            .state()
            .prepared_destination
            .as_ref()
            .ok_or("destination prepared state is absent")?;
        let prepared_destination_digest = canonical_digest(prepared_destination).map_err(debug)?;
        let authorities_digest =
            canonical_digest(&prepared_destination.authorities).map_err(debug)?;
        let bindings_digest = canonical_digest(&prepared_destination.bindings).map_err(debug)?;
        let mapping = JointMappingManifest {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            key,
            visa_operation_cohort_digest: canonical_digest(
                &source.coordinator().state().operations,
            )
            .map_err(debug)?,
            effect_scope: EffectScopeVersion {
                registry_instance: fixture.effect_config.registry_instance,
                scope_id: fixture.effect_config.scope_id,
                scope_generation: fixture.effect_config.scope_generation,
                authority_epoch: fixture.effect_config.authority_epoch,
                freeze_generation: fixture.effect_config.freeze_generation,
            },
            effect_cohort_digest: frozen.receipt.effect_cohort_digest,
            domain_bindings_manifest_digest: fixture.effect_config.domain_bindings_digest,
            ownership_service: OwnershipVersion {
                service_id: fixture.effect_config.ownership_issuer.issuer,
                service_incarnation: fixture.effect_config.ownership_issuer.issuer_incarnation,
                log_sequence: ownership_intent.header.sequence,
            },
            protocol_revision: 1,
        };
        let destination_prepared = DestinationPreparedReceipt {
            header: admission_header(
                issuers.visa_destination,
                ReceiptKind::DestinationPrepared,
                1,
                None,
            ),
            key,
            intent: intent_ref,
            visa_freeze: visa_freeze_ref,
            nexus_freeze: nexus_freeze_ref,
            snapshot: SnapshotBinding {
                snapshot: snapshot.body.snapshot.snapshot,
                integrity: snapshot.integrity,
                body_digest: canonical_digest(&snapshot.body).map_err(debug)?,
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
            lease_commit_operation: destination_commit_operation,
            lease_commit_idempotency: destination_commit_idempotency,
            lease_commit_request_digest: destination_commit_request_digest,
        };
        record_admission_receipt(
            &mut joint,
            &destination_prepared,
            derived_identity(run, b"record-destination-prepared")?,
            &authenticator,
            &mut receipt_material,
            None,
        )?;
        let destination_prepared_ref = destination_prepared.receipt_ref().map_err(debug)?;

        let sealed_bindings = PreparedBindings {
            prepare_intent_receipt_digest: intent_ref.digest,
            visa_freeze_receipt_digest: visa_freeze_ref.digest,
            effect_freeze_receipt_digest: nexus_freeze_ref.digest,
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
        let seal_request = OwnershipSealRequest {
            key,
            reservation: ownership_intent.reservation,
            intent: intent_ref,
            visa_freeze: visa_freeze_ref,
            effect_freeze: nexus_freeze_ref,
            destination_prepared: destination_prepared_ref,
            bindings: sealed_bindings,
            expected_state_sequence: 1,
        };
        let seal_invocation = joint_bytes(&seal_request).map_err(debug)?;
        let ownership_prepared = ownership.seal(seal_request).map_err(debug)?;
        record_admission_receipt(
            &mut joint,
            &ownership_prepared,
            derived_identity(run, b"record-ownership-prepared")?,
            &authenticator,
            &mut receipt_material,
            Some(seal_invocation),
        )?;

        let commit_request = OwnershipCommitRequest {
            key,
            reservation: ownership_intent.reservation,
            prepared: ownership_prepared.receipt_ref().map_err(debug)?,
            expected_state_sequence: 2,
        };
        let commit_invocation = joint_bytes(&commit_request).map_err(debug)?;
        ownership.arm_next_commit_ack_loss().map_err(debug)?;
        if ownership.commit(commit_request) != Err(OwnershipLogError::AcknowledgementLost) {
            return Err(
                "armed ownership Commit did not lose its ACK after the durable write".to_owned()
            );
        }
        drop(ownership);
        let mut ownership =
            ReferenceOwnershipLog::open(&fixture.paths.ownership, ownership_namespace)
                .map_err(debug)?;
        let Some(OwnershipQuery::CommitDecided(queried_commit)) =
            ownership.query(key.handoff).map_err(debug)?
        else {
            return Err("reopened ownership log did not recover CommitDecided".to_owned());
        };
        let retried_commit = ownership.commit(commit_request).map_err(debug)?;
        if retried_commit != queried_commit {
            return Err("exact ownership Commit retry changed the durable decision".to_owned());
        }
        let unit = ownership
            .query_unit(key.continuity_unit)
            .map_err(debug)?
            .ok_or("ownership unit disappeared after Commit")?;
        if unit.owner != key.destination
            || unit.epoch != key.next_epoch
            || unit.active_handoff.is_some()
            || unit.active_reservation.is_some()
        {
            return Err("ownership unit did not advance to the destination epoch".to_owned());
        }
        drop(ownership);
        record_admission_receipt(
            &mut joint,
            &queried_commit,
            derived_identity(run, b"record-ownership-commit")?,
            &authenticator,
            &mut receipt_material,
            Some(commit_invocation),
        )?;

        let closure = close_admission_nexus_cohort(
            &process_peer,
            &mut joint,
            &authenticator,
            &mut receipt_material,
            run,
            &frozen,
            &queried_commit,
        )?;
        let terminal = process_peer.query().map_err(debug)?;
        if terminal.gate_open
            || terminal.effect_count != 1
            || terminal.latest_close != Some(EffectCloseResult::Closed(closure.clone()))
        {
            return Err("Nexus terminal query did not retain the exact closed cohort".to_owned());
        }
        process_peer.shutdown().map_err(debug)?;
        let native_chain = process_peer.native_transcript().map_err(debug)?;
        validate_native_jsonl_chain(&native_chain).map_err(debug)?;
        if native_command_count(&native_chain, |command| {
            matches!(command, PeerCommand::Complete(_))
        })? != 0
            || native_command_count(&native_chain, |command| {
                matches!(command, PeerCommand::AcknowledgePublication(_))
            })? != 1
        {
            return Err(
                "Nexus close did not use exactly one Publication ACK without native Complete"
                    .to_owned(),
            );
        }

        let sequence = [
            "preview",
            "nexus-register",
            "nexus-prepare",
            "nexus-commit-ack-lost",
            "nexus-commit-recovered",
            "source-start",
            "nexus-outcome-recorded",
            "ownership-reserved",
            "visa-frozen",
            "destination-locally-prepared",
            "nexus-frozen",
            "ownership-sealed",
            "ownership-commit-ack-lost",
            "ownership-commit-recovered",
            "nexus-closed",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let source = source.into_coordinator();
        let destination = AdmissionDestinationRuntime::new(destination, portable);
        let source_truth = audit_logical_provider_truth(
            &fixture.paths.source,
            prepared_start.effect_request().operation,
            fixture.ids.logical_operation,
        )?;
        let source_ledger = source_truth
            .ledger
            .as_ref()
            .ok_or("source logical-request ledger is absent after UnknownCompletion")?;
        if source_truth.provider_row_count != 1
            || source_truth.provider_outcome_count != 1
            || source_truth.exact_effect_mapping_count != 1
            || source_ledger.revision != 3
            || !source_ledger.request_retained
            || source_ledger.phase != "unknown_completion"
        {
            return Err("source SQLite did not retain the exact UnknownCompletion truth".to_owned());
        }

        Ok(Self {
            fixture,
            source,
            destination: Some(destination),
            destination_adapter: None,
            logical_peer,
            process_identity,
            prepared_start,
            registration,
            final_publication,
            registered,
            prepared,
            committed,
            outcome_recorded,
            commit_ack_loss,
            source_outcome,
            source_logical_state,
            source_start_state,
            source_start_journal_position,
            source_start_state_digest,
            snapshot,
            visa_freeze,
            frozen,
            destination_prepared_state,
            destination_prepared,
            source_fence: None,
            destination_activation: None,
            ownership_intent,
            ownership_prepared,
            ownership_commit: queried_commit.clone(),
            ownership_commit_request: commit_request,
            ownership_retried_commit: retried_commit,
            ownership_journal_mode: journal_mode,
            ownership_synchronous: synchronous,
            closure,
            ownership_commit_ack_lost_after_durable_write: true,
            ownership_reopened_query_exact: true,
            ownership_exact_retry: true,
            destination_guest_restored_before_activation_receipt: false,
            destination_release_blocked_before_completion: false,
            source_start_provider_row_present: true,
            source_start_effect_mapping_present: true,
            source_ledger_revision: source_ledger.revision,
            source_ledger_retained_request: source_ledger.request_retained,
            destination_source_start_absent_before_reconcile: false,
            destination_logical_ledger_absent_before_reconcile: false,
            destination_portable_source_operation_present_before_reconcile: false,
            destination_reconcile_effect: None,
            destination_reconcile_provider_row_present: false,
            destination_ledger_revision: 0,
            destination_ledger_retained_request: false,
            destination_logical_state: None,
            destination_activation_state: None,
            destination_commit_operation,
            destination_commit_idempotency,
            destination_resume_command,
            receipt_material,
            native_chain,
            sequence,
            authenticator,
            joint,
        })
    }

    fn complete(mut self) -> Result<Self, String> {
        let run = self.fixture.run_identity;
        let key = self.fixture.key;
        let commit_ref = self.ownership_commit.receipt_ref().map_err(debug)?;
        let closure_ref = self.closure.receipt_ref().map_err(debug)?;
        let visa_freeze_ref = self.visa_freeze.receipt_ref().map_err(debug)?;

        let source_fence_header = admission_header(
            self.authenticator.issuers.visa_source,
            ReceiptKind::VisaSourceFence,
            2,
            Some(visa_freeze_ref.digest),
        );
        let source_fence_template = VisaSourceFenceReceipt {
            header: source_fence_header,
            key,
            commit: commit_ref,
            closure: closure_ref,
            journal_position: JournalPosition::ORIGIN,
            state_digest: Digest::ZERO,
        };
        let source_completion_command = derived_identity(run, b"record-visa-source-fence")?;
        let source_completion_digest =
            ReceiptRequest::for_receipt(source_completion_command, &source_fence_template)
                .digest()
                .map_err(debug)?;
        let source_attempt = SourceFenceAttempt::new(
            self.joint.state().state().revision,
            commit_ref,
            closure_ref,
            derived_identity(run, b"source-fence-command")?,
            derived_identity(run, b"source-fence-operation")?,
            self.source.state_digest().map_err(debug)?,
            self.source.journal_position(),
            source_completion_digest,
        )
        .map_err(debug)?;
        let source_projection = DurableProjectionDriver::new(&mut self.joint)
            .project_source_fence(&mut self.source, source_attempt)
            .map_err(|error| format!("durable source-fence projection failed: {error:?}"))?
            .local;
        let source_fence = VisaSourceFenceReceipt {
            header: source_fence_header,
            key,
            commit: commit_ref,
            closure: closure_ref,
            journal_position: source_projection.journal_position,
            state_digest: source_projection.state_digest,
        };
        let (request, envelope, payload, material) =
            encode_receipt_material(&source_fence, source_completion_command, &self.authenticator)?;
        DurableProjectionDriver::new(&mut self.joint)
            .record_completion(source_completion_command, &request, &envelope, &payload)
            .map_err(debug)?;
        self.receipt_material.push(material);
        if self.joint.replay_source_fence_attempt().is_some()
            || self.source.state().phase != HandoffPhase::Committed
            || self.source.state().activation.role != ActivationRole::Source
            || self.source.state().activation.status != ActivationStatus::Fenced
            || self.source.state().ownership.owner != Some(key.destination)
            || self.source.state().ownership.epoch != key.next_epoch
            || self.source.journal_position() != source_projection.journal_position
            || self.source.state_digest().map_err(debug)? != source_projection.state_digest
        {
            return Err(
                "durable source fence did not reach exact Committed/Fenced state".to_owned()
            );
        }
        self.source_fence = Some(source_fence.clone());
        self.sequence.push("source-fenced".to_owned());

        let source_fence_ref = source_fence.receipt_ref().map_err(debug)?;
        let destination = self.destination.take().ok_or("destination runtime is absent")?;
        let destination_binding = destination.joint_runtime_binding().map_err(debug)?;
        let destination_request_digest = destination
            .destination_commit_request_digest(
                self.destination_commit_operation,
                self.destination_commit_idempotency,
                self.destination_resume_command,
            )
            .map_err(debug)?;
        if destination_request_digest != self.destination_prepared.lease_commit_request_digest {
            return Err(
                "destination lease-commit request digest drifted before activation".to_owned()
            );
        }
        let activation_attempt = DestinationActivationAttempt::new(
            self.joint.state().state().revision,
            commit_ref,
            closure_ref,
            source_fence_ref,
            derived_identity(run, b"destination-activation-command")?,
            derived_identity(run, b"destination-lease-commit-command")?,
            self.destination_commit_operation,
            self.destination_commit_idempotency,
            destination_request_digest,
            self.destination_resume_command,
            destination_binding.state_digest,
            destination_binding.journal_position,
        )
        .map_err(debug)?;
        let destination_completion_command =
            derived_identity(run, b"record-visa-destination-activation")?;
        let destination_activation_header = admission_header(
            self.authenticator.issuers.visa_destination,
            ReceiptKind::VisaDestinationActivation,
            2,
            Some(self.destination_prepared.receipt_ref().map_err(debug)?.digest),
        );
        let mut guard = DurableDestinationGuard::new(&mut self.joint, destination);
        let destination_projection = guard
            .project(activation_attempt)
            .map_err(|error| format!("guarded destination projection failed: {error:?}"))?
            .local;
        let activation_attempt_record_digest =
            destination_projection
                .authorization_record_digest
                .ok_or("guarded destination projection omitted its durable attempt digest")?;
        self.destination_guest_restored_before_activation_receipt = true;
        if !matches!(guard.check_release(), Err(DurableProjectionError::CompletionPending)) {
            return Err("destination guard released before its completion receipt".to_owned());
        }
        self.destination_release_blocked_before_completion = true;
        let destination_activation = VisaDestinationActivationReceipt {
            header: destination_activation_header,
            key,
            commit: commit_ref,
            closure: closure_ref,
            source_fence: source_fence_ref,
            activation_command: activation_attempt.joint_command,
            resume_command: activation_attempt.resume_command,
            activation_attempt_record_digest,
            journal_position: destination_projection.journal_position,
            state_digest: destination_projection.state_digest,
        };
        let (request, envelope, payload, material) = encode_receipt_material(
            &destination_activation,
            destination_completion_command,
            &self.authenticator,
        )?;
        guard
            .record_completion(destination_completion_command, &request, &envelope, &payload)
            .map_err(|error| format!("record destination activation completion: {error:?}"))?;
        self.receipt_material.push(material);
        let destination = guard
            .release()
            .map_err(|error| format!("release completed destination guard: {error:?}"))?;
        let mut destination = destination.into_adapter().map_err(debug)?;
        if destination.coordinator().state().phase != HandoffPhase::Running
            || destination.coordinator().state().activation.role != ActivationRole::Destination
            || destination.coordinator().state().activation.status != ActivationStatus::Active
            || self.joint.state().state().phase != joint_handoff_core::JointPhase::DestinationActive
        {
            return Err("destination did not reach receipt-authorized Running/Active".to_owned());
        }
        self.destination_activation_state = Some(destination.coordinator().state().clone());
        self.destination_activation = Some(destination_activation);
        self.sequence.push("destination-guest-restored".to_owned());
        self.sequence.push("destination-activated".to_owned());

        let source_start_effect = self.prepared_start.effect_request().operation;
        let portable_source_operation_present =
            destination.coordinator().state().operations.iter().any(|record| {
                record.request == *self.prepared_start.effect_request()
                    && record.outcome.as_ref() == Some(&self.source_outcome)
            });
        let destination_before = audit_logical_provider_truth(
            &self.fixture.paths.destination,
            source_start_effect,
            self.fixture.ids.logical_operation,
        )?;
        if destination_before.provider_row_count != 0
            || destination_before.provider_outcome_count != 0
            || destination_before.exact_effect_mapping_count != 0
            || destination_before.ledger.is_some()
            || !portable_source_operation_present
        {
            return Err(
                "destination copied source provider truth or lost the portable source operation"
                    .to_owned(),
            );
        }
        self.destination_source_start_absent_before_reconcile = true;
        self.destination_logical_ledger_absent_before_reconcile = true;
        self.destination_portable_source_operation_present_before_reconcile = true;

        let reconciled = destination.reconcile().map_err(debug)?;
        let LogicalRequestResult::Reconciled { observation } = &reconciled.result else {
            return Err("destination reconcile returned the wrong logical result".to_owned());
        };
        if observation.phase != LogicalRequestPhase::Completed {
            return Err("destination reconcile did not observe Completed".to_owned());
        }
        let destination_logical_state =
            canonical_logical_request(destination.coordinator().state())?;
        let reconcile_effect = destination_logical_state
            .last_operation
            .ok_or("destination reconcile omitted its effect identity")?;
        if reconcile_effect == source_start_effect
            || destination_logical_state.operation_id != self.fixture.ids.logical_operation
            || destination_logical_state.phase != LogicalRequestPhase::Completed
        {
            return Err(
                "destination reconcile did not create a distinct Completed effect".to_owned()
            );
        }
        let destination_after = audit_logical_provider_truth(
            &self.fixture.paths.destination,
            reconcile_effect,
            self.fixture.ids.logical_operation,
        )?;
        let destination_ledger = destination_after
            .ledger
            .as_ref()
            .ok_or("destination reconcile did not create its logical ledger")?;
        if destination_after.provider_row_count != 1
            || destination_after.provider_outcome_count != 1
            || destination_after.exact_effect_mapping_count != 1
            || destination_ledger.revision != 2
            || destination_ledger.request_retained
            || destination_ledger.phase != "completed"
            || self.logical_peer.request_count() != 2
            || self.logical_peer.execution_count() != 1
        {
            return Err("destination reconcile did not preserve one remote execution".to_owned());
        }
        self.destination_reconcile_effect = Some(reconcile_effect);
        self.destination_reconcile_provider_row_present = true;
        self.destination_ledger_revision = destination_ledger.revision;
        self.destination_ledger_retained_request = destination_ledger.request_retained;
        self.destination_logical_state = Some(destination_logical_state);
        self.destination_adapter = Some(destination);
        self.sequence.push("destination-reconciled".to_owned());
        Ok(self)
    }

    fn into_report(self) -> Result<LogicalRequestAdmissionReport, String> {
        let destination =
            self.destination_adapter.as_ref().ok_or("terminal destination adapter is absent")?;
        let source_fence = self.source_fence.clone().ok_or("source fence receipt is absent")?;
        let destination_activation = self
            .destination_activation
            .clone()
            .ok_or("destination activation receipt is absent")?;
        let destination_logical_state = self
            .destination_logical_state
            .clone()
            .ok_or("terminal destination logical state is absent")?;
        let destination_activation_state = self
            .destination_activation_state
            .clone()
            .ok_or("destination activation state is absent")?;
        let reconcile_effect =
            self.destination_reconcile_effect.ok_or("destination reconcile effect is absent")?;
        let verified = self
            .committed
            .verified_commit()
            .ok_or("terminal report cannot recover verified Nexus Commit")?;
        let verified_commit = AdmissionVerifiedCommitEvidence {
            client_effect: verified.client_effect(),
            native_effect_id: verified.native_effect_id(),
            native_effect_generation: verified.native_effect_generation(),
            binding_epoch: verified.binding_epoch(),
            commit_sequence: verified.commit_sequence(),
            result: verified.result(),
            domain_revision: verified.domain_revision(),
            registry_replay: verified.registry_replay(),
        };
        let joint_projection = admission_joint_projection(self.joint.log())?;
        let native_complete_count = native_command_count(&self.native_chain, |command| {
            matches!(command, PeerCommand::Complete(_))
        })?;
        let sequence = AdmissionSequenceEvidence {
            steps: self.sequence.clone(),
            external_requests_before_nexus_commit: 0,
            external_executions_before_nexus_commit: 0,
            external_executions_after_source_start: 1,
            external_executions_after_destination_reconcile: self.logical_peer.execution_count(),
        };
        let source = AdmissionSourceEvidence {
            logical_operation: self.fixture.ids.logical_operation,
            preview: self.prepared_start.effect_request().clone(),
            source_start_outcome: self.source_outcome.clone(),
            source_start_state: self.source_start_state.clone(),
            source_start_phase: "unknown_completion".to_owned(),
            source_start_effect: self.prepared_start.effect_request().operation,
            source_journal_position: self.source_start_journal_position,
            source_state_digest: self.source_start_state_digest,
            source_ledger_revision: self.source_ledger_revision,
            source_ledger_retained_request: self.source_ledger_retained_request,
            source_start_provider_row_present: self.source_start_provider_row_present,
            source_start_effect_mapping_present: self.source_start_effect_mapping_present,
        };
        let nexus = AdmissionNexusEvidence {
            process: self.process_identity.clone(),
            registration: self.registration.clone(),
            final_publication: self.final_publication.clone(),
            register: staged_advance_evidence(&self.registered),
            prepare: staged_advance_evidence(&self.prepared),
            commit: staged_advance_evidence(&self.committed),
            outcome: staged_advance_evidence(&self.outcome_recorded),
            verified_commit,
            commit_metadata_result: verified.result(),
            commit_metadata_meaning: "logical-request-send-admitted".to_owned(),
            commit_domain_revision: verified.domain_revision(),
            commit_ack_loss: self.commit_ack_loss.clone(),
            freeze: self.frozen.receipt.clone(),
            frozen_counts: self.frozen.receipt.counts,
            closure: self.closure.clone(),
            native_complete_count,
            native_chain: self.native_chain.clone(),
        };
        let ownership = AdmissionOwnershipEvidence {
            intent: self.ownership_intent.clone(),
            prepared: self.ownership_prepared.clone(),
            commit: self.ownership_commit.clone(),
            commit_request: self.ownership_commit_request,
            queried_commit: self.ownership_commit.clone(),
            retried_commit: self.ownership_retried_commit.clone(),
            journal_mode: self.ownership_journal_mode.clone(),
            synchronous: self.ownership_synchronous,
            acknowledgement_error: "acknowledgement_lost".to_owned(),
            commit_ack_lost_after_durable_write: self.ownership_commit_ack_lost_after_durable_write,
            reopened_query_exact: self.ownership_reopened_query_exact,
            exact_retry: self.ownership_exact_retry,
        };
        let runtime = AdmissionRuntimeEvidence {
            issuer_set: self.authenticator.issuers,
            authentication_secret: self.authenticator.secret,
            snapshot: self.snapshot.clone(),
            visa_freeze: self.visa_freeze.clone(),
            destination_prepared: self.destination_prepared.clone(),
            source_fence,
            destination_activation,
            destination_guest_restored_before_activation_receipt: self
                .destination_guest_restored_before_activation_receipt,
            destination_release_blocked_before_completion: self
                .destination_release_blocked_before_completion,
            source_terminal_state: self.source.state().clone(),
            destination_prepared_state: self.destination_prepared_state.clone(),
            destination_activation_state,
            destination_terminal_state: destination.coordinator().state().clone(),
            receipt_material: self.receipt_material.clone(),
            joint_projection,
        };
        let destination_evidence = AdmissionDestinationEvidence {
            source_start_absent_before_reconcile: self
                .destination_source_start_absent_before_reconcile,
            logical_ledger_absent_before_reconcile: self
                .destination_logical_ledger_absent_before_reconcile,
            portable_source_operation_present_before_reconcile: self
                .destination_portable_source_operation_present_before_reconcile,
            reconcile_effect,
            reconcile_effect_differs_from_source_start: reconcile_effect
                != self.prepared_start.effect_request().operation,
            reconcile_provider_row_present: self.destination_reconcile_provider_row_present,
            destination_ledger_revision: self.destination_ledger_revision,
            destination_ledger_retained_request: self.destination_ledger_retained_request,
            terminal_phase: logical_phase_name(destination_logical_state.phase).to_owned(),
            remote_request_count: self.logical_peer.request_count(),
            remote_execution_count: self.logical_peer.execution_count(),
        };
        let paths = self.fixture.paths.clone();
        let expectations = LogicalRequestAdmissionExpectations {
            run_identity: self.fixture.run_identity,
            nexus_process: self.process_identity.clone(),
        };
        let run_identity = expectations.run_identity;
        drop(self);

        let databases = finalize_and_audit_databases(&paths)?;
        let report = LogicalRequestAdmissionReport {
            schema: LOGICAL_REQUEST_ADMISSION_SCHEMA.to_owned(),
            all_passed: true,
            run_identity,
            claims: LogicalRequestAdmissionClaims::bounded(),
            sequence,
            source,
            nexus,
            ownership,
            runtime,
            destination: destination_evidence,
            databases,
            limitations: ADMISSION_LIMITATIONS.map(str::to_owned).to_vec(),
        };
        if report.runtime.snapshot.body.component_digest != admission_component::digest() {
            return Err("admission report did not bind the component bytes executed by this cell"
                .to_owned());
        }
        crate::validate_logical_request_admission_report(&report, &expectations)?;
        let report_bytes = serde_json::to_vec_pretty(&report).map_err(debug)?;
        let decoded: LogicalRequestAdmissionReport =
            serde_json::from_slice(&report_bytes).map_err(debug)?;
        if decoded != report {
            return Err("terminal admission report did not round-trip exactly".to_owned());
        }
        publish_new_regular_file(&paths.report, &report_bytes)?;
        Ok(report)
    }
}

fn close_admission_nexus_cohort(
    peer: &ProcessEffectPeer,
    joint: &mut AdmissionJointSession,
    authenticator: &AdmissionAuthenticator,
    materials: &mut Vec<AdmissionReceiptMaterial>,
    run: Identity,
    frozen: &EffectFreezeResult,
    commit: &OwnershipCommitReceipt,
) -> Result<ClosureReceipt, String> {
    let mut revision = 0_u64;
    for step in 1_u64..=16 {
        let request = EffectCloseRequest {
            token: frozen.token,
            commit: commit.clone(),
            expected_closure_revision: revision,
        };
        let invocation = joint_bytes(&request).map_err(debug)?;
        let result = peer
            .close(request)
            .map_err(|error| format!("close admission Nexus cohort step {step}: {error:?}"))?;
        revision = result.closure_revision();
        let command = derived_identity(run, format!("record-nexus-close-{step}").as_bytes())?;
        match result {
            EffectCloseResult::Progress(progress) => {
                record_admission_receipt(
                    joint,
                    &progress,
                    command,
                    authenticator,
                    materials,
                    Some(invocation),
                )?;
            }
            EffectCloseResult::Closed(closure) => {
                record_admission_receipt(
                    joint,
                    &closure,
                    command,
                    authenticator,
                    materials,
                    Some(invocation),
                )?;
                return Ok(closure);
            }
            EffectCloseResult::RetainedTombstone(_) => {
                return Err("bounded admission cell unexpectedly retained a tombstone".to_owned());
            }
        }
    }
    Err("Nexus cohort did not close within 16 revisioned steps".to_owned())
}

fn record_admission_receipt<T>(
    joint: &mut AdmissionJointSession,
    receipt: &T,
    command: Identity,
    authenticator: &AdmissionAuthenticator,
    materials: &mut Vec<AdmissionReceiptMaterial>,
    peer_invocation: Option<Vec<u8>>,
) -> Result<(), String>
where
    T: VerifiedCommandReceipt + Serialize,
{
    if peer_invocation.as_ref().is_some_and(Vec::is_empty) {
        return Err("admission peer invocation bytes are empty".to_owned());
    }
    let (request, envelope, payload, mut material) =
        encode_receipt_material(receipt, command, authenticator)?;
    joint.record_native_receipt(command, &request, &envelope, &payload).map_err(debug)?;
    material.peer_invocation = peer_invocation;
    materials.push(material);
    Ok(())
}

fn admission_header(
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

fn staged_advance_evidence(advance: &ProcessLiveEffectAdvance) -> AdmissionStagedAdvanceEvidence {
    AdmissionStagedAdvanceEvidence {
        phase: process_phase_name(advance.phase()).to_owned(),
        advance: advance.advance(),
        replay: advance.is_replay(),
        native_effect_id: advance.native_effect_id(),
        native_effect_generation: advance.native_effect_generation(),
        native_sequence: advance.native_sequence(),
        native_request_sha256: advance.native_request_sha256().map(str::to_owned),
        native_receipt_sha256: advance.native_receipt_sha256().map(str::to_owned),
    }
}

const fn process_phase_name(phase: ProcessLiveEffectPhase) -> &'static str {
    match phase {
        ProcessLiveEffectPhase::Registered => "registered",
        ProcessLiveEffectPhase::Prepared => "prepared",
        ProcessLiveEffectPhase::CommittedAwaitingOutcome => "committed_awaiting_outcome",
        ProcessLiveEffectPhase::OutcomeRecorded => "outcome_recorded",
    }
}

const fn logical_phase_name(phase: LogicalRequestPhase) -> &'static str {
    match phase {
        LogicalRequestPhase::Ready => "ready",
        LogicalRequestPhase::Pending => "pending",
        LogicalRequestPhase::PartialResponse => "partial_response",
        LogicalRequestPhase::UnknownCompletion => "unknown_completion",
        LogicalRequestPhase::Reconciling => "reconciling",
        LogicalRequestPhase::Replaying => "replaying",
        LogicalRequestPhase::Cancelling => "cancelling",
        LogicalRequestPhase::Completed => "completed",
        LogicalRequestPhase::TimedOut => "timed_out",
        LogicalRequestPhase::Cancelled => "cancelled",
        LogicalRequestPhase::Rejected => "rejected",
    }
}

fn admission_joint_projection(
    log: &AdmissionJointLog,
) -> Result<AdmissionJointProjectionEvidence, String> {
    let head = log.head().map_err(debug)?.ok_or("joint projection head is absent")?;
    let mut canonical_record_bytes = Vec::new();
    for sequence in 1..=head.sequence {
        let record = log
            .read(sequence)
            .map_err(debug)?
            .ok_or_else(|| format!("joint projection record {sequence} is absent"))?;
        canonical_record_bytes.push(record.canonical_bytes().map_err(debug)?);
    }
    if log.head().map_err(debug)? != Some(head) {
        return Err("joint projection head changed while the report was built".to_owned());
    }
    Ok(AdmissionJointProjectionEvidence { head, canonical_record_bytes })
}

#[derive(Clone, Copy)]
struct DatabaseCheckpointEvidence {
    runtime_journal_mode: &'static str,
    busy: u32,
    log_frames: u32,
    checkpointed_frames: u32,
    archive_journal_mode: &'static str,
}

#[derive(Clone, Copy)]
struct DatabaseCheckpointSet {
    source: DatabaseCheckpointEvidence,
    destination: DatabaseCheckpointEvidence,
    ownership: DatabaseCheckpointEvidence,
    joint_projection: DatabaseCheckpointEvidence,
}

fn finalize_and_audit_databases(
    paths: &AdmissionDatabasePaths,
) -> Result<AdmissionDatabaseSetEvidence, String> {
    let checkpoints = DatabaseCheckpointSet {
        source: checkpoint_database(&paths.source)?,
        destination: checkpoint_database(&paths.destination)?,
        ownership: checkpoint_database(&paths.ownership)?,
        joint_projection: checkpoint_database(&paths.joint_projection)?,
    };
    let source = audit_database(&paths.source, 5, checkpoints.source)?;
    let destination = audit_database(&paths.destination, 5, checkpoints.destination)?;
    let ownership = audit_database(&paths.ownership, 2, checkpoints.ownership)?;
    let joint_projection =
        audit_database(&paths.joint_projection, 0, checkpoints.joint_projection)?;
    let databases = [&source, &destination, &ownership, &joint_projection];
    let all_device_inode_pairs_distinct = databases.iter().enumerate().all(|(index, left)| {
        databases
            .iter()
            .skip(index + 1)
            .all(|right| (left.device, left.inode) != (right.device, right.inode))
    });
    let source_destination_paths_distinct = paths.source != paths.destination;
    if !all_device_inode_pairs_distinct || !source_destination_paths_distinct {
        return Err("admission SQLite databases are not independent files".to_owned());
    }
    Ok(AdmissionDatabaseSetEvidence {
        source,
        destination,
        ownership,
        joint_projection,
        all_device_inode_pairs_distinct,
        source_destination_paths_distinct,
    })
}

fn checkpoint_database(path: &Path) -> Result<DatabaseCheckpointEvidence, String> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open SQLite checkpoint {}: {error}", path.display()))?;
    let runtime_journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| format!("read SQLite journal mode {}: {error}", path.display()))?;
    if !runtime_journal_mode.eq_ignore_ascii_case("wal") {
        return Err(format!(
            "SQLite did not retain runtime WAL mode: {} mode={runtime_journal_mode}",
            path.display()
        ));
    }
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| format!("checkpoint SQLite {}: {error}", path.display()))?;
    let archive_journal_mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|error| format!("seal SQLite journal mode {}: {error}", path.display()))?;
    if !archive_journal_mode.eq_ignore_ascii_case("delete") {
        return Err(format!(
            "SQLite did not enter single-file archive mode: {} mode={archive_journal_mode}",
            path.display()
        ));
    }
    drop(connection);
    let busy = u32::try_from(busy).map_err(|_| "negative SQLite checkpoint busy count")?;
    let log_frames = u32::try_from(log_frames).map_err(|_| "negative SQLite WAL frame count")?;
    let checkpointed_frames = u32::try_from(checkpointed_frames)
        .map_err(|_| "negative SQLite checkpointed frame count")?;
    if busy != 0 {
        return Err(format!("SQLite checkpoint remained busy: {}", path.display()));
    }
    Ok(DatabaseCheckpointEvidence {
        runtime_journal_mode: "wal",
        busy,
        log_frames,
        checkpointed_frames,
        archive_journal_mode: "delete",
    })
}

fn audit_database(
    path: &Path,
    expected_user_version: u32,
    checkpoint: DatabaseCheckpointEvidence,
) -> Result<AdmissionDatabaseEvidence, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path).map_err(debug)?;
    let regular_file = metadata.file_type().is_file();
    let symlink = metadata.file_type().is_symlink();
    let hard_link_count = metadata.nlink();
    if !regular_file || symlink || hard_link_count != 1 {
        return Err(format!(
            "SQLite artifact is not one regular unlinked file: {}",
            path.display()
        ));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open finalized SQLite {}: {error}", path.display()))?;
    connection
        .execute_batch("PRAGMA query_only = ON;")
        .map_err(|error| format!("set finalized SQLite query_only {}: {error}", path.display()))?;
    let observed_archive_journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| format!("read finalized journal mode {}: {error}", path.display()))?;
    let user_version: i64 =
        connection.query_row("PRAGMA user_version", [], |row| row.get(0)).map_err(debug)?;
    let user_version = u32::try_from(user_version).map_err(|_| "negative SQLite user_version")?;
    let integrity_check: String =
        connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0)).map_err(debug)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| row.get(0))
        .map_err(debug)?;
    drop(connection);
    let foreign_key_violations = usize::try_from(foreign_key_violations)
        .map_err(|_| "negative SQLite foreign-key finding count")?;
    let sidecars_absent =
        sqlite_sidecars(path).iter().try_fold(true, |absent, sidecar| -> Result<bool, String> {
            Ok(absent && !path_entry_exists(sidecar)?)
        })?;
    if user_version != expected_user_version
        || integrity_check != "ok"
        || foreign_key_violations != 0
        || checkpoint.busy != 0
        || checkpoint.log_frames != checkpoint.checkpointed_frames
        || checkpoint.runtime_journal_mode != "wal"
        || checkpoint.archive_journal_mode != "delete"
        || !observed_archive_journal_mode.eq_ignore_ascii_case("delete")
        || !sidecars_absent
    {
        return Err(format!(
            "finalized SQLite audit failed: {} user_version={user_version} expected={expected_user_version} integrity={integrity_check:?} foreign_keys={foreign_key_violations} runtime_mode={} checkpoint_busy={} checkpoint_frames={}/{} archive_mode={} observed_archive_mode={} sidecars_absent={sidecars_absent}",
            path.display(),
            checkpoint.runtime_journal_mode,
            checkpoint.busy,
            checkpoint.log_frames,
            checkpoint.checkpointed_frames,
            checkpoint.archive_journal_mode,
            observed_archive_journal_mode,
        ));
    }
    let path_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("SQLite artifact name is not UTF-8")?
        .to_owned();
    Ok(AdmissionDatabaseEvidence {
        path: path_name,
        user_version,
        device: metadata.dev(),
        inode: metadata.ino(),
        hard_link_count,
        regular_file,
        symlink,
        integrity_check,
        foreign_key_violations,
        runtime_journal_mode: checkpoint.runtime_journal_mode.to_owned(),
        wal_checkpoint_busy: checkpoint.busy,
        wal_log_frames: checkpoint.log_frames,
        wal_checkpointed_frames: checkpoint.checkpointed_frames,
        archive_journal_mode: checkpoint.archive_journal_mode.to_owned(),
        sidecars_absent,
    })
}

fn sqlite_sidecars(path: &Path) -> [PathBuf; 3] {
    let sidecar = |suffix: &str| {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    };
    [sidecar("-wal"), sidecar("-shm"), sidecar("-journal")]
}

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect filesystem entry {}: {error}", path.display())),
    }
}

fn publish_new_regular_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    publish_new_regular_file_with_checkpoint(path, bytes, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportPublicationCheckpoint {
    AfterWrite,
    AfterSync,
    BeforeFinalPathAudit,
}

fn publish_new_regular_file_with_checkpoint(
    path: &Path,
    bytes: &[u8],
    mut checkpoint: impl FnMut(ReportPublicationCheckpoint) -> Result<(), String>,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create terminal report {}: {error}", path.display()))?;
    let publication = (|| -> Result<(u64, u64), String> {
        file.write_all(bytes)
            .map_err(|error| format!("write terminal report {}: {error}", path.display()))?;
        checkpoint(ReportPublicationCheckpoint::AfterWrite)?;
        file.sync_all()
            .map_err(|error| format!("sync terminal report {}: {error}", path.display()))?;
        checkpoint(ReportPublicationCheckpoint::AfterSync)?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("stat terminal report {}: {error}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err("terminal report is not a singly-linked regular file".to_owned());
        }
        Ok((metadata.dev(), metadata.ino()))
    })();
    drop(file);
    let (device, inode) = match publication {
        Ok(identity) => identity,
        Err(error) => return cleanup_published_file(path, error),
    };
    if let Err(error) = checkpoint(ReportPublicationCheckpoint::BeforeFinalPathAudit) {
        return cleanup_published_file(path, error);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return cleanup_published_file(
                path,
                format!("stat published terminal report {}: {error}", path.display()),
            );
        }
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.dev() != device
        || metadata.ino() != inode
    {
        return cleanup_published_file(
            path,
            "published terminal report changed filesystem identity".to_owned(),
        );
    }
    Ok(())
}

fn cleanup_published_file(path: &Path, error: String) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Err(error),
        Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => Err(error),
        Err(cleanup) => {
            Err(format!("{error}; cleanup terminal report {} failed: {cleanup}", path.display()))
        }
    }
}

pub fn run_logical_request_admission_cell(
    root: impl AsRef<Path>,
    inputs: LogicalRequestAdmissionInputs,
) -> Result<LogicalRequestAdmissionReport, String> {
    let prefix = AdmissionPrefix::run(root.as_ref(), &inputs)?;
    AdmissionCommittedHandoff::run(prefix)?.complete()?.into_report()
}

fn publication(fixture: &AdmissionFixture, record: JointEffectRecord) -> EffectPublicationRequest {
    EffectPublicationRequest {
        key: fixture.key,
        registry_instance: fixture.effect_config.registry_instance,
        scope_id: fixture.effect_config.scope_id,
        scope_generation: fixture.effect_config.scope_generation,
        source_epoch: fixture.key.expected_epoch,
        record,
    }
}

fn require_advance(
    advance: &ProcessLiveEffectAdvance,
    phase: ProcessLiveEffectPhase,
    sequence: u64,
    replay: bool,
) -> Result<(), String> {
    if advance.phase() != phase
        || advance.advance() != sequence
        || advance.is_replay() != replay
        || advance.native_effect_id() == 0
        || advance.native_effect_generation() == 0
    {
        return Err(format!("staged admission advance {sequence} did not bind its phase"));
    }
    Ok(())
}

fn require_unknown_start_outcome(outcome: &EffectOutcome) -> Result<(), String> {
    let EffectOutcome::Succeeded { result: EffectResult::Profile { profile, payload }, .. } =
        outcome
    else {
        return Err("source UnknownCompletion was not a successful profile observation".to_owned());
    };
    if *profile != LOGICAL_REQUEST_EXTENSION_ID {
        return Err("source Start outcome used the wrong profile".to_owned());
    }
    let result = visa_profile::decode_logical_request_result(payload).map_err(debug)?;
    let LogicalRequestResult::Started { observation } = result else {
        return Err("source Start outcome used the wrong logical result variant".to_owned());
    };
    if observation.phase != LogicalRequestPhase::UnknownCompletion
        || observation.response.is_some()
        || observation.rejection.is_some()
    {
        return Err("source Start outcome did not honestly encode UnknownCompletion".to_owned());
    }
    Ok(())
}

fn canonical_logical_request(state: &CanonicalState) -> Result<LogicalRequestState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or("logical-request extension is absent")?;
    if matching.next().is_some() {
        return Err("logical-request extension is duplicated".to_owned());
    }
    logical_request_state(extension).map_err(debug)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalLedgerAudit {
    revision: u64,
    request_retained: bool,
    phase: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalProviderAudit {
    provider_row_count: usize,
    provider_outcome_count: usize,
    exact_effect_mapping_count: usize,
    ledger: Option<LogicalLedgerAudit>,
}

fn audit_logical_provider_truth(
    path: &Path,
    effect: Identity,
    logical_operation: Identity,
) -> Result<LogicalProviderAudit, String> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open live SQLite audit {}: {error}", path.display()))?;
    connection
        .execute_batch("PRAGMA query_only = ON;")
        .map_err(|error| format!("set SQLite query_only {}: {error}", path.display()))?;
    let provider_row_count = identity_count(
        &connection,
        "SELECT COUNT(*) FROM provider_operation WHERE operation = ?1",
        effect,
    )?;
    let provider_outcome_count = identity_count(
        &connection,
        "SELECT COUNT(*) FROM provider_operation WHERE operation = ?1 AND outcome IS NOT NULL",
        effect,
    )?;
    let exact_effect_mapping_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM logical_request_effect
             WHERE effect_operation = ?1 AND logical_operation = ?2",
            params![effect.0.as_slice(), logical_operation.0.as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| format!("query logical effect mapping {}: {error}", path.display()))?;
    let ledger_bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record FROM logical_request_ledger WHERE operation_id = ?1",
            params![logical_operation.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("query logical ledger {}: {error}", path.display()))?;
    let ledger = ledger_bytes.map(|bytes| decode_logical_ledger_audit(&bytes)).transpose()?;
    Ok(LogicalProviderAudit {
        provider_row_count,
        provider_outcome_count,
        exact_effect_mapping_count: usize::try_from(exact_effect_mapping_count)
            .map_err(|_| "negative logical effect mapping count".to_owned())?,
        ledger,
    })
}

fn identity_count(connection: &Connection, sql: &str, identity: Identity) -> Result<usize, String> {
    let count: i64 = connection
        .query_row(sql, params![identity.0.as_slice()], |row| row.get(0))
        .map_err(|error| format!("query SQLite identity count: {error}"))?;
    usize::try_from(count).map_err(|_| "negative SQLite identity count".to_owned())
}

fn decode_logical_ledger_audit(bytes: &[u8]) -> Result<LogicalLedgerAudit, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("decode logical-request ledger JSON: {error}"))?;
    let revision = value
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or("logical-request ledger revision is absent")?;
    let request_retained =
        !value.get("request").ok_or("logical-request ledger request field is absent")?.is_null();
    let phase = value
        .get("phase")
        .and_then(serde_json::Value::as_str)
        .ok_or("logical-request ledger phase is absent")?
        .to_owned();
    Ok(LogicalLedgerAudit { revision, request_retained, phase })
}

fn native_command_count(
    chain: &[NativeJsonlExchange],
    predicate: impl Fn(&PeerCommand) -> bool,
) -> Result<usize, String> {
    chain.iter().try_fold(0_usize, |count, exchange| {
        let request: PeerRequest =
            serde_json::from_str(exchange.request_jsonl.trim()).map_err(debug)?;
        Ok(count + usize::from(predicate(&request.command)))
    })
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

fn derived_issuer(run: Identity, label: &[u8]) -> Result<ReceiptIssuerIdentity, String> {
    Ok(ReceiptIssuerIdentity {
        issuer: derived_identity(run, &[label, b"-issuer"].concat())?,
        issuer_incarnation: derived_identity(run, &[label, b"-incarnation"].concat())?,
        key_id: derived_identity(run, &[label, b"-key"].concat())?,
        log_id: derived_identity(run, &[label, b"-log"].concat())?,
    })
}

pub(crate) fn expected_admission_authenticator(
    run: Identity,
    key: joint_handoff_core::JointHandoffKey,
) -> Result<AdmissionAuthenticator, String> {
    let ownership_namespace = derived_issuer(run, b"ownership")?;
    let effect_namespace = derived_issuer(run, b"effect")?;
    Ok(AdmissionAuthenticator {
        key,
        issuers: JointIssuerSet {
            ownership: ownership_receipt_issuer(ownership_namespace, key).map_err(debug)?,
            visa_source: derived_issuer(run, b"visa-source")?,
            visa_destination: derived_issuer(run, b"visa-destination")?,
            effect_closure: effect_receipt_issuer(effect_namespace, key).map_err(debug)?,
        },
        secret: derived_digest(run, b"receipt-authentication-secret")?.0,
    })
}

pub(crate) fn admission_identity(run: Identity, label: &[u8]) -> Result<Identity, String> {
    derived_identity(run, label)
}

pub(crate) fn admission_digest(run: Identity, label: &[u8]) -> Result<Digest, String> {
    derived_digest(run, label)
}

fn derived_entity(run: Identity, label: &[u8]) -> Result<EntityRef, String> {
    derived_identity(run, label).map(EntityRef::initial)
}

fn derived_identity(run: Identity, label: &[u8]) -> Result<Identity, String> {
    let digest = derived_digest(run, label)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(bytes);
    if identity.is_zero() {
        return Err("derived admission identity is zero".to_owned());
    }
    Ok(identity)
}

fn derived_digest(run: Identity, label: &[u8]) -> Result<Digest, String> {
    let mut digest = Sha256::new();
    digest.update(ADMISSION_ID_DOMAIN);
    digest.update(run.0);
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label);
    let value = Digest::from_bytes(digest.finalize().into());
    if value == Digest::ZERO {
        return Err("derived admission digest is zero".to_owned());
    }
    Ok(value)
}

const fn timer_rights() -> Rights {
    Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
}

const fn key_value_rights() -> Rights {
    Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
}

const fn profile_rights() -> Rights {
    Rights::PROFILE_READ
        .union(Rights::PROFILE_WRITE)
        .union(Rights::PROFILE_CONTROL)
        .union(Rights::REBIND)
}

fn debug(error: impl fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::state_digest;
    use substrate_api::{EffectClosureProvider, EffectDispatchAcquireError, EffectDispatchOutcome};
    use visa_profile::LogicalRequestOperation;
    use visa_wasmtime::{LogicalRequestFailure, LogicalRequestWorkloadFailure};

    use super::*;
    use crate::{
        ReferenceEffectCommitEvidence, ReferenceEffectCommitMetadata,
        ReferenceEffectCompletionEvidence, ReferenceEffectCompletionRequest,
        ReferenceEffectDispatchFence, ReferenceEffectOutcomeEvidence, ReferenceEffectPeer,
        ReferenceEffectQueryObservation, ReferencePreparedEffect, ReferenceRegisteredEffect,
        nexus_effect_wire::{
            AUTHENTICATION_BOUNDARY, NativeHandoffStatus, NativeReceipt, NativeReceiptPayload,
            PeerRequest, PeerResponse, RECEIPT_SCHEMA, RESPONSE_SCHEMA, ReceiptDigestInput,
            ResponseStatus,
        },
        process_effect_peer::validate_native_jsonl_chain,
    };

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct FinishAckLossProvider {
        inner: ReferenceEffectPeer,
    }

    impl FinishAckLossProvider {
        fn new(config: EffectPeerConfig) -> Self {
            Self { inner: ReferenceEffectPeer::new_admission_required(config).unwrap() }
        }
    }

    impl EffectClosureProvider for FinishAckLossProvider {
        type RegistrationRequest = EffectAdmissionRegistration;
        type Registered = ReferenceRegisteredEffect;
        type Prepared = ReferencePreparedEffect;
        type CommitMetadata = ReferenceEffectCommitMetadata;
        type CommitEvidence = ReferenceEffectCommitEvidence;
        type DispatchFence = ReferenceEffectDispatchFence;
        type OutcomeEvidence = ReferenceEffectOutcomeEvidence;
        type CompletionRequest = ReferenceEffectCompletionRequest;
        type CompletionEvidence = ReferenceEffectCompletionEvidence;
        type QueryObservation = ReferenceEffectQueryObservation;
        type Error = EffectPeerError;

        fn descriptor(
            &self,
        ) -> Result<substrate_api::EffectClosureProviderDescriptor, Self::Error> {
            EffectClosureProvider::descriptor(&self.inner)
        }

        fn register_effect(
            &self,
            effect: &EffectRequest,
            request: &Self::RegistrationRequest,
        ) -> Result<Self::Registered, Self::Error> {
            EffectClosureProvider::register_effect(&self.inner, effect, request)
        }

        fn prepare_effect(
            &self,
            effect: &EffectRequest,
            registered: &Self::Registered,
        ) -> Result<Self::Prepared, Self::Error> {
            EffectClosureProvider::prepare_effect(&self.inner, effect, registered)
        }

        fn commit_effect(
            &self,
            effect: &EffectRequest,
            prepared: &Self::Prepared,
            metadata: &Self::CommitMetadata,
        ) -> Result<Self::CommitEvidence, Self::Error> {
            EffectClosureProvider::commit_effect(&self.inner, effect, prepared, metadata)
        }

        fn consume_committed_effect(
            &self,
            effect: &EffectRequest,
            evidence: &Self::CommitEvidence,
        ) -> Result<Self::DispatchFence, Self::Error> {
            EffectClosureProvider::consume_committed_effect(&self.inner, effect, evidence)
        }

        fn finish_effect_dispatch(
            &self,
            effect: &EffectRequest,
            fence: &Self::DispatchFence,
            outcome: EffectDispatchOutcome,
        ) -> Result<(), Self::Error> {
            EffectClosureProvider::finish_effect_dispatch(&self.inner, effect, fence, outcome)?;
            Err(EffectPeerError::AcknowledgementLost { request_id: 1 })
        }

        fn record_effect_outcome(
            &self,
            effect: &EffectRequest,
            committed: &Self::CommitEvidence,
            outcome: &EffectOutcome,
        ) -> Result<Self::OutcomeEvidence, Self::Error> {
            EffectClosureProvider::record_effect_outcome(&self.inner, effect, committed, outcome)
        }

        fn complete_effect(
            &self,
            effect: &EffectRequest,
            request: &Self::CompletionRequest,
        ) -> Result<Self::CompletionEvidence, Self::Error> {
            EffectClosureProvider::complete_effect(&self.inner, effect, request)
        }

        fn query_effect(
            &self,
            effect: &EffectRequest,
        ) -> Result<Option<Self::QueryObservation>, Self::Error> {
            EffectClosureProvider::query_effect(&self.inner, effect)
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-logical-request-admission-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create admission test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn reference_registration(
        fixture: &AdmissionFixture,
        prepared: &PreparedLogicalRequestStart,
    ) -> EffectPublicationRequest {
        publication(
            fixture,
            JointEffectRecord {
                effect: fixture.logical_request.operation_id,
                operation: prepared.effect_request().operation,
                domain: LOGICAL_REQUEST_EXTENSION_ID,
                binding_generation: fixture.effect_config.scope_generation,
                classification: JointEffectClassification::Registered,
                outcome_digest: None,
                tombstone_digest: None,
            },
        )
    }

    fn reference_permit<'a>(
        peer: &'a ReferenceEffectPeer,
        fixture: &AdmissionFixture,
        prepared: &PreparedLogicalRequestStart,
    ) -> substrate_api::CommittedEffectPermit<'a, ReferenceEffectPeer> {
        let registration = reference_registration(fixture, prepared);
        EffectAdmissionSession::new(peer)
            .register(
                prepared.effect_request().clone(),
                EffectAdmissionRegistration::new(prepared.effect_request(), registration).unwrap(),
            )
            .unwrap_or_else(|failure| panic!("register failed: {:?}", failure.error()))
            .prepare()
            .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()))
            .commit(ReferenceEffectCommitMetadata {
                result: 0,
                domain_revision: fixture.effect_config.scope_generation,
            })
            .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()))
    }

    fn finish_ack_loss_permit<'a>(
        peer: &'a FinishAckLossProvider,
        fixture: &AdmissionFixture,
        prepared: &PreparedLogicalRequestStart,
    ) -> substrate_api::CommittedEffectPermit<'a, FinishAckLossProvider> {
        let registration = reference_registration(fixture, prepared);
        EffectAdmissionSession::new(peer)
            .register(
                prepared.effect_request().clone(),
                EffectAdmissionRegistration::new(prepared.effect_request(), registration).unwrap(),
            )
            .unwrap_or_else(|failure| panic!("register failed: {:?}", failure.error()))
            .prepare()
            .unwrap_or_else(|failure| panic!("prepare failed: {:?}", failure.error()))
            .commit(ReferenceEffectCommitMetadata {
                result: 0,
                domain_revision: fixture.effect_config.scope_generation,
            })
            .unwrap_or_else(|failure| panic!("commit failed: {:?}", failure.error()))
    }

    fn rehashed_native_chain(
        chain: &[NativeJsonlExchange],
        mutate: impl FnOnce(&mut Vec<(PeerRequest, NativeReceiptPayload)>),
    ) -> Vec<NativeJsonlExchange> {
        let mut entries = chain
            .iter()
            .map(|exchange| {
                let request: PeerRequest =
                    serde_json::from_str(exchange.request_jsonl.trim_end()).unwrap();
                let response: PeerResponse =
                    serde_json::from_str(exchange.response_jsonl.trim_end()).unwrap();
                (request, response.receipt.unwrap().payload)
            })
            .collect::<Vec<_>>();
        mutate(&mut entries);

        let mut previous = None;
        let mut rebuilt = Vec::with_capacity(entries.len());
        for (index, (mut request, payload)) in entries.into_iter().enumerate() {
            let sequence = u64::try_from(index).unwrap() + 1;
            request.request_id = sequence;
            let request_bytes = serde_json::to_vec(&request).unwrap();
            let request_sha256 = test_sha256_hex(&request_bytes);
            let payload_sha256 = test_sha256_hex(&serde_json::to_vec(&payload).unwrap());
            let kind = payload.receipt_kind();
            let digest_input = ReceiptDigestInput {
                schema: RECEIPT_SCHEMA,
                sequence,
                kind,
                request_sha256: &request_sha256,
                previous_receipt_sha256: previous.as_deref(),
                payload_sha256: &payload_sha256,
                authentication_boundary: AUTHENTICATION_BOUNDARY,
                payload: &payload,
            };
            let receipt_sha256 = test_sha256_hex(&serde_json::to_vec(&digest_input).unwrap());
            let receipt = NativeReceipt {
                schema: RECEIPT_SCHEMA.to_owned(),
                sequence,
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
                request_id: sequence,
                status: ResponseStatus::Ok,
                receipt: Some(receipt.clone()),
                error: None,
            };
            let receipt_kind = serde_json::to_value(kind).unwrap().as_str().unwrap().to_owned();
            rebuilt.push(NativeJsonlExchange {
                request_id: sequence,
                request_jsonl: format!("{}\n", String::from_utf8(request_bytes).unwrap()),
                response_jsonl: format!("{}\n", serde_json::to_string(&response).unwrap()),
                receipt_sequence: sequence,
                receipt_kind,
                request_sha256,
                previous_receipt_sha256: receipt.previous_receipt_sha256.clone(),
                receipt_sha256: receipt_sha256.clone(),
            });
            previous = Some(receipt_sha256);
        }
        rebuilt
    }

    fn test_sha256_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    #[test]
    fn admission_fixture_identity_is_deterministic_and_domain_separated() {
        let run = Identity::from_u128(91_001);
        let first = AdmissionFixtureIds::for_run(run).unwrap();
        let second = AdmissionFixtureIds::for_run(run).unwrap();
        let other = AdmissionFixtureIds::for_run(Identity::from_u128(91_002)).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(first.source_component.identity, first.destination_component.identity);
        assert_eq!(first.source_component.generation, Generation(0));
        assert_eq!(first.destination_component.generation, Generation(1));
        assert_ne!(first.logical_operation, first.handoff);
    }

    #[test]
    fn admission_setup_rejects_a_dangling_report_symlink_without_creating_outputs() {
        let root = TestRoot::new("dangling-report");
        let paths = AdmissionDatabasePaths::new(&root.0);
        let target = root.0.join("missing-report-target");
        symlink(&target, &paths.report).unwrap();

        assert!(AdmissionSetup::create(&root.0, Identity::from_u128(91_010)).is_err());
        assert!(fs::symlink_metadata(&paths.report).unwrap().file_type().is_symlink());
        assert!(!path_entry_exists(&target).unwrap());
        assert!(paths.databases().iter().all(|path| !path_entry_exists(path).unwrap()));
    }

    #[test]
    fn admission_setup_rejects_every_dangling_sqlite_sidecar_before_opening_a_database() {
        for database_index in 0..4 {
            for sidecar_index in 0..3 {
                let root =
                    TestRoot::new(&format!("dangling-sidecar-{database_index}-{sidecar_index}"));
                let paths = AdmissionDatabasePaths::new(&root.0);
                let databases = paths.databases();
                let sidecar = sqlite_sidecars(databases[database_index])[sidecar_index].clone();
                let target =
                    root.0.join(format!("missing-sidecar-target-{database_index}-{sidecar_index}"));
                symlink(&target, &sidecar).unwrap();

                assert!(
                    AdmissionSetup::create(
                        &root.0,
                        Identity::from_u128(91_020 + (database_index * 3 + sidecar_index) as u128,),
                    )
                    .is_err()
                );
                assert!(fs::symlink_metadata(&sidecar).unwrap().file_type().is_symlink());
                assert!(!path_entry_exists(&target).unwrap());
                assert!(!path_entry_exists(&paths.report).unwrap());
                assert!(databases.iter().all(|path| !path_entry_exists(path).unwrap()));
            }
        }
    }

    #[test]
    fn terminal_report_publication_is_create_new_and_does_not_follow_symlinks() {
        let regular_root = TestRoot::new("report-no-clobber");
        let regular = regular_root.0.join(LOGICAL_REQUEST_ADMISSION_REPORT);
        fs::write(&regular, b"existing").unwrap();
        assert!(publish_new_regular_file(&regular, b"replacement").is_err());
        assert_eq!(fs::read(&regular).unwrap(), b"existing");

        let symlink_root = TestRoot::new("report-symlink-no-clobber");
        let symlink_path = symlink_root.0.join(LOGICAL_REQUEST_ADMISSION_REPORT);
        let target = symlink_root.0.join("missing-target");
        symlink(&target, &symlink_path).unwrap();
        assert!(publish_new_regular_file(&symlink_path, b"replacement").is_err());
        assert!(fs::symlink_metadata(&symlink_path).unwrap().file_type().is_symlink());
        assert!(!path_entry_exists(&target).unwrap());
    }

    #[test]
    fn terminal_report_publication_cleans_up_every_post_create_failure() {
        for fault in [
            ReportPublicationCheckpoint::AfterWrite,
            ReportPublicationCheckpoint::AfterSync,
            ReportPublicationCheckpoint::BeforeFinalPathAudit,
        ] {
            let root = TestRoot::new(&format!("report-cleanup-{fault:?}"));
            let path = root.0.join(LOGICAL_REQUEST_ADMISSION_REPORT);
            let result = publish_new_regular_file_with_checkpoint(&path, b"terminal", |point| {
                if point == fault { Err(format!("injected {fault:?}")) } else { Ok(()) }
            });
            assert!(result.is_err());
            assert!(!path_entry_exists(&path).unwrap());
        }
    }

    #[test]
    fn sqlite_checkpoint_seals_wal_to_one_auditable_archive_file() {
        let root = TestRoot::new("sqlite-checkpoint");
        let path = root.0.join("checkpoint.sqlite3");
        let connection = Connection::open(&path).unwrap();
        let mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0)).unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        connection
            .execute_batch("PRAGMA user_version = 7; CREATE TABLE evidence(value INTEGER);")
            .unwrap();
        connection.execute("INSERT INTO evidence VALUES (1)", []).unwrap();
        drop(connection);

        let checkpoint = checkpoint_database(&path).unwrap();
        assert_eq!(checkpoint.runtime_journal_mode, "wal");
        assert_eq!(checkpoint.archive_journal_mode, "delete");
        assert_eq!(checkpoint.busy, 0);
        assert_eq!(checkpoint.log_frames, checkpoint.checkpointed_frames);
        let evidence = audit_database(&path, 7, checkpoint).unwrap();
        assert_eq!(evidence.archive_journal_mode, "delete");
        assert!(evidence.sidecars_absent);
    }

    #[test]
    fn sqlite_checkpoint_rejects_non_wal_and_audit_rejects_dangling_sidecar() {
        let non_wal_root = TestRoot::new("sqlite-non-wal");
        let non_wal = non_wal_root.0.join("non-wal.sqlite3");
        drop(Connection::open(&non_wal).unwrap());
        assert!(checkpoint_database(&non_wal).is_err());

        let sidecar_root = TestRoot::new("sqlite-audit-sidecar");
        let path = sidecar_root.0.join("audit.sqlite3");
        let connection = Connection::open(&path).unwrap();
        let _: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0)).unwrap();
        connection.execute_batch("CREATE TABLE evidence(value INTEGER);").unwrap();
        drop(connection);
        let checkpoint = checkpoint_database(&path).unwrap();
        let sidecar = sqlite_sidecars(&path)[0].clone();
        symlink(sidecar_root.0.join("missing-sidecar-target"), &sidecar).unwrap();
        assert!(audit_database(&path, 0, checkpoint).is_err());
    }

    #[test]
    fn admission_required_runtime_rejects_all_legacy_start_bypasses() {
        let root = TestRoot::new("raw-start-bypass");
        let setup = AdmissionSetup::create(&root.0, Identity::from_u128(91_050)).unwrap();
        let (fixture, mut source, _destination, logical_peer) = setup.into_active_source().unwrap();
        assert_eq!(source.admission_profile(), EffectAdmissionProfile::AdmissionRequired);
        let prepared = source.prepare_start(fixture.request.clone()).unwrap();

        assert_eq!(
            source.start(fixture.request.clone()),
            Err(LogicalRequestAdapterError::AdmissionRequired)
        );
        assert_eq!(
            source.execute(LogicalRequestOperation::Start { request: fixture.request.clone() }),
            Err(LogicalRequestAdapterError::AdmissionRequired)
        );
        assert_eq!(
            source.start_prepared(&prepared),
            Err(LogicalRequestAdapterError::AdmissionRequired)
        );
        assert_eq!(logical_peer.request_count(), 0);
        assert_eq!(logical_peer.execution_count(), 0);
    }

    #[test]
    fn admission_gate_rejects_start_called_from_a_different_guest_export_before_io() {
        let root = TestRoot::new("start-from-observe");
        let setup =
            AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(91_052))
                .unwrap();
        let (_fixture, mut source, _destination, logical_peer) =
            setup.into_active_source_with_session("adversarial:start-from-observe").unwrap();

        assert!(matches!(
            source.observe(1),
            Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
                LogicalRequestFailure::Denied
            )))
        ));
        assert_eq!(logical_peer.request_count(), 0);
        assert_eq!(logical_peer.execution_count(), 0);
    }

    #[test]
    fn admission_gate_consumes_a_mutated_start_attempt_before_io() {
        for (sequence, session) in
            [(91_053, "adversarial:mutate-start"), (91_059, "adversarial:invalid-then-start")]
        {
            let root = TestRoot::new(session);
            let setup =
                AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(sequence))
                    .unwrap();
            let (fixture, mut source, _destination, logical_peer) =
                setup.into_active_source_with_session(session).unwrap();
            let prepared = source.prepare_start(fixture.request.clone()).unwrap();
            let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
            let permit = reference_permit(&peer, &fixture, &prepared);
            let duplicate = reference_permit(&peer, &fixture, &prepared);

            assert!(matches!(
                source.start_admitted(&prepared, &peer, permit),
                Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
                    LogicalRequestFailure::Denied
                )))
            ));
            assert_eq!(logical_peer.request_count(), 0, "{session}");
            assert_eq!(logical_peer.execution_count(), 0, "{session}");
            assert!(matches!(
                duplicate.consume(&peer, prepared.effect_request()),
                Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
            ));
        }
    }

    #[test]
    fn admission_gate_closes_on_guest_trap_or_an_unused_authorization() {
        for (sequence, session) in [
            (91_056, "adversarial:trap-before-start"),
            (91_057, "adversarial:return-without-start"),
        ] {
            let root = TestRoot::new(session);
            let setup =
                AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(sequence))
                    .unwrap();
            let (fixture, mut source, _destination, logical_peer) =
                setup.into_active_source_with_session(session).unwrap();
            let prepared = source.prepare_start(fixture.request.clone()).unwrap();
            let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
            let permit = reference_permit(&peer, &fixture, &prepared);
            let duplicate = reference_permit(&peer, &fixture, &prepared);

            assert!(source.start_admitted(&prepared, &peer, permit).is_err());
            assert_eq!(logical_peer.request_count(), 0, "{session}");
            assert_eq!(logical_peer.execution_count(), 0, "{session}");
            assert!(matches!(
                duplicate.consume(&peer, prepared.effect_request()),
                Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
            ));
        }
    }

    #[test]
    fn admission_gate_dispatches_one_exact_start_once() {
        let root = TestRoot::new("exact-start");
        let setup =
            AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(91_058))
                .unwrap();
        let (fixture, mut source, _destination, logical_peer) = setup.into_active_source().unwrap();
        let prepared = source.prepare_start(fixture.request.clone()).unwrap();
        let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
        let permit = reference_permit(&peer, &fixture, &prepared);

        assert!(source.start_admitted(&prepared, &peer, permit).is_ok());
        assert_eq!(logical_peer.request_count(), 1);
        assert_eq!(logical_peer.execution_count(), 1);
    }

    #[test]
    fn admission_gate_allows_at_most_one_host_start_per_consumed_permit() {
        let root = TestRoot::new("duplicate-start");
        let setup =
            AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(91_054))
                .unwrap();
        let (fixture, mut source, _destination, logical_peer) =
            setup.into_active_source_with_session("adversarial:duplicate-start").unwrap();
        let prepared = source.prepare_start(fixture.request.clone()).unwrap();
        let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
        let permit = reference_permit(&peer, &fixture, &prepared);
        let duplicate = reference_permit(&peer, &fixture, &prepared);

        assert!(matches!(
            source.start_admitted(&prepared, &peer, permit),
            Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
                LogicalRequestFailure::Denied
            )))
        ));
        assert_eq!(logical_peer.request_count(), 1);
        assert_eq!(logical_peer.execution_count(), 1);
        assert!(matches!(
            duplicate.consume(&peer, prepared.effect_request()),
            Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
        ));
    }

    #[test]
    fn admitted_start_denies_every_additional_effectful_import() {
        for (sequence, session) in [
            (91_060, "adversarial:start-then-cancel"),
            (91_061, "adversarial:start-then-observe"),
            (91_062, "adversarial:start-then-reconcile"),
        ] {
            let root = TestRoot::new(session);
            let setup =
                AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(sequence))
                    .unwrap();
            let (fixture, mut source, _destination, logical_peer) =
                setup.into_active_source_with_session(session).unwrap();
            let prepared = source.prepare_start(fixture.request.clone()).unwrap();
            let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
            let permit = reference_permit(&peer, &fixture, &prepared);
            let duplicate = reference_permit(&peer, &fixture, &prepared);

            assert!(matches!(
                source.start_admitted(&prepared, &peer, permit),
                Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
                    LogicalRequestFailure::Denied
                )))
            ));
            assert_eq!(logical_peer.request_count(), 1, "{session}");
            assert_eq!(logical_peer.execution_count(), 1, "{session}");
            assert!(matches!(
                duplicate.consume(&peer, prepared.effect_request()),
                Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
            ));
        }
    }

    #[test]
    fn terminal_finish_ack_loss_is_unknown_and_never_reopens_the_permit() {
        let root = TestRoot::new("finish-ack-loss");
        let setup =
            AdmissionSetup::create_without_source_fault(&root.0, Identity::from_u128(91_055))
                .unwrap();
        let (fixture, mut source, _destination, logical_peer) = setup.into_active_source().unwrap();
        let prepared = source.prepare_start(fixture.request.clone()).unwrap();
        let peer = FinishAckLossProvider::new(fixture.effect_config);
        let permit = finish_ack_loss_permit(&peer, &fixture, &prepared);
        let duplicate = finish_ack_loss_permit(&peer, &fixture, &prepared);

        assert_eq!(
            source.start_admitted(&prepared, &peer, permit),
            Err(LogicalRequestAdapterError::AdmissionOutcomeUnknown)
        );
        assert_eq!(logical_peer.request_count(), 1);
        assert_eq!(logical_peer.execution_count(), 1);
        assert!(matches!(
            duplicate.consume(&peer, prepared.effect_request()),
            Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
        ));
    }

    #[test]
    fn guest_failure_closes_the_consumed_fence_and_forbids_retry_dispatch() {
        let root = TestRoot::new("guest-failure-fence");
        let setup = AdmissionSetup::create_with_source_fault(
            &root.0,
            Identity::from_u128(91_051),
            FaultPoint::BeforeLogicalRequestIo,
        )
        .unwrap();
        let (fixture, mut source, _destination, logical_peer) = setup.into_active_source().unwrap();
        let prepared = source.prepare_start(fixture.request.clone()).unwrap();
        let peer = ReferenceEffectPeer::new_admission_required(fixture.effect_config).unwrap();
        let permit = reference_permit(&peer, &fixture, &prepared);
        let duplicate = reference_permit(&peer, &fixture, &prepared);

        assert!(matches!(
            source.start_admitted(&prepared, &peer, permit),
            Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
                LogicalRequestFailure::Unavailable
            )))
        ));
        assert_eq!(logical_peer.request_count(), 0);
        assert_eq!(logical_peer.execution_count(), 0);
        assert!(matches!(
            duplicate.consume(&peer, prepared.effect_request()),
            Err(EffectDispatchAcquireError::Provider(EffectPeerError::StepConflict))
        ));
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_wasmtime_admission_prefix_orders_commit_before_external_send() {
        let root = TestRoot::new("real-prefix");
        let inputs = LogicalRequestAdmissionInputs {
            run_identity: Identity::from_u128(91_100),
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
        let prefix = AdmissionPrefix::run(&root.0, &inputs).unwrap();
        assert_eq!(prefix.registration.record.effect, prefix.fixture.ids.logical_operation);
        assert_eq!(
            prefix.registration.record.operation,
            prefix.prepared_start.effect_request().operation
        );
        assert_eq!(prefix.registration.record.domain, LOGICAL_REQUEST_EXTENSION_ID);
        assert_eq!(prefix.logical_peer.request_count(), 1);
        assert_eq!(prefix.logical_peer.execution_count(), 1);
        assert_eq!(prefix.source_logical_state.phase, LogicalRequestPhase::UnknownCompletion);
        assert_eq!(prefix.outcome_recorded.phase(), ProcessLiveEffectPhase::OutcomeRecorded);
        assert_eq!(
            prefix.commit_ack_loss.discarded_response_jsonl,
            prefix.commit_ack_loss.replay_response_jsonl
        );
        prefix.shutdown().unwrap();
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_wasmtime_admission_handoff_closes_the_source_cohort() {
        let root = TestRoot::new("real-handoff");
        let inputs = LogicalRequestAdmissionInputs {
            run_identity: Identity::from_u128(91_101),
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
        let prefix = AdmissionPrefix::run(&root.0, &inputs).unwrap();
        let handoff = AdmissionCommittedHandoff::run(prefix).unwrap();
        assert_eq!(handoff.sequence.len(), 15);
        assert_eq!(
            handoff.joint.state().state().phase,
            joint_handoff_core::JointPhase::SourceClosed
        );
        assert_eq!(handoff.source.state().phase, HandoffPhase::Exported);
        assert_eq!(
            handoff.destination.as_ref().unwrap().coordinator().unwrap().state().phase,
            HandoffPhase::DestinationPrepared
        );
        assert_eq!(handoff.frozen.receipt.counts.registered, 1);
        assert_eq!(handoff.frozen.receipt.counts.committed, 1);
        assert!(handoff.ownership_commit_ack_lost_after_durable_write);
        assert!(handoff.ownership_reopened_query_exact);
        assert!(handoff.ownership_exact_retry);
        assert_eq!(handoff.logical_peer.request_count(), 1);
        assert_eq!(handoff.logical_peer.execution_count(), 1);
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_wasmtime_admission_guard_activates_then_reconciles() {
        let root = TestRoot::new("real-activation");
        let inputs = LogicalRequestAdmissionInputs {
            run_identity: Identity::from_u128(91_102),
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
        let prefix = AdmissionPrefix::run(&root.0, &inputs).unwrap();
        let completed = AdmissionCommittedHandoff::run(prefix).unwrap().complete().unwrap();
        assert_eq!(completed.sequence.len(), 19);
        assert_eq!(completed.sequence.last().map(String::as_str), Some("destination-reconciled"));
        assert_eq!(
            completed.joint.state().state().phase,
            joint_handoff_core::JointPhase::DestinationActive
        );
        assert_eq!(completed.source.state().phase, HandoffPhase::Committed);
        assert_eq!(completed.source.state().activation.status, ActivationStatus::Fenced);
        let destination = completed.destination_adapter.as_ref().unwrap();
        assert_eq!(destination.coordinator().state().phase, HandoffPhase::Running);
        assert_eq!(destination.coordinator().state().activation.role, ActivationRole::Destination);
        assert_eq!(destination.coordinator().state().activation.status, ActivationStatus::Active);
        assert!(completed.destination_guest_restored_before_activation_receipt);
        assert!(completed.destination_release_blocked_before_completion);
        assert!(completed.destination_source_start_absent_before_reconcile);
        assert!(completed.destination_logical_ledger_absent_before_reconcile);
        assert!(completed.destination_portable_source_operation_present_before_reconcile);
        assert_ne!(
            completed.destination_reconcile_effect,
            Some(completed.prepared_start.effect_request().operation)
        );
        assert_eq!(completed.destination_ledger_revision, 2);
        assert!(!completed.destination_ledger_retained_request);
        assert_eq!(completed.logical_peer.request_count(), 2);
        assert_eq!(completed.logical_peer.execution_count(), 1);
    }

    #[test]
    #[ignore = "requires a separately built nexus-effect-peer binary"]
    fn real_wasmtime_admission_publishes_a_strict_terminal_report() {
        let root = TestRoot::new("real-report");
        let inputs = LogicalRequestAdmissionInputs {
            run_identity: Identity::from_u128(91_103),
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
        let report = run_logical_request_admission_cell(&root.0, inputs).unwrap();
        let expectations = LogicalRequestAdmissionExpectations {
            run_identity: report.run_identity,
            nexus_process: report.nexus.process.clone(),
        };
        crate::validate_logical_request_admission_report(&report, &expectations).unwrap();
        let bytes = fs::read(root.0.join(LOGICAL_REQUEST_ADMISSION_REPORT)).unwrap();
        let decoded: LogicalRequestAdmissionReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, report);
        for database in AdmissionDatabasePaths::new(&root.0).databases() {
            assert!(
                sqlite_sidecars(database)
                    .iter()
                    .all(|sidecar| !path_entry_exists(sidecar).unwrap())
            );
        }

        let rejects = |candidate: &LogicalRequestAdmissionReport| {
            assert!(
                crate::validate_logical_request_admission_report(candidate, &expectations).is_err()
            );
        };
        let rejects_with = |candidate: &LogicalRequestAdmissionReport, expected: &str| {
            let error = crate::validate_logical_request_admission_report(candidate, &expectations)
                .unwrap_err();
            assert!(error.contains(expected), "unexpected rejection: {error}");
        };
        let mut mutated = report.clone();
        mutated.nexus.registration.record.effect = Identity::from_u128(1);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.registration.record.operation = Identity::from_u128(2);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.registration.record.domain = Identity::from_u128(3);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.final_publication.record.outcome_digest = Some(Digest::ZERO);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.verified_commit.commit_sequence = 2;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.verified_commit.registry_replay = true;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.commit_ack_loss.replay_response_jsonl.push(' ');
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.run_identity = Identity::from_u128(91_104);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.process.process_id = 0;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.nexus.process.executable_sha256 = "0".repeat(64);
        rejects_with(&mutated, "external expectations");
        let mut mutated = report.clone();
        mutated.nexus.process.start_time_ticks =
            mutated.nexus.process.start_time_ticks.checked_add(1).unwrap();
        rejects_with(&mutated, "external expectations");
        let mut mutated = report.clone();
        mutated.source.source_start_state.phase = HandoffPhase::Frozen;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.ownership.queried_commit.header.sequence += 1;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.runtime.snapshot.integrity = Digest::ZERO;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.runtime.joint_projection.canonical_record_bytes[0][0] ^= 1;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.runtime.receipt_material[0].peer_invocation.as_mut().unwrap().push(0);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.runtime.source_terminal_state.phase = HandoffPhase::Exported;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.runtime.destination_activation_state.phase = HandoffPhase::Committed;
        rejects(&mutated);
        let mut mutated = report.clone();
        let mut extra_extension = mutated.runtime.destination_terminal_state.extensions[0].clone();
        extra_extension.id = Identity::from_u128(91_199);
        extra_extension.required = false;
        mutated.runtime.destination_terminal_state.extensions.push(extra_extension);
        rejects_with(&mutated, "activation-to-Reconcile transition");
        let mut mutated = report.clone();
        mutated.runtime.destination_prepared_state.portable_state.push(0);
        mutated.runtime.destination_prepared.state_digest =
            state_digest(&mutated.runtime.destination_prepared_state).unwrap();
        rejects_with(&mutated, "exact semantic projection of the snapshot");
        let mut mutated = report.clone();
        let mut extra_extension = mutated.source.source_start_state.extensions[0].clone();
        extra_extension.id = Identity::from_u128(91_197);
        extra_extension.required = false;
        mutated.source.source_start_state.extensions.push(extra_extension.clone());
        mutated.source.source_state_digest =
            state_digest(&mutated.source.source_start_state).unwrap();
        mutated.runtime.snapshot.body.extensions.push(extra_extension);
        mutated.runtime.snapshot.integrity =
            contract_core::snapshot_integrity(&mutated.runtime.snapshot.body).unwrap();
        rejects_with(&mutated, "exact independently rebuilt fixture transition");
        let mut mutated = report.clone();
        {
            let prepared =
                mutated.runtime.destination_prepared_state.prepared_destination.as_mut().unwrap();
            let handoff = prepared
                .authorities
                .iter_mut()
                .find(|grant| {
                    grant.rights.contains(Rights::HANDOFF) && grant.resource == grant.subject
                })
                .unwrap();
            handoff.authority = EntityRef::initial(Identity::from_u128(91_198));
        }
        let prepared =
            mutated.runtime.destination_prepared_state.prepared_destination.as_ref().unwrap();
        mutated.runtime.destination_prepared.prepared_destination_digest =
            canonical_digest(prepared).unwrap();
        mutated.runtime.destination_prepared.authorities_digest =
            canonical_digest(&prepared.authorities).unwrap();
        mutated.runtime.destination_prepared.state_digest =
            state_digest(&mutated.runtime.destination_prepared_state).unwrap();
        rejects_with(&mutated, "exact semantic projection of the snapshot");
        let mut mutated = report.clone();
        let fake_lease_digest = Digest::from_bytes([0x5a; 32]);
        mutated.runtime.destination_prepared.lease_commit_request_digest = fake_lease_digest;
        mutated
            .runtime
            .destination_activation_state
            .operations
            .last_mut()
            .unwrap()
            .request
            .request_digest = fake_lease_digest;
        rejects_with(&mutated, "lease-commit request digest was not independently derived");
        let mut mutated = report.clone();
        let lease_operation = mutated
            .runtime
            .destination_activation_state
            .operations
            .last()
            .unwrap()
            .request
            .operation;
        for state in [
            &mut mutated.runtime.destination_activation_state,
            &mut mutated.runtime.destination_terminal_state,
        ] {
            let EffectOutcome::Succeeded { evidence, .. } = state
                .operations
                .iter_mut()
                .find(|record| record.request.operation == lease_operation)
                .unwrap()
                .outcome
                .as_mut()
                .unwrap()
            else {
                unreachable!();
            };
            evidence.identity = Identity::from_u128(91_200);
        }
        mutated.runtime.destination_activation.state_digest =
            state_digest(&mutated.runtime.destination_activation_state).unwrap();
        rejects_with(&mutated, "lease-commit request or outcome");
        let mut mutated = report.clone();
        let EffectOutcome::Succeeded { evidence, .. } = mutated
            .runtime
            .destination_terminal_state
            .operations
            .last_mut()
            .unwrap()
            .outcome
            .as_mut()
            .unwrap()
        else {
            unreachable!();
        };
        evidence.identity = Identity::from_u128(91_201);
        rejects_with(&mutated, "Reconcile outcome was not the exact independently rebuilt");
        let mut mutated = report.clone();
        mutated.runtime.source_terminal_state.portable_state.push(0);
        mutated.runtime.source_fence.state_digest =
            state_digest(&mutated.runtime.source_terminal_state).unwrap();
        mutated.runtime.destination_activation.source_fence =
            mutated.runtime.source_fence.receipt_ref().unwrap();
        rejects_with(&mutated, "source terminal state is not exact");
        let mut mutated = report.clone();
        mutated.nexus.native_chain = rehashed_native_chain(&report.nexus.native_chain, |entries| {
            let (_, NativeReceiptPayload::ClosureProgress(closed)) = entries
                .iter_mut()
                .find(|(_, payload)| {
                    matches!(
                        payload,
                        NativeReceiptPayload::ClosureProgress(progress)
                            if progress.status == NativeHandoffStatus::Closed
                    )
                })
                .unwrap()
            else {
                unreachable!();
            };
            closed.live_effects = 1;
        });
        validate_native_jsonl_chain(&mutated.nexus.native_chain).unwrap();
        rejects_with(&mutated, "Closure did not refine");
        let mut mutated = report.clone();
        let fake_terminal_manifest = 0xfeed_face_cafe_beef;
        mutated.nexus.native_chain = rehashed_native_chain(&report.nexus.native_chain, |entries| {
            for (_, payload) in entries {
                match payload {
                    NativeReceiptPayload::ClosureProgress(progress)
                        if progress.status == NativeHandoffStatus::Closed =>
                    {
                        progress.terminal_manifest_digest = Some(fake_terminal_manifest);
                    }
                    NativeReceiptPayload::HandoffQuery(query)
                        if query.status == NativeHandoffStatus::Closed =>
                    {
                        query.terminal_manifest_digest = Some(fake_terminal_manifest);
                    }
                    _ => {}
                }
            }
        });
        mutated.nexus.closure.effect_manifest_digest =
            crate::process_effect_peer::mapped_u64_digest(
                b"terminal-manifest",
                fake_terminal_manifest,
            );
        validate_native_jsonl_chain(&mutated.nexus.native_chain).unwrap();
        rejects_with(&mutated, "Closure did not refine");
        let mut mutated = report.clone();
        mutated.nexus.native_chain = rehashed_native_chain(&report.nexus.native_chain, |entries| {
            let extra_query = entries
                .iter()
                .find(|(request, _)| matches!(request.command, PeerCommand::Query))
                .cloned()
                .unwrap();
            let shutdown = entries
                .iter()
                .position(|(request, _)| matches!(request.command, PeerCommand::Shutdown))
                .unwrap();
            entries.insert(shutdown, extra_query);
        });
        validate_native_jsonl_chain(&mutated.nexus.native_chain).unwrap();
        rejects_with(&mutated, "exact bounded command sequence");
        let mut mutated = report.clone();
        mutated.databases.joint_projection.user_version = 1;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.databases.source.runtime_journal_mode = "delete".to_owned();
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.databases.destination.archive_journal_mode = "wal".to_owned();
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.databases.ownership.wal_checkpoint_busy = 1;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.databases.joint_projection.wal_log_frames =
            mutated.databases.joint_projection.wal_checkpointed_frames.saturating_add(1);
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.claims.cross_host = true;
        rejects(&mutated);
        let mut mutated = report.clone();
        mutated.limitations[0].push(' ');
        rejects(&mutated);
    }
}
