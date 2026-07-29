//! Canonical regular-file endpoint used by the Wanco compute-state carrier.
//!
//! Wanco preserves guest compute progress. This module keeps resource state in
//! the existing vISA profile, coordinator, and SQLite provider path. Native
//! roots and file identities are endpoint-local; only the profile state,
//! component state, snapshot, and an explicitly separate storage image cross
//! the handoff boundary.

use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read as _, Write},
    os::unix::{
        fs::MetadataExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, BindingReceipt, CanonicalState,
    DeliveryPolicy, Digest, EffectOutcome, EntityRef, EvidenceKind, EvidenceRef, ExtensionSupport,
    Generation, HandoffPhase, IdempotencyKey, Identity, JournalEntry, KeyValueClaim, LeaseEpoch,
    NodeIdentity, OperationRecord, ProfileAccess, Replay, ResourceClaims, Rights, SchemaVersion,
    SnapshotEnvelope, TimerClaim, TimerClock,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, BindingPort, JournalScope, LeasePort, LeaseRecord,
};
use substrate_host::SqliteProvider;
use visa_component_adapter::{
    PortableRegularFileState, ProfileBinding, RegularFileComponentState, RegularFileWorkloadPhase,
    identity_string, profile_execute, profile_observe,
};
use visa_profile::{
    ContinuityDisposition, CooperativeHandoffProfile, FileAccessMode, FileDurability,
    FileLockPolicy, FileLockState, REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION,
    RegularFileClaim, RegularFileOperation, RegularFileResult, RegularFileState,
    decode_regular_file_result, encode_regular_file_operation, regular_file_extension,
    regular_file_state,
};
use visa_regular_file_observation::{GenericCallResult, ProtocolAction};
use visa_runtime::{
    AuthorityPlan, CommandReceipt, Coordinator, ProfileAuthorityPlan, SafePointTimer,
    SnapshotExpectations, canonical_digest, validate_snapshot,
};

const TRANSFER_SCHEMA: &str = "visa-wanco-canonical-transfer-v1";
const RECEIPT_SCHEMA: &str = "visa-wanco-canonical-service-receipt-v1";
const ID_DOMAIN: &[u8] = b"visa-wanco-canonical-endpoint-v1\0";
const RELATIVE_FILE: &[u8] = b"data.bin";
const MAX_WIRE_LINE: usize = 128 * 1024;
const INITIAL_LEASE_EPOCH: LeaseEpoch = LeaseEpoch(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalWorkload {
    ReadWriteOffset,
    AppendContinuity,
}

impl CanonicalWorkload {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadWriteOffset => "read-write-offset",
            Self::AppendContinuity => "append-continuity",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read-write-offset" => Ok(Self::ReadWriteOffset),
            "append-continuity" => Ok(Self::AppendContinuity),
            _ => Err(format!("unknown canonical workload {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Source,
    Destination,
}

impl EndpointRole {
    const fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "source" => Ok(Self::Source),
            "destination" => Ok(Self::Destination),
            _ => Err(format!("unknown endpoint role {value:?}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceEndpointConfig {
    pub cell_id: String,
    pub route: String,
    pub workload: CanonicalWorkload,
    pub database: PathBuf,
    pub file_root: PathBuf,
    pub component_digest: Digest,
    pub session_id: String,
    pub initial_content: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DestinationEndpointConfig {
    pub cell_id: String,
    pub route: String,
    pub workload: CanonicalWorkload,
    pub database: PathBuf,
    pub file_root: PathBuf,
    pub component_digest: Digest,
    pub session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigestReceipt {
    pub kind: String,
    pub sha256: String,
    pub size: u64,
}

impl ArtifactDigestReceipt {
    fn new(kind: &str, bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            kind: kind.to_owned(),
            sha256: sha256_hex(bytes),
            size: u64::try_from(bytes.len())
                .map_err(|_| format!("{kind} size does not fit in u64"))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObjectReceipt {
    pub node: NodeIdentity,
    pub root_path: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub file_device: u64,
    pub file_inode: u64,
    pub file_mode: u32,
    pub file_link_count: u64,
    pub file_size: u64,
    pub file_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalCommandReceipt {
    Committed {
        entry: JournalEntry,
    },
    Effect {
        intent: Option<JournalEntry>,
        resolution: Box<JournalEntry>,
        outcome: Box<EffectOutcome>,
        reconciled: bool,
    },
    ReplayedOperation {
        operation: OperationRecord,
    },
    ReplayedEvent {
        event: contract_core::Event,
    },
    ReplayedNoChange,
}

impl From<&CommandReceipt> for CanonicalCommandReceipt {
    fn from(receipt: &CommandReceipt) -> Self {
        match receipt {
            CommandReceipt::Committed(entry) => Self::Committed { entry: entry.clone() },
            CommandReceipt::Effect(effect) => Self::Effect {
                intent: effect.intent.clone(),
                resolution: Box::new(effect.resolution.clone()),
                outcome: Box::new(effect.outcome.clone()),
                reconciled: effect.reconciled,
            },
            CommandReceipt::Replayed(Replay::Operation(operation)) => {
                Self::ReplayedOperation { operation: operation.clone() }
            }
            CommandReceipt::Replayed(Replay::Event(event)) => {
                Self::ReplayedEvent { event: event.clone() }
            }
            CommandReceipt::Replayed(Replay::NoChange) => Self::ReplayedNoChange,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalStateProbe {
    pub journal_position: contract_core::JournalPosition,
    pub state_digest: Digest,
    pub phase: HandoffPhase,
    pub activation_role: ActivationRole,
    pub activation_status: ActivationStatus,
    pub activation_node: NodeIdentity,
    pub owner: Option<NodeIdentity>,
    pub lease_epoch: LeaseEpoch,
    pub file_lease: Option<CanonicalLeaseReceipt>,
    pub destination_binding: Option<BindingReceipt>,
    pub operation_ledger: Vec<OperationRecord>,
    pub profile_state: RegularFileState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalLeaseReceipt {
    pub resource: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
}

impl From<LeaseRecord> for CanonicalLeaseReceipt {
    fn from(lease: LeaseRecord) -> Self {
        Self { resource: lease.resource, owner: lease.owner, epoch: lease.epoch }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalSafePointTimerReceipt {
    Idle,
    Pending { remaining_nanos: u64, arm_operation: Identity },
    Completed { arm_operation: Option<Identity> },
    Cancelled,
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSafePointReceipt {
    pub safe_point_id: String,
    pub timer: CanonicalSafePointTimerReceipt,
}

impl CanonicalSafePointReceipt {
    fn new(safe_point_id: String, timer: SafePointTimer) -> Self {
        let timer = match timer {
            SafePointTimer::Idle => CanonicalSafePointTimerReceipt::Idle,
            SafePointTimer::Pending { remaining, arm_operation } => {
                CanonicalSafePointTimerReceipt::Pending {
                    remaining_nanos: remaining.0,
                    arm_operation,
                }
            }
            SafePointTimer::Completed { arm_operation } => {
                CanonicalSafePointTimerReceipt::Completed { arm_operation }
            }
            SafePointTimer::Cancelled => CanonicalSafePointTimerReceipt::Cancelled,
            SafePointTimer::Cleaned => CanonicalSafePointTimerReceipt::Cleaned,
        };
        Self { safe_point_id, timer }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReceipt {
    pub action: String,
    pub protocol_action: Option<ProtocolAction>,
    pub result: Option<GenericCallResult>,
    pub command: Option<Identity>,
    pub coordinator_receipt: Option<CanonicalCommandReceipt>,
    pub artifacts: Vec<ArtifactDigestReceipt>,
    pub state: CanonicalStateProbe,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOperationReceipt {
    pub role: EndpointRole,
    pub workload: CanonicalWorkload,
    pub progress: i32,
    pub is_start: bool,
    pub operation_kind: String,
    pub operation: Option<RegularFileOperation>,
    pub workload_key: String,
    pub attempt: u32,
    pub canonical_operation: Option<Identity>,
    pub replayed: bool,
    pub result: Option<RegularFileResult>,
    pub error: Option<String>,
    pub raw_event: String,
    pub before: CanonicalStateProbe,
    pub after: CanonicalStateProbe,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalServiceReceipt {
    pub schema: String,
    pub cell_id: String,
    pub route: String,
    pub workload: CanonicalWorkload,
    pub role: EndpointRole,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub native_object: NativeObjectReceipt,
    pub lifecycle: Vec<LifecycleReceipt>,
    pub operations: Vec<CanonicalOperationReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTransfer {
    pub schema: String,
    pub cell_id: String,
    pub workload: CanonicalWorkload,
    pub snapshot: SnapshotEnvelope,
    pub portable_state: Vec<u8>,
    /// Deployment/storage transfer. This is intentionally not part of
    /// `PortableRegularFileState` or the canonical snapshot extension.
    pub storage_image: Vec<u8>,
    pub storage_image_sha256: String,
}

impl CanonicalTransfer {
    pub fn encode_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self)
            .map(|mut bytes| {
                bytes.push(b'\n');
                bytes
            })
            .map_err(|error| format!("cannot encode canonical transfer: {error}"))
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, String> {
        let transfer: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("cannot decode canonical transfer: {error}"))?;
        if transfer.schema != TRANSFER_SCHEMA {
            return Err("canonical transfer schema mismatch".to_owned());
        }
        Ok(transfer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointPhase {
    Running,
    SafePointCommitted,
    Exported,
    DestinationCommitted,
    Resumed,
}

#[derive(Clone, Debug)]
struct EndpointIds {
    source_node: NodeIdentity,
    destination_node: NodeIdentity,
    source_component: EntityRef,
    destination_component: EntityRef,
    timer: EntityRef,
    key_value: EntityRef,
    key_value_namespace: Identity,
    file: EntityRef,
    file_namespace: Identity,
    source_handoff_authority: EntityRef,
    destination_handoff_authority: EntityRef,
    attenuated_handoff_authority: EntityRef,
    source_timer_authority: EntityRef,
    destination_timer_authority: EntityRef,
    attenuated_timer_authority: EntityRef,
    source_key_value_authority: EntityRef,
    destination_key_value_authority: EntityRef,
    attenuated_key_value_authority: EntityRef,
    source_file_authority: EntityRef,
    destination_file_authority: EntityRef,
    attenuated_file_authority: EntityRef,
    handoff: Identity,
    snapshot: Identity,
}

impl EndpointIds {
    fn for_cell(cell_id: &str) -> Self {
        let component = derive_identity(cell_id, "component");
        Self {
            source_node: NodeIdentity::new(derive_identity(cell_id, "source-node")),
            destination_node: NodeIdentity::new(derive_identity(cell_id, "destination-node")),
            source_component: EntityRef::initial(component),
            destination_component: EntityRef::new(component, Generation(1)),
            timer: entity(cell_id, "timer"),
            key_value: entity(cell_id, "key-value"),
            key_value_namespace: derive_identity(cell_id, "key-value-namespace"),
            file: entity(cell_id, "regular-file"),
            file_namespace: derive_identity(cell_id, "regular-file-namespace"),
            source_handoff_authority: entity(cell_id, "source-handoff-authority"),
            destination_handoff_authority: entity(cell_id, "destination-handoff-authority"),
            attenuated_handoff_authority: entity(cell_id, "attenuated-handoff-authority"),
            source_timer_authority: entity(cell_id, "source-timer-authority"),
            destination_timer_authority: entity(cell_id, "destination-timer-authority"),
            attenuated_timer_authority: entity(cell_id, "attenuated-timer-authority"),
            source_key_value_authority: entity(cell_id, "source-key-value-authority"),
            destination_key_value_authority: entity(cell_id, "destination-key-value-authority"),
            attenuated_key_value_authority: entity(cell_id, "attenuated-key-value-authority"),
            source_file_authority: entity(cell_id, "source-file-authority"),
            destination_file_authority: entity(cell_id, "destination-file-authority"),
            attenuated_file_authority: entity(cell_id, "attenuated-file-authority"),
            handoff: derive_identity(cell_id, "handoff"),
            snapshot: derive_identity(cell_id, "snapshot"),
        }
    }

    fn authority_plans(
        &self,
    ) -> (AuthorityPlan, AuthorityPlan, AuthorityPlan, ProfileAuthorityPlan) {
        (
            AuthorityPlan {
                source_authority: self.source_handoff_authority,
                destination_authority: self.destination_handoff_authority,
                attenuated_authority: self.attenuated_handoff_authority,
            },
            AuthorityPlan {
                source_authority: self.source_timer_authority,
                destination_authority: self.destination_timer_authority,
                attenuated_authority: self.attenuated_timer_authority,
            },
            AuthorityPlan {
                source_authority: self.source_key_value_authority,
                destination_authority: self.destination_key_value_authority,
                attenuated_authority: self.attenuated_key_value_authority,
            },
            ProfileAuthorityPlan {
                profile: REGULAR_FILE_EXTENSION_ID,
                resource: self.file,
                authority: AuthorityPlan {
                    source_authority: self.source_file_authority,
                    destination_authority: self.destination_file_authority,
                    attenuated_authority: self.attenuated_file_authority,
                },
            },
        )
    }
}

pub struct CanonicalEndpoint {
    cell_id: String,
    workload: CanonicalWorkload,
    role: EndpointRole,
    ids: EndpointIds,
    root: PathBuf,
    file_path: PathBuf,
    session_id: String,
    coordinator: Coordinator<SqliteProvider>,
    phase: EndpointPhase,
    portable_state: Option<PortableRegularFileState>,
    receipt: CanonicalServiceReceipt,
}

impl CanonicalEndpoint {
    pub fn initialize_source(config: SourceEndpointConfig) -> Result<Self, String> {
        validate_cell_id(&config.cell_id)?;
        if config.initial_content.len() > visa_profile::MAX_REGULAR_FILE_BYTES as usize {
            return Err("initial regular-file image exceeds profile bound".to_owned());
        }
        ensure_new_database(&config.database)?;
        let (root, file_path) = create_endpoint_file(&config.file_root, &config.initial_content)?;
        let ids = EndpointIds::for_cell(&config.cell_id);
        let regular_file = initial_regular_file(&ids, &config.initial_content)?;
        let profile_digest = profile_digest()?;
        let source_authorities = source_authorities(&ids);
        let source_state = canonical_source_state(
            &ids,
            config.component_digest,
            profile_digest,
            regular_file.clone(),
            source_authorities.clone(),
        )?;
        let mut provider = SqliteProvider::open(
            &config.database,
            JournalScope { node: ids.source_node, component: ids.source_component.identity },
        )
        .map_err(provider_error)?;
        install_source_material(&mut provider, &ids, &regular_file, &root, &source_authorities)?;
        let mut coordinator =
            Coordinator::recover(source_state, provider).map_err(runtime_error)?;
        let activate_command = derive_identity(&config.cell_id, "source-activate");
        let activate = coordinator
            .activate(activate_command, ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
            .map_err(runtime_error)?;
        ProfileBinding::for_state(coordinator.state(), REGULAR_FILE_EXTENSION_ID)
            .map_err(binding_error)?;
        let native = native_receipt(ids.source_node, &root, &file_path)?;
        let mut endpoint = Self {
            cell_id: config.cell_id.clone(),
            workload: config.workload,
            role: EndpointRole::Source,
            ids,
            root,
            file_path,
            session_id: config.session_id,
            coordinator,
            phase: EndpointPhase::Running,
            portable_state: None,
            receipt: CanonicalServiceReceipt {
                schema: RECEIPT_SCHEMA.to_owned(),
                cell_id: config.cell_id,
                route: config.route,
                workload: config.workload,
                role: EndpointRole::Source,
                component_digest: config.component_digest,
                profile_digest,
                native_object: native,
                lifecycle: Vec::new(),
                operations: Vec::new(),
            },
        };
        endpoint.push_lifecycle(
            "source_activate",
            None,
            Some(command_result(&activate)?),
            Some(activate_command),
            Some(&activate),
            Vec::new(),
        )?;
        Ok(endpoint)
    }

    /// Restore and prepare a destination against a fresh provider database and
    /// a freshly materialized node-local storage object. The endpoint remains
    /// blocked until [`Self::resume_destination`] validates the portable state.
    pub fn restore_destination(
        config: DestinationEndpointConfig,
        transfer: &CanonicalTransfer,
    ) -> Result<Self, String> {
        validate_cell_id(&config.cell_id)?;
        let validated = validate_transfer(&config, transfer)?;
        ensure_new_database(&config.database)?;
        let (root, file_path) = create_endpoint_file(&config.file_root, &transfer.storage_image)?;
        let ids = EndpointIds::for_cell(&config.cell_id);
        let mut provider = SqliteProvider::open(
            &config.database,
            JournalScope {
                node: ids.destination_node,
                component: ids.destination_component.identity,
            },
        )
        .map_err(provider_error)?;
        install_destination_material(
            &mut provider,
            &ids,
            &transfer.snapshot,
            &validated.regular_file,
            &root,
        )?;
        let coordinator =
            Coordinator::restore(validated.snapshot, provider).map_err(runtime_error)?;
        let native = native_receipt(ids.destination_node, &root, &file_path)?;
        let mut endpoint = Self {
            cell_id: config.cell_id.clone(),
            workload: config.workload,
            role: EndpointRole::Destination,
            ids,
            root,
            file_path,
            session_id: config.session_id,
            coordinator,
            phase: EndpointPhase::DestinationCommitted,
            portable_state: Some(validated.portable),
            receipt: CanonicalServiceReceipt {
                schema: RECEIPT_SCHEMA.to_owned(),
                cell_id: config.cell_id,
                route: config.route,
                workload: config.workload,
                role: EndpointRole::Destination,
                component_digest: config.component_digest,
                profile_digest: validated.profile_digest,
                native_object: native,
                lifecycle: Vec::new(),
                operations: Vec::new(),
            },
        };
        endpoint.push_lifecycle("destination_restore", None, None, None, None, Vec::new())?;
        let (handoff, timer, key_value, file) = endpoint.ids.authority_plans();
        let prepare_command = derive_identity(&endpoint.cell_id, "destination-prepare");
        let prepare = endpoint
            .coordinator
            .prepare_destination_with_profiles(prepare_command, handoff, timer, key_value, &[file])
            .map_err(runtime_error)?;
        endpoint.push_lifecycle(
            "destination_prepare",
            Some(ProtocolAction::PrepareDestination {
                command_id: identity_string(prepare_command),
            }),
            Some(command_result(&prepare)?),
            Some(prepare_command),
            Some(&prepare),
            Vec::new(),
        )?;
        let commit_command = derive_identity(&endpoint.cell_id, "destination-commit-command");
        let commit = endpoint
            .coordinator
            .commit_handoff(
                commit_command,
                derive_identity(&endpoint.cell_id, "destination-commit-operation"),
                IdempotencyKey::from_bytes(
                    derive_identity(&endpoint.cell_id, "destination-commit-idempotency").0,
                ),
            )
            .map_err(runtime_error)?;
        endpoint.push_lifecycle(
            "destination_commit",
            Some(ProtocolAction::CommitHandoff {
                command_id: identity_string(commit_command),
                operation_id: identity_string(derive_identity(
                    &endpoint.cell_id,
                    "destination-commit-operation",
                )),
            }),
            Some(command_result(&commit)?),
            Some(commit_command),
            Some(&commit),
            Vec::new(),
        )?;
        Ok(endpoint)
    }

    pub const fn role(&self) -> EndpointRole {
        self.role
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn receipt(&self) -> &CanonicalServiceReceipt {
        &self.receipt
    }

    pub fn write_receipt(&self, path: &Path) -> Result<(), String> {
        let mut bytes = serde_json::to_vec_pretty(&self.receipt)
            .map_err(|error| format!("cannot encode canonical service receipt: {error}"))?;
        bytes.push(b'\n');
        write_new(path, &bytes, "canonical service receipt")
    }

    /// Commit the source profile/component safe point. The runner must create
    /// the Wanco compute checkpoint only after this call returns successfully.
    pub fn source_safe_point(&mut self) -> Result<ArtifactDigestReceipt, String> {
        if self.role != EndpointRole::Source || self.phase != EndpointPhase::Running {
            return Err("source safe point is unavailable in the current endpoint phase".to_owned());
        }
        let begin_command = derive_identity(&self.cell_id, "source-begin-quiesce");
        let begin = self
            .coordinator
            .begin_quiesce(begin_command, self.ids.source_handoff_authority)
            .map_err(runtime_error)?;
        self.push_lifecycle(
            "source_begin_quiesce",
            Some(ProtocolAction::BeginQuiesce {
                command_id: identity_string(begin_command),
                authority_id: identity_string(self.ids.source_handoff_authority.identity),
            }),
            Some(command_result(&begin)?),
            Some(begin_command),
            Some(&begin),
            Vec::new(),
        )?;
        let safe_point = self.coordinator.prepare_safe_point().map_err(runtime_error)?;
        let safe_point_id = identity_string(derive_identity(&self.cell_id, "safe-point"));
        let safe_point_result = serde_json::to_vec(&CanonicalSafePointReceipt::new(
            safe_point_id.clone(),
            safe_point.timer(),
        ))
        .map_err(|error| format!("cannot encode safe-point receipt: {error}"))?;
        self.push_lifecycle(
            "source_prepare_safe_point",
            Some(ProtocolAction::PrepareSafePoint { safe_point_id: safe_point_id.clone() }),
            Some(GenericCallResult::Returned { bytes: safe_point_result }),
            None,
            None,
            Vec::new(),
        )?;
        let canonical = canonical_regular_file(self.coordinator.state())?;
        let component = RegularFileComponentState::from_canonical(
            self.session_id.clone(),
            &canonical,
            RegularFileWorkloadPhase::Frozen,
        )
        .map_err(codec_error)?;
        let portable = PortableRegularFileState::encode(&component).map_err(codec_error)?;
        portable
            .decode()
            .and_then(|decoded| decoded.validate_canonical(&canonical))
            .map_err(codec_error)?;
        let artifact =
            ArtifactDigestReceipt::new("portable_regular_file_state", portable.as_bytes())?;
        self.push_lifecycle(
            "source_freeze_runtime",
            Some(ProtocolAction::FreezeRuntime { safe_point_id: safe_point_id.clone() }),
            Some(GenericCallResult::Returned { bytes: portable.as_bytes().to_vec() }),
            None,
            None,
            vec![artifact.clone()],
        )?;
        let freeze_command = derive_identity(&self.cell_id, "source-freeze");
        let freeze = self
            .coordinator
            .commit_safe_point(freeze_command, portable.as_bytes().to_vec(), safe_point)
            .map_err(runtime_error)?;
        self.portable_state = Some(portable);
        self.phase = EndpointPhase::SafePointCommitted;
        self.push_lifecycle(
            "source_commit_safe_point",
            Some(ProtocolAction::CommitSafePoint {
                command_id: identity_string(freeze_command),
                safe_point_id,
            }),
            Some(command_result(&freeze)?),
            Some(freeze_command),
            Some(&freeze),
            vec![artifact.clone()],
        )?;
        Ok(artifact)
    }

    /// Export the canonical snapshot after the runner has captured Wanco's
    /// compute checkpoint.
    pub fn source_export(&mut self) -> Result<CanonicalTransfer, String> {
        if self.role != EndpointRole::Source || self.phase != EndpointPhase::SafePointCommitted {
            return Err("source export requires a committed safe point".to_owned());
        }
        let portable_state = self
            .portable_state
            .as_ref()
            .ok_or_else(|| "committed source has no portable state".to_owned())?;
        let portable_bytes = portable_state.as_bytes().to_vec();
        let evidence = EvidenceRef {
            identity: derive_identity(&self.cell_id, "snapshot-evidence"),
            kind: EvidenceKind::SnapshotIntegrity,
            digest: self.coordinator.state_digest().map_err(runtime_error)?,
        };
        let export_command = derive_identity(&self.cell_id, "source-export");
        let (receipt, snapshot) = self
            .coordinator
            .export_snapshot(export_command, self.ids.handoff, self.ids.snapshot, evidence)
            .map_err(runtime_error)?;
        let storage_image = fs::read(&self.file_path)
            .map_err(|error| format!("cannot read source storage image: {error}"))?;
        let snapshot_bytes = serde_json::to_vec(&snapshot)
            .map_err(|error| format!("cannot encode snapshot for receipt: {error}"))?;
        let artifacts = vec![
            ArtifactDigestReceipt::new("snapshot_envelope", &snapshot_bytes)?,
            ArtifactDigestReceipt::new("portable_regular_file_state", &portable_bytes)?,
            ArtifactDigestReceipt::new("regular_file_storage_image", &storage_image)?,
        ];
        let transfer = CanonicalTransfer {
            schema: TRANSFER_SCHEMA.to_owned(),
            cell_id: self.cell_id.clone(),
            workload: self.workload,
            snapshot,
            portable_state: portable_bytes,
            storage_image_sha256: sha256_hex(&storage_image),
            storage_image,
        };
        validate_transfer_shape(&transfer)?;
        self.phase = EndpointPhase::Exported;
        self.push_lifecycle(
            "source_export_snapshot",
            Some(ProtocolAction::ExportSnapshot {
                command_id: identity_string(export_command),
                snapshot_id: identity_string(transfer.snapshot.body.snapshot.snapshot),
            }),
            Some(command_result(&receipt)?),
            Some(export_command),
            Some(&receipt),
            artifacts,
        )?;
        Ok(transfer)
    }

    /// Validate the profile/component state restored into a fresh Wanco
    /// process, then publish the destination activation. Calls remain blocked
    /// until this explicit step succeeds.
    pub fn resume_destination(&mut self) -> Result<(), String> {
        if self.role != EndpointRole::Destination
            || self.phase != EndpointPhase::DestinationCommitted
        {
            return Err(
                "destination resume is unavailable in the current endpoint phase".to_owned()
            );
        }
        let portable_state = self
            .portable_state
            .as_ref()
            .ok_or_else(|| "destination has no portable state".to_owned())?;
        let portable_bytes = portable_state.as_bytes().to_vec();
        if self.coordinator.state().portable_state != portable_bytes {
            return Err("destination canonical portable state mismatch".to_owned());
        }
        let component = portable_state.decode().map_err(codec_error)?;
        if component.phase != RegularFileWorkloadPhase::Frozen
            || component.session_id != self.session_id
        {
            return Err(
                "destination portable workload state is not the expected frozen session".to_owned()
            );
        }
        let canonical = canonical_regular_file(self.coordinator.state())?;
        component.validate_canonical(&canonical).map_err(codec_error)?;
        self.push_lifecycle(
            "destination_restore_runtime",
            Some(ProtocolAction::RestoreRuntime {
                snapshot_id: identity_string(self.ids.snapshot),
            }),
            Some(GenericCallResult::Returned { bytes: portable_bytes.clone() }),
            None,
            None,
            vec![ArtifactDigestReceipt::new("portable_regular_file_state", &portable_bytes)?],
        )?;
        let resume_command = derive_identity(&self.cell_id, "destination-resume");
        let resume = self.coordinator.resume_destination(resume_command).map_err(runtime_error)?;
        ProfileBinding::for_state(self.coordinator.state(), REGULAR_FILE_EXTENSION_ID)
            .map_err(binding_error)?;
        self.phase = EndpointPhase::Resumed;
        self.push_lifecycle(
            "destination_resume",
            Some(ProtocolAction::ResumeDestination { command_id: identity_string(resume_command) }),
            Some(command_result(&resume)?),
            Some(resume_command),
            Some(&resume),
            Vec::new(),
        )?;
        Ok(())
    }

    pub fn handle_wire_line(&mut self, line: &str) -> Result<WireAction, String> {
        let request = WireRequest::parse(line)?;
        match request {
            WireRequest::SafePoint => {
                let artifact = self.source_safe_point()?;
                Ok(WireAction::Reply(format!(
                    "OK\tSAFE_POINT\t{}\t{}",
                    artifact.sha256, artifact.size
                )))
            }
            WireRequest::Export => {
                let transfer = self.source_export()?;
                let encoded = transfer.encode_json()?;
                Ok(WireAction::Exported {
                    response: format!("OK\tEXPORT\t{}\t{}", sha256_hex(&encoded), encoded.len()),
                    transfer: Box::new(transfer),
                })
            }
            WireRequest::Resume => {
                self.resume_destination()?;
                Ok(WireAction::Reply("OK\tRESUME".to_owned()))
            }
            WireRequest::Shutdown => Ok(WireAction::Shutdown("OK\tSHUTDOWN".to_owned())),
            WireRequest::Open(call) => {
                let event = self.open_event(&call)?;
                Ok(WireAction::Reply(event))
            }
            WireRequest::Operation(call) => {
                let event = self.execute_wire_operation(call)?;
                Ok(WireAction::Reply(event))
            }
        }
    }

    pub fn serve_unix(&mut self, socket: &Path) -> Result<ServiceExit, String> {
        if socket.exists() {
            return Err(format!(
                "refusing to replace existing endpoint socket {}",
                socket.display()
            ));
        }
        if let Some(parent) = socket.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create endpoint socket parent: {error}"))?;
        }
        let listener = UnixListener::bind(socket).map_err(|error| {
            format!("cannot bind endpoint socket {}: {error}", socket.display())
        })?;
        let result = self.serve_listener(&listener);
        drop(listener);
        fs::remove_file(socket).map_err(|error| {
            format!("cannot remove endpoint socket {}: {error}", socket.display())
        })?;
        result
    }

    fn serve_listener(&mut self, listener: &UnixListener) -> Result<ServiceExit, String> {
        loop {
            let (mut stream, _) =
                listener.accept().map_err(|error| format!("endpoint accept failed: {error}"))?;
            let line = read_wire_line(&mut stream)?;
            match self.handle_wire_line(&line) {
                Ok(WireAction::Reply(response)) => write_wire_line(&mut stream, &response)?,
                Ok(WireAction::Exported { response, transfer }) => {
                    write_wire_line(&mut stream, &response)?;
                    return Ok(ServiceExit::Exported(transfer));
                }
                Ok(WireAction::Shutdown(response)) => {
                    write_wire_line(&mut stream, &response)?;
                    return Ok(ServiceExit::Shutdown);
                }
                Err(error) => {
                    write_wire_line(&mut stream, &format!("ERROR\tcontrol\t{error}"))?;
                }
            }
        }
    }

    fn open_event(&mut self, call: &WireCallContext) -> Result<String, String> {
        if let Err(error) = self.validate_call_context(call) {
            let event = wire_open_error(call, "lost-binding");
            self.record_failed_call(FailedCall {
                call,
                operation_kind: "open",
                operation: None,
                workload_key: "",
                attempt: 0,
                event: &event,
                error,
            })?;
            return Ok(event);
        }
        let probe = self.state_probe()?;
        let native =
            native_receipt(self.coordinator.state().activation.node, &self.root, &self.file_path)?;
        let state = canonical_regular_file(self.coordinator.state())?;
        let content = fs::read(&self.file_path)
            .map_err(|error| format!("cannot inspect endpoint file: {error}"))?;
        let event = format!(
            "OPEN\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            call.progress,
            if self.role == EndpointRole::Source { "initial" } else { "visa-rebind" },
            native.file_device,
            native.file_inode,
            state.logical_offset,
            native.file_size,
            native.file_mode,
            native.file_link_count,
            hex_encode(&content),
        );
        self.receipt.operations.push(CanonicalOperationReceipt {
            role: call.role,
            workload: call.workload,
            progress: call.progress,
            is_start: call.is_start,
            operation_kind: "open".to_owned(),
            operation: None,
            workload_key: String::new(),
            attempt: 0,
            canonical_operation: None,
            replayed: false,
            result: None,
            error: None,
            raw_event: event.clone(),
            before: probe.clone(),
            after: probe,
        });
        Ok(event)
    }

    fn execute_wire_operation(&mut self, call: WireOperationCall) -> Result<String, String> {
        if let Err(error) = self.validate_call_context(&call.context) {
            let kind = call.operation.kind_name();
            let event = wire_error(
                &call.context,
                &call.workload_key,
                call.attempt,
                &call.operation,
                "lost-binding",
            );
            self.record_failed_call(FailedCall {
                call: &call.context,
                operation_kind: kind,
                operation: Some(call.operation.to_profile()),
                workload_key: &call.workload_key,
                attempt: call.attempt,
                event: &event,
                error,
            })?;
            return Ok(event);
        }
        let before = self.state_probe()?;
        let before_position = self.coordinator.journal_position();
        let binding =
            ProfileBinding::for_state(self.coordinator.state(), REGULAR_FILE_EXTENSION_ID)
                .map_err(binding_error)?;
        let operation = call.operation.to_profile();
        let payload = encode_regular_file_operation(&operation).map_err(profile_payload_error)?;
        let profile_call = match &operation {
            RegularFileOperation::Read { .. } => {
                profile_observe(&mut self.coordinator, &binding, payload)
            }
            _ => profile_execute(
                &mut self.coordinator,
                &binding,
                call.operation.access(),
                call.workload_key.as_bytes(),
                payload,
            ),
        };
        let profile_call = match profile_call {
            Ok(result) => result,
            Err(error) => {
                let detail = format!("canonical profile call failed: {error:?}");
                let event = wire_error(
                    &call.context,
                    &call.workload_key,
                    call.attempt,
                    &call.operation,
                    "canonical-profile",
                );
                self.record_failed_call(FailedCall {
                    call: &call.context,
                    operation_kind: call.operation.kind_name(),
                    operation: Some(operation.clone()),
                    workload_key: &call.workload_key,
                    attempt: call.attempt,
                    event: &event,
                    error: detail,
                })?;
                return Ok(event);
            }
        };
        let result =
            decode_regular_file_result(&profile_call.payload).map_err(profile_payload_error)?;
        let after = self.state_probe()?;
        let replayed = self.coordinator.journal_position() == before_position;
        let native =
            native_receipt(self.coordinator.state().activation.node, &self.root, &self.file_path)?;
        let content = fs::read(&self.file_path)
            .map_err(|error| format!("cannot inspect endpoint file after operation: {error}"))?;
        let event = operation_event(OperationEventInput {
            call: &call,
            profile_call: &profile_call,
            result: &result,
            before: &before.profile_state,
            after: &after.profile_state,
            native: &native,
            content: &content,
            replayed,
        })?;
        self.receipt.operations.push(CanonicalOperationReceipt {
            role: call.context.role,
            workload: call.context.workload,
            progress: call.context.progress,
            is_start: call.context.is_start,
            operation_kind: call.operation.kind_name().to_owned(),
            operation: Some(operation),
            workload_key: call.workload_key,
            attempt: call.attempt,
            canonical_operation: Some(profile_call.operation),
            replayed,
            result: Some(result),
            error: None,
            raw_event: event.clone(),
            before,
            after,
        });
        Ok(event)
    }

    fn validate_call_context(&self, call: &WireCallContext) -> Result<(), String> {
        if call.role != self.role {
            return Err(format!(
                "{} binding is unavailable on {} endpoint",
                call.role.name(),
                self.role.name()
            ));
        }
        if call.workload != self.workload {
            return Err("wire workload does not match endpoint workload".to_owned());
        }
        let ready = match self.role {
            EndpointRole::Source => self.phase == EndpointPhase::Running,
            EndpointRole::Destination => self.phase == EndpointPhase::Resumed,
        };
        if !ready {
            return Err(format!(
                "{} endpoint has not published an active profile binding",
                self.role.name()
            ));
        }
        Ok(())
    }

    fn record_failed_call(&mut self, failed: FailedCall<'_>) -> Result<(), String> {
        let FailedCall { call, operation_kind, operation, workload_key, attempt, event, error } =
            failed;
        let probe = self.state_probe()?;
        self.receipt.operations.push(CanonicalOperationReceipt {
            role: call.role,
            workload: call.workload,
            progress: call.progress,
            is_start: call.is_start,
            operation_kind: operation_kind.to_owned(),
            operation,
            workload_key: workload_key.to_owned(),
            attempt,
            canonical_operation: None,
            replayed: false,
            result: None,
            error: Some(error),
            raw_event: event.to_owned(),
            before: probe.clone(),
            after: probe,
        });
        Ok(())
    }

    fn push_lifecycle(
        &mut self,
        action: &str,
        protocol_action: Option<ProtocolAction>,
        result: Option<GenericCallResult>,
        command: Option<Identity>,
        receipt: Option<&CommandReceipt>,
        artifacts: Vec<ArtifactDigestReceipt>,
    ) -> Result<(), String> {
        self.receipt.lifecycle.push(LifecycleReceipt {
            action: action.to_owned(),
            protocol_action,
            result,
            command,
            coordinator_receipt: receipt.map(Into::into),
            artifacts,
            state: self.state_probe()?,
        });
        Ok(())
    }

    fn state_probe(&self) -> Result<CanonicalStateProbe, String> {
        let state = self.coordinator.state();
        let profile_state = canonical_regular_file(state)?;
        let file_lease = self
            .coordinator
            .provider()
            .current_lease(self.ids.file)
            .map_err(provider_error)?
            .map(Into::into);
        let destination_binding = self
            .coordinator
            .provider()
            .binding(self.ids.snapshot, self.ids.file)
            .map_err(provider_error)?;
        Ok(CanonicalStateProbe {
            journal_position: self.coordinator.journal_position(),
            state_digest: self.coordinator.state_digest().map_err(runtime_error)?,
            phase: state.phase,
            activation_role: state.activation.role,
            activation_status: state.activation.status,
            activation_node: state.activation.node,
            owner: state.ownership.owner,
            lease_epoch: state.ownership.epoch,
            file_lease,
            destination_binding,
            operation_ledger: state.operations.clone(),
            profile_state,
        })
    }
}

pub enum ServiceExit {
    Exported(Box<CanonicalTransfer>),
    Shutdown,
}

pub enum WireAction {
    Reply(String),
    Exported { response: String, transfer: Box<CanonicalTransfer> },
    Shutdown(String),
}

#[derive(Clone, Debug)]
struct WireCallContext {
    role: EndpointRole,
    workload: CanonicalWorkload,
    progress: i32,
    is_start: bool,
}

#[derive(Clone, Debug)]
struct WireOperationCall {
    context: WireCallContext,
    workload_key: String,
    attempt: u32,
    operation: WireOperation,
}

struct FailedCall<'a> {
    call: &'a WireCallContext,
    operation_kind: &'a str,
    operation: Option<RegularFileOperation>,
    workload_key: &'a str,
    attempt: u32,
    event: &'a str,
    error: String,
}

#[derive(Clone, Debug)]
enum WireOperation {
    Read { max_bytes: u32 },
    Write { bytes: Vec<u8>, durability: FileDurability },
    Append { bytes: Vec<u8>, durability: FileDurability },
}

impl WireOperation {
    const fn kind_name(&self) -> &'static str {
        match self {
            Self::Read { .. } => "read",
            Self::Write { .. } => "write",
            Self::Append { .. } => "append",
        }
    }

    const fn access(&self) -> ProfileAccess {
        match self {
            Self::Read { .. } => ProfileAccess::Read,
            Self::Write { .. } | Self::Append { .. } => ProfileAccess::Write,
        }
    }

    fn to_profile(&self) -> RegularFileOperation {
        match self {
            Self::Read { max_bytes } => RegularFileOperation::Read { max_bytes: *max_bytes },
            Self::Write { bytes, durability } => {
                RegularFileOperation::Write { bytes: bytes.clone(), durability: *durability }
            }
            Self::Append { bytes, durability } => {
                RegularFileOperation::Append { bytes: bytes.clone(), durability: *durability }
            }
        }
    }

    fn error_fields(&self) -> (&'static str, String, &'static str) {
        match self {
            Self::Read { max_bytes } => ("read", max_bytes.to_string(), "-"),
            Self::Write { bytes, durability } => {
                ("write", hex_encode(bytes), durability_name(*durability))
            }
            Self::Append { bytes, durability } => {
                ("append", hex_encode(bytes), durability_name(*durability))
            }
        }
    }
}

enum WireRequest {
    SafePoint,
    Export,
    Resume,
    Shutdown,
    Open(WireCallContext),
    Operation(WireOperationCall),
}

impl WireRequest {
    fn parse(line: &str) -> Result<Self, String> {
        let fields = line.trim_end_matches(['\r', '\n']).split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["SAFE_POINT"] => Ok(Self::SafePoint),
            ["EXPORT"] => Ok(Self::Export),
            ["RESUME"] => Ok(Self::Resume),
            ["SHUTDOWN"] => Ok(Self::Shutdown),
            ["OPEN", role, workload, progress, is_start] => Ok(Self::Open(WireCallContext {
                role: EndpointRole::parse(role)?,
                workload: CanonicalWorkload::parse(workload)?,
                progress: parse_i32(progress, "progress")?,
                is_start: parse_bool(is_start, "is_start")?,
            })),
            [
                tag @ ("READ" | "WRITE" | "APPEND"),
                role,
                workload,
                progress,
                is_start,
                key,
                attempt,
                value,
                tail @ ..,
            ] => {
                if key.is_empty() {
                    return Err("wire workload key is empty".to_owned());
                }
                let context = WireCallContext {
                    role: EndpointRole::parse(role)?,
                    workload: CanonicalWorkload::parse(workload)?,
                    progress: parse_i32(progress, "progress")?,
                    is_start: parse_bool(is_start, "is_start")?,
                };
                let attempt = parse_u32(attempt, "attempt")?;
                let operation = match *tag {
                    "READ" if tail.is_empty() => {
                        WireOperation::Read { max_bytes: parse_u32(value, "max_bytes")? }
                    }
                    "WRITE" | "APPEND" if tail.len() == 1 => {
                        let bytes = hex_decode(value)?;
                        let durability = parse_durability(tail[0])?;
                        if *tag == "WRITE" {
                            WireOperation::Write { bytes, durability }
                        } else {
                            WireOperation::Append { bytes, durability }
                        }
                    }
                    _ => return Err("wire operation has an invalid field count".to_owned()),
                };
                Ok(Self::Operation(WireOperationCall {
                    context,
                    workload_key: (*key).to_owned(),
                    attempt,
                    operation,
                }))
            }
            _ => Err("unknown or malformed canonical endpoint request".to_owned()),
        }
    }
}

struct ValidatedTransfer {
    snapshot: visa_runtime::ValidatedSnapshot,
    portable: PortableRegularFileState,
    regular_file: RegularFileState,
    profile_digest: Digest,
}

fn validate_transfer(
    config: &DestinationEndpointConfig,
    transfer: &CanonicalTransfer,
) -> Result<ValidatedTransfer, String> {
    validate_transfer_shape(transfer)?;
    if transfer.cell_id != config.cell_id || transfer.workload != config.workload {
        return Err("canonical transfer cell or workload mismatch".to_owned());
    }
    let ids = EndpointIds::for_cell(&config.cell_id);
    let profile_digest = profile_digest()?;
    let snapshot = &transfer.snapshot;
    if snapshot.body.source_node != ids.source_node
        || snapshot.body.component != ids.source_component
        || snapshot.body.snapshot.handoff != ids.handoff
        || snapshot.body.snapshot.snapshot != ids.snapshot
        || snapshot.body.source_lease_epoch != INITIAL_LEASE_EPOCH
        || snapshot.body.component_digest != config.component_digest
        || snapshot.body.profile_digest != profile_digest
        || snapshot.body.profile_version != SchemaVersion::new(1, 0)
        || snapshot.body.claims.timer.resource != ids.timer
        || snapshot.body.claims.key_value.resource != ids.key_value
        || snapshot.body.claims.key_value.namespace != ids.key_value_namespace
        || snapshot.body.portable_state != transfer.portable_state
    {
        return Err("canonical transfer snapshot identity or profile mismatch".to_owned());
    }
    if snapshot.body.extensions.len() != 1
        || snapshot.body.extensions[0].id != REGULAR_FILE_EXTENSION_ID
        || snapshot.body.extensions[0].version != REGULAR_FILE_EXTENSION_VERSION
    {
        return Err("canonical transfer regular-file extension exact set mismatch".to_owned());
    }
    let regular_file =
        regular_file_state(&snapshot.body.extensions[0]).map_err(profile_payload_error)?;
    validate_storage_image(&regular_file, &transfer.storage_image)?;
    let portable = PortableRegularFileState::try_from_bytes(transfer.portable_state.clone())
        .map_err(codec_error)?;
    let decoded = portable.decode().map_err(codec_error)?;
    if decoded.phase != RegularFileWorkloadPhase::Frozen {
        return Err("canonical transfer portable state is not frozen".to_owned());
    }
    decoded.validate_canonical(&regular_file).map_err(codec_error)?;
    validate_source_authorities(snapshot, &ids)?;
    let validated = validate_snapshot(
        snapshot,
        &SnapshotExpectations {
            component_digest: config.component_digest,
            profile_digest,
            profile_version: SchemaVersion::new(1, 0),
            supported_extensions: vec![ExtensionSupport {
                id: REGULAR_FILE_EXTENSION_ID,
                version: REGULAR_FILE_EXTENSION_VERSION,
            }],
            destination: ids.destination_node,
        },
    )
    .map_err(runtime_error)?;
    Ok(ValidatedTransfer { snapshot: validated, portable, regular_file, profile_digest })
}

fn validate_transfer_shape(transfer: &CanonicalTransfer) -> Result<(), String> {
    if transfer.schema != TRANSFER_SCHEMA {
        return Err("canonical transfer schema mismatch".to_owned());
    }
    validate_cell_id(&transfer.cell_id)?;
    if transfer.storage_image_sha256 != sha256_hex(&transfer.storage_image) {
        return Err("canonical transfer storage image digest mismatch".to_owned());
    }
    Ok(())
}

fn validate_storage_image(state: &RegularFileState, image: &[u8]) -> Result<(), String> {
    let size = u64::try_from(image.len()).map_err(|_| "storage image size does not fit u64")?;
    if state.size != size
        || state.content_digest
            != canonical_digest(&image.to_vec())
                .map_err(|error| format!("cannot digest storage image: {error:?}"))?
    {
        return Err("storage image does not match canonical regular-file state".to_owned());
    }
    Ok(())
}

fn validate_source_authorities(
    snapshot: &SnapshotEnvelope,
    ids: &EndpointIds,
) -> Result<(), String> {
    let expected = source_authorities(ids);
    if snapshot.body.authorities.len() != expected.len()
        || expected.iter().any(|authority| !snapshot.body.authorities.contains(authority))
    {
        return Err("snapshot source authority exact set mismatch".to_owned());
    }
    Ok(())
}

fn canonical_source_state(
    ids: &EndpointIds,
    component_digest: Digest,
    profile_digest: Digest,
    regular_file: RegularFileState,
    authorities: Vec<AuthorityGrant>,
) -> Result<CanonicalState, String> {
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
    let extension = regular_file_extension(&regular_file).map_err(profile_payload_error)?;
    Ok(CanonicalState::dormant_with_extensions(
        ids.source_component,
        ids.source_node,
        component_digest,
        profile_digest,
        SchemaVersion::new(1, 0),
        claims,
        authorities,
        vec![extension],
    ))
}

fn initial_regular_file(
    ids: &EndpointIds,
    initial_content: &[u8],
) -> Result<RegularFileState, String> {
    Ok(RegularFileState {
        claim: RegularFileClaim {
            resource: ids.file,
            namespace: ids.file_namespace,
            relative_path: RELATIVE_FILE.to_vec(),
            required_rights: profile_rights(),
            access_mode: FileAccessMode::ReadWrite,
            durability: FileDurability::Visible,
            lock_policy: FileLockPolicy::ExclusiveLease,
            max_size: visa_profile::MAX_REGULAR_FILE_BYTES,
        },
        logical_offset: 0,
        version: 1,
        size: u64::try_from(initial_content.len())
            .map_err(|_| "initial content size does not fit u64")?,
        content_digest: canonical_digest(&initial_content.to_vec())
            .map_err(|error| format!("cannot digest initial content: {error:?}"))?,
        durable_through: FileDurability::Visible,
        lock_state: FileLockState::Unlocked,
        disposition: ContinuityDisposition::Revalidate,
        last_operation: None,
    })
}

fn source_authorities(ids: &EndpointIds) -> Vec<AuthorityGrant> {
    vec![
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
            ids.source_file_authority,
            ids.source_component,
            ids.file,
            profile_rights(),
        ),
    ]
}

fn install_source_material(
    provider: &mut SqliteProvider,
    ids: &EndpointIds,
    regular_file: &RegularFileState,
    root: &Path,
    authorities: &[AuthorityGrant],
) -> Result<(), String> {
    for (resource, rights) in [
        (ids.source_component, Rights::HANDOFF),
        (ids.timer, timer_rights()),
        (ids.key_value, key_value_rights()),
        (ids.file, profile_rights()),
    ] {
        provider
            .install_policy(AuthorityPolicy {
                subject: ids.source_component,
                resource,
                allowed_rights: rights,
            })
            .map_err(provider_error)?;
    }
    for authority in authorities {
        provider.install_grant(authority).map_err(provider_error)?;
    }
    provider
        .provision_key_value_namespace(ids.key_value, ids.key_value_namespace)
        .map_err(provider_error)?;
    provider.provision_regular_file(regular_file, root).map_err(provider_error)
}

fn install_destination_material(
    provider: &mut SqliteProvider,
    ids: &EndpointIds,
    snapshot: &SnapshotEnvelope,
    regular_file: &RegularFileState,
    root: &Path,
) -> Result<(), String> {
    for (subject, resource, rights) in [
        (ids.source_component, ids.source_component, Rights::HANDOFF),
        (ids.source_component, ids.timer, timer_rights()),
        (ids.source_component, ids.key_value, key_value_rights()),
        (ids.source_component, ids.file, profile_rights()),
        (ids.destination_component, ids.destination_component, Rights::HANDOFF),
        (ids.destination_component, ids.timer, timer_rights()),
        (ids.destination_component, ids.key_value, key_value_rights()),
        (ids.destination_component, ids.file, profile_rights()),
    ] {
        provider
            .install_policy(AuthorityPolicy { subject, resource, allowed_rights: rights })
            .map_err(provider_error)?;
    }
    for authority in &snapshot.body.authorities {
        provider.install_grant(authority).map_err(provider_error)?;
    }
    provider
        .provision_key_value_namespace(ids.key_value, ids.key_value_namespace)
        .map_err(provider_error)?;
    provider.provision_regular_file(regular_file, root).map_err(provider_error)?;
    for resource in [ids.timer, ids.key_value, ids.file] {
        provider
            .initialize_lease(LeaseRecord {
                resource,
                owner: ids.source_node,
                epoch: INITIAL_LEASE_EPOCH,
            })
            .map_err(provider_error)?;
    }
    Ok(())
}

fn profile_digest() -> Result<Digest, String> {
    let profile = CooperativeHandoffProfile::v1(vec![ExtensionSupport {
        id: REGULAR_FILE_EXTENSION_ID,
        version: REGULAR_FILE_EXTENSION_VERSION,
    }]);
    canonical_digest(&profile).map_err(runtime_error)
}

fn canonical_regular_file(state: &CanonicalState) -> Result<RegularFileState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension =
        matching.next().ok_or_else(|| "canonical regular-file extension is missing".to_owned())?;
    if matching.next().is_some() {
        return Err("canonical regular-file extension is ambiguous".to_owned());
    }
    regular_file_state(extension).map_err(profile_payload_error)
}

struct OperationEventInput<'a> {
    call: &'a WireOperationCall,
    profile_call: &'a visa_component_adapter::ProfileCallResult,
    result: &'a RegularFileResult,
    before: &'a RegularFileState,
    after: &'a RegularFileState,
    native: &'a NativeObjectReceipt,
    content: &'a [u8],
    replayed: bool,
}

fn operation_event(input: OperationEventInput<'_>) -> Result<String, String> {
    let OperationEventInput {
        call,
        profile_call,
        result,
        before,
        after,
        native,
        content,
        replayed,
    } = input;
    match (&call.operation, result) {
        (
            WireOperation::Read { max_bytes },
            RegularFileResult::Read { bytes, logical_offset, .. },
        ) => Ok(format!(
            "READ\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            call.context.progress,
            call.workload_key,
            call.attempt,
            before.logical_offset,
            logical_offset,
            max_bytes,
            after.size,
            native.file_device,
            native.file_inode,
            hex_encode(bytes),
            hex_encode(content),
        )),
        (WireOperation::Write { bytes, .. }, RegularFileResult::Mutated { logical_offset, .. }) => {
            Ok(format!(
                "WRITE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                call.context.progress,
                call.workload_key,
                call.attempt,
                before.logical_offset,
                logical_offset,
                after.size,
                native.file_device,
                native.file_inode,
                hex_encode(bytes),
                hex_encode(content),
            ))
        }
        (
            WireOperation::Append { bytes, .. },
            RegularFileResult::Mutated { logical_offset, .. },
        ) => Ok(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            if replayed { "APPEND_REPLAY" } else { "APPEND" },
            call.context.progress,
            call.workload_key,
            call.attempt,
            before.logical_offset,
            logical_offset,
            after.size,
            native.file_device,
            native.file_inode,
            hex_encode(bytes),
            hex_encode(content),
        )),
        _ => Err(format!(
            "profile call {} returned an incompatible result for {}",
            identity_string(profile_call.operation),
            call.operation.kind_name()
        )),
    }
}

fn wire_error(
    call: &WireCallContext,
    workload_key: &str,
    attempt: u32,
    operation: &WireOperation,
    stage: &str,
) -> String {
    let (operation_kind, request_value, durability) = operation.error_fields();
    format!(
        "ERROR\t{}\t{}\t{}\t{}\t{}\t5\t0\t{}\t{}",
        call.progress, workload_key, attempt, operation_kind, stage, request_value, durability,
    )
}

fn wire_open_error(call: &WireCallContext, stage: &str) -> String {
    format!("BINDING_ERROR\t{}\t{}\t5", call.progress, stage)
}

fn create_endpoint_file(root: &Path, bytes: &[u8]) -> Result<(PathBuf, PathBuf), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create endpoint file root {}: {error}", root.display()))?;
    let root = fs::canonicalize(root).map_err(|error| {
        format!("cannot canonicalize endpoint root {}: {error}", root.display())
    })?;
    let file_path = root.join("data.bin");
    write_new(&file_path, bytes, "endpoint regular file")?;
    Ok((root, file_path))
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {label} {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {label} {}: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("cannot sync {label} {}: {error}", path.display()))
}

fn ensure_new_database(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "canonical endpoint requires a fresh provider database: {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create provider database parent: {error}"))?;
    }
    Ok(())
}

fn native_receipt(
    node: NodeIdentity,
    root: &Path,
    file: &Path,
) -> Result<NativeObjectReceipt, String> {
    let root_metadata = fs::metadata(root)
        .map_err(|error| format!("cannot inspect endpoint root {}: {error}", root.display()))?;
    let file_metadata = fs::metadata(file)
        .map_err(|error| format!("cannot inspect endpoint file {}: {error}", file.display()))?;
    let bytes = fs::read(file)
        .map_err(|error| format!("cannot read endpoint file {}: {error}", file.display()))?;
    Ok(NativeObjectReceipt {
        node,
        root_path: root.to_string_lossy().into_owned(),
        root_device: root_metadata.dev(),
        root_inode: root_metadata.ino(),
        file_device: file_metadata.dev(),
        file_inode: file_metadata.ino(),
        file_mode: file_metadata.mode(),
        file_link_count: file_metadata.nlink(),
        file_size: file_metadata.size(),
        file_sha256: sha256_hex(&bytes),
    })
}

fn read_wire_line(stream: &mut UnixStream) -> Result<String, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let size = reader
        .by_ref()
        .take((MAX_WIRE_LINE + 1) as u64)
        .read_line(&mut line)
        .map_err(|error| format!("cannot read endpoint request: {error}"))?;
    if size == 0 || size > MAX_WIRE_LINE {
        return Err("endpoint request is empty or exceeds the wire bound".to_owned());
    }
    Ok(line)
}

fn write_wire_line(stream: &mut UnixStream, line: &str) -> Result<(), String> {
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|error| format!("cannot write endpoint response: {error}"))
}

fn validate_cell_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid canonical endpoint cell ID".to_owned());
    }
    Ok(())
}

fn parse_i32(value: &str, label: &str) -> Result<i32, String> {
    value.parse().map_err(|_| format!("wire {label} is not an i32"))
}

fn parse_u32(value: &str, label: &str) -> Result<u32, String> {
    value.parse().map_err(|_| format!("wire {label} is not a u32"))
}

fn parse_bool(value: &str, label: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("wire {label} must be 0 or 1")),
    }
}

fn parse_durability(value: &str) -> Result<FileDurability, String> {
    match value {
        "visible" => Ok(FileDurability::Visible),
        "data" => Ok(FileDurability::Data),
        "data-and-metadata" => Ok(FileDurability::DataAndMetadata),
        _ => Err(format!("unknown file durability {value:?}")),
    }
}

const fn durability_name(value: FileDurability) -> &'static str {
    match value {
        FileDurability::Visible => "visible",
        FileDurability::Data => "data",
        FileDurability::DataAndMetadata => "data-and-metadata",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || value.len() > visa_profile::MAX_REGULAR_FILE_BYTES as usize * 2
    {
        return Err("wire hex payload has an invalid size".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("wire payload is not hexadecimal".to_owned()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_encode(&digest.finalize())
}

fn derive_identity(cell_id: &str, label: &str) -> Identity {
    let mut digest = Sha256::new();
    digest.update(ID_DOMAIN);
    digest.update((cell_id.len() as u64).to_be_bytes());
    digest.update(cell_id.as_bytes());
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label.as_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    Identity::from_bytes(identity)
}

fn entity(cell_id: &str, label: &str) -> EntityRef {
    EntityRef::initial(derive_identity(cell_id, label))
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

fn command_result(receipt: &CommandReceipt) -> Result<GenericCallResult, String> {
    let projected = CanonicalCommandReceipt::from(receipt);
    let bytes = serde_json::to_vec(&projected)
        .map_err(|error| format!("cannot encode coordinator command receipt: {error}"))?;
    Ok(GenericCallResult::Returned { bytes })
}

fn runtime_error(error: impl core::fmt::Debug) -> String {
    format!("canonical coordinator error: {error:?}")
}

fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("canonical provider error {:?} (retryable={})", error.kind, error.retryable)
}

fn binding_error(error: impl core::fmt::Debug) -> String {
    format!("canonical profile binding error: {error:?}")
}

fn codec_error(error: impl core::fmt::Debug) -> String {
    format!("canonical portable-state codec error: {error:?}")
}

fn profile_payload_error(error: impl core::fmt::Debug) -> String {
    format!("canonical regular-file payload error: {error:?}")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead as _, BufReader, Write as _},
        os::unix::net::UnixStream,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TestTree {
        root: PathBuf,
    }

    impl TestTree {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("visa-wanco-canonical-{label}-{}-{sequence}", std::process::id()));
            fs::create_dir(&root).expect("test tree root is new");
            Self { root }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn component_digest() -> Digest {
        canonical_digest(&b"wanco-canonical-test-component".to_vec())
            .expect("test component digest")
    }

    fn source_config(
        tree: &TestTree,
        cell_id: &str,
        workload: CanonicalWorkload,
        initial_content: &[u8],
    ) -> SourceEndpointConfig {
        SourceEndpointConfig {
            cell_id: cell_id.to_owned(),
            route: "control".to_owned(),
            workload,
            database: tree.path("source.sqlite"),
            file_root: tree.path("source-binding-secret"),
            component_digest: component_digest(),
            session_id: format!("{cell_id}-session"),
            initial_content: initial_content.to_vec(),
        }
    }

    fn destination_config(
        tree: &TestTree,
        cell_id: &str,
        workload: CanonicalWorkload,
        suffix: &str,
    ) -> DestinationEndpointConfig {
        DestinationEndpointConfig {
            cell_id: cell_id.to_owned(),
            route: "visa-plus-carrier".to_owned(),
            workload,
            database: tree.path(&format!("destination-{suffix}.sqlite")),
            file_root: tree.path(&format!("destination-{suffix}-binding-secret")),
            component_digest: component_digest(),
            session_id: format!("{cell_id}-session"),
        }
    }

    fn reply(endpoint: &mut CanonicalEndpoint, request: &str) -> String {
        match endpoint.handle_wire_line(request).expect("wire request succeeds structurally") {
            WireAction::Reply(response) => response,
            WireAction::Exported { .. } => panic!("operation unexpectedly exported"),
            WireAction::Shutdown(_) => panic!("operation unexpectedly shut down"),
        }
    }

    fn socket_request(socket: &Path, request: &str) -> String {
        let mut stream = loop {
            match UnixStream::connect(socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    thread::yield_now();
                }
                Err(error) => panic!("cannot connect test endpoint socket: {error}"),
            }
        };
        stream.write_all(request.as_bytes()).expect("write socket request");
        stream.write_all(b"\n").expect("terminate socket request");
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).expect("read socket response");
        response.trim_end().to_owned()
    }

    #[test]
    fn read_write_handoff_uses_canonical_profile_and_fresh_destination() {
        let tree = TestTree::new("read-write");
        let cell = "read-write-handoff";
        let source_database = tree.path("source.sqlite");
        let mut source = CanonicalEndpoint::initialize_source(source_config(
            &tree,
            cell,
            CanonicalWorkload::ReadWriteOffset,
            b"abcdef",
        ))
        .expect("source endpoint initializes");

        let opened = reply(&mut source, "OPEN\tsource\tread-write-offset\t0\t1");
        assert!(opened.starts_with("OPEN\t0\tinitial\t"));
        let read = reply(&mut source, "READ\tsource\tread-write-offset\t0\t1\tread-prefix\t0\t2");
        assert!(read.starts_with("READ\t0\tread-prefix\t0\t0\t2\t2\t6\t"));
        let write = reply(
            &mut source,
            "WRITE\tsource\tread-write-offset\t1\t0\twrite-middle\t0\t5859\tvisible",
        );
        assert!(write.starts_with("WRITE\t1\twrite-middle\t0\t2\t4\t6\t"));
        assert_eq!(fs::read(&source.file_path).expect("source file"), b"abXYef");
        assert_eq!(source.receipt.operations.len(), 3);
        assert_eq!(source.receipt.operations[0].operation_kind, "open");
        assert!(source.receipt.operations[0].error.is_none());
        assert!(matches!(
            source.receipt.operations[1].result,
            Some(RegularFileResult::Read {
                ref bytes,
                logical_offset: 2,
                ..
            }) if bytes == b"ab"
        ));
        assert!(matches!(
            source.receipt.operations[2].result,
            Some(RegularFileResult::Mutated { logical_offset: 4, version: 2, size: 6, .. })
        ));

        let source_native = source.receipt.native_object.clone();
        let portable_artifact = source.source_safe_point().expect("source safe point");
        let blocked_source =
            reply(&mut source, "READ\tsource\tread-write-offset\t4\t0\tblocked-source\t0\t2");
        assert_eq!(blocked_source, "ERROR\t4\tblocked-source\t0\tread\tlost-binding\t5\t0\t2\t-");
        let transfer = source.source_export().expect("source snapshot export");
        assert!(source_database.exists());
        assert_eq!(transfer.storage_image, b"abXYef");
        assert_eq!(portable_artifact.sha256, sha256_hex(&transfer.portable_state));

        let lifecycle = source
            .receipt
            .lifecycle
            .iter()
            .map(|receipt| receipt.action.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            lifecycle,
            [
                "source_activate",
                "source_begin_quiesce",
                "source_prepare_safe_point",
                "source_freeze_runtime",
                "source_commit_safe_point",
                "source_export_snapshot",
            ]
        );
        for receipt in source.receipt.lifecycle.iter().skip(1) {
            assert!(receipt.protocol_action.is_some(), "{} lacks protocol action", receipt.action);
            assert!(
                matches!(receipt.result, Some(GenericCallResult::Returned { .. })),
                "{} lacks actual returned result",
                receipt.action
            );
        }
        let freeze = source
            .receipt
            .lifecycle
            .iter()
            .find(|receipt| receipt.action == "source_freeze_runtime")
            .expect("freeze receipt");
        assert!(matches!(
            freeze.result,
            Some(GenericCallResult::Returned { ref bytes }) if bytes == &transfer.portable_state
        ));

        let transfer_json = transfer.encode_json().expect("transfer encoding");
        let snapshot_json = serde_json::to_vec(&transfer.snapshot).expect("snapshot encoding");
        for forbidden in
            [source.root.to_string_lossy().as_bytes(), source_database.to_string_lossy().as_bytes()]
        {
            assert!(!contains_bytes(&transfer_json, forbidden));
            assert!(!contains_bytes(&snapshot_json, forbidden));
            assert!(!contains_bytes(&transfer.portable_state, forbidden));
        }
        let transfer_text =
            String::from_utf8(transfer_json.clone()).expect("transfer JSON is UTF-8");
        let snapshot_text = String::from_utf8(snapshot_json).expect("snapshot JSON is UTF-8");
        for forbidden in ["root_path", "root_device", "root_inode", "file_device", "file_inode"] {
            assert!(!transfer_text.contains(forbidden));
            assert!(!snapshot_text.contains(forbidden));
        }
        let decoded_portable =
            PortableRegularFileState::try_from_bytes(transfer.portable_state.clone())
                .expect("portable shape")
                .decode()
                .expect("portable decode");
        assert_eq!(decoded_portable.session_id, format!("{cell}-session"));
        assert_eq!(decoded_portable.phase, RegularFileWorkloadPhase::Frozen);
        assert_eq!(decoded_portable.logical_offset, 4);

        let destination_database = tree.path("destination-main.sqlite");
        let mut destination = CanonicalEndpoint::restore_destination(
            destination_config(&tree, cell, CanonicalWorkload::ReadWriteOffset, "main"),
            &transfer,
        )
        .expect("fresh destination restores and commits");
        assert!(destination_database.exists());
        assert_ne!(source_database, destination_database);
        assert_ne!(source.root, destination.root);
        assert_ne!(source_native.root_inode, destination.receipt.native_object.root_inode);
        assert_ne!(source_native.file_inode, destination.receipt.native_object.file_inode);
        assert_eq!(
            fs::read(&destination.file_path).expect("destination file"),
            transfer.storage_image
        );
        assert_eq!(destination.receipt.native_object.file_sha256, transfer.storage_image_sha256);

        let blocked_destination = reply(
            &mut destination,
            "READ\tdestination\tread-write-offset\t12\t0\tblocked-destination\t0\t4",
        );
        assert_eq!(
            blocked_destination,
            "ERROR\t12\tblocked-destination\t0\tread\tlost-binding\t5\t0\t4\t-"
        );
        destination.resume_destination().expect("destination resumes");
        let resumed_read = reply(
            &mut destination,
            "READ\tdestination\tread-write-offset\t12\t0\tread-suffix\t0\t8",
        );
        assert!(resumed_read.ends_with("\t6566\t616258596566"));
        assert!(matches!(
            destination.receipt.operations.last().and_then(|receipt| receipt.result.as_ref()),
            Some(RegularFileResult::Read {
                bytes,
                logical_offset: 6,
                ..
            }) if bytes == b"ef"
        ));
        let destination_protocol = destination
            .receipt
            .lifecycle
            .iter()
            .filter_map(|receipt| receipt.protocol_action.as_ref())
            .collect::<Vec<_>>();
        assert!(
            destination_protocol
                .iter()
                .any(|action| { matches!(action, ProtocolAction::PrepareDestination { .. }) })
        );
        assert!(
            destination_protocol
                .iter()
                .any(|action| matches!(action, ProtocolAction::CommitHandoff { .. }))
        );
        assert!(
            destination_protocol
                .iter()
                .any(|action| matches!(action, ProtocolAction::RestoreRuntime { .. }))
        );
        assert!(
            destination_protocol
                .iter()
                .any(|action| matches!(action, ProtocolAction::ResumeDestination { .. }))
        );
    }

    #[test]
    fn append_replay_survives_fresh_destination_without_duplicate_write() {
        let tree = TestTree::new("append");
        let cell = "append-handoff";
        let mut source = CanonicalEndpoint::initialize_source(source_config(
            &tree,
            cell,
            CanonicalWorkload::AppendContinuity,
            b"abc",
        ))
        .expect("source endpoint initializes");

        let first = reply(
            &mut source,
            "APPEND\tsource\tappend-continuity\t1\t0\tappend-once\t0\t21\tvisible",
        );
        let replay = reply(
            &mut source,
            "APPEND\tsource\tappend-continuity\t2\t0\tappend-once\t1\t21\tvisible",
        );
        assert!(first.starts_with("APPEND\t"));
        assert!(replay.starts_with("APPEND_REPLAY\t"));
        assert_eq!(fs::read(&source.file_path).expect("source file"), b"abc!");
        assert_eq!(
            source.receipt.operations[0].canonical_operation,
            source.receipt.operations[1].canonical_operation
        );
        assert!(!source.receipt.operations[0].replayed);
        assert!(source.receipt.operations[1].replayed);

        source.source_safe_point().expect("append source safe point");
        let transfer = source.source_export().expect("append source export");
        let mut destination = CanonicalEndpoint::restore_destination(
            destination_config(&tree, cell, CanonicalWorkload::AppendContinuity, "append"),
            &transfer,
        )
        .expect("append destination restores");
        destination.resume_destination().expect("append destination resumes");

        let relocated_replay = reply(
            &mut destination,
            "APPEND\tdestination\tappend-continuity\t12\t0\tappend-once\t2\t21\tvisible",
        );
        assert!(relocated_replay.starts_with("APPEND_REPLAY\t"));
        assert_eq!(fs::read(&destination.file_path).expect("destination file"), b"abc!");
        let destination_append = reply(
            &mut destination,
            "APPEND\tdestination\tappend-continuity\t13\t0\tappend-destination\t0\t3f\tvisible",
        );
        assert!(destination_append.starts_with("APPEND\t"));
        assert_eq!(fs::read(&destination.file_path).expect("destination file"), b"abc!?");
        let state = canonical_regular_file(destination.coordinator.state())
            .expect("destination canonical profile");
        assert_eq!(state.logical_offset, 5);
        assert_eq!(state.version, 3);
        assert_eq!(state.size, 5);
    }

    #[test]
    fn tampering_phase_role_and_unix_wire_fail_closed() {
        let tree = TestTree::new("negative");
        let cell = "negative-handoff";
        let mut source = CanonicalEndpoint::initialize_source(source_config(
            &tree,
            cell,
            CanonicalWorkload::ReadWriteOffset,
            b"abcdef",
        ))
        .expect("negative source initializes");

        assert!(
            source
                .handle_wire_line("READ\tsource\tread-write-offset\t0\tmaybe\tkey\t0\t2")
                .is_err()
        );
        assert!(
            source
                .handle_wire_line("WRITE\tsource\tread-write-offset\t0\t0\tkey\t0\t0\tvisible")
                .is_err()
        );
        let mismatched_role =
            reply(&mut source, "READ\tdestination\tread-write-offset\t0\t1\trole-mismatch\t0\t2");
        assert_eq!(mismatched_role, "ERROR\t0\trole-mismatch\t0\tread\tlost-binding\t5\t0\t2\t-");
        assert!(source.receipt.operations.last().is_some_and(|receipt| {
            receipt.role == EndpointRole::Destination
                && matches!(receipt.operation, Some(RegularFileOperation::Read { max_bytes: 2 }))
                && receipt.error.as_deref().is_some_and(|error| error.contains("unavailable"))
        }));

        source.source_safe_point().expect("negative source safe point");
        assert!(source.source_safe_point().is_err());
        let transfer = source.source_export().expect("negative source export");
        assert!(source.source_export().is_err());

        let mut storage_tamper = transfer.clone();
        storage_tamper.storage_image[0] ^= 0xff;
        assert!(
            CanonicalEndpoint::restore_destination(
                destination_config(
                    &tree,
                    cell,
                    CanonicalWorkload::ReadWriteOffset,
                    "bad-storage-digest",
                ),
                &storage_tamper,
            )
            .is_err()
        );

        let mut coherent_storage_tamper = transfer.clone();
        coherent_storage_tamper.storage_image[0] ^= 0xff;
        coherent_storage_tamper.storage_image_sha256 =
            sha256_hex(&coherent_storage_tamper.storage_image);
        assert!(
            CanonicalEndpoint::restore_destination(
                destination_config(
                    &tree,
                    cell,
                    CanonicalWorkload::ReadWriteOffset,
                    "bad-storage-content",
                ),
                &coherent_storage_tamper,
            )
            .is_err()
        );

        let mut portable_tamper = transfer.clone();
        portable_tamper.portable_state[0] ^= 0xff;
        assert!(CanonicalEndpoint::restore_destination(
            destination_config(
                &tree,
                cell,
                CanonicalWorkload::ReadWriteOffset,
                "bad-portable",
            ),
            &portable_tamper,
        )
        .is_err());

        let mut snapshot_tamper = transfer.clone();
        snapshot_tamper.snapshot.integrity.0[0] ^= 0xff;
        assert!(CanonicalEndpoint::restore_destination(
            destination_config(
                &tree,
                cell,
                CanonicalWorkload::ReadWriteOffset,
                "bad-snapshot",
            ),
            &snapshot_tamper,
        )
        .is_err());

        let mut destination = CanonicalEndpoint::restore_destination(
            destination_config(&tree, cell, CanonicalWorkload::ReadWriteOffset, "wire"),
            &transfer,
        )
        .expect("wire destination restores");
        let before_resume = reply(&mut destination, "OPEN\tdestination\tread-write-offset\t12\t0");
        assert_eq!(before_resume, "BINDING_ERROR\t12\tlost-binding\t5");
        destination.resume_destination().expect("wire destination resumes");
        assert!(destination.resume_destination().is_err());

        let socket = tree.path("canonical.sock");
        let (role_response, malformed_response, open_response, shutdown_response, exit) =
            thread::scope(|scope| {
                let server = scope.spawn(|| destination.serve_unix(&socket));
                let role_response = socket_request(
                    &socket,
                    "READ\tsource\tread-write-offset\t12\t0\tsocket-role\t7\t2",
                );
                let malformed_response =
                    socket_request(&socket, "READ\tdestination\tread-write-offset");
                let open_response =
                    socket_request(&socket, "OPEN\tdestination\tread-write-offset\t12\t0");
                let shutdown_response = socket_request(&socket, "SHUTDOWN");
                let exit = server.join().expect("socket server thread").expect("socket server");
                (role_response, malformed_response, open_response, shutdown_response, exit)
            });
        assert_eq!(role_response, "ERROR\t12\tsocket-role\t7\tread\tlost-binding\t5\t0\t2\t-");
        assert!(malformed_response.starts_with("ERROR\tcontrol\t"));
        assert!(open_response.starts_with("OPEN\t12\tvisa-rebind\t"));
        assert_eq!(shutdown_response, "OK\tSHUTDOWN");
        assert!(matches!(exit, ServiceExit::Shutdown));
        assert!(!socket.exists());

        let receipt_path = tree.path("destination-receipt.json");
        destination.write_receipt(&receipt_path).expect("receipt survives service shutdown");
        let decoded: CanonicalServiceReceipt = serde_json::from_slice(
            &fs::read(&receipt_path).expect("read written destination receipt"),
        )
        .expect("decode written destination receipt");
        assert_eq!(decoded, *destination.receipt());
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
    }
}
