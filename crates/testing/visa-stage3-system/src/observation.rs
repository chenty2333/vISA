use std::{
    collections::BTreeMap,
    fs,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::Path,
};

use contract_core::{
    ActivationRole, ActivationStatus, CanonicalState, CleanupStatus, EffectOutcome, EffectResult,
    EntityRef, FailureClass, HandoffPhase, Identity, OperationRecord,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{LeasePort as _, ProviderError, ProviderErrorKind};
use substrate_host::SqliteProvider;
use visa_component_adapter::{
    RegularFileAdapterError, RegularFileCallResult, RegularFileFailure, RegularFileWorkloadFailure,
};
use visa_profile::{
    ContinuityDisposition, FileDurability, FileLockState, REGULAR_FILE_EXTENSION_ID,
    RegularFileOperation, RegularFileResult, RegularFileState, regular_file_state,
};
use visa_regular_file_observation::{
    ActivationObservation, CleanupObservation, ContinuityDispositionObservation,
    CoordinatorPhaseObservation, CoordinatorStateObservation, DestinationBindingObservation,
    DestinationBindingState, ErrorCode, ErrorDomain, FileDurabilityObservation,
    FileEntryObservation, FileLockStateObservation, FileMetadataObservation, GenericCallResult,
    ObservationActor, ObservationPhase, ObservedEvent, OperationCallResult,
    OperationOutcomeObservation, OperationRecordObservation, OsAction, ProfileStateObservation,
    ProtocolAction, RawErrorObservation, RawObservationEvent, RegularFileCase,
    RegularFileCaseObservation, RegularFileOperationObservation, RegularFileOutputObservation,
    ResourceSubject, RouteMode,
};
use visa_runtime::{Coordinator, RuntimeError};

use crate::fixture::{FixtureIds, FixturePaths};

const SCHEDULE_DOMAIN: &[u8] = b"visa-stage3a-regular-file-schedule-v2\0";

pub(crate) struct CaseObservationRecorder {
    observation_id: String,
    case_id: RegularFileCase,
    schedule_id: String,
    schedule_sha256: String,
    subject: ResourceSubject,
    events: Vec<ObservedEvent>,
    attempts: BTreeMap<String, u32>,
}

impl CaseObservationRecorder {
    pub(crate) fn new(
        definition_id: &str,
        route: RouteMode,
        ids: FixtureIds,
    ) -> Result<Self, String> {
        let case_id = regular_file_case(definition_id)?;
        let schedule = schedule_text(case_id);
        let schedule_sha256 = sha256_domain(SCHEDULE_DOMAIN, schedule.as_bytes());
        let route_name = match route {
            RouteMode::UninterruptedControl => "control",
            RouteMode::Handoff => "handoff",
            RouteMode::Restart => "restart",
            RouteMode::CarrierOnly => "carrier-only",
            RouteMode::NaiveReopen => "naive-reopen",
            RouteMode::VisaPlusCarrier => "visa-plus-carrier",
        };
        Ok(Self {
            observation_id: format!("stage3a-{definition_id}-{route_name}"),
            case_id,
            schedule_id: format!("stage3a-{definition_id}-schedule-v2"),
            schedule_sha256,
            subject: ResourceSubject {
                resource_id: entity_hex(ids.file),
                initial_path: b"data.bin".to_vec(),
            },
            events: Vec::new(),
            attempts: BTreeMap::new(),
        })
    }

    pub(crate) fn finish(self) -> RegularFileCaseObservation {
        RegularFileCaseObservation::new(
            self.observation_id,
            self.case_id,
            self.schedule_id,
            self.schedule_sha256,
            self.subject,
            self.events,
        )
    }

    pub(crate) fn push(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        body: RawObservationEvent,
    ) {
        let sequence = self.events.len() as u64;
        self.events.push(ObservedEvent::new(sequence, phase, actor, body));
    }

    pub(crate) fn operation_call(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        idempotency_key: Option<&str>,
        operation_id: String,
        operation: &RegularFileOperation,
        result: &Result<RegularFileCallResult, RegularFileAdapterError>,
    ) {
        let attempt_key = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(|| format!("anonymous:{operation_id}"));
        let attempt = self.attempts.entry(attempt_key).or_insert(0);
        let current_attempt = *attempt;
        *attempt = attempt.saturating_add(1);
        self.push(
            phase,
            actor,
            RawObservationEvent::OperationCall {
                operation_id,
                attempt: current_attempt,
                idempotency_key: idempotency_key.map(str::to_owned),
                operation: operation_observation(operation),
                result: match result {
                    Ok(call) => {
                        OperationCallResult::Returned { output: output_observation(&call.result) }
                    }
                    Err(error) => {
                        OperationCallResult::Error { error: adapter_error_observation(error) }
                    }
                },
            },
        );
    }

    pub(crate) fn protocol_call(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        action: ProtocolAction,
        result: GenericCallResult,
    ) {
        self.push(phase, actor, RawObservationEvent::ProtocolCall { action, result });
    }

    pub(crate) fn os_call(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        action: OsAction,
        result: GenericCallResult,
    ) {
        self.push(phase, actor, RawObservationEvent::OsCall { action, result });
    }

    pub(crate) fn lease_check(
        &mut self,
        phase: ObservationPhase,
        resource: EntityRef,
        owner: contract_core::NodeIdentity,
        epoch: contract_core::LeaseEpoch,
        result: &Result<(), ProviderError>,
    ) {
        self.push(
            phase,
            ObservationActor::Provider,
            RawObservationEvent::LeaseCheck {
                resource_id: entity_hex(resource),
                owner: identity_hex(owner.0),
                epoch: epoch.0,
                result: match result {
                    Ok(()) => returned(Vec::new()),
                    Err(error) => {
                        GenericCallResult::Error { error: provider_error_observation(*error) }
                    }
                },
            },
        );
    }

    pub(crate) fn file_probe(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        root: &Path,
        path: &Path,
    ) {
        let relative = path.strip_prefix(root).unwrap_or(path).as_os_str().as_bytes().to_vec();
        self.push(
            phase,
            actor,
            RawObservationEvent::FileProbe { path: relative, entry: file_entry(path) },
        );
    }

    pub(crate) fn checkpoint(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        coordinator: &Coordinator<SqliteProvider>,
        paths: &FixturePaths,
        file_resource: EntityRef,
    ) -> Result<(), String> {
        let canonical = coordinator.state();
        let profile = canonical_file(canonical)?;
        self.push(
            phase,
            actor,
            RawObservationEvent::ProfileStateProbe { state: profile_state_observation(&profile) },
        );
        self.push(
            phase,
            actor,
            RawObservationEvent::CoordinatorStateProbe {
                state: coordinator_state_observation(canonical),
            },
        );
        let lease = coordinator
            .provider()
            .current_lease(file_resource)
            .map_err(|error| format!("cannot observe regular-file lease: {error:?}"))?;
        self.push(
            phase,
            ObservationActor::Provider,
            RawObservationEvent::LeaseProbe {
                resource_id: entity_hex(file_resource),
                owner: lease.map(|record| identity_hex(record.owner.0)),
                epoch: lease.map_or(canonical.ownership.epoch.0, |record| record.epoch.0),
            },
        );
        self.push(
            phase,
            ObservationActor::Provider,
            RawObservationEvent::OperationLedgerProbe { records: operation_records(canonical) },
        );
        self.push(
            phase,
            ObservationActor::Provider,
            RawObservationEvent::DestinationBindingProbe {
                bindings: destination_bindings(canonical, file_resource),
            },
        );
        let relative = std::str::from_utf8(&profile.claim.relative_path)
            .map_err(|_| "regular-file path is not UTF-8 in Stage3A fixture".to_owned())?;
        self.file_probe(
            phase,
            ObservationActor::ExternalObserver,
            &paths.file_root,
            &paths.file_root.join(relative),
        );
        Ok(())
    }
}

pub(crate) fn returned(bytes: Vec<u8>) -> GenericCallResult {
    GenericCallResult::Returned { bytes }
}

pub(crate) fn runtime_error_result(error: &RuntimeError) -> GenericCallResult {
    GenericCallResult::Error { error: runtime_error_observation(error) }
}

pub(crate) fn adapter_error_result(error: &RegularFileAdapterError) -> GenericCallResult {
    GenericCallResult::Error { error: adapter_error_observation(error) }
}

pub(crate) fn identity_hex(identity: Identity) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in identity.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn entity_hex(entity: EntityRef) -> String {
    format!("{}:{:016x}", identity_hex(entity.identity), entity.generation.0)
}

pub(crate) fn operation_id_after_call(
    coordinator: &Coordinator<SqliteProvider>,
    result: &Result<RegularFileCallResult, RegularFileAdapterError>,
) -> String {
    if let Ok(call) = result {
        return call.operation_id.clone();
    }
    if let Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
        RegularFileFailure::Indeterminate(operation),
    ))) = result
    {
        return operation.clone();
    }
    coordinator
        .state()
        .operations
        .last()
        .map(|record| identity_hex(record.request.operation))
        .unwrap_or_else(|| "00000000000000000000000000000000".to_owned())
}

fn file_entry(path: &Path) -> FileEntryObservation {
    match fs::read(path) {
        Ok(bytes) => match fs::metadata(path) {
            Ok(metadata) => FileEntryObservation::File {
                size: metadata.len(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                bytes,
                metadata: FileMetadataObservation {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    generation: None,
                    birth_time_unix_ns: None,
                    mode: metadata.mode(),
                    link_count: metadata.nlink(),
                },
            },
            Err(error) => FileEntryObservation::ProbeError { error: io_error_observation(&error) },
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => FileEntryObservation::Missing,
        Err(error) => FileEntryObservation::ProbeError { error: io_error_observation(&error) },
    }
}

fn canonical_file(state: &CanonicalState) -> Result<RegularFileState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension = matching.next().ok_or("missing regular-file extension")?;
    if matching.next().is_some() {
        return Err("duplicate regular-file extension".to_owned());
    }
    regular_file_state(extension).map_err(|error| format!("invalid regular-file state: {error:?}"))
}

fn profile_state_observation(state: &RegularFileState) -> ProfileStateObservation {
    let mut object_binding = state.claim.resource.identity.0.to_vec();
    object_binding.extend_from_slice(&state.claim.resource.generation.0.to_be_bytes());
    // This encodes the logical EntityRef. Native identity is observed only by FileProbe.
    ProfileStateObservation {
        relative_path: state.claim.relative_path.clone(),
        object_binding,
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: state.content_digest.0.to_vec(),
        durable_through: durability_observation(state.durable_through),
        lock_state: lock_observation(state.lock_state),
        disposition: disposition_observation(state.disposition),
        last_operation: state.last_operation.map(identity_hex),
    }
}

fn coordinator_state_observation(state: &CanonicalState) -> CoordinatorStateObservation {
    CoordinatorStateObservation {
        phase: match state.phase {
            HandoffPhase::Dormant => CoordinatorPhaseObservation::Inactive,
            HandoffPhase::Running => CoordinatorPhaseObservation::Active,
            HandoffPhase::Quiescing => CoordinatorPhaseObservation::Quiescing,
            HandoffPhase::Frozen => CoordinatorPhaseObservation::Frozen,
            HandoffPhase::Exported => CoordinatorPhaseObservation::Exported,
            HandoffPhase::DestinationPrepared => CoordinatorPhaseObservation::PreparedDestination,
            HandoffPhase::Committed => CoordinatorPhaseObservation::Committed,
            HandoffPhase::Aborted => CoordinatorPhaseObservation::Aborted,
        },
        activation: match (state.activation.role, state.activation.status) {
            (_, ActivationStatus::Inactive) => ActivationObservation::Inactive,
            (ActivationRole::Source, ActivationStatus::Active) => ActivationObservation::Source,
            (ActivationRole::Source, ActivationStatus::Fenced) => {
                ActivationObservation::SourceFenced
            }
            (ActivationRole::Destination, ActivationStatus::Prepared) => {
                ActivationObservation::DestinationPrepared
            }
            (ActivationRole::Destination, ActivationStatus::Active) => {
                ActivationObservation::DestinationActive
            }
            (_, ActivationStatus::Prepared | ActivationStatus::Fenced) => {
                ActivationObservation::Inactive
            }
        },
        owner: state.ownership.owner.map(|owner| identity_hex(owner.0)),
        epoch: state.ownership.epoch.0,
    }
}

fn operation_records(state: &CanonicalState) -> Vec<OperationRecordObservation> {
    state
        .operations
        .iter()
        .filter(|record| {
            matches!(
                record.request.kind,
                contract_core::EffectKind::Profile { profile, .. }
                    if profile == REGULAR_FILE_EXTENSION_ID
            )
        })
        .map(operation_record_observation)
        .collect()
}

fn operation_record_observation(record: &OperationRecord) -> OperationRecordObservation {
    OperationRecordObservation {
        operation_id: identity_hex(record.request.operation),
        request_digest: record.request.request_digest.0.to_vec(),
        outcome: match &record.outcome {
            None => OperationOutcomeObservation::Pending,
            Some(EffectOutcome::Succeeded {
                result: EffectResult::Profile { payload, .. },
                ..
            }) => OperationOutcomeObservation::Applied {
                // SHA-256 of the raw profile result payload, not a producer verdict.
                result_digest: Sha256::digest(payload).to_vec(),
            },
            Some(EffectOutcome::Succeeded { .. }) => {
                OperationOutcomeObservation::Applied { result_digest: Vec::new() }
            }
            Some(EffectOutcome::Indeterminate { .. }) => OperationOutcomeObservation::Indeterminate,
            Some(EffectOutcome::Failed(failure)) => OperationOutcomeObservation::Rejected {
                error: effect_failure_observation(failure.class, failure.retryable),
            },
            Some(EffectOutcome::Cancelled { .. }) => OperationOutcomeObservation::Rejected {
                error: raw_error(ErrorDomain::Provider, ErrorCode::Other, false),
            },
            Some(EffectOutcome::Unsupported { .. }) => OperationOutcomeObservation::Rejected {
                error: raw_error(ErrorDomain::RegularFileProfile, ErrorCode::Unsupported, false),
            },
        },
        cleanup: match record.cleanup {
            CleanupStatus::Pending => CleanupObservation::Required,
            CleanupStatus::Cleaned => CleanupObservation::Cleaned,
        },
    }
}

fn destination_bindings(
    state: &CanonicalState,
    resource: EntityRef,
) -> Vec<DestinationBindingObservation> {
    let matching = state
        .prepared_destination
        .as_ref()
        .into_iter()
        .flat_map(|prepared| prepared.bindings.iter())
        .filter(|binding| binding.claim == resource)
        .map(|binding| DestinationBindingObservation {
            resource_id: entity_hex(resource),
            state: if matches!(state.phase, HandoffPhase::Committed | HandoffPhase::Running)
                && state.activation.role == ActivationRole::Destination
                && state.activation.status == ActivationStatus::Active
            {
                DestinationBindingState::Published
            } else {
                DestinationBindingState::Prepared
            },
            owner: Some(identity_hex(binding.node.0)),
            epoch: Some(binding.lease_epoch.0),
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        vec![DestinationBindingObservation {
            resource_id: entity_hex(resource),
            state: DestinationBindingState::Absent,
            owner: None,
            epoch: None,
        }]
    } else {
        matching
    }
}

fn operation_observation(operation: &RegularFileOperation) -> RegularFileOperationObservation {
    match operation {
        RegularFileOperation::Read { max_bytes } => {
            RegularFileOperationObservation::Read { max_bytes: *max_bytes }
        }
        RegularFileOperation::Write { bytes, durability } => {
            RegularFileOperationObservation::Write {
                bytes: bytes.clone(),
                durability: durability_observation(*durability),
            }
        }
        RegularFileOperation::Append { bytes, durability } => {
            RegularFileOperationObservation::Append {
                bytes: bytes.clone(),
                durability: durability_observation(*durability),
            }
        }
        RegularFileOperation::Truncate { size, durability } => {
            RegularFileOperationObservation::Truncate {
                size: *size,
                durability: durability_observation(*durability),
            }
        }
        RegularFileOperation::Rename { relative_path } => {
            RegularFileOperationObservation::Rename { relative_path: relative_path.clone() }
        }
        RegularFileOperation::Sync { durability } => RegularFileOperationObservation::Sync {
            durability: durability_observation(*durability),
        },
        RegularFileOperation::AcquireLock => RegularFileOperationObservation::AcquireLock,
        RegularFileOperation::ReleaseLock => RegularFileOperationObservation::ReleaseLock,
    }
}

fn output_observation(result: &RegularFileResult) -> RegularFileOutputObservation {
    match result {
        RegularFileResult::Read { bytes, logical_offset, version, size, content_digest } => {
            RegularFileOutputObservation::Read {
                bytes: bytes.clone(),
                logical_offset: *logical_offset,
                version: *version,
                size: *size,
                content_digest: content_digest.0.to_vec(),
            }
        }
        RegularFileResult::Mutated {
            logical_offset,
            version,
            size,
            content_digest,
            durable_through,
        } => RegularFileOutputObservation::Mutated {
            logical_offset: *logical_offset,
            version: *version,
            size: *size,
            content_digest: content_digest.0.to_vec(),
            durable_through: durability_observation(*durable_through),
        },
        RegularFileResult::Renamed { relative_path, version, content_digest } => {
            RegularFileOutputObservation::Renamed {
                relative_path: relative_path.clone(),
                version: *version,
                content_digest: content_digest.0.to_vec(),
            }
        }
        RegularFileResult::Synced { version, durable_through } => {
            RegularFileOutputObservation::Synced {
                version: *version,
                durable_through: durability_observation(*durable_through),
            }
        }
        RegularFileResult::Lock { state } => {
            RegularFileOutputObservation::Lock { state: lock_observation(*state) }
        }
    }
}

fn adapter_error_observation(error: &RegularFileAdapterError) -> RawErrorObservation {
    match error {
        RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(failure)) => {
            match failure {
                RegularFileFailure::Denied => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::ProviderDenied, false)
                }
                RegularFileFailure::Conflict => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::Conflict, false)
                }
                RegularFileFailure::StaleBinding => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::StaleEpoch, false)
                }
                RegularFileFailure::Unsupported => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::Unsupported, false)
                }
                RegularFileFailure::Indeterminate(_) => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::Indeterminate, true)
                }
                RegularFileFailure::Unavailable => {
                    raw_error(ErrorDomain::RegularFileProfile, ErrorCode::Unavailable, true)
                }
            }
        }
        RegularFileAdapterError::Workload(RegularFileWorkloadFailure::SafePointUnavailable)
        | RegularFileAdapterError::LiveResourcesAtSafePoint { .. } => {
            raw_error(ErrorDomain::Runtime, ErrorCode::SafePointUnavailable, false)
        }
        RegularFileAdapterError::InvalidOperation
        | RegularFileAdapterError::InvalidCanonicalProfile
        | RegularFileAdapterError::Workload(RegularFileWorkloadFailure::InvalidState)
        | RegularFileAdapterError::Workload(RegularFileWorkloadFailure::AlreadyActive) => {
            raw_error(ErrorDomain::Runtime, ErrorCode::Invalid, false)
        }
        _ => raw_error(ErrorDomain::Runtime, ErrorCode::Other, false),
    }
}

fn runtime_error_observation(error: &RuntimeError) -> RawErrorObservation {
    match error {
        RuntimeError::Provider(error) | RuntimeError::PreparationCleanupFailed(error) => {
            provider_error_observation(*error)
        }
        RuntimeError::Rejected(contract_core::Rejection::IndeterminateEffect { .. }) => {
            raw_error(ErrorDomain::Runtime, ErrorCode::IndeterminateEffect, false)
        }
        RuntimeError::OperationOutcomeUnknown { .. }
        | RuntimeError::JournalOutcomeUnknown { .. } => {
            raw_error(ErrorDomain::Runtime, ErrorCode::Indeterminate, true)
        }
        RuntimeError::SnapshotUnavailable => {
            raw_error(ErrorDomain::Runtime, ErrorCode::NotFound, false)
        }
        RuntimeError::InvalidSafePoint => {
            raw_error(ErrorDomain::Runtime, ErrorCode::SafePointUnavailable, false)
        }
        _ => raw_error(ErrorDomain::Runtime, ErrorCode::Other, false),
    }
}

fn provider_error_observation(error: ProviderError) -> RawErrorObservation {
    let code = match error.kind {
        ProviderErrorKind::InvalidRequest => ErrorCode::Invalid,
        ProviderErrorKind::Unsupported => ErrorCode::Unsupported,
        ProviderErrorKind::NotFound => ErrorCode::NotFound,
        ProviderErrorKind::Conflict | ProviderErrorKind::StaleGeneration => ErrorCode::Conflict,
        ProviderErrorKind::StaleEpoch => ErrorCode::StaleEpoch,
        ProviderErrorKind::Denied | ProviderErrorKind::Revoked => ErrorCode::ProviderDenied,
        ProviderErrorKind::Unavailable => ErrorCode::Unavailable,
        ProviderErrorKind::OutcomeUnknown => ErrorCode::Indeterminate,
        ProviderErrorKind::Integrity | ProviderErrorKind::Storage => ErrorCode::Other,
    };
    raw_error(ErrorDomain::Provider, code, error.retryable)
}

fn effect_failure_observation(class: FailureClass, retryable: bool) -> RawErrorObservation {
    let code = match class {
        FailureClass::Denied => ErrorCode::ProviderDenied,
        FailureClass::Conflict => ErrorCode::Conflict,
        FailureClass::Unavailable => ErrorCode::Unavailable,
        FailureClass::Integrity | FailureClass::Internal => ErrorCode::Other,
    };
    raw_error(ErrorDomain::Provider, code, retryable)
}

fn io_error_observation(error: &std::io::Error) -> RawErrorObservation {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        std::io::ErrorKind::WouldBlock => ErrorCode::WouldBlock,
        std::io::ErrorKind::Unsupported => ErrorCode::Unsupported,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => ErrorCode::Invalid,
        _ => ErrorCode::Io,
    };
    RawErrorObservation {
        domain: ErrorDomain::OperatingSystem,
        code,
        errno: error.raw_os_error(),
        retryable: matches!(error.kind(), std::io::ErrorKind::WouldBlock),
        detail: None,
    }
}

fn raw_error(domain: ErrorDomain, code: ErrorCode, retryable: bool) -> RawErrorObservation {
    RawErrorObservation { domain, code, errno: None, retryable, detail: None }
}

fn durability_observation(value: FileDurability) -> FileDurabilityObservation {
    match value {
        FileDurability::Visible => FileDurabilityObservation::Visible,
        FileDurability::Data => FileDurabilityObservation::Data,
        FileDurability::DataAndMetadata => FileDurabilityObservation::DataAndMetadata,
    }
}

fn lock_observation(value: FileLockState) -> FileLockStateObservation {
    match value {
        FileLockState::Unlocked => FileLockStateObservation::Unlocked,
        FileLockState::Held => FileLockStateObservation::Held,
    }
}

fn disposition_observation(value: ContinuityDisposition) -> ContinuityDispositionObservation {
    match value {
        ContinuityDisposition::Revalidate => ContinuityDispositionObservation::Revalidate,
        ContinuityDisposition::Reconnect => ContinuityDispositionObservation::Reconnect,
        ContinuityDisposition::Replay => ContinuityDispositionObservation::Replay,
        ContinuityDisposition::Reject => ContinuityDispositionObservation::Reject,
    }
}

fn regular_file_case(id: &str) -> Result<RegularFileCase, String> {
    match id {
        "read-write-offset" => Ok(RegularFileCase::ReadWriteOffset),
        "append-continuity" => Ok(RegularFileCase::AppendContinuity),
        "truncate-version" => Ok(RegularFileCase::TruncateVersion),
        "rename-object-identity" => Ok(RegularFileCase::RenameObjectIdentity),
        "replacement-rejected" => Ok(RegularFileCase::ReplacementRejected),
        "external-mutation-rejected" => Ok(RegularFileCase::ExternalMutationRejected),
        "lock-conflict" => Ok(RegularFileCase::LockConflict),
        "durability-reconciled" => Ok(RegularFileCase::DurabilityReconciled),
        "stale-source-fenced" => Ok(RegularFileCase::StaleSourceFenced),
        "cleanup-idempotent" => Ok(RegularFileCase::CleanupIdempotent),
        "indeterminate-write-blocks-handoff" => {
            Ok(RegularFileCase::IndeterminateWriteBlocksHandoff)
        }
        "destination-reauthorization-denied" => {
            Ok(RegularFileCase::DestinationReauthorizationDenied)
        }
        other => Err(format!("unknown Stage3A observation case {other}")),
    }
}

fn schedule_text(case: RegularFileCase) -> &'static str {
    match case {
        RegularFileCase::ReadWriteOffset => {
            "initial=abcdef;fault=before_profile_effect_once;read(2);retry_read(2);write(XY,visible,key=write-offset);route_boundary;read(2)"
        }
        RegularFileCase::AppendContinuity => {
            "initial=abc;append(!,data,key=append-continuity);route_boundary;append(!,data,key=append-continuity);append(?,data,key=append-destination)"
        }
        RegularFileCase::TruncateVersion => {
            "initial=abcdef;truncate(3,data_and_metadata,key=truncate);route_boundary"
        }
        RegularFileCase::RenameObjectIdentity => {
            "initial=rename-me;create(occupied.bin,occupied-target);rename(occupied.bin,key=rename-occupied);rename(renamed.bin,key=rename);route_boundary;read(9)"
        }
        RegularFileCase::ReplacementRejected => {
            "initial=same;create(replacement.bin,same);replace(data.bin,replacement.bin);read(4)"
        }
        RegularFileCase::ExternalMutationRejected => {
            "initial=original;external_write(data.bin,external);read(8)"
        }
        RegularFileCase::LockConflict => {
            "initial=locked;acquire_lock(key=lock-source);competing_try_lock;freeze_while_live;release_lock(key=unlock-source);route_boundary;acquire_lock(key=lock-destination);release_lock(key=unlock-destination)"
        }
        RegularFileCase::DurabilityReconciled => {
            "initial=a;fault=after_regular_file_mutation_once;append(b,data_and_metadata,key=durable-append);retry_append(b,data_and_metadata,key=durable-append);route_boundary"
        }
        RegularFileCase::StaleSourceFenced => {
            "initial=fence;route_boundary;check_source_lease(epoch=1);append(!,visible,key=destination-write)"
        }
        RegularFileCase::CleanupIdempotent => {
            "initial=clean;append(!,visible,key=cleanup-write);cleanup(operation,command=cleanup-one);cleanup(operation,command=cleanup-two);route_boundary"
        }
        RegularFileCase::IndeterminateWriteBlocksHandoff => {
            "initial=a;fault=after_profile_effect_once;append(b,data,key=unknown-write);route_boundary_attempt"
        }
        RegularFileCase::DestinationReauthorizationDenied => {
            "initial=policy;destination_file_policy=deny;route_boundary_attempt"
        }
    }
}

fn sha256_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
