use std::path::PathBuf;

use wire::{
    CaseObservation, CleanupObservation, DestinationBindingObservation, EndpointObservation,
    ErrorDomain, FileEntryObservation, FileMetadataObservation, ObservationActor,
    ObservationBundle, ObservationPhase, ObservationSchemaVersion, OperationRecordObservation,
    ProfileStateObservation, RawErrorObservation, ResourceSubject, RouteObservation,
};

use super::*;

const PRIMARY: &[u8] = b"data.bin";

struct CaseBuilder {
    case_id: RegularFileCase,
    events: Vec<wire::ObservedEvent>,
}

impl CaseBuilder {
    fn new(case_id: RegularFileCase, initial: &[u8]) -> Self {
        let mut builder = Self { case_id, events: Vec::new() };
        builder.file(ObservationPhase::Setup, PRIMARY, Some((initial, 7, 11)));
        builder.profile(ObservationPhase::Setup, profile(PRIMARY, 0, 1, initial));
        builder
    }

    fn push(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        body: RawObservationEvent,
    ) -> u64 {
        let sequence = self.events.len() as u64;
        self.events.push(wire::ObservedEvent { sequence, phase, actor, body });
        sequence
    }

    fn file(&mut self, phase: ObservationPhase, path: &[u8], file: Option<(&[u8], u64, u64)>) {
        let entry = file.map_or(FileEntryObservation::Missing, |(bytes, device, inode)| {
            FileEntryObservation::File {
                bytes: bytes.to_vec(),
                size: bytes.len() as u64,
                sha256: sha256_hex(bytes),
                metadata: FileMetadataObservation {
                    device,
                    inode,
                    generation: Some(1),
                    birth_time_unix_ns: Some(10),
                    mode: 0o100600,
                    link_count: 1,
                },
            }
        });
        self.push(
            phase,
            ObservationActor::ExternalObserver,
            RawObservationEvent::FileProbe { path: path.to_vec(), entry },
        );
    }

    fn profile(&mut self, phase: ObservationPhase, state: ProfileStateObservation) {
        self.push(
            phase,
            ObservationActor::ExternalObserver,
            RawObservationEvent::ProfileStateProbe { state },
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn operation(
        &mut self,
        phase: ObservationPhase,
        actor: ObservationActor,
        operation_id: &str,
        attempt: u32,
        key: Option<&str>,
        operation: RegularFileOperationObservation,
        result: OperationCallResult,
    ) {
        self.push(
            phase,
            actor,
            RawObservationEvent::OperationCall {
                operation_id: operation_id.to_owned(),
                attempt,
                idempotency_key: key.map(str::to_owned),
                operation,
                result,
            },
        );
    }

    fn protocol(
        &mut self,
        phase: ObservationPhase,
        action: ProtocolAction,
        result: GenericCallResult,
    ) {
        self.push(
            phase,
            ObservationActor::Controller,
            RawObservationEvent::ProtocolCall { action, result },
        );
    }

    fn committed(&mut self) {
        self.protocol(
            ObservationPhase::Quiesce,
            ProtocolAction::BeginQuiesce {
                command_id: "begin".to_owned(),
                authority_id: "authority".to_owned(),
            },
            ok(),
        );
        self.protocol(
            ObservationPhase::Quiesce,
            ProtocolAction::PrepareSafePoint { safe_point_id: "safe".to_owned() },
            ok(),
        );
        self.protocol(
            ObservationPhase::Quiesce,
            ProtocolAction::FreezeRuntime { safe_point_id: "safe".to_owned() },
            ok(),
        );
        self.protocol(
            ObservationPhase::Quiesce,
            ProtocolAction::CommitSafePoint {
                command_id: "freeze".to_owned(),
                safe_point_id: "safe".to_owned(),
            },
            ok(),
        );
        self.protocol(
            ObservationPhase::Transfer,
            ProtocolAction::ExportSnapshot {
                command_id: "export".to_owned(),
                snapshot_id: "snapshot".to_owned(),
            },
            ok(),
        );
        self.protocol(
            ObservationPhase::DestinationPrepare,
            ProtocolAction::PrepareDestination { command_id: "prepare".to_owned() },
            ok(),
        );
        self.protocol(
            ObservationPhase::DestinationPrepare,
            ProtocolAction::CommitHandoff {
                command_id: "commit".to_owned(),
                operation_id: "commit-operation".to_owned(),
            },
            ok(),
        );
        self.protocol(
            ObservationPhase::CarrierRestore,
            ProtocolAction::RestoreRuntime { snapshot_id: "snapshot".to_owned() },
            ok(),
        );
        self.protocol(
            ObservationPhase::DestinationExecution,
            ProtocolAction::ResumeDestination { command_id: "resume".to_owned() },
            ok(),
        );
    }

    fn lease(&mut self, phase: ObservationPhase, owner: Option<&str>, epoch: u64) {
        self.push(
            phase,
            ObservationActor::Provider,
            RawObservationEvent::LeaseProbe {
                resource_id: "resource".to_owned(),
                owner: owner.map(str::to_owned),
                epoch,
            },
        );
    }

    fn finish(self) -> CaseObservation {
        CaseObservation {
            observation_id: format!("{}-observation", self.case_id.as_str()),
            case_id: self.case_id,
            schedule_id: format!("{}-schedule", self.case_id.as_str()),
            schedule_sha256: "11".repeat(32),
            subject: ResourceSubject {
                resource_id: "resource".to_owned(),
                initial_path: PRIMARY.to_vec(),
            },
            events: self.events,
        }
    }
}

fn ok() -> GenericCallResult {
    GenericCallResult::Returned { bytes: Vec::new() }
}

fn error(code: ErrorCode, retryable: bool) -> RawErrorObservation {
    RawErrorObservation {
        domain: match code {
            ErrorCode::WouldBlock => ErrorDomain::OperatingSystem,
            ErrorCode::ProviderDenied | ErrorCode::StaleEpoch => ErrorDomain::Provider,
            ErrorCode::SafePointUnavailable | ErrorCode::IndeterminateEffect => {
                ErrorDomain::Runtime
            }
            _ => ErrorDomain::RegularFileProfile,
        },
        code,
        errno: None,
        retryable,
        detail: None,
    }
}

fn op_error(code: ErrorCode, retryable: bool) -> OperationCallResult {
    OperationCallResult::Error { error: error(code, retryable) }
}

fn generic_error_result(code: ErrorCode) -> GenericCallResult {
    GenericCallResult::Error { error: error(code, false) }
}

fn profile(
    path: &[u8],
    logical_offset: u64,
    version: u64,
    content: &[u8],
) -> ProfileStateObservation {
    ProfileStateObservation {
        relative_path: path.to_vec(),
        object_binding: b"resource-binding".to_vec(),
        logical_offset,
        version,
        size: content.len() as u64,
        content_digest: canonical_byte_vector_digest(content),
        durable_through: FileDurabilityObservation::Visible,
        lock_state: FileLockStateObservation::Unlocked,
        disposition: wire::ContinuityDispositionObservation::Revalidate,
        last_operation: None,
    }
}

fn mutated(
    logical_offset: u64,
    version: u64,
    content: &[u8],
    durability: FileDurabilityObservation,
) -> OperationCallResult {
    OperationCallResult::Returned {
        output: RegularFileOutputObservation::Mutated {
            logical_offset,
            version,
            size: content.len() as u64,
            content_digest: canonical_byte_vector_digest(content),
            durable_through: durability,
        },
    }
}

fn read(bytes: &[u8], offset: u64, version: u64, content: &[u8]) -> OperationCallResult {
    OperationCallResult::Returned {
        output: RegularFileOutputObservation::Read {
            bytes: bytes.to_vec(),
            logical_offset: offset,
            version,
            size: content.len() as u64,
            content_digest: canonical_byte_vector_digest(content),
        },
    }
}

fn read_write_offset() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::ReadWriteOffset, b"abcdef");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "read",
        0,
        None,
        RegularFileOperationObservation::Read { max_bytes: 2 },
        op_error(ErrorCode::Unavailable, true),
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "read",
        1,
        None,
        RegularFileOperationObservation::Read { max_bytes: 2 },
        read(b"ab", 2, 1, b"abcdef"),
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "write",
        0,
        Some("write-key"),
        RegularFileOperationObservation::Write {
            bytes: b"XY".to_vec(),
            durability: FileDurabilityObservation::Visible,
        },
        mutated(4, 2, b"abXYef", FileDurabilityObservation::Visible),
    );
    builder.committed();
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "post-read",
        0,
        None,
        RegularFileOperationObservation::Read { max_bytes: 2 },
        read(b"ef", 6, 2, b"abXYef"),
    );
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 6, 2, b"abXYef"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"abXYef", 7, 11)));
    builder.finish()
}

fn append_continuity() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::AppendContinuity, b"abc");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "append-one",
        0,
        Some("append-continuity"),
        RegularFileOperationObservation::Append {
            bytes: b"!".to_vec(),
            durability: FileDurabilityObservation::Data,
        },
        mutated(4, 2, b"abc!", FileDurabilityObservation::Data),
    );
    builder.committed();
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "append-one",
        1,
        Some("append-continuity"),
        RegularFileOperationObservation::Append {
            bytes: b"!".to_vec(),
            durability: FileDurabilityObservation::Data,
        },
        mutated(4, 2, b"abc!", FileDurabilityObservation::Data),
    );
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "append-two",
        0,
        Some("append-destination"),
        RegularFileOperationObservation::Append {
            bytes: b"?".to_vec(),
            durability: FileDurabilityObservation::Data,
        },
        mutated(5, 3, b"abc!?", FileDurabilityObservation::Data),
    );
    let mut final_state = profile(PRIMARY, 5, 3, b"abc!?");
    final_state.durable_through = FileDurabilityObservation::Data;
    builder.profile(ObservationPhase::FinalObservation, final_state);
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"abc!?", 7, 11)));
    builder.finish()
}

fn truncate_version() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::TruncateVersion, b"abcdef");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "truncate",
        0,
        Some("truncate"),
        RegularFileOperationObservation::Truncate {
            size: 3,
            durability: FileDurabilityObservation::DataAndMetadata,
        },
        mutated(0, 2, b"abc", FileDurabilityObservation::DataAndMetadata),
    );
    builder.committed();
    let mut final_state = profile(PRIMARY, 0, 2, b"abc");
    final_state.durable_through = FileDurabilityObservation::DataAndMetadata;
    builder.profile(ObservationPhase::FinalObservation, final_state);
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"abc", 7, 11)));
    builder.finish()
}

fn rename_identity() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::RenameObjectIdentity, b"rename-me");
    builder.file(ObservationPhase::Setup, b"occupied.bin", Some((b"occupied-target", 7, 22)));
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "rename-conflict",
        0,
        Some("rename-occupied"),
        RegularFileOperationObservation::Rename { relative_path: b"occupied.bin".to_vec() },
        op_error(ErrorCode::Conflict, false),
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "rename",
        0,
        Some("rename"),
        RegularFileOperationObservation::Rename { relative_path: b"renamed.bin".to_vec() },
        OperationCallResult::Returned {
            output: RegularFileOutputObservation::Renamed {
                relative_path: b"renamed.bin".to_vec(),
                version: 2,
                content_digest: canonical_byte_vector_digest(b"rename-me"),
            },
        },
    );
    builder.committed();
    builder
        .profile(ObservationPhase::FinalObservation, profile(b"renamed.bin", 0, 2, b"rename-me"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, None);
    builder.file(ObservationPhase::FinalObservation, b"renamed.bin", Some((b"rename-me", 7, 11)));
    builder.file(
        ObservationPhase::FinalObservation,
        b"occupied.bin",
        Some((b"occupied-target", 7, 22)),
    );
    builder.finish()
}

fn replacement_rejected() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::ReplacementRejected, b"same");
    builder.push(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalMutator,
        RawObservationEvent::OsCall {
            action: OsAction::ReplacePath {
                source: b"replacement.bin".to_vec(),
                destination: PRIMARY.to_vec(),
            },
            result: ok(),
        },
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "read",
        0,
        None,
        RegularFileOperationObservation::Read { max_bytes: 4 },
        op_error(ErrorCode::Conflict, false),
    );
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 0, 1, b"same"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"same", 7, 33)));
    builder.finish()
}

fn external_mutation() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::ExternalMutationRejected, b"original");
    builder.push(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalMutator,
        RawObservationEvent::OsCall {
            action: OsAction::WriteWhole { path: PRIMARY.to_vec(), bytes: b"external".to_vec() },
            result: ok(),
        },
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "read",
        0,
        None,
        RegularFileOperationObservation::Read { max_bytes: 8 },
        op_error(ErrorCode::Conflict, false),
    );
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 0, 1, b"original"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"external", 7, 11)));
    builder.finish()
}

fn lock_conflict() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::LockConflict, b"locked");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "lock-source",
        0,
        Some("lock-source"),
        RegularFileOperationObservation::AcquireLock,
        OperationCallResult::Returned {
            output: RegularFileOutputObservation::Lock { state: FileLockStateObservation::Held },
        },
    );
    builder.push(
        ObservationPhase::SourceExecution,
        ObservationActor::CompetingProcess,
        RawObservationEvent::OsCall {
            action: OsAction::TryExclusiveLock { path: PRIMARY.to_vec() },
            result: generic_error_result(ErrorCode::WouldBlock),
        },
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::FreezeRuntime { safe_point_id: "live-lock".to_owned() },
        generic_error_result(ErrorCode::SafePointUnavailable),
    );
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "unlock-source",
        0,
        Some("unlock-source"),
        RegularFileOperationObservation::ReleaseLock,
        OperationCallResult::Returned {
            output: RegularFileOutputObservation::Lock {
                state: FileLockStateObservation::Unlocked,
            },
        },
    );
    builder.committed();
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "lock-destination",
        0,
        Some("lock-destination"),
        RegularFileOperationObservation::AcquireLock,
        OperationCallResult::Returned {
            output: RegularFileOutputObservation::Lock { state: FileLockStateObservation::Held },
        },
    );
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "unlock-destination",
        0,
        Some("unlock-destination"),
        RegularFileOperationObservation::ReleaseLock,
        OperationCallResult::Returned {
            output: RegularFileOutputObservation::Lock {
                state: FileLockStateObservation::Unlocked,
            },
        },
    );
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 0, 1, b"locked"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"locked", 7, 11)));
    builder.finish()
}

fn durability_reconciled() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::DurabilityReconciled, b"a");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "durable-append",
        0,
        Some("durable-append"),
        RegularFileOperationObservation::Append {
            bytes: b"b".to_vec(),
            durability: FileDurabilityObservation::DataAndMetadata,
        },
        op_error(ErrorCode::Indeterminate, false),
    );
    builder.file(ObservationPhase::SourceExecution, PRIMARY, Some((b"ab", 7, 11)));
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "durable-append",
        1,
        Some("durable-append"),
        RegularFileOperationObservation::Append {
            bytes: b"b".to_vec(),
            durability: FileDurabilityObservation::DataAndMetadata,
        },
        mutated(2, 2, b"ab", FileDurabilityObservation::DataAndMetadata),
    );
    builder.push(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        RawObservationEvent::OperationLedgerProbe {
            records: vec![OperationRecordObservation {
                operation_id: "durable-append".to_owned(),
                request_digest: vec![1; 32],
                outcome: OperationOutcomeObservation::Applied { result_digest: vec![2; 32] },
                cleanup: CleanupObservation::Required,
            }],
        },
    );
    builder.committed();
    let mut final_state = profile(PRIMARY, 2, 2, b"ab");
    final_state.durable_through = FileDurabilityObservation::DataAndMetadata;
    final_state.last_operation = Some("durable-append".to_owned());
    builder.profile(ObservationPhase::FinalObservation, final_state);
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"ab", 7, 11)));
    builder.finish()
}

fn stale_source_fenced() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::StaleSourceFenced, b"fence");
    builder.lease(ObservationPhase::Setup, Some("source"), 1);
    builder.committed();
    builder.push(
        ObservationPhase::DestinationExecution,
        ObservationActor::Provider,
        RawObservationEvent::LeaseCheck {
            resource_id: "resource".to_owned(),
            owner: "source".to_owned(),
            epoch: 1,
            result: generic_error_result(ErrorCode::StaleEpoch),
        },
    );
    builder.operation(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        "destination-write",
        0,
        Some("destination-write"),
        RegularFileOperationObservation::Append {
            bytes: b"!".to_vec(),
            durability: FileDurabilityObservation::Visible,
        },
        mutated(6, 2, b"fence!", FileDurabilityObservation::Visible),
    );
    builder.lease(ObservationPhase::FinalObservation, Some("destination"), 2);
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 6, 2, b"fence!"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"fence!", 7, 11)));
    builder.finish()
}

fn cleanup_idempotent() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::CleanupIdempotent, b"clean");
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "cleanup-write",
        0,
        Some("cleanup-write"),
        RegularFileOperationObservation::Append {
            bytes: b"!".to_vec(),
            durability: FileDurabilityObservation::Visible,
        },
        mutated(6, 2, b"clean!", FileDurabilityObservation::Visible),
    );
    let record = OperationRecordObservation {
        operation_id: "cleanup-write".to_owned(),
        request_digest: vec![1; 32],
        outcome: OperationOutcomeObservation::Applied { result_digest: vec![2; 32] },
        cleanup: CleanupObservation::Cleaned,
    };
    builder.protocol(
        ObservationPhase::Cleanup,
        ProtocolAction::CleanupOperation {
            command_id: "cleanup-one".to_owned(),
            operation_id: "cleanup-write".to_owned(),
            evidence_id: "evidence".to_owned(),
        },
        ok(),
    );
    builder.push(
        ObservationPhase::Cleanup,
        ObservationActor::ExternalObserver,
        RawObservationEvent::OperationLedgerProbe { records: vec![record.clone()] },
    );
    builder.protocol(
        ObservationPhase::Cleanup,
        ProtocolAction::CleanupOperation {
            command_id: "cleanup-two".to_owned(),
            operation_id: "cleanup-write".to_owned(),
            evidence_id: "evidence".to_owned(),
        },
        ok(),
    );
    builder.push(
        ObservationPhase::Cleanup,
        ObservationActor::ExternalObserver,
        RawObservationEvent::OperationLedgerProbe { records: vec![record] },
    );
    builder.committed();
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 6, 2, b"clean!"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"clean!", 7, 11)));
    builder.finish()
}

fn indeterminate_blocks() -> CaseObservation {
    let mut builder = CaseBuilder::new(RegularFileCase::IndeterminateWriteBlocksHandoff, b"a");
    builder.lease(ObservationPhase::Setup, Some("source"), 1);
    builder.operation(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        "unknown-write",
        0,
        Some("unknown-write"),
        RegularFileOperationObservation::Append {
            bytes: b"b".to_vec(),
            durability: FileDurabilityObservation::Data,
        },
        op_error(ErrorCode::Indeterminate, false),
    );
    builder.push(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        RawObservationEvent::OperationLedgerProbe {
            records: vec![OperationRecordObservation {
                operation_id: "unknown-write".to_owned(),
                request_digest: vec![1; 32],
                outcome: OperationOutcomeObservation::Indeterminate,
                cleanup: CleanupObservation::Required,
            }],
        },
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::BeginQuiesce {
            command_id: "begin".to_owned(),
            authority_id: "authority".to_owned(),
        },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::PrepareSafePoint { safe_point_id: "safe".to_owned() },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::FreezeRuntime { safe_point_id: "safe".to_owned() },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::CommitSafePoint {
            command_id: "freeze".to_owned(),
            safe_point_id: "safe".to_owned(),
        },
        generic_error_result(ErrorCode::IndeterminateEffect),
    );
    builder.lease(ObservationPhase::FinalObservation, Some("source"), 1);
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 0, 1, b"a"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"ab", 7, 11)));
    builder.finish()
}

fn destination_denied() -> CaseObservation {
    let mut builder =
        CaseBuilder::new(RegularFileCase::DestinationReauthorizationDenied, b"policy");
    builder.lease(ObservationPhase::Setup, Some("source"), 1);
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::BeginQuiesce {
            command_id: "begin".to_owned(),
            authority_id: "authority".to_owned(),
        },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::PrepareSafePoint { safe_point_id: "safe".to_owned() },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::FreezeRuntime { safe_point_id: "safe".to_owned() },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Quiesce,
        ProtocolAction::CommitSafePoint {
            command_id: "freeze".to_owned(),
            safe_point_id: "safe".to_owned(),
        },
        ok(),
    );
    builder.protocol(
        ObservationPhase::Transfer,
        ProtocolAction::ExportSnapshot {
            command_id: "export".to_owned(),
            snapshot_id: "snapshot".to_owned(),
        },
        ok(),
    );
    builder.protocol(
        ObservationPhase::DestinationPrepare,
        ProtocolAction::PrepareDestination { command_id: "prepare".to_owned() },
        generic_error_result(ErrorCode::ProviderDenied),
    );
    builder.push(
        ObservationPhase::DestinationPrepare,
        ObservationActor::ExternalObserver,
        RawObservationEvent::DestinationBindingProbe {
            bindings: vec![DestinationBindingObservation {
                resource_id: "resource".to_owned(),
                state: DestinationBindingState::Absent,
                owner: None,
                epoch: None,
            }],
        },
    );
    builder.lease(ObservationPhase::FinalObservation, Some("source"), 1);
    builder.profile(ObservationPhase::FinalObservation, profile(PRIMARY, 0, 1, b"policy"));
    builder.file(ObservationPhase::FinalObservation, PRIMARY, Some((b"policy", 7, 11)));
    builder.finish()
}

fn all_cases() -> Vec<CaseObservation> {
    vec![
        read_write_offset(),
        append_continuity(),
        truncate_version(),
        rename_identity(),
        replacement_rejected(),
        external_mutation(),
        lock_conflict(),
        durability_reconciled(),
        stale_source_fenced(),
        cleanup_idempotent(),
        indeterminate_blocks(),
        destination_denied(),
    ]
}

fn endpoint(instance: &str) -> EndpointObservation {
    EndpointObservation {
        instance_id: instance.to_owned(),
        runtime: "fixture-runtime".to_owned(),
        runtime_version: "1".to_owned(),
        host_id: "fixture-host".to_owned(),
        operating_system: "linux".to_owned(),
        isa: "x86_64".to_owned(),
    }
}

fn bundle(mode: RouteMode, cases: Vec<CaseObservation>) -> ObservationBundle {
    ObservationBundle {
        schema_version: ObservationSchemaVersion::V2,
        bundle_id: format!("fixture-{}", route_mode_name(mode)),
        route: RouteObservation {
            mode,
            source: endpoint("source"),
            destination: (mode != RouteMode::UninterruptedControl).then(|| endpoint("destination")),
            execution_boundary: "fixture".to_owned(),
            carrier: None,
        },
        cases,
    }
}

#[test]
fn all_twelve_candidate_cases_are_derived_from_raw_facts() {
    let cases = all_cases();
    assert_eq!(cases.len(), RegularFileCase::ALL.len());
    for case in &cases {
        let report = evaluate_case(RouteMode::Handoff, case);
        assert!(report.accepted, "{} failed: {:#?}", case.case_id.as_str(), report);
        assert!(!report.assertions.is_empty());
        assert!(report.assertions.iter().all(|assertion| assertion.passed));
        assert!(report.projection.is_some());
    }
}

#[test]
fn complete_registry_is_owned_and_checked_by_the_oracle() {
    let complete = bundle(RouteMode::Handoff, all_cases());
    assert!(evaluate_bundle(&complete, Coverage::CompleteRegistry).accepted);
    let mut incomplete = complete;
    incomplete.cases.pop();
    let report = evaluate_bundle(&incomplete, Coverage::CompleteRegistry);
    assert!(!report.accepted);
    assert!(report.findings.iter().any(|finding| finding.code == "incomplete-case-registry"));
}

#[test]
fn changed_read_bytes_are_rejected() {
    let mut case = read_write_offset();
    for event in &mut case.events {
        if let RawObservationEvent::OperationCall {
            operation_id,
            result:
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Read { bytes, .. },
                },
            ..
        } = &mut event.body
            && operation_id == "post-read"
        {
            *bytes = b"zz".to_vec();
        }
    }
    let report = evaluate_case(RouteMode::Handoff, &case);
    assert!(!report.accepted);
    assert!(
        report
            .assertions
            .iter()
            .any(|assertion| { assertion.name == "bytes_preserved" && !assertion.passed })
    );
}

#[test]
fn changed_read_offset_is_rejected() {
    let mut case = read_write_offset();
    for event in &mut case.events {
        if let RawObservationEvent::OperationCall {
            operation_id,
            result:
                OperationCallResult::Returned {
                    output: RegularFileOutputObservation::Read { logical_offset, .. },
                },
            ..
        } = &mut event.body
            && operation_id == "post-read"
        {
            *logical_offset = 5;
        }
    }
    let report = evaluate_case(RouteMode::Handoff, &case);
    assert!(!report.accepted);
    assert!(
        report
            .assertions
            .iter()
            .any(|assertion| { assertion.name == "logical_offset_preserved" && !assertion.passed })
    );
}

#[test]
fn returned_content_digests_are_recomputed_for_read_mutation_and_rename() {
    let mut cases = [read_write_offset(), read_write_offset(), rename_identity()];
    for (index, case) in cases.iter_mut().enumerate() {
        let output = case.events.iter_mut().find_map(|event| match &mut event.body {
            RawObservationEvent::OperationCall {
                result: OperationCallResult::Returned { output },
                ..
            } if matches!(
                (index, &*output),
                (0, RegularFileOutputObservation::Read { .. })
                    | (1, RegularFileOutputObservation::Mutated { .. })
                    | (2, RegularFileOutputObservation::Renamed { .. })
            ) =>
            {
                Some(output)
            }
            _ => None,
        });
        let digest = output
            .and_then(|output| match output {
                RegularFileOutputObservation::Read { content_digest, .. }
                | RegularFileOutputObservation::Mutated { content_digest, .. }
                | RegularFileOutputObservation::Renamed { content_digest, .. } => {
                    Some(content_digest)
                }
                _ => None,
            })
            .expect("selected output has a content digest");
        *digest = vec![0; 32];

        let report =
            evaluate_bundle(&bundle(RouteMode::Handoff, vec![case.clone()]), Coverage::AnySubset);
        assert!(!report.accepted, "mutated digest kind {index} escaped");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "operation-content-digest-mismatch"),
            "{report:#?}"
        );
    }
}

#[test]
fn profile_content_digest_is_recomputed_from_raw_file_state() {
    let mut case = read_write_offset();
    for event in &mut case.events {
        if let RawObservationEvent::ProfileStateProbe { state } = &mut event.body
            && event.phase == ObservationPhase::FinalObservation
        {
            state.content_digest = vec![0; 32];
        }
    }
    let report = evaluate_bundle(&bundle(RouteMode::Handoff, vec![case]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "profile-content-digest-mismatch")
    );
}

#[test]
fn duplicate_final_file_probe_is_rejected_instead_of_last_write_winning() {
    let mut case = read_write_offset();
    let mut duplicate = case
        .events
        .iter()
        .find(|event| {
            event.phase == ObservationPhase::FinalObservation
                && matches!(event.body, RawObservationEvent::FileProbe { .. })
        })
        .cloned()
        .expect("read-write-offset has a final file probe");
    duplicate.sequence = case.events.len() as u64;
    case.events.push(duplicate);
    let report = evaluate_case(RouteMode::Handoff, &case);
    assert!(!report.accepted);
    assert!(report.findings.iter().any(|finding| finding.code == "duplicate-final-file-probe"));
}

#[test]
fn duplicate_append_call_is_rejected() {
    let mut case = append_continuity();
    let duplicate = case
        .events
        .iter()
        .find_map(|event| match &event.body {
            RawObservationEvent::OperationCall { operation_id, .. }
                if operation_id == "append-two" =>
            {
                Some(event.body.clone())
            }
            _ => None,
        })
        .expect("append call exists");
    let insert = case
        .events
        .iter()
        .position(|event| event.phase == ObservationPhase::FinalObservation)
        .expect("final observations exist");
    case.events.insert(
        insert,
        wire::ObservedEvent {
            sequence: 0,
            phase: ObservationPhase::DestinationExecution,
            actor: ObservationActor::DestinationRuntime,
            body: duplicate,
        },
    );
    for (sequence, event) in case.events.iter_mut().enumerate() {
        event.sequence = sequence as u64;
    }
    let report = evaluate_case(RouteMode::Handoff, &case);
    assert!(!report.accepted);
    assert!(
        report
            .assertions
            .iter()
            .any(|assertion| { assertion.name == "append_once" && !assertion.passed })
    );
}

#[test]
fn deleted_write_operation_event_is_rejected() {
    let mut case = read_write_offset();
    case.events.retain(|event| {
        !matches!(
            &event.body,
            RawObservationEvent::OperationCall { operation_id, .. } if operation_id == "write"
        )
    });
    for (sequence, event) in case.events.iter_mut().enumerate() {
        event.sequence = sequence as u64;
    }
    let report = evaluate_case(RouteMode::Handoff, &case);
    assert!(!report.accepted);
    assert!(
        report
            .assertions
            .iter()
            .any(|assertion| { assertion.name == "write_once" && !assertion.passed })
    );
}

#[test]
fn forged_terminal_and_producer_claim_are_strictly_rejected() {
    let base = serde_json::json!({
        "schema_version": "regular-file-observation-v2",
        "bundle_id": "strict",
        "route": {
            "mode": "uninterrupted_control",
            "source": {
                "instance_id": "source",
                "runtime": "runtime",
                "runtime_version": "1",
                "host_id": "host",
                "operating_system": "linux",
                "isa": "x86_64"
            },
            "destination": null,
            "execution_boundary": "test",
            "carrier": null
        },
        "cases": []
    });
    for field in ["terminal", "producer_claim"] {
        let mut forged = base.clone();
        forged
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), serde_json::json!("handoff_committed"));
        let report =
            evaluate_json(&serde_json::to_vec(&forged).expect("encode"), Coverage::AnySubset);
        assert!(!report.accepted, "{field} was accepted");
        assert_eq!(report.findings[0].code, "invalid-observation-json");
    }
}

#[test]
fn operation_attempts_must_start_at_zero() {
    let mut case = read_write_offset();
    for event in &mut case.events {
        if let RawObservationEvent::OperationCall { attempt, .. } = &mut event.body {
            *attempt += 1;
        }
    }
    let mut findings = Vec::new();
    validate_case_structure(&case, &mut findings);
    assert!(findings.iter().any(|finding| finding.code == "noncontiguous-operation-attempts"));
}

#[test]
fn committed_handoff_rejects_protocol_actor_phase_and_identity_drift() {
    let baseline = evaluate_bundle(
        &bundle(RouteMode::Handoff, vec![read_write_offset()]),
        Coverage::AnySubset,
    );
    assert!(baseline.accepted, "{baseline:#?}");

    let mut wrong_context = read_write_offset();
    let resume = wrong_context
        .events
        .iter_mut()
        .find(|event| {
            matches!(
                event.body,
                RawObservationEvent::ProtocolCall {
                    action: ProtocolAction::ResumeDestination { .. },
                    ..
                }
            )
        })
        .expect("resume event");
    resume.phase = ObservationPhase::Setup;
    resume.actor = ObservationActor::SourceRuntime;
    let report =
        evaluate_bundle(&bundle(RouteMode::Handoff, vec![wrong_context]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-protocol-observation-context")
    );

    let mut safe_point_drift = read_write_offset();
    let freeze = safe_point_drift
        .events
        .iter_mut()
        .find_map(|event| match &mut event.body {
            RawObservationEvent::ProtocolCall {
                action: ProtocolAction::FreezeRuntime { safe_point_id },
                ..
            } => Some(safe_point_id),
            _ => None,
        })
        .expect("freeze event");
    *freeze = "forged-safe-point".to_owned();
    let report =
        evaluate_bundle(&bundle(RouteMode::Handoff, vec![safe_point_drift]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "handoff-safe-point-identity-mismatch")
    );

    let mut snapshot_drift = read_write_offset();
    let restore = snapshot_drift
        .events
        .iter_mut()
        .find_map(|event| match &mut event.body {
            RawObservationEvent::ProtocolCall {
                action: ProtocolAction::RestoreRuntime { snapshot_id },
                ..
            } => Some(snapshot_id),
            _ => None,
        })
        .expect("restore event");
    *restore = "forged-snapshot".to_owned();
    let report =
        evaluate_bundle(&bundle(RouteMode::Handoff, vec![snapshot_drift]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "handoff-snapshot-identity-mismatch")
    );
}

#[test]
fn committed_handoff_binds_post_commit_operations_to_resumed_destination() {
    let mut source_replay = read_write_offset();
    let post_read = source_replay
        .events
        .iter_mut()
        .find(|event| {
            matches!(
                &event.body,
                RawObservationEvent::OperationCall { operation_id, .. }
                    if operation_id == "post-read"
            )
        })
        .expect("post-handoff read");
    post_read.actor = ObservationActor::SourceRuntime;
    let report =
        evaluate_bundle(&bundle(RouteMode::Handoff, vec![source_replay]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-post-commit-operation-context")
    );

    let mut wrong_phase = append_continuity();
    let destination_append = wrong_phase
        .events
        .iter_mut()
        .find(|event| {
            matches!(
                &event.body,
                RawObservationEvent::OperationCall { operation_id, attempt, .. }
                    if operation_id == "append-one" && *attempt == 1
            )
        })
        .expect("destination replay");
    destination_append.phase = ObservationPhase::SourceExecution;
    let report =
        evaluate_bundle(&bundle(RouteMode::Handoff, vec![wrong_phase]), Coverage::AnySubset);
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "invalid-destination-operation-context")
    );
}

#[test]
fn committed_handoff_preserves_explicit_stale_source_negative() {
    let mut case = stale_source_fenced();
    let insertion = case
        .events
        .iter()
        .position(|event| event.phase == ObservationPhase::FinalObservation)
        .expect("final observation");
    case.events.insert(
        insertion,
        wire::ObservedEvent {
            sequence: 0,
            phase: ObservationPhase::DestinationExecution,
            actor: ObservationActor::SourceRuntime,
            body: RawObservationEvent::OperationCall {
                operation_id: "stale-source-write".to_owned(),
                attempt: 0,
                idempotency_key: Some("stale-source-write".to_owned()),
                operation: RegularFileOperationObservation::Append {
                    bytes: b"x".to_vec(),
                    durability: FileDurabilityObservation::Visible,
                },
                result: op_error(ErrorCode::StaleEpoch, false),
            },
        },
    );
    for (sequence, event) in case.events.iter_mut().enumerate() {
        event.sequence = sequence as u64;
    }
    let report = evaluate_bundle(&bundle(RouteMode::Handoff, vec![case]), Coverage::AnySubset);
    assert!(report.accepted, "{report:#?}");
}

#[test]
fn subset_equivalence_compares_route_neutral_observables() {
    let candidate_case = read_write_offset();
    let control_case = candidate_case.clone();
    let control = bundle(RouteMode::UninterruptedControl, vec![control_case]);
    let candidate = bundle(RouteMode::Handoff, vec![candidate_case]);
    let control_json = serde_json::to_vec(&bundle_json(&control)).expect("encode control");
    let candidate_json = serde_json::to_vec(&bundle_json(&candidate)).expect("encode candidate");
    let report =
        evaluate_equivalence_with_coverage(&control_json, &candidate_json, Coverage::AnySubset);
    assert!(report.accepted, "{report:#?}");
}

#[test]
fn stage3a_gate_binds_exact_route_endpoints_and_execution_boundary() {
    let (control, candidate, expectation) = stage3a_pair_json();
    let baseline = evaluate_stage3a_equivalence_with_coverage(
        &serde_json::to_vec(&control).expect("encode Stage3A control"),
        &serde_json::to_vec(&candidate).expect("encode Stage3A candidate"),
        &expectation,
        Coverage::CarrierProbe,
    );
    assert!(baseline.accepted, "{baseline:#?}");

    let mut restart = candidate.clone();
    restart["route"]["mode"] = serde_json::Value::String("restart".to_owned());
    let report = evaluate_stage3a_equivalence_with_coverage(
        &serde_json::to_vec(&control).unwrap(),
        &serde_json::to_vec(&restart).unwrap(),
        &expectation,
        Coverage::CarrierProbe,
    );
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "invalid-stage3a-candidate-topology")
    );

    let mut runtime_drift = candidate.clone();
    runtime_drift["route"]["source"]["runtime"] =
        serde_json::Value::String("forged-runtime".to_owned());
    runtime_drift["route"]["destination"]["runtime_version"] =
        serde_json::Value::String("forged-version".to_owned());
    let report = evaluate_stage3a_equivalence_with_coverage(
        &serde_json::to_vec(&control).unwrap(),
        &serde_json::to_vec(&runtime_drift).unwrap(),
        &expectation,
        Coverage::CarrierProbe,
    );
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "stage3a-endpoint-scope-mismatch")
    );

    let mut boundary_drift = candidate.clone();
    boundary_drift["route"]["execution_boundary"] =
        serde_json::Value::String("forged-boundary".to_owned());
    let report = evaluate_stage3a_equivalence_with_coverage(
        &serde_json::to_vec(&control).unwrap(),
        &serde_json::to_vec(&boundary_drift).unwrap(),
        &expectation,
        Coverage::CarrierProbe,
    );
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "stage3a-execution-boundary-mismatch")
    );

    let mut overloaded_control = control.clone();
    overloaded_control["route"]["destination"] = candidate["route"]["destination"].clone();
    overloaded_control["route"]["carrier"] = serde_json::json!({
        "implementation": "forged-carrier",
        "implementation_version": "1",
        "mode": "forged"
    });
    let report = evaluate_stage3a_equivalence_with_coverage(
        &serde_json::to_vec(&overloaded_control).unwrap(),
        &serde_json::to_vec(&candidate).unwrap(),
        &expectation,
        Coverage::CarrierProbe,
    );
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "invalid-stage3a-control-topology")
    );
}

#[test]
fn carrier_probe_requires_exactly_the_two_named_cases() {
    let candidate_cases = vec![read_write_offset(), append_continuity()];
    let control_cases = candidate_cases.clone();
    let control = bundle(RouteMode::UninterruptedControl, control_cases);
    let candidate = bundle(RouteMode::Handoff, candidate_cases);
    let control_json = serde_json::to_vec(&bundle_json(&control)).expect("encode control");
    let candidate_json = serde_json::to_vec(&bundle_json(&candidate)).expect("encode candidate");
    let report =
        evaluate_equivalence_with_coverage(&control_json, &candidate_json, Coverage::CarrierProbe);
    assert!(report.accepted, "{report:#?}");

    let extra = bundle(
        RouteMode::Handoff,
        vec![read_write_offset(), append_continuity(), truncate_version()],
    );
    let rejected = evaluate_bundle(&extra, Coverage::CarrierProbe);
    assert!(!rejected.accepted);
    assert!(
        rejected.findings.iter().any(|finding| finding.code == "invalid-carrier-probe-registry")
    );
}

fn stage3a_pair_json() -> (serde_json::Value, serde_json::Value, Stage3aTopologyExpectation) {
    let cases = vec![read_write_offset(), append_continuity()];
    let mut control = bundle(RouteMode::UninterruptedControl, cases.clone());
    control.route.execution_boundary = "single-runtime-instance-uninterrupted-control".to_owned();
    let mut candidate = bundle(RouteMode::Handoff, cases);
    candidate.route.execution_boundary =
        "same-process-distinct-wasmtime-store-and-provider-instance".to_owned();
    let expectation = Stage3aTopologyExpectation {
        source: Stage3aEndpointExpectation {
            instance_id: "source".to_owned(),
            runtime: "fixture-runtime".to_owned(),
            runtime_version: "1".to_owned(),
            operating_system: "linux".to_owned(),
            isa: "x86_64".to_owned(),
        },
        destination: Stage3aEndpointExpectation {
            instance_id: "destination".to_owned(),
            runtime: "fixture-runtime".to_owned(),
            runtime_version: "1".to_owned(),
            operating_system: "linux".to_owned(),
            isa: "x86_64".to_owned(),
        },
        candidate_execution_boundary: "same-process-distinct-wasmtime-store-and-provider-instance"
            .to_owned(),
    };
    (bundle_json(&control), bundle_json(&candidate), expectation)
}

const TEST_WANCO_REVISION: &str = "3c2e400dda5ce51d78333223f6fcbde08e6b198a";

struct TestArtifactRoot(PathBuf);

impl TestArtifactRoot {
    fn new(label: &str, bytes: &[u8]) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir()
            .join(format!("visa-regular-file-oracle-{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(root.join("checkpoints")).expect("create isolated artifact root");
        fs::write(root.join("checkpoints/checkpoint.pb"), bytes).expect("write checkpoint fixture");
        Self(root)
    }

    fn checkpoint(&self) -> PathBuf {
        self.0.join("checkpoints/checkpoint.pb")
    }
}

impl Drop for TestArtifactRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wanco_probe_json(route: &str, checkpoint: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let cases = vec![read_write_offset(), append_continuity()];
    let mut control = bundle_json(&bundle(RouteMode::UninterruptedControl, cases.clone()));
    let mut candidate = bundle_json(&bundle(RouteMode::Handoff, cases));
    control["route"]["execution_boundary"] =
        serde_json::Value::String("same-process-uninterrupted".to_owned());
    candidate["route"]["execution_boundary"] =
        serde_json::Value::String("same-host-fresh-process-and-node-local-storage".to_owned());
    bind_wanco_endpoint(&mut control["route"]["source"], "uninterrupted", "source");
    bind_wanco_endpoint(&mut candidate["route"]["source"], route, "source");
    bind_wanco_endpoint(&mut candidate["route"]["destination"], route, "destination");
    candidate["route"]["mode"] = serde_json::Value::String(route.replace('-', "_"));
    candidate["route"]["carrier"] = serde_json::json!({
        "implementation": "tamaroning/wanco",
        "implementation_version": TEST_WANCO_REVISION,
        "mode": "signal-triggered-llvm-stackmap-protobuf"
    });

    let payload = serde_json::json!({
        "storage": "artifact",
        "data": {
            "reference": {
                "uri": "checkpoints/checkpoint.pb",
                "sha256": sha256_hex(checkpoint),
                "size": checkpoint.len() as u64
            }
        }
    });
    for case in candidate["cases"].as_array_mut().expect("candidate cases") {
        let events = case["events"].as_array_mut().expect("candidate events");
        let capture_sequence = events.len() as u64;
        events.push(serde_json::json!({
            "sequence": capture_sequence,
            "phase": "carrier_capture",
            "actor": "carrier",
            "body": {
                "kind": "carrier_call",
                "data": {
                    "action": {
                        "kind": "capture",
                        "data": {"capture_id": "wanco-checkpoint-1"}
                    },
                    "result": {
                        "status": "captured",
                        "data": {"payload": payload.clone()}
                    }
                }
            }
        }));
        events.push(serde_json::json!({
            "sequence": capture_sequence + 1,
            "phase": "carrier_restore",
            "actor": "carrier",
            "body": {
                "kind": "carrier_call",
                "data": {
                    "action": {
                        "kind": "restore",
                        "data": {
                            "capture_id": "wanco-checkpoint-1",
                            "payload": payload.clone()
                        }
                    },
                    "result": {"status": "returned", "data": {"bytes": []}}
                }
            }
        }));
        events.push(serde_json::json!({
            "sequence": capture_sequence + 2,
            "phase": "carrier_restore",
            "actor": "carrier",
            "body": {
                "kind": "carrier_call",
                "data": {
                    "action": {"kind": "resume"},
                    "result": {"status": "returned", "data": {"bytes": []}}
                }
            }
        }));
    }
    (serde_json::to_vec(&control).expect("encode Wanco control"), candidate)
}

fn bind_wanco_endpoint(endpoint: &mut serde_json::Value, route: &str, role: &str) {
    *endpoint = serde_json::json!({
        "instance_id": format!("wanco-aot-{route}-{role}"),
        "runtime": "tamaroning/wanco-aot",
        "runtime_version": TEST_WANCO_REVISION,
        "host_id": "fixture-host",
        "operating_system": "linux",
        "isa": "x86_64"
    });
}

fn evaluate_wanco_fixture(
    root: &TestArtifactRoot,
    expected_route: CarrierProbeRoute,
    control: &[u8],
    candidate: &serde_json::Value,
) -> EquivalenceReport {
    evaluate_carrier_probe(
        control,
        &serde_json::to_vec(candidate).expect("encode Wanco candidate"),
        CarrierProbeExpectation {
            route: expected_route,
            artifact_root: &root.0,
            carrier_revision: TEST_WANCO_REVISION,
        },
    )
}

fn carrier_events_mut(case: &mut serde_json::Value) -> Vec<&mut serde_json::Value> {
    case["events"]
        .as_array_mut()
        .expect("candidate events")
        .iter_mut()
        .filter(|event| event["body"]["kind"] == "carrier_call")
        .collect()
}

#[test]
fn wanco_carrier_probe_binds_expected_route_and_identity() {
    let checkpoint = b"checkpoint-state";
    let root = TestArtifactRoot::new("route", checkpoint);
    let (control, candidate) = wanco_probe_json("visa-plus-carrier", checkpoint);
    let accepted =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &candidate);
    assert!(accepted.accepted, "{accepted:#?}");

    let swapped =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::CarrierOnly, &control, &candidate);
    assert!(!swapped.accepted);
    assert!(
        swapped.findings.iter().any(|finding| finding.code == "unexpected-wanco-carrier-route")
    );

    let mut wrong_identity = candidate;
    wrong_identity["route"]["carrier"]["implementation"] =
        serde_json::Value::String("not-wanco".to_owned());
    let rejected = evaluate_wanco_fixture(
        &root,
        CarrierProbeRoute::VisaPlusCarrier,
        &control,
        &wrong_identity,
    );
    assert!(!rejected.accepted);
    assert!(
        rejected.findings.iter().any(|finding| finding.code == "unexpected-wanco-carrier-identity")
    );
}

#[test]
fn wanco_carrier_probe_binds_boundary_instances_and_same_host_topology() {
    let checkpoint = b"checkpoint-state";
    let root = TestArtifactRoot::new("topology", checkpoint);
    let (control, candidate) = wanco_probe_json("visa-plus-carrier", checkpoint);

    let mut boundary_drift = candidate.clone();
    boundary_drift["route"]["execution_boundary"] =
        serde_json::Value::String("same-process-forged".to_owned());
    let report = evaluate_wanco_fixture(
        &root,
        CarrierProbeRoute::VisaPlusCarrier,
        &control,
        &boundary_drift,
    );
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "unexpected-wanco-execution-boundary")
    );

    let mut aliased = candidate.clone();
    aliased["route"]["destination"]["instance_id"] =
        aliased["route"]["source"]["instance_id"].clone();
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &aliased);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "aliased-wanco-endpoint-instance")
    );

    let mut wrong_role = candidate.clone();
    wrong_role["route"]["source"]["instance_id"] =
        serde_json::Value::String("wanco-aot-visa-plus-carrier-destination".to_owned());
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &wrong_role);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "unexpected-wanco-endpoint-identity")
    );

    let mut other_host = candidate;
    other_host["route"]["destination"]["host_id"] =
        serde_json::Value::String("forged-other-host".to_owned());
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &other_host);
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "wanco-same-host-observation-mismatch")
    );
}

#[test]
fn wanco_carrier_probe_rejects_capture_id_mismatch() {
    let checkpoint = b"checkpoint-state";
    let root = TestArtifactRoot::new("capture-id", checkpoint);
    let (control, mut candidate) = wanco_probe_json("visa-plus-carrier", checkpoint);
    for case in candidate["cases"].as_array_mut().expect("candidate cases") {
        carrier_events_mut(case)[1]["body"]["data"]["action"]["data"]["capture_id"] =
            serde_json::Value::String("different-capture".to_owned());
    }
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &candidate);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "invalid-wanco-carrier-lifecycle")
    );
}

#[test]
fn wanco_carrier_probe_rejects_checkpoint_uri_escape() {
    let checkpoint = b"checkpoint-state";
    let root = TestArtifactRoot::new("uri", checkpoint);
    let (control, mut candidate) = wanco_probe_json("visa-plus-carrier", checkpoint);
    for case in candidate["cases"].as_array_mut().expect("candidate cases") {
        let mut calls = carrier_events_mut(case);
        calls[0]["body"]["data"]["result"]["data"]["payload"]["data"]["reference"]["uri"] =
            serde_json::Value::String("../checkpoint.pb".to_owned());
        calls[1]["body"]["data"]["action"]["data"]["payload"]["data"]["reference"]["uri"] =
            serde_json::Value::String("../checkpoint.pb".to_owned());
    }
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &candidate);
    assert!(!report.accepted);
    assert!(report.findings.iter().any(|finding| finding.code == "unsafe-wanco-checkpoint-uri"));
}

#[test]
fn wanco_carrier_probe_rehashes_checkpoint_bytes() {
    let checkpoint = b"checkpoint-state";
    let root = TestArtifactRoot::new("rehash", checkpoint);
    let (control, candidate) = wanco_probe_json("visa-plus-carrier", checkpoint);
    fs::write(root.checkpoint(), b"checkpoint-statz").expect("mutate checkpoint bytes");
    let report =
        evaluate_wanco_fixture(&root, CarrierProbeRoute::VisaPlusCarrier, &control, &candidate);
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| finding.code == "wanco-checkpoint-artifact-mismatch")
    );
}

fn bundle_json(bundle: &ObservationBundle) -> serde_json::Value {
    // Tests deliberately serialize through an independent handwritten JSON
    // projection instead of adding a dependency on the producer schema crate.
    serde_json::json!({
        "schema_version": "regular-file-observation-v2",
        "bundle_id": bundle.bundle_id,
        "route": route_json(&bundle.route),
        "cases": bundle.cases.iter().map(case_json).collect::<Vec<_>>()
    })
}

fn route_json(route: &RouteObservation) -> serde_json::Value {
    let mode = route_mode_name(route.mode);
    serde_json::json!({
        "mode": mode,
        "source": endpoint_json(&route.source),
        "destination": route.destination.as_ref().map(endpoint_json),
        "execution_boundary": route.execution_boundary,
        "carrier": null
    })
}

fn endpoint_json(endpoint: &EndpointObservation) -> serde_json::Value {
    serde_json::json!({
        "instance_id": endpoint.instance_id,
        "runtime": endpoint.runtime,
        "runtime_version": endpoint.runtime_version,
        "host_id": endpoint.host_id,
        "operating_system": endpoint.operating_system,
        "isa": endpoint.isa
    })
}

fn case_json(case: &CaseObservation) -> serde_json::Value {
    serde_json::json!({
        "observation_id": case.observation_id,
        "case_id": case.case_id.as_str(),
        "schedule_id": case.schedule_id,
        "schedule_sha256": case.schedule_sha256,
        "subject": {
            "resource_id": case.subject.resource_id,
            "initial_path": case.subject.initial_path
        },
        "events": case.events.iter().map(event_json).collect::<Vec<_>>()
    })
}

fn event_json(event: &wire::ObservedEvent) -> serde_json::Value {
    // Only the subset-equivalence fixture needs serialization. Supporting all
    // event variants here would duplicate the production producer serializer;
    // serialize the read/write fixture variants explicitly.
    let phase = format!("{:?}", event.phase)
        .chars()
        .enumerate()
        .flat_map(|(index, ch)| {
            if ch.is_ascii_uppercase() && index > 0 {
                vec!['_', ch.to_ascii_lowercase()]
            } else {
                vec![ch.to_ascii_lowercase()]
            }
        })
        .collect::<String>();
    let actor = match event.actor {
        ObservationActor::ExternalObserver => "external_observer",
        ObservationActor::Controller => "controller",
        ObservationActor::SourceRuntime => "source_runtime",
        ObservationActor::DestinationRuntime => "destination_runtime",
        ObservationActor::Provider => "provider",
        ObservationActor::Carrier => "carrier",
        ObservationActor::CompetingProcess => "competing_process",
        ObservationActor::ExternalMutator => "external_mutator",
    };
    serde_json::json!({
        "sequence": event.sequence,
        "phase": phase,
        "actor": actor,
        "body": raw_event_json(&event.body)
    })
}

fn raw_event_json(event: &RawObservationEvent) -> serde_json::Value {
    match event {
        RawObservationEvent::FileProbe { path, entry } => serde_json::json!({
            "kind": "file_probe",
            "data": {"path": path, "entry": file_entry_json(entry)}
        }),
        RawObservationEvent::ProfileStateProbe { state } => serde_json::json!({
            "kind": "profile_state_probe",
            "data": {"state": profile_json(state)}
        }),
        RawObservationEvent::OperationCall {
            operation_id,
            attempt,
            idempotency_key,
            operation,
            result,
        } => serde_json::json!({
            "kind": "operation_call",
            "data": {
                "operation_id": operation_id,
                "attempt": attempt,
                "idempotency_key": idempotency_key,
                "operation": operation_json(operation),
                "result": operation_result_json(result)
            }
        }),
        RawObservationEvent::ProtocolCall { action, result } => serde_json::json!({
            "kind": "protocol_call",
            "data": {
                "action": protocol_json(action),
                "result": generic_result_json(result)
            }
        }),
        other => panic!("unsupported subset fixture event: {other:?}"),
    }
}

fn file_entry_json(entry: &FileEntryObservation) -> serde_json::Value {
    match entry {
        FileEntryObservation::Missing => serde_json::json!({"kind": "missing"}),
        FileEntryObservation::File { bytes, size, sha256, metadata } => serde_json::json!({
            "kind": "file",
            "data": {
                "bytes": bytes,
                "size": size,
                "sha256": sha256,
                "metadata": {
                    "device": metadata.device,
                    "inode": metadata.inode,
                    "generation": metadata.generation,
                    "birth_time_unix_ns": metadata.birth_time_unix_ns,
                    "mode": metadata.mode,
                    "link_count": metadata.link_count
                }
            }
        }),
        FileEntryObservation::ProbeError { .. } => unreachable!(),
    }
}

fn profile_json(state: &ProfileStateObservation) -> serde_json::Value {
    serde_json::json!({
        "relative_path": state.relative_path,
        "object_binding": state.object_binding,
        "logical_offset": state.logical_offset,
        "version": state.version,
        "size": state.size,
        "content_digest": state.content_digest,
        "durable_through": durability_name(state.durable_through),
        "lock_state": lock_state_name(state.lock_state),
        "disposition": "revalidate",
        "last_operation": state.last_operation
    })
}

fn operation_json(operation: &RegularFileOperationObservation) -> serde_json::Value {
    match operation {
        RegularFileOperationObservation::Read { max_bytes } => {
            serde_json::json!({"kind": "read", "data": {"max_bytes": max_bytes}})
        }
        RegularFileOperationObservation::Write { bytes, durability } => serde_json::json!({
            "kind": "write",
            "data": {"bytes": bytes, "durability": durability_name(*durability)}
        }),
        RegularFileOperationObservation::Append { bytes, durability } => serde_json::json!({
            "kind": "append",
            "data": {"bytes": bytes, "durability": durability_name(*durability)}
        }),
        _ => panic!("unsupported subset operation"),
    }
}

fn operation_result_json(result: &OperationCallResult) -> serde_json::Value {
    match result {
        OperationCallResult::Error { error } => serde_json::json!({
            "status": "error",
            "data": {"error": error_json(error)}
        }),
        OperationCallResult::Returned {
            output:
                RegularFileOutputObservation::Read {
                    bytes,
                    logical_offset,
                    version,
                    size,
                    content_digest,
                },
        } => serde_json::json!({
            "status": "returned",
            "data": {"output": {
                "kind": "read",
                "data": {
                    "bytes": bytes,
                    "logical_offset": logical_offset,
                    "version": version,
                    "size": size,
                    "content_digest": content_digest
                }
            }}
        }),
        OperationCallResult::Returned {
            output:
                RegularFileOutputObservation::Mutated {
                    logical_offset,
                    version,
                    size,
                    content_digest,
                    durable_through,
                },
        } => serde_json::json!({
            "status": "returned",
            "data": {"output": {
                "kind": "mutated",
                "data": {
                    "logical_offset": logical_offset,
                    "version": version,
                    "size": size,
                    "content_digest": content_digest,
                    "durable_through": durability_name(*durable_through)
                }
            }}
        }),
        _ => panic!("unsupported subset result"),
    }
}

fn protocol_json(action: &ProtocolAction) -> serde_json::Value {
    match action {
        ProtocolAction::BeginQuiesce { command_id, authority_id } => serde_json::json!({
            "kind": "begin_quiesce",
            "data": {"command_id": command_id, "authority_id": authority_id}
        }),
        ProtocolAction::PrepareSafePoint { safe_point_id } => serde_json::json!({
            "kind": "prepare_safe_point",
            "data": {"safe_point_id": safe_point_id}
        }),
        ProtocolAction::FreezeRuntime { safe_point_id } => serde_json::json!({
            "kind": "freeze_runtime",
            "data": {"safe_point_id": safe_point_id}
        }),
        ProtocolAction::CommitSafePoint { command_id, safe_point_id } => serde_json::json!({
            "kind": "commit_safe_point",
            "data": {"command_id": command_id, "safe_point_id": safe_point_id}
        }),
        ProtocolAction::ExportSnapshot { command_id, snapshot_id } => serde_json::json!({
            "kind": "export_snapshot",
            "data": {"command_id": command_id, "snapshot_id": snapshot_id}
        }),
        ProtocolAction::PrepareDestination { command_id } => serde_json::json!({
            "kind": "prepare_destination",
            "data": {"command_id": command_id}
        }),
        ProtocolAction::CommitHandoff { command_id, operation_id } => serde_json::json!({
            "kind": "commit_handoff",
            "data": {"command_id": command_id, "operation_id": operation_id}
        }),
        ProtocolAction::RestoreRuntime { snapshot_id } => serde_json::json!({
            "kind": "restore_runtime",
            "data": {"snapshot_id": snapshot_id}
        }),
        ProtocolAction::ResumeDestination { command_id } => serde_json::json!({
            "kind": "resume_destination",
            "data": {"command_id": command_id}
        }),
        ProtocolAction::CleanupOperation { .. } => unreachable!(),
    }
}

fn generic_result_json(result: &GenericCallResult) -> serde_json::Value {
    match result {
        GenericCallResult::Returned { bytes } => {
            serde_json::json!({"status": "returned", "data": {"bytes": bytes}})
        }
        GenericCallResult::Error { error } => serde_json::json!({
            "status": "error",
            "data": {"error": error_json(error)}
        }),
    }
}

fn error_json(error: &RawErrorObservation) -> serde_json::Value {
    serde_json::json!({
        "domain": match error.domain {
            ErrorDomain::OperatingSystem => "operating_system",
            ErrorDomain::RegularFileProfile => "regular_file_profile",
            ErrorDomain::Provider => "provider",
            ErrorDomain::Runtime => "runtime",
            ErrorDomain::Carrier => "carrier",
        },
        "code": error_code_name(error.code),
        "errno": error.errno,
        "retryable": error.retryable,
        "detail": error.detail
    })
}
