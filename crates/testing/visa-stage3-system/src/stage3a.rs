use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use contract_core::{
    CleanupStatus, Digest, EvidenceKind, EvidenceRef, ExtensionSupport, IdempotencyKey, Identity,
    SchemaVersion,
};
use serde_json::json;
use substrate_api::{LeasePort, ProviderErrorKind};
use substrate_host::{FaultPoint, SqliteProvider};
use visa_component_adapter::parse_identity;
use visa_conformance::{STAGE3A_CASE_DEFINITIONS, Stage3CaseDefinition, Stage3CaseTerminal};
use visa_profile::{
    FileDurability, FileLockState, REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION,
    RegularFileOperation, RegularFileResult, RegularFileState, regular_file_state,
};
use visa_runtime::{Coordinator, RuntimeError, SnapshotExpectations, validate_snapshot};
use visa_wasmtime::{
    PortableRegularFileState, RegularFileAdapter, RegularFileAdapterError, RegularFileFailure,
    RegularFileWorkloadFailure,
};

use crate::{
    component,
    evidence::{Stage3CaseCapture, create_incomplete_marker, publish_stage3a, terminal_name},
    fixture::{
        FixtureIds, FixturePaths, INITIAL_LEASE_EPOCH, Stage3aFixture, Stage3aFixtureOptions,
        derive_identity,
    },
};

struct CaseContext {
    definition: &'static Stage3CaseDefinition,
    case_id: String,
    paths: FixturePaths,
    ids: FixtureIds,
    profile_digest: Digest,
    handoff_authority: visa_runtime::AuthorityPlan,
    timer_authority: visa_runtime::AuthorityPlan,
    key_value_authority: visa_runtime::AuthorityPlan,
    file_authority: visa_runtime::ProfileAuthorityPlan,
    source: RegularFileAdapter<SqliteProvider>,
    destination_provider: Option<SqliteProvider>,
    canonical_before: Digest,
    file_before: Vec<u8>,
    operations: Vec<String>,
}

struct CommittedContext {
    destination: RegularFileAdapter<SqliteProvider>,
    portable: PortableRegularFileState,
}

pub fn run_stage3a(artifact_root: &Path) -> Result<PathBuf, String> {
    create_incomplete_marker(artifact_root)?;
    let work_root = artifact_root.join(".stage3-work");
    let started = now_unix_ms()?;
    let mut captures = Vec::with_capacity(STAGE3A_CASE_DEFINITIONS.len());
    for definition in STAGE3A_CASE_DEFINITIONS {
        captures.push(run_case(&work_root, definition)?);
    }
    remove_completed_work_tree(&work_root)?;
    let finished = now_unix_ms()?;
    let profile_manifest = json!({
        "profile": "bounded-regular-file-continuity",
        "extension_id": identity_hex(REGULAR_FILE_EXTENSION_ID),
        "extension_version": {
            "major": REGULAR_FILE_EXTENSION_VERSION.major,
            "minor": REGULAR_FILE_EXTENSION_VERSION.minor,
        },
        "canonical_state": [
            "object_identity", "relative_path", "logical_offset", "version", "size",
            "content_digest", "durability", "lock_state", "last_operation"
        ],
        "native_state_excluded": [
            "file_descriptor", "root_directory_descriptor", "inode_number",
            "device_number", "statx_birth_time", "absolute_root", "advisory_lock_handle"
        ],
        "explicit_non_claims": [
            "arbitrary_directory_tree", "device_object", "fifo", "arbitrary_open_fd",
            "atomic_compare_and_mutate_against_uncooperative_writer"
        ],
    });
    let configuration = json!({
        "source_runtime": "visa_wasmtime_stage3a",
        "destination_runtime": "visa_wasmtime_stage3a",
        "independent_runtime_coverage": false,
        "unsupported_stage3_runtime": "wacogo",
        "provider": "substrate_host::SqliteProvider",
        "path_resolution": "linux-openat2-beneath-no-symlink-no-xdev",
        "native_identity": "linux-statx-device-inode-birth-time-required",
        "effect_fence": "sqlite-immediate-effect-admission-authority-lease-prestate-recheck",
        "file_effect_and_sqlite_outcome_atomic": false,
        "external_mutation_boundary":
            "pre-operation-drift-detection-and-cooperative-advisory-lock-lease",
        "component_state_encoding": "visa-regular-file-state-v1",
        "execution_boundary": "same-process-distinct-wasmtime-store-and-provider-instance",
        "case_count": STAGE3A_CASE_DEFINITIONS.len(),
    });
    publish_stage3a(
        artifact_root,
        started,
        finished,
        RegularFileAdapter::<SqliteProvider>::runtime_identity_static(),
        &profile_manifest,
        &configuration,
        &captures,
    )
}

fn run_case(
    artifact_root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    match definition.id {
        "read-write-offset" => case_read_write_offset(artifact_root, definition),
        "append-continuity" => case_append_continuity(artifact_root, definition),
        "truncate-version" => case_truncate_version(artifact_root, definition),
        "rename-object-identity" => case_rename_identity(artifact_root, definition),
        "replacement-rejected" => case_replacement_rejected(artifact_root, definition),
        "external-mutation-rejected" => case_external_mutation(artifact_root, definition),
        "lock-conflict" => case_lock_conflict(artifact_root, definition),
        "durability-reconciled" => case_durability_reconciled(artifact_root, definition),
        "stale-source-fenced" => case_stale_source_fenced(artifact_root, definition),
        "cleanup-idempotent" => case_cleanup_idempotent(artifact_root, definition),
        "indeterminate-write-blocks-handoff" => {
            case_indeterminate_blocks(artifact_root, definition)
        }
        "destination-reauthorization-denied" => case_destination_denied(artifact_root, definition),
        other => Err(format!("unimplemented Stage 3A case {other}")),
    }
}

fn case_read_write_offset(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        b"abcdef",
        Stage3aFixtureOptions {
            destination_file_policy: true,
            source_fault: Some(FaultPoint::BeforeProfileEffect),
        },
    )?;
    let transient_observe_failure = matches!(
        case.source.execute(RegularFileOperation::Read { max_bytes: 2 }, None),
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Unavailable
        )))
    );
    let pending_observe = case
        .source
        .coordinator()
        .state()
        .operations
        .last()
        .filter(|record| record.outcome.is_none())
        .map(|record| record.request.operation);
    let retried = case
        .source
        .execute(RegularFileOperation::Read { max_bytes: 2 }, None)
        .map_err(adapter_error)?;
    let retried_operation = parse_identity(&retried.operation_id);
    let transient_observe_retried = transient_observe_failure
        && pending_observe.is_some()
        && retried_operation == pending_observe
        && case
            .source
            .coordinator()
            .state()
            .operations
            .iter()
            .all(|record| record.outcome.is_some());
    case.operations.push(retried.operation_id);
    let read = retried.result;
    let read_ok = matches!(read, RegularFileResult::Read { ref bytes, logical_offset: 2, .. } if bytes == b"ab");
    execute(
        &mut case,
        RegularFileOperation::Write { bytes: b"XY".to_vec(), durability: FileDurability::Visible },
        Some("write-offset"),
    )?;
    let mut committed = handoff(&mut case)?;
    let read_after = execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::Read { max_bytes: 2 },
        None,
    )?;
    let state = canonical_file(committed.destination.coordinator().state())?;
    let after = read_live_file(&case.paths, &state);
    capture(
        case,
        committed,
        vec![
            ("transient_observe_retried", transient_observe_retried),
            ("bytes_preserved", read_ok && after == b"abXYef"),
            ("logical_offset_preserved", state.logical_offset == 6),
            (
                "write_once",
                state.version == 2
                    && matches!(read_after, RegularFileResult::Read { ref bytes, .. } if bytes == b"ef"),
            ),
        ],
        json!({
            "transient_observe_failure": transient_observe_failure,
            "pending_observe_operation": pending_observe.map(identity_hex),
            "retried_observe_operation": retried_operation.map(identity_hex),
            "final_file": String::from_utf8_lossy(&after),
            "version": state.version,
            "offset": state.logical_offset,
        }),
    )
}

fn case_append_continuity(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"abc", Stage3aFixtureOptions::standard())?;
    execute(
        &mut case,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Data },
        Some("append-continuity"),
    )?;
    let source_operation = case.operations.last().cloned().ok_or("missing source append")?;
    let mut committed = handoff(&mut case)?;
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Data },
        Some("append-continuity"),
    )?;
    let replay_operation = case.operations.last().cloned().ok_or("missing replayed append")?;
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::Append { bytes: b"?".to_vec(), durability: FileDurability::Data },
        Some("append-destination"),
    )?;
    let state = canonical_file(committed.destination.coordinator().state())?;
    let after = read_live_file(&case.paths, &state);
    let expected_digest = contract_core::canonical_digest(after.as_slice())
        .map_err(|_| "cannot digest appended file")?;
    capture(
        case,
        committed,
        vec![
            (
                "append_once",
                after == b"abc!?" && state.version == 3 && replay_operation == source_operation,
            ),
            ("size_preserved", state.size == 5 && state.logical_offset == 5),
            ("digest_preserved", state.content_digest == expected_digest),
        ],
        json!({
            "final_file": String::from_utf8_lossy(&after),
            "version": state.version,
            "source_operation": source_operation,
            "replayed_operation": replay_operation,
        }),
    )
}

fn case_truncate_version(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"abcdef", Stage3aFixtureOptions::standard())?;
    execute(
        &mut case,
        RegularFileOperation::Truncate { size: 3, durability: FileDurability::DataAndMetadata },
        Some("truncate"),
    )?;
    let committed = handoff(&mut case)?;
    let state = canonical_file(committed.destination.coordinator().state())?;
    let after = read_live_file(&case.paths, &state);
    let expected_digest = contract_core::canonical_digest(after.as_slice())
        .map_err(|_| "cannot digest truncated file")?;
    capture(
        case,
        committed,
        vec![
            ("size_preserved", state.size == 3 && after == b"abc"),
            ("version_advanced", state.version == 2),
            ("digest_preserved", state.content_digest == expected_digest),
        ],
        json!({"size": state.size, "version": state.version}),
    )
}

fn case_rename_identity(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut case = start_case(root, definition, b"rename-me", Stage3aFixtureOptions::standard())?;
    let inode_before =
        fs::metadata(&case.paths.file_path).map_err(io_error("inspect source inode"))?.ino();
    let occupied = case.paths.file_root.join("occupied.bin");
    fs::write(&occupied, b"occupied-target").map_err(io_error("create occupied rename target"))?;
    let profile_before_conflict = canonical_file(case.source.coordinator().state())?;
    let occupied_rejected = is_file_conflict(case.source.execute(
        RegularFileOperation::Rename { relative_path: b"occupied.bin".to_vec() },
        Some("rename-occupied"),
    ));
    let profile_after_conflict = canonical_file(case.source.coordinator().state())?;
    let occupied_bytes =
        fs::read(&occupied).map_err(io_error("read occupied rename target after conflict"))?;
    let source_bytes = fs::read(&case.paths.file_path)
        .map_err(io_error("read source after occupied rename conflict"))?;
    let existing_target_preserved = occupied_rejected
        && occupied_bytes == b"occupied-target"
        && source_bytes == b"rename-me"
        && profile_before_conflict == profile_after_conflict;
    execute(
        &mut case,
        RegularFileOperation::Rename { relative_path: b"renamed.bin".to_vec() },
        Some("rename"),
    )?;
    let renamed = case.paths.file_root.join("renamed.bin");
    let inode_after = fs::metadata(&renamed).map_err(io_error("inspect renamed inode"))?.ino();
    let mut committed = handoff(&mut case)?;
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::Read { max_bytes: 9 },
        None,
    )?;
    let state = canonical_file(committed.destination.coordinator().state())?;
    capture(
        case,
        committed,
        vec![
            ("path_rebound", state.claim.relative_path == b"renamed.bin"),
            ("object_identity_preserved", inode_before == inode_after),
            ("existing_target_preserved", existing_target_preserved),
            ("old_path_absent", !renamed.with_file_name("data.bin").exists()),
        ],
        json!({
            "inode_before": inode_before,
            "inode_after": inode_after,
            "occupied_rename_rejected": occupied_rejected,
            "occupied_bytes_preserved": occupied_bytes == b"occupied-target",
            "source_bytes_preserved_after_conflict": source_bytes == b"rename-me",
            "profile_state_preserved_after_conflict": profile_before_conflict == profile_after_conflict,
            "path": "renamed.bin",
        }),
    )
}

fn case_replacement_rejected(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"same", Stage3aFixtureOptions::standard())?;
    let extension_before = canonical_file(case.source.coordinator().state())?;
    let replacement = case.paths.file_root.join("replacement.bin");
    fs::write(&replacement, b"same").map_err(io_error("write replacement"))?;
    fs::rename(&replacement, &case.paths.file_path).map_err(io_error("replace file"))?;
    let rejected =
        is_file_conflict(case.source.execute(RegularFileOperation::Read { max_bytes: 4 }, None));
    let extension_after = canonical_file(case.source.coordinator().state())?;
    rejected_capture(
        case,
        vec![
            ("replacement_detected", rejected),
            ("same_content_not_accepted", extension_before == extension_after),
        ],
        json!({"replacement_detected": rejected, "same_bytes": true}),
    )
}

fn case_external_mutation(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"original", Stage3aFixtureOptions::standard())?;
    let extension_before = canonical_file(case.source.coordinator().state())?;
    fs::write(&case.paths.file_path, b"external").map_err(io_error("mutate file externally"))?;
    let rejected =
        is_file_conflict(case.source.execute(RegularFileOperation::Read { max_bytes: 8 }, None));
    let extension_after = canonical_file(case.source.coordinator().state())?;
    rejected_capture(
        case,
        vec![
            ("version_conflict_detected", rejected),
            ("canonical_state_unchanged", extension_before == extension_after),
        ],
        json!({"external_bytes": "external", "rejected": rejected}),
    )
}

fn case_lock_conflict(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"locked", Stage3aFixtureOptions::standard())?;
    execute(&mut case, RegularFileOperation::AcquireLock, Some("lock-source"))?;
    let competitor = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&case.paths.file_path)
        .map_err(io_error("open competing file"))?;
    let exclusive =
        rustix::fs::flock(&competitor, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .is_err();
    let live_lock_rejected = matches!(
        case.source.freeze(),
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::SafePointUnavailable))
    );
    execute(&mut case, RegularFileOperation::ReleaseLock, Some("unlock-source"))?;
    let mut committed = handoff(&mut case)?;
    let frozen = committed.portable.decode().map_err(adapter_codec_error)?;
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::AcquireLock,
        Some("lock-destination"),
    )?;
    let reacquired = canonical_file(committed.destination.coordinator().state())?.lock_state
        == FileLockState::Held;
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::ReleaseLock,
        Some("unlock-destination"),
    )?;
    capture(
        case,
        committed,
        vec![
            ("exclusive_lock_enforced", exclusive),
            (
                "lock_not_snapshotted_live",
                live_lock_rejected && frozen.lock_state == FileLockState::Unlocked,
            ),
            ("reacquired", reacquired),
        ],
        json!({"competing_lock_denied": exclusive, "live_lock_freeze_rejected": live_lock_rejected}),
    )
}

fn case_durability_reconciled(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        b"a",
        Stage3aFixtureOptions {
            destination_file_policy: true,
            source_fault: Some(FaultPoint::AfterRegularFileMutation),
        },
    )?;
    let operation = RegularFileOperation::Append {
        bytes: b"b".to_vec(),
        durability: FileDurability::DataAndMetadata,
    };
    let indeterminate_operation = match case
        .source
        .execute(operation.clone(), Some("durable-append"))
    {
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Indeterminate(operation),
        ))) => operation,
        other => return Err(format!("expected post-mutation indeterminate result, got {other:?}")),
    };
    case.operations.push(indeterminate_operation.clone());
    let live_after_fault =
        fs::read(&case.paths.file_path).map_err(io_error("read file after post-mutation fault"))?;
    execute(&mut case, operation, Some("durable-append"))?;
    let canonical_after_reconcile = canonical_file(case.source.coordinator().state())?;
    let reconciled = identity_hex(
        canonical_after_reconcile
            .last_operation
            .ok_or("reconciled durability operation did not update canonical state")?,
    ) == indeterminate_operation;
    let committed = handoff(&mut case)?;
    let state = canonical_file(committed.destination.coordinator().state())?;
    let after = read_live_file(&case.paths, &state);
    capture(
        case,
        committed,
        vec![
            ("durability_met", state.durable_through == FileDurability::DataAndMetadata),
            ("lost_ack_reconciled", reconciled),
            (
                "mutation_not_repeated",
                live_after_fault == b"ab" && after == b"ab" && state.version == 2,
            ),
        ],
        json!({
            "final_file": String::from_utf8_lossy(&after),
            "live_file_after_fault": String::from_utf8_lossy(&live_after_fault),
            "indeterminate_operation": indeterminate_operation,
            "reconciled": reconciled,
        }),
    )
}

fn case_stale_source_fenced(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"fence", Stage3aFixtureOptions::standard())?;
    let mut committed = handoff(&mut case)?;
    let source_denied = matches!(
        case.source.coordinator().provider().check_lease(
            case.ids.file,
            case.ids.source_node,
            INITIAL_LEASE_EPOCH,
        ),
        Err(error) if error.kind == ProviderErrorKind::StaleEpoch
    );
    execute_destination(
        &mut case.operations,
        &mut committed.destination,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Visible },
        Some("destination-write"),
    )?;
    let ownership = committed.destination.coordinator().state().ownership;
    let destination_epoch_advanced = ownership.owner == Some(case.ids.destination_node)
        && ownership.epoch == INITIAL_LEASE_EPOCH.next().ok_or("lease epoch exhausted")?;
    let destination_state = canonical_file(committed.destination.coordinator().state())?;
    capture(
        case,
        committed,
        vec![
            ("destination_epoch_advanced", destination_epoch_advanced),
            ("source_write_denied", source_denied),
            ("destination_write_succeeded", destination_state.version == 2),
        ],
        json!({
            "source_resume_denied": source_denied,
            "destination_owner": ownership.owner.map(|owner| identity_hex(owner.0)),
            "destination_epoch": ownership.epoch.0,
            "destination_version": destination_state.version,
        }),
    )
}

fn case_cleanup_idempotent(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(root, definition, b"clean", Stage3aFixtureOptions::standard())?;
    execute(
        &mut case,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Visible },
        Some("cleanup-write"),
    )?;
    let operation_text = case.operations.last().cloned().ok_or("missing cleanup operation")?;
    let operation = parse_identity(&operation_text).ok_or("invalid cleanup operation identity")?;
    let evidence = EvidenceRef {
        identity: derive_identity(definition.id, "cleanup-evidence"),
        kind: EvidenceKind::Cleanup,
        digest: case.source.coordinator().state_digest().map_err(runtime_error)?,
    };
    case.source
        .coordinator_mut()
        .cleanup_operation(derive_identity(definition.id, "cleanup-one"), operation, evidence)
        .map_err(runtime_error)?;
    let cleaned_after_first = case.source.coordinator().state().operations.iter().any(|record| {
        record.request.operation == operation && record.cleanup == CleanupStatus::Cleaned
    });
    case.source
        .coordinator_mut()
        .cleanup_operation(derive_identity(definition.id, "cleanup-two"), operation, evidence)
        .map_err(runtime_error)?;
    let matching_after_second = case
        .source
        .coordinator()
        .state()
        .operations
        .iter()
        .filter(|record| record.request.operation == operation)
        .collect::<Vec<_>>();
    let cleanup_repeated = cleaned_after_first
        && matching_after_second.len() == 1
        && matching_after_second[0].cleanup == CleanupStatus::Cleaned;
    let retained = matching_after_second.first().is_some_and(|record| record.outcome.is_some());
    let matching_records_after_second = matching_after_second.len();
    let committed = handoff(&mut case)?;
    capture(
        case,
        committed,
        vec![("cleanup_repeated", cleanup_repeated), ("operation_truth_retained", retained)],
        json!({
            "operation": operation_text,
            "cleaned_after_first": cleaned_after_first,
            "matching_records_after_second": matching_records_after_second,
            "operation_outcome_retained": retained,
        }),
    )
}

fn case_indeterminate_blocks(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        b"a",
        Stage3aFixtureOptions {
            destination_file_policy: true,
            source_fault: Some(FaultPoint::AfterProfileEffect),
        },
    )?;
    let unknown = matches!(
        case.source.execute(
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
            Some("unknown-write")
        ),
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Indeterminate(_)
        )))
    );
    let operation =
        case.source.coordinator().state().operations.last().map(|record| record.request.operation);
    if let Some(operation) = operation {
        case.operations.push(identity_hex(operation));
    }
    case.source
        .coordinator_mut()
        .begin_quiesce(
            derive_identity(definition.id, "blocked-begin"),
            case.ids.source_handoff_authority,
        )
        .map_err(runtime_error)?;
    let safe_point = case.source.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = case.source.freeze().map_err(adapter_error)?;
    let blocked = matches!(
        case.source.coordinator_mut().commit_safe_point(
            derive_identity(definition.id, "blocked-freeze"),
            portable.as_bytes().to_vec(),
            safe_point,
        ),
        Err(RuntimeError::Rejected(contract_core::Rejection::IndeterminateEffect { .. }))
    );
    let lease = case
        .source
        .coordinator()
        .provider()
        .current_lease(case.ids.file)
        .map_err(provider_error)?;
    let source_node = case.ids.source_node;
    blocked_capture(
        case,
        vec![
            ("unknown_outcome_recorded", unknown),
            ("freeze_rejected", blocked),
            (
                "no_lease_transfer",
                lease.is_some_and(|lease| {
                    lease.owner == source_node && lease.epoch == INITIAL_LEASE_EPOCH
                }),
            ),
        ],
        json!({"unknown": unknown, "handoff_blocked": blocked}),
    )
}

fn case_destination_denied(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        b"policy",
        Stage3aFixtureOptions { destination_file_policy: false, source_fault: None },
    )?;
    let (mut destination, _portable) = export_to_destination(&mut case)?;
    let denied = matches!(
        destination.prepare_destination_with_profiles(
            derive_identity(definition.id, "destination-prepare"),
            case.handoff_authority,
            case.timer_authority,
            case.key_value_authority,
            &[case.file_authority],
        ),
        Err(RuntimeError::Provider(error)) if error.kind == ProviderErrorKind::Denied
    );
    let no_binding = destination.state().prepared_destination.is_none();
    let lease = destination.provider().current_lease(case.ids.file).map_err(provider_error)?;
    let source_node = case.ids.source_node;
    blocked_capture(
        case,
        vec![
            ("destination_policy_denied", denied),
            ("binding_not_published", no_binding),
            (
                "source_lease_retained",
                lease.is_some_and(|lease| {
                    lease.owner == source_node && lease.epoch == INITIAL_LEASE_EPOCH
                }),
            ),
        ],
        json!({"prepare_denied": denied, "prepared_destination": !no_binding}),
    )
}

fn start_case(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
    initial: &[u8],
    options: Stage3aFixtureOptions,
) -> Result<CaseContext, String> {
    let fixture = Stage3aFixture::create(root, definition.id, initial, options)?;
    let Stage3aFixture {
        case_id,
        paths,
        ids,
        source_state,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        file_authority,
        source,
        destination,
        ..
    } = fixture;
    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(
            derive_identity(definition.id, "activate"),
            ids.source_handoff_authority,
            INITIAL_LEASE_EPOCH,
        )
        .map_err(runtime_error)?;
    let mut source = RegularFileAdapter::instantiate(component::stage3a_bytes(), coordinator)
        .map_err(adapter_error)?;
    source.activate(format!("{}:session", definition.id)).map_err(adapter_error)?;
    let canonical_before = source.coordinator().state_digest().map_err(runtime_error)?;
    let file_before = fs::read(&paths.file_path).map_err(io_error("read initial file"))?;
    Ok(CaseContext {
        definition,
        case_id,
        paths,
        ids,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        file_authority,
        source,
        destination_provider: Some(destination),
        canonical_before,
        file_before,
        operations: Vec::new(),
    })
}

fn execute(
    case: &mut CaseContext,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<RegularFileResult, String> {
    let result = case.source.execute(operation, key).map_err(adapter_error)?;
    case.operations.push(result.operation_id);
    Ok(result.result)
}

fn execute_destination(
    operations: &mut Vec<String>,
    destination: &mut RegularFileAdapter<SqliteProvider>,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<RegularFileResult, String> {
    let result = destination.execute(operation, key).map_err(adapter_error)?;
    operations.push(result.operation_id);
    Ok(result.result)
}

fn handoff(case: &mut CaseContext) -> Result<CommittedContext, String> {
    let (mut destination, portable) = export_to_destination(case)?;
    destination
        .prepare_destination_with_profiles(
            derive_identity(&case.case_id, "destination-prepare"),
            case.handoff_authority,
            case.timer_authority,
            case.key_value_authority,
            &[case.file_authority],
        )
        .map_err(runtime_error)?;
    destination
        .commit_handoff(
            derive_identity(&case.case_id, "destination-commit-command"),
            derive_identity(&case.case_id, "destination-commit-operation"),
            IdempotencyKey::from_bytes(
                derive_identity(&case.case_id, "destination-commit-idempotency").0,
            ),
        )
        .map_err(runtime_error)?;
    let mut destination = RegularFileAdapter::instantiate(component::stage3a_bytes(), destination)
        .map_err(adapter_error)?;
    destination.restore(&portable).map_err(adapter_error)?;
    destination
        .coordinator_mut()
        .resume_destination(derive_identity(&case.case_id, "destination-resume"))
        .map_err(runtime_error)?;
    Ok(CommittedContext { destination, portable })
}

fn export_to_destination(
    case: &mut CaseContext,
) -> Result<(Coordinator<SqliteProvider>, PortableRegularFileState), String> {
    case.source
        .coordinator_mut()
        .begin_quiesce(
            derive_identity(&case.case_id, "source-begin-quiesce"),
            case.ids.source_handoff_authority,
        )
        .map_err(runtime_error)?;
    let safe_point = case.source.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = match case.source.freeze() {
        Ok(portable) => portable,
        Err(error) => {
            case.source.coordinator_mut().cancel_safe_point(safe_point).map_err(runtime_error)?;
            return Err(adapter_error(error));
        }
    };
    if let Err(error) = case.source.coordinator_mut().commit_safe_point(
        derive_identity(&case.case_id, "source-freeze"),
        portable.as_bytes().to_vec(),
        safe_point,
    ) {
        case.source.thaw(&portable).map_err(adapter_error)?;
        return Err(runtime_error(error));
    }
    let evidence = EvidenceRef {
        identity: derive_identity(&case.case_id, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: case.source.coordinator().state_digest().map_err(runtime_error)?,
    };
    let (_, snapshot) = case
        .source
        .coordinator_mut()
        .export_snapshot(
            derive_identity(&case.case_id, "source-export"),
            case.ids.handoff,
            case.ids.snapshot,
            evidence,
        )
        .map_err(runtime_error)?;
    let validated = validate_snapshot(
        &snapshot,
        &SnapshotExpectations {
            component_digest: component::stage3a_digest(),
            profile_digest: case.profile_digest,
            profile_version: SchemaVersion::new(1, 0),
            supported_extensions: vec![ExtensionSupport {
                id: REGULAR_FILE_EXTENSION_ID,
                version: REGULAR_FILE_EXTENSION_VERSION,
            }],
            destination: case.ids.destination_node,
        },
    )
    .map_err(runtime_error)?;
    let provider = case.destination_provider.take().ok_or("destination provider already used")?;
    let destination = Coordinator::restore(validated, provider).map_err(runtime_error)?;
    Ok((destination, portable))
}

fn capture(
    case: CaseContext,
    committed: CommittedContext,
    assertions: Vec<(&str, bool)>,
    trace: serde_json::Value,
) -> Result<Stage3CaseCapture, String> {
    let state = canonical_file(committed.destination.coordinator().state())?;
    let destination_epoch = committed.destination.coordinator().state().ownership.epoch.0;
    let file_after = read_live_file(&case.paths, &state);
    let canonical_after =
        committed.destination.coordinator().state_digest().map_err(runtime_error)?;
    Ok(Stage3CaseCapture {
        definition: case.definition,
        canonical_before: case.canonical_before,
        canonical_after,
        source_epoch: INITIAL_LEASE_EPOCH.0,
        destination_epoch: Some(destination_epoch),
        profile_operations: case.operations,
        assertions: named_assertions(assertions),
        trace: json!({
            "case_id": case.definition.id,
            "terminal": terminal_name(case.definition.terminal),
            "source_phase": format!("{:?}", case.source.coordinator().state().phase),
            "destination_phase": format!("{:?}", committed.destination.coordinator().state().phase),
            "observations": trace,
        }),
        file_before: case.file_before,
        file_after,
    })
}

fn rejected_capture(
    case: CaseContext,
    assertions: Vec<(&str, bool)>,
    trace: serde_json::Value,
) -> Result<Stage3CaseCapture, String> {
    terminal_capture(case, Stage3CaseTerminal::ProfileRejected, assertions, trace)
}

fn blocked_capture(
    case: CaseContext,
    assertions: Vec<(&str, bool)>,
    trace: serde_json::Value,
) -> Result<Stage3CaseCapture, String> {
    terminal_capture(case, Stage3CaseTerminal::HandoffBlocked, assertions, trace)
}

fn terminal_capture(
    case: CaseContext,
    terminal: Stage3CaseTerminal,
    assertions: Vec<(&str, bool)>,
    trace: serde_json::Value,
) -> Result<Stage3CaseCapture, String> {
    if case.definition.terminal != terminal {
        return Err(format!("{} has an unexpected terminal class", case.definition.id));
    }
    let state = canonical_file(case.source.coordinator().state())?;
    let file_after = read_live_file(&case.paths, &state);
    let source_epoch = case.source.coordinator().state().ownership.epoch.0;
    Ok(Stage3CaseCapture {
        definition: case.definition,
        canonical_before: case.canonical_before,
        canonical_after: case.source.coordinator().state_digest().map_err(runtime_error)?,
        source_epoch,
        destination_epoch: None,
        profile_operations: case.operations,
        assertions: named_assertions(assertions),
        trace: json!({
            "case_id": case.definition.id,
            "terminal": terminal_name(terminal),
            "source_phase": format!("{:?}", case.source.coordinator().state().phase),
            "observations": trace,
        }),
        file_before: case.file_before,
        file_after,
    })
}

fn remove_completed_work_tree(work_root: &Path) -> Result<(), String> {
    fs::remove_dir_all(work_root).map_err(|error| {
        format!("cannot remove completed Stage 3 work tree {}: {error}", work_root.display())
    })
}

fn named_assertions(assertions: Vec<(&str, bool)>) -> Vec<(String, bool)> {
    assertions.into_iter().map(|(name, passed)| (name.to_owned(), passed)).collect()
}

fn canonical_file(state: &contract_core::CanonicalState) -> Result<RegularFileState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension = matching.next().ok_or("missing regular-file extension")?;
    if matching.next().is_some() {
        return Err("duplicate regular-file extension".to_owned());
    }
    regular_file_state(extension).map_err(|error| format!("invalid regular-file state: {error:?}"))
}

fn read_live_file(paths: &FixturePaths, state: &RegularFileState) -> Vec<u8> {
    let relative = String::from_utf8_lossy(&state.claim.relative_path);
    fs::read(paths.file_root.join(relative.as_ref())).unwrap_or_default()
}

fn is_file_conflict(
    result: Result<visa_wasmtime::RegularFileCallResult, RegularFileAdapterError>,
) -> bool {
    matches!(
        result,
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Conflict
        )))
    )
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    u64::try_from(duration.as_millis()).map_err(|_| "timestamp does not fit u64".to_owned())
}

fn identity_hex(identity: Identity) -> String {
    visa_component_adapter::identity_string(identity)
}

fn runtime_error(error: RuntimeError) -> String {
    format!("runtime error: {error:?}")
}

fn adapter_error(error: RegularFileAdapterError) -> String {
    format!("regular-file adapter error: {error}")
}

fn adapter_codec_error(error: visa_component_adapter::RegularFileStateCodecError) -> String {
    format!("regular-file state error: {error:?}")
}

fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("provider error: {:?} (retryable={})", error.kind, error.retryable)
}

fn io_error(action: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("cannot {action}: {error}")
}
