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
use visa_component_adapter::{
    PortableRegularFileState, RegularFileAdapterError, RegularFileCallResult, RegularFileFailure,
    RegularFileWorkloadFailure, parse_identity,
};
use visa_conformance::{
    STAGE3A_CASE_DEFINITIONS, Stage3CaseDefinition, Stage3CaseTerminal, Stage3RuntimeScope,
};
use visa_profile::{
    FileDurability, FileLockState, REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION,
    RegularFileOperation, RegularFileResult, RegularFileState, regular_file_state,
};
use visa_regular_file_observation::{
    EndpointObservation, ErrorCode, ErrorDomain, GenericCallResult, ObservationActor,
    ObservationPhase, OsAction, ProtocolAction, RawErrorObservation, RegularFileObservationBundle,
    RouteMode, RouteObservation,
};
use visa_runtime::{Coordinator, RuntimeError, SnapshotExpectations, validate_snapshot};

use crate::{
    component,
    evidence::{
        Stage3CaseCapture, Stage3aPublication, create_incomplete_marker, publish_stage3a,
        runtime_identity, terminal_name,
    },
    fixture::{
        FixtureIds, FixturePaths, INITIAL_LEASE_EPOCH, Stage3aFixture, Stage3aFixtureOptions,
        derive_identity,
    },
    observation::{
        CaseObservationRecorder, adapter_error_result, identity_hex as observation_identity_hex,
        operation_id_after_call, returned, runtime_error_result,
    },
    regular_file_runtime::{
        MatrixRegularFileAdapter, RegularFileRuntimeKind, RegularFileRuntimePair,
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
    runtime_pair: RegularFileRuntimePair,
    source: MatrixRegularFileAdapter,
    destination_provider: Option<SqliteProvider>,
    canonical_before: Digest,
    file_before: Vec<u8>,
    operations: Vec<String>,
    route: RouteMode,
    observation: CaseObservationRecorder,
}

enum ContinuedContext {
    Uninterrupted,
    Handoff { destination: MatrixRegularFileAdapter, portable: PortableRegularFileState },
}

pub fn run_stage3a(artifact_root: &Path) -> Result<PathBuf, String> {
    run_stage3a_for_pair(artifact_root, RegularFileRuntimePair::WASMTIME_BASELINE)
}

pub(crate) fn run_stage3a_for_pair(
    artifact_root: &Path,
    runtime_pair: RegularFileRuntimePair,
) -> Result<PathBuf, String> {
    create_incomplete_marker(artifact_root)?;
    let work_root = artifact_root.join(".stage3-work");
    let started = now_unix_ms()?;
    let mut control_captures = Vec::with_capacity(STAGE3A_CASE_DEFINITIONS.len());
    let control_root = work_root.join("control");
    for definition in STAGE3A_CASE_DEFINITIONS {
        control_captures.push(run_case(
            &control_root,
            definition,
            runtime_pair,
            RouteMode::UninterruptedControl,
        )?);
    }
    let mut captures = Vec::with_capacity(STAGE3A_CASE_DEFINITIONS.len());
    let candidate_root = work_root.join("candidate");
    for definition in STAGE3A_CASE_DEFINITIONS {
        captures.push(run_case(&candidate_root, definition, runtime_pair, RouteMode::Handoff)?);
    }
    remove_completed_work_tree(&work_root)?;
    let finished = now_unix_ms()?;
    let includes_wacogo = runtime_pair.source == RegularFileRuntimeKind::SourceLockedWacogo
        || runtime_pair.destination == RegularFileRuntimeKind::SourceLockedWacogo;
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
        "source_runtime": runtime_pair.source.implementation(),
        "destination_runtime": runtime_pair.destination.implementation(),
        "independent_runtime_coverage": includes_wacogo,
        "provider": "substrate_host::SqliteProvider",
        "path_resolution": "linux-openat2-beneath-no-symlink-no-xdev",
        "native_identity": "linux-statx-device-inode-birth-time-required",
        "effect_fence": "sqlite-immediate-effect-admission-authority-lease-prestate-recheck",
        "file_effect_and_sqlite_outcome_atomic": false,
        "external_mutation_boundary":
            "pre-operation-drift-detection-and-cooperative-advisory-lock-lease",
        "component_state_encoding": "visa-regular-file-state-v1",
        "execution_boundary": runtime_pair.execution_boundary(),
        "case_count": STAGE3A_CASE_DEFINITIONS.len(),
    });
    let runtime = Stage3RuntimeScope {
        source: runtime_identity(&runtime_pair.source.runtime_identity()),
        destination: runtime_identity(&runtime_pair.destination.runtime_identity()),
        host_os: std::env::consts::OS.to_owned(),
        source_isa: std::env::consts::ARCH.to_owned(),
        destination_isa: std::env::consts::ARCH.to_owned(),
        substrate: "substrate_host::SqliteProvider".to_owned(),
        execution_boundary: runtime_pair.execution_boundary().to_owned(),
        independent_runtime_coverage: includes_wacogo,
        unsupported_runtime_implementations: if includes_wacogo {
            Vec::new()
        } else {
            vec!["wacogo".to_owned()]
        },
    };
    let control_observation = observation_bundle(
        RouteMode::UninterruptedControl,
        runtime_pair,
        started,
        control_captures.into_iter().map(|capture| capture.raw_observation).collect(),
    );
    let candidate_observation = observation_bundle(
        RouteMode::Handoff,
        runtime_pair,
        started,
        captures.iter().map(|capture| capture.raw_observation.clone()).collect(),
    );
    publish_stage3a(
        artifact_root,
        started,
        finished,
        &profile_manifest,
        &configuration,
        Stage3aPublication {
            runtime,
            control_observation: &control_observation,
            candidate_observation: &candidate_observation,
            captures: &captures,
        },
    )
}

fn observation_bundle(
    mode: RouteMode,
    runtime_pair: RegularFileRuntimePair,
    started_at_unix_ms: u64,
    cases: Vec<visa_regular_file_observation::RegularFileCaseObservation>,
) -> RegularFileObservationBundle {
    let route_name = if mode == RouteMode::UninterruptedControl { "control" } else { "candidate" };
    RegularFileObservationBundle::new(
        format!(
            "stage3a-{route_name}-{}-{}-{started_at_unix_ms}",
            runtime_pair.source.implementation(),
            runtime_pair.destination.implementation()
        ),
        RouteObservation {
            mode,
            source: observation_endpoint(runtime_pair.source, "source"),
            destination: (mode != RouteMode::UninterruptedControl)
                .then(|| observation_endpoint(runtime_pair.destination, "destination")),
            execution_boundary: if mode == RouteMode::UninterruptedControl {
                "single-runtime-instance-uninterrupted-control".to_owned()
            } else {
                runtime_pair.execution_boundary().to_owned()
            },
            carrier: None,
        },
        cases,
    )
}

fn observation_endpoint(kind: RegularFileRuntimeKind, role: &str) -> EndpointObservation {
    let identity = kind.runtime_identity();
    EndpointObservation {
        instance_id: format!("stage3a-{role}-{}", identity.implementation),
        runtime: identity.implementation,
        runtime_version: identity.implementation_version,
        host_id: observation_host_id(),
        operating_system: std::env::consts::OS.to_owned(),
        isa: std::env::consts::ARCH.to_owned(),
    }
}

fn observation_host_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "stage3a-local-host".to_owned())
}

fn run_case(
    artifact_root: &Path,
    definition: &'static Stage3CaseDefinition,
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    match definition.id {
        "read-write-offset" => {
            case_read_write_offset(artifact_root, definition, runtime_pair, route)
        }
        "append-continuity" => {
            case_append_continuity(artifact_root, definition, runtime_pair, route)
        }
        "truncate-version" => case_truncate_version(artifact_root, definition, runtime_pair, route),
        "rename-object-identity" => {
            case_rename_identity(artifact_root, definition, runtime_pair, route)
        }
        "replacement-rejected" => {
            case_replacement_rejected(artifact_root, definition, runtime_pair, route)
        }
        "external-mutation-rejected" => {
            case_external_mutation(artifact_root, definition, runtime_pair, route)
        }
        "lock-conflict" => case_lock_conflict(artifact_root, definition, runtime_pair, route),
        "durability-reconciled" => {
            case_durability_reconciled(artifact_root, definition, runtime_pair, route)
        }
        "stale-source-fenced" => {
            case_stale_source_fenced(artifact_root, definition, runtime_pair, route)
        }
        "cleanup-idempotent" => {
            case_cleanup_idempotent(artifact_root, definition, runtime_pair, route)
        }
        "indeterminate-write-blocks-handoff" => {
            case_indeterminate_blocks(artifact_root, definition, runtime_pair, route)
        }
        "destination-reauthorization-denied" => {
            case_destination_denied(artifact_root, definition, runtime_pair, route)
        }
        other => Err(format!("unimplemented Stage 3A case {other}")),
    }
}

fn case_read_write_offset(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"abcdef",
        Stage3aFixtureOptions {
            destination_file_policy: true,
            source_fault: Some(FaultPoint::BeforeProfileEffect),
        },
    )?;
    let transient_observe_failure = matches!(
        attempt_source(&mut case, RegularFileOperation::Read { max_bytes: 2 }, None)?,
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
    let retried = attempt_source(&mut case, RegularFileOperation::Read { max_bytes: 2 }, None)?
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
    let mut committed = continue_route(&mut case)?;
    let read_after = execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::Read { max_bytes: 2 },
        None,
    )?;
    let state = canonical_file(continued_coordinator(&case, &committed).state())?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"abc",
        Stage3aFixtureOptions::standard(),
    )?;
    execute(
        &mut case,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Data },
        Some("append-continuity"),
    )?;
    let source_operation = case.operations.last().cloned().ok_or("missing source append")?;
    let mut committed = continue_route(&mut case)?;
    execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Data },
        Some("append-continuity"),
    )?;
    let replay_operation = case.operations.last().cloned().ok_or("missing replayed append")?;
    execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::Append { bytes: b"?".to_vec(), durability: FileDurability::Data },
        Some("append-destination"),
    )?;
    let state = canonical_file(continued_coordinator(&case, &committed).state())?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"abcdef",
        Stage3aFixtureOptions::standard(),
    )?;
    execute(
        &mut case,
        RegularFileOperation::Truncate { size: 3, durability: FileDurability::DataAndMetadata },
        Some("truncate"),
    )?;
    let committed = continue_route(&mut case)?;
    let state = canonical_file(continued_coordinator(&case, &committed).state())?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"rename-me",
        Stage3aFixtureOptions::standard(),
    )?;
    let inode_before =
        fs::metadata(&case.paths.file_path).map_err(io_error("inspect source inode"))?.ino();
    let occupied = case.paths.file_root.join("occupied.bin");
    fs::write(&occupied, b"occupied-target").map_err(io_error("create occupied rename target"))?;
    case.observation.os_call(
        ObservationPhase::Setup,
        ObservationActor::ExternalMutator,
        OsAction::WriteWhole { path: b"occupied.bin".to_vec(), bytes: b"occupied-target".to_vec() },
        returned(Vec::new()),
    );
    case.observation.file_probe(
        ObservationPhase::Setup,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &occupied,
    );
    let profile_before_conflict = canonical_file(case.source.coordinator().state())?;
    let occupied_rejected = is_file_conflict(attempt_source(
        &mut case,
        RegularFileOperation::Rename { relative_path: b"occupied.bin".to_vec() },
        Some("rename-occupied"),
    )?);
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
    case.observation.file_probe(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &renamed,
    );
    case.observation.file_probe(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &case.paths.file_path,
    );
    let mut committed = continue_route(&mut case)?;
    execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::Read { max_bytes: 9 },
        None,
    )?;
    let state = canonical_file(continued_coordinator(&case, &committed).state())?;
    case.observation.file_probe(
        ObservationPhase::FinalObservation,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &occupied,
    );
    case.observation.file_probe(
        ObservationPhase::FinalObservation,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &case.paths.file_path,
    );
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"same",
        Stage3aFixtureOptions::standard(),
    )?;
    let extension_before = canonical_file(case.source.coordinator().state())?;
    let replacement = case.paths.file_root.join("replacement.bin");
    fs::write(&replacement, b"same").map_err(io_error("write replacement"))?;
    case.observation.os_call(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalMutator,
        OsAction::WriteWhole { path: b"replacement.bin".to_vec(), bytes: b"same".to_vec() },
        returned(Vec::new()),
    );
    case.observation.file_probe(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &replacement,
    );
    fs::rename(&replacement, &case.paths.file_path).map_err(io_error("replace file"))?;
    case.observation.os_call(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalMutator,
        OsAction::ReplacePath {
            source: b"replacement.bin".to_vec(),
            destination: b"data.bin".to_vec(),
        },
        returned(Vec::new()),
    );
    case.observation.file_probe(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &case.paths.file_path,
    );
    let rejected = is_file_conflict(attempt_source(
        &mut case,
        RegularFileOperation::Read { max_bytes: 4 },
        None,
    )?);
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"original",
        Stage3aFixtureOptions::standard(),
    )?;
    let extension_before = canonical_file(case.source.coordinator().state())?;
    fs::write(&case.paths.file_path, b"external").map_err(io_error("mutate file externally"))?;
    case.observation.os_call(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalMutator,
        OsAction::WriteWhole { path: b"data.bin".to_vec(), bytes: b"external".to_vec() },
        returned(Vec::new()),
    );
    case.observation.file_probe(
        ObservationPhase::SourceExecution,
        ObservationActor::ExternalObserver,
        &case.paths.file_root,
        &case.paths.file_path,
    );
    let rejected = is_file_conflict(attempt_source(
        &mut case,
        RegularFileOperation::Read { max_bytes: 8 },
        None,
    )?);
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"locked",
        Stage3aFixtureOptions::standard(),
    )?;
    execute(&mut case, RegularFileOperation::AcquireLock, Some("lock-source"))?;
    let competitor = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&case.paths.file_path)
        .map_err(io_error("open competing file"))?;
    let competing_lock =
        rustix::fs::flock(&competitor, rustix::fs::FlockOperation::NonBlockingLockExclusive);
    case.observation.os_call(
        ObservationPhase::SourceExecution,
        ObservationActor::CompetingProcess,
        OsAction::TryExclusiveLock { path: b"data.bin".to_vec() },
        match competing_lock {
            Ok(()) => returned(Vec::new()),
            Err(error) => os_error_result(ErrorCode::WouldBlock, error.raw_os_error(), true),
        },
    );
    let exclusive = competing_lock.is_err();
    let live_freeze = case.source.freeze();
    case.observation.protocol_call(
        ObservationPhase::CarrierCapture,
        ObservationActor::SourceRuntime,
        ProtocolAction::FreezeRuntime {
            safe_point_id: observation_identity_hex(derive_identity(
                definition.id,
                "live-lock-probe",
            )),
        },
        match &live_freeze {
            Ok(portable) => returned(portable.as_bytes().to_vec()),
            Err(error) => adapter_error_result(error),
        },
    );
    let live_lock_rejected = matches!(
        live_freeze,
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::SafePointUnavailable))
    );
    execute(&mut case, RegularFileOperation::ReleaseLock, Some("unlock-source"))?;
    let mut committed = continue_route(&mut case)?;
    let frozen_lock_state = match &committed {
        ContinuedContext::Uninterrupted => {
            canonical_file(case.source.coordinator().state())?.lock_state
        }
        ContinuedContext::Handoff { portable, .. } => {
            portable.decode().map_err(adapter_codec_error)?.lock_state
        }
    };
    execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::AcquireLock,
        Some("lock-destination"),
    )?;
    let reacquired = canonical_file(continued_coordinator(&case, &committed).state())?.lock_state
        == FileLockState::Held;
    execute_continued(
        &mut case,
        &mut committed,
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
                live_lock_rejected && frozen_lock_state == FileLockState::Unlocked,
            ),
            ("reacquired", reacquired),
        ],
        json!({"competing_lock_denied": exclusive, "live_lock_freeze_rejected": live_lock_rejected}),
    )
}

fn case_durability_reconciled(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
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
    let indeterminate_operation =
        match attempt_source(&mut case, operation.clone(), Some("durable-append"))? {
            Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
                RegularFileFailure::Indeterminate(operation),
            ))) => operation,
            other => {
                return Err(format!("expected post-mutation indeterminate result, got {other:?}"));
            }
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
    let committed = continue_route(&mut case)?;
    let state = canonical_file(continued_coordinator(&case, &committed).state())?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"fence",
        Stage3aFixtureOptions::standard(),
    )?;
    let mut committed = continue_route(&mut case)?;
    let lease_check = case.source.coordinator().provider().check_lease(
        case.ids.file,
        case.ids.source_node,
        INITIAL_LEASE_EPOCH,
    );
    case.observation.lease_check(
        ObservationPhase::DestinationExecution,
        case.ids.file,
        case.ids.source_node,
        INITIAL_LEASE_EPOCH,
        &lease_check,
    );
    let source_denied = matches!(
        lease_check,
        Err(error) if error.kind == ProviderErrorKind::StaleEpoch
    );
    execute_continued(
        &mut case,
        &mut committed,
        RegularFileOperation::Append { bytes: b"!".to_vec(), durability: FileDurability::Visible },
        Some("destination-write"),
    )?;
    let ownership = continued_coordinator(&case, &committed).state().ownership;
    let expected_owner = if route == RouteMode::UninterruptedControl {
        case.ids.source_node
    } else {
        case.ids.destination_node
    };
    let expected_epoch = if route == RouteMode::UninterruptedControl {
        INITIAL_LEASE_EPOCH
    } else {
        INITIAL_LEASE_EPOCH.next().ok_or("lease epoch exhausted")?
    };
    let destination_epoch_advanced =
        ownership.owner == Some(expected_owner) && ownership.epoch == expected_epoch;
    let destination_state = canonical_file(continued_coordinator(&case, &committed).state())?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"clean",
        Stage3aFixtureOptions::standard(),
    )?;
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
    let cleanup_one_command = derive_identity(definition.id, "cleanup-one");
    let cleanup_one =
        case.source.coordinator_mut().cleanup_operation(cleanup_one_command, operation, evidence);
    case.observation.protocol_call(
        ObservationPhase::Cleanup,
        ObservationActor::Provider,
        ProtocolAction::CleanupOperation {
            command_id: observation_identity_hex(cleanup_one_command),
            operation_id: observation_identity_hex(operation),
            evidence_id: observation_identity_hex(evidence.identity),
        },
        match &cleanup_one {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    cleanup_one.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::Cleanup,
        ObservationActor::Provider,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let cleaned_after_first = case.source.coordinator().state().operations.iter().any(|record| {
        record.request.operation == operation && record.cleanup == CleanupStatus::Cleaned
    });
    let cleanup_two_command = derive_identity(definition.id, "cleanup-two");
    let cleanup_two =
        case.source.coordinator_mut().cleanup_operation(cleanup_two_command, operation, evidence);
    case.observation.protocol_call(
        ObservationPhase::Cleanup,
        ObservationActor::Provider,
        ProtocolAction::CleanupOperation {
            command_id: observation_identity_hex(cleanup_two_command),
            operation_id: observation_identity_hex(operation),
            evidence_id: observation_identity_hex(evidence.identity),
        },
        match &cleanup_two {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    cleanup_two.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::Cleanup,
        ObservationActor::Provider,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
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
    let committed = continue_route(&mut case)?;
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"a",
        Stage3aFixtureOptions {
            destination_file_policy: true,
            source_fault: Some(FaultPoint::AfterProfileEffect),
        },
    )?;
    let unknown = matches!(
        attempt_source(
            &mut case,
            RegularFileOperation::Append { bytes: b"b".to_vec(), durability: FileDurability::Data },
            Some("unknown-write")
        )?,
        Err(RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Indeterminate(_)
        )))
    );
    let operation =
        case.source.coordinator().state().operations.last().map(|record| record.request.operation);
    if let Some(operation) = operation {
        case.operations.push(identity_hex(operation));
    }
    let blocked = if route == RouteMode::UninterruptedControl {
        case.observation.checkpoint(
            ObservationPhase::Transfer,
            ObservationActor::SourceRuntime,
            case.source.coordinator(),
            &case.paths,
            case.ids.file,
        )?;
        false
    } else {
        let begin_command = derive_identity(definition.id, "blocked-begin");
        let begin = case
            .source
            .coordinator_mut()
            .begin_quiesce(begin_command, case.ids.source_handoff_authority);
        case.observation.protocol_call(
            ObservationPhase::Quiesce,
            ObservationActor::SourceRuntime,
            ProtocolAction::BeginQuiesce {
                command_id: observation_identity_hex(begin_command),
                authority_id: entity_ref_text(case.ids.source_handoff_authority),
            },
            match &begin {
                Ok(_) => returned(Vec::new()),
                Err(error) => runtime_error_result(error),
            },
        );
        begin.map_err(runtime_error)?;
        let safe_point_id =
            observation_identity_hex(derive_identity(definition.id, "blocked-safe-point"));
        let safe_point_result = case.source.coordinator_mut().prepare_safe_point();
        case.observation.protocol_call(
            ObservationPhase::Quiesce,
            ObservationActor::SourceRuntime,
            ProtocolAction::PrepareSafePoint { safe_point_id: safe_point_id.clone() },
            match &safe_point_result {
                Ok(_) => returned(Vec::new()),
                Err(error) => runtime_error_result(error),
            },
        );
        let safe_point = safe_point_result.map_err(runtime_error)?;
        let freeze = case.source.freeze();
        case.observation.protocol_call(
            ObservationPhase::CarrierCapture,
            ObservationActor::SourceRuntime,
            ProtocolAction::FreezeRuntime { safe_point_id: safe_point_id.clone() },
            match &freeze {
                Ok(portable) => returned(portable.as_bytes().to_vec()),
                Err(error) => adapter_error_result(error),
            },
        );
        let portable = freeze.map_err(adapter_error)?;
        let freeze_command = derive_identity(definition.id, "blocked-freeze");
        let commit = case.source.coordinator_mut().commit_safe_point(
            freeze_command,
            portable.as_bytes().to_vec(),
            safe_point,
        );
        case.observation.protocol_call(
            ObservationPhase::CarrierCapture,
            ObservationActor::SourceRuntime,
            ProtocolAction::CommitSafePoint {
                command_id: observation_identity_hex(freeze_command),
                safe_point_id,
            },
            match &commit {
                Ok(_) => returned(Vec::new()),
                Err(error) => runtime_error_result(error),
            },
        );
        matches!(
            commit,
            Err(RuntimeError::Rejected(contract_core::Rejection::IndeterminateEffect { .. }))
        )
    };
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
) -> Result<Stage3CaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        runtime_pair,
        route,
        b"policy",
        Stage3aFixtureOptions { destination_file_policy: false, source_fault: None },
    )?;
    let (denied, no_binding, lease) = if route == RouteMode::UninterruptedControl {
        case.observation.checkpoint(
            ObservationPhase::Transfer,
            ObservationActor::SourceRuntime,
            case.source.coordinator(),
            &case.paths,
            case.ids.file,
        )?;
        (
            false,
            true,
            case.source
                .coordinator()
                .provider()
                .current_lease(case.ids.file)
                .map_err(provider_error)?,
        )
    } else {
        let (mut destination, _portable) = export_to_destination(&mut case)?;
        let prepare_command = derive_identity(definition.id, "destination-prepare");
        let prepare = destination.prepare_destination_with_profiles(
            prepare_command,
            case.handoff_authority,
            case.timer_authority,
            case.key_value_authority,
            &[case.file_authority],
        );
        case.observation.protocol_call(
            ObservationPhase::DestinationPrepare,
            ObservationActor::Provider,
            ProtocolAction::PrepareDestination {
                command_id: observation_identity_hex(prepare_command),
            },
            match &prepare {
                Ok(_) => returned(Vec::new()),
                Err(error) => runtime_error_result(error),
            },
        );
        let denied = matches!(
            prepare,
            Err(RuntimeError::Provider(error)) if error.kind == ProviderErrorKind::Denied
        );
        case.observation.checkpoint(
            ObservationPhase::DestinationPrepare,
            ObservationActor::Provider,
            &destination,
            &case.paths,
            case.ids.file,
        )?;
        let no_binding = destination.state().prepared_destination.is_none();
        let lease = destination.provider().current_lease(case.ids.file).map_err(provider_error)?;
        (denied, no_binding, lease)
    };
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
    runtime_pair: RegularFileRuntimePair,
    route: RouteMode,
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
    let mut source = MatrixRegularFileAdapter::instantiate(
        runtime_pair.source,
        component::stage3a_bytes(),
        coordinator,
    )
    .map_err(adapter_error)?;
    source.activate(format!("{}:session", definition.id)).map_err(adapter_error)?;
    let canonical_before = source.coordinator().state_digest().map_err(runtime_error)?;
    let file_before = fs::read(&paths.file_path).map_err(io_error("read initial file"))?;
    let mut observation = CaseObservationRecorder::new(definition.id, route, ids)?;
    observation.checkpoint(
        ObservationPhase::Setup,
        ObservationActor::SourceRuntime,
        source.coordinator(),
        &paths,
        ids.file,
    )?;
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
        runtime_pair,
        source,
        destination_provider: Some(destination),
        canonical_before,
        file_before,
        operations: Vec::new(),
        route,
        observation,
    })
}

fn execute(
    case: &mut CaseContext,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<RegularFileResult, String> {
    let result = attempt_source(case, operation, key)?.map_err(adapter_error)?;
    case.operations.push(result.operation_id);
    Ok(result.result)
}

fn attempt_source(
    case: &mut CaseContext,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<Result<RegularFileCallResult, RegularFileAdapterError>, String> {
    let result = case.source.execute(operation.clone(), key);
    let operation_id = operation_id_after_call(case.source.coordinator(), &result);
    case.observation.operation_call(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        key,
        operation_id,
        &operation,
        &result,
    );
    case.observation.checkpoint(
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    Ok(result)
}

fn execute_destination(
    case: &mut CaseContext,
    destination: &mut MatrixRegularFileAdapter,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<RegularFileResult, String> {
    let result = destination.execute(operation.clone(), key);
    let operation_id = operation_id_after_call(destination.coordinator(), &result);
    case.observation.operation_call(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        key,
        operation_id,
        &operation,
        &result,
    );
    case.observation.checkpoint(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        destination.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let result = result.map_err(adapter_error)?;
    case.operations.push(result.operation_id);
    Ok(result.result)
}

fn execute_continued(
    case: &mut CaseContext,
    continued: &mut ContinuedContext,
    operation: RegularFileOperation,
    key: Option<&str>,
) -> Result<RegularFileResult, String> {
    match continued {
        ContinuedContext::Uninterrupted => execute(case, operation, key),
        ContinuedContext::Handoff { destination, .. } => {
            execute_destination(case, destination, operation, key)
        }
    }
}

fn continued_coordinator<'a>(
    case: &'a CaseContext,
    continued: &'a ContinuedContext,
) -> &'a Coordinator<SqliteProvider> {
    match continued {
        ContinuedContext::Uninterrupted => case.source.coordinator(),
        ContinuedContext::Handoff { destination, .. } => destination.coordinator(),
    }
}

fn entity_ref_text(entity: contract_core::EntityRef) -> String {
    format!("{}:{:016x}", observation_identity_hex(entity.identity), entity.generation.0)
}

fn os_error_result(code: ErrorCode, errno: i32, retryable: bool) -> GenericCallResult {
    GenericCallResult::Error {
        error: RawErrorObservation {
            domain: ErrorDomain::OperatingSystem,
            code,
            errno: Some(errno),
            retryable,
            detail: None,
        },
    }
}

fn continue_route(case: &mut CaseContext) -> Result<ContinuedContext, String> {
    if case.route == RouteMode::UninterruptedControl {
        case.observation.checkpoint(
            ObservationPhase::Transfer,
            ObservationActor::SourceRuntime,
            case.source.coordinator(),
            &case.paths,
            case.ids.file,
        )?;
        return Ok(ContinuedContext::Uninterrupted);
    }
    handoff(case)
}

fn handoff(case: &mut CaseContext) -> Result<ContinuedContext, String> {
    let (mut destination, portable) = export_to_destination(case)?;
    let prepare_command = derive_identity(&case.case_id, "destination-prepare");
    let prepare = destination.prepare_destination_with_profiles(
        prepare_command,
        case.handoff_authority,
        case.timer_authority,
        case.key_value_authority,
        &[case.file_authority],
    );
    case.observation.protocol_call(
        ObservationPhase::DestinationPrepare,
        ObservationActor::Provider,
        ProtocolAction::PrepareDestination {
            command_id: observation_identity_hex(prepare_command),
        },
        match &prepare {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    prepare.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::DestinationPrepare,
        ObservationActor::Provider,
        &destination,
        &case.paths,
        case.ids.file,
    )?;
    let commit_command = derive_identity(&case.case_id, "destination-commit-command");
    let commit_operation = derive_identity(&case.case_id, "destination-commit-operation");
    let commit = destination.commit_handoff(
        commit_command,
        commit_operation,
        IdempotencyKey::from_bytes(
            derive_identity(&case.case_id, "destination-commit-idempotency").0,
        ),
    );
    case.observation.protocol_call(
        ObservationPhase::DestinationPrepare,
        ObservationActor::Provider,
        ProtocolAction::CommitHandoff {
            command_id: observation_identity_hex(commit_command),
            operation_id: observation_identity_hex(commit_operation),
        },
        match &commit {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    commit.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::DestinationPrepare,
        ObservationActor::Provider,
        &destination,
        &case.paths,
        case.ids.file,
    )?;
    let mut destination = MatrixRegularFileAdapter::instantiate(
        case.runtime_pair.destination,
        component::stage3a_bytes(),
        destination,
    )
    .map_err(adapter_error)?;
    let restore = destination.restore(&portable);
    case.observation.protocol_call(
        ObservationPhase::CarrierRestore,
        ObservationActor::DestinationRuntime,
        ProtocolAction::RestoreRuntime { snapshot_id: observation_identity_hex(case.ids.snapshot) },
        match &restore {
            Ok(()) => returned(Vec::new()),
            Err(error) => adapter_error_result(error),
        },
    );
    restore.map_err(adapter_error)?;
    case.observation.checkpoint(
        ObservationPhase::CarrierRestore,
        ObservationActor::DestinationRuntime,
        destination.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let resume_command = derive_identity(&case.case_id, "destination-resume");
    let resume = destination.coordinator_mut().resume_destination(resume_command);
    case.observation.protocol_call(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        ProtocolAction::ResumeDestination { command_id: observation_identity_hex(resume_command) },
        match &resume {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    resume.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        destination.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    Ok(ContinuedContext::Handoff { destination, portable })
}

fn export_to_destination(
    case: &mut CaseContext,
) -> Result<(Coordinator<SqliteProvider>, PortableRegularFileState), String> {
    let begin_command = derive_identity(&case.case_id, "source-begin-quiesce");
    let begin = case
        .source
        .coordinator_mut()
        .begin_quiesce(begin_command, case.ids.source_handoff_authority);
    case.observation.protocol_call(
        ObservationPhase::Quiesce,
        ObservationActor::SourceRuntime,
        ProtocolAction::BeginQuiesce {
            command_id: observation_identity_hex(begin_command),
            authority_id: entity_ref_text(case.ids.source_handoff_authority),
        },
        match &begin {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    begin.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::Quiesce,
        ObservationActor::SourceRuntime,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let safe_point_id = observation_identity_hex(derive_identity(&case.case_id, "safe-point"));
    let safe_point_result = case.source.coordinator_mut().prepare_safe_point();
    case.observation.protocol_call(
        ObservationPhase::Quiesce,
        ObservationActor::SourceRuntime,
        ProtocolAction::PrepareSafePoint { safe_point_id: safe_point_id.clone() },
        match &safe_point_result {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    let safe_point = safe_point_result.map_err(runtime_error)?;
    let portable = match case.source.freeze() {
        Ok(portable) => {
            case.observation.protocol_call(
                ObservationPhase::CarrierCapture,
                ObservationActor::SourceRuntime,
                ProtocolAction::FreezeRuntime { safe_point_id: safe_point_id.clone() },
                returned(portable.as_bytes().to_vec()),
            );
            portable
        }
        Err(error) => {
            case.observation.protocol_call(
                ObservationPhase::CarrierCapture,
                ObservationActor::SourceRuntime,
                ProtocolAction::FreezeRuntime { safe_point_id: safe_point_id.clone() },
                adapter_error_result(&error),
            );
            case.source.coordinator_mut().cancel_safe_point(safe_point).map_err(runtime_error)?;
            return Err(adapter_error(error));
        }
    };
    let freeze_command = derive_identity(&case.case_id, "source-freeze");
    let commit = case.source.coordinator_mut().commit_safe_point(
        freeze_command,
        portable.as_bytes().to_vec(),
        safe_point,
    );
    case.observation.protocol_call(
        ObservationPhase::CarrierCapture,
        ObservationActor::SourceRuntime,
        ProtocolAction::CommitSafePoint {
            command_id: observation_identity_hex(freeze_command),
            safe_point_id,
        },
        match &commit {
            Ok(_) => returned(Vec::new()),
            Err(error) => runtime_error_result(error),
        },
    );
    if let Err(error) = commit {
        case.source.thaw(&portable).map_err(adapter_error)?;
        return Err(runtime_error(error));
    }
    case.observation.checkpoint(
        ObservationPhase::CarrierCapture,
        ObservationActor::SourceRuntime,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let evidence = EvidenceRef {
        identity: derive_identity(&case.case_id, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: case.source.coordinator().state_digest().map_err(runtime_error)?,
    };
    let export_command = derive_identity(&case.case_id, "source-export");
    let export = case.source.coordinator_mut().export_snapshot(
        export_command,
        case.ids.handoff,
        case.ids.snapshot,
        evidence,
    );
    case.observation.protocol_call(
        ObservationPhase::Transfer,
        ObservationActor::SourceRuntime,
        ProtocolAction::ExportSnapshot {
            command_id: observation_identity_hex(export_command),
            snapshot_id: observation_identity_hex(case.ids.snapshot),
        },
        match &export {
            Ok((_, snapshot)) => returned(
                serde_json::to_vec(snapshot)
                    .map_err(|error| format!("cannot encode raw snapshot observation: {error}"))?,
            ),
            Err(error) => runtime_error_result(error),
        },
    );
    let (_, snapshot) = export.map_err(runtime_error)?;
    case.observation.checkpoint(
        ObservationPhase::Transfer,
        ObservationActor::SourceRuntime,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
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
    mut case: CaseContext,
    mut continued: ContinuedContext,
    assertions: Vec<(&str, bool)>,
    trace: serde_json::Value,
) -> Result<Stage3CaseCapture, String> {
    match &mut continued {
        ContinuedContext::Uninterrupted => case.observation.checkpoint(
            ObservationPhase::FinalObservation,
            ObservationActor::SourceRuntime,
            case.source.coordinator(),
            &case.paths,
            case.ids.file,
        )?,
        ContinuedContext::Handoff { destination, .. } => case.observation.checkpoint(
            ObservationPhase::FinalObservation,
            ObservationActor::DestinationRuntime,
            destination.coordinator(),
            &case.paths,
            case.ids.file,
        )?,
    }
    let state = canonical_file(continued_coordinator(&case, &continued).state())?;
    let destination_epoch = match &continued {
        ContinuedContext::Uninterrupted => None,
        ContinuedContext::Handoff { destination, .. } => {
            Some(destination.coordinator().state().ownership.epoch.0)
        }
    };
    let file_after = read_live_file(&case.paths, &state);
    let canonical_after =
        continued_coordinator(&case, &continued).state_digest().map_err(runtime_error)?;
    let source_runtime = case.source.runtime_identity();
    let destination_runtime = match &continued {
        ContinuedContext::Uninterrupted => source_runtime.clone(),
        ContinuedContext::Handoff { destination, .. } => destination.runtime_identity(),
    };
    let source_phase = format!("{:?}", case.source.coordinator().state().phase);
    let destination_phase = format!("{:?}", continued_coordinator(&case, &continued).state().phase);
    case.source.shutdown().map_err(adapter_error)?;
    if let ContinuedContext::Handoff { destination, .. } = &mut continued {
        destination.shutdown().map_err(adapter_error)?;
    }
    let raw_observation = case.observation.finish();
    Ok(Stage3CaseCapture {
        definition: case.definition,
        canonical_before: case.canonical_before,
        canonical_after,
        source_epoch: INITIAL_LEASE_EPOCH.0,
        destination_epoch,
        profile_operations: case.operations,
        assertions: named_assertions(assertions),
        trace: json!({
            "case_id": case.definition.id,
            "terminal": terminal_name(case.definition.terminal),
            "source_phase": source_phase,
            "destination_phase": destination_phase,
            "source_runtime": source_runtime.implementation,
            "destination_runtime": destination_runtime.implementation,
            "runtime_shutdown": "clean",
            "observations": trace,
        }),
        file_before: case.file_before,
        file_after,
        raw_observation,
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
    mut case: CaseContext,
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
    let source_runtime = case.source.runtime_identity();
    case.observation.checkpoint(
        ObservationPhase::FinalObservation,
        ObservationActor::SourceRuntime,
        case.source.coordinator(),
        &case.paths,
        case.ids.file,
    )?;
    let canonical_after = case.source.coordinator().state_digest().map_err(runtime_error)?;
    let source_phase = format!("{:?}", case.source.coordinator().state().phase);
    case.source.shutdown().map_err(adapter_error)?;
    let raw_observation = case.observation.finish();
    Ok(Stage3CaseCapture {
        definition: case.definition,
        canonical_before: case.canonical_before,
        canonical_after,
        source_epoch,
        destination_epoch: None,
        profile_operations: case.operations,
        assertions: named_assertions(assertions),
        trace: json!({
            "case_id": case.definition.id,
            "terminal": terminal_name(terminal),
            "source_phase": source_phase,
            "source_runtime": source_runtime.implementation,
            "destination_runtime": case.runtime_pair.destination.implementation(),
            "runtime_shutdown": "clean",
            "observations": trace,
        }),
        file_before: case.file_before,
        file_after,
        raw_observation,
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

fn is_file_conflict(result: Result<RegularFileCallResult, RegularFileAdapterError>) -> bool {
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

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use visa_regular_file_observation::{
        REGULAR_FILE_CANDIDATE_OBSERVATION_FILE, REGULAR_FILE_CONTROL_OBSERVATION_FILE,
        RecordingCoverage, RegularFileCase, RegularFileObservationBundle, RouteMode,
        validate_recording_bundle,
    };

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("visa-stage3a-{label}-{}-{nonce}", std::process::id()));
            fs::create_dir(&root).expect("create Stage3A test root");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stage3a_emits_independent_complete_control_and_handoff_routes() {
        let root = TestRoot::new("raw-observation-v2");
        run_stage3a_for_pair(root.path(), RegularFileRuntimePair::WASMTIME_BASELINE)
            .expect("run Stage3A baseline with independent semantic oracle");

        let control = read_bundle(root.path(), REGULAR_FILE_CONTROL_OBSERVATION_FILE);
        let candidate = read_bundle(root.path(), REGULAR_FILE_CANDIDATE_OBSERVATION_FILE);
        validate_recording_bundle(&control, RecordingCoverage::CompleteRegistry)
            .expect("control observation is structurally complete");
        validate_recording_bundle(&candidate, RecordingCoverage::CompleteRegistry)
            .expect("candidate observation is structurally complete");
        assert_eq!(control.route.mode, RouteMode::UninterruptedControl);
        assert_eq!(candidate.route.mode, RouteMode::Handoff);
        assert_eq!(control.cases.len(), RegularFileCase::ALL.len());
        assert_eq!(candidate.cases.len(), RegularFileCase::ALL.len());

        let control_schedules = control
            .cases
            .iter()
            .map(|case| (case.case_id, (&case.schedule_id, &case.schedule_sha256)))
            .collect::<BTreeMap<_, _>>();
        let candidate_schedules = candidate
            .cases
            .iter()
            .map(|case| (case.case_id, (&case.schedule_id, &case.schedule_sha256)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(control_schedules, candidate_schedules);
        assert!(control.cases.iter().all(|case| !case.events.is_empty()));
        assert!(candidate.cases.iter().all(|case| !case.events.is_empty()));
        assert_ne!(control.bundle_id, candidate.bundle_id);
        assert!(!root.path().join(".stage3-work").exists());
    }

    fn read_bundle(root: &Path, relative: &str) -> RegularFileObservationBundle {
        let bytes = fs::read(root.join(relative)).expect("read raw observation bundle");
        serde_json::from_slice(&bytes).expect("decode raw observation bundle")
    }
}
