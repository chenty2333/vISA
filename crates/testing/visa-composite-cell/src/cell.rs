//! One composite handoff: activate four resources on the source, take a single
//! safe point across all of them, and resume on the destination.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use contract_core::{
    EvidenceKind, EvidenceRef, ExtensionSupport, IdempotencyKey, Identity, SchemaVersion,
};
use substrate_api::{LeasePort, ProviderErrorKind};
use substrate_host::{LoopbackLogicalPeer, LoopbackLogicalPeerBehavior};
use visa_component_adapter::identity_string;
use visa_profile::{
    FileDurability, LOGICAL_REQUEST_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_VERSION,
    LogicalRequestState, REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION,
    RegularFileState,
};
use visa_runtime::{
    Coordinator, RuntimeError, SafePointTimer, SnapshotExpectations, TimerPoll, validate_snapshot,
};

use crate::{
    adapter::{CompositeAdapter, CompositeAdapterError},
    bindings::visa::request_continuity::logical_request::RequestPhase,
    component,
    fixture::{CompositeFixture, CompositeFixtureIds, CompositeFixturePaths, INITIAL_LEASE_EPOCH},
    host::{canonical_logical_request, canonical_regular_file},
    state::{CompositeComponentState, PortableCompositeState, TimerKvComponentState},
};

pub const BASELINE_KEY: &str = "composite-work";
pub const DEFAULT_TIMER_DELAY_NANOS: u64 = 5_000_000_000;
pub const REQUEST_BODY: &[u8] = b"ping";
pub const INITIAL_FILE_CONTENT: &[u8] = b"abcdef";

/// Everything the verifier needs, collected while the cell runs. Nothing here
/// is re-derived afterwards, so an assertion cannot silently observe a
/// different state than the one the cell actually reached.
pub struct CompositeCellOutcome {
    pub case_id: String,
    pub paths: CompositeFixturePaths,
    pub ids: CompositeFixtureIds,
    pub source_operations: Vec<String>,
    pub destination_operations: Vec<String>,
    pub canonical_before: contract_core::Digest,
    pub canonical_after: contract_core::Digest,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub portable_frozen: PortableCompositeState,
    pub destination_portable_state: Vec<u8>,
    pub frozen_state: CompositeComponentState,
    pub restored_status: CompositeComponentState,
    pub file_before: Vec<u8>,
    pub file_after_source: Vec<u8>,
    pub file_after_destination: Vec<u8>,
    pub file_after_replay: Vec<u8>,
    pub file_pre_export: RegularFileState,
    pub file_post_restore: RegularFileState,
    pub request_pre_export: LogicalRequestState,
    pub request_post_restore: LogicalRequestState,
    pub source_response: Vec<u8>,
    pub destination_response_size: u32,
    pub destination_response_digest: Vec<u8>,
    pub source_append_operation: String,
    pub replayed_append_operation: String,
    pub timer_arm_operation: String,
    pub safe_point_remaining_ns: Option<u64>,
    pub polled_remaining_ns: Option<u64>,
    pub destination_arm_operation: String,
    pub timer_fired_operations: Vec<String>,
    pub kv_baseline_version: u64,
    pub kv_completion_version: u64,
    pub kv_final_version: Option<u64>,
    pub resource_table_empty_at_freeze: bool,
    pub source_fenced_resources: Vec<(String, bool)>,
    pub source_operation_ids: Vec<String>,
    pub destination_visible_operations: Vec<String>,
}

pub fn run_composite_cell(
    artifact_root: &Path,
    case_id: &str,
    timer_delay_ns: u64,
) -> Result<CompositeCellOutcome, String> {
    let peer = LoopbackLogicalPeer::spawn(
        crate::fixture::DEFAULT_PEER_IDENTITY.to_vec(),
        crate::fixture::DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Echo,
    )
    .map_err(|error| format!("cannot start loopback peer: {error:?}"))?;

    let fixture = CompositeFixture::create(
        artifact_root,
        case_id,
        INITIAL_FILE_CONTENT,
        REQUEST_BODY,
        &peer,
    )?;
    let CompositeFixture {
        case_id,
        paths,
        ids,
        source_state,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        file_authority,
        request_authority,
        source,
        destination,
        ..
    } = fixture;

    let file_before = fs::read(&paths.file_path).map_err(io_error("read initial file"))?;

    // ---- source activation -------------------------------------------------
    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(derive(&case_id, "activate"), ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
        .map_err(runtime_error)?;
    let mut source_adapter =
        CompositeAdapter::instantiate(component::composite_bytes(), coordinator)
            .map_err(adapter_error)?;
    let session = format!("{case_id}:session");
    source_adapter
        .activate(
            session.clone(),
            TimerKvComponentState {
                key: BASELINE_KEY.to_owned(),
                expected_version: 0,
                completion_value: b"composite-completed".to_vec(),
                timer_operation_id: None,
                timer_idempotency_key: format!("{case_id}-timer"),
                completion_idempotency_key: format!("{case_id}-completion"),
                timer_completed: false,
            },
        )
        .map_err(adapter_error)?;
    let canonical_before = source_adapter.coordinator().state_digest().map_err(runtime_error)?;

    // ---- four real source effects -----------------------------------------
    let mut source_operations = Vec::new();
    let kv_baseline_version =
        source_adapter.kv_put("baseline", b"composite-baseline").map_err(adapter_error)?;
    let timer_arm_operation = source_adapter.timer_arm(timer_delay_ns).map_err(adapter_error)?;
    source_operations.push(timer_arm_operation.clone());

    let appended = source_adapter
        .file_append("append-src", b"!", FileDurability::Data)
        .map_err(adapter_error)?;
    let source_append_operation = appended.operation_id.clone();
    source_operations.push(source_append_operation.clone());
    let file_after_source = fs::read(&paths.file_path).map_err(io_error("read appended file"))?;

    let started = source_adapter.request_start(REQUEST_BODY).map_err(adapter_error)?;
    source_operations.push(started.operation_id.clone());
    // The loopback peer answers synchronously, so Start can already report
    // Completed. Draining is driven by the response cursor rather than the
    // phase, otherwise the response body is never read back.
    let mut source_response = Vec::new();
    let mut request_phase = started.phase;
    let mut response_size = started.response.as_ref().map(|response| response.size as usize);
    for _ in 0..16 {
        if request_phase == RequestPhase::Completed && response_size == Some(source_response.len())
        {
            break;
        }
        let observed = source_adapter.request_observe(64).map_err(adapter_error)?;
        let progressed = !observed.bytes.is_empty();
        source_response.extend_from_slice(&observed.bytes);
        request_phase = observed.observation.phase;
        if let Some(response) = &observed.observation.response {
            response_size = Some(response.size as usize);
        }
        if !progressed {
            break;
        }
    }
    if request_phase != RequestPhase::Completed || response_size != Some(source_response.len()) {
        // Export validation would refuse a request that is still in flight;
        // failing here reports the real cause instead of the later symptom.
        return Err(format!(
            "logical request did not complete: phase {request_phase:?}, \
             drained {} of {response_size:?} response bytes",
            source_response.len(),
        ));
    }

    let file_pre_export = canonical_regular_file(source_adapter.coordinator().state())
        .map_err(|error| format!("missing regular-file extension: {error:?}"))?;
    let request_pre_export = canonical_logical_request(source_adapter.coordinator().state())
        .map_err(|error| format!("missing logical-request extension: {error:?}"))?;
    let source_operation_ids = source_adapter
        .coordinator()
        .state()
        .operations
        .iter()
        .map(|record| identity_string(record.request.operation))
        .collect::<Vec<_>>();

    // ---- single safe point across all four resources -----------------------
    source_adapter
        .coordinator_mut()
        .begin_quiesce(derive(&case_id, "source-begin-quiesce"), ids.source_handoff_authority)
        .map_err(runtime_error)?;
    let safe_point =
        source_adapter.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let safe_point_remaining_ns = match safe_point.timer() {
        SafePointTimer::Pending { remaining, .. } => Some(remaining.0),
        _ => None,
    };
    let portable_frozen = match source_adapter.freeze() {
        Ok(portable) => portable,
        Err(error) => {
            source_adapter
                .coordinator_mut()
                .cancel_safe_point(safe_point)
                .map_err(runtime_error)?;
            return Err(adapter_error(error));
        }
    };
    let resource_table_empty_at_freeze = source_adapter.resource_table_is_empty();
    if let Err(error) = source_adapter.coordinator_mut().commit_safe_point(
        derive(&case_id, "source-freeze"),
        portable_frozen.as_bytes().to_vec(),
        safe_point,
    ) {
        source_adapter.thaw(&portable_frozen).map_err(adapter_error)?;
        return Err(runtime_error(error));
    }
    let frozen_state = portable_frozen.decode().map_err(|error| format!("{error:?}"))?;

    // ---- export and validate ----------------------------------------------
    let evidence = EvidenceRef {
        identity: derive(&case_id, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: source_adapter.coordinator().state_digest().map_err(runtime_error)?,
    };
    let (_, snapshot) = source_adapter
        .coordinator_mut()
        .export_snapshot(derive(&case_id, "source-export"), ids.handoff, ids.snapshot, evidence)
        .map_err(runtime_error)?;
    let validated = validate_snapshot(
        &snapshot,
        &SnapshotExpectations {
            component_digest: component::composite_digest(),
            profile_digest,
            profile_version: SchemaVersion::new(1, 0),
            supported_extensions: vec![
                ExtensionSupport {
                    id: REGULAR_FILE_EXTENSION_ID,
                    version: REGULAR_FILE_EXTENSION_VERSION,
                },
                ExtensionSupport {
                    id: LOGICAL_REQUEST_EXTENSION_ID,
                    version: LOGICAL_REQUEST_EXTENSION_VERSION,
                },
            ],
            destination: ids.destination_node,
        },
    )
    .map_err(runtime_error)?;
    let mut destination_coordinator =
        Coordinator::restore(validated, destination).map_err(runtime_error)?;

    // ---- destination preparation and resume --------------------------------
    destination_coordinator
        .prepare_destination_with_profiles(
            derive(&case_id, "destination-prepare"),
            handoff_authority,
            timer_authority,
            key_value_authority,
            &[file_authority, request_authority],
        )
        .map_err(runtime_error)?;
    destination_coordinator
        .commit_handoff(
            derive(&case_id, "destination-commit-command"),
            derive(&case_id, "destination-commit-operation"),
            IdempotencyKey::from_bytes(derive(&case_id, "destination-commit-idempotency").0),
        )
        .map_err(runtime_error)?;
    let destination_portable_state = destination_coordinator.state().portable_state.clone();
    let mut destination_adapter =
        CompositeAdapter::instantiate(component::composite_bytes(), destination_coordinator)
            .map_err(adapter_error)?;
    destination_adapter
        .restore(&portable_frozen, safe_point_remaining_ns)
        .map_err(adapter_error)?;
    destination_adapter
        .coordinator_mut()
        .resume_destination(derive(&case_id, "destination-resume"))
        .map_err(runtime_error)?;

    let restored_status = destination_adapter
        .status()
        .map_err(adapter_error)?
        .ok_or("destination component reported no status after restore")?;
    let destination_arm_operation = restored_status
        .timer_kv
        .timer_operation_id
        .clone()
        .ok_or("destination component lost the timer operation")?;

    // ---- the source is fenced on every claimed resource --------------------
    let source_fenced_resources = [
        ("timer", ids.timer),
        ("key-value", ids.key_value),
        ("regular-file", ids.file),
        ("logical-request", ids.request),
    ]
    .into_iter()
    .map(|(label, resource)| {
        let fenced = matches!(
            source_adapter.coordinator().provider().check_lease(
                resource,
                ids.source_node,
                INITIAL_LEASE_EPOCH,
            ),
            Err(error) if error.kind == ProviderErrorKind::StaleEpoch
        );
        (label.to_owned(), fenced)
    })
    .collect::<Vec<_>>();

    // ---- destination continuity effects ------------------------------------
    let mut destination_operations = Vec::new();
    let replayed = destination_adapter
        .file_append("append-src", b"!", FileDurability::Data)
        .map_err(adapter_error)?;
    let replayed_append_operation = replayed.operation_id.clone();
    destination_operations.push(replayed_append_operation.clone());
    let file_after_replay = fs::read(&paths.file_path).map_err(io_error("read replayed file"))?;

    let extended = destination_adapter
        .file_append("append-dst", b"?", FileDurability::Data)
        .map_err(adapter_error)?;
    destination_operations.push(extended.operation_id.clone());
    let file_after_destination =
        fs::read(&paths.file_path).map_err(io_error("read extended file"))?;

    let observed = destination_adapter.request_observe(64).map_err(adapter_error)?;
    let response = observed
        .observation
        .response
        .clone()
        .ok_or("destination request lost its response metadata")?;
    let destination_response_size = response.size;
    let destination_response_digest = response.digest.clone();

    // ---- the timer fires exactly once, on the destination ------------------
    let mut timer_fired_operations = Vec::new();
    let mut polled_remaining_ns = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match destination_adapter.coordinator_mut().poll_timer().map_err(runtime_error)? {
            TimerPoll::Pending { remaining, .. } => {
                polled_remaining_ns.get_or_insert(remaining.0);
                if Instant::now() >= deadline {
                    return Err("composite timer never fired on the destination".to_owned());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            TimerPoll::Fired { arm_operation, .. } => {
                destination_adapter.timer_fired(arm_operation).map_err(adapter_error)?;
                timer_fired_operations.push(identity_string(arm_operation));
                break;
            }
            other => return Err(format!("unexpected timer poll result {other:?}")),
        }
    }
    // A second poll must not produce another firing.
    if let TimerPoll::Fired { arm_operation, .. } =
        destination_adapter.coordinator_mut().poll_timer().map_err(runtime_error)?
    {
        timer_fired_operations.push(identity_string(arm_operation));
    }

    let kv_completion_version = destination_adapter
        .status()
        .map_err(adapter_error)?
        .ok_or("destination component reported no status after the timer fired")?
        .timer_kv
        .expected_version;
    let kv_final_version = destination_adapter.kv_get().map_err(adapter_error)?;

    let file_post_restore = canonical_regular_file(destination_adapter.coordinator().state())
        .map_err(|error| format!("missing destination regular-file extension: {error:?}"))?;
    let request_post_restore = canonical_logical_request(destination_adapter.coordinator().state())
        .map_err(|error| format!("missing destination logical-request extension: {error:?}"))?;
    let destination_visible_operations = destination_adapter
        .coordinator()
        .state()
        .operations
        .iter()
        .map(|record| identity_string(record.request.operation))
        .collect::<Vec<_>>();
    let canonical_after =
        destination_adapter.coordinator().state_digest().map_err(runtime_error)?;
    let destination_epoch = destination_adapter.coordinator().state().ownership.epoch.0;

    drop(peer);
    Ok(CompositeCellOutcome {
        case_id,
        paths,
        ids,
        source_operations,
        destination_operations,
        canonical_before,
        canonical_after,
        source_epoch: INITIAL_LEASE_EPOCH.0,
        destination_epoch,
        portable_frozen,
        destination_portable_state,
        frozen_state,
        restored_status,
        file_before,
        file_after_source,
        file_after_destination,
        file_after_replay,
        file_pre_export,
        file_post_restore,
        request_pre_export,
        request_post_restore,
        source_response,
        destination_response_size,
        destination_response_digest,
        source_append_operation,
        replayed_append_operation,
        timer_arm_operation,
        safe_point_remaining_ns,
        polled_remaining_ns,
        destination_arm_operation,
        timer_fired_operations,
        kv_baseline_version,
        kv_completion_version,
        kv_final_version,
        resource_table_empty_at_freeze,
        source_fenced_resources,
        source_operation_ids,
        destination_visible_operations,
    })
}

pub fn artifact_case_root(artifact_root: &Path, case_id: &str) -> PathBuf {
    artifact_root.join("cases").join(case_id)
}

fn derive(case_id: &str, label: &str) -> Identity {
    crate::fixture::derive_identity(case_id, label)
}

fn runtime_error(error: RuntimeError) -> String {
    format!("runtime error: {error:?}")
}

fn adapter_error(error: CompositeAdapterError) -> String {
    format!("composite adapter error: {error}")
}

fn io_error(action: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("cannot {action}: {error}")
}
