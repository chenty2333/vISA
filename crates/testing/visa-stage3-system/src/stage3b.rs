use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use contract_core::{
    CleanupStatus, DeliveryPolicy, Digest, EvidenceKind, EvidenceRef, ExtensionSupport,
    IdempotencyKey, Identity, SchemaVersion,
};
use serde_json::json;
use substrate_api::{LeasePort, ProviderErrorKind};
use substrate_host::{
    FaultPoint, LoopbackLogicalPeer, LoopbackLogicalPeerBehavior, SqliteProvider,
};
use visa_conformance::{STAGE3B_CASE_DEFINITIONS, Stage3CaseDefinition, Stage3CaseTerminal};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_VERSION, LogicalRequestIdempotency,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestResult,
    LogicalRequestState, LogicalRequestTransport, logical_request_extension, logical_request_state,
};
use visa_runtime::{Coordinator, RuntimeError, SnapshotExpectations, validate_snapshot};
use visa_wasmtime::{
    LogicalRequestAdapter, LogicalRequestAdapterError, LogicalRequestFailure,
    LogicalRequestWorkloadFailure, PortableLogicalRequestState,
};

use crate::{
    component,
    evidence::{Stage3bCaseCapture, create_incomplete_marker, publish_stage3b, terminal_name},
    fixture_request::{
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL, STAGE3B_DEFAULT_PEER_IDENTITY,
        STAGE3B_INITIAL_LEASE_EPOCH, Stage3bFixture, Stage3bFixtureIds, Stage3bFixtureOptions,
        derive_stage3b_identity,
    },
};

struct RequestCaseContext {
    definition: &'static Stage3CaseDefinition,
    case_id: String,
    ids: Stage3bFixtureIds,
    profile_digest: Digest,
    handoff_authority: visa_runtime::AuthorityPlan,
    timer_authority: visa_runtime::AuthorityPlan,
    key_value_authority: visa_runtime::AuthorityPlan,
    request_authority: visa_runtime::ProfileAuthorityPlan,
    source: LogicalRequestAdapter<SqliteProvider>,
    destination_provider: Option<SqliteProvider>,
    peer: LoopbackLogicalPeer,
    canonical_before: Digest,
    request: Vec<u8>,
    delivered_response: Vec<u8>,
    operations: Vec<String>,
}

struct RequestCommitted {
    destination: LogicalRequestAdapter<SqliteProvider>,
    portable: PortableLogicalRequestState,
}

pub fn run_stage3b(artifact_root: &Path) -> Result<PathBuf, String> {
    create_incomplete_marker(artifact_root)?;
    let work_root = artifact_root.join(".stage3-work");
    let started = now_unix_ms()?;
    let mut captures = Vec::with_capacity(STAGE3B_CASE_DEFINITIONS.len());
    for definition in STAGE3B_CASE_DEFINITIONS {
        captures.push(run_case(&work_root, definition)?);
    }
    remove_completed_work_tree(&work_root)?;
    let finished = now_unix_ms()?;
    let profile_manifest = json!({
        "profile": "bounded-logical-request-continuity",
        "extension_id": identity_hex(LOGICAL_REQUEST_EXTENSION_ID),
        "extension_version": {
            "major": LOGICAL_REQUEST_EXTENSION_VERSION.major,
            "minor": LOGICAL_REQUEST_EXTENSION_VERSION.minor,
        },
        "canonical_state": [
            "peer_identity", "credential_reference", "logical_operation_id",
            "request_digest", "phase", "response_cursor", "response_metadata",
            "rejection", "continuity_disposition"
        ],
        "native_state_excluded": [
            "socket", "tcp_sequence", "runtime_future", "credential_material"
        ],
        "operations": ["start", "observe", "reconcile", "cancel"],
        "explicit_non_claims": ["arbitrary_live_tcp", "general_async_runtime"],
    });
    let configuration = json!({
        "source_runtime": "visa_wasmtime_stage3b",
        "destination_runtime": "visa_wasmtime_stage3b",
        "independent_runtime_coverage": false,
        "unsupported_stage3_runtime": "wacogo",
        "provider": "substrate_host::SqliteProvider",
        "transport": "bounded-loopback-VISALR03-authenticated",
        "peer_authentication": "fresh-nonce-hmac-sha256-challenge-response",
        "deduplication": "execute-derived-digest-and-lookup-cancel-expected-digest-bound",
        "send_fence": "sqlite-immediate-frame-admission-authority-lease-binding-recheck",
        "ledger_update":
            "sqlite-immediate-revision-checked-compare-and-save-terminal-cursor-cleanup-monotonic",
        "component_state_encoding": "visa-logical-request-state-v1",
        "credential_material_retained": false,
        "credential_material_transmitted": false,
        "execution_boundary": "same-process-distinct-wasmtime-store-and-provider-instance",
        "case_count": STAGE3B_CASE_DEFINITIONS.len(),
    });
    publish_stage3b(
        artifact_root,
        started,
        finished,
        LogicalRequestAdapter::<SqliteProvider>::runtime_identity_static(),
        &profile_manifest,
        &configuration,
        &captures,
    )
}

fn run_case(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let result = match definition.id {
        "completed-before-freeze" => case_completed_before_freeze(root, definition),
        "pending-before-send" => case_pending_before_send(root, definition),
        "lost-ack-deduplicated" => case_lost_ack(root, definition),
        "unknown-completion-reconciled" => case_unknown_reconciled(root, definition),
        "partial-response-resumed" => case_partial_response(root, definition),
        "timeout" => case_timeout(root, definition),
        "cancel-completion-race" => case_cancel_race(root, definition),
        "peer-mismatch" => case_peer_mismatch(root, definition),
        "credential-reacquired" => case_credential_reacquired(root, definition),
        "credential-denied" => case_credential_denied(root, definition),
        "non-idempotent-unknown-blocked" => case_non_idempotent_unknown(root, definition),
        "raw-live-tcp-rejected" => case_raw_tcp(root, definition),
        "stale-source-fenced" => case_stale_source(root, definition),
        "cleanup-idempotent" => case_cleanup(root, definition),
        other => Err(format!("unimplemented Stage 3B case {other}")),
    };
    result.map_err(|error| format!("{}: {error}", definition.id))
}

fn case_completed_before_freeze(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_standard(root, definition, b"request-a", b"response-a")?;
    start_request(&mut case)?;
    observe_request(&mut case, 64)?;
    let executions_before = case.peer.execution_count();
    let operation_id = canonical_request(case.source.coordinator().state())?.operation_id;
    case.destination_provider
        .as_mut()
        .ok_or("missing destination provider")?
        .forget_logical_request_operation(operation_id)
        .map_err(provider_error)?;
    case.peer.clear_operation_ledger();
    let mut committed = handoff(&mut case)?;
    let reconciled = committed.destination.reconcile().map_err(adapter_error)?;
    case.operations.push(reconciled.effect_operation_id);
    let executions_after = case.peer.execution_count();
    let state = canonical_request(committed.destination.coordinator().state())?;
    finish_committed(
        case,
        committed,
        vec![
            (
                "response_preserved",
                state.phase == LogicalRequestPhase::Completed
                    && state.response_cursor == b"response-a".len() as u32,
            ),
            ("completion_not_replayed", executions_before == 1 && executions_after == 1),
        ],
        json!({
            "provider_ledger_absent_before_rebind": true,
            "peer_ledger_cleared_before_terminal_reconcile": true,
            "peer_executions_before_reconcile": executions_before,
            "peer_executions_after_reconcile": executions_after,
            "phase": format!("{:?}", state.phase),
        }),
    )
}

fn case_pending_before_send(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_case(
        root,
        definition,
        b"deferred",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::DropGreetingOnce { response: b"sent-after-restore".to_vec() },
        Stage3bFixtureOptions::standard(),
    )?;
    let before = canonical_request(case.source.coordinator().state())?;
    let executions_before = case.peer.execution_count();
    let mut committed = handoff(&mut case)?;
    let restored = canonical_request(committed.destination.coordinator().state())?;
    let transient_failure = matches!(
        committed.destination.start(case.request.clone()),
        Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
            LogicalRequestFailure::Unavailable
        )))
    );
    let retryable_intent_open = committed
        .destination
        .coordinator()
        .state()
        .operations
        .last()
        .is_some_and(|record| record.outcome.is_none());
    start_destination(&mut case, &mut committed.destination)?;
    let sent = canonical_request(committed.destination.coordinator().state())?;
    let executions_after = case.peer.execution_count();
    let received_frames = case.peer.received_frame_count();
    finish_committed(
        case,
        committed,
        vec![
            (
                "pending_state_preserved",
                before.phase == LogicalRequestPhase::Ready
                    && restored.phase == LogicalRequestPhase::Ready,
            ),
            (
                "send_after_restore",
                executions_before == 0
                    && executions_after == 1
                    && received_frames == 3
                    && transient_failure
                    && retryable_intent_open
                    && sent.phase == LogicalRequestPhase::Completed
                    && sent.last_operation.is_some(),
            ),
        ],
        json!({
            "source_phase": format!("{:?}", before.phase),
            "restored_phase": format!("{:?}", restored.phase),
            "phase_after_destination_send": format!("{:?}", sent.phase),
            "peer_executions_before": executions_before,
            "peer_executions_after": executions_after,
            "received_frames_after_retry": received_frames,
            "first_attempt_dropped_before_greeting": true,
            "transient_start_failure": transient_failure,
            "retryable_intent_open": retryable_intent_open,
        }),
    )
}

fn case_lost_ack(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.source_fault = Some(FaultPoint::AfterLogicalRequestCommit);
    let mut case = start_case(
        root,
        definition,
        b"dedup-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Static(b"dedup-response".to_vec()),
        options,
    )?;
    let call = start_request(&mut case)?;
    let state = canonical_request(case.source.coordinator().state())?;
    let executions = case.peer.execution_count();
    let committed = handoff(&mut case)?;
    finish_committed(
        case,
        committed,
        vec![
            ("operation_id_preserved", call.operation_id == identity_hex(state.operation_id)),
            ("request_applied_once", executions == 1),
            ("ack_reconciled", state.last_operation.is_some()),
        ],
        json!({"peer_executions": executions, "effect_operation": call.effect_operation_id}),
    )
}

fn case_unknown_reconciled(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.source_fault = Some(FaultPoint::AfterLogicalRequestSend);
    let mut case = start_case(
        root,
        definition,
        b"unknown-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Static(b"known-response".to_vec()),
        options,
    )?;
    start_request(&mut case)?;
    let unknown = canonical_request(case.source.coordinator().state())?.phase
        == LogicalRequestPhase::UnknownCompletion;
    let mut committed = handoff(&mut case)?;
    let reconciled = reconcile_until_terminal(&mut case, &mut committed.destination)?;
    let executions = case.peer.execution_count();
    finish_committed(
        case,
        committed,
        vec![
            ("unknown_state_preserved", unknown),
            ("provider_truth_queried", reconciled),
            ("no_unsafe_replay", executions == 1),
        ],
        json!({"unknown_before_handoff": unknown, "peer_executions": executions}),
    )
}

fn case_partial_response(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_standard(root, definition, b"chunk-request", b"abcdef")?;
    start_request(&mut case)?;
    observe_request(&mut case, 3)?;
    let cursor = canonical_request(case.source.coordinator().state())?.response_cursor;
    case.destination_provider
        .as_mut()
        .ok_or("missing destination provider")?
        .inject_failure_once(FaultPoint::BeforeLogicalRequestIo);
    let mut committed = handoff(&mut case)?;
    let transient_observe_failure = matches!(
        committed.destination.observe(3),
        Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
            LogicalRequestFailure::Unavailable
        )))
    );
    let pending_observe = committed
        .destination
        .coordinator()
        .state()
        .operations
        .last()
        .filter(|record| record.outcome.is_none())
        .map(|record| record.request.operation);
    let retried = observe_destination(&mut case, &mut committed.destination, 3)?;
    let transient_observe_retried = transient_observe_failure
        && pending_observe.is_some()
        && pending_observe.map(identity_hex).as_deref()
            == Some(retried.effect_operation_id.as_str())
        && committed
            .destination
            .coordinator()
            .state()
            .operations
            .iter()
            .all(|record| record.outcome.is_some());
    let state = canonical_request(committed.destination.coordinator().state())?;
    let delivered_response = case.delivered_response.clone();
    let expected = contract_core::canonical_digest(b"abcdef".as_slice())
        .map_err(|_| "cannot digest response")?;
    finish_committed(
        case,
        committed,
        vec![
            ("transient_observe_retried", transient_observe_retried),
            ("cursor_preserved", cursor == 3 && state.response_cursor == 6),
            ("bytes_not_duplicated", delivered_response == b"abcdef"),
            (
                "response_digest_matched",
                state.response.is_some_and(|response| response.digest == expected),
            ),
        ],
        json!({
            "cursor_before": cursor,
            "cursor_after": state.response_cursor,
            "transient_observe_failure": transient_observe_failure,
            "pending_observe_operation": pending_observe.map(identity_hex),
            "retried_observe_operation": retried.effect_operation_id,
            "delivered_response": String::from_utf8_lossy(&delivered_response),
            "delivered_size": delivered_response.len(),
        }),
    )
}

fn case_timeout(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.timeout_millis = 100;
    let peer_delay = Duration::from_millis(300);
    let mut case = start_case(
        root,
        definition,
        b"expired-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Delayed {
            delay: peer_delay,
            response: b"eventual-timeout-response".to_vec(),
        },
        options,
    )?;
    let started = Instant::now();
    start_request(&mut case)?;
    let elapsed = started.elapsed();
    let unknown = canonical_request(case.source.coordinator().state())?.phase
        == LogicalRequestPhase::UnknownCompletion;
    case.destination_provider
        .as_mut()
        .ok_or("missing destination provider")?
        .inject_failure_once(FaultPoint::BeforeLogicalRequestIo);
    let mut committed = handoff(&mut case)?;
    thread::sleep(peer_delay);
    let transient_reconcile_failure = matches!(
        committed.destination.reconcile(),
        Err(LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
            LogicalRequestFailure::Unavailable
        )))
    );
    let reconcile_intent_open = committed
        .destination
        .coordinator()
        .state()
        .operations
        .last()
        .is_some_and(|record| record.outcome.is_none());
    let reconciled = reconcile_until_terminal(&mut case, &mut committed.destination)?;
    let state = canonical_request(committed.destination.coordinator().state())?;
    let executions = case.peer.execution_count();
    finish_committed(
        case,
        committed,
        vec![
            ("read_timeout_became_unknown", unknown),
            (
                "late_completion_reconciled",
                reconciled
                    && transient_reconcile_failure
                    && reconcile_intent_open
                    && state.phase == LogicalRequestPhase::Completed
                    && state.response.is_some(),
            ),
            ("request_not_replayed", executions == 1),
        ],
        json!({
            "timeout_millis": 100,
            "peer_delay_millis": peer_delay.as_millis(),
            "start_elapsed_millis": elapsed.as_millis(),
            "phase_after_read_timeout": if unknown { "unknown_completion" } else { "unexpected" },
            "phase_after_reconcile": format!("{:?}", state.phase),
            "peer_executions": executions,
            "transient_reconcile_failure": transient_reconcile_failure,
            "reconcile_intent_open": reconcile_intent_open,
        }),
    )
}

fn case_cancel_race(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.source_fault = Some(FaultPoint::AfterLogicalRequestSend);
    let mut case = start_case(
        root,
        definition,
        b"race-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Delayed {
            delay: Duration::from_millis(30),
            response: b"race-response".to_vec(),
        },
        options,
    )?;
    start_request(&mut case).map_err(|error| format!("start: {error}"))?;
    let call =
        case.source.cancel().map_err(adapter_error).map_err(|error| format!("cancel: {error}"))?;
    case.operations.push(call.effect_operation_id);
    thread::sleep(Duration::from_millis(40));
    let mut committed = handoff(&mut case).map_err(|error| format!("handoff: {error}"))?;
    let restored_phase = canonical_request(committed.destination.coordinator().state())?.phase;
    if !matches!(
        restored_phase,
        LogicalRequestPhase::Cancelled
            | LogicalRequestPhase::Completed
            | LogicalRequestPhase::TimedOut
            | LogicalRequestPhase::Rejected
    ) {
        let _ = reconcile_until_terminal(&mut case, &mut committed.destination)
            .map_err(|error| format!("reconcile: {error}"))?;
    }
    let state = canonical_request(committed.destination.coordinator().state())?;
    let terminal =
        matches!(state.phase, LogicalRequestPhase::Cancelled | LogicalRequestPhase::Completed);
    let executions = case.peer.execution_count();
    finish_committed(
        case,
        committed,
        vec![("single_terminal_outcome", terminal), ("race_reconciled", executions <= 1)],
        json!({"phase": format!("{:?}", state.phase), "peer_executions": executions}),
    )
}

fn case_peer_mismatch(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.source_peer_identity = b"claimed-peer".to_vec();
    let mut case = start_case(
        root,
        definition,
        b"peer-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Echo,
        options,
    )?;
    start_request(&mut case)?;
    let state = canonical_request(case.source.coordinator().state())?;
    let requests = case.peer.request_count();
    let executions = case.peer.execution_count();
    let request_disclosed = case.peer.received_wire_contains(b"peer-request");
    let credential_disclosed =
        case.peer.received_wire_contains(STAGE3B_DEFAULT_CREDENTIAL_MATERIAL);
    rejected(
        case,
        vec![
            (
                "peer_identity_checked",
                state.rejection == Some(LogicalRequestRejection::PeerMismatch),
            ),
            (
                "request_not_sent",
                state.phase == LogicalRequestPhase::Rejected
                    && requests == 0
                    && executions == 0
                    && !request_disclosed
                    && !credential_disclosed,
            ),
        ],
        json!({
            "rejection": format!("{:?}", state.rejection),
            "authenticated_application_frames": requests,
            "peer_executions": executions,
            "request_bytes_observed_on_wire": request_disclosed,
            "credential_bytes_observed_on_wire": credential_disclosed,
        }),
    )
}

fn case_credential_reacquired(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.destination_credential_available = false;
    let mut case = start_case(
        root,
        definition,
        b"credential-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Static(b"credential-response".to_vec()),
        options,
    )?;
    case.destination_provider
        .as_mut()
        .ok_or("missing destination provider")?
        .provision_logical_request_peer(
            case.ids.destination_node,
            STAGE3B_DEFAULT_PEER_IDENTITY,
            case.peer.address(),
            case.ids.credential_reference,
            STAGE3B_DEFAULT_CREDENTIAL_MATERIAL,
        )
        .map_err(provider_error)?;
    let executions_before = case.peer.execution_count();
    let mut committed = handoff(&mut case)?;
    let reference = identity_hex(case.ids.credential_reference);
    let portable_material_absent =
        !contains_bytes(committed.portable.as_bytes(), STAGE3B_DEFAULT_CREDENTIAL_MATERIAL);
    start_destination(&mut case, &mut committed.destination)
        .map_err(|error| format!("destination start after credential reacquisition: {error}"))?;
    observe_destination(&mut case, &mut committed.destination, 64)
        .map_err(|error| format!("destination observe after credential reacquisition: {error}"))?;
    let state = canonical_request(committed.destination.coordinator().state())?;
    let executions_after = case.peer.execution_count();
    let wire_material_absent =
        !case.peer.received_wire_contains(STAGE3B_DEFAULT_CREDENTIAL_MATERIAL);
    let material_absent = portable_material_absent && wire_material_absent;
    let credential_reference_preserved =
        state.claim.credential_reference == case.ids.credential_reference;
    let destination_credential_used = executions_before == 0
        && executions_after == 1
        && credential_reference_preserved
        && state.phase == LogicalRequestPhase::Completed
        && case.delivered_response == b"credential-response";
    let destination_response_size = case.delivered_response.len();
    finish_committed(
        case,
        committed,
        vec![
            ("credential_reference_preserved", credential_reference_preserved),
            ("credential_bytes_absent", material_absent),
            ("destination_credential_used", destination_credential_used),
        ],
        json!({
            "credential_reference": reference,
            "credential_material_retained": false,
            "credential_material_transmitted": !wire_material_absent,
            "peer_executions_before_handoff": executions_before,
            "peer_executions_after_destination_send": executions_after,
            "destination_phase": format!("{:?}", state.phase),
            "destination_response_size": destination_response_size,
        }),
    )
}

fn case_credential_denied(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let local_credential = b"wrong-provider-credential".to_vec();
    let mut options = Stage3bFixtureOptions::standard();
    options.source_credential_material = local_credential.clone();
    let mut case = start_case(
        root,
        definition,
        b"secret-request",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Echo,
        options,
    )?;
    start_request(&mut case)?;
    let state = canonical_request(case.source.coordinator().state())?;
    let requests = case.peer.request_count();
    let canonical = contract_core::canonical_bytes(case.source.coordinator().state())
        .map_err(|_| "cannot encode canonical state")?;
    let local_credential_on_wire = case.peer.received_wire_contains(&local_credential);
    let server_credential_on_wire =
        case.peer.received_wire_contains(STAGE3B_DEFAULT_CREDENTIAL_MATERIAL);
    rejected(
        case,
        vec![
            (
                "credential_denial_preserved",
                state.rejection == Some(LogicalRequestRejection::CredentialDenied),
            ),
            (
                "secret_not_exposed",
                requests == 0
                    && !contains_bytes(&canonical, &local_credential)
                    && !contains_bytes(&canonical, STAGE3B_DEFAULT_CREDENTIAL_MATERIAL)
                    && !local_credential_on_wire
                    && !server_credential_on_wire,
            ),
        ],
        json!({
            "rejection": format!("{:?}", state.rejection),
            "authenticated_application_frames": requests,
            "credential_material_retained": false,
            "local_credential_observed_on_wire": local_credential_on_wire,
            "server_credential_observed_on_wire": server_credential_on_wire,
        }),
    )
}

fn case_non_idempotent_unknown(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut options = Stage3bFixtureOptions::standard();
    options.delivery = DeliveryPolicy::AtMostOnce;
    options.replay = LogicalRequestReplay::Never;
    options.idempotency = LogicalRequestIdempotency::NonIdempotent;
    options.source_fault = Some(FaultPoint::AfterLogicalRequestSend);
    let mut case = start_case(
        root,
        definition,
        b"non-idempotent",
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Static(b"maybe-applied".to_vec()),
        options,
    )?;
    start_request(&mut case)?;
    let unsafe_unknown = canonical_request(case.source.coordinator().state())?.phase
        == LogicalRequestPhase::UnknownCompletion;
    let blocked = freeze_is_profile_blocked(&mut case)?;
    let executions = case.peer.execution_count();
    blocked_capture(
        case,
        vec![
            ("unsafe_replay_rejected", unsafe_unknown && blocked),
            ("request_not_repeated", executions <= 1),
        ],
        json!({"unknown_completion": unsafe_unknown, "freeze_blocked": blocked, "peer_executions": executions}),
    )
}

fn case_raw_tcp(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_standard(root, definition, b"raw-request", b"unused")?;
    let mut raw = canonical_request(case.source.coordinator().state())?;
    raw.claim.transport = LogicalRequestTransport::RawLiveTcp;
    let rejected_transport = matches!(
        logical_request_extension(&raw),
        Err(visa_profile::ProfilePayloadError::UnsupportedContinuity)
    );
    let portable = case.source.status().map_err(adapter_error)?.ok_or("missing guest status")?;
    let socket_absent = portable.transport == LogicalRequestTransport::Reconnectable;
    rejected(
        case,
        vec![
            ("unsupported_transport_explicit", rejected_transport),
            ("socket_state_absent", socket_absent),
        ],
        json!({"raw_live_tcp_extension_rejected": rejected_transport, "socket_field_present": false}),
    )
}

fn case_stale_source(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_standard(root, definition, b"fenced-request", b"fenced-response")?;
    let mut committed = handoff(&mut case)?;
    let source_denied = matches!(
        case.source.coordinator().provider().check_lease(
            case.ids.request,
            case.ids.source_node,
            STAGE3B_INITIAL_LEASE_EPOCH,
        ),
        Err(error) if error.kind == ProviderErrorKind::StaleEpoch
    );
    start_destination(&mut case, &mut committed.destination)?;
    let ownership = committed.destination.coordinator().state().ownership;
    let destination_epoch_advanced = ownership.owner == Some(case.ids.destination_node)
        && ownership.epoch == STAGE3B_INITIAL_LEASE_EPOCH.next().ok_or("lease epoch exhausted")?;
    let state = canonical_request(committed.destination.coordinator().state())?;
    finish_committed(
        case,
        committed,
        vec![
            ("destination_epoch_advanced", destination_epoch_advanced),
            ("source_request_denied", source_denied),
            ("destination_request_succeeded", state.last_operation.is_some()),
        ],
        json!({
            "source_effect_boundary_denied": source_denied,
            "destination_owner": ownership.owner.map(|owner| identity_hex(owner.0)),
            "destination_epoch": ownership.epoch.0,
        }),
    )
}

fn case_cleanup(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
) -> Result<Stage3bCaseCapture, String> {
    let mut case = start_standard(root, definition, b"cleanup-request", b"cleanup-response")?;
    let call = start_request(&mut case)?;
    let effect = visa_component_adapter::parse_identity(&call.effect_operation_id)
        .ok_or("invalid effect operation identity")?;
    let evidence = EvidenceRef {
        identity: derive_stage3b_identity(definition.id, "cleanup-evidence"),
        kind: EvidenceKind::Cleanup,
        digest: case.source.coordinator().state_digest().map_err(runtime_error)?,
    };
    for suffix in ["cleanup-one", "cleanup-two"] {
        case.source
            .coordinator_mut()
            .cleanup_operation(derive_stage3b_identity(definition.id, suffix), effect, evidence)
            .map_err(runtime_error)?;
    }
    let retained = case.source.coordinator().state().operations.iter().any(|record| {
        record.request.operation == effect && record.cleanup == CleanupStatus::Cleaned
    });
    let mut committed = handoff(&mut case)?;
    let _ = reconcile_until_terminal(&mut case, &mut committed.destination)?;
    let executions = case.peer.execution_count();
    finish_committed(
        case,
        committed,
        vec![("cleanup_repeated", retained), ("dedup_truth_retained", executions == 1)],
        json!({"effect_operation": call.effect_operation_id, "peer_executions": executions}),
    )
}

fn start_standard(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
    request: &[u8],
    response: &[u8],
) -> Result<RequestCaseContext, String> {
    start_case(
        root,
        definition,
        request,
        STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
        STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Static(response.to_vec()),
        Stage3bFixtureOptions::standard(),
    )
}

#[allow(clippy::too_many_arguments)]
fn start_case(
    root: &Path,
    definition: &'static Stage3CaseDefinition,
    request: &[u8],
    server_peer_identity: Vec<u8>,
    server_credential: Vec<u8>,
    behavior: LoopbackLogicalPeerBehavior,
    options: Stage3bFixtureOptions,
) -> Result<RequestCaseContext, String> {
    let peer = LoopbackLogicalPeer::spawn(server_peer_identity, server_credential, behavior)
        .map_err(|error| format!("cannot spawn logical peer: {error}"))?;
    let fixture = Stage3bFixture::create(root, definition.id, request, &peer, options)?;
    let Stage3bFixture {
        case_id,
        paths: _,
        ids,
        source_state,
        profile_digest,
        request_bytes,
        handoff_authority,
        timer_authority,
        key_value_authority,
        request_authority,
        source,
        destination,
        ..
    } = fixture;
    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(
            derive_stage3b_identity(definition.id, "activate"),
            ids.source_handoff_authority,
            STAGE3B_INITIAL_LEASE_EPOCH,
        )
        .map_err(runtime_error)?;
    let mut source = LogicalRequestAdapter::instantiate(component::stage3b_bytes(), coordinator)
        .map_err(adapter_error)?;
    source.activate(format!("{}:session", definition.id)).map_err(adapter_error)?;
    let canonical_before = source.coordinator().state_digest().map_err(runtime_error)?;
    Ok(RequestCaseContext {
        definition,
        case_id,
        ids,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        request_authority,
        source,
        destination_provider: Some(destination),
        peer,
        canonical_before,
        request: request_bytes,
        delivered_response: Vec::new(),
        operations: Vec::new(),
    })
}

fn start_request(
    case: &mut RequestCaseContext,
) -> Result<visa_wasmtime::LogicalRequestCallResult, String> {
    let call = case.source.start(case.request.clone()).map_err(adapter_error)?;
    case.operations.push(call.effect_operation_id.clone());
    Ok(call)
}

fn start_destination(
    case: &mut RequestCaseContext,
    destination: &mut LogicalRequestAdapter<SqliteProvider>,
) -> Result<visa_wasmtime::LogicalRequestCallResult, String> {
    let call = destination.start(case.request.clone()).map_err(adapter_error)?;
    case.operations.push(call.effect_operation_id.clone());
    Ok(call)
}

fn observe_request(
    case: &mut RequestCaseContext,
    max_bytes: u32,
) -> Result<visa_wasmtime::LogicalRequestCallResult, String> {
    let call = case.source.observe(max_bytes).map_err(adapter_error)?;
    record_observe(case, &call);
    Ok(call)
}

fn observe_destination(
    case: &mut RequestCaseContext,
    destination: &mut LogicalRequestAdapter<SqliteProvider>,
    max_bytes: u32,
) -> Result<visa_wasmtime::LogicalRequestCallResult, String> {
    let call = destination.observe(max_bytes).map_err(adapter_error)?;
    record_observe(case, &call);
    Ok(call)
}

fn record_observe(case: &mut RequestCaseContext, call: &visa_wasmtime::LogicalRequestCallResult) {
    case.operations.push(call.effect_operation_id.clone());
    if let LogicalRequestResult::Observed { bytes, .. } = &call.result {
        case.delivered_response.extend_from_slice(bytes);
    }
}

fn reconcile_until_terminal(
    case: &mut RequestCaseContext,
    destination: &mut LogicalRequestAdapter<SqliteProvider>,
) -> Result<bool, String> {
    for _ in 0..20 {
        let call = destination.reconcile().map_err(adapter_error)?;
        case.operations.push(call.effect_operation_id);
        let state = canonical_request(destination.coordinator().state())?;
        if matches!(
            state.phase,
            LogicalRequestPhase::Completed
                | LogicalRequestPhase::Cancelled
                | LogicalRequestPhase::TimedOut
                | LogicalRequestPhase::Rejected
        ) {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

fn handoff(case: &mut RequestCaseContext) -> Result<RequestCommitted, String> {
    let (mut destination, portable) = export_to_destination(case)?;
    destination
        .prepare_destination_with_profiles(
            derive_stage3b_identity(&case.case_id, "destination-prepare"),
            case.handoff_authority,
            case.timer_authority,
            case.key_value_authority,
            &[case.request_authority],
        )
        .map_err(runtime_error)?;
    destination
        .commit_handoff(
            derive_stage3b_identity(&case.case_id, "destination-commit-command"),
            derive_stage3b_identity(&case.case_id, "destination-commit-operation"),
            IdempotencyKey::from_bytes(
                derive_stage3b_identity(&case.case_id, "destination-commit-idempotency").0,
            ),
        )
        .map_err(runtime_error)?;
    let mut destination =
        LogicalRequestAdapter::instantiate(component::stage3b_bytes(), destination)
            .map_err(adapter_error)?;
    destination.restore(&portable).map_err(adapter_error)?;
    destination
        .coordinator_mut()
        .resume_destination(derive_stage3b_identity(&case.case_id, "destination-resume"))
        .map_err(runtime_error)?;
    Ok(RequestCommitted { destination, portable })
}

fn export_to_destination(
    case: &mut RequestCaseContext,
) -> Result<(Coordinator<SqliteProvider>, PortableLogicalRequestState), String> {
    case.source
        .coordinator_mut()
        .begin_quiesce(
            derive_stage3b_identity(&case.case_id, "source-begin-quiesce"),
            case.ids.source_handoff_authority,
        )
        .map_err(runtime_error)?;
    let safe_point = case.source.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = case.source.freeze().map_err(adapter_error)?;
    case.source
        .coordinator_mut()
        .commit_safe_point(
            derive_stage3b_identity(&case.case_id, "source-freeze"),
            portable.as_bytes().to_vec(),
            safe_point,
        )
        .map_err(runtime_error)?;
    let evidence = EvidenceRef {
        identity: derive_stage3b_identity(&case.case_id, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: case.source.coordinator().state_digest().map_err(runtime_error)?,
    };
    let (_, snapshot) = case
        .source
        .coordinator_mut()
        .export_snapshot(
            derive_stage3b_identity(&case.case_id, "source-export"),
            case.ids.handoff,
            case.ids.snapshot,
            evidence,
        )
        .map_err(runtime_error)?;
    let validated = validate_snapshot(
        &snapshot,
        &SnapshotExpectations {
            component_digest: component::stage3b_digest(),
            profile_digest: case.profile_digest,
            profile_version: SchemaVersion::new(1, 0),
            supported_extensions: vec![ExtensionSupport {
                id: LOGICAL_REQUEST_EXTENSION_ID,
                version: LOGICAL_REQUEST_EXTENSION_VERSION,
            }],
            destination: case.ids.destination_node,
        },
    )
    .map_err(runtime_error)?;
    let provider = case.destination_provider.take().ok_or("destination provider already used")?;
    Ok((Coordinator::restore(validated, provider).map_err(runtime_error)?, portable))
}

fn freeze_is_profile_blocked(case: &mut RequestCaseContext) -> Result<bool, String> {
    case.source
        .coordinator_mut()
        .begin_quiesce(
            derive_stage3b_identity(&case.case_id, "blocked-begin"),
            case.ids.source_handoff_authority,
        )
        .map_err(runtime_error)?;
    let safe = case.source.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = case.source.freeze().map_err(adapter_error)?;
    Ok(matches!(
        case.source.coordinator_mut().commit_safe_point(
            derive_stage3b_identity(&case.case_id, "blocked-freeze"),
            portable.as_bytes().to_vec(),
            safe,
        ),
        Err(RuntimeError::Rejected(contract_core::Rejection::ProfileMismatch))
    ))
}

fn finish_committed(
    case: RequestCaseContext,
    committed: RequestCommitted,
    assertions: Vec<(&str, bool)>,
    observations: serde_json::Value,
) -> Result<Stage3bCaseCapture, String> {
    let destination_epoch = committed.destination.coordinator().state().ownership.epoch.0;
    Ok(Stage3bCaseCapture {
        definition: case.definition,
        canonical_before: case.canonical_before,
        canonical_after: committed
            .destination
            .coordinator()
            .state_digest()
            .map_err(runtime_error)?,
        source_epoch: STAGE3B_INITIAL_LEASE_EPOCH.0,
        destination_epoch: Some(destination_epoch),
        profile_operations: case.operations,
        assertions: named_assertions(assertions),
        trace: json!({
            "case_id": case.definition.id,
            "terminal": terminal_name(case.definition.terminal),
            "source_phase": format!("{:?}", case.source.coordinator().state().phase),
            "destination_phase": format!("{:?}", committed.destination.coordinator().state().phase),
            "peer_executions": case.peer.execution_count(),
            "credential_material_retained": false,
            "observations": observations,
        }),
        request: case.request,
        delivered_response: case.delivered_response,
    })
}

fn rejected(
    case: RequestCaseContext,
    assertions: Vec<(&str, bool)>,
    observations: serde_json::Value,
) -> Result<Stage3bCaseCapture, String> {
    terminal_capture(case, Stage3CaseTerminal::ProfileRejected, assertions, observations)
}

fn blocked_capture(
    case: RequestCaseContext,
    assertions: Vec<(&str, bool)>,
    observations: serde_json::Value,
) -> Result<Stage3bCaseCapture, String> {
    terminal_capture(case, Stage3CaseTerminal::HandoffBlocked, assertions, observations)
}

fn terminal_capture(
    case: RequestCaseContext,
    terminal: Stage3CaseTerminal,
    assertions: Vec<(&str, bool)>,
    observations: serde_json::Value,
) -> Result<Stage3bCaseCapture, String> {
    if case.definition.terminal != terminal {
        return Err(format!("{} has the wrong terminal class", case.definition.id));
    }
    let source_epoch = case.source.coordinator().state().ownership.epoch.0;
    Ok(Stage3bCaseCapture {
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
            "peer_executions": case.peer.execution_count(),
            "credential_material_retained": false,
            "observations": observations,
        }),
        request: case.request,
        delivered_response: case.delivered_response,
    })
}

fn remove_completed_work_tree(work_root: &Path) -> Result<(), String> {
    fs::remove_dir_all(work_root).map_err(|error| {
        format!("cannot remove completed Stage 3 work tree {}: {error}", work_root.display())
    })
}

fn canonical_request(state: &contract_core::CanonicalState) -> Result<LogicalRequestState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or("missing logical-request extension")?;
    if matching.next().is_some() {
        return Err("duplicate logical-request extension".to_owned());
    }
    logical_request_state(extension)
        .map_err(|error| format!("invalid logical-request state: {error:?}"))
}

fn named_assertions(values: Vec<(&str, bool)>) -> Vec<(String, bool)> {
    values.into_iter().map(|(name, passed)| (name.to_owned(), passed)).collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
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

fn adapter_error(error: LogicalRequestAdapterError) -> String {
    format!("logical-request adapter error: {error}")
}

fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("provider error: {:?} (retryable={})", error.kind, error.retryable)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use contract_core::{AuthorityStatus, ProfileAccess};
    use visa_component_adapter::{ProfileBinding, prepare_profile_effect};

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-stage3b-prepared-start-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn definition() -> &'static Stage3CaseDefinition {
        &STAGE3B_CASE_DEFINITIONS[0]
    }

    fn standard_case(root: &Path, request: &[u8]) -> RequestCaseContext {
        start_standard(root, definition(), request, b"prepared response").unwrap()
    }

    #[test]
    fn prepared_start_matches_the_actual_stored_effect_request() {
        let root = TestRoot::new("actual-request");
        let mut case = standard_case(&root.0, b"prepared request");
        let prepared = case.source.prepare_start(case.request.clone()).unwrap();
        let expected = prepared.effect_request().clone();
        assert_eq!(case.peer.execution_count(), 0);

        let result = case.source.start_prepared(&prepared).unwrap();
        let actual = case
            .source
            .coordinator()
            .state()
            .operations
            .iter()
            .find(|record| record.request.operation == expected.operation)
            .unwrap();
        assert_eq!(actual.request, expected);
        assert_eq!(result.effect_operation_id, identity_hex(expected.operation));
        assert_eq!(case.peer.execution_count(), 1);
    }

    #[test]
    fn changed_request_is_rejected_before_external_dispatch() {
        let root = TestRoot::new("changed-request");
        let expected = b"prepared request";
        let changed = b"tampered request";
        assert_eq!(expected.len(), changed.len());
        let case = standard_case(&root.0, expected);
        assert!(case.source.prepare_start(changed.to_vec()).is_err());
        assert_eq!(case.peer.execution_count(), 0);
    }

    #[test]
    fn canonical_transition_invalidates_prepared_start_before_external_dispatch() {
        let root = TestRoot::new("changed-prestate");
        let mut case = standard_case(&root.0, b"prepared request");
        let prepared = case.source.prepare_start(case.request.clone()).unwrap();
        case.source
            .coordinator_mut()
            .begin_quiesce(
                derive_stage3b_identity(definition().id, "prepared-start-begin-quiesce"),
                case.ids.source_handoff_authority,
            )
            .unwrap();
        assert_ne!(case.source.coordinator().state_digest().unwrap(), prepared.pre_state_digest());
        assert_ne!(case.source.coordinator().journal_position(), prepared.pre_journal_position());
        assert!(case.source.start_prepared(&prepared).is_err());
        assert_eq!(case.peer.execution_count(), 0);
    }

    #[test]
    fn different_prestate_at_same_journal_position_is_rejected_before_external_dispatch() {
        let expected_root = TestRoot::new("expected-prestate");
        let changed_root = TestRoot::new("changed-prestate");
        let expected = standard_case(&expected_root.0, b"prepared request");
        let mut changed = standard_case(&changed_root.0, b"tampered request");
        let prepared = expected.source.prepare_start(expected.request.clone()).unwrap();
        assert_eq!(
            changed.source.coordinator().journal_position(),
            prepared.pre_journal_position()
        );
        assert_ne!(
            changed.source.coordinator().state_digest().unwrap(),
            prepared.pre_state_digest()
        );
        assert!(changed.source.start_prepared(&prepared).is_err());
        assert_eq!(changed.peer.execution_count(), 0);
    }

    #[test]
    fn revoked_request_authority_invalidates_prepared_start_before_external_dispatch() {
        let root = TestRoot::new("changed-authority");
        let mut case = standard_case(&root.0, b"prepared request");
        let prepared = case.source.prepare_start(case.request.clone()).unwrap();
        case.source
            .coordinator_mut()
            .revoke_authority(
                derive_stage3b_identity(definition().id, "prepared-start-revoke-authority"),
                case.ids.source_request_authority,
            )
            .unwrap();
        assert!(case.source.coordinator().state().authorities.iter().any(|grant| {
            grant.authority.identity == case.ids.source_request_authority.identity
                && grant.status == AuthorityStatus::Revoked
        }));
        assert!(case.source.start_prepared(&prepared).is_err());
        assert_eq!(case.peer.execution_count(), 0);
    }

    #[test]
    fn exact_existing_effect_identity_is_reused_for_the_durable_retry() {
        let root = TestRoot::new("existing-identity");
        let mut options = Stage3bFixtureOptions::standard();
        options.source_fault = Some(FaultPoint::BeforeLogicalRequestIo);
        let mut case = start_case(
            &root.0,
            definition(),
            b"prepared request",
            STAGE3B_DEFAULT_PEER_IDENTITY.to_vec(),
            STAGE3B_DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
            LoopbackLogicalPeerBehavior::Static(b"prepared response".to_vec()),
            options,
        )
        .unwrap();
        assert!(case.source.start(case.request.clone()).is_err());
        assert_eq!(case.peer.execution_count(), 0);
        let existing = case.source.coordinator().state().operations.last().unwrap().request.clone();

        let prepared = case.source.prepare_start(case.request.clone()).unwrap();
        assert_eq!(prepared.effect_request(), &existing);
        let result = case.source.start_prepared(&prepared).unwrap();
        assert_eq!(result.effect_operation_id, identity_hex(existing.operation));
        assert_eq!(case.peer.execution_count(), 1);
    }

    #[test]
    fn revoked_source_grant_one_generation_later_keeps_real_handoff_replay_identity() {
        let root = TestRoot::new("revoked-source-continuity");
        let mut case = standard_case(&root.0, b"prepared request");
        let call = case.source.start(case.request.clone()).unwrap();
        let source_effect = visa_component_adapter::parse_identity(&call.effect_operation_id)
            .and_then(|operation| {
                case.source
                    .coordinator()
                    .state()
                    .operations
                    .iter()
                    .find(|record| record.request.operation == operation)
                    .map(|record| record.request.clone())
            })
            .unwrap();
        let logical_operation =
            canonical_request(case.source.coordinator().state()).unwrap().operation_id;
        let mut committed = handoff(&mut case).unwrap();
        committed
            .destination
            .coordinator_mut()
            .revoke_authority(
                derive_stage3b_identity(definition().id, "revoke-source-request-after-handoff"),
                source_effect.authority,
            )
            .unwrap();
        let historical = committed
            .destination
            .coordinator()
            .state()
            .authorities
            .iter()
            .find(|grant| grant.authority.identity == source_effect.authority.identity)
            .unwrap();
        assert_eq!(historical.status, AuthorityStatus::Revoked);
        assert_eq!(
            historical.authority.generation,
            source_effect.authority.generation.next().unwrap()
        );
        let binding = ProfileBinding::for_state(
            committed.destination.coordinator().state(),
            LOGICAL_REQUEST_EXTENSION_ID,
        )
        .unwrap();
        let contract_core::EffectKind::Profile { payload, .. } = &source_effect.kind else {
            panic!("logical request stored a non-profile effect");
        };
        let idempotency = identity_hex(logical_operation);
        assert_eq!(
            prepare_profile_effect(
                committed.destination.coordinator().state(),
                &binding,
                ProfileAccess::Write,
                idempotency.as_bytes(),
                payload.clone(),
            ),
            Ok(source_effect),
        );
        assert_eq!(case.peer.execution_count(), 1);
    }
}
