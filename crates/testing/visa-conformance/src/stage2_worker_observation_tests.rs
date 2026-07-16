use serde_json::{Value, json};

use super::{
    Stage2NormalizedWorkerResponse, Stage2WorkerCommandKind, Stage2WorkerResultKind,
    project_worker_protocol_observations,
};
use crate::Stage1TraceRole;

const CASE_ID: &str = "repeated-cancel-abort-cleanup";
const WORKER: &str = "repeated-cancel-abort-cleanup-source";

#[test]
fn v1_retains_repeated_cancel_cleanup_abort_counts_and_order() {
    let baseline = project(&paired_success_transcript(&[
        "cancel_pending",
        "cleanup_pending_timer",
        "cleanup_pending_timer",
        "abort_source",
        "abort_source",
    ]))
    .unwrap();
    assert_eq!(
        baseline.iter().map(|entry| entry.command).collect::<Vec<_>>(),
        vec![
            Stage2WorkerCommandKind::CancelPending,
            Stage2WorkerCommandKind::CleanupPendingTimer,
            Stage2WorkerCommandKind::CleanupPendingTimer,
            Stage2WorkerCommandKind::AbortSource,
            Stage2WorkerCommandKind::AbortSource,
        ]
    );
    assert_eq!(
        baseline.iter().map(|entry| entry.command_occurrence).collect::<Vec<_>>(),
        vec![1, 1, 2, 1, 2]
    );
    assert!(baseline.iter().all(|entry| {
        entry.worker_scope == "source"
            && entry.response
                == Stage2NormalizedWorkerResponse::Success { result: Stage2WorkerResultKind::State }
    }));

    let without_second_cleanup_and_abort = project(&paired_success_transcript(&[
        "cancel_pending",
        "cleanup_pending_timer",
        "abort_source",
    ]))
    .unwrap();
    assert_ne!(baseline, without_second_cleanup_and_abort);

    let reordered = project(&paired_success_transcript(&[
        "cancel_pending",
        "cleanup_pending_timer",
        "abort_source",
        "cleanup_pending_timer",
        "abort_source",
    ]))
    .unwrap();
    assert_ne!(baseline, reordered);

    let with_extra_cleanup = project(&paired_success_transcript(&[
        "cancel_pending",
        "cleanup_pending_timer",
        "cleanup_pending_timer",
        "cleanup_pending_timer",
        "abort_source",
        "abort_source",
    ]))
    .unwrap();
    assert_ne!(baseline, with_extra_cleanup);
}

#[test]
fn v1_retains_response_class_and_result_kind() {
    let success_state = project(&single_pair(
        json!({ "kind": "cleanup_pending_timer" }),
        json!({ "status": "success", "result": { "kind": "state" } }),
    ))
    .unwrap();
    let impossible_ack = project(&single_pair(
        json!({ "kind": "cleanup_pending_timer" }),
        json!({ "status": "success", "result": { "kind": "ack" } }),
    ))
    .unwrap_err();
    let error = project(&single_pair(
        json!({ "kind": "cleanup_pending_timer" }),
        json!({ "status": "error", "error": { "message": "runtime-local diagnostic" } }),
    ))
    .unwrap();

    assert_eq!(impossible_ack.code, "incompatible-stage2-worker-protocol-result");
    assert_ne!(success_state, error);
}

#[test]
fn v1_excludes_pid_database_path_and_runtime_local_payloads() {
    let baseline = project(&metadata_transcript(
        11,
        "/cell-a/.runner-work/case.sqlite3",
        "engine-a",
        "diagnostic-a",
    ))
    .unwrap();
    let changed = project(&metadata_transcript(
        999,
        "/cell-b/.runner-work/case.sqlite3",
        "engine-b",
        "diagnostic-b",
    ))
    .unwrap();

    assert_eq!(baseline, changed);
}

#[test]
fn missing_non_crash_response_and_unknown_command_are_rejected() {
    let missing_response =
        request_only(WORKER, 7, "request-1", json!({ "kind": "cleanup_pending_timer" }));
    assert_eq!(
        project(&missing_response).unwrap_err().code,
        "missing-stage2-worker-protocol-response"
    );

    let unknown = single_pair(
        json!({ "kind": "cleanup_pending_timer", "ignored": true }),
        json!({ "status": "success", "result": { "kind": "state" } }),
    );
    assert_eq!(project(&unknown).unwrap_err().code, "invalid-stage2-worker-protocol-request");
}

#[test]
fn crash_without_response_is_retained_as_no_response() {
    let transcript = request_only(
        WORKER,
        7,
        "request-1",
        json!({ "kind": "crash", "mode": "immediate", "exit_code": 42 }),
    );
    let observations = project(&transcript).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].command, Stage2WorkerCommandKind::Crash);
    assert_eq!(observations[0].response, Stage2NormalizedWorkerResponse::NoResponse);

    let immediate_with_response = single_pair(
        json!({ "kind": "crash", "mode": "immediate", "exit_code": 42 }),
        json!({ "status": "success", "result": { "kind": "ack" } }),
    );
    assert_eq!(
        project(&immediate_with_response).unwrap_err().code,
        "forbidden-stage2-worker-protocol-response"
    );

    let after_response = request_only(
        WORKER,
        7,
        "request-2",
        json!({ "kind": "crash", "mode": "after_response", "exit_code": 42 }),
    );
    assert_eq!(
        project(&after_response).unwrap_err().code,
        "missing-stage2-worker-protocol-response"
    );
}

#[test]
fn worker_sequences_must_start_at_one_and_remain_contiguous() {
    let mut starts_at_two = Vec::new();
    append_pair(
        &mut starts_at_two,
        WORKER,
        7,
        2,
        "request-1",
        json!({ "kind": "read" }),
        json!({ "status": "success", "result": { "kind": "state" } }),
    );
    assert_eq!(project(&starts_at_two).unwrap_err().code, "invalid-stage2-worker-transcript-order");

    let mut missing_middle_pair = Vec::new();
    append_pair(
        &mut missing_middle_pair,
        WORKER,
        7,
        1,
        "request-1",
        json!({ "kind": "read" }),
        json!({ "status": "success", "result": { "kind": "state" } }),
    );
    append_pair(
        &mut missing_middle_pair,
        WORKER,
        7,
        5,
        "request-3",
        json!({ "kind": "read" }),
        json!({ "status": "success", "result": { "kind": "state" } }),
    );
    assert_eq!(
        project(&missing_middle_pair).unwrap_err().code,
        "invalid-stage2-worker-transcript-order"
    );
}

fn project(
    bytes: &[u8],
) -> Result<Vec<super::Stage2NormalizedWorkerProtocolObservation>, super::Stage2NormalizationError>
{
    project_worker_protocol_observations(CASE_ID, "source.jsonl", Stage1TraceRole::Source, bytes)
}

fn paired_success_transcript(commands: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        append_pair(
            &mut bytes,
            WORKER,
            7,
            index * 2 + 1,
            &format!("request-{index}"),
            json!({ "kind": command }),
            json!({ "status": "success", "result": { "kind": "state" } }),
        );
    }
    bytes
}

fn single_pair(command: Value, outcome: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_pair(&mut bytes, WORKER, 7, 1, "request-1", command, outcome);
    bytes
}

fn metadata_transcript(pid: u32, database_path: &str, engine: &str, message: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_pair(
        &mut bytes,
        WORKER,
        pid,
        1,
        "initialize-1",
        json!({
            "kind": "initialize",
            "role": "source",
            "runtime": "wasmtime",
            "database_path": database_path,
            "options": {
                "case_id": CASE_ID,
                "namespace_availability": "correct",
                "authority_policy": "sufficient",
                "timer_delay_ns": crate::STAGE1_DEFAULT_TIMER_DELAY_NS
            },
            "fault": null,
        }),
        json!({
            "status": "success",
            "result": {
                "kind": "initialized",
                "role": "source",
                "case_id": CASE_ID,
                "runtime": { "engine": engine },
            }
        }),
    );
    append_pair(
        &mut bytes,
        WORKER,
        pid,
        3,
        "read-2",
        json!({ "kind": "read" }),
        json!({
            "status": "error",
            "error": {
                "code": "runtime",
                "message": message,
                "retryable": false,
                "provider_kind": null,
                "adapter_kind": null,
                "workload_kind": null,
            }
        }),
    );
    bytes
}

fn append_pair(
    bytes: &mut Vec<u8>,
    worker: &str,
    pid: u32,
    sequence: usize,
    request_id: &str,
    command: Value,
    outcome: Value,
) {
    append_outer(
        bytes,
        worker,
        pid,
        sequence,
        "parent_request",
        json!({
            "version": crate::STAGE1_WORKER_PROTOCOL_VERSION,
            "id": request_id,
            "command": command
        }),
    );
    append_outer(
        bytes,
        worker,
        pid,
        sequence + 1,
        "worker_response",
        json!({
            "version": crate::STAGE1_WORKER_PROTOCOL_VERSION,
            "id": request_id,
            "outcome": outcome
        }),
    );
}

fn request_only(worker: &str, pid: u32, request_id: &str, command: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_outer(
        &mut bytes,
        worker,
        pid,
        1,
        "parent_request",
        json!({
            "version": crate::STAGE1_WORKER_PROTOCOL_VERSION,
            "id": request_id,
            "command": command
        }),
    );
    bytes
}

fn append_outer(
    bytes: &mut Vec<u8>,
    worker: &str,
    pid: u32,
    sequence: usize,
    stream: &str,
    protocol: Value,
) {
    bytes.extend_from_slice(
        &serde_json::to_vec(&json!({
            "worker": worker,
            "pid": pid,
            "sequence": sequence,
            "stream": stream,
            "line": protocol.to_string(),
        }))
        .unwrap(),
    );
    bytes.push(b'\n');
}
