//! Assertions over one composite cell run, plus the JSON trace written beside
//! the case artifacts.
//!
//! These checks are deliberately local to this crate rather than reusing the
//! conformance verifier, which is bound to the registered claim gates.

use contract_core::canonical_digest;
use serde_json::{Value, json};
use visa_component_adapter::{
    LogicalRequestComponentState, LogicalRequestWorkloadLifecycle, RegularFileComponentState,
    RegularFileWorkloadPhase,
};

use crate::cell::CompositeCellOutcome;

pub struct CompositeVerification {
    pub assertions: Vec<(String, bool)>,
    pub trace: Value,
}

impl CompositeVerification {
    pub fn passed(&self) -> bool {
        self.assertions.iter().all(|(_, passed)| *passed)
    }

    pub fn failures(&self) -> Vec<&str> {
        self.assertions
            .iter()
            .filter(|(_, passed)| !*passed)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

pub fn verify(outcome: &CompositeCellOutcome) -> CompositeVerification {
    let frozen = &outcome.frozen_state;
    let restored = &outcome.restored_status;

    let portable_state_identical =
        outcome.destination_portable_state == outcome.portable_frozen.as_bytes();

    // The two profile segments must survive the round trip unchanged except
    // for the lifecycle field the restore itself flips back to active.
    let file_state_survived = file_matches_ignoring_phase(&frozen.file, &restored.file);
    let request_state_survived =
        request_matches_ignoring_lifecycle(&frozen.request, &restored.request);

    let disk_digest = canonical_digest(outcome.file_after_source.as_slice()).ok();
    let file_digest_matches_disk = disk_digest == Some(frozen.file.content_digest)
        && frozen.file.size == outcome.file_after_source.len() as u64;

    let echo_digest = canonical_digest(outcome.source_response.as_slice()).ok();
    let frozen_response = frozen.request.response;
    let response_digest_matches_echo = match (frozen_response, echo_digest) {
        (Some(response), Some(digest)) => {
            response.digest == digest
                && response.size as usize == outcome.source_response.len()
                && outcome.source_response == crate::cell::REQUEST_BODY
        }
        _ => false,
    };
    let response_survived_handoff = frozen_response.is_some_and(|response| {
        response.digest.0.to_vec() == outcome.destination_response_digest
            && response.size == outcome.destination_response_size
    });

    let source_operations_visible = outcome
        .source_operation_ids
        .iter()
        .all(|operation| outcome.destination_visible_operations.contains(operation));

    let append_replay_idempotent = outcome.replayed_append_operation
        == outcome.source_append_operation
        && outcome.file_after_replay == outcome.file_after_source;

    let mut expected_final = crate::cell::INITIAL_FILE_CONTENT.to_vec();
    expected_final.extend_from_slice(b"!?");
    let destination_append_extended = outcome.file_after_destination == expected_final;

    let timer_fired_once = outcome.timer_fired_operations.len() == 1
        && outcome.timer_fired_operations[0] == outcome.destination_arm_operation;
    let timer_rearmed_on_destination =
        outcome.destination_arm_operation != outcome.timer_arm_operation;
    let timer_remaining_cross_checked =
        match (outcome.safe_point_remaining_ns, outcome.polled_remaining_ns) {
            (Some(safe_point), Some(polled)) => polled <= safe_point,
            (Some(_), None) => true,
            _ => false,
        };

    let completion_put_applied = outcome.kv_completion_version > outcome.kv_baseline_version
        && outcome.kv_final_version == Some(outcome.kv_completion_version);
    let kv_version_chain = outcome.kv_baseline_version > 0
        && outcome.kv_completion_version > outcome.kv_baseline_version;

    let source_fully_fenced = outcome.source_fenced_resources.iter().all(|(_, fenced)| *fenced)
        && outcome.source_fenced_resources.len() == 4;

    let destination_epoch_advanced = outcome.destination_epoch == outcome.source_epoch + 1;

    let assertions = vec![
        ("portable_state_identical", portable_state_identical),
        ("file_state_survived_restore", file_state_survived),
        ("request_state_survived_restore", request_state_survived),
        ("file_digest_matches_disk", file_digest_matches_disk),
        ("response_digest_matches_echo", response_digest_matches_echo),
        ("response_survived_handoff", response_survived_handoff),
        ("source_operations_visible_on_destination", source_operations_visible),
        ("append_replay_idempotent", append_replay_idempotent),
        ("destination_append_extended", destination_append_extended),
        ("timer_fired_exactly_once", timer_fired_once),
        ("timer_rearmed_on_destination", timer_rearmed_on_destination),
        ("timer_remaining_cross_checked", timer_remaining_cross_checked),
        ("completion_put_applied", completion_put_applied),
        ("kv_version_chain_advances", kv_version_chain),
        ("source_fenced_on_every_resource", source_fully_fenced),
        ("destination_epoch_advanced", destination_epoch_advanced),
        ("resource_table_empty_at_freeze", outcome.resource_table_empty_at_freeze),
    ]
    .into_iter()
    .map(|(name, passed)| (name.to_owned(), passed))
    .collect::<Vec<_>>();

    let trace = json!({
        "case_id": outcome.case_id,
        "component_state_encoding": crate::state::COMPOSITE_COMPONENT_STATE_ENCODING,
        "canonical_digest": {
            "before": hex(&outcome.canonical_before.0),
            "after": hex(&outcome.canonical_after.0),
        },
        "epochs": {
            "source": outcome.source_epoch,
            "destination": outcome.destination_epoch,
        },
        "operations": {
            "source": outcome.source_operations,
            "destination": outcome.destination_operations,
            "source_canonical_records": outcome.source_operation_ids,
            "destination_canonical_records": outcome.destination_visible_operations,
        },
        "timer": {
            "source_arm_operation": outcome.timer_arm_operation,
            "destination_arm_operation": outcome.destination_arm_operation,
            "safe_point_remaining_ns": outcome.safe_point_remaining_ns,
            "polled_remaining_ns": outcome.polled_remaining_ns,
            "fired_operations": outcome.timer_fired_operations,
        },
        "key_value": {
            "key": frozen.timer_kv.key,
            "baseline_version": outcome.kv_baseline_version,
            "completion_version": outcome.kv_completion_version,
            "final_version": outcome.kv_final_version,
        },
        "regular_file": {
            "before": String::from_utf8_lossy(&outcome.file_before),
            "after_source_append": String::from_utf8_lossy(&outcome.file_after_source),
            "after_replayed_append": String::from_utf8_lossy(&outcome.file_after_replay),
            "after_destination_append": String::from_utf8_lossy(&outcome.file_after_destination),
            "source_append_operation": outcome.source_append_operation,
            "replayed_append_operation": outcome.replayed_append_operation,
            "frozen_version": frozen.file.version,
            "destination_version": outcome.file_post_restore.version,
        },
        "logical_request": {
            "request": String::from_utf8_lossy(crate::cell::REQUEST_BODY),
            "response": String::from_utf8_lossy(&outcome.source_response),
            "frozen_phase": format!("{:?}", frozen.request.request_phase),
            "destination_phase": format!("{:?}", outcome.request_post_restore.phase),
            "response_size": outcome.destination_response_size,
            "response_digest": hex(&outcome.destination_response_digest),
        },
        "safe_point": {
            "portable_state_bytes": outcome.portable_frozen.as_bytes().len(),
            "portable_state_digest": hex(&contract_core::canonical_digest(
                outcome.portable_frozen.as_bytes(),
            ).map(|digest| digest.0.to_vec()).unwrap_or_default()),
            "resource_table_empty": outcome.resource_table_empty_at_freeze,
        },
        "source_fence": outcome
            .source_fenced_resources
            .iter()
            .map(|(label, fenced)| json!({"resource": label, "stale_epoch": fenced}))
            .collect::<Vec<_>>(),
        "assertions": assertions
            .iter()
            .map(|(name, passed)| json!({"name": name, "passed": passed}))
            .collect::<Vec<_>>(),
    });

    CompositeVerification { assertions, trace }
}

fn file_matches_ignoring_phase(
    frozen: &RegularFileComponentState,
    restored: &RegularFileComponentState,
) -> bool {
    let mut normalized = restored.clone();
    normalized.phase = frozen.phase;
    &normalized == frozen && restored.phase == RegularFileWorkloadPhase::Active
}

fn request_matches_ignoring_lifecycle(
    frozen: &LogicalRequestComponentState,
    restored: &LogicalRequestComponentState,
) -> bool {
    let mut normalized = restored.clone();
    normalized.lifecycle = frozen.lifecycle;
    &normalized == frozen && restored.lifecycle == LogicalRequestWorkloadLifecycle::Active
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
