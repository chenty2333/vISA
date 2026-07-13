use std::path::Path;

use contract_core::{Digest, HandoffPhase, JournalPosition};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{model::Stage2Runtime, runtime::runtime_metadata_value_is_exact};
use crate::STAGE1_WORKER_PROTOCOL_VERSION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProtocolResponseStatus {
    Success,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CanonicalStateBoundary {
    SourceBootstrap,
    DestinationCommit,
    DestinationResume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolCommandKind {
    Initialize,
    BootstrapSource,
    Read,
    BeginQuiesce,
    FreezeSource,
    ExportSourceSnapshot,
    AbortSource,
    ThawSource,
    CancelPending,
    CleanupPendingTimer,
    InjectUnsupportedLiveResource,
    ClearUnsupportedLiveResource,
    RevokeRequiredAuthority,
    StaleSourceKvProbe,
    AdversarialStaleKvWriteProbe,
    DuplicateCompletionKvProbe,
    ValidateDestination,
    LoadDestination,
    PrepareDestination,
    CommitDestination,
    ResumeDestination,
    PollTimer,
    Dump,
    Crash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolResultKind {
    Ack,
    Prepared,
    Initialized,
    State,
    SafePoint,
    Snapshot,
    Timer,
    EffectProbe,
    Dump,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolResponseProjection {
    Success(ProtocolResultKind),
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProtocolRequestProjection {
    pub(crate) kind: ProtocolCommandKind,
    pub(crate) permits_no_response: bool,
    pub(crate) forbids_response: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeProjection {
    version: u64,
    id: String,
    command: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelopeProjection {
    version: u64,
    id: String,
    outcome: ResponseOutcomeProjection,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseOutcomeProjection {
    Success { result: Value },
    Error { error: Value },
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProtocolWorkerRole {
    Source,
    Destination,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProtocolRuntime {
    Wasmtime,
    JcoNode,
    Wacogo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializeCommandProjection {
    kind: String,
    role: ProtocolWorkerRole,
    runtime: ProtocolRuntime,
    database_path: String,
    options: InitializeOptionsProjection,
    #[serde(rename = "fault")]
    _fault: Option<ProtocolFaultPoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializeOptionsProjection {
    case_id: String,
    #[serde(rename = "namespace_availability")]
    _namespace_availability: ProtocolNamespaceAvailability,
    #[serde(rename = "authority_policy")]
    _authority_policy: ProtocolAuthorityPolicyMode,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolNamespaceAvailability {
    Correct,
    Missing,
    Wrong,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolAuthorityPolicyMode {
    Sufficient,
    Missing,
    Broader,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolFaultPoint {
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    AfterKvCommit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializedResultProjection {
    kind: String,
    role: ProtocolWorkerRole,
    case_id: String,
    prepared_runtime: Value,
    live_runtime: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedResultProjection {
    kind: String,
    runtime: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateResultProjection {
    kind: String,
    view: StateViewProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateViewProjection {
    role: ProtocolWorkerRole,
    canonical_phase: HandoffPhase,
    #[serde(rename = "journal_position")]
    _journal_position: JournalPosition,
    #[serde(rename = "state_digest")]
    _state_digest: Digest,
    component_instantiated: bool,
    live_runtime: Option<Value>,
    component: Option<ComponentStatusProjection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentStatusProjection {
    #[serde(rename = "session_id")]
    _session_id: String,
    #[serde(rename = "key")]
    _key: String,
    #[serde(rename = "expected_version")]
    _expected_version: u64,
    #[serde(rename = "completion_value")]
    _completion_value: Vec<u8>,
    #[serde(rename = "timer_operation_id")]
    _timer_operation_id: String,
    #[serde(rename = "timer_idempotency_key")]
    _timer_idempotency_key: String,
    #[serde(rename = "completion_idempotency_key")]
    _completion_idempotency_key: String,
    #[serde(rename = "phase")]
    _phase: WorkloadPhaseProjection,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkloadPhaseProjection {
    Armed,
    Frozen,
    Completed,
    Cancelled,
}

pub(super) fn validate_request_envelope(value: &Value) -> Result<(), String> {
    let envelope: RequestEnvelopeProjection =
        serde_json::from_value(value.clone()).map_err(|source| source.to_string())?;
    if envelope.version != STAGE1_WORKER_PROTOCOL_VERSION || envelope.id.is_empty() {
        return Err(format!(
            "request must use protocol version {STAGE1_WORKER_PROTOCOL_VERSION} and a non-empty id"
        ));
    }
    if !envelope.command.is_object() {
        return Err("request command must be an object".to_owned());
    }
    Ok(())
}

pub(super) fn validate_response_envelope(value: &Value) -> Result<ProtocolResponseStatus, String> {
    let envelope: ResponseEnvelopeProjection =
        serde_json::from_value(value.clone()).map_err(|source| source.to_string())?;
    if envelope.version != STAGE1_WORKER_PROTOCOL_VERSION || envelope.id.is_empty() {
        return Err(format!(
            "response must use protocol version {STAGE1_WORKER_PROTOCOL_VERSION} and a non-empty id"
        ));
    }
    match envelope.outcome {
        ResponseOutcomeProjection::Success { result } if result.is_object() => {
            let kind = result.get("kind").and_then(Value::as_str).unwrap_or_default();
            if matches!(
                kind,
                "ack"
                    | "prepared"
                    | "initialized"
                    | "state"
                    | "safe_point"
                    | "snapshot"
                    | "timer"
                    | "effect_probe"
                    | "dump"
            ) {
                Ok(ProtocolResponseStatus::Success)
            } else {
                Err(format!("successful response has unknown result kind {kind:?}"))
            }
        }
        ResponseOutcomeProjection::Error { error } if error.is_object() => {
            Ok(ProtocolResponseStatus::Error)
        }
        ResponseOutcomeProjection::Success { .. } => {
            Err("successful response result must be an object".to_owned())
        }
        ResponseOutcomeProjection::Error { .. } => {
            Err("error response error must be an object".to_owned())
        }
    }
}

pub(crate) fn project_request_command(value: &Value) -> Result<ProtocolRequestProjection, String> {
    validate_request_envelope(value)?;
    let command = value
        .get("command")
        .and_then(Value::as_object)
        .ok_or("request command must be an object")?;
    let kind = command.get("kind").and_then(Value::as_str).unwrap_or_default();
    let mut permits_no_response = false;
    let mut forbids_response = false;
    let kind = match kind {
        "initialize" => {
            require_exact_fields(
                command,
                &["kind", "role", "runtime", "database_path", "options", "fault"],
            )?;
            require_one_of(command, "role", &["source", "destination"])?;
            require_one_of(command, "runtime", &["wasmtime", "jco_node", "wacogo"])?;
            require_nonempty_string(command, "database_path")?;
            require_object(command, "options")?;
            let fault = command.get("fault").ok_or("command field fault is missing")?;
            if !fault.is_null()
                && !matches!(
                    fault.as_str(),
                    Some(
                        "before_journal_write"
                            | "after_journal_write"
                            | "before_activation_bundle"
                            | "after_activation_bundle"
                            | "before_commit_bundle"
                            | "after_commit_bundle"
                            | "after_kv_commit"
                    )
                )
            {
                return Err("command field fault has an unknown value".to_owned());
            }
            serde_json::from_value::<InitializeCommandProjection>(Value::Object(command.clone()))
                .map_err(|source| format!("initialize command is not exact: {source}"))?;
            ProtocolCommandKind::Initialize
        }
        "revoke_required_authority" => {
            require_exact_fields(command, &["kind", "authority"])?;
            require_one_of(command, "authority", &["handoff", "timer", "key_value"])?;
            ProtocolCommandKind::RevokeRequiredAuthority
        }
        "validate_destination" => {
            require_exact_fields(command, &["kind", "envelope", "expectations", "support"])?;
            require_object(command, "envelope")?;
            require_object(command, "expectations")?;
            require_one_of(command, "support", &["compatible", "timer_semantics_unsupported"])?;
            ProtocolCommandKind::ValidateDestination
        }
        "load_destination" => {
            require_exact_fields(command, &["kind", "envelope", "component_state"])?;
            require_object(command, "envelope")?;
            require_array(command, "component_state")?;
            ProtocolCommandKind::LoadDestination
        }
        "poll_timer" => {
            require_exact_fields(command, &["kind", "deliver"])?;
            if command.get("deliver").and_then(Value::as_bool).is_none() {
                return Err("command field deliver must be a boolean".to_owned());
            }
            ProtocolCommandKind::PollTimer
        }
        "crash" => {
            require_exact_fields(command, &["kind", "mode", "exit_code"])?;
            require_one_of(command, "mode", &["after_response", "immediate"])?;
            permits_no_response = command.get("mode").and_then(Value::as_str) == Some("immediate");
            forbids_response = permits_no_response;
            let exit_code = command
                .get("exit_code")
                .and_then(Value::as_i64)
                .ok_or("command field exit_code must be an integer")?;
            i32::try_from(exit_code)
                .map_err(|_| "command field exit_code is outside i32".to_owned())?;
            ProtocolCommandKind::Crash
        }
        "bootstrap_source" => no_payload(command, ProtocolCommandKind::BootstrapSource)?,
        "read" => no_payload(command, ProtocolCommandKind::Read)?,
        "begin_quiesce" => no_payload(command, ProtocolCommandKind::BeginQuiesce)?,
        "freeze_source" => no_payload(command, ProtocolCommandKind::FreezeSource)?,
        "export_source_snapshot" => no_payload(command, ProtocolCommandKind::ExportSourceSnapshot)?,
        "abort_source" => no_payload(command, ProtocolCommandKind::AbortSource)?,
        "thaw_source" => no_payload(command, ProtocolCommandKind::ThawSource)?,
        "cancel_pending" => no_payload(command, ProtocolCommandKind::CancelPending)?,
        "cleanup_pending_timer" => no_payload(command, ProtocolCommandKind::CleanupPendingTimer)?,
        "inject_unsupported_live_resource" => {
            no_payload(command, ProtocolCommandKind::InjectUnsupportedLiveResource)?
        }
        "clear_unsupported_live_resource" => {
            no_payload(command, ProtocolCommandKind::ClearUnsupportedLiveResource)?
        }
        "stale_source_kv_probe" => no_payload(command, ProtocolCommandKind::StaleSourceKvProbe)?,
        "adversarial_stale_kv_write_probe" => {
            no_payload(command, ProtocolCommandKind::AdversarialStaleKvWriteProbe)?
        }
        "duplicate_completion_kv_probe" => {
            no_payload(command, ProtocolCommandKind::DuplicateCompletionKvProbe)?
        }
        "prepare_destination" => no_payload(command, ProtocolCommandKind::PrepareDestination)?,
        "commit_destination" => no_payload(command, ProtocolCommandKind::CommitDestination)?,
        "resume_destination" => no_payload(command, ProtocolCommandKind::ResumeDestination)?,
        "dump" => no_payload(command, ProtocolCommandKind::Dump)?,
        _ => return Err(format!("request has unknown command kind {kind:?}")),
    };
    Ok(ProtocolRequestProjection { kind, permits_no_response, forbids_response })
}

pub(crate) fn project_response(value: &Value) -> Result<ProtocolResponseProjection, String> {
    match validate_response_envelope(value)? {
        ProtocolResponseStatus::Error => Ok(ProtocolResponseProjection::Error),
        ProtocolResponseStatus::Success => {
            let kind =
                value.pointer("/outcome/result/kind").and_then(Value::as_str).unwrap_or_default();
            let result = match kind {
                "ack" => ProtocolResultKind::Ack,
                "prepared" => ProtocolResultKind::Prepared,
                "initialized" => ProtocolResultKind::Initialized,
                "state" => ProtocolResultKind::State,
                "safe_point" => ProtocolResultKind::SafePoint,
                "snapshot" => ProtocolResultKind::Snapshot,
                "timer" => ProtocolResultKind::Timer,
                "effect_probe" => ProtocolResultKind::EffectProbe,
                "dump" => ProtocolResultKind::Dump,
                _ => unreachable!("validate_response_envelope accepts only closed result kinds"),
            };
            Ok(ProtocolResponseProjection::Success(result))
        }
    }
}

pub(crate) const fn success_result_matches(
    command: ProtocolCommandKind,
    result: ProtocolResultKind,
) -> bool {
    match command {
        ProtocolCommandKind::Initialize => matches!(result, ProtocolResultKind::Initialized),
        ProtocolCommandKind::BootstrapSource
        | ProtocolCommandKind::Read
        | ProtocolCommandKind::BeginQuiesce
        | ProtocolCommandKind::AbortSource
        | ProtocolCommandKind::ThawSource
        | ProtocolCommandKind::CancelPending
        | ProtocolCommandKind::CleanupPendingTimer
        | ProtocolCommandKind::InjectUnsupportedLiveResource
        | ProtocolCommandKind::ClearUnsupportedLiveResource
        | ProtocolCommandKind::RevokeRequiredAuthority
        | ProtocolCommandKind::StaleSourceKvProbe
        | ProtocolCommandKind::LoadDestination
        | ProtocolCommandKind::PrepareDestination
        | ProtocolCommandKind::CommitDestination
        | ProtocolCommandKind::ResumeDestination => matches!(result, ProtocolResultKind::State),
        ProtocolCommandKind::FreezeSource => matches!(result, ProtocolResultKind::SafePoint),
        ProtocolCommandKind::ExportSourceSnapshot => {
            matches!(result, ProtocolResultKind::Snapshot)
        }
        ProtocolCommandKind::DuplicateCompletionKvProbe => {
            matches!(result, ProtocolResultKind::EffectProbe)
        }
        ProtocolCommandKind::ValidateDestination => matches!(result, ProtocolResultKind::Prepared),
        ProtocolCommandKind::Crash => matches!(result, ProtocolResultKind::Ack),
        ProtocolCommandKind::PollTimer => matches!(result, ProtocolResultKind::Timer),
        ProtocolCommandKind::Dump => matches!(result, ProtocolResultKind::Dump),
        ProtocolCommandKind::AdversarialStaleKvWriteProbe => false,
    }
}

fn no_payload(
    command: &serde_json::Map<String, Value>,
    kind: ProtocolCommandKind,
) -> Result<ProtocolCommandKind, String> {
    require_exact_fields(command, &["kind"])?;
    Ok(kind)
}

fn require_exact_fields(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
) -> Result<(), String> {
    if object.len() != expected.len() || !expected.iter().all(|field| object.contains_key(*field)) {
        return Err(format!("command {expected:?} fields are not exact"));
    }
    Ok(())
}

fn require_one_of(
    object: &serde_json::Map<String, Value>,
    field: &str,
    expected: &[&str],
) -> Result<(), String> {
    let value = object.get(field).and_then(Value::as_str).unwrap_or_default();
    if expected.contains(&value) {
        Ok(())
    } else {
        Err(format!("command field {field} has an unknown value"))
    }
}

fn require_nonempty_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), String> {
    if object.get(field).and_then(Value::as_str).is_some_and(|value| !value.is_empty()) {
        Ok(())
    } else {
        Err(format!("command field {field} must be a non-empty string"))
    }
}

fn require_object(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), String> {
    if object.get(field).is_some_and(Value::is_object) {
        Ok(())
    } else {
        Err(format!("command field {field} must be an object"))
    }
}

fn require_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), String> {
    if object.get(field).is_some_and(Value::is_array) {
        Ok(())
    } else {
        Err(format!("command field {field} must be an array"))
    }
}

pub(crate) fn observed_component_instantiated(value: &Value) -> Result<Option<bool>, String> {
    let result = value
        .pointer("/outcome/result")
        .and_then(Value::as_object)
        .ok_or("successful response has no result object")?;
    let kind = result.get("kind").and_then(Value::as_str).unwrap_or_default();
    match kind {
        "state" | "safe_point" | "snapshot" | "timer" | "effect_probe" => {
            let view = result
                .get("view")
                .and_then(Value::as_object)
                .ok_or_else(|| format!("{kind} result has no state view"))?;
            let instantiated = view
                .get("component_instantiated")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("{kind} result has no boolean live-state observation"))?;
            let live = view
                .get("live_runtime")
                .ok_or_else(|| format!("{kind} result has no explicit live_runtime field"))?;
            if !(live.is_null() || runtime_metadata_value_is_exact(live))
                || live.is_object() != instantiated
            {
                return Err(format!(
                    "{kind} live runtime presence does not match component_instantiated"
                ));
            }
            Ok(Some(instantiated))
        }
        "dump" => {
            let instantiated = result
                .get("component_instantiated")
                .and_then(Value::as_bool)
                .ok_or_else(|| "dump result has no boolean live-state observation".to_owned())?;
            let live = result
                .get("live_runtime")
                .ok_or_else(|| "dump result has no explicit live_runtime field".to_owned())?;
            if !(live.is_null() || runtime_metadata_value_is_exact(live))
                || live.is_object() != instantiated
            {
                return Err(
                    "dump live runtime presence does not match component_instantiated".to_owned()
                );
            }
            Ok(Some(instantiated))
        }
        "ack" | "prepared" | "initialized" => Ok(None),
        _ => Err(format!("cannot audit live state for result kind {kind:?}")),
    }
}

pub(super) fn validate_initialize_request(
    value: &Value,
    role_name: &str,
    expected_runtime: Stage2Runtime,
    expected_case_id: &str,
    provider_binding: Option<(&Path, &str)>,
) -> Result<String, String> {
    let command: InitializeCommandProjection = serde_json::from_value(
        value.get("command").cloned().ok_or("initialize request has no command")?,
    )
    .map_err(|source| source.to_string())?;
    let expected_role = expected_role(role_name)?;
    let initialized_case_id = command.options.case_id.as_str();
    let runtime_matches = matches!(
        (command.runtime, expected_runtime),
        (ProtocolRuntime::Wasmtime, Stage2Runtime::Wasmtime)
            | (ProtocolRuntime::JcoNode, Stage2Runtime::JcoNode)
            | (ProtocolRuntime::Wacogo, Stage2Runtime::Wacogo)
    );
    if command.kind != "initialize" || command.role != expected_role || !runtime_matches {
        return Err("initialize request must bind the expected role and runtime".to_owned());
    }
    if let Some((cell_root, worker)) = provider_binding {
        validate_initialize_worker(worker, expected_role, expected_case_id, initialized_case_id)?;
        validate_provider_database_path(&command.database_path, cell_root, initialized_case_id)?;
    } else if initialized_case_id != expected_case_id {
        return Err("initialize request must bind the expected case".to_owned());
    }
    Ok(initialized_case_id.to_owned())
}

pub(super) fn validate_initialize_response(
    value: &Value,
    role_name: &str,
    expected_case_id: &str,
) -> Result<(), String> {
    let result: InitializedResultProjection = serde_json::from_value(
        value.pointer("/outcome/result").cloned().ok_or("initialize response has no result")?,
    )
    .map_err(|source| source.to_string())?;
    let expected_role = expected_role(role_name)?;
    let result_value = value
        .pointer("/outcome/result")
        .and_then(Value::as_object)
        .ok_or("initialize response has no result object")?;
    let prepared_is_exact =
        result_value.get("prepared_runtime").is_some_and(runtime_metadata_value_is_exact);
    let live_is_explicit = result_value.contains_key("live_runtime");
    if result.kind != "initialized"
        || result.role != expected_role
        || result.case_id != expected_case_id
        || !prepared_is_exact
        || !live_is_explicit
        || match expected_role {
            ProtocolWorkerRole::Source => {
                result.live_runtime.as_ref() != Some(&result.prepared_runtime)
            }
            ProtocolWorkerRole::Destination => result.live_runtime.is_some(),
        }
    {
        return Err(
            "initialize response must bind the expected role, case, and runtime observation"
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn validate_prepared_response(value: &Value) -> Result<&Value, String> {
    let result: PreparedResultProjection = serde_json::from_value(
        value.pointer("/outcome/result").cloned().ok_or("prepared response has no result")?,
    )
    .map_err(|source| source.to_string())?;
    if result.kind != "prepared" || !runtime_metadata_value_is_exact(&result.runtime) {
        return Err("prepared response must carry one runtime observation".to_owned());
    }
    value
        .pointer("/outcome/result/runtime")
        .ok_or_else(|| "prepared response has no runtime observation".to_owned())
}

pub(super) fn validate_canonical_state_response(
    value: &Value,
    boundary: CanonicalStateBoundary,
) -> Result<(), String> {
    let result: StateResultProjection = serde_json::from_value(
        value.pointer("/outcome/result").cloned().ok_or("state response has no result")?,
    )
    .map_err(|source| source.to_string())?;
    let (expected_role, expected_phase, expected_live) = match boundary {
        CanonicalStateBoundary::SourceBootstrap => {
            (ProtocolWorkerRole::Source, HandoffPhase::Running, true)
        }
        CanonicalStateBoundary::DestinationCommit => {
            (ProtocolWorkerRole::Destination, HandoffPhase::Committed, false)
        }
        CanonicalStateBoundary::DestinationResume => {
            (ProtocolWorkerRole::Destination, HandoffPhase::Running, true)
        }
    };
    let component_shape_matches = if expected_live {
        result.view.component.is_some()
    } else {
        result.view.component.is_none()
    };
    if result.kind != "state"
        || result.view.role != expected_role
        || result.view.canonical_phase != expected_phase
        || result.view.component_instantiated != expected_live
        || result.view.live_runtime.is_some() != expected_live
        || !component_shape_matches
    {
        return Err(
            "canonical state response has the wrong role, phase, live state, or component shape"
                .to_owned(),
        );
    }
    Ok(())
}

fn expected_role(role_name: &str) -> Result<ProtocolWorkerRole, String> {
    match role_name {
        "source.jsonl" => Ok(ProtocolWorkerRole::Source),
        "destination.jsonl" => Ok(ProtocolWorkerRole::Destination),
        _ => Err(format!("unsupported transcript role {role_name}")),
    }
}

fn validate_initialize_worker(
    worker: &str,
    role: ProtocolWorkerRole,
    top_case_id: &str,
    initialized_case_id: &str,
) -> Result<(), String> {
    if initialized_case_id == top_case_id {
        let expected_labels: &[&str] = match role {
            ProtocolWorkerRole::Source => &["source", "source-audit"],
            ProtocolWorkerRole::Destination => &[
                "destination",
                "destination-audit",
                "destination-recovery-before-commit",
                "destination-recovery-after-commit",
                "duplicate-destination",
            ],
        };
        if expected_labels.iter().any(|label| worker == format!("{top_case_id}-{label}")) {
            return Ok(());
        }
        return Err("top-level initialize worker does not match its case and role".to_owned());
    }

    let supplemental_prefix = format!("{top_case_id}-");
    let Some(suffix) = initialized_case_id.strip_prefix(&supplemental_prefix) else {
        return Err("supplemental initialize case is outside the top-level case".to_owned());
    };
    if !is_canonical_case_suffix(suffix) {
        return Err("supplemental initialize case has an invalid suffix".to_owned());
    }
    if role != ProtocolWorkerRole::Source {
        return Err("supplemental initialize workers must use the source role".to_owned());
    }
    for label in
        ["supplemental-source", "supplemental-source-retry", "supplemental-source-recovery"]
    {
        if worker == format!("{initialized_case_id}-{label}") {
            return Ok(());
        }
    }
    Err("supplemental initialize worker does not match its case and role".to_owned())
}

pub(crate) fn validate_initialize_worker_binding(
    worker: &str,
    role_name: &str,
    top_case_id: &str,
    initialized_case_id: &str,
) -> Result<(), String> {
    validate_initialize_worker(worker, expected_role(role_name)?, top_case_id, initialized_case_id)
}

fn is_canonical_case_suffix(suffix: &str) -> bool {
    suffix.split('-').all(|segment| {
        !segment.is_empty()
            && segment.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

fn validate_provider_database_path(
    database_path: &str,
    cell_root: &Path,
    initialized_case_id: &str,
) -> Result<(), String> {
    let expected = cell_root.join(".runner-work").join(format!("{initialized_case_id}.sqlite3"));
    if Path::new(database_path) != expected {
        return Err(format!(
            "initialize provider database must be the exact cell-local case database {}",
            expected.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::{Stage2Runtime, observed_component_instantiated, validate_initialize_request};

    const TOP_CASE: &str = "evidence-verification";
    const CELL_ROOT: &str = "/stage2/cells/wasmtime-to-wasmtime";

    fn exact_runtime() -> serde_json::Value {
        json!({
            "implementation": "visa_wasmtime",
            "implementation_version": super::super::model::STAGE2_WASMTIME_IMPLEMENTATION_VERSION,
            "engine": "wasmtime",
            "engine_version": super::super::model::STAGE2_WASMTIME_ENGINE_VERSION,
            "translation_provenance": null,
            "implementation_lineage": null
        })
    }

    fn live_result(
        kind: &str,
        component_instantiated: bool,
        live_runtime: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut observed = json!({ "component_instantiated": component_instantiated });
        if let Some(live_runtime) = live_runtime {
            observed["live_runtime"] = live_runtime;
        }
        let result = if kind == "dump" {
            let mut result = observed;
            result["kind"] = json!(kind);
            result
        } else {
            json!({ "kind": kind, "view": observed })
        };
        json!({
            "outcome": {
                "status": "success",
                "result": result
            }
        })
    }

    #[test]
    fn live_runtime_requires_explicit_null_or_an_exact_metadata_object() {
        for kind in ["state", "safe_point", "snapshot", "timer", "effect_probe", "dump"] {
            assert_eq!(
                observed_component_instantiated(&live_result(kind, false, Some(json!(null)))),
                Ok(Some(false)),
                "{kind} must accept explicit null for a non-instantiated component"
            );
            assert_eq!(
                observed_component_instantiated(&live_result(kind, true, Some(exact_runtime()))),
                Ok(Some(true)),
                "{kind} must accept exact metadata for an instantiated component"
            );

            for invalid in [Some(json!("runtime")), Some(json!(["runtime"])), None] {
                assert!(
                    observed_component_instantiated(&live_result(kind, false, invalid)).is_err(),
                    "{kind} accepted a non-null, non-object, or missing false live_runtime"
                );
            }
            assert!(
                observed_component_instantiated(&live_result(
                    kind,
                    true,
                    Some(json!({ "implementation": "incomplete" }))
                ))
                .is_err(),
                "{kind} accepted an invalid live runtime object"
            );
        }
    }

    fn initialize(
        worker: &str,
        role: &str,
        initialized_case: &str,
        database_path: &str,
    ) -> Result<String, String> {
        let role_name = match role {
            "source" => "source.jsonl",
            "destination" => "destination.jsonl",
            role => panic!("unsupported test role {role}"),
        };
        validate_initialize_request(
            &json!({
                "version": crate::STAGE1_WORKER_PROTOCOL_VERSION,
                "id": "initialize-1",
                "command": {
                    "kind": "initialize",
                    "role": role,
                    "runtime": "wasmtime",
                    "database_path": database_path,
                    "options": {
                        "case_id": initialized_case,
                        "namespace_availability": "correct",
                        "authority_policy": "sufficient"
                    },
                    "fault": null
                }
            }),
            role_name,
            Stage2Runtime::Wasmtime,
            TOP_CASE,
            Some((Path::new(CELL_ROOT), worker)),
        )
    }

    #[test]
    fn provider_path_accepts_top_case_and_real_supplemental_worker_bindings() {
        let top_database = format!("{CELL_ROOT}/.runner-work/{TOP_CASE}.sqlite3");
        assert_eq!(
            initialize("evidence-verification-source-audit", "source", TOP_CASE, &top_database,),
            Ok(TOP_CASE.to_owned())
        );
        assert_eq!(
            initialize(
                "evidence-verification-destination-audit",
                "destination",
                TOP_CASE,
                &top_database,
            ),
            Ok(TOP_CASE.to_owned())
        );

        let supplemental_case = "evidence-verification-fault-before-journal-write";
        let supplemental_database = format!("{CELL_ROOT}/.runner-work/{supplemental_case}.sqlite3");
        assert_eq!(
            initialize(
                "evidence-verification-fault-before-journal-write-supplemental-source-retry",
                "source",
                supplemental_case,
                &supplemental_database,
            ),
            Ok(supplemental_case.to_owned())
        );
    }

    #[test]
    fn provider_path_rejects_shared_other_cell_and_wrong_filename_bindings() {
        let worker = "evidence-verification-source";
        for database_path in [
            "/tmp/shared.sqlite3",
            "/stage2/cells/jco-node-to-jco-node/.runner-work/evidence-verification.sqlite3",
            "/stage2/cells/wasmtime-to-wasmtime/.runner-work/another-case.sqlite3",
        ] {
            let error = initialize(worker, "source", TOP_CASE, database_path)
                .expect_err("non-cell-local provider path must be rejected");
            assert!(error.contains("exact cell-local case database"), "{error}");
        }
    }

    #[test]
    fn provider_path_rejects_invalid_subcase_and_worker_role_bindings() {
        let outside_case = "another-case";
        let outside_database = format!("{CELL_ROOT}/.runner-work/{outside_case}.sqlite3");
        assert!(
            initialize(
                "another-case-supplemental-source",
                "source",
                outside_case,
                &outside_database,
            )
            .expect_err("foreign supplemental case must be rejected")
            .contains("outside the top-level case")
        );

        let invalid_case = "evidence-verification-fault//escape";
        let invalid_database = format!("{CELL_ROOT}/.runner-work/{invalid_case}.sqlite3");
        assert!(
            initialize(
                "evidence-verification-fault//escape-supplemental-source",
                "source",
                invalid_case,
                &invalid_database,
            )
            .expect_err("non-canonical supplemental case must be rejected")
            .contains("invalid suffix")
        );

        let top_database = format!("{CELL_ROOT}/.runner-work/{TOP_CASE}.sqlite3");
        assert!(
            initialize("evidence-verification-destination", "source", TOP_CASE, &top_database,)
                .expect_err("worker label must agree with the source role")
                .contains("does not match its case and role")
        );
    }
}
