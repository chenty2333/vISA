use std::{
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::{Path, PathBuf},
};

use contract_core::{
    ActivationRole, ActivationStatus, CleanupStatus, EffectKind, EffectOutcome, EffectResult,
    EntityRef, FailureClass, HandoffPhase, Identity, OperationRecord,
};
use sha2::{Digest as _, Sha256};
use visa_profile::{
    ContinuityDisposition, FileDurability, FileLockState, REGULAR_FILE_EXTENSION_ID,
    RegularFileOperation, RegularFileResult, RegularFileState,
};
use visa_regular_file_observation::{
    ActivationObservation, ArtifactReferenceObservation, CarrierAction, CarrierCallResult,
    CarrierIdentity, CarrierPayloadObservation, CleanupObservation,
    ContinuityDispositionObservation, CoordinatorPhaseObservation, CoordinatorStateObservation,
    DestinationBindingObservation, DestinationBindingState, EndpointObservation, ErrorCode,
    ErrorDomain, FileDurabilityObservation, FileEntryObservation, FileLockStateObservation,
    FileMetadataObservation, ObservationActor, ObservationPhase, ObservedEvent,
    OperationCallResult, OperationOutcomeObservation, OperationRecordObservation, OutputChannel,
    ProfileStateObservation, ProtocolAction, RawErrorObservation, RawObservationEvent,
    RecordingCoverage, RegularFileCase, RegularFileCaseObservation, RegularFileObservationBundle,
    RegularFileOperationObservation, RegularFileOutputObservation, ResourceSubject,
    RouteObservation, validate_recording_bundle,
};
use visa_runtime::canonical_digest;

use crate::{
    CarrierProbeCase, CarrierRoute, RecordInput, WANCO_REVISION,
    canonical::{
        CanonicalOperationReceipt, CanonicalServiceReceipt, CanonicalStateProbe, CanonicalWorkload,
        EndpointRole, LifecycleReceipt, NativeObjectReceipt,
    },
};

const RECEIPT_SCHEMA: &str = "visa-wanco-canonical-service-receipt-v1";
const CAPTURE_ID: &str = "wanco-checkpoint-1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenObservation {
    raw_event: String,
    kind: String,
    device: u64,
    inode: u64,
    offset: u64,
    size: u64,
    mode: u32,
    link_count: u64,
    content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EndpointOperation {
    Read {
        progress: i32,
        workload_key: String,
        attempt: u32,
        before: u64,
        after: u64,
        max_bytes: u32,
        size: u64,
        bytes: Vec<u8>,
        content: Vec<u8>,
    },
    Write {
        progress: i32,
        workload_key: String,
        attempt: u32,
        before: u64,
        after: u64,
        size: u64,
        bytes: Vec<u8>,
        content: Vec<u8>,
    },
    Append {
        progress: i32,
        workload_key: String,
        attempt: u32,
        before: u64,
        after: u64,
        size: u64,
        bytes: Vec<u8>,
        content: Vec<u8>,
        replayed: bool,
    },
    Error {
        progress: i32,
        workload_key: String,
        attempt: u32,
        operation: RegularFileOperationObservation,
        stage: String,
        errno: i32,
        retryable: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedEndpointOperation {
    raw_event: String,
    operation: EndpointOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedEndpointLog {
    initial_open: Option<OpenObservation>,
    opens: Vec<OpenObservation>,
    operations: Vec<ParsedEndpointOperation>,
    returned_progress: Vec<(i32, i32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessStatusObservation {
    code: Option<i32>,
    signal: Option<i32>,
}

pub fn record_observation(input: &RecordInput<'_>) -> Result<RegularFileObservationBundle, String> {
    validate_input_shape(input)?;
    let source_raw = read_required(input.source_events, "source endpoint events")?;
    let destination_raw = read_optional(input.destination_events, "destination endpoint events")?;
    let source_stdout = read_required(input.source_stdout, "source stdout")?;
    let destination_stdout = read_optional(input.destination_stdout, "destination stdout")?;
    let source_status = parse_process_status(input.source_status)?;
    let destination_status = input.destination_status.map(parse_process_status).transpose()?;
    let source_receipt_raw = read_required(input.source_receipt, "source canonical receipt")?;
    let source_receipt: CanonicalServiceReceipt = decode_json(&source_receipt_raw, "source")?;
    let destination_receipt_raw =
        read_optional(input.destination_receipt, "destination canonical receipt")?;
    let destination_receipt = destination_receipt_raw
        .as_deref()
        .map(|bytes| decode_json::<CanonicalServiceReceipt>(bytes, "destination"))
        .transpose()?;
    validate_receipt(input, &source_receipt, EndpointRole::Source)?;
    if let Some(receipt) = &destination_receipt {
        validate_receipt(input, receipt, EndpointRole::Destination)?;
    }
    validate_receipt_resource_consistency(&source_receipt)?;
    if let Some(receipt) = &destination_receipt {
        validate_receipt_resource_consistency(receipt)?;
        validate_cross_receipt_provenance(&source_receipt, receipt)?;
    }

    let source_log = parse_endpoint_events(&source_raw)?;
    let destination_log = destination_raw
        .as_deref()
        .map(parse_endpoint_events)
        .transpose()?
        .unwrap_or_else(ParsedEndpointLog::empty);
    validate_endpoint_logs(input, &source_log, &destination_log)?;
    let initial = source_log
        .initial_open
        .as_ref()
        .ok_or_else(|| "source endpoint did not record its canonical initial open".to_owned())?;
    validate_native_open(initial, &source_receipt.native_object, "source")?;
    validate_open_receipts(&source_log, &source_receipt, "source")?;
    if let Some(receipt) = &destination_receipt {
        validate_open_receipts(&destination_log, receipt, "destination")?;
    }

    let initial_state = source_receipt
        .lifecycle
        .first()
        .map(|entry| &entry.state)
        .ok_or_else(|| "source canonical receipt has no lifecycle state".to_owned())?;
    validate_initial_state(initial, &initial_state.profile_state)?;
    let logical_path = initial_state.profile_state.claim.relative_path.clone();
    let resource_id = entity_hex(initial_state.profile_state.claim.resource);
    let final_bytes = read_required(input.subject_file, "final subject")?;
    let final_metadata = fs::metadata(input.subject_file)
        .map_err(|error| format!("failed to stat final subject: {error}"))?;

    let route = route_observation(input.route)?;
    let mut events = Vec::new();
    push_event(
        &mut events,
        ObservationPhase::Setup,
        ObservationActor::ExternalObserver,
        RawObservationEvent::FileProbe {
            path: logical_path.clone(),
            entry: file_entry_from_open(initial),
        },
    );
    append_state_events(
        &mut events,
        ObservationPhase::Setup,
        ObservationActor::Provider,
        initial_state,
    );
    append_endpoint_operations(
        &mut events,
        ObservationPhase::SourceExecution,
        ObservationActor::SourceRuntime,
        &source_log.operations,
        Some(&source_receipt),
        input.route,
    )?;

    let checkpoint_payload = input
        .checkpoint
        .map(|checkpoint| artifact_payload(input.artifact_root, checkpoint))
        .transpose()?;
    match input.route {
        CarrierRoute::Uninterrupted => {
            validate_protocol_shape(input.route, &source_receipt, None)?;
            append_output_and_exit(
                &mut events,
                ObservationPhase::SourceExecution,
                ObservationActor::SourceRuntime,
                &source_stdout,
                source_status,
            );
        }
        CarrierRoute::CarrierOnly => {
            validate_protocol_shape(input.route, &source_receipt, None)?;
            let payload = checkpoint_payload
                .as_ref()
                .ok_or_else(|| "carrier-only route has no checkpoint payload".to_owned())?;
            append_capture(&mut events, payload.clone());
            append_process_exit(
                &mut events,
                ObservationPhase::CarrierCapture,
                ObservationActor::SourceRuntime,
                source_status,
            );
            append_restore(&mut events, payload.clone());
            append_carrier_resume(&mut events);
            append_endpoint_operations(
                &mut events,
                ObservationPhase::DestinationExecution,
                ObservationActor::DestinationRuntime,
                &destination_log.operations,
                None,
                input.route,
            )?;
            append_destination_output_and_exit(
                &mut events,
                &source_stdout,
                destination_stdout.as_deref().unwrap_or_default(),
                destination_status.expect("input shape validated"),
            );
        }
        CarrierRoute::VisaPlusCarrier => {
            let destination_receipt = destination_receipt
                .as_ref()
                .ok_or_else(|| "visa-plus-carrier route has no destination receipt".to_owned())?;
            validate_protocol_shape(input.route, &source_receipt, Some(destination_receipt))?;
            append_protocols(&mut events, &source_receipt.lifecycle, |action| {
                !matches!(action, ProtocolAction::ExportSnapshot { .. })
            })?;
            let payload = checkpoint_payload
                .as_ref()
                .ok_or_else(|| "visa-plus-carrier route has no checkpoint payload".to_owned())?;
            append_capture(&mut events, payload.clone());
            append_process_exit(
                &mut events,
                ObservationPhase::CarrierCapture,
                ObservationActor::SourceRuntime,
                source_status,
            );
            append_protocols(&mut events, &source_receipt.lifecycle, |action| {
                matches!(action, ProtocolAction::ExportSnapshot { .. })
            })?;
            append_protocols(&mut events, &destination_receipt.lifecycle, |action| {
                matches!(
                    action,
                    ProtocolAction::PrepareDestination { .. }
                        | ProtocolAction::CommitHandoff { .. }
                )
            })?;
            append_restore(&mut events, payload.clone());
            append_protocols(&mut events, &destination_receipt.lifecycle, |action| {
                matches!(
                    action,
                    ProtocolAction::RestoreRuntime { .. }
                        | ProtocolAction::ResumeDestination { .. }
                )
            })?;
            append_carrier_resume(&mut events);
            append_endpoint_operations(
                &mut events,
                ObservationPhase::DestinationExecution,
                ObservationActor::DestinationRuntime,
                &destination_log.operations,
                Some(destination_receipt),
                input.route,
            )?;
            append_destination_output_and_exit(
                &mut events,
                &source_stdout,
                destination_stdout.as_deref().unwrap_or_default(),
                destination_status.expect("input shape validated"),
            );
        }
    }

    let final_state = if let Some(destination) = &destination_receipt {
        terminal_state(destination)?
    } else {
        terminal_state(&source_receipt)?
    };
    validate_final_state(&final_bytes, &final_state.profile_state)?;
    append_state_events(
        &mut events,
        ObservationPhase::FinalObservation,
        ObservationActor::Provider,
        final_state,
    );
    push_event(
        &mut events,
        ObservationPhase::FinalObservation,
        ObservationActor::ExternalObserver,
        RawObservationEvent::FileProbe {
            path: logical_path.clone(),
            entry: FileEntryObservation::File {
                bytes: final_bytes.clone(),
                size: final_metadata.len(),
                sha256: sha256_hex(&final_bytes),
                metadata: FileMetadataObservation {
                    device: final_metadata.dev(),
                    inode: final_metadata.ino(),
                    generation: None,
                    birth_time_unix_ns: None,
                    mode: final_metadata.mode(),
                    link_count: final_metadata.nlink(),
                },
            },
        },
    );

    let identity = observation_identity(&[
        input.route.name().as_bytes(),
        &source_raw,
        destination_raw.as_deref().unwrap_or_default(),
        &source_stdout,
        destination_stdout.as_deref().unwrap_or_default(),
        &source_receipt_raw,
        destination_receipt_raw.as_deref().unwrap_or_default(),
        &final_bytes,
    ]);
    let case = RegularFileCaseObservation::new(
        format!("wanco-{}-{}", input.case.name(), &identity[..24]),
        input.case.wire(),
        format!("wanco-{}-progress-v2", input.case.name()),
        sha256_hex(input.case.workload()),
        ResourceSubject { resource_id, initial_path: logical_path },
        events,
    );
    let bundle = RegularFileObservationBundle::new(
        format!("wanco-carrier-{}-{}", input.route.name(), &identity[..24]),
        route,
        vec![case],
    );
    validate_recording_bundle(&bundle, RecordingCoverage::AnySubset).map_err(|findings| {
        findings
            .into_iter()
            .map(|finding| format!("{}: {}", finding.code, finding.detail))
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    let mut json = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("failed to serialize observation bundle: {error}"))?;
    json.push(b'\n');
    write_atomic(input.output, &json)?;
    Ok(bundle)
}

pub fn merge_carrier_probe(
    read_write_bundle: &Path,
    append_bundle: &Path,
    output: &Path,
) -> Result<RegularFileObservationBundle, String> {
    let read_bytes = read_required(read_write_bundle, "read-write bundle")?;
    let append_bytes = read_required(append_bundle, "append bundle")?;
    let read: RegularFileObservationBundle = decode_json(&read_bytes, "read-write bundle")?;
    let append: RegularFileObservationBundle = decode_json(&append_bytes, "append bundle")?;
    if read.route != append.route {
        return Err("carrier probe case bundles identify different routes".to_owned());
    }
    if read.cases.len() != 1 || read.cases[0].case_id != RegularFileCase::ReadWriteOffset {
        return Err("read-write input is not exactly the read-write-offset case".to_owned());
    }
    if append.cases.len() != 1 || append.cases[0].case_id != RegularFileCase::AppendContinuity {
        return Err("append input is not exactly the append-continuity case".to_owned());
    }
    let identity = sha256_hex(&[read_bytes, append_bytes].concat());
    let bundle = RegularFileObservationBundle::new(
        format!("wanco-carrier-probe-{}", &identity[..32]),
        read.route,
        vec![read.cases[0].clone(), append.cases[0].clone()],
    );
    validate_recording_bundle(&bundle, RecordingCoverage::AnySubset).map_err(|findings| {
        findings
            .into_iter()
            .map(|finding| format!("{}: {}", finding.code, finding.detail))
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    let mut json = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("failed to serialize carrier probe: {error}"))?;
    json.push(b'\n');
    write_atomic(output, &json)?;
    Ok(bundle)
}

fn validate_input_shape(input: &RecordInput<'_>) -> Result<(), String> {
    if input.route.needs_checkpoint() != input.checkpoint.is_some() {
        return Err("checkpoint presence does not match canonical route".to_owned());
    }
    if input.route.has_destination()
        != (input.destination_events.is_some()
            && input.destination_stdout.is_some()
            && input.destination_status.is_some())
    {
        return Err(
            "destination process evidence presence does not match canonical route".to_owned()
        );
    }
    if input.route.needs_destination_receipt() != input.destination_receipt.is_some() {
        return Err(
            "destination canonical receipt presence does not match canonical route".to_owned()
        );
    }
    Ok(())
}

fn validate_receipt(
    input: &RecordInput<'_>,
    receipt: &CanonicalServiceReceipt,
    role: EndpointRole,
) -> Result<(), String> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.route != input.route.name()
        || receipt.workload != canonical_workload(input.case)
        || receipt.role != role
        || receipt.cell_id.is_empty()
        || receipt.lifecycle.is_empty()
    {
        return Err(format!("{role:?} canonical receipt identity or shape mismatch"));
    }
    Ok(())
}

fn validate_receipt_resource_consistency(receipt: &CanonicalServiceReceipt) -> Result<(), String> {
    let expected = receipt
        .lifecycle
        .first()
        .map(|entry| &entry.state.profile_state.claim)
        .ok_or_else(|| "canonical receipt has no initial profile claim".to_owned())?;
    let lifecycle_consistent =
        receipt.lifecycle.iter().all(|entry| entry.state.profile_state.claim == *expected);
    let operations_consistent = receipt.operations.iter().all(|operation| {
        operation.before.profile_state.claim == *expected
            && operation.after.profile_state.claim == *expected
    });
    if !lifecycle_consistent || !operations_consistent {
        return Err(format!(
            "{:?} canonical receipt changes its logical regular-file claim",
            receipt.role
        ));
    }
    Ok(())
}

fn validate_cross_receipt_provenance(
    source: &CanonicalServiceReceipt,
    destination: &CanonicalServiceReceipt,
) -> Result<(), String> {
    let source_terminal = terminal_state(source)?;
    let destination_initial = destination
        .lifecycle
        .first()
        .map(|entry| &entry.state)
        .ok_or_else(|| "destination receipt has no restored state".to_owned())?;
    let destination_terminal = terminal_state(destination)?;
    let source_native = &source.native_object;
    let destination_native = &destination.native_object;
    if source.cell_id != destination.cell_id {
        return Err("source/destination canonical cell_id mismatch".to_owned());
    }
    if source.component_digest != destination.component_digest {
        return Err("source/destination canonical component_digest mismatch".to_owned());
    }
    if source.profile_digest != destination.profile_digest {
        return Err("source/destination canonical profile_digest mismatch".to_owned());
    }
    if source.workload != destination.workload {
        return Err("source/destination canonical workload mismatch".to_owned());
    }
    let source_resource = source_terminal.profile_state.claim.resource;
    if source_resource != destination_initial.profile_state.claim.resource
        || source_resource != destination_terminal.profile_state.claim.resource
    {
        return Err("source/destination canonical resource identity mismatch".to_owned());
    }
    if source_terminal.profile_state != destination_initial.profile_state {
        return Err(
            "destination restored profile state does not match source terminal state".to_owned()
        );
    }
    if source_terminal.profile_state.claim != destination_terminal.profile_state.claim {
        return Err("destination terminal claim diverges from source claim".to_owned());
    }
    if source_native.node == destination_native.node {
        return Err("source/destination native node identity is not distinct".to_owned());
    }
    if source_native.root_path == destination_native.root_path
        || (source_native.root_device, source_native.root_inode)
            == (destination_native.root_device, destination_native.root_inode)
    {
        return Err("source/destination native root identity is not distinct".to_owned());
    }
    if (source_native.file_device, source_native.file_inode)
        == (destination_native.file_device, destination_native.file_inode)
    {
        return Err("source/destination native file identity is not distinct".to_owned());
    }
    Ok(())
}

fn canonical_workload(case: CarrierProbeCase) -> CanonicalWorkload {
    match case {
        CarrierProbeCase::ReadWriteOffset => CanonicalWorkload::ReadWriteOffset,
        CarrierProbeCase::AppendContinuity => CanonicalWorkload::AppendContinuity,
    }
}

fn validate_endpoint_logs(
    input: &RecordInput<'_>,
    source: &ParsedEndpointLog,
    destination: &ParsedEndpointLog,
) -> Result<(), String> {
    if source.operations.is_empty() {
        return Err("source endpoint produced no resource operations".to_owned());
    }
    if input.route.has_destination() && destination.returned_progress.is_empty() {
        return Err("handoff route produced no destination calls".to_owned());
    }
    if !input.route.has_destination() && !destination.returned_progress.is_empty() {
        return Err("uninterrupted route unexpectedly has destination calls".to_owned());
    }
    Ok(())
}

fn validate_native_open(
    open: &OpenObservation,
    native: &NativeObjectReceipt,
    role: &str,
) -> Result<(), String> {
    if open.kind != "initial"
        || open.device != native.file_device
        || open.inode != native.file_inode
        || open.size != native.file_size
        || open.mode != native.file_mode
        || open.link_count != native.file_link_count
        || sha256_hex(&open.content) != native.file_sha256
    {
        return Err(format!("{role} OPEN event does not match canonical native-object receipt"));
    }
    Ok(())
}

fn validate_open_receipts(
    log: &ParsedEndpointLog,
    receipt: &CanonicalServiceReceipt,
    role: &str,
) -> Result<(), String> {
    let recorded = receipt
        .operations
        .iter()
        .filter(|operation| operation.operation_kind == "open")
        .collect::<Vec<_>>();
    if recorded.len() != log.opens.len()
        || recorded.iter().zip(&log.opens).any(|(operation, open)| {
            operation.raw_event != open.raw_event
                || operation.operation.is_some()
                || operation.result.is_some()
                || operation.error.is_some()
        })
    {
        return Err(format!("{role} OPEN events do not exactly match canonical open receipts"));
    }
    Ok(())
}

fn validate_initial_state(open: &OpenObservation, state: &RegularFileState) -> Result<(), String> {
    if open.offset != state.logical_offset
        || open.size != state.size
        || canonical_digest(&open.content)
            .map_err(|error| format!("cannot digest initial file content: {error:?}"))?
            != state.content_digest
    {
        return Err("initial OPEN event does not match canonical profile state".to_owned());
    }
    Ok(())
}

fn validate_final_state(bytes: &[u8], state: &RegularFileState) -> Result<(), String> {
    let size = u64::try_from(bytes.len()).map_err(|_| "final file size does not fit u64")?;
    if state.size != size
        || canonical_digest(&bytes.to_vec())
            .map_err(|error| format!("cannot digest final file content: {error:?}"))?
            != state.content_digest
    {
        return Err("final file does not match the terminal canonical profile state".to_owned());
    }
    Ok(())
}

fn terminal_state(receipt: &CanonicalServiceReceipt) -> Result<&CanonicalStateProbe, String> {
    receipt
        .operations
        .last()
        .map(|operation| &operation.after)
        .or_else(|| receipt.lifecycle.last().map(|entry| &entry.state))
        .ok_or_else(|| "canonical receipt has no terminal state".to_owned())
}

fn append_endpoint_operations(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    parsed: &[ParsedEndpointOperation],
    receipt: Option<&CanonicalServiceReceipt>,
    route: CarrierRoute,
) -> Result<(), String> {
    let mut used = receipt.map_or_else(Vec::new, |value| {
        value.operations.iter().map(|operation| operation.operation_kind == "open").collect()
    });
    for observed in parsed {
        let matching = receipt.and_then(|receipt| {
            receipt.operations.iter().enumerate().find(|(index, operation)| {
                !used[*index] && operation.raw_event == observed.raw_event
            })
        });
        if let Some((index, canonical)) = matching {
            used[index] = true;
            append_receipt_operation(events, phase, actor, observed, canonical)?;
        } else {
            append_unbacked_error(events, phase, actor, observed, route, receipt)?;
        }
    }
    if let Some(receipt) = receipt
        && used.iter().any(|used| !used)
    {
        let missing = receipt
            .operations
            .iter()
            .zip(used)
            .filter(|(_, used)| !*used)
            .map(|(operation, _)| operation.raw_event.as_str())
            .collect::<Vec<_>>();
        return Err(format!(
            "canonical receipt operations are absent from the Wanco endpoint log: {missing:?}"
        ));
    }
    Ok(())
}

fn append_receipt_operation(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    observed: &ParsedEndpointOperation,
    receipt: &CanonicalOperationReceipt,
) -> Result<(), String> {
    let operation = receipt
        .operation
        .as_ref()
        .ok_or_else(|| "canonical operation receipt lacks the executed request".to_owned())?;
    validate_operation_identity(observed, receipt, operation)?;
    let result = match (&receipt.result, &receipt.error) {
        (Some(result), None) => {
            validate_successful_result(observed, receipt, operation, result)?;
            OperationCallResult::Returned { output: output_observation(result) }
        }
        (None, Some(_)) => match &observed.operation {
            EndpointOperation::Error { stage, errno, retryable, .. } => {
                OperationCallResult::Error { error: endpoint_error(stage, *errno, *retryable) }
            }
            _ => {
                return Err(
                    "canonical receipt reports failure for a successful raw event".to_owned()
                );
            }
        },
        _ => return Err("canonical operation receipt has ambiguous result/error fields".to_owned()),
    };
    push_event(
        events,
        phase,
        actor,
        RawObservationEvent::OperationCall {
            operation_id: receipt.workload_key.clone(),
            attempt: receipt.attempt,
            idempotency_key: mutation_idempotency_key(operation, &receipt.workload_key),
            operation: operation_observation(operation),
            result,
        },
    );
    append_state_events(events, phase, ObservationActor::Provider, &receipt.after);
    Ok(())
}

fn validate_operation_identity(
    observed: &ParsedEndpointOperation,
    receipt: &CanonicalOperationReceipt,
    operation: &RegularFileOperation,
) -> Result<(), String> {
    let (progress, key, attempt, observed_operation) =
        parsed_operation_identity(&observed.operation);
    if receipt.progress != progress
        || receipt.workload_key != key
        || receipt.attempt != attempt
        || receipt.operation_kind != operation_kind(operation)
        || operation_observation(operation) != observed_operation
    {
        return Err(format!(
            "canonical operation receipt does not match endpoint event {:?}",
            observed.raw_event
        ));
    }
    Ok(())
}

fn validate_successful_result(
    observed: &ParsedEndpointOperation,
    receipt: &CanonicalOperationReceipt,
    operation: &RegularFileOperation,
    result: &RegularFileResult,
) -> Result<(), String> {
    if receipt.canonical_operation.is_none() {
        return Err("successful canonical call lacks its canonical operation identity".to_owned());
    }
    let before = &receipt.before.profile_state;
    let after = &receipt.after.profile_state;
    let content_check = |content: &[u8], size: u64| -> Result<(), String> {
        let digest = canonical_digest(&content.to_vec())
            .map_err(|error| format!("cannot digest endpoint content: {error:?}"))?;
        if size != after.size || digest != after.content_digest {
            return Err("endpoint content does not match canonical after-state".to_owned());
        }
        Ok(())
    };
    match (&observed.operation, operation, result) {
        (
            EndpointOperation::Read {
                before: raw_before,
                after: raw_after,
                max_bytes,
                size,
                bytes,
                content,
                ..
            },
            RegularFileOperation::Read { max_bytes: actual_max },
            RegularFileResult::Read {
                bytes: actual_bytes,
                logical_offset,
                version,
                size: actual_size,
                content_digest,
            },
        ) if raw_before == &before.logical_offset
            && raw_after == logical_offset
            && max_bytes == actual_max
            && bytes == actual_bytes
            && size == actual_size
            && logical_offset == &after.logical_offset
            && version == &after.version
            && content_digest == &after.content_digest =>
        {
            content_check(content, *size)
        }
        (
            EndpointOperation::Write {
                before: raw_before,
                after: raw_after,
                size,
                bytes,
                content,
                ..
            },
            RegularFileOperation::Write { bytes: actual_bytes, .. },
            RegularFileResult::Mutated {
                logical_offset,
                version,
                size: actual_size,
                content_digest,
                durable_through,
            },
        ) if raw_before == &before.logical_offset
            && raw_after == logical_offset
            && bytes == actual_bytes
            && size == actual_size
            && logical_offset == &after.logical_offset
            && version == &after.version
            && content_digest == &after.content_digest
            && durable_through == &after.durable_through =>
        {
            content_check(content, *size)
        }
        (
            EndpointOperation::Append {
                before: raw_before,
                after: raw_after,
                size,
                bytes,
                content,
                replayed,
                ..
            },
            RegularFileOperation::Append { bytes: actual_bytes, .. },
            RegularFileResult::Mutated {
                logical_offset,
                version,
                size: actual_size,
                content_digest,
                durable_through,
            },
        ) if raw_before == &before.logical_offset
            && raw_after == logical_offset
            && bytes == actual_bytes
            && size == actual_size
            && replayed == &receipt.replayed
            && logical_offset == &after.logical_offset
            && version == &after.version
            && content_digest == &after.content_digest
            && durable_through == &after.durable_through =>
        {
            content_check(content, *size)
        }
        _ => Err("raw endpoint result diverges from canonical request/result/state".to_owned()),
    }
}

fn append_unbacked_error(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    observed: &ParsedEndpointOperation,
    route: CarrierRoute,
    receipt: Option<&CanonicalServiceReceipt>,
) -> Result<(), String> {
    let EndpointOperation::Error {
        workload_key, attempt, operation, stage, errno, retryable, ..
    } = &observed.operation
    else {
        return Err(format!(
            "successful endpoint event has no matching canonical receipt: {:?}",
            observed.raw_event
        ));
    };
    let allowed_transient = receipt.is_some()
        && stage == "transient-invalid-fd"
        && *retryable
        && receipt.is_some_and(|receipt| {
            receipt.operations.iter().any(|operation| {
                operation.workload_key == *workload_key && operation.attempt == attempt + 1
            })
        });
    let allowed_carrier_loss = receipt.is_none()
        && route == CarrierRoute::CarrierOnly
        && stage == "lost-process-local-binding"
        && !*retryable;
    if !allowed_transient && !allowed_carrier_loss {
        return Err(format!(
            "unbacked endpoint error is not an allowed observed boundary: {:?}",
            observed.raw_event
        ));
    }
    push_event(
        events,
        phase,
        actor,
        RawObservationEvent::OperationCall {
            operation_id: workload_key.clone(),
            attempt: *attempt,
            idempotency_key: match operation {
                RegularFileOperationObservation::Write { .. }
                | RegularFileOperationObservation::Append { .. }
                | RegularFileOperationObservation::Truncate { .. } => Some(workload_key.clone()),
                _ => None,
            },
            operation: operation.clone(),
            result: OperationCallResult::Error { error: endpoint_error(stage, *errno, *retryable) },
        },
    );
    Ok(())
}

fn parsed_operation_identity(
    operation: &EndpointOperation,
) -> (i32, &str, u32, RegularFileOperationObservation) {
    match operation {
        EndpointOperation::Read { progress, workload_key, attempt, max_bytes, .. } => (
            *progress,
            workload_key,
            *attempt,
            RegularFileOperationObservation::Read { max_bytes: *max_bytes },
        ),
        EndpointOperation::Write { progress, workload_key, attempt, bytes, .. } => (
            *progress,
            workload_key,
            *attempt,
            RegularFileOperationObservation::Write {
                bytes: bytes.clone(),
                durability: FileDurabilityObservation::Visible,
            },
        ),
        EndpointOperation::Append { progress, workload_key, attempt, bytes, .. } => (
            *progress,
            workload_key,
            *attempt,
            RegularFileOperationObservation::Append {
                bytes: bytes.clone(),
                durability: FileDurabilityObservation::Visible,
            },
        ),
        EndpointOperation::Error { progress, workload_key, attempt, operation, .. } => {
            (*progress, workload_key, *attempt, operation.clone())
        }
    }
}

fn operation_kind(operation: &RegularFileOperation) -> &'static str {
    match operation {
        RegularFileOperation::Read { .. } => "read",
        RegularFileOperation::Write { .. } => "write",
        RegularFileOperation::Append { .. } => "append",
        RegularFileOperation::Truncate { .. } => "truncate",
        RegularFileOperation::Rename { .. } => "rename",
        RegularFileOperation::Sync { .. } => "sync",
        RegularFileOperation::AcquireLock => "acquire_lock",
        RegularFileOperation::ReleaseLock => "release_lock",
    }
}

fn mutation_idempotency_key(
    operation: &RegularFileOperation,
    workload_key: &str,
) -> Option<String> {
    (!matches!(operation, RegularFileOperation::Read { .. })).then(|| workload_key.to_owned())
}

fn append_protocols(
    events: &mut Vec<ObservedEvent>,
    lifecycle: &[LifecycleReceipt],
    include: impl Fn(&ProtocolAction) -> bool,
) -> Result<(), String> {
    for entry in lifecycle {
        let Some(action) = &entry.protocol_action else {
            continue;
        };
        if !include(action) {
            continue;
        }
        let result = entry.result.clone().ok_or_else(|| {
            format!("canonical lifecycle {} lacks its actual result", entry.action)
        })?;
        let phase = protocol_phase(action);
        push_event(
            events,
            phase,
            ObservationActor::Controller,
            RawObservationEvent::ProtocolCall { action: action.clone(), result },
        );
        append_state_events(events, phase, ObservationActor::Provider, &entry.state);
    }
    Ok(())
}

fn validate_protocol_shape(
    route: CarrierRoute,
    source: &CanonicalServiceReceipt,
    destination: Option<&CanonicalServiceReceipt>,
) -> Result<(), String> {
    let source_kinds = protocol_kinds(&source.lifecycle)?;
    let destination_kinds = destination
        .map(|receipt| protocol_kinds(&receipt.lifecycle))
        .transpose()?
        .unwrap_or_default();
    match route {
        CarrierRoute::Uninterrupted | CarrierRoute::CarrierOnly
            if source_kinds.is_empty() && destination_kinds.is_empty() =>
        {
            Ok(())
        }
        CarrierRoute::VisaPlusCarrier
            if source_kinds
                == ["begin", "prepare_safe_point", "freeze", "commit_safe_point", "export"]
                && destination_kinds
                    == ["prepare_destination", "commit_handoff", "restore", "resume"] =>
        {
            Ok(())
        }
        _ => Err(format!(
            "canonical protocol lifecycle mismatch for {}: source={source_kinds:?}, destination={destination_kinds:?}",
            route.name()
        )),
    }
}

fn protocol_kinds(lifecycle: &[LifecycleReceipt]) -> Result<Vec<&'static str>, String> {
    lifecycle
        .iter()
        .filter_map(|entry| entry.protocol_action.as_ref().map(|action| (entry, action)))
        .map(|(entry, action)| {
            if entry.result.is_none() {
                return Err(format!("protocol lifecycle {} has no result", entry.action));
            }
            Ok(match action {
                ProtocolAction::BeginQuiesce { .. } => "begin",
                ProtocolAction::PrepareSafePoint { .. } => "prepare_safe_point",
                ProtocolAction::FreezeRuntime { .. } => "freeze",
                ProtocolAction::CommitSafePoint { .. } => "commit_safe_point",
                ProtocolAction::ExportSnapshot { .. } => "export",
                ProtocolAction::PrepareDestination { .. } => "prepare_destination",
                ProtocolAction::CommitHandoff { .. } => "commit_handoff",
                ProtocolAction::RestoreRuntime { .. } => "restore",
                ProtocolAction::ResumeDestination { .. } => "resume",
                ProtocolAction::CleanupOperation { .. } => "cleanup",
            })
        })
        .collect()
}

fn protocol_phase(action: &ProtocolAction) -> ObservationPhase {
    match action {
        ProtocolAction::BeginQuiesce { .. }
        | ProtocolAction::PrepareSafePoint { .. }
        | ProtocolAction::FreezeRuntime { .. }
        | ProtocolAction::CommitSafePoint { .. } => ObservationPhase::Quiesce,
        ProtocolAction::ExportSnapshot { .. } => ObservationPhase::Transfer,
        ProtocolAction::PrepareDestination { .. } | ProtocolAction::CommitHandoff { .. } => {
            ObservationPhase::DestinationPrepare
        }
        ProtocolAction::RestoreRuntime { .. } => ObservationPhase::CarrierRestore,
        ProtocolAction::ResumeDestination { .. } => ObservationPhase::DestinationExecution,
        ProtocolAction::CleanupOperation { .. } => ObservationPhase::Cleanup,
    }
}

fn append_state_events(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    state: &CanonicalStateProbe,
) {
    let resource = state.profile_state.claim.resource;
    push_event(
        events,
        phase,
        actor,
        RawObservationEvent::ProfileStateProbe {
            state: profile_state_observation(&state.profile_state),
        },
    );
    push_event(
        events,
        phase,
        ObservationActor::Controller,
        RawObservationEvent::CoordinatorStateProbe { state: coordinator_state_observation(state) },
    );
    push_event(
        events,
        phase,
        ObservationActor::Provider,
        RawObservationEvent::LeaseProbe {
            resource_id: entity_hex(resource),
            owner: state.file_lease.map(|lease| identity_hex(lease.owner.0)),
            epoch: state.file_lease.map_or(state.lease_epoch.0, |lease| lease.epoch.0),
        },
    );
    push_event(
        events,
        phase,
        ObservationActor::Provider,
        RawObservationEvent::OperationLedgerProbe {
            records: state
                .operation_ledger
                .iter()
                .filter(|record| {
                    matches!(
                        record.request.kind,
                        EffectKind::Profile { profile, .. }
                            if profile == REGULAR_FILE_EXTENSION_ID
                    )
                })
                .map(operation_record_observation)
                .collect(),
        },
    );
    let binding = state.destination_binding.as_ref().filter(|binding| binding.claim == resource);
    push_event(
        events,
        phase,
        ObservationActor::Provider,
        RawObservationEvent::DestinationBindingProbe {
            bindings: vec![match binding {
                Some(binding) => DestinationBindingObservation {
                    resource_id: entity_hex(resource),
                    state: if state.activation_role == ActivationRole::Destination
                        && state.activation_status == ActivationStatus::Active
                    {
                        DestinationBindingState::Published
                    } else {
                        DestinationBindingState::Prepared
                    },
                    owner: Some(identity_hex(binding.node.0)),
                    epoch: Some(binding.lease_epoch.0),
                },
                None => DestinationBindingObservation {
                    resource_id: entity_hex(resource),
                    state: DestinationBindingState::Absent,
                    owner: None,
                    epoch: None,
                },
            }],
        },
    );
}

fn profile_state_observation(state: &RegularFileState) -> ProfileStateObservation {
    let mut object_binding = state.claim.resource.identity.0.to_vec();
    object_binding.extend_from_slice(&state.claim.resource.generation.0.to_be_bytes());
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

fn coordinator_state_observation(state: &CanonicalStateProbe) -> CoordinatorStateObservation {
    let phase = match state.phase {
        HandoffPhase::Dormant => CoordinatorPhaseObservation::Inactive,
        HandoffPhase::Running => CoordinatorPhaseObservation::Active,
        HandoffPhase::Quiescing => CoordinatorPhaseObservation::Quiescing,
        HandoffPhase::Frozen => CoordinatorPhaseObservation::Frozen,
        HandoffPhase::Exported => CoordinatorPhaseObservation::Exported,
        HandoffPhase::DestinationPrepared => CoordinatorPhaseObservation::PreparedDestination,
        HandoffPhase::Committed
            if state.activation_role == ActivationRole::Destination
                && state.activation_status == ActivationStatus::Active =>
        {
            CoordinatorPhaseObservation::ResumedDestination
        }
        HandoffPhase::Committed => CoordinatorPhaseObservation::Committed,
        HandoffPhase::Aborted => CoordinatorPhaseObservation::Aborted,
    };
    let activation = match (state.activation_role, state.activation_status) {
        (_, ActivationStatus::Inactive) => ActivationObservation::Inactive,
        (ActivationRole::Source, ActivationStatus::Active) => ActivationObservation::Source,
        (ActivationRole::Source, ActivationStatus::Fenced) => ActivationObservation::SourceFenced,
        (ActivationRole::Destination, ActivationStatus::Prepared) => {
            ActivationObservation::DestinationPrepared
        }
        (ActivationRole::Destination, ActivationStatus::Active) => {
            ActivationObservation::DestinationActive
        }
        (_, ActivationStatus::Prepared | ActivationStatus::Fenced) => {
            ActivationObservation::Inactive
        }
    };
    CoordinatorStateObservation {
        phase,
        activation,
        owner: state.owner.map(|owner| identity_hex(owner.0)),
        epoch: state.lease_epoch.0,
    }
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
                error: raw_error(ErrorDomain::Provider, ErrorCode::Other, false, None, None),
            },
            Some(EffectOutcome::Unsupported { .. }) => OperationOutcomeObservation::Rejected {
                error: raw_error(
                    ErrorDomain::RegularFileProfile,
                    ErrorCode::Unsupported,
                    false,
                    None,
                    None,
                ),
            },
        },
        cleanup: match record.cleanup {
            CleanupStatus::Pending => CleanupObservation::Required,
            CleanupStatus::Cleaned => CleanupObservation::Cleaned,
        },
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

fn effect_failure_observation(class: FailureClass, retryable: bool) -> RawErrorObservation {
    let code = match class {
        FailureClass::Denied => ErrorCode::ProviderDenied,
        FailureClass::Conflict => ErrorCode::Conflict,
        FailureClass::Unavailable => ErrorCode::Unavailable,
        FailureClass::Integrity | FailureClass::Internal => ErrorCode::Other,
    };
    raw_error(ErrorDomain::Provider, code, retryable, None, None)
}

fn endpoint_error(stage: &str, errno: i32, retryable: bool) -> RawErrorObservation {
    let domain = if stage.starts_with("canonical-") {
        ErrorDomain::RegularFileProfile
    } else {
        ErrorDomain::OperatingSystem
    };
    let code = match errno {
        9 | 107 => ErrorCode::Unavailable,
        17 => ErrorCode::AlreadyExists,
        2 => ErrorCode::NotFound,
        22 => ErrorCode::Invalid,
        110 => ErrorCode::Unavailable,
        _ => ErrorCode::Io,
    };
    raw_error(domain, code, retryable, Some(errno), Some(stage.to_owned()))
}

fn raw_error(
    domain: ErrorDomain,
    code: ErrorCode,
    retryable: bool,
    errno: Option<i32>,
    detail: Option<String>,
) -> RawErrorObservation {
    RawErrorObservation { domain, code, errno, retryable, detail }
}

fn append_capture(events: &mut Vec<ObservedEvent>, payload: CarrierPayloadObservation) {
    push_event(
        events,
        ObservationPhase::CarrierCapture,
        ObservationActor::Carrier,
        RawObservationEvent::CarrierCall {
            action: CarrierAction::Capture { capture_id: CAPTURE_ID.to_owned() },
            result: CarrierCallResult::Captured { payload },
        },
    );
}

fn append_restore(events: &mut Vec<ObservedEvent>, payload: CarrierPayloadObservation) {
    push_event(
        events,
        ObservationPhase::CarrierRestore,
        ObservationActor::Carrier,
        RawObservationEvent::CarrierCall {
            action: CarrierAction::Restore { capture_id: CAPTURE_ID.to_owned(), payload },
            result: CarrierCallResult::Returned { bytes: Vec::new() },
        },
    );
}

fn append_carrier_resume(events: &mut Vec<ObservedEvent>) {
    push_event(
        events,
        ObservationPhase::CarrierRestore,
        ObservationActor::Carrier,
        RawObservationEvent::CarrierCall {
            action: CarrierAction::Resume,
            result: CarrierCallResult::Returned { bytes: Vec::new() },
        },
    );
}

fn append_output_and_exit(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    stdout: &[u8],
    status: ProcessStatusObservation,
) {
    push_event(
        events,
        phase,
        ObservationActor::ExternalObserver,
        RawObservationEvent::ClientOutput {
            channel: OutputChannel::Stdout,
            bytes: stdout.to_vec(),
        },
    );
    append_process_exit(events, phase, actor, status);
}

fn append_destination_output_and_exit(
    events: &mut Vec<ObservedEvent>,
    source_stdout: &[u8],
    destination_stdout: &[u8],
    status: ProcessStatusObservation,
) {
    let mut output = source_stdout.to_vec();
    output.extend_from_slice(destination_stdout);
    push_event(
        events,
        ObservationPhase::DestinationExecution,
        ObservationActor::ExternalObserver,
        RawObservationEvent::ClientOutput { channel: OutputChannel::Stdout, bytes: output },
    );
    append_process_exit(
        events,
        ObservationPhase::DestinationExecution,
        ObservationActor::DestinationRuntime,
        status,
    );
}

fn append_process_exit(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    status: ProcessStatusObservation,
) {
    push_event(
        events,
        phase,
        actor,
        RawObservationEvent::ProcessExit { code: status.code, signal: status.signal },
    );
}

fn route_observation(route: CarrierRoute) -> Result<RouteObservation, String> {
    Ok(RouteObservation {
        mode: route.wire_mode(),
        source: current_endpoint(route, "source")?,
        destination: route
            .has_destination()
            .then(|| current_endpoint(route, "destination"))
            .transpose()?,
        execution_boundary: if route == CarrierRoute::Uninterrupted {
            "same-process-uninterrupted".to_owned()
        } else {
            "same-host-fresh-process-and-node-local-storage".to_owned()
        },
        carrier: route.needs_checkpoint().then(|| CarrierIdentity {
            implementation: "tamaroning/wanco".to_owned(),
            implementation_version: WANCO_REVISION.to_owned(),
            mode: "signal-triggered-llvm-stackmap-protobuf".to_owned(),
        }),
    })
}

fn current_endpoint(route: CarrierRoute, role: &str) -> Result<EndpointObservation, String> {
    let host = ["/etc/hostname", "/proc/sys/kernel/hostname"]
        .into_iter()
        .find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| "host identity is unavailable from hostname files".to_owned())?;
    Ok(EndpointObservation {
        instance_id: format!("wanco-aot-{}-{role}", route.name()),
        runtime: "tamaroning/wanco-aot".to_owned(),
        runtime_version: WANCO_REVISION.to_owned(),
        host_id: host,
        operating_system: std::env::consts::OS.to_owned(),
        isa: std::env::consts::ARCH.to_owned(),
    })
}

fn file_entry_from_open(open: &OpenObservation) -> FileEntryObservation {
    FileEntryObservation::File {
        bytes: open.content.clone(),
        size: open.size,
        sha256: sha256_hex(&open.content),
        metadata: FileMetadataObservation {
            device: open.device,
            inode: open.inode,
            generation: None,
            birth_time_unix_ns: None,
            mode: open.mode,
            link_count: open.link_count,
        },
    }
}

fn parse_endpoint_events(raw: &[u8]) -> Result<ParsedEndpointLog, String> {
    let text =
        std::str::from_utf8(raw).map_err(|error| format!("endpoint log is not UTF-8: {error}"))?;
    let mut calls = Vec::new();
    let mut returned_progress = Vec::new();
    let mut initial_open = None;
    let mut opens = Vec::new();
    let mut operations = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let fields = line.split('\t').collect::<Vec<_>>();
        let operation = match fields.as_slice() {
            ["CALL", progress, is_start] => {
                let progress = parse_number::<i32>(progress, line_number)?;
                let is_start = parse_number::<i32>(is_start, line_number)?;
                if !matches!(is_start, 0 | 1) {
                    return Err(format!("line {} has invalid start marker", line_number + 1));
                }
                calls.push(progress);
                None
            }
            ["RETURN", progress, result] => {
                returned_progress.push((
                    parse_number(progress, line_number)?,
                    parse_number(result, line_number)?,
                ));
                None
            }
            ["BINDING_ERROR", _progress, _stage, _errno] => None,
            ["OPEN", _progress, kind, device, inode, offset, size, mode, link_count, content] => {
                let open = OpenObservation {
                    raw_event: line.to_owned(),
                    kind: (*kind).to_owned(),
                    device: parse_number(device, line_number)?,
                    inode: parse_number(inode, line_number)?,
                    offset: parse_number(offset, line_number)?,
                    size: parse_number(size, line_number)?,
                    mode: parse_number(mode, line_number)?,
                    link_count: parse_number(link_count, line_number)?,
                    content: decode_hex(content, line_number)?,
                };
                if *kind == "initial" && initial_open.replace(open.clone()).is_some() {
                    return Err("endpoint log has multiple initial OPEN events".to_owned());
                }
                opens.push(open);
                None
            }
            [
                "READ",
                progress,
                key,
                attempt,
                before,
                after,
                max_bytes,
                size,
                _device,
                _inode,
                bytes,
                content,
            ] => Some(EndpointOperation::Read {
                progress: parse_number(progress, line_number)?,
                workload_key: (*key).to_owned(),
                attempt: parse_number(attempt, line_number)?,
                before: parse_number(before, line_number)?,
                after: parse_number(after, line_number)?,
                max_bytes: parse_number(max_bytes, line_number)?,
                size: parse_number(size, line_number)?,
                bytes: decode_hex(bytes, line_number)?,
                content: decode_hex(content, line_number)?,
            }),
            [
                tag @ ("WRITE" | "APPEND" | "APPEND_REPLAY"),
                progress,
                key,
                attempt,
                before,
                after,
                size,
                _device,
                _inode,
                bytes,
                content,
            ] => {
                let common = (
                    parse_number(progress, line_number)?,
                    (*key).to_owned(),
                    parse_number(attempt, line_number)?,
                    parse_number(before, line_number)?,
                    parse_number(after, line_number)?,
                    parse_number(size, line_number)?,
                    decode_hex(bytes, line_number)?,
                    decode_hex(content, line_number)?,
                );
                if *tag == "WRITE" {
                    Some(EndpointOperation::Write {
                        progress: common.0,
                        workload_key: common.1,
                        attempt: common.2,
                        before: common.3,
                        after: common.4,
                        size: common.5,
                        bytes: common.6,
                        content: common.7,
                    })
                } else {
                    Some(EndpointOperation::Append {
                        progress: common.0,
                        workload_key: common.1,
                        attempt: common.2,
                        before: common.3,
                        after: common.4,
                        size: common.5,
                        bytes: common.6,
                        content: common.7,
                        replayed: *tag == "APPEND_REPLAY",
                    })
                }
            }
            [
                "ERROR",
                progress,
                key,
                attempt,
                kind,
                stage,
                errno,
                retryable,
                request_value,
                durability,
            ] => Some(EndpointOperation::Error {
                progress: parse_number(progress, line_number)?,
                workload_key: (*key).to_owned(),
                attempt: parse_number(attempt, line_number)?,
                operation: parse_error_operation(kind, request_value, durability, line_number)?,
                stage: (*stage).to_owned(),
                errno: parse_number(errno, line_number)?,
                retryable: parse_bool_flag(retryable, line_number)?,
            }),
            _ => return Err(format!("line {} has an unknown endpoint event", line_number + 1)),
        };
        if let Some(operation) = operation {
            operations.push(ParsedEndpointOperation { raw_event: line.to_owned(), operation });
        }
    }
    if calls.len() != returned_progress.len() {
        return Err(format!(
            "endpoint log has {} calls but {} returns",
            calls.len(),
            returned_progress.len()
        ));
    }
    if calls.iter().zip(&returned_progress).any(|(call, returned)| *call != returned.0) {
        return Err("endpoint calls and returns are out of order".to_owned());
    }
    Ok(ParsedEndpointLog { initial_open, opens, operations, returned_progress })
}

fn parse_error_operation(
    kind: &str,
    value: &str,
    durability: &str,
    line: usize,
) -> Result<RegularFileOperationObservation, String> {
    match kind {
        "read" if durability == "-" => {
            Ok(RegularFileOperationObservation::Read { max_bytes: parse_number(value, line)? })
        }
        "write" => Ok(RegularFileOperationObservation::Write {
            bytes: decode_hex(value, line)?,
            durability: parse_observed_durability(durability, line)?,
        }),
        "append" => Ok(RegularFileOperationObservation::Append {
            bytes: decode_hex(value, line)?,
            durability: parse_observed_durability(durability, line)?,
        }),
        _ => Err(format!("line {} has an invalid error operation", line + 1)),
    }
}

fn parse_observed_durability(
    value: &str,
    line: usize,
) -> Result<FileDurabilityObservation, String> {
    match value {
        "visible" => Ok(FileDurabilityObservation::Visible),
        "data" => Ok(FileDurabilityObservation::Data),
        "data-and-metadata" => Ok(FileDurabilityObservation::DataAndMetadata),
        _ => Err(format!("line {} has invalid durability", line + 1)),
    }
}

fn parse_bool_flag(value: &str, line: usize) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("line {} has invalid boolean flag", line + 1)),
    }
}

impl ParsedEndpointLog {
    fn empty() -> Self {
        Self {
            initial_open: None,
            opens: Vec::new(),
            operations: Vec::new(),
            returned_progress: Vec::new(),
        }
    }
}

fn parse_number<T: std::str::FromStr>(value: &str, line: usize) -> Result<T, String> {
    value.parse().map_err(|_| format!("line {} contains an invalid number", line + 1))
}

fn parse_process_status(path: &Path) -> Result<ProcessStatusObservation, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read process status {}: {error}", path.display()))?;
    let line = raw.strip_suffix('\n').unwrap_or(&raw);
    if line.contains(['\n', '\r']) {
        return Err(format!("process status {} is not exactly one line", path.display()));
    }
    let (kind, value) = line
        .split_once('\t')
        .ok_or_else(|| format!("process status {} has no tab separator", path.display()))?;
    let value = value
        .parse::<i32>()
        .map_err(|_| format!("process status {} has an invalid value", path.display()))?;
    match kind {
        "code" if (0..=255).contains(&value) => {
            Ok(ProcessStatusObservation { code: Some(value), signal: None })
        }
        "signal" if (1..=64).contains(&value) => {
            Ok(ProcessStatusObservation { code: None, signal: Some(value) })
        }
        _ => Err(format!("process status {} has an invalid kind or range", path.display())),
    }
}

fn artifact_payload(root: &Path, path: &Path) -> Result<CarrierPayloadObservation, String> {
    let root =
        root.canonicalize().map_err(|error| format!("failed to resolve artifact root: {error}"))?;
    let path =
        path.canonicalize().map_err(|error| format!("failed to resolve checkpoint: {error}"))?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| "checkpoint is outside the artifact root".to_owned())?;
    let bytes = fs::read(&path).map_err(|error| format!("failed to read checkpoint: {error}"))?;
    if bytes.is_empty() {
        return Err("Wanco checkpoint artifact is empty".to_owned());
    }
    Ok(CarrierPayloadObservation::Artifact {
        reference: ArtifactReferenceObservation {
            uri: relative.to_string_lossy().into_owned(),
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        },
    })
}

fn push_event(
    events: &mut Vec<ObservedEvent>,
    phase: ObservationPhase,
    actor: ObservationActor,
    body: RawObservationEvent,
) {
    events.push(ObservedEvent::new(events.len() as u64, phase, actor, body));
}

fn identity_hex(identity: Identity) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in identity.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn entity_hex(entity: EntityRef) -> String {
    format!("{}:{:016x}", identity_hex(entity.identity), entity.generation.0)
}

fn decode_hex(value: &str, line: usize) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("line {} contains invalid hex", line + 1));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn read_required(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read {label} {}: {error}", path.display()))
}

fn read_optional(path: Option<&Path>, label: &str) -> Result<Option<Vec<u8>>, String> {
    path.map(|path| read_required(path, label)).transpose()
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("failed to decode {label}: {error}"))
}

fn observation_identity(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "output has no parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create output parent {}: {error}", parent.display()))?;
    let temporary = temporary_path(path);
    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|error| {
            format!("failed to create temporary output {}: {error}", temporary.display())
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist temporary output: {error}"))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("failed to publish output {}: {error}", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_else(|| OsStr::new("output")).as_bytes().to_vec();
    name.extend_from_slice(format!(".{}.tmp", std::process::id()).as_bytes());
    path.with_file_name(OsStr::from_bytes(&name))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use visa_component_adapter::component_digest;

    use super::*;
    use crate::canonical::{
        CanonicalEndpoint, DestinationEndpointConfig, SourceEndpointConfig, WireAction,
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestTree(PathBuf);

    impl TestTree {
        fn new(label: &str) -> Self {
            let ordinal = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("visa-wanco-record-{label}-{}-{ordinal}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn reply(endpoint: &mut CanonicalEndpoint, request: &str) -> String {
        match endpoint.handle_wire_line(request).unwrap() {
            WireAction::Reply(line) => line,
            WireAction::Exported { .. } | WireAction::Shutdown(_) => {
                panic!("operation unexpectedly exited endpoint service")
            }
        }
    }

    fn write_status(path: &Path) {
        fs::write(path, b"code\t0\n").unwrap();
    }

    fn source_read_write(tree: &TestTree, cell: &str, route: &str) -> (CanonicalEndpoint, String) {
        let mut source = CanonicalEndpoint::initialize_source(SourceEndpointConfig {
            cell_id: cell.to_owned(),
            route: route.to_owned(),
            workload: CanonicalWorkload::ReadWriteOffset,
            database: tree.path("source.sqlite"),
            file_root: tree.path("source-root"),
            component_digest: component_digest(b"record-test-component"),
            session_id: format!("{cell}-session"),
            initial_content: b"abcdef".to_vec(),
        })
        .unwrap();
        let open = reply(&mut source, "OPEN\tsource\tread-write-offset\t0\t1");
        let read = reply(&mut source, "READ\tsource\tread-write-offset\t0\t0\tread-prefix\t1\t2");
        let write = reply(
            &mut source,
            "WRITE\tsource\tread-write-offset\t1\t0\twrite-middle\t0\t5859\tvisible",
        );
        let events = format!(
            "CALL\t0\t1\n{open}\nERROR\t0\tread-prefix\t0\tread\ttransient-invalid-fd\t9\t1\t2\t-\n{read}\nRETURN\t0\t0\nCALL\t1\t0\n{write}\nRETURN\t1\t0\n"
        );
        (source, events)
    }

    fn common_record_files(tree: &TestTree, source_events: &str) {
        fs::write(tree.path("source.events"), source_events).unwrap();
        fs::write(tree.path("source.stdout"), b"").unwrap();
        fs::write(tree.path("destination.stdout"), b"").unwrap();
        write_status(&tree.path("source.status"));
        write_status(&tree.path("destination.status"));
        fs::write(tree.path("checkpoint.pb"), b"real-checkpoint-bytes").unwrap();
    }

    fn canonical_receipt_pair(
        tree: &TestTree,
        cell: &str,
    ) -> (CanonicalServiceReceipt, CanonicalServiceReceipt) {
        let (mut source, _) = source_read_write(tree, cell, "visa-plus-carrier");
        source.source_safe_point().unwrap();
        let transfer = source.source_export().unwrap();
        let source_receipt = source.receipt().clone();
        let mut destination = CanonicalEndpoint::restore_destination(
            DestinationEndpointConfig {
                cell_id: cell.to_owned(),
                route: "visa-plus-carrier".to_owned(),
                workload: CanonicalWorkload::ReadWriteOffset,
                database: tree.path("provenance-destination.sqlite"),
                file_root: tree.path("provenance-destination-root"),
                component_digest: component_digest(b"record-test-component"),
                session_id: format!("{cell}-session"),
            },
            &transfer,
        )
        .unwrap();
        destination.resume_destination().unwrap();
        (source_receipt, destination.receipt().clone())
    }

    #[test]
    fn cross_receipt_provenance_rejects_every_mixed_identity_dimension() {
        let tree = TestTree::new("provenance");
        let (source, destination) = canonical_receipt_pair(&tree, "provenance-cell");
        validate_cross_receipt_provenance(&source, &destination).unwrap();

        let mut mixed = destination.clone();
        mixed.cell_id = "another-cell".to_owned();
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination canonical cell_id mismatch"
        );

        let mut mixed = destination.clone();
        mixed.component_digest = contract_core::Digest::from_bytes([0x41; 32]);
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination canonical component_digest mismatch"
        );

        let mut mixed = destination.clone();
        mixed.profile_digest = contract_core::Digest::from_bytes([0x42; 32]);
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination canonical profile_digest mismatch"
        );

        let mut mixed = destination.clone();
        mixed.lifecycle[0].state.profile_state.claim.resource = contract_core::EntityRef::new(
            contract_core::Identity::from_u128(0x43),
            contract_core::Generation::INITIAL,
        );
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination canonical resource identity mismatch"
        );

        let mut mixed = destination.clone();
        mixed.native_object.node = source.native_object.node;
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination native node identity is not distinct"
        );

        let mut mixed = destination.clone();
        mixed.native_object.root_path.clone_from(&source.native_object.root_path);
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination native root identity is not distinct"
        );

        let mut mixed = destination.clone();
        mixed.native_object.root_device = source.native_object.root_device;
        mixed.native_object.root_inode = source.native_object.root_inode;
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination native root identity is not distinct"
        );

        let mut mixed = destination;
        mixed.native_object.file_device = source.native_object.file_device;
        mixed.native_object.file_inode = source.native_object.file_inode;
        assert_eq!(
            validate_cross_receipt_provenance(&source, &mixed).unwrap_err(),
            "source/destination native file identity is not distinct"
        );
    }

    #[test]
    fn parser_preserves_explicit_error_request_and_raw_event() {
        let raw = "CALL\t0\t1\nOPEN\t0\tinitial\t1\t2\t0\t6\t33152\t1\t616263646566\nERROR\t0\tread-prefix\t0\tread\ttransient-invalid-fd\t9\t1\t2\t-\nREAD\t0\tread-prefix\t1\t0\t2\t2\t6\t1\t2\t6162\t616263646566\nRETURN\t0\t0\n";
        let parsed = parse_endpoint_events(raw.as_bytes()).unwrap();
        assert_eq!(parsed.operations.len(), 2);
        assert_eq!(
            parsed.operations[0].raw_event,
            "ERROR\t0\tread-prefix\t0\tread\ttransient-invalid-fd\t9\t1\t2\t-"
        );
        assert!(matches!(
            parsed.operations[0].operation,
            EndpointOperation::Error {
                operation: RegularFileOperationObservation::Read { max_bytes: 2 },
                ..
            }
        ));
    }

    #[test]
    fn parser_rejects_old_underspecified_error_event() {
        let error = parse_endpoint_events(
            b"CALL\t0\t1\nERROR\t0\tread-prefix\t0\tread\ttransient-invalid-fd\t9\t1\nRETURN\t0\t9\n",
        )
        .unwrap_err();
        assert!(error.contains("unknown endpoint event"));
    }

    #[test]
    fn process_status_rejects_ambiguous_code_and_signal() {
        let root = std::env::temp_dir().join(format!(
            "visa-wanco-status-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        fs::create_dir_all(&root).unwrap();
        let status = root.join("status");
        fs::write(&status, b"signal\t9\n").unwrap();
        assert_eq!(
            parse_process_status(&status).unwrap(),
            ProcessStatusObservation { code: None, signal: Some(9) }
        );
        fs::write(&status, b"code\t0\nsignal\t9\n").unwrap();
        assert!(parse_process_status(&status).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recorder_transcribes_canonical_fresh_destination_handoff() {
        let tree = TestTree::new("positive");
        let cell = "record-positive";
        let (mut source, source_events) = source_read_write(&tree, cell, "visa-plus-carrier");
        source.source_safe_point().unwrap();
        let transfer = source.source_export().unwrap();
        source.write_receipt(&tree.path("source-receipt.json")).unwrap();

        let mut destination = CanonicalEndpoint::restore_destination(
            DestinationEndpointConfig {
                cell_id: cell.to_owned(),
                route: "visa-plus-carrier".to_owned(),
                workload: CanonicalWorkload::ReadWriteOffset,
                database: tree.path("destination.sqlite"),
                file_root: tree.path("destination-root"),
                component_digest: component_digest(b"record-test-component"),
                session_id: format!("{cell}-session"),
            },
            &transfer,
        )
        .unwrap();
        destination.resume_destination().unwrap();
        let read = reply(
            &mut destination,
            "READ\tdestination\tread-write-offset\t12\t0\tread-suffix\t0\t4",
        );
        destination.write_receipt(&tree.path("destination-receipt.json")).unwrap();
        common_record_files(&tree, &source_events);
        fs::write(tree.path("destination.events"), format!("CALL\t12\t0\n{read}\nRETURN\t12\t0\n"))
            .unwrap();

        let bundle = record_observation(&RecordInput {
            case: CarrierProbeCase::ReadWriteOffset,
            route: CarrierRoute::VisaPlusCarrier,
            artifact_root: &tree.0,
            source_events: &tree.path("source.events"),
            destination_events: Some(&tree.path("destination.events")),
            source_stdout: &tree.path("source.stdout"),
            destination_stdout: Some(&tree.path("destination.stdout")),
            source_status: &tree.path("source.status"),
            destination_status: Some(&tree.path("destination.status")),
            source_receipt: &tree.path("source-receipt.json"),
            destination_receipt: Some(&tree.path("destination-receipt.json")),
            subject_file: &destination.root().join("data.bin"),
            checkpoint: Some(&tree.path("checkpoint.pb")),
            output: &tree.path("observation.json"),
        })
        .unwrap();
        let case = &bundle.cases[0];
        assert_eq!(bundle.route.mode, visa_regular_file_observation::RouteMode::VisaPlusCarrier);
        assert_eq!(
            case.events
                .iter()
                .filter(|event| matches!(event.body, RawObservationEvent::ProtocolCall { .. }))
                .count(),
            9
        );
        assert!(case.events.iter().any(|event| {
            matches!(
                &event.body,
                RawObservationEvent::OperationCall {
                    result: OperationCallResult::Returned {
                        output: RegularFileOutputObservation::Read { version: 2, .. }
                    },
                    ..
                }
            ) && event.actor == ObservationActor::DestinationRuntime
        }));
    }

    #[test]
    fn recorder_keeps_carrier_only_loss_as_observed_negative() {
        let tree = TestTree::new("carrier-only");
        let cell = "record-carrier-only";
        let (source, source_events) = source_read_write(&tree, cell, "carrier-only");
        source.write_receipt(&tree.path("source-receipt.json")).unwrap();
        common_record_files(&tree, &source_events);
        fs::write(
            tree.path("destination.events"),
            b"CALL\t12\t0\nBINDING_ERROR\t12\tlost-process-local-binding\t9\nERROR\t12\tread-suffix\t0\tread\tlost-process-local-binding\t9\t0\t4\t-\nRETURN\t12\t9\n",
        )
        .unwrap();

        let bundle = record_observation(&RecordInput {
            case: CarrierProbeCase::ReadWriteOffset,
            route: CarrierRoute::CarrierOnly,
            artifact_root: &tree.0,
            source_events: &tree.path("source.events"),
            destination_events: Some(&tree.path("destination.events")),
            source_stdout: &tree.path("source.stdout"),
            destination_stdout: Some(&tree.path("destination.stdout")),
            source_status: &tree.path("source.status"),
            destination_status: Some(&tree.path("destination.status")),
            source_receipt: &tree.path("source-receipt.json"),
            destination_receipt: None,
            subject_file: &source.root().join("data.bin"),
            checkpoint: Some(&tree.path("checkpoint.pb")),
            output: &tree.path("observation.json"),
        })
        .unwrap();
        assert!(bundle.cases[0].events.iter().any(|event| {
            matches!(
                &event.body,
                RawObservationEvent::OperationCall {
                    operation_id,
                    result: OperationCallResult::Error { error },
                    ..
                } if operation_id == "read-suffix"
                    && error.code == ErrorCode::Unavailable
                    && !error.retryable
            ) && event.actor == ObservationActor::DestinationRuntime
        }));
    }
}
