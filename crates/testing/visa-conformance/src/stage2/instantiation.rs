use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::Deserialize;

use super::{
    artifacts::finding,
    model::{
        STAGE2_INSTANTIATION_OBSERVATIONS_SCHEMA_VERSION, Stage2CaseInstantiationObservation,
        Stage2CellId, Stage2InstantiationObservation, Stage2InstantiationObservations,
        Stage2LiveInstantiationBoundary, Stage2NotInstantiatedBoundary,
        Stage2NotInstantiatedReason, Stage2Runtime, Stage2ValidationFinding,
    },
    protocol::{
        CanonicalStateBoundary, ProtocolCommandKind, ProtocolRequestProjection,
        ProtocolResponseProjection, ProtocolResultKind, observed_component_instantiated,
        project_request_command, project_response, success_result_matches,
        validate_canonical_state_response, validate_initialize_request,
        validate_initialize_response,
    },
    runtime::{ObservedCellTranslationProvenance, validate_observed_runtime},
};
use crate::{
    Stage1CaseEvidence, Stage1EvidenceBundle, Stage1ExpectedOwnership, VerifiedStage1Artifacts,
    stage1_expected_ownership,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ObservedCellTranscriptEvidence {
    pub(super) translation_provenance: ObservedCellTranslationProvenance,
    pub(super) instantiation_observations: Stage2InstantiationObservations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptEnvelope {
    worker: String,
    pid: u32,
    sequence: u64,
    stream: TranscriptStream,
    line: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TranscriptStream {
    ParentRequest,
    WorkerResponse,
    WorkerStderr,
}

pub(super) fn audit_runtime_transcripts(
    id: Stage2CellId,
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> ObservedCellTranscriptEvidence {
    let mut translation_provenance = ObservedCellTranslationProvenance::default();
    let mut cases = Vec::with_capacity(bundle.cases.len());
    for case in &bundle.cases {
        let source = audit_role_transcript(
            id,
            case,
            "source.jsonl",
            id.source_runtime(),
            &format!("{}-source", case.case_id),
            artifacts,
            cell_root,
            &mut translation_provenance,
            findings,
        );
        let destination = audit_role_transcript(
            id,
            case,
            "destination.jsonl",
            id.destination_runtime(),
            &format!("{}-destination", case.case_id),
            artifacts,
            cell_root,
            &mut translation_provenance,
            findings,
        );
        if let (Some(source), Some(destination)) = (source, destination) {
            cases.push(Stage2CaseInstantiationObservation {
                case_id: case.case_id.clone(),
                source,
                destination,
            });
        }
    }
    ObservedCellTranscriptEvidence {
        translation_provenance,
        instantiation_observations: Stage2InstantiationObservations {
            schema_version: STAGE2_INSTANTIATION_OBSERVATIONS_SCHEMA_VERSION.to_owned(),
            cases,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_role_transcript(
    id: Stage2CellId,
    case: &Stage1CaseEvidence,
    role_name: &str,
    expected_runtime: Stage2Runtime,
    primary_worker: &str,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    translation_provenance: &mut ObservedCellTranslationProvenance,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<Stage2InstantiationObservation> {
    let expected_uri = format!("cases/{}/raw/{role_name}", case.case_id);
    let Some(reference) =
        case.artifacts.raw_execution.iter().find(|reference| reference.uri == expected_uri)
    else {
        finding(
            findings,
            "missing-stage2-runtime-transcript",
            format!("{} {} has no {role_name}", id.as_str(), case.case_id),
        );
        return None;
    };
    let Some(bytes) = artifacts.bytes(&reference.uri) else {
        finding(
            findings,
            "missing-stage2-captured-runtime-transcript",
            format!("{} {} was not retained", id.as_str(), reference.uri),
        );
        return None;
    };
    audit_runtime_transcript(
        RuntimeTranscriptContext {
            id,
            case,
            role_name,
            expected_runtime,
            primary_worker,
            provider_cell_root: Some(cell_root),
        },
        bytes,
        translation_provenance,
        findings,
    )
}

#[derive(Clone, Copy)]
struct RuntimeTranscriptContext<'a> {
    id: Stage2CellId,
    case: &'a Stage1CaseEvidence,
    role_name: &'a str,
    expected_runtime: Stage2Runtime,
    primary_worker: &'a str,
    provider_cell_root: Option<&'a Path>,
}

#[derive(Default)]
struct InstantiationFacts {
    canonical_live_count: usize,
    primary_commit_success_count: usize,
    any_relevant_live: bool,
    unexpected_live: bool,
}

#[derive(Default)]
struct PrimaryHandshakeFacts {
    requested: usize,
    observed: usize,
}

struct RequestAuditState<'a> {
    handshake: &'a mut PrimaryHandshakeFacts,
    requests: &'a mut BTreeMap<(String, String), RuntimeRequestFacts>,
    initialize_case_ids: &'a mut BTreeMap<(String, String), String>,
    findings: &'a mut Vec<Stage2ValidationFinding>,
}

struct RuntimeRequestFacts {
    command: ProtocolCommandKind,
    permits_no_response: bool,
    forbids_response: bool,
}

fn audit_runtime_transcript(
    context: RuntimeTranscriptContext<'_>,
    bytes: &[u8],
    translation_provenance: &mut ObservedCellTranslationProvenance,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<Stage2InstantiationObservation> {
    let RuntimeTranscriptContext { id, case, role_name, expected_runtime, primary_worker, .. } =
        context;
    let mut handshake = PrimaryHandshakeFacts::default();
    let mut requests = BTreeMap::<(String, String), RuntimeRequestFacts>::new();
    let mut initialize_case_ids = BTreeMap::<(String, String), String>::new();
    let mut responses = BTreeSet::<(String, String)>::new();
    let mut worker_processes = BTreeMap::<String, (u32, u64)>::new();
    let mut facts = InstantiationFacts::default();

    for (line_index, line) in
        bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
    {
        let transcript: TranscriptEnvelope = match serde_json::from_slice(line) {
            Ok(transcript) => transcript,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage2-runtime-transcript-envelope",
                    format!("{} {} line {}: {source}", id.as_str(), case.case_id, line_index + 1),
                );
                continue;
            }
        };
        if transcript.worker.is_empty() || transcript.pid == 0 || transcript.sequence == 0 {
            finding(
                findings,
                "invalid-stage2-runtime-transcript-envelope",
                format!("{} {} has an invalid envelope", id.as_str(), case.case_id),
            );
            continue;
        }
        if let Some((pid, last_sequence)) = worker_processes.get_mut(&transcript.worker) {
            if *pid != transcript.pid || last_sequence.checked_add(1) != Some(transcript.sequence) {
                finding(
                    findings,
                    "invalid-stage2-runtime-transcript-order",
                    format!(
                        "{} {} worker {} changed pid or used a non-contiguous sequence",
                        id.as_str(),
                        case.case_id,
                        transcript.worker
                    ),
                );
                continue;
            }
            *last_sequence = transcript.sequence;
        } else {
            if transcript.sequence != 1 {
                finding(
                    findings,
                    "invalid-stage2-runtime-transcript-order",
                    format!(
                        "{} {} worker {} did not start its transcript at sequence 1",
                        id.as_str(),
                        case.case_id,
                        transcript.worker
                    ),
                );
                continue;
            }
            worker_processes
                .insert(transcript.worker.clone(), (transcript.pid, transcript.sequence));
        }
        if transcript.stream == TranscriptStream::WorkerStderr {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&transcript.line) {
            Ok(value) => value,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage2-runtime-protocol-json",
                    format!("{} {}: {source}", id.as_str(), case.case_id),
                );
                continue;
            }
        };
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        let request_id = value.get("id").and_then(serde_json::Value::as_str).unwrap_or_default();
        if version != Some(crate::STAGE1_WORKER_PROTOCOL_VERSION) || request_id.is_empty() {
            finding(
                findings,
                "invalid-stage2-runtime-protocol-envelope",
                format!("{} {} has an invalid version or request id", id.as_str(), case.case_id),
            );
            continue;
        }
        if transcript.stream == TranscriptStream::ParentRequest {
            let projection = match project_request_command(&value) {
                Ok(projection) => projection,
                Err(source) => {
                    finding(
                        findings,
                        "invalid-stage2-runtime-protocol-request-envelope",
                        format!("{} {}: {source}", id.as_str(), case.case_id),
                    );
                    continue;
                }
            };
            audit_request(
                context,
                &transcript.worker,
                request_id,
                &value,
                projection,
                RequestAuditState {
                    handshake: &mut handshake,
                    requests: &mut requests,
                    initialize_case_ids: &mut initialize_case_ids,
                    findings,
                },
            );
            continue;
        }

        let request_key = (transcript.worker.clone(), request_id.to_owned());
        if !responses.insert(request_key.clone()) {
            finding(
                findings,
                "duplicate-stage2-runtime-response",
                format!("{} {} repeats a worker response", id.as_str(), case.case_id),
            );
            continue;
        }
        let Some(request) = requests.get(&request_key) else {
            finding(
                findings,
                "unmatched-stage2-runtime-response",
                format!("{} {} response has no preceding request", id.as_str(), case.case_id),
            );
            continue;
        };
        if request.forbids_response {
            finding(
                findings,
                "forbidden-stage2-runtime-response",
                format!(
                    "{} {} immediate crash request {request_id} unexpectedly has a response",
                    id.as_str(),
                    case.case_id
                ),
            );
            continue;
        }
        let command = request.command;
        let response_projection = match project_response(&value) {
            Ok(projection) => projection,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage2-runtime-protocol-response-envelope",
                    format!("{} {}: {source}", id.as_str(), case.case_id),
                );
                continue;
            }
        };
        let result_kind = match response_projection {
            ProtocolResponseProjection::Error => continue,
            ProtocolResponseProjection::Success(result_kind) => result_kind,
        };
        if !success_result_matches(command, result_kind) {
            finding(
                findings,
                "incompatible-stage2-runtime-protocol-result",
                format!(
                    "{} {} result {result_kind:?} is impossible for {command:?}",
                    id.as_str(),
                    case.case_id
                ),
            );
            continue;
        }
        if command == ProtocolCommandKind::Initialize {
            let initialized_case_id =
                initialize_case_ids.get(&request_key).map(String::as_str).unwrap_or(&case.case_id);
            if let Err(source) =
                validate_initialize_response(&value, role_name, initialized_case_id)
            {
                finding(
                    findings,
                    "invalid-stage2-runtime-initialize-response",
                    format!("{} {}: {source}", id.as_str(), case.case_id),
                );
                continue;
            }
            if transcript.worker == primary_worker {
                handshake.observed += 1;
            }
            validate_observed_runtime(
                id,
                case,
                role_name,
                expected_runtime,
                &value,
                translation_provenance,
                findings,
            );
        }
        let canonical_boundary = if transcript.worker == primary_worker {
            match (role_name, command) {
                ("source.jsonl", ProtocolCommandKind::BootstrapSource) => {
                    Some(CanonicalStateBoundary::SourceBootstrap)
                }
                ("destination.jsonl", ProtocolCommandKind::CommitDestination) => {
                    Some(CanonicalStateBoundary::DestinationCommit)
                }
                ("destination.jsonl", ProtocolCommandKind::ResumeDestination) => {
                    Some(CanonicalStateBoundary::DestinationResume)
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(boundary) = canonical_boundary
            && let Err(source) = validate_canonical_state_response(&value, boundary)
        {
            finding(
                findings,
                "invalid-stage2-runtime-canonical-state-observation",
                format!("{} {}: {source}", id.as_str(), case.case_id),
            );
            continue;
        }
        let component_instantiated = match observed_component_instantiated(&value) {
            Ok(observed) => observed,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage2-runtime-live-state-observation",
                    format!("{} {}: {source}", id.as_str(), case.case_id),
                );
                continue;
            }
        };
        audit_successful_instantiation_response(
            context,
            &transcript.worker,
            command,
            result_kind,
            component_instantiated,
            &mut facts,
            findings,
        );
    }

    for ((worker, request_id), request) in &requests {
        if !request.permits_no_response
            && !responses.contains(&(worker.clone(), request_id.clone()))
        {
            finding(
                findings,
                "missing-stage2-runtime-response",
                format!(
                    "{} {} request {request_id} ({:?}) has no response",
                    id.as_str(),
                    case.case_id,
                    request.command
                ),
            );
        }
    }
    if handshake.requested != 1 || handshake.observed != 1 {
        finding(
            findings,
            "missing-stage2-runtime-handshake",
            format!(
                "{} {} requires exactly one requested/observed primary {role_name} identity",
                id.as_str(),
                case.case_id
            ),
        );
    }
    derive_and_validate_instantiation(context, &facts, findings)
}

fn audit_request(
    context: RuntimeTranscriptContext<'_>,
    worker: &str,
    request_id: &str,
    value: &serde_json::Value,
    projection: ProtocolRequestProjection,
    state: RequestAuditState<'_>,
) {
    let RequestAuditState { handshake, requests, initialize_case_ids, findings } = state;
    let RuntimeTranscriptContext {
        id,
        case,
        role_name,
        expected_runtime,
        primary_worker,
        provider_cell_root,
    } = context;
    let ProtocolRequestProjection { kind: command, permits_no_response, forbids_response } =
        projection;
    if requests
        .insert(
            (worker.to_owned(), request_id.to_owned()),
            RuntimeRequestFacts { command, permits_no_response, forbids_response },
        )
        .is_some()
    {
        finding(
            findings,
            "invalid-stage2-runtime-request-order",
            format!("{} {} has an empty or duplicate request", id.as_str(), case.case_id),
        );
        return;
    }
    if worker == primary_worker
        && command != ProtocolCommandKind::Initialize
        && handshake.observed != 1
    {
        finding(
            findings,
            "stage2-runtime-command-before-initialize",
            format!(
                "{} {} primary worker requested {command:?} before its valid initialize response",
                id.as_str(),
                case.case_id
            ),
        );
    }
    if command == ProtocolCommandKind::Initialize {
        let valid_initialize = match validate_initialize_request(
            value,
            role_name,
            expected_runtime,
            &case.case_id,
            provider_cell_root.map(|cell_root| (cell_root, worker)),
        ) {
            Ok(initialized_case_id) => {
                initialize_case_ids
                    .insert((worker.to_owned(), request_id.to_owned()), initialized_case_id);
                true
            }
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage2-runtime-initialize-request",
                    format!("{} {}: {source}", id.as_str(), case.case_id),
                );
                false
            }
        };
        if worker == primary_worker && valid_initialize {
            handshake.requested += 1;
        }
        if value.pointer("/command/runtime").and_then(serde_json::Value::as_str)
            != Some(expected_runtime.protocol_selector())
        {
            finding(
                findings,
                "stage2-runtime-selector-fallback",
                format!("{} {} requested a different runtime", id.as_str(), case.case_id),
            );
        }
    }
}

fn audit_successful_instantiation_response(
    context: RuntimeTranscriptContext<'_>,
    worker: &str,
    command: ProtocolCommandKind,
    result_kind: ProtocolResultKind,
    component_instantiated: Option<bool>,
    facts: &mut InstantiationFacts,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let RuntimeTranscriptContext { id, case, role_name, primary_worker, .. } = context;
    let component_instantiated = component_instantiated == Some(true);
    let destination_role = role_name == "destination.jsonl";
    if component_instantiated && (worker == primary_worker || destination_role) {
        facts.any_relevant_live = true;
    }

    let canonical_live = if role_name == "source.jsonl" {
        worker == primary_worker
            && command == ProtocolCommandKind::BootstrapSource
            && result_kind == ProtocolResultKind::State
            && component_instantiated
    } else {
        if worker == primary_worker && command == ProtocolCommandKind::CommitDestination {
            if result_kind == ProtocolResultKind::State {
                facts.primary_commit_success_count += 1;
            } else {
                finding(
                    findings,
                    "invalid-stage2-destination-commit-observation",
                    format!("{} {} commit did not return state", id.as_str(), case.case_id),
                );
            }
        }
        worker == primary_worker
            && command == ProtocolCommandKind::ResumeDestination
            && facts.primary_commit_success_count == 1
            && result_kind == ProtocolResultKind::State
            && component_instantiated
    };

    if canonical_live {
        facts.canonical_live_count += 1;
        return;
    }
    if role_name == "destination.jsonl"
        && worker == primary_worker
        && command == ProtocolCommandKind::ResumeDestination
    {
        finding(
            findings,
            "invalid-stage2-destination-resume-observation",
            format!(
                "{} {} destination resume was not a live post-commit state",
                id.as_str(),
                case.case_id
            ),
        );
    }
    let unexpected_live = component_instantiated
        && ((worker == primary_worker && facts.canonical_live_count == 0)
            || (destination_role && worker != primary_worker));
    if unexpected_live {
        facts.unexpected_live = true;
        let code = if role_name == "source.jsonl" {
            "noncanonical-stage2-source-live-observation"
        } else {
            "noncanonical-stage2-destination-live-observation"
        };
        finding(
            findings,
            code,
            format!(
                "{} {} observed a component live outside the canonical activation boundary",
                id.as_str(),
                case.case_id
            ),
        );
    }
}

fn derive_and_validate_instantiation(
    context: RuntimeTranscriptContext<'_>,
    facts: &InstantiationFacts,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> Option<Stage2InstantiationObservation> {
    let RuntimeTranscriptContext { id, case, role_name, .. } = context;
    if role_name == "source.jsonl" {
        let actual = (facts.canonical_live_count == 1 && !facts.unexpected_live).then_some(
            Stage2InstantiationObservation::Live {
                boundary: Stage2LiveInstantiationBoundary::BootstrapSource,
            },
        );
        if actual.is_none() {
            finding(
                findings,
                "missing-stage2-live-source-observation",
                format!(
                    "{} {} requires exactly one canonical live source bootstrap",
                    id.as_str(),
                    case.case_id
                ),
            );
        }
        return actual;
    }

    if facts.primary_commit_success_count > 1 {
        finding(
            findings,
            "duplicate-stage2-destination-commit-observation",
            format!("{} {} repeats successful destination commit", id.as_str(), case.case_id),
        );
    }
    let actual = if facts.canonical_live_count == 1
        && facts.primary_commit_success_count == 1
        && !facts.unexpected_live
    {
        Some(Stage2InstantiationObservation::Live {
            boundary: Stage2LiveInstantiationBoundary::PostCommitResume,
        })
    } else if facts.canonical_live_count == 0 && !facts.any_relevant_live {
        match facts.primary_commit_success_count {
            0 => Some(Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::BeforeCommit,
                reason: Stage2NotInstantiatedReason::SourceRetained,
            }),
            1 => Some(Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::AfterCommitBeforeResume,
                reason: Stage2NotInstantiatedReason::RecoveryRequired,
            }),
            _ => None,
        }
    } else {
        None
    };
    let expected = expected_destination_observation(stage1_expected_ownership(case.outcome));
    if actual.as_ref() != Some(&expected) {
        let (code, detail) = match stage1_expected_ownership(case.outcome) {
            Stage1ExpectedOwnership::DestinationCommitted => (
                "missing-stage2-live-destination-observation",
                "requires exactly one live post-commit destination resume",
            ),
            Stage1ExpectedOwnership::SourceRetained
            | Stage1ExpectedOwnership::DestinationRecoveryRequired => (
                "unexpected-stage2-live-destination-observation",
                "does not match the case-designed destination absence boundary",
            ),
        };
        finding(findings, code, format!("{} {} {detail}", id.as_str(), case.case_id));
    }
    actual
}

fn expected_destination_observation(
    ownership: Stage1ExpectedOwnership,
) -> Stage2InstantiationObservation {
    match ownership {
        Stage1ExpectedOwnership::DestinationCommitted => Stage2InstantiationObservation::Live {
            boundary: Stage2LiveInstantiationBoundary::PostCommitResume,
        },
        Stage1ExpectedOwnership::SourceRetained => {
            Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::BeforeCommit,
                reason: Stage2NotInstantiatedReason::SourceRetained,
            }
        }
        Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            Stage2InstantiationObservation::NotInstantiatedByCaseDesign {
                boundary: Stage2NotInstantiatedBoundary::AfterCommitBeforeResume,
                reason: Stage2NotInstantiatedReason::RecoveryRequired,
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn audit_runtime_transcript_for_test(
    id: Stage2CellId,
    case: &Stage1CaseEvidence,
    role_name: &str,
    bytes: &[u8],
) -> Vec<Stage2ValidationFinding> {
    audit_runtime_transcript_observation_for_test(id, case, role_name, bytes).1
}

#[cfg(test)]
pub(crate) fn audit_runtime_transcript_observation_for_test(
    id: Stage2CellId,
    case: &Stage1CaseEvidence,
    role_name: &str,
    bytes: &[u8],
) -> (Option<Stage2InstantiationObservation>, Vec<Stage2ValidationFinding>) {
    let (expected_runtime, primary_worker) = match role_name {
        "source.jsonl" => (id.source_runtime(), format!("{}-source", case.case_id)),
        "destination.jsonl" => (id.destination_runtime(), format!("{}-destination", case.case_id)),
        _ => panic!("unsupported Stage 2 transcript role {role_name}"),
    };
    let mut findings = Vec::new();
    let mut provenance = ObservedCellTranslationProvenance::default();
    let observation = audit_runtime_transcript(
        RuntimeTranscriptContext {
            id,
            case,
            role_name,
            expected_runtime,
            primary_worker: &primary_worker,
            provider_cell_root: None,
        },
        bytes,
        &mut provenance,
        &mut findings,
    );
    (observation, findings)
}
