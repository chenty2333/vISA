use visa_local_rpc::{
    agent_control as wire,
    common::{
        AgentRole, ArtifactRoot, MAX_CANONICAL_PAYLOAD_BYTES, OperationEvidence, WireValidation,
        WireValidationError,
    },
};

use super::{
    GoldenCorpusError,
    fixtures::{
        Context, artifact, digest, internal_failure, nonminimal_header_major, operation_id,
        payload, payload_with_len, request_id,
    },
    model::{CorpusBuilder, GoldenCorpus, WireDirection, hex_digest},
};

pub(super) fn build() -> Result<GoldenCorpus, GoldenCorpusError> {
    let context = Context::new(0x1000);
    let controller = context.controller(0x1100);
    let source = context.agent(AgentRole::Source, 0x1200);
    let destination = context.agent(AgentRole::Destination, 0x1300);
    let mut builder = CorpusBuilder::new(wire::GOLDEN_CORPUS_ID, wire::SCHEMA, wire::FAMILY_ID);

    let status = wire::Request::new(
        request_id(0x1001),
        controller,
        wire::Operation::Status(wire::StatusRequest { expected_projection_digest: None }),
    );
    push_request(
        &mut builder,
        "agent-request-status-none",
        "Status(None)",
        &status,
        &[("agent_control::Operation", "Status")],
    )?;

    let status_with_digest = wire::Request::new(
        request_id(0x1002),
        controller,
        wire::Operation::Status(wire::StatusRequest {
            expected_projection_digest: Some(digest("expected-projection")),
        }),
    );
    push_request(
        &mut builder,
        "agent-request-status-some",
        "Status(Some)",
        &status_with_digest,
        &[("agent_control::Operation", "Status")],
    )?;

    let run_without_input = wire::Request::new(
        request_id(0x1003),
        controller,
        wire::Operation::Run(wire::RunRequest {
            operation: operation_id(0x1401),
            command: payload(wire::CONTRACT_COMMAND_SCHEMA, "run-command"),
            component: artifact(ArtifactRoot::Runtime, "components/workload.wasm", "component"),
            input: None,
        }),
    );
    push_request(
        &mut builder,
        "agent-request-run-no-input",
        "Run(None)",
        &run_without_input,
        &[("agent_control::Operation", "Run"), ("common::ArtifactRoot", "Runtime")],
    )?;

    let run_with_input = wire::Request::new(
        request_id(0x1004),
        controller,
        wire::Operation::Run(wire::RunRequest {
            operation: operation_id(0x1402),
            command: payload(wire::CONTRACT_COMMAND_SCHEMA, "run-command-with-input"),
            component: artifact(ArtifactRoot::Runtime, "components/workload.wasm", "component"),
            input: Some(artifact(ArtifactRoot::State, "inputs/request.bin", "input")),
        }),
    );
    push_request(
        &mut builder,
        "agent-request-run-with-input",
        "Run(Some)",
        &run_with_input,
        &[
            ("agent_control::Operation", "Run"),
            ("common::ArtifactRoot", "Runtime"),
            ("common::ArtifactRoot", "State"),
        ],
    )?;

    let run_max_path = wire::Request::new(
        request_id(0x1005),
        controller,
        wire::Operation::Run(wire::RunRequest {
            operation: operation_id(0x1403),
            command: payload(wire::CONTRACT_COMMAND_SCHEMA, "run-max-path"),
            component: artifact(ArtifactRoot::Runtime, "a".repeat(4096), "component"),
            input: None,
        }),
    );
    push_request(
        &mut builder,
        "agent-request-run-max-secure-path",
        "Run(MaxSecurePath)",
        &run_max_path,
        &[("agent_control::Operation", "Run"), ("common::ArtifactRoot", "Runtime")],
    )?;

    let handoff = wire::Request::new(
        request_id(0x1006),
        controller,
        wire::Operation::Handoff(wire::HandoffRequest {
            operation: operation_id(0x1501),
            command: payload_with_len(wire::JOINT_COMMAND_SCHEMA, MAX_CANONICAL_PAYLOAD_BYTES),
        }),
    );
    push_request(
        &mut builder,
        "agent-request-handoff-max-payload",
        "Handoff(MaxPayload)",
        &handoff,
        &[("agent_control::Operation", "Handoff")],
    )?;

    let reconcile = wire::Request::new(
        request_id(0x1007),
        controller,
        wire::Operation::Reconcile(wire::ReconcileRequest {
            operation: operation_id(0x1502),
            command: payload(wire::JOINT_COMMAND_SCHEMA, "r"),
        }),
    );
    push_request(
        &mut builder,
        "agent-request-reconcile-min-payload",
        "Reconcile(MinPayload)",
        &reconcile,
        &[("agent_control::Operation", "Reconcile")],
    )?;

    let verify = wire::Request::new(
        request_id(0x1008),
        controller,
        wire::Operation::VerifyEvidence(wire::VerifyEvidenceRequest {
            evidence_index: artifact(
                ArtifactRoot::Evidence,
                "release/evidence-index.json",
                "evidence-index",
            ),
        }),
    );
    push_request(
        &mut builder,
        "agent-request-verify-evidence",
        "VerifyEvidence",
        &verify,
        &[("agent_control::Operation", "VerifyEvidence"), ("common::ArtifactRoot", "Evidence")],
    )?;

    let phases = [
        (wire::AgentPhase::Initializing, AgentRole::Source, source),
        (wire::AgentPhase::Ready, AgentRole::Destination, destination),
        (wire::AgentPhase::Running, AgentRole::Source, source),
        (wire::AgentPhase::Fenced, AgentRole::Destination, destination),
        (wire::AgentPhase::Retiring, AgentRole::Source, source),
    ];
    let mut replay_exchange = None;
    for (index, (phase, role, server)) in phases.into_iter().enumerate() {
        let phase_name = agent_phase_name(phase);
        let response = wire::Response::new(
            &status,
            server,
            wire::Outcome::Success(wire::Success::Status(wire::Status {
                role,
                phase,
                logical_incarnation: server.logical_incarnation,
                projection_sequence: if index == 4 { u64::MAX } else { index as u64 },
                projection_digest: digest(&format!("agent-phase-{phase_name}")),
                effects_fenced: matches!(phase, wire::AgentPhase::Fenced),
            })),
        )
        .map_err(contract)?;
        push_response(
            &mut builder,
            format!("agent-response-status-{}", phase_name.to_ascii_lowercase()),
            format!("Success.Status.{phase_name}"),
            &status,
            &response,
            &[
                ("agent_control::Outcome", "Success"),
                ("agent_control::Success", "Status"),
                ("agent_control::AgentPhase", phase_name),
                ("common::AgentRole", agent_role_name(role)),
            ],
        )?;
        if matches!(phase, wire::AgentPhase::Ready) {
            replay_exchange = Some(response);
        }
    }

    let run_no_input_operation = match &run_without_input.operation {
        wire::Operation::Run(value) => value.operation,
        _ => unreachable!(),
    };
    let run_response = wire::Response::new(
        &run_without_input,
        source,
        wire::Outcome::Success(wire::Success::Run(OperationEvidence {
            operation: run_no_input_operation,
            sequence: 1,
            state_digest: digest("run-state"),
            evidence: None,
        })),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "agent-response-run-no-evidence",
        "Success.Run(None)",
        &run_without_input,
        &run_response,
        &[
            ("agent_control::Outcome", "Success"),
            ("agent_control::Success", "Run"),
            ("common::AgentRole", "Source"),
        ],
    )?;

    let run_input_operation = match &run_with_input.operation {
        wire::Operation::Run(value) => value.operation,
        _ => unreachable!(),
    };
    let run_with_evidence_response = wire::Response::new(
        &run_with_input,
        destination,
        wire::Outcome::Success(wire::Success::Run(OperationEvidence {
            operation: run_input_operation,
            sequence: u64::MAX,
            state_digest: digest("run-with-evidence-state"),
            evidence: Some(artifact(ArtifactRoot::Evidence, "operations/run.json", "run-evidence")),
        })),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "agent-response-run-with-evidence",
        "Success.Run(Some)",
        &run_with_input,
        &run_with_evidence_response,
        &[
            ("agent_control::Outcome", "Success"),
            ("agent_control::Success", "Run"),
            ("common::AgentRole", "Destination"),
            ("common::ArtifactRoot", "Evidence"),
        ],
    )?;

    for (case_id, request, success_name, success) in [
        (
            "agent-response-handoff",
            &handoff,
            "Handoff",
            wire::Success::Handoff(operation_evidence_for(&handoff, 3)?),
        ),
        (
            "agent-response-reconcile",
            &reconcile,
            "Reconcile",
            wire::Success::Reconcile(operation_evidence_for(&reconcile, 4)?),
        ),
    ] {
        let response = wire::Response::new(request, source, wire::Outcome::Success(success))
            .map_err(contract)?;
        push_response(
            &mut builder,
            case_id,
            format!("Success.{success_name}"),
            request,
            &response,
            &[
                ("agent_control::Outcome", "Success"),
                ("agent_control::Success", success_name),
                ("common::AgentRole", "Source"),
            ],
        )?;
    }

    let verify_response = wire::Response::new(
        &verify,
        destination,
        wire::Outcome::Success(wire::Success::VerifyEvidence(wire::EvidenceVerification {
            index_digest: match &verify.operation {
                wire::Operation::VerifyEvidence(request) => request.evidence_index.sha256,
                _ => unreachable!(),
            },
            verifier_receipt_digest: digest("verifier-receipt"),
        })),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "agent-response-verify-evidence",
        "Success.VerifyEvidence",
        &verify,
        &verify_response,
        &[
            ("agent_control::Outcome", "Success"),
            ("agent_control::Success", "VerifyEvidence"),
            ("common::AgentRole", "Destination"),
        ],
    )?;

    for (index, rejection) in agent_rejections().into_iter().enumerate() {
        let name = rejection_name(&rejection);
        let response = wire::Response::new(&status, source, wire::Outcome::Rejected(rejection))
            .map_err(contract)?;
        push_response(
            &mut builder,
            format!("agent-response-rejected-{}", name.to_ascii_lowercase()),
            format!("Rejected.{name}"),
            &status,
            &response,
            &[
                ("agent_control::Outcome", "Rejected"),
                ("agent_control::Rejection", name),
                ("common::AgentRole", "Source"),
            ],
        )?;
        debug_assert!(index < 16);
    }

    let unknown = wire::Response::new(
        &run_without_input,
        source,
        wire::Outcome::Unknown(wire::Unknown {
            operation: run_no_input_operation,
            last_known_sequence: u64::MAX,
        }),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "agent-response-unknown-run",
        "Unknown.Run",
        &run_without_input,
        &unknown,
        &[("agent_control::Outcome", "Unknown"), ("common::AgentRole", "Source")],
    )?;

    let internal = wire::Response::new(
        &status,
        destination,
        wire::Outcome::Internal(internal_failure(0x1601)),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "agent-response-internal",
        "Internal",
        &status,
        &internal,
        &[("agent_control::Outcome", "Internal"), ("common::AgentRole", "Destination")],
    )?;

    let replay_response = replay_exchange.expect("ready response is constructed");
    let replay =
        wire::ReplayRecord::from_exchange(&status, replay_response.server.role, &replay_response)
            .map_err(contract)?;
    replay.validate().map_err(contract)?;
    builder.push(
        "agent-replay-exact-status",
        WireDirection::Replay,
        "ReplayRecord.ExactExchange",
        checked_replay_bytes(&replay)?,
        &[],
    );

    add_negative_records(&mut builder)?;
    let corpus = builder.finish()?;
    require_coverage(&corpus)?;
    Ok(corpus)
}

pub(super) fn verify_negative_contracts() -> Result<(), GoldenCorpusError> {
    let vectors = negative_vectors()?;

    require_decode(wire::decode_request(&vectors.wrong_family), "wrong family", |error| {
        matches!(error, visa_local_rpc::DecodeError::Invalid(WireValidationError::WrongFamily))
    })?;
    require_decode(wire::decode_request(&vectors.nonminimal), "non-minimal varint", |error| {
        matches!(error, visa_local_rpc::DecodeError::NonCanonical)
    })?;
    require_decode(wire::decode_request(&vectors.trailing), "trailing bytes", |error| {
        matches!(error, visa_local_rpc::DecodeError::TrailingBytes)
    })?;
    require_decode(
        wire::decode_request(&vectors.unknown_discriminant),
        "unknown operation discriminant",
        |error| matches!(error, visa_local_rpc::DecodeError::Codec),
    )?;
    require_decode(wire::decode_request(&vectors.oversized), "oversized request", |error| {
        matches!(error, visa_local_rpc::DecodeError::TooLarge)
    })?;
    for (label, bytes, expected) in [
        (
            "response wrong family",
            &vectors.response_wrong_family,
            visa_local_rpc::DecodeError::Invalid(WireValidationError::WrongFamily),
        ),
        (
            "response non-minimal varint",
            &vectors.response_nonminimal,
            visa_local_rpc::DecodeError::NonCanonical,
        ),
        (
            "response trailing bytes",
            &vectors.response_trailing,
            visa_local_rpc::DecodeError::TrailingBytes,
        ),
        (
            "response unknown outcome",
            &vectors.response_unknown_discriminant,
            visa_local_rpc::DecodeError::Codec,
        ),
        ("oversized response", &vectors.oversized_response, visa_local_rpc::DecodeError::TooLarge),
    ] {
        require_decode(
            wire::decode_response_for(&vectors.status_request, AgentRole::Source, bytes),
            label,
            |error| error == expected,
        )?;
    }
    require_decode(
        wire::decode_response_for(
            &vectors.status_request,
            AgentRole::Destination,
            &vectors.canonical_response,
        ),
        "wrong verified endpoint role",
        |error| {
            matches!(error, visa_local_rpc::DecodeError::Invalid(WireValidationError::InvalidRole))
        },
    )?;
    require_decode(
        wire::decode_request(&vectors.invalid_payload_digest),
        "payload digest mismatch",
        |error| {
            matches!(
                error,
                visa_local_rpc::DecodeError::Invalid(WireValidationError::InvalidDigest)
            )
        },
    )?;
    require_decode(wire::decode_replay(&vectors.mutated_replay), "mutated replay", |error| {
        matches!(
            error,
            visa_local_rpc::DecodeError::Invalid(WireValidationError::InvalidArtifact)
                | visa_local_rpc::DecodeError::Invalid(WireValidationError::InvalidBinding)
        )
    })?;
    for (label, bytes, expected) in [
        (
            "replay wrong family",
            &vectors.replay_wrong_family,
            visa_local_rpc::DecodeError::Invalid(WireValidationError::WrongFamily),
        ),
        (
            "replay non-minimal varint",
            &vectors.replay_nonminimal,
            visa_local_rpc::DecodeError::NonCanonical,
        ),
        (
            "replay trailing bytes",
            &vectors.replay_trailing,
            visa_local_rpc::DecodeError::TrailingBytes,
        ),
        (
            "replay unknown endpoint role",
            &vectors.replay_unknown_role,
            visa_local_rpc::DecodeError::Codec,
        ),
        ("oversized replay", &vectors.oversized_replay, visa_local_rpc::DecodeError::TooLarge),
    ] {
        require_decode(wire::decode_replay(bytes), label, |error| error == expected)?;
    }
    let mismatch_bytes = postcard::to_allocvec(&vectors.mismatched_response).map_err(contract)?;
    require_decode(
        wire::decode_response_for(
            &vectors.status_request,
            vectors.mismatched_response.server.role,
            &mismatch_bytes,
        ),
        "operation/response mismatch",
        |error| {
            matches!(
                error,
                visa_local_rpc::DecodeError::Invalid(WireValidationError::InvalidBinding)
            )
        },
    )?;
    Ok(())
}

fn push_request(
    builder: &mut CorpusBuilder,
    case_id: impl Into<String>,
    semantic_variant: impl Into<String>,
    request: &wire::Request,
    coverage: &[(&str, &str)],
) -> Result<(), GoldenCorpusError> {
    let bytes = checked_request_bytes(request)?;
    builder.push(case_id, WireDirection::Request, semantic_variant, bytes, coverage);
    Ok(())
}

fn push_response(
    builder: &mut CorpusBuilder,
    case_id: impl Into<String>,
    semantic_variant: impl Into<String>,
    request: &wire::Request,
    response: &wire::Response,
    coverage: &[(&str, &str)],
) -> Result<(), GoldenCorpusError> {
    let bytes = checked_response_bytes(request, response)?;
    builder.push(case_id, WireDirection::Response, semantic_variant, bytes, coverage);
    Ok(())
}

fn checked_request_bytes(request: &wire::Request) -> Result<Vec<u8>, GoldenCorpusError> {
    let bytes = wire::encode_request(request).map_err(contract)?;
    let decoded = wire::decode_request(&bytes).map_err(contract)?;
    if decoded != *request || wire::encode_request(&decoded).map_err(contract)? != bytes {
        return Err(GoldenCorpusError::Contract(
            "agent request changed across canonical decode/re-encode".to_owned(),
        ));
    }
    Ok(bytes)
}

fn checked_response_bytes(
    request: &wire::Request,
    response: &wire::Response,
) -> Result<Vec<u8>, GoldenCorpusError> {
    let role = response.server.role;
    let bytes = wire::encode_response_for(request, role, response).map_err(contract)?;
    let decoded = wire::decode_response_for(request, role, &bytes).map_err(contract)?;
    if decoded != *response
        || wire::encode_response_for(request, role, &decoded).map_err(contract)? != bytes
    {
        return Err(GoldenCorpusError::Contract(
            "agent response changed across paired canonical decode/re-encode".to_owned(),
        ));
    }
    Ok(bytes)
}

fn checked_replay_bytes(replay: &wire::ReplayRecord) -> Result<Vec<u8>, GoldenCorpusError> {
    let bytes = wire::encode_replay(replay).map_err(contract)?;
    let decoded = wire::decode_replay(&bytes).map_err(contract)?;
    let (request, response) = decoded.exchange().map_err(contract)?;
    if decoded != *replay
        || request != replay.request().map_err(contract)?
        || response.server.role != replay.endpoint_role
        || wire::encode_replay(&decoded).map_err(contract)? != bytes
    {
        return Err(GoldenCorpusError::Contract(
            "agent replay changed across paired canonical decode/re-encode".to_owned(),
        ));
    }
    Ok(bytes)
}

fn operation_evidence_for(
    request: &wire::Request,
    sequence: u64,
) -> Result<OperationEvidence, GoldenCorpusError> {
    let operation = match &request.operation {
        wire::Operation::Handoff(value) => value.operation,
        wire::Operation::Reconcile(value) => value.operation,
        _ => {
            return Err(GoldenCorpusError::Contract(
                "operation evidence requested for non-operation command".to_owned(),
            ));
        }
    };
    Ok(OperationEvidence {
        operation,
        sequence,
        state_digest: digest(&format!("operation-evidence-{sequence}")),
        evidence: None,
    })
}

fn agent_rejections() -> [wire::Rejection; 11] {
    [
        wire::Rejection::InvalidRequest,
        wire::Rejection::WrongCohort,
        wire::Rejection::WrongBoot,
        wire::Rejection::WrongRuntimeSession,
        wire::Rejection::WrongRole,
        wire::Rejection::Busy,
        wire::Rejection::NotFound,
        wire::Rejection::StaleProjection {
            expected: digest("stale-expected"),
            actual: digest("stale-actual"),
        },
        wire::Rejection::Conflict,
        wire::Rejection::Unsupported,
        wire::Rejection::EffectsFenced,
    ]
}

fn rejection_name(value: &wire::Rejection) -> &'static str {
    match value {
        wire::Rejection::InvalidRequest => "InvalidRequest",
        wire::Rejection::WrongCohort => "WrongCohort",
        wire::Rejection::WrongBoot => "WrongBoot",
        wire::Rejection::WrongRuntimeSession => "WrongRuntimeSession",
        wire::Rejection::WrongRole => "WrongRole",
        wire::Rejection::Busy => "Busy",
        wire::Rejection::NotFound => "NotFound",
        wire::Rejection::StaleProjection { .. } => "StaleProjection",
        wire::Rejection::Conflict => "Conflict",
        wire::Rejection::Unsupported => "Unsupported",
        wire::Rejection::EffectsFenced => "EffectsFenced",
    }
}

fn agent_phase_name(value: wire::AgentPhase) -> &'static str {
    match value {
        wire::AgentPhase::Initializing => "Initializing",
        wire::AgentPhase::Ready => "Ready",
        wire::AgentPhase::Running => "Running",
        wire::AgentPhase::Fenced => "Fenced",
        wire::AgentPhase::Retiring => "Retiring",
    }
}

fn agent_role_name(value: AgentRole) -> &'static str {
    match value {
        AgentRole::Source => "Source",
        AgentRole::Destination => "Destination",
    }
}

struct NegativeVectors {
    wrong_family: Vec<u8>,
    nonminimal: Vec<u8>,
    trailing: Vec<u8>,
    unknown_discriminant: Vec<u8>,
    oversized: Vec<u8>,
    response_wrong_family: Vec<u8>,
    response_nonminimal: Vec<u8>,
    response_trailing: Vec<u8>,
    response_unknown_discriminant: Vec<u8>,
    oversized_response: Vec<u8>,
    canonical_response: Vec<u8>,
    replay_wrong_family: Vec<u8>,
    replay_nonminimal: Vec<u8>,
    replay_trailing: Vec<u8>,
    replay_unknown_role: Vec<u8>,
    oversized_replay: Vec<u8>,
    invalid_payload_digest: Vec<u8>,
    mutated_replay: Vec<u8>,
    status_request: wire::Request,
    mismatched_response: wire::Response,
}

fn negative_vectors() -> Result<NegativeVectors, GoldenCorpusError> {
    let context = Context::new(0x1700);
    let controller = context.controller(0x1710);
    let source = context.agent(AgentRole::Source, 0x1720);
    let status_request = wire::Request::new(
        request_id(0x1730),
        controller,
        wire::Operation::Status(wire::StatusRequest { expected_projection_digest: None }),
    );
    let canonical = wire::encode_request(&status_request).map_err(contract)?;

    let mut wrong_family = canonical.clone();
    wrong_family[..16].copy_from_slice(&visa_local_rpc::ownership::FAMILY_ID);
    let nonminimal = nonminimal_header_major(&canonical);
    let mut trailing = canonical.clone();
    trailing.push(0);

    let prefix = postcard::to_allocvec(&(
        status_request.header,
        status_request.request_id,
        status_request.caller,
    ))
    .map_err(contract)?;
    let mut unknown_discriminant = canonical.clone();
    unknown_discriminant[prefix.len()] = 0x7f;

    let oversized = vec![0; visa_local_rpc::MAX_INNER_REQUEST_BYTES + 1];

    let mut invalid_request = wire::Request::new(
        request_id(0x1740),
        controller,
        wire::Operation::Run(wire::RunRequest {
            operation: operation_id(0x1741),
            command: payload(wire::CONTRACT_COMMAND_SCHEMA, "bad-digest"),
            component: artifact(ArtifactRoot::Runtime, "component.wasm", "component"),
            input: None,
        }),
    );
    if let wire::Operation::Run(run) = &mut invalid_request.operation {
        run.command.sha256 = digest("not-the-command");
    }
    let invalid_payload_digest = postcard::to_allocvec(&invalid_request).map_err(contract)?;

    let status_response = wire::Response::new(
        &status_request,
        source,
        wire::Outcome::Success(wire::Success::Status(wire::Status {
            role: AgentRole::Source,
            phase: wire::AgentPhase::Ready,
            logical_incarnation: source.logical_incarnation,
            projection_sequence: 1,
            projection_digest: digest("negative-status"),
            effects_fenced: false,
        })),
    )
    .map_err(contract)?;
    let canonical_response =
        wire::encode_response_for(&status_request, source.role, &status_response)
            .map_err(contract)?;
    let mut response_wrong_family = canonical_response.clone();
    response_wrong_family[..16].copy_from_slice(&visa_local_rpc::ownership::FAMILY_ID);
    let response_nonminimal = nonminimal_header_major(&canonical_response);
    let mut response_trailing = canonical_response.clone();
    response_trailing.push(0);
    let response_prefix = postcard::to_allocvec(&(
        status_response.header,
        status_response.request_id,
        status_response.request_digest,
        status_response.server,
    ))
    .map_err(contract)?;
    let mut response_unknown_discriminant = canonical_response.clone();
    response_unknown_discriminant[response_prefix.len()] = 4;
    let oversized_response = vec![0; visa_local_rpc::MAX_INNER_RESPONSE_BYTES + 1];

    let replay_seed =
        wire::ReplayRecord::from_exchange(&status_request, source.role, &status_response)
            .map_err(contract)?;
    let canonical_replay = wire::encode_replay(&replay_seed).map_err(contract)?;
    let mut replay_wrong_family = canonical_replay.clone();
    replay_wrong_family[..16].copy_from_slice(&visa_local_rpc::ownership::FAMILY_ID);
    let replay_nonminimal = nonminimal_header_major(&canonical_replay);
    let mut replay_trailing = canonical_replay.clone();
    replay_trailing.push(0);
    let replay_prefix = postcard::to_allocvec(&(
        replay_seed.header,
        replay_seed.request_id,
        replay_seed.request_digest,
        replay_seed.response_digest,
    ))
    .map_err(contract)?;
    let mut replay_unknown_role = canonical_replay;
    replay_unknown_role[replay_prefix.len()] = 2;
    let oversized_replay = vec![0; visa_local_rpc::MAX_REPLAY_RECORD_BYTES + 1];

    let mut replay = replay_seed;
    *replay.response_bytes.last_mut().expect("response bytes are nonempty") ^= 1;
    let mutated_replay = postcard::to_allocvec(&replay).map_err(contract)?;

    let mismatched_response = wire::Response {
        header: visa_local_rpc::common::WireHeader::new(wire::FAMILY_ID),
        request_id: status_request.request_id,
        request_digest: status_request.digest().map_err(contract)?,
        server: source,
        outcome: wire::Outcome::Success(wire::Success::Run(OperationEvidence {
            operation: operation_id(0x1750),
            sequence: 1,
            state_digest: digest("mismatch"),
            evidence: None,
        })),
    };

    Ok(NegativeVectors {
        wrong_family,
        nonminimal,
        trailing,
        unknown_discriminant,
        oversized,
        response_wrong_family,
        response_nonminimal,
        response_trailing,
        response_unknown_discriminant,
        oversized_response,
        canonical_response,
        replay_wrong_family,
        replay_nonminimal,
        replay_trailing,
        replay_unknown_role,
        oversized_replay,
        invalid_payload_digest,
        mutated_replay,
        status_request,
        mismatched_response,
    })
}

fn add_negative_records(builder: &mut CorpusBuilder) -> Result<(), GoldenCorpusError> {
    let vectors = negative_vectors()?;
    for (case_id, mutation, target, expected, bytes) in [
        (
            "agent-negative-wrong-family",
            "replace-family-id-with-ownership",
            "agent_control::Request",
            "Invalid.WrongFamily",
            Some(vectors.wrong_family),
        ),
        (
            "agent-negative-nonminimal-varint",
            "encode-header-major-one-as-u16-marker",
            "agent_control::Request",
            "NonCanonical",
            Some(vectors.nonminimal),
        ),
        (
            "agent-negative-trailing-byte",
            "append-zero-byte",
            "agent_control::Request",
            "TrailingBytes",
            Some(vectors.trailing),
        ),
        (
            "agent-negative-unknown-operation",
            "replace-operation-discriminant",
            "agent_control::Request",
            "Codec",
            Some(vectors.unknown_discriminant),
        ),
        (
            "agent-negative-payload-digest",
            "replace-canonical-payload-digest",
            "agent_control::Request",
            "Invalid.InvalidDigest",
            Some(vectors.invalid_payload_digest),
        ),
        (
            "agent-negative-response-wrong-family",
            "replace-response-family-id-with-ownership",
            "agent_control::Response",
            "Invalid.WrongFamily",
            Some(vectors.response_wrong_family),
        ),
        (
            "agent-negative-response-nonminimal-varint",
            "encode-response-header-major-one-as-nonminimal-varint",
            "agent_control::Response",
            "NonCanonical",
            Some(vectors.response_nonminimal),
        ),
        (
            "agent-negative-response-trailing-byte",
            "append-zero-byte-after-response",
            "agent_control::Response",
            "TrailingBytes",
            Some(vectors.response_trailing),
        ),
        (
            "agent-negative-response-unknown-outcome",
            "replace-response-outcome-discriminant",
            "agent_control::Response",
            "Codec",
            Some(vectors.response_unknown_discriminant),
        ),
        (
            "agent-negative-replay-wrong-family",
            "replace-replay-family-id-with-ownership",
            "agent_control::ReplayRecord",
            "Invalid.WrongFamily",
            Some(vectors.replay_wrong_family),
        ),
        (
            "agent-negative-replay-nonminimal-varint",
            "encode-replay-header-major-one-as-nonminimal-varint",
            "agent_control::ReplayRecord",
            "NonCanonical",
            Some(vectors.replay_nonminimal),
        ),
        (
            "agent-negative-replay-trailing-byte",
            "append-zero-byte-after-replay",
            "agent_control::ReplayRecord",
            "TrailingBytes",
            Some(vectors.replay_trailing),
        ),
        (
            "agent-negative-replay-unknown-endpoint-role",
            "replace-replay-endpoint-role-discriminant",
            "agent_control::ReplayRecord",
            "Codec",
            Some(vectors.replay_unknown_role),
        ),
        (
            "agent-negative-mutated-replay",
            "flip-stored-response-byte-without-updating-digest",
            "agent_control::ReplayRecord",
            "Invalid.InvalidArtifact",
            Some(vectors.mutated_replay),
        ),
    ] {
        let bytes = bytes.expect("small negative vectors retain exact bytes");
        builder.push_negative(
            case_id,
            mutation,
            target,
            expected,
            Some(bytes.clone()),
            bytes.len(),
            hex_digest(&bytes),
        );
    }
    let oversized_digest = hex_digest(&vectors.oversized);
    builder.push_negative(
        "agent-negative-request-over-cap",
        "zero-byte-repeat-1048577",
        "agent_control::Request",
        "TooLargeBeforeDecode",
        None,
        vectors.oversized.len(),
        oversized_digest,
    );
    for (case_id, mutation, target, bytes) in [
        (
            "agent-negative-response-over-cap",
            "zero-byte-repeat-1048577",
            "agent_control::Response",
            &vectors.oversized_response,
        ),
        (
            "agent-negative-replay-over-cap",
            "zero-byte-repeat-max-replay-plus-one",
            "agent_control::ReplayRecord",
            &vectors.oversized_replay,
        ),
    ] {
        builder.push_negative(
            case_id,
            mutation,
            target,
            "TooLargeBeforeDecode",
            None,
            bytes.len(),
            hex_digest(bytes),
        );
    }
    builder.push_negative(
        "agent-negative-wrong-endpoint-role",
        "verify-source-response-against-destination-endpoint",
        "agent_control::decode_response_for",
        "Invalid.InvalidRole",
        Some(vectors.canonical_response.clone()),
        vectors.canonical_response.len(),
        hex_digest(&vectors.canonical_response),
    );
    let mismatch_bytes = postcard::to_allocvec(&vectors.mismatched_response).map_err(contract)?;
    builder.push_negative(
        "agent-negative-operation-response-mismatch",
        "status-request-with-run-success-response",
        "agent_control::decode_response_for",
        "InvalidBinding",
        Some(mismatch_bytes.clone()),
        mismatch_bytes.len(),
        hex_digest(&mismatch_bytes),
    );
    Ok(())
}

fn require_coverage(corpus: &GoldenCorpus) -> Result<(), GoldenCorpusError> {
    for (type_name, expected) in [
        (
            "agent_control::Operation",
            &["Handoff", "Reconcile", "Run", "Status", "VerifyEvidence"][..],
        ),
        ("agent_control::Outcome", &["Internal", "Rejected", "Success", "Unknown"][..]),
        (
            "agent_control::Success",
            &["Handoff", "Reconcile", "Run", "Status", "VerifyEvidence"][..],
        ),
        (
            "agent_control::AgentPhase",
            &["Fenced", "Initializing", "Ready", "Retiring", "Running"][..],
        ),
        (
            "agent_control::Rejection",
            &[
                "Busy",
                "Conflict",
                "EffectsFenced",
                "InvalidRequest",
                "NotFound",
                "StaleProjection",
                "Unsupported",
                "WrongBoot",
                "WrongCohort",
                "WrongRole",
                "WrongRuntimeSession",
            ][..],
        ),
        ("common::AgentRole", &["Destination", "Source"][..]),
        ("common::ArtifactRoot", &["Evidence", "Runtime", "State"][..]),
    ] {
        let actual =
            corpus.coverage.iter().find(|entry| entry.type_name == type_name).ok_or_else(|| {
                GoldenCorpusError::Contract(format!("{type_name} has no corpus coverage"))
            })?;
        if actual.variants.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(GoldenCorpusError::Contract(format!(
                "{type_name} corpus coverage drifted"
            )));
        }
    }
    Ok(())
}

fn require_decode<T>(
    result: Result<T, visa_local_rpc::DecodeError>,
    label: &str,
    expected: impl FnOnce(visa_local_rpc::DecodeError) -> bool,
) -> Result<(), GoldenCorpusError> {
    match result {
        Err(error) if expected(error) => Ok(()),
        Err(error) => Err(GoldenCorpusError::Contract(format!(
            "{label} returned unexpected decode error {error:?}"
        ))),
        Ok(_) => Err(GoldenCorpusError::Contract(format!("{label} unexpectedly decoded"))),
    }
}

fn contract(error: impl std::fmt::Debug) -> GoldenCorpusError {
    GoldenCorpusError::Contract(format!("agent-control corpus construction failed: {error:?}"))
}
