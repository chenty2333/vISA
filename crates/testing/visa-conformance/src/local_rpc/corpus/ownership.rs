use visa_local_rpc::{
    common::{
        AgentRole, AuthorityRole, MAX_CANONICAL_PAYLOAD_BYTES, NodeId, ReceiptArtifact,
        ReceiptKindWire, ReservationId, WireValidation, WireValidationError,
    },
    ownership as wire,
};

use super::{
    GoldenCorpusError,
    fixtures::{
        Context, all_receipt_kinds, digest, entity, handoff_key, internal_failure,
        nonminimal_header_major, payload, payload_with_len, receipt, receipt_for_handoff,
        receipt_kind_name, request_id,
    },
    model::{CorpusBuilder, GoldenCorpus, WireDirection, hex_digest},
};

pub(super) fn build() -> Result<GoldenCorpus, GoldenCorpusError> {
    let context = Context::new(0x2000);
    let source = context.agent(AgentRole::Source, 0x2100);
    let destination = context.agent(AgentRole::Destination, 0x2200);
    let server = context.authority(AuthorityRole::Ownership, 0x2300);
    let mut builder = CorpusBuilder::new(wire::GOLDEN_CORPUS_ID, wire::SCHEMA, wire::FAMILY_ID);

    let initialize = wire::Request::new(
        request_id(0x2001),
        source,
        wire::Operation::InitializeUnit(wire::InitializeUnitRequest {
            continuity_unit: entity(0x2400),
            owner: NodeId::from_u128(0x2401),
            epoch: 0,
        }),
    );
    push_request(
        &mut builder,
        "ownership-request-initialize-unit",
        "InitializeUnit",
        &initialize,
        &[("ownership::Operation", "InitializeUnit"), ("common::AgentRole", "Source")],
    )?;

    let key = handoff_key(0x2500);
    let reserve =
        decision_request(request_id(0x2002), destination, OperationKind::Reserve, key, 0, false);
    push_request(
        &mut builder,
        "ownership-request-reserve",
        "Reserve",
        &reserve,
        &[("ownership::Operation", "Reserve"), ("common::AgentRole", "Destination")],
    )?;

    let seal = decision_request(request_id(0x2003), source, OperationKind::Seal, key, 1, true);
    push_request(
        &mut builder,
        "ownership-request-seal-max-payload",
        "Seal(MaxPayload)",
        &seal,
        &[("ownership::Operation", "Seal"), ("common::AgentRole", "Source")],
    )?;

    let abort = decision_request(request_id(0x2004), source, OperationKind::Abort, key, 2, false);
    push_request(
        &mut builder,
        "ownership-request-abort",
        "Abort",
        &abort,
        &[("ownership::Operation", "Abort"), ("common::AgentRole", "Source")],
    )?;

    let commit = decision_request(
        request_id(0x2005),
        destination,
        OperationKind::Commit,
        key,
        u64::MAX,
        false,
    );
    push_request(
        &mut builder,
        "ownership-request-commit-max-sequence",
        "Commit(MaxSequence)",
        &commit,
        &[("ownership::Operation", "Commit"), ("common::AgentRole", "Destination")],
    )?;

    let query_unit = wire::Request::new(
        request_id(0x2006),
        source,
        wire::Operation::Query(wire::QueryRequest::Unit(match &initialize.operation {
            wire::Operation::InitializeUnit(request) => request.continuity_unit,
            _ => unreachable!(),
        })),
    );
    push_request(
        &mut builder,
        "ownership-request-query-unit",
        "Query.Unit",
        &query_unit,
        &[
            ("ownership::Operation", "Query"),
            ("ownership::QueryRequest", "Unit"),
            ("common::AgentRole", "Source"),
        ],
    )?;

    let query_handoff = wire::Request::new(
        request_id(0x2007),
        destination,
        wire::Operation::Query(wire::QueryRequest::Handoff(key.handoff)),
    );
    push_request(
        &mut builder,
        "ownership-request-query-handoff",
        "Query.Handoff",
        &query_handoff,
        &[
            ("ownership::Operation", "Query"),
            ("ownership::QueryRequest", "Handoff"),
            ("common::AgentRole", "Destination"),
        ],
    )?;

    let initialized = wire::Response::new(
        &initialize,
        server,
        wire::Outcome::Success(wire::Success::Initialized(wire::UnitOwnership {
            continuity_unit: match &initialize.operation {
                wire::Operation::InitializeUnit(request) => request.continuity_unit,
                _ => unreachable!(),
            },
            owner: match &initialize.operation {
                wire::Operation::InitializeUnit(request) => request.owner,
                _ => unreachable!(),
            },
            epoch: 0,
            active_handoff: None,
            active_reservation: None,
        })),
    )
    .map_err(contract)?;
    push_response(
        &mut builder,
        "ownership-response-initialized-none",
        "Success.Initialized(None)",
        &initialize,
        &initialized,
        &[
            ("ownership::Outcome", "Success"),
            ("ownership::Success", "Initialized"),
            ("common::AuthorityRole", "Ownership"),
        ],
    )?;

    for (case_id, request, name, kind, success_ctor) in [
        (
            "ownership-response-reserved",
            &reserve,
            "Reserved",
            ReceiptKindWire::PrepareIntent,
            wire::Success::Reserved as fn(ReceiptArtifact) -> wire::Success,
        ),
        (
            "ownership-response-prepared",
            &seal,
            "Prepared",
            ReceiptKindWire::OwnershipPrepared,
            wire::Success::Prepared,
        ),
        (
            "ownership-response-aborted",
            &abort,
            "Aborted",
            ReceiptKindWire::OwnershipAbort,
            wire::Success::Aborted,
        ),
        (
            "ownership-response-committed",
            &commit,
            "Committed",
            ReceiptKindWire::OwnershipCommit,
            wire::Success::Committed,
        ),
    ] {
        let response = wire::Response::new(
            request,
            server,
            wire::Outcome::Success(success_ctor(receipt_for(kind, key.handoff, 0x2600))),
        )
        .map_err(contract)?;
        push_response(
            &mut builder,
            case_id,
            format!("Success.{name}"),
            request,
            &response,
            &[
                ("ownership::Outcome", "Success"),
                ("ownership::Success", name),
                ("common::ReceiptKindWire", receipt_kind_name(kind)),
                ("common::AuthorityRole", "Ownership"),
            ],
        )?;
    }

    for (case_id, request, semantic, result, coverage) in [
        (
            "ownership-response-query-missing",
            &query_unit,
            "Query.Missing",
            wire::QueryResult::Missing,
            "Missing",
        ),
        (
            "ownership-response-query-unit",
            &query_unit,
            "Query.Unit",
            wire::QueryResult::Unit(wire::UnitOwnership {
                continuity_unit: match &query_unit.operation {
                    wire::Operation::Query(wire::QueryRequest::Unit(unit)) => *unit,
                    _ => unreachable!(),
                },
                owner: NodeId::from_u128(0x2701),
                epoch: u64::MAX,
                active_handoff: Some(key.handoff),
                active_reservation: Some(ReservationId::from_u128(0x2702)),
            }),
            "Unit",
        ),
        (
            "ownership-response-query-reserved",
            &query_handoff,
            "Query.Reserved",
            wire::QueryResult::Reserved(receipt_for(
                ReceiptKindWire::PrepareIntent,
                key.handoff,
                0x2703,
            )),
            "Reserved",
        ),
        (
            "ownership-response-query-prepared",
            &query_handoff,
            "Query.Prepared",
            wire::QueryResult::Prepared(receipt_for(
                ReceiptKindWire::OwnershipPrepared,
                key.handoff,
                0x2704,
            )),
            "Prepared",
        ),
        (
            "ownership-response-query-abort-decided",
            &query_handoff,
            "Query.AbortDecided",
            wire::QueryResult::AbortDecided(receipt_for(
                ReceiptKindWire::OwnershipAbort,
                key.handoff,
                0x2705,
            )),
            "AbortDecided",
        ),
        (
            "ownership-response-query-commit-decided",
            &query_handoff,
            "Query.CommitDecided",
            wire::QueryResult::CommitDecided(receipt_for(
                ReceiptKindWire::OwnershipCommit,
                key.handoff,
                0x2706,
            )),
            "CommitDecided",
        ),
    ] {
        let response = wire::Response::new(
            request,
            server,
            wire::Outcome::Success(wire::Success::Query(result)),
        )
        .map_err(contract)?;
        push_response(
            &mut builder,
            case_id,
            semantic,
            request,
            &response,
            &[
                ("ownership::Outcome", "Success"),
                ("ownership::Success", "Query"),
                ("ownership::QueryResult", coverage),
                ("common::AuthorityRole", "Ownership"),
            ],
        )?;
    }

    for (index, kind) in all_receipt_kinds().into_iter().enumerate() {
        let name = receipt_kind_name(kind);
        let response =
            wire::Response::new(
                &query_handoff,
                server,
                wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Reserved(
                    receipt_for(kind, key.handoff, 0x2800 + index as u128),
                ))),
            )
            .map_err(contract)?;
        push_response(
            &mut builder,
            format!("ownership-response-receipt-kind-{}", name.to_ascii_lowercase()),
            format!("Query.ReceiptKind.{name}"),
            &query_handoff,
            &response,
            &[
                ("ownership::Outcome", "Success"),
                ("ownership::Success", "Query"),
                ("ownership::QueryResult", "Reserved"),
                ("common::ReceiptKindWire", name),
                ("common::AuthorityRole", "Ownership"),
            ],
        )?;
    }

    for rejection in ownership_rejections(key.handoff) {
        let name = rejection_name(&rejection);
        let response =
            wire::Response::new(&query_handoff, server, wire::Outcome::Rejected(rejection))
                .map_err(contract)?;
        push_response(
            &mut builder,
            format!("ownership-response-rejected-{}", name.to_ascii_lowercase()),
            format!("Rejected.{name}"),
            &query_handoff,
            &response,
            &[
                ("ownership::Outcome", "Rejected"),
                ("ownership::Rejection", name),
                ("common::AuthorityRole", "Ownership"),
            ],
        )?;
    }

    for (case_id, request, query) in [
        (
            "ownership-response-unknown-initialize",
            &initialize,
            wire::QueryRequest::Unit(match &initialize.operation {
                wire::Operation::InitializeUnit(value) => value.continuity_unit,
                _ => unreachable!(),
            }),
        ),
        ("ownership-response-unknown-reserve", &reserve, wire::QueryRequest::Handoff(key.handoff)),
        ("ownership-response-unknown-seal", &seal, wire::QueryRequest::Handoff(key.handoff)),
        ("ownership-response-unknown-abort", &abort, wire::QueryRequest::Handoff(key.handoff)),
        ("ownership-response-unknown-commit", &commit, wire::QueryRequest::Handoff(key.handoff)),
    ] {
        let response = wire::Response::new(
            request,
            server,
            wire::Outcome::Unknown(wire::Unknown { query, last_known_sequence: u64::MAX }),
        )
        .map_err(contract)?;
        push_response(
            &mut builder,
            case_id,
            "Unknown",
            request,
            &response,
            &[("ownership::Outcome", "Unknown"), ("common::AuthorityRole", "Ownership")],
        )?;
    }

    let internal =
        wire::Response::new(&query_unit, server, wire::Outcome::Internal(internal_failure(0x2900)))
            .map_err(contract)?;
    push_response(
        &mut builder,
        "ownership-response-internal",
        "Internal",
        &query_unit,
        &internal,
        &[("ownership::Outcome", "Internal"), ("common::AuthorityRole", "Ownership")],
    )?;

    let replay = wire::ReplayRecord::from_exchange(&initialize, &initialized).map_err(contract)?;
    replay.validate().map_err(contract)?;
    builder.push(
        "ownership-replay-exact-initialize",
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
        require_decode(wire::decode_response_for(&vectors.initialize, bytes), label, |error| {
            error == expected
        })?;
    }
    require_decode(
        wire::decode_request(&vectors.invalid_payload_digest),
        "proposal digest mismatch",
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
        ("oversized replay", &vectors.oversized_replay, visa_local_rpc::DecodeError::TooLarge),
    ] {
        require_decode(wire::decode_replay(bytes), label, |error| error == expected)?;
    }
    for (label, bytes, expected) in [
        (
            "receipt digest mismatch",
            &vectors.receipt_digest_mismatch,
            WireValidationError::InvalidDigest,
        ),
        (
            "receipt schema substitution",
            &vectors.receipt_schema_substitution,
            WireValidationError::UnsupportedVersion,
        ),
        (
            "receipt kind substitution",
            &vectors.receipt_kind_substitution,
            WireValidationError::UnsupportedVersion,
        ),
    ] {
        require_decode(
            wire::decode_response_for(&vectors.receipt_request, bytes),
            label,
            |error| error == visa_local_rpc::DecodeError::Invalid(expected),
        )?;
    }
    let mismatch_bytes = postcard::to_allocvec(&vectors.mismatched_response).map_err(contract)?;
    require_decode(
        wire::decode_response_for(&vectors.initialize, &mismatch_bytes),
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

#[derive(Clone, Copy)]
enum OperationKind {
    Reserve,
    Seal,
    Abort,
    Commit,
}

fn decision_request(
    id: visa_local_rpc::common::RequestId,
    caller: visa_local_rpc::common::AgentBinding,
    kind: OperationKind,
    key: visa_local_rpc::common::JointHandoffKeyWire,
    expected_state_sequence: u64,
    maximum_payload: bool,
) -> wire::Request {
    let schema = match kind {
        OperationKind::Reserve => wire::RESERVE_PROPOSAL_SCHEMA,
        OperationKind::Seal => wire::SEAL_PROPOSAL_SCHEMA,
        OperationKind::Abort => wire::ABORT_PROPOSAL_SCHEMA,
        OperationKind::Commit => wire::COMMIT_PROPOSAL_SCHEMA,
    };
    let proposal = wire::DecisionProposal {
        key,
        expected_state_sequence,
        proposal: if maximum_payload {
            payload_with_len(schema, MAX_CANONICAL_PAYLOAD_BYTES)
        } else {
            payload(schema, "ownership-proposal")
        },
    };
    let operation = match kind {
        OperationKind::Reserve => wire::Operation::Reserve(proposal),
        OperationKind::Seal => wire::Operation::Seal(proposal),
        OperationKind::Abort => wire::Operation::Abort(proposal),
        OperationKind::Commit => wire::Operation::Commit(proposal),
    };
    wire::Request::new(id, caller, operation)
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
            "ownership request changed across canonical decode/re-encode".to_owned(),
        ));
    }
    Ok(bytes)
}

fn checked_response_bytes(
    request: &wire::Request,
    response: &wire::Response,
) -> Result<Vec<u8>, GoldenCorpusError> {
    let bytes = wire::encode_response_for(request, response).map_err(contract)?;
    let decoded = wire::decode_response_for(request, &bytes).map_err(contract)?;
    if decoded != *response
        || wire::encode_response_for(request, &decoded).map_err(contract)? != bytes
    {
        return Err(GoldenCorpusError::Contract(
            "ownership response changed across paired canonical decode/re-encode".to_owned(),
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
        || wire::encode_response_for(&request, &response).map_err(contract)?
            != replay.response_bytes
        || wire::encode_replay(&decoded).map_err(contract)? != bytes
    {
        return Err(GoldenCorpusError::Contract(
            "ownership replay changed across paired canonical decode/re-encode".to_owned(),
        ));
    }
    Ok(bytes)
}

fn receipt_for(
    kind: ReceiptKindWire,
    handoff: visa_local_rpc::common::HandoffId,
    seed: u128,
) -> ReceiptArtifact {
    receipt_for_handoff(kind, handoff, seed)
}

fn ownership_rejections(handoff: visa_local_rpc::common::HandoffId) -> [wire::Rejection; 9] {
    [
        wire::Rejection::InvalidRequest,
        wire::Rejection::NotFound,
        wire::Rejection::Conflict,
        wire::Rejection::Busy,
        wire::Rejection::StaleSequence { expected: 3, actual: 4 },
        wire::Rejection::OwnershipMismatch { owner: NodeId::from_u128(0x2a01), epoch: u64::MAX },
        wire::Rejection::ExistingAbort(receipt_for(
            ReceiptKindWire::OwnershipAbort,
            handoff,
            0x2a02,
        )),
        wire::Rejection::ExistingCommit(receipt_for(
            ReceiptKindWire::OwnershipCommit,
            handoff,
            0x2a03,
        )),
        wire::Rejection::Integrity,
    ]
}

fn rejection_name(value: &wire::Rejection) -> &'static str {
    match value {
        wire::Rejection::InvalidRequest => "InvalidRequest",
        wire::Rejection::NotFound => "NotFound",
        wire::Rejection::Conflict => "Conflict",
        wire::Rejection::Busy => "Busy",
        wire::Rejection::StaleSequence { .. } => "StaleSequence",
        wire::Rejection::OwnershipMismatch { .. } => "OwnershipMismatch",
        wire::Rejection::ExistingAbort(_) => "ExistingAbort",
        wire::Rejection::ExistingCommit(_) => "ExistingCommit",
        wire::Rejection::Integrity => "Integrity",
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
    replay_wrong_family: Vec<u8>,
    replay_nonminimal: Vec<u8>,
    replay_trailing: Vec<u8>,
    oversized_replay: Vec<u8>,
    receipt_digest_mismatch: Vec<u8>,
    receipt_schema_substitution: Vec<u8>,
    receipt_kind_substitution: Vec<u8>,
    invalid_payload_digest: Vec<u8>,
    mutated_replay: Vec<u8>,
    initialize: wire::Request,
    receipt_request: wire::Request,
    mismatched_response: wire::Response,
}

fn negative_vectors() -> Result<NegativeVectors, GoldenCorpusError> {
    let context = Context::new(0x2b00);
    let caller = context.agent(AgentRole::Source, 0x2b10);
    let server = context.authority(AuthorityRole::Ownership, 0x2b20);
    let initialize = wire::Request::new(
        request_id(0x2b30),
        caller,
        wire::Operation::InitializeUnit(wire::InitializeUnitRequest {
            continuity_unit: entity(0x2b31),
            owner: NodeId::from_u128(0x2b32),
            epoch: 1,
        }),
    );
    let canonical = wire::encode_request(&initialize).map_err(contract)?;
    let mut wrong_family = canonical.clone();
    wrong_family[..16].copy_from_slice(&visa_local_rpc::agent_control::FAMILY_ID);
    let nonminimal = nonminimal_header_major(&canonical);
    let mut trailing = canonical.clone();
    trailing.push(0);
    let prefix =
        postcard::to_allocvec(&(initialize.header, initialize.request_id, initialize.caller))
            .map_err(contract)?;
    let mut unknown_discriminant = canonical.clone();
    unknown_discriminant[prefix.len()] = 0x7f;
    let oversized = vec![0; visa_local_rpc::MAX_INNER_REQUEST_BYTES + 1];

    let mut invalid_request = decision_request(
        request_id(0x2b40),
        caller,
        OperationKind::Reserve,
        handoff_key(0x2b41),
        0,
        false,
    );
    if let wire::Operation::Reserve(proposal) = &mut invalid_request.operation {
        proposal.proposal.sha256 = digest("wrong-proposal-digest");
    }
    let invalid_payload_digest = postcard::to_allocvec(&invalid_request).map_err(contract)?;

    let initialized = wire::Response::new(
        &initialize,
        server,
        wire::Outcome::Success(wire::Success::Initialized(wire::UnitOwnership {
            continuity_unit: match &initialize.operation {
                wire::Operation::InitializeUnit(value) => value.continuity_unit,
                _ => unreachable!(),
            },
            owner: match &initialize.operation {
                wire::Operation::InitializeUnit(value) => value.owner,
                _ => unreachable!(),
            },
            epoch: 1,
            active_handoff: None,
            active_reservation: None,
        })),
    )
    .map_err(contract)?;
    let canonical_response =
        wire::encode_response_for(&initialize, &initialized).map_err(contract)?;
    let mut response_wrong_family = canonical_response.clone();
    response_wrong_family[..16].copy_from_slice(&visa_local_rpc::agent_control::FAMILY_ID);
    let response_nonminimal = nonminimal_header_major(&canonical_response);
    let mut response_trailing = canonical_response.clone();
    response_trailing.push(0);
    let response_prefix = postcard::to_allocvec(&(
        initialized.header,
        initialized.request_id,
        initialized.request_digest,
        initialized.server,
    ))
    .map_err(contract)?;
    let mut response_unknown_discriminant = canonical_response;
    response_unknown_discriminant[response_prefix.len()] = 4;
    let oversized_response = vec![0; visa_local_rpc::MAX_INNER_RESPONSE_BYTES + 1];

    let replay_seed =
        wire::ReplayRecord::from_exchange(&initialize, &initialized).map_err(contract)?;
    let canonical_replay = wire::encode_replay(&replay_seed).map_err(contract)?;
    let mut replay_wrong_family = canonical_replay.clone();
    replay_wrong_family[..16].copy_from_slice(&visa_local_rpc::agent_control::FAMILY_ID);
    let replay_nonminimal = nonminimal_header_major(&canonical_replay);
    let mut replay_trailing = canonical_replay;
    replay_trailing.push(0);
    let oversized_replay = vec![0; visa_local_rpc::MAX_REPLAY_RECORD_BYTES + 1];

    let mut replay = replay_seed;
    *replay.response_bytes.last_mut().expect("response bytes are nonempty") ^= 1;
    let mutated_replay = postcard::to_allocvec(&replay).map_err(contract)?;

    let receipt_key = handoff_key(0x2b60);
    let receipt_request =
        decision_request(request_id(0x2b61), caller, OperationKind::Reserve, receipt_key, 0, false);
    let receipt_response = wire::Response::new(
        &receipt_request,
        server,
        wire::Outcome::Success(wire::Success::Reserved(receipt_for_handoff(
            ReceiptKindWire::PrepareIntent,
            receipt_key.handoff,
            0x2b62,
        ))),
    )
    .map_err(contract)?;
    let mut digest_mismatch = receipt_response.clone();
    let wire::Outcome::Success(wire::Success::Reserved(artifact)) = &mut digest_mismatch.outcome
    else {
        unreachable!("fixture constructs Reserved receipt")
    };
    artifact.reference.digest = digest("wrong-neutral-receipt-digest");
    let receipt_digest_mismatch = postcard::to_allocvec(&digest_mismatch).map_err(contract)?;

    let mut schema_substitution = receipt_response.clone();
    let wire::Outcome::Success(wire::Success::Reserved(artifact)) =
        &mut schema_substitution.outcome
    else {
        unreachable!("fixture constructs Reserved receipt")
    };
    artifact.payload.schema = ReceiptKindWire::OwnershipCommit.payload_schema();
    let receipt_schema_substitution =
        postcard::to_allocvec(&schema_substitution).map_err(contract)?;

    let mut kind_substitution = receipt_response;
    let wire::Outcome::Success(wire::Success::Reserved(artifact)) = &mut kind_substitution.outcome
    else {
        unreachable!("fixture constructs Reserved receipt")
    };
    artifact.reference.kind = ReceiptKindWire::NexusFreeze;
    let receipt_kind_substitution = postcard::to_allocvec(&kind_substitution).map_err(contract)?;

    let mismatched_response = wire::Response {
        header: visa_local_rpc::common::WireHeader::new(wire::FAMILY_ID),
        request_id: initialize.request_id,
        request_digest: initialize.digest().map_err(contract)?,
        server,
        outcome: wire::Outcome::Success(wire::Success::Reserved(receipt(
            ReceiptKindWire::PrepareIntent,
            0x2b50,
        ))),
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
        replay_wrong_family,
        replay_nonminimal,
        replay_trailing,
        oversized_replay,
        receipt_digest_mismatch,
        receipt_schema_substitution,
        receipt_kind_substitution,
        invalid_payload_digest,
        mutated_replay,
        initialize,
        receipt_request,
        mismatched_response,
    })
}

fn add_negative_records(builder: &mut CorpusBuilder) -> Result<(), GoldenCorpusError> {
    let vectors = negative_vectors()?;
    for (case_id, mutation, target, expected, bytes) in [
        (
            "ownership-negative-wrong-family",
            "replace-family-id-with-agent-control",
            "ownership::Request",
            "Invalid.WrongFamily",
            vectors.wrong_family,
        ),
        (
            "ownership-negative-nonminimal-varint",
            "encode-header-major-one-as-u16-marker",
            "ownership::Request",
            "NonCanonical",
            vectors.nonminimal,
        ),
        (
            "ownership-negative-trailing-byte",
            "append-zero-byte",
            "ownership::Request",
            "TrailingBytes",
            vectors.trailing,
        ),
        (
            "ownership-negative-unknown-operation",
            "replace-operation-discriminant",
            "ownership::Request",
            "Codec",
            vectors.unknown_discriminant,
        ),
        (
            "ownership-negative-proposal-digest",
            "replace-canonical-payload-digest",
            "ownership::Request",
            "Invalid.InvalidDigest",
            vectors.invalid_payload_digest,
        ),
        (
            "ownership-negative-response-wrong-family",
            "replace-response-family-id-with-agent-control",
            "ownership::Response",
            "Invalid.WrongFamily",
            vectors.response_wrong_family,
        ),
        (
            "ownership-negative-response-nonminimal-varint",
            "encode-response-header-major-one-as-nonminimal-varint",
            "ownership::Response",
            "NonCanonical",
            vectors.response_nonminimal,
        ),
        (
            "ownership-negative-response-trailing-byte",
            "append-zero-byte-after-response",
            "ownership::Response",
            "TrailingBytes",
            vectors.response_trailing,
        ),
        (
            "ownership-negative-response-unknown-outcome",
            "replace-response-outcome-discriminant",
            "ownership::Response",
            "Codec",
            vectors.response_unknown_discriminant,
        ),
        (
            "ownership-negative-replay-wrong-family",
            "replace-replay-family-id-with-agent-control",
            "ownership::ReplayRecord",
            "Invalid.WrongFamily",
            vectors.replay_wrong_family,
        ),
        (
            "ownership-negative-replay-nonminimal-varint",
            "encode-replay-header-major-one-as-nonminimal-varint",
            "ownership::ReplayRecord",
            "NonCanonical",
            vectors.replay_nonminimal,
        ),
        (
            "ownership-negative-replay-trailing-byte",
            "append-zero-byte-after-replay",
            "ownership::ReplayRecord",
            "TrailingBytes",
            vectors.replay_trailing,
        ),
        (
            "ownership-negative-receipt-digest-mismatch",
            "replace-neutral-receipt-reference-digest",
            "ownership::ReceiptArtifact",
            "Invalid.InvalidDigest",
            vectors.receipt_digest_mismatch,
        ),
        (
            "ownership-negative-receipt-schema-substitution",
            "replace-receipt-payload-schema-with-another-kind",
            "ownership::ReceiptArtifact",
            "Invalid.UnsupportedVersion",
            vectors.receipt_schema_substitution,
        ),
        (
            "ownership-negative-receipt-kind-substitution",
            "replace-receipt-reference-kind-without-payload",
            "ownership::ReceiptArtifact",
            "Invalid.UnsupportedVersion",
            vectors.receipt_kind_substitution,
        ),
        (
            "ownership-negative-mutated-replay",
            "flip-stored-response-byte-without-updating-digest",
            "ownership::ReplayRecord",
            "Invalid.InvalidArtifact",
            vectors.mutated_replay,
        ),
    ] {
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
    builder.push_negative(
        "ownership-negative-request-over-cap",
        "zero-byte-repeat-1048577",
        "ownership::Request",
        "TooLargeBeforeDecode",
        None,
        vectors.oversized.len(),
        hex_digest(&vectors.oversized),
    );
    for (case_id, mutation, target, bytes) in [
        (
            "ownership-negative-response-over-cap",
            "zero-byte-repeat-1048577",
            "ownership::Response",
            &vectors.oversized_response,
        ),
        (
            "ownership-negative-replay-over-cap",
            "zero-byte-repeat-max-replay-plus-one",
            "ownership::ReplayRecord",
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
    let mismatch_bytes = postcard::to_allocvec(&vectors.mismatched_response).map_err(contract)?;
    builder.push_negative(
        "ownership-negative-operation-response-mismatch",
        "initialize-request-with-reserved-response",
        "ownership::decode_response_for",
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
            "ownership::Operation",
            &["Abort", "Commit", "InitializeUnit", "Query", "Reserve", "Seal"][..],
        ),
        ("ownership::Outcome", &["Internal", "Rejected", "Success", "Unknown"][..]),
        (
            "ownership::Success",
            &["Aborted", "Committed", "Initialized", "Prepared", "Query", "Reserved"][..],
        ),
        ("ownership::QueryRequest", &["Handoff", "Unit"][..]),
        (
            "ownership::QueryResult",
            &["AbortDecided", "CommitDecided", "Missing", "Prepared", "Reserved", "Unit"][..],
        ),
        (
            "ownership::Rejection",
            &[
                "Busy",
                "Conflict",
                "ExistingAbort",
                "ExistingCommit",
                "Integrity",
                "InvalidRequest",
                "NotFound",
                "OwnershipMismatch",
                "StaleSequence",
            ][..],
        ),
        ("common::AgentRole", &["Destination", "Source"][..]),
        ("common::AuthorityRole", &["Ownership"][..]),
        (
            "common::ReceiptKindWire",
            &[
                "Closure",
                "ClosureProgress",
                "DestinationPrepared",
                "NexusFreeze",
                "NexusThaw",
                "OwnershipAbort",
                "OwnershipCommit",
                "OwnershipPrepared",
                "PrepareIntent",
                "RetainedTombstone",
                "VisaDestinationActivation",
                "VisaFreeze",
                "VisaSourceFence",
                "VisaSourceResume",
            ][..],
        ),
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
    GoldenCorpusError::Contract(format!("ownership corpus construction failed: {error:?}"))
}
