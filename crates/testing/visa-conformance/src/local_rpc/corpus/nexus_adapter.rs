use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};
use visa_local_rpc::{
    DecodeError, MAX_INNER_REQUEST_BYTES, MAX_INNER_RESPONSE_BYTES, MAX_REPLAY_RECORD_BYTES,
    WireValidation, WireValidationError, agent_control,
    common::{
        AgentRole, AuthorityRole, AuthorityServiceBinding, GrantId, IdempotencyId, ReceiptKindWire,
        RegistryInstanceId, ServiceIncarnation,
    },
    nexus_adapter::{
        self, CLOSE_SCHEMA, COMMIT_SCHEMA, COMPLETE_SCHEMA, DispatchCommitRequest, DispatchGrant,
        EffectIdentity, EffectInvocation, EffectPhase, EffectState, FAMILY_ID, FREEZE_SCHEMA,
        GOLDEN_CORPUS_ID, JointInvocation, Operation, Outcome, PREPARE_SCHEMA, ProviderDescriptor,
        QueryRequest, QueryResult, REGISTER_SCHEMA, REPLAY_NAMESPACE, Rejection, ReplayRecord,
        Request, Response, SCHEMA, Success, THAW_SCHEMA, Unknown,
    },
};

use super::{
    GoldenCorpusError,
    fixtures::{
        Context, all_receipt_kinds, digest, handoff_key, internal_failure, operation_id, payload,
        payload_with_len, receipt, receipt_for_handoff, receipt_kind_name, registry, request_id,
    },
    model::{CorpusBuilder, GoldenCorpus, WireDirection, hex_digest},
};

const MAX_CANONICAL_PAYLOAD_BYTES: usize = 65_536;
const OPERATION_VARIANT_COUNT: u8 = 10;
const OUTCOME_VARIANT_COUNT: u8 = 4;

pub(super) fn build() -> Result<GoldenCorpus, GoldenCorpusError> {
    let mut builder = CorpusBuilder::new(GOLDEN_CORPUS_ID, SCHEMA, FAMILY_ID);

    let descriptor_request = request(100, AgentRole::Source, Operation::Descriptor);
    let descriptor = ProviderDescriptor {
        provider_protocol_major: 2,
        provider_protocol_minor: 1,
        native_wire_major: 1,
        registry_instance: registry(101),
        provider_identity_digest: digest("nexus-provider-identity"),
        maximum_native_request_bytes: MAX_CANONICAL_PAYLOAD_BYTES as u32,
    };
    let (descriptor_request, descriptor_response) = push_exchange(
        &mut builder,
        "descriptor",
        descriptor_request,
        Outcome::Success(Success::Descriptor(descriptor)),
        "Operation::Descriptor",
        "Outcome::Success(Success::Descriptor)",
        &[("Operation", "Descriptor"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Descriptor")],
    )?;

    let registered_effect = effect(200);
    push_exchange(
        &mut builder,
        "register-initial-revision",
        request(
            200,
            AgentRole::Source,
            Operation::Register(effect_invocation(
                registered_effect,
                0,
                REGISTER_SCHEMA,
                "register-initial",
            )),
        ),
        Outcome::Success(Success::Registered(effect_state(
            registered_effect,
            EffectPhase::Registered,
            1,
            "registered",
        ))),
        "Operation::Register",
        "Outcome::Success(Success::Registered)",
        &[("Operation", "Register"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Registered"), ("EffectPhase", "Registered")],
    )?;

    let prepared_effect = effect(300);
    push_exchange(
        &mut builder,
        "prepare",
        request(
            300,
            AgentRole::Destination,
            Operation::Prepare(effect_invocation(prepared_effect, 1, PREPARE_SCHEMA, "prepare")),
        ),
        Outcome::Success(Success::Prepared(effect_state(
            prepared_effect,
            EffectPhase::Prepared,
            2,
            "prepared",
        ))),
        "Operation::Prepare",
        "Outcome::Success(Success::Prepared)",
        &[("Operation", "Prepare"), ("AgentRole", "Destination")],
        &[("Outcome", "Success"), ("Success", "Prepared"), ("EffectPhase", "Prepared")],
    )?;

    let committed_effect = effect(400);
    let commit_request = request(
        400,
        AgentRole::Source,
        Operation::CommitAndAuthorizeDispatch(DispatchCommitRequest {
            effect: committed_effect,
            expected_provider_revision: 2,
            expected_projection_digest: digest("commit-projection"),
            invocation: payload(COMMIT_SCHEMA, "commit-and-authorize"),
        }),
    );
    let dispatch_grant = grant_for(&commit_request, 401)?;
    push_exchange(
        &mut builder,
        "commit-and-authorize-dispatch",
        commit_request,
        Outcome::Success(Success::DispatchAuthorized(dispatch_grant)),
        "Operation::CommitAndAuthorizeDispatch",
        "Outcome::Success(Success::DispatchAuthorized)",
        &[("Operation", "CommitAndAuthorizeDispatch"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "DispatchAuthorized"), ("AgentRole", "Source")],
    )?;

    let outcome_effect = effect(500);
    push_exchange(
        &mut builder,
        "record-outcome",
        request(
            500,
            AgentRole::Destination,
            Operation::RecordOutcome(effect_invocation(
                outcome_effect,
                3,
                nexus_adapter::OUTCOME_SCHEMA,
                "record-outcome",
            )),
        ),
        Outcome::Success(Success::OutcomeRecorded(effect_state(
            outcome_effect,
            EffectPhase::OutcomeRecorded,
            4,
            "outcome-recorded",
        ))),
        "Operation::RecordOutcome",
        "Outcome::Success(Success::OutcomeRecorded)",
        &[("Operation", "RecordOutcome"), ("AgentRole", "Destination")],
        &[
            ("Outcome", "Success"),
            ("Success", "OutcomeRecorded"),
            ("EffectPhase", "OutcomeRecorded"),
        ],
    )?;

    let completed_effect = effect(600);
    push_exchange(
        &mut builder,
        "complete",
        request(
            600,
            AgentRole::Source,
            Operation::Complete(effect_invocation(
                completed_effect,
                4,
                COMPLETE_SCHEMA,
                "complete",
            )),
        ),
        Outcome::Success(Success::Completed(effect_state(
            completed_effect,
            EffectPhase::Completed,
            5,
            "completed",
        ))),
        "Operation::Complete",
        "Outcome::Success(Success::Completed)",
        &[("Operation", "Complete"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Completed"), ("EffectPhase", "Completed")],
    )?;

    let freeze_request = request(
        700,
        AgentRole::Source,
        Operation::Freeze(joint_invocation(700, 5, FREEZE_SCHEMA, "freeze")),
    );
    let freeze_receipt = receipt_for_joint(&freeze_request, ReceiptKindWire::NexusFreeze, 700)?;
    push_exchange(
        &mut builder,
        "freeze",
        freeze_request,
        Outcome::Success(Success::Frozen(freeze_receipt)),
        "Operation::Freeze",
        "Outcome::Success(Success::Frozen)",
        &[("Operation", "Freeze"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Frozen"), ("ReceiptKindWire", "NexusFreeze")],
    )?;

    let thaw_request = request(
        800,
        AgentRole::Destination,
        Operation::Thaw(joint_invocation(800, 6, THAW_SCHEMA, "thaw")),
    );
    let thaw_receipt = receipt_for_joint(&thaw_request, ReceiptKindWire::NexusThaw, 800)?;
    push_exchange(
        &mut builder,
        "thaw",
        thaw_request,
        Outcome::Success(Success::Thawed(thaw_receipt)),
        "Operation::Thaw",
        "Outcome::Success(Success::Thawed)",
        &[("Operation", "Thaw"), ("AgentRole", "Destination")],
        &[("Outcome", "Success"), ("Success", "Thawed"), ("ReceiptKindWire", "NexusThaw")],
    )?;

    let close_request = request(
        900,
        AgentRole::Source,
        Operation::CloseStep(joint_invocation(900, 7, CLOSE_SCHEMA, "close-step")),
    );
    let close_receipt = receipt_for_joint(&close_request, ReceiptKindWire::Closure, 900)?;
    push_exchange(
        &mut builder,
        "close-step",
        close_request,
        Outcome::Success(Success::Closed(close_receipt)),
        "Operation::CloseStep",
        "Outcome::Success(Success::Closed)",
        &[("Operation", "CloseStep"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Closed"), ("ReceiptKindWire", "Closure")],
    )?;

    push_exchange(
        &mut builder,
        "query-effect-missing",
        request(1_000, AgentRole::Source, Operation::Query(QueryRequest::Effect(effect(1_000)))),
        Outcome::Success(Success::Query(QueryResult::Missing)),
        "Operation::Query(QueryRequest::Effect)",
        "Outcome::Success(Success::Query(QueryResult::Missing))",
        &[("Operation", "Query"), ("QueryRequest", "Effect"), ("AgentRole", "Source")],
        &[("Outcome", "Success"), ("Success", "Query"), ("QueryResult", "Missing")],
    )?;

    let pending_query_effect = effect(1_050);
    push_exchange(
        &mut builder,
        "query-effect-unknown",
        request(
            1_050,
            AgentRole::Source,
            Operation::Query(QueryRequest::Effect(pending_query_effect)),
        ),
        Outcome::Unknown(Unknown {
            query: QueryRequest::Effect(pending_query_effect),
            last_known_provider_revision: 7,
        }),
        "Operation::Query(QueryRequest::Effect)",
        "Outcome::Unknown",
        &[("Operation", "Query"), ("QueryRequest", "Effect"), ("AgentRole", "Source")],
        &[("Outcome", "Unknown")],
    )?;

    for (index, kind) in all_receipt_kinds().into_iter().enumerate() {
        let kind_name = receipt_kind_name(kind);
        let seed = 1_100 + index as u128 * 10;
        let handoff = receipt(kind, seed).reference.handoff;
        push_exchange(
            &mut builder,
            &format!("query-joint-receipt-{}", kebab(kind_name)),
            request(
                seed,
                if index % 2 == 0 { AgentRole::Source } else { AgentRole::Destination },
                Operation::Query(QueryRequest::Joint(handoff)),
            ),
            Outcome::Success(Success::Query(QueryResult::Joint(receipt(kind, seed)))),
            "Operation::Query(QueryRequest::Joint)",
            "Outcome::Success(Success::Query(QueryResult::Joint))",
            &[("Operation", "Query"), ("QueryRequest", "Joint")],
            &[
                ("Outcome", "Success"),
                ("Success", "Query"),
                ("QueryResult", "Joint"),
                ("ReceiptKindWire", kind_name),
            ],
        )?;
    }

    push_exchange(
        &mut builder,
        "query-grant",
        request(
            1_300,
            AgentRole::Destination,
            Operation::Query(QueryRequest::Grant(dispatch_grant.grant)),
        ),
        Outcome::Success(Success::Query(QueryResult::Grant(dispatch_grant))),
        "Operation::Query(QueryRequest::Grant)",
        "Outcome::Success(Success::Query(QueryResult::Grant))",
        &[("Operation", "Query"), ("QueryRequest", "Grant"), ("AgentRole", "Destination")],
        &[
            ("Outcome", "Success"),
            ("Success", "Query"),
            ("QueryResult", "Grant"),
            ("AgentRole", "Source"),
        ],
    )?;

    for (index, phase) in [EffectPhase::Committed, EffectPhase::Dispatched].into_iter().enumerate()
    {
        let phase_name = match phase {
            EffectPhase::Committed => "Committed",
            EffectPhase::Dispatched => "Dispatched",
            _ => unreachable!("loop contains the two remaining effect phases"),
        };
        let seed = 1_400 + index as u128 * 10;
        let query_effect = effect(seed);
        push_exchange(
            &mut builder,
            &format!("query-effect-phase-{}", kebab(phase_name)),
            request(seed, AgentRole::Source, Operation::Query(QueryRequest::Effect(query_effect))),
            Outcome::Success(Success::Query(QueryResult::Effect(effect_state(
                query_effect,
                phase,
                9 + index as u64,
                phase_name,
            )))),
            "Operation::Query(QueryRequest::Effect)",
            "Outcome::Success(Success::Query(QueryResult::Effect))",
            &[("Operation", "Query"), ("QueryRequest", "Effect")],
            &[
                ("Outcome", "Success"),
                ("Success", "Query"),
                ("QueryResult", "Effect"),
                ("EffectPhase", phase_name),
            ],
        )?;
    }

    for (index, (name, rejection)) in rejections().into_iter().enumerate() {
        let seed = 1_500 + index as u128 * 10;
        push_exchange(
            &mut builder,
            &format!("rejected-{}", kebab(name)),
            request(seed, AgentRole::Source, Operation::Descriptor),
            Outcome::Rejected(rejection),
            "Operation::Descriptor",
            &format!("Outcome::Rejected(Rejection::{name})"),
            &[("Operation", "Descriptor")],
            &[("Outcome", "Rejected"), ("Rejection", name)],
        )?;
    }

    let unknown_effect = effect(1_700);
    push_exchange(
        &mut builder,
        "unknown-effect-zero-last-known-revision",
        request(
            1_700,
            AgentRole::Destination,
            Operation::Register(effect_invocation(
                unknown_effect,
                0,
                REGISTER_SCHEMA,
                "unknown-register",
            )),
        ),
        Outcome::Unknown(Unknown {
            query: QueryRequest::Effect(unknown_effect),
            last_known_provider_revision: 0,
        }),
        "Operation::Register",
        "Outcome::Unknown",
        &[("Operation", "Register"), ("QueryRequest", "Effect"), ("AgentRole", "Destination")],
        &[("Outcome", "Unknown")],
    )?;

    push_exchange(
        &mut builder,
        "internal-retryable",
        request(1_800, AgentRole::Source, Operation::Descriptor),
        Outcome::Internal(internal_failure(1_800)),
        "Operation::Descriptor",
        "Outcome::Internal(retryable)",
        &[("Operation", "Descriptor")],
        &[("Outcome", "Internal"), ("InternalFailure", "Retryable")],
    )?;

    let replay = ReplayRecord::from_exchange(&descriptor_request, &descriptor_response)
        .map_err(|error| contract("construct descriptor replay", error))?;
    replay.validate().map_err(|error| contract("validate descriptor replay", error))?;
    let replay_bytes = nexus_adapter::encode_replay(&replay)
        .map_err(|error| contract("encode descriptor replay", error))?;
    let decoded_replay = nexus_adapter::decode_replay(&replay_bytes)
        .map_err(|error| contract("decode descriptor replay", error))?;
    decoded_replay
        .validate()
        .map_err(|error| contract("validate decoded descriptor replay", error))?;
    let (replay_request, replay_response) = decoded_replay
        .exchange()
        .map_err(|error| contract("decode exchange from descriptor replay", error))?;
    if replay_request != descriptor_request || replay_response != descriptor_response {
        return Err(GoldenCorpusError::Contract(
            "Nexus descriptor replay did not preserve its typed exchange".to_owned(),
        ));
    }
    let reencoded_replay_request = nexus_adapter::encode_request(&replay_request)
        .map_err(|error| contract("re-encode request from descriptor replay", error))?;
    let reencoded_replay_response =
        nexus_adapter::encode_response_for(&replay_request, &replay_response)
            .map_err(|error| contract("re-encode response from descriptor replay", error))?;
    if reencoded_replay_request != decoded_replay.request_bytes
        || reencoded_replay_response != decoded_replay.response_bytes
    {
        return Err(GoldenCorpusError::Contract(
            "Nexus replay embedded exchange did not preserve exact canonical bytes".to_owned(),
        ));
    }
    if decoded_replay != replay {
        return Err(GoldenCorpusError::Contract(
            "Nexus descriptor replay changed across its canonical round trip".to_owned(),
        ));
    }
    let reencoded_replay = nexus_adapter::encode_replay(&decoded_replay)
        .map_err(|error| contract("re-encode descriptor replay", error))?;
    if reencoded_replay != replay_bytes {
        return Err(GoldenCorpusError::Contract(
            "Nexus descriptor replay did not preserve exact canonical bytes".to_owned(),
        ));
    }
    builder.push(
        "nexus-replay-descriptor",
        WireDirection::Replay,
        format!("ReplayRecord({REPLAY_NAMESPACE})"),
        replay_bytes,
        &[("ReplayRecord", "Exchange")],
    );

    let maximum_payload_request = request(
        1_900,
        AgentRole::Source,
        Operation::Register(EffectInvocation {
            effect: effect(1_900),
            expected_provider_revision: 0,
            invocation: payload_with_len(REGISTER_SCHEMA, MAX_CANONICAL_PAYLOAD_BYTES),
        }),
    );
    push_request(
        &mut builder,
        "nexus-request-register-maximum-canonical-payload",
        "Operation::Register(maximum-canonical-payload)",
        maximum_payload_request,
        &[("Operation", "Register"), ("Boundary", "MaximumCanonicalPayload")],
    )?;

    for negative in negative_vectors()? {
        builder.push_negative(
            negative.case_id,
            negative.mutation,
            negative.target,
            negative.expected_rejection,
            negative.bytes,
            negative.byte_length,
            negative.sha256,
        );
    }

    let corpus = builder.finish()?;
    verify_required_coverage(&corpus)?;
    Ok(corpus)
}

pub(super) fn verify_negative_contracts() -> Result<(), GoldenCorpusError> {
    let vectors = negative_vectors()?;
    if vectors.len() != 22 {
        return Err(GoldenCorpusError::Contract(format!(
            "Nexus executable negative suite has {} cases instead of 22",
            vectors.len()
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_exchange(
    builder: &mut CorpusBuilder,
    stem: &str,
    request: Request,
    outcome: Outcome,
    request_semantic: &str,
    response_semantic: &str,
    request_coverage: &[(&str, &str)],
    response_coverage: &[(&str, &str)],
) -> Result<(Request, Response), GoldenCorpusError> {
    let request_bytes = checked_request_bytes(&request)?;
    let response = Response::new(&request, server_for(&request, request_seed(stem)), outcome)
        .map_err(|error| contract("construct Nexus response", error))?;
    response
        .validate_for(&request)
        .map_err(|error| contract("validate Nexus response binding", error))?;
    let response_bytes = checked_response_bytes(&request, &response)?;

    builder.push(
        format!("nexus-request-{stem}"),
        WireDirection::Request,
        request_semantic,
        request_bytes,
        request_coverage,
    );
    builder.push(
        format!("nexus-response-{stem}"),
        WireDirection::Response,
        response_semantic,
        response_bytes,
        response_coverage,
    );
    Ok((request, response))
}

fn push_request(
    builder: &mut CorpusBuilder,
    case_id: &str,
    semantic: &str,
    request: Request,
    coverage: &[(&str, &str)],
) -> Result<(), GoldenCorpusError> {
    let bytes = checked_request_bytes(&request)?;
    builder.push(case_id, WireDirection::Request, semantic, bytes, coverage);
    Ok(())
}

fn checked_request_bytes(request: &Request) -> Result<Vec<u8>, GoldenCorpusError> {
    request.validate().map_err(|error| contract("validate Nexus request", error))?;
    let bytes = nexus_adapter::encode_request(request)
        .map_err(|error| contract("encode Nexus request", error))?;
    let decoded = nexus_adapter::decode_request(&bytes)
        .map_err(|error| contract("decode Nexus request", error))?;
    if decoded != *request {
        return Err(GoldenCorpusError::Contract(
            "Nexus request changed across its canonical round trip".to_owned(),
        ));
    }
    decoded.validate().map_err(|error| contract("validate decoded Nexus request", error))?;
    let reencoded = nexus_adapter::encode_request(&decoded)
        .map_err(|error| contract("re-encode Nexus request", error))?;
    if reencoded != bytes {
        return Err(GoldenCorpusError::Contract(
            "Nexus request did not preserve exact canonical bytes".to_owned(),
        ));
    }
    Ok(bytes)
}

fn checked_response_bytes(
    request: &Request,
    response: &Response,
) -> Result<Vec<u8>, GoldenCorpusError> {
    response.validate_for(request).map_err(|error| contract("validate Nexus response", error))?;
    let bytes = nexus_adapter::encode_response_for(request, response)
        .map_err(|error| contract("encode Nexus response", error))?;
    let decoded = nexus_adapter::decode_response_for(request, &bytes)
        .map_err(|error| contract("decode Nexus response", error))?;
    decoded
        .validate_for(request)
        .map_err(|error| contract("validate decoded Nexus response", error))?;
    if decoded != *response {
        return Err(GoldenCorpusError::Contract(
            "Nexus response changed across its canonical round trip".to_owned(),
        ));
    }
    let reencoded = nexus_adapter::encode_response_for(request, &decoded)
        .map_err(|error| contract("re-encode Nexus response", error))?;
    if reencoded != bytes {
        return Err(GoldenCorpusError::Contract(
            "Nexus response did not preserve exact canonical bytes".to_owned(),
        ));
    }
    Ok(bytes)
}

fn request(seed: u128, role: AgentRole, operation: Operation) -> Request {
    let context = Context::new(seed * 100);
    Request::new(request_id(seed), context.agent(role, seed * 100 + 10), operation)
}

fn server_for(request: &Request, seed: u128) -> AuthorityServiceBinding {
    AuthorityServiceBinding {
        product_version: request.caller.product_version,
        cohort: request.caller.cohort,
        boot: request.caller.boot,
        runtime_session: request.caller.runtime_session,
        role: AuthorityRole::NexusAdapter,
        service_incarnation: ServiceIncarnation::from_u128(seed + 1),
        process_nonce: visa_local_rpc::common::ProcessNonce::from_u128(seed + 2),
        process_generation: 1,
    }
}

fn request_seed(stem: &str) -> u128 {
    let digest = Sha256::digest(stem.as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix is 8 bytes")) as u128 + 1
}

fn effect(seed: u128) -> EffectIdentity {
    EffectIdentity {
        operation: operation_id(seed + 1),
        idempotency: IdempotencyId::from_u128(seed + 2),
    }
}

fn effect_invocation(
    effect: EffectIdentity,
    expected_provider_revision: u64,
    schema: [u8; 16],
    label: &str,
) -> EffectInvocation {
    EffectInvocation { effect, expected_provider_revision, invocation: payload(schema, label) }
}

fn joint_invocation(
    seed: u128,
    expected_provider_revision: u64,
    schema: [u8; 16],
    label: &str,
) -> JointInvocation {
    JointInvocation {
        key: handoff_key(seed),
        operation: operation_id(seed + 10),
        expected_provider_revision,
        invocation: payload(schema, label),
    }
}

fn effect_state(
    effect: EffectIdentity,
    phase: EffectPhase,
    provider_revision: u64,
    label: &str,
) -> EffectState {
    EffectState {
        effect,
        phase,
        provider_revision,
        native_request_digest: digest(&format!("{label}-native-request")),
        native_receipt_digest: digest(&format!("{label}-native-receipt")),
    }
}

fn grant_for(request: &Request, seed: u128) -> Result<DispatchGrant, GoldenCorpusError> {
    let Operation::CommitAndAuthorizeDispatch(commit) = &request.operation else {
        return Err(GoldenCorpusError::Contract(
            "dispatch grant fixture requires a commit-and-authorize request".to_owned(),
        ));
    };
    Ok(DispatchGrant {
        grant: GrantId::from_u128(seed + 1),
        registry_instance: RegistryInstanceId::from_u128(seed + 2),
        effect: commit.effect,
        role: request.caller.role,
        logical_incarnation: request.caller.logical_incarnation,
        cohort: request.caller.cohort,
        boot: request.caller.boot,
        projection_digest: commit.expected_projection_digest,
        native_request_digest: digest("dispatch-native-request"),
        native_receipt_digest: digest("dispatch-native-receipt"),
        grant_sequence: 1,
    })
}

fn receipt_for_joint(
    request: &Request,
    kind: ReceiptKindWire,
    seed: u128,
) -> Result<visa_local_rpc::common::ReceiptArtifact, GoldenCorpusError> {
    let handoff = match &request.operation {
        Operation::Freeze(invocation)
        | Operation::Thaw(invocation)
        | Operation::CloseStep(invocation) => invocation.key.handoff,
        _ => {
            return Err(GoldenCorpusError::Contract(
                "joint receipt fixture requires Freeze, Thaw, or CloseStep".to_owned(),
            ));
        }
    };
    Ok(receipt_for_handoff(kind, handoff, seed))
}

fn rejections() -> Vec<(&'static str, Rejection)> {
    vec![
        ("InvalidRequest", Rejection::InvalidRequest),
        ("NotFound", Rejection::NotFound),
        ("Conflict", Rejection::Conflict),
        ("Busy", Rejection::Busy),
        ("StaleProviderRevision", Rejection::StaleProviderRevision { expected: 7, actual: 9 }),
        (
            "StaleProjection",
            Rejection::StaleProjection {
                expected: digest("stale-projection-expected"),
                actual: digest("stale-projection-actual"),
            },
        ),
        ("FenceClosed", Rejection::FenceClosed),
        ("GrantConsumed", Rejection::GrantConsumed),
        ("RegistryLost", Rejection::RegistryLost),
        ("Unsupported", Rejection::Unsupported),
        ("Integrity", Rejection::Integrity),
    ]
}

fn verify_required_coverage(corpus: &GoldenCorpus) -> Result<(), GoldenCorpusError> {
    for (type_name, expected) in [
        (
            "Operation",
            &[
                "Descriptor",
                "Register",
                "Prepare",
                "CommitAndAuthorizeDispatch",
                "RecordOutcome",
                "Complete",
                "Freeze",
                "Thaw",
                "CloseStep",
                "Query",
            ][..],
        ),
        (
            "Success",
            &[
                "Descriptor",
                "Registered",
                "Prepared",
                "DispatchAuthorized",
                "OutcomeRecorded",
                "Completed",
                "Frozen",
                "Thawed",
                "Closed",
                "Query",
            ][..],
        ),
        (
            "Rejection",
            &[
                "InvalidRequest",
                "NotFound",
                "Conflict",
                "Busy",
                "StaleProviderRevision",
                "StaleProjection",
                "FenceClosed",
                "GrantConsumed",
                "RegistryLost",
                "Unsupported",
                "Integrity",
            ][..],
        ),
        ("QueryRequest", &["Effect", "Joint", "Grant"][..]),
        ("QueryResult", &["Missing", "Effect", "Grant", "Joint"][..]),
        (
            "EffectPhase",
            &["Registered", "Prepared", "Committed", "Dispatched", "OutcomeRecorded", "Completed"]
                [..],
        ),
        ("AgentRole", &["Source", "Destination"][..]),
        (
            "ReceiptKindWire",
            &[
                "PrepareIntent",
                "VisaFreeze",
                "NexusFreeze",
                "DestinationPrepared",
                "OwnershipPrepared",
                "OwnershipAbort",
                "OwnershipCommit",
                "NexusThaw",
                "ClosureProgress",
                "Closure",
                "RetainedTombstone",
                "VisaSourceFence",
                "VisaSourceResume",
                "VisaDestinationActivation",
            ][..],
        ),
        ("Outcome", &["Success", "Rejected", "Unknown", "Internal"][..]),
        ("ReplayRecord", &["Exchange"][..]),
    ] {
        let actual =
            corpus.coverage.iter().find(|coverage| coverage.type_name == type_name).ok_or_else(
                || {
                    GoldenCorpusError::Contract(format!(
                        "Nexus corpus omits required {type_name} coverage"
                    ))
                },
            )?;
        let actual: BTreeSet<_> = actual.variants.iter().map(String::as_str).collect();
        let expected: BTreeSet<_> = expected.iter().copied().collect();
        if actual != expected {
            return Err(GoldenCorpusError::Contract(format!(
                "Nexus corpus {type_name} coverage is {actual:?}, expected {expected:?}"
            )));
        }
    }
    Ok(())
}

fn kebab(name: &str) -> String {
    let mut output = String::with_capacity(name.len() + 4);
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            output.push('-');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

struct NegativeVector {
    case_id: &'static str,
    mutation: &'static str,
    target: &'static str,
    expected_rejection: &'static str,
    bytes: Option<Vec<u8>>,
    byte_length: usize,
    sha256: String,
}

fn negative_vectors() -> Result<Vec<NegativeVector>, GoldenCorpusError> {
    let descriptor_request = request(10_000, AgentRole::Source, Operation::Descriptor);
    let canonical_descriptor = checked_request_bytes(&descriptor_request)?;

    let mut wrong_family = descriptor_request.clone();
    wrong_family.header.family = agent_control::FAMILY_ID;
    let wrong_family_bytes = raw_bytes(&wrong_family, "serialize wrong-family request")?;
    expect_request_decode(
        &wrong_family_bytes,
        Err(DecodeError::Invalid(WireValidationError::WrongFamily)),
        "wrong-family substitution",
    )?;

    let nonminimal_major = nonminimal_header_major(&canonical_descriptor)?;
    expect_request_decode(
        &nonminimal_major,
        Err(DecodeError::NonCanonical),
        "non-minimal header major",
    )?;

    let mut trailing = canonical_descriptor.clone();
    trailing.push(0);
    expect_request_decode(&trailing, Err(DecodeError::TrailingBytes), "trailing request byte")?;

    let mut unknown_operation = canonical_descriptor.clone();
    let operation_tag = unknown_operation.last_mut().ok_or_else(|| {
        GoldenCorpusError::Contract("canonical descriptor request is empty".to_owned())
    })?;
    if *operation_tag != 0 {
        return Err(GoldenCorpusError::Contract(
            "descriptor operation is no longer the final zero postcard discriminant".to_owned(),
        ));
    }
    *operation_tag = OPERATION_VARIANT_COUNT;
    expect_request_decode(
        &unknown_operation,
        Err(DecodeError::Codec),
        "unknown operation discriminant",
    )?;

    let over_limit = vec![0; MAX_INNER_REQUEST_BYTES + 1];
    expect_request_decode(&over_limit, Err(DecodeError::TooLarge), "request predecode size limit")?;

    let descriptor_response = Response::new(
        &descriptor_request,
        server_for(&descriptor_request, 10_050),
        Outcome::Success(Success::Descriptor(ProviderDescriptor {
            provider_protocol_major: 2,
            provider_protocol_minor: 1,
            native_wire_major: 1,
            registry_instance: registry(10_050),
            provider_identity_digest: digest("negative-response-provider"),
            maximum_native_request_bytes: MAX_CANONICAL_PAYLOAD_BYTES as u32,
        })),
    )
    .map_err(|error| contract("construct response-negative seed", error))?;
    descriptor_response
        .validate_for(&descriptor_request)
        .map_err(|error| contract("validate response-negative seed", error))?;
    let canonical_descriptor_response =
        nexus_adapter::encode_response_for(&descriptor_request, &descriptor_response)
            .map_err(|error| contract("encode response-negative seed", error))?;

    let mut response_wrong_family = descriptor_response.clone();
    response_wrong_family.header.family = agent_control::FAMILY_ID;
    let response_wrong_family_bytes =
        raw_bytes(&response_wrong_family, "serialize wrong-family response")?;
    expect_paired_response_decode(
        &descriptor_request,
        &response_wrong_family_bytes,
        Err(DecodeError::Invalid(WireValidationError::WrongFamily)),
        "response wrong-family substitution",
    )?;

    let response_nonminimal_major = nonminimal_header_major(&canonical_descriptor_response)?;
    expect_paired_response_decode(
        &descriptor_request,
        &response_nonminimal_major,
        Err(DecodeError::NonCanonical),
        "response non-minimal header major",
    )?;

    let mut response_trailing = canonical_descriptor_response.clone();
    response_trailing.push(0);
    expect_paired_response_decode(
        &descriptor_request,
        &response_trailing,
        Err(DecodeError::TrailingBytes),
        "response trailing byte",
    )?;

    let response_prefix = postcard::to_allocvec(&(
        descriptor_response.header,
        descriptor_response.request_id,
        descriptor_response.request_digest,
        descriptor_response.server,
    ))
    .map_err(|error| contract("encode response prefix", error))?;
    let mut response_unknown_outcome = canonical_descriptor_response.clone();
    let outcome_tag = response_unknown_outcome.get_mut(response_prefix.len()).ok_or_else(|| {
        GoldenCorpusError::Contract(
            "canonical descriptor response has no Outcome discriminant".to_owned(),
        )
    })?;
    if *outcome_tag != 0 {
        return Err(GoldenCorpusError::Contract(
            "Success is no longer the zero postcard Outcome discriminant".to_owned(),
        ));
    }
    *outcome_tag = OUTCOME_VARIANT_COUNT;
    expect_paired_response_decode(
        &descriptor_request,
        &response_unknown_outcome,
        Err(DecodeError::Codec),
        "response unknown Outcome discriminant",
    )?;

    let response_over_limit = vec![0; MAX_INNER_RESPONSE_BYTES + 1];
    expect_paired_response_decode(
        &descriptor_request,
        &response_over_limit,
        Err(DecodeError::TooLarge),
        "response predecode size limit",
    )?;

    let mismatched_effect = effect(10_100);
    let mut mismatch_response = descriptor_response.clone();
    mismatch_response.outcome = Outcome::Success(Success::Registered(effect_state(
        mismatched_effect,
        EffectPhase::Registered,
        1,
        "mismatched-operation",
    )));
    mismatch_response
        .validate()
        .map_err(|error| contract("validate standalone operation-mismatch response", error))?;
    let mismatch_bytes = raw_bytes(&mismatch_response, "serialize operation-mismatch response")?;
    expect_paired_response_decode(
        &descriptor_request,
        &mismatch_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidBinding)),
        "operation/response mismatch",
    )?;

    let mut payload_mismatch = request(
        10_200,
        AgentRole::Source,
        Operation::Register(effect_invocation(
            effect(10_200),
            0,
            REGISTER_SCHEMA,
            "payload-digest-mismatch",
        )),
    );
    let Operation::Register(invocation) = &mut payload_mismatch.operation else {
        unreachable!("fixture constructs Register")
    };
    invocation.invocation.sha256 = digest("not-the-payload-digest");
    let payload_mismatch_bytes = raw_bytes(&payload_mismatch, "serialize payload mismatch")?;
    expect_request_decode(
        &payload_mismatch_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidDigest)),
        "payload digest mismatch",
    )?;

    let replay_descriptor_response = Response::new(
        &descriptor_request,
        server_for(&descriptor_request, 10_300),
        Outcome::Success(Success::Descriptor(ProviderDescriptor {
            provider_protocol_major: 2,
            provider_protocol_minor: 1,
            native_wire_major: 1,
            registry_instance: registry(10_300),
            provider_identity_digest: digest("negative-provider"),
            maximum_native_request_bytes: MAX_CANONICAL_PAYLOAD_BYTES as u32,
        })),
    )
    .map_err(|error| contract("construct replay seed response", error))?;
    let replay = ReplayRecord::from_exchange(&descriptor_request, &replay_descriptor_response)
        .map_err(|error| contract("construct replay seed", error))?;
    let canonical_replay = nexus_adapter::encode_replay(&replay)
        .map_err(|error| contract("encode replay negative seed", error))?;

    let mut replay_wrong_family = replay.clone();
    replay_wrong_family.header.family = agent_control::FAMILY_ID;
    let replay_wrong_family_bytes =
        raw_bytes(&replay_wrong_family, "serialize wrong-family replay")?;
    expect_replay_decode(
        &replay_wrong_family_bytes,
        Err(DecodeError::Invalid(WireValidationError::WrongFamily)),
        "replay wrong-family substitution",
    )?;

    let replay_nonminimal_major = nonminimal_header_major(&canonical_replay)?;
    expect_replay_decode(
        &replay_nonminimal_major,
        Err(DecodeError::NonCanonical),
        "replay non-minimal header major",
    )?;

    let mut replay_trailing = canonical_replay.clone();
    replay_trailing.push(0);
    expect_replay_decode(
        &replay_trailing,
        Err(DecodeError::TrailingBytes),
        "replay trailing byte",
    )?;

    let replay_over_limit = vec![0; MAX_REPLAY_RECORD_BYTES + 1];
    expect_replay_decode(
        &replay_over_limit,
        Err(DecodeError::TooLarge),
        "replay predecode size limit",
    )?;

    let mut mutated_replay = replay.clone();
    let embedded_operation = mutated_replay
        .request_bytes
        .last_mut()
        .ok_or_else(|| GoldenCorpusError::Contract("replay request bytes are empty".to_owned()))?;
    *embedded_operation = OPERATION_VARIANT_COUNT;
    let mutated_replay_bytes = raw_bytes(&mutated_replay, "serialize mutated replay")?;
    expect_replay_decode(
        &mutated_replay_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidArtifact)),
        "replay embedded request mutation",
    )?;

    let mut conflicting_replay = replay.clone();
    conflicting_replay.request_id = request_id(10_301);
    let conflicting_replay_bytes = raw_bytes(&conflicting_replay, "serialize conflicting replay")?;
    expect_replay_decode(
        &conflicting_replay_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidBinding)),
        "replay request identity conflict",
    )?;

    let mut response_digest_conflict = replay.clone();
    response_digest_conflict.response_digest = digest("conflicting-response-digest");
    let response_digest_conflict_bytes =
        raw_bytes(&response_digest_conflict, "serialize replay response-digest conflict")?;
    expect_replay_decode(
        &response_digest_conflict_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidBinding)),
        "replay response digest conflict",
    )?;

    let receipt_request = request(
        10_400,
        AgentRole::Source,
        Operation::Freeze(joint_invocation(10_400, 1, FREEZE_SCHEMA, "negative-receipt-freeze")),
    );
    let receipt_handoff = match &receipt_request.operation {
        Operation::Freeze(invocation) => invocation.key.handoff,
        _ => unreachable!("receipt negative fixture constructs Freeze"),
    };
    let valid_freeze_response = Response::new(
        &receipt_request,
        server_for(&receipt_request, 10_400),
        Outcome::Success(Success::Frozen(receipt_for_handoff(
            ReceiptKindWire::NexusFreeze,
            receipt_handoff,
            10_400,
        ))),
    )
    .map_err(|error| contract("construct receipt-negative seed response", error))?;

    let mut receipt_digest_mismatch = valid_freeze_response.clone();
    let Outcome::Success(Success::Frozen(digest_mismatch_receipt)) =
        &mut receipt_digest_mismatch.outcome
    else {
        unreachable!("receipt negative fixture contains Frozen success")
    };
    digest_mismatch_receipt.reference.digest = digest("wrong-neutral-reference-digest");
    let receipt_digest_mismatch_bytes = raw_bytes(
        &receipt_digest_mismatch,
        "serialize neutral reference digest mismatch response",
    )?;
    expect_paired_response_decode(
        &receipt_request,
        &receipt_digest_mismatch_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidDigest)),
        "receipt neutral reference digest mismatch",
    )?;

    let mut receipt_payload_schema_substitution = valid_freeze_response.clone();
    let Outcome::Success(Success::Frozen(schema_substitution_receipt)) =
        &mut receipt_payload_schema_substitution.outcome
    else {
        unreachable!("receipt negative fixture contains Frozen success")
    };
    schema_substitution_receipt.payload.schema = ReceiptKindWire::NexusThaw.payload_schema();
    let receipt_payload_schema_substitution_bytes = raw_bytes(
        &receipt_payload_schema_substitution,
        "serialize receipt payload-schema substitution response",
    )?;
    expect_paired_response_decode(
        &receipt_request,
        &receipt_payload_schema_substitution_bytes,
        Err(DecodeError::Invalid(WireValidationError::UnsupportedVersion)),
        "receipt payload-schema substitution",
    )?;

    let mut receipt_kind_substitution = valid_freeze_response;
    receipt_kind_substitution.outcome = Outcome::Success(Success::Frozen(receipt_for_handoff(
        ReceiptKindWire::NexusThaw,
        receipt_handoff,
        10_401,
    )));
    receipt_kind_substitution
        .validate()
        .map_err(|error| contract("validate standalone receipt-kind substitution", error))?;
    let receipt_kind_substitution_bytes =
        raw_bytes(&receipt_kind_substitution, "serialize receipt-kind substitution response")?;
    expect_paired_response_decode(
        &receipt_request,
        &receipt_kind_substitution_bytes,
        Err(DecodeError::Invalid(WireValidationError::InvalidBinding)),
        "receipt kind substitution",
    )?;

    Ok(vec![
        negative(
            "nexus-negative-wrong-family",
            "replace Nexus family ID with agent-control family ID",
            "Request.header.family",
            "DecodeError::Invalid(WireValidationError::WrongFamily)",
            Some(wrong_family_bytes),
        ),
        negative(
            "nexus-negative-nonminimal-varint",
            "expand canonical header major into a non-minimal postcard varint",
            "Request.header.major",
            "DecodeError::NonCanonical",
            Some(nonminimal_major),
        ),
        negative(
            "nexus-negative-trailing-byte",
            "append one byte after a complete canonical request",
            "Request",
            "DecodeError::TrailingBytes",
            Some(trailing),
        ),
        negative(
            "nexus-negative-unknown-operation-discriminant",
            "replace Descriptor with the first unassigned Operation discriminant",
            "Request.operation",
            "DecodeError::Codec",
            Some(unknown_operation),
        ),
        negative_without_bytes(
            "nexus-negative-predecode-size-limit",
            "supply one byte beyond the 1 MiB request limit",
            "Request",
            "DecodeError::TooLarge",
            &over_limit,
        ),
        negative(
            "nexus-negative-response-wrong-family",
            "replace Nexus response family ID with agent-control family ID",
            "Response.header.family",
            "DecodeError::Invalid(WireValidationError::WrongFamily)",
            Some(response_wrong_family_bytes),
        ),
        negative(
            "nexus-negative-response-nonminimal-varint",
            "expand canonical response header major into a non-minimal postcard varint",
            "Response.header.major",
            "DecodeError::NonCanonical",
            Some(response_nonminimal_major),
        ),
        negative(
            "nexus-negative-response-trailing-byte",
            "append one byte after a complete canonical response",
            "Response",
            "DecodeError::TrailingBytes",
            Some(response_trailing),
        ),
        negative(
            "nexus-negative-response-unknown-outcome-discriminant",
            "replace Success with the first unassigned Outcome discriminant",
            "Response.outcome",
            "DecodeError::Codec",
            Some(response_unknown_outcome),
        ),
        negative_without_bytes(
            "nexus-negative-response-predecode-size-limit",
            "supply one byte beyond the 1 MiB response limit",
            "Response",
            "DecodeError::TooLarge",
            &response_over_limit,
        ),
        negative(
            "nexus-negative-operation-response-mismatch",
            "bind a Registered success to a Descriptor request",
            "Response.outcome",
            "WireValidationError::InvalidBinding",
            Some(mismatch_bytes),
        ),
        negative(
            "nexus-negative-payload-digest-mismatch",
            "replace the digest of an otherwise valid canonical payload",
            "Operation::Register.invocation.sha256",
            "DecodeError::Invalid(WireValidationError::InvalidDigest)",
            Some(payload_mismatch_bytes),
        ),
        negative(
            "nexus-negative-replay-wrong-family",
            "replace Nexus replay family ID with agent-control family ID",
            "ReplayRecord.header.family",
            "DecodeError::Invalid(WireValidationError::WrongFamily)",
            Some(replay_wrong_family_bytes),
        ),
        negative(
            "nexus-negative-replay-nonminimal-varint",
            "expand canonical replay header major into a non-minimal postcard varint",
            "ReplayRecord.header.major",
            "DecodeError::NonCanonical",
            Some(replay_nonminimal_major),
        ),
        negative(
            "nexus-negative-replay-trailing-byte",
            "append one byte after a complete canonical replay record",
            "ReplayRecord",
            "DecodeError::TrailingBytes",
            Some(replay_trailing),
        ),
        negative_without_bytes(
            "nexus-negative-replay-predecode-size-limit",
            "supply one byte beyond the replay-record input limit",
            "ReplayRecord",
            "DecodeError::TooLarge",
            &replay_over_limit,
        ),
        negative(
            "nexus-negative-replay-request-mutation",
            "mutate the embedded request Operation discriminant",
            "ReplayRecord.request_bytes",
            "DecodeError::Invalid(WireValidationError::InvalidArtifact)",
            Some(mutated_replay_bytes),
        ),
        negative(
            "nexus-negative-replay-request-id-conflict",
            "replace the outer request ID without changing the embedded exchange",
            "ReplayRecord.request_id",
            "DecodeError::Invalid(WireValidationError::InvalidBinding)",
            Some(conflicting_replay_bytes),
        ),
        negative(
            "nexus-negative-replay-response-digest-conflict",
            "replace the outer response digest without changing the embedded response",
            "ReplayRecord.response_digest",
            "DecodeError::Invalid(WireValidationError::InvalidBinding)",
            Some(response_digest_conflict_bytes),
        ),
        negative(
            "nexus-negative-receipt-reference-digest-mismatch",
            "replace the neutral receipt reference digest without changing typed receipt bytes",
            "Response.outcome.Success.Frozen.reference.digest",
            "DecodeError::Invalid(WireValidationError::InvalidDigest)",
            Some(receipt_digest_mismatch_bytes),
        ),
        negative(
            "nexus-negative-receipt-payload-schema-substitution",
            "replace the receipt payload schema with the NexusThaw receipt schema",
            "Response.outcome.Success.Frozen.payload.schema",
            "DecodeError::Invalid(WireValidationError::UnsupportedVersion)",
            Some(receipt_payload_schema_substitution_bytes),
        ),
        negative(
            "nexus-negative-receipt-kind-substitution",
            "replace a self-consistent NexusFreeze receipt with a NexusThaw receipt",
            "Response.outcome.Success.Frozen.reference.kind",
            "DecodeError::Invalid(WireValidationError::InvalidBinding)",
            Some(receipt_kind_substitution_bytes),
        ),
    ])
}

fn negative(
    case_id: &'static str,
    mutation: &'static str,
    target: &'static str,
    expected_rejection: &'static str,
    bytes: Option<Vec<u8>>,
) -> NegativeVector {
    let bytes = bytes.expect("stored negative vector has bytes");
    let byte_length = bytes.len();
    let sha256 = hex_digest(&bytes);
    NegativeVector {
        case_id,
        mutation,
        target,
        expected_rejection,
        bytes: Some(bytes),
        byte_length,
        sha256,
    }
}

fn negative_without_bytes(
    case_id: &'static str,
    mutation: &'static str,
    target: &'static str,
    expected_rejection: &'static str,
    bytes: &[u8],
) -> NegativeVector {
    NegativeVector {
        case_id,
        mutation,
        target,
        expected_rejection,
        bytes: None,
        byte_length: bytes.len(),
        sha256: hex_digest(bytes),
    }
}

fn raw_bytes<T: serde::Serialize>(value: &T, action: &str) -> Result<Vec<u8>, GoldenCorpusError> {
    postcard::to_allocvec(value).map_err(|error| contract(action, error))
}

fn nonminimal_header_major(canonical: &[u8]) -> Result<Vec<u8>, GoldenCorpusError> {
    let major = canonical.get(16).copied().ok_or_else(|| {
        GoldenCorpusError::Contract("canonical Nexus wire value has no header major".to_owned())
    })?;
    if major >= 0x80 {
        return Err(GoldenCorpusError::Contract(
            "canonical Nexus wire header major is not a one-byte postcard varint".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(canonical.len() + 1);
    bytes.extend_from_slice(&canonical[..16]);
    bytes.push(major | 0x80);
    bytes.push(0);
    bytes.extend_from_slice(&canonical[17..]);
    Ok(bytes)
}

fn expect_request_decode(
    bytes: &[u8],
    expected: Result<Request, DecodeError>,
    label: &str,
) -> Result<(), GoldenCorpusError> {
    let actual = nexus_adapter::decode_request(bytes);
    if actual != expected {
        return Err(GoldenCorpusError::Contract(format!(
            "Nexus negative {label} returned {actual:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

fn expect_replay_decode(
    bytes: &[u8],
    expected: Result<ReplayRecord, DecodeError>,
    label: &str,
) -> Result<(), GoldenCorpusError> {
    let actual = nexus_adapter::decode_replay(bytes);
    if actual != expected {
        return Err(GoldenCorpusError::Contract(format!(
            "Nexus negative {label} returned {actual:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

fn expect_paired_response_decode(
    request: &Request,
    bytes: &[u8],
    expected: Result<Response, DecodeError>,
    label: &str,
) -> Result<(), GoldenCorpusError> {
    let actual = nexus_adapter::decode_response_for(request, bytes);
    if actual != expected {
        return Err(GoldenCorpusError::Contract(format!(
            "Nexus negative {label} returned {actual:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

fn contract(action: &str, error: impl std::fmt::Debug) -> GoldenCorpusError {
    GoldenCorpusError::Contract(format!("cannot {action}: {error:?}"))
}
