use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

use crate::{
    codec::{
        DecodeError, EncodeError, canonical_replay_bytes, canonical_request_bytes,
        canonical_response_bytes, decode_canonical_replay, decode_canonical_request,
        decode_canonical_response, request_digest, response_digest,
    },
    common::{
        AgentBinding, AgentRole, AuthorityRole, AuthorityServiceBinding, BootId, CanonicalPayload,
        CohortId, GrantId, HandoffId, IdempotencyId, InternalFailure, JointHandoffKeyWire,
        LogicalIncarnation, OperationId, ReceiptArtifact, ReceiptKindWire, RegistryInstanceId,
        RequestId, Sha256Digest, WireHeader, WireValidation, WireValidationError,
    },
};

pub const FAMILY_ID: [u8; 16] = *b"visa-nex-rpc-v1\0";
pub const SCHEMA: &str = "visa.nexus-adapter.local.v1";
pub const REQUEST_NAMESPACE: &str = "visa.nexus-adapter.local.request.v1";
pub const RESPONSE_NAMESPACE: &str = "visa.nexus-adapter.local.response.v1";
pub const ERROR_NAMESPACE: &str = "visa.nexus-adapter.local.error.v1";
pub const REPLAY_NAMESPACE: &str = "visa.nexus-adapter.local.replay.v1";
pub const GOLDEN_CORPUS_ID: &str = "visa.nexus-adapter.local.golden.v1";
pub const OWNED_SCHEMA_ARTIFACT_ID: &str = "visa.nexus-adapter.local.owned-schema.v1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/nexus-adapter/request/v1\0";
pub const RESPONSE_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/nexus-adapter/response/v1\0";
pub const REGISTER_SCHEMA: [u8; 16] = *b"visa-nex-bind-v1";
pub const PREPARE_SCHEMA: [u8; 16] = *b"visa-nex-prep-v1";
pub const COMMIT_SCHEMA: [u8; 16] = *b"visa-nex-cmit-v1";
pub const OUTCOME_SCHEMA: [u8; 16] = *b"visa-nex-outc-v1";
pub const COMPLETE_SCHEMA: [u8; 16] = *b"visa-nex-comp-v1";
pub const FREEZE_SCHEMA: [u8; 16] = *b"visa-nex-frze-v1";
pub const THAW_SCHEMA: [u8; 16] = *b"visa-nex-thaw-v1";
pub const CLOSE_SCHEMA: [u8; 16] = *b"visa-nex-clos-v1";

pub const WELL_KNOWN_NAME: &str = "io.github.chenty2333.vISA.NexusAdapter1";
pub const OBJECT_PATH: &str = "/io/github/chenty2333/vISA/NexusAdapter";
pub const INTERFACE: &str = "io.github.chenty2333.vISA.NexusAdapter1";
pub const METHOD: &str = "Execute";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Request {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub caller: AgentBinding,
    pub operation: Operation,
}

impl Request {
    pub fn new(request_id: RequestId, caller: AgentBinding, operation: Operation) -> Self {
        Self { header: WireHeader::new(FAMILY_ID), request_id, caller, operation }
    }

    pub fn digest(&self) -> Result<Sha256Digest, EncodeError> {
        request_digest(REQUEST_DIGEST_DOMAIN, self)
    }
}

impl WireValidation for Request {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.header.validate_family(FAMILY_ID)?;
        self.request_id.validate()?;
        self.caller.validate()?;
        self.operation.validate()
    }
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>, EncodeError> {
    canonical_request_bytes(request)
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, DecodeError> {
    decode_canonical_request(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Operation {
    Descriptor,
    Register(EffectInvocation),
    Prepare(EffectInvocation),
    CommitAndAuthorizeDispatch(DispatchCommitRequest),
    RecordOutcome(EffectInvocation),
    Complete(EffectInvocation),
    Freeze(JointInvocation),
    Thaw(JointInvocation),
    CloseStep(JointInvocation),
    Query(QueryRequest),
}

impl WireValidation for Operation {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Descriptor => Ok(()),
            Self::Register(value) => value.validate_with_schema(REGISTER_SCHEMA, true),
            Self::Prepare(value) => value.validate_with_schema(PREPARE_SCHEMA, false),
            Self::CommitAndAuthorizeDispatch(value) => value.validate(),
            Self::RecordOutcome(value) => value.validate_with_schema(OUTCOME_SCHEMA, false),
            Self::Complete(value) => value.validate_with_schema(COMPLETE_SCHEMA, false),
            Self::Freeze(value) => value.validate_with_schema(FREEZE_SCHEMA),
            Self::Thaw(value) => value.validate_with_schema(THAW_SCHEMA),
            Self::CloseStep(value) => value.validate_with_schema(CLOSE_SCHEMA),
            Self::Query(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct EffectIdentity {
    pub operation: OperationId,
    pub idempotency: IdempotencyId,
}

impl WireValidation for EffectIdentity {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()?;
        self.idempotency.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct EffectInvocation {
    pub effect: EffectIdentity,
    pub expected_provider_revision: u64,
    pub invocation: CanonicalPayload,
}

impl EffectInvocation {
    fn validate_with_schema(
        &self,
        schema_id: [u8; 16],
        allow_initial_revision: bool,
    ) -> Result<(), WireValidationError> {
        self.effect.validate()?;
        if !allow_initial_revision && self.expected_provider_revision == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.invocation.validate()?;
        if self.invocation.schema.id != schema_id
            || self.invocation.schema.major != 1
            || self.invocation.schema.minor != 0
        {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct DispatchCommitRequest {
    pub effect: EffectIdentity,
    pub expected_provider_revision: u64,
    pub expected_projection_digest: Sha256Digest,
    pub invocation: CanonicalPayload,
}

impl WireValidation for DispatchCommitRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.effect.validate()?;
        if self.expected_provider_revision == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.expected_projection_digest.validate()?;
        self.invocation.validate()?;
        if self.invocation.schema.id != COMMIT_SCHEMA
            || self.invocation.schema.major != 1
            || self.invocation.schema.minor != 0
        {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct JointInvocation {
    pub key: JointHandoffKeyWire,
    pub operation: OperationId,
    pub expected_provider_revision: u64,
    pub invocation: CanonicalPayload,
}

impl JointInvocation {
    fn validate_with_schema(&self, schema_id: [u8; 16]) -> Result<(), WireValidationError> {
        self.key.validate()?;
        self.operation.validate()?;
        if self.expected_provider_revision == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.invocation.validate()?;
        if self.invocation.schema.id != schema_id
            || self.invocation.schema.major != 1
            || self.invocation.schema.minor != 0
        {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum QueryRequest {
    Effect(EffectIdentity),
    Joint(HandoffId),
    Grant(GrantId),
}

impl WireValidation for QueryRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Effect(value) => value.validate(),
            Self::Joint(value) => value.validate(),
            Self::Grant(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Response {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub request_digest: Sha256Digest,
    pub server: AuthorityServiceBinding,
    pub outcome: Outcome,
}

impl Response {
    pub fn new(
        request: &Request,
        server: AuthorityServiceBinding,
        outcome: Outcome,
    ) -> Result<Self, EncodeError> {
        let response = Self {
            header: WireHeader::new(FAMILY_ID),
            request_id: request.request_id,
            request_digest: request.digest()?,
            server,
            outcome,
        };
        response.validate_for(request).map_err(EncodeError::Invalid)?;
        Ok(response)
    }

    pub fn validate_for(&self, request: &Request) -> Result<(), WireValidationError> {
        self.validate()?;
        request.validate()?;
        if self.request_id != request.request_id
            || self.request_digest
                != request.digest().map_err(|_| WireValidationError::InvalidDigest)?
            || self.server.role != AuthorityRole::NexusAdapter
            || self.server.cohort != request.caller.cohort
            || self.server.boot != request.caller.boot
            || self.server.runtime_session != request.caller.runtime_session
        {
            return Err(WireValidationError::InvalidBinding);
        }
        self.outcome.validate_for(request)
    }

    pub fn digest(&self) -> Result<Sha256Digest, EncodeError> {
        response_digest(RESPONSE_DIGEST_DOMAIN, self)
    }
}

pub fn encode_response_for(request: &Request, response: &Response) -> Result<Vec<u8>, EncodeError> {
    response.validate_for(request).map_err(EncodeError::Invalid)?;
    canonical_response_bytes(response)
}

pub fn decode_response_for(request: &Request, bytes: &[u8]) -> Result<Response, DecodeError> {
    let response: Response = decode_canonical_response(bytes)?;
    response.validate_for(request).map_err(DecodeError::Invalid)?;
    Ok(response)
}

impl WireValidation for Response {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.header.validate_family(FAMILY_ID)?;
        self.request_id.validate()?;
        self.request_digest.validate()?;
        self.server.validate()?;
        if self.server.role != AuthorityRole::NexusAdapter {
            return Err(WireValidationError::InvalidRole);
        }
        self.outcome.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Outcome {
    Success(Success),
    Rejected(Rejection),
    Unknown(Unknown),
    Internal(InternalFailure),
}

impl Outcome {
    fn validate_for(&self, request: &Request) -> Result<(), WireValidationError> {
        match self {
            Self::Success(value) => value.validate_for(request),
            Self::Unknown(value) if value.matches_operation(&request.operation) => Ok(()),
            Self::Rejected(_) | Self::Internal(_) => Ok(()),
            Self::Unknown(_) => Err(WireValidationError::InvalidBinding),
        }
    }
}

impl WireValidation for Outcome {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Success(value) => value.validate(),
            Self::Rejected(value) => value.validate(),
            Self::Unknown(value) => value.validate(),
            Self::Internal(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Success {
    Descriptor(ProviderDescriptor),
    Registered(EffectState),
    Prepared(EffectState),
    DispatchAuthorized(DispatchGrant),
    OutcomeRecorded(EffectState),
    Completed(EffectState),
    Frozen(ReceiptArtifact),
    Thawed(ReceiptArtifact),
    Closed(ReceiptArtifact),
    Query(QueryResult),
}

impl Success {
    fn validate_for(&self, request: &Request) -> Result<(), WireValidationError> {
        let valid = match (self, &request.operation) {
            (Self::Descriptor(_), Operation::Descriptor) => true,
            (Self::Registered(state), Operation::Register(invocation)) => {
                effect_state_matches(state, invocation, EffectPhase::Registered)
            }
            (Self::Prepared(state), Operation::Prepare(invocation)) => {
                effect_state_matches(state, invocation, EffectPhase::Prepared)
            }
            (Self::DispatchAuthorized(grant), Operation::CommitAndAuthorizeDispatch(_)) => {
                grant.validate_for(&request.caller, &request.operation).is_ok()
            }
            (Self::OutcomeRecorded(state), Operation::RecordOutcome(invocation)) => {
                effect_state_matches(state, invocation, EffectPhase::OutcomeRecorded)
            }
            (Self::Completed(state), Operation::Complete(invocation)) => {
                effect_state_matches(state, invocation, EffectPhase::Completed)
            }
            (Self::Frozen(receipt), Operation::Freeze(invocation)) => {
                receipt_matches(receipt, invocation.key.handoff, &[ReceiptKindWire::NexusFreeze])
            }
            (Self::Thawed(receipt), Operation::Thaw(invocation)) => {
                receipt_matches(receipt, invocation.key.handoff, &[ReceiptKindWire::NexusThaw])
            }
            (Self::Closed(receipt), Operation::CloseStep(invocation)) => receipt_matches(
                receipt,
                invocation.key.handoff,
                &[
                    ReceiptKindWire::ClosureProgress,
                    ReceiptKindWire::Closure,
                    ReceiptKindWire::RetainedTombstone,
                ],
            ),
            (Self::Query(result), Operation::Query(query)) => result.matches_query(*query),
            _ => false,
        };
        if valid { Ok(()) } else { Err(WireValidationError::InvalidBinding) }
    }
}

impl WireValidation for Success {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Descriptor(value) => value.validate(),
            Self::Registered(value)
            | Self::Prepared(value)
            | Self::OutcomeRecorded(value)
            | Self::Completed(value) => value.validate(),
            Self::DispatchAuthorized(value) => value.validate(),
            Self::Frozen(value) | Self::Thawed(value) | Self::Closed(value) => value.validate(),
            Self::Query(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ProviderDescriptor {
    pub provider_protocol_major: u16,
    pub provider_protocol_minor: u16,
    pub native_wire_major: u16,
    pub registry_instance: RegistryInstanceId,
    pub provider_identity_digest: Sha256Digest,
    pub maximum_native_request_bytes: u32,
}

impl WireValidation for ProviderDescriptor {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.provider_protocol_major != 2
            || self.provider_protocol_minor != 1
            || self.native_wire_major != 1
            || self.maximum_native_request_bytes == 0
            || self.maximum_native_request_bytes > 65_536
        {
            return Err(WireValidationError::UnsupportedVersion);
        }
        self.registry_instance.validate()?;
        self.provider_identity_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum EffectPhase {
    Registered,
    Prepared,
    Committed,
    Dispatched,
    OutcomeRecorded,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct EffectState {
    pub effect: EffectIdentity,
    pub phase: EffectPhase,
    pub provider_revision: u64,
    pub native_request_digest: Sha256Digest,
    pub native_receipt_digest: Sha256Digest,
}

impl WireValidation for EffectState {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.effect.validate()?;
        if self.provider_revision == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        self.native_request_digest.validate()?;
        self.native_receipt_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct DispatchGrant {
    pub grant: GrantId,
    pub registry_instance: RegistryInstanceId,
    pub effect: EffectIdentity,
    pub role: AgentRole,
    pub logical_incarnation: LogicalIncarnation,
    pub cohort: CohortId,
    pub boot: BootId,
    pub projection_digest: Sha256Digest,
    pub native_request_digest: Sha256Digest,
    pub native_receipt_digest: Sha256Digest,
    pub grant_sequence: u64,
}

impl DispatchGrant {
    fn validate_for(
        &self,
        caller: &AgentBinding,
        operation: &Operation,
    ) -> Result<(), WireValidationError> {
        let Operation::CommitAndAuthorizeDispatch(request) = operation else {
            return Err(WireValidationError::InvalidOperation);
        };
        if self.effect != request.effect
            || self.role != caller.role
            || self.logical_incarnation != caller.logical_incarnation
            || self.cohort != caller.cohort
            || self.boot != caller.boot
            || self.projection_digest != request.expected_projection_digest
        {
            return Err(WireValidationError::InvalidBinding);
        }
        Ok(())
    }
}

impl WireValidation for DispatchGrant {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.grant.validate()?;
        self.registry_instance.validate()?;
        self.effect.validate()?;
        self.logical_incarnation.validate()?;
        self.cohort.validate()?;
        self.boot.validate()?;
        self.projection_digest.validate()?;
        self.native_request_digest.validate()?;
        self.native_receipt_digest.validate()?;
        if self.grant_sequence == 0 {
            return Err(WireValidationError::InvalidSequence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum QueryResult {
    Missing,
    Effect(EffectState),
    Grant(DispatchGrant),
    Joint(ReceiptArtifact),
}

impl WireValidation for QueryResult {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Missing => Ok(()),
            Self::Effect(value) => value.validate(),
            Self::Grant(value) => value.validate(),
            Self::Joint(value) => value.validate(),
        }
    }
}

impl QueryResult {
    fn matches_query(&self, query: QueryRequest) -> bool {
        match (self, query) {
            (Self::Missing, _) => true,
            (Self::Effect(state), QueryRequest::Effect(effect)) => state.effect == effect,
            (Self::Grant(grant), QueryRequest::Grant(grant_id)) => grant.grant == grant_id,
            (Self::Joint(receipt), QueryRequest::Joint(handoff)) => {
                receipt.reference.handoff == handoff
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Rejection {
    InvalidRequest,
    NotFound,
    Conflict,
    Busy,
    StaleProviderRevision { expected: u64, actual: u64 },
    StaleProjection { expected: Sha256Digest, actual: Sha256Digest },
    FenceClosed,
    GrantConsumed,
    RegistryLost,
    Unsupported,
    Integrity,
}

impl WireValidation for Rejection {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::StaleProjection { expected, actual } => {
                expected.validate()?;
                actual.validate()
            }
            Self::InvalidRequest
            | Self::NotFound
            | Self::Conflict
            | Self::Busy
            | Self::StaleProviderRevision { .. }
            | Self::FenceClosed
            | Self::GrantConsumed
            | Self::RegistryLost
            | Self::Unsupported
            | Self::Integrity => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Unknown {
    pub query: QueryRequest,
    pub last_known_provider_revision: u64,
}

impl Unknown {
    fn matches_operation(&self, operation: &Operation) -> bool {
        match (self.query, operation) {
            (QueryRequest::Effect(effect), Operation::Register(request))
            | (QueryRequest::Effect(effect), Operation::Prepare(request))
            | (QueryRequest::Effect(effect), Operation::RecordOutcome(request))
            | (QueryRequest::Effect(effect), Operation::Complete(request)) => {
                effect == request.effect
            }
            (QueryRequest::Effect(effect), Operation::CommitAndAuthorizeDispatch(request)) => {
                effect == request.effect
            }
            (QueryRequest::Joint(handoff), Operation::Freeze(request))
            | (QueryRequest::Joint(handoff), Operation::Thaw(request))
            | (QueryRequest::Joint(handoff), Operation::CloseStep(request)) => {
                handoff == request.key.handoff
            }
            (query, Operation::Query(requested)) => query == *requested,
            (_, Operation::Descriptor) => false,
            _ => false,
        }
    }
}

impl WireValidation for Unknown {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.query.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ReplayRecord {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub request_digest: Sha256Digest,
    pub response_digest: Sha256Digest,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
}

impl ReplayRecord {
    pub fn from_exchange(request: &Request, response: &Response) -> Result<Self, EncodeError> {
        response.validate_for(request).map_err(EncodeError::Invalid)?;
        Ok(Self {
            header: WireHeader::new(FAMILY_ID),
            request_id: request.request_id,
            request_digest: request.digest()?,
            response_digest: response.digest()?,
            request_bytes: canonical_request_bytes(request)?,
            response_bytes: canonical_response_bytes(response)?,
        })
    }

    pub fn request(&self) -> Result<Request, ReplayDecodeError> {
        decode_request(&self.request_bytes).map_err(ReplayDecodeError::Request)
    }

    pub fn exchange(&self) -> Result<(Request, Response), ReplayDecodeError> {
        let request = self.request()?;
        let response = decode_response_for(&request, &self.response_bytes)
            .map_err(ReplayDecodeError::Response)?;
        Ok((request, response))
    }
}

impl WireValidation for ReplayRecord {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.header.validate_family(FAMILY_ID)?;
        self.request_id.validate()?;
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        let (request, response) =
            self.exchange().map_err(|_| WireValidationError::InvalidArtifact)?;
        if request.request_id != self.request_id
            || request.digest().map_err(|_| WireValidationError::InvalidDigest)?
                != self.request_digest
            || response.digest().map_err(|_| WireValidationError::InvalidDigest)?
                != self.response_digest
        {
            return Err(WireValidationError::InvalidBinding);
        }
        response.validate_for(&request)
    }
}

pub fn encode_replay(record: &ReplayRecord) -> Result<Vec<u8>, EncodeError> {
    canonical_replay_bytes(record)
}

pub fn decode_replay(bytes: &[u8]) -> Result<ReplayRecord, DecodeError> {
    decode_canonical_replay(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDecodeError {
    Request(DecodeError),
    Response(DecodeError),
}

fn effect_state_matches(
    state: &EffectState,
    invocation: &EffectInvocation,
    phase: EffectPhase,
) -> bool {
    state.effect == invocation.effect
        && state.phase == phase
        && invocation.expected_provider_revision.checked_add(1) == Some(state.provider_revision)
}

fn receipt_matches(
    receipt: &ReceiptArtifact,
    handoff: HandoffId,
    allowed_kinds: &[ReceiptKindWire],
) -> bool {
    receipt.reference.handoff == handoff && allowed_kinds.contains(&receipt.reference.kind)
}
