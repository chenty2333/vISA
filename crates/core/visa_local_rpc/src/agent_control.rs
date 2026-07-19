use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

use crate::{
    codec::{
        DecodeError, EncodeError, canonical_replay_bytes, canonical_request_bytes,
        canonical_response_bytes, decode_canonical_replay, decode_canonical_request,
        decode_canonical_response, request_digest, response_digest,
    },
    common::{
        AgentBinding, AgentRole, CanonicalPayload, ControllerBinding, InternalFailure,
        OperationEvidence, OperationId, RequestId, SecureArtifactRef, Sha256Digest, WireHeader,
        WireValidation, WireValidationError,
    },
};

pub const FAMILY_ID: [u8; 16] = *b"visa-agent-rpc1\0";
pub const SCHEMA: &str = "visa.agent.control.v1";
pub const REQUEST_NAMESPACE: &str = "visa.agent.control.request.v1";
pub const RESPONSE_NAMESPACE: &str = "visa.agent.control.response.v1";
pub const ERROR_NAMESPACE: &str = "visa.agent.control.error.v1";
pub const REPLAY_NAMESPACE: &str = "visa.agent.control.replay.v1";
pub const GOLDEN_CORPUS_ID: &str = "visa.agent.control.golden.v1";
pub const OWNED_SCHEMA_ARTIFACT_ID: &str = "visa.agent.control.owned-schema.v1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/agent-control/request/v1\0";
pub const RESPONSE_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/agent-control/response/v1\0";
pub const CONTRACT_COMMAND_SCHEMA: [u8; 16] = *b"contract-cmd-v1\0";
pub const JOINT_COMMAND_SCHEMA: [u8; 16] = *b"joint-command-v1";

pub const SOURCE_WELL_KNOWN_NAME: &str = "io.github.chenty2333.vISA.Agent.Source1";
pub const DESTINATION_WELL_KNOWN_NAME: &str = "io.github.chenty2333.vISA.Agent.Destination1";
pub const SOURCE_OBJECT_PATH: &str = "/io/github/chenty2333/vISA/Agent/Source";
pub const DESTINATION_OBJECT_PATH: &str = "/io/github/chenty2333/vISA/Agent/Destination";
pub const INTERFACE: &str = "io.github.chenty2333.vISA.AgentControl1";
pub const METHOD: &str = "Execute";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Request {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub caller: ControllerBinding,
    pub operation: Operation,
}

impl Request {
    pub fn new(request_id: RequestId, caller: ControllerBinding, operation: Operation) -> Self {
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
    Status(StatusRequest),
    Run(RunRequest),
    Handoff(HandoffRequest),
    Reconcile(ReconcileRequest),
    VerifyEvidence(VerifyEvidenceRequest),
}

impl WireValidation for Operation {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Status(value) => value.validate(),
            Self::Run(value) => value.validate(),
            Self::Handoff(value) => value.validate(),
            Self::Reconcile(value) => value.validate(),
            Self::VerifyEvidence(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct StatusRequest {
    pub expected_projection_digest: Option<Sha256Digest>,
}

impl WireValidation for StatusRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        if let Some(digest) = self.expected_projection_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct RunRequest {
    pub operation: OperationId,
    pub command: CanonicalPayload,
    pub component: SecureArtifactRef,
    pub input: Option<SecureArtifactRef>,
}

impl WireValidation for RunRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()?;
        validate_payload_schema(&self.command, CONTRACT_COMMAND_SCHEMA)?;
        self.component.validate()?;
        if let Some(input) = &self.input {
            input.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct HandoffRequest {
    pub operation: OperationId,
    pub command: CanonicalPayload,
}

impl WireValidation for HandoffRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()?;
        validate_payload_schema(&self.command, JOINT_COMMAND_SCHEMA)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ReconcileRequest {
    pub operation: OperationId,
    pub command: CanonicalPayload,
}

impl WireValidation for ReconcileRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()?;
        validate_payload_schema(&self.command, JOINT_COMMAND_SCHEMA)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct VerifyEvidenceRequest {
    pub evidence_index: SecureArtifactRef,
}

impl WireValidation for VerifyEvidenceRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.evidence_index.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Response {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub request_digest: Sha256Digest,
    pub server: AgentBinding,
    pub outcome: Outcome,
}

impl Response {
    pub fn new(
        request: &Request,
        server: AgentBinding,
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

    fn validate_for(&self, request: &Request) -> Result<(), WireValidationError> {
        self.validate()?;
        request.validate()?;
        if self.request_id != request.request_id
            || self.request_digest
                != request.digest().map_err(|_| WireValidationError::InvalidDigest)?
            || self.server.cohort != request.caller.cohort
            || self.server.boot != request.caller.boot
            || self.server.runtime_session != request.caller.runtime_session
        {
            return Err(WireValidationError::InvalidBinding);
        }
        self.outcome.validate_for(request, &self.server)
    }

    pub fn validate_for_endpoint(
        &self,
        request: &Request,
        expected_role: AgentRole,
    ) -> Result<(), WireValidationError> {
        self.validate_for(request)?;
        if self.server.role != expected_role {
            return Err(WireValidationError::InvalidRole);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Sha256Digest, EncodeError> {
        response_digest(RESPONSE_DIGEST_DOMAIN, self)
    }
}

pub fn encode_response_for(
    request: &Request,
    expected_role: AgentRole,
    response: &Response,
) -> Result<Vec<u8>, EncodeError> {
    response.validate_for_endpoint(request, expected_role).map_err(EncodeError::Invalid)?;
    canonical_response_bytes(response)
}

pub fn decode_response_for(
    request: &Request,
    expected_role: AgentRole,
    bytes: &[u8],
) -> Result<Response, DecodeError> {
    let response: Response = decode_canonical_response(bytes)?;
    response.validate_for_endpoint(request, expected_role).map_err(DecodeError::Invalid)?;
    Ok(response)
}

impl WireValidation for Response {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.header.validate_family(FAMILY_ID)?;
        self.request_id.validate()?;
        self.request_digest.validate()?;
        self.server.validate()?;
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
    fn validate_for(
        &self,
        request: &Request,
        server: &AgentBinding,
    ) -> Result<(), WireValidationError> {
        match self {
            Self::Success(value) => value.validate_for(&request.operation, server),
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

impl WireValidation for Rejection {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::StaleProjection { expected, actual } => {
                expected.validate()?;
                actual.validate()
            }
            Self::InvalidRequest
            | Self::WrongCohort
            | Self::WrongBoot
            | Self::WrongRuntimeSession
            | Self::WrongRole
            | Self::Busy
            | Self::NotFound
            | Self::Conflict
            | Self::Unsupported
            | Self::EffectsFenced => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Success {
    Status(Status),
    Run(OperationEvidence),
    Handoff(OperationEvidence),
    Reconcile(OperationEvidence),
    VerifyEvidence(EvidenceVerification),
}

impl Success {
    fn validate_for(
        &self,
        operation: &Operation,
        server: &AgentBinding,
    ) -> Result<(), WireValidationError> {
        let valid = match (self, operation) {
            (Self::Status(status), Operation::Status(request)) => {
                status.role == server.role
                    && status.logical_incarnation == server.logical_incarnation
                    && request
                        .expected_projection_digest
                        .is_none_or(|digest| digest == status.projection_digest)
            }
            (Self::Run(evidence), Operation::Run(request)) => {
                evidence.operation == request.operation
            }
            (Self::Handoff(evidence), Operation::Handoff(request)) => {
                evidence.operation == request.operation
            }
            (Self::Reconcile(evidence), Operation::Reconcile(request)) => {
                evidence.operation == request.operation
            }
            (Self::VerifyEvidence(evidence), Operation::VerifyEvidence(request)) => {
                evidence.index_digest == request.evidence_index.sha256
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(WireValidationError::InvalidBinding) }
    }
}

impl WireValidation for Success {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Status(value) => value.validate(),
            Self::Run(value) | Self::Handoff(value) | Self::Reconcile(value) => value.validate(),
            Self::VerifyEvidence(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum AgentPhase {
    Initializing,
    Ready,
    Running,
    Fenced,
    Retiring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Status {
    pub role: AgentRole,
    pub phase: AgentPhase,
    pub logical_incarnation: crate::common::LogicalIncarnation,
    pub projection_sequence: u64,
    pub projection_digest: Sha256Digest,
    pub effects_fenced: bool,
}

impl WireValidation for Status {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.logical_incarnation.validate()?;
        self.projection_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct EvidenceVerification {
    pub index_digest: Sha256Digest,
    pub verifier_receipt_digest: Sha256Digest,
}

impl WireValidation for EvidenceVerification {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.index_digest.validate()?;
        self.verifier_receipt_digest.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum Rejection {
    InvalidRequest,
    WrongCohort,
    WrongBoot,
    WrongRuntimeSession,
    WrongRole,
    Busy,
    NotFound,
    StaleProjection { expected: Sha256Digest, actual: Sha256Digest },
    Conflict,
    Unsupported,
    EffectsFenced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Unknown {
    pub operation: OperationId,
    pub last_known_sequence: u64,
}

impl Unknown {
    fn matches_operation(&self, operation: &Operation) -> bool {
        match operation {
            Operation::Run(value) => self.operation == value.operation,
            Operation::Handoff(value) => self.operation == value.operation,
            Operation::Reconcile(value) => self.operation == value.operation,
            Operation::Status(_) | Operation::VerifyEvidence(_) => false,
        }
    }
}

impl WireValidation for Unknown {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.operation.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct ReplayRecord {
    pub header: WireHeader,
    pub request_id: RequestId,
    pub request_digest: Sha256Digest,
    pub response_digest: Sha256Digest,
    pub endpoint_role: AgentRole,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
}

impl ReplayRecord {
    pub fn from_exchange(
        request: &Request,
        endpoint_role: AgentRole,
        response: &Response,
    ) -> Result<Self, EncodeError> {
        response.validate_for_endpoint(request, endpoint_role).map_err(EncodeError::Invalid)?;
        Ok(Self {
            header: WireHeader::new(FAMILY_ID),
            request_id: request.request_id,
            request_digest: request.digest()?,
            response_digest: response.digest()?,
            endpoint_role,
            request_bytes: canonical_request_bytes(request)?,
            response_bytes: canonical_response_bytes(response)?,
        })
    }

    pub fn request(&self) -> Result<Request, ReplayDecodeError> {
        decode_request(&self.request_bytes).map_err(ReplayDecodeError::Request)
    }

    pub fn exchange(&self) -> Result<(Request, Response), ReplayDecodeError> {
        let request = self.request()?;
        let response = decode_response_for(&request, self.endpoint_role, &self.response_bytes)
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

fn validate_payload_schema(
    payload: &CanonicalPayload,
    schema_id: [u8; 16],
) -> Result<(), WireValidationError> {
    payload.validate()?;
    if payload.schema.id != schema_id || payload.schema.major != 1 || payload.schema.minor != 0 {
        return Err(WireValidationError::UnsupportedVersion);
    }
    Ok(())
}
