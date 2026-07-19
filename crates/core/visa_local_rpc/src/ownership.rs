use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

use crate::{
    codec::{
        DecodeError, EncodeError, canonical_replay_bytes, canonical_request_bytes,
        canonical_response_bytes, decode_canonical_replay, decode_canonical_request,
        decode_canonical_response, request_digest, response_digest,
    },
    common::{
        AgentBinding, AuthorityRole, AuthorityServiceBinding, CanonicalPayload, EntityRefWire,
        HandoffId, InternalFailure, JointHandoffKeyWire, NodeId, ReceiptArtifact, ReceiptKindWire,
        RequestId, ReservationId, Sha256Digest, WireHeader, WireValidation, WireValidationError,
    },
};

pub const FAMILY_ID: [u8; 16] = *b"visa-own-rpc-v1\0";
pub const SCHEMA: &str = "visa.ownership.local.v1";
pub const REQUEST_NAMESPACE: &str = "visa.ownership.local.request.v1";
pub const RESPONSE_NAMESPACE: &str = "visa.ownership.local.response.v1";
pub const ERROR_NAMESPACE: &str = "visa.ownership.local.error.v1";
pub const REPLAY_NAMESPACE: &str = "visa.ownership.local.replay.v1";
pub const GOLDEN_CORPUS_ID: &str = "visa.ownership.local.golden.v1";
pub const OWNED_SCHEMA_ARTIFACT_ID: &str = "visa.ownership.local.owned-schema.v1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/ownership/request/v1\0";
pub const RESPONSE_DIGEST_DOMAIN: &[u8] = b"vISA/local-rpc/ownership/response/v1\0";
pub const RESERVE_PROPOSAL_SCHEMA: [u8; 16] = *b"visa-own-resv-v1";
pub const SEAL_PROPOSAL_SCHEMA: [u8; 16] = *b"visa-own-seal-v1";
pub const ABORT_PROPOSAL_SCHEMA: [u8; 16] = *b"visa-own-abrt-v1";
pub const COMMIT_PROPOSAL_SCHEMA: [u8; 16] = *b"visa-own-cmit-v1";

pub const WELL_KNOWN_NAME: &str = "io.github.chenty2333.vISA.Ownership1";
pub const OBJECT_PATH: &str = "/io/github/chenty2333/vISA/Ownership";
pub const INTERFACE: &str = "io.github.chenty2333.vISA.Ownership1";
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
    InitializeUnit(InitializeUnitRequest),
    Reserve(DecisionProposal),
    Seal(DecisionProposal),
    Abort(DecisionProposal),
    Commit(DecisionProposal),
    Query(QueryRequest),
}

impl WireValidation for Operation {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::InitializeUnit(value) => value.validate(),
            Self::Reserve(value) => value.validate_with_schema(RESERVE_PROPOSAL_SCHEMA),
            Self::Seal(value) => value.validate_with_schema(SEAL_PROPOSAL_SCHEMA),
            Self::Abort(value) => value.validate_with_schema(ABORT_PROPOSAL_SCHEMA),
            Self::Commit(value) => value.validate_with_schema(COMMIT_PROPOSAL_SCHEMA),
            Self::Query(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct InitializeUnitRequest {
    pub continuity_unit: EntityRefWire,
    pub owner: NodeId,
    pub epoch: u64,
}

impl WireValidation for InitializeUnitRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.continuity_unit.validate()?;
        self.owner.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct DecisionProposal {
    pub key: JointHandoffKeyWire,
    pub expected_state_sequence: u64,
    pub proposal: CanonicalPayload,
}

impl DecisionProposal {
    fn validate_with_schema(&self, schema_id: [u8; 16]) -> Result<(), WireValidationError> {
        self.key.validate()?;
        self.proposal.validate()?;
        if self.proposal.schema.id != schema_id
            || self.proposal.schema.major != 1
            || self.proposal.schema.minor != 0
        {
            return Err(WireValidationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum QueryRequest {
    Unit(EntityRefWire),
    Handoff(HandoffId),
}

impl WireValidation for QueryRequest {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Unit(value) => value.validate(),
            Self::Handoff(value) => value.validate(),
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
            || self.server.role != AuthorityRole::Ownership
            || self.server.cohort != request.caller.cohort
            || self.server.boot != request.caller.boot
            || self.server.runtime_session != request.caller.runtime_session
        {
            return Err(WireValidationError::InvalidBinding);
        }
        self.outcome.validate_for(&request.operation)
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
        if self.server.role != AuthorityRole::Ownership {
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
    fn validate_for(&self, operation: &Operation) -> Result<(), WireValidationError> {
        match self {
            Self::Success(value) => value.validate_for(operation),
            Self::Unknown(value) if value.matches_operation(operation) => Ok(()),
            Self::Rejected(value) => value.validate_for(operation),
            Self::Internal(_) => Ok(()),
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
    Initialized(UnitOwnership),
    Reserved(ReceiptArtifact),
    Prepared(ReceiptArtifact),
    Aborted(ReceiptArtifact),
    Committed(ReceiptArtifact),
    Query(QueryResult),
}

impl Success {
    fn validate_for(&self, operation: &Operation) -> Result<(), WireValidationError> {
        let valid = match (self, operation) {
            (Self::Initialized(ownership), Operation::InitializeUnit(request)) => {
                ownership.continuity_unit == request.continuity_unit
                    && ownership.owner == request.owner
                    && ownership.epoch == request.epoch
            }
            (Self::Reserved(receipt), Operation::Reserve(request)) => {
                receipt_matches(receipt, request.key.handoff, ReceiptKindWire::PrepareIntent)
            }
            (Self::Prepared(receipt), Operation::Seal(request)) => {
                receipt_matches(receipt, request.key.handoff, ReceiptKindWire::OwnershipPrepared)
            }
            (Self::Aborted(receipt), Operation::Abort(request)) => {
                receipt_matches(receipt, request.key.handoff, ReceiptKindWire::OwnershipAbort)
            }
            (Self::Committed(receipt), Operation::Commit(request)) => {
                receipt_matches(receipt, request.key.handoff, ReceiptKindWire::OwnershipCommit)
            }
            (Self::Query(result), Operation::Query(query)) => result.matches_query(*query),
            _ => false,
        };
        if valid { Ok(()) } else { Err(WireValidationError::InvalidBinding) }
    }
}

impl WireValidation for Success {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Initialized(value) => value.validate(),
            Self::Reserved(value)
            | Self::Prepared(value)
            | Self::Aborted(value)
            | Self::Committed(value) => value.validate(),
            Self::Query(value) => value.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct UnitOwnership {
    pub continuity_unit: EntityRefWire,
    pub owner: NodeId,
    pub epoch: u64,
    pub active_handoff: Option<HandoffId>,
    pub active_reservation: Option<ReservationId>,
}

impl WireValidation for UnitOwnership {
    fn validate(&self) -> Result<(), WireValidationError> {
        self.continuity_unit.validate()?;
        self.owner.validate()?;
        if self.active_handoff.is_some() != self.active_reservation.is_some() {
            return Err(WireValidationError::InvalidBinding);
        }
        if let Some(handoff) = self.active_handoff {
            handoff.validate()?;
        }
        if let Some(reservation) = self.active_reservation {
            reservation.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum QueryResult {
    Missing,
    Unit(UnitOwnership),
    Reserved(ReceiptArtifact),
    Prepared(ReceiptArtifact),
    AbortDecided(ReceiptArtifact),
    CommitDecided(ReceiptArtifact),
}

impl WireValidation for QueryResult {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::Missing => Ok(()),
            Self::Unit(value) => value.validate(),
            Self::Reserved(value)
            | Self::Prepared(value)
            | Self::AbortDecided(value)
            | Self::CommitDecided(value) => value.validate(),
        }
    }
}

impl QueryResult {
    fn matches_query(&self, query: QueryRequest) -> bool {
        match (self, query) {
            (Self::Missing, _) => true,
            (Self::Unit(ownership), QueryRequest::Unit(unit)) => ownership.continuity_unit == unit,
            (
                Self::Reserved(receipt)
                | Self::Prepared(receipt)
                | Self::AbortDecided(receipt)
                | Self::CommitDecided(receipt),
                QueryRequest::Handoff(handoff),
            ) => receipt.reference.handoff == handoff,
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
    StaleSequence { expected: u64, actual: u64 },
    OwnershipMismatch { owner: NodeId, epoch: u64 },
    ExistingAbort(ReceiptArtifact),
    ExistingCommit(ReceiptArtifact),
    Integrity,
}

impl WireValidation for Rejection {
    fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::OwnershipMismatch { owner, .. } => owner.validate(),
            Self::ExistingAbort(value) | Self::ExistingCommit(value) => value.validate(),
            Self::InvalidRequest
            | Self::NotFound
            | Self::Conflict
            | Self::Busy
            | Self::StaleSequence { .. }
            | Self::Integrity => Ok(()),
        }
    }
}

impl Rejection {
    fn validate_for(&self, operation: &Operation) -> Result<(), WireValidationError> {
        self.validate()?;
        let (receipt, kind) = match self {
            Self::ExistingAbort(receipt) => (receipt, ReceiptKindWire::OwnershipAbort),
            Self::ExistingCommit(receipt) => (receipt, ReceiptKindWire::OwnershipCommit),
            _ => return Ok(()),
        };
        let handoff = match operation {
            Operation::Reserve(request)
            | Operation::Seal(request)
            | Operation::Abort(request)
            | Operation::Commit(request) => Some(request.key.handoff),
            Operation::Query(QueryRequest::Handoff(handoff)) => Some(*handoff),
            Operation::InitializeUnit(_) | Operation::Query(QueryRequest::Unit(_)) => None,
        };
        if handoff.is_some_and(|handoff| receipt_matches(receipt, handoff, kind)) {
            Ok(())
        } else {
            Err(WireValidationError::InvalidBinding)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct Unknown {
    pub query: QueryRequest,
    pub last_known_sequence: u64,
}

impl Unknown {
    fn matches_operation(&self, operation: &Operation) -> bool {
        match (self.query, operation) {
            (QueryRequest::Unit(unit), Operation::InitializeUnit(request)) => {
                unit == request.continuity_unit
            }
            (QueryRequest::Handoff(handoff), Operation::Reserve(request))
            | (QueryRequest::Handoff(handoff), Operation::Seal(request))
            | (QueryRequest::Handoff(handoff), Operation::Abort(request))
            | (QueryRequest::Handoff(handoff), Operation::Commit(request)) => {
                handoff == request.key.handoff
            }
            (_, Operation::Query(_)) => false,
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

fn receipt_matches(receipt: &ReceiptArtifact, handoff: HandoffId, kind: ReceiptKindWire) -> bool {
    receipt.reference.handoff == handoff && receipt.reference.kind == kind
}
