use joint_handoff_core::{
    DecodeError as JointDecodeError, Identity, JOINT_PROTOCOL_VERSION, JointProtocolVersion,
    PreparedBindings, canonical_bytes, canonical_from_bytes,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use visa_local_rpc::{
    WireValidation,
    common::CanonicalPayload,
    ownership::{
        ABORT_PROPOSAL_SCHEMA, COMMIT_PROPOSAL_SCHEMA, RESERVE_PROPOSAL_SCHEMA,
        SEAL_PROPOSAL_SCHEMA,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalCodecError {
    WrongSchema,
    Decode,
    TrailingBytes,
    NonCanonical,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveProposalV1 {
    pub version: JointProtocolVersion,
}

impl Default for ReserveProposalV1 {
    fn default() -> Self {
        Self { version: JOINT_PROTOCOL_VERSION }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealProposalV1 {
    pub version: JointProtocolVersion,
    pub reservation: Identity,
    pub intent: visa_local_rpc::common::ReceiptArtifact,
    pub visa_freeze: visa_local_rpc::common::ReceiptArtifact,
    pub nexus_freeze: visa_local_rpc::common::ReceiptArtifact,
    pub destination_prepared: visa_local_rpc::common::ReceiptArtifact,
    pub bindings: PreparedBindings,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortProposalV1 {
    pub version: JointProtocolVersion,
    pub reservation: Identity,
    pub basis: visa_local_rpc::common::ReceiptArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitProposalV1 {
    pub version: JointProtocolVersion,
    pub reservation: Identity,
    pub prepared: visa_local_rpc::common::ReceiptArtifact,
}

pub fn encode_reserve_proposal(
    value: &ReserveProposalV1,
) -> Result<CanonicalPayload, ProposalCodecError> {
    encode_payload(RESERVE_PROPOSAL_SCHEMA, value)
}

pub fn decode_reserve_proposal(
    payload: &CanonicalPayload,
) -> Result<ReserveProposalV1, ProposalCodecError> {
    decode_payload(RESERVE_PROPOSAL_SCHEMA, payload)
}

pub fn encode_seal_proposal(
    value: &SealProposalV1,
) -> Result<CanonicalPayload, ProposalCodecError> {
    encode_payload(SEAL_PROPOSAL_SCHEMA, value)
}

pub fn decode_seal_proposal(
    payload: &CanonicalPayload,
) -> Result<SealProposalV1, ProposalCodecError> {
    decode_payload(SEAL_PROPOSAL_SCHEMA, payload)
}

pub fn encode_abort_proposal(
    value: &AbortProposalV1,
) -> Result<CanonicalPayload, ProposalCodecError> {
    encode_payload(ABORT_PROPOSAL_SCHEMA, value)
}

pub fn decode_abort_proposal(
    payload: &CanonicalPayload,
) -> Result<AbortProposalV1, ProposalCodecError> {
    decode_payload(ABORT_PROPOSAL_SCHEMA, payload)
}

pub fn encode_commit_proposal(
    value: &CommitProposalV1,
) -> Result<CanonicalPayload, ProposalCodecError> {
    encode_payload(COMMIT_PROPOSAL_SCHEMA, value)
}

pub fn decode_commit_proposal(
    payload: &CanonicalPayload,
) -> Result<CommitProposalV1, ProposalCodecError> {
    decode_payload(COMMIT_PROPOSAL_SCHEMA, payload)
}

fn encode_payload<T>(schema: [u8; 16], value: &T) -> Result<CanonicalPayload, ProposalCodecError>
where
    T: Serialize,
{
    let bytes = canonical_bytes(value).map_err(|_| ProposalCodecError::Invalid)?;
    CanonicalPayload::new(
        visa_local_rpc::common::PayloadSchema { id: schema, major: 1, minor: 0 },
        bytes,
    )
    .map_err(|_| ProposalCodecError::Invalid)
}

fn decode_payload<T>(schema: [u8; 16], payload: &CanonicalPayload) -> Result<T, ProposalCodecError>
where
    T: Serialize + DeserializeOwned,
{
    payload.validate().map_err(|_| ProposalCodecError::Invalid)?;
    if payload.schema.id != schema || payload.schema.major != 1 || payload.schema.minor != 0 {
        return Err(ProposalCodecError::WrongSchema);
    }
    let value = canonical_from_bytes(&payload.bytes).map_err(|error| match error {
        JointDecodeError::TrailingBytes => ProposalCodecError::TrailingBytes,
        JointDecodeError::Codec => ProposalCodecError::Decode,
    })?;
    if canonical_bytes(&value).ok().as_deref() != Some(payload.bytes.as_slice()) {
        return Err(ProposalCodecError::NonCanonical);
    }
    Ok(value)
}

pub(crate) fn require_supported_version(
    version: JointProtocolVersion,
) -> Result<(), ProposalCodecError> {
    if version == JOINT_PROTOCOL_VERSION { Ok(()) } else { Err(ProposalCodecError::Invalid) }
}
