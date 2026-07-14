use alloc::vec::Vec;

use contract_core::{
    DeliveryPolicy, Digest, EntityRef, Extension, Identity, ProfileAccess, Rights, SchemaVersion,
    canonical_bytes, canonical_digest, canonical_from_bytes,
};
use serde::{Deserialize, Serialize};

use crate::{ContinuityDisposition, ProfilePayloadError};

/// Stable identity of the bounded logical-request continuity profile.
pub const LOGICAL_REQUEST_EXTENSION_ID: Identity = Identity::from_bytes(*b"visa:req:v1\0\0\0\0\0");
pub const LOGICAL_REQUEST_EXTENSION_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

const MAX_PEER_IDENTITY_BYTES: usize = 1024;
const MAX_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_LOGICAL_REQUEST_BYTES: u32 = 256 * 1024;
pub const MAX_LOGICAL_RESPONSE_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_LOGICAL_RESPONSE_CHUNK_BYTES: u32 = 64 * 1024;

const MAX_OPERATION_PAYLOAD_BYTES: usize = MAX_LOGICAL_REQUEST_BYTES as usize + 512;
const MAX_RESULT_PAYLOAD_BYTES: usize = MAX_LOGICAL_RESPONSE_CHUNK_BYTES as usize + 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestTransport {
    /// A provider-level operation that can be looked up by operation ID.
    Reconnectable,
    /// Native transport state is intentionally outside this profile.
    RawLiveTcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestReplay {
    Never,
    BeforeSend,
    IfIdempotent,
    WithOperationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestIdempotency {
    NonIdempotent,
    Idempotent,
    OperationIdDeduplicated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestPhase {
    Ready,
    Pending,
    PartialResponse,
    UnknownCompletion,
    Reconciling,
    Replaying,
    Cancelling,
    Completed,
    TimedOut,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestRejection {
    PeerMismatch,
    CredentialDenied,
    UnsafeReplay,
    UnsupportedTransport,
    PolicyDenied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestClaim {
    pub resource: EntityRef,
    /// Provider-defined stable peer identity, never a native socket address or handle.
    pub peer_identity: Vec<u8>,
    /// Reference resolved by the destination provider. Credential material is never canonical.
    pub credential_reference: Identity,
    pub required_rights: Rights,
    pub transport: LogicalRequestTransport,
    pub delivery: DeliveryPolicy,
    pub replay: LogicalRequestReplay,
    pub idempotency: LogicalRequestIdempotency,
    pub timeout_millis: u64,
    pub max_request_size: u32,
    pub max_response_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalResponseMetadata {
    pub size: u32,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestState {
    pub claim: LogicalRequestClaim,
    /// Stable provider-level deduplication and lookup key for this request.
    pub operation_id: Identity,
    pub request_size: u32,
    pub request_digest: Digest,
    pub phase: LogicalRequestPhase,
    /// Number of response bytes already delivered to the guest.
    pub response_cursor: u32,
    pub response: Option<LogicalResponseMetadata>,
    pub rejection: Option<LogicalRequestRejection>,
    pub disposition: ContinuityDisposition,
    /// Last canonical vISA effect operation applied to this extension.
    pub last_operation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestOperation {
    Start { request: Vec<u8> },
    Observe { max_bytes: u32 },
    Reconcile,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRequestObservation {
    pub phase: LogicalRequestPhase,
    pub response: Option<LogicalResponseMetadata>,
    pub rejection: Option<LogicalRequestRejection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalRequestResult {
    Started { observation: LogicalRequestObservation },
    Observed { observation: LogicalRequestObservation, bytes: Vec<u8>, response_cursor: u32 },
    Reconciled { observation: LogicalRequestObservation },
    Cancelled { observation: LogicalRequestObservation },
}

pub fn logical_request_extension(
    state: &LogicalRequestState,
) -> Result<Extension, ProfilePayloadError> {
    validate_state(state)?;
    Ok(Extension {
        id: LOGICAL_REQUEST_EXTENSION_ID,
        version: LOGICAL_REQUEST_EXTENSION_VERSION,
        required: true,
        payload: canonical_bytes(state).map_err(|_| ProfilePayloadError::InvalidPayload)?,
    })
}

pub fn logical_request_state(
    extension: &Extension,
) -> Result<LogicalRequestState, ProfilePayloadError> {
    decode_extension(extension)
}

pub(crate) fn decode_extension(
    extension: &Extension,
) -> Result<LogicalRequestState, ProfilePayloadError> {
    if extension.id != LOGICAL_REQUEST_EXTENSION_ID {
        return Err(ProfilePayloadError::UnknownProfile);
    }
    if extension.version != LOGICAL_REQUEST_EXTENSION_VERSION {
        return Err(ProfilePayloadError::VersionMismatch);
    }
    let state = canonical_from_bytes::<LogicalRequestState>(&extension.payload)
        .map_err(|_| ProfilePayloadError::InvalidPayload)?;
    validate_state(&state)?;
    Ok(state)
}

pub(crate) fn validate_effect(
    extension: &Extension,
    resource: EntityRef,
    access: ProfileAccess,
    payload: &[u8],
) -> Result<Rights, ProfilePayloadError> {
    let state = decode_extension(extension)?;
    if state.claim.resource != resource {
        return Err(ProfilePayloadError::ResourceMismatch);
    }
    let operation = decode_logical_request_operation(payload)?;
    let expected_access = operation_access(&operation);
    if access != expected_access {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    let required = access.required_rights();
    if !state.claim.required_rights.contains(required) {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    validate_operation(&state, &operation)?;
    Ok(required)
}

pub(crate) fn validate_handoff(extension: &Extension) -> Result<(), ProfilePayloadError> {
    let state = decode_extension(extension)?;
    if state.disposition == ContinuityDisposition::Reject
        || (state.phase == LogicalRequestPhase::UnknownCompletion
            && !unknown_completion_is_safe(&state.claim))
    {
        return Err(ProfilePayloadError::StateConflict);
    }
    Ok(())
}

pub(crate) fn result_matches(
    access: ProfileAccess,
    operation_payload: &[u8],
    result_payload: &[u8],
) -> bool {
    let Ok(operation) = decode_logical_request_operation(operation_payload) else {
        return false;
    };
    if operation_access(&operation) != access {
        return false;
    }
    let Ok(result) = decode_logical_request_result(result_payload) else {
        return false;
    };
    matches!(
        (&operation, &result),
        (LogicalRequestOperation::Start { .. }, LogicalRequestResult::Started { .. })
            | (LogicalRequestOperation::Observe { .. }, LogicalRequestResult::Observed { .. })
            | (LogicalRequestOperation::Reconcile, LogicalRequestResult::Reconciled { .. })
            | (LogicalRequestOperation::Cancel, LogicalRequestResult::Cancelled { .. })
    )
}

pub(crate) fn apply_result(
    extension: &mut Extension,
    access: ProfileAccess,
    operation_payload: &[u8],
    result_payload: &[u8],
    canonical_operation_id: Identity,
) -> Result<(), ProfilePayloadError> {
    let mut state = decode_extension(extension)?;
    let operation = decode_logical_request_operation(operation_payload)?;
    let result = decode_logical_request_result(result_payload)?;
    if operation_access(&operation) != access
        || !result_matches(access, operation_payload, result_payload)
    {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    validate_operation(&state, &operation)?;

    match (&operation, result) {
        (LogicalRequestOperation::Start { .. }, LogicalRequestResult::Started { observation }) => {
            apply_observation(&mut state, &operation, observation)?
        }
        (
            LogicalRequestOperation::Observe { max_bytes },
            LogicalRequestResult::Observed { observation, bytes, response_cursor },
        ) => {
            let consumed =
                u32::try_from(bytes.len()).map_err(|_| ProfilePayloadError::StateConflict)?;
            if consumed > *max_bytes
                || consumed > MAX_LOGICAL_RESPONSE_CHUNK_BYTES
                || response_cursor != state.response_cursor.saturating_add(consumed)
                || response_cursor > state.claim.max_response_size
            {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.response_cursor = response_cursor;
            apply_observation(&mut state, &operation, observation)?;
        }
        (LogicalRequestOperation::Reconcile, LogicalRequestResult::Reconciled { observation }) => {
            apply_observation(&mut state, &operation, observation)?
        }
        (LogicalRequestOperation::Cancel, LogicalRequestResult::Cancelled { observation }) => {
            apply_observation(&mut state, &operation, observation)?
        }
        _ => return Err(ProfilePayloadError::InvalidPayload),
    }

    state.last_operation = Some(canonical_operation_id);
    validate_state(&state)?;
    extension.payload = canonical_bytes(&state).map_err(|_| ProfilePayloadError::InvalidPayload)?;
    Ok(())
}

pub fn encode_logical_request_operation(
    operation: &LogicalRequestOperation,
) -> Result<Vec<u8>, ProfilePayloadError> {
    validate_operation_shape(operation)?;
    canonical_bytes(operation).map_err(|_| ProfilePayloadError::InvalidPayload)
}

pub fn decode_logical_request_operation(
    payload: &[u8],
) -> Result<LogicalRequestOperation, ProfilePayloadError> {
    if payload.len() > MAX_OPERATION_PAYLOAD_BYTES {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    let operation =
        canonical_from_bytes(payload).map_err(|_| ProfilePayloadError::InvalidPayload)?;
    validate_operation_shape(&operation)?;
    Ok(operation)
}

pub fn encode_logical_request_result(
    result: &LogicalRequestResult,
) -> Result<Vec<u8>, ProfilePayloadError> {
    validate_result_shape(result)?;
    canonical_bytes(result).map_err(|_| ProfilePayloadError::InvalidPayload)
}

pub fn decode_logical_request_result(
    payload: &[u8],
) -> Result<LogicalRequestResult, ProfilePayloadError> {
    if payload.len() > MAX_RESULT_PAYLOAD_BYTES {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    let result = canonical_from_bytes(payload).map_err(|_| ProfilePayloadError::InvalidPayload)?;
    validate_result_shape(&result)?;
    Ok(result)
}

fn validate_state(state: &LogicalRequestState) -> Result<(), ProfilePayloadError> {
    if state.claim.transport == LogicalRequestTransport::RawLiveTcp {
        return Err(ProfilePayloadError::UnsupportedContinuity);
    }
    if state.claim.resource.identity.is_zero()
        || state.claim.credential_reference.is_zero()
        || state.operation_id.is_zero()
        || state.claim.peer_identity.is_empty()
        || state.claim.peer_identity.len() > MAX_PEER_IDENTITY_BYTES
        || state.claim.peer_identity.contains(&0)
        || state.claim.timeout_millis == 0
        || state.claim.timeout_millis > MAX_TIMEOUT_MILLIS
        || state.claim.max_request_size == 0
        || state.claim.max_request_size > MAX_LOGICAL_REQUEST_BYTES
        || state.claim.max_response_size == 0
        || state.claim.max_response_size > MAX_LOGICAL_RESPONSE_BYTES
        || state.request_size > state.claim.max_request_size
        || state.request_digest == Digest::ZERO
        || state.response_cursor > state.claim.max_response_size
        || !state.claim.required_rights.contains(Rights::REBIND)
        || !valid_policy(&state.claim)
        || state.disposition != disposition_for(state.phase)
    {
        return Err(ProfilePayloadError::InvalidPayload);
    }

    if let Some(response) = state.response
        && (response.size > state.claim.max_response_size
            || state.response_cursor > response.size
            || response.digest == Digest::ZERO)
    {
        return Err(ProfilePayloadError::InvalidPayload);
    }

    if state.phase == LogicalRequestPhase::Completed && state.response.is_none() {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if state.phase == LogicalRequestPhase::Rejected {
        if state.rejection.is_none() {
            return Err(ProfilePayloadError::InvalidPayload);
        }
    } else if state.rejection.is_some() {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if state.phase == LogicalRequestPhase::Ready
        && (state.response_cursor != 0
            || state.response.is_some()
            || state.last_operation.is_some())
    {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if state.phase == LogicalRequestPhase::Replaying && !replay_is_safe(&state.claim) {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    Ok(())
}

fn valid_policy(claim: &LogicalRequestClaim) -> bool {
    if claim.delivery == DeliveryPolicy::Deduplicated
        && claim.idempotency != LogicalRequestIdempotency::OperationIdDeduplicated
    {
        return false;
    }
    if claim.delivery == DeliveryPolicy::AtLeastOnce
        && (claim.idempotency != LogicalRequestIdempotency::Idempotent
            || claim.replay != LogicalRequestReplay::IfIdempotent)
    {
        return false;
    }
    if claim.delivery == DeliveryPolicy::AtMostOnce
        && !matches!(claim.replay, LogicalRequestReplay::Never | LogicalRequestReplay::BeforeSend)
    {
        return false;
    }
    if claim.delivery == DeliveryPolicy::NonRecoverable
        && claim.replay != LogicalRequestReplay::Never
    {
        return false;
    }
    match claim.replay {
        LogicalRequestReplay::Never | LogicalRequestReplay::BeforeSend => true,
        LogicalRequestReplay::IfIdempotent => {
            claim.idempotency == LogicalRequestIdempotency::Idempotent
        }
        LogicalRequestReplay::WithOperationId => {
            claim.delivery == DeliveryPolicy::Deduplicated
                && claim.idempotency == LogicalRequestIdempotency::OperationIdDeduplicated
        }
    }
}

fn replay_is_safe(claim: &LogicalRequestClaim) -> bool {
    unknown_completion_is_safe(claim)
}

fn unknown_completion_is_safe(claim: &LogicalRequestClaim) -> bool {
    matches!(
        (claim.delivery, claim.replay, claim.idempotency),
        (
            DeliveryPolicy::AtLeastOnce,
            LogicalRequestReplay::IfIdempotent,
            LogicalRequestIdempotency::Idempotent
        ) | (
            DeliveryPolicy::Deduplicated,
            LogicalRequestReplay::WithOperationId,
            LogicalRequestIdempotency::OperationIdDeduplicated
        )
    )
}

fn validate_operation_shape(
    operation: &LogicalRequestOperation,
) -> Result<(), ProfilePayloadError> {
    match operation {
        LogicalRequestOperation::Start { request } => {
            if request.len() > MAX_LOGICAL_REQUEST_BYTES as usize {
                return Err(ProfilePayloadError::InvalidPayload);
            }
        }
        LogicalRequestOperation::Observe { max_bytes } => {
            if *max_bytes == 0 || *max_bytes > MAX_LOGICAL_RESPONSE_CHUNK_BYTES {
                return Err(ProfilePayloadError::InvalidPayload);
            }
        }
        LogicalRequestOperation::Reconcile | LogicalRequestOperation::Cancel => {}
    }
    Ok(())
}

fn validate_operation(
    state: &LogicalRequestState,
    operation: &LogicalRequestOperation,
) -> Result<(), ProfilePayloadError> {
    validate_operation_shape(operation)?;
    match operation {
        LogicalRequestOperation::Start { request } => {
            let request_size =
                u32::try_from(request.len()).map_err(|_| ProfilePayloadError::InvalidPayload)?;
            let request_digest = canonical_digest(request.as_slice())
                .map_err(|_| ProfilePayloadError::InvalidPayload)?;
            if state.phase != LogicalRequestPhase::Ready
                || request_size != state.request_size
                || request_size > state.claim.max_request_size
                || request_digest != state.request_digest
            {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
        LogicalRequestOperation::Observe { .. } => {
            if !matches!(
                state.phase,
                LogicalRequestPhase::Pending
                    | LogicalRequestPhase::PartialResponse
                    | LogicalRequestPhase::Completed
            ) {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
        LogicalRequestOperation::Reconcile => {
            if !matches!(
                state.phase,
                LogicalRequestPhase::Pending
                    | LogicalRequestPhase::PartialResponse
                    | LogicalRequestPhase::UnknownCompletion
                    | LogicalRequestPhase::Reconciling
                    | LogicalRequestPhase::Replaying
                    | LogicalRequestPhase::Cancelling
                    | LogicalRequestPhase::Completed
            ) {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
        LogicalRequestOperation::Cancel => {
            if !matches!(
                state.phase,
                LogicalRequestPhase::Pending
                    | LogicalRequestPhase::PartialResponse
                    | LogicalRequestPhase::UnknownCompletion
                    | LogicalRequestPhase::Reconciling
                    | LogicalRequestPhase::Replaying
                    | LogicalRequestPhase::Cancelling
            ) {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
    }
    Ok(())
}

fn validate_result_shape(result: &LogicalRequestResult) -> Result<(), ProfilePayloadError> {
    let observation = match result {
        LogicalRequestResult::Started { observation }
        | LogicalRequestResult::Reconciled { observation }
        | LogicalRequestResult::Cancelled { observation } => observation,
        LogicalRequestResult::Observed { observation, bytes, response_cursor } => {
            if bytes.len() > MAX_LOGICAL_RESPONSE_CHUNK_BYTES as usize
                || *response_cursor > MAX_LOGICAL_RESPONSE_BYTES
            {
                return Err(ProfilePayloadError::InvalidPayload);
            }
            observation
        }
    };
    validate_observation_shape(observation)
}

fn validate_observation_shape(
    observation: &LogicalRequestObservation,
) -> Result<(), ProfilePayloadError> {
    if observation.phase == LogicalRequestPhase::Ready {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if let Some(response) = observation.response
        && (response.size > MAX_LOGICAL_RESPONSE_BYTES || response.digest == Digest::ZERO)
    {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if observation.phase == LogicalRequestPhase::Completed && observation.response.is_none() {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    if (observation.phase == LogicalRequestPhase::Rejected) != observation.rejection.is_some() {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    Ok(())
}

fn apply_observation(
    state: &mut LogicalRequestState,
    operation: &LogicalRequestOperation,
    observation: LogicalRequestObservation,
) -> Result<(), ProfilePayloadError> {
    if (terminal_phase(state.phase) && observation.phase != state.phase)
        || !phase_allowed(operation, observation.phase)
        || (observation.phase == LogicalRequestPhase::Replaying && !replay_is_safe(&state.claim))
    {
        return Err(ProfilePayloadError::StateConflict);
    }

    if let Some(observed_response) = observation.response {
        if observed_response.size > state.claim.max_response_size
            || state.response_cursor > observed_response.size
            || state.response.is_some_and(|known| known != observed_response)
        {
            return Err(ProfilePayloadError::StateConflict);
        }
        state.response = Some(observed_response);
    }
    if observation.phase == LogicalRequestPhase::Completed && state.response.is_none() {
        return Err(ProfilePayloadError::StateConflict);
    }

    state.phase = observation.phase;
    state.rejection = observation.rejection;
    state.disposition = disposition_for(observation.phase);
    Ok(())
}

const fn terminal_phase(phase: LogicalRequestPhase) -> bool {
    matches!(
        phase,
        LogicalRequestPhase::Completed
            | LogicalRequestPhase::TimedOut
            | LogicalRequestPhase::Cancelled
            | LogicalRequestPhase::Rejected
    )
}

fn phase_allowed(operation: &LogicalRequestOperation, phase: LogicalRequestPhase) -> bool {
    match operation {
        LogicalRequestOperation::Start { .. } => matches!(
            phase,
            LogicalRequestPhase::Pending
                | LogicalRequestPhase::PartialResponse
                | LogicalRequestPhase::Completed
                | LogicalRequestPhase::UnknownCompletion
                | LogicalRequestPhase::TimedOut
                | LogicalRequestPhase::Cancelled
                | LogicalRequestPhase::Rejected
        ),
        LogicalRequestOperation::Observe { .. } => matches!(
            phase,
            LogicalRequestPhase::Pending
                | LogicalRequestPhase::PartialResponse
                | LogicalRequestPhase::Completed
                | LogicalRequestPhase::UnknownCompletion
                | LogicalRequestPhase::TimedOut
                | LogicalRequestPhase::Cancelled
                | LogicalRequestPhase::Rejected
        ),
        LogicalRequestOperation::Reconcile => matches!(
            phase,
            LogicalRequestPhase::Pending
                | LogicalRequestPhase::PartialResponse
                | LogicalRequestPhase::UnknownCompletion
                | LogicalRequestPhase::Reconciling
                | LogicalRequestPhase::Replaying
                | LogicalRequestPhase::Completed
                | LogicalRequestPhase::TimedOut
                | LogicalRequestPhase::Cancelled
                | LogicalRequestPhase::Rejected
        ),
        LogicalRequestOperation::Cancel => matches!(
            phase,
            LogicalRequestPhase::UnknownCompletion
                | LogicalRequestPhase::Cancelling
                | LogicalRequestPhase::Completed
                | LogicalRequestPhase::TimedOut
                | LogicalRequestPhase::Cancelled
                | LogicalRequestPhase::Rejected
        ),
    }
}

fn operation_access(operation: &LogicalRequestOperation) -> ProfileAccess {
    match operation {
        LogicalRequestOperation::Start { .. } => ProfileAccess::Write,
        LogicalRequestOperation::Observe { .. } => ProfileAccess::Read,
        LogicalRequestOperation::Reconcile | LogicalRequestOperation::Cancel => {
            ProfileAccess::Control
        }
    }
}

const fn disposition_for(phase: LogicalRequestPhase) -> ContinuityDisposition {
    match phase {
        LogicalRequestPhase::Pending
        | LogicalRequestPhase::PartialResponse
        | LogicalRequestPhase::Cancelling => ContinuityDisposition::Reconnect,
        LogicalRequestPhase::Replaying => ContinuityDisposition::Replay,
        LogicalRequestPhase::Rejected => ContinuityDisposition::Reject,
        LogicalRequestPhase::Ready
        | LogicalRequestPhase::UnknownCompletion
        | LogicalRequestPhase::Reconciling
        | LogicalRequestPhase::Completed
        | LogicalRequestPhase::TimedOut
        | LogicalRequestPhase::Cancelled => ContinuityDisposition::Revalidate,
    }
}

#[cfg(test)]
mod tests {
    use contract_core::{Generation, canonical_digest};

    use super::*;

    fn request() -> Vec<u8> {
        b"GET /work/42".to_vec()
    }

    fn state() -> LogicalRequestState {
        LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: EntityRef::new(Identity::from_u128(1), Generation::INITIAL),
                peer_identity: b"service.example/v1".to_vec(),
                credential_reference: Identity::from_u128(2),
                required_rights: Rights::PROFILE_READ
                    .union(Rights::PROFILE_WRITE)
                    .union(Rights::PROFILE_CONTROL)
                    .union(Rights::REBIND),
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 5_000,
                max_request_size: 1024,
                max_response_size: 4096,
            },
            operation_id: Identity::from_u128(3),
            request_size: request().len() as u32,
            request_digest: canonical_digest(request().as_slice()).unwrap(),
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        }
    }

    fn observation(phase: LogicalRequestPhase) -> LogicalRequestObservation {
        LogicalRequestObservation { phase, response: None, rejection: None }
    }

    fn apply(
        extension: &mut Extension,
        access: ProfileAccess,
        operation: &LogicalRequestOperation,
        result: &LogicalRequestResult,
        canonical_operation_id: u128,
    ) -> Result<(), ProfilePayloadError> {
        apply_result(
            extension,
            access,
            &encode_logical_request_operation(operation).unwrap(),
            &encode_logical_request_result(result).unwrap(),
            Identity::from_u128(canonical_operation_id),
        )
    }

    #[test]
    fn extension_round_trips_but_raw_live_tcp_is_explicitly_unsupported() {
        let accepted = state();
        let extension = logical_request_extension(&accepted).unwrap();
        assert_eq!(logical_request_state(&extension).unwrap(), accepted);

        let mut raw_tcp = state();
        raw_tcp.claim.transport = LogicalRequestTransport::RawLiveTcp;
        assert_eq!(
            logical_request_extension(&raw_tcp),
            Err(ProfilePayloadError::UnsupportedContinuity)
        );
    }

    #[test]
    fn unsafe_delivery_and_replay_combinations_are_rejected() {
        let mut unsafe_claim = state();
        unsafe_claim.claim.delivery = DeliveryPolicy::AtLeastOnce;
        unsafe_claim.claim.idempotency = LogicalRequestIdempotency::NonIdempotent;
        unsafe_claim.claim.replay = LogicalRequestReplay::IfIdempotent;
        assert_eq!(
            logical_request_extension(&unsafe_claim),
            Err(ProfilePayloadError::InvalidPayload)
        );

        let mut at_most_once_replay = state();
        at_most_once_replay.claim.delivery = DeliveryPolicy::AtMostOnce;
        at_most_once_replay.claim.idempotency = LogicalRequestIdempotency::Idempotent;
        at_most_once_replay.claim.replay = LogicalRequestReplay::IfIdempotent;
        assert_eq!(
            logical_request_extension(&at_most_once_replay),
            Err(ProfilePayloadError::InvalidPayload)
        );

        let mut at_least_once_without_replay = state();
        at_least_once_without_replay.claim.delivery = DeliveryPolicy::AtLeastOnce;
        at_least_once_without_replay.claim.idempotency = LogicalRequestIdempotency::Idempotent;
        at_least_once_without_replay.claim.replay = LogicalRequestReplay::BeforeSend;
        assert_eq!(
            logical_request_extension(&at_least_once_without_replay),
            Err(ProfilePayloadError::InvalidPayload)
        );
    }

    #[test]
    fn start_requires_exact_request_and_write_authority() {
        let state = state();
        let extension = logical_request_extension(&state).unwrap();
        let operation = LogicalRequestOperation::Start { request: request() };
        let payload = encode_logical_request_operation(&operation).unwrap();
        assert_eq!(
            validate_effect(&extension, state.claim.resource, ProfileAccess::Write, &payload),
            Ok(Rights::PROFILE_WRITE)
        );
        assert_eq!(
            validate_effect(&extension, state.claim.resource, ProfileAccess::Read, &payload),
            Err(ProfilePayloadError::AccessMismatch)
        );

        let changed = encode_logical_request_operation(&LogicalRequestOperation::Start {
            request: b"GET /work/43".to_vec(),
        })
        .unwrap();
        assert_eq!(
            validate_effect(&extension, state.claim.resource, ProfileAccess::Write, &changed,),
            Err(ProfilePayloadError::StateConflict)
        );
    }

    #[test]
    fn partial_response_cursor_and_final_metadata_reduce_deterministically() {
        let mut extension = logical_request_extension(&state()).unwrap();
        apply(
            &mut extension,
            ProfileAccess::Write,
            &LogicalRequestOperation::Start { request: request() },
            &LogicalRequestResult::Started {
                observation: observation(LogicalRequestPhase::Pending),
            },
            10,
        )
        .unwrap();

        apply(
            &mut extension,
            ProfileAccess::Read,
            &LogicalRequestOperation::Observe { max_bytes: 3 },
            &LogicalRequestResult::Observed {
                observation: observation(LogicalRequestPhase::PartialResponse),
                bytes: b"abc".to_vec(),
                response_cursor: 3,
            },
            11,
        )
        .unwrap();
        let partial = logical_request_state(&extension).unwrap();
        assert_eq!(partial.response_cursor, 3);
        assert_eq!(partial.disposition, ContinuityDisposition::Reconnect);

        let complete_response = b"abcde";
        let metadata = LogicalResponseMetadata {
            size: complete_response.len() as u32,
            digest: canonical_digest(complete_response.as_slice()).unwrap(),
        };
        apply(
            &mut extension,
            ProfileAccess::Read,
            &LogicalRequestOperation::Observe { max_bytes: 2 },
            &LogicalRequestResult::Observed {
                observation: LogicalRequestObservation {
                    phase: LogicalRequestPhase::Completed,
                    response: Some(metadata),
                    rejection: None,
                },
                bytes: b"de".to_vec(),
                response_cursor: 5,
            },
            12,
        )
        .unwrap();
        let completed = logical_request_state(&extension).unwrap();
        assert_eq!(completed.phase, LogicalRequestPhase::Completed);
        assert_eq!(completed.response_cursor, 5);
        assert_eq!(completed.response, Some(metadata));
        assert_eq!(completed.last_operation, Some(Identity::from_u128(12)));
    }

    #[test]
    fn lost_acknowledgement_can_reconcile_through_operation_id_replay() {
        let mut extension = logical_request_extension(&state()).unwrap();
        apply(
            &mut extension,
            ProfileAccess::Write,
            &LogicalRequestOperation::Start { request: request() },
            &LogicalRequestResult::Started {
                observation: observation(LogicalRequestPhase::UnknownCompletion),
            },
            20,
        )
        .unwrap();
        apply(
            &mut extension,
            ProfileAccess::Control,
            &LogicalRequestOperation::Reconcile,
            &LogicalRequestResult::Reconciled {
                observation: observation(LogicalRequestPhase::Replaying),
            },
            21,
        )
        .unwrap();

        let replaying = logical_request_state(&extension).unwrap();
        assert_eq!(replaying.phase, LogicalRequestPhase::Replaying);
        assert_eq!(replaying.disposition, ContinuityDisposition::Replay);
    }

    #[test]
    fn completed_request_is_terminal_under_observe_and_reconcile() {
        let response = b"terminal-response";
        let metadata = LogicalResponseMetadata {
            size: response.len() as u32,
            digest: canonical_digest(response.as_slice()).unwrap(),
        };
        let mut completed = state();
        completed.phase = LogicalRequestPhase::Completed;
        completed.response_cursor = metadata.size;
        completed.response = Some(metadata);
        completed.disposition = ContinuityDisposition::Revalidate;
        let mut extension = logical_request_extension(&completed).unwrap();

        assert_eq!(
            apply(
                &mut extension,
                ProfileAccess::Control,
                &LogicalRequestOperation::Reconcile,
                &LogicalRequestResult::Reconciled {
                    observation: observation(LogicalRequestPhase::UnknownCompletion),
                },
                13,
            ),
            Err(ProfilePayloadError::StateConflict)
        );
        apply(
            &mut extension,
            ProfileAccess::Control,
            &LogicalRequestOperation::Reconcile,
            &LogicalRequestResult::Reconciled {
                observation: LogicalRequestObservation {
                    phase: LogicalRequestPhase::Completed,
                    response: Some(metadata),
                    rejection: None,
                },
            },
            14,
        )
        .unwrap();
        assert_eq!(
            logical_request_state(&extension).unwrap().phase,
            LogicalRequestPhase::Completed
        );
    }

    #[test]
    fn start_and_observe_accept_a_peer_cancelled_terminal() {
        let mut start_extension = logical_request_extension(&state()).unwrap();
        apply(
            &mut start_extension,
            ProfileAccess::Write,
            &LogicalRequestOperation::Start { request: request() },
            &LogicalRequestResult::Started {
                observation: observation(LogicalRequestPhase::Cancelled),
            },
            15,
        )
        .unwrap();
        assert_eq!(
            logical_request_state(&start_extension).unwrap().phase,
            LogicalRequestPhase::Cancelled
        );

        let mut pending = state();
        pending.phase = LogicalRequestPhase::Pending;
        pending.disposition = disposition_for(pending.phase);
        let mut observe_extension = logical_request_extension(&pending).unwrap();
        apply(
            &mut observe_extension,
            ProfileAccess::Read,
            &LogicalRequestOperation::Observe { max_bytes: 1 },
            &LogicalRequestResult::Observed {
                observation: observation(LogicalRequestPhase::Cancelled),
                bytes: Vec::new(),
                response_cursor: 0,
            },
            16,
        )
        .unwrap();
        assert_eq!(
            logical_request_state(&observe_extension).unwrap().phase,
            LogicalRequestPhase::Cancelled
        );
    }

    #[test]
    fn non_idempotent_unknown_completion_cannot_enter_replay() {
        let mut non_idempotent = state();
        non_idempotent.claim.delivery = DeliveryPolicy::AtMostOnce;
        non_idempotent.claim.replay = LogicalRequestReplay::Never;
        non_idempotent.claim.idempotency = LogicalRequestIdempotency::NonIdempotent;
        let mut extension = logical_request_extension(&non_idempotent).unwrap();
        apply(
            &mut extension,
            ProfileAccess::Write,
            &LogicalRequestOperation::Start { request: request() },
            &LogicalRequestResult::Started {
                observation: observation(LogicalRequestPhase::UnknownCompletion),
            },
            30,
        )
        .unwrap();

        assert_eq!(
            apply(
                &mut extension,
                ProfileAccess::Control,
                &LogicalRequestOperation::Reconcile,
                &LogicalRequestResult::Reconciled {
                    observation: observation(LogicalRequestPhase::Replaying),
                },
                31,
            ),
            Err(ProfilePayloadError::StateConflict)
        );

        apply(
            &mut extension,
            ProfileAccess::Control,
            &LogicalRequestOperation::Reconcile,
            &LogicalRequestResult::Reconciled {
                observation: LogicalRequestObservation {
                    phase: LogicalRequestPhase::Rejected,
                    response: None,
                    rejection: Some(LogicalRequestRejection::UnsafeReplay),
                },
            },
            32,
        )
        .unwrap();
        assert_eq!(
            logical_request_state(&extension).unwrap().disposition,
            ContinuityDisposition::Reject
        );
    }

    #[test]
    fn before_send_policy_never_replays_an_unknown_completion() {
        let mut before_send = state();
        before_send.claim.delivery = DeliveryPolicy::AtMostOnce;
        before_send.claim.replay = LogicalRequestReplay::BeforeSend;
        before_send.claim.idempotency = LogicalRequestIdempotency::NonIdempotent;
        before_send.phase = LogicalRequestPhase::UnknownCompletion;
        before_send.disposition = ContinuityDisposition::Revalidate;
        before_send.last_operation = Some(Identity::from_u128(50));
        let mut extension = logical_request_extension(&before_send).unwrap();

        assert_eq!(validate_handoff(&extension), Err(ProfilePayloadError::StateConflict));
        assert_eq!(
            apply(
                &mut extension,
                ProfileAccess::Control,
                &LogicalRequestOperation::Reconcile,
                &LogicalRequestResult::Reconciled {
                    observation: observation(LogicalRequestPhase::Replaying),
                },
                51,
            ),
            Err(ProfilePayloadError::StateConflict)
        );
    }

    #[test]
    fn observe_rejects_cursor_gaps() {
        let mut pending = state();
        pending.phase = LogicalRequestPhase::Pending;
        pending.disposition = ContinuityDisposition::Reconnect;
        pending.last_operation = Some(Identity::from_u128(40));
        let mut extension = logical_request_extension(&pending).unwrap();
        assert_eq!(
            apply(
                &mut extension,
                ProfileAccess::Read,
                &LogicalRequestOperation::Observe { max_bytes: 2 },
                &LogicalRequestResult::Observed {
                    observation: observation(LogicalRequestPhase::PartialResponse),
                    bytes: b"ab".to_vec(),
                    response_cursor: 3,
                },
                41,
            ),
            Err(ProfilePayloadError::StateConflict)
        );
    }

    #[test]
    fn unknown_completion_requires_safe_replay_before_handoff() {
        let mut safe = state();
        safe.phase = LogicalRequestPhase::UnknownCompletion;
        safe.disposition = ContinuityDisposition::Revalidate;
        let safe = logical_request_extension(&safe).unwrap();
        assert_eq!(validate_handoff(&safe), Ok(()));

        let mut unsafe_state = state();
        unsafe_state.claim.delivery = DeliveryPolicy::AtMostOnce;
        unsafe_state.claim.replay = LogicalRequestReplay::Never;
        unsafe_state.claim.idempotency = LogicalRequestIdempotency::NonIdempotent;
        unsafe_state.phase = LogicalRequestPhase::UnknownCompletion;
        unsafe_state.disposition = ContinuityDisposition::Revalidate;
        let unsafe_extension = logical_request_extension(&unsafe_state).unwrap();
        assert_eq!(validate_handoff(&unsafe_extension), Err(ProfilePayloadError::StateConflict));
    }
}
