use contract_core::{DeliveryPolicy, Digest};
use visa_profile::{
    ContinuityDisposition, LogicalRequestIdempotency, LogicalRequestPhase, LogicalRequestRejection,
    LogicalRequestReplay, LogicalRequestState, LogicalRequestTransport, LogicalResponseMetadata,
    MAX_LOGICAL_REQUEST_BYTES, MAX_LOGICAL_RESPONSE_BYTES,
};

const MAGIC: &[u8; 8] = b"VISARQ01";
const MAX_SESSION_ID_BYTES: usize = 64 * 1024;
const MAX_PEER_IDENTITY_BYTES: usize = 1024;
const IDENTITY_STRING_BYTES: usize = 32;
const MAX_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1000;

pub const LOGICAL_REQUEST_COMPONENT_STATE_ENCODING: &str = "visa-logical-request-state-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalRequestWorkloadLifecycle {
    Active,
    Frozen,
}

/// Engine-neutral form of the Stage 3B WIT component-state record.
///
/// Credentials are represented only by a canonical identity string. There is
/// no field capable of carrying credential bytes or a native transport handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalRequestComponentState {
    pub session_id: String,
    pub peer_identity: String,
    pub credential_reference: String,
    pub transport: LogicalRequestTransport,
    pub delivery: DeliveryPolicy,
    pub replay: LogicalRequestReplay,
    pub idempotency: LogicalRequestIdempotency,
    pub timeout_millis: u64,
    pub max_request_size: u32,
    pub max_response_size: u32,
    pub operation_id: String,
    pub request_size: u32,
    pub request_digest: Digest,
    pub request_phase: LogicalRequestPhase,
    pub response_cursor: u32,
    pub response: Option<LogicalResponseMetadata>,
    pub rejection: Option<LogicalRequestRejection>,
    pub disposition: ContinuityDisposition,
    pub lifecycle: LogicalRequestWorkloadLifecycle,
}

impl LogicalRequestComponentState {
    pub fn from_canonical(
        session_id: String,
        state: &LogicalRequestState,
        lifecycle: LogicalRequestWorkloadLifecycle,
    ) -> Result<Self, LogicalRequestStateCodecError> {
        let peer_identity = String::from_utf8(state.claim.peer_identity.clone())
            .map_err(|_| LogicalRequestStateCodecError::InvalidUtf8)?;
        let component = Self {
            session_id,
            peer_identity,
            credential_reference: crate::identity_string(state.claim.credential_reference),
            transport: state.claim.transport,
            delivery: state.claim.delivery,
            replay: state.claim.replay,
            idempotency: state.claim.idempotency,
            timeout_millis: state.claim.timeout_millis,
            max_request_size: state.claim.max_request_size,
            max_response_size: state.claim.max_response_size,
            operation_id: crate::identity_string(state.operation_id),
            request_size: state.request_size,
            request_digest: state.request_digest,
            request_phase: state.phase,
            response_cursor: state.response_cursor,
            response: state.response,
            rejection: state.rejection,
            disposition: state.disposition,
            lifecycle,
        };
        validate_shape(&component)?;
        Ok(component)
    }

    pub fn validate_canonical(
        &self,
        state: &LogicalRequestState,
    ) -> Result<(), LogicalRequestStateCodecError> {
        if self.peer_identity.as_bytes() != state.claim.peer_identity
            || self.credential_reference != crate::identity_string(state.claim.credential_reference)
            || self.transport != state.claim.transport
            || self.delivery != state.claim.delivery
            || self.replay != state.claim.replay
            || self.idempotency != state.claim.idempotency
            || self.timeout_millis != state.claim.timeout_millis
            || self.max_request_size != state.claim.max_request_size
            || self.max_response_size != state.claim.max_response_size
            || self.operation_id != crate::identity_string(state.operation_id)
            || self.request_size != state.request_size
            || self.request_digest != state.request_digest
            || self.request_phase != state.phase
            || self.response_cursor != state.response_cursor
            || self.response != state.response
            || self.rejection != state.rejection
            || self.disposition != state.disposition
        {
            return Err(LogicalRequestStateCodecError::CanonicalMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableLogicalRequestState(Vec<u8>);

impl PortableLogicalRequestState {
    pub fn encode(
        state: &LogicalRequestComponentState,
    ) -> Result<Self, LogicalRequestStateCodecError> {
        validate_shape(state)?;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        push_string(&mut bytes, &state.session_id, MAX_SESSION_ID_BYTES)?;
        push_string(&mut bytes, &state.peer_identity, MAX_PEER_IDENTITY_BYTES)?;
        push_string(&mut bytes, &state.credential_reference, IDENTITY_STRING_BYTES)?;
        bytes.push(transport_tag(state.transport));
        bytes.push(delivery_tag(state.delivery));
        bytes.push(replay_tag(state.replay));
        bytes.push(idempotency_tag(state.idempotency));
        bytes.extend_from_slice(&state.timeout_millis.to_be_bytes());
        bytes.extend_from_slice(&state.max_request_size.to_be_bytes());
        bytes.extend_from_slice(&state.max_response_size.to_be_bytes());
        push_string(&mut bytes, &state.operation_id, IDENTITY_STRING_BYTES)?;
        bytes.extend_from_slice(&state.request_size.to_be_bytes());
        bytes.extend_from_slice(&state.request_digest.0);
        bytes.push(request_phase_tag(state.request_phase));
        bytes.extend_from_slice(&state.response_cursor.to_be_bytes());
        match state.response {
            Some(response) => {
                bytes.push(1);
                bytes.extend_from_slice(&response.size.to_be_bytes());
                bytes.extend_from_slice(&response.digest.0);
            }
            None => bytes.push(0),
        }
        match state.rejection {
            Some(rejection) => {
                bytes.push(1);
                bytes.push(rejection_tag(rejection));
            }
            None => bytes.push(0),
        }
        bytes.push(disposition_tag(state.disposition));
        bytes.push(lifecycle_tag(state.lifecycle));
        Ok(Self(bytes))
    }

    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, LogicalRequestStateCodecError> {
        decode(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn decode(&self) -> Result<LogicalRequestComponentState, LogicalRequestStateCodecError> {
        decode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalRequestStateCodecError {
    InvalidMagic,
    Truncated,
    InvalidUtf8,
    InvalidTransport,
    InvalidDeliveryPolicy,
    InvalidReplayPolicy,
    InvalidIdempotency,
    InvalidRequestPhase,
    InvalidRejection,
    InvalidDisposition,
    InvalidOptional,
    InvalidLifecycle,
    InvalidIdentity,
    InvalidState,
    TrailingBytes,
    FieldTooLarge,
    CanonicalMismatch,
}

fn decode(bytes: &[u8]) -> Result<LogicalRequestComponentState, LogicalRequestStateCodecError> {
    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(LogicalRequestStateCodecError::InvalidMagic);
    }
    let session_id = decoder.string(MAX_SESSION_ID_BYTES)?;
    let peer_identity = decoder.string(MAX_PEER_IDENTITY_BYTES)?;
    let credential_reference = decoder.string(IDENTITY_STRING_BYTES)?;
    let transport = match decoder.byte()? {
        0 => LogicalRequestTransport::Reconnectable,
        1 => LogicalRequestTransport::RawLiveTcp,
        _ => return Err(LogicalRequestStateCodecError::InvalidTransport),
    };
    let delivery = match decoder.byte()? {
        0 => DeliveryPolicy::Deduplicated,
        1 => DeliveryPolicy::AtMostOnce,
        2 => DeliveryPolicy::AtLeastOnce,
        3 => DeliveryPolicy::NonRecoverable,
        _ => return Err(LogicalRequestStateCodecError::InvalidDeliveryPolicy),
    };
    let replay = match decoder.byte()? {
        0 => LogicalRequestReplay::Never,
        1 => LogicalRequestReplay::BeforeSend,
        2 => LogicalRequestReplay::IfIdempotent,
        3 => LogicalRequestReplay::WithOperationId,
        _ => return Err(LogicalRequestStateCodecError::InvalidReplayPolicy),
    };
    let idempotency = match decoder.byte()? {
        0 => LogicalRequestIdempotency::NonIdempotent,
        1 => LogicalRequestIdempotency::Idempotent,
        2 => LogicalRequestIdempotency::OperationIdDeduplicated,
        _ => return Err(LogicalRequestStateCodecError::InvalidIdempotency),
    };
    let timeout_millis = decoder.u64()?;
    let max_request_size = decoder.u32()?;
    let max_response_size = decoder.u32()?;
    let operation_id = decoder.string(IDENTITY_STRING_BYTES)?;
    let request_size = decoder.u32()?;
    let request_digest = decoder.digest()?;
    let request_phase = match decoder.byte()? {
        0 => LogicalRequestPhase::Ready,
        1 => LogicalRequestPhase::Pending,
        2 => LogicalRequestPhase::PartialResponse,
        3 => LogicalRequestPhase::UnknownCompletion,
        4 => LogicalRequestPhase::Reconciling,
        5 => LogicalRequestPhase::Replaying,
        6 => LogicalRequestPhase::Cancelling,
        7 => LogicalRequestPhase::Completed,
        8 => LogicalRequestPhase::TimedOut,
        9 => LogicalRequestPhase::Cancelled,
        10 => LogicalRequestPhase::Rejected,
        _ => return Err(LogicalRequestStateCodecError::InvalidRequestPhase),
    };
    let response_cursor = decoder.u32()?;
    let response = match decoder.byte()? {
        0 => None,
        1 => Some(LogicalResponseMetadata { size: decoder.u32()?, digest: decoder.digest()? }),
        _ => return Err(LogicalRequestStateCodecError::InvalidOptional),
    };
    let rejection = match decoder.byte()? {
        0 => None,
        1 => Some(match decoder.byte()? {
            0 => LogicalRequestRejection::PeerMismatch,
            1 => LogicalRequestRejection::CredentialDenied,
            2 => LogicalRequestRejection::UnsafeReplay,
            3 => LogicalRequestRejection::UnsupportedTransport,
            4 => LogicalRequestRejection::PolicyDenied,
            _ => return Err(LogicalRequestStateCodecError::InvalidRejection),
        }),
        _ => return Err(LogicalRequestStateCodecError::InvalidOptional),
    };
    let disposition = match decoder.byte()? {
        0 => ContinuityDisposition::Revalidate,
        1 => ContinuityDisposition::Reconnect,
        2 => ContinuityDisposition::Replay,
        3 => ContinuityDisposition::Reject,
        _ => return Err(LogicalRequestStateCodecError::InvalidDisposition),
    };
    let lifecycle = match decoder.byte()? {
        0 => LogicalRequestWorkloadLifecycle::Active,
        1 => LogicalRequestWorkloadLifecycle::Frozen,
        _ => return Err(LogicalRequestStateCodecError::InvalidLifecycle),
    };
    if decoder.offset != bytes.len() {
        return Err(LogicalRequestStateCodecError::TrailingBytes);
    }

    let state = LogicalRequestComponentState {
        session_id,
        peer_identity,
        credential_reference,
        transport,
        delivery,
        replay,
        idempotency,
        timeout_millis,
        max_request_size,
        max_response_size,
        operation_id,
        request_size,
        request_digest,
        request_phase,
        response_cursor,
        response,
        rejection,
        disposition,
        lifecycle,
    };
    validate_shape(&state)?;
    Ok(state)
}

fn validate_shape(
    state: &LogicalRequestComponentState,
) -> Result<(), LogicalRequestStateCodecError> {
    if !valid_identity_reference(&state.credential_reference)
        || !valid_identity_reference(&state.operation_id)
    {
        return Err(LogicalRequestStateCodecError::InvalidIdentity);
    }

    if state.session_id.is_empty()
        || state.session_id.len() > MAX_SESSION_ID_BYTES
        || state.peer_identity.is_empty()
        || state.peer_identity.len() > MAX_PEER_IDENTITY_BYTES
        || state.peer_identity.as_bytes().contains(&0)
        || state.timeout_millis == 0
        || state.timeout_millis > MAX_TIMEOUT_MILLIS
        || state.max_request_size == 0
        || state.max_request_size > MAX_LOGICAL_REQUEST_BYTES
        || state.max_response_size == 0
        || state.max_response_size > MAX_LOGICAL_RESPONSE_BYTES
        || state.request_size > state.max_request_size
        || state.request_digest == Digest::ZERO
        || state.response_cursor > state.max_response_size
        || state.disposition != disposition_for(state.request_phase)
        || !policy_valid(state)
    {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }

    if let Some(response) = state.response
        && (response.size > state.max_response_size
            || state.response_cursor > response.size
            || response.digest == Digest::ZERO)
    {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }
    if state.request_phase == LogicalRequestPhase::Completed && state.response.is_none() {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }
    if (state.request_phase == LogicalRequestPhase::Rejected) != state.rejection.is_some() {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }
    if state.request_phase == LogicalRequestPhase::Ready
        && (state.response_cursor != 0 || state.response.is_some())
    {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }
    if state.request_phase == LogicalRequestPhase::Replaying
        && state.replay == LogicalRequestReplay::Never
    {
        return Err(LogicalRequestStateCodecError::InvalidState);
    }
    Ok(())
}

fn valid_identity_reference(value: &str) -> bool {
    crate::parse_identity(value).is_some_and(|identity| !identity.is_zero())
}

fn policy_valid(state: &LogicalRequestComponentState) -> bool {
    if state.delivery == DeliveryPolicy::Deduplicated
        && state.idempotency != LogicalRequestIdempotency::OperationIdDeduplicated
    {
        return false;
    }
    if state.delivery == DeliveryPolicy::AtLeastOnce
        && state.idempotency == LogicalRequestIdempotency::NonIdempotent
    {
        return false;
    }
    if state.delivery == DeliveryPolicy::NonRecoverable
        && state.replay != LogicalRequestReplay::Never
    {
        return false;
    }
    match state.replay {
        LogicalRequestReplay::Never | LogicalRequestReplay::BeforeSend => true,
        LogicalRequestReplay::IfIdempotent => {
            state.idempotency == LogicalRequestIdempotency::Idempotent
        }
        LogicalRequestReplay::WithOperationId => {
            state.delivery == DeliveryPolicy::Deduplicated
                && state.idempotency == LogicalRequestIdempotency::OperationIdDeduplicated
        }
    }
}

fn push_string(
    output: &mut Vec<u8>,
    value: &str,
    max_length: usize,
) -> Result<(), LogicalRequestStateCodecError> {
    if value.len() > max_length {
        return Err(LogicalRequestStateCodecError::FieldTooLarge);
    }
    let length =
        u32::try_from(value.len()).map_err(|_| LogicalRequestStateCodecError::FieldTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

const fn transport_tag(value: LogicalRequestTransport) -> u8 {
    match value {
        LogicalRequestTransport::Reconnectable => 0,
        LogicalRequestTransport::RawLiveTcp => 1,
    }
}

const fn delivery_tag(value: DeliveryPolicy) -> u8 {
    match value {
        DeliveryPolicy::Deduplicated => 0,
        DeliveryPolicy::AtMostOnce => 1,
        DeliveryPolicy::AtLeastOnce => 2,
        DeliveryPolicy::NonRecoverable => 3,
    }
}

const fn replay_tag(value: LogicalRequestReplay) -> u8 {
    match value {
        LogicalRequestReplay::Never => 0,
        LogicalRequestReplay::BeforeSend => 1,
        LogicalRequestReplay::IfIdempotent => 2,
        LogicalRequestReplay::WithOperationId => 3,
    }
}

const fn idempotency_tag(value: LogicalRequestIdempotency) -> u8 {
    match value {
        LogicalRequestIdempotency::NonIdempotent => 0,
        LogicalRequestIdempotency::Idempotent => 1,
        LogicalRequestIdempotency::OperationIdDeduplicated => 2,
    }
}

const fn request_phase_tag(value: LogicalRequestPhase) -> u8 {
    match value {
        LogicalRequestPhase::Ready => 0,
        LogicalRequestPhase::Pending => 1,
        LogicalRequestPhase::PartialResponse => 2,
        LogicalRequestPhase::UnknownCompletion => 3,
        LogicalRequestPhase::Reconciling => 4,
        LogicalRequestPhase::Replaying => 5,
        LogicalRequestPhase::Cancelling => 6,
        LogicalRequestPhase::Completed => 7,
        LogicalRequestPhase::TimedOut => 8,
        LogicalRequestPhase::Cancelled => 9,
        LogicalRequestPhase::Rejected => 10,
    }
}

const fn rejection_tag(value: LogicalRequestRejection) -> u8 {
    match value {
        LogicalRequestRejection::PeerMismatch => 0,
        LogicalRequestRejection::CredentialDenied => 1,
        LogicalRequestRejection::UnsafeReplay => 2,
        LogicalRequestRejection::UnsupportedTransport => 3,
        LogicalRequestRejection::PolicyDenied => 4,
    }
}

const fn disposition_tag(value: ContinuityDisposition) -> u8 {
    match value {
        ContinuityDisposition::Revalidate => 0,
        ContinuityDisposition::Reconnect => 1,
        ContinuityDisposition::Replay => 2,
        ContinuityDisposition::Reject => 3,
    }
}

const fn lifecycle_tag(value: LogicalRequestWorkloadLifecycle) -> u8 {
    match value {
        LogicalRequestWorkloadLifecycle::Active => 0,
        LogicalRequestWorkloadLifecycle::Frozen => 1,
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

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], LogicalRequestStateCodecError> {
        let end =
            self.offset.checked_add(length).ok_or(LogicalRequestStateCodecError::Truncated)?;
        let value =
            self.bytes.get(self.offset..end).ok_or(LogicalRequestStateCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, LogicalRequestStateCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, LogicalRequestStateCodecError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| LogicalRequestStateCodecError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, LogicalRequestStateCodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| LogicalRequestStateCodecError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<Digest, LogicalRequestStateCodecError> {
        Ok(Digest::from_bytes(
            self.take(32)?.try_into().map_err(|_| LogicalRequestStateCodecError::Truncated)?,
        ))
    }

    fn string(&mut self, max_length: usize) -> Result<String, LogicalRequestStateCodecError> {
        let length = self.u32()? as usize;
        if length > max_length {
            return Err(LogicalRequestStateCodecError::FieldTooLarge);
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| LogicalRequestStateCodecError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use contract_core::{EntityRef, Identity, Rights};
    use visa_profile::LogicalRequestClaim;

    use super::*;

    fn canonical() -> LogicalRequestState {
        LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: EntityRef::initial(Identity::from_u128(1)),
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
            request_size: 12,
            request_digest: Digest::from_bytes([4; 32]),
            phase: LogicalRequestPhase::PartialResponse,
            response_cursor: 3,
            response: Some(LogicalResponseMetadata {
                size: 5,
                digest: Digest::from_bytes([5; 32]),
            }),
            rejection: None,
            disposition: ContinuityDisposition::Reconnect,
            last_operation: Some(Identity::from_u128(4)),
        }
    }

    #[test]
    fn portable_request_state_round_trips_and_matches_canonical_truth() {
        let state = LogicalRequestComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            LogicalRequestWorkloadLifecycle::Frozen,
        )
        .unwrap();
        assert_eq!(state.credential_reference, crate::identity_string(Identity::from_u128(2)));
        assert_eq!(state.operation_id, crate::identity_string(Identity::from_u128(3)));

        let first = PortableLogicalRequestState::encode(&state).unwrap();
        let second = PortableLogicalRequestState::encode(&state).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first.as_bytes()[..MAGIC.len()], MAGIC);

        let decoded = first.decode().unwrap();
        assert_eq!(decoded, state);
        decoded.validate_canonical(&canonical()).unwrap();
    }

    #[test]
    fn canonical_peer_credential_and_cursor_drift_are_rejected() {
        let state = LogicalRequestComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            LogicalRequestWorkloadLifecycle::Active,
        )
        .unwrap();

        let mut changed = canonical();
        changed.claim.credential_reference = Identity::from_u128(9);
        assert_eq!(
            state.validate_canonical(&changed),
            Err(LogicalRequestStateCodecError::CanonicalMismatch)
        );
        changed = canonical();
        changed.claim.peer_identity = b"different-peer".to_vec();
        assert_eq!(
            state.validate_canonical(&changed),
            Err(LogicalRequestStateCodecError::CanonicalMismatch)
        );
        changed = canonical();
        changed.response_cursor += 1;
        assert_eq!(
            state.validate_canonical(&changed),
            Err(LogicalRequestStateCodecError::CanonicalMismatch)
        );
    }

    #[test]
    fn credential_field_accepts_only_an_identity_reference() {
        let mut state = LogicalRequestComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            LogicalRequestWorkloadLifecycle::Frozen,
        )
        .unwrap();
        state.credential_reference = "bearer-secret-material".into();
        assert_eq!(
            PortableLogicalRequestState::encode(&state),
            Err(LogicalRequestStateCodecError::InvalidIdentity)
        );
    }

    #[test]
    fn decoder_rejects_corruption_truncation_and_trailing_data() {
        let state = LogicalRequestComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            LogicalRequestWorkloadLifecycle::Frozen,
        )
        .unwrap();
        let encoded = PortableLogicalRequestState::encode(&state).unwrap();

        let mut corrupt = encoded.as_bytes().to_vec();
        corrupt[0] ^= 0xff;
        assert_eq!(
            PortableLogicalRequestState::try_from_bytes(corrupt),
            Err(LogicalRequestStateCodecError::InvalidMagic)
        );

        let mut truncated = encoded.as_bytes().to_vec();
        truncated.pop();
        assert_eq!(
            PortableLogicalRequestState::try_from_bytes(truncated),
            Err(LogicalRequestStateCodecError::Truncated)
        );

        let mut trailing = encoded.into_bytes();
        trailing.push(0);
        assert_eq!(
            PortableLogicalRequestState::try_from_bytes(trailing),
            Err(LogicalRequestStateCodecError::TrailingBytes)
        );
    }

    #[test]
    fn canonical_non_utf8_peer_identity_is_not_exposed_to_the_guest() {
        let mut state = canonical();
        state.claim.peer_identity = vec![0xff];
        assert_eq!(
            LogicalRequestComponentState::from_canonical(
                "session-a".into(),
                &state,
                LogicalRequestWorkloadLifecycle::Active,
            ),
            Err(LogicalRequestStateCodecError::InvalidUtf8)
        );
    }
}
