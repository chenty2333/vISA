use contract_core::{DeliveryPolicy, Digest};
use visa_component_adapter::{
    LogicalRequestComponentState, LogicalRequestStateCodecError, LogicalRequestWorkloadLifecycle,
};
use visa_profile::{
    ContinuityDisposition, LogicalRequestIdempotency, LogicalRequestPhase, LogicalRequestRejection,
    LogicalRequestReplay, LogicalRequestTransport, LogicalResponseMetadata,
};

use super::bindings::{
    exports::visa::request_continuity::workload::{
        ComponentState as WitComponentState, Lifecycle as WitLifecycle,
    },
    visa::request_continuity::logical_request::{
        ContinuityDisposition as WitDisposition, DeliveryPolicy as WitDelivery,
        Idempotency as WitIdempotency, ReplayPolicy as WitReplay, RequestPhase as WitPhase,
        RequestRejection as WitRejection, ResponseMetadata as WitResponse,
        Transport as WitTransport,
    },
};

pub(crate) fn from_wit_state(
    state: WitComponentState,
) -> Result<LogicalRequestComponentState, LogicalRequestStateCodecError> {
    Ok(LogicalRequestComponentState {
        session_id: state.session_id,
        peer_identity: state.peer_identity,
        credential_reference: state.credential_reference,
        transport: from_wit_transport(state.transport),
        delivery: from_wit_delivery(state.delivery),
        replay: from_wit_replay(state.replay),
        idempotency: from_wit_idempotency(state.idempotency),
        timeout_millis: state.timeout_ms,
        max_request_size: state.max_request_size,
        max_response_size: state.max_response_size,
        operation_id: state.operation_id,
        request_size: state.request_size,
        request_digest: digest(state.request_digest)?,
        request_phase: from_wit_phase(state.request_phase),
        response_cursor: state.response_cursor,
        response: state.response.map(from_wit_response).transpose()?,
        rejection: state.rejection.map(from_wit_rejection),
        disposition: from_wit_disposition(state.disposition),
        lifecycle: from_wit_lifecycle(state.lifecycle),
    })
}

pub(crate) fn to_wit_state(state: &LogicalRequestComponentState) -> WitComponentState {
    WitComponentState {
        session_id: state.session_id.clone(),
        peer_identity: state.peer_identity.clone(),
        credential_reference: state.credential_reference.clone(),
        transport: to_wit_transport(state.transport),
        delivery: to_wit_delivery(state.delivery),
        replay: to_wit_replay(state.replay),
        idempotency: to_wit_idempotency(state.idempotency),
        timeout_ms: state.timeout_millis,
        max_request_size: state.max_request_size,
        max_response_size: state.max_response_size,
        operation_id: state.operation_id.clone(),
        request_size: state.request_size,
        request_digest: state.request_digest.0.to_vec(),
        request_phase: to_wit_phase(state.request_phase),
        response_cursor: state.response_cursor,
        response: state.response.map(to_wit_response),
        rejection: state.rejection.map(to_wit_rejection),
        disposition: to_wit_disposition(state.disposition),
        lifecycle: to_wit_lifecycle(state.lifecycle),
    }
}

pub(crate) fn to_wit_response(value: LogicalResponseMetadata) -> WitResponse {
    WitResponse { size: value.size, digest: value.digest.0.to_vec() }
}

fn from_wit_response(
    value: WitResponse,
) -> Result<LogicalResponseMetadata, LogicalRequestStateCodecError> {
    Ok(LogicalResponseMetadata { size: value.size, digest: digest(value.digest)? })
}

fn digest(bytes: Vec<u8>) -> Result<Digest, LogicalRequestStateCodecError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| LogicalRequestStateCodecError::Truncated)?;
    Ok(Digest::from_bytes(bytes))
}

pub(crate) const fn from_wit_transport(value: WitTransport) -> LogicalRequestTransport {
    match value {
        WitTransport::Reconnectable => LogicalRequestTransport::Reconnectable,
        WitTransport::RawLiveTcp => LogicalRequestTransport::RawLiveTcp,
    }
}

pub(crate) const fn to_wit_transport(value: LogicalRequestTransport) -> WitTransport {
    match value {
        LogicalRequestTransport::Reconnectable => WitTransport::Reconnectable,
        LogicalRequestTransport::RawLiveTcp => WitTransport::RawLiveTcp,
    }
}

const fn from_wit_delivery(value: WitDelivery) -> DeliveryPolicy {
    match value {
        WitDelivery::Deduplicated => DeliveryPolicy::Deduplicated,
        WitDelivery::AtMostOnce => DeliveryPolicy::AtMostOnce,
        WitDelivery::AtLeastOnce => DeliveryPolicy::AtLeastOnce,
        WitDelivery::NonRecoverable => DeliveryPolicy::NonRecoverable,
    }
}

const fn to_wit_delivery(value: DeliveryPolicy) -> WitDelivery {
    match value {
        DeliveryPolicy::Deduplicated => WitDelivery::Deduplicated,
        DeliveryPolicy::AtMostOnce => WitDelivery::AtMostOnce,
        DeliveryPolicy::AtLeastOnce => WitDelivery::AtLeastOnce,
        DeliveryPolicy::NonRecoverable => WitDelivery::NonRecoverable,
    }
}

const fn from_wit_replay(value: WitReplay) -> LogicalRequestReplay {
    match value {
        WitReplay::Never => LogicalRequestReplay::Never,
        WitReplay::BeforeSend => LogicalRequestReplay::BeforeSend,
        WitReplay::IfIdempotent => LogicalRequestReplay::IfIdempotent,
        WitReplay::WithOperationId => LogicalRequestReplay::WithOperationId,
    }
}

const fn to_wit_replay(value: LogicalRequestReplay) -> WitReplay {
    match value {
        LogicalRequestReplay::Never => WitReplay::Never,
        LogicalRequestReplay::BeforeSend => WitReplay::BeforeSend,
        LogicalRequestReplay::IfIdempotent => WitReplay::IfIdempotent,
        LogicalRequestReplay::WithOperationId => WitReplay::WithOperationId,
    }
}

const fn from_wit_idempotency(value: WitIdempotency) -> LogicalRequestIdempotency {
    match value {
        WitIdempotency::NonIdempotent => LogicalRequestIdempotency::NonIdempotent,
        WitIdempotency::Idempotent => LogicalRequestIdempotency::Idempotent,
        WitIdempotency::OperationIdDeduplicated => {
            LogicalRequestIdempotency::OperationIdDeduplicated
        }
    }
}

const fn to_wit_idempotency(value: LogicalRequestIdempotency) -> WitIdempotency {
    match value {
        LogicalRequestIdempotency::NonIdempotent => WitIdempotency::NonIdempotent,
        LogicalRequestIdempotency::Idempotent => WitIdempotency::Idempotent,
        LogicalRequestIdempotency::OperationIdDeduplicated => {
            WitIdempotency::OperationIdDeduplicated
        }
    }
}

pub(crate) const fn from_wit_phase(value: WitPhase) -> LogicalRequestPhase {
    match value {
        WitPhase::Ready => LogicalRequestPhase::Ready,
        WitPhase::Pending => LogicalRequestPhase::Pending,
        WitPhase::PartialResponse => LogicalRequestPhase::PartialResponse,
        WitPhase::UnknownCompletion => LogicalRequestPhase::UnknownCompletion,
        WitPhase::Reconciling => LogicalRequestPhase::Reconciling,
        WitPhase::Replaying => LogicalRequestPhase::Replaying,
        WitPhase::Cancelling => LogicalRequestPhase::Cancelling,
        WitPhase::Completed => LogicalRequestPhase::Completed,
        WitPhase::TimedOut => LogicalRequestPhase::TimedOut,
        WitPhase::Cancelled => LogicalRequestPhase::Cancelled,
        WitPhase::Rejected => LogicalRequestPhase::Rejected,
    }
}

pub(crate) const fn to_wit_phase(value: LogicalRequestPhase) -> WitPhase {
    match value {
        LogicalRequestPhase::Ready => WitPhase::Ready,
        LogicalRequestPhase::Pending => WitPhase::Pending,
        LogicalRequestPhase::PartialResponse => WitPhase::PartialResponse,
        LogicalRequestPhase::UnknownCompletion => WitPhase::UnknownCompletion,
        LogicalRequestPhase::Reconciling => WitPhase::Reconciling,
        LogicalRequestPhase::Replaying => WitPhase::Replaying,
        LogicalRequestPhase::Cancelling => WitPhase::Cancelling,
        LogicalRequestPhase::Completed => WitPhase::Completed,
        LogicalRequestPhase::TimedOut => WitPhase::TimedOut,
        LogicalRequestPhase::Cancelled => WitPhase::Cancelled,
        LogicalRequestPhase::Rejected => WitPhase::Rejected,
    }
}

pub(crate) const fn from_wit_rejection(value: WitRejection) -> LogicalRequestRejection {
    match value {
        WitRejection::PeerMismatch => LogicalRequestRejection::PeerMismatch,
        WitRejection::CredentialDenied => LogicalRequestRejection::CredentialDenied,
        WitRejection::UnsafeReplay => LogicalRequestRejection::UnsafeReplay,
        WitRejection::UnsupportedTransport => LogicalRequestRejection::UnsupportedTransport,
        WitRejection::PolicyDenied => LogicalRequestRejection::PolicyDenied,
    }
}

pub(crate) const fn to_wit_rejection(value: LogicalRequestRejection) -> WitRejection {
    match value {
        LogicalRequestRejection::PeerMismatch => WitRejection::PeerMismatch,
        LogicalRequestRejection::CredentialDenied => WitRejection::CredentialDenied,
        LogicalRequestRejection::UnsafeReplay => WitRejection::UnsafeReplay,
        LogicalRequestRejection::UnsupportedTransport => WitRejection::UnsupportedTransport,
        LogicalRequestRejection::PolicyDenied => WitRejection::PolicyDenied,
    }
}

const fn from_wit_disposition(value: WitDisposition) -> ContinuityDisposition {
    match value {
        WitDisposition::Revalidate => ContinuityDisposition::Revalidate,
        WitDisposition::Reconnect => ContinuityDisposition::Reconnect,
        WitDisposition::Replay => ContinuityDisposition::Replay,
        WitDisposition::Reject => ContinuityDisposition::Reject,
    }
}

const fn to_wit_disposition(value: ContinuityDisposition) -> WitDisposition {
    match value {
        ContinuityDisposition::Revalidate => WitDisposition::Revalidate,
        ContinuityDisposition::Reconnect => WitDisposition::Reconnect,
        ContinuityDisposition::Replay => WitDisposition::Replay,
        ContinuityDisposition::Reject => WitDisposition::Reject,
    }
}

const fn from_wit_lifecycle(value: WitLifecycle) -> LogicalRequestWorkloadLifecycle {
    match value {
        WitLifecycle::Active => LogicalRequestWorkloadLifecycle::Active,
        WitLifecycle::Frozen => LogicalRequestWorkloadLifecycle::Frozen,
    }
}

const fn to_wit_lifecycle(value: LogicalRequestWorkloadLifecycle) -> WitLifecycle {
    match value {
        LogicalRequestWorkloadLifecycle::Active => WitLifecycle::Active,
        LogicalRequestWorkloadLifecycle::Frozen => WitLifecycle::Frozen,
    }
}

#[cfg(test)]
mod tests {
    use contract_core::Identity;

    use super::*;

    fn state() -> LogicalRequestComponentState {
        LogicalRequestComponentState {
            session_id: "session-a".into(),
            peer_identity: "service.example/v1".into(),
            credential_reference: visa_component_adapter::identity_string(Identity::from_u128(1)),
            transport: LogicalRequestTransport::Reconnectable,
            delivery: DeliveryPolicy::Deduplicated,
            replay: LogicalRequestReplay::WithOperationId,
            idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
            timeout_millis: 5_000,
            max_request_size: 1024,
            max_response_size: 4096,
            operation_id: visa_component_adapter::identity_string(Identity::from_u128(2)),
            request_size: 3,
            request_digest: Digest::from_bytes([3; 32]),
            request_phase: LogicalRequestPhase::PartialResponse,
            response_cursor: 2,
            response: Some(LogicalResponseMetadata {
                size: 4,
                digest: Digest::from_bytes([4; 32]),
            }),
            rejection: None,
            disposition: ContinuityDisposition::Reconnect,
            lifecycle: LogicalRequestWorkloadLifecycle::Frozen,
        }
    }

    #[test]
    fn wit_state_round_trips_all_policy_and_continuity_fields() {
        let state = state();
        assert_eq!(from_wit_state(to_wit_state(&state)).unwrap(), state);
    }

    #[test]
    fn wit_state_rejects_non_digest_request_metadata() {
        let mut wit = to_wit_state(&state());
        wit.request_digest.pop();
        assert_eq!(from_wit_state(wit), Err(LogicalRequestStateCodecError::Truncated));
    }
}
