use contract_core::{CanonicalState, ProfileAccess};
use visa_component_adapter::{
    AdapterProvider, BindingError, ProfileBinding, ProfileCallResult, ProfileFailure,
    identity_string, profile_execute, profile_observe,
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestOperation, LogicalRequestResult,
    LogicalRequestState, LogicalRequestTransport, ProfilePayloadError,
    decode_logical_request_result, encode_logical_request_operation, logical_request_state,
};
use visa_runtime::Coordinator;
use wasmtime::component::{Resource, ResourceTable};

use super::{
    bindings::visa::request_continuity::logical_request::{
        Host, HostRequestBinding, ObserveResult, RequestError, RequestObservation, Transport,
    },
    state::{to_wit_phase, to_wit_rejection, to_wit_response},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalRequestError {
    Invalid,
    UnsupportedRawLiveTcp,
}

/// Wasmtime-local state for the Stage 3B world. The table contains an opaque
/// binding receipt only; it never contains a socket, credential, or response
/// stream whose identity could accidentally become portable.
pub struct LogicalRequestStoreState<P> {
    coordinator: Coordinator<P>,
    table: ResourceTable,
}

impl<P> LogicalRequestStoreState<P> {
    pub(crate) fn new(coordinator: Coordinator<P>) -> Self {
        Self { coordinator, table: ResourceTable::new() }
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        &self.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.coordinator
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub(crate) fn into_coordinator(self) -> Coordinator<P> {
        self.coordinator
    }

    pub(crate) fn fresh_request_resource(
        &mut self,
    ) -> Result<Resource<ProfileBinding>, BindingError> {
        if !self.table.is_empty() {
            return Err(BindingError::LiveResources);
        }
        let binding =
            ProfileBinding::for_state(self.coordinator.state(), LOGICAL_REQUEST_EXTENSION_ID)?;
        self.table.push(binding).map_err(|_| BindingError::ResourceTable)
    }
}

impl<P> Host for LogicalRequestStoreState<P> where P: AdapterProvider {}

impl<P> HostRequestBinding for LogicalRequestStoreState<P>
where
    P: AdapterProvider,
{
    fn start(
        &mut self,
        resource: Resource<ProfileBinding>,
        operation_id: String,
        peer_identity: String,
        credential_reference: String,
        request: Vec<u8>,
        timeout_ms: u64,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(start(
            &mut self.coordinator,
            &binding,
            operation_id,
            peer_identity,
            credential_reference,
            request,
            timeout_ms,
        ))
    }

    fn observe(
        &mut self,
        resource: Resource<ProfileBinding>,
        operation_id: String,
        max_bytes: u32,
    ) -> wasmtime::Result<Result<ObserveResult, RequestError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(observe(&mut self.coordinator, &binding, operation_id, max_bytes))
    }

    fn reconcile(
        &mut self,
        resource: Resource<ProfileBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(control(
            &mut self.coordinator,
            &binding,
            operation_id,
            LogicalRequestOperation::Reconcile,
            ControlKind::Reconcile,
        ))
    }

    fn cancel(
        &mut self,
        resource: Resource<ProfileBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(control(
            &mut self.coordinator,
            &binding,
            operation_id,
            LogicalRequestOperation::Cancel,
            ControlKind::Cancel,
        ))
    }

    fn drop(&mut self, resource: Resource<ProfileBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

fn start<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation_id: String,
    peer_identity: String,
    credential_reference: String,
    request: Vec<u8>,
    timeout_ms: u64,
) -> Result<RequestObservation, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &operation_id)?;
    if before.claim.peer_identity != peer_identity.as_bytes() {
        return Err(RequestError::PeerMismatch);
    }
    if identity_string(before.claim.credential_reference) != credential_reference {
        return Err(RequestError::CredentialDenied);
    }
    if before.claim.timeout_millis != timeout_ms {
        return Err(RequestError::PolicyDenied);
    }

    let operation = LogicalRequestOperation::Start { request };
    let payload =
        encode_logical_request_operation(&operation).map_err(|_| RequestError::PolicyDenied)?;
    let call = profile_execute(
        coordinator,
        binding,
        ProfileAccess::Write,
        operation_id.as_bytes(),
        payload,
    )
    .map_err(|error| request_error(error, FailureContext::Start))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    if !matches!(result, LogicalRequestResult::Started { .. }) {
        return Err(RequestError::Unavailable);
    }
    observation_after(coordinator.state(), &call)
}

fn observe<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation_id: String,
    max_bytes: u32,
) -> Result<ObserveResult, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &operation_id)?;
    let operation = LogicalRequestOperation::Observe { max_bytes };
    let payload =
        encode_logical_request_operation(&operation).map_err(|_| RequestError::InvalidCursor)?;
    let call = profile_observe(coordinator, binding, payload)
        .map_err(|error| request_error(error, FailureContext::Observe))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    let LogicalRequestResult::Observed { bytes, response_cursor, .. } = result else {
        return Err(RequestError::Unavailable);
    };
    let observation = observation_after(coordinator.state(), &call)?;
    let canonical = request_state_for_call(coordinator.state())?;
    if response_cursor != canonical.response_cursor {
        return Err(RequestError::InvalidCursor);
    }
    Ok(ObserveResult { observation, bytes, response_cursor })
}

#[derive(Clone, Copy)]
enum ControlKind {
    Reconcile,
    Cancel,
}

fn control<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation_id: String,
    operation: LogicalRequestOperation,
    kind: ControlKind,
) -> Result<RequestObservation, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &operation_id)?;
    let idempotency = control_idempotency(kind, &before);
    let payload =
        encode_logical_request_operation(&operation).map_err(|_| RequestError::PolicyDenied)?;
    let call = profile_execute(coordinator, binding, ProfileAccess::Control, &idempotency, payload)
        .map_err(|error| request_error(error, FailureContext::Control))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    let expected = matches!(
        (&kind, &result),
        (ControlKind::Reconcile, LogicalRequestResult::Reconciled { .. })
            | (ControlKind::Cancel, LogicalRequestResult::Cancelled { .. })
    );
    if !expected {
        return Err(RequestError::Unavailable);
    }
    observation_after(coordinator.state(), &call)
}

fn control_idempotency(kind: ControlKind, state: &LogicalRequestState) -> Vec<u8> {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(match kind {
        ControlKind::Reconcile => b"logical-request-reconcile-v1".as_slice(),
        ControlKind::Cancel => b"logical-request-cancel-v1".as_slice(),
    });
    value.extend_from_slice(&state.operation_id.0);
    match state.last_operation {
        Some(operation) => value.extend_from_slice(&operation.0),
        None => value.extend_from_slice(&[0; 16]),
    }
    value
}

fn observation_after(
    state: &CanonicalState,
    call: &ProfileCallResult,
) -> Result<RequestObservation, RequestError> {
    let state = request_state_for_call(state)?;
    if state.last_operation != Some(call.operation) {
        return Err(RequestError::Unavailable);
    }
    Ok(RequestObservation {
        operation_id: identity_string(state.operation_id),
        phase: to_wit_phase(state.phase),
        response: state.response.map(to_wit_response),
        rejection: state.rejection.map(to_wit_rejection),
    })
}

fn validate_operation_id(state: &LogicalRequestState, supplied: &str) -> Result<(), RequestError> {
    if identity_string(state.operation_id) == supplied {
        Ok(())
    } else {
        Err(RequestError::PolicyDenied)
    }
}

fn validate_transport(state: &LogicalRequestState) -> Result<(), RequestError> {
    match state.claim.transport {
        LogicalRequestTransport::Reconnectable => Ok(()),
        LogicalRequestTransport::RawLiveTcp => {
            Err(RequestError::UnsupportedTransport(Transport::RawLiveTcp))
        }
    }
}

#[derive(Clone, Copy)]
enum FailureContext {
    Start,
    Observe,
    Control,
}

fn request_error(error: ProfileFailure, context: FailureContext) -> RequestError {
    match error {
        ProfileFailure::Denied if matches!(context, FailureContext::Start) => {
            RequestError::CredentialDenied
        }
        ProfileFailure::Denied => RequestError::Denied,
        ProfileFailure::Conflict if matches!(context, FailureContext::Start) => {
            RequestError::PeerMismatch
        }
        ProfileFailure::Conflict if matches!(context, FailureContext::Observe) => {
            RequestError::InvalidCursor
        }
        ProfileFailure::Conflict => RequestError::PolicyDenied,
        ProfileFailure::StaleBinding => RequestError::StaleBinding,
        ProfileFailure::Invalid => RequestError::PolicyDenied,
        ProfileFailure::Unsupported => RequestError::UnsupportedTransport(Transport::RawLiveTcp),
        ProfileFailure::Cancelled => RequestError::Unavailable,
        ProfileFailure::Indeterminate(operation) => RequestError::Indeterminate(operation),
        ProfileFailure::Unavailable => RequestError::Unavailable,
    }
}

fn request_state_for_call(state: &CanonicalState) -> Result<LogicalRequestState, RequestError> {
    match canonical_logical_request(state) {
        Ok(state) => Ok(state),
        Err(CanonicalRequestError::UnsupportedRawLiveTcp) => {
            Err(RequestError::UnsupportedTransport(Transport::RawLiveTcp))
        }
        Err(CanonicalRequestError::Invalid) => Err(RequestError::Unavailable),
    }
}

pub(crate) fn canonical_logical_request(
    state: &CanonicalState,
) -> Result<LogicalRequestState, CanonicalRequestError> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or(CanonicalRequestError::Invalid)?;
    if matching.next().is_some() {
        return Err(CanonicalRequestError::Invalid);
    }
    logical_request_state(extension).map_err(|error| match error {
        ProfilePayloadError::UnsupportedContinuity => CanonicalRequestError::UnsupportedRawLiveTcp,
        _ => CanonicalRequestError::Invalid,
    })
}

#[cfg(test)]
mod tests {
    use contract_core::{DeliveryPolicy, Digest, EntityRef, Identity, Rights};
    use visa_profile::{
        ContinuityDisposition, LogicalRequestClaim, LogicalRequestIdempotency, LogicalRequestPhase,
        LogicalRequestReplay,
    };

    use super::*;

    fn state() -> LogicalRequestState {
        LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: EntityRef::initial(Identity::from_u128(1)),
                peer_identity: b"service.example/v1".to_vec(),
                credential_reference: Identity::from_u128(2),
                required_rights: Rights::ALL,
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 5_000,
                max_request_size: 1024,
                max_response_size: 4096,
            },
            operation_id: Identity::from_u128(3),
            request_size: 3,
            request_digest: Digest::from_bytes([4; 32]),
            phase: LogicalRequestPhase::Pending,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Reconnect,
            last_operation: Some(Identity::from_u128(5)),
        }
    }

    #[test]
    fn control_idempotency_separates_action_and_advances_with_canonical_effect() {
        let first = state();
        let reconcile = control_idempotency(ControlKind::Reconcile, &first);
        let cancel = control_idempotency(ControlKind::Cancel, &first);
        assert_ne!(reconcile, cancel);

        let mut next = first;
        next.last_operation = Some(Identity::from_u128(6));
        assert_ne!(reconcile, control_idempotency(ControlKind::Reconcile, &next));
    }

    #[test]
    fn profile_failures_keep_request_specific_error_meaning() {
        assert!(matches!(
            request_error(ProfileFailure::Denied, FailureContext::Start),
            RequestError::CredentialDenied
        ));
        assert!(matches!(
            request_error(ProfileFailure::Conflict, FailureContext::Observe),
            RequestError::InvalidCursor
        ));
        assert!(matches!(
            request_error(ProfileFailure::Unsupported, FailureContext::Control),
            RequestError::UnsupportedTransport(Transport::RawLiveTcp)
        ));
    }
}
