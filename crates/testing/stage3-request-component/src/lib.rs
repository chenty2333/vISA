wit_bindgen::generate!({
    path: "../../../wit/logical-request-continuity",
    world: "logical-request-continuity",
});

use std::cell::RefCell;

use exports::visa::request_continuity::workload::{
    ComponentState, Guest, Lifecycle, WorkloadError,
};
use visa::request_continuity::logical_request::{
    ContinuityDisposition, DeliveryPolicy, Idempotency, ObserveResult, ReplayPolicy,
    RequestBinding, RequestError, RequestObservation, RequestPhase, ResponseMetadata, Transport,
};

const MAX_RESPONSE_CHUNK_BYTES: u32 = 64 * 1024;

struct LiveState {
    portable: ComponentState,
    request: RequestBinding,
}

thread_local! {
    static STATE: RefCell<Option<LiveState>> = const { RefCell::new(None) };
}

struct RequestWorkload;

impl Guest for RequestWorkload {
    fn activate(
        session_id: String,
        state: ComponentState,
        request: RequestBinding,
    ) -> Result<(), WorkloadError> {
        if state.session_id != session_id || state.lifecycle != Lifecycle::Active {
            return Err(WorkloadError::InvalidState);
        }
        install(state, request, Lifecycle::Active)
    }

    fn start(bytes: Vec<u8>) -> Result<RequestObservation, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            if live.portable.request_phase != RequestPhase::Ready
                || usize::try_from(live.portable.request_size).ok() != Some(bytes.len())
                || live.portable.request_size > live.portable.max_request_size
            {
                return Err(WorkloadError::InvalidState);
            }

            let observed = live
                .request
                .start(
                    &live.portable.operation_id,
                    &live.portable.peer_identity,
                    &live.portable.credential_reference,
                    &bytes,
                    live.portable.timeout_ms,
                )
                .map_err(WorkloadError::Request)?;
            apply_observation(&mut live.portable, &observed, Operation::Start)?;
            Ok(observed)
        })
    }

    fn observe(max_bytes: u32) -> Result<ObserveResult, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            if max_bytes == 0
                || max_bytes > MAX_RESPONSE_CHUNK_BYTES
                || !matches!(
                    live.portable.request_phase,
                    RequestPhase::Pending | RequestPhase::PartialResponse | RequestPhase::Completed
                )
            {
                return Err(WorkloadError::InvalidState);
            }

            let result = live
                .request
                .observe(&live.portable.operation_id, max_bytes)
                .map_err(WorkloadError::Request)?;
            let consumed =
                u32::try_from(result.bytes.len()).map_err(|_| WorkloadError::InvalidState)?;
            if consumed > max_bytes
                || result.response_cursor != live.portable.response_cursor.saturating_add(consumed)
                || result.response_cursor > live.portable.max_response_size
            {
                return Err(WorkloadError::InvalidState);
            }
            let mut next = live.portable.clone();
            next.response_cursor = result.response_cursor;
            apply_observation(&mut next, &result.observation, Operation::Observe)?;
            live.portable = next;
            Ok(result)
        })
    }

    fn reconcile() -> Result<RequestObservation, WorkloadError> {
        control(
            |phase| {
                matches!(
                    phase,
                    RequestPhase::Pending
                        | RequestPhase::PartialResponse
                        | RequestPhase::UnknownCompletion
                        | RequestPhase::Reconciling
                        | RequestPhase::Replaying
                        | RequestPhase::Cancelling
                        | RequestPhase::Completed
                )
            },
            Operation::Reconcile,
            |request, operation_id| request.reconcile(operation_id),
        )
    }

    fn cancel() -> Result<RequestObservation, WorkloadError> {
        control(
            |phase| {
                matches!(
                    phase,
                    RequestPhase::Pending
                        | RequestPhase::PartialResponse
                        | RequestPhase::UnknownCompletion
                        | RequestPhase::Reconciling
                        | RequestPhase::Replaying
                        | RequestPhase::Cancelling
                )
            },
            Operation::Cancel,
            |request, operation_id| request.cancel(operation_id),
        )
    }

    fn freeze() -> Result<ComponentState, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let mut live = slot.take().ok_or(WorkloadError::InvalidState)?;
            if live.portable.session_id == "safe-point-unreachable:session" {
                *slot = Some(live);
                return Err(WorkloadError::SafePointUnavailable);
            }
            if !state_valid(&live.portable) {
                *slot = Some(live);
                return Err(WorkloadError::InvalidState);
            }

            live.portable.lifecycle = Lifecycle::Frozen;
            Ok(live.portable)
        })
    }

    fn thaw(state: ComponentState, request: RequestBinding) -> Result<(), WorkloadError> {
        install(state, request, Lifecycle::Frozen)
    }

    fn restore(state: ComponentState, request: RequestBinding) -> Result<(), WorkloadError> {
        install(state, request, Lifecycle::Frozen)
    }

    fn status() -> Option<ComponentState> {
        STATE.with_borrow(|slot| slot.as_ref().map(|live| live.portable.clone()))
    }
}

fn active(slot: &mut Option<LiveState>) -> Result<&mut LiveState, WorkloadError> {
    let live = slot.as_mut().ok_or(WorkloadError::InvalidState)?;
    if live.portable.lifecycle != Lifecycle::Active {
        return Err(WorkloadError::InvalidState);
    }
    Ok(live)
}

fn control(
    phase_allowed: impl FnOnce(RequestPhase) -> bool,
    operation: Operation,
    call: impl FnOnce(&RequestBinding, &str) -> Result<RequestObservation, RequestError>,
) -> Result<RequestObservation, WorkloadError> {
    STATE.with_borrow_mut(|slot| {
        let live = active(slot)?;
        if !phase_allowed(live.portable.request_phase) {
            return Err(WorkloadError::InvalidState);
        }
        let observed =
            call(&live.request, &live.portable.operation_id).map_err(WorkloadError::Request)?;
        apply_observation(&mut live.portable, &observed, operation)?;
        Ok(observed)
    })
}

fn install(
    mut state: ComponentState,
    request: RequestBinding,
    expected_lifecycle: Lifecycle,
) -> Result<(), WorkloadError> {
    if state.lifecycle != expected_lifecycle {
        return Err(WorkloadError::InvalidState);
    }
    if state.transport == Transport::RawLiveTcp {
        return Err(WorkloadError::Request(RequestError::UnsupportedTransport(
            Transport::RawLiveTcp,
        )));
    }
    if !state_valid(&state) {
        return Err(WorkloadError::InvalidState);
    }

    STATE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return Err(WorkloadError::AlreadyActive);
        }
        state.lifecycle = Lifecycle::Active;
        *slot = Some(LiveState { portable: state, request });
        Ok(())
    })
}

fn state_valid(state: &ComponentState) -> bool {
    if state.session_id.is_empty()
        || state.peer_identity.is_empty()
        || state.peer_identity.contains('\0')
        || state.credential_reference.is_empty()
        || state.operation_id.is_empty()
        || state.timeout_ms == 0
        || state.max_request_size == 0
        || state.max_response_size == 0
        || state.request_size > state.max_request_size
        || state.request_digest.is_empty()
        || state.response_cursor > state.max_response_size
        || state.transport != Transport::Reconnectable
        || state.disposition != disposition_for(state.request_phase)
        || !policy_valid(state)
    {
        return false;
    }

    if state.response.as_ref().is_some_and(|response| {
        response.size > state.max_response_size
            || state.response_cursor > response.size
            || response.digest.is_empty()
    }) {
        return false;
    }
    if state.request_phase == RequestPhase::Completed && state.response.is_none() {
        return false;
    }
    if (state.request_phase == RequestPhase::Rejected) != state.rejection.is_some() {
        return false;
    }
    if state.request_phase == RequestPhase::Ready
        && (state.response_cursor != 0 || state.response.is_some() || state.rejection.is_some())
    {
        return false;
    }
    state.request_phase != RequestPhase::Replaying || replay_is_safe(state)
}

fn policy_valid(state: &ComponentState) -> bool {
    if state.delivery == DeliveryPolicy::Deduplicated
        && state.idempotency != Idempotency::OperationIdDeduplicated
    {
        return false;
    }
    if state.delivery == DeliveryPolicy::AtLeastOnce
        && state.idempotency == Idempotency::NonIdempotent
    {
        return false;
    }
    if state.delivery == DeliveryPolicy::NonRecoverable && state.replay != ReplayPolicy::Never {
        return false;
    }
    match state.replay {
        ReplayPolicy::Never | ReplayPolicy::BeforeSend => true,
        ReplayPolicy::IfIdempotent => state.idempotency == Idempotency::Idempotent,
        ReplayPolicy::WithOperationId => {
            state.delivery == DeliveryPolicy::Deduplicated
                && state.idempotency == Idempotency::OperationIdDeduplicated
        }
    }
}

fn replay_is_safe(state: &ComponentState) -> bool {
    state.replay != ReplayPolicy::Never
}

fn apply_observation(
    state: &mut ComponentState,
    observed: &RequestObservation,
    operation: Operation,
) -> Result<(), WorkloadError> {
    if observed.operation_id != state.operation_id
        || observed.phase == RequestPhase::Ready
        || !result_phase_allowed(operation, observed.phase)
        || (observed.phase == RequestPhase::Replaying && !replay_is_safe(state))
        || (observed.phase == RequestPhase::Rejected) != observed.rejection.is_some()
    {
        return Err(WorkloadError::InvalidState);
    }

    if let Some(response) = &observed.response {
        if !valid_response(state, response)
            || state
                .response
                .as_ref()
                .is_some_and(|known| known.size != response.size || known.digest != response.digest)
        {
            return Err(WorkloadError::InvalidState);
        }
        state.response = Some(response.clone());
    }
    if observed.phase == RequestPhase::Completed && state.response.is_none() {
        return Err(WorkloadError::InvalidState);
    }

    state.request_phase = observed.phase;
    state.rejection = observed.rejection;
    state.disposition = disposition_for(observed.phase);
    Ok(())
}

#[derive(Clone, Copy)]
enum Operation {
    Start,
    Observe,
    Reconcile,
    Cancel,
}

const fn result_phase_allowed(operation: Operation, phase: RequestPhase) -> bool {
    match operation {
        Operation::Start | Operation::Observe => matches!(
            phase,
            RequestPhase::Pending
                | RequestPhase::PartialResponse
                | RequestPhase::Completed
                | RequestPhase::UnknownCompletion
                | RequestPhase::TimedOut
                | RequestPhase::Rejected
        ),
        Operation::Reconcile => matches!(
            phase,
            RequestPhase::Pending
                | RequestPhase::PartialResponse
                | RequestPhase::UnknownCompletion
                | RequestPhase::Reconciling
                | RequestPhase::Replaying
                | RequestPhase::Completed
                | RequestPhase::TimedOut
                | RequestPhase::Cancelled
                | RequestPhase::Rejected
        ),
        Operation::Cancel => matches!(
            phase,
            RequestPhase::UnknownCompletion
                | RequestPhase::Cancelling
                | RequestPhase::Completed
                | RequestPhase::TimedOut
                | RequestPhase::Cancelled
                | RequestPhase::Rejected
        ),
    }
}

fn valid_response(state: &ComponentState, response: &ResponseMetadata) -> bool {
    response.size <= state.max_response_size
        && state.response_cursor <= response.size
        && !response.digest.is_empty()
}

const fn disposition_for(phase: RequestPhase) -> ContinuityDisposition {
    match phase {
        RequestPhase::Pending | RequestPhase::PartialResponse | RequestPhase::Cancelling => {
            ContinuityDisposition::Reconnect
        }
        RequestPhase::Replaying => ContinuityDisposition::Replay,
        RequestPhase::Rejected => ContinuityDisposition::Reject,
        RequestPhase::Ready
        | RequestPhase::UnknownCompletion
        | RequestPhase::Reconciling
        | RequestPhase::Completed
        | RequestPhase::TimedOut
        | RequestPhase::Cancelled => ContinuityDisposition::Revalidate,
    }
}

export!(RequestWorkload);
