//! Guest for the composite continuity world.
//!
//! One instance holds four imported resource handles at once - key-value,
//! timer, regular file, and logical request - alongside a single portable
//! record covering all four. Freezing drops the whole handle set together so
//! the safe point cannot observe a partially released component.

wit_bindgen::generate!({
    path: "../../../wit/composite-continuity",
    world: "composite-continuity",
    generate_all,
});

use std::cell::RefCell;

use exports::visa::composite_continuity::workload::{
    ArmResult, CompositeError, CompositePhase, CompositeState, Durability, FileObservation,
    FilePhase, Guest, KvError, ObserveResult, ReadResult, RequestLifecycle, RequestObservation,
    RequestPhase, Transport,
};
use visa::{
    continuity::{key_value::Namespace, timers::TimerBinding},
    file_continuity::regular_file::FileBinding,
    request_continuity::logical_request::RequestBinding,
};

const MAX_RESPONSE_CHUNK_BYTES: u32 = 64 * 1024;

/// Sentinel used by the safe-point fault tests, matching the Stage 3 guests.
const UNREACHABLE_SAFE_POINT_SESSION: &str = "safe-point-unreachable:session";

struct LiveState {
    portable: CompositeState,
    kv: Option<Namespace>,
    timer: Option<TimerBinding>,
    file: Option<FileBinding>,
    request: Option<RequestBinding>,
}

thread_local! {
    static STATE: RefCell<Option<LiveState>> = const { RefCell::new(None) };
}

struct CompositeWorkload;

impl Guest for CompositeWorkload {
    fn activate(
        session_id: String,
        state: CompositeState,
        kv: Namespace,
        timer: TimerBinding,
        file: FileBinding,
        request: RequestBinding,
    ) -> Result<(), CompositeError> {
        if state.session_id != session_id
            || state.phase != CompositePhase::Active
            || state.file.phase != FilePhase::Active
            || state.request.lifecycle != RequestLifecycle::Active
        {
            return Err(CompositeError::InvalidState);
        }
        install(state, kv, timer, file, request, CompositePhase::Active)
    }

    fn kv_put(idempotency_key: String, value: Vec<u8>) -> Result<u64, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let kv = live.kv.as_ref().ok_or(CompositeError::InvalidState)?;
            let expected = expected_version(&live.portable);
            let key = live.portable.timer_kv.key.clone();
            let write = kv
                .conditional_put(&idempotency_key, &key, expected, &value)
                .map_err(CompositeError::Kv)?;
            if !write.applied {
                return Err(CompositeError::Kv(KvError::Conflict));
            }
            live.portable.timer_kv.expected_version = write.version;
            Ok(write.version)
        })
    }

    fn kv_get() -> Result<Option<u64>, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let kv = live.kv.as_ref().ok_or(CompositeError::InvalidState)?;
            let observed = kv.read(&live.portable.timer_kv.key).map_err(CompositeError::Kv)?;
            let version = observed.map(|value| value.version);
            // A read that disagrees with the version this component believes it
            // wrote means another writer reached the namespace.
            if let Some(version) = version
                && live.portable.timer_kv.expected_version != 0
                && version != live.portable.timer_kv.expected_version
            {
                return Err(CompositeError::InvalidState);
            }
            Ok(version)
        })
    }

    fn timer_arm(duration_ns: u64) -> Result<ArmResult, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            if live.portable.timer_kv.timer_operation_id.is_some()
                || live.portable.timer_kv.timer_completed
            {
                return Err(CompositeError::InvalidState);
            }
            let timer = live.timer.as_ref().ok_or(CompositeError::InvalidState)?;
            let armed = timer
                .arm(&live.portable.timer_kv.timer_idempotency_key, duration_ns)
                .map_err(CompositeError::Timer)?;
            live.portable.timer_kv.timer_operation_id = Some(armed.operation_id.clone());
            Ok(armed)
        })
    }

    fn timer_fired(operation_id: String) -> Result<(), CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            if live.portable.timer_kv.timer_completed {
                return Err(CompositeError::InvalidState);
            }
            if live.portable.timer_kv.timer_operation_id.as_deref() != Some(operation_id.as_str()) {
                return Err(CompositeError::WrongTimer);
            }
            let kv = live.kv.as_ref().ok_or(CompositeError::InvalidState)?;
            let write = kv
                .conditional_put(
                    &live.portable.timer_kv.completion_idempotency_key,
                    &live.portable.timer_kv.key,
                    expected_version(&live.portable),
                    &live.portable.timer_kv.completion_value,
                )
                .map_err(CompositeError::Kv)?;
            if !write.applied {
                return Err(CompositeError::Kv(KvError::Conflict));
            }
            live.portable.timer_kv.expected_version = write.version;
            live.portable.timer_kv.timer_completed = true;
            live.timer = None;
            Ok(())
        })
    }

    fn file_append(
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: Durability,
    ) -> Result<FileObservation, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let file = live.file.as_ref().ok_or(CompositeError::InvalidState)?;
            let observed =
                file.append(&idempotency_key, &bytes, durability).map_err(CompositeError::File)?;
            apply_file_observation(&mut live.portable, &observed);
            Ok(observed)
        })
    }

    fn file_read(max_bytes: u32) -> Result<ReadResult, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let file = live.file.as_ref().ok_or(CompositeError::InvalidState)?;
            let result = file.read(max_bytes).map_err(CompositeError::File)?;
            apply_file_observation(&mut live.portable, &result.observation);
            Ok(result)
        })
    }

    fn request_start(bytes: Vec<u8>) -> Result<RequestObservation, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let request = live.request.as_ref().ok_or(CompositeError::InvalidState)?;
            let state = &live.portable.request;
            if state.request_phase != RequestPhase::Ready
                || usize::try_from(state.request_size).ok() != Some(bytes.len())
                || state.request_size > state.max_request_size
            {
                return Err(CompositeError::InvalidState);
            }
            let observed = request
                .start(
                    &state.operation_id,
                    &state.peer_identity,
                    &state.credential_reference,
                    &bytes,
                    state.timeout_ms,
                )
                .map_err(CompositeError::Request)?;
            apply_request_observation(&mut live.portable, &observed)?;
            Ok(observed)
        })
    }

    fn request_observe(max_bytes: u32) -> Result<ObserveResult, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let request = live.request.as_ref().ok_or(CompositeError::InvalidState)?;
            let state = &live.portable.request;
            if max_bytes == 0
                || max_bytes > MAX_RESPONSE_CHUNK_BYTES
                || !matches!(
                    state.request_phase,
                    RequestPhase::Pending | RequestPhase::PartialResponse | RequestPhase::Completed
                )
            {
                return Err(CompositeError::InvalidState);
            }
            let result =
                request.observe(&state.operation_id, max_bytes).map_err(CompositeError::Request)?;
            let consumed =
                u32::try_from(result.bytes.len()).map_err(|_| CompositeError::InvalidState)?;
            if consumed > max_bytes
                || result.response_cursor != state.response_cursor.saturating_add(consumed)
                || result.response_cursor > state.max_response_size
            {
                return Err(CompositeError::InvalidState);
            }
            live.portable.request.response_cursor = result.response_cursor;
            apply_request_observation(&mut live.portable, &result.observation)?;
            Ok(result)
        })
    }

    fn freeze() -> Result<CompositeState, CompositeError> {
        STATE.with_borrow_mut(|slot| {
            let mut live = slot.take().ok_or(CompositeError::InvalidState)?;
            if let Err(error) = safe_point_reachable(&live.portable) {
                *slot = Some(live);
                return Err(error);
            }
            live.portable.phase = CompositePhase::Frozen;
            live.portable.file.phase = FilePhase::Frozen;
            live.portable.request.lifecycle = RequestLifecycle::Frozen;
            // Taking the slot drops the key-value, timer, file, and request
            // handles as one unit, so no single resource can outlive the
            // safe point.
            Ok(live.portable)
        })
    }

    fn thaw(
        state: CompositeState,
        kv: Namespace,
        timer: TimerBinding,
        file: FileBinding,
        request: RequestBinding,
    ) -> Result<(), CompositeError> {
        install(state, kv, timer, file, request, CompositePhase::Frozen)
    }

    fn restore(
        mut state: CompositeState,
        remaining_duration_ns: Option<u64>,
        kv: Namespace,
        timer: TimerBinding,
        file: FileBinding,
        request: RequestBinding,
    ) -> Result<(), CompositeError> {
        if state.phase != CompositePhase::Frozen {
            return Err(CompositeError::InvalidState);
        }
        // A timer that was pending at the safe point is re-armed on the
        // destination for exactly the remaining duration the source observed.
        match (remaining_duration_ns, state.timer_kv.timer_completed) {
            (Some(remaining), false) => {
                if state.timer_kv.timer_operation_id.is_none() {
                    return Err(CompositeError::InvalidState);
                }
                let armed = timer
                    .arm(&state.timer_kv.timer_idempotency_key, remaining)
                    .map_err(CompositeError::Timer)?;
                state.timer_kv.timer_operation_id = Some(armed.operation_id);
            }
            (Some(_), true) => return Err(CompositeError::InvalidState),
            (None, _) => {}
        }
        install(state, kv, timer, file, request, CompositePhase::Frozen)
    }

    fn status() -> Option<CompositeState> {
        STATE.with_borrow(|slot| slot.as_ref().map(|live| live.portable.clone()))
    }
}

fn active(slot: &mut Option<LiveState>) -> Result<&mut LiveState, CompositeError> {
    let live = slot.as_mut().ok_or(CompositeError::InvalidState)?;
    if live.portable.phase != CompositePhase::Active {
        return Err(CompositeError::InvalidState);
    }
    Ok(live)
}

fn install(
    mut state: CompositeState,
    kv: Namespace,
    timer: TimerBinding,
    file: FileBinding,
    request: RequestBinding,
    expected_phase: CompositePhase,
) -> Result<(), CompositeError> {
    if state.phase != expected_phase {
        return Err(CompositeError::InvalidState);
    }
    if state.request.transport != Transport::Reconnectable {
        return Err(CompositeError::InvalidState);
    }
    STATE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return Err(CompositeError::AlreadyActive);
        }
        state.phase = CompositePhase::Active;
        state.file.phase = FilePhase::Active;
        state.request.lifecycle = RequestLifecycle::Active;
        *slot = Some(LiveState {
            portable: state,
            kv: Some(kv),
            timer: Some(timer),
            file: Some(file),
            request: Some(request),
        });
        Ok(())
    })
}

/// A safe point requires every one of the four resources to be at a boundary
/// the destination can resume from.
fn safe_point_reachable(state: &CompositeState) -> Result<(), CompositeError> {
    if state.session_id == UNREACHABLE_SAFE_POINT_SESSION {
        return Err(CompositeError::SafePointUnavailable);
    }
    if state.file.lock_held {
        return Err(CompositeError::SafePointUnavailable);
    }
    if matches!(
        state.request.request_phase,
        RequestPhase::Reconciling | RequestPhase::Replaying | RequestPhase::Cancelling
    ) {
        return Err(CompositeError::SafePointUnavailable);
    }
    Ok(())
}

/// Version 0 stands for "this component has not written the key yet", which
/// the key-value import expresses as an absent expected version.
const fn expected_version(state: &CompositeState) -> Option<u64> {
    if state.timer_kv.expected_version == 0 { None } else { Some(state.timer_kv.expected_version) }
}

fn apply_file_observation(state: &mut CompositeState, observed: &FileObservation) {
    state.file.logical_offset = observed.logical_offset;
    state.file.version = observed.version;
    state.file.size = observed.size;
    state.file.content_digest.clone_from(&observed.content_digest);
    state.file.durable_through = observed.durable_through;
    state.file.last_operation_id = Some(observed.operation_id.clone());
}

fn apply_request_observation(
    state: &mut CompositeState,
    observed: &RequestObservation,
) -> Result<(), CompositeError> {
    if observed.operation_id != state.request.operation_id
        || observed.phase == RequestPhase::Ready
        || (observed.phase == RequestPhase::Rejected) != observed.rejection.is_some()
    {
        return Err(CompositeError::InvalidState);
    }
    if let Some(response) = &observed.response {
        if response.size > state.request.max_response_size
            || state.request.response_cursor > response.size
            || response.digest.is_empty()
            || state
                .request
                .response
                .as_ref()
                .is_some_and(|known| known.size != response.size || known.digest != response.digest)
        {
            return Err(CompositeError::InvalidState);
        }
        state.request.response = Some(response.clone());
    }
    if observed.phase == RequestPhase::Completed && state.request.response.is_none() {
        return Err(CompositeError::InvalidState);
    }
    state.request.request_phase = observed.phase;
    state.request.rejection = observed.rejection;
    state.request.disposition = disposition_for(observed.phase);
    Ok(())
}

const fn disposition_for(
    phase: RequestPhase,
) -> exports::visa::composite_continuity::workload::ContinuityDisposition {
    use exports::visa::composite_continuity::workload::ContinuityDisposition as Disposition;
    match phase {
        RequestPhase::Pending | RequestPhase::PartialResponse | RequestPhase::Cancelling => {
            Disposition::Reconnect
        }
        RequestPhase::Replaying => Disposition::Replay,
        RequestPhase::Rejected => Disposition::Reject,
        RequestPhase::Ready
        | RequestPhase::UnknownCompletion
        | RequestPhase::Reconciling
        | RequestPhase::Completed
        | RequestPhase::TimedOut
        | RequestPhase::Cancelled => Disposition::Revalidate,
    }
}

export!(CompositeWorkload);
