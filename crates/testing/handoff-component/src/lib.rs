wit_bindgen::generate!({
    path: "../../../wit/cooperative-handoff",
    world: "cooperative-handoff",
});

use std::cell::RefCell;

use exports::visa::continuity::workload::{ComponentState, Guest, Phase, WorkloadError};
use visa::continuity::{
    key_value::{KvError, Namespace},
    timers::{TimerBinding, TimerError},
};

struct LiveState {
    portable: ComponentState,
    kv: Option<Namespace>,
    timer: Option<TimerBinding>,
}

thread_local! {
    static STATE: RefCell<Option<LiveState>> = const { RefCell::new(None) };
}

struct HandoffWorkload;

impl Guest for HandoffWorkload {
    fn activate(
        session_id: String,
        key: String,
        initial_value: Vec<u8>,
        completion_value: Vec<u8>,
        delay_ns: u64,
        baseline_idempotency_key: String,
        timer_idempotency_key: String,
        completion_idempotency_key: String,
        kv: Namespace,
        timer: TimerBinding,
    ) -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            if slot.is_some() {
                return Err(WorkloadError::AlreadyActive);
            }

            let baseline = kv
                .conditional_put(&baseline_idempotency_key, &key, None, &initial_value)
                .map_err(WorkloadError::Kv)?;
            if !baseline.applied {
                return Err(WorkloadError::Kv(KvError::Conflict));
            }
            let observed = kv.read(&key).map_err(WorkloadError::Kv)?;
            if !observed.is_some_and(|value| {
                value.version == baseline.version && value.value == initial_value
            }) {
                return Err(WorkloadError::InvalidState);
            }
            let armed =
                timer.arm(&timer_idempotency_key, delay_ns).map_err(WorkloadError::Timer)?;

            *slot = Some(LiveState {
                portable: ComponentState {
                    session_id,
                    key,
                    expected_version: baseline.version,
                    completion_value,
                    timer_operation_id: armed.operation_id,
                    timer_idempotency_key,
                    completion_idempotency_key,
                    phase: Phase::Armed,
                },
                kv: Some(kv),
                timer: Some(timer),
            });
            Ok(())
        })
    }

    fn freeze() -> Result<ComponentState, WorkloadError> {
        if STATE.with_borrow(|slot| {
            slot.as_ref()
                .is_some_and(|live| live.portable.session_id == "safe-point-unreachable:session")
        }) {
            return Err(WorkloadError::SafePointUnavailable);
        }

        STATE.with_borrow_mut(|slot| {
            let mut live = slot.take().ok_or(WorkloadError::InvalidState)?;
            if live.portable.phase == Phase::Armed {
                live.portable.phase = Phase::Frozen;
            }
            Ok(live.portable)
        })
    }

    fn thaw(
        mut state: ComponentState,
        kv: Namespace,
        timer: TimerBinding,
    ) -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            if slot.is_some() {
                return Err(WorkloadError::AlreadyActive);
            }

            match state.phase {
                Phase::Frozen => {
                    state.phase = Phase::Armed;
                    *slot = Some(LiveState { portable: state, kv: Some(kv), timer: Some(timer) });
                }
                Phase::Completed | Phase::Cancelled => {
                    *slot = Some(LiveState { portable: state, kv: None, timer: None });
                }
                Phase::Armed => return Err(WorkloadError::InvalidState),
            }
            Ok(())
        })
    }

    fn restore(
        mut state: ComponentState,
        remaining_duration_ns: u64,
        kv: Namespace,
        timer: TimerBinding,
    ) -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            if slot.is_some() {
                return Err(WorkloadError::AlreadyActive);
            }

            match state.phase {
                Phase::Frozen => {
                    let armed = timer
                        .arm(&state.timer_idempotency_key, remaining_duration_ns)
                        .map_err(WorkloadError::Timer)?;
                    state.timer_operation_id = armed.operation_id;
                    state.phase = Phase::Armed;
                    *slot = Some(LiveState { portable: state, kv: Some(kv), timer: Some(timer) });
                }
                Phase::Completed | Phase::Cancelled => {
                    *slot = Some(LiveState { portable: state, kv: None, timer: None });
                }
                Phase::Armed => return Err(WorkloadError::InvalidState),
            }
            Ok(())
        })
    }

    fn timer_fired(operation_id: String) -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = slot.as_mut().ok_or(WorkloadError::InvalidState)?;
            if live.portable.phase != Phase::Armed {
                return Err(WorkloadError::InvalidState);
            }
            if operation_id != live.portable.timer_operation_id {
                return Err(WorkloadError::WrongTimer);
            }

            let kv = live.kv.as_ref().ok_or(WorkloadError::InvalidState)?;
            let write = kv
                .conditional_put(
                    &live.portable.completion_idempotency_key,
                    &live.portable.key,
                    Some(live.portable.expected_version),
                    &live.portable.completion_value,
                )
                .map_err(WorkloadError::Kv)?;
            if !write.applied {
                return Err(WorkloadError::Kv(KvError::Conflict));
            }
            live.portable.expected_version = write.version;
            live.portable.phase = Phase::Completed;
            live.timer = None;
            Ok(())
        })
    }

    fn cancel_pending() -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = slot.as_mut().ok_or(WorkloadError::InvalidState)?;
            if live.portable.phase != Phase::Armed {
                return Err(WorkloadError::InvalidState);
            }
            let timer = live.timer.as_ref().ok_or(WorkloadError::InvalidState)?;
            timer.cancel(&live.portable.timer_operation_id).map_err(WorkloadError::Timer)?;
            live.portable.phase = Phase::Cancelled;
            live.timer = None;
            Ok(())
        })
    }

    fn status() -> Option<ComponentState> {
        STATE.with_borrow(|slot| slot.as_ref().map(|live| live.portable.clone()))
    }
}

impl From<KvError> for WorkloadError {
    fn from(error: KvError) -> Self {
        Self::Kv(error)
    }
}

impl From<TimerError> for WorkloadError {
    fn from(error: TimerError) -> Self {
        Self::Timer(error)
    }
}

export!(HandoffWorkload);
