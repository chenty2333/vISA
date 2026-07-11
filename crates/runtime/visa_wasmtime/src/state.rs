use visa_component_adapter::{ComponentState, WorkloadPhase};

use crate::bindings::exports::visa::continuity::workload::{
    ComponentState as WitComponentState, Phase as WitPhase,
};

pub(crate) fn from_wit_state(state: WitComponentState) -> ComponentState {
    ComponentState {
        session_id: state.session_id,
        key: state.key,
        expected_version: state.expected_version,
        completion_value: state.completion_value,
        timer_operation_id: state.timer_operation_id,
        timer_idempotency_key: state.timer_idempotency_key,
        completion_idempotency_key: state.completion_idempotency_key,
        phase: from_wit_phase(state.phase),
    }
}

pub(crate) fn to_wit_state(state: ComponentState) -> WitComponentState {
    WitComponentState {
        session_id: state.session_id,
        key: state.key,
        expected_version: state.expected_version,
        completion_value: state.completion_value,
        timer_operation_id: state.timer_operation_id,
        timer_idempotency_key: state.timer_idempotency_key,
        completion_idempotency_key: state.completion_idempotency_key,
        phase: to_wit_phase(state.phase),
    }
}

const fn from_wit_phase(phase: WitPhase) -> WorkloadPhase {
    match phase {
        WitPhase::Armed => WorkloadPhase::Armed,
        WitPhase::Frozen => WorkloadPhase::Frozen,
        WitPhase::Completed => WorkloadPhase::Completed,
        WitPhase::Cancelled => WorkloadPhase::Cancelled,
    }
}

const fn to_wit_phase(phase: WorkloadPhase) -> WitPhase {
    match phase {
        WorkloadPhase::Armed => WitPhase::Armed,
        WorkloadPhase::Frozen => WitPhase::Frozen,
        WorkloadPhase::Completed => WitPhase::Completed,
        WorkloadPhase::Cancelled => WitPhase::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_state_round_trips_through_engine_neutral_state() {
        let state = WitComponentState {
            session_id: "session-a".into(),
            key: "work".into(),
            expected_version: 7,
            completion_value: vec![0, 1, 255],
            timer_operation_id: "timer-op".into(),
            timer_idempotency_key: "timer-key".into(),
            completion_idempotency_key: "completion-key".into(),
            phase: WitPhase::Frozen,
        };

        let round_trip = to_wit_state(from_wit_state(state));
        assert_eq!(round_trip.session_id, "session-a");
        assert_eq!(round_trip.expected_version, 7);
        assert_eq!(round_trip.completion_value, vec![0, 1, 255]);
        assert_eq!(round_trip.phase, WitPhase::Frozen);
    }
}
