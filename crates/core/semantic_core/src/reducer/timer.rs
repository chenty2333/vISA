use contract_core::{
    CanonicalState, Decision, EffectKind, EffectOutcome, EffectResult, EntityRef, EventKind,
    HandoffPhase, Identity, LeaseEpoch, Rejection, Replay, TimerDisposition, TimerStatus,
};

use super::{commit, local_active, reject_phase};

pub(super) fn preflight_timer_completed(
    state: &CanonicalState,
    event_id: Identity,
    timer: EntityRef,
    arm_operation: Identity,
    lease_epoch: LeaseEpoch,
    evidence: contract_core::EvidenceRef,
) -> Decision {
    if !matches!(state.phase, HandoffPhase::Running | HandoffPhase::Quiescing) {
        return reject_phase(state);
    }
    if timer.identity == state.timer.claim.resource.identity
        && timer.generation != state.timer.claim.resource.generation
    {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: timer.identity,
            expected: state.timer.claim.resource.generation,
            actual: timer.generation,
        });
    }
    if timer != state.timer.claim.resource {
        return Decision::Reject(Rejection::TimerStateConflict);
    }
    if !local_active(state) {
        return reject_phase(state);
    }
    let epoch = state.ownership.epoch;
    if epoch != lease_epoch {
        return Decision::Reject(Rejection::LeaseEpochMismatch {
            expected: epoch,
            actual: lease_epoch,
        });
    }
    match state.timer.status {
        TimerStatus::Armed { .. } if state.timer.active_operation == Some(arm_operation) => {
            commit(event_id, EventKind::TimerCompleted { timer, arm_operation, evidence })
        }
        TimerStatus::Completed | TimerStatus::Cleaned => Decision::Replay(Replay::NoChange),
        _ => Decision::Reject(Rejection::TimerStateConflict),
    }
}

pub(super) fn quiescing_timer_completion_parent(
    state: &CanonicalState,
    causal_parent: Option<Identity>,
) -> bool {
    if state.timer.status != TimerStatus::Completed {
        return false;
    }
    let Some(causal_parent) = causal_parent else {
        return false;
    };

    state.operations.iter().rev().find_map(|record| match (&record.request.kind, &record.outcome) {
        (
            EffectKind::TimerArm { .. },
            Some(EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. }),
        ) if record.request.resource == state.timer.claim.resource => {
            Some(record.request.operation)
        }
        _ => None,
    }) == Some(causal_parent)
}

pub(super) fn valid_timer_freeze(state: &CanonicalState, disposition: TimerDisposition) -> bool {
    match (state.timer.status, disposition) {
        (TimerStatus::Idle, TimerDisposition::Idle)
        | (TimerStatus::Completed, TimerDisposition::Completed)
        | (TimerStatus::Cancelled, TimerDisposition::Cancelled)
        | (TimerStatus::Cleaned, TimerDisposition::Cleaned) => true,
        (
            TimerStatus::Armed { remaining: armed },
            TimerDisposition::Pending { remaining, arm_operation },
        ) => {
            remaining.0 > 0
                && remaining.0 <= armed.0
                && state.timer.active_operation == Some(arm_operation)
        }
        _ => false,
    }
}

pub(super) fn thaw_timer(state: &mut CanonicalState) {
    state.timer.status = match state.timer.status {
        TimerStatus::Frozen(TimerDisposition::Idle) => TimerStatus::Idle,
        TimerStatus::Frozen(TimerDisposition::Pending { remaining, arm_operation }) => {
            state.timer.active_operation = Some(arm_operation);
            TimerStatus::Armed { remaining }
        }
        TimerStatus::Frozen(TimerDisposition::Completed) => {
            state.timer.active_operation = None;
            TimerStatus::Completed
        }
        TimerStatus::Frozen(TimerDisposition::Cancelled) => {
            state.timer.active_operation = None;
            TimerStatus::Cancelled
        }
        TimerStatus::Frozen(TimerDisposition::Cleaned) => {
            state.timer.active_operation = None;
            TimerStatus::Cleaned
        }
        status => status,
    };
}
