mod authority;
mod effect;
mod handoff;
mod preflight;
mod timer;
mod transition;

use alloc::vec::Vec;

use authority::{
    authorize, grant_by_identity, preflight_attenuation, preflight_revocation,
    validate_destination_authorities,
};
use contract_core::{
    ActivationStatus, CanonicalState, Decision, Event, EventKind, Identity, Rejection,
};
use effect::{
    apply_effect_outcome, operation_record, outcome_evidence, preflight_cleanup,
    preflight_effect_request, preflight_effect_resolution,
};
use handoff::{
    preflight_abort, preflight_activate, preflight_begin_handoff, preflight_cleanup_preparation,
    preflight_export, preflight_freeze, preflight_prepare, preflight_resume,
    preflight_resume_source,
};
pub use preflight::preflight;
use timer::{
    preflight_timer_completed, quiescing_timer_completion_parent, thaw_timer, valid_timer_freeze,
};
pub use transition::{ApplyResult, apply};

fn commit(identity: Identity, kind: EventKind) -> Decision {
    Decision::Commit(Event::new(identity, kind))
}

fn reject_phase(state: &CanonicalState) -> Decision {
    Decision::Reject(Rejection::InvalidPhase { actual: state.phase })
}

fn local_active(state: &CanonicalState) -> bool {
    state.activation.status == ActivationStatus::Active
        && state.ownership.owner == Some(state.activation.node)
}

fn push_evidence(evidence: &mut Vec<contract_core::EvidenceRef>, item: contract_core::EvidenceRef) {
    if !evidence.contains(&item) {
        evidence.push(item);
    }
}
