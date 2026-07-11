use contract_core::{CanonicalState, Command, CommandKind, Decision, Rejection};

use super::{
    preflight_abort, preflight_activate, preflight_attenuation, preflight_begin_handoff,
    preflight_cleanup, preflight_cleanup_preparation, preflight_effect_request,
    preflight_effect_resolution, preflight_export, preflight_freeze, preflight_prepare,
    preflight_resume, preflight_resume_source, preflight_revocation, preflight_timer_completed,
};

/// Pure preflight. It never mutates `state` and never executes an effect.
pub fn preflight(state: &CanonicalState, command: &Command) -> Decision {
    if !state.version.is_supported() {
        return Decision::Reject(Rejection::UnsupportedVersion { found: state.version });
    }
    if !command.version.is_supported() {
        return Decision::Reject(Rejection::UnsupportedVersion { found: command.version });
    }
    if command.identity.is_zero() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }

    match &command.kind {
        CommandKind::Activate { authority, lease_epoch } => {
            preflight_activate(state, command.identity, *authority, *lease_epoch)
        }
        CommandKind::AttenuateAuthority { parent, derived } => {
            preflight_attenuation(state, command.identity, *parent, derived)
        }
        CommandKind::RevokeAuthority { authority } => {
            preflight_revocation(state, command.identity, *authority)
        }
        CommandKind::RequestEffect(request) => {
            preflight_effect_request(state, command.identity, request)
        }
        CommandKind::ResolveEffect { operation, outcome } => {
            preflight_effect_resolution(state, command.identity, *operation, outcome, false)
        }
        CommandKind::ReconcileEffect { operation, outcome } => {
            preflight_effect_resolution(state, command.identity, *operation, outcome, true)
        }
        CommandKind::CleanupOperation { operation, evidence } => {
            preflight_cleanup(state, command.identity, *operation, *evidence)
        }
        CommandKind::TimerCompleted { timer, arm_operation, lease_epoch, evidence } => {
            preflight_timer_completed(
                state,
                command.identity,
                *timer,
                *arm_operation,
                *lease_epoch,
                *evidence,
            )
        }
        CommandKind::BeginHandoff { authority } => {
            preflight_begin_handoff(state, command.identity, *authority)
        }
        CommandKind::Freeze { portable_state, timer } => {
            preflight_freeze(state, command.identity, portable_state, *timer)
        }
        CommandKind::ExportSnapshot { snapshot } => {
            preflight_export(state, command.identity, snapshot)
        }
        CommandKind::PrepareDestination(prepared) => {
            preflight_prepare(state, command.identity, prepared)
        }
        CommandKind::AbortHandoff { evidence } => {
            preflight_abort(state, command.identity, *evidence)
        }
        CommandKind::CleanupPreparation { snapshot, evidence } => {
            preflight_cleanup_preparation(state, command.identity, *snapshot, *evidence)
        }
        CommandKind::ResumeSource => preflight_resume_source(state, command.identity),
        CommandKind::ResumeDestination => preflight_resume(state, command.identity),
    }
}
