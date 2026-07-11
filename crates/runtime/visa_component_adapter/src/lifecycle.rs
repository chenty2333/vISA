use contract_core::{ActivationRole, Digest, HandoffPhase, Identity};
use sha2::{Digest as _, Sha256};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::{Coordinator, SafePoint, SafePointTimer, canonical_digest};

use crate::{
    ActivationRequest, AdapterError, AdapterProvider, ComponentSafePoint, ComponentState,
    ComponentStatus, PortableComponentState, PreflightExpectations, ResourceBindingError,
    RuntimeIdentity, WorkloadFailure, WorkloadPhase, parse_identity,
};

pub struct RecoverableInstantiation<P> {
    pub error: AdapterError,
    pub coordinator: Coordinator<P>,
}

pub trait CooperativeRuntimeFactory<P>
where
    P: AdapterProvider + 'static,
{
    type Instance: CooperativeRuntimeInstance<P>;
    type Prepared;

    fn identity() -> RuntimeIdentity;

    /// Validate and compile/type-check the selected runtime path without
    /// instantiating the component or executing guest code.
    fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<Self::Prepared, AdapterError>;

    fn instantiate_prepared_recoverable(
        prepared: Self::Prepared,
        coordinator: Coordinator<P>,
    ) -> Result<Self::Instance, Box<RecoverableInstantiation<P>>>;
}

/// Shared lifecycle protocol. Implementations provide only engine-specific
/// guest calls and local resource bookkeeping; ordering and rollback remain
/// vISA-owned here.
pub trait CooperativeRuntimeInstance<P>
where
    P: AdapterProvider + 'static,
{
    fn runtime_identity(&self) -> RuntimeIdentity;
    fn verified_component_digest(&self) -> Digest;
    fn coordinator(&self) -> &Coordinator<P>;
    fn coordinator_mut(&mut self) -> &mut Coordinator<P>;

    fn invoke_activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError>;
    fn invoke_freeze(&mut self) -> Result<ComponentState, AdapterError>;
    fn invoke_thaw(&mut self, state: &ComponentState) -> Result<(), AdapterError>;
    fn invoke_restore(
        &mut self,
        state: &ComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError>;
    fn invoke_timer_fired(&mut self, operation: &str) -> Result<(), AdapterError>;
    fn invoke_cancel_pending(&mut self) -> Result<(), AdapterError>;
    fn invoke_status(&mut self) -> Result<Option<ComponentStatus>, AdapterError>;
    fn has_live_resources(&self) -> bool;
    fn set_completion_parent(&mut self, parent: Identity) -> Result<(), AdapterError>;
    fn clear_completion_parent(&mut self);

    fn activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        let state = self.coordinator().state();
        if state.activation.role != ActivationRole::Source || state.phase != HandoffPhase::Running {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        self.invoke_activate(request)
    }

    fn freeze(&mut self) -> Result<PortableComponentState, AdapterError> {
        let state = PortableComponentState::encode(&self.invoke_freeze()?)?;
        if self.has_live_resources() {
            return Err(AdapterError::LiveResourcesAtSafePoint { state });
        }
        Ok(state)
    }

    fn safe_point(&mut self, command: Identity) -> Result<ComponentSafePoint, AdapterError> {
        let safe_point = self.coordinator_mut().prepare_safe_point()?;
        let timer = safe_point.timer();
        if let SafePointTimer::Completed { arm_operation: Some(operation) } = timer
            && let Err(error) = self.timer_fired(operation)
        {
            return Err(self.cancel_safe_point_after(safe_point, error));
        }

        let state = match self.freeze() {
            Ok(state) => state,
            Err(AdapterError::LiveResourcesAtSafePoint { state }) => {
                let error = AdapterError::LiveResourcesAtSafePoint { state: state.clone() };
                return Err(self.cancel_safe_point_after_state(safe_point, &state, error));
            }
            Err(error) => return Err(self.cancel_safe_point_after(safe_point, error)),
        };
        let component_state = state.decode()?;
        if !safe_point_state_matches(timer, &component_state) {
            let error = AdapterError::SafePointStateMismatch { state: state.clone(), timer };
            return Err(self.cancel_safe_point_after_state(safe_point, &state, error));
        }
        match self.coordinator_mut().commit_safe_point(
            command,
            state.as_bytes().to_vec(),
            safe_point,
        ) {
            Ok(_) => Ok(ComponentSafePoint { state, timer }),
            Err(coordinator) => match self.thaw_guest(&state) {
                Ok(()) => Err(AdapterError::Coordinator(coordinator)),
                Err(guest) => {
                    Err(AdapterError::SafePointRollback { coordinator, guest: Box::new(guest) })
                }
            },
        }
    }

    fn restore(
        &mut self,
        state: &PortableComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Destination
            || canonical.phase != HandoffPhase::Committed
            || canonical.prepared_destination.is_none()
        {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        let component_state = validate_canonical_portable_state(&canonical.portable_state, state)?;
        self.invoke_restore(&component_state, remaining_duration_ns)
    }

    fn thaw(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Source
            || canonical.phase != HandoffPhase::Running
        {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        let component_state = validate_canonical_portable_state(&canonical.portable_state, state)?;
        self.invoke_thaw(&component_state)
    }

    fn timer_fired(&mut self, operation: Identity) -> Result<(), AdapterError> {
        self.timer_fired_text(&crate::identity_string(operation))
    }

    fn timer_fired_text(&mut self, operation: &str) -> Result<(), AdapterError> {
        let parent =
            parse_identity(operation).ok_or(AdapterError::Workload(WorkloadFailure::WrongTimer))?;
        self.set_completion_parent(parent)?;
        let result = self.invoke_timer_fired(operation);
        self.clear_completion_parent();
        result
    }

    fn cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.invoke_cancel_pending()
    }

    fn status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.invoke_status()
    }

    fn thaw_guest(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        self.invoke_thaw(&state.decode()?)
    }

    fn cancel_safe_point_after(
        &mut self,
        safe_point: SafePoint,
        guest: AdapterError,
    ) -> AdapterError {
        match self.coordinator_mut().cancel_safe_point(safe_point) {
            Ok(()) => guest,
            Err(coordinator) => {
                AdapterError::SafePointRollback { coordinator, guest: Box::new(guest) }
            }
        }
    }

    fn cancel_safe_point_after_state(
        &mut self,
        safe_point: SafePoint,
        state: &PortableComponentState,
        original: AdapterError,
    ) -> AdapterError {
        if let Err(coordinator) = self.coordinator_mut().cancel_safe_point(safe_point) {
            return AdapterError::SafePointRollback { coordinator, guest: Box::new(original) };
        }
        match self.thaw_guest(state) {
            Ok(()) => original,
            Err(rollback) => AdapterError::SafePointGuestRollback {
                original: Box::new(original),
                rollback: Box::new(rollback),
            },
        }
    }
}

pub fn validate_preflight_contract(
    component_bytes: &[u8],
    profile: &CooperativeHandoffProfile,
    support: &ProviderSupport,
    expectations: PreflightExpectations,
) -> Result<Digest, AdapterError> {
    profile.validate(support).map_err(AdapterError::IncompatibleProfile)?;
    let actual_profile_digest =
        canonical_digest(profile).map_err(|_| AdapterError::ProfileEncoding)?;
    if actual_profile_digest != expectations.profile_digest {
        return Err(AdapterError::ProfileDigestMismatch {
            expected: expectations.profile_digest,
            actual: actual_profile_digest,
        });
    }
    let actual_component_digest = component_digest(component_bytes);
    if actual_component_digest != expectations.component_digest {
        return Err(AdapterError::ComponentDigestMismatch {
            expected: expectations.component_digest,
            actual: actual_component_digest,
        });
    }
    Ok(actual_component_digest)
}

pub fn component_digest(component_bytes: &[u8]) -> Digest {
    bytes_digest(component_bytes)
}

fn validate_canonical_portable_state(
    canonical: &[u8],
    provided: &PortableComponentState,
) -> Result<ComponentState, AdapterError> {
    if canonical != provided.as_bytes() {
        return Err(AdapterError::PortableStateMismatch {
            expected: bytes_digest(canonical),
            actual: bytes_digest(provided.as_bytes()),
        });
    }
    provided.decode().map_err(Into::into)
}

fn bytes_digest(bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(bytes);
    Digest::from_bytes(digest.finalize().into())
}

fn safe_point_state_matches(timer: SafePointTimer, state: &ComponentState) -> bool {
    match (timer, state.phase) {
        (SafePointTimer::Pending { arm_operation, .. }, WorkloadPhase::Frozen)
        | (
            SafePointTimer::Completed { arm_operation: Some(arm_operation) },
            WorkloadPhase::Completed,
        ) => state.timer_operation_id == crate::identity_string(arm_operation),
        (SafePointTimer::Completed { arm_operation: None }, WorkloadPhase::Completed)
        | (SafePointTimer::Cancelled, WorkloadPhase::Cancelled) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use contract_core::LogicalDurationNanos;

    use super::*;

    fn component_state(phase: WorkloadPhase, timer_operation_id: String) -> ComponentState {
        ComponentState {
            session_id: "session-a".into(),
            key: "work".into(),
            expected_version: 1,
            completion_value: vec![1],
            timer_operation_id,
            timer_idempotency_key: "timer-key".into(),
            completion_idempotency_key: "completion-key".into(),
            phase,
        }
    }

    #[test]
    fn safe_point_timer_requires_the_exact_pending_or_completed_arm_operation() {
        let expected = Identity::from_u128(7);
        let matching = crate::identity_string(expected);
        let wrong = crate::identity_string(Identity::from_u128(8));

        assert!(safe_point_state_matches(
            SafePointTimer::Pending { remaining: LogicalDurationNanos(1), arm_operation: expected },
            &component_state(WorkloadPhase::Frozen, matching.clone()),
        ));
        assert!(!safe_point_state_matches(
            SafePointTimer::Pending { remaining: LogicalDurationNanos(1), arm_operation: expected },
            &component_state(WorkloadPhase::Frozen, wrong.clone()),
        ));
        assert!(safe_point_state_matches(
            SafePointTimer::Completed { arm_operation: Some(expected) },
            &component_state(WorkloadPhase::Completed, matching),
        ));
        assert!(!safe_point_state_matches(
            SafePointTimer::Completed { arm_operation: Some(expected) },
            &component_state(WorkloadPhase::Completed, wrong),
        ));
    }

    #[test]
    fn safe_point_timer_does_not_invent_an_identity_when_canonical_state_has_none() {
        assert!(safe_point_state_matches(
            SafePointTimer::Completed { arm_operation: None },
            &component_state(WorkloadPhase::Completed, "guest-retained-operation".into()),
        ));
        assert!(safe_point_state_matches(
            SafePointTimer::Cancelled,
            &component_state(WorkloadPhase::Cancelled, "guest-retained-operation".into()),
        ));
        assert!(!safe_point_state_matches(
            SafePointTimer::Cancelled,
            &component_state(WorkloadPhase::Frozen, "guest-retained-operation".into()),
        ));
    }

    #[test]
    fn canonical_state_gates_public_guest_dispatch_but_not_internal_rollback_state() {
        let expected = PortableComponentState::encode(&component_state(
            WorkloadPhase::Frozen,
            crate::identity_string(Identity::from_u128(7)),
        ))
        .unwrap();
        let provided = PortableComponentState::encode(&component_state(
            WorkloadPhase::Frozen,
            crate::identity_string(Identity::from_u128(8)),
        ))
        .unwrap();

        let mut public_guest_invocations = 0;
        assert_eq!(
            validate_canonical_portable_state(expected.as_bytes(), &provided).inspect(|_| {
                public_guest_invocations += 1;
            }),
            Err(AdapterError::PortableStateMismatch {
                expected: bytes_digest(expected.as_bytes()),
                actual: bytes_digest(provided.as_bytes()),
            })
        );
        assert_eq!(public_guest_invocations, 0);

        // Safe-point rollback intentionally uses the just-frozen guest state,
        // before it can become canonical. That private path must remain able
        // to decode and dispatch the temporary state.
        let mut rollback_guest_invocations = 0;
        let rollback_state = provided
            .decode()
            .inspect(|_| {
                rollback_guest_invocations += 1;
            })
            .unwrap();
        assert_eq!(rollback_guest_invocations, 1);
        assert_eq!(
            rollback_state.timer_operation_id,
            crate::identity_string(Identity::from_u128(8))
        );
    }
}
