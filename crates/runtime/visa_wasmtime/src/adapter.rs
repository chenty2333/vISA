use contract_core::{ActivationRole, Digest, HandoffPhase, Identity};
use sha2::{Digest as _, Sha256};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::{Coordinator, SafePoint, SafePointTimer, canonical_digest};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

use crate::{
    AdapterError, ComponentStatus, PortableComponentState, StoreState, WorkloadFailure,
    bindings::CooperativeHandoff, host::AdapterProvider,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRequest {
    pub session_id: String,
    pub key: String,
    pub initial_value: Vec<u8>,
    pub completion_value: Vec<u8>,
    pub delay_ns: u64,
    pub baseline_idempotency_key: String,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentSafePoint {
    pub state: PortableComponentState,
    pub timer: SafePointTimer,
}

/// One isolated Wasmtime component instance and its authoritative coordinator.
pub struct ComponentAdapter<P: 'static> {
    store: Store<StoreState<P>>,
    instance: CooperativeHandoff,
    component_digest: Digest,
}

impl<P> ComponentAdapter<P>
where
    P: AdapterProvider + 'static,
{
    /// Validate the component digest before compiling, linking, or executing
    /// any component code.
    pub fn instantiate(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        coordinator: Coordinator<P>,
    ) -> Result<Self, AdapterError> {
        Self::instantiate_recoverable(component_bytes, profile, support, coordinator).map_err(
            |failure| {
                let (error, _) = *failure;
                error
            },
        )
    }

    /// Build an adapter while returning the unmodified coordinator if engine
    /// setup or instantiation fails before guest execution begins.
    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(AdapterError, Coordinator<P>)>> {
        if let Err(error) = profile.validate(support) {
            return Err(Box::new((AdapterError::IncompatibleProfile(error), coordinator)));
        }
        let actual_profile_digest = match canonical_digest(profile) {
            Ok(digest) => digest,
            Err(_) => return Err(Box::new((AdapterError::ProfileEncoding, coordinator))),
        };
        let expected_profile_digest = coordinator.state().profile_digest;
        if actual_profile_digest != expected_profile_digest {
            return Err(Box::new((
                AdapterError::ProfileDigestMismatch {
                    expected: expected_profile_digest,
                    actual: actual_profile_digest,
                },
                coordinator,
            )));
        }
        let actual_digest = component_digest(component_bytes);
        let expected_digest = coordinator.state().component_digest;
        if actual_digest != expected_digest {
            return Err(Box::new((
                AdapterError::ComponentDigestMismatch {
                    expected: expected_digest,
                    actual: actual_digest,
                },
                coordinator,
            )));
        }

        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = match Engine::new(&config) {
            Ok(engine) => engine,
            Err(error) => {
                return Err(Box::new((AdapterError::Engine(error.to_string()), coordinator)));
            }
        };
        let component = match Component::new(&engine, component_bytes) {
            Ok(component) => component,
            Err(error) => {
                return Err(Box::new((
                    AdapterError::InvalidComponent(error.to_string()),
                    coordinator,
                )));
            }
        };
        let mut linker = Linker::new(&engine);
        if let Err(error) =
            CooperativeHandoff::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
        {
            return Err(Box::new((AdapterError::Link(error.to_string()), coordinator)));
        }
        let mut store = Store::new(&engine, StoreState::new(coordinator));
        let instance = match CooperativeHandoff::instantiate(&mut store, &component, &linker) {
            Ok(instance) => instance,
            Err(error) => {
                let coordinator = store.into_data().into_coordinator();
                return Err(Box::new((
                    AdapterError::Instantiation(error.to_string()),
                    coordinator,
                )));
            }
        };
        Ok(Self { store, instance, component_digest: actual_digest })
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        self.store.data().coordinator()
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        self.store.data_mut().coordinator_mut()
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.store.data().resource_table_is_empty()
    }

    /// Insert a real unreturned table entry for lifecycle fault injection.
    /// This is unavailable in production builds.
    #[cfg(any(test, feature = "test-control"))]
    pub fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.store.data_mut().inject_unsupported_live_resource().map_err(Into::into)
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.store.data_mut().clear_unsupported_live_resource().map_err(Into::into)
    }

    pub fn into_coordinator(self) -> Coordinator<P> {
        self.store.into_data().into_coordinator()
    }

    pub fn activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        let state = self.coordinator().state();
        if state.activation.role != ActivationRole::Source || state.phase != HandoffPhase::Running {
            return Err(AdapterError::ResourceBinding(crate::ResourceBindingError::Inactive));
        }
        let (key_value, timer) = self.store.data_mut().fresh_resources()?;
        let result = self
            .instance
            .visa_continuity_workload()
            .call_activate(
                &mut self.store,
                &request.session_id,
                &request.key,
                &request.initial_value,
                &request.completion_value,
                request.delay_ns,
                &request.baseline_idempotency_key,
                &request.timer_idempotency_key,
                &request.completion_idempotency_key,
                key_value,
                timer,
            )
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?;
        result.map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    /// Reach the explicit component safe point and reject it unless every
    /// imported resource handle has been returned to the host.
    pub fn freeze(&mut self) -> Result<PortableComponentState, AdapterError> {
        let state = self
            .instance
            .visa_continuity_workload()
            .call_freeze(&mut self.store)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))?;
        let state = PortableComponentState::encode(&state)?;
        if !self.resource_table_is_empty() {
            return Err(AdapterError::LiveResourcesAtSafePoint { state });
        }
        Ok(state)
    }

    /// Coordinate timer observation, the optional completion callback, guest
    /// handle release, deterministic state encoding, and canonical freeze as
    /// one safe-point protocol.
    pub fn safe_point(&mut self, command: Identity) -> Result<ComponentSafePoint, AdapterError> {
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
        let phase = state.phase()?;
        if !safe_point_state_matches(timer, phase) {
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

    /// Restore only from deterministic component state and fresh receipts in
    /// a committed destination coordinator. The caller resumes canonical
    /// destination state only after this function rearms the timer.
    pub fn restore(
        &mut self,
        state: &PortableComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Destination
            || canonical.phase != HandoffPhase::Committed
            || canonical.prepared_destination.is_none()
        {
            return Err(AdapterError::ResourceBinding(crate::ResourceBindingError::Inactive));
        }
        let state = state.decode()?;
        let (key_value, timer) = self.store.data_mut().fresh_resources()?;
        self.instance
            .visa_continuity_workload()
            .call_restore(&mut self.store, &state, remaining_duration_ns, key_value, timer)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    /// Recreate source-local handles after a pre-commit abort. The coordinator
    /// must already have restored source ownership and resumed its suspended
    /// timer; unlike destination restore this call never arms a new timer.
    pub fn thaw(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Source
            || !matches!(canonical.phase, HandoffPhase::Running | HandoffPhase::Quiescing)
        {
            return Err(AdapterError::ResourceBinding(crate::ResourceBindingError::Inactive));
        }
        self.thaw_guest(state)
    }

    fn thaw_guest(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        let state = state.decode()?;
        let (key_value, timer) = self.store.data_mut().fresh_source_thaw_resources()?;
        self.instance
            .visa_continuity_workload()
            .call_thaw(&mut self.store, &state, key_value, timer)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    pub fn timer_fired(&mut self, operation: Identity) -> Result<(), AdapterError> {
        self.timer_fired_text(&crate::host::identity_string(operation))
    }

    pub fn timer_fired_text(&mut self, operation: &str) -> Result<(), AdapterError> {
        let parent = crate::host::parse_identity(operation)
            .ok_or(AdapterError::Workload(WorkloadFailure::WrongTimer))?;
        self.store.data_mut().set_completion_parent(parent)?;
        let result = self.invoke_timer_fired(operation);
        self.store.data_mut().clear_completion_parent();
        result
    }

    fn invoke_timer_fired(&mut self, operation: &str) -> Result<(), AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_timer_fired(&mut self.store, operation)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    pub fn cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_cancel_pending(&mut self.store)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    pub fn status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_status(&mut self.store)
            .map(|state| state.map(Into::into))
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))
    }
}

const fn safe_point_state_matches(timer: SafePointTimer, phase: crate::WorkloadPhase) -> bool {
    matches!(
        (timer, phase),
        (SafePointTimer::Pending { .. }, crate::WorkloadPhase::Frozen)
            | (SafePointTimer::Completed { .. }, crate::WorkloadPhase::Completed)
            | (SafePointTimer::Cancelled, crate::WorkloadPhase::Cancelled)
    )
}

pub fn component_digest(component_bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(component_bytes);
    Digest::from_bytes(digest.finalize().into())
}
