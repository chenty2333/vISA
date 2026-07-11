use contract_core::{Digest, Identity};
use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterProvider, ComponentSafePoint, ComponentState,
    ComponentStatus, CooperativeRuntimeFactory, CooperativeRuntimeInstance, PortableComponentState,
    PreflightExpectations, RecoverableInstantiation, RuntimeIdentity, validate_preflight_contract,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::Coordinator;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

use crate::{
    StoreState, WorkloadFailure,
    bindings::{CooperativeHandoff, CooperativeHandoffPre},
    state::{from_wit_state, to_wit_state},
};

pub const VISA_WASMTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WASMTIME_VERSION: &str = "43.0.2";

/// Opaque, runtime-bound result of non-executing Component Model preflight.
/// It cannot be serialized or placed in a portable snapshot.
pub struct PreparedComponent<P: 'static> {
    instance_pre: CooperativeHandoffPre<StoreState<P>>,
    component_digest: Digest,
    profile_digest: Digest,
}

impl<P> PreparedComponent<P> {
    pub fn runtime_identity(&self) -> RuntimeIdentity {
        RuntimeIdentity::new("visa_wasmtime", VISA_WASMTIME_VERSION, "wasmtime", WASMTIME_VERSION)
    }
}

impl<P> std::fmt::Debug for PreparedComponent<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedComponent")
            .field("component_digest", &self.component_digest)
            .field("profile_digest", &self.profile_digest)
            .finish_non_exhaustive()
    }
}

/// Factory identity used by generic runtime selection code.
pub struct WasmtimeRuntime;

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
    pub fn runtime_identity_static() -> RuntimeIdentity {
        RuntimeIdentity::new("visa_wasmtime", VISA_WASMTIME_VERSION, "wasmtime", WASMTIME_VERSION)
    }

    /// Compile and type-check the component and its complete WIT surface
    /// without instantiating it or executing guest code.
    pub fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<PreparedComponent<P>, AdapterError> {
        let component_digest =
            validate_preflight_contract(component_bytes, profile, support, expectations)?;
        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| AdapterError::InvalidComponent(error.to_string()))?;
        let mut linker = Linker::new(&engine);
        CooperativeHandoff::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|error| AdapterError::Link(error.to_string()))?;
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|error| AdapterError::Link(error.to_string()))?;
        let instance_pre = CooperativeHandoffPre::new(instance_pre)
            .map_err(|error| AdapterError::Link(error.to_string()))?;
        Ok(PreparedComponent {
            instance_pre,
            component_digest,
            profile_digest: expectations.profile_digest,
        })
    }

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

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(AdapterError, Coordinator<P>)>> {
        let expectations = PreflightExpectations {
            component_digest: coordinator.state().component_digest,
            profile_digest: coordinator.state().profile_digest,
        };
        let prepared = match Self::preflight(component_bytes, profile, support, expectations) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        Self::instantiate_prepared_recoverable(prepared, coordinator)
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedComponent<P>,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(AdapterError, Coordinator<P>)>> {
        if coordinator.state().component_digest != prepared.component_digest {
            return Err(Box::new((
                AdapterError::ComponentDigestMismatch {
                    expected: coordinator.state().component_digest,
                    actual: prepared.component_digest,
                },
                coordinator,
            )));
        }
        if coordinator.state().profile_digest != prepared.profile_digest {
            return Err(Box::new((
                AdapterError::ProfileDigestMismatch {
                    expected: coordinator.state().profile_digest,
                    actual: prepared.profile_digest,
                },
                coordinator,
            )));
        }
        let mut store = Store::new(prepared.instance_pre.engine(), StoreState::new(coordinator));
        let instance = match prepared.instance_pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => {
                let coordinator = store.into_data().into_coordinator();
                return Err(Box::new((
                    AdapterError::Instantiation(error.to_string()),
                    coordinator,
                )));
            }
        };
        Ok(Self { store, instance, component_digest: prepared.component_digest })
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn runtime_identity(&self) -> RuntimeIdentity {
        Self::runtime_identity_static()
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

    #[cfg(any(test, feature = "test-control"))]
    pub fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.store
            .data_mut()
            .inject_unsupported_live_resource()
            .map_err(|error| AdapterError::ResourceBinding(error.into()))
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.store
            .data_mut()
            .clear_unsupported_live_resource()
            .map_err(|error| AdapterError::ResourceBinding(error.into()))
    }

    pub fn into_coordinator(self) -> Coordinator<P> {
        self.store.into_data().into_coordinator()
    }

    pub fn activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::activate(self, request)
    }

    pub fn freeze(&mut self) -> Result<PortableComponentState, AdapterError> {
        CooperativeRuntimeInstance::freeze(self)
    }

    pub fn safe_point(&mut self, command: Identity) -> Result<ComponentSafePoint, AdapterError> {
        CooperativeRuntimeInstance::safe_point(self, command)
    }

    pub fn restore(
        &mut self,
        state: &PortableComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::restore(self, state, remaining_duration_ns)
    }

    pub fn thaw(&mut self, state: &PortableComponentState) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::thaw(self, state)
    }

    pub fn timer_fired(&mut self, operation: Identity) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::timer_fired(self, operation)
    }

    pub fn timer_fired_text(&mut self, operation: &str) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::timer_fired_text(self, operation)
    }

    pub fn cancel_pending(&mut self) -> Result<(), AdapterError> {
        CooperativeRuntimeInstance::cancel_pending(self)
    }

    pub fn status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        CooperativeRuntimeInstance::status(self)
    }
}

impl<P> CooperativeRuntimeInstance<P> for ComponentAdapter<P>
where
    P: AdapterProvider + 'static,
{
    fn runtime_identity(&self) -> RuntimeIdentity {
        Self::runtime_identity_static()
    }

    fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    fn coordinator(&self) -> &Coordinator<P> {
        self.store.data().coordinator()
    }

    fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        self.store.data_mut().coordinator_mut()
    }

    fn invoke_activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        let (key_value, timer) = self
            .store
            .data_mut()
            .fresh_resources()
            .map_err(|error| AdapterError::ResourceBinding(error.into()))?;
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

    fn invoke_freeze(&mut self) -> Result<ComponentState, AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_freeze(&mut self.store)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map(from_wit_state)
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    fn invoke_thaw(&mut self, state: &ComponentState) -> Result<(), AdapterError> {
        let (key_value, timer) = self
            .store
            .data_mut()
            .fresh_source_thaw_resources()
            .map_err(|error| AdapterError::ResourceBinding(error.into()))?;
        self.instance
            .visa_continuity_workload()
            .call_thaw(&mut self.store, &to_wit_state(state.clone()), key_value, timer)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    fn invoke_restore(
        &mut self,
        state: &ComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        let (key_value, timer) = self
            .store
            .data_mut()
            .fresh_resources()
            .map_err(|error| AdapterError::ResourceBinding(error.into()))?;
        self.instance
            .visa_continuity_workload()
            .call_restore(
                &mut self.store,
                &to_wit_state(state.clone()),
                remaining_duration_ns,
                key_value,
                timer,
            )
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    fn invoke_timer_fired(&mut self, operation: &str) -> Result<(), AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_timer_fired(&mut self.store, operation)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    fn invoke_cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_cancel_pending(&mut self.store)
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))?
            .map_err(|error| AdapterError::Workload(WorkloadFailure::from(error)))
    }

    fn invoke_status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.instance
            .visa_continuity_workload()
            .call_status(&mut self.store)
            .map(|state| state.map(from_wit_state))
            .map_err(|error| AdapterError::GuestTrap(error.to_string()))
    }

    fn has_live_resources(&self) -> bool {
        !self.store.data().resource_table_is_empty()
    }

    fn set_completion_parent(&mut self, parent: Identity) -> Result<(), AdapterError> {
        self.store
            .data_mut()
            .set_completion_parent(parent)
            .map_err(|error| AdapterError::ResourceBinding(error.into()))
    }

    fn clear_completion_parent(&mut self) {
        self.store.data_mut().clear_completion_parent();
    }
}

impl<P> CooperativeRuntimeFactory<P> for WasmtimeRuntime
where
    P: AdapterProvider + 'static,
{
    type Instance = ComponentAdapter<P>;
    type Prepared = PreparedComponent<P>;

    fn identity() -> RuntimeIdentity {
        ComponentAdapter::<P>::runtime_identity_static()
    }

    fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<Self::Prepared, AdapterError> {
        ComponentAdapter::<P>::preflight(component_bytes, profile, support, expectations)
    }

    fn instantiate_prepared_recoverable(
        prepared: Self::Prepared,
        coordinator: Coordinator<P>,
    ) -> Result<Self::Instance, Box<RecoverableInstantiation<P>>> {
        ComponentAdapter::instantiate_prepared_recoverable(prepared, coordinator).map_err(
            |failure| {
                let (error, coordinator) = *failure;
                Box::new(RecoverableInstantiation { error, coordinator })
            },
        )
    }
}

fn build_engine() -> Result<Engine, AdapterError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| AdapterError::Engine(error.to_string()))
}
