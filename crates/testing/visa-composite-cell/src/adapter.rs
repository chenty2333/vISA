//! Dedicated Wasmtime instance for the composite continuity world.
//!
//! The adapter owns ordering and validation; the guest owns only its portable
//! record. Every export call is followed by a canonical cross-check so a guest
//! cannot report progress the coordinator did not actually commit.

use contract_core::{ActivationRole, Digest, HandoffPhase, Identity};
use visa_component_adapter::{
    AdapterProvider, ResourceBindingError, RuntimeIdentity, component_digest, identity_string,
    parse_identity,
};
use visa_runtime::Coordinator;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

use crate::{
    bindings::{
        CompositeContinuity, CompositeContinuityPre,
        exports::visa::composite_continuity::workload::CompositeError as WitCompositeError,
        visa::{
            continuity::{key_value::KvError, timers::TimerError},
            file_continuity::regular_file::{FileError, FileObservation, ReadResult},
            request_continuity::logical_request::{
                ObserveResult, RequestError, RequestObservation,
            },
        },
    },
    host::{CompositeStoreState, canonical_logical_request, canonical_regular_file},
    state::{
        CompositeComponentState, CompositePhase, CompositeStateCodecError, PortableCompositeState,
        TimerKvComponentState, from_wit_state, to_wit_durability, to_wit_state,
    },
};

pub const VISA_COMPOSITE_CELL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WASMTIME_VERSION: &str = "43.0.2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositeWorkloadFailure {
    AlreadyActive,
    InvalidState,
    WrongTimer,
    SafePointUnavailable,
    KeyValue(KvError),
    Timer(TimerError),
    File(FileError),
    Request(RequestError),
}

impl From<WitCompositeError> for CompositeWorkloadFailure {
    fn from(error: WitCompositeError) -> Self {
        match error {
            WitCompositeError::AlreadyActive => Self::AlreadyActive,
            WitCompositeError::InvalidState => Self::InvalidState,
            WitCompositeError::WrongTimer => Self::WrongTimer,
            WitCompositeError::SafePointUnavailable => Self::SafePointUnavailable,
            WitCompositeError::Kv(error) => Self::KeyValue(error),
            WitCompositeError::Timer(error) => Self::Timer(error),
            WitCompositeError::File(error) => Self::File(error),
            WitCompositeError::Request(error) => Self::Request(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositeAdapterError {
    ComponentDigestMismatch { expected: Digest, actual: Digest },
    InvalidComponent(String),
    Link(String),
    Engine(String),
    Instantiation(String),
    GuestTrap(String),
    Workload(CompositeWorkloadFailure),
    InvalidCanonicalProfile,
    InvalidOperation,
    ResourceBinding(ResourceBindingError),
    StateCodec(CompositeStateCodecError),
    PortableStateMismatch { expected: Digest, actual: Digest },
    LiveResourcesAtSafePoint { state: PortableCompositeState },
    Coordinator(String),
}

impl From<CompositeStateCodecError> for CompositeAdapterError {
    fn from(error: CompositeStateCodecError) -> Self {
        Self::StateCodec(error)
    }
}

impl std::fmt::Display for CompositeAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Compiled, type-checked composite component. Runtime-local; it never enters
/// portable evidence or handoff state.
pub struct PreparedCompositeComponent<P: 'static> {
    instance_pre: CompositeContinuityPre<CompositeStoreState<P>>,
    component_digest: Digest,
}

impl<P> std::fmt::Debug for PreparedCompositeComponent<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedCompositeComponent")
            .field("component_digest", &self.component_digest)
            .finish_non_exhaustive()
    }
}

pub struct CompositeAdapter<P: 'static> {
    store: Store<CompositeStoreState<P>>,
    instance: CompositeContinuity,
    component_digest: Digest,
    session_id: Option<String>,
}

impl<P> CompositeAdapter<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity_static() -> RuntimeIdentity {
        RuntimeIdentity::new(
            "visa_composite_cell",
            VISA_COMPOSITE_CELL_VERSION,
            "wasmtime",
            WASMTIME_VERSION,
        )
    }

    pub fn preflight(
        component_bytes: &[u8],
        expected_component_digest: Digest,
    ) -> Result<PreparedCompositeComponent<P>, CompositeAdapterError> {
        let actual = component_digest(component_bytes);
        if actual != expected_component_digest {
            return Err(CompositeAdapterError::ComponentDigestMismatch {
                expected: expected_component_digest,
                actual,
            });
        }
        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| CompositeAdapterError::InvalidComponent(error.to_string()))?;
        let mut linker = Linker::new(&engine);
        CompositeContinuity::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|error| CompositeAdapterError::Link(error.to_string()))?;
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|error| CompositeAdapterError::Link(error.to_string()))?;
        let instance_pre = CompositeContinuityPre::new(instance_pre)
            .map_err(|error| CompositeAdapterError::Link(error.to_string()))?;
        Ok(PreparedCompositeComponent { instance_pre, component_digest: actual })
    }

    pub fn instantiate(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, CompositeAdapterError> {
        Self::instantiate_recoverable(component_bytes, coordinator).map_err(|failure| failure.0)
    }

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(CompositeAdapterError, Coordinator<P>)>> {
        let expected = coordinator.state().component_digest;
        let prepared = match Self::preflight(component_bytes, expected) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        Self::instantiate_prepared_recoverable(prepared, coordinator)
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedCompositeComponent<P>,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(CompositeAdapterError, Coordinator<P>)>> {
        if coordinator.state().component_digest != prepared.component_digest {
            return Err(Box::new((
                CompositeAdapterError::ComponentDigestMismatch {
                    expected: coordinator.state().component_digest,
                    actual: prepared.component_digest,
                },
                coordinator,
            )));
        }
        // Both profiles must be present and unambiguous before the guest can
        // be handed either binding.
        if canonical_regular_file(coordinator.state()).is_err()
            || canonical_logical_request(coordinator.state()).is_err()
        {
            return Err(Box::new((CompositeAdapterError::InvalidCanonicalProfile, coordinator)));
        }
        let mut store =
            Store::new(prepared.instance_pre.engine(), CompositeStoreState::new(coordinator));
        let instance = match prepared.instance_pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => {
                let coordinator = store.into_data().into_coordinator();
                return Err(Box::new((
                    CompositeAdapterError::Instantiation(error.to_string()),
                    coordinator,
                )));
            }
        };
        Ok(Self { store, instance, component_digest: prepared.component_digest, session_id: None })
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

    pub fn into_coordinator(self) -> Coordinator<P> {
        self.store.into_data().into_coordinator()
    }

    pub fn activate(
        &mut self,
        session_id: impl Into<String>,
        timer_kv: TimerKvComponentState,
    ) -> Result<(), CompositeAdapterError> {
        self.require_source_running()?;
        let session_id = session_id.into();
        let state = self.compose_state(session_id.clone(), timer_kv, CompositePhase::Active)?;
        let resources = self.fresh_resources()?;
        self.instance
            .visa_composite_continuity_workload()
            .call_activate(
                &mut self.store,
                &session_id,
                &to_wit_state(&state),
                resources.key_value,
                resources.timer,
                resources.file,
                resources.request,
            )
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.session_id = Some(session_id);
        self.validate_active_status()
    }

    pub fn kv_put(
        &mut self,
        idempotency_key: &str,
        value: &[u8],
    ) -> Result<u64, CompositeAdapterError> {
        let version = self
            .instance
            .visa_composite_continuity_workload()
            .call_kv_put(&mut self.store, idempotency_key, value)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()?;
        Ok(version)
    }

    pub fn kv_get(&mut self) -> Result<Option<u64>, CompositeAdapterError> {
        let version = self
            .instance
            .visa_composite_continuity_workload()
            .call_kv_get(&mut self.store)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()?;
        Ok(version)
    }

    pub fn timer_arm(&mut self, duration_ns: u64) -> Result<String, CompositeAdapterError> {
        let armed = self
            .instance
            .visa_composite_continuity_workload()
            .call_timer_arm(&mut self.store, duration_ns)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        // The coordinator must agree that this exact arm operation is live.
        let canonical = self.coordinator().state().timer.active_operation;
        if canonical.map(identity_string).as_deref() != Some(armed.operation_id.as_str()) {
            return Err(CompositeAdapterError::InvalidOperation);
        }
        self.validate_active_status()?;
        Ok(armed.operation_id)
    }

    pub fn timer_fired(&mut self, operation: Identity) -> Result<(), CompositeAdapterError> {
        self.timer_fired_text(&identity_string(operation))
    }

    pub fn timer_fired_text(&mut self, operation: &str) -> Result<(), CompositeAdapterError> {
        let parent = parse_identity(operation)
            .ok_or(CompositeAdapterError::Workload(CompositeWorkloadFailure::WrongTimer))?;
        self.store
            .data_mut()
            .set_completion_parent(parent)
            .map_err(|error| CompositeAdapterError::ResourceBinding(error.into()))?;
        let result = self
            .instance
            .visa_composite_continuity_workload()
            .call_timer_fired(&mut self.store, operation)
            .map_err(guest_trap)
            .and_then(|result| result.map_err(workload_error));
        self.store.data_mut().clear_completion_parent();
        result?;
        self.validate_active_status()
    }

    pub fn file_append(
        &mut self,
        idempotency_key: &str,
        bytes: &[u8],
        durability: visa_profile::FileDurability,
    ) -> Result<FileObservation, CompositeAdapterError> {
        let observed = self
            .instance
            .visa_composite_continuity_workload()
            .call_file_append(
                &mut self.store,
                idempotency_key,
                bytes,
                to_wit_durability(durability),
            )
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_file_observation(&observed)?;
        self.validate_active_status()?;
        Ok(observed)
    }

    pub fn file_read(&mut self, max_bytes: u32) -> Result<ReadResult, CompositeAdapterError> {
        let result = self
            .instance
            .visa_composite_continuity_workload()
            .call_file_read(&mut self.store, max_bytes)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_file_observation(&result.observation)?;
        self.validate_active_status()?;
        Ok(result)
    }

    pub fn request_start(
        &mut self,
        bytes: &[u8],
    ) -> Result<RequestObservation, CompositeAdapterError> {
        let observed = self
            .instance
            .visa_composite_continuity_workload()
            .call_request_start(&mut self.store, bytes)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()?;
        Ok(observed)
    }

    pub fn request_observe(
        &mut self,
        max_bytes: u32,
    ) -> Result<ObserveResult, CompositeAdapterError> {
        let result = self
            .instance
            .visa_composite_continuity_workload()
            .call_request_observe(&mut self.store, max_bytes)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()?;
        Ok(result)
    }

    pub fn freeze(&mut self) -> Result<PortableCompositeState, CompositeAdapterError> {
        let state = self
            .instance
            .visa_composite_continuity_workload()
            .call_freeze(&mut self.store)
            .map_err(guest_trap)?
            .map_err(workload_error)
            .and_then(|state| from_wit_state(state).map_err(Into::into))?;
        if state.phase != CompositePhase::Frozen {
            return Err(CompositeAdapterError::InvalidOperation);
        }
        self.validate_session(&state)?;
        self.validate_canonical_state(&state)?;
        let state = PortableCompositeState::encode(&state)?;
        if !self.resource_table_is_empty() {
            return Err(CompositeAdapterError::LiveResourcesAtSafePoint { state });
        }
        Ok(state)
    }

    pub fn thaw(&mut self, state: &PortableCompositeState) -> Result<(), CompositeAdapterError> {
        self.require_source_running()?;
        let state = self.validate_portable_state(state)?;
        let resources = self.fresh_resources()?;
        self.instance
            .visa_composite_continuity_workload()
            .call_thaw(
                &mut self.store,
                &to_wit_state(&state),
                resources.key_value,
                resources.timer,
                resources.file,
                resources.request,
            )
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()
    }

    pub fn restore(
        &mut self,
        state: &PortableCompositeState,
        remaining_duration_ns: Option<u64>,
    ) -> Result<(), CompositeAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Destination
            || canonical.phase != HandoffPhase::Committed
            || canonical.prepared_destination.is_none()
        {
            return Err(CompositeAdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        let state = self.validate_portable_state(state)?;
        let resources = self.fresh_resources()?;
        self.instance
            .visa_composite_continuity_workload()
            .call_restore(
                &mut self.store,
                &to_wit_state(&state),
                remaining_duration_ns,
                resources.key_value,
                resources.timer,
                resources.file,
                resources.request,
            )
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.validate_active_status()
    }

    pub fn status(&mut self) -> Result<Option<CompositeComponentState>, CompositeAdapterError> {
        let state = self
            .instance
            .visa_composite_continuity_workload()
            .call_status(&mut self.store)
            .map_err(guest_trap)?
            .map(from_wit_state)
            .transpose()?;
        if let Some(state) = &state {
            self.validate_session(state)?;
            self.validate_canonical_state(state)?;
        }
        Ok(state)
    }

    fn fresh_resources(
        &mut self,
    ) -> Result<crate::host::CompositeResources, CompositeAdapterError> {
        self.store
            .data_mut()
            .fresh_resources()
            .map_err(|error| CompositeAdapterError::ResourceBinding(error.into()))
    }

    fn compose_state(
        &self,
        session_id: String,
        timer_kv: TimerKvComponentState,
        phase: CompositePhase,
    ) -> Result<CompositeComponentState, CompositeAdapterError> {
        let file = canonical_regular_file(self.coordinator().state())
            .map_err(|_| CompositeAdapterError::InvalidCanonicalProfile)?;
        let request = canonical_logical_request(self.coordinator().state())
            .map_err(|_| CompositeAdapterError::InvalidCanonicalProfile)?;
        CompositeComponentState::from_canonical(session_id, timer_kv, &file, &request, phase)
            .map_err(Into::into)
    }

    fn validate_file_observation(
        &self,
        observed: &FileObservation,
    ) -> Result<(), CompositeAdapterError> {
        let canonical = canonical_regular_file(self.coordinator().state())
            .map_err(|_| CompositeAdapterError::InvalidCanonicalProfile)?;
        let expected = canonical
            .last_operation
            .map(identity_string)
            .ok_or(CompositeAdapterError::InvalidCanonicalProfile)?;
        if observed.operation_id != expected
            || observed.logical_offset != canonical.logical_offset
            || observed.version != canonical.version
            || observed.size != canonical.size
            || observed.content_digest != canonical.content_digest.0
            || crate::state::from_wit_durability(observed.durable_through)
                != canonical.durable_through
        {
            return Err(CompositeAdapterError::InvalidCanonicalProfile);
        }
        Ok(())
    }

    fn validate_active_status(&mut self) -> Result<(), CompositeAdapterError> {
        match self.status()? {
            Some(state) if state.phase == CompositePhase::Active => Ok(()),
            _ => Err(CompositeAdapterError::InvalidOperation),
        }
    }

    fn validate_session(
        &self,
        state: &CompositeComponentState,
    ) -> Result<(), CompositeAdapterError> {
        if self.session_id.as_ref().is_some_and(|session| session != &state.session_id) {
            return Err(CompositeAdapterError::InvalidOperation);
        }
        Ok(())
    }

    fn validate_canonical_state(
        &self,
        state: &CompositeComponentState,
    ) -> Result<(), CompositeAdapterError> {
        let file = canonical_regular_file(self.coordinator().state())
            .map_err(|_| CompositeAdapterError::InvalidCanonicalProfile)?;
        let request = canonical_logical_request(self.coordinator().state())
            .map_err(|_| CompositeAdapterError::InvalidCanonicalProfile)?;
        state.validate_canonical(self.coordinator().state(), &file, &request).map_err(Into::into)
    }

    fn validate_portable_state(
        &mut self,
        provided: &PortableCompositeState,
    ) -> Result<CompositeComponentState, CompositeAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.portable_state != provided.as_bytes() {
            return Err(CompositeAdapterError::PortableStateMismatch {
                expected: component_digest(&canonical.portable_state),
                actual: component_digest(provided.as_bytes()),
            });
        }
        let state = provided.decode()?;
        if state.phase != CompositePhase::Frozen {
            return Err(CompositeAdapterError::InvalidOperation);
        }
        self.validate_canonical_state(&state)?;
        match &self.session_id {
            Some(session) if session != &state.session_id => {
                return Err(CompositeAdapterError::InvalidOperation);
            }
            None => self.session_id = Some(state.session_id.clone()),
            Some(_) => {}
        }
        Ok(state)
    }

    fn require_source_running(&self) -> Result<(), CompositeAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Source
            || canonical.phase != HandoffPhase::Running
        {
            return Err(CompositeAdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        Ok(())
    }
}

fn guest_trap(error: wasmtime::Error) -> CompositeAdapterError {
    CompositeAdapterError::GuestTrap(error.to_string())
}

fn workload_error(error: WitCompositeError) -> CompositeAdapterError {
    CompositeAdapterError::Workload(CompositeWorkloadFailure::from(error))
}

fn build_engine() -> Result<Engine, CompositeAdapterError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| CompositeAdapterError::Engine(error.to_string()))
}
