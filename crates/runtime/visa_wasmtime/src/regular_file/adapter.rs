use contract_core::{ActivationRole, Digest, HandoffPhase};
use visa_component_adapter::{
    AdapterProvider, PortableRegularFileState, RegularFileComponentState, RegularFileWorkloadPhase,
    ResourceBindingError, RuntimeIdentity, component_digest,
};
use visa_profile::{RegularFileOperation, RegularFileResult};
use visa_runtime::Coordinator;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

use super::{
    bindings::{
        RegularFileContinuity, RegularFileContinuityPre,
        visa::file_continuity::regular_file::{FileObservation, ReadResult},
    },
    error::{RegularFileAdapterError, RegularFileWorkloadFailure},
    host::{RegularFileStoreState, canonical_regular_file},
    state::{from_wit_state, to_wit_durability, to_wit_state},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegularFileCallResult {
    pub operation_id: String,
    pub result: RegularFileResult,
}

/// Compiled, type-checked Stage 3A component. This value is runtime-local and
/// never enters portable evidence or handoff state.
pub struct PreparedRegularFileComponent<P: 'static> {
    instance_pre: RegularFileContinuityPre<RegularFileStoreState<P>>,
    component_digest: Digest,
}

impl<P> std::fmt::Debug for PreparedRegularFileComponent<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRegularFileComponent")
            .field("component_digest", &self.component_digest)
            .finish_non_exhaustive()
    }
}

impl<P> PreparedRegularFileComponent<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity(&self) -> RuntimeIdentity {
        RegularFileAdapter::<P>::runtime_identity_static_unchecked()
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }
}

/// Dedicated Wasmtime instance for the bounded regular-file continuity world.
/// It deliberately shares no generated bindings or resource table with the
/// Stage 1/2 cooperative-handoff adapter.
pub struct RegularFileAdapter<P: 'static> {
    store: Store<RegularFileStoreState<P>>,
    instance: RegularFileContinuity,
    component_digest: Digest,
    session_id: Option<String>,
}

impl<P> RegularFileAdapter<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity_static() -> RuntimeIdentity {
        Self::runtime_identity_static_unchecked()
    }

    fn runtime_identity_static_unchecked() -> RuntimeIdentity {
        RuntimeIdentity::new(
            "visa_wasmtime_stage3a",
            crate::VISA_WASMTIME_VERSION,
            "wasmtime",
            crate::WASMTIME_VERSION,
        )
    }

    pub fn preflight(
        component_bytes: &[u8],
        expected_component_digest: Digest,
    ) -> Result<PreparedRegularFileComponent<P>, RegularFileAdapterError> {
        let actual = component_digest(component_bytes);
        if actual != expected_component_digest {
            return Err(RegularFileAdapterError::ComponentDigestMismatch {
                expected: expected_component_digest,
                actual,
            });
        }
        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| RegularFileAdapterError::InvalidComponent(error.to_string()))?;
        let mut linker = Linker::new(&engine);
        RegularFileContinuity::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|error| RegularFileAdapterError::Link(error.to_string()))?;
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|error| RegularFileAdapterError::Link(error.to_string()))?;
        let instance_pre = RegularFileContinuityPre::new(instance_pre)
            .map_err(|error| RegularFileAdapterError::Link(error.to_string()))?;
        Ok(PreparedRegularFileComponent { instance_pre, component_digest: actual })
    }

    pub fn instantiate(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, RegularFileAdapterError> {
        Self::instantiate_recoverable(component_bytes, coordinator).map_err(|failure| failure.0)
    }

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(RegularFileAdapterError, Coordinator<P>)>> {
        let expected = coordinator.state().component_digest;
        let prepared = match Self::preflight(component_bytes, expected) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        Self::instantiate_prepared_recoverable(prepared, coordinator)
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedRegularFileComponent<P>,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(RegularFileAdapterError, Coordinator<P>)>> {
        if coordinator.state().component_digest != prepared.component_digest {
            return Err(Box::new((
                RegularFileAdapterError::ComponentDigestMismatch {
                    expected: coordinator.state().component_digest,
                    actual: prepared.component_digest,
                },
                coordinator,
            )));
        }
        if canonical_regular_file(coordinator.state()).is_err() {
            return Err(Box::new((RegularFileAdapterError::InvalidCanonicalProfile, coordinator)));
        }
        let mut store =
            Store::new(prepared.instance_pre.engine(), RegularFileStoreState::new(coordinator));
        let instance = match prepared.instance_pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => {
                let coordinator = store.into_data().into_coordinator();
                return Err(Box::new((
                    RegularFileAdapterError::Instantiation(error.to_string()),
                    coordinator,
                )));
            }
        };
        Ok(Self { store, instance, component_digest: prepared.component_digest, session_id: None })
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

    pub fn into_coordinator(self) -> Coordinator<P> {
        self.store.into_data().into_coordinator()
    }

    pub fn activate(
        &mut self,
        session_id: impl Into<String>,
    ) -> Result<(), RegularFileAdapterError> {
        self.require_source_running()?;
        let session_id = session_id.into();
        let canonical = canonical_regular_file(self.coordinator().state())
            .map_err(|_| RegularFileAdapterError::InvalidCanonicalProfile)?;
        let state = RegularFileComponentState::from_canonical(
            session_id.clone(),
            &canonical,
            RegularFileWorkloadPhase::Active,
        )?;
        let file = self
            .store
            .data_mut()
            .fresh_file_resource()
            .map_err(|error| RegularFileAdapterError::ResourceBinding(error.into()))?;
        self.instance
            .visa_file_continuity_workload()
            .call_activate(&mut self.store, &session_id, &to_wit_state(&state), file)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.session_id = Some(session_id);
        self.validate_active_status()
    }

    pub fn execute(
        &mut self,
        operation: RegularFileOperation,
        idempotency_key: Option<&str>,
    ) -> Result<RegularFileCallResult, RegularFileAdapterError> {
        let (operation_id, result) = match operation {
            RegularFileOperation::Read { max_bytes } => {
                if idempotency_key.is_some() {
                    return Err(RegularFileAdapterError::InvalidOperation);
                }
                let result = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_read(&mut self.store, max_bytes)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                self.result_from_read(result)?
            }
            RegularFileOperation::Write { bytes, durability } => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_write(&mut self.store, key, &bytes, to_wit_durability(durability))
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (
                    observed.operation_id,
                    RegularFileResult::Mutated {
                        logical_offset: canonical.logical_offset,
                        version: canonical.version,
                        size: canonical.size,
                        content_digest: canonical.content_digest,
                        durable_through: canonical.durable_through,
                    },
                )
            }
            RegularFileOperation::Append { bytes, durability } => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_append(&mut self.store, key, &bytes, to_wit_durability(durability))
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (
                    observed.operation_id,
                    RegularFileResult::Mutated {
                        logical_offset: canonical.logical_offset,
                        version: canonical.version,
                        size: canonical.size,
                        content_digest: canonical.content_digest,
                        durable_through: canonical.durable_through,
                    },
                )
            }
            RegularFileOperation::Truncate { size, durability } => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_truncate(&mut self.store, key, size, to_wit_durability(durability))
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (
                    observed.operation_id,
                    RegularFileResult::Mutated {
                        logical_offset: canonical.logical_offset,
                        version: canonical.version,
                        size: canonical.size,
                        content_digest: canonical.content_digest,
                        durable_through: canonical.durable_through,
                    },
                )
            }
            RegularFileOperation::Rename { relative_path } => {
                let key = require_idempotency_key(idempotency_key)?;
                let path = String::from_utf8(relative_path)
                    .map_err(|_| RegularFileAdapterError::InvalidOperation)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_rename(&mut self.store, key, &path)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (
                    observed.operation_id,
                    RegularFileResult::Renamed {
                        relative_path: canonical.claim.relative_path.clone(),
                        version: canonical.version,
                        content_digest: canonical.content_digest,
                    },
                )
            }
            RegularFileOperation::Sync { durability } => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_sync(&mut self.store, key, to_wit_durability(durability))
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (
                    observed.operation_id,
                    RegularFileResult::Synced {
                        version: canonical.version,
                        durable_through: canonical.durable_through,
                    },
                )
            }
            RegularFileOperation::AcquireLock => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_acquire_lock(&mut self.store, key)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (observed.operation_id, RegularFileResult::Lock { state: canonical.lock_state })
            }
            RegularFileOperation::ReleaseLock => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self
                    .instance
                    .visa_file_continuity_workload()
                    .call_release_lock(&mut self.store, key)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let canonical = self.validate_observation(&observed)?;
                (observed.operation_id, RegularFileResult::Lock { state: canonical.lock_state })
            }
        };
        self.validate_active_status()?;
        Ok(RegularFileCallResult { operation_id, result })
    }

    pub fn freeze(&mut self) -> Result<PortableRegularFileState, RegularFileAdapterError> {
        let state = self
            .instance
            .visa_file_continuity_workload()
            .call_freeze(&mut self.store)
            .map_err(guest_trap)?
            .map_err(workload_error)
            .and_then(|state| from_wit_state(state).map_err(Into::into))?;
        if state.phase != RegularFileWorkloadPhase::Frozen {
            return Err(RegularFileAdapterError::InvalidOperation);
        }
        self.validate_session(&state)?;
        self.validate_canonical_state(&state)?;
        let state = PortableRegularFileState::encode(&state)?;
        if !self.resource_table_is_empty() {
            return Err(RegularFileAdapterError::LiveResourcesAtSafePoint { state });
        }
        Ok(state)
    }

    pub fn thaw(
        &mut self,
        state: &PortableRegularFileState,
    ) -> Result<(), RegularFileAdapterError> {
        self.require_source_running()?;
        let state = self.validate_portable_state(state)?;
        self.resume_guest(&state, false)
    }

    pub fn restore(
        &mut self,
        state: &PortableRegularFileState,
    ) -> Result<(), RegularFileAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Destination
            || canonical.phase != HandoffPhase::Committed
            || canonical.prepared_destination.is_none()
        {
            return Err(RegularFileAdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        let state = self.validate_portable_state(state)?;
        self.resume_guest(&state, true)
    }

    pub fn status(&mut self) -> Result<Option<RegularFileComponentState>, RegularFileAdapterError> {
        let state = self
            .instance
            .visa_file_continuity_workload()
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

    fn result_from_read(
        &self,
        result: ReadResult,
    ) -> Result<(String, RegularFileResult), RegularFileAdapterError> {
        let canonical = self.validate_observation(&result.observation)?;
        Ok((
            result.observation.operation_id,
            RegularFileResult::Read {
                bytes: result.bytes,
                logical_offset: canonical.logical_offset,
                version: canonical.version,
                size: canonical.size,
                content_digest: canonical.content_digest,
            },
        ))
    }

    fn validate_observation(
        &self,
        observed: &FileObservation,
    ) -> Result<visa_profile::RegularFileState, RegularFileAdapterError> {
        let canonical = canonical_regular_file(self.coordinator().state())
            .map_err(|_| RegularFileAdapterError::InvalidCanonicalProfile)?;
        let expected_operation = canonical
            .last_operation
            .map(visa_component_adapter::identity_string)
            .ok_or(RegularFileAdapterError::InvalidCanonicalProfile)?;
        if observed.operation_id != expected_operation
            || observed.logical_offset != canonical.logical_offset
            || observed.version != canonical.version
            || observed.size != canonical.size
            || observed.content_digest != canonical.content_digest.0
            || super::state::from_wit_durability(observed.durable_through)
                != canonical.durable_through
        {
            return Err(RegularFileAdapterError::InvalidCanonicalProfile);
        }
        Ok(canonical)
    }

    fn validate_active_status(&mut self) -> Result<(), RegularFileAdapterError> {
        match self.status()? {
            Some(state) if state.phase == RegularFileWorkloadPhase::Active => Ok(()),
            _ => Err(RegularFileAdapterError::InvalidOperation),
        }
    }

    fn validate_session(
        &self,
        state: &RegularFileComponentState,
    ) -> Result<(), RegularFileAdapterError> {
        if self.session_id.as_ref().is_some_and(|session| session != &state.session_id) {
            return Err(RegularFileAdapterError::InvalidOperation);
        }
        Ok(())
    }

    fn validate_canonical_state(
        &self,
        state: &RegularFileComponentState,
    ) -> Result<(), RegularFileAdapterError> {
        let canonical = canonical_regular_file(self.coordinator().state())
            .map_err(|_| RegularFileAdapterError::InvalidCanonicalProfile)?;
        state.validate_canonical(&canonical).map_err(Into::into)
    }

    fn validate_portable_state(
        &mut self,
        provided: &PortableRegularFileState,
    ) -> Result<RegularFileComponentState, RegularFileAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.portable_state != provided.as_bytes() {
            return Err(RegularFileAdapterError::PortableStateMismatch {
                expected: component_digest(&canonical.portable_state),
                actual: component_digest(provided.as_bytes()),
            });
        }
        let state = provided.decode()?;
        if state.phase != RegularFileWorkloadPhase::Frozen {
            return Err(RegularFileAdapterError::InvalidOperation);
        }
        self.validate_canonical_state(&state)?;
        match &self.session_id {
            Some(session) if session != &state.session_id => {
                return Err(RegularFileAdapterError::InvalidOperation);
            }
            None => self.session_id = Some(state.session_id.clone()),
            Some(_) => {}
        }
        Ok(state)
    }

    fn resume_guest(
        &mut self,
        state: &RegularFileComponentState,
        destination: bool,
    ) -> Result<(), RegularFileAdapterError> {
        let file = self
            .store
            .data_mut()
            .fresh_file_resource()
            .map_err(|error| RegularFileAdapterError::ResourceBinding(error.into()))?;
        let state = to_wit_state(state);
        let result = if destination {
            self.instance.visa_file_continuity_workload().call_restore(
                &mut self.store,
                &state,
                file,
            )
        } else {
            self.instance.visa_file_continuity_workload().call_thaw(&mut self.store, &state, file)
        };
        result.map_err(guest_trap)?.map_err(workload_error)?;
        self.validate_active_status()
    }

    fn require_source_running(&self) -> Result<(), RegularFileAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Source
            || canonical.phase != HandoffPhase::Running
        {
            return Err(RegularFileAdapterError::ResourceBinding(ResourceBindingError::Inactive));
        }
        Ok(())
    }
}

fn require_idempotency_key(value: Option<&str>) -> Result<&str, RegularFileAdapterError> {
    value.filter(|value| !value.is_empty()).ok_or(RegularFileAdapterError::InvalidOperation)
}

fn guest_trap(error: wasmtime::Error) -> RegularFileAdapterError {
    RegularFileAdapterError::GuestTrap(error.to_string())
}

fn workload_error(
    error: super::bindings::exports::visa::file_continuity::workload::WorkloadError,
) -> RegularFileAdapterError {
    RegularFileAdapterError::Workload(RegularFileWorkloadFailure::from(error))
}

fn build_engine() -> Result<Engine, RegularFileAdapterError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| RegularFileAdapterError::Engine(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_require_a_nonempty_idempotency_key() {
        assert_eq!(require_idempotency_key(None), Err(RegularFileAdapterError::InvalidOperation));
        assert_eq!(
            require_idempotency_key(Some("")),
            Err(RegularFileAdapterError::InvalidOperation)
        );
        assert_eq!(require_idempotency_key(Some("operation-a")), Ok("operation-a"));
    }
}
