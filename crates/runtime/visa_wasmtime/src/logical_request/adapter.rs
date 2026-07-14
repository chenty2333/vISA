use contract_core::{ActivationRole, Digest, HandoffPhase};
use visa_component_adapter::{
    AdapterProvider, LogicalRequestComponentState, LogicalRequestWorkloadLifecycle,
    PortableLogicalRequestState, ResourceBindingError, RuntimeIdentity, component_digest,
    identity_string,
};
use visa_profile::{
    LogicalRequestObservation, LogicalRequestOperation, LogicalRequestResult, LogicalRequestState,
    LogicalRequestTransport,
};
use visa_runtime::Coordinator;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

use super::{
    bindings::{
        LogicalRequestContinuity, LogicalRequestContinuityPre,
        visa::request_continuity::logical_request::{
            ObserveResult, RequestObservation as WitObservation,
        },
    },
    error::{LogicalRequestAdapterError, LogicalRequestWorkloadFailure},
    host::{CanonicalRequestError, LogicalRequestStoreState, canonical_logical_request},
    state::{from_wit_phase, from_wit_rejection, from_wit_state, to_wit_state},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalRequestCallResult {
    /// Stable provider-level lookup and deduplication identity.
    pub operation_id: String,
    /// Canonical vISA effect identity used by journal reconciliation.
    pub effect_operation_id: String,
    pub result: LogicalRequestResult,
}

pub struct PreparedLogicalRequestComponent<P: 'static> {
    instance_pre: LogicalRequestContinuityPre<LogicalRequestStoreState<P>>,
    component_digest: Digest,
}

impl<P> std::fmt::Debug for PreparedLogicalRequestComponent<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedLogicalRequestComponent")
            .field("component_digest", &self.component_digest)
            .finish_non_exhaustive()
    }
}

impl<P> PreparedLogicalRequestComponent<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity(&self) -> RuntimeIdentity {
        LogicalRequestAdapter::<P>::runtime_identity_static()
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }
}

/// Dedicated Wasmtime instance for bounded logical-request continuity. It
/// carries logical request identity and response progress, never live TCP or
/// credential material.
pub struct LogicalRequestAdapter<P: 'static> {
    store: Store<LogicalRequestStoreState<P>>,
    instance: LogicalRequestContinuity,
    component_digest: Digest,
    session_id: Option<String>,
}

impl<P> LogicalRequestAdapter<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity_static() -> RuntimeIdentity {
        RuntimeIdentity::new(
            "visa_wasmtime_stage3b",
            crate::VISA_WASMTIME_VERSION,
            "wasmtime",
            crate::WASMTIME_VERSION,
        )
    }

    pub fn preflight(
        component_bytes: &[u8],
        expected_component_digest: Digest,
    ) -> Result<PreparedLogicalRequestComponent<P>, LogicalRequestAdapterError> {
        let actual = component_digest(component_bytes);
        if actual != expected_component_digest {
            return Err(LogicalRequestAdapterError::ComponentDigestMismatch {
                expected: expected_component_digest,
                actual,
            });
        }
        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| LogicalRequestAdapterError::InvalidComponent(error.to_string()))?;
        let mut linker = Linker::new(&engine);
        LogicalRequestContinuity::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|error| LogicalRequestAdapterError::Link(error.to_string()))?;
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|error| LogicalRequestAdapterError::Link(error.to_string()))?;
        let instance_pre = LogicalRequestContinuityPre::new(instance_pre)
            .map_err(|error| LogicalRequestAdapterError::Link(error.to_string()))?;
        Ok(PreparedLogicalRequestComponent { instance_pre, component_digest: actual })
    }

    pub fn instantiate(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, LogicalRequestAdapterError> {
        Self::instantiate_recoverable(component_bytes, coordinator).map_err(|failure| failure.0)
    }

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(LogicalRequestAdapterError, Coordinator<P>)>> {
        let expected = coordinator.state().component_digest;
        let prepared = match Self::preflight(component_bytes, expected) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        Self::instantiate_prepared_recoverable(prepared, coordinator)
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedLogicalRequestComponent<P>,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(LogicalRequestAdapterError, Coordinator<P>)>> {
        if coordinator.state().component_digest != prepared.component_digest {
            return Err(Box::new((
                LogicalRequestAdapterError::ComponentDigestMismatch {
                    expected: coordinator.state().component_digest,
                    actual: prepared.component_digest,
                },
                coordinator,
            )));
        }
        if let Err(error) = canonical_logical_request(coordinator.state()) {
            return Err(Box::new((canonical_error(error), coordinator)));
        }
        let mut store =
            Store::new(prepared.instance_pre.engine(), LogicalRequestStoreState::new(coordinator));
        let instance = match prepared.instance_pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => {
                let coordinator = store.into_data().into_coordinator();
                return Err(Box::new((
                    LogicalRequestAdapterError::Instantiation(error.to_string()),
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
    ) -> Result<(), LogicalRequestAdapterError> {
        self.require_source_running()?;
        let session_id = session_id.into();
        let canonical = self.canonical_request()?;
        ensure_supported_transport(canonical.claim.transport)?;
        let state = LogicalRequestComponentState::from_canonical(
            session_id.clone(),
            &canonical,
            LogicalRequestWorkloadLifecycle::Active,
        )?;
        let request = self
            .store
            .data_mut()
            .fresh_request_resource()
            .map_err(|error| LogicalRequestAdapterError::ResourceBinding(error.into()))?;
        self.instance
            .visa_request_continuity_workload()
            .call_activate(&mut self.store, &session_id, &to_wit_state(&state), request)
            .map_err(guest_trap)?
            .map_err(workload_error)?;
        self.session_id = Some(session_id);
        self.validate_active_status()
    }

    pub fn start(
        &mut self,
        request: Vec<u8>,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.execute(LogicalRequestOperation::Start { request })
    }

    pub fn observe(
        &mut self,
        max_bytes: u32,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.execute(LogicalRequestOperation::Observe { max_bytes })
    }

    pub fn reconcile(&mut self) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.execute(LogicalRequestOperation::Reconcile)
    }

    pub fn cancel(&mut self) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.execute(LogicalRequestOperation::Cancel)
    }

    pub fn execute(
        &mut self,
        operation: LogicalRequestOperation,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        let previous_effect = self.canonical_request()?.last_operation;
        let result = match operation {
            LogicalRequestOperation::Start { request } => {
                let observed = self
                    .instance
                    .visa_request_continuity_workload()
                    .call_start(&mut self.store, &request)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let (_, observation) = self.validate_observation(&observed)?;
                LogicalRequestResult::Started { observation }
            }
            LogicalRequestOperation::Observe { max_bytes } => {
                let observed = self
                    .instance
                    .visa_request_continuity_workload()
                    .call_observe(&mut self.store, max_bytes)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                self.result_from_observe(observed)?
            }
            LogicalRequestOperation::Reconcile => {
                let observed = self
                    .instance
                    .visa_request_continuity_workload()
                    .call_reconcile(&mut self.store)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let (_, observation) = self.validate_observation(&observed)?;
                LogicalRequestResult::Reconciled { observation }
            }
            LogicalRequestOperation::Cancel => {
                let observed = self
                    .instance
                    .visa_request_continuity_workload()
                    .call_cancel(&mut self.store)
                    .map_err(guest_trap)?
                    .map_err(workload_error)?;
                let (_, observation) = self.validate_observation(&observed)?;
                LogicalRequestResult::Cancelled { observation }
            }
        };
        self.validate_active_status()?;
        let canonical = self.canonical_request()?;
        let effect_operation =
            canonical.last_operation.ok_or(LogicalRequestAdapterError::InvalidCanonicalProfile)?;
        if Some(effect_operation) == previous_effect {
            return Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        Ok(LogicalRequestCallResult {
            operation_id: identity_string(canonical.operation_id),
            effect_operation_id: identity_string(effect_operation),
            result,
        })
    }

    pub fn freeze(&mut self) -> Result<PortableLogicalRequestState, LogicalRequestAdapterError> {
        let state = self
            .instance
            .visa_request_continuity_workload()
            .call_freeze(&mut self.store)
            .map_err(guest_trap)?
            .map_err(workload_error)
            .and_then(|state| from_wit_state(state).map_err(Into::into))?;
        if state.lifecycle != LogicalRequestWorkloadLifecycle::Frozen {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }
        self.validate_session(&state)?;
        self.validate_canonical_state(&state)?;
        ensure_supported_transport(state.transport)?;
        let state = PortableLogicalRequestState::encode(&state)?;
        if !self.resource_table_is_empty() {
            return Err(LogicalRequestAdapterError::LiveResourcesAtSafePoint { state });
        }
        Ok(state)
    }

    pub fn thaw(
        &mut self,
        state: &PortableLogicalRequestState,
    ) -> Result<(), LogicalRequestAdapterError> {
        self.require_source_running()?;
        let state = self.validate_portable_state(state)?;
        self.resume_guest(&state, false)
    }

    pub fn restore(
        &mut self,
        state: &PortableLogicalRequestState,
    ) -> Result<(), LogicalRequestAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Destination
            || canonical.phase != HandoffPhase::Committed
            || canonical.prepared_destination.is_none()
        {
            return Err(LogicalRequestAdapterError::ResourceBinding(
                ResourceBindingError::Inactive,
            ));
        }
        let state = self.validate_portable_state(state)?;
        self.resume_guest(&state, true)
    }

    pub fn status(
        &mut self,
    ) -> Result<Option<LogicalRequestComponentState>, LogicalRequestAdapterError> {
        let state = self
            .instance
            .visa_request_continuity_workload()
            .call_status(&mut self.store)
            .map_err(guest_trap)?
            .map(from_wit_state)
            .transpose()?;
        if let Some(state) = &state {
            self.validate_session(state)?;
            ensure_supported_transport(state.transport)?;
            self.validate_canonical_state(state)?;
        }
        Ok(state)
    }

    fn result_from_observe(
        &self,
        result: ObserveResult,
    ) -> Result<LogicalRequestResult, LogicalRequestAdapterError> {
        let (canonical, observation) = self.validate_observation(&result.observation)?;
        if result.response_cursor != canonical.response_cursor {
            return Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        Ok(LogicalRequestResult::Observed {
            observation,
            bytes: result.bytes,
            response_cursor: canonical.response_cursor,
        })
    }

    fn validate_observation(
        &self,
        observed: &WitObservation,
    ) -> Result<(LogicalRequestState, LogicalRequestObservation), LogicalRequestAdapterError> {
        let canonical = self.canonical_request()?;
        let expected_operation = identity_string(canonical.operation_id);
        let response_matches = match (&observed.response, canonical.response) {
            (None, None) => true,
            (Some(observed), Some(expected)) => {
                observed.size == expected.size && observed.digest == expected.digest.0
            }
            _ => false,
        };
        if observed.operation_id != expected_operation
            || from_wit_phase(observed.phase) != canonical.phase
            || !response_matches
            || observed.rejection.map(from_wit_rejection) != canonical.rejection
            || canonical.last_operation.is_none()
        {
            return Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        Ok((
            canonical.clone(),
            LogicalRequestObservation {
                phase: canonical.phase,
                response: canonical.response,
                rejection: canonical.rejection,
            },
        ))
    }

    fn validate_active_status(&mut self) -> Result<(), LogicalRequestAdapterError> {
        match self.status()? {
            Some(state) if state.lifecycle == LogicalRequestWorkloadLifecycle::Active => Ok(()),
            _ => Err(LogicalRequestAdapterError::InvalidOperation),
        }
    }

    fn validate_session(
        &self,
        state: &LogicalRequestComponentState,
    ) -> Result<(), LogicalRequestAdapterError> {
        if self.session_id.as_ref().is_some_and(|session| session != &state.session_id) {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }
        Ok(())
    }

    fn canonical_request(&self) -> Result<LogicalRequestState, LogicalRequestAdapterError> {
        canonical_logical_request(self.coordinator().state()).map_err(canonical_error)
    }

    fn validate_canonical_state(
        &self,
        state: &LogicalRequestComponentState,
    ) -> Result<(), LogicalRequestAdapterError> {
        let canonical = self.canonical_request()?;
        state.validate_canonical(&canonical).map_err(Into::into)
    }

    fn validate_portable_state(
        &mut self,
        provided: &PortableLogicalRequestState,
    ) -> Result<LogicalRequestComponentState, LogicalRequestAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.portable_state != provided.as_bytes() {
            return Err(LogicalRequestAdapterError::PortableStateMismatch {
                expected: component_digest(&canonical.portable_state),
                actual: component_digest(provided.as_bytes()),
            });
        }
        let state = provided.decode()?;
        if state.lifecycle != LogicalRequestWorkloadLifecycle::Frozen {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }
        ensure_supported_transport(state.transport)?;
        self.validate_canonical_state(&state)?;
        match &self.session_id {
            Some(session) if session != &state.session_id => {
                return Err(LogicalRequestAdapterError::InvalidOperation);
            }
            None => self.session_id = Some(state.session_id.clone()),
            Some(_) => {}
        }
        Ok(state)
    }

    fn resume_guest(
        &mut self,
        state: &LogicalRequestComponentState,
        destination: bool,
    ) -> Result<(), LogicalRequestAdapterError> {
        let request = self
            .store
            .data_mut()
            .fresh_request_resource()
            .map_err(|error| LogicalRequestAdapterError::ResourceBinding(error.into()))?;
        let state = to_wit_state(state);
        let result = if destination {
            self.instance.visa_request_continuity_workload().call_restore(
                &mut self.store,
                &state,
                request,
            )
        } else {
            self.instance.visa_request_continuity_workload().call_thaw(
                &mut self.store,
                &state,
                request,
            )
        };
        result.map_err(guest_trap)?.map_err(workload_error)?;
        self.validate_active_status()
    }

    fn require_source_running(&self) -> Result<(), LogicalRequestAdapterError> {
        let canonical = self.coordinator().state();
        if canonical.activation.role != ActivationRole::Source
            || canonical.phase != HandoffPhase::Running
        {
            return Err(LogicalRequestAdapterError::ResourceBinding(
                ResourceBindingError::Inactive,
            ));
        }
        Ok(())
    }
}

fn ensure_supported_transport(
    transport: LogicalRequestTransport,
) -> Result<(), LogicalRequestAdapterError> {
    match transport {
        LogicalRequestTransport::Reconnectable => Ok(()),
        LogicalRequestTransport::RawLiveTcp => Err(
            LogicalRequestAdapterError::UnsupportedTransport(LogicalRequestTransport::RawLiveTcp),
        ),
    }
}

fn canonical_error(error: CanonicalRequestError) -> LogicalRequestAdapterError {
    match error {
        CanonicalRequestError::Invalid => LogicalRequestAdapterError::InvalidCanonicalProfile,
        CanonicalRequestError::UnsupportedRawLiveTcp => {
            LogicalRequestAdapterError::UnsupportedTransport(LogicalRequestTransport::RawLiveTcp)
        }
    }
}

fn guest_trap(error: wasmtime::Error) -> LogicalRequestAdapterError {
    LogicalRequestAdapterError::GuestTrap(error.to_string())
}

fn workload_error(
    error: super::bindings::exports::visa::request_continuity::workload::WorkloadError,
) -> LogicalRequestAdapterError {
    LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::from(error))
}

fn build_engine() -> Result<Engine, LogicalRequestAdapterError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| LogicalRequestAdapterError::Engine(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_live_tcp_is_an_explicit_adapter_rejection() {
        assert_eq!(
            ensure_supported_transport(LogicalRequestTransport::RawLiveTcp),
            Err(LogicalRequestAdapterError::UnsupportedTransport(
                LogicalRequestTransport::RawLiveTcp
            ))
        );
        assert_eq!(ensure_supported_transport(LogicalRequestTransport::Reconnectable), Ok(()));
    }
}
