use contract_core::{
    ActivationRole, ActivationStatus, Digest, EffectRequest, HandoffPhase, JournalPosition,
    ProfileAccess,
};
use substrate_api::{
    CommittedEffectPermit, EffectAdmissionProfile, EffectClosureProvider,
    EffectDispatchAcquireError, EffectDispatchOutcome,
};
use visa_component_adapter::{
    AdapterProvider, LogicalRequestComponentState, LogicalRequestWorkloadLifecycle,
    PortableLogicalRequestState, ProfileBinding, ResourceBindingError, RuntimeIdentity,
    component_digest, identity_string, prepare_profile_effect,
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestObservation, LogicalRequestOperation,
    LogicalRequestPhase, LogicalRequestResult, LogicalRequestState, LogicalRequestTransport,
    encode_logical_request_operation,
};
use visa_runtime::{Coordinator, canonical_digest};
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
    error::{LogicalRequestAdapterError, LogicalRequestFailure, LogicalRequestWorkloadFailure},
    host::{
        CanonicalRequestError, LogicalRequestStoreState, canonical_logical_request,
        start_profile_failure,
    },
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

/// Immutable preview of one logical-request start. Private fields prevent a
/// caller from substituting request bytes or canonical effect identity between
/// admission and the Wasmtime/provider dispatch path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLogicalRequestStart {
    request: Vec<u8>,
    effect_request: EffectRequest,
    pre_state_digest: Digest,
    pre_journal_position: JournalPosition,
}

impl PreparedLogicalRequestStart {
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub const fn effect_request(&self) -> &EffectRequest {
        &self.effect_request
    }

    pub const fn pre_state_digest(&self) -> Digest {
        self.pre_state_digest
    }

    pub const fn pre_journal_position(&self) -> JournalPosition {
        self.pre_journal_position
    }
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
    admission_profile: EffectAdmissionProfile,
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
        Self::instantiate_with_profile(
            component_bytes,
            coordinator,
            EffectAdmissionProfile::Compatibility,
        )
    }

    pub fn instantiate_with_profile(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
        admission_profile: EffectAdmissionProfile,
    ) -> Result<Self, LogicalRequestAdapterError> {
        Self::instantiate_recoverable_with_profile(component_bytes, coordinator, admission_profile)
            .map_err(|failure| failure.0)
    }

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(LogicalRequestAdapterError, Coordinator<P>)>> {
        Self::instantiate_recoverable_with_profile(
            component_bytes,
            coordinator,
            EffectAdmissionProfile::Compatibility,
        )
    }

    pub fn instantiate_recoverable_with_profile(
        component_bytes: &[u8],
        coordinator: Coordinator<P>,
        admission_profile: EffectAdmissionProfile,
    ) -> Result<Self, Box<(LogicalRequestAdapterError, Coordinator<P>)>> {
        let expected = coordinator.state().component_digest;
        let prepared = match Self::preflight(component_bytes, expected) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        Self::instantiate_prepared_recoverable_with_profile(
            prepared,
            coordinator,
            admission_profile,
        )
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedLogicalRequestComponent<P>,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(LogicalRequestAdapterError, Coordinator<P>)>> {
        Self::instantiate_prepared_recoverable_with_profile(
            prepared,
            coordinator,
            EffectAdmissionProfile::Compatibility,
        )
    }

    pub fn instantiate_prepared_recoverable_with_profile(
        prepared: PreparedLogicalRequestComponent<P>,
        coordinator: Coordinator<P>,
        admission_profile: EffectAdmissionProfile,
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
        let mut store = Store::new(
            prepared.instance_pre.engine(),
            LogicalRequestStoreState::new(coordinator, admission_profile),
        );
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
        Ok(Self {
            store,
            instance,
            component_digest: prepared.component_digest,
            session_id: None,
            admission_profile,
        })
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn runtime_identity(&self) -> RuntimeIdentity {
        Self::runtime_identity_static()
    }

    pub const fn admission_profile(&self) -> EffectAdmissionProfile {
        self.admission_profile
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

    /// Legacy Stage 3 entrypoint. This profile does not enforce Nexus effect
    /// admission; admission-required callers use `prepare_start` followed by
    /// `start_admitted`.
    pub fn start(
        &mut self,
        request: Vec<u8>,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.require_compatibility_dispatch()?;
        self.execute(LogicalRequestOperation::Start { request })
    }

    /// Preview the exact effect identity for a logical-request start without
    /// entering the guest or dispatching to the provider.
    pub fn prepare_start(
        &self,
        request: Vec<u8>,
    ) -> Result<PreparedLogicalRequestStart, LogicalRequestAdapterError> {
        self.require_source_running()?;
        if self.session_id.is_none() {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }
        let canonical = self.canonical_request()?;
        ensure_supported_transport(canonical.claim.transport)?;
        let request_size = u32::try_from(request.len())
            .map_err(|_| LogicalRequestAdapterError::InvalidOperation)?;
        let request_digest = canonical_digest(request.as_slice())
            .map_err(|_| LogicalRequestAdapterError::InvalidCanonicalProfile)?;
        if canonical.phase != LogicalRequestPhase::Ready
            || request_size != canonical.request_size
            || request_size > canonical.claim.max_request_size
            || request_digest != canonical.request_digest
        {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }

        let operation = LogicalRequestOperation::Start { request: request.clone() };
        let payload = encode_logical_request_operation(&operation)
            .map_err(|_| LogicalRequestAdapterError::InvalidOperation)?;
        let binding =
            ProfileBinding::for_state(self.coordinator().state(), LOGICAL_REQUEST_EXTENSION_ID)
                .map_err(|error| LogicalRequestAdapterError::ResourceBinding(error.into()))?;
        let operation_id = identity_string(canonical.operation_id);
        let effect_request = prepare_profile_effect(
            self.coordinator().state(),
            &binding,
            ProfileAccess::Write,
            operation_id.as_bytes(),
            payload,
        )
        .map_err(profile_start_error)?;
        let pre_state_digest = self
            .coordinator()
            .state_digest()
            .map_err(|_| LogicalRequestAdapterError::InvalidCanonicalProfile)?;
        Ok(PreparedLogicalRequestStart {
            request,
            effect_request,
            pre_state_digest,
            pre_journal_position: self.coordinator().journal_position(),
        })
    }

    /// Start a previously previewed request only while the complete canonical
    /// state, journal position, and re-derived effect request still match.
    /// This remains an unadmitted Stage 3 compatibility entrypoint; it is not a
    /// universal effect-admission enforcement boundary.
    pub fn start_prepared(
        &mut self,
        prepared: &PreparedLogicalRequestStart,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        self.require_compatibility_dispatch()?;
        self.review_prepared_start(prepared)?;
        self.dispatch_reviewed_start(prepared)
    }

    fn review_prepared_start(
        &self,
        prepared: &PreparedLogicalRequestStart,
    ) -> Result<(), LogicalRequestAdapterError> {
        let current_digest = self
            .coordinator()
            .state_digest()
            .map_err(|_| LogicalRequestAdapterError::InvalidCanonicalProfile)?;
        validate_prepared_start_prestate(
            prepared.pre_state_digest,
            prepared.pre_journal_position,
            current_digest,
            self.coordinator().journal_position(),
        )?;
        let reviewed = self.prepare_start(prepared.request.clone())?;
        if reviewed != *prepared {
            return Err(LogicalRequestAdapterError::InvalidOperation);
        }

        Ok(())
    }

    fn dispatch_reviewed_start(
        &mut self,
        prepared: &PreparedLogicalRequestStart,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError> {
        let result = self
            .execute_inner(LogicalRequestOperation::Start { request: prepared.request.clone() })?;
        if result.effect_operation_id != identity_string(prepared.effect_request.operation) {
            return Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        let actual = self
            .coordinator()
            .state()
            .operations
            .iter()
            .find(|record| record.request.operation == prepared.effect_request.operation)
            .ok_or(LogicalRequestAdapterError::InvalidCanonicalProfile)?;
        if actual.request != prepared.effect_request {
            return Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        Ok(result)
    }

    /// Dispatch a prepared request only after an effect-closure provider has
    /// committed the exact canonical effect. Consuming this permit prevents
    /// local reuse; canonical operation/idempotency identity still governs
    /// provider replay and duplicate dispatch recovery.
    pub fn start_admitted<'a, C>(
        &mut self,
        prepared: &PreparedLogicalRequestStart,
        provider: &'a C,
        permit: CommittedEffectPermit<'a, C>,
    ) -> Result<LogicalRequestCallResult, LogicalRequestAdapterError>
    where
        C: EffectClosureProvider,
    {
        if self.admission_profile != EffectAdmissionProfile::AdmissionRequired {
            return Err(LogicalRequestAdapterError::AdmissionRequired);
        }
        let descriptor =
            provider.descriptor().map_err(|_| LogicalRequestAdapterError::AdmissionRejected)?;
        if !descriptor.admission_profile.satisfies(EffectAdmissionProfile::AdmissionRequired) {
            return Err(LogicalRequestAdapterError::AdmissionRejected);
        }
        self.review_prepared_start(prepared)?;
        let dispatch =
            permit.consume(provider, prepared.effect_request()).map_err(|error| match error {
                EffectDispatchAcquireError::BindingMismatch
                | EffectDispatchAcquireError::Provider(_) => {
                    LogicalRequestAdapterError::AdmissionRejected
                }
            })?;
        if !self.store.data_mut().arm_admitted_start(prepared.effect_request().clone()) {
            return if dispatch.finish(EffectDispatchOutcome::GuestFailed).is_err() {
                Err(LogicalRequestAdapterError::AdmissionOutcomeUnknown)
            } else {
                Err(LogicalRequestAdapterError::AdmissionRejected)
            };
        }
        let mut result = self.dispatch_reviewed_start(prepared);
        if !self.store.data_mut().finish_admitted_start() {
            result = Err(LogicalRequestAdapterError::InvalidCanonicalProfile);
        }
        let outcome = if result.is_ok() {
            EffectDispatchOutcome::GuestReturned
        } else {
            EffectDispatchOutcome::GuestFailed
        };
        if dispatch.finish(outcome).is_err() {
            return Err(LogicalRequestAdapterError::AdmissionOutcomeUnknown);
        }
        result
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
        if matches!(operation, LogicalRequestOperation::Start { .. }) {
            self.require_compatibility_dispatch()?;
        }
        self.execute_inner(operation)
    }

    fn execute_inner(
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
            || canonical.activation.status != ActivationStatus::Active
            || canonical.phase != HandoffPhase::Running
        {
            return Err(LogicalRequestAdapterError::ResourceBinding(
                ResourceBindingError::Inactive,
            ));
        }
        Ok(())
    }

    fn require_compatibility_dispatch(&self) -> Result<(), LogicalRequestAdapterError> {
        if self.admission_profile == EffectAdmissionProfile::AdmissionRequired {
            Err(LogicalRequestAdapterError::AdmissionRequired)
        } else {
            Ok(())
        }
    }
}

fn validate_prepared_start_prestate(
    expected_digest: Digest,
    expected_position: JournalPosition,
    current_digest: Digest,
    current_position: JournalPosition,
) -> Result<(), LogicalRequestAdapterError> {
    if current_digest != expected_digest || current_position != expected_position {
        Err(LogicalRequestAdapterError::InvalidOperation)
    } else {
        Ok(())
    }
}

fn profile_start_error(
    error: visa_component_adapter::ProfileFailure,
) -> LogicalRequestAdapterError {
    LogicalRequestAdapterError::Workload(LogicalRequestWorkloadFailure::Request(
        LogicalRequestFailure::from(start_profile_failure(error)),
    ))
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

    #[test]
    fn prepared_start_prestate_digest_and_journal_position_are_independent_fences() {
        let digest = Digest::from_bytes([1; 32]);
        let position = JournalPosition(2);
        assert_eq!(validate_prepared_start_prestate(digest, position, digest, position), Ok(()));
        assert_eq!(
            validate_prepared_start_prestate(
                digest,
                position,
                Digest::from_bytes([3; 32]),
                position,
            ),
            Err(LogicalRequestAdapterError::InvalidOperation)
        );
        assert_eq!(
            validate_prepared_start_prestate(digest, position, digest, JournalPosition(3)),
            Err(LogicalRequestAdapterError::InvalidOperation)
        );
    }
}
