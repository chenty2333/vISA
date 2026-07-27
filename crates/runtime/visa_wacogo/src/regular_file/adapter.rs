use contract_core::{ActivationRole, Digest, HandoffPhase};
use serde_json::{Value, json};
use visa_component_adapter::{
    AdapterProvider, PortableRegularFileState, RegularFileAdapterError, RegularFileCallResult,
    RegularFileComponentState, RegularFileWorkloadPhase, ResourceBindingError, RuntimeIdentity,
    component_digest,
};
use visa_profile::{RegularFileOperation, RegularFileResult};
use visa_runtime::Coordinator;

use super::{
    error::{terminal_error, transport_error},
    host::{RegularFileHostState, canonical_regular_file},
    state::{
        Observation, ObservationWire, ReadWire, durability_name, state_from_value, state_to_value,
    },
};
use crate::{
    identity::{WacogoProvenance, static_identity},
    preflight::{PreparedWacogoRegularFileComponent, regular_file_preflight},
    process::WacogoProcess,
};

pub struct WacogoRegularFileAdapter<P: 'static> {
    process: WacogoProcess,
    host: RegularFileHostState<P>,
    component_digest: Digest,
    identity: RuntimeIdentity,
    provenance: WacogoProvenance,
    sidecar_live_resources: usize,
    session_id: Option<String>,
}

impl<P> WacogoRegularFileAdapter<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity_static() -> RuntimeIdentity {
        static_identity()
    }

    pub fn preflight(
        component_bytes: &[u8],
        expected_component_digest: Digest,
    ) -> Result<PreparedWacogoRegularFileComponent, RegularFileAdapterError> {
        regular_file_preflight(component_bytes, expected_component_digest).map_err(transport_error)
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
        prepared: PreparedWacogoRegularFileComponent,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(RegularFileAdapterError, Coordinator<P>)>> {
        if let Err(error) = prepared.component.validate() {
            return Err(Box::new((transport_error(error), coordinator)));
        }
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
        let process = match prepared.process.instantiate() {
            Ok(process) => process,
            Err(error) => return Err(Box::new((transport_error(error), coordinator))),
        };
        Ok(Self {
            process,
            host: RegularFileHostState::new(coordinator),
            component_digest: prepared.component_digest,
            identity: prepared.identity,
            provenance: prepared.provenance,
            sidecar_live_resources: 0,
            session_id: None,
        })
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn runtime_identity(&self) -> RuntimeIdentity {
        self.identity.clone()
    }

    pub fn provenance(&self) -> &WacogoProvenance {
        &self.provenance
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        self.host.coordinator()
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        self.host.coordinator_mut()
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.host.resources_are_empty() && self.sidecar_live_resources == 0
    }

    pub fn into_coordinator(
        mut self,
    ) -> Result<Coordinator<P>, Box<(RegularFileAdapterError, Coordinator<P>)>> {
        if let Err(error) = self.shutdown() {
            let Self { process, host, .. } = self;
            drop(process);
            return Err(Box::new((error, host.into_coordinator())));
        }
        let Self { process, host, .. } = self;
        drop(process);
        Ok(host.into_coordinator())
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
        let file = self.host.fresh_file().map_err(RegularFileAdapterError::ResourceBinding)?;
        self.call_unit(
            "activate",
            json!({
                "sessionId": session_id,
                "state": state_to_value(&state)?,
                "fileResource": file,
            }),
        )?;
        self.session_id = Some(state.session_id);
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
                let value = self.call_value("read", json!({ "maxBytes": max_bytes }))?;
                let wire: ReadWire = serde_json::from_value(value).map_err(|error| {
                    self.process.terminate_after_adapter_failure();
                    RegularFileAdapterError::GuestTrap(format!(
                        "wacogo returned an invalid regular-file read result: {error}"
                    ))
                })?;
                let observation = wire.observation.decode()?;
                let bytes =
                    crate::state::decode_canonical_hex(&wire.bytes_hex).map_err(|detail| {
                        RegularFileAdapterError::GuestTrap(format!(
                            "wacogo regular-file read bytesHex was invalid: {detail}"
                        ))
                    })?;
                let canonical = self.validate_observation(&observation)?;
                (
                    observation.operation_id,
                    RegularFileResult::Read {
                        bytes,
                        logical_offset: canonical.logical_offset,
                        version: canonical.version,
                        size: canonical.size,
                        content_digest: canonical.content_digest,
                    },
                )
            }
            RegularFileOperation::Write { bytes, durability } => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed = self.call_observation(
                    "write",
                    json!({
                        "idempotencyKey": key,
                        "bytesHex": hex::encode(bytes),
                        "durability": durability_name(durability),
                    }),
                )?;
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
                let observed = self.call_observation(
                    "append",
                    json!({
                        "idempotencyKey": key,
                        "bytesHex": hex::encode(bytes),
                        "durability": durability_name(durability),
                    }),
                )?;
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
                let observed = self.call_observation(
                    "truncate",
                    json!({
                        "idempotencyKey": key,
                        "size": size.to_string(),
                        "durability": durability_name(durability),
                    }),
                )?;
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
                let relative_path = String::from_utf8(relative_path)
                    .map_err(|_| RegularFileAdapterError::InvalidOperation)?;
                let observed = self.call_observation(
                    "rename",
                    json!({ "idempotencyKey": key, "relativePath": relative_path }),
                )?;
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
                let observed = self.call_observation(
                    "sync",
                    json!({
                        "idempotencyKey": key,
                        "durability": durability_name(durability),
                    }),
                )?;
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
                let observed =
                    self.call_observation("acquire-lock", json!({ "idempotencyKey": key }))?;
                let canonical = self.validate_observation(&observed)?;
                (observed.operation_id, RegularFileResult::Lock { state: canonical.lock_state })
            }
            RegularFileOperation::ReleaseLock => {
                let key = require_idempotency_key(idempotency_key)?;
                let observed =
                    self.call_observation("release-lock", json!({ "idempotencyKey": key }))?;
                let canonical = self.validate_observation(&observed)?;
                (observed.operation_id, RegularFileResult::Lock { state: canonical.lock_state })
            }
        };
        self.validate_active_status()?;
        Ok(RegularFileCallResult { operation_id, result })
    }

    pub fn freeze(&mut self) -> Result<PortableRegularFileState, RegularFileAdapterError> {
        let state = self.call_state("freeze", json!({}))?;
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
        let value = self.call_value("status", json!({}))?;
        let state = if value.is_null() { None } else { Some(state_from_value(value)?) };
        if let Some(state) = &state {
            self.validate_session(state)?;
            self.validate_canonical_state(state)?;
        }
        Ok(state)
    }

    pub fn shutdown(&mut self) -> Result<(), RegularFileAdapterError> {
        let reply = {
            let process = &mut self.process;
            let host = &mut self.host;
            process.shutdown(|call| host.handle(call)).map_err(transport_error)?
        };
        self.finish_reply_resource_count(reply.live_resources)?;
        unit_result(reply.result.map_err(transport_error)?, "shutdown")?;
        if !self.resource_table_is_empty() {
            return Err(RegularFileAdapterError::ResourceBinding(
                ResourceBindingError::LiveResources,
            ));
        }
        Ok(())
    }

    fn resume_guest(
        &mut self,
        state: &RegularFileComponentState,
        destination: bool,
    ) -> Result<(), RegularFileAdapterError> {
        let file = self.host.fresh_file().map_err(RegularFileAdapterError::ResourceBinding)?;
        self.call_unit(
            if destination { "restore" } else { "thaw" },
            json!({ "state": state_to_value(state)?, "fileResource": file }),
        )?;
        self.validate_active_status()
    }

    fn call_observation(
        &mut self,
        operation: &str,
        args: Value,
    ) -> Result<Observation, RegularFileAdapterError> {
        let value = self.call_value(operation, args)?;
        let wire: ObservationWire = serde_json::from_value(value).map_err(|error| {
            self.process.terminate_after_adapter_failure();
            RegularFileAdapterError::GuestTrap(format!(
                "wacogo returned an invalid regular-file observation: {error}"
            ))
        })?;
        wire.decode()
    }

    fn call_state(
        &mut self,
        operation: &str,
        args: Value,
    ) -> Result<RegularFileComponentState, RegularFileAdapterError> {
        state_from_value(self.call_value(operation, args)?)
    }

    fn call_unit(&mut self, operation: &str, args: Value) -> Result<(), RegularFileAdapterError> {
        unit_result(self.call_value(operation, args)?, operation)
    }

    fn call_value(
        &mut self,
        operation: &str,
        args: Value,
    ) -> Result<Value, RegularFileAdapterError> {
        let reply = {
            let process = &mut self.process;
            let host = &mut self.host;
            process.call_raw(operation, args, |call| host.handle(call)).map_err(transport_error)?
        };
        self.finish_reply_resource_count(reply.live_resources)?;
        match reply.result {
            Ok(value) => Ok(value),
            Err(error) => match terminal_error(error) {
                Ok(error) => Err(error),
                Err(detail) => {
                    self.process.terminate_after_adapter_failure();
                    Err(RegularFileAdapterError::GuestTrap(detail))
                }
            },
        }
    }

    fn finish_reply_resource_count(
        &mut self,
        sidecar_count: usize,
    ) -> Result<(), RegularFileAdapterError> {
        self.sidecar_live_resources = sidecar_count;
        let rust_count = self.host.resource_count();
        if sidecar_count != rust_count {
            self.process.terminate_after_adapter_failure();
            return Err(RegularFileAdapterError::GuestTrap(format!(
                "wacogo regular-file resource count mismatch: sidecar reported {sidecar_count}, Rust owns {rust_count}"
            )));
        }
        Ok(())
    }

    fn validate_observation(
        &self,
        observed: &Observation,
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
            || observed.durable_through != canonical.durable_through
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

fn unit_result(value: Value, operation: &str) -> Result<(), RegularFileAdapterError> {
    if value.is_null() {
        Ok(())
    } else {
        Err(RegularFileAdapterError::GuestTrap(format!(
            "wacogo returned a non-null result for regular-file unit operation {operation}"
        )))
    }
}
