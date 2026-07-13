use std::collections::BTreeMap;

use contract_core::{Digest, Identity};
use serde_json::{Value, json};
use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterProvider, BindingError, BindingSet, ComponentSafePoint,
    ComponentState, ComponentStatus, CooperativeRuntimeFactory, CooperativeRuntimeInstance,
    KvBinding, PortableComponentState, PreflightExpectations, RecoverableInstantiation,
    ResourceBindingError, RuntimeIdentity, TimerBinding, kv_conditional_put, kv_read, timer_arm,
    timer_cancel,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::Coordinator;

use crate::{
    error::{kv_wire_error, protocol_error, timer_wire_error},
    identity::{WacogoProvenance, static_identity},
    preflight::{PreparedWacogoComponent, preflight},
    process::WacogoProcess,
    protocol::{HostCall, HostCallOperation, NullableU64Text, ResourceKind, WireError},
    state::{decode_canonical_hex, parse_canonical_u64, state_from_value, state_to_value},
};

/// Factory identity for the pinned downstream wacogo derivative.
pub struct WacogoRuntime;

impl WacogoRuntime {
    pub fn runtime_identity_static() -> RuntimeIdentity {
        static_identity()
    }

    pub fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<PreparedWacogoComponent, AdapterError> {
        preflight(component_bytes, profile, support, expectations)
    }
}

/// One isolated wacogo Component instance. Canonical state and effects remain
/// exclusively owned by the Rust Coordinator.
pub struct WacogoAdapter<P: 'static> {
    process: WacogoProcess,
    host: HostState<P>,
    component_digest: Digest,
    identity: RuntimeIdentity,
    provenance: WacogoProvenance,
    sidecar_live_resources: usize,
    #[cfg(any(test, feature = "test-control"))]
    test_control_live_resource: bool,
}

impl<P> WacogoAdapter<P>
where
    P: AdapterProvider + 'static,
{
    pub fn runtime_identity_static() -> RuntimeIdentity {
        static_identity()
    }

    pub fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<PreparedWacogoComponent, AdapterError> {
        preflight(component_bytes, profile, support, expectations)
    }

    pub fn instantiate(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        coordinator: Coordinator<P>,
    ) -> Result<Self, AdapterError> {
        Self::instantiate_recoverable(component_bytes, profile, support, coordinator).map_err(
            |failure| {
                let RecoverableInstantiation { error, .. } = *failure;
                error
            },
        )
    }

    pub fn instantiate_recoverable(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<RecoverableInstantiation<P>>> {
        let expectations = PreflightExpectations {
            component_digest: coordinator.state().component_digest,
            profile_digest: coordinator.state().profile_digest,
        };
        let prepared = match Self::preflight(component_bytes, profile, support, expectations) {
            Ok(prepared) => prepared,
            Err(error) => return Err(Box::new(RecoverableInstantiation { error, coordinator })),
        };
        Self::instantiate_prepared_recoverable(prepared, coordinator)
    }

    pub fn instantiate_prepared_recoverable(
        prepared: PreparedWacogoComponent,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<RecoverableInstantiation<P>>> {
        if let Err(error) = prepared.component.validate() {
            return Err(Box::new(RecoverableInstantiation { error, coordinator }));
        }
        if coordinator.state().component_digest != prepared.component_digest {
            return Err(Box::new(RecoverableInstantiation {
                error: AdapterError::ComponentDigestMismatch {
                    expected: coordinator.state().component_digest,
                    actual: prepared.component_digest,
                },
                coordinator,
            }));
        }
        if coordinator.state().profile_digest != prepared.profile_digest {
            return Err(Box::new(RecoverableInstantiation {
                error: AdapterError::ProfileDigestMismatch {
                    expected: coordinator.state().profile_digest,
                    actual: prepared.profile_digest,
                },
                coordinator,
            }));
        }
        let process = match prepared.process.instantiate() {
            Ok(process) => process,
            Err(error) => return Err(Box::new(RecoverableInstantiation { error, coordinator })),
        };
        Ok(Self {
            process,
            host: HostState::new(coordinator),
            component_digest: prepared.component_digest,
            identity: prepared.identity,
            provenance: prepared.provenance,
            sidecar_live_resources: 0,
            #[cfg(any(test, feature = "test-control"))]
            test_control_live_resource: false,
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
        &self.host.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.host.coordinator
    }

    pub fn resource_table_is_empty(&self) -> bool {
        let runtime_resources_are_empty =
            self.host.resources_are_empty() && self.sidecar_live_resources == 0;
        #[cfg(any(test, feature = "test-control"))]
        {
            runtime_resources_are_empty && !self.test_control_live_resource
        }
        #[cfg(not(any(test, feature = "test-control")))]
        {
            runtime_resources_are_empty
        }
    }

    /// Install one deliberately non-portable live resource for negative
    /// safe-point tests. This flag is local to the test-control build and is
    /// never sent to the sidecar or included in portable state.
    #[cfg(any(test, feature = "test-control"))]
    pub fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        if self.test_control_live_resource {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::LiveResources));
        }
        self.test_control_live_resource = true;
        Ok(())
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        if !self.test_control_live_resource {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::Missing));
        }
        self.test_control_live_resource = false;
        Ok(())
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

    /// Close the guest, both generated host instances, and the engine. Resource
    /// drops emitted during shutdown are still routed through the Rust table.
    pub fn shutdown(&mut self) -> Result<(), AdapterError> {
        let reply = {
            let process = &mut self.process;
            let host = &mut self.host;
            process.shutdown(|call| host.handle(call))?
        };
        self.finish_reply_resource_count(reply.live_resources)?;
        unit_result(reply.result?, "shutdown")?;
        if !self.resource_table_is_empty() {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::LiveResources));
        }
        Ok(())
    }

    pub fn into_coordinator(mut self) -> Result<Coordinator<P>, Box<RecoverableInstantiation<P>>> {
        if let Err(error) = self.shutdown() {
            let Self { process, host, .. } = self;
            drop(process);
            return Err(Box::new(RecoverableInstantiation {
                error,
                coordinator: host.coordinator,
            }));
        }
        let Self { process, host, .. } = self;
        drop(process);
        Ok(host.coordinator)
    }

    fn call_decoded<T>(
        &mut self,
        operation: &str,
        args: Value,
        decode: impl FnOnce(Value) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let reply = {
            let process = &mut self.process;
            let host = &mut self.host;
            process.call(operation, args, |call| host.handle(call))?
        };
        self.finish_reply_resource_count(reply.live_resources)?;
        match reply.result {
            Ok(value) => match decode(value) {
                Ok(value) => Ok(value),
                Err(error) => {
                    self.process.terminate_after_adapter_failure();
                    Err(error)
                }
            },
            Err(error) => {
                if error.kind() != visa_component_adapter::AdapterFailureKind::Workload {
                    self.process.terminate_after_adapter_failure();
                }
                Err(error)
            }
        }
    }

    fn call_unit(&mut self, operation: &str, args: Value) -> Result<(), AdapterError> {
        self.call_decoded(operation, args, |value| unit_result(value, operation))
    }

    fn call_state(&mut self, operation: &str, args: Value) -> Result<ComponentState, AdapterError> {
        self.call_decoded(operation, args, state_from_value)
    }

    fn finish_reply_resource_count(&mut self, sidecar_count: usize) -> Result<(), AdapterError> {
        self.sidecar_live_resources = sidecar_count;
        let rust_count = self.host.resource_count();
        if sidecar_count != rust_count {
            self.process.terminate_after_adapter_failure();
            return Err(AdapterError::GuestTrap(format!(
                "wacogo resource count mismatch: sidecar reported {sidecar_count}, Rust owns {rust_count}"
            )));
        }
        Ok(())
    }
}

impl<P> CooperativeRuntimeInstance<P> for WacogoAdapter<P>
where
    P: AdapterProvider + 'static,
{
    fn runtime_identity(&self) -> RuntimeIdentity {
        self.identity.clone()
    }

    fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    fn coordinator(&self) -> &Coordinator<P> {
        &self.host.coordinator
    }

    fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.host.coordinator
    }

    fn invoke_activate(&mut self, request: &ActivationRequest) -> Result<(), AdapterError> {
        let resources = self.host.fresh_resources()?;
        self.call_unit(
            "activate",
            json!({
                "sessionId": request.session_id,
                "key": request.key,
                "initialValueHex": hex::encode(&request.initial_value),
                "completionValueHex": hex::encode(&request.completion_value),
                "delayNs": request.delay_ns.to_string(),
                "baselineIdempotencyKey": request.baseline_idempotency_key,
                "timerIdempotencyKey": request.timer_idempotency_key,
                "completionIdempotencyKey": request.completion_idempotency_key,
                "kvResource": resources.kv,
                "timerResource": resources.timer,
            }),
        )
    }

    fn invoke_freeze(&mut self) -> Result<ComponentState, AdapterError> {
        self.call_state("freeze", json!({}))
    }

    fn invoke_thaw(&mut self, state: &ComponentState) -> Result<(), AdapterError> {
        let resources = self.host.fresh_resources()?;
        self.call_unit(
            "thaw",
            json!({
                "state": state_to_value(state)?,
                "kvResource": resources.kv,
                "timerResource": resources.timer,
            }),
        )
    }

    fn invoke_restore(
        &mut self,
        state: &ComponentState,
        remaining_duration_ns: u64,
    ) -> Result<(), AdapterError> {
        let resources = self.host.fresh_resources()?;
        self.call_unit(
            "restore",
            json!({
                "state": state_to_value(state)?,
                "remainingDurationNs": remaining_duration_ns.to_string(),
                "kvResource": resources.kv,
                "timerResource": resources.timer,
            }),
        )
    }

    fn invoke_timer_fired(&mut self, operation: &str) -> Result<(), AdapterError> {
        self.call_unit("timer-fired", json!({ "operationId": operation }))
    }

    fn invoke_cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.call_unit("cancel-pending", json!({}))
    }

    fn invoke_status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.call_decoded("status", json!({}), |value| {
            if value.is_null() { Ok(None) } else { state_from_value(value).map(Some) }
        })
    }

    fn has_live_resources(&self) -> bool {
        !self.resource_table_is_empty()
    }

    fn set_completion_parent(&mut self, parent: Identity) -> Result<(), AdapterError> {
        self.host.set_completion_parent(parent).map_err(AdapterError::from)
    }

    fn clear_completion_parent(&mut self) {
        self.host.clear_completion_parent();
    }
}

impl<P> CooperativeRuntimeFactory<P> for WacogoRuntime
where
    P: AdapterProvider + 'static,
{
    type Instance = WacogoAdapter<P>;
    type Prepared = PreparedWacogoComponent;

    fn identity() -> RuntimeIdentity {
        static_identity()
    }

    fn preflight(
        component_bytes: &[u8],
        profile: &CooperativeHandoffProfile,
        support: &ProviderSupport,
        expectations: PreflightExpectations,
    ) -> Result<Self::Prepared, AdapterError> {
        preflight(component_bytes, profile, support, expectations)
    }

    fn instantiate_prepared_recoverable(
        prepared: Self::Prepared,
        coordinator: Coordinator<P>,
    ) -> Result<Self::Instance, Box<RecoverableInstantiation<P>>> {
        WacogoAdapter::instantiate_prepared_recoverable(prepared, coordinator)
    }
}

struct HostState<P> {
    coordinator: Coordinator<P>,
    kv: BTreeMap<u64, KvBinding>,
    timers: BTreeMap<u64, TimerBinding>,
    next_resource: u64,
}

impl<P> HostState<P>
where
    P: AdapterProvider,
{
    fn new(coordinator: Coordinator<P>) -> Self {
        Self { coordinator, kv: BTreeMap::new(), timers: BTreeMap::new(), next_resource: 1 }
    }

    fn fresh_resources(&mut self) -> Result<ResourcePair, AdapterError> {
        if !self.resources_are_empty() {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::LiveResources));
        }
        let BindingSet { key_value, timer } = BindingSet::for_state(self.coordinator.state())?;
        let kv = self.allocate_resource()?;
        let timer_id = self.allocate_resource()?;
        self.kv.insert(kv, key_value);
        self.timers.insert(timer_id, timer);
        Ok(ResourcePair { kv, timer: timer_id })
    }

    fn allocate_resource(&mut self) -> Result<u64, AdapterError> {
        let id = self.next_resource;
        if id == 0 {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::ResourceTable));
        }
        self.next_resource = id
            .checked_add(1)
            .ok_or(AdapterError::ResourceBinding(ResourceBindingError::ResourceTable))?;
        Ok(id)
    }

    fn resource_count(&self) -> usize {
        self.kv.len() + self.timers.len()
    }

    fn resources_are_empty(&self) -> bool {
        self.kv.is_empty() && self.timers.is_empty()
    }

    fn set_completion_parent(&mut self, parent: Identity) -> Result<(), BindingError> {
        if self.kv.len() != 1 {
            return Err(if self.kv.is_empty() {
                BindingError::Missing
            } else {
                BindingError::Ambiguous
            });
        }
        self.kv.values_mut().next().expect("length checked").set_completion_parent(parent);
        Ok(())
    }

    fn clear_completion_parent(&mut self) {
        for binding in self.kv.values_mut() {
            binding.clear_completion_parent();
        }
    }

    fn handle(&mut self, call: HostCall) -> Result<Value, WireError> {
        match call.operation {
            HostCallOperation::KvRead(args) => {
                let binding = self.kv.get(&call.resource).cloned().ok_or_else(|| {
                    protocol_error(
                        "unknown-resource",
                        format!("unknown kv resource {}", call.resource),
                    )
                })?;
                kv_read(&mut self.coordinator, &binding, args.key)
                    .map(|value| {
                        value.map_or(Value::Null, |value| {
                            json!({
                                "valueHex": hex::encode(value.value),
                                "version": value.version.to_string(),
                            })
                        })
                    })
                    .map_err(kv_wire_error)
            }
            HostCallOperation::KvConditionalPut(args) => {
                let expected_version =
                    optional_canonical_u64(args.expected_version, "expectedVersion")?;
                let value = decode_canonical_hex(&args.value_hex).map_err(|detail| {
                    protocol_error("invalid-argument", format!("valueHex is invalid: {detail}"))
                })?;
                let binding = self.kv.get(&call.resource).cloned().ok_or_else(|| {
                    protocol_error(
                        "unknown-resource",
                        format!("unknown kv resource {}", call.resource),
                    )
                })?;
                kv_conditional_put(
                    &mut self.coordinator,
                    &binding,
                    args.idempotency_key,
                    args.key,
                    expected_version,
                    value,
                )
                .map(|result| {
                    json!({
                        "operationId": result.operation_id,
                        "version": result.version.to_string(),
                        "applied": result.applied,
                    })
                })
                .map_err(kv_wire_error)
            }
            HostCallOperation::TimerArm(args) => {
                let duration_ns = canonical_u64(&args.duration_ns, "durationNs")?;
                let binding = self.timers.get(&call.resource).cloned().ok_or_else(|| {
                    protocol_error(
                        "unknown-resource",
                        format!("unknown timer resource {}", call.resource),
                    )
                })?;
                timer_arm(&mut self.coordinator, &binding, args.idempotency_key, duration_ns)
                    .map(|result| json!({ "operationId": result.operation_id }))
                    .map_err(timer_wire_error)
            }
            HostCallOperation::TimerCancel(args) => {
                let binding = self.timers.get(&call.resource).cloned().ok_or_else(|| {
                    protocol_error(
                        "unknown-resource",
                        format!("unknown timer resource {}", call.resource),
                    )
                })?;
                timer_cancel(&mut self.coordinator, &binding, args.operation_id)
                    .map(|()| Value::Null)
                    .map_err(timer_wire_error)
            }
            HostCallOperation::ResourceDispose(args) => {
                let removed = match args.kind {
                    ResourceKind::Kv => self.kv.remove(&call.resource).is_some(),
                    ResourceKind::Timer => self.timers.remove(&call.resource).is_some(),
                };
                if !removed {
                    return Err(protocol_error(
                        "unknown-resource",
                        format!("resource {} was already disposed", call.resource),
                    ));
                }
                Ok(Value::Null)
            }
        }
    }
}

struct ResourcePair {
    kv: u64,
    timer: u64,
}

fn unit_result(value: Value, operation: &str) -> Result<(), AdapterError> {
    if value.is_null() {
        Ok(())
    } else {
        Err(AdapterError::GuestTrap(format!(
            "wacogo returned a non-null result for unit operation {operation}"
        )))
    }
}

fn canonical_u64(value: &str, name: &str) -> Result<u64, WireError> {
    parse_canonical_u64(value).ok_or_else(|| {
        protocol_error("invalid-argument", format!("{name} must be canonical u64 text"))
    })
}

fn optional_canonical_u64(value: NullableU64Text, name: &str) -> Result<Option<u64>, WireError> {
    match value.0 {
        None => Ok(None),
        Some(value) => canonical_u64(&value, name).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_results_and_semantic_integers_are_strict() {
        assert_eq!(unit_result(Value::Null, "activate"), Ok(()));
        assert!(unit_result(json!({}), "activate").is_err());
        assert_eq!(canonical_u64("18446744073709551615", "value").unwrap(), u64::MAX);
        assert!(canonical_u64("01", "value").is_err());
    }
}
