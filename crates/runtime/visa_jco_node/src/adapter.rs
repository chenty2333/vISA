use std::collections::BTreeMap;

use contract_core::{Digest, Identity};
use serde::Deserialize;
use serde_json::{Value, json};
use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterProvider, BindingError, BindingSet, ComponentSafePoint,
    ComponentState, ComponentStatus, CooperativeRuntimeFactory, CooperativeRuntimeInstance,
    KvBinding, PortableComponentState, PreflightExpectations, RecoverableInstantiation,
    ResourceBindingError, RuntimeIdentity, TimerBinding, WorkloadPhase, kv_conditional_put,
    kv_read, timer_arm, timer_cancel,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};
use visa_runtime::Coordinator;

use crate::{
    error::{kv_wire_error, protocol_error, timer_wire_error},
    preflight::{JcoTranslationProvenance, PreparedJcoComponent, preflight, static_identity},
    process::NodeProcess,
    protocol::{
        HostCall, HostCallOperation, MAX_JS_SAFE_INTEGER, NullableU64Text, ResourceKind, WireError,
    },
};

/// Factory identity used by generic runtime selection code.
pub struct JcoNodeRuntime;

/// One isolated Jco-generated component instance running in Node/V8.
pub struct JcoNodeAdapter<P: 'static> {
    process: NodeProcess,
    host: HostState<P>,
    component_digest: Digest,
    identity: RuntimeIdentity,
    translation_provenance: JcoTranslationProvenance,
    node_live_resources: usize,
}

impl<P> JcoNodeAdapter<P>
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
    ) -> Result<PreparedJcoComponent, AdapterError> {
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
        prepared: PreparedJcoComponent,
        coordinator: Coordinator<P>,
    ) -> Result<Self, Box<(AdapterError, Coordinator<P>)>> {
        if let Err(error) = prepared.revalidate_for_instantiation() {
            return Err(Box::new((error, coordinator)));
        }
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
        let process = match NodeProcess::spawn(&prepared.node_bin, &prepared.graph) {
            Ok(process) => process,
            Err(error) => return Err(Box::new((error, coordinator))),
        };
        let translation_provenance = prepared.translation_provenance();
        Ok(Self {
            process,
            host: HostState::new(coordinator),
            component_digest: prepared.component_digest,
            identity: prepared.identity,
            translation_provenance,
            node_live_resources: 0,
        })
    }

    pub const fn verified_component_digest(&self) -> Digest {
        self.component_digest
    }

    pub fn runtime_identity(&self) -> RuntimeIdentity {
        self.identity.clone()
    }

    pub fn translation_provenance(&self) -> &JcoTranslationProvenance {
        &self.translation_provenance
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        &self.host.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.host.coordinator
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.host.resources_are_empty() && self.node_live_resources == 0
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn inject_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.call_node_unit("test.inject-live-resource", json!({}))
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn clear_unsupported_live_resource(&mut self) -> Result<(), AdapterError> {
        self.call_node_unit("test.clear-live-resource", json!({}))
    }

    pub fn into_coordinator(self) -> Coordinator<P> {
        let Self { process, host, .. } = self;
        drop(process);
        host.coordinator
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

    fn call_node_decoded<T>(
        &mut self,
        op: &str,
        args: Value,
        decode: impl FnOnce(Value) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let reply = {
            let process = &mut self.process;
            let host = &mut self.host;
            process.call(op, args, |call| host.handle(call))?
        };
        let live_resources = reply.live_resources;
        match reply.result {
            Ok(value) => match decode(value) {
                Ok(value) => {
                    finish_node_call(&mut self.node_live_resources, live_resources, Ok(value))
                }
                Err(error) => {
                    self.process.terminate_after_adapter_failure();
                    Err(error)
                }
            },
            Err(error) => {
                finish_node_call(&mut self.node_live_resources, live_resources, Err(error))
            }
        }
    }

    fn call_node_unit(&mut self, op: &str, args: Value) -> Result<(), AdapterError> {
        self.call_node_decoded(op, args, unit_result)
    }

    fn call_node_state(&mut self, op: &str, args: Value) -> Result<ComponentState, AdapterError> {
        self.call_node_decoded(op, args, state_from_wire)
    }
}

fn finish_node_call<T>(
    node_live_resources: &mut usize,
    live_resources: usize,
    result: Result<T, AdapterError>,
) -> Result<T, AdapterError> {
    *node_live_resources = live_resources;
    result
}

impl<P> CooperativeRuntimeInstance<P> for JcoNodeAdapter<P>
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
        self.call_node_unit(
            "activate",
            json!({
                "sessionId": request.session_id,
                "key": request.key,
                "initialValue": request.initial_value,
                "completionValue": request.completion_value,
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
        self.call_node_state("freeze", json!({}))
    }

    fn invoke_thaw(&mut self, state: &ComponentState) -> Result<(), AdapterError> {
        let resources = self.host.fresh_resources()?;
        self.call_node_unit(
            "thaw",
            json!({
                "state": state_to_wire(state),
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
        self.call_node_unit(
            "restore",
            json!({
                "state": state_to_wire(state),
                "remainingDurationNs": remaining_duration_ns.to_string(),
                "kvResource": resources.kv,
                "timerResource": resources.timer,
            }),
        )
    }

    fn invoke_timer_fired(&mut self, operation: &str) -> Result<(), AdapterError> {
        self.call_node_unit("timer-fired", json!({ "operationId": operation }))
    }

    fn invoke_cancel_pending(&mut self) -> Result<(), AdapterError> {
        self.call_node_unit("cancel-pending", json!({}))
    }

    fn invoke_status(&mut self) -> Result<Option<ComponentStatus>, AdapterError> {
        self.call_node_decoded("status", json!({}), |state| {
            if state.is_null() { Ok(None) } else { state_from_wire(state).map(Some) }
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

impl<P> CooperativeRuntimeFactory<P> for JcoNodeRuntime
where
    P: AdapterProvider + 'static,
{
    type Instance = JcoNodeAdapter<P>;
    type Prepared = PreparedJcoComponent;

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
        JcoNodeAdapter::instantiate_prepared_recoverable(prepared, coordinator).map_err(|failure| {
            let (error, coordinator) = *failure;
            Box::new(RecoverableInstantiation { error, coordinator })
        })
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
        if id > MAX_JS_SAFE_INTEGER {
            return Err(AdapterError::ResourceBinding(ResourceBindingError::ResourceTable));
        }
        self.next_resource = self
            .next_resource
            .checked_add(1)
            .ok_or(AdapterError::ResourceBinding(ResourceBindingError::ResourceTable))?;
        Ok(id)
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
                            json!({ "value": value.value, "version": value.version.to_string() })
                        })
                    })
                    .map_err(kv_wire_error)
            }
            HostCallOperation::KvConditionalPut(args) => {
                let expected_version =
                    optional_canonical_u64(args.expected_version, "expectedVersion")?;
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
                    args.value,
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

fn state_to_wire(state: &ComponentState) -> Value {
    json!({
        "sessionId": state.session_id,
        "key": state.key,
        "expectedVersion": state.expected_version.to_string(),
        "completionValue": state.completion_value,
        "timerOperationId": state.timer_operation_id,
        "timerIdempotencyKey": state.timer_idempotency_key,
        "completionIdempotencyKey": state.completion_idempotency_key,
        "phase": phase_name(state.phase),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComponentStateWire {
    session_id: String,
    key: String,
    expected_version: String,
    completion_value: Vec<u8>,
    timer_operation_id: String,
    timer_idempotency_key: String,
    completion_idempotency_key: String,
    phase: String,
}

fn state_from_wire(value: Value) -> Result<ComponentState, AdapterError> {
    let state: ComponentStateWire = serde_json::from_value(value).map_err(|error| {
        AdapterError::GuestTrap(format!("Node returned an invalid component state: {error}"))
    })?;
    let expected_version = parse_canonical_u64(&state.expected_version).ok_or_else(|| {
        AdapterError::GuestTrap("Node state version was not canonical u64 text".into())
    })?;
    let phase = match state.phase.as_str() {
        "armed" => WorkloadPhase::Armed,
        "frozen" => WorkloadPhase::Frozen,
        "completed" => WorkloadPhase::Completed,
        "cancelled" => WorkloadPhase::Cancelled,
        other => {
            return Err(AdapterError::GuestTrap(format!("Node state phase was invalid: {other}")));
        }
    };
    Ok(ComponentState {
        session_id: state.session_id,
        key: state.key,
        expected_version,
        completion_value: state.completion_value,
        timer_operation_id: state.timer_operation_id,
        timer_idempotency_key: state.timer_idempotency_key,
        completion_idempotency_key: state.completion_idempotency_key,
        phase,
    })
}

fn unit_result(value: Value) -> Result<(), AdapterError> {
    if value.is_null() {
        Ok(())
    } else {
        Err(AdapterError::GuestTrap(
            "Node returned a non-null result for a unit lifecycle operation".into(),
        ))
    }
}

const fn phase_name(phase: WorkloadPhase) -> &'static str {
    match phase {
        WorkloadPhase::Armed => "armed",
        WorkloadPhase::Frozen => "frozen",
        WorkloadPhase::Completed => "completed",
        WorkloadPhase::Cancelled => "cancelled",
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

fn parse_canonical_u64(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use visa_component_adapter::{AdapterError, WorkloadFailure};

    use super::{finish_node_call, parse_canonical_u64, state_from_wire, unit_result};

    #[test]
    fn adapter_refreshes_live_resource_count_before_propagating_guest_failure() {
        let mut live_resources = 2;
        let error = finish_node_call(
            &mut live_resources,
            0,
            Err::<(), _>(AdapterError::Workload(WorkloadFailure::InvalidState)),
        )
        .expect_err("guest failure must still propagate");

        assert_eq!(live_resources, 0);
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Workload);
    }

    #[test]
    fn lifecycle_results_require_exact_unit_or_state_shapes() {
        assert_eq!(unit_result(Value::Null), Ok(()));
        assert_eq!(
            unit_result(json!({})).expect_err("unit result must be null").kind(),
            visa_component_adapter::AdapterFailureKind::GuestTrap
        );

        let state = json!({
            "sessionId": "session-a",
            "key": "work",
            "expectedVersion": "1",
            "completionValue": [1, 2],
            "timerOperationId": "00000000000000000000000000000001",
            "timerIdempotencyKey": "timer-key",
            "completionIdempotencyKey": "completion-key",
            "phase": "frozen",
        });
        assert_eq!(state_from_wire(state.clone()).expect("exact state").expected_version, 1);

        let mut extra = state.clone();
        extra.as_object_mut().unwrap().insert("unexpected".into(), Value::Bool(true));
        assert!(state_from_wire(extra).is_err(), "unknown state fields must fail closed");

        let mut noncanonical = state;
        noncanonical.as_object_mut().unwrap().insert("expectedVersion".into(), json!("01"));
        assert!(
            state_from_wire(noncanonical).is_err(),
            "noncanonical state integers must fail closed"
        );
    }

    #[test]
    fn u64_text_is_canonical() {
        for accepted in ["0", "1", "18446744073709551615"] {
            assert!(parse_canonical_u64(accepted).is_some(), "{accepted}");
        }
        for rejected in ["", "00", "01", "+1", "-0", " 1", "1 ", "18446744073709551616"] {
            assert!(parse_canonical_u64(rejected).is_none(), "{rejected}");
        }
    }
}
