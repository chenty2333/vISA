use contract_core::Identity;
pub use visa_component_adapter::{AdapterProvider, KvBinding, TimerBinding};
use visa_component_adapter::{
    BindingError, BindingSet, kv_conditional_put, kv_read, timer_arm, timer_cancel,
};
use visa_runtime::Coordinator;
use wasmtime::component::{Resource, ResourceTable};

use crate::bindings::visa::continuity::{
    key_value::{
        Host as KvHost, HostNamespace, KvError, VersionedValue as WitVersionedValue, WriteResult,
    },
    timers::{ArmResult, Host as TimerHost, HostTimerBinding, TimerError},
};

#[cfg(any(test, feature = "test-control"))]
struct UnsupportedLiveResource;

/// Wasmtime-local store data. Canonical state and provider ownership remain
/// solely inside the coordinator; the resource table contains only opaque
/// receipts produced by the engine-neutral adapter contract.
pub struct StoreState<P> {
    coordinator: Coordinator<P>,
    table: ResourceTable,
    #[cfg(any(test, feature = "test-control"))]
    unsupported_live_resource: Option<Resource<UnsupportedLiveResource>>,
}

impl<P> StoreState<P> {
    pub(crate) fn new(coordinator: Coordinator<P>) -> Self {
        Self {
            coordinator,
            table: ResourceTable::new(),
            #[cfg(any(test, feature = "test-control"))]
            unsupported_live_resource: None,
        }
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        &self.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.coordinator
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub(crate) fn into_coordinator(self) -> Coordinator<P> {
        self.coordinator
    }

    pub(crate) fn fresh_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        if !self.table.is_empty() {
            return Err(BindingError::LiveResources);
        }
        self.push_profile_resources()
    }

    /// Recreate only the source profile handles after a rejected safe point.
    /// Unrelated local handles remain owned by the source; existing timer or
    /// KV handles would make this recovery ambiguous and are rejected.
    pub(crate) fn fresh_source_thaw_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        if self.table.iter_mut().any(|entry| {
            entry.downcast_mut::<KvBinding>().is_some()
                || entry.downcast_mut::<TimerBinding>().is_some()
        }) {
            return Err(BindingError::LiveResources);
        }
        self.push_profile_resources()
    }

    fn push_profile_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        let BindingSet { key_value, timer } = BindingSet::for_state(self.coordinator.state())?;
        let key_value = self.table.push(key_value).map_err(|_| BindingError::ResourceTable)?;
        let timer = match self.table.push(timer) {
            Ok(timer) => timer,
            Err(_) => {
                self.table.delete(key_value).map_err(|_| BindingError::ResourceTable)?;
                return Err(BindingError::ResourceTable);
            }
        };
        Ok((key_value, timer))
    }

    pub(crate) fn set_completion_parent(&mut self, parent: Identity) -> Result<(), BindingError> {
        let mut count = 0;
        for entry in self.table.iter_mut() {
            if let Some(binding) = entry.downcast_mut::<KvBinding>() {
                binding.set_completion_parent(parent);
                count += 1;
            }
        }
        match count {
            1 => Ok(()),
            0 => Err(BindingError::Missing),
            _ => {
                self.clear_completion_parent();
                Err(BindingError::Ambiguous)
            }
        }
    }

    pub(crate) fn clear_completion_parent(&mut self) {
        for entry in self.table.iter_mut() {
            if let Some(binding) = entry.downcast_mut::<KvBinding>() {
                binding.clear_completion_parent();
            }
        }
    }

    /// Insert a real unreturned Wasmtime resource-table entry. This preserves
    /// the Stage 1 safe-point fault path without inventing a semantic handle.
    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn inject_unsupported_live_resource(&mut self) -> Result<(), BindingError> {
        if self.unsupported_live_resource.is_some() {
            return Err(BindingError::LiveResources);
        }
        let resource =
            self.table.push(UnsupportedLiveResource).map_err(|_| BindingError::ResourceTable)?;
        self.unsupported_live_resource = Some(resource);
        Ok(())
    }

    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn clear_unsupported_live_resource(&mut self) -> Result<(), BindingError> {
        let resource = self.unsupported_live_resource.take().ok_or(BindingError::Missing)?;
        self.table.delete(resource).map(|_| ()).map_err(|_| BindingError::ResourceTable)
    }
}

impl<P> KvHost for StoreState<P> where P: AdapterProvider {}

impl<P> HostNamespace for StoreState<P>
where
    P: AdapterProvider,
{
    fn read(
        &mut self,
        resource: Resource<KvBinding>,
        key: String,
    ) -> wasmtime::Result<Result<Option<WitVersionedValue>, KvError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(kv_read(&mut self.coordinator, &binding, key)
            .map(|value| {
                value.map(|value| WitVersionedValue { value: value.value, version: value.version })
            })
            .map_err(KvError::from))
    }

    fn conditional_put(
        &mut self,
        resource: Resource<KvBinding>,
        idempotency_key: String,
        key: String,
        expected_version: Option<u64>,
        value: Vec<u8>,
    ) -> wasmtime::Result<Result<WriteResult, KvError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(kv_conditional_put(
            &mut self.coordinator,
            &binding,
            idempotency_key,
            key,
            expected_version,
            value,
        )
        .map(|result| WriteResult {
            operation_id: result.operation_id,
            version: result.version,
            applied: result.applied,
        })
        .map_err(KvError::from))
    }

    fn drop(&mut self, resource: Resource<KvBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> TimerHost for StoreState<P> where P: AdapterProvider {}

impl<P> HostTimerBinding for StoreState<P>
where
    P: AdapterProvider,
{
    fn arm(
        &mut self,
        resource: Resource<TimerBinding>,
        idempotency_key: String,
        duration_ns: u64,
    ) -> wasmtime::Result<Result<ArmResult, TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(timer_arm(&mut self.coordinator, &binding, idempotency_key, duration_ns)
            .map(|result| ArmResult { operation_id: result.operation_id })
            .map_err(TimerError::from))
    }

    fn cancel(
        &mut self,
        resource: Resource<TimerBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<(), TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(timer_cancel(&mut self.coordinator, &binding, operation_id).map_err(TimerError::from))
    }

    fn drop(&mut self, resource: Resource<TimerBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}
