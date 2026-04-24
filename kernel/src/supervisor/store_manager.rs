use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{
    FaultDomainId, ResourceId, SemanticGraph, StoreDropReport, StoreId, StoreRebindReport,
    StoreState, TrapClass,
};

use super::artifacts::{ArtifactLoadPlan, ArtifactManifestBinding, StoreLoadBlueprint};
use super::engine::{
    ExecutorHostcallTable, ExecutorInstanceHandle, ExecutorLoadPlan, ExecutorMemoryLayout,
    ExecutorStorePlan, ExecutorStoreState, ExecutorTrapSurface,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreRuntimeState {
    Loaded,
    Running,
    Draining,
    Restarting,
    Dead,
}

impl StoreRuntimeState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
            Self::Dead => "dead",
        }
    }

    const fn from_semantic(state: StoreState) -> Self {
        match state {
            StoreState::Created | StoreState::Instantiating => Self::Loaded,
            StoreState::Running => Self::Running,
            StoreState::Degraded | StoreState::Draining => Self::Draining,
            StoreState::Restarting | StoreState::Rebinding => Self::Restarting,
            StoreState::Dead => Self::Dead,
        }
    }
}

pub(crate) struct StoreRuntimeRecord {
    pub(crate) package: &'static str,
    pub(crate) artifact_name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) fault_policy: &'static str,
    pub(crate) store: StoreId,
    pub(crate) state: StoreRuntimeState,
    pub(crate) generation: u64,
    pub(crate) restart_count: u64,
    pub(crate) capability_owner: &'static str,
    pub(crate) resource_arena: String,
    pub(crate) cleanup_policy: &'static str,
    pub(crate) rebind_policy: &'static str,
    pub(crate) executor_instance: ExecutorInstanceHandle,
    pub(crate) executor_state: ExecutorStoreState,
    pub(crate) executor_memory: ExecutorMemoryLayout,
    pub(crate) executor_hostcalls: ExecutorHostcallTable,
    pub(crate) executor_traps: ExecutorTrapSurface,
    pub(crate) dependency_count: usize,
    pub(crate) expected_export_count: usize,
    pub(crate) manifest_binding: ArtifactManifestBinding,
    pub(crate) last_trap: Option<TrapClass>,
    pub(crate) last_closed_resources: usize,
    pub(crate) last_dropped_resource: Option<ResourceId>,
    pub(crate) last_rebound_resource: Option<ResourceId>,
}

pub(crate) struct StoreManager {
    records: Vec<StoreRuntimeRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoreMicroReboot {
    pub(crate) store: StoreId,
    pub(crate) fault_domain: Option<FaultDomainId>,
    pub(crate) trap: TrapClass,
}

impl StoreManager {
    pub(crate) fn from_load_plan(
        plan: &ArtifactLoadPlan,
        executor_plan: &ExecutorLoadPlan,
        semantic: &mut SemanticGraph,
    ) -> Result<Self, &'static str> {
        let mut records = Vec::with_capacity(plan.stores().len());
        for blueprint in plan.stores() {
            let executor = executor_plan
                .store(blueprint.package)
                .ok_or("executor plan was missing store blueprint")?;
            records.push(Self::bind_blueprint(blueprint, executor, semantic)?);
        }
        Ok(Self { records })
    }

    fn bind_blueprint(
        blueprint: &StoreLoadBlueprint,
        executor: &ExecutorStorePlan,
        semantic: &mut SemanticGraph,
    ) -> Result<StoreRuntimeRecord, &'static str> {
        let store = semantic.register_store(
            blueprint.package,
            blueprint.artifact_name,
            blueprint.role,
            blueprint.fault_policy,
        );
        semantic.set_store_state(store, StoreState::Instantiating);
        semantic.set_store_state(store, StoreState::Running);
        let semantic_store = semantic
            .stores()
            .iter()
            .find(|record| record.id == store)
            .ok_or("store manager could not bind semantic store")?;
        Ok(StoreRuntimeRecord {
            package: blueprint.package,
            artifact_name: blueprint.artifact_name,
            role: blueprint.role,
            fault_policy: blueprint.fault_policy,
            store,
            state: StoreRuntimeState::from_semantic(semantic_store.state),
            generation: semantic_store.generation,
            restart_count: semantic_store.restart_count,
            capability_owner: blueprint.package,
            resource_arena: format!("store-arena:{}", blueprint.package),
            cleanup_policy: executor.cleanup_policy,
            rebind_policy: executor.rebind_policy,
            executor_instance: executor.handle,
            executor_state: executor.state,
            executor_memory: executor.memory_layout,
            executor_hostcalls: executor.hostcall_table,
            executor_traps: executor.trap_surface,
            dependency_count: blueprint.dependency_count,
            expected_export_count: blueprint.expected_export_count,
            manifest_binding: blueprint.binding,
            last_trap: None,
            last_closed_resources: 0,
            last_dropped_resource: None,
            last_rebound_resource: semantic_store.resource,
        })
    }

    pub(crate) fn set_state(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
        state: StoreState,
    ) -> Result<(), &'static str> {
        self.record_index(store)?;
        semantic.set_store_state(store, state);
        self.sync_record(store, semantic)
    }

    pub(crate) fn begin_micro_reboot(
        &mut self,
        semantic: &mut SemanticGraph,
        package: &str,
        trap: TrapClass,
        detail: &str,
    ) -> Result<StoreMicroReboot, &'static str> {
        let store = self
            .store_id(package)
            .ok_or("store was not registered in store manager")?;
        let fault_domain = semantic.fault_domain_id(package);
        self.record_trap(semantic, store, trap, detail)?;
        self.set_state(semantic, store, StoreState::Draining)?;
        self.set_state(semantic, store, StoreState::Restarting)?;
        Ok(StoreMicroReboot {
            store,
            fault_domain,
            trap,
        })
    }

    pub(crate) fn drop_instance(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
    ) -> Result<StoreDropReport, &'static str> {
        self.record_index(store)?;
        let report = semantic
            .drop_store_instance(store)
            .ok_or("store to drop was not present")?;
        self.sync_record(store, semantic)?;
        let record = self.record_mut(store)?;
        record.executor_state = ExecutorStoreState::Dropped;
        record.executor_instance.generation += 1;
        record.last_closed_resources = report.closed_resources;
        record.last_dropped_resource = report.previous_resource;
        record.last_rebound_resource = None;
        Ok(report)
    }

    pub(crate) fn fail_micro_reboot(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
    ) -> Result<StoreDropReport, &'static str> {
        let report = self.drop_instance(semantic, store)?;
        self.record_mut(store)?.executor_state = ExecutorStoreState::InstanceUnavailable;
        Ok(report)
    }

    pub(crate) fn rebind_instance(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
    ) -> Result<StoreRebindReport, &'static str> {
        self.record_index(store)?;
        let report = semantic
            .rebind_store_instance(store)
            .ok_or("store to rebind was not present")?;
        self.sync_record(store, semantic)?;
        let record = self.record_mut(store)?;
        record.executor_state = ExecutorStoreState::CodeUnpublished;
        record.executor_instance.generation += 1;
        record.last_rebound_resource = Some(report.resource);
        Ok(report)
    }

    pub(crate) fn finish_micro_reboot(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
    ) -> Result<(), &'static str> {
        self.set_state(semantic, store, StoreState::Running)
    }

    pub(crate) fn record_trap(
        &mut self,
        semantic: &mut SemanticGraph,
        store: StoreId,
        trap: TrapClass,
        detail: &str,
    ) -> Result<(), &'static str> {
        self.record_index(store)?;
        semantic.record_store_trap_class(store, trap, detail);
        self.sync_record(store, semantic)?;
        let record = self.record_mut(store)?;
        record.last_trap = Some(trap);
        record.state = StoreRuntimeState::Draining;
        record.executor_state = ExecutorStoreState::Draining;
        Ok(())
    }

    pub(crate) fn store_id(&self, package: &str) -> Option<StoreId> {
        self.records
            .iter()
            .find(|record| record.package == package)
            .map(|record| record.store)
    }

    fn record_index(&self, store: StoreId) -> Result<usize, &'static str> {
        self.records
            .iter()
            .position(|record| record.store == store)
            .ok_or("store was not registered in store manager")
    }

    fn record_mut(&mut self, store: StoreId) -> Result<&mut StoreRuntimeRecord, &'static str> {
        let index = self.record_index(store)?;
        Ok(&mut self.records[index])
    }

    fn sync_record(
        &mut self,
        store: StoreId,
        semantic: &SemanticGraph,
    ) -> Result<(), &'static str> {
        let semantic_store = semantic
            .stores()
            .iter()
            .find(|item| item.id == store)
            .ok_or("semantic store was not registered")?;
        let record = self.record_mut(store)?;
        record.state = StoreRuntimeState::from_semantic(semantic_store.state);
        record.generation = semantic_store.generation;
        record.restart_count = semantic_store.restart_count;
        Ok(())
    }

    pub(crate) fn lifecycle_line(&self, semantic: &SemanticGraph, package: &str) -> Option<String> {
        let record = self
            .records
            .iter()
            .find(|record| record.package == package)?;
        let semantic_store = semantic
            .stores()
            .iter()
            .find(|item| item.id == record.store)?;
        let last_dropped = record
            .last_dropped_resource
            .map(|resource| resource.to_string())
            .unwrap_or_else(|| "none".to_string());
        let last_rebound = record
            .last_rebound_resource
            .map(|resource| resource.to_string())
            .unwrap_or_else(|| "none".to_string());
        Some(format!(
            "store {} state={} runtime={} executor={} executor_instance={}@{} generation={} restarts={} resource={} arena={} cap_owner={} cleanup={} last_closed={} dropped={} rebound={} rebind={} artifact={} manifest_source={} wasm={} wasm_hash={} abi={} cwasm={} binding={} signature={} signer={} limits=mem{} table{} hostcalls{} executor_mem=pages{} table{} dmw={} publish={} hostcall_table={} max={} exports={} traps={}/{}/{} deps={} exports={} last_trap={}",
            record.package,
            semantic_store.state.as_str(),
            record.state.as_str(),
            record.executor_state.as_str(),
            record.executor_instance.id,
            record.executor_instance.generation,
            semantic_store.generation,
            semantic_store.restart_count,
            semantic_store
                .resource
                .map(|resource| resource.to_string())
                .unwrap_or_else(|| "none".to_string()),
            record.resource_arena,
            record.capability_owner,
            record.cleanup_policy,
            record.last_closed_resources,
            last_dropped,
            last_rebound,
            record.rebind_policy,
            record.artifact_name,
            record.manifest_binding.source,
            record.manifest_binding.wasm_path,
            record.manifest_binding.wasm_sha256,
            record.manifest_binding.abi_fingerprint,
            record.manifest_binding.cwasm_sha256,
            record.manifest_binding.manifest_binding_hash,
            record.manifest_binding.signature_profile,
            record.manifest_binding.signer,
            record.manifest_binding.resource_limits.max_memory_pages,
            record.manifest_binding.resource_limits.max_table_elements,
            record
                .manifest_binding
                .resource_limits
                .max_hostcalls_per_activation,
            record.executor_memory.max_memory_pages,
            record.executor_memory.max_table_elements,
            record.executor_memory.dmw_layout,
            record.executor_memory.publish_policy,
            record.executor_hostcalls.state.as_str(),
            record.executor_hostcalls.max_hostcalls_per_activation,
            record.executor_hostcalls.expected_export_count,
            record.executor_traps.guest_trap,
            record.executor_traps.supervisor_trap,
            record.executor_traps.substrate_fault,
            record.dependency_count,
            record.expected_export_count,
            record
                .last_trap
                .map(|trap| trap.fault_class().as_str())
                .unwrap_or("none")
        ))
    }

    pub(crate) fn records(&self) -> &[StoreRuntimeRecord] {
        &self.records
    }
}
