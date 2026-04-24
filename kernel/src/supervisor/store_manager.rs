use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{SemanticGraph, StoreId, StoreState, TrapClass};

use super::artifacts::{ArtifactLoadPlan, ArtifactManifestBinding, StoreLoadBlueprint};
use super::engine::{
    ExecutorHostcallTable, ExecutorLoadPlan, ExecutorMemoryLayout, ExecutorStorePlan,
    ExecutorStoreState, ExecutorTrapSurface,
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
    pub(crate) executor_state: ExecutorStoreState,
    pub(crate) executor_memory: ExecutorMemoryLayout,
    pub(crate) executor_hostcalls: ExecutorHostcallTable,
    pub(crate) executor_traps: ExecutorTrapSurface,
    pub(crate) dependency_count: usize,
    pub(crate) expected_export_count: usize,
    pub(crate) manifest_binding: ArtifactManifestBinding,
    pub(crate) last_trap: Option<TrapClass>,
}

pub(crate) struct StoreManager {
    records: Vec<StoreRuntimeRecord>,
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
            executor_state: executor.state,
            executor_memory: executor.memory_layout,
            executor_hostcalls: executor.hostcall_table,
            executor_traps: executor.trap_surface,
            dependency_count: blueprint.dependency_count,
            expected_export_count: blueprint.expected_export_count,
            manifest_binding: blueprint.binding,
            last_trap: None,
        })
    }

    pub(crate) fn set_state(
        &mut self,
        store: StoreId,
        state: StoreState,
        semantic: &SemanticGraph,
    ) {
        if let Some(record) = self.records.iter_mut().find(|record| record.store == store) {
            record.state = StoreRuntimeState::from_semantic(state);
            if let Some(semantic_store) = semantic.stores().iter().find(|item| item.id == store) {
                record.generation = semantic_store.generation;
                record.restart_count = semantic_store.restart_count;
            }
        }
    }

    pub(crate) fn mark_dropped(&mut self, store: StoreId, semantic: &SemanticGraph) {
        self.set_state(store, StoreState::Dead, semantic);
        if let Some(record) = self.records.iter_mut().find(|record| record.store == store) {
            record.executor_state = ExecutorStoreState::Dropped;
        }
    }

    pub(crate) fn mark_rebound(&mut self, store: StoreId, semantic: &SemanticGraph) {
        self.set_state(store, StoreState::Rebinding, semantic);
        if let Some(record) = self.records.iter_mut().find(|record| record.store == store) {
            record.executor_state = ExecutorStoreState::CodeUnpublished;
        }
    }

    pub(crate) fn record_trap(&mut self, store: StoreId, trap: TrapClass) {
        if let Some(record) = self.records.iter_mut().find(|record| record.store == store) {
            record.last_trap = Some(trap);
            record.state = StoreRuntimeState::Draining;
            record.executor_state = ExecutorStoreState::Draining;
        }
    }

    pub(crate) fn store_id(&self, package: &str) -> Option<StoreId> {
        self.records
            .iter()
            .find(|record| record.package == package)
            .map(|record| record.store)
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
        Some(format!(
            "store {} state={} runtime={} executor={} generation={} restarts={} resource={} arena={} cap_owner={} cleanup={} rebind={} artifact={} manifest_source={} wasm={} wasm_hash={} abi={} cwasm={} binding={} signature={} signer={} limits=mem{} table{} hostcalls{} executor_mem=pages{} table{} dmw={} publish={} hostcall_table={} max={} exports={} traps={}/{}/{} deps={} exports={} last_trap={}",
            record.package,
            semantic_store.state.as_str(),
            record.state.as_str(),
            record.executor_state.as_str(),
            semantic_store.generation,
            semantic_store.restart_count,
            semantic_store
                .resource
                .map(|resource| resource.to_string())
                .unwrap_or_else(|| "none".to_string()),
            record.resource_arena,
            record.capability_owner,
            record.cleanup_policy,
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
