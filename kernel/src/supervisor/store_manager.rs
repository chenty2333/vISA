use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{SemanticGraph, StoreId, StoreState, TrapClass};

use super::artifacts::{ArtifactLoadPlan, StoreLoadBlueprint};

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
    pub(crate) dependency_count: usize,
    pub(crate) expected_export_count: usize,
    pub(crate) last_trap: Option<TrapClass>,
}

pub(crate) struct StoreManager {
    records: Vec<StoreRuntimeRecord>,
}

impl StoreManager {
    pub(crate) fn from_load_plan(
        plan: &ArtifactLoadPlan,
        semantic: &mut SemanticGraph,
    ) -> Result<Self, &'static str> {
        let mut records = Vec::with_capacity(plan.stores().len());
        for blueprint in plan.stores() {
            records.push(Self::bind_blueprint(blueprint, semantic)?);
        }
        Ok(Self { records })
    }

    fn bind_blueprint(
        blueprint: &StoreLoadBlueprint,
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
            dependency_count: blueprint.dependency_count,
            expected_export_count: blueprint.expected_export_count,
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
    }

    pub(crate) fn mark_rebound(&mut self, store: StoreId, semantic: &SemanticGraph) {
        self.set_state(store, StoreState::Rebinding, semantic);
    }

    pub(crate) fn record_trap(&mut self, store: StoreId, trap: TrapClass) {
        if let Some(record) = self.records.iter_mut().find(|record| record.store == store) {
            record.last_trap = Some(trap);
            record.state = StoreRuntimeState::Draining;
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
            "store {} state={} runtime={} generation={} restarts={} resource={} artifact={} deps={} exports={} last_trap={}",
            record.package,
            semantic_store.state.as_str(),
            record.state.as_str(),
            semantic_store.generation,
            semantic_store.restart_count,
            semantic_store
                .resource
                .map(|resource| resource.to_string())
                .unwrap_or_else(|| "none".to_string()),
            record.artifact_name,
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
