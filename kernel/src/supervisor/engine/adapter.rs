use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use semantic_core::RuntimeMode;
use supervisor_catalog::{DMW_LAYOUT, RUNTIME_ONLY_EXECUTOR_ABI};

use super::super::artifacts::{ArtifactLoadPlan, StoreLoadBlueprint};
use super::contract::{
    ArtifactFormat, ArtifactLoadError, ExecutorPlanError, RuntimeOnlyProfile, SupervisorArtifact,
};
use super::state::{
    ExecutorHostcallTable, ExecutorInstanceHandle, ExecutorMemoryLayout, ExecutorRuntimeState,
    ExecutorStoreState, ExecutorTableState, ExecutorTrapSurface,
};

pub(crate) struct RuntimeOnlyExecutor {
    profile: RuntimeOnlyProfile,
}

impl Default for RuntimeOnlyExecutor {
    fn default() -> Self {
        Self {
            profile: RuntimeOnlyProfile::current(),
        }
    }
}

impl RuntimeOnlyExecutor {
    pub(crate) const fn profile(&self) -> RuntimeOnlyProfile {
        self.profile
    }

    pub(crate) fn prepare_load_plan(
        &self,
        plan: &ArtifactLoadPlan,
    ) -> Result<ExecutorLoadPlan, ExecutorPlanError> {
        self.validate_load_plan(plan)?;
        let stores = plan
            .stores()
            .iter()
            .enumerate()
            .map(|(index, blueprint)| {
                ExecutorStorePlan::from_blueprint(index as u64 + 1, blueprint)
            })
            .collect();
        Ok(ExecutorLoadPlan {
            profile: self.profile,
            artifact_profile: plan.artifact_profile,
            runtime_mode: plan.runtime_mode,
            stores,
        })
    }

    fn validate_load_plan(&self, plan: &ArtifactLoadPlan) -> Result<(), ExecutorPlanError> {
        if plan.stores().is_empty() {
            return Err(ExecutorPlanError::EmptyLoadPlan);
        }
        if self.profile.compiler_engine != plan.profile.compiler_engine {
            return Err(ExecutorPlanError::CompilerEngineMismatch);
        }
        if self.profile.execution_mode != plan.profile.execution_mode {
            return Err(ExecutorPlanError::ExecutionModeMismatch);
        }
        if self.profile.artifact_format != plan.profile.artifact_format {
            return Err(ExecutorPlanError::ArtifactFormatMismatch);
        }
        if self.profile.runtime_executor_abi != plan.profile.runtime_executor_abi {
            return Err(ExecutorPlanError::RuntimeExecutorAbiMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_artifact(
        &self,
        artifact: SupervisorArtifact<'_>,
    ) -> Result<(), ArtifactLoadError> {
        let _profile = self.profile;
        if artifact.bytes.is_empty() {
            return Err(ArtifactLoadError::EmptyArtifact);
        }
        match artifact.format {
            ArtifactFormat::WasmModuleBytes => Err(ArtifactLoadError::RawWasmRejected),
            ArtifactFormat::WasmtimePrecompiledModule => Err(ArtifactLoadError::RuntimeNotLinked),
        }
    }
}

pub(crate) struct ExecutorLoadPlan {
    pub(crate) profile: RuntimeOnlyProfile,
    pub(crate) artifact_profile: &'static str,
    pub(crate) runtime_mode: RuntimeMode,
    stores: Vec<ExecutorStorePlan>,
}

impl ExecutorLoadPlan {
    pub(crate) fn stores(&self) -> &[ExecutorStorePlan] {
        &self.stores
    }

    pub(crate) fn store_count(&self) -> usize {
        self.stores.len()
    }

    pub(crate) fn store(&self, package: &str) -> Option<&ExecutorStorePlan> {
        self.stores.iter().find(|store| store.package == package)
    }

    pub(crate) fn summary_line(&self) -> String {
        format!(
            "executor load plan profile={} mode={} stores={} engine={} exec_mode={} format={} abi={}",
            self.artifact_profile,
            self.runtime_mode.as_str(),
            self.store_count(),
            self.profile.compiler_engine,
            self.profile.execution_mode,
            self.profile.artifact_format,
            self.profile.runtime_executor_abi
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorStorePlan {
    pub(crate) handle: ExecutorInstanceHandle,
    pub(crate) package: &'static str,
    pub(crate) artifact_name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) fault_policy: &'static str,
    pub(crate) artifact_format: ArtifactFormat,
    pub(crate) manifest_binding_hash: &'static str,
    pub(crate) abi_fingerprint: &'static str,
    pub(crate) memory_layout: ExecutorMemoryLayout,
    pub(crate) hostcall_table: ExecutorHostcallTable,
    pub(crate) trap_surface: ExecutorTrapSurface,
    pub(crate) state: ExecutorStoreState,
    pub(crate) blocked_by: Option<&'static str>,
    pub(crate) cleanup_policy: &'static str,
    pub(crate) rebind_policy: &'static str,
}

impl ExecutorStorePlan {
    fn from_blueprint(handle: u64, blueprint: &StoreLoadBlueprint) -> Self {
        Self {
            handle: ExecutorInstanceHandle::planned(handle),
            package: blueprint.package,
            artifact_name: blueprint.artifact_name,
            role: blueprint.role,
            fault_policy: blueprint.fault_policy,
            artifact_format: ArtifactFormat::WasmtimePrecompiledModule,
            manifest_binding_hash: blueprint.binding.manifest_binding_hash,
            abi_fingerprint: blueprint.binding.abi_fingerprint,
            memory_layout: ExecutorMemoryLayout {
                dmw_layout: DMW_LAYOUT,
                max_memory_pages: blueprint.binding.resource_limits.max_memory_pages,
                max_table_elements: blueprint.binding.resource_limits.max_table_elements,
                publish_policy: "runtime-only-wx-publish-required",
            },
            hostcall_table: ExecutorHostcallTable {
                abi: RUNTIME_ONLY_EXECUTOR_ABI,
                state: ExecutorTableState::NotLinked,
                max_hostcalls_per_activation: blueprint
                    .binding
                    .resource_limits
                    .max_hostcalls_per_activation,
                expected_export_count: blueprint.expected_export_count,
            },
            trap_surface: ExecutorTrapSurface::runtime_only_v1(),
            state: ExecutorStoreState::ArtifactVerified,
            blocked_by: Some("code-publish-not-linked"),
            cleanup_policy: cleanup_policy(blueprint.fault_policy),
            rebind_policy: rebind_policy(blueprint.fault_policy),
        }
    }
}

impl ExecutorRuntimeState {
    pub(crate) const fn from_plan(plan: &ExecutorStorePlan) -> Self {
        Self {
            store: plan.state,
            hostcall_table: plan.hostcall_table,
            trap_surface: plan.trap_surface,
            blocked_by: plan.blocked_by,
        }
    }
}

fn cleanup_policy(fault_policy: &str) -> &'static str {
    if fault_policy == "restartable" {
        "drop-instance-close-store-owned-resources"
    } else {
        "kill-store-close-owned-resources"
    }
}

fn rebind_policy(fault_policy: &str) -> &'static str {
    if fault_policy == "restartable" {
        "manifest-binding-rebind"
    } else {
        "no-rebind"
    }
}
