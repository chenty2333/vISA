#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::supervisor::types::ServiceCallError;
use semantic_core::RuntimeMode;
use supervisor_catalog::{
    DMW_LAYOUT, RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_COMPILER_ENGINE,
    SUPERVISOR_EXECUTION_MODE,
};

use super::super::artifacts::{ArtifactLoadPlan, StoreLoadBlueprint};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactFormat {
    WasmModuleBytes,
    WasmtimePrecompiledModule,
}

impl ArtifactFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WasmModuleBytes => "wasm",
            Self::WasmtimePrecompiledModule => "cwasm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeOnlyProfile {
    pub(crate) compiler_engine: &'static str,
    pub(crate) execution_mode: &'static str,
    pub(crate) artifact_format: &'static str,
    pub(crate) runtime_executor_abi: &'static str,
}

impl RuntimeOnlyProfile {
    pub(crate) const fn current() -> Self {
        Self {
            compiler_engine: SUPERVISOR_COMPILER_ENGINE,
            execution_mode: SUPERVISOR_EXECUTION_MODE,
            artifact_format: SUPERVISOR_ARTIFACT_FORMAT,
            runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorPlanError {
    CompilerEngineMismatch,
    ExecutionModeMismatch,
    ArtifactFormatMismatch,
    RuntimeExecutorAbiMismatch,
    EmptyLoadPlan,
}

impl ExecutorPlanError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::CompilerEngineMismatch => "executor compiler engine does not match load plan",
            Self::ExecutionModeMismatch => "executor execution mode does not match load plan",
            Self::ArtifactFormatMismatch => "executor artifact format does not match load plan",
            Self::RuntimeExecutorAbiMismatch => "executor ABI does not match artifact load plan",
            Self::EmptyLoadPlan => "executor load plan is empty",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SupervisorArtifact<'bytes> {
    pub(crate) package: &'static str,
    pub(crate) format: ArtifactFormat,
    pub(crate) bytes: &'bytes [u8],
}

impl<'bytes> SupervisorArtifact<'bytes> {
    pub(crate) const fn embedded_wasm(package: &'static str, bytes: &'bytes [u8]) -> Self {
        Self {
            package,
            format: ArtifactFormat::WasmModuleBytes,
            bytes,
        }
    }

    pub(crate) const fn precompiled(package: &'static str, bytes: &'bytes [u8]) -> Self {
        Self {
            package,
            format: ArtifactFormat::WasmtimePrecompiledModule,
            bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactLoadError {
    RawWasmRejected,
    RuntimeNotLinked,
    EmptyArtifact,
}

impl ArtifactLoadError {
    pub(crate) const fn message(&self) -> &'static str {
        match self {
            Self::RawWasmRejected => {
                "raw wasm supervisor artifact rejected; load signed wasmtime cwasm"
            }
            Self::RuntimeNotLinked => "target runtime-only executor is not linked yet",
            Self::EmptyArtifact => "supervisor artifact is empty",
        }
    }
}

pub(crate) trait FunctionParams {}
impl<T> FunctionParams for T {}

pub(crate) trait FunctionResults {}
impl<T> FunctionResults for T {}

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

    fn validate_artifact(&self, artifact: SupervisorArtifact<'_>) -> Result<(), ArtifactLoadError> {
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
pub(crate) struct ExecutorInstanceHandle {
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

impl ExecutorInstanceHandle {
    const fn planned(id: u64) -> Self {
        Self { id, generation: 1 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorStoreState {
    Planned,
    CodeUnpublished,
    InstanceUnavailable,
    Draining,
    Dropped,
}

impl ExecutorStoreState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::CodeUnpublished => "code-unpublished",
            Self::InstanceUnavailable => "instance-unavailable",
            Self::Draining => "draining",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorTableState {
    Planned,
    NotLinked,
    Bound,
}

impl ExecutorTableState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::NotLinked => "not-linked",
            Self::Bound => "bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorMemoryLayout {
    pub(crate) dmw_layout: &'static str,
    pub(crate) max_memory_pages: u32,
    pub(crate) max_table_elements: u32,
    pub(crate) publish_policy: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorHostcallTable {
    pub(crate) abi: &'static str,
    pub(crate) state: ExecutorTableState,
    pub(crate) max_hostcalls_per_activation: u32,
    pub(crate) expected_export_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorTrapSurface {
    pub(crate) guest_trap: &'static str,
    pub(crate) supervisor_trap: &'static str,
    pub(crate) substrate_fault: &'static str,
}

impl ExecutorTrapSurface {
    const fn runtime_only_v1() -> Self {
        Self {
            guest_trap: "guest-trap->frontend-personality",
            supervisor_trap: "supervisor-trap->store-fault-domain",
            substrate_fault: "substrate-fault->machine-fault",
        }
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
            state: ExecutorStoreState::CodeUnpublished,
            cleanup_policy: cleanup_policy(blueprint.fault_policy),
            rebind_policy: rebind_policy(blueprint.fault_policy),
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

pub(crate) type SupervisorEngine = RuntimeOnlyExecutor;
pub(crate) type ModuleInstance = ArtifactInstance;
pub(crate) type WasmFn<Params, Results> = ArtifactFn<Params, Results>;
pub(crate) type BufferedModule = BufferedArtifactInstance;

pub(crate) struct ArtifactFn<Params, Results> {
    export: &'static str,
    _marker: PhantomData<fn(Params) -> Results>,
}

impl<Params, Results> ArtifactFn<Params, Results> {
    const fn new(export: &'static str) -> Self {
        Self {
            export,
            _marker: PhantomData,
        }
    }

    pub(crate) const fn export(&self) -> &'static str {
        self.export
    }
}

pub(crate) struct ArtifactInstance {
    package: &'static str,
    format: ArtifactFormat,
}

impl ArtifactInstance {
    pub(crate) fn instantiate(
        executor: &RuntimeOnlyExecutor,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let artifact = SupervisorArtifact::embedded_wasm("embedded-supervisor-module", bytes);
        Self::instantiate_artifact(executor, artifact, instantiate_msg)
    }

    pub(crate) fn instantiate_artifact(
        executor: &RuntimeOnlyExecutor,
        artifact: SupervisorArtifact<'_>,
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        executor.validate_artifact(artifact).map_err(|error| {
            crate::kwarn!(
                "{}: package={} format={} reason={}",
                instantiate_msg,
                artifact.package,
                artifact.format.as_str(),
                error.message()
            );
            instantiate_msg
        })?;
        Ok(Self {
            package: artifact.package,
            format: artifact.format,
        })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        _missing_msg: &'static str,
    ) -> Result<ArtifactFn<Params, Results>, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        let _package = self.package;
        Ok(ArtifactFn::new(export))
    }

    pub(crate) fn export_u32(
        &mut self,
        export: &'static str,
        missing_msg: &'static str,
        call_msg: &'static str,
    ) -> Result<u32, &'static str> {
        let getter = self.bind::<(), u32>(export, missing_msg)?;
        self.call(&getter, (), call_msg)
    }

    pub(crate) fn call<Params, Results>(
        &mut self,
        func: &ArtifactFn<Params, Results>,
        _args: Params,
        trap_msg: &'static str,
    ) -> Result<Results, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        crate::kwarn!(
            "runtime-only executor cannot call {}::{} format={} without target loader",
            self.package,
            func.export(),
            self.format.as_str()
        );
        Err(trap_msg)
    }

    pub(crate) fn write_memory(
        &mut self,
        ptr: u32,
        bytes: &[u8],
        error_msg: &'static str,
    ) -> Result<(), &'static str> {
        let _ = (ptr, bytes);
        Err(error_msg)
    }

    pub(crate) fn read_memory(
        &self,
        ptr: u32,
        len: u32,
        error_msg: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        let _ = (ptr, len);
        Err(error_msg)
    }
}

pub(crate) struct BufferedArtifactInstance {
    module: ArtifactInstance,
    request_ptr: u32,
    request_capacity: u32,
    response_ptr: u32,
    response_capacity: u32,
}

impl BufferedArtifactInstance {
    pub(crate) fn instantiate(
        executor: &RuntimeOnlyExecutor,
        bytes: &[u8],
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let artifact = SupervisorArtifact::embedded_wasm("embedded-buffered-service", bytes);
        Self::instantiate_artifact(executor, artifact, instantiate_msg)
    }

    pub(crate) fn instantiate_artifact(
        executor: &RuntimeOnlyExecutor,
        artifact: SupervisorArtifact<'_>,
        instantiate_msg: &'static str,
    ) -> Result<Self, &'static str> {
        let mut module =
            ArtifactInstance::instantiate_artifact(executor, artifact, instantiate_msg)?;
        let request_ptr = module.export_u32(
            "request_ptr",
            "missing service request_ptr export",
            "failed to fetch service request_ptr",
        )?;
        let request_capacity = module.export_u32(
            "request_capacity",
            "missing service request_capacity export",
            "failed to fetch service request_capacity",
        )?;
        let response_ptr = module.export_u32(
            "response_ptr",
            "missing service response_ptr export",
            "failed to fetch service response_ptr",
        )?;
        let response_capacity = module.export_u32(
            "response_capacity",
            "missing service response_capacity export",
            "failed to fetch service response_capacity",
        )?;
        Ok(Self {
            module,
            request_ptr,
            request_capacity,
            response_ptr,
            response_capacity,
        })
    }

    pub(crate) fn bind<Params, Results>(
        &self,
        export: &'static str,
        missing_msg: &'static str,
    ) -> Result<ArtifactFn<Params, Results>, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        self.module.bind(export, missing_msg)
    }

    pub(crate) fn call<Params, Results>(
        &mut self,
        func: &ArtifactFn<Params, Results>,
        args: Params,
        trap_msg: &'static str,
    ) -> Result<Results, &'static str>
    where
        Params: FunctionParams,
        Results: FunctionResults,
    {
        self.module.call(func, args, trap_msg)
    }

    pub(crate) fn write_request(&mut self, bytes: &[u8]) -> Result<u32, &'static str> {
        if bytes.len() > self.request_capacity as usize {
            return Err("service request buffer overflowed");
        }
        self.module.write_memory(
            self.request_ptr,
            bytes,
            "failed to write service request buffer",
        )?;
        Ok(bytes.len() as u32)
    }

    pub(crate) fn read_response(&self, len: u32) -> Result<Vec<u8>, &'static str> {
        if len > self.response_capacity {
            return Err("service response exceeded capacity");
        }
        self.module.read_memory(
            self.response_ptr,
            len,
            "failed to read service response buffer",
        )
    }
}

pub(crate) fn expect_ok(rc: i32) -> Result<(), ServiceCallError> {
    if rc == 0 {
        Ok(())
    } else if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Err(ServiceCallError::Invalid(
            "service returned an unexpected positive status",
        ))
    }
}

pub(crate) fn expect_len(rc: i32) -> Result<u32, ServiceCallError> {
    if rc < 0 {
        Err(ServiceCallError::Errno(-rc))
    } else {
        Ok(rc as u32)
    }
}
