use supervisor_catalog::{
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_COMPILER_ENGINE,
    SUPERVISOR_EXECUTION_MODE,
};

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
