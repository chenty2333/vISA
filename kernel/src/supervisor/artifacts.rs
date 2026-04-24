use alloc::vec::Vec;

use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, CapabilitySpec, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT,
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_CONTRACT_VERSION, SUPERVISOR_EXECUTION_MODE,
    SUPERVISOR_WASM_MODULES, SUPERVISOR_WORLD, StoreBlueprint, WASM_FEATURE_PROFILE,
    WasmModuleSpec, module_dependencies,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactTrustProfile {
    pub(crate) contract_version: &'static str,
    pub(crate) supervisor_world: &'static str,
    pub(crate) machine_abi: &'static str,
    pub(crate) supervisor_abi: &'static str,
    pub(crate) wasm_feature_profile: &'static str,
    pub(crate) dmw_layout: &'static str,
    pub(crate) linux_abi: &'static str,
    pub(crate) network_contract: &'static str,
    pub(crate) signature_profile: &'static str,
    pub(crate) compiler_engine: &'static str,
    pub(crate) execution_mode: &'static str,
    pub(crate) artifact_format: &'static str,
    pub(crate) runtime_executor_abi: &'static str,
}

impl ArtifactTrustProfile {
    pub(crate) const fn current() -> Self {
        Self {
            contract_version: SUPERVISOR_CONTRACT_VERSION,
            supervisor_world: SUPERVISOR_WORLD,
            machine_abi: MACHINE_ABI_VERSION,
            supervisor_abi: SUPERVISOR_ABI_VERSION,
            wasm_feature_profile: WASM_FEATURE_PROFILE,
            dmw_layout: DMW_LAYOUT,
            linux_abi: LINUX_ABI_PROFILE,
            network_contract: NETWORK_CONTRACT_VERSION,
            signature_profile: ARTIFACT_SIGNATURE_PROFILE,
            compiler_engine: SUPERVISOR_COMPILER_ENGINE,
            execution_mode: SUPERVISOR_EXECUTION_MODE,
            artifact_format: SUPERVISOR_ARTIFACT_FORMAT,
            runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactRegistryError {
    EmptyCatalog,
    EmptyPackage,
    EmptyArtifact,
    MissingMemoryExport,
    RawWasmExecutionMode,
}

impl ArtifactRegistryError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::EmptyCatalog => "supervisor artifact catalog is empty",
            Self::EmptyPackage => "supervisor artifact package is empty",
            Self::EmptyArtifact => "supervisor artifact name is empty",
            Self::MissingMemoryExport => "supervisor artifact does not export memory",
            Self::RawWasmExecutionMode => "supervisor artifact profile does not require cwasm",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TrustedArtifact {
    pub(crate) package: &'static str,
    pub(crate) artifact_name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) fault_policy: &'static str,
    pub(crate) expected_exports: &'static [&'static str],
    pub(crate) capabilities: &'static [CapabilitySpec],
    pub(crate) dependencies: &'static [&'static str],
}

impl TrustedArtifact {
    fn from_spec(spec: &'static WasmModuleSpec) -> Result<Self, ArtifactRegistryError> {
        if spec.package.is_empty() {
            return Err(ArtifactRegistryError::EmptyPackage);
        }
        if spec.artifact_name.is_empty() {
            return Err(ArtifactRegistryError::EmptyArtifact);
        }
        if !spec
            .expected_exports
            .iter()
            .any(|export| *export == "memory")
        {
            return Err(ArtifactRegistryError::MissingMemoryExport);
        }
        Ok(Self {
            package: spec.package,
            artifact_name: spec.artifact_name,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
            expected_exports: spec.expected_exports,
            capabilities: spec.capabilities,
            dependencies: module_dependencies(spec),
        })
    }
}

pub(crate) struct ArtifactRegistry {
    profile: ArtifactTrustProfile,
    artifacts: Vec<TrustedArtifact>,
}

impl ArtifactRegistry {
    pub(crate) fn from_catalog() -> Result<Self, ArtifactRegistryError> {
        let profile = ArtifactTrustProfile::current();
        if profile.compiler_engine != "wasmtime"
            || profile.execution_mode != "precompiled-core-module"
            || profile.artifact_format != "cwasm"
        {
            return Err(ArtifactRegistryError::RawWasmExecutionMode);
        }
        if SUPERVISOR_WASM_MODULES.is_empty() {
            return Err(ArtifactRegistryError::EmptyCatalog);
        }

        let mut artifacts = Vec::with_capacity(SUPERVISOR_WASM_MODULES.len());
        for spec in SUPERVISOR_WASM_MODULES {
            artifacts.push(TrustedArtifact::from_spec(spec)?);
        }
        Ok(Self { profile, artifacts })
    }

    pub(crate) fn profile(&self) -> ArtifactTrustProfile {
        self.profile
    }

    pub(crate) fn load_plan(&self) -> ArtifactLoadPlan {
        let stores = self
            .artifacts
            .iter()
            .map(|artifact| StoreLoadBlueprint {
                package: artifact.package,
                artifact_name: artifact.artifact_name,
                role: artifact.role,
                fault_policy: artifact.fault_policy,
                capabilities: artifact.capabilities,
                dependency_count: artifact.dependencies.len(),
                expected_export_count: artifact.expected_exports.len(),
            })
            .collect();
        ArtifactLoadPlan {
            profile: self.profile,
            stores,
        }
    }

    pub(crate) fn artifacts(&self) -> &[TrustedArtifact] {
        &self.artifacts
    }
}

pub(crate) struct ArtifactLoadPlan {
    pub(crate) profile: ArtifactTrustProfile,
    stores: Vec<StoreLoadBlueprint>,
}

impl ArtifactLoadPlan {
    pub(crate) fn stores(&self) -> &[StoreLoadBlueprint] {
        &self.stores
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StoreLoadBlueprint {
    pub(crate) package: &'static str,
    pub(crate) artifact_name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) fault_policy: &'static str,
    pub(crate) capabilities: &'static [CapabilitySpec],
    pub(crate) dependency_count: usize,
    pub(crate) expected_export_count: usize,
}

impl From<&StoreLoadBlueprint> for StoreBlueprint {
    fn from(value: &StoreLoadBlueprint) -> Self {
        let role = SUPERVISOR_WASM_MODULES
            .iter()
            .find(|spec| spec.package == value.package)
            .map(|spec| spec.role)
            .expect("store load blueprint must originate from supervisor catalog");
        let fault_policy = SUPERVISOR_WASM_MODULES
            .iter()
            .find(|spec| spec.package == value.package)
            .map(|spec| spec.fault_policy)
            .expect("store load blueprint must originate from supervisor catalog");
        Self {
            package: value.package,
            role,
            fault_policy,
            capabilities: value.capabilities,
        }
    }
}
