use alloc::vec::Vec;

use semantic_core::RuntimeMode;
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use supervisor_catalog::{
    ARTIFACT_HASH_STATUS_MANIFEST_BOUND, ARTIFACT_SIGNATURE_PROFILE,
    ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED, ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
    CapabilitySpec, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION, RUNTIME_ONLY_EXECUTOR_ABI,
    SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_COMPILER_ENGINE,
    SUPERVISOR_CONTRACT_VERSION, SUPERVISOR_EXECUTION_MODE, SUPERVISOR_WASM_MODULES,
    SUPERVISOR_WORLD, StoreBlueprint, WASM_FEATURE_PROFILE, WasmModuleSpec, module_dependencies,
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

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactRegistryError {
    EmptyCatalog,
    EmptyPackage,
    EmptyArtifact,
    MissingMemoryExport,
    RawWasmExecutionMode,
    EmptyManifestPlan,
    ManifestModuleCountMismatch,
    ManifestPackageMismatch,
    ManifestArtifactMismatch,
    ManifestRoleMismatch,
    ManifestFaultPolicyMismatch,
    ManifestExportCountMismatch,
    ManifestDependencyCountMismatch,
    UnsupportedRuntimeMode,
}

impl ArtifactRegistryError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::EmptyCatalog => "supervisor artifact catalog is empty",
            Self::EmptyPackage => "supervisor artifact package is empty",
            Self::EmptyArtifact => "supervisor artifact name is empty",
            Self::MissingMemoryExport => "supervisor artifact does not export memory",
            Self::RawWasmExecutionMode => {
                "supervisor artifact profile does not require TargetArtifactImage"
            }
            Self::EmptyManifestPlan => "embedded supervisor manifest plan is empty",
            Self::ManifestModuleCountMismatch => {
                "embedded supervisor manifest module count does not match catalog"
            }
            Self::ManifestPackageMismatch => {
                "embedded supervisor manifest package does not match catalog"
            }
            Self::ManifestArtifactMismatch => {
                "embedded supervisor manifest artifact does not match catalog"
            }
            Self::ManifestRoleMismatch => {
                "embedded supervisor manifest role does not match catalog"
            }
            Self::ManifestFaultPolicyMismatch => {
                "embedded supervisor manifest fault policy does not match catalog"
            }
            Self::ManifestExportCountMismatch => {
                "embedded supervisor manifest export count does not match catalog"
            }
            Self::ManifestDependencyCountMismatch => {
                "embedded supervisor manifest dependency count does not match catalog"
            }
            Self::UnsupportedRuntimeMode => {
                "embedded supervisor manifest runtime mode is unsupported"
            }
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
    pub(crate) binding: ArtifactManifestBinding,
}

impl TrustedArtifact {
    #[allow(dead_code)]
    fn from_spec(spec: &'static WasmModuleSpec) -> Result<Self, ArtifactRegistryError> {
        Self::validate_spec(spec)?;
        Ok(Self {
            package: spec.package,
            artifact_name: spec.artifact_name,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
            expected_exports: spec.expected_exports,
            capabilities: spec.capabilities,
            dependencies: module_dependencies(spec),
            binding: ArtifactManifestBinding::catalog(),
        })
    }

    fn from_manifest_entry(
        spec: &'static WasmModuleSpec,
        entry: &'static EmbeddedArtifactManifestEntry,
    ) -> Result<Self, ArtifactRegistryError> {
        Self::validate_spec(spec)?;
        if entry.package != spec.package {
            return Err(ArtifactRegistryError::ManifestPackageMismatch);
        }
        if entry.artifact_name != spec.artifact_name {
            return Err(ArtifactRegistryError::ManifestArtifactMismatch);
        }
        if entry.role != spec.role.as_str() {
            return Err(ArtifactRegistryError::ManifestRoleMismatch);
        }
        if entry.fault_policy != spec.fault_policy.as_str() {
            return Err(ArtifactRegistryError::ManifestFaultPolicyMismatch);
        }
        if entry.expected_export_count != spec.expected_exports.len() {
            return Err(ArtifactRegistryError::ManifestExportCountMismatch);
        }
        if entry.dependency_count != module_dependencies(spec).len() {
            return Err(ArtifactRegistryError::ManifestDependencyCountMismatch);
        }
        Ok(Self {
            package: spec.package,
            artifact_name: spec.artifact_name,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
            expected_exports: spec.expected_exports,
            capabilities: spec.capabilities,
            dependencies: module_dependencies(spec),
            binding: ArtifactManifestBinding::embedded(entry),
        })
    }

    fn validate_spec(spec: &'static WasmModuleSpec) -> Result<(), ArtifactRegistryError> {
        if spec.package.is_empty() {
            return Err(ArtifactRegistryError::EmptyPackage);
        }
        if spec.artifact_name.is_empty() {
            return Err(ArtifactRegistryError::EmptyArtifact);
        }
        if !spec.expected_exports.contains(&"memory") {
            return Err(ArtifactRegistryError::MissingMemoryExport);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ArtifactManifestBinding {
    pub(crate) source: &'static str,
    pub(crate) wasm_path: &'static str,
    pub(crate) wasm_sha256: &'static str,
    pub(crate) abi_fingerprint: &'static str,
    pub(crate) cwasm_sha256: &'static str,
    pub(crate) manifest_binding_hash: &'static str,
    pub(crate) hash_status: &'static str,
    pub(crate) signature_profile: &'static str,
    pub(crate) signature_status: &'static str,
    pub(crate) signature_verified: bool,
    pub(crate) signer: &'static str,
    pub(crate) resource_limits: StoreResourceLimits,
}

impl ArtifactManifestBinding {
    #[allow(dead_code)]
    const fn catalog() -> Self {
        Self {
            source: "catalog-embedded-manifest-view",
            wasm_path: "catalog-only",
            wasm_sha256: "catalog-only",
            abi_fingerprint: "catalog-derived",
            cwasm_sha256: "target-cwasm-not-linked",
            manifest_binding_hash: "catalog-derived",
            hash_status: ARTIFACT_HASH_STATUS_MANIFEST_BOUND,
            signature_profile: ARTIFACT_SIGNATURE_PROFILE,
            signature_status: ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED,
            signature_verified: ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
            signer: "supervisor_catalog",
            resource_limits: StoreResourceLimits::prototype_default(),
        }
    }

    const fn embedded(entry: &'static EmbeddedArtifactManifestEntry) -> Self {
        Self {
            source: "buildrs-embedded-manifest-plan",
            wasm_path: entry.wasm_path,
            wasm_sha256: entry.wasm_sha256,
            abi_fingerprint: entry.abi_fingerprint,
            cwasm_sha256: entry.cwasm_sha256,
            manifest_binding_hash: entry.manifest_binding_hash,
            hash_status: ARTIFACT_HASH_STATUS_MANIFEST_BOUND,
            signature_profile: entry.signature_profile,
            signature_status: ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED,
            signature_verified: ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
            signer: entry.signer,
            resource_limits: entry.resource_limits,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StoreResourceLimits {
    pub(crate) max_memory_pages: u32,
    pub(crate) max_table_elements: u32,
    pub(crate) max_hostcalls_per_activation: u32,
}

impl StoreResourceLimits {
    #[allow(dead_code)]
    const fn prototype_default() -> Self {
        Self { max_memory_pages: 16, max_table_elements: 0, max_hostcalls_per_activation: 64 }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct EmbeddedArtifactManifestPlan {
    pub(crate) artifact_profile: &'static str,
    pub(crate) runtime_mode: &'static str,
    pub(crate) entries: &'static [EmbeddedArtifactManifestEntry],
}

#[derive(Clone, Copy)]
pub(crate) struct EmbeddedArtifactManifestEntry {
    pub(crate) package: &'static str,
    pub(crate) artifact_name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) fault_policy: &'static str,
    pub(crate) wasm_path: &'static str,
    pub(crate) wasm_sha256: &'static str,
    pub(crate) cwasm_sha256: &'static str,
    pub(crate) abi_fingerprint: &'static str,
    pub(crate) manifest_binding_hash: &'static str,
    pub(crate) signature_profile: &'static str,
    pub(crate) signer: &'static str,
    pub(crate) resource_limits: StoreResourceLimits,
    pub(crate) dependency_count: usize,
    pub(crate) expected_export_count: usize,
}

include!(concat!(env!("OUT_DIR"), "/supervisor_manifest_plan.rs"));

pub(crate) struct ArtifactRegistry {
    profile: ArtifactTrustProfile,
    artifact_profile: &'static str,
    runtime_mode: RuntimeMode,
    artifacts: Vec<TrustedArtifact>,
}

impl ArtifactRegistry {
    pub(crate) fn from_embedded_manifest_plan() -> Result<Self, ArtifactRegistryError> {
        let profile = ArtifactTrustProfile::current();
        Self::validate_trust_profile(profile)?;
        let manifest = &EMBEDDED_ARTIFACT_MANIFEST_PLAN;
        if manifest.entries.is_empty() {
            return Err(ArtifactRegistryError::EmptyManifestPlan);
        }
        if manifest.entries.len() != SUPERVISOR_WASM_MODULES.len() {
            return Err(ArtifactRegistryError::ManifestModuleCountMismatch);
        }
        let runtime_mode = runtime_mode_from_manifest(manifest.runtime_mode)?;

        let mut artifacts = Vec::with_capacity(manifest.entries.len());
        for (spec, entry) in SUPERVISOR_WASM_MODULES.iter().zip(manifest.entries.iter()) {
            artifacts.push(TrustedArtifact::from_manifest_entry(spec, entry)?);
        }
        Ok(Self { profile, artifact_profile: manifest.artifact_profile, runtime_mode, artifacts })
    }

    #[allow(dead_code)]
    pub(crate) fn from_catalog() -> Result<Self, ArtifactRegistryError> {
        let profile = ArtifactTrustProfile::current();
        Self::validate_trust_profile(profile)?;
        if SUPERVISOR_WASM_MODULES.is_empty() {
            return Err(ArtifactRegistryError::EmptyCatalog);
        }

        let mut artifacts = Vec::with_capacity(SUPERVISOR_WASM_MODULES.len());
        for spec in SUPERVISOR_WASM_MODULES {
            artifacts.push(TrustedArtifact::from_spec(spec)?);
        }
        Ok(Self {
            profile,
            artifact_profile: "catalog-prototype",
            runtime_mode: RuntimeMode::Research,
            artifacts,
        })
    }

    fn validate_trust_profile(profile: ArtifactTrustProfile) -> Result<(), ArtifactRegistryError> {
        if profile.compiler_engine != "wasmtime"
            || profile.execution_mode != "precompiled-core-module"
            || profile.artifact_format != SUPERVISOR_ARTIFACT_FORMAT
        {
            return Err(ArtifactRegistryError::RawWasmExecutionMode);
        }
        Ok(())
    }

    pub(crate) fn profile(&self) -> ArtifactTrustProfile {
        self.profile
    }

    pub(crate) fn artifact_profile(&self) -> &'static str {
        self.artifact_profile
    }

    pub(crate) fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
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
                binding: artifact.binding,
            })
            .collect();
        ArtifactLoadPlan {
            profile: self.profile,
            artifact_profile: self.artifact_profile,
            runtime_mode: self.runtime_mode,
            stores,
        }
    }

    pub(crate) fn artifacts(&self) -> &[TrustedArtifact] {
        &self.artifacts
    }
}

fn runtime_mode_from_manifest(mode: &str) -> Result<RuntimeMode, ArtifactRegistryError> {
    match mode {
        "research" | "" => Ok(RuntimeMode::Research),
        "production" => Ok(RuntimeMode::Production),
        "replay" => Ok(RuntimeMode::Replay),
        _ => Err(ArtifactRegistryError::UnsupportedRuntimeMode),
    }
}

pub(crate) struct ArtifactLoadPlan {
    pub(crate) profile: ArtifactTrustProfile,
    pub(crate) artifact_profile: &'static str,
    pub(crate) runtime_mode: RuntimeMode,
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
    pub(crate) binding: ArtifactManifestBinding,
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
        Self { package: value.package, role, fault_policy, capabilities: value.capabilities }
    }
}
