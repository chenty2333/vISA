//! vISA effect validation and compatibility checks.
//!
//! This crate validates stable Semantic Virtual ISA effect encodings, artifact
//! manifests, package roots, profile compatibility, and catalog/interface facts.
//! It is a validation layer around `contract_core` records, not a runtime
//! executor and not a frontend personality implementation.

use artifact_manifest::{
    ArtifactBundleManifest, BoundaryValidationReportManifest, CapabilityManifest,
    ContractCoreEvidenceManifest, InterfaceRequirementManifest, MigrationPackageManifest,
    ModuleArtifactManifest, ResourceLimitsManifest, SupervisorContractManifest,
};
use contract_core::*;
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use sha2::{Digest, Sha256};
pub use supervisor_catalog::{
    ARTIFACT_HASH_STATUS_MANIFEST_BOUND, ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED,
    ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
};
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, CAPABILITY_ABI_VERSION, COMPONENT_MODEL_VERSION, CapabilitySpec,
    DMW_LAYOUT, HOSTCALL_ABI_VERSION, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SEMANTIC_CONTRACT_SCHEMA_VERSION, SUPERVISOR_ABI_VERSION,
    SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_CONTRACT_VERSION,
    SUPERVISOR_EXECUTION_MODE, SUPERVISOR_WASM_MODULES, SUPERVISOR_WORLD, WASI_PROFILE_NONE,
    WASM_FEATURE_PROFILE, WIT_PACKAGE_VERSION, WasmModuleSpec, catalog_contract_fingerprint,
    module_dependencies, module_interface_spec, package_set_fingerprint,
};
use visa_profile::{
    AuthorityMismatch, AuthorityRequirementSet, SubstrateAuthorityRequirements,
    SubstrateCapabilitySet, SubstrateCompatibilityReport, SubstrateProfile,
    is_supported_real_target_arch,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactPlan {
    pub artifact_profile: String,
    pub runtime_mode: String,
    pub contract_version: String,
    pub supervisor_world: String,
    pub target_arch: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    pub target_artifact_format: String,
    pub runtime_executor_abi: String,
    pub modules: Vec<ValidatedArtifactEntry>,
}

impl ValidatedArtifactPlan {
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn capability_count(&self) -> usize {
        self.modules.iter().map(|entry| entry.capabilities.len()).sum()
    }

    pub fn expected_export_count(&self) -> usize {
        self.modules.iter().map(|entry| entry.expected_exports.len()).sum()
    }

    pub fn entry(&self, package: &str) -> Option<&ValidatedArtifactEntry> {
        self.modules.iter().find(|entry| entry.package == package)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactEntry {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    pub target_artifact_sha256: String,
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub capabilities: Vec<CapabilityManifest>,
    pub abi_fingerprint: String,
    pub service_dependencies: Vec<String>,
    pub resource_limits: ResourceLimitsManifest,
    pub interfaces: InterfaceRequirementManifest,
    pub signature_scheme: String,
    pub signer: String,
    pub manifest_binding_hash: String,
    pub hash_status: String,
    pub signature_status: String,
    pub signature_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateCompatibilityItem {
    pub authority: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSubstrateCompatibilityReport {
    pub package: String,
    pub substrate_profile_required: String,
    pub reported_profile: String,
    pub enforced_profile: String,
    pub ok: bool,
    pub profile_ok: bool,
    pub authority_ok: bool,
    pub missing_required: Vec<SubstrateCompatibilityItem>,
    pub degraded_optional: Vec<SubstrateCompatibilityItem>,
    pub forbidden_requested: Vec<String>,
    pub forbidden_authorities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSubstrateCompatibilityReport {
    pub artifact_profile: String,
    pub reported_profile: String,
    pub enforced_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleSubstrateCompatibilityReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceHostCapabilitySet {
    pub wasi_worlds: Vec<String>,
    pub custom_wit_worlds: Vec<String>,
    pub component_model_version: String,
    pub wasi_profile: String,
    pub hostcall_abi_version: String,
    pub capability_abi_version: String,
    pub semantic_contract_version: String,
}

impl InterfaceHostCapabilitySet {
    pub fn empty() -> Self {
        Self {
            wasi_worlds: Vec::new(),
            custom_wit_worlds: Vec::new(),
            component_model_version: DEFAULT_COMPONENT_MODEL_VERSION.to_owned(),
            wasi_profile: DEFAULT_WASI_PROFILE.to_owned(),
            hostcall_abi_version: DEFAULT_HOSTCALL_ABI_VERSION.to_owned(),
            capability_abi_version: DEFAULT_CAPABILITY_ABI_VERSION.to_owned(),
            semantic_contract_version: DEFAULT_SEMANTIC_CONTRACT_SCHEMA_VERSION.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceVersionMismatch {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInterfaceCompatibilityReport {
    pub package: String,
    pub ok: bool,
    pub missing_required_wasi_worlds: Vec<String>,
    pub degraded_optional_wasi_worlds: Vec<String>,
    pub missing_custom_wit_worlds: Vec<String>,
    pub version_mismatches: Vec<InterfaceVersionMismatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactInterfaceCompatibilityReport {
    pub artifact_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleInterfaceCompatibilityReport>,
}

mod artifact;
mod audit;
mod contract_core_evidence;
mod migration;

pub use artifact::*;
pub use audit::*;
pub use contract_core_evidence::*;
pub use migration::*;

#[cfg(test)]
mod tests;
