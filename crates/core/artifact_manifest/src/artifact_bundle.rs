use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactBundleManifest {
    pub schema_version: u32,
    pub artifact_profile: String,
    #[serde(default)]
    pub runtime_mode: String,
    #[serde(default)]
    pub contract: SupervisorContractManifest,
    pub target: TargetManifest,
    pub compiler: CompilerManifest,
    pub modules: Vec<ModuleArtifactManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SupervisorContractManifest {
    pub contract_version: String,
    pub supervisor_world: String,
    pub catalog_fingerprint: String,
    pub package_set_fingerprint: String,
    pub module_count: usize,
    pub required_packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetManifest {
    pub arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub linux_abi_profile: String,
    #[serde(default)]
    pub artifact_signature_profile: String,
    #[serde(default)]
    pub network_contract_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompilerManifest {
    pub engine: String,
    pub engine_version: String,
    pub execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub target_artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModuleArtifactManifest {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    #[serde(default)]
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    #[serde(default)]
    pub target_artifact_sha256: String,
    #[serde(default)]
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub exports: Vec<ExternManifest>,
    pub imports: Vec<ImportManifest>,
    pub capabilities: Vec<CapabilityManifest>,
    #[serde(default)]
    pub abi_fingerprint: String,
    #[serde(default)]
    pub service_dependencies: Vec<String>,
    #[serde(default)]
    pub resource_limits: ResourceLimitsManifest,
    #[serde(default)]
    pub interfaces: InterfaceRequirementManifest,
    pub signature: SignatureManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ResourceLimitsManifest {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternManifest {
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportManifest {
    pub module: String,
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CapabilityManifest {
    pub name: String,
    pub rights: Vec<String>,
    pub lifetime: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct InterfaceRequirementManifest {
    #[serde(default)]
    pub required_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub optional_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub custom_wit_worlds: Vec<String>,
    #[serde(default)]
    pub wit_package_versions: Vec<String>,
    #[serde(default)]
    pub component_model_version: String,
    #[serde(default)]
    pub wasi_profile: String,
    #[serde(default)]
    pub hostcall_abi_version: String,
    #[serde(default)]
    pub capability_abi_version: String,
    #[serde(default)]
    pub semantic_contract_version: String,
    #[serde(default)]
    pub substrate_profile_required: String,
    #[serde(default)]
    pub substrate_authorities: SubstrateAuthorityRequirementManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubstrateAuthorityRequirementManifest {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureManifest {
    pub scheme: String,
    pub artifact_hash: String,
    pub manifest_binding_hash: String,
    pub signer: String,
    #[serde(default)]
    pub public_key_hint: String,
    #[serde(default)]
    pub signature: String,
}
