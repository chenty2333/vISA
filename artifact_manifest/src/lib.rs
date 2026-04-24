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
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationPackageManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub package_format: String,
    pub package_id: String,
    pub source: MigrationHostManifest,
    pub target: MigrationTargetManifest,
    pub required_artifact_profile: RequiredArtifactProfileManifest,
    pub guest: GuestStateManifest,
    pub semantic: SemanticSnapshotManifest,
    pub logical_capabilities: Vec<MigrationCapabilityManifest>,
    pub substrate_boundary: SubstrateBoundaryManifest,
    pub not_migrated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationHostManifest {
    pub arch: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationTargetManifest {
    pub arch_requirement: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequiredArtifactProfileManifest {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub network_contract_version: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuestStateManifest {
    pub canonical_isa: String,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SemanticSnapshotManifest {
    pub barrier_id: u64,
    pub event_log_cursor: u64,
    #[serde(default)]
    pub roots: SemanticRootSetManifest,
    #[serde(default)]
    pub pending_wait_count: usize,
    pub task_count: usize,
    pub resource_count: usize,
    #[serde(default)]
    pub authority_count: usize,
    #[serde(default)]
    pub active_authority_count: usize,
    pub wait_token_count: usize,
    pub capability_count: usize,
    pub fault_domain_count: usize,
    #[serde(default)]
    pub store_count: usize,
    #[serde(default)]
    pub transaction_count: usize,
    #[serde(default)]
    pub active_transaction_count: usize,
    #[serde(default)]
    pub fast_path_plan_count: usize,
    #[serde(default)]
    pub active_fast_path_plan_count: usize,
    #[serde(default)]
    pub network_socket_count: u32,
    #[serde(default)]
    pub network_rx_queue_bytes: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SemanticRootSetManifest {
    #[serde(default)]
    pub task_roots: Vec<String>,
    #[serde(default)]
    pub resource_roots: Vec<String>,
    #[serde(default)]
    pub authority_roots: Vec<String>,
    #[serde(default)]
    pub wait_roots: Vec<String>,
    #[serde(default)]
    pub store_roots: Vec<String>,
    #[serde(default)]
    pub capability_roots: Vec<String>,
    #[serde(default)]
    pub fast_path_roots: Vec<String>,
    #[serde(default)]
    pub event_log_tail: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubstrateBoundaryManifest {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    #[serde(default)]
    pub pending_network_inputs: u32,
    #[serde(default)]
    pub random_epoch: u64,
    #[serde(default)]
    pub scheduler_decision_cursor: u64,
    #[serde(default)]
    pub cow_epoch: u64,
    #[serde(default)]
    pub background_copy_pages: u64,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationCapabilityManifest {
    pub subject: String,
    pub object: String,
    pub rights: Vec<String>,
    pub lifetime: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_task: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub revoked: bool,
}
