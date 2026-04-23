use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactBundleManifest {
    pub schema_version: u32,
    pub artifact_profile: String,
    pub target: TargetManifest,
    pub compiler: CompilerManifest,
    pub modules: Vec<ModuleArtifactManifest>,
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompilerManifest {
    pub engine: String,
    pub engine_version: String,
    pub execution_mode: String,
    pub artifact_format: String,
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
    pub signature: SignatureManifest,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationPackageManifest {
    pub schema_version: u32,
    pub package_id: String,
    pub source: MigrationHostManifest,
    pub target: MigrationTargetManifest,
    pub required_artifact_profile: RequiredArtifactProfileManifest,
    pub guest: GuestStateManifest,
    pub semantic: SemanticSnapshotManifest,
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
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
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
    pub task_count: usize,
    pub resource_count: usize,
    pub wait_token_count: usize,
    pub capability_count: usize,
    pub fault_domain_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubstrateBoundaryManifest {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    pub native_state_policy: String,
}
