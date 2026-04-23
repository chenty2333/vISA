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
