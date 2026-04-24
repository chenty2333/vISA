use std::error::Error;
use std::fmt;

use artifact_manifest::{
    ArtifactBundleManifest, MigrationPackageManifest, ModuleArtifactManifest,
    SupervisorContractManifest,
};
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use sha2::{Digest, Sha256};
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, CapabilitySpec, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT,
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_CONTRACT_VERSION, SUPERVISOR_EXECUTION_MODE,
    SUPERVISOR_WASM_MODULES, SUPERVISOR_WORLD, WASM_FEATURE_PROFILE, WasmModuleSpec,
    catalog_contract_fingerprint, module_dependencies, package_set_fingerprint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError {
    message: String,
}

impl ContractError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ContractError {}

pub type ContractResult<T> = Result<T, ContractError>;

pub fn contract_hex(value: u64) -> String {
    format!("{value:016x}")
}

pub fn expected_supervisor_contract() -> SupervisorContractManifest {
    SupervisorContractManifest {
        contract_version: SUPERVISOR_CONTRACT_VERSION.to_owned(),
        supervisor_world: SUPERVISOR_WORLD.to_owned(),
        catalog_fingerprint: contract_hex(catalog_contract_fingerprint()),
        package_set_fingerprint: contract_hex(package_set_fingerprint()),
        module_count: SUPERVISOR_WASM_MODULES.len(),
        required_packages: SUPERVISOR_WASM_MODULES
            .iter()
            .map(|module| module.package.to_owned())
            .collect(),
    }
}

pub fn validate_artifact_manifest(manifest: &ArtifactBundleManifest) -> ContractResult<()> {
    if manifest.schema_version != 1 {
        return Err(ContractError::new("unsupported manifest schema version"));
    }
    validate_supervisor_contract(manifest)?;
    if manifest.compiler.engine != SUPERVISOR_COMPILER_ENGINE {
        return Err(ContractError::new("manifest compiler engine mismatch"));
    }
    if manifest.compiler.artifact_format != SUPERVISOR_ARTIFACT_FORMAT {
        return Err(ContractError::new("manifest artifact format mismatch"));
    }
    if manifest.compiler.execution_mode != SUPERVISOR_EXECUTION_MODE {
        return Err(ContractError::new("manifest execution mode mismatch"));
    }
    if manifest.compiler.runtime_executor_abi != RUNTIME_ONLY_EXECUTOR_ABI {
        return Err(ContractError::new("manifest runtime executor ABI mismatch"));
    }
    if manifest.target.linux_abi_profile != LINUX_ABI_PROFILE {
        return Err(ContractError::new("manifest Linux ABI profile mismatch"));
    }
    if manifest.target.artifact_signature_profile != ARTIFACT_SIGNATURE_PROFILE {
        return Err(ContractError::new(
            "manifest artifact signature profile mismatch",
        ));
    }
    if manifest.target.machine_abi_version != MACHINE_ABI_VERSION {
        return Err(ContractError::new("manifest machine ABI mismatch"));
    }
    if manifest.target.supervisor_abi_version != SUPERVISOR_ABI_VERSION {
        return Err(ContractError::new("manifest supervisor ABI mismatch"));
    }
    if manifest.target.wasm_feature_profile != WASM_FEATURE_PROFILE {
        return Err(ContractError::new("manifest Wasm feature profile mismatch"));
    }
    if manifest.target.dmw_layout != DMW_LAYOUT {
        return Err(ContractError::new("manifest DMW layout mismatch"));
    }
    if manifest.target.network_contract_version != NETWORK_CONTRACT_VERSION {
        return Err(ContractError::new("manifest network contract mismatch"));
    }
    Ok(())
}

pub fn validate_supervisor_contract(manifest: &ArtifactBundleManifest) -> ContractResult<()> {
    let expected = expected_supervisor_contract();
    let contract = &manifest.contract;
    if contract.contract_version != expected.contract_version {
        return Err(ContractError::new("supervisor contract version mismatch"));
    }
    if contract.supervisor_world != expected.supervisor_world {
        return Err(ContractError::new("supervisor world mismatch"));
    }
    if contract.catalog_fingerprint != expected.catalog_fingerprint {
        return Err(ContractError::new(
            "supervisor catalog fingerprint mismatch",
        ));
    }
    if contract.package_set_fingerprint != expected.package_set_fingerprint {
        return Err(ContractError::new(
            "supervisor package set fingerprint mismatch",
        ));
    }
    if contract.module_count != SUPERVISOR_WASM_MODULES.len()
        || manifest.modules.len() != SUPERVISOR_WASM_MODULES.len()
        || contract.required_packages.len() != SUPERVISOR_WASM_MODULES.len()
    {
        return Err(ContractError::new("supervisor module count mismatch"));
    }
    for (index, spec) in SUPERVISOR_WASM_MODULES.iter().enumerate() {
        let Some(package) = contract.required_packages.get(index) else {
            return Err(ContractError::new("supervisor package order mismatch"));
        };
        if package != spec.package {
            return Err(ContractError::new("supervisor package order mismatch"));
        }
        let count = manifest
            .modules
            .iter()
            .filter(|entry| entry.package == spec.package)
            .count();
        if count != 1 {
            return Err(ContractError::new(format!(
                "manifest has invalid module count for {}",
                spec.package
            )));
        }
    }
    for entry in &manifest.modules {
        if !SUPERVISOR_WASM_MODULES
            .iter()
            .any(|spec| spec.package == entry.package)
        {
            return Err(ContractError::new(format!(
                "manifest contains unknown module {}",
                entry.package
            )));
        }
    }
    Ok(())
}

pub fn validate_manifest_entry(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.artifact_name != spec.artifact_name {
        return Err(ContractError::new(format!(
            "{} artifact name mismatch",
            spec.package
        )));
    }
    if entry.role != spec.role.as_str() {
        return Err(ContractError::new(format!(
            "{} role mismatch",
            spec.package
        )));
    }
    if entry.fault_policy != spec.fault_policy.as_str() {
        return Err(ContractError::new(format!(
            "{} fault policy mismatch",
            spec.package
        )));
    }
    let expected_dependencies = module_dependencies(spec);
    if entry.service_dependencies.len() != expected_dependencies.len()
        || expected_dependencies.iter().any(|dependency| {
            !entry
                .service_dependencies
                .iter()
                .any(|entry| entry == dependency)
        })
    {
        return Err(ContractError::new(format!(
            "{} service dependency mismatch",
            spec.package
        )));
    }
    if entry.signature.scheme != ARTIFACT_SIGNATURE_PROFILE {
        return Err(ContractError::new(format!(
            "{} signature scheme mismatch",
            spec.package
        )));
    }
    if entry.abi_fingerprint != module_abi_fingerprint(spec) {
        return Err(ContractError::new(format!(
            "{} ABI fingerprint mismatch",
            spec.package
        )));
    }
    if entry.signature.artifact_hash != entry.cwasm_sha256 {
        return Err(ContractError::new(format!(
            "{} signature artifact hash mismatch",
            spec.package
        )));
    }
    if entry.signature.public_key_hint.is_empty() || entry.signature.signature.is_empty() {
        return Err(ContractError::new(format!(
            "{} signature payload is incomplete",
            spec.package
        )));
    }
    let expected_binding = manifest_binding_hash(
        spec,
        &entry.wasm_sha256,
        &entry.cwasm_sha256,
        &entry.abi_fingerprint,
    );
    if entry.signature.manifest_binding_hash != expected_binding {
        return Err(ContractError::new(format!(
            "{} manifest binding hash mismatch",
            spec.package
        )));
    }
    if !entry.cwasm_path.ends_with(".cwasm") {
        return Err(ContractError::new(format!(
            "{} artifact path is not a cwasm module",
            spec.package
        )));
    }
    validate_capabilities(spec, entry)?;
    Ok(())
}

pub fn validate_migration_package(package: &MigrationPackageManifest) -> ContractResult<()> {
    if package.schema_version != 1 {
        return Err(ContractError::new(
            "unsupported semantic package schema version",
        ));
    }
    if package.package_format != "vmos-semantic-package-v1" {
        return Err(ContractError::new("unsupported semantic package format"));
    }
    if package.guest.canonical_isa != "riscv64" {
        return Err(ContractError::new("unsupported canonical guest ISA"));
    }
    if package.semantic.active_transaction_count != 0 {
        return Err(ContractError::new(
            "package contains active semantic transactions",
        ));
    }
    if package.logical_capabilities.len() != package.semantic.capability_count {
        return Err(ContractError::new("package capability list/count mismatch"));
    }
    for capability in &package.logical_capabilities {
        if capability.subject.is_empty()
            || capability.object.is_empty()
            || capability.rights.is_empty()
            || capability.generation == 0
        {
            return Err(ContractError::new(
                "package contains an invalid logical capability",
            ));
        }
    }
    validate_semantic_roots(package)?;
    Ok(())
}

pub fn validate_migration_against_manifest(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> ContractResult<()> {
    validate_artifact_manifest(manifest)?;
    validate_migration_package(package)?;
    let required = &package.required_artifact_profile;
    if required.target_arch != "target-native" && required.target_arch != manifest.target.arch {
        return Err(ContractError::new(
            "package target arch is incompatible with manifest",
        ));
    }
    if required.machine_abi_version != manifest.target.machine_abi_version {
        return Err(ContractError::new("package machine ABI mismatch"));
    }
    if required.supervisor_abi_version != manifest.target.supervisor_abi_version {
        return Err(ContractError::new("package supervisor ABI mismatch"));
    }
    if required.wasm_feature_profile != manifest.target.wasm_feature_profile {
        return Err(ContractError::new("package Wasm feature profile mismatch"));
    }
    if required.memory64 != manifest.target.memory64
        || required.multi_memory != manifest.target.multi_memory
    {
        return Err(ContractError::new("package Wasm memory model mismatch"));
    }
    if required.dmw_layout != manifest.target.dmw_layout {
        return Err(ContractError::new("package DMW layout mismatch"));
    }
    if required.network_contract_version != manifest.target.network_contract_version {
        return Err(ContractError::new("package network contract mismatch"));
    }
    if required.compiler_engine != manifest.compiler.engine
        || required.compiler_execution_mode != manifest.compiler.execution_mode
        || required.artifact_format != manifest.compiler.artifact_format
        || required.runtime_executor_abi != manifest.compiler.runtime_executor_abi
    {
        return Err(ContractError::new(
            "package compiler/artifact mode mismatch",
        ));
    }
    Ok(())
}

pub fn validate_replay_quiescent(package: &MigrationPackageManifest) -> ContractResult<()> {
    validate_migration_package(package)?;
    if package.substrate_boundary.pending_dma_completions != 0
        || package.substrate_boundary.pending_network_inputs != 0
        || package.substrate_boundary.active_dmw_lease_count != 0
    {
        return Err(ContractError::new("package is not replay-quiescent"));
    }
    if package.substrate_boundary.background_copy_pages != 0 {
        return Err(ContractError::new(
            "package contains unfinished background COW copies",
        ));
    }
    Ok(())
}

pub fn validate_semantic_roots(package: &MigrationPackageManifest) -> ContractResult<()> {
    let roots = &package.semantic.roots;
    if roots.task_roots.len() != package.semantic.task_count {
        return Err(ContractError::new("task root/count mismatch"));
    }
    if roots.resource_roots.len() != package.semantic.resource_count {
        return Err(ContractError::new("resource root/count mismatch"));
    }
    if roots.authority_roots.len() != package.semantic.authority_count {
        return Err(ContractError::new("authority root/count mismatch"));
    }
    if package.semantic.active_authority_count > package.semantic.authority_count {
        return Err(ContractError::new(
            "active authority count exceeds authority count",
        ));
    }
    if roots.wait_roots.len() != package.semantic.wait_token_count {
        return Err(ContractError::new("wait root/count mismatch"));
    }
    if roots.store_roots.len() != package.semantic.store_count {
        return Err(ContractError::new("store root/count mismatch"));
    }
    if roots.capability_roots.len() != package.semantic.capability_count {
        return Err(ContractError::new("capability root/count mismatch"));
    }
    if roots.fast_path_roots.len() != package.semantic.fast_path_plan_count {
        return Err(ContractError::new("fastpath root/count mismatch"));
    }
    if roots.event_log_tail.is_empty() && package.semantic.event_log_cursor != 0 {
        return Err(ContractError::new(
            "event log cursor is nonzero but package has no event tail",
        ));
    }
    Ok(())
}

pub fn manifest_binding_hash(
    spec: &WasmModuleSpec,
    wasm_sha256: &str,
    cwasm_sha256: &str,
    abi_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spec.package.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.artifact_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.role.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.fault_policy.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(wasm_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(cwasm_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(abi_fingerprint.as_bytes());
    for export in spec.expected_exports {
        hasher.update(b"\0");
        hasher.update(export.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn module_abi_fingerprint(spec: &WasmModuleSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spec.package.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.artifact_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.role.as_str().as_bytes());
    for export in spec.expected_exports {
        hasher.update(b"\0export:");
        hasher.update(export.as_bytes());
    }
    for capability in spec.capabilities {
        hasher.update(b"\0cap:");
        hasher.update(capability.name.as_bytes());
        hasher.update(b":");
        hasher.update(capability.lifetime.as_bytes());
        for right in capability.rights {
            hasher.update(b":");
            hasher.update(right.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn validate_capabilities(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.capabilities.len() != spec.capabilities.len() {
        return Err(ContractError::new(format!(
            "{} capability count mismatch",
            spec.package
        )));
    }
    for capability in spec.capabilities {
        let Some(entry_capability) = entry
            .capabilities
            .iter()
            .find(|candidate| candidate.name == capability.name)
        else {
            return Err(ContractError::new(format!(
                "{} missing capability {}",
                spec.package, capability.name
            )));
        };
        if entry_capability.lifetime != capability.lifetime {
            return Err(ContractError::new(format!(
                "{} capability lifetime mismatch",
                spec.package
            )));
        }
        if entry_capability.rights != rights_vec(capability) {
            return Err(ContractError::new(format!(
                "{} capability rights mismatch",
                spec.package
            )));
        }
    }
    Ok(())
}

fn rights_vec(capability: &CapabilitySpec) -> Vec<String> {
    capability
        .rights
        .iter()
        .map(|right| (*right).to_owned())
        .collect()
}
