use std::error::Error;
use std::fmt;

use artifact_manifest::{
    ArtifactBundleManifest, CapabilityManifest, MigrationPackageManifest, ModuleArtifactManifest,
    ResourceLimitsManifest, SupervisorContractManifest,
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

pub const RUNTIME_MODE_RESEARCH: &str = "research";
pub const RUNTIME_MODE_PRODUCTION: &str = "production";
pub const RUNTIME_MODE_REPLAY: &str = "replay";

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
    pub runtime_executor_abi: String,
    pub modules: Vec<ValidatedArtifactEntry>,
}

impl ValidatedArtifactPlan {
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn capability_count(&self) -> usize {
        self.modules
            .iter()
            .map(|entry| entry.capabilities.len())
            .sum()
    }

    pub fn expected_export_count(&self) -> usize {
        self.modules
            .iter()
            .map(|entry| entry.expected_exports.len())
            .sum()
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
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    pub expected_exports: Vec<String>,
    pub capabilities: Vec<CapabilityManifest>,
    pub abi_fingerprint: String,
    pub service_dependencies: Vec<String>,
    pub resource_limits: ResourceLimitsManifest,
    pub signature_scheme: String,
    pub signer: String,
    pub manifest_binding_hash: String,
}

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
    validate_runtime_mode(&manifest.runtime_mode)?;
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
    for spec in SUPERVISOR_WASM_MODULES {
        let entry = manifest_entry_for_spec(manifest, spec)?;
        validate_manifest_entry(spec, entry)?;
    }
    Ok(())
}

pub fn build_validated_artifact_plan(
    manifest: &ArtifactBundleManifest,
) -> ContractResult<ValidatedArtifactPlan> {
    validate_artifact_manifest(manifest)?;
    let modules = SUPERVISOR_WASM_MODULES
        .iter()
        .map(|spec| {
            let entry = manifest_entry_for_spec(manifest, spec)?;
            Ok(ValidatedArtifactEntry {
                package: entry.package.clone(),
                artifact_name: entry.artifact_name.clone(),
                role: entry.role.clone(),
                fault_policy: entry.fault_policy.clone(),
                wasm_path: entry.wasm_path.clone(),
                cwasm_path: entry.cwasm_path.clone(),
                wasm_sha256: entry.wasm_sha256.clone(),
                cwasm_sha256: entry.cwasm_sha256.clone(),
                expected_exports: entry.expected_exports.clone(),
                capabilities: entry.capabilities.clone(),
                abi_fingerprint: entry.abi_fingerprint.clone(),
                service_dependencies: entry.service_dependencies.clone(),
                resource_limits: entry.resource_limits.clone(),
                signature_scheme: entry.signature.scheme.clone(),
                signer: entry.signature.signer.clone(),
                manifest_binding_hash: entry.signature.manifest_binding_hash.clone(),
            })
        })
        .collect::<ContractResult<Vec<_>>>()?;

    Ok(ValidatedArtifactPlan {
        artifact_profile: manifest.artifact_profile.clone(),
        runtime_mode: normalized_runtime_mode(&manifest.runtime_mode).to_owned(),
        contract_version: manifest.contract.contract_version.clone(),
        supervisor_world: manifest.contract.supervisor_world.clone(),
        target_arch: manifest.target.arch.clone(),
        compiler_engine: manifest.compiler.engine.clone(),
        compiler_execution_mode: manifest.compiler.execution_mode.clone(),
        artifact_format: manifest.compiler.artifact_format.clone(),
        runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
        modules,
    })
}

pub fn manifest_entry_for_package<'a>(
    manifest: &'a ArtifactBundleManifest,
    package: &str,
) -> ContractResult<&'a ModuleArtifactManifest> {
    manifest
        .modules
        .iter()
        .find(|entry| entry.package == package)
        .ok_or_else(|| ContractError::new(format!("manifest is missing {package}")))
}

pub fn normalized_runtime_mode(mode: &str) -> &'static str {
    if mode.is_empty() {
        RUNTIME_MODE_RESEARCH
    } else if mode == RUNTIME_MODE_PRODUCTION {
        RUNTIME_MODE_PRODUCTION
    } else if mode == RUNTIME_MODE_REPLAY {
        RUNTIME_MODE_REPLAY
    } else {
        RUNTIME_MODE_RESEARCH
    }
}

fn manifest_entry_for_spec<'a>(
    manifest: &'a ArtifactBundleManifest,
    spec: &WasmModuleSpec,
) -> ContractResult<&'a ModuleArtifactManifest> {
    manifest_entry_for_package(manifest, spec.package)
}

fn validate_runtime_mode(mode: &str) -> ContractResult<()> {
    if mode.is_empty()
        || mode == RUNTIME_MODE_RESEARCH
        || mode == RUNTIME_MODE_PRODUCTION
        || mode == RUNTIME_MODE_REPLAY
    {
        return Ok(());
    }
    Err(ContractError::new("unsupported runtime mode"))
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
    if package.semantic.artifact_verification_count != 0
        && package.semantic.artifact_verification_count != manifest.modules.len()
    {
        return Err(ContractError::new(
            "package artifact verification count does not match manifest",
        ));
    }
    if package.semantic.store_activation_count != 0
        && package.semantic.store_activation_count != manifest.modules.len()
    {
        return Err(ContractError::new(
            "package store activation count does not match manifest",
        ));
    }
    Ok(())
}

pub fn validate_replay_quiescent(package: &MigrationPackageManifest) -> ContractResult<()> {
    validate_migration_package(package)?;
    if package.substrate_boundary.pending_dma_completions != 0
        || package.substrate_boundary.pending_network_inputs != 0
        || package.substrate_boundary.active_dmw_lease_count != 0
        || package.substrate_boundary.active_mmio_authority_count != 0
        || package.substrate_boundary.active_dma_authority_count != 0
        || package.substrate_boundary.active_irq_authority_count != 0
        || package
            .substrate_boundary
            .active_packet_device_authority_count
            != 0
        || package
            .substrate_boundary
            .active_virtio_queue_authority_count
            != 0
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
    if roots.boundary_roots.len() != package.semantic.boundary_count {
        return Err(ContractError::new("boundary root/count mismatch"));
    }
    if roots.artifact_verification_roots.len() != package.semantic.artifact_verification_count {
        return Err(ContractError::new(
            "artifact verification root/count mismatch",
        ));
    }
    if roots.store_activation_roots.len() != package.semantic.store_activation_count {
        return Err(ContractError::new("store activation root/count mismatch"));
    }
    if roots.executor_transition_roots.len() != package.semantic.executor_transition_count {
        return Err(ContractError::new(
            "executor transition root/count mismatch",
        ));
    }
    if roots.target_artifact_roots.len() != package.semantic.target_artifact_count
        || package.semantic.target_artifacts.len() != package.semantic.target_artifact_count
    {
        return Err(ContractError::new("target artifact root/count mismatch"));
    }
    if roots.code_object_roots.len() != package.semantic.code_object_count
        || package.semantic.code_objects.len() != package.semantic.code_object_count
    {
        return Err(ContractError::new("code object root/count mismatch"));
    }
    if package.semantic.store_records.len() != package.semantic.store_record_count {
        return Err(ContractError::new("store record count mismatch"));
    }
    if roots.target_store_record_roots.len() != package.semantic.store_record_count {
        return Err(ContractError::new(
            "target store record root/count mismatch",
        ));
    }
    if package.semantic.capability_records.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("capability record count mismatch"));
    }
    if roots.target_capability_record_roots.len() != package.semantic.capability_record_count {
        return Err(ContractError::new(
            "target capability record root/count mismatch",
        ));
    }
    if roots.activation_record_roots.len() != package.semantic.activation_record_count
        || package.semantic.activation_records.len() != package.semantic.activation_record_count
    {
        return Err(ContractError::new("activation record root/count mismatch"));
    }
    if roots.trap_roots.len() != package.semantic.trap_record_count
        || package.semantic.trap_records.len() != package.semantic.trap_record_count
    {
        return Err(ContractError::new("trap record root/count mismatch"));
    }
    if roots.hostcall_trace_roots.len() != package.semantic.hostcall_trace_count
        || package.semantic.hostcall_trace.len() != package.semantic.hostcall_trace_count
    {
        return Err(ContractError::new("hostcall trace root/count mismatch"));
    }
    if roots.migration_object_roots.len() != package.semantic.migration_object_count
        || package.semantic.migration_objects.len() != package.semantic.migration_object_count
    {
        return Err(ContractError::new("migration object root/count mismatch"));
    }
    if roots.cleanup_roots.len() != package.semantic.cleanup_transaction_count
        || package.semantic.cleanup_transactions.len() != package.semantic.cleanup_transaction_count
    {
        return Err(ContractError::new(
            "cleanup transaction root/count mismatch",
        ));
    }
    if roots.memory_policy_roots.len() != package.semantic.memory_policy_count
        || package.semantic.memory_policies.len() != package.semantic.memory_policy_count
    {
        return Err(ContractError::new("memory policy root/count mismatch"));
    }
    if package.semantic.snapshot_validation.violations.len()
        != package.semantic.snapshot_validation_violation_count
    {
        return Err(ContractError::new(
            "snapshot validation violation count mismatch",
        ));
    }
    if package.semantic.replay_validation.violations.len()
        != package.semantic.replay_validation_violation_count
    {
        return Err(ContractError::new(
            "replay validation violation count mismatch",
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_manifest::{CompilerManifest, ExternManifest, SignatureManifest, TargetManifest};

    fn valid_manifest() -> ArtifactBundleManifest {
        let modules = SUPERVISOR_WASM_MODULES
            .iter()
            .map(|spec| {
                let wasm_sha256 = format!("{}-wasm", spec.package);
                let cwasm_sha256 = format!("{}-cwasm", spec.package);
                let abi_fingerprint = module_abi_fingerprint(spec);
                let manifest_binding_hash =
                    manifest_binding_hash(spec, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);
                ModuleArtifactManifest {
                    package: spec.package.to_owned(),
                    artifact_name: spec.artifact_name.to_owned(),
                    role: spec.role.as_str().to_owned(),
                    fault_policy: spec.fault_policy.as_str().to_owned(),
                    wasm_path: format!("target/test/{}.wasm", spec.package),
                    cwasm_path: format!("target/test/{}.cwasm", spec.package),
                    wasm_sha256,
                    cwasm_sha256: cwasm_sha256.clone(),
                    expected_exports: spec
                        .expected_exports
                        .iter()
                        .map(|export| (*export).to_owned())
                        .collect(),
                    exports: spec
                        .expected_exports
                        .iter()
                        .map(|export| ExternManifest {
                            name: (*export).to_owned(),
                            kind: if *export == "memory" {
                                "memory"
                            } else {
                                "func"
                            }
                            .to_owned(),
                        })
                        .collect(),
                    imports: Vec::new(),
                    capabilities: spec
                        .capabilities
                        .iter()
                        .map(|capability| CapabilityManifest {
                            name: capability.name.to_owned(),
                            rights: capability
                                .rights
                                .iter()
                                .map(|right| (*right).to_owned())
                                .collect(),
                            lifetime: capability.lifetime.to_owned(),
                        })
                        .collect(),
                    abi_fingerprint,
                    service_dependencies: module_dependencies(spec)
                        .iter()
                        .map(|dependency| (*dependency).to_owned())
                        .collect(),
                    resource_limits: ResourceLimitsManifest {
                        max_memory_pages: 16,
                        max_table_elements: 0,
                        max_hostcalls_per_activation: 64,
                    },
                    signature: SignatureManifest {
                        scheme: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
                        artifact_hash: cwasm_sha256,
                        manifest_binding_hash,
                        signer: "test-signer".to_owned(),
                        public_key_hint: "test-key".to_owned(),
                        signature: "test-signature".to_owned(),
                    },
                }
            })
            .collect();

        ArtifactBundleManifest {
            schema_version: 1,
            artifact_profile: "host-validation".to_owned(),
            runtime_mode: RUNTIME_MODE_RESEARCH.to_owned(),
            contract: expected_supervisor_contract(),
            target: TargetManifest {
                arch: "x86_64".to_owned(),
                machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
                supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
                wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
                memory64: false,
                multi_memory: false,
                dmw_layout: DMW_LAYOUT.to_owned(),
                linux_abi_profile: LINUX_ABI_PROFILE.to_owned(),
                artifact_signature_profile: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
                network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
            },
            compiler: CompilerManifest {
                engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
                engine_version: "test".to_owned(),
                execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
                artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
                runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
            },
            modules,
        }
    }

    #[test]
    fn validated_plan_preserves_manifest_order_and_totals() {
        let manifest = valid_manifest();
        let plan = build_validated_artifact_plan(&manifest).expect("valid plan");

        assert_eq!(plan.module_count(), SUPERVISOR_WASM_MODULES.len());
        assert_eq!(plan.runtime_mode, RUNTIME_MODE_RESEARCH);
        assert_eq!(plan.modules[0].package, SUPERVISOR_WASM_MODULES[0].package);
        assert_eq!(
            plan.capability_count(),
            SUPERVISOR_WASM_MODULES
                .iter()
                .map(|spec| spec.capabilities.len())
                .sum()
        );
    }

    #[test]
    fn manifest_validation_rejects_bad_entry_binding() {
        let mut manifest = valid_manifest();
        manifest.modules[0].signature.manifest_binding_hash = "stale-binding".to_owned();

        let err = validate_artifact_manifest(&manifest).expect_err("bad binding must fail");
        assert!(err.to_string().contains("manifest binding hash mismatch"));
    }

    #[test]
    fn manifest_validation_rejects_unknown_runtime_mode() {
        let mut manifest = valid_manifest();
        manifest.runtime_mode = "max-debug-production-replay".to_owned();

        assert_eq!(
            validate_artifact_manifest(&manifest)
                .unwrap_err()
                .to_string(),
            "unsupported runtime mode"
        );
    }
}
