use artifact_manifest::{
    ArtifactBundleManifest, MigrationPackageManifest, ModuleArtifactManifest,
    SupervisorContractManifest,
};
use contract_core::*;
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use sha2::{Digest, Sha256};
use substrate_api::{
    AuthorityMismatch, AuthorityRequirementSet, SubstrateAuthorityRequirements,
    SubstrateCapabilitySet, SubstrateCompatibilityReport, SubstrateProfile,
};
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

pub fn host_validation_interface_capabilities() -> InterfaceHostCapabilitySet {
    let mut capabilities = InterfaceHostCapabilitySet::empty();
    for module in SUPERVISOR_WASM_MODULES {
        let interfaces = module_interface_spec(module);
        for world in interfaces.required_wasi_worlds {
            push_unique(&mut capabilities.wasi_worlds, world);
        }
        for world in interfaces.optional_wasi_worlds {
            push_unique(&mut capabilities.wasi_worlds, world);
        }
        for world in interfaces.custom_wit_worlds {
            push_unique(&mut capabilities.custom_wit_worlds, world);
        }
    }
    capabilities
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
    if normalized_target_artifact_format(&manifest.compiler) != TARGET_ARTIFACT_FORMAT_V1 {
        return Err(ContractError::new("manifest target artifact format mismatch"));
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
        return Err(ContractError::new("manifest artifact signature profile mismatch"));
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
                target_artifact_path: entry.target_artifact_path.clone(),
                wasm_sha256: entry.wasm_sha256.clone(),
                cwasm_sha256: entry.cwasm_sha256.clone(),
                target_artifact_sha256: entry.target_artifact_sha256.clone(),
                code_payload_format: normalized_code_payload_format(entry).to_owned(),
                expected_exports: spec
                    .expected_exports
                    .iter()
                    .map(|export| (*export).to_owned())
                    .collect(),
                capabilities: entry.capabilities.clone(),
                abi_fingerprint: entry.abi_fingerprint.clone(),
                service_dependencies: entry.service_dependencies.clone(),
                resource_limits: entry.resource_limits.clone(),
                interfaces: entry.interfaces.clone(),
                signature_scheme: entry.signature.scheme.clone(),
                signer: entry.signature.signer.clone(),
                manifest_binding_hash: entry.signature.manifest_binding_hash.clone(),
                hash_status: ARTIFACT_HASH_STATUS_MANIFEST_BOUND.to_owned(),
                signature_status: ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED.to_owned(),
                signature_verified: ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
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
        target_artifact_format: normalized_target_artifact_format(&manifest.compiler).to_owned(),
        runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
        modules,
    })
}

pub fn check_artifact_manifest_substrate_compatibility(
    manifest: &ArtifactBundleManifest,
    capabilities: SubstrateCapabilitySet,
) -> ContractResult<ArtifactSubstrateCompatibilityReport> {
    let plan = build_validated_artifact_plan(manifest)?;
    let modules = plan
        .modules
        .iter()
        .map(|module| check_module_substrate_compatibility(module, capabilities))
        .collect::<ContractResult<Vec<_>>>()?;
    let ok = modules.iter().all(|module| module.ok);
    Ok(ArtifactSubstrateCompatibilityReport {
        artifact_profile: plan.artifact_profile,
        module_count: modules.len(),
        ok,
        modules,
    })
}

pub fn check_artifact_manifest_interface_compatibility(
    manifest: &ArtifactBundleManifest,
    capabilities: &InterfaceHostCapabilitySet,
) -> ContractResult<ArtifactInterfaceCompatibilityReport> {
    let plan = build_validated_artifact_plan(manifest)?;
    let modules = plan
        .modules
        .iter()
        .map(|module| check_module_interface_compatibility(module, capabilities))
        .collect::<Vec<_>>();
    let ok = modules.iter().all(|module| module.ok);
    Ok(ArtifactInterfaceCompatibilityReport {
        artifact_profile: plan.artifact_profile,
        module_count: modules.len(),
        ok,
        modules,
    })
}

pub fn check_module_interface_compatibility(
    module: &ValidatedArtifactEntry,
    capabilities: &InterfaceHostCapabilitySet,
) -> ModuleInterfaceCompatibilityReport {
    let missing_required_wasi_worlds =
        missing_interfaces(&module.interfaces.required_wasi_worlds, &capabilities.wasi_worlds);
    let degraded_optional_wasi_worlds =
        missing_interfaces(&module.interfaces.optional_wasi_worlds, &capabilities.wasi_worlds);
    let missing_custom_wit_worlds =
        missing_interfaces(&module.interfaces.custom_wit_worlds, &capabilities.custom_wit_worlds);
    let version_mismatches = interface_version_mismatches(module, capabilities);
    let ok = missing_required_wasi_worlds.is_empty()
        && missing_custom_wit_worlds.is_empty()
        && version_mismatches.is_empty();
    ModuleInterfaceCompatibilityReport {
        package: module.package.clone(),
        ok,
        missing_required_wasi_worlds,
        degraded_optional_wasi_worlds,
        missing_custom_wit_worlds,
        version_mismatches,
    }
}

pub fn check_module_substrate_compatibility(
    module: &ValidatedArtifactEntry,
    capabilities: SubstrateCapabilitySet,
) -> ContractResult<ModuleSubstrateCompatibilityReport> {
    let Some(profile) = SubstrateProfile::parse(&module.interfaces.substrate_profile_required)
    else {
        return Err(ContractError::new(format!(
            "{} unknown substrate profile {}",
            module.package, module.interfaces.substrate_profile_required
        )));
    };
    let profile_report = capabilities.check_profile(profile);
    let required = parse_authority_requirements(
        &module.package,
        "required",
        &module.interfaces.substrate_authorities.required,
    )?;
    let optional = parse_authority_requirements(
        &module.package,
        "optional",
        &module.interfaces.substrate_authorities.optional,
    )?;
    let authority_report = SubstrateAuthorityRequirements {
        required,
        optional,
        forbidden: AuthorityRequirementSet::default(),
    }
    .check(capabilities);
    let forbidden_requested = forbidden_requested_by_module(module);
    let missing_required = combine_missing(&profile_report, &authority_report);
    let degraded_optional =
        compatibility_items_from_mismatches(&authority_report.degraded_optional);
    let profile_ok = profile_report.ok;
    let authority_ok = authority_report.ok;
    Ok(ModuleSubstrateCompatibilityReport {
        package: module.package.clone(),
        substrate_profile_required: module.interfaces.substrate_profile_required.clone(),
        ok: profile_ok && authority_ok && forbidden_requested.is_empty(),
        profile_ok,
        authority_ok,
        missing_required,
        degraded_optional,
        forbidden_requested,
        forbidden_authorities: module.interfaces.substrate_authorities.forbidden.clone(),
    })
}

fn parse_authority_requirements(
    package: &str,
    list_name: &str,
    tokens: &[String],
) -> ContractResult<AuthorityRequirementSet> {
    AuthorityRequirementSet::from_tokens(tokens.iter().map(String::as_str)).map_err(|err| {
        ContractError::new(format!(
            "{package} has invalid {list_name} substrate authority token `{}`: {}",
            err.token, err.reason
        ))
    })
}

pub(crate) fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn missing_interfaces(required: &[String], available: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !available.iter().any(|available| available == *required))
        .cloned()
        .collect()
}

fn interface_version_mismatches(
    module: &ValidatedArtifactEntry,
    capabilities: &InterfaceHostCapabilitySet,
) -> Vec<InterfaceVersionMismatch> {
    let interfaces = &module.interfaces;
    let mut mismatches = Vec::new();
    push_version_mismatch(
        &mut mismatches,
        "component_model_version",
        &interfaces.component_model_version,
        &capabilities.component_model_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "wasi_profile",
        &interfaces.wasi_profile,
        &capabilities.wasi_profile,
    );
    push_version_mismatch(
        &mut mismatches,
        "hostcall_abi_version",
        &interfaces.hostcall_abi_version,
        &capabilities.hostcall_abi_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "capability_abi_version",
        &interfaces.capability_abi_version,
        &capabilities.capability_abi_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "semantic_contract_version",
        &interfaces.semantic_contract_version,
        &capabilities.semantic_contract_version,
    );
    mismatches
}

fn push_version_mismatch(
    mismatches: &mut Vec<InterfaceVersionMismatch>,
    field: &str,
    expected: &str,
    actual: &str,
) {
    if expected != actual {
        mismatches.push(InterfaceVersionMismatch {
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
}

fn forbidden_requested_by_module(module: &ValidatedArtifactEntry) -> Vec<String> {
    module
        .interfaces
        .substrate_authorities
        .forbidden
        .iter()
        .filter(|forbidden| {
            module
                .interfaces
                .substrate_authorities
                .required
                .iter()
                .any(|required| required == *forbidden)
                || module
                    .interfaces
                    .substrate_authorities
                    .optional
                    .iter()
                    .any(|optional| optional == *forbidden)
                || module.capabilities.iter().any(|capability| {
                    capability_matches_forbidden_authority(&capability.name, forbidden)
                })
        })
        .cloned()
        .collect()
}

fn capability_matches_forbidden_authority(capability: &str, forbidden: &str) -> bool {
    match forbidden {
        "direct-dma" => capability == "direct-dma" || capability.starts_with("dma."),
        "raw-mmio" => capability == "raw-mmio" || capability.starts_with("mmio."),
        "raw-irq" => capability == "raw-irq" || capability.starts_with("irq."),
        other => capability == other,
    }
}

fn combine_missing(
    profile_report: &SubstrateCompatibilityReport,
    authority_report: &SubstrateCompatibilityReport,
) -> Vec<SubstrateCompatibilityItem> {
    let mut out = compatibility_items_from_mismatches(&profile_report.missing_required);
    for item in compatibility_items_from_mismatches(&authority_report.missing_required) {
        if !out.iter().any(|existing| {
            existing.authority == item.authority
                && existing.expected == item.expected
                && existing.actual == item.actual
        }) {
            out.push(item);
        }
    }
    out
}

fn compatibility_items_from_mismatches(
    items: &[AuthorityMismatch],
) -> Vec<SubstrateCompatibilityItem> {
    items
        .iter()
        .map(|item| SubstrateCompatibilityItem {
            authority: item.authority.to_owned(),
            expected: item.required.to_owned(),
            actual: item.actual.to_owned(),
        })
        .collect()
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

pub fn normalized_target_artifact_format(compiler: &artifact_manifest::CompilerManifest) -> &str {
    if compiler.target_artifact_format.is_empty() {
        TARGET_ARTIFACT_FORMAT_V1
    } else {
        &compiler.target_artifact_format
    }
}

pub fn normalized_code_payload_format(entry: &ModuleArtifactManifest) -> &str {
    if entry.code_payload_format.is_empty() {
        CODE_PAYLOAD_FORMAT_CWASM
    } else {
        &entry.code_payload_format
    }
}

pub fn canonical_wasmtime_config_fingerprint(host_arch: &str, target_arch: &str) -> String {
    let canonical = format!(
        "engine={};engine_version={};host_arch={};target_arch={};strategy={};wasm_feature_profile={};memory64=false;multi_memory=false;component_model=false",
        SUPERVISOR_COMPILER_ENGINE,
        WASMTIME_CRATE_VERSION,
        host_arch,
        target_arch,
        WASMTIME_COMPILATION_STRATEGY,
        WASM_FEATURE_PROFILE,
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
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
        return Err(ContractError::new("supervisor catalog fingerprint mismatch"));
    }
    if contract.package_set_fingerprint != expected.package_set_fingerprint {
        return Err(ContractError::new("supervisor package set fingerprint mismatch"));
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
        let count = manifest.modules.iter().filter(|entry| entry.package == spec.package).count();
        if count != 1 {
            return Err(ContractError::new(format!(
                "manifest has invalid module count for {}",
                spec.package
            )));
        }
    }
    for entry in &manifest.modules {
        if !SUPERVISOR_WASM_MODULES.iter().any(|spec| spec.package == entry.package) {
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
        return Err(ContractError::new(format!("{} artifact name mismatch", spec.package)));
    }
    if entry.role != spec.role.as_str() {
        return Err(ContractError::new(format!("{} role mismatch", spec.package)));
    }
    if entry.fault_policy != spec.fault_policy.as_str() {
        return Err(ContractError::new(format!("{} fault policy mismatch", spec.package)));
    }
    let expected_dependencies = module_dependencies(spec);
    if entry.service_dependencies.len() != expected_dependencies.len()
        || expected_dependencies
            .iter()
            .any(|dependency| !entry.service_dependencies.iter().any(|entry| entry == dependency))
    {
        return Err(ContractError::new(format!("{} service dependency mismatch", spec.package)));
    }
    if entry.signature.scheme != ARTIFACT_SIGNATURE_PROFILE {
        return Err(ContractError::new(format!("{} signature scheme mismatch", spec.package)));
    }
    if entry.abi_fingerprint != module_abi_fingerprint(spec) {
        return Err(ContractError::new(format!("{} ABI fingerprint mismatch", spec.package)));
    }
    if normalized_code_payload_format(entry) != CODE_PAYLOAD_FORMAT_CWASM {
        return Err(ContractError::new(format!("{} code payload format mismatch", spec.package)));
    }
    if entry.target_artifact_path.is_empty() || !entry.target_artifact_path.ends_with(".tart") {
        return Err(ContractError::new(format!(
            "{} target artifact path is not a TargetArtifactImage",
            spec.package
        )));
    }
    if entry.target_artifact_sha256.is_empty() {
        return Err(ContractError::new(format!("{} target artifact hash is empty", spec.package)));
    }
    if entry.signature.artifact_hash != entry.target_artifact_sha256 {
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
        return Err(ContractError::new(format!("{} manifest binding hash mismatch", spec.package)));
    }
    if !entry.cwasm_path.ends_with(".cwasm") {
        return Err(ContractError::new(format!(
            "{} code payload path is not a cwasm module",
            spec.package
        )));
    }
    validate_expected_exports(spec, entry)?;
    validate_exports(spec, entry)?;
    validate_resource_limits(spec, entry)?;
    validate_capabilities(spec, entry)?;
    validate_interface_requirements(spec, entry)?;
    Ok(())
}

fn validate_expected_exports(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.expected_exports.len() == spec.expected_exports.len()
        && spec
            .expected_exports
            .iter()
            .zip(entry.expected_exports.iter())
            .all(|(expected, actual)| actual == expected)
    {
        return Ok(());
    }
    Err(ContractError::new(format!("{} expected exports mismatch", spec.package)))
}

fn validate_exports(spec: &WasmModuleSpec, entry: &ModuleArtifactManifest) -> ContractResult<()> {
    for export in &entry.exports {
        if entry.exports.iter().filter(|candidate| candidate.name == export.name).count() != 1 {
            return Err(ContractError::new(format!(
                "{} duplicate export {}",
                spec.package, export.name
            )));
        }
        if !spec.expected_exports.iter().any(|expected| *expected == export.name)
            && !is_allowed_compiler_aux_export(&export.name)
        {
            return Err(ContractError::new(format!(
                "{} unexpected export {}",
                spec.package, export.name
            )));
        }
    }
    for expected in spec.expected_exports {
        let Some(export) = entry.exports.iter().find(|candidate| candidate.name == *expected)
        else {
            return Err(ContractError::new(format!(
                "{} missing export {}",
                spec.package, expected
            )));
        };
        let expected_kind = if *expected == "memory" { "memory" } else { "func" };
        if export.kind != expected_kind {
            return Err(ContractError::new(format!(
                "{} export {} kind mismatch",
                spec.package, expected
            )));
        }
    }
    Ok(())
}

fn is_allowed_compiler_aux_export(name: &str) -> bool {
    matches!(name, "__data_end" | "__heap_base")
}

fn validate_resource_limits(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.resource_limits.max_memory_pages != DEFAULT_MAX_MEMORY_PAGES
        || entry.resource_limits.max_table_elements != DEFAULT_MAX_TABLE_ELEMENTS
        || entry.resource_limits.max_hostcalls_per_activation
            != DEFAULT_MAX_HOSTCALLS_PER_ACTIVATION
    {
        return Err(ContractError::new(format!("{} resource limits mismatch", spec.package)));
    }
    Ok(())
}

fn validate_interface_requirements(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    let expected = module_interface_spec(spec);
    let interfaces = &entry.interfaces;
    validate_string_list(
        spec,
        "required WASI worlds",
        &interfaces.required_wasi_worlds,
        expected.required_wasi_worlds,
    )?;
    validate_string_list(
        spec,
        "optional WASI worlds",
        &interfaces.optional_wasi_worlds,
        expected.optional_wasi_worlds,
    )?;
    validate_string_list(
        spec,
        "custom WIT worlds",
        &interfaces.custom_wit_worlds,
        expected.custom_wit_worlds,
    )?;
    validate_string_list(
        spec,
        "WIT package versions",
        &interfaces.wit_package_versions,
        expected.wit_package_versions,
    )?;
    validate_string_list(
        spec,
        "required substrate authorities",
        &interfaces.substrate_authorities.required,
        expected.substrate_required,
    )?;
    validate_string_list(
        spec,
        "optional substrate authorities",
        &interfaces.substrate_authorities.optional,
        expected.substrate_optional,
    )?;
    validate_string_list(
        spec,
        "forbidden substrate authorities",
        &interfaces.substrate_authorities.forbidden,
        expected.substrate_forbidden,
    )?;
    validate_interface_field(
        spec,
        "component model version",
        &interfaces.component_model_version,
        expected.component_model_version,
    )?;
    validate_interface_field(
        spec,
        "WASI profile",
        &interfaces.wasi_profile,
        expected.wasi_profile,
    )?;
    validate_interface_field(
        spec,
        "hostcall ABI version",
        &interfaces.hostcall_abi_version,
        expected.hostcall_abi_version,
    )?;
    validate_interface_field(
        spec,
        "capability ABI version",
        &interfaces.capability_abi_version,
        expected.capability_abi_version,
    )?;
    validate_interface_field(
        spec,
        "semantic contract version",
        &interfaces.semantic_contract_version,
        expected.semantic_contract_version,
    )?;
    validate_interface_field(
        spec,
        "substrate profile",
        &interfaces.substrate_profile_required,
        expected.substrate_profile_required,
    )?;
    if interfaces.component_model_version != COMPONENT_MODEL_VERSION
        || interfaces.wasi_profile != WASI_PROFILE_NONE
        || interfaces.hostcall_abi_version != HOSTCALL_ABI_VERSION
        || interfaces.capability_abi_version != CAPABILITY_ABI_VERSION
        || interfaces.semantic_contract_version != SEMANTIC_CONTRACT_SCHEMA_VERSION
        || !interfaces.wit_package_versions.iter().any(|entry| entry == WIT_PACKAGE_VERSION)
    {
        return Err(ContractError::new(format!(
            "{} interface ABI boundary mismatch",
            spec.package
        )));
    }
    Ok(())
}

fn validate_interface_field(
    spec: &WasmModuleSpec,
    label: &str,
    actual: &str,
    expected: &str,
) -> ContractResult<()> {
    if actual == expected {
        return Ok(());
    }
    Err(ContractError::new(format!("{} {label} mismatch", spec.package)))
}

fn validate_string_list(
    spec: &WasmModuleSpec,
    label: &str,
    actual: &[String],
    expected: &[&str],
) -> ContractResult<()> {
    if actual.len() == expected.len()
        && expected.iter().zip(actual.iter()).all(|(expected, actual)| actual == expected)
    {
        return Ok(());
    }
    Err(ContractError::new(format!("{} {label} mismatch", spec.package)))
}

pub fn validate_migration_package(package: &MigrationPackageManifest) -> ContractResult<()> {
    if package.schema_version != 1 {
        return Err(ContractError::new("unsupported semantic package schema version"));
    }
    if package.package_format != "vmos-semantic-package-v1" {
        return Err(ContractError::new("unsupported semantic package format"));
    }
    if package.guest.canonical_isa != "riscv64" {
        return Err(ContractError::new("unsupported canonical guest ISA"));
    }
    if package.semantic.active_transaction_count != 0 {
        return Err(ContractError::new("package contains active semantic transactions"));
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
            return Err(ContractError::new("package contains an invalid logical capability"));
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
    let plan = build_validated_artifact_plan(manifest)?;
    validate_migration_package(package)?;
    let required = &package.required_artifact_profile;
    if required.target_arch != "target-native" && required.target_arch != manifest.target.arch {
        return Err(ContractError::new("package target arch is incompatible with manifest"));
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
        return Err(ContractError::new("package compiler/artifact mode mismatch"));
    }
    if package.semantic.artifact_verification_count != manifest.modules.len() {
        return Err(ContractError::new(
            "package artifact verification count does not match manifest",
        ));
    }
    if package.semantic.store_activation_count != manifest.modules.len() {
        return Err(ContractError::new("package store activation count does not match manifest"));
    }
    if package.semantic.target_artifact_count != manifest.modules.len() {
        return Err(ContractError::new("package target artifact count does not match manifest"));
    }
    for module in &plan.modules {
        let Some(artifact) = package.semantic.target_artifacts.iter().find(|artifact| {
            artifact.package == module.package && artifact.artifact_name == module.artifact_name
        }) else {
            return Err(ContractError::new(format!(
                "{} target artifact evidence missing",
                module.package
            )));
        };
        if artifact.target_profile != plan.artifact_profile {
            return Err(ContractError::new(format!(
                "{} target profile evidence mismatch",
                module.package
            )));
        }
        if artifact.artifact_hash != module.target_artifact_sha256
            || artifact.code_hash != module.cwasm_sha256
            || artifact.abi_fingerprint != module.abi_fingerprint
            || artifact.manifest_binding_hash != module.manifest_binding_hash
        {
            return Err(ContractError::new(format!(
                "{} artifact hash evidence mismatch",
                module.package
            )));
        }
        if artifact.hash_status != module.hash_status
            || artifact.signature_scheme != module.signature_scheme
            || artifact.signature_status != module.signature_status
            || artifact.signature_verified != module.signature_verified
            || artifact.signer != module.signer
        {
            return Err(ContractError::new(format!(
                "{} artifact policy evidence mismatch",
                module.package
            )));
        }
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
        || package.substrate_boundary.active_packet_device_authority_count != 0
        || package.substrate_boundary.active_virtio_queue_authority_count != 0
    {
        return Err(ContractError::new("package is not replay-quiescent"));
    }
    if package.substrate_boundary.background_copy_pages != 0 {
        return Err(ContractError::new("package contains unfinished background COW copies"));
    }
    Ok(())
}

pub fn validate_semantic_roots(package: &MigrationPackageManifest) -> ContractResult<()> {
    let roots = &package.semantic.roots;
    if roots.hart_roots.len() != package.semantic.hart_count
        || package.semantic.hart_records.len() != package.semantic.hart_count
    {
        return Err(ContractError::new("hart root/count mismatch"));
    }
    if roots.task_roots.len() != package.semantic.task_count {
        return Err(ContractError::new("task root/count mismatch"));
    }
    if package.semantic.task_records.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record count mismatch"));
    }
    if roots.task_record_roots.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record root/count mismatch"));
    }
    if roots.runtime_activation_roots.len() != package.semantic.runtime_activation_count
        || package.semantic.runtime_activation_records.len()
            != package.semantic.runtime_activation_count
    {
        return Err(ContractError::new("runtime activation root/count mismatch"));
    }
    if roots.runnable_queue_roots.len() != package.semantic.runnable_queue_count
        || package.semantic.runnable_queues.len() != package.semantic.runnable_queue_count
    {
        return Err(ContractError::new("runnable queue root/count mismatch"));
    }
    if roots.activation_context_roots.len() != package.semantic.activation_context_count
        || package.semantic.activation_contexts.len() != package.semantic.activation_context_count
    {
        return Err(ContractError::new("activation context root/count mismatch"));
    }
    if roots.saved_context_roots.len() != package.semantic.saved_context_count
        || package.semantic.saved_contexts.len() != package.semantic.saved_context_count
    {
        return Err(ContractError::new("saved context root/count mismatch"));
    }
    if roots.timer_interrupt_roots.len() != package.semantic.timer_interrupt_count
        || package.semantic.timer_interrupts.len() != package.semantic.timer_interrupt_count
    {
        return Err(ContractError::new("timer interrupt root/count mismatch"));
    }
    if roots.ipi_event_roots.len() != package.semantic.ipi_event_count
        || package.semantic.ipi_events.len() != package.semantic.ipi_event_count
    {
        return Err(ContractError::new("ipi event root/count mismatch"));
    }
    if roots.remote_preempt_roots.len() != package.semantic.remote_preempt_count
        || package.semantic.remote_preempts.len() != package.semantic.remote_preempt_count
    {
        return Err(ContractError::new("remote preempt root/count mismatch"));
    }
    if roots.remote_park_roots.len() != package.semantic.remote_park_count
        || package.semantic.remote_parks.len() != package.semantic.remote_park_count
    {
        return Err(ContractError::new("remote park root/count mismatch"));
    }
    if roots.preemption_roots.len() != package.semantic.preemption_count
        || package.semantic.preemptions.len() != package.semantic.preemption_count
    {
        return Err(ContractError::new("preemption root/count mismatch"));
    }
    if roots.scheduler_decision_roots.len() != package.semantic.scheduler_decision_count
        || package.semantic.scheduler_decisions.len() != package.semantic.scheduler_decision_count
    {
        return Err(ContractError::new("scheduler decision root/count mismatch"));
    }
    if roots.cross_hart_scheduler_decision_roots.len()
        != package.semantic.cross_hart_scheduler_decision_count
        || package.semantic.cross_hart_scheduler_decisions.len()
            != package.semantic.cross_hart_scheduler_decision_count
    {
        return Err(ContractError::new("cross-hart scheduler decision root/count mismatch"));
    }
    if roots.activation_migration_roots.len() != package.semantic.activation_migration_count
        || package.semantic.activation_migrations.len()
            != package.semantic.activation_migration_count
    {
        return Err(ContractError::new("activation migration root/count mismatch"));
    }
    if roots.smp_safe_point_roots.len() != package.semantic.smp_safe_point_count
        || package.semantic.smp_safe_points.len() != package.semantic.smp_safe_point_count
    {
        return Err(ContractError::new("smp safe point root/count mismatch"));
    }
    if roots.stop_the_world_rendezvous_roots.len()
        != package.semantic.stop_the_world_rendezvous_count
        || package.semantic.stop_the_world_rendezvous.len()
            != package.semantic.stop_the_world_rendezvous_count
    {
        return Err(ContractError::new("stop-the-world rendezvous root/count mismatch"));
    }
    if roots.smp_code_publish_barrier_roots.len() != package.semantic.smp_code_publish_barrier_count
        || package.semantic.smp_code_publish_barriers.len()
            != package.semantic.smp_code_publish_barrier_count
    {
        return Err(ContractError::new("smp code publish barrier root/count mismatch"));
    }
    if roots.smp_cleanup_quiescence_roots.len() != package.semantic.smp_cleanup_quiescence_count
        || package.semantic.smp_cleanup_quiescence.len()
            != package.semantic.smp_cleanup_quiescence_count
    {
        return Err(ContractError::new("smp cleanup quiescence root/count mismatch"));
    }
    if roots.smp_snapshot_barrier_roots.len() != package.semantic.smp_snapshot_barrier_count
        || package.semantic.smp_snapshot_barriers.len()
            != package.semantic.smp_snapshot_barrier_count
    {
        return Err(ContractError::new("smp snapshot barrier root/count mismatch"));
    }
    if roots.smp_stress_run_roots.len() != package.semantic.smp_stress_run_count
        || package.semantic.smp_stress_runs.len() != package.semantic.smp_stress_run_count
    {
        return Err(ContractError::new("smp stress run root/count mismatch"));
    }
    if roots.smp_scaling_benchmark_roots.len() != package.semantic.smp_scaling_benchmark_count
        || package.semantic.smp_scaling_benchmarks.len()
            != package.semantic.smp_scaling_benchmark_count
    {
        return Err(ContractError::new("smp scaling benchmark root/count mismatch"));
    }
    if roots.integrated_smp_preemption_cleanup_roots.len()
        != package.semantic.integrated_smp_preemption_cleanup_count
        || package.semantic.integrated_smp_preemption_cleanups.len()
            != package.semantic.integrated_smp_preemption_cleanup_count
    {
        return Err(ContractError::new("integrated smp preemption cleanup root/count mismatch"));
    }
    if roots.integrated_smp_network_fault_roots.len()
        != package.semantic.integrated_smp_network_fault_count
        || package.semantic.integrated_smp_network_faults.len()
            != package.semantic.integrated_smp_network_fault_count
    {
        return Err(ContractError::new("integrated smp network fault root/count mismatch"));
    }
    if roots.integrated_disk_preempt_fault_roots.len()
        != package.semantic.integrated_disk_preempt_fault_count
        || package.semantic.integrated_disk_preempt_faults.len()
            != package.semantic.integrated_disk_preempt_fault_count
    {
        return Err(ContractError::new("integrated disk preempt fault root/count mismatch"));
    }
    if roots.integrated_simd_migration_roots.len()
        != package.semantic.integrated_simd_migration_count
        || package.semantic.integrated_simd_migrations.len()
            != package.semantic.integrated_simd_migration_count
    {
        return Err(ContractError::new("integrated simd migration root/count mismatch"));
    }
    if roots.integrated_network_disk_io_roots.len()
        != package.semantic.integrated_network_disk_io_count
        || package.semantic.integrated_network_disk_ios.len()
            != package.semantic.integrated_network_disk_io_count
    {
        return Err(ContractError::new("integrated network disk io root/count mismatch"));
    }
    if roots.integrated_display_scheduler_load_roots.len()
        != package.semantic.integrated_display_scheduler_load_count
        || package.semantic.integrated_display_scheduler_loads.len()
            != package.semantic.integrated_display_scheduler_load_count
    {
        return Err(ContractError::new("integrated display scheduler load root/count mismatch"));
    }
    if roots.integrated_snapshot_io_lease_barrier_roots.len()
        != package.semantic.integrated_snapshot_io_lease_barrier_count
        || package.semantic.integrated_snapshot_io_lease_barriers.len()
            != package.semantic.integrated_snapshot_io_lease_barrier_count
    {
        return Err(ContractError::new("integrated snapshot io lease barrier root/count mismatch"));
    }
    if roots.integrated_code_publish_smp_workload_roots.len()
        != package.semantic.integrated_code_publish_smp_workload_count
        || package.semantic.integrated_code_publish_smp_workloads.len()
            != package.semantic.integrated_code_publish_smp_workload_count
    {
        return Err(ContractError::new("integrated code publish smp workload root/count mismatch"));
    }
    if roots.device_object_roots.len() != package.semantic.device_object_count
        || package.semantic.device_objects.len() != package.semantic.device_object_count
    {
        return Err(ContractError::new("device object root/count mismatch"));
    }
    if roots.queue_object_roots.len() != package.semantic.queue_object_count
        || package.semantic.queue_objects.len() != package.semantic.queue_object_count
    {
        return Err(ContractError::new("queue object root/count mismatch"));
    }
    if roots.descriptor_object_roots.len() != package.semantic.descriptor_object_count
        || package.semantic.descriptor_objects.len() != package.semantic.descriptor_object_count
    {
        return Err(ContractError::new("descriptor object root/count mismatch"));
    }
    if roots.dma_buffer_object_roots.len() != package.semantic.dma_buffer_object_count
        || package.semantic.dma_buffer_objects.len() != package.semantic.dma_buffer_object_count
    {
        return Err(ContractError::new("dma buffer object root/count mismatch"));
    }
    if roots.mmio_region_object_roots.len() != package.semantic.mmio_region_object_count
        || package.semantic.mmio_region_objects.len() != package.semantic.mmio_region_object_count
    {
        return Err(ContractError::new("mmio region object root/count mismatch"));
    }
    if roots.irq_line_object_roots.len() != package.semantic.irq_line_object_count
        || package.semantic.irq_line_objects.len() != package.semantic.irq_line_object_count
    {
        return Err(ContractError::new("irq line object root/count mismatch"));
    }
    if roots.irq_event_roots.len() != package.semantic.irq_event_count
        || package.semantic.irq_events.len() != package.semantic.irq_event_count
    {
        return Err(ContractError::new("irq event root/count mismatch"));
    }
    if roots.device_capability_roots.len() != package.semantic.device_capability_count
        || package.semantic.device_capabilities.len() != package.semantic.device_capability_count
    {
        return Err(ContractError::new("device capability root/count mismatch"));
    }
    if roots.driver_store_binding_roots.len() != package.semantic.driver_store_binding_count
        || package.semantic.driver_store_bindings.len()
            != package.semantic.driver_store_binding_count
    {
        return Err(ContractError::new("driver store binding root/count mismatch"));
    }
    if roots.io_wait_roots.len() != package.semantic.io_wait_count
        || package.semantic.io_waits.len() != package.semantic.io_wait_count
    {
        return Err(ContractError::new("io wait root/count mismatch"));
    }
    if roots.io_cleanup_roots.len() != package.semantic.io_cleanup_count
        || package.semantic.io_cleanups.len() != package.semantic.io_cleanup_count
    {
        return Err(ContractError::new("io cleanup root/count mismatch"));
    }
    if roots.io_fault_injection_roots.len() != package.semantic.io_fault_injection_count
        || package.semantic.io_fault_injections.len() != package.semantic.io_fault_injection_count
    {
        return Err(ContractError::new("io fault injection root/count mismatch"));
    }
    if roots.io_validation_report_roots.len() != package.semantic.io_validation_report_count
        || package.semantic.io_validation_reports.len()
            != package.semantic.io_validation_report_count
    {
        return Err(ContractError::new("io validation report root/count mismatch"));
    }
    if roots.packet_device_object_roots.len() != package.semantic.packet_device_object_count
        || package.semantic.packet_device_objects.len()
            != package.semantic.packet_device_object_count
    {
        return Err(ContractError::new("packet device object root/count mismatch"));
    }
    if roots.packet_buffer_object_roots.len() != package.semantic.packet_buffer_object_count
        || package.semantic.packet_buffer_objects.len()
            != package.semantic.packet_buffer_object_count
    {
        return Err(ContractError::new("packet buffer object root/count mismatch"));
    }
    if roots.packet_queue_object_roots.len() != package.semantic.packet_queue_object_count
        || package.semantic.packet_queue_objects.len() != package.semantic.packet_queue_object_count
    {
        return Err(ContractError::new("packet queue object root/count mismatch"));
    }
    if roots.packet_descriptor_object_roots.len() != package.semantic.packet_descriptor_object_count
        || package.semantic.packet_descriptors.len()
            != package.semantic.packet_descriptor_object_count
    {
        return Err(ContractError::new("packet descriptor object root/count mismatch"));
    }
    if roots.fake_net_backend_object_roots.len() != package.semantic.fake_net_backend_object_count
        || package.semantic.fake_net_backends.len()
            != package.semantic.fake_net_backend_object_count
    {
        return Err(ContractError::new("fake net backend object root/count mismatch"));
    }
    if roots.virtio_net_backend_object_roots.len()
        != package.semantic.virtio_net_backend_object_count
        || package.semantic.virtio_net_backends.len()
            != package.semantic.virtio_net_backend_object_count
    {
        return Err(ContractError::new("virtio net backend object root/count mismatch"));
    }
    if roots.network_rx_interrupt_roots.len() != package.semantic.network_rx_interrupt_count
        || package.semantic.network_rx_interrupts.len()
            != package.semantic.network_rx_interrupt_count
    {
        return Err(ContractError::new("network rx interrupt root/count mismatch"));
    }
    if roots.network_rx_wait_resolution_roots.len()
        != package.semantic.network_rx_wait_resolution_count
        || package.semantic.network_rx_wait_resolutions.len()
            != package.semantic.network_rx_wait_resolution_count
    {
        return Err(ContractError::new("network rx wait resolution root/count mismatch"));
    }
    if roots.network_tx_capability_gate_roots.len()
        != package.semantic.network_tx_capability_gate_count
        || package.semantic.network_tx_capability_gates.len()
            != package.semantic.network_tx_capability_gate_count
    {
        return Err(ContractError::new("network tx capability gate root/count mismatch"));
    }
    if roots.network_tx_completion_roots.len() != package.semantic.network_tx_completion_count
        || package.semantic.network_tx_completions.len()
            != package.semantic.network_tx_completion_count
    {
        return Err(ContractError::new("network tx completion root/count mismatch"));
    }
    if roots.network_stack_adapter_roots.len() != package.semantic.network_stack_adapter_count
        || package.semantic.network_stack_adapters.len()
            != package.semantic.network_stack_adapter_count
    {
        return Err(ContractError::new("network stack adapter root/count mismatch"));
    }
    if roots.socket_object_roots.len() != package.semantic.socket_object_count
        || package.semantic.socket_objects.len() != package.semantic.socket_object_count
    {
        return Err(ContractError::new("socket object root/count mismatch"));
    }
    if roots.endpoint_object_roots.len() != package.semantic.endpoint_object_count
        || package.semantic.endpoint_objects.len() != package.semantic.endpoint_object_count
    {
        return Err(ContractError::new("endpoint object root/count mismatch"));
    }
    if roots.socket_operation_roots.len() != package.semantic.socket_operation_count
        || package.semantic.socket_operations.len() != package.semantic.socket_operation_count
    {
        return Err(ContractError::new("socket operation root/count mismatch"));
    }
    if roots.socket_wait_roots.len() != package.semantic.socket_wait_count
        || package.semantic.socket_waits.len() != package.semantic.socket_wait_count
    {
        return Err(ContractError::new("socket wait root/count mismatch"));
    }
    if roots.network_backpressure_roots.len() != package.semantic.network_backpressure_count
        || package.semantic.network_backpressures.len()
            != package.semantic.network_backpressure_count
    {
        return Err(ContractError::new("network backpressure root/count mismatch"));
    }
    if roots.network_driver_cleanup_roots.len() != package.semantic.network_driver_cleanup_count
        || package.semantic.network_driver_cleanups.len()
            != package.semantic.network_driver_cleanup_count
    {
        return Err(ContractError::new("network driver cleanup root/count mismatch"));
    }
    if roots.network_generation_audit_roots.len() != package.semantic.network_generation_audit_count
        || package.semantic.network_generation_audits.len()
            != package.semantic.network_generation_audit_count
    {
        return Err(ContractError::new("network generation audit root/count mismatch"));
    }
    if roots.network_fault_injection_roots.len() != package.semantic.network_fault_injection_count
        || package.semantic.network_fault_injections.len()
            != package.semantic.network_fault_injection_count
    {
        return Err(ContractError::new("network fault injection root/count mismatch"));
    }
    if roots.network_benchmark_roots.len() != package.semantic.network_benchmark_count
        || package.semantic.network_benchmarks.len() != package.semantic.network_benchmark_count
    {
        return Err(ContractError::new("network benchmark root/count mismatch"));
    }
    if roots.network_recovery_benchmark_roots.len()
        != package.semantic.network_recovery_benchmark_count
        || package.semantic.network_recovery_benchmarks.len()
            != package.semantic.network_recovery_benchmark_count
    {
        return Err(ContractError::new("network recovery benchmark root/count mismatch"));
    }
    if roots.block_device_object_roots.len() != package.semantic.block_device_object_count
        || package.semantic.block_device_objects.len() != package.semantic.block_device_object_count
    {
        return Err(ContractError::new("block device object root/count mismatch"));
    }
    if roots.block_range_object_roots.len() != package.semantic.block_range_object_count
        || package.semantic.block_range_objects.len() != package.semantic.block_range_object_count
    {
        return Err(ContractError::new("block range object root/count mismatch"));
    }
    if roots.block_request_object_roots.len() != package.semantic.block_request_object_count
        || package.semantic.block_request_objects.len()
            != package.semantic.block_request_object_count
    {
        return Err(ContractError::new("block request object root/count mismatch"));
    }
    if roots.block_completion_object_roots.len() != package.semantic.block_completion_object_count
        || package.semantic.block_completion_objects.len()
            != package.semantic.block_completion_object_count
    {
        return Err(ContractError::new("block completion object root/count mismatch"));
    }
    if roots.block_wait_roots.len() != package.semantic.block_wait_count
        || package.semantic.block_waits.len() != package.semantic.block_wait_count
    {
        return Err(ContractError::new("block wait root/count mismatch"));
    }
    if roots.fake_block_backend_object_roots.len()
        != package.semantic.fake_block_backend_object_count
        || package.semantic.fake_block_backends.len()
            != package.semantic.fake_block_backend_object_count
    {
        return Err(ContractError::new("fake block backend object root/count mismatch"));
    }
    if roots.virtio_blk_backend_object_roots.len()
        != package.semantic.virtio_blk_backend_object_count
        || package.semantic.virtio_blk_backends.len()
            != package.semantic.virtio_blk_backend_object_count
    {
        return Err(ContractError::new("virtio block backend object root/count mismatch"));
    }
    if roots.block_read_path_roots.len() != package.semantic.block_read_path_count
        || package.semantic.block_read_paths.len() != package.semantic.block_read_path_count
    {
        return Err(ContractError::new("block read path root/count mismatch"));
    }
    if roots.block_write_path_roots.len() != package.semantic.block_write_path_count
        || package.semantic.block_write_paths.len() != package.semantic.block_write_path_count
    {
        return Err(ContractError::new("block write path root/count mismatch"));
    }
    if roots.block_request_queue_roots.len() != package.semantic.block_request_queue_count
        || package.semantic.block_request_queues.len() != package.semantic.block_request_queue_count
    {
        return Err(ContractError::new("block request queue root/count mismatch"));
    }
    if roots.block_dma_buffer_roots.len() != package.semantic.block_dma_buffer_count
        || package.semantic.block_dma_buffers.len() != package.semantic.block_dma_buffer_count
    {
        return Err(ContractError::new("block dma buffer root/count mismatch"));
    }
    if roots.block_page_object_roots.len() != package.semantic.block_page_object_count
        || package.semantic.block_page_objects.len() != package.semantic.block_page_object_count
    {
        return Err(ContractError::new("block page object root/count mismatch"));
    }
    if roots.buffer_cache_object_roots.len() != package.semantic.buffer_cache_object_count
        || package.semantic.buffer_cache_objects.len() != package.semantic.buffer_cache_object_count
    {
        return Err(ContractError::new("buffer cache object root/count mismatch"));
    }
    if roots.file_object_roots.len() != package.semantic.file_object_count
        || package.semantic.file_objects.len() != package.semantic.file_object_count
    {
        return Err(ContractError::new("file object root/count mismatch"));
    }
    if roots.directory_object_roots.len() != package.semantic.directory_object_count
        || package.semantic.directory_objects.len() != package.semantic.directory_object_count
    {
        return Err(ContractError::new("directory object root/count mismatch"));
    }
    if roots.fat_adapter_object_roots.len() != package.semantic.fat_adapter_object_count
        || package.semantic.fat_adapter_objects.len() != package.semantic.fat_adapter_object_count
    {
        return Err(ContractError::new("fat adapter object root/count mismatch"));
    }
    if roots.ext4_adapter_object_roots.len() != package.semantic.ext4_adapter_object_count
        || package.semantic.ext4_adapter_objects.len() != package.semantic.ext4_adapter_object_count
    {
        return Err(ContractError::new("ext4 adapter object root/count mismatch"));
    }
    if roots.file_handle_capability_roots.len() != package.semantic.file_handle_capability_count
        || package.semantic.file_handle_capabilities.len()
            != package.semantic.file_handle_capability_count
    {
        return Err(ContractError::new("file handle capability root/count mismatch"));
    }
    if roots.fs_wait_roots.len() != package.semantic.fs_wait_count
        || package.semantic.fs_waits.len() != package.semantic.fs_wait_count
    {
        return Err(ContractError::new("fs wait root/count mismatch"));
    }
    if roots.block_driver_cleanup_roots.len() != package.semantic.block_driver_cleanup_count
        || package.semantic.block_driver_cleanups.len()
            != package.semantic.block_driver_cleanup_count
    {
        return Err(ContractError::new("block driver cleanup root/count mismatch"));
    }
    if roots.block_pending_io_policy_roots.len() != package.semantic.block_pending_io_policy_count
        || package.semantic.block_pending_io_policies.len()
            != package.semantic.block_pending_io_policy_count
    {
        return Err(ContractError::new("block pending io policy root/count mismatch"));
    }
    if roots.block_request_generation_audit_roots.len()
        != package.semantic.block_request_generation_audit_count
        || package.semantic.block_request_generation_audits.len()
            != package.semantic.block_request_generation_audit_count
    {
        return Err(ContractError::new("block request generation audit root/count mismatch"));
    }
    if roots.block_benchmark_roots.len() != package.semantic.block_benchmark_count
        || package.semantic.block_benchmarks.len() != package.semantic.block_benchmark_count
    {
        return Err(ContractError::new("block benchmark root/count mismatch"));
    }
    if roots.block_recovery_benchmark_roots.len() != package.semantic.block_recovery_benchmark_count
        || package.semantic.block_recovery_benchmarks.len()
            != package.semantic.block_recovery_benchmark_count
    {
        return Err(ContractError::new("block recovery benchmark root/count mismatch"));
    }
    if roots.target_feature_set_roots.len() != package.semantic.target_feature_set_count
        || package.semantic.target_feature_sets.len() != package.semantic.target_feature_set_count
    {
        return Err(ContractError::new("target feature set root/count mismatch"));
    }
    if roots.vector_state_roots.len() != package.semantic.vector_state_count
        || package.semantic.vector_states.len() != package.semantic.vector_state_count
    {
        return Err(ContractError::new("vector state root/count mismatch"));
    }
    if roots.simd_fault_injection_roots.len() != package.semantic.simd_fault_injection_count
        || package.semantic.simd_fault_injections.len()
            != package.semantic.simd_fault_injection_count
    {
        return Err(ContractError::new("simd fault injection root/count mismatch"));
    }
    if roots.simd_benchmark_roots.len() != package.semantic.simd_benchmark_count
        || package.semantic.simd_benchmarks.len() != package.semantic.simd_benchmark_count
    {
        return Err(ContractError::new("simd benchmark root/count mismatch"));
    }
    if roots.simd_context_switch_benchmark_roots.len()
        != package.semantic.simd_context_switch_benchmark_count
        || package.semantic.simd_context_switch_benchmarks.len()
            != package.semantic.simd_context_switch_benchmark_count
    {
        return Err(ContractError::new("simd context switch benchmark root/count mismatch"));
    }
    if roots.framebuffer_object_roots.len() != package.semantic.framebuffer_object_count
        || package.semantic.framebuffer_objects.len() != package.semantic.framebuffer_object_count
    {
        return Err(ContractError::new("framebuffer object root/count mismatch"));
    }
    if roots.display_object_roots.len() != package.semantic.display_object_count
        || package.semantic.display_objects.len() != package.semantic.display_object_count
    {
        return Err(ContractError::new("display object root/count mismatch"));
    }
    if roots.display_capability_roots.len() != package.semantic.display_capability_count
        || package.semantic.display_capabilities.len() != package.semantic.display_capability_count
    {
        return Err(ContractError::new("display capability root/count mismatch"));
    }
    if roots.framebuffer_window_lease_roots.len() != package.semantic.framebuffer_window_lease_count
        || package.semantic.framebuffer_window_leases.len()
            != package.semantic.framebuffer_window_lease_count
    {
        return Err(ContractError::new("framebuffer window lease root/count mismatch"));
    }
    if roots.framebuffer_mapping_roots.len() != package.semantic.framebuffer_mapping_count
        || package.semantic.framebuffer_mappings.len() != package.semantic.framebuffer_mapping_count
    {
        return Err(ContractError::new("framebuffer mapping root/count mismatch"));
    }
    if roots.framebuffer_write_roots.len() != package.semantic.framebuffer_write_count
        || package.semantic.framebuffer_writes.len() != package.semantic.framebuffer_write_count
    {
        return Err(ContractError::new("framebuffer write root/count mismatch"));
    }
    if roots.framebuffer_flush_region_roots.len() != package.semantic.framebuffer_flush_region_count
        || package.semantic.framebuffer_flush_regions.len()
            != package.semantic.framebuffer_flush_region_count
    {
        return Err(ContractError::new("framebuffer flush region root/count mismatch"));
    }
    if roots.framebuffer_dirty_region_roots.len() != package.semantic.framebuffer_dirty_region_count
        || package.semantic.framebuffer_dirty_regions.len()
            != package.semantic.framebuffer_dirty_region_count
    {
        return Err(ContractError::new("framebuffer dirty region root/count mismatch"));
    }
    if roots.display_event_log_roots.len() != package.semantic.display_event_log_count
        || package.semantic.display_event_logs.len() != package.semantic.display_event_log_count
    {
        return Err(ContractError::new("display event log root/count mismatch"));
    }
    if roots.display_cleanup_roots.len() != package.semantic.display_cleanup_count
        || package.semantic.display_cleanups.len() != package.semantic.display_cleanup_count
    {
        return Err(ContractError::new("display cleanup root/count mismatch"));
    }
    if roots.display_snapshot_barrier_roots.len() != package.semantic.display_snapshot_barrier_count
        || package.semantic.display_snapshot_barriers.len()
            != package.semantic.display_snapshot_barrier_count
    {
        return Err(ContractError::new("display snapshot barrier root/count mismatch"));
    }
    if roots.display_panic_last_frame_roots.len() != package.semantic.display_panic_last_frame_count
        || package.semantic.display_panic_last_frames.len()
            != package.semantic.display_panic_last_frame_count
    {
        return Err(ContractError::new("display panic last-frame root/count mismatch"));
    }
    if roots.integrated_display_panic_roots.len() != package.semantic.integrated_display_panic_count
        || package.semantic.integrated_display_panics.len()
            != package.semantic.integrated_display_panic_count
    {
        return Err(ContractError::new("integrated display panic root/count mismatch"));
    }
    if roots.integrated_osctl_trace_replay_roots.len()
        != package.semantic.integrated_osctl_trace_replay_count
        || package.semantic.integrated_osctl_trace_replays.len()
            != package.semantic.integrated_osctl_trace_replay_count
    {
        return Err(ContractError::new("integrated osctl trace replay root/count mismatch"));
    }
    if roots.framebuffer_benchmark_roots.len() != package.semantic.framebuffer_benchmark_count
        || package.semantic.framebuffer_benchmarks.len()
            != package.semantic.framebuffer_benchmark_count
    {
        return Err(ContractError::new("framebuffer benchmark root/count mismatch"));
    }
    if roots.activation_resume_roots.len() != package.semantic.activation_resume_count
        || package.semantic.activation_resumes.len() != package.semantic.activation_resume_count
    {
        return Err(ContractError::new("activation resume root/count mismatch"));
    }
    if roots.activation_wait_roots.len() != package.semantic.activation_wait_count
        || package.semantic.activation_waits.len() != package.semantic.activation_wait_count
    {
        return Err(ContractError::new("activation wait root/count mismatch"));
    }
    if roots.activation_cleanup_roots.len() != package.semantic.activation_cleanup_count
        || package.semantic.activation_cleanups.len() != package.semantic.activation_cleanup_count
    {
        return Err(ContractError::new("activation cleanup root/count mismatch"));
    }
    if roots.preemption_latency_roots.len() != package.semantic.preemption_latency_sample_count
        || package.semantic.preemption_latency_samples.len()
            != package.semantic.preemption_latency_sample_count
    {
        return Err(ContractError::new("preemption latency root/count mismatch"));
    }
    if roots.hart_event_attribution_roots.len() != package.semantic.hart_event_attribution_count
        || package.semantic.hart_event_attributions.len()
            != package.semantic.hart_event_attribution_count
    {
        return Err(ContractError::new("hart event attribution root/count mismatch"));
    }
    if roots.resource_roots.len() != package.semantic.resource_count {
        return Err(ContractError::new("resource root/count mismatch"));
    }
    if roots.authority_roots.len() != package.semantic.authority_count {
        return Err(ContractError::new("authority root/count mismatch"));
    }
    if package.semantic.active_authority_count > package.semantic.authority_count {
        return Err(ContractError::new("active authority count exceeds authority count"));
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
        return Err(ContractError::new("artifact verification root/count mismatch"));
    }
    if roots.store_activation_roots.len() != package.semantic.store_activation_count {
        return Err(ContractError::new("store activation root/count mismatch"));
    }
    if roots.executor_transition_roots.len() != package.semantic.executor_transition_count {
        return Err(ContractError::new("executor transition root/count mismatch"));
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
        return Err(ContractError::new("target store record root/count mismatch"));
    }
    if package.semantic.capability_records.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("capability record count mismatch"));
    }
    if roots.target_capability_record_roots.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("target capability record root/count mismatch"));
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
        return Err(ContractError::new("cleanup transaction root/count mismatch"));
    }
    if roots.memory_policy_roots.len() != package.semantic.memory_policy_count
        || package.semantic.memory_policies.len() != package.semantic.memory_policy_count
    {
        return Err(ContractError::new("memory policy root/count mismatch"));
    }
    if roots.substrate_event_roots.len() != package.semantic.substrate_event_count
        || package.semantic.substrate_events.len() != package.semantic.substrate_event_count
    {
        return Err(ContractError::new("substrate event root/count mismatch"));
    }
    if roots.command_result_roots.len() != package.semantic.command_result_count
        || package.semantic.command_results.len() != package.semantic.command_result_count
    {
        return Err(ContractError::new("command result root/count mismatch"));
    }
    if roots.interface_event_roots.len() != package.semantic.interface_event_count
        || package.semantic.interface_events.len() != package.semantic.interface_event_count
    {
        return Err(ContractError::new("interface event root/count mismatch"));
    }
    if package.semantic.snapshot_validation.violations.len()
        != package.semantic.snapshot_validation_violation_count
    {
        return Err(ContractError::new("snapshot validation violation count mismatch"));
    }
    if package.semantic.replay_validation.violations.len()
        != package.semantic.replay_validation_violation_count
    {
        return Err(ContractError::new("replay validation violation count mismatch"));
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
    let interfaces = module_interface_spec(spec);
    hasher.update(b"\0component-model:");
    hasher.update(interfaces.component_model_version.as_bytes());
    hasher.update(b"\0wasi-profile:");
    hasher.update(interfaces.wasi_profile.as_bytes());
    hasher.update(b"\0hostcall-abi:");
    hasher.update(interfaces.hostcall_abi_version.as_bytes());
    hasher.update(b"\0capability-abi:");
    hasher.update(interfaces.capability_abi_version.as_bytes());
    hasher.update(b"\0semantic-contract:");
    hasher.update(interfaces.semantic_contract_version.as_bytes());
    hasher.update(b"\0substrate-profile:");
    hasher.update(interfaces.substrate_profile_required.as_bytes());
    for entry in interfaces.required_wasi_worlds {
        hasher.update(b"\0required-wasi:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.optional_wasi_worlds {
        hasher.update(b"\0optional-wasi:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.custom_wit_worlds {
        hasher.update(b"\0custom-wit:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.wit_package_versions {
        hasher.update(b"\0wit-package:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_required {
        hasher.update(b"\0substrate-required:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_optional {
        hasher.update(b"\0substrate-optional:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_forbidden {
        hasher.update(b"\0substrate-forbidden:");
        hasher.update(entry.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn validate_capabilities(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.capabilities.len() != spec.capabilities.len() {
        return Err(ContractError::new(format!("{} capability count mismatch", spec.package)));
    }
    for capability in spec.capabilities {
        let Some(entry_capability) =
            entry.capabilities.iter().find(|candidate| candidate.name == capability.name)
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
            return Err(ContractError::new(format!("{} capability rights mismatch", spec.package)));
        }
    }
    Ok(())
}

fn rights_vec(capability: &CapabilitySpec) -> Vec<String> {
    capability.rights.iter().map(|right| (*right).to_owned()).collect()
}

#[cfg(test)]
mod tests;
