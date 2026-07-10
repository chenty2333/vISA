use super::*;

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
    validate_artifact_contract_core_evidence(manifest)?;
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
    check_artifact_manifest_profile_gate(manifest, "unspecified", capabilities)
}

pub fn check_artifact_manifest_profile_gate(
    manifest: &ArtifactBundleManifest,
    reported_profile: &str,
    capabilities: SubstrateCapabilitySet,
) -> ContractResult<ArtifactSubstrateCompatibilityReport> {
    let plan = build_validated_artifact_plan(manifest)?;
    let enforced_profile = strongest_enforced_profile(capabilities);
    let modules = plan
        .modules
        .iter()
        .map(|module| {
            check_module_substrate_profile_gate(
                module,
                reported_profile,
                &enforced_profile,
                capabilities,
            )
        })
        .collect::<ContractResult<Vec<_>>>()?;
    let ok = modules.iter().all(|module| module.ok);
    Ok(ArtifactSubstrateCompatibilityReport {
        artifact_profile: plan.artifact_profile,
        reported_profile: reported_profile.to_owned(),
        enforced_profile,
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
    let enforced_profile = strongest_enforced_profile(capabilities);
    check_module_substrate_profile_gate(module, "unspecified", &enforced_profile, capabilities)
}

pub fn check_module_substrate_profile_gate(
    module: &ValidatedArtifactEntry,
    reported_profile: &str,
    enforced_profile: &str,
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
        reported_profile: reported_profile.to_owned(),
        enforced_profile: enforced_profile.to_owned(),
        ok: profile_ok && authority_ok && forbidden_requested.is_empty(),
        profile_ok,
        authority_ok,
        missing_required,
        degraded_optional,
        forbidden_requested,
        forbidden_authorities: module.interfaces.substrate_authorities.forbidden.clone(),
    })
}

fn strongest_enforced_profile(capabilities: SubstrateCapabilitySet) -> String {
    SubstrateProfile::strongest_satisfied_by(capabilities)
        .map(SubstrateProfile::as_str)
        .unwrap_or("none")
        .to_owned()
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
