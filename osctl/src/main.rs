use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use artifact_manifest::{ArtifactBundleManifest, MigrationPackageManifest};
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use supervisor_catalog::{
    DMW_LAYOUT, MACHINE_ABI_VERSION, SUPERVISOR_ABI_VERSION, SUPERVISOR_CONTRACT_VERSION,
    SUPERVISOR_WASM_MODULES, SUPERVISOR_WORLD, WASM_FEATURE_PROFILE, catalog_contract_fingerprint,
    package_set_fingerprint,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("osctl error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "summary" => {
            let Some(path) = args.next() else {
                return Err("summary requires a manifest/package JSON path".into());
            };
            print_summary(Path::new(&path))
        }
        "replay" => {
            let Some(until_flag) = args.next() else {
                return Err(
                    "replay requires --until <cursor> [--manifest <manifest.json>] <package.json>"
                        .into(),
                );
            };
            if until_flag != "--until" {
                return Err(
                    "replay syntax is: osctl replay --until <cursor> [--manifest <manifest.json>] <package.json>".into(),
                );
            }
            let cursor = args
                .next()
                .ok_or("replay requires a cursor")?
                .parse::<u64>()?;
            let mut manifest_path = None;
            let mut package_path = None;
            while let Some(arg) = args.next() {
                if arg == "--manifest" {
                    let path = args.next().ok_or("replay --manifest requires a path")?;
                    manifest_path = Some(path);
                } else if package_path.is_none() {
                    package_path = Some(arg);
                } else {
                    return Err("replay received too many positional paths".into());
                }
            }
            let path = package_path.ok_or("replay requires a package JSON path")?;
            replay_until(
                cursor,
                manifest_path.as_deref().map(Path::new),
                Path::new(&path),
            )
        }
        _ => {
            print_usage();
            Err(format!("unknown command `{command}`").into())
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  osctl summary <manifest-or-migration.json>");
    eprintln!(
        "  osctl replay --until <event-cursor> [--manifest <manifest.json>] <migration.json>"
    );
}

fn print_summary(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        print_migration_summary(&package);
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    print_artifact_summary(&manifest);
    Ok(())
}

fn replay_until(
    cursor: u64,
    manifest_path: Option<&Path>,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let package = serde_json::from_slice::<MigrationPackageManifest>(&bytes)?;
    validate_package(&package)?;
    if let Some(manifest_path) = manifest_path {
        let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(manifest_path)?)?;
        validate_package_against_manifest(&package, &manifest)?;
    }
    if cursor > package.semantic.event_log_cursor {
        return Err(format!(
            "requested cursor {} exceeds package cursor {}",
            cursor, package.semantic.event_log_cursor
        )
        .into());
    }
    if package.substrate_boundary.pending_dma_completions != 0
        || package.substrate_boundary.pending_network_inputs != 0
        || package.substrate_boundary.active_dmw_lease_count != 0
    {
        return Err("package is not replay-quiescent".into());
    }
    println!(
        "replay plan accepted package={} format={} cursor={} guest_isa={} scheduler_cursor={} random_epoch={}",
        package.package_id,
        package.package_format,
        cursor,
        package.guest.canonical_isa,
        package.substrate_boundary.scheduler_decision_cursor,
        package.substrate_boundary.random_epoch
    );
    println!(
        "replay imports: waits={} resources={} fastpath={}/{} sockets={} rx_bytes={}",
        package.semantic.pending_wait_count,
        package.semantic.resource_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes
    );
    println!(
        "replay roots: tasks={} resources={} authorities={} stores={} caps={} event_tail={}",
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.event_log_tail.len()
    );
    Ok(())
}

fn validate_package(package: &MigrationPackageManifest) -> Result<(), Box<dyn Error>> {
    if package.schema_version != 1 {
        return Err("unsupported semantic package schema version".into());
    }
    if package.package_format != "vmos-semantic-package-v1" {
        return Err("unsupported semantic package format".into());
    }
    if package.guest.canonical_isa != "riscv64" {
        return Err("unsupported canonical guest ISA".into());
    }
    if package.semantic.active_transaction_count != 0 {
        return Err("package contains active semantic transactions".into());
    }
    if package.logical_capabilities.len() != package.semantic.capability_count {
        return Err("package capability list/count mismatch".into());
    }
    for capability in &package.logical_capabilities {
        if capability.subject.is_empty()
            || capability.object.is_empty()
            || capability.rights.is_empty()
            || capability.generation == 0
        {
            return Err("package contains an invalid logical capability".into());
        }
    }
    validate_roots(package)?;
    Ok(())
}

fn validate_roots(package: &MigrationPackageManifest) -> Result<(), Box<dyn Error>> {
    let roots = &package.semantic.roots;
    if roots.task_roots.len() != package.semantic.task_count {
        return Err("task root/count mismatch".into());
    }
    if roots.resource_roots.len() != package.semantic.resource_count {
        return Err("resource root/count mismatch".into());
    }
    if roots.authority_roots.len() != package.semantic.authority_count {
        return Err("authority root/count mismatch".into());
    }
    if package.semantic.active_authority_count > package.semantic.authority_count {
        return Err("active authority count exceeds authority count".into());
    }
    if roots.wait_roots.len() != package.semantic.wait_token_count {
        return Err("wait root/count mismatch".into());
    }
    if roots.store_roots.len() != package.semantic.store_count {
        return Err("store root/count mismatch".into());
    }
    if roots.capability_roots.len() != package.semantic.capability_count {
        return Err("capability root/count mismatch".into());
    }
    if roots.fast_path_roots.len() != package.semantic.fast_path_plan_count {
        return Err("fastpath root/count mismatch".into());
    }
    if roots.event_log_tail.is_empty() && package.semantic.event_log_cursor != 0 {
        return Err("event log cursor is nonzero but package has no event tail".into());
    }
    Ok(())
}

fn validate_package_against_manifest(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> Result<(), Box<dyn Error>> {
    validate_supervisor_contract(manifest)?;
    let required = &package.required_artifact_profile;
    if required.target_arch != "target-native" && required.target_arch != manifest.target.arch {
        return Err("package target arch is incompatible with manifest".into());
    }
    if required.machine_abi_version != manifest.target.machine_abi_version {
        return Err("package machine ABI mismatch".into());
    }
    if required.supervisor_abi_version != manifest.target.supervisor_abi_version {
        return Err("package supervisor ABI mismatch".into());
    }
    if required.wasm_feature_profile != manifest.target.wasm_feature_profile {
        return Err("package Wasm feature profile mismatch".into());
    }
    if required.memory64 != manifest.target.memory64
        || required.multi_memory != manifest.target.multi_memory
    {
        return Err("package Wasm memory model mismatch".into());
    }
    if required.dmw_layout != manifest.target.dmw_layout {
        return Err("package DMW layout mismatch".into());
    }
    if required.network_contract_version != manifest.target.network_contract_version {
        return Err("package network contract mismatch".into());
    }
    if required.compiler_engine != manifest.compiler.engine
        || required.compiler_execution_mode != manifest.compiler.execution_mode
        || required.artifact_format != manifest.compiler.artifact_format
    {
        return Err("package compiler/artifact mode mismatch".into());
    }
    Ok(())
}

fn validate_supervisor_contract(manifest: &ArtifactBundleManifest) -> Result<(), Box<dyn Error>> {
    if manifest.contract.contract_version != SUPERVISOR_CONTRACT_VERSION {
        return Err("manifest supervisor contract version mismatch".into());
    }
    if manifest.contract.supervisor_world != SUPERVISOR_WORLD {
        return Err("manifest supervisor world mismatch".into());
    }
    if manifest.contract.catalog_fingerprint != contract_hex(catalog_contract_fingerprint()) {
        return Err("manifest supervisor catalog fingerprint mismatch".into());
    }
    if manifest.contract.package_set_fingerprint != contract_hex(package_set_fingerprint()) {
        return Err("manifest supervisor package set fingerprint mismatch".into());
    }
    if manifest.contract.module_count != SUPERVISOR_WASM_MODULES.len()
        || manifest.modules.len() != SUPERVISOR_WASM_MODULES.len()
        || manifest.contract.required_packages.len() != SUPERVISOR_WASM_MODULES.len()
    {
        return Err("manifest supervisor module count mismatch".into());
    }
    if manifest.target.machine_abi_version != MACHINE_ABI_VERSION {
        return Err("manifest machine ABI mismatch".into());
    }
    if manifest.target.supervisor_abi_version != SUPERVISOR_ABI_VERSION {
        return Err("manifest supervisor ABI mismatch".into());
    }
    if manifest.target.wasm_feature_profile != WASM_FEATURE_PROFILE {
        return Err("manifest Wasm feature profile mismatch".into());
    }
    if manifest.target.dmw_layout != DMW_LAYOUT {
        return Err("manifest DMW layout mismatch".into());
    }
    if manifest.target.network_contract_version != NETWORK_CONTRACT_VERSION {
        return Err("manifest network contract mismatch".into());
    }
    for (index, spec) in SUPERVISOR_WASM_MODULES.iter().enumerate() {
        let Some(package) = manifest.contract.required_packages.get(index) else {
            return Err("manifest supervisor package order mismatch".into());
        };
        if package != spec.package {
            return Err("manifest supervisor package order mismatch".into());
        }
        let count = manifest
            .modules
            .iter()
            .filter(|entry| entry.package == spec.package)
            .count();
        if count != 1 {
            return Err(format!("manifest has invalid module count for {}", spec.package).into());
        }
    }
    for entry in &manifest.modules {
        if !SUPERVISOR_WASM_MODULES
            .iter()
            .any(|spec| spec.package == entry.package)
        {
            return Err(format!("manifest contains unknown module {}", entry.package).into());
        }
    }
    Ok(())
}

fn print_migration_summary(package: &MigrationPackageManifest) {
    println!(
        "migration package={} format={} source={} target={} guest_isa={} cursor={}",
        package.package_id,
        package.package_format,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa,
        package.semantic.event_log_cursor
    );
    println!(
        "semantic roots: tasks={} resources={} authorities={}/{} waits={} capabilities={} stores={} fastpath={}/{}",
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.capability_count,
        package.semantic.store_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count
    );
    println!(
        "substrate boundary: irq={} dma={} net_inputs={} dmw={} cow_epoch={} background_pages={}",
        package.substrate_boundary.pending_irq_causes,
        package.substrate_boundary.pending_dma_completions,
        package.substrate_boundary.pending_network_inputs,
        package.substrate_boundary.active_dmw_lease_count,
        package.substrate_boundary.cow_epoch,
        package.substrate_boundary.background_copy_pages
    );
}

fn print_artifact_summary(manifest: &ArtifactBundleManifest) {
    println!(
        "artifact bundle profile={} arch={} engine={} mode={} signature_profile={}",
        manifest.artifact_profile,
        manifest.target.arch,
        manifest.compiler.engine,
        manifest.compiler.execution_mode,
        manifest.target.artifact_signature_profile
    );
    println!(
        "contract version={} world={} catalog={} packages={}",
        manifest.contract.contract_version,
        manifest.contract.supervisor_world,
        manifest.contract.catalog_fingerprint,
        manifest.contract.package_set_fingerprint
    );
    println!(
        "abi machine={} supervisor={} linux={} wasm_profile={} network={}",
        manifest.target.machine_abi_version,
        manifest.target.supervisor_abi_version,
        manifest.target.linux_abi_profile,
        manifest.target.wasm_feature_profile,
        manifest.target.network_contract_version
    );
    println!("modules={}", manifest.modules.len());
    for module in &manifest.modules {
        println!(
            "module {} role={} exports={} caps={} abi={} signer={}",
            module.package,
            module.role,
            module.expected_exports.len(),
            module.capabilities.len(),
            short_hash(&module.abi_fingerprint),
            module.signature.signer
        );
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn contract_hex(value: u64) -> String {
    format!("{value:016x}")
}
