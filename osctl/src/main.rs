use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use artifact_manifest::{ArtifactBundleManifest, MigrationPackageManifest};
use contract_core::{
    ValidatedArtifactPlan, build_validated_artifact_plan, validate_migration_against_manifest,
    validate_migration_package, validate_replay_quiescent,
};
use semantic_core::{CapabilityClass, RuntimeMode};

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
        "check" => {
            let Some(path) = args.next() else {
                return Err("check requires a manifest/package JSON path".into());
            };
            check_path(Path::new(&path))
        }
        "plan" => {
            let mut json = false;
            let mut path = None;
            for arg in args {
                if arg == "--json" {
                    json = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("plan received too many positional paths".into());
                }
            }
            let path = path.ok_or("plan requires a manifest JSON path")?;
            print_plan(Path::new(&path), json)
        }
        "modes" => print_modes(),
        "caps" => {
            let mut subject = None;
            let mut path = None;
            while let Some(arg) = args.next() {
                if arg == "--subject" {
                    subject = Some(args.next().ok_or("caps --subject requires a value")?);
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("caps received too many positional paths".into());
                }
            }
            let path = path.ok_or("caps requires a manifest/package JSON path")?;
            print_caps(Path::new(&path), subject.as_deref())
        }
        "state" => {
            let Some(path) = args.next() else {
                return Err("state requires a manifest/package JSON path".into());
            };
            print_state(Path::new(&path))
        }
        "graph" => {
            let Some(path) = args.next() else {
                return Err("graph requires a migration package JSON path".into());
            };
            print_graph(Path::new(&path))
        }
        "activation" => {
            let mut blocked_only = false;
            let mut path = None;
            for arg in args {
                if arg == "--blocked" {
                    blocked_only = true;
                } else if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err("activation received too many positional paths".into());
                }
            }
            let path = path.ok_or("activation requires a migration package JSON path")?;
            print_activation(Path::new(&path), blocked_only)
        }
        "event-log" => {
            let Some(subcommand) = args.next() else {
                return Err("event-log requires a subcommand".into());
            };
            if subcommand != "tail" {
                return Err("event-log syntax is: osctl event-log tail <migration.json>".into());
            }
            let Some(path) = args.next() else {
                return Err("event-log tail requires a migration package JSON path".into());
            };
            print_event_log_tail(Path::new(&path))
        }
        "replay" => {
            let Some(until_flag) = args.next() else {
                return Err(
                    "replay requires --until <cursor> [--manifest <manifest.json>] [--json] <package.json>"
                        .into(),
                );
            };
            if until_flag != "--until" {
                return Err(
                    "replay syntax is: osctl replay --until <cursor> [--manifest <manifest.json>] [--json] <package.json>".into(),
                );
            }
            let cursor = args
                .next()
                .ok_or("replay requires a cursor")?
                .parse::<u64>()?;
            let mut manifest_path = None;
            let mut package_path = None;
            let mut json = false;
            while let Some(arg) = args.next() {
                if arg == "--manifest" {
                    let path = args.next().ok_or("replay --manifest requires a path")?;
                    manifest_path = Some(path);
                } else if arg == "--json" {
                    json = true;
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
                json,
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
    eprintln!("  osctl check <manifest-or-migration.json>");
    eprintln!("  osctl plan [--json] <manifest.json>");
    eprintln!("  osctl modes");
    eprintln!("  osctl caps [--subject <subject>] <manifest-or-migration.json>");
    eprintln!("  osctl state <manifest-or-migration.json>");
    eprintln!("  osctl graph <migration.json>");
    eprintln!("  osctl activation [--blocked] <migration.json>");
    eprintln!("  osctl event-log tail <migration.json>");
    eprintln!(
        "  osctl replay --until <event-cursor> [--manifest <manifest.json>] [--json] <migration.json>"
    );
}

fn print_summary(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        print_migration_summary(&package);
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    print_artifact_summary(&manifest)?;
    Ok(())
}

fn check_path(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        validate_migration_package(&package)?;
        println!(
            "package check ok package={} cursor={}",
            package.package_id, package.semantic.event_log_cursor
        );
        return Ok(());
    }
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    println!(
        "manifest check ok profile={} mode={} modules={} caps={} exports={}",
        manifest.artifact_profile,
        plan.runtime_mode,
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    Ok(())
}

fn print_plan(path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(path)?)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    if json {
        let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
        let value = serde_json::json!({
            "artifact_profile": &plan.artifact_profile,
            "runtime_mode": &plan.runtime_mode,
            "mode_policy": {
                "event_log": mode.event_log_policy(),
                "dmw": mode.dmw_policy(),
                "fastpath_enabled": mode.fast_path_enabled(),
                "deterministic_boundary": mode.deterministic_boundary(),
                "capability_audit": mode.capability_audit_policy(),
                "debug_metadata": mode.debug_metadata_policy(),
                "nondeterminism": mode.nondeterminism_policy()
            },
            "contract_version": &plan.contract_version,
            "target_arch": &plan.target_arch,
            "compiler": {
                "engine": &plan.compiler_engine,
                "execution_mode": &plan.compiler_execution_mode,
                "artifact_format": &plan.artifact_format,
                "runtime_executor_abi": &plan.runtime_executor_abi
            },
            "module_count": plan.module_count(),
            "capability_count": plan.capability_count(),
            "expected_export_count": plan.expected_export_count(),
            "modules": plan.modules.iter().map(|module| serde_json::json!({
                "package": &module.package,
                "artifact_name": &module.artifact_name,
                "role": &module.role,
                "fault_policy": &module.fault_policy,
                "cwasm_path": &module.cwasm_path,
                "cwasm_sha256": &module.cwasm_sha256,
                "abi_fingerprint": &module.abi_fingerprint,
                "manifest_binding_hash": &module.manifest_binding_hash,
                "capabilities": module.capabilities.len(),
                "dependencies": module.service_dependencies.len(),
                "resource_limits": {
                    "max_memory_pages": module.resource_limits.max_memory_pages,
                    "max_table_elements": module.resource_limits.max_table_elements,
                    "max_hostcalls_per_activation": module.resource_limits.max_hostcalls_per_activation
                }
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    print_plan_text(&plan);
    Ok(())
}

fn print_modes() -> Result<(), Box<dyn Error>> {
    for mode in RuntimeMode::all() {
        println!(
            "mode {} event_log={} dmw={} fastpath={} deterministic={} capability_audit={} debug_metadata={} nondeterminism={}",
            mode.as_str(),
            mode.event_log_policy(),
            mode.dmw_policy(),
            if mode.fast_path_enabled() {
                "enabled"
            } else {
                "disabled"
            },
            mode.deterministic_boundary(),
            mode.capability_audit_policy(),
            mode.debug_metadata_policy(),
            mode.nondeterminism_policy()
        );
    }
    Ok(())
}

fn print_caps(path: &Path, subject: Option<&str>) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        println!(
            "capability ledger package={} caps={} cursor={}",
            package.package_id,
            package.logical_capabilities.len(),
            package.semantic.event_log_cursor
        );
        for capability in package
            .logical_capabilities
            .iter()
            .filter(|capability| subject.is_none_or(|subject| capability.subject == subject))
        {
            println!(
                "cap subject={} object={} class={} rights={} lifetime={} generation={} source={} owner_store={} owner_task={} revoked={}",
                capability.subject,
                capability.object,
                display_capability_class(&capability.class, &capability.object),
                capability.rights.join("+"),
                capability.lifetime,
                capability.generation,
                display_default(&capability.source, "unknown"),
                display_option_u64(capability.owner_store),
                display_option_u64(capability.owner_task),
                capability.revoked
            );
        }
        return Ok(());
    }

    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    println!(
        "capability manifest profile={} mode={} caps={} modules={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.capability_count(),
        plan.module_count()
    );
    for module in &plan.modules {
        if subject.is_some_and(|subject| module.package != subject) {
            continue;
        }
        for capability in &module.capabilities {
            println!(
                "cap subject={} object={} class={} rights={} lifetime={} source=artifact-manifest owner_store=planned-store",
                module.package,
                capability.name,
                CapabilityClass::from_object(&capability.name).as_str(),
                capability.rights.join("+"),
                capability.lifetime
            );
        }
    }
    Ok(())
}

fn print_state(path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(package) = serde_json::from_slice::<MigrationPackageManifest>(&bytes) {
        println!(
            "semantic state package={} cursor={} tasks={} resources={} stores={} caps={} waits={} authorities={}/{} boundaries={} artifacts={} activations={} executor_transitions={}",
            package.package_id,
            package.semantic.event_log_cursor,
            package.semantic.task_count,
            package.semantic.resource_count,
            package.semantic.store_count,
            package.semantic.capability_count,
            package.semantic.wait_token_count,
            package.semantic.active_authority_count,
            package.semantic.authority_count,
            package.semantic.boundary_count,
            package.semantic.artifact_verification_count,
            package.semantic.store_activation_count,
            package.semantic.executor_transition_count
        );
        println!(
            "substrate/executor boundary native_policy={} not_migrated={}",
            package.substrate_boundary.native_state_policy,
            package.not_migrated.join(", ")
        );
        println!(
            "replay boundary scheduler_cursor={} random_epoch={} irq={} dma={} net_inputs={} dmw_leases={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} cow_epoch={} background_pages={}",
            package.substrate_boundary.scheduler_decision_cursor,
            package.substrate_boundary.random_epoch,
            package.substrate_boundary.pending_irq_causes,
            package.substrate_boundary.pending_dma_completions,
            package.substrate_boundary.pending_network_inputs,
            package.substrate_boundary.active_dmw_lease_count,
            package.substrate_boundary.active_mmio_authority_count,
            package.substrate_boundary.active_dma_authority_count,
            package.substrate_boundary.active_irq_authority_count,
            package
                .substrate_boundary
                .active_packet_device_authority_count,
            package
                .substrate_boundary
                .active_virtio_queue_authority_count,
            package.substrate_boundary.cow_epoch,
            package.substrate_boundary.background_copy_pages
        );
        return Ok(());
    }

    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&bytes)?;
    let plan = build_validated_artifact_plan(&manifest)?;
    let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
    println!(
        "planned semantic/executor boundary profile={} mode={} modules={} caps={} exports={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    println!(
        "mode policy event_log={} dmw={} fastpath={} deterministic={} capability_audit={} metadata={} nondeterminism={}",
        mode.event_log_policy(),
        mode.dmw_policy(),
        if mode.fast_path_enabled() {
            "enabled"
        } else {
            "disabled"
        },
        mode.deterministic_boundary(),
        mode.capability_audit_policy(),
        mode.debug_metadata_policy(),
        mode.nondeterminism_policy()
    );
    println!(
        "executor boundary engine={} execution_mode={} artifact_format={} runtime_executor={}",
        plan.compiler_engine,
        plan.compiler_execution_mode,
        plan.artifact_format,
        plan.runtime_executor_abi
    );
    Ok(())
}

fn print_graph(path: &Path) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "graph package={} cursor={} task_roots={} resource_roots={} authority_roots={} store_roots={} capability_roots={} fastpath_roots={} boundary_roots={} artifact_verification_roots={} store_activation_roots={} executor_transition_roots={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.fast_path_roots.len(),
        package.semantic.roots.boundary_roots.len(),
        package.semantic.roots.artifact_verification_roots.len(),
        package.semantic.roots.store_activation_roots.len(),
        package.semantic.roots.executor_transition_roots.len()
    );
    print_roots("task", &package.semantic.roots.task_roots);
    print_roots("resource", &package.semantic.roots.resource_roots);
    print_roots("authority", &package.semantic.roots.authority_roots);
    print_roots("store", &package.semantic.roots.store_roots);
    print_roots("capability", &package.semantic.roots.capability_roots);
    print_roots("fastpath", &package.semantic.roots.fast_path_roots);
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots(
        "artifact-verification",
        &package.semantic.roots.artifact_verification_roots,
    );
    print_roots(
        "store-activation",
        &package.semantic.roots.store_activation_roots,
    );
    print_roots(
        "executor-transition",
        &package.semantic.roots.executor_transition_roots,
    );
    Ok(())
}

fn print_event_log_tail(path: &Path) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "event-log tail package={} cursor={} events={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.event_log_tail.len()
    );
    for event in &package.semantic.roots.event_log_tail {
        println!("{event}");
    }
    Ok(())
}

fn print_activation(path: &Path, blocked_only: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    println!(
        "activation package={} cursor={} roots={} blocked_only={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.store_activation_roots.len(),
        blocked_only
    );
    for activation in &package.semantic.roots.store_activation_roots {
        if blocked_only && activation.contains(" blocked=none ") {
            continue;
        }
        println!("{activation}");
    }
    Ok(())
}

fn replay_until(
    cursor: u64,
    manifest_path: Option<&Path>,
    path: &Path,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let package = serde_json::from_slice::<MigrationPackageManifest>(&bytes)?;
    validate_replay_quiescent(&package)?;
    if let Some(manifest_path) = manifest_path {
        let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(manifest_path)?)?;
        validate_migration_against_manifest(&package, &manifest)?;
    }
    if cursor > package.semantic.event_log_cursor {
        return Err(format!(
            "requested cursor {} exceeds package cursor {}",
            cursor, package.semantic.event_log_cursor
        )
        .into());
    }
    if json {
        print_replay_json(cursor, &package)?;
        return Ok(());
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
        "replay roots: tasks={} resources={} authorities={} stores={} caps={} boundaries={} artifacts={} activations={} executor_transitions={} event_tail={}",
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.boundary_roots.len(),
        package.semantic.roots.artifact_verification_roots.len(),
        package.semantic.roots.store_activation_roots.len(),
        package.semantic.roots.executor_transition_roots.len(),
        package.semantic.roots.event_log_tail.len()
    );
    for boundary in &package.semantic.roots.boundary_roots {
        println!("replay boundary {boundary}");
    }
    for artifact in &package.semantic.roots.artifact_verification_roots {
        println!("replay artifact {artifact}");
    }
    for activation in &package.semantic.roots.store_activation_roots {
        println!("replay activation {activation}");
    }
    for transition in &package.semantic.roots.executor_transition_roots {
        println!("replay executor {transition}");
    }
    Ok(())
}

fn print_replay_json(
    cursor: u64,
    package: &MigrationPackageManifest,
) -> Result<(), Box<dyn Error>> {
    let value = serde_json::json!({
        "status": "accepted",
        "package": package.package_id,
        "format": package.package_format,
        "cursor": cursor,
        "guest_isa": package.guest.canonical_isa,
        "scheduler_cursor": package.substrate_boundary.scheduler_decision_cursor,
        "random_epoch": package.substrate_boundary.random_epoch,
        "imports": {
            "pending_waits": package.semantic.pending_wait_count,
            "resources": package.semantic.resource_count,
            "active_fastpath": package.semantic.active_fast_path_plan_count,
            "fastpath": package.semantic.fast_path_plan_count,
            "sockets": package.semantic.network_socket_count,
            "rx_bytes": package.semantic.network_rx_queue_bytes
        },
        "substrate_boundary": {
            "pending_irq_causes": package.substrate_boundary.pending_irq_causes,
            "pending_dma_completions": package.substrate_boundary.pending_dma_completions,
            "active_dmw_lease_count": package.substrate_boundary.active_dmw_lease_count,
            "active_mmio_authority_count": package.substrate_boundary.active_mmio_authority_count,
            "active_dma_authority_count": package.substrate_boundary.active_dma_authority_count,
            "active_irq_authority_count": package.substrate_boundary.active_irq_authority_count,
            "active_packet_device_authority_count": package.substrate_boundary.active_packet_device_authority_count,
            "active_virtio_queue_authority_count": package.substrate_boundary.active_virtio_queue_authority_count
        },
        "roots": {
            "tasks": package.semantic.roots.task_roots.len(),
            "resources": package.semantic.roots.resource_roots.len(),
            "authorities": package.semantic.roots.authority_roots.len(),
            "stores": package.semantic.roots.store_roots.len(),
            "capabilities": package.semantic.roots.capability_roots.len(),
            "boundaries": package.semantic.roots.boundary_roots.len(),
            "artifacts": package.semantic.roots.artifact_verification_roots.len(),
            "activations": package.semantic.roots.store_activation_roots.len(),
            "executor_transitions": package.semantic.roots.executor_transition_roots.len(),
            "event_tail": package.semantic.roots.event_log_tail.len(),
            "boundary_roots": &package.semantic.roots.boundary_roots,
            "artifact_verification_roots": &package.semantic.roots.artifact_verification_roots,
            "store_activation_roots": &package.semantic.roots.store_activation_roots,
            "executor_transition_roots": &package.semantic.roots.executor_transition_roots
        }
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
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
        "semantic roots: tasks={} resources={} authorities={}/{} waits={} capabilities={} stores={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={}",
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.capability_count,
        package.semantic.store_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.boundary_count,
        package.semantic.artifact_verification_count,
        package.semantic.store_activation_count,
        package.semantic.executor_transition_count
    );
    println!(
        "substrate boundary: irq={} dma={} net_inputs={} dmw={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} cow_epoch={} background_pages={}",
        package.substrate_boundary.pending_irq_causes,
        package.substrate_boundary.pending_dma_completions,
        package.substrate_boundary.pending_network_inputs,
        package.substrate_boundary.active_dmw_lease_count,
        package.substrate_boundary.active_mmio_authority_count,
        package.substrate_boundary.active_dma_authority_count,
        package.substrate_boundary.active_irq_authority_count,
        package
            .substrate_boundary
            .active_packet_device_authority_count,
        package
            .substrate_boundary
            .active_virtio_queue_authority_count,
        package.substrate_boundary.cow_epoch,
        package.substrate_boundary.background_copy_pages
    );
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots(
        "artifact-verification",
        &package.semantic.roots.artifact_verification_roots,
    );
    print_roots(
        "store-activation",
        &package.semantic.roots.store_activation_roots,
    );
    print_roots(
        "executor-transition",
        &package.semantic.roots.executor_transition_roots,
    );
}

fn print_artifact_summary(manifest: &ArtifactBundleManifest) -> Result<(), Box<dyn Error>> {
    let plan = build_validated_artifact_plan(manifest)?;
    println!(
        "artifact bundle profile={} runtime_mode={} arch={} engine={} mode={} runtime_executor={} signature_profile={}",
        manifest.artifact_profile,
        plan.runtime_mode,
        manifest.target.arch,
        manifest.compiler.engine,
        manifest.compiler.execution_mode,
        manifest.compiler.runtime_executor_abi,
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
    println!(
        "modules={} caps={} exports={}",
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    for module in &plan.modules {
        println!(
            "module {} role={} exports={} caps={} deps={} abi={} binding={} signer={}",
            module.package,
            module.role,
            module.expected_exports.len(),
            module.capabilities.len(),
            module.service_dependencies.len(),
            short_hash(&module.abi_fingerprint),
            short_hash(&module.manifest_binding_hash),
            module.signer
        );
    }
    Ok(())
}

fn print_plan_text(plan: &ValidatedArtifactPlan) {
    let mode = RuntimeMode::parse(&plan.runtime_mode).unwrap_or(RuntimeMode::Research);
    println!(
        "load plan profile={} mode={} contract={} world={} target={} engine={} exec_mode={} format={} runtime={}",
        plan.artifact_profile,
        plan.runtime_mode,
        plan.contract_version,
        plan.supervisor_world,
        plan.target_arch,
        plan.compiler_engine,
        plan.compiler_execution_mode,
        plan.artifact_format,
        plan.runtime_executor_abi
    );
    println!(
        "mode policy event_log={} dmw={} fastpath={} deterministic={} capability_audit={} metadata={} nondeterminism={}",
        mode.event_log_policy(),
        mode.dmw_policy(),
        if mode.fast_path_enabled() {
            "enabled"
        } else {
            "disabled"
        },
        mode.deterministic_boundary(),
        mode.capability_audit_policy(),
        mode.debug_metadata_policy(),
        mode.nondeterminism_policy()
    );
    println!(
        "load plan modules={} caps={} exports={}",
        plan.module_count(),
        plan.capability_count(),
        plan.expected_export_count()
    );
    for module in &plan.modules {
        println!(
            "load {} artifact={} role={} policy={} path={} hash={} abi={} binding={} limits=mem{} table{} hostcalls{}",
            module.package,
            module.artifact_name,
            module.role,
            module.fault_policy,
            module.cwasm_path,
            short_hash(&module.cwasm_sha256),
            short_hash(&module.abi_fingerprint),
            short_hash(&module.manifest_binding_hash),
            module.resource_limits.max_memory_pages,
            module.resource_limits.max_table_elements,
            module.resource_limits.max_hostcalls_per_activation
        );
    }
}

fn print_roots(label: &str, roots: &[String]) {
    for root in roots {
        println!("{label} {root}");
    }
}

fn display_capability_class<'a>(class: &'a str, object: &str) -> &'a str {
    if class.is_empty() {
        CapabilityClass::from_object(object).as_str()
    } else {
        class
    }
}

fn display_default<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn display_option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}
