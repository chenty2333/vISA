use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use artifact_manifest::{ArtifactBundleManifest, MigrationPackageManifest};

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
                return Err("replay requires --until <cursor> <package.json>".into());
            };
            if until_flag != "--until" {
                return Err(
                    "replay syntax is: osctl replay --until <cursor> <package.json>".into(),
                );
            }
            let cursor = args
                .next()
                .ok_or("replay requires a cursor")?
                .parse::<u64>()?;
            let path = args.next().ok_or("replay requires a package JSON path")?;
            replay_until(cursor, Path::new(&path))
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
    eprintln!("  osctl replay --until <event-cursor> <migration.json>");
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

fn replay_until(cursor: u64, path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let package = serde_json::from_slice::<MigrationPackageManifest>(&bytes)?;
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
        "replay plan accepted package={} cursor={} guest_isa={} scheduler_cursor={} random_epoch={}",
        package.package_id,
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
    Ok(())
}

fn print_migration_summary(package: &MigrationPackageManifest) {
    println!(
        "migration package={} source={} target={} guest_isa={} cursor={}",
        package.package_id,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa,
        package.semantic.event_log_cursor
    );
    println!(
        "semantic roots: tasks={} resources={} waits={} capabilities={} stores={} fastpath={}/{}",
        package.semantic.task_count,
        package.semantic.resource_count,
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
        "abi machine={} supervisor={} linux={} wasm_profile={}",
        manifest.target.machine_abi_version,
        manifest.target.supervisor_abi_version,
        manifest.target.linux_abi_profile,
        manifest.target.wasm_feature_profile
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
