use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use artifact_manifest::{
    ArtifactBundleManifest, GuestStateManifest, MigrationCapabilityManifest, MigrationHostManifest,
    MigrationPackageManifest, MigrationTargetManifest, ModuleArtifactManifest,
    RequiredArtifactProfileManifest, SemanticRootSetManifest, SemanticSnapshotManifest,
    SubstrateBoundaryManifest,
};
use contract_core::{
    validate_artifact_manifest, validate_manifest_entry, validate_migration_against_manifest,
    validate_replay_quiescent,
};
use semantic_core::{FrontendKind, SemanticGraph, StoreState, TaskState};
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};
use sha2::{Digest, Sha256};
use supervisor_catalog::{SUPERVISOR_WASM_MODULES, WasmModuleSpec};
use wasmtime::{Config, Engine, Instance, Module, Precompiled, Store};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";

fn main() {
    if let Err(err) = run() {
        eprintln!("target_executor error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let workspace_root = workspace_root()?;
    let artifact_root = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join(DEFAULT_ARTIFACT_ROOT));
    let migration_path = env::args().nth(2).map(PathBuf::from);
    let manifest = read_manifest(&artifact_root)?;
    let engine = runtime_engine()?;
    let mut semantic = SemanticGraph::new();
    let mut stores = Vec::with_capacity(SUPERVISOR_WASM_MODULES.len());

    validate_bundle_manifest(&manifest)?;
    semantic.ensure_task(1, FrontendKind::Supervisor, "target-executor-bootstrap");
    semantic.set_task_state(1, TaskState::Running);

    for spec in SUPERVISOR_WASM_MODULES {
        let entry = find_entry(&manifest, spec)?;
        validate_manifest_entry(spec, entry)?;
        let module_path = workspace_root.join(&entry.cwasm_path);
        let module_bytes = fs::read(&module_path)?;
        if sha256_hex(&module_bytes) != entry.cwasm_sha256 {
            return Err(format!("{} cwasm hash mismatch", spec.package).into());
        }

        match Engine::detect_precompiled(&module_bytes) {
            Some(Precompiled::Module) => {}
            Some(Precompiled::Component) => {
                return Err(format!("{} is a component artifact", spec.package).into());
            }
            None => return Err(format!("{} is not a precompiled artifact", spec.package).into()),
        }

        let module = unsafe { Module::deserialize(&engine, &module_bytes)? };
        validate_exports(spec, &module)?;
        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])?;
        smoke_instance(spec, &instance, &mut store)?;
        register_store_semantics(&mut semantic, spec);
        stores.push(LoadedStore {
            package: spec.package,
            role: spec.role.as_str(),
            fault_policy: spec.fault_policy.as_str(),
        });
    }

    println!(
        "target executor loaded {} runtime-only stores with {} capability grants across {} fault domains",
        stores.len(),
        semantic.capability_count(),
        semantic.fault_domain_count()
    );
    println!(
        "semantic store graph contains {} stores",
        semantic.store_count()
    );
    println!(
        "semantic event log contains {} events",
        semantic.event_count()
    );
    for store in stores {
        println!(
            "store {} role={} fault_policy={}",
            store.package, store.role, store.fault_policy
        );
    }
    let network_store_count = SUPERVISOR_WASM_MODULES
        .iter()
        .filter(|module| {
            matches!(
                module.package,
                "driver_virtio_net" | "net_core" | "linux_socket_service"
            )
        })
        .count();
    println!("network runtime stores loaded: {network_store_count}");
    let migration_path =
        prepare_migration_package(&artifact_root, migration_path, &manifest, &semantic)?;
    let migration = read_migration_package(&migration_path)?;
    validate_migration_package(&migration, &manifest)?;
    restore_migration_package(&migration, &semantic)?;

    Ok(())
}

fn register_store_semantics(semantic: &mut SemanticGraph, spec: &WasmModuleSpec) {
    let store = semantic.register_store(
        spec.package,
        spec.artifact_name,
        spec.role.as_str(),
        spec.fault_policy.as_str(),
    );
    semantic.set_store_state(store, StoreState::Instantiating);
    semantic.set_store_state(store, StoreState::Running);
    for capability in spec.capabilities {
        semantic.grant_capability(
            spec.package,
            capability.name,
            capability.rights,
            capability.lifetime,
        );
    }
}

fn prepare_migration_package(
    artifact_root: &Path,
    migration_path: Option<PathBuf>,
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = migration_path {
        return Ok(path);
    }

    let path = artifact_root.join("semantic-package-v1.json");
    let package = demo_migration_package(manifest, semantic);
    fs::write(&path, serde_json::to_vec_pretty(&package)?)?;
    Ok(path)
}

fn demo_migration_package(
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
) -> MigrationPackageManifest {
    let logical_capabilities = manifest
        .modules
        .iter()
        .flat_map(|module| {
            module
                .capabilities
                .iter()
                .map(|capability| MigrationCapabilityManifest {
                    subject: module.package.clone(),
                    object: capability.name.clone(),
                    rights: capability.rights.clone(),
                    lifetime: capability.lifetime.clone(),
                    generation: 1,
                })
        })
        .collect::<Vec<_>>();
    let capability_count = logical_capabilities.len();
    let roots = semantic_roots(manifest, &logical_capabilities, semantic);
    MigrationPackageManifest {
        schema_version: 1,
        package_format: "vmos-semantic-package-v1".to_owned(),
        package_id: "target-executor-semantic-package-v1".to_owned(),
        source: MigrationHostManifest {
            arch: "x86_64".to_owned(),
        },
        target: MigrationTargetManifest {
            arch_requirement: "target-native".to_owned(),
        },
        required_artifact_profile: RequiredArtifactProfileManifest {
            artifact_profile: manifest.artifact_profile.clone(),
            target_arch: "target-native".to_owned(),
            machine_abi_version: manifest.target.machine_abi_version.clone(),
            supervisor_abi_version: manifest.target.supervisor_abi_version.clone(),
            wasm_feature_profile: manifest.target.wasm_feature_profile.clone(),
            memory64: manifest.target.memory64,
            multi_memory: manifest.target.multi_memory,
            dmw_layout: manifest.target.dmw_layout.clone(),
            network_contract_version: manifest.target.network_contract_version.clone(),
            compiler_engine: manifest.compiler.engine.clone(),
            compiler_execution_mode: manifest.compiler.execution_mode.clone(),
            artifact_format: manifest.compiler.artifact_format.clone(),
        },
        guest: GuestStateManifest {
            canonical_isa: "riscv64".to_owned(),
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "host-side package proving cross-ISA restore/rebind boundaries".to_owned(),
        },
        semantic: SemanticSnapshotManifest {
            barrier_id: 1,
            event_log_cursor: semantic.event_log().cursor(),
            roots,
            pending_wait_count: 0,
            task_count: semantic.task_count(),
            resource_count: semantic.resource_count(),
            authority_count: semantic.authority_count(),
            active_authority_count: semantic.active_authority_count(),
            wait_token_count: 0,
            capability_count,
            fault_domain_count: semantic.fault_domain_count(),
            store_count: semantic.store_count(),
            transaction_count: 0,
            active_transaction_count: 0,
            fast_path_plan_count: semantic.fast_path_plan_count(),
            active_fast_path_plan_count: semantic.active_fast_path_plan_count(),
            network_socket_count: 1,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities,
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: semantic.event_count() as u64,
            cow_epoch: 1,
            background_copy_pages: 0,
            native_state_policy:
                "target rebuilds page tables, DMW slots, IRQ registrations, stores, and code cache"
                    .to_owned(),
        },
        not_migrated: vec![
            "host raw pointers".to_owned(),
            "native stacks".to_owned(),
            "active semantic transactions".to_owned(),
            "active DMW leases".to_owned(),
            "DMA/IOMMU mappings".to_owned(),
            "MMIO mappings".to_owned(),
            "IRQ registrations".to_owned(),
            "translated guest code cache".to_owned(),
        ],
    }
}

fn semantic_roots(
    manifest: &ArtifactBundleManifest,
    capabilities: &[MigrationCapabilityManifest],
    semantic: &SemanticGraph,
) -> SemanticRootSetManifest {
    SemanticRootSetManifest {
        task_roots: vec!["task:1:target-executor-bootstrap".to_owned()],
        resource_roots: manifest
            .modules
            .iter()
            .map(|module| format!("resource:store:{}", module.package))
            .collect(),
        authority_roots: semantic
            .authority_bindings()
            .iter()
            .map(|authority| {
                format!(
                    "authority:{}:{}:{}:gen{}:{}",
                    authority.id,
                    authority.subject,
                    authority.object,
                    authority.generation,
                    authority.state.as_str()
                )
            })
            .collect(),
        wait_roots: Vec::new(),
        store_roots: manifest
            .modules
            .iter()
            .map(|module| format!("store:{}", module.package))
            .collect(),
        capability_roots: capabilities
            .iter()
            .map(|capability| {
                format!(
                    "cap:{}:{}:{}:gen{}",
                    capability.subject,
                    capability.object,
                    capability.rights.join("+"),
                    capability.generation
                )
            })
            .collect(),
        fast_path_roots: semantic
            .fast_path_plans()
            .iter()
            .map(|plan| {
                format!(
                    "fastpath:{}:gen{}:valid{}",
                    plan.id, plan.generation, plan.valid
                )
            })
            .collect(),
        event_log_tail: semantic
            .event_log_tail(16)
            .iter()
            .map(|event| event.summary())
            .collect(),
    }
}

fn validate_bundle_manifest(manifest: &ArtifactBundleManifest) -> Result<(), Box<dyn Error>> {
    validate_artifact_manifest(manifest).map_err(Into::into)
}

fn validate_migration_package(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> Result<(), Box<dyn Error>> {
    validate_migration_against_manifest(package, manifest)?;
    validate_replay_quiescent(package)?;
    Ok(())
}

fn restore_migration_package(
    package: &MigrationPackageManifest,
    semantic: &SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    if package.semantic.fault_domain_count > semantic.fault_domain_count() {
        return Err(
            "migration package requires more fault domains than the executor rebuilt".into(),
        );
    }
    if package.semantic.store_count > semantic.store_count() {
        return Err("migration package requires more stores than the executor rebuilt".into());
    }
    if package.semantic.capability_count > semantic.capability_count() {
        return Err(
            "migration package requires more capabilities than the executor rebound".into(),
        );
    }
    for capability in &package.logical_capabilities {
        let Some(module) = SUPERVISOR_WASM_MODULES
            .iter()
            .find(|module| module.package == capability.subject)
        else {
            return Err(format!(
                "migration package capability subject {} is not in target catalog",
                capability.subject
            )
            .into());
        };
        let Some(target_capability) = module
            .capabilities
            .iter()
            .find(|target| target.name == capability.object)
        else {
            return Err(format!(
                "target manifest cannot satisfy capability {}::{}",
                capability.subject, capability.object
            )
            .into());
        };
        if target_capability.lifetime != capability.lifetime {
            return Err(format!(
                "target manifest lifetime mismatch for {}::{}",
                capability.subject, capability.object
            )
            .into());
        }
        for right in &capability.rights {
            if !target_capability
                .rights
                .iter()
                .any(|target_right| target_right == right)
            {
                return Err(format!(
                    "target manifest cannot satisfy right {} for {}::{}",
                    right, capability.subject, capability.object
                )
                .into());
            }
            semantic
                .capabilities()
                .check(&capability.subject, &capability.object, right)
                .map_err(|_| {
                    format!(
                        "target executor failed to rebind capability {}::{} right {}",
                        capability.subject, capability.object, right
                    )
                })?;
        }
    }

    println!(
        "migration restore/rebind demo package={} source_arch={} target_requirement={} guest_isa={}",
        package.package_id,
        package.source.arch,
        package.target.arch_requirement,
        package.guest.canonical_isa
    );
    println!(
        "restore plan: import semantic roots tasks={} resources={} authorities={}/{} waits={} pending_waits={} transactions={} active_transactions={} fastpath={}/{} sockets={} rx_bytes={} event_cursor={}",
        package.semantic.task_count,
        package.semantic.resource_count,
        package.semantic.active_authority_count,
        package.semantic.authority_count,
        package.semantic.wait_token_count,
        package.semantic.pending_wait_count,
        package.semantic.transaction_count,
        package.semantic.active_transaction_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes,
        package.semantic.event_log_cursor
    );
    println!(
        "restore plan: rebuilt {} stores across {} fault domains and rebound {} logical capabilities",
        semantic.store_count(),
        semantic.fault_domain_count(),
        package.logical_capabilities.len()
    );
    println!(
        "restore plan: not migrated = {}",
        package.not_migrated.join(", ")
    );
    Ok(())
}

fn find_entry<'a>(
    manifest: &'a ArtifactBundleManifest,
    spec: &WasmModuleSpec,
) -> Result<&'a ModuleArtifactManifest, Box<dyn Error>> {
    manifest
        .modules
        .iter()
        .find(|entry| entry.package == spec.package)
        .ok_or_else(|| format!("manifest is missing {}", spec.package).into())
}

fn validate_exports(spec: &WasmModuleSpec, module: &Module) -> Result<(), Box<dyn Error>> {
    let export_names = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for expected in spec.expected_exports {
        if !export_names.iter().any(|name| name == expected) {
            return Err(format!("{} missing export `{expected}`", spec.package).into());
        }
    }
    Ok(())
}

fn smoke_instance(
    spec: &WasmModuleSpec,
    instance: &Instance,
    store: &mut Store<()>,
) -> Result<(), Box<dyn Error>> {
    check_u32_export(instance, store, "request_capacity")?;
    check_u32_export(instance, store, "response_capacity")?;
    check_u32_export(instance, store, "buffer_capacity")?;
    check_u32_export(instance, store, "arg_buffer_capacity")?;
    check_u32_export(instance, store, "result_buffer_capacity")?;
    check_u32_export(instance, store, "request_ptr")?;
    check_u32_export(instance, store, "response_ptr")?;
    check_u32_export(instance, store, "buffer_ptr")?;
    check_u32_export(instance, store, "arg_buffer_ptr")?;
    check_u32_export(instance, store, "result_buffer_ptr")?;

    if spec.package == "console_service" {
        if let Ok(func) = instance.get_typed_func::<(u32, u32), i32>(&mut *store, "commit_write") {
            let rc = func.call(&mut *store, (0, 0))?;
            if rc != 0 {
                return Err("console_service commit_write(0, 0) failed".into());
            }
        }
    }
    if spec.package == "wasm_app" {
        if let Ok(func) = instance.get_typed_func::<(), u64>(&mut *store, "run") {
            let _ = func.call(&mut *store, ())?;
        }
    }
    if matches!(
        spec.package,
        "driver_virtio_net" | "net_core" | "linux_socket_service"
    ) {
        check_u32_export_eq(
            instance,
            store,
            "network_contract_version",
            NETWORK_CONTRACT_ABI_VERSION,
        )?;
    }
    if matches!(spec.package, "driver_virtio_net" | "net_core") {
        check_u32_export_eq(instance, store, "packet_mtu", VIRTIO_NET0_MTU)?;
        check_u32_export_eq(
            instance,
            store,
            "packet_rx_queue_depth",
            VIRTIO_NET0_RX_QUEUE_DEPTH,
        )?;
        check_u32_export_eq(
            instance,
            store,
            "packet_tx_queue_depth",
            VIRTIO_NET0_TX_QUEUE_DEPTH,
        )?;
    }
    Ok(())
}

fn check_u32_export(
    instance: &Instance,
    store: &mut Store<()>,
    export: &str,
) -> Result<(), Box<dyn Error>> {
    if let Ok(func) = instance.get_typed_func::<(), u32>(&mut *store, export) {
        let value = func.call(&mut *store, ())?;
        if value == 0 {
            return Err(format!("export `{export}` returned zero").into());
        }
    }
    Ok(())
}

fn check_u32_export_eq(
    instance: &Instance,
    store: &mut Store<()>,
    export: &str,
    expected: u32,
) -> Result<(), Box<dyn Error>> {
    let func = instance.get_typed_func::<(), u32>(&mut *store, export)?;
    let value = func.call(&mut *store, ())?;
    if value != expected {
        return Err(format!("export `{export}` returned {value}, expected {expected}").into());
    }
    Ok(())
}

fn runtime_engine() -> Result<Engine, Box<dyn Error>> {
    Ok(Engine::new(&Config::new())?)
}

fn read_manifest(artifact_root: &Path) -> Result<ArtifactBundleManifest, Box<dyn Error>> {
    let bytes = fs::read(artifact_root.join("manifest.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_migration_package(path: &Path) -> Result<MigrationPackageManifest, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    Ok(manifest_dir
        .parent()
        .ok_or("target_executor must live in workspace root")?
        .to_path_buf())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

struct LoadedStore {
    package: &'static str,
    role: &'static str,
    fault_policy: &'static str,
}
