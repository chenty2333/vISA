use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

mod runtime;

use artifact_manifest::{
    ActivationRecordManifest, ArtifactBundleManifest, CapabilityHandleArgManifest,
    CodeObjectManifest, GuestStateManifest, HostcallSpecManifest, HostcallTraceManifest,
    MigrationCapabilityManifest, MigrationHostManifest, MigrationObjectManifest,
    MigrationPackageManifest, MigrationTargetManifest, RequiredArtifactProfileManifest,
    SemanticRootSetManifest, SemanticSnapshotManifest, SubstrateBoundaryManifest,
    TargetAddressMapEntryManifest, TargetArtifactImageManifest, TargetCapabilitySpecManifest,
    TargetMemoryPlanManifest, TargetTrapMetadataManifest, TrapRecordManifest,
};
use contract_core::{
    ValidatedArtifactEntry, ValidatedArtifactPlan, build_validated_artifact_plan,
    validate_migration_against_manifest, validate_replay_quiescent,
};
use runtime::RuntimeOnlyExecutor;
use semantic_core::{
    ActivationEntry, ArtifactRegistry, ArtifactVerificationState, BoundaryKind, BoundaryStatus,
    CapabilityClass, CapabilityHandleArg, CapabilityLedger, CodeObject, CodePublishState,
    CodePublisher, EntrypointState, ExpectedTargetArtifact, FrontendKind, HostcallCategory,
    HostcallFrame, HostcallLinkState, HostcallSpec, HostcallTraceRecord, ManagedStoreRecord,
    MemoryLayoutState, MigrationObjectRecord, RuntimeMode, SemanticGraph, StoreState,
    TargetAddressMapEntry, TargetArtifactImage, TargetCapabilitySpec, TargetExecutor,
    TargetMemoryPlan, TargetStoreManager, TargetTrapClass, TargetTrapMetadata, TaskState,
    TrapSurfaceState, VerifiedArtifact,
};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";

#[derive(Clone, Debug, Default)]
struct TargetExecutorV1Report {
    target_artifacts: Vec<TargetArtifactImageManifest>,
    code_objects: Vec<CodeObjectManifest>,
    activation_records: Vec<ActivationRecordManifest>,
    trap_records: Vec<TrapRecordManifest>,
    hostcall_trace: Vec<HostcallTraceManifest>,
    migration_objects: Vec<MigrationObjectManifest>,
    target_event_tail: Vec<String>,
}

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
    let plan = validate_bundle_manifest(&manifest)?;
    let executor = RuntimeOnlyExecutor::host_validation(workspace_root.clone())?;
    let mut semantic = SemanticGraph::with_runtime_mode(runtime_mode_from_plan(&plan));
    let mut stores = Vec::with_capacity(plan.module_count());

    semantic.ensure_task(1, FrontendKind::Supervisor, "target-executor-bootstrap");
    semantic.set_task_state(1, TaskState::Running);
    publish_host_boundary_status(&mut semantic, &manifest);

    for entry in &plan.modules {
        let store = executor.load_store(entry)?;
        register_store_semantics(&mut semantic, entry);
        stores.push(store);
    }
    let target_v1 = build_target_executor_v1(&plan, &semantic)?;

    println!(
        "target executor loaded {} runtime-only stores with {} capability grants across {} fault domains in {} mode",
        stores.len(),
        semantic.capability_count(),
        semantic.fault_domain_count(),
        semantic.runtime_mode().as_str()
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
            "store {} role={} fault_policy={} abi={} binding={}",
            store.package,
            store.role,
            store.fault_policy,
            short_hash(&store.abi_fingerprint),
            short_hash(&store.manifest_binding_hash)
        );
    }
    let network_store_count = plan
        .modules
        .iter()
        .filter(|entry| {
            matches!(
                entry.package.as_str(),
                "driver_virtio_net" | "net_core" | "linux_socket_service"
            )
        })
        .count();
    println!("network runtime stores loaded: {network_store_count}");
    let migration_path = prepare_migration_package(
        &artifact_root,
        migration_path,
        &manifest,
        &semantic,
        &target_v1,
    )?;
    let migration = read_migration_package(&migration_path)?;
    validate_migration_package(&migration, &manifest)?;
    restore_migration_package(&migration, &semantic, &plan)?;

    Ok(())
}

fn runtime_mode_from_plan(plan: &ValidatedArtifactPlan) -> RuntimeMode {
    match plan.runtime_mode.as_str() {
        "production" => RuntimeMode::Production,
        "replay" => RuntimeMode::Replay,
        _ => RuntimeMode::Research,
    }
}

fn register_store_semantics(semantic: &mut SemanticGraph, entry: &ValidatedArtifactEntry) {
    let store = semantic.register_store(
        &entry.package,
        &entry.artifact_name,
        &entry.role,
        &entry.fault_policy,
    );
    semantic.set_store_state(store, StoreState::Instantiating);
    semantic.set_store_state(store, StoreState::Running);
    semantic.record_store_executor_transition(
        store,
        "planned",
        "artifact-verified",
        Some("host-side-runtime-validation"),
        "host-side-wasmtime-validation",
        "host-side-trap-validation",
    );
    semantic.record_artifact_verification(
        &entry.package,
        &entry.artifact_name,
        &entry.manifest_binding_hash,
        &entry.cwasm_sha256,
        &entry.abi_fingerprint,
        &entry.signature_scheme,
        &entry.signer,
        ArtifactVerificationState::HostValidated,
        Some("target-runtime-only-loader"),
    );
    semantic.record_store_activation(
        store,
        &entry.package,
        &entry.manifest_binding_hash,
        &entry.cwasm_sha256,
        CodePublishState::NotPublished,
        MemoryLayoutState::Verified,
        HostcallLinkState::NotLinked,
        TrapSurfaceState::ContractDeclared,
        EntrypointState::NotRunnable,
        Some("target-runtime-only-loader"),
    );
    for capability in &entry.capabilities {
        let rights = capability
            .rights
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        semantic.grant_manifest_capability(
            &entry.package,
            &capability.name,
            &rights,
            &capability.lifetime,
        );
    }
}

fn publish_host_boundary_status(semantic: &mut SemanticGraph, manifest: &ArtifactBundleManifest) {
    semantic.publish_boundary(
        "artifact-loader",
        BoundaryKind::ArtifactLoader,
        BoundaryStatus::ManifestBacked,
        &manifest.artifact_profile,
        None,
    );
    semantic.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::HostSide,
        &manifest.compiler.runtime_executor_abi,
        Some("bare-metal-cwasm-loader"),
    );
    semantic.publish_boundary(
        "hostcall-table",
        BoundaryKind::HostcallTable,
        BoundaryStatus::HostSide,
        &manifest.compiler.runtime_executor_abi,
        Some("target-hostcall-trampoline"),
    );
    semantic.publish_boundary(
        "target-executor",
        BoundaryKind::TargetExecutor,
        BoundaryStatus::HostSide,
        "wasmtime-host-validator",
        Some("target-runtime-only-executor"),
    );
    semantic.publish_boundary(
        "store-lifecycle",
        BoundaryKind::StoreLifecycle,
        BoundaryStatus::LifecycleObject,
        "target_executor-host-validation",
        Some("target-store-memory-stack-code-object"),
    );
    semantic.publish_boundary(
        "snapshot-replay",
        BoundaryKind::SnapshotReplay,
        BoundaryStatus::PackageOnly,
        "semantic-package-v1",
        Some("target-replay-runner"),
    );
}

fn build_target_executor_v1(
    plan: &ValidatedArtifactPlan,
    semantic: &SemanticGraph,
) -> Result<TargetExecutorV1Report, Box<dyn Error>> {
    let mut registry = ArtifactRegistry::with_expected(expected_target_artifacts(plan));
    let mut publisher = CodePublisher::new();
    let mut store_manager = TargetStoreManager::new();
    let mut executor = TargetExecutor::new();
    let mut ledger = CapabilityLedger::new();
    let mut report = TargetExecutorV1Report::default();

    for (index, entry) in plan.modules.iter().enumerate() {
        let image = target_artifact_image((index + 1) as u64, entry, plan);
        report
            .target_artifacts
            .push(target_artifact_manifest(&image));
        let verified = registry.verify(image).map_err(|error| error.message())?;
        let store_id = semantic_store_id(semantic, &entry.package)?;
        let store_id = store_manager.register_verified_artifact_with_id(
            store_id,
            &verified,
            &entry.fault_policy,
            "rebuild-from-verified-artifact",
        );
        store_manager
            .set_running(store_id)
            .map_err(|error| error.message())?;
        grant_verified_capabilities(&mut ledger, &verified, store_id);

        let code_id = publisher
            .allocate(&verified)
            .map_err(|error| error.message())?;
        publisher.fill(code_id).map_err(|error| error.message())?;
        publisher.seal(code_id).map_err(|error| error.message())?;
        publisher
            .publish_rx(code_id)
            .map_err(|error| error.message())?;
        publisher
            .bind_to_store(code_id, store_id)
            .map_err(|error| error.message())?;
        let code = publisher
            .object(code_id)
            .ok_or("publisher lost code object after bind")?
            .clone();
        let store = store_manager
            .record(store_id)
            .ok_or("store manager lost store after register")?;

        run_activation_harness(index, &mut executor, store, &code, &ledger)?;
    }

    executor
        .snapshot_barrier()
        .map_err(|error| error.message())?;
    for code in publisher.objects() {
        report.code_objects.push(code_object_manifest(code));
    }
    for activation in executor.activations() {
        report
            .activation_records
            .push(activation_record_manifest(activation));
    }
    for trap in executor.traps() {
        report.trap_records.push(trap_record_manifest(trap));
    }
    for trace in executor.hostcall_trace() {
        report.hostcall_trace.push(hostcall_trace_manifest(trace));
    }
    for object in executor.classify_migration_objects(publisher.objects()) {
        report
            .migration_objects
            .push(migration_object_manifest(&object));
    }
    report.target_event_tail = executor.event_log().to_vec();
    Ok(report)
}

fn run_activation_harness(
    index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let activation = executor
        .start_activation(
            &store.store,
            code,
            ActivationEntry::Symbol("vmos_service_entry".to_owned()),
        )
        .map_err(|error| error.message())?;
    if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
        let generation = ledger
            .generation_of(&code.package, &spec.object)
            .unwrap_or(1);
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            spec.number,
            &spec.object,
            &spec.operation,
            generation,
        );
        if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        executor
            .invoke_hostcall(code, frame, ledger)
            .map_err(|error| error.message())?;
    }
    executor
        .return_exit(activation)
        .map_err(|error| error.message())?;

    if index == 0 {
        for (number, object, operation) in [
            (9000, "mmio.denied", "map"),
            (9001, "dma.denied", "map"),
            (9002, "irq.denied", "bind"),
            (9003, "dmw.denied", "open"),
            (9004, "code-publish.denied", "publish"),
            (9006, "packet-device.denied", "rx"),
            (9007, "device.denied", "read"),
            (9008, "virtqueue.denied", "kick"),
            (9009, "timer.denied", "arm"),
            (9010, "guest-memory.denied", "read"),
            (9011, "snapshot.denied", "enter"),
            (9012, "fault-domain.denied", "restart"),
            (9013, "event-log.denied", "append"),
            (9014, "store-control.denied", "kill"),
        ] {
            let denied = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("capability_gate".to_owned()),
                )
                .map_err(|error| error.message())?;
            let _ = executor.invoke_hostcall(
                code,
                HostcallFrame::new_bound(denied, &store.store, code, number, object, operation, 1),
                ledger,
            );
        }
        if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
            let bad_abi = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_abi".to_owned()),
                )
                .map_err(|error| error.message())?;
            let generation = ledger
                .generation_of(&code.package, &spec.object)
                .unwrap_or(1);
            let mut frame = HostcallFrame::new_bound(
                bad_abi,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            frame.abi_version = "bad-hostcall-abi".to_owned();
            let _ = executor.invoke_hostcall(code, frame, ledger);

            let bad_frame_size = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_frame_size".to_owned()),
                )
                .map_err(|error| error.message())?;
            let mut frame = HostcallFrame::new_bound(
                bad_frame_size,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
            let _ = executor.invoke_hostcall(code, frame, ledger);

            if let Some(mut cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
                let bad_cap_arg = executor
                    .start_activation(
                        &store.store,
                        code,
                        ActivationEntry::Symbol("bad_capability_handle".to_owned()),
                    )
                    .map_err(|error| error.message())?;
                cap_arg.rights_mask = 0;
                let frame = HostcallFrame::new_bound(
                    bad_cap_arg,
                    &store.store,
                    code,
                    spec.number,
                    &spec.object,
                    &spec.operation,
                    generation,
                )
                .with_cap_args(vec![cap_arg]);
                let _ = executor.invoke_hostcall(code, frame, ledger);
            }
        }

        let dmw = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol("dmw_pending".to_owned()),
            )
            .map_err(|error| error.message())?;
        let lease = executor
            .acquire_dmw_lease(dmw, "dmw.handle-mode.harness")
            .map_err(|error| error.message())?;
        let _ = executor.invoke_hostcall(
            code,
            HostcallFrame::new_bound(dmw, &store.store, code, 9005, "wait.timer", "park", 1),
            ledger,
        );
        executor
            .release_dmw_lease(lease)
            .map_err(|error| error.message())?;

        for class in [
            TargetTrapClass::GuestTrap,
            TargetTrapClass::SupervisorStoreTrap,
            TargetTrapClass::CapabilityTrap,
            TargetTrapClass::WindowTrap,
            TargetTrapClass::HostcallTrap,
            TargetTrapClass::CodeObjectTrap,
            TargetTrapClass::SubstrateFault,
        ] {
            executor.synthetic_trap(
                class,
                store.store.id,
                Some(activation),
                Some(code),
                None,
                "target executor v1 typed trap harness",
            );
        }
    }
    Ok(())
}

fn target_artifact_image(
    id: u64,
    entry: &ValidatedArtifactEntry,
    plan: &ValidatedArtifactPlan,
) -> TargetArtifactImage {
    let mut image = TargetArtifactImage::new(
        id,
        &entry.package,
        &entry.artifact_name,
        &entry.role,
        &plan.artifact_profile,
        &entry.abi_fingerprint,
        &entry.manifest_binding_hash,
        &entry.cwasm_sha256,
        TargetMemoryPlan::new(
            entry.resource_limits.max_memory_pages,
            entry.resource_limits.max_table_elements,
            entry.resource_limits.max_hostcalls_per_activation,
        ),
    );
    image.exports = entry.expected_exports.clone();
    image.payload_len = entry.cwasm_sha256.len();
    image
        .address_map
        .push(TargetAddressMapEntry::new("vmos_service_entry", 0, 64));
    image.trap_metadata.push(TargetTrapMetadata::new(
        TargetTrapClass::CodeObjectTrap,
        "vmos_service_entry",
        0,
    ));
    let mut next_hostcall = 1;
    for capability in &entry.capabilities {
        image.capabilities.push(TargetCapabilitySpec {
            object: capability.name.clone(),
            operations: capability.rights.clone(),
            lifetime: capability.lifetime.clone(),
            class: CapabilityClass::from_object(&capability.name),
        });
        for right in &capability.rights {
            let category = hostcall_category_for_object(&capability.name);
            image.hostcalls.push(HostcallSpec::new(
                next_hostcall,
                &format!("hostcall.{}.{}", capability.name, right),
                category,
                &capability.name,
                right,
                matches!(category, HostcallCategory::Wait | HostcallCategory::Timer),
            ));
            next_hostcall += 1;
        }
    }
    image.hostcalls.push(HostcallSpec::new(
        9000,
        "hostcall.mmio.denied",
        HostcallCategory::Mmio,
        "mmio.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9001,
        "hostcall.dma.denied",
        HostcallCategory::Dma,
        "dma.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9002,
        "hostcall.irq.denied",
        HostcallCategory::Irq,
        "irq.denied",
        "bind",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9003,
        "hostcall.dmw.denied",
        HostcallCategory::Dmw,
        "dmw.denied",
        "open",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9004,
        "hostcall.code-publish.denied",
        HostcallCategory::CodePublish,
        "code-publish.denied",
        "publish",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9005,
        "hostcall.wait.pending",
        HostcallCategory::Wait,
        "wait.timer",
        "park",
        true,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9006,
        "hostcall.packet-device.denied",
        HostcallCategory::PacketDevice,
        "packet-device.denied",
        "rx",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9007,
        "hostcall.device.denied",
        HostcallCategory::Device,
        "device.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9008,
        "hostcall.virtqueue.denied",
        HostcallCategory::Virtqueue,
        "virtqueue.denied",
        "kick",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9009,
        "hostcall.timer.denied",
        HostcallCategory::Timer,
        "timer.denied",
        "arm",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9010,
        "hostcall.guest-memory.denied",
        HostcallCategory::GuestMemory,
        "guest-memory.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9011,
        "hostcall.snapshot.denied",
        HostcallCategory::Snapshot,
        "snapshot.denied",
        "enter",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9012,
        "hostcall.fault-domain.denied",
        HostcallCategory::FaultDomain,
        "fault-domain.denied",
        "restart",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9013,
        "hostcall.event-log.denied",
        HostcallCategory::EventLog,
        "event-log.denied",
        "append",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9014,
        "hostcall.store-control.denied",
        HostcallCategory::StoreControl,
        "store-control.denied",
        "kill",
        false,
    ));
    image
}

fn hostcall_category_for_object(object: &str) -> HostcallCategory {
    if object.starts_with("packet-device.") {
        HostcallCategory::PacketDevice
    } else if object.starts_with("code-publish.") || object.starts_with("code-object.") {
        HostcallCategory::CodePublish
    } else if object.starts_with("device.") {
        HostcallCategory::Device
    } else if object.starts_with("mmio.") {
        HostcallCategory::Mmio
    } else if object.starts_with("dma.") {
        HostcallCategory::Dma
    } else if object.starts_with("irq.") {
        HostcallCategory::Irq
    } else if object.starts_with("virtqueue.") {
        HostcallCategory::Virtqueue
    } else if object.starts_with("dmw.") {
        HostcallCategory::Dmw
    } else if object.starts_with("code-publish.") {
        HostcallCategory::CodePublish
    } else if object.starts_with("snapshot.") {
        HostcallCategory::Snapshot
    } else if object.starts_with("guest-memory.") {
        HostcallCategory::GuestMemory
    } else if object.starts_with("timer.") {
        HostcallCategory::Timer
    } else if object.starts_with("fault-domain.") {
        HostcallCategory::FaultDomain
    } else if object.starts_with("event-log.") {
        HostcallCategory::EventLog
    } else if object.starts_with("store-control.") {
        HostcallCategory::StoreControl
    } else if object.starts_with("wait.") {
        HostcallCategory::Wait
    } else {
        HostcallCategory::Service
    }
}

fn expected_target_artifacts(plan: &ValidatedArtifactPlan) -> Vec<ExpectedTargetArtifact> {
    plan.modules
        .iter()
        .map(|entry| {
            ExpectedTargetArtifact::new(
                &entry.package,
                &entry.artifact_name,
                &plan.artifact_profile,
                &entry.abi_fingerprint,
                &entry.manifest_binding_hash,
                &entry.cwasm_sha256,
            )
        })
        .collect()
}

fn grant_verified_capabilities(
    ledger: &mut CapabilityLedger,
    verified: &VerifiedArtifact,
    store_id: u64,
) {
    for capability in &verified.capabilities {
        let operations = capability
            .operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        ledger.grant_with_metadata(
            &verified.package,
            &capability.object,
            &operations,
            &capability.lifetime,
            capability.class,
            Some(store_id),
            None,
            "target-executor-v1",
        );
    }
}

fn capability_handle_arg_for(
    ledger: &CapabilityLedger,
    subject: &str,
    spec: &HostcallSpec,
) -> Option<CapabilityHandleArg> {
    let capability = ledger.check(subject, &spec.object, &spec.operation).ok()?;
    let index = capability
        .operations
        .as_slice()
        .iter()
        .position(|right| right == &spec.operation)?;
    Some(CapabilityHandleArg::new(
        capability.id,
        &capability.object,
        capability.generation,
        1u64 << index,
        &[spec.operation.as_str()],
    ))
}

fn semantic_store_id(semantic: &SemanticGraph, package: &str) -> Result<u64, Box<dyn Error>> {
    semantic
        .stores()
        .iter()
        .find(|store| store.package == package)
        .map(|store| store.id)
        .ok_or_else(|| format!("semantic graph missing store {package}").into())
}

fn prepare_migration_package(
    artifact_root: &Path,
    migration_path: Option<PathBuf>,
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = migration_path {
        return Ok(path);
    }

    let path = artifact_root.join("semantic-package-v1.json");
    let package = demo_migration_package(manifest, semantic, target_v1);
    fs::write(&path, serde_json::to_vec_pretty(&package)?)?;
    Ok(path)
}

fn demo_migration_package(
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> MigrationPackageManifest {
    let logical_capabilities = semantic
        .capabilities()
        .records()
        .iter()
        .map(|capability| MigrationCapabilityManifest {
            subject: capability.subject.clone(),
            object: capability.object.clone(),
            rights: capability.operations.as_slice().to_vec(),
            lifetime: capability.lifetime.clone(),
            class: capability.class.as_str().to_owned(),
            source: capability.source.clone(),
            owner_store: capability.owner_store,
            owner_task: capability.owner_task.map(u64::from),
            generation: capability.generation,
            revoked: capability.revoked,
        })
        .collect::<Vec<_>>();
    let capability_count = logical_capabilities.len();
    let roots = semantic_roots(manifest, &logical_capabilities, semantic, target_v1);
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
            runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
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
            boundary_count: semantic.boundary_count(),
            artifact_verification_count: semantic.artifact_verification_count(),
            store_activation_count: semantic.store_activation_count(),
            executor_transition_count: semantic.store_executor_transition_count(),
            target_artifact_count: target_v1.target_artifacts.len(),
            code_object_count: target_v1.code_objects.len(),
            activation_record_count: target_v1.activation_records.len(),
            trap_record_count: target_v1.trap_records.len(),
            hostcall_trace_count: target_v1.hostcall_trace.len(),
            migration_object_count: target_v1.migration_objects.len(),
            target_artifacts: target_v1.target_artifacts.clone(),
            code_objects: target_v1.code_objects.clone(),
            activation_records: target_v1.activation_records.clone(),
            trap_records: target_v1.trap_records.clone(),
            hostcall_trace: target_v1.hostcall_trace.clone(),
            migration_objects: target_v1.migration_objects.clone(),
            network_socket_count: 1,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities,
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
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
    target_v1: &TargetExecutorV1Report,
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
                    "cap:{}:{}:{}:{}:gen{}:{}",
                    capability.subject,
                    capability.class,
                    capability.object,
                    capability.rights.join("+"),
                    capability.generation,
                    capability.source
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
        boundary_roots: semantic
            .boundaries()
            .iter()
            .map(|boundary| boundary.summary())
            .collect(),
        artifact_verification_roots: semantic
            .artifact_verifications()
            .iter()
            .map(|artifact| artifact.summary())
            .collect(),
        store_activation_roots: semantic
            .store_activations()
            .iter()
            .map(|activation| activation.summary())
            .collect(),
        executor_transition_roots: semantic
            .store_executor_transition_tail(semantic.store_executor_transition_count()),
        target_artifact_roots: target_v1
            .target_artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "target-artifact id={} package={} artifact={} profile={} abi={} hash={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.target_profile,
                    artifact.abi_fingerprint,
                    artifact.code_hash
                )
            })
            .collect(),
        code_object_roots: target_v1
            .code_objects
            .iter()
            .map(|code| {
                let store = code
                    .bound_store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "code-object id={} artifact={} package={} state={} store={} generation={}",
                    code.id, code.artifact_id, code.package, code.state, store, code.generation
                )
            })
            .collect(),
        activation_record_roots: target_v1
            .activation_records
            .iter()
            .map(|activation| {
                let wait = activation
                    .blocked_wait
                    .map(|wait| wait.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let trap = activation
                    .trap
                    .map(|trap| trap.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} state={} entry={} wait={} trap={} dmw={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.state,
                    activation.entry,
                    wait,
                    trap,
                    activation.active_dmw_leases
                )
            })
            .collect(),
        trap_roots: target_v1
            .trap_records
            .iter()
            .map(|trap| {
                let store = trap
                    .store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let activation = trap
                    .activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "trap id={} class={} store={} activation={} effect={} detail={}",
                    trap.id, trap.class, store, activation, trap.effect, trap.detail
                )
            })
            .collect(),
        hostcall_trace_roots: target_v1
            .hostcall_trace
            .iter()
            .map(|trace| {
                format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} code={} number={} category={} subject={} object={} op={} cap_args={} allowed={} result={} ret={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    trace.record_mode,
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.code_object,
                    trace.hostcall_number,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    trace.cap_args.len(),
                    trace.allowed,
                    trace.result,
                    trace.ret_tag
                )
            })
            .collect(),
        migration_object_roots: target_v1
            .migration_objects
            .iter()
            .map(|object| {
                format!(
                    "migration-object object={} class={} reason={}",
                    object.object, object.class, object.reason
                )
            })
            .collect(),
        event_log_tail: semantic
            .event_log_tail(16)
            .iter()
            .map(|event| event.summary())
            .chain(target_v1.target_event_tail.iter().cloned())
            .collect(),
    }
}

fn target_artifact_manifest(image: &TargetArtifactImage) -> TargetArtifactImageManifest {
    TargetArtifactImageManifest {
        id: image.id,
        package: image.package.clone(),
        artifact_name: image.artifact_name.clone(),
        role: image.role.clone(),
        kind: image.kind.as_str().to_owned(),
        target_profile: image.target_profile.clone(),
        abi_fingerprint: image.abi_fingerprint.clone(),
        manifest_binding_hash: image.manifest_binding_hash.clone(),
        code_hash: image.code_hash.clone(),
        exports: image.exports.clone(),
        imports: image.imports.clone(),
        hostcalls: image.hostcalls.iter().map(hostcall_manifest).collect(),
        capabilities: image
            .capabilities
            .iter()
            .map(target_capability_manifest)
            .collect(),
        memory_plan: TargetMemoryPlanManifest {
            max_memory_pages: image.memory_plan.max_memory_pages,
            max_table_elements: image.memory_plan.max_table_elements,
            max_hostcalls_per_activation: image.memory_plan.max_hostcalls_per_activation,
        },
        trap_metadata: image
            .trap_metadata
            .iter()
            .map(trap_metadata_manifest)
            .collect(),
        address_map: image.address_map.iter().map(address_map_manifest).collect(),
        payload_len: image.payload_len,
    }
}

fn code_object_manifest(code: &CodeObject) -> CodeObjectManifest {
    CodeObjectManifest {
        id: code.id,
        artifact_id: code.artifact_id,
        package: code.package.clone(),
        owner_profile: code.owner_profile.clone(),
        generation: code.generation,
        state: code.state.as_str().to_owned(),
        bound_store: code.bound_store,
        hostcall_table: code.hostcall_table,
        text_start: code.text.start,
        text_len: code.text.len,
        text_permission: code.text.permission.as_str().to_owned(),
        rodata_start: code.rodata.start,
        rodata_len: code.rodata.len,
        rodata_permission: code.rodata.permission.as_str().to_owned(),
        code_hash: code.code_hash.clone(),
        hostcalls: code.hostcalls.iter().map(hostcall_manifest).collect(),
        trap_metadata: code
            .trap_metadata
            .iter()
            .map(trap_metadata_manifest)
            .collect(),
        address_map: code.address_map.iter().map(address_map_manifest).collect(),
    }
}

fn activation_record_manifest(
    activation: &semantic_core::ActivationRecord,
) -> ActivationRecordManifest {
    ActivationRecordManifest {
        id: activation.id,
        store: activation.store,
        store_generation: activation.store_generation,
        code_object: activation.code_object,
        code_generation: activation.code_generation,
        artifact: activation.artifact,
        entry: activation.entry.summary(),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        start_event: activation.start_event,
        exit_event: activation.exit_event,
        active_dmw_leases: activation.active_dmw_leases,
        blocked_wait: activation.blocked_wait,
        trap: activation.trap,
        return_tag: activation.return_tag.map(|tag| tag.as_str().to_owned()),
    }
}

fn trap_record_manifest(trap: &semantic_core::TargetTrapRecord) -> TrapRecordManifest {
    TrapRecordManifest {
        id: trap.id,
        class: trap.class.as_str().to_owned(),
        store: trap.store,
        activation: trap.activation,
        code_object: trap.code_object,
        artifact: trap.artifact,
        offset: trap.offset,
        hostcall: trap.hostcall.clone(),
        fault_policy: trap.fault_policy.clone(),
        effect: trap.effect.summary(),
        detail: trap.detail.clone(),
    }
}

fn hostcall_trace_manifest(trace: &HostcallTraceRecord) -> HostcallTraceManifest {
    HostcallTraceManifest {
        abi_version: trace.abi_version.clone(),
        frame_size: trace.frame_size,
        flags: trace.flags,
        activation: trace.activation,
        activation_generation: trace.activation_generation,
        store: trace.store,
        store_generation: trace.store_generation,
        code_object: trace.code_object,
        code_generation: trace.code_generation,
        artifact: trace.artifact,
        hostcall_number: trace.hostcall_number,
        hostcall_seq: trace.hostcall_seq,
        caller_offset: trace.caller_offset,
        name: trace.name.clone(),
        category: trace.category.as_str().to_owned(),
        subject: trace.subject.clone(),
        object: trace.object.clone(),
        operation: trace.operation.clone(),
        args: trace.args,
        cap_args: trace.cap_args.iter().map(cap_arg_manifest).collect(),
        record_mode: trace.record_mode.as_str().to_owned(),
        allowed: trace.allowed,
        result: trace.result.clone(),
        ret_tag: trace.ret_tag.as_str().to_owned(),
        ret0: trace.ret0,
        ret1: trace.ret1,
        trap_out: trace.trap_out,
        wait_token_out: trace.wait_token_out,
    }
}

fn cap_arg_manifest(arg: &CapabilityHandleArg) -> CapabilityHandleArgManifest {
    CapabilityHandleArgManifest {
        id: arg.id,
        object: arg.object.clone(),
        generation: arg.generation,
        rights_mask: arg.rights_mask,
        rights: arg.rights.clone(),
    }
}

fn migration_object_manifest(record: &MigrationObjectRecord) -> MigrationObjectManifest {
    MigrationObjectManifest {
        object: record.object.clone(),
        class: record.class.as_str().to_owned(),
        reason: record.reason.clone(),
    }
}

fn hostcall_manifest(hostcall: &HostcallSpec) -> HostcallSpecManifest {
    HostcallSpecManifest {
        number: hostcall.number,
        name: hostcall.name.clone(),
        category: hostcall.category.as_str().to_owned(),
        object: hostcall.object.clone(),
        operation: hostcall.operation.clone(),
        may_pending: hostcall.may_pending,
    }
}

fn target_capability_manifest(capability: &TargetCapabilitySpec) -> TargetCapabilitySpecManifest {
    TargetCapabilitySpecManifest {
        object: capability.object.clone(),
        operations: capability.operations.clone(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
    }
}

fn trap_metadata_manifest(metadata: &TargetTrapMetadata) -> TargetTrapMetadataManifest {
    TargetTrapMetadataManifest {
        class: metadata.class.as_str().to_owned(),
        symbol: metadata.symbol.clone(),
        offset: metadata.offset,
    }
}

fn address_map_manifest(entry: &TargetAddressMapEntry) -> TargetAddressMapEntryManifest {
    TargetAddressMapEntryManifest {
        symbol: entry.symbol.clone(),
        offset: entry.offset,
        len: entry.len,
    }
}

fn validate_bundle_manifest(
    manifest: &ArtifactBundleManifest,
) -> Result<ValidatedArtifactPlan, Box<dyn Error>> {
    build_validated_artifact_plan(manifest).map_err(Into::into)
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
    plan: &ValidatedArtifactPlan,
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
        let Some(module) = plan.entry(&capability.subject) else {
            return Err(format!(
                "migration package capability subject {} is not in target load plan",
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
        "restore plan: import semantic roots tasks={} resources={} authorities={}/{} waits={} pending_waits={} transactions={} active_transactions={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} sockets={} rx_bytes={} event_cursor={}",
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
        package.semantic.boundary_count,
        package.semantic.artifact_verification_count,
        package.semantic.store_activation_count,
        package.semantic.executor_transition_count,
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

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
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
