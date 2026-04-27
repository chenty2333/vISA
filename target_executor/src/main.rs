use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

mod runtime;

use artifact_manifest::{
    ActivationCleanupManifest, ActivationCleanupStepManifest, ActivationContextManifest,
    ActivationMigrationManifest, ActivationRecordManifest, ActivationResumeManifest,
    ActivationWaitManifest, ArtifactBundleManifest, AuthorityObjectRefManifest,
    BlockCompletionObjectManifest, BlockDeviceObjectManifest, BlockDmaBufferManifest,
    BlockPageObjectManifest, BlockRangeObjectManifest, BlockReadPathManifest,
    BlockRequestObjectManifest, BlockRequestQueueEntryManifest, BlockRequestQueueManifest,
    BlockWaitManifest, BlockWritePathManifest, BoundaryValidationReportManifest,
    BoundaryValidationViolationManifest, BufferCacheObjectManifest, CapabilityHandleArgManifest,
    CapabilityRecordManifest, CleanupEffectManifest, CleanupStepManifest,
    CleanupTransactionManifest, CodeObjectManifest, CommandEffectManifest, CommandResultManifest,
    ContractObjectRefManifest, ContractViolationManifest, CrossHartSchedulerDecisionManifest,
    DescriptorObjectManifest, DeviceCapabilityManifest, DeviceObjectManifest,
    DirectoryObjectManifest, DmaBufferObjectManifest, DriverStoreBindingManifest,
    EndpointObjectManifest, Ext4AdapterObjectManifest, FakeBlockBackendObjectManifest,
    FakeNetBackendObjectManifest, FatAdapterObjectManifest, FileHandleCapabilityManifest,
    FileObjectManifest, FsWaitManifest, GuestStateManifest, HartEventAttributionManifest,
    HartRecordManifest, HostcallSpecManifest, HostcallTraceManifest, InterfaceEventManifest,
    IoCleanupManifest, IoCleanupStepManifest, IoFaultInjectionManifest, IoValidationReportManifest,
    IoValidationViolationManifest, IoWaitManifest, IpiEventManifest, IrqEventManifest,
    IrqLineObjectManifest, MemoryClassPolicyManifest, MigrationCapabilityManifest,
    MigrationHostManifest, MigrationObjectManifest, MigrationPackageManifest,
    MigrationTargetManifest, MmioRegionObjectManifest, NetworkBackpressureManifest,
    NetworkBenchmarkManifest, NetworkDriverCleanupManifest, NetworkFaultInjectionManifest,
    NetworkGenerationAuditManifest, NetworkRecoveryBenchmarkManifest, NetworkRxInterruptManifest,
    NetworkRxWaitResolutionManifest, NetworkStackAdapterManifest, NetworkTxCapabilityGateManifest,
    NetworkTxCompletionManifest, PacketBufferObjectManifest, PacketDescriptorObjectManifest,
    PacketDeviceObjectManifest, PacketQueueObjectManifest, PreemptionLatencySampleManifest,
    PreemptionManifest, QueueObjectManifest, RemoteParkManifest, RemotePreemptManifest,
    RequiredArtifactProfileManifest, RunnableQueueEntryManifest, RunnableQueueManifest,
    RuntimeActivationRecordManifest, SavedContextManifest, SchedulerDecisionManifest,
    SemanticRootSetManifest, SemanticSnapshotManifest, SmpCleanupQuiescenceManifest,
    SmpCleanupQuiescenceParticipantManifest, SmpCodePublishBarrierManifest,
    SmpCodePublishBarrierParticipantManifest, SmpSafePointManifest,
    SmpSafePointParticipantManifest, SmpScalingBenchmarkManifest, SmpSnapshotBarrierManifest,
    SmpSnapshotBarrierParticipantManifest, SmpStressRunManifest, SocketObjectManifest,
    SocketOperationManifest, SocketWaitManifest, StopTheWorldRendezvousManifest,
    StopTheWorldRendezvousParticipantManifest, StoreRecordManifest, SubstrateBoundaryManifest,
    SubstrateEventManifest, TargetAddressMapEntryManifest, TargetArtifactImageManifest,
    TargetCapabilitySpecManifest, TargetMemoryPlanManifest, TargetTrapMetadataManifest,
    TaskRecordManifest, TimerInterruptManifest, TombstoneManifest, TrapRecordManifest,
    VirtioBlkBackendObjectManifest, VirtioNetBackendObjectManifest, WaitRecordManifest,
};
use contract_core::{
    ValidatedArtifactEntry, ValidatedArtifactPlan, build_validated_artifact_plan,
    validate_migration_against_manifest, validate_replay_quiescent,
};
use fs_adapter::{
    Ext4AdapterConfig, FatAdapterConfig, build_ext4_read_only_evidence,
    build_fat_read_write_evidence,
};
use net_stack_adapter::{SmoltcpAdapterConfig, build_smoltcp_adapter_evidence};
use runtime::{HostValidationSmokeTrace, RuntimeOnlyExecutor};
use semantic_core::{
    ActivationEntry, ArtifactRegistry, ArtifactVerificationState, AuthorityObjectRef,
    BlockCompletionStatus, BlockRequestOperation, BlockRequestQueueEntryRef, BoundaryKind,
    BoundaryStatus, BoundaryValidationReport, BoundaryValidationViolation, BufferCacheObjectState,
    CapabilityClass, CapabilityHandleArg, CapabilityLedger, CapabilityRecord, CodeObject,
    CodePublishState, CodePublisher, CommandEnvelope, CommandResult, CommandStatus,
    ContractGraphSnapshot, ContractObjectKind, ContractObjectRef, ContractViolation, CowState,
    DescriptorObjectAccess, DirectoryEntryKind, DirectoryObjectState, DmaBufferObjectAccess,
    EntrypointState, EventKind, EventRecord, ExpectedTargetArtifact, Ext4AdapterObjectState,
    ExternalObjectDeclaration, FatAdapterObjectState, FileObjectState, FrontendKind, HartState,
    HostcallCategory, HostcallFrame, HostcallLinkState, HostcallSpec, HostcallTraceRecord,
    IpiEventKind, IrqLinePolarity, IrqLineTrigger, ManagedStoreRecord, MemoryClassPolicy,
    MemoryLayoutState, MigrationObjectRecord, MmioRegionObjectAccess, NetworkBackpressureAction,
    NetworkBackpressureReason, NetworkFaultInjectionEffect, NetworkFaultInjectionKind,
    PackageReplayValidator, PacketBufferDirection, PacketBufferObjectState, PacketQueueRole,
    PageBacking, PageObjectState, QueueObjectRole, ReplayPackageValidationState, ResourceKind,
    RestartPolicy, RuntimeMode, SavedContextReason, SemanticCommand, SemanticGraph,
    SemanticWaitKind, SnapshotBarrierValidationState, SnapshotBarrierValidator, StoreRecord,
    StoreState, TargetAddressMapEntry, TargetArtifactImage, TargetCapabilitySpec, TargetExecutor,
    TargetMemoryPlan, TargetStoreManager, TargetTrapClass, TargetTrapMetadata, TaskState,
    TombstoneRecord, TrapSurfaceState, VerifiedArtifact, WaitCancelReason, memory_class_policies,
    validate_contract_graph,
};
use service_core::fake_block::{
    FAKE_BLOCK_BACKEND_PROFILE, FAKE_BLOCK_BACKEND_PROVIDER, FakeBlockBackendConfig,
};
use service_core::fake_net::{
    FAKE_NET_BACKEND_PROFILE, FAKE_NET_BACKEND_PROVIDER, FAKE_NET_BACKEND_SEED,
};
use service_core::net_contract::{
    PACKET_FRAME_FORMAT_VERSION, PACKET_MAX_PAYLOAD_LEN, VIRTIO_NET0_CONTRACT,
};
use substrate_api::{SubstrateEvent, SubstrateRequester};
use substrate_virtio::block::{
    VIRTIO_BLK_BACKEND_MODEL, VIRTIO_BLK_BACKEND_PROFILE, VIRTIO_BLK_BACKEND_PROVIDER,
    VirtioBlkBackendConfig,
};
use substrate_virtio::net::{
    VIRTIO_NET_BACKEND_MODEL, VIRTIO_NET_BACKEND_PROFILE, VIRTIO_NET_BACKEND_PROVIDER,
    VirtioNetBackendConfig,
};
use target_abi::{
    OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, RV64_ENTRY_TRAP_EBREAK_OFFSET, TrapKindV1,
    TrapMapEntryV1,
};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";
const SEMANTIC_EVIDENCE_CAPABILITY_SOURCES: &[&str] = &[
    "i7-device-capability",
    "n17-dma-generation-capability",
    "b6-virtio-blk-device-capability",
    "target-executor-b17",
];

#[derive(Clone, Debug, Default)]
struct TargetExecutorV1Report {
    target_artifacts: Vec<TargetArtifactImageManifest>,
    code_objects: Vec<CodeObjectManifest>,
    store_records: Vec<StoreRecordManifest>,
    capability_records: Vec<CapabilityRecordManifest>,
    wait_records: Vec<WaitRecordManifest>,
    activation_records: Vec<ActivationRecordManifest>,
    trap_records: Vec<TrapRecordManifest>,
    hostcall_trace: Vec<HostcallTraceManifest>,
    migration_objects: Vec<MigrationObjectManifest>,
    tombstones: Vec<TombstoneManifest>,
    contract_violations: Vec<ContractViolationManifest>,
    cleanup_transactions: Vec<CleanupTransactionManifest>,
    memory_policies: Vec<MemoryClassPolicyManifest>,
    snapshot_validation: BoundaryValidationReportManifest,
    replay_validation: BoundaryValidationReportManifest,
    target_event_tail: Vec<String>,
    substrate_events: Vec<SubstrateEventManifest>,
    command_results: Vec<CommandResultManifest>,
    interface_events: Vec<InterfaceEventManifest>,
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
    let executor =
        RuntimeOnlyExecutor::host_validation(workspace_root.clone(), &plan.artifact_profile)?;
    let mut semantic = SemanticGraph::with_runtime_mode(runtime_mode_from_plan(&plan));
    let mut stores = Vec::with_capacity(plan.module_count());

    semantic.ensure_task(1, FrontendKind::Supervisor, "target-executor-bootstrap");
    semantic.set_task_state(1, TaskState::Running);
    record_preemptive_runtime_context_evidence(&mut semantic)?;
    publish_host_boundary_status(&mut semantic, &manifest);

    for entry in &plan.modules {
        match executor.load_store(entry) {
            Ok(store) => {
                register_store_semantics(&mut semantic, entry);
                stores.push(store);
            }
            Err(error) => {
                let reason = format!("host-validation-error:{error}");
                semantic.record_artifact_verification(
                    &entry.package,
                    &entry.artifact_name,
                    &entry.manifest_binding_hash,
                    &entry.target_artifact_sha256,
                    &entry.abi_fingerprint,
                    &entry.signature_scheme,
                    &entry.signer,
                    ArtifactVerificationState::Rejected,
                    Some(&reason),
                );
                let package_path = prepare_migration_package(
                    &artifact_root,
                    migration_path.clone(),
                    &manifest,
                    &semantic,
                    &TargetExecutorV1Report::default(),
                )?;
                return Err(format!(
                    "{} host-side validation failed before activation; wrote rejection evidence to {}",
                    entry.package,
                    package_path.display()
                )
                .into());
            }
        }
    }
    record_network_runtime_n5_evidence(&mut semantic)?;
    record_network_runtime_n6_evidence(&mut semantic)?;
    record_network_runtime_n7_evidence(&mut semantic)?;
    record_network_runtime_n8_evidence(&mut semantic)?;
    record_network_runtime_n9_evidence(&mut semantic)?;
    record_network_runtime_n10_evidence(&mut semantic)?;
    record_network_runtime_n11_evidence(&mut semantic)?;
    record_network_runtime_n12_evidence(&mut semantic)?;
    record_network_runtime_n13_evidence(&mut semantic)?;
    record_network_runtime_n14_evidence(&mut semantic)?;
    record_network_runtime_n15_evidence(&mut semantic)?;
    record_network_runtime_n17_evidence(&mut semantic)?;
    record_network_runtime_n18_evidence(&mut semantic)?;
    record_network_runtime_n16_evidence(&mut semantic)?;
    record_network_runtime_n19_evidence(&mut semantic)?;
    record_network_runtime_n20_evidence(&mut semantic)?;
    record_block_runtime_b0_evidence(&mut semantic)?;
    record_block_runtime_b1_evidence(&mut semantic)?;
    record_block_runtime_b2_evidence(&mut semantic)?;
    record_block_runtime_b3_evidence(&mut semantic)?;
    record_block_runtime_b4_evidence(&mut semantic)?;
    record_block_runtime_b5_evidence(&mut semantic)?;
    record_block_runtime_b6_evidence(&mut semantic)?;
    record_block_runtime_b7_evidence(&mut semantic)?;
    record_block_runtime_b8_evidence(&mut semantic)?;
    record_block_runtime_b9_evidence(&mut semantic)?;
    record_block_runtime_b10_evidence(&mut semantic)?;
    record_block_runtime_b11_evidence(&mut semantic)?;
    record_block_runtime_b12_evidence(&mut semantic)?;
    record_block_runtime_b13_evidence(&mut semantic)?;
    record_block_runtime_b14_evidence(&mut semantic)?;
    record_block_runtime_b15_evidence(&mut semantic)?;
    record_block_runtime_b16_evidence(&mut semantic)?;
    record_block_runtime_b17_evidence(&mut semantic)?;
    record_block_runtime_b18_evidence(&mut semantic)?;
    record_substrate_conformance_evidence(&mut semantic);
    record_command_surface_evidence(&mut semantic);
    record_interface_boundary_evidence(&mut semantic);
    let target_v1 = build_target_executor_v1(&plan, &semantic, &stores)?;

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
        &entry.target_artifact_sha256,
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

fn record_network_runtime_n5_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n5 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n5 evidence")?;
    let virtio_device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 10_001, 1);
    let virtio_device_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "device.virtio-net0",
        AuthorityObjectRef::internal(CapabilityClass::Device, virtio_device_ref),
        &["probe"],
        "store",
        "n5-virtio-net-device-capability",
        true,
    );
    let virtio_device_handle = semantic
        .capabilities()
        .record(virtio_device_capability)
        .and_then(|record| record.store_local_handle(vec!["probe".to_owned()]))
        .ok_or("n5 virtio net device capability handle is missing")?;
    let virtio_config = VirtioNetBackendConfig::net0();
    let commands = [
        CommandEnvelope::new(
            127,
            "target-executor-n5",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_008,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: virtio_device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: virtio_device_handle,
                note: "n5-record-virtio-net-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            128,
            "target-executor-n5",
            SemanticCommand::BindDriverStore {
                binding: 10_009,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                device: 10_001,
                device_generation: 1,
                device_capability: 10_008,
                device_capability_generation: 1,
                note: "n5-bind-virtio-net-driver-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            129,
            "target-executor-n5",
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend: 10_010,
                name: "virtio-net0-backend".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                driver_binding: 10_009,
                driver_binding_generation: 1,
                provider: VIRTIO_NET_BACKEND_PROVIDER.to_owned(),
                profile: VIRTIO_NET_BACKEND_PROFILE.to_owned(),
                model: VIRTIO_NET_BACKEND_MODEL.to_owned(),
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                device_features: virtio_config.device_features,
                driver_features: virtio_config.driver_features,
                negotiated_features: virtio_config.negotiated_features,
                rx_queue_index: virtio_config.rx_queue_index,
                tx_queue_index: virtio_config.tx_queue_index,
                queue_size: virtio_config.queue_size,
                irq_vector: virtio_config.irq_vector,
                note: "n5-bind-virtio-net-backend-skeleton-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n5 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

fn record_network_runtime_n6_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n6 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n6 evidence")?;
    let irq_line_resource =
        semantic.register_resource(ResourceKind::IrqLine, None, "irq:virtio-net0-rx");
    let irq_line_resource_generation = semantic
        .resource_handle(irq_line_resource)
        .map(|handle| handle.generation)
        .ok_or("n6 virtio net irq line resource handle is missing")?;
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 10_011, 1);
    let irq_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "irq.net0",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
        &["ack"],
        "store",
        "n6-virtio-net-rx-irq-capability",
        true,
    );
    let irq_handle = semantic
        .capabilities()
        .record(irq_capability)
        .and_then(|record| record.store_local_handle(vec!["ack".to_owned()]))
        .ok_or("n6 virtio net irq capability handle is missing")?;
    let commands = [
        CommandEnvelope::new(
            130,
            "target-executor-n6",
            SemanticCommand::RecordIrqLineObject {
                irq_line: 10_011,
                device: 10_001,
                device_generation: 1,
                resource: irq_line_resource,
                resource_generation: irq_line_resource_generation,
                irq_number: 5,
                trigger: IrqLineTrigger::Level,
                polarity: IrqLinePolarity::ActiveHigh,
                note: "n6-record-virtio-net-rx-irq-line-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            131,
            "target-executor-n6",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_012,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: irq_ref,
                class: CapabilityClass::IrqLine,
                operation: "ack".to_owned(),
                handle: irq_handle,
                note: "n6-record-virtio-net-rx-irq-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            132,
            "target-executor-n6",
            SemanticCommand::RecordIrqEvent {
                irq_event: 10_013,
                irq_line: 10_011,
                irq_line_generation: 1,
                device: 10_001,
                device_generation: 1,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                sequence: 1,
                note: "n6-record-virtio-net-rx-irq-event-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            133,
            "target-executor-n6",
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt: 10_014,
                virtio_net_backend: 10_010,
                virtio_net_backend_generation: 1,
                irq_event: 10_013,
                irq_event_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                rx_queue: 10_004,
                rx_queue_generation: 1,
                ready_descriptors: 1,
                sequence: 1,
                note: "n6-record-network-rx-interrupt-path-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n6 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

fn record_network_runtime_n7_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n7 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n7 evidence")?;
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 10_004, 1);
    let commands = [
        CommandEnvelope::new(
            134,
            "target-executor-n7",
            SemanticCommand::CreateWait {
                wait: 10_015,
                owner_task: None,
                owner_store: Some(virtio_driver_store),
                owner_store_generation: Some(virtio_driver_store_generation),
                kind: semantic_core::SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![rx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver_virtio_net:rx-queue-wait".to_owned()),
            },
        ),
        CommandEnvelope::new(
            135,
            "target-executor-n7",
            SemanticCommand::RecordIoWait {
                io_wait: 10_016,
                wait: 10_015,
                wait_generation: 1,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                device: 10_001,
                device_generation: 1,
                driver_binding: 10_009,
                driver_binding_generation: 1,
                blocker: rx_queue_ref,
                note: "n7-record-rx-queue-io-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            136,
            "target-executor-n7",
            SemanticCommand::ResolveNetworkRxWait {
                resolution: 10_017,
                io_wait: 10_016,
                io_wait_generation: 1,
                rx_interrupt: 10_014,
                rx_interrupt_generation: 1,
                note: "n7-resolve-rx-wait-from-network-interrupt-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n7 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

fn record_network_runtime_n8_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n8 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n8 evidence")?;
    let packet_device_ref =
        ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 10_002, 1);
    let packet_tx_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "packet-device.net0",
        AuthorityObjectRef::internal(CapabilityClass::PacketDevice, packet_device_ref),
        &["tx"],
        "store",
        "n8-packet-device-tx-capability",
        true,
    );
    let packet_tx_handle = semantic
        .capabilities()
        .record(packet_tx_capability)
        .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
        .ok_or("n8 packet tx capability handle is missing")?;
    let mut forged_tx_handle = packet_tx_handle.clone();
    forged_tx_handle.generation = forged_tx_handle.generation.saturating_add(1);
    let commands = [
        CommandEnvelope::new(
            137,
            "target-executor-n8",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_018,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Tx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: 52,
                sequence: 2,
                state: PacketBufferObjectState::Filled,
                note: "n8-record-tx-packet-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            138,
            "target-executor-n8",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_019,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                packet_buffer: 10_018,
                packet_buffer_generation: 1,
                slot: 0,
                length: 52,
                note: "n8-record-tx-packet-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            139,
            "target-executor-n8",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_020,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: packet_device_ref,
                class: CapabilityClass::PacketDevice,
                operation: "tx".to_owned(),
                handle: packet_tx_handle.clone(),
                note: "n8-record-packet-device-tx-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            140,
            "target-executor-n8",
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate: 10_021,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                packet_descriptor: 10_019,
                packet_descriptor_generation: 1,
                device_capability: 10_020,
                device_capability_generation: 1,
                handle: packet_tx_handle,
                note: "n8-allow-tx-descriptor-through-packet-device-capability".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n8 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let denied = semantic.apply_envelope(CommandEnvelope::new(
        141,
        "target-executor-n8",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 10_022,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 1,
            device_capability: 10_020,
            device_capability_generation: 1,
            handle: forged_tx_handle,
            note: "n8-deny-forged-packet-device-tx-capability-handle".to_owned(),
        },
    ));
    if denied.status != CommandStatus::Rejected
        || !denied
            .violations
            .iter()
            .any(|violation| violation.contains("handle"))
    {
        return Err(format!(
            "network runtime n8 forged tx capability command {} ({}) was not rejected: status={} violations={:?}",
            denied.command_id,
            denied.command,
            denied.status.as_str(),
            denied.violations
        )
        .into());
    }
    Ok(())
}

fn record_network_runtime_n9_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1);
    let command = CommandEnvelope::new(
        142,
        "target-executor-n9",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 10_023,
            tx_gate: 10_021,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 1,
            note: "n9-record-tx-completion-after-capability-gate".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n9 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        143,
        "target-executor-n9",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 10_024,
            tx_gate: 10_021,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 2,
            note: "n9-reject-duplicate-tx-completion-for-gate".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already completed"))
    {
        return Err(format!(
            "network runtime n9 duplicate tx completion command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }
    Ok(())
}

fn record_network_runtime_n10_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_vmos())
        .map_err(|err| format!("network runtime n10 smoltcp adapter evidence failed: {err}"))?;
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1);
    let command = CommandEnvelope::new(
        144,
        "target-executor-n10",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 10_025,
            backend,
            packet_device: 10_002,
            packet_device_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            implementation: evidence.implementation.to_owned(),
            implementation_version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            medium: evidence.medium.to_owned(),
            mac: evidence.hardware_addr,
            ipv4_addr: evidence.ipv4_addr,
            ipv4_prefix_len: evidence.ipv4_prefix_len,
            mtu: evidence.mtu,
            rx_queue_depth: evidence.rx_queue_depth,
            tx_queue_depth: evidence.tx_queue_depth,
            max_payload_len: evidence.max_payload_len,
            socket_capacity: evidence.socket_capacity,
            note: "n10-bind-smoltcp-adapter-to-packet-device".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n10 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        145,
        "target-executor-n10",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 10_026,
            backend,
            packet_device: 10_002,
            packet_device_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            implementation: evidence.implementation.to_owned(),
            implementation_version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            medium: evidence.medium.to_owned(),
            mac: evidence.hardware_addr,
            ipv4_addr: evidence.ipv4_addr,
            ipv4_prefix_len: evidence.ipv4_prefix_len,
            mtu: evidence.mtu,
            rx_queue_depth: evidence.rx_queue_depth,
            tx_queue_depth: evidence.tx_queue_depth,
            max_payload_len: evidence.max_payload_len,
            socket_capacity: evidence.socket_capacity,
            note: "n10-reject-duplicate-smoltcp-adapter".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "network runtime n10 duplicate adapter command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }
    Ok(())
}

fn record_network_runtime_n11_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n11 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n11 evidence")?;
    let command = CommandEnvelope::new(
        146,
        "target-executor-n11",
        SemanticCommand::RecordSocketObject {
            socket: 10_027,
            adapter: 10_025,
            adapter_generation: 1,
            owner_store: linux_socket_store,
            owner_store_generation: linux_socket_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11-record-linux-inet-stream-socket-object".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n11 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let stale_adapter = semantic.apply_envelope(CommandEnvelope::new(
        147,
        "target-executor-n11",
        SemanticCommand::RecordSocketObject {
            socket: 10_028,
            adapter: 10_025,
            adapter_generation: 2,
            owner_store: linux_socket_store,
            owner_store_generation: linux_socket_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11-reject-stale-socket-adapter-generation".to_owned(),
        },
    ));
    if stale_adapter.status != CommandStatus::Rejected
        || !stale_adapter
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n11 stale adapter command {} ({}) was not rejected: status={} violations={:?}",
            stale_adapter.command_id,
            stale_adapter.command,
            stale_adapter.status.as_str(),
            stale_adapter.violations
        )
        .into());
    }
    Ok(())
}

fn record_network_runtime_n12_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let command = CommandEnvelope::new(
        148,
        "target-executor-n12",
        SemanticCommand::RecordEndpointObject {
            endpoint: 10_029,
            socket: 10_027,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12-record-unbound-inet-tcp-endpoint-object".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n12 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let stale_socket = semantic.apply_envelope(CommandEnvelope::new(
        149,
        "target-executor-n12",
        SemanticCommand::RecordEndpointObject {
            endpoint: 10_030,
            socket: 10_027,
            socket_generation: 2,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12-reject-stale-endpoint-socket-generation".to_owned(),
        },
    ));
    if stale_socket.status != CommandStatus::Rejected
        || !stale_socket
            .violations
            .iter()
            .any(|violation| violation.contains("socket generation"))
    {
        return Err(format!(
            "network runtime n12 stale socket command {} ({}) was not rejected: status={} violations={:?}",
            stale_socket.command_id,
            stale_socket.command,
            stale_socket.status.as_str(),
            stale_socket.violations
        )
        .into());
    }
    Ok(())
}

fn record_network_runtime_n13_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n13 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n13 evidence")?;

    let commands = [
        CommandEnvelope::new(
            150,
            "target-executor-n13",
            SemanticCommand::RecordSocketObject {
                socket: 10_031,
                adapter: 10_025,
                adapter_generation: 1,
                owner_store: linux_socket_store,
                owner_store_generation: linux_socket_store_generation,
                domain: 2,
                socket_type: 1,
                protocol: 0,
                note: "n13-record-connected-inet-stream-socket-object".to_owned(),
            },
        ),
        CommandEnvelope::new(
            151,
            "target-executor-n13",
            SemanticCommand::RecordEndpointObject {
                endpoint: 10_032,
                socket: 10_031,
                socket_generation: 1,
                local_addr: [0, 0, 0, 0],
                local_port: 0,
                remote_addr: [0, 0, 0, 0],
                remote_port: 0,
                note: "n13-record-connected-endpoint-object".to_owned(),
            },
        ),
        CommandEnvelope::new(
            152,
            "target-executor-n13",
            SemanticCommand::BindSocketEndpoint {
                operation_id: 10_033,
                endpoint: 10_029,
                endpoint_generation: 1,
                local_addr: [10, 0, 2, 15],
                local_port: 8080,
                sequence: 1,
                note: "n13-bind-listening-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            153,
            "target-executor-n13",
            SemanticCommand::ListenSocketEndpoint {
                operation_id: 10_034,
                endpoint: 10_029,
                endpoint_generation: 1,
                backlog: 16,
                sequence: 2,
                note: "n13-listen-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            154,
            "target-executor-n13",
            SemanticCommand::BindSocketEndpoint {
                operation_id: 10_035,
                endpoint: 10_032,
                endpoint_generation: 1,
                local_addr: [10, 0, 2, 15],
                local_port: 40000,
                sequence: 1,
                note: "n13-bind-connected-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            155,
            "target-executor-n13",
            SemanticCommand::ConnectSocketEndpoint {
                operation_id: 10_036,
                endpoint: 10_032,
                endpoint_generation: 1,
                remote_addr: [10, 0, 2, 2],
                remote_port: 80,
                sequence: 2,
                note: "n13-connect-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            156,
            "target-executor-n13",
            SemanticCommand::SendSocket {
                operation_id: 10_037,
                endpoint: 10_032,
                endpoint_generation: 1,
                byte_len: 18,
                sequence: 3,
                note: "n13-send-socket".to_owned(),
            },
        ),
        CommandEnvelope::new(
            157,
            "target-executor-n13",
            SemanticCommand::RecvSocket {
                operation_id: 10_038,
                endpoint: 10_032,
                endpoint_generation: 1,
                byte_len: 19,
                sequence: 4,
                note: "n13-recv-socket".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n13 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let invalid_send = semantic.apply_envelope(CommandEnvelope::new(
        158,
        "target-executor-n13",
        SemanticCommand::SendSocket {
            operation_id: 10_039,
            endpoint: 10_029,
            endpoint_generation: 1,
            byte_len: 1,
            sequence: 3,
            note: "n13-reject-send-on-listening-endpoint".to_owned(),
        },
    ));
    if invalid_send.status != CommandStatus::Rejected
        || !invalid_send
            .violations
            .iter()
            .any(|violation| violation.contains("connected endpoint"))
    {
        return Err(format!(
            "network runtime n13 invalid send command {} ({}) was not rejected: status={} violations={:?}",
            invalid_send.command_id,
            invalid_send.command,
            invalid_send.status.as_str(),
            invalid_send.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n14_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n14 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n14 evidence")?;
    let connected_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_032, 1);
    let listening_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_029, 1);

    let commands = [
        CommandEnvelope::new(
            159,
            "target-executor-n14",
            SemanticCommand::CreateWait {
                wait: 10_040,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketReadable,
                generation: 1,
                blockers: vec![connected_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("recv-would-block".to_owned()),
            },
        ),
        CommandEnvelope::new(
            160,
            "target-executor-n14",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_041,
                wait: 10_040,
                wait_generation: 1,
                endpoint: 10_032,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketReadable,
                blocker: connected_endpoint,
                note: "n14-record-readable-wait-on-connected-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            161,
            "target-executor-n14",
            SemanticCommand::ResolveSocketWait {
                socket_wait: 10_041,
                socket_wait_generation: 1,
                ready_sequence: 1,
                byte_len: 19,
                note: "n14-resolve-readable-wait".to_owned(),
            },
        ),
        CommandEnvelope::new(
            162,
            "target-executor-n14",
            SemanticCommand::CreateWait {
                wait: 10_042,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketAccept,
                generation: 1,
                blockers: vec![listening_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("accept-would-block".to_owned()),
            },
        ),
        CommandEnvelope::new(
            163,
            "target-executor-n14",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_043,
                wait: 10_042,
                wait_generation: 1,
                endpoint: 10_029,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketAccept,
                blocker: listening_endpoint,
                note: "n14-record-accept-wait-on-listening-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            164,
            "target-executor-n14",
            SemanticCommand::CancelSocketWait {
                socket_wait: 10_043,
                socket_wait_generation: 1,
                errno: 9,
                reason: semantic_core::WaitCancelReason::CloseFd,
                note: "n14-cancel-accept-wait-on-close".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n14 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_wait = semantic.apply_envelope(CommandEnvelope::new(
        165,
        "target-executor-n14",
        SemanticCommand::RecordSocketWait {
            socket_wait: 10_044,
            wait: 10_040,
            wait_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: connected_endpoint,
            note: "n14-reject-record-socket-wait-on-resolved-token".to_owned(),
        },
    ));
    if stale_wait.status != CommandStatus::Rejected
        || !stale_wait
            .violations
            .iter()
            .any(|violation| violation.contains("not pending"))
    {
        return Err(format!(
            "network runtime n14 stale wait command {} ({}) was not rejected: status={} violations={:?}",
            stale_wait.command_id,
            stale_wait.command,
            stale_wait.status.as_str(),
            stale_wait.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n15_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let commands = [
        CommandEnvelope::new(
            166,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_045,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                endpoint: None,
                endpoint_generation: None,
                direction: PacketBufferDirection::Rx,
                reason: NetworkBackpressureReason::QueueHighWatermark,
                action: NetworkBackpressureAction::ThrottleProducer,
                queue_depth: 4,
                queue_limit: 4,
                dropped_packets: 0,
                dropped_bytes: 0,
                sequence: 1,
                note: "n15-rx-high-watermark-throttle-producer".to_owned(),
            },
        ),
        CommandEnvelope::new(
            167,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_046,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                endpoint: Some(10_032),
                endpoint_generation: Some(1),
                direction: PacketBufferDirection::Tx,
                reason: NetworkBackpressureReason::QueueFull,
                action: NetworkBackpressureAction::RejectSend,
                queue_depth: 4,
                queue_limit: 4,
                dropped_packets: 0,
                dropped_bytes: 0,
                sequence: 2,
                note: "n15-tx-queue-full-reject-send".to_owned(),
            },
        ),
        CommandEnvelope::new(
            168,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_047,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                endpoint: None,
                endpoint_generation: None,
                direction: PacketBufferDirection::Rx,
                reason: NetworkBackpressureReason::QueueFull,
                action: NetworkBackpressureAction::DropNewest,
                queue_depth: 5,
                queue_limit: 4,
                dropped_packets: 1,
                dropped_bytes: 1514,
                sequence: 3,
                note: "n15-rx-queue-full-drop-newest".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n15 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let invalid_drop = semantic.apply_envelope(CommandEnvelope::new(
        169,
        "target-executor-n15",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 10_048,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_004,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 1514,
            sequence: 4,
            note: "n15-reject-drop-without-packet-count".to_owned(),
        },
    ));
    if invalid_drop.status != CommandStatus::Rejected
        || !invalid_drop
            .violations
            .iter()
            .any(|violation| violation.contains("drop action"))
    {
        return Err(format!(
            "network runtime n15 invalid drop command {} ({}) was not rejected: status={} violations={:?}",
            invalid_drop.command_id,
            invalid_drop.command,
            invalid_drop.status.as_str(),
            invalid_drop.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n16_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n16 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n16 evidence")?;
    let connected_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_032, 1);
    let commands = [
        CommandEnvelope::new(
            186,
            "target-executor-n16",
            SemanticCommand::CreateWait {
                wait: 10_049,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketReadable,
                generation: 1,
                blockers: vec![connected_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("n16-recv-would-block-before-driver-fault".to_owned()),
            },
        ),
        CommandEnvelope::new(
            187,
            "target-executor-n16",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_050,
                wait: 10_049,
                wait_generation: 1,
                endpoint: 10_032,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketReadable,
                blocker: connected_endpoint,
                note: "n16-record-pending-socket-wait-before-driver-cleanup".to_owned(),
            },
        ),
        CommandEnvelope::new(
            188,
            "target-executor-n16",
            SemanticCommand::CleanupNetworkDriver {
                cleanup: 10_051,
                io_cleanup: 10_052,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                backend: ContractObjectRef::new(
                    ContractObjectKind::VirtioNetBackendObject,
                    10_010,
                    1,
                ),
                reason: "device-fault".to_owned(),
                note: "n16-cleanup-virtio-net-driver-fault".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n16 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        189,
        "target-executor-n16",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 10_053,
            io_cleanup: 10_054,
            adapter: 10_025,
            adapter_generation: 2,
            packet_device: 10_002,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1),
            reason: "device-fault".to_owned(),
            note: "n16-reject-stale-adapter-cleanup".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n16 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n19_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        190,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_067,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-record-host-validation-network-throughput-latency-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n19 benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_adapter = semantic.apply_envelope(CommandEnvelope::new(
        191,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_068,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 2,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-reject-stale-adapter-generation".to_owned(),
        },
    ));
    if stale_adapter.status != CommandStatus::Rejected
        || !stale_adapter
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n19 stale adapter command {} ({}) was not rejected: status={} violations={:?}",
            stale_adapter.command_id,
            stale_adapter.command,
            stale_adapter.status.as_str(),
            stale_adapter.violations
        )
        .into());
    }

    let budget_overrun = semantic.apply_envelope(CommandEnvelope::new(
        192,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_069,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 260_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-reject-network-benchmark-over-budget".to_owned(),
        },
    ));
    if budget_overrun.status != CommandStatus::Rejected
        || !budget_overrun
            .violations
            .iter()
            .any(|violation| violation.contains("exceeds latency budget"))
    {
        return Err(format!(
            "network runtime n19 budget command {} ({}) was not rejected: status={} violations={:?}",
            budget_overrun.command_id,
            budget_overrun.command,
            budget_overrun.status.as_str(),
            budget_overrun.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n20_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let cleanup = semantic
        .network_driver_cleanups()
        .iter()
        .find(|record| record.id == 10_051 && record.generation == 1)
        .cloned()
        .ok_or("network driver cleanup 10051@1 is missing for n20 evidence")?;
    let cleanup_complete_event = cleanup
        .completed_at_event
        .ok_or("network driver cleanup completion event is missing for n20 evidence")?;
    let cancelled_socket_waits = cleanup.cancelled_socket_waits.len() as u32;
    let revoked_packet_capabilities = cleanup.revoked_packet_capabilities.len() as u32;
    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        193,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_068,
            scenario: "host-validation-network-driver-recovery".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20-record-host-validation-network-recovery-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n20 recovery benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        194,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_069,
            scenario: "stale cleanup generation cannot record recovery benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation.saturating_add(1),
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20-reject-stale-cleanup-generation".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("cleanup generation"))
    {
        return Err(format!(
            "network runtime n20 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    let budget_overrun = semantic.apply_envelope(CommandEnvelope::new(
        195,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_069,
            scenario: "recovery budget overrun cannot record benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 210_000,
            budget_nanos: 200_000,
            note: "n20-reject-recovery-budget-overrun".to_owned(),
        },
    ));
    if budget_overrun.status != CommandStatus::Rejected
        || !budget_overrun
            .violations
            .iter()
            .any(|violation| violation.contains("recovery budget"))
    {
        return Err(format!(
            "network runtime n20 budget command {} ({}) was not rejected: status={} violations={:?}",
            budget_overrun.command_id,
            budget_overrun.command,
            budget_overrun.status.as_str(),
            budget_overrun.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n17_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n17 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n17 evidence")?;

    let dma_resource = semantic.register_resource(
        ResourceKind::DmaBuffer,
        None,
        "dma:virtio-net0-tx-stale-probe",
    );
    let dma_resource_generation = semantic
        .resource_handle(dma_resource)
        .map(|handle| handle.generation)
        .ok_or("n17 dma resource handle is missing")?;
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 10_057, 1);
    let dma_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "dma.virtio-net0.tx-stale-probe",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "n17-dma-generation-capability",
        true,
    );
    let dma_handle = semantic
        .capabilities()
        .record(dma_capability)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_owned()]))
        .ok_or("n17 dma capability handle is missing")?;

    let setup_commands = [
        CommandEnvelope::new(
            170,
            "target-executor-n17",
            SemanticCommand::RecordQueueObject {
                queue: 10_055,
                name: "virtio-net0-tx-dma".to_owned(),
                role: QueueObjectRole::Tx,
                queue_index: 1,
                depth: 4,
                device: 10_001,
                device_generation: 1,
                note: "n17-record-dma-queue-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            171,
            "target-executor-n17",
            SemanticCommand::RecordDescriptorObject {
                descriptor: 10_056,
                queue: 10_055,
                queue_generation: 1,
                slot: 0,
                access: DescriptorObjectAccess::ReadWrite,
                length: 2048,
                note: "n17-record-dma-descriptor-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            172,
            "target-executor-n17",
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer: 10_057,
                descriptor: 10_056,
                descriptor_generation: 1,
                resource: dma_resource,
                resource_generation: dma_resource_generation,
                access: DmaBufferObjectAccess::ReadWrite,
                length: 2048,
                note: "n17-record-dma-buffer-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            173,
            "target-executor-n17",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_058,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: dma_ref,
                class: CapabilityClass::DmaBuffer,
                operation: "sync-for-device".to_owned(),
                handle: dma_handle.clone(),
                note: "n17-record-dma-capability-fixture".to_owned(),
            },
        ),
    ];
    for command in setup_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n17 setup command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_packet_buffer = semantic.apply_envelope(CommandEnvelope::new(
        174,
        "target-executor-n17",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 10_059,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_buffer: 10_018,
            packet_buffer_generation: 2,
            slot: 1,
            length: 52,
            note: "n17-reject-stale-packet-buffer-generation".to_owned(),
        },
    ));
    if stale_packet_buffer.status != CommandStatus::Rejected
        || !stale_packet_buffer
            .violations
            .iter()
            .any(|violation| violation.contains("buffer generation"))
    {
        return Err(format!(
            "network runtime n17 stale packet buffer command {} ({}) was not rejected: status={} violations={:?}",
            stale_packet_buffer.command_id,
            stale_packet_buffer.command,
            stale_packet_buffer.status.as_str(),
            stale_packet_buffer.violations
        )
        .into());
    }

    let stale_packet_descriptor = semantic.apply_envelope(CommandEnvelope::new(
        175,
        "target-executor-n17",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 10_060,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 2,
            device_capability: 10_020,
            device_capability_generation: 1,
            handle: semantic
                .device_capabilities()
                .iter()
                .find(|record| record.id == 10_020)
                .and_then(|record| semantic.capabilities().record(record.capability))
                .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
                .ok_or("n17 packet tx capability handle is missing")?,
            note: "n17-reject-stale-packet-descriptor-generation".to_owned(),
        },
    ));
    if stale_packet_descriptor.status != CommandStatus::Rejected
        || !stale_packet_descriptor
            .violations
            .iter()
            .any(|violation| violation.contains("descriptor generation"))
    {
        return Err(format!(
            "network runtime n17 stale packet descriptor command {} ({}) was not rejected: status={} violations={:?}",
            stale_packet_descriptor.command_id,
            stale_packet_descriptor.command,
            stale_packet_descriptor.status.as_str(),
            stale_packet_descriptor.violations
        )
        .into());
    }

    let stale_dma_target = semantic.apply_envelope(CommandEnvelope::new(
        176,
        "target-executor-n17",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 10_061,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 10_057, 2),
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_owned(),
            handle: dma_handle,
            note: "n17-reject-stale-dma-buffer-generation".to_owned(),
        },
    ));
    if stale_dma_target.status != CommandStatus::Rejected
        || !stale_dma_target
            .violations
            .iter()
            .any(|violation| violation.contains("target generation"))
    {
        return Err(format!(
            "network runtime n17 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma_target.command_id,
            stale_dma_target.command,
            stale_dma_target.status.as_str(),
            stale_dma_target.violations
        )
        .into());
    }

    let audit = semantic.apply_envelope(CommandEnvelope::new(
        177,
        "target-executor-n17",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 10_062,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 1,
            packet_buffer: 10_018,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: ContractObjectRef::new(
                ContractObjectKind::DeviceCapability,
                10_058,
                1,
            ),
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17-record-stale-packet-dma-generation-audit".to_owned(),
        },
    ));
    if audit.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n17 audit command {} ({}) failed: status={} violations={:?}",
            audit.command_id,
            audit.command,
            audit.status.as_str(),
            audit.violations
        )
        .into());
    }

    Ok(())
}

fn record_network_runtime_n18_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let packet_loss = semantic.apply_envelope(CommandEnvelope::new(
        182,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_063,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 18,
            note: "n18-inject-tx-packet-loss".to_owned(),
        },
    ));
    if packet_loss.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n18 packet loss command {} ({}) failed: status={} violations={:?}",
            packet_loss.command_id,
            packet_loss.command,
            packet_loss.status.as_str(),
            packet_loss.violations
        )
        .into());
    }

    let packet_error = semantic.apply_envelope(CommandEnvelope::new(
        183,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_064,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_owned(),
            sequence: 19,
            note: "n18-inject-tx-packet-error".to_owned(),
        },
    ));
    if packet_error.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n18 packet error command {} ({}) failed: status={} violations={:?}",
            packet_error.command_id,
            packet_error.command,
            packet_error.status.as_str(),
            packet_error.violations
        )
        .into());
    }

    let stale_queue = semantic.apply_envelope(CommandEnvelope::new(
        184,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_065,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 2,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 20,
            note: "n18-reject-stale-queue-generation".to_owned(),
        },
    ));
    if stale_queue.status != CommandStatus::Rejected
        || !stale_queue
            .violations
            .iter()
            .any(|violation| violation.contains("packet queue generation"))
    {
        return Err(format!(
            "network runtime n18 stale queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_queue.command_id,
            stale_queue.command,
            stale_queue.status.as_str(),
            stale_queue.violations
        )
        .into());
    }

    let malformed_error = semantic.apply_envelope(CommandEnvelope::new(
        185,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_066,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_owned(),
            sequence: 21,
            note: "n18-reject-malformed-packet-error-injection".to_owned(),
        },
    ));
    if malformed_error.status != CommandStatus::Rejected
        || !malformed_error
            .violations
            .iter()
            .any(|violation| violation.contains("packet error injection requires endpoint"))
    {
        return Err(format!(
            "network runtime n18 malformed error command {} ({}) was not rejected: status={} violations={:?}",
            malformed_error.command_id,
            malformed_error.command,
            malformed_error.status.as_str(),
            malformed_error.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b0_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let block_resource =
        semantic.register_resource(ResourceKind::BlockDevice, None, "block-device:fake-block0");
    let block_resource_generation = semantic
        .resource_handle(block_resource)
        .map(|handle| handle.generation)
        .ok_or("b0 block device resource handle is missing")?;
    if !semantic.record_device_object_with_id(
        20_001,
        "fake-block0",
        "block-device",
        block_resource,
        block_resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b0-record-block-backing-device",
    ) {
        return Err("b0 block backing device could not be recorded".into());
    }

    let block_device = semantic.apply_envelope(CommandEnvelope::new(
        196,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_002,
            name: "blk0".to_owned(),
            device: 20_001,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-record-block-device-object-harness".to_owned(),
        },
    ));
    if block_device.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b0 block device command {} ({}) failed: status={} violations={:?}",
            block_device.command_id,
            block_device.command,
            block_device.status.as_str(),
            block_device.violations
        )
        .into());
    }

    let stale_device = semantic.apply_envelope(CommandEnvelope::new(
        197,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_003,
            name: "blk0-stale".to_owned(),
            device: 20_001,
            device_generation: 2,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-reject-stale-device-generation".to_owned(),
        },
    ));
    if stale_device.status != CommandStatus::Rejected
        || !stale_device
            .violations
            .iter()
            .any(|violation| violation.contains("device generation"))
    {
        return Err(format!(
            "block runtime b0 stale device command {} ({}) was not rejected: status={} violations={:?}",
            stale_device.command_id,
            stale_device.command,
            stale_device.status.as_str(),
            stale_device.violations
        )
        .into());
    }

    let bad_contract = semantic.apply_envelope(CommandEnvelope::new(
        198,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_004,
            name: "blk0-bad-sector".to_owned(),
            device: 20_001,
            device_generation: 1,
            sector_size: 0,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-reject-zero-sector-size".to_owned(),
        },
    ));
    if bad_contract.status != CommandStatus::Rejected
        || !bad_contract
            .violations
            .iter()
            .any(|violation| violation.contains("contract values"))
    {
        return Err(format!(
            "block runtime b0 bad contract command {} ({}) was not rejected: status={} violations={:?}",
            bad_contract.command_id,
            bad_contract.command,
            bad_contract.status.as_str(),
            bad_contract.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b1_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let block_range = semantic.apply_envelope(CommandEnvelope::new(
        199,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_005,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 64,
            sector_count: 8,
            note: "b1-record-sector-range-with-derived-byte-bounds".to_owned(),
        },
    ));
    if block_range.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b1 block range command {} ({}) failed: status={} violations={:?}",
            block_range.command_id,
            block_range.command,
            block_range.status.as_str(),
            block_range.violations
        )
        .into());
    }

    let stale_device = semantic.apply_envelope(CommandEnvelope::new(
        200,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_006,
            block_device: 20_002,
            block_device_generation: 2,
            start_sector: 64,
            sector_count: 8,
            note: "b1-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_device.status != CommandStatus::Rejected
        || !stale_device
            .violations
            .iter()
            .any(|violation| violation.contains("block device generation"))
    {
        return Err(format!(
            "block runtime b1 stale device command {} ({}) was not rejected: status={} violations={:?}",
            stale_device.command_id,
            stale_device.command,
            stale_device.status.as_str(),
            stale_device.violations
        )
        .into());
    }

    let out_of_bounds = semantic.apply_envelope(CommandEnvelope::new(
        201,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_007,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 4090,
            sector_count: 16,
            note: "b1-reject-sector-range-beyond-device".to_owned(),
        },
    ));
    if out_of_bounds.status != CommandStatus::Rejected
        || !out_of_bounds
            .violations
            .iter()
            .any(|violation| violation.contains("beyond block device"))
    {
        return Err(format!(
            "block runtime b1 out-of-bounds command {} ({}) was not rejected: status={} violations={:?}",
            out_of_bounds.command_id,
            out_of_bounds.command,
            out_of_bounds.status.as_str(),
            out_of_bounds.violations
        )
        .into());
    }

    let over_transfer = semantic.apply_envelope(CommandEnvelope::new(
        202,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_008,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 128,
            sector_count: 129,
            note: "b1-reject-range-over-max-transfer".to_owned(),
        },
    ));
    if over_transfer.status != CommandStatus::Rejected
        || !over_transfer
            .violations
            .iter()
            .any(|violation| violation.contains("max transfer"))
    {
        return Err(format!(
            "block runtime b1 over-transfer command {} ({}) was not rejected: status={} violations={:?}",
            over_transfer.command_id,
            over_transfer.command,
            over_transfer.status.as_str(),
            over_transfer.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b2_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let request = semantic.apply_envelope(CommandEnvelope::new(
        203,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_009,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2-record-read-request-over-sector-range".to_owned(),
        },
    ));
    if request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b2 request command {} ({}) failed: status={} violations={:?}",
            request.command_id,
            request.command,
            request.status.as_str(),
            request.violations
        )
        .into());
    }

    let stale_range = semantic.apply_envelope(CommandEnvelope::new(
        204,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_010,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 2,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b2-reject-stale-range-generation".to_owned(),
        },
    ));
    if stale_range.status != CommandStatus::Rejected
        || !stale_range
            .violations
            .iter()
            .any(|violation| violation.contains("block range generation"))
    {
        return Err(format!(
            "block runtime b2 stale range command {} ({}) was not rejected: status={} violations={:?}",
            stale_range.command_id,
            stale_range.command,
            stale_range.status.as_str(),
            stale_range.violations
        )
        .into());
    }

    let mismatched_device = semantic.apply_envelope(CommandEnvelope::new(
        205,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_011,
            block_device: 20_003,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 3,
            note: "b2-reject-request-device-mismatch".to_owned(),
        },
    ));
    if mismatched_device.status != CommandStatus::Rejected
        || !mismatched_device
            .violations
            .iter()
            .any(|violation| violation.contains("block device generation"))
    {
        return Err(format!(
            "block runtime b2 mismatched device command {} ({}) was not rejected: status={} violations={:?}",
            mismatched_device.command_id,
            mismatched_device.command,
            mismatched_device.status.as_str(),
            mismatched_device.violations
        )
        .into());
    }

    let duplicate_sequence = semantic.apply_envelope(CommandEnvelope::new(
        206,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_012,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2-reject-duplicate-request-sequence".to_owned(),
        },
    ));
    if duplicate_sequence.status != CommandStatus::Rejected
        || !duplicate_sequence
            .violations
            .iter()
            .any(|violation| violation.contains("sequence already exists"))
    {
        return Err(format!(
            "block runtime b2 duplicate sequence command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_sequence.command_id,
            duplicate_sequence.command,
            duplicate_sequence.status.as_str(),
            duplicate_sequence.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b3_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let completion = semantic.apply_envelope(CommandEnvelope::new(
        207,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_013,
            block_request: 20_009,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-record-completion-for-read-request".to_owned(),
        },
    ));
    if completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b3 completion command {} ({}) failed: status={} violations={:?}",
            completion.command_id,
            completion.command,
            completion.status.as_str(),
            completion.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        208,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_014,
            block_request: 20_009,
            block_request_generation: 2,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("block request generation"))
    {
        return Err(format!(
            "block runtime b3 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    let duplicate_completion = semantic.apply_envelope(CommandEnvelope::new(
        209,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_015,
            block_request: 20_009,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-duplicate-completion".to_owned(),
        },
    ));
    if duplicate_completion.status != CommandStatus::Rejected
        || !duplicate_completion.violations.iter().any(|violation| {
            violation.contains("not submitted") || violation.contains("already exists")
        })
    {
        return Err(format!(
            "block runtime b3 duplicate completion command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_completion.command_id,
            duplicate_completion.command,
            duplicate_completion.status.as_str(),
            duplicate_completion.violations
        )
        .into());
    }

    let second_request = semantic.apply_envelope(CommandEnvelope::new(
        210,
        "target-executor-b3",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_017,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b3-record-second-request-for-byte-count-negative".to_owned(),
        },
    ));
    if second_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b3 second request command {} ({}) failed: status={} violations={:?}",
            second_request.command_id,
            second_request.command,
            second_request.status.as_str(),
            second_request.violations
        )
        .into());
    }

    let bad_byte_count = semantic.apply_envelope(CommandEnvelope::new(
        211,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_016,
            block_request: 20_017,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 2048,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-partial-success".to_owned(),
        },
    ));
    if bad_byte_count.status != CommandStatus::Rejected
        || !bad_byte_count
            .violations
            .iter()
            .any(|violation| violation.contains("full byte range"))
    {
        return Err(format!(
            "block runtime b3 bad byte count command {} ({}) was not rejected: status={} violations={:?}",
            bad_byte_count.command_id,
            bad_byte_count.command,
            bad_byte_count.status.as_str(),
            bad_byte_count.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b4_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let block_driver_store = semantic.register_store(
        "b4.block.driver",
        "b4-block-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(block_driver_store, StoreState::Running);
    let block_driver_store_generation = semantic
        .store_handle(block_driver_store)
        .map(|handle| handle.generation)
        .ok_or("b4 block driver store handle is missing")?;
    let pending_request_ref =
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 20_017, 1);
    let create_wait = semantic.apply_envelope(CommandEnvelope::new(
        212,
        "target-executor-b4",
        SemanticCommand::CreateWait {
            wait: 20_018,
            owner_task: None,
            owner_store: Some(block_driver_store),
            owner_store_generation: Some(block_driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![pending_request_ref],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-request-pending-completion".to_owned()),
        },
    ));
    if create_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 create wait command {} ({}) failed: status={} violations={:?}",
            create_wait.command_id,
            create_wait.command,
            create_wait.status.as_str(),
            create_wait.violations
        )
        .into());
    }

    let record_wait = semantic.apply_envelope(CommandEnvelope::new(
        213,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_019,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 1,
            note: "b4-record-block-wait-for-request".to_owned(),
        },
    ));
    if record_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 block wait command {} ({}) failed: status={} violations={:?}",
            record_wait.command_id,
            record_wait.command,
            record_wait.status.as_str(),
            record_wait.violations
        )
        .into());
    }

    let duplicate_wait = semantic.apply_envelope(CommandEnvelope::new(
        214,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_020,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 1,
            note: "b4-reject-duplicate-block-wait".to_owned(),
        },
    ));
    if duplicate_wait.status != CommandStatus::Rejected
        || !duplicate_wait
            .violations
            .iter()
            .any(|violation| violation.contains("pending block wait"))
    {
        return Err(format!(
            "block runtime b4 duplicate wait command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_wait.command_id,
            duplicate_wait.command,
            duplicate_wait.status.as_str(),
            duplicate_wait.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        215,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_021,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 2,
            note: "b4-reject-stale-block-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request.violations.iter().any(|violation| {
            violation.contains("block request") || violation.contains("block wait token")
        })
    {
        return Err(format!(
            "block runtime b4 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    let completion = semantic.apply_envelope(CommandEnvelope::new(
        216,
        "target-executor-b4",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_022,
            block_request: 20_017,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b4-record-completion-for-waited-request".to_owned(),
        },
    ));
    if completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 completion command {} ({}) failed: status={} violations={:?}",
            completion.command_id,
            completion.command,
            completion.status.as_str(),
            completion.violations
        )
        .into());
    }

    let resolve_wait = semantic.apply_envelope(CommandEnvelope::new(
        217,
        "target-executor-b4",
        SemanticCommand::ResolveBlockWait {
            block_wait: 20_019,
            block_wait_generation: 1,
            block_completion: 20_022,
            block_completion_generation: 1,
            note: "b4-resolve-block-wait-through-completion".to_owned(),
        },
    ));
    if resolve_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 resolve wait command {} ({}) failed: status={} violations={:?}",
            resolve_wait.command_id,
            resolve_wait.command,
            resolve_wait.status.as_str(),
            resolve_wait.violations
        )
        .into());
    }

    let cancel_request = semantic.apply_envelope(CommandEnvelope::new(
        218,
        "target-executor-b4",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_023,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 3,
            note: "b4-record-cancellable-block-request".to_owned(),
        },
    ));
    if cancel_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 cancel request command {} ({}) failed: status={} violations={:?}",
            cancel_request.command_id,
            cancel_request.command,
            cancel_request.status.as_str(),
            cancel_request.violations
        )
        .into());
    }
    let cancel_request_ref =
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 20_023, 1);
    let create_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        219,
        "target-executor-b4",
        SemanticCommand::CreateWait {
            wait: 20_024,
            owner_task: None,
            owner_store: Some(block_driver_store),
            owner_store_generation: Some(block_driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![cancel_request_ref],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-request-device-fault".to_owned()),
        },
    ));
    if create_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 create cancel wait command {} ({}) failed: status={} violations={:?}",
            create_cancel_wait.command_id,
            create_cancel_wait.command,
            create_cancel_wait.status.as_str(),
            create_cancel_wait.violations
        )
        .into());
    }
    let record_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        220,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_025,
            wait: 20_024,
            wait_generation: 1,
            block_request: 20_023,
            block_request_generation: 1,
            note: "b4-record-cancellable-block-wait".to_owned(),
        },
    ));
    if record_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 record cancel wait command {} ({}) failed: status={} violations={:?}",
            record_cancel_wait.command_id,
            record_cancel_wait.command,
            record_cancel_wait.status.as_str(),
            record_cancel_wait.violations
        )
        .into());
    }
    let cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        221,
        "target-executor-b4",
        SemanticCommand::CancelBlockWait {
            block_wait: 20_025,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4-cancel-block-wait-on-device-fault".to_owned(),
        },
    ));
    if cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 cancel wait command {} ({}) failed: status={} violations={:?}",
            cancel_wait.command_id,
            cancel_wait.command,
            cancel_wait.status.as_str(),
            cancel_wait.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b5_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let bind_backend = semantic.apply_envelope(CommandEnvelope::new(
        222,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_026,
            name: "fake-block0".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-bind-fake-block-backend".to_owned(),
        },
    ));
    if bind_backend.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b5 bind fake backend command {} ({}) failed: status={} violations={:?}",
            bind_backend.command_id,
            bind_backend.command,
            bind_backend.status.as_str(),
            bind_backend.violations
        )
        .into());
    }

    let duplicate_backend = semantic.apply_envelope(CommandEnvelope::new(
        223,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_027,
            name: "fake-block0-duplicate".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-duplicate-fake-block-backend".to_owned(),
        },
    ));
    if duplicate_backend.status != CommandStatus::Rejected
        || !duplicate_backend
            .violations
            .iter()
            .any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "block runtime b5 duplicate fake backend command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_backend.command_id,
            duplicate_backend.command,
            duplicate_backend.status.as_str(),
            duplicate_backend.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        224,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_028,
            name: "fake-block0-stale".to_owned(),
            block_device: 20_002,
            block_device_generation: 2,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend.violations.iter().any(|violation| {
            violation.contains("block device generation") || violation.contains("missing")
        })
    {
        return Err(format!(
            "block runtime b5 stale fake backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let mismatched_backend = semantic.apply_envelope(CommandEnvelope::new(
        225,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_029,
            name: "fake-block0-mismatched".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count.saturating_add(1),
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-contract-mismatch".to_owned(),
        },
    ));
    if mismatched_backend.status != CommandStatus::Rejected
        || !mismatched_backend
            .violations
            .iter()
            .any(|violation| violation.contains("contract does not match"))
    {
        return Err(format!(
            "block runtime b5 mismatched fake backend command {} ({}) was not rejected: status={} violations={:?}",
            mismatched_backend.command_id,
            mismatched_backend.command,
            mismatched_backend.status.as_str(),
            mismatched_backend.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b6_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let config = VirtioBlkBackendConfig::blk0();
    let block_resource =
        semantic.register_resource(ResourceKind::BlockDevice, None, "block-device:virtio-blk0");
    let block_resource_generation = semantic
        .resource_handle(block_resource)
        .map(|handle| handle.generation)
        .ok_or("b6 virtio block device resource handle is missing")?;
    if !semantic.record_device_object_with_id(
        20_030,
        "virtio-blk0",
        "block-device",
        block_resource,
        block_resource_generation,
        "virtio-blk-backend-skeleton",
        "virtio-mmio",
        "virtio",
        VIRTIO_BLK_BACKEND_MODEL,
        "b6-record-virtio-block-backing-device",
    ) {
        return Err("b6 virtio block backing device could not be recorded".into());
    }

    let block_device = semantic.apply_envelope(CommandEnvelope::new(
        226,
        "target-executor-b6",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_031,
            name: "vblk0".to_owned(),
            device: 20_030,
            device_generation: 1,
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            note: "b6-record-virtio-block-device-object".to_owned(),
        },
    ));
    if block_device.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b6 block device command {} ({}) failed: status={} violations={:?}",
            block_device.command_id,
            block_device.command,
            block_device.status.as_str(),
            block_device.violations
        )
        .into());
    }

    let block_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for b6 evidence")?;
    let block_driver_store_generation = semantic
        .store_handle(block_driver_store)
        .map(|handle| handle.generation)
        .ok_or("b6 block driver store handle is missing")?;
    let virtio_device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 20_030, 1);
    let virtio_device_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "device.virtio-blk0",
        AuthorityObjectRef::internal(CapabilityClass::Device, virtio_device_ref),
        &["probe"],
        "store",
        "b6-virtio-blk-device-capability",
        true,
    );
    let virtio_device_handle = semantic
        .capabilities()
        .record(virtio_device_capability)
        .and_then(|record| record.store_local_handle(vec!["probe".to_owned()]))
        .ok_or("b6 virtio block device capability handle is missing")?;

    let commands = [
        CommandEnvelope::new(
            227,
            "target-executor-b6",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 20_032,
                driver_store: block_driver_store,
                driver_store_generation: block_driver_store_generation,
                target: virtio_device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: virtio_device_handle,
                note: "b6-record-virtio-block-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            228,
            "target-executor-b6",
            SemanticCommand::BindDriverStore {
                binding: 20_033,
                driver_store: block_driver_store,
                driver_store_generation: block_driver_store_generation,
                device: 20_030,
                device_generation: 1,
                device_capability: 20_032,
                device_capability_generation: 1,
                note: "b6-bind-virtio-block-driver-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            229,
            "target-executor-b6",
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend: 20_034,
                name: "virtio-blk0-backend".to_owned(),
                block_device: 20_031,
                block_device_generation: 1,
                driver_binding: 20_033,
                driver_binding_generation: 1,
                provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
                profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
                model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
                sector_size: config.sector_size,
                sector_count: config.sector_count,
                read_only: config.read_only,
                max_transfer_sectors: config.max_transfer_sectors,
                device_features: config.device_features,
                driver_features: config.driver_features,
                negotiated_features: config.negotiated_features,
                request_queue_index: config.request_queue_index,
                queue_size: config.queue_size,
                irq_vector: config.irq_vector,
                note: "b6-bind-virtio-block-backend-skeleton-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b6 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let duplicate_backend = semantic.apply_envelope(CommandEnvelope::new(
        230,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_035,
            name: "virtio-blk0-backend-duplicate".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-duplicate-virtio-block-backend".to_owned(),
        },
    ));
    if duplicate_backend.status != CommandStatus::Rejected
        || !duplicate_backend
            .violations
            .iter()
            .any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "block runtime b6 duplicate backend command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_backend.command_id,
            duplicate_backend.command,
            duplicate_backend.status.as_str(),
            duplicate_backend.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        231,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_036,
            name: "virtio-blk0-backend-stale".to_owned(),
            block_device: 20_031,
            block_device_generation: 2,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend.violations.iter().any(|violation| {
            violation.contains("block device generation") || violation.contains("missing")
        })
    {
        return Err(format!(
            "block runtime b6 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let stale_binding = semantic.apply_envelope(CommandEnvelope::new(
        232,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_037,
            name: "virtio-blk0-backend-stale-binding".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 2,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-stale-driver-binding-generation".to_owned(),
        },
    ));
    if stale_binding.status != CommandStatus::Rejected
        || !stale_binding
            .violations
            .iter()
            .any(|violation| violation.contains("driver binding generation"))
    {
        return Err(format!(
            "block runtime b6 stale binding command {} ({}) was not rejected: status={} violations={:?}",
            stale_binding.command_id,
            stale_binding.command,
            stale_binding.status.as_str(),
            stale_binding.violations
        )
        .into());
    }

    let feature_mismatch = semantic.apply_envelope(CommandEnvelope::new(
        233,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_038,
            name: "virtio-blk0-backend-feature-mismatch".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.device_features | (1 << 63),
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-feature-negotiation-mismatch".to_owned(),
        },
    ));
    if feature_mismatch.status != CommandStatus::Rejected
        || !feature_mismatch
            .violations
            .iter()
            .any(|violation| violation.contains("negotiated features"))
    {
        return Err(format!(
            "block runtime b6 feature mismatch command {} ({}) was not rejected: status={} violations={:?}",
            feature_mismatch.command_id,
            feature_mismatch.command,
            feature_mismatch.status.as_str(),
            feature_mismatch.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b7_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let data_digest = SemanticGraph::expected_block_read_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        64,
        8,
        1,
        4096,
    );
    let read_path = semantic.apply_envelope(CommandEnvelope::new(
        234,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_039,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-record-block-read-path-through-fake-backend".to_owned(),
        },
    ));
    if read_path.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 read path command {} ({}) failed: status={} violations={:?}",
            read_path.command_id,
            read_path.command,
            read_path.status.as_str(),
            read_path.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        235,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_040,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-duplicate-read-path".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already exists for request generation"))
    {
        return Err(format!(
            "block runtime b7 duplicate read path command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        236,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_041,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b7 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let write_request = semantic.apply_envelope(CommandEnvelope::new(
        237,
        "target-executor-b7",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_042,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 4,
            note: "b7-record-write-request-for-read-path-negative".to_owned(),
        },
    ));
    if write_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 write request command {} ({}) failed: status={} violations={:?}",
            write_request.command_id,
            write_request.command,
            write_request.status.as_str(),
            write_request.violations
        )
        .into());
    }
    let write_completion = semantic.apply_envelope(CommandEnvelope::new(
        238,
        "target-executor-b7",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_043,
            block_request: 20_042,
            block_request_generation: 1,
            sequence: 4,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b7-record-write-completion-for-read-path-negative".to_owned(),
        },
    ));
    if write_completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 write completion command {} ({}) failed: status={} violations={:?}",
            write_completion.command_id,
            write_completion.command,
            write_completion.status.as_str(),
            write_completion.violations
        )
        .into());
    }
    let write_not_read = semantic.apply_envelope(CommandEnvelope::new(
        239,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_044,
            backend,
            block_request: 20_042,
            block_request_generation: 1,
            block_completion: 20_043,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-write-request-as-read-path".to_owned(),
        },
    ));
    if write_not_read.status != CommandStatus::Rejected
        || !write_not_read
            .violations
            .iter()
            .any(|violation| violation.contains("operation is not read"))
    {
        return Err(format!(
            "block runtime b7 write-as-read command {} ({}) was not rejected: status={} violations={:?}",
            write_not_read.command_id,
            write_not_read.command,
            write_not_read.status.as_str(),
            write_not_read.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        240,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_045,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest: data_digest.wrapping_add(1),
            note: "b7-reject-data-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest
            .violations
            .iter()
            .any(|violation| violation.contains("data digest mismatch"))
    {
        return Err(format!(
            "block runtime b7 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b8_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let write_request = semantic.apply_envelope(CommandEnvelope::new(
        241,
        "target-executor-b8",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_046,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 5,
            note: "b8-record-write-request".to_owned(),
        },
    ));
    if write_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write request command {} ({}) failed: status={} violations={:?}",
            write_request.command_id,
            write_request.command,
            write_request.status.as_str(),
            write_request.violations
        )
        .into());
    }
    let write_completion = semantic.apply_envelope(CommandEnvelope::new(
        242,
        "target-executor-b8",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_047,
            block_request: 20_046,
            block_request_generation: 1,
            sequence: 5,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b8-record-write-completion".to_owned(),
        },
    ));
    if write_completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write completion command {} ({}) failed: status={} violations={:?}",
            write_completion.command_id,
            write_completion.command,
            write_completion.status.as_str(),
            write_completion.violations
        )
        .into());
    }
    let payload_digest = SemanticGraph::expected_block_write_payload_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        64,
        8,
        5,
        4096,
    );
    let write_path = semantic.apply_envelope(CommandEnvelope::new(
        243,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_048,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-record-block-write-path-through-fake-backend".to_owned(),
        },
    ));
    if write_path.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write path command {} ({}) failed: status={} violations={:?}",
            write_path.command_id,
            write_path.command,
            write_path.status.as_str(),
            write_path.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        244,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_049,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-duplicate-write-path".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already exists for request generation"))
    {
        return Err(format!(
            "block runtime b8 duplicate write path command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        245,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_050,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b8 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let read_not_write = semantic.apply_envelope(CommandEnvelope::new(
        246,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_051,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-read-request-as-write-path".to_owned(),
        },
    ));
    if read_not_write.status != CommandStatus::Rejected
        || !read_not_write
            .violations
            .iter()
            .any(|violation| violation.contains("operation is not write"))
    {
        return Err(format!(
            "block runtime b8 read-as-write command {} ({}) was not rejected: status={} violations={:?}",
            read_not_write.command_id,
            read_not_write.command,
            read_not_write.status.as_str(),
            read_not_write.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        247,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_052,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest: payload_digest.wrapping_add(1),
            note: "b8-reject-payload-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest
            .violations
            .iter()
            .any(|violation| violation.contains("payload digest mismatch"))
    {
        return Err(format!(
            "block runtime b8 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b9_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let entries = vec![
        BlockRequestQueueEntryRef::completed(20_009, 1, 20_013, 1),
        BlockRequestQueueEntryRef::completed(20_046, 1, 20_047, 1),
    ];
    let queue = semantic.apply_envelope(CommandEnvelope::new(
        248,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_053,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: entries.clone(),
            note: "b9-record-block-request-queue-through-fake-backend".to_owned(),
        },
    ));
    if queue.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b9 queue command {} ({}) failed: status={} violations={:?}",
            queue.command_id,
            queue.command,
            queue.status.as_str(),
            queue.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        249,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_054,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: entries.clone(),
            note: "b9-reject-request-already-queued".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already belongs to an active queue"))
    {
        return Err(format!(
            "block runtime b9 duplicate request queue command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        250,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_055,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: vec![BlockRequestQueueEntryRef::completed(20_009, 1, 20_013, 1)],
            note: "b9-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b9 stale backend queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let over_depth = semantic.apply_envelope(CommandEnvelope::new(
        251,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_056,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 1,
            entries: entries.clone(),
            note: "b9-reject-depth-exceeded".to_owned(),
        },
    ));
    if over_depth.status != CommandStatus::Rejected
        || !over_depth
            .violations
            .iter()
            .any(|violation| violation.contains("depth exceeded"))
    {
        return Err(format!(
            "block runtime b9 over-depth queue command {} ({}) was not rejected: status={} violations={:?}",
            over_depth.command_id,
            over_depth.command,
            over_depth.status.as_str(),
            over_depth.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        252,
        "target-executor-b9",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 20_057,
            backend,
            block_device: 20_002,
            block_device_generation: 1,
            depth: 8,
            entries: vec![BlockRequestQueueEntryRef::completed(20_046, 2, 20_047, 1)],
            note: "b9-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b9 stale request queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b10_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let dma_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-block0-buf0");
    let dma_resource_generation = semantic
        .resource_handle(dma_resource)
        .map(|handle| handle.generation)
        .ok_or("b10 dma resource handle is missing")?;

    let queue = semantic.apply_envelope(CommandEnvelope::new(
        253,
        "target-executor-b10",
        SemanticCommand::RecordQueueObject {
            queue: 20_058,
            name: "fake-block0-submit".to_owned(),
            role: QueueObjectRole::Submission,
            queue_index: 1,
            depth: 16,
            device: 20_001,
            device_generation: 1,
            note: "b10-record-block-submission-queue".to_owned(),
        },
    ));
    if queue.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 queue command {} ({}) failed: status={} violations={:?}",
            queue.command_id,
            queue.command,
            queue.status.as_str(),
            queue.violations
        )
        .into());
    }

    let descriptor = semantic.apply_envelope(CommandEnvelope::new(
        254,
        "target-executor-b10",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 20_059,
            queue: 20_058,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 4096,
            note: "b10-record-block-dma-descriptor".to_owned(),
        },
    ));
    if descriptor.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 descriptor command {} ({}) failed: status={} violations={:?}",
            descriptor.command_id,
            descriptor.command,
            descriptor.status.as_str(),
            descriptor.violations
        )
        .into());
    }

    let dma_buffer = semantic.apply_envelope(CommandEnvelope::new(
        255,
        "target-executor-b10",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 20_060,
            descriptor: 20_059,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 4096,
            note: "b10-record-dma-buffer-object".to_owned(),
        },
    ));
    if dma_buffer.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 dma buffer command {} ({}) failed: status={} violations={:?}",
            dma_buffer.command_id,
            dma_buffer.command,
            dma_buffer.status.as_str(),
            dma_buffer.violations
        )
        .into());
    }

    let buffer_digest = SemanticGraph::expected_block_dma_buffer_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        20_046,
        1,
        20_060,
        1,
        20_059,
        1,
        20_058,
        1,
        BlockRequestOperation::Write,
        DmaBufferObjectAccess::ReadWrite,
        5,
        4096,
        4096,
    );
    let binding = semantic.apply_envelope(CommandEnvelope::new(
        256,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_061,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest,
            note: "b10-bind-block-request-to-dma-buffer".to_owned(),
        },
    ));
    if binding.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b10 binding command {} ({}) failed: status={} violations={:?}",
            binding.command_id,
            binding.command,
            binding.status.as_str(),
            binding.violations
        )
        .into());
    }

    let stale_dma = semantic.apply_envelope(CommandEnvelope::new(
        257,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_062,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 2,
            buffer_digest,
            note: "b10-reject-stale-dma-generation".to_owned(),
        },
    ));
    if stale_dma.status != CommandStatus::Rejected
        || !stale_dma
            .violations
            .iter()
            .any(|violation| violation.contains("dma generation"))
    {
        return Err(format!(
            "block runtime b10 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma.command_id,
            stale_dma.command,
            stale_dma.status.as_str(),
            stale_dma.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        258,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_063,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest: buffer_digest ^ 1,
            note: "b10-reject-dma-buffer-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest
            .violations
            .iter()
            .any(|violation| violation.contains("digest mismatch"))
    {
        return Err(format!(
            "block runtime b10 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        259,
        "target-executor-b10",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 20_064,
            backend,
            block_request: 20_046,
            block_request_generation: 2,
            dma_buffer: 20_060,
            dma_buffer_generation: 1,
            buffer_digest,
            note: "b10-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("request generation"))
    {
        return Err(format!(
            "block runtime b10 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b11_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let aspace = ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, 30_001, 1);
    let vma_region = ContractObjectRef::new(ContractObjectKind::VmaRegion, 30_002, 1);
    let page = ContractObjectRef::new(ContractObjectKind::PageObject, 30_003, 1);

    let integrated = semantic.apply_envelope(CommandEnvelope::new(
        260,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_065,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page,
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-integrate-block-dma-buffer-with-page-object".to_owned(),
        },
    ));
    if integrated.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b11 page object command {} ({}) failed: status={} violations={:?}",
            integrated.command_id,
            integrated.command,
            integrated.status.as_str(),
            integrated.violations
        )
        .into());
    }

    let stale_dma = semantic.apply_envelope(CommandEnvelope::new(
        261,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_066,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 2,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_004, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-reject-stale-block-dma-generation".to_owned(),
        },
    ));
    if stale_dma.status != CommandStatus::Rejected
        || !stale_dma
            .violations
            .iter()
            .any(|violation| violation.contains("dma buffer generation"))
    {
        return Err(format!(
            "block runtime b11 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma.command_id,
            stale_dma.command,
            stale_dma.status.as_str(),
            stale_dma.violations
        )
        .into());
    }

    let dead_page = semantic.apply_envelope(CommandEnvelope::new(
        262,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_067,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_005, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Dead,
            page_offset: 0,
            byte_len: 4096,
            note: "b11-reject-dead-page-object".to_owned(),
        },
    ));
    if dead_page.status != CommandStatus::Rejected
        || !dead_page
            .violations
            .iter()
            .any(|violation| violation.contains("page must be live"))
    {
        return Err(format!(
            "block runtime b11 dead page command {} ({}) was not rejected: status={} violations={:?}",
            dead_page.command_id,
            dead_page.command,
            dead_page.status.as_str(),
            dead_page.violations
        )
        .into());
    }

    let over_page = semantic.apply_envelope(CommandEnvelope::new(
        263,
        "target-executor-b11",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 20_068,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            aspace,
            vma_region,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_006, 1),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 1,
            byte_len: 4096,
            note: "b11-reject-page-byte-range-overflow".to_owned(),
        },
    ));
    if over_page.status != CommandStatus::Rejected
        || !over_page
            .violations
            .iter()
            .any(|violation| violation.contains("byte range exceeds page"))
    {
        return Err(format!(
            "block runtime b11 over-page command {} ({}) was not rejected: status={} violations={:?}",
            over_page.command_id,
            over_page.command,
            over_page.status.as_str(),
            over_page.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b12_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let page = ContractObjectRef::new(ContractObjectKind::PageObject, 30_003, 1);

    let cached = semantic.apply_envelope(CommandEnvelope::new(
        264,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_069,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page,
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 1,
            note: "b12-cache-block-page-object-as-dirty-buffer".to_owned(),
        },
    ));
    if cached.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b12 buffer cache command {} ({}) failed: status={} violations={:?}",
            cached.command_id,
            cached.command,
            cached.status.as_str(),
            cached.violations
        )
        .into());
    }

    let stale_page = semantic.apply_envelope(CommandEnvelope::new(
        265,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_070,
            block_page_object: 20_065,
            block_page_object_generation: 2,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_004, 1),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 2,
            note: "b12-reject-stale-block-page-generation".to_owned(),
        },
    ));
    if stale_page.status != CommandStatus::Rejected
        || !stale_page
            .violations
            .iter()
            .any(|violation| violation.contains("page integration generation"))
    {
        return Err(format!(
            "block runtime b12 stale page command {} ({}) was not rejected: status={} violations={:?}",
            stale_page.command_id,
            stale_page.command,
            stale_page.status.as_str(),
            stale_page.violations
        )
        .into());
    }

    let wrong_page = semantic.apply_envelope(CommandEnvelope::new(
        266,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_071,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page: ContractObjectRef::new(ContractObjectKind::PageObject, 30_005, 1),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 3,
            note: "b12-reject-page-ref-mismatch".to_owned(),
        },
    ));
    if wrong_page.status != CommandStatus::Rejected
        || !wrong_page
            .violations
            .iter()
            .any(|violation| violation.contains("page ref does not match"))
    {
        return Err(format!(
            "block runtime b12 wrong page command {} ({}) was not rejected: status={} violations={:?}",
            wrong_page.command_id,
            wrong_page.command,
            wrong_page.status.as_str(),
            wrong_page.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        267,
        "target-executor-b12",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 20_072,
            block_page_object: 20_065,
            block_page_object_generation: 1,
            page,
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::WritebackPending,
            coherency_epoch: 4,
            note: "b12-reject-duplicate-cache-key".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("block range already cached"))
    {
        return Err(format!(
            "block runtime b12 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b13_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let file = semantic.apply_envelope(CommandEnvelope::new(
        268,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_073,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-materialize-file-object-from-buffer-cache".to_owned(),
        },
    ));
    if file.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b13 file object command {} ({}) failed: status={} violations={:?}",
            file.command_id,
            file.command,
            file.status.as_str(),
            file.violations
        )
        .into());
    }

    let stale_cache = semantic.apply_envelope(CommandEnvelope::new(
        269,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_074,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 2,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-stale-buffer-cache-generation".to_owned(),
        },
    ));
    if stale_cache.status != CommandStatus::Rejected
        || !stale_cache
            .violations
            .iter()
            .any(|violation| violation.contains("buffer cache generation"))
    {
        return Err(format!(
            "block runtime b13 stale cache command {} ({}) was not rejected: status={} violations={:?}",
            stale_cache.command_id,
            stale_cache.command,
            stale_cache.status.as_str(),
            stale_cache.violations
        )
        .into());
    }

    let oversized = semantic.apply_envelope(CommandEnvelope::new(
        270,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_075,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4097,
            file_size: 4097,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-oversized-cache-range".to_owned(),
        },
    ));
    if oversized.status != CommandStatus::Rejected
        || !oversized
            .violations
            .iter()
            .any(|violation| violation.contains("byte range exceeds"))
    {
        return Err(format!(
            "block runtime b13 oversized command {} ({}) was not rejected: status={} violations={:?}",
            oversized.command_id,
            oversized.command,
            oversized.status.as_str(),
            oversized.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        271,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_076,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 1024,
            byte_len: 1024,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-overlapping-file-range".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("range already materialized"))
    {
        return Err(format!(
            "block runtime b13 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b14_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let directory = semantic.apply_envelope(CommandEnvelope::new(
        272,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_077,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "file.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-record-directory-entry-for-file-object".to_owned(),
        },
    ));
    if directory.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b14 directory object command {} ({}) failed: status={} violations={:?}",
            directory.command_id,
            directory.command,
            directory.status.as_str(),
            directory.violations
        )
        .into());
    }

    let stale_file = semantic.apply_envelope(CommandEnvelope::new(
        273,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_078,
            file_object: 20_073,
            file_object_generation: 2,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "stale.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-stale-file-object-generation".to_owned(),
        },
    ));
    if stale_file.status != CommandStatus::Rejected
        || !stale_file
            .violations
            .iter()
            .any(|violation| violation.contains("file generation"))
    {
        return Err(format!(
            "block runtime b14 stale file command {} ({}) was not rejected: status={} violations={:?}",
            stale_file.command_id,
            stale_file.command,
            stale_file.status.as_str(),
            stale_file.violations
        )
        .into());
    }

    let mismatch = semantic.apply_envelope(CommandEnvelope::new(
        274,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_079,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "wrong.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/wrong.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-directory-file-identity-mismatch".to_owned(),
        },
    ));
    if mismatch.status != CommandStatus::Rejected
        || !mismatch
            .violations
            .iter()
            .any(|violation| violation.contains("file identity mismatch"))
    {
        return Err(format!(
            "block runtime b14 mismatch command {} ({}) was not rejected: status={} violations={:?}",
            mismatch.command_id,
            mismatch.command,
            mismatch.status.as_str(),
            mismatch.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        275,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_080,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "file.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-duplicate-directory-entry".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("entry already materialized"))
    {
        return Err(format!(
            "block runtime b14 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b15_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let payload = b"vmos fat adapter read write payload";
    let evidence = build_fat_read_write_evidence(FatAdapterConfig::default_vmos(), payload)
        .map_err(|error| format!("block runtime b15 fat adapter evidence failed: {error}"))?;

    let adapter = semantic.apply_envelope(CommandEnvelope::new(
        276,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_081,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-verify-fatfs-read-write-adapter".to_owned(),
        },
    ));
    if adapter.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b15 fat adapter command {} ({}) failed: status={} violations={:?}",
            adapter.command_id,
            adapter.command,
            adapter.status.as_str(),
            adapter.violations
        )
        .into());
    }

    let stale_directory = semantic.apply_envelope(CommandEnvelope::new(
        277,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_082,
            directory_object: 20_077,
            directory_object_generation: 2,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-stale-directory-generation".to_owned(),
        },
    ));
    if stale_directory.status != CommandStatus::Rejected
        || !stale_directory
            .violations
            .iter()
            .any(|violation| violation.contains("directory generation"))
    {
        return Err(format!(
            "block runtime b15 stale directory command {} ({}) was not rejected: status={} violations={:?}",
            stale_directory.command_id,
            stale_directory.command,
            stale_directory.status.as_str(),
            stale_directory.violations
        )
        .into());
    }

    let digest_mismatch = semantic.apply_envelope(CommandEnvelope::new(
        278,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_083,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: "BROKEN.TXT".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest.wrapping_add(1),
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-read-write-digest-mismatch".to_owned(),
        },
    ));
    if digest_mismatch.status != CommandStatus::Rejected
        || !digest_mismatch
            .violations
            .iter()
            .any(|violation| violation.contains("roundtrip mismatch"))
    {
        return Err(format!(
            "block runtime b15 digest mismatch command {} ({}) was not rejected: status={} violations={:?}",
            digest_mismatch.command_id,
            digest_mismatch.command,
            digest_mismatch.status.as_str(),
            digest_mismatch.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        279,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_084,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-duplicate-fat-adapter-binding".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("binding already verified"))
    {
        return Err(format!(
            "block runtime b15 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b16_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let payload = b"vmos ext4 adapter read only payload";
    let evidence = build_ext4_read_only_evidence(Ext4AdapterConfig::default_vmos(), payload)
        .map_err(|error| format!("block runtime b16 ext4 adapter evidence failed: {error}"))?;

    let adapter = semantic.apply_envelope(CommandEnvelope::new(
        280,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_085,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-verify-ext4-read-only-adapter".to_owned(),
        },
    ));
    if adapter.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b16 ext4 adapter command {} ({}) failed: status={} violations={:?}",
            adapter.command_id,
            adapter.command,
            adapter.status.as_str(),
            adapter.violations
        )
        .into());
    }

    let stale_directory = semantic.apply_envelope(CommandEnvelope::new(
        281,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_086,
            directory_object: 20_077,
            directory_object_generation: 2,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-stale-directory-generation".to_owned(),
        },
    ));
    if stale_directory.status != CommandStatus::Rejected
        || !stale_directory
            .violations
            .iter()
            .any(|violation| violation.contains("directory generation"))
    {
        return Err(format!(
            "block runtime b16 stale directory command {} ({}) was not rejected: status={} violations={:?}",
            stale_directory.command_id,
            stale_directory.command,
            stale_directory.status.as_str(),
            stale_directory.violations
        )
        .into());
    }

    let not_read_only = semantic.apply_envelope(CommandEnvelope::new(
        282,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_087,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: "/demo-rw.txt".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: false,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-non-read-only-adapter".to_owned(),
        },
    ));
    if not_read_only.status != CommandStatus::Rejected
        || !not_read_only
            .violations
            .iter()
            .any(|violation| violation.contains("read-only evidence"))
    {
        return Err(format!(
            "block runtime b16 read-only command {} ({}) was not rejected: status={} violations={:?}",
            not_read_only.command_id,
            not_read_only.command,
            not_read_only.status.as_str(),
            not_read_only.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        283,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_088,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-duplicate-ext4-adapter-binding".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("binding already verified"))
    {
        return Err(format!(
            "block runtime b16 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b17_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let owner_store = semantic_store_id(semantic, "linux_syscall")?;
    let file_ref = ContractObjectRef::new(ContractObjectKind::FileObject, 20_073, 1);
    let capability = semantic.grant_capability_with_authority_ref(
        "linux_syscall",
        "file-handle./demo/file.txt",
        AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_ref),
        &["read", "write"],
        "task",
        "target-executor-b17",
        true,
    );
    let capability_record = semantic
        .capabilities()
        .record(capability)
        .ok_or("block runtime b17 file handle capability record is missing")?;
    let capability_generation = capability_record.generation;
    let owner_store_generation = capability_record
        .owner_store_generation
        .ok_or("block runtime b17 file handle capability owner generation is missing")?;
    let handle = capability_record
        .store_local_handle(vec!["read".to_owned()])
        .ok_or("block runtime b17 file handle capability handle is missing")?;

    let allowed = semantic.apply_envelope(CommandEnvelope::new(
        284,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_089,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-allow-file-handle-read".to_owned(),
        },
    ));
    if allowed.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b17 file handle command {} ({}) failed: status={} violations={:?}",
            allowed.command_id,
            allowed.command,
            allowed.status.as_str(),
            allowed.violations
        )
        .into());
    }

    let stale_file = semantic.apply_envelope(CommandEnvelope::new(
        285,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_090,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 2,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-stale-file-generation".to_owned(),
        },
    ));
    if stale_file.status != CommandStatus::Rejected
        || !stale_file
            .violations
            .iter()
            .any(|violation| violation.contains("file generation"))
    {
        return Err(format!(
            "block runtime b17 stale file command {} ({}) was not rejected: status={} violations={:?}",
            stale_file.command_id,
            stale_file.command,
            stale_file.status.as_str(),
            stale_file.violations
        )
        .into());
    }

    let mut forged_handle = handle.clone();
    forged_handle.generation = forged_handle.generation.saturating_add(1);
    let forged = semantic.apply_envelope(CommandEnvelope::new(
        286,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_091,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: forged_handle,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-forged-file-handle-generation".to_owned(),
        },
    ));
    if forged.status != CommandStatus::Rejected
        || !forged
            .violations
            .iter()
            .any(|violation| violation.contains("handle is not authorized"))
    {
        return Err(format!(
            "block runtime b17 forged handle command {} ({}) was not rejected: status={} violations={:?}",
            forged.command_id,
            forged.command,
            forged.status.as_str(),
            forged.violations
        )
        .into());
    }

    let oversized = semantic.apply_envelope(CommandEnvelope::new(
        287,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_092,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 4090,
            byte_len: 16,
            content_digest: 0xB13,
            note: "b17-reject-oversized-file-handle-range".to_owned(),
        },
    ));
    if oversized.status != CommandStatus::Rejected
        || !oversized
            .violations
            .iter()
            .any(|violation| violation.contains("file binding mismatch"))
    {
        return Err(format!(
            "block runtime b17 oversized file command {} ({}) was not rejected: status={} violations={:?}",
            oversized.command_id,
            oversized.command,
            oversized.status.as_str(),
            oversized.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        288,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_093,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-duplicate-file-handle-read".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already allowed"))
    {
        return Err(format!(
            "block runtime b17 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

fn record_block_runtime_b18_evidence(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let capability = semantic
        .file_handle_capabilities()
        .iter()
        .find(|record| record.id == 20_089 && record.generation == 1)
        .cloned()
        .ok_or("block runtime b18 file handle capability evidence is missing")?;
    let blocker = capability.object_ref();

    let create_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        289,
        "target-executor-b18",
        SemanticCommand::CreateWait {
            wait: 20_094,
            owner_task: None,
            owner_store: Some(capability.owner_store),
            owner_store_generation: Some(capability.owner_store_generation),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18-fs-read-wait-pending".to_owned()),
        },
    ));
    if create_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 create read wait command {} ({}) failed: status={} violations={:?}",
            create_read_wait.command_id,
            create_read_wait.command,
            create_read_wait.status.as_str(),
            create_read_wait.violations
        )
        .into());
    }

    let record_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        290,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_095,
            wait: 20_094,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 1,
            note: "b18-record-fs-read-wait".to_owned(),
        },
    ));
    if record_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 record read wait command {} ({}) failed: status={} violations={:?}",
            record_read_wait.command_id,
            record_read_wait.command,
            record_read_wait.status.as_str(),
            record_read_wait.violations
        )
        .into());
    }

    let resolve_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        291,
        "target-executor-b18",
        SemanticCommand::ResolveFsWait {
            fs_wait: 20_095,
            fs_wait_generation: 1,
            note: "b18-resolve-fs-read-wait".to_owned(),
        },
    ));
    if resolve_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 resolve read wait command {} ({}) failed: status={} violations={:?}",
            resolve_read_wait.command_id,
            resolve_read_wait.command,
            resolve_read_wait.status.as_str(),
            resolve_read_wait.violations
        )
        .into());
    }

    let create_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        292,
        "target-executor-b18",
        SemanticCommand::CreateWait {
            wait: 20_096,
            owner_task: None,
            owner_store: Some(capability.owner_store),
            owner_store_generation: Some(capability.owner_store_generation),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18-fs-read-wait-close-fd".to_owned()),
        },
    ));
    if create_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 create cancel wait command {} ({}) failed: status={} violations={:?}",
            create_cancel_wait.command_id,
            create_cancel_wait.command,
            create_cancel_wait.status.as_str(),
            create_cancel_wait.violations
        )
        .into());
    }

    let record_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        293,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_097,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 2,
            note: "b18-record-cancellable-fs-wait".to_owned(),
        },
    ));
    if record_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 record cancel wait command {} ({}) failed: status={} violations={:?}",
            record_cancel_wait.command_id,
            record_cancel_wait.command,
            record_cancel_wait.status.as_str(),
            record_cancel_wait.violations
        )
        .into());
    }

    let duplicate_pending = semantic.apply_envelope(CommandEnvelope::new(
        294,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_098,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 2,
            note: "b18-reject-duplicate-pending-fs-wait".to_owned(),
        },
    ));
    if duplicate_pending.status != CommandStatus::Rejected
        || !duplicate_pending
            .violations
            .iter()
            .any(|violation| violation.contains("pending fs wait"))
    {
        return Err(format!(
            "block runtime b18 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_pending.command_id,
            duplicate_pending.command,
            duplicate_pending.status.as_str(),
            duplicate_pending.violations
        )
        .into());
    }

    let stale_handle = semantic.apply_envelope(CommandEnvelope::new(
        295,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_099,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation.saturating_add(1),
            operation: "read".to_owned(),
            sequence: 3,
            note: "b18-reject-stale-file-handle-capability-generation".to_owned(),
        },
    ));
    if stale_handle.status != CommandStatus::Rejected
        || !stale_handle
            .violations
            .iter()
            .any(|violation| violation.contains("file handle capability generation"))
    {
        return Err(format!(
            "block runtime b18 stale handle command {} ({}) was not rejected: status={} violations={:?}",
            stale_handle.command_id,
            stale_handle.command,
            stale_handle.status.as_str(),
            stale_handle.violations
        )
        .into());
    }

    let cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        296,
        "target-executor-b18",
        SemanticCommand::CancelFsWait {
            fs_wait: 20_097,
            fs_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "b18-cancel-fs-wait-on-close-fd".to_owned(),
        },
    ));
    if cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 cancel wait command {} ({}) failed: status={} violations={:?}",
            cancel_wait.command_id,
            cancel_wait.command,
            cancel_wait.status.as_str(),
            cancel_wait.violations
        )
        .into());
    }

    Ok(())
}

fn record_substrate_conformance_evidence(semantic: &mut SemanticGraph) {
    record_substrate_event(
        semantic,
        SubstrateEvent::unsupported(
            "DmaAuthority",
            "dma_alloc",
            Some(SubstrateRequester::new("target-executor-substrate-probe")),
        ),
    );
}

fn record_command_surface_evidence(semantic: &mut SemanticGraph) {
    let command = CommandEnvelope::new(
        1,
        "target-executor-command-probe",
        SemanticCommand::CreateWait {
            wait: 9000,
            owner_task: None,
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Timer,
            generation: 1,
            blockers: Vec::new(),
            deadline: None,
            restart_policy: RestartPolicy::Never,
            saved_context: None,
        },
    );
    let _ = semantic.apply_envelope(command);
}

fn record_preemptive_runtime_context_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    semantic.ensure_task(9001, FrontendKind::LinuxElf, "p0-preemptive-demo-task");
    semantic.ensure_task(9002, FrontendKind::LinuxElf, "p2-timer-demo-task");
    semantic.ensure_task(9003, FrontendKind::LinuxElf, "p8-cleanup-demo-task");
    semantic.ensure_task(9004, FrontendKind::LinuxElf, "s6-remote-preempt-task");
    let cleanup_store = semantic.register_store(
        "p8.cleanup.driver",
        "p8-cleanup-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(cleanup_store, StoreState::Running);
    let cleanup_store_generation = semantic
        .store_handle(cleanup_store)
        .map(|handle| handle.generation)
        .ok_or("p8 cleanup store handle is missing")?;
    let io_device_resource =
        semantic.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let io_device_resource_generation = semantic
        .resource_handle(io_device_resource)
        .map(|handle| handle.generation)
        .ok_or("i0 device resource handle is missing")?;
    let io_dma_buffer_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let io_dma_buffer_resource_generation = semantic
        .resource_handle(io_dma_buffer_resource)
        .map(|handle| handle.generation)
        .ok_or("i3 dma buffer resource handle is missing")?;
    let io_mmio_region_resource =
        semantic.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let io_mmio_region_resource_generation = semantic
        .resource_handle(io_mmio_region_resource)
        .map(|handle| handle.generation)
        .ok_or("i4 mmio region resource handle is missing")?;
    let io_irq_line_resource =
        semantic.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let io_irq_line_resource_generation = semantic
        .resource_handle(io_irq_line_resource)
        .map(|handle| handle.generation)
        .ok_or("i5 irq line resource handle is missing")?;
    let packet_device_resource =
        semantic.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let packet_device_resource_generation = semantic
        .resource_handle(packet_device_resource)
        .map(|handle| handle.generation)
        .ok_or("n0 packet device resource handle is missing")?;
    let io_driver_store = semantic.register_store(
        "i6.irq.driver",
        "i6-irq-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(io_driver_store, StoreState::Running);
    let io_driver_store_generation = semantic
        .store_handle(io_driver_store)
        .map(|handle| handle.generation)
        .ok_or("i6 driver store handle is missing")?;
    // The P8 cleanup command moves the store through Cleaning and Dead, bumping
    // the semantic generation once for each transition before S13 validates it.
    let cleanup_result_store_generation = cleanup_store_generation + 2;
    let commands = [
        CommandEnvelope::new(
            1,
            "target-executor-s0",
            SemanticCommand::RegisterHart {
                hart: 1,
                hardware_id: 0,
                label: "boot-hart0".to_owned(),
                boot: true,
                note: "s0-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            2,
            "target-executor-s0",
            SemanticCommand::SetHartState {
                hart: 1,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "scheduler-ready".to_owned(),
                note: "s0-hart-state-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            3,
            "target-executor-s4",
            SemanticCommand::RegisterHart {
                hart: 2,
                hardware_id: 1,
                label: "secondary-hart1".to_owned(),
                boot: false,
                note: "s4-secondary-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            4,
            "target-executor-s4",
            SemanticCommand::SetHartState {
                hart: 2,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "secondary-scheduler-ready".to_owned(),
                note: "s4-secondary-hart-idle-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            5,
            "target-executor-s5",
            SemanticCommand::RecordIpiEvent {
                ipi: 9001,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 2,
                kind: IpiEventKind::SchedulerKick,
                reason: "s5-scheduler-kick".to_owned(),
                note: "s5-ipi-event-model-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            6,
            "target-executor-s6",
            SemanticCommand::CreateRunnableQueue {
                queue: 9004,
                label: "remote-preempt-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            7,
            "target-executor-s6",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9004,
                queue_generation: 1,
                hart: 2,
                hart_generation: 2,
                note: "s6-target-queue-owned-by-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            8,
            "target-executor-s6",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9004,
                owner_task: 9004,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            9,
            "target-executor-s6",
            SemanticCommand::EnqueueRunnable {
                queue: 9004,
                activation: 9004,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            9_001,
            "target-executor-s6",
            SemanticCommand::DequeueRunnable {
                queue: 9004,
                activation: 9004,
            },
        ),
        CommandEnvelope::new(
            9_002,
            "target-executor-s6",
            SemanticCommand::BindHartCurrentActivation {
                hart: 2,
                hart_generation: 2,
                activation: 9004,
                activation_generation: 3,
                note: "s6-dispatch-target-on-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_003,
            "target-executor-s6",
            SemanticCommand::RecordIpiEvent {
                ipi: 9002,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                kind: IpiEventKind::SchedulerKick,
                reason: "s6-remote-preempt-ipi".to_owned(),
                note: "s6-remote-preempt-ipi-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_004,
            "target-executor-s6",
            SemanticCommand::RemotePreemptActivation {
                remote_preempt: 9001,
                ipi: 9002,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                activation: 9004,
                activation_generation: 3,
                queue: 9004,
                note: "s6-remote-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_005,
            "target-executor-s8",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9004,
                queue: 9004,
                queue_generation: 2,
                selected_activation: 9004,
                selected_activation_generation: 4,
                reason: "s8-cross-hart-runnable".to_owned(),
                note: "s8-cross-hart-base-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_006,
            "target-executor-s8",
            SemanticCommand::RecordCrossHartSchedulerDecision {
                cross_decision: 9001,
                scheduler_decision: 9004,
                scheduler_decision_generation: 1,
                deciding_hart: 1,
                deciding_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 4,
                reason: "s8-remote-runnable-selected".to_owned(),
                note: "s8-cross-hart-scheduler-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_007,
            "target-executor-s9",
            SemanticCommand::CreateRunnableQueue {
                queue: 9005,
                label: "s9-migration-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_008,
            "target-executor-s9",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9005,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s9-target-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_009,
            "target-executor-s9",
            SemanticCommand::MigrateRunnableActivation {
                migration: 9001,
                activation: 9004,
                activation_generation: 4,
                source_queue: 9004,
                source_queue_generation: 2,
                target_queue: 9005,
                target_queue_generation: 2,
                source_hart: 2,
                source_hart_generation: 4,
                target_hart: 1,
                target_hart_generation: 2,
                reason: "s9-cross-hart-rebalance".to_owned(),
                note: "s9-activation-migration-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_010,
            "target-executor-s10",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9001,
                coordinator_hart: 1,
                coordinator_hart_generation: 2,
                participants: vec![(1, 2), (2, 4)],
                reason: "s10-quiescent-boundary".to_owned(),
                note: "s10-smp-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_011,
            "target-executor-s11",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9101,
                epoch: 1,
                safe_point: 9001,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s11-stop-the-world-code-publish-boundary".to_owned(),
                note: "s11-stop-the-world-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_012,
            "target-executor-s12",
            SemanticCommand::ValidateSmpCodePublishBarrier {
                barrier: 9201,
                rendezvous: 9101,
                rendezvous_generation: 1,
                code_publish_epoch_before: 0,
                code_publish_epoch_after: 1,
                remote_icache_sync_required: true,
                code_publish_executed: false,
                reason: "s12-smp-code-publish-barrier".to_owned(),
                note: "s12-semantic-code-publish-barrier-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10,
            "target-executor-p0",
            SemanticCommand::CreateRunnableQueue {
                queue: 9001,
                label: "bootstrap-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9001,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-bootstrap-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            11,
            "target-executor-p0",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9001,
                owner_task: 9001,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            12,
            "target-executor-p0",
            SemanticCommand::EnqueueRunnable {
                queue: 9001,
                activation: 9001,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            13,
            "target-executor-p1",
            SemanticCommand::CreateActivationContext {
                context: 9001,
                activation: 9001,
                activation_generation: 2,
            },
        ),
        CommandEnvelope::new(
            14,
            "target-executor-p1",
            SemanticCommand::CaptureSavedContext {
                saved_context: 9001,
                context: 9001,
                context_generation: 1,
                reason: SavedContextReason::Initial,
                pc: 0x1000,
                sp: 0x8000,
                flags: 0,
                note: "p1-initial-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20,
            "target-executor-p2",
            SemanticCommand::CreateRunnableQueue {
                queue: 9002,
                label: "timer-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9002,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-timer-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            21,
            "target-executor-p2",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9002,
                owner_task: 9002,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            22,
            "target-executor-p2",
            SemanticCommand::EnqueueRunnable {
                queue: 9002,
                activation: 9002,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            23,
            "target-executor-p2",
            SemanticCommand::DequeueRunnable {
                queue: 9002,
                activation: 9002,
            },
        ),
        CommandEnvelope::new(
            24,
            "target-executor-s1",
            SemanticCommand::BindHartCurrentActivation {
                hart: 1,
                hart_generation: 2,
                activation: 9002,
                activation_generation: 3,
                note: "s1-hart-current-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            25,
            "target-executor-p2",
            SemanticCommand::RecordTimerInterrupt {
                interrupt: 9001,
                timer_epoch: 1,
                hart: 1,
                hart_generation: 3,
                target_activation: Some(9002),
                target_activation_generation: Some(3),
                note: "p2-timer-interrupt-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            29,
            "target-executor-s1",
            SemanticCommand::ClearHartCurrentActivation {
                hart: 1,
                hart_generation: 3,
                activation: 9002,
                activation_generation: 3,
                reason: "timer-preempt".to_owned(),
                note: "s1-clear-current-before-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            30,
            "target-executor-p3",
            SemanticCommand::PreemptActivation {
                preemption: 9001,
                activation: 9002,
                activation_generation: 3,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                queue: 9002,
                note: "p3-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            40,
            "target-executor-p4",
            SemanticCommand::SavePreemptedContext {
                context: 9002,
                saved_context: 9002,
                preemption: 9001,
                preemption_generation: 1,
                pc: 0x2000,
                sp: 0x9000,
                flags: 0,
                note: "p4-save-preempted-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            50,
            "target-executor-p5",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9001,
                queue: 9002,
                queue_generation: 2,
                selected_activation: 9002,
                selected_activation_generation: 4,
                reason: "runnable-available".to_owned(),
                note: "p5-scheduler-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            60,
            "target-executor-p6",
            SemanticCommand::ResumeActivation {
                resume: 9001,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation: 9002,
                activation_generation: 4,
                note: "p6-resume-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            61,
            "target-executor-p9",
            SemanticCommand::RecordPreemptionLatencySample {
                sample: 9001,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                preemption: 9001,
                preemption_generation: 1,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation_resume: 9001,
                activation_resume_generation: 1,
                measured_nanos: 8_500,
                budget_nanos: 50_000,
                note: "p9-host-validation-preemption-latency-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70,
            "target-executor-p7",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9001,
                activation: 9002,
                activation_generation: 5,
                wait: 9003,
                kind: SemanticWaitKind::Timer,
                blockers: {
                    let mut blockers = Vec::new();
                    blockers.push(ContractObjectRef::new(
                        ContractObjectKind::TimerInterrupt,
                        9001,
                        1,
                    ));
                    blockers
                },
                deadline: Some(200),
                restart_policy: RestartPolicy::RestartIfAllowed,
                note: "p7-block-on-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            71,
            "target-executor-p7",
            SemanticCommand::CancelActivationWait {
                activation_wait: 9001,
                activation_wait_generation: 1,
                wait_generation: 1,
                errno: 110,
                reason: semantic_core::WaitCancelReason::Timeout,
                note: "p7-cancel-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80,
            "target-executor-p8",
            SemanticCommand::CreateRunnableQueue {
                queue: 9003,
                label: "cleanup-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9003,
                queue_generation: 1,
                hart: 1,
                hart_generation: 4,
                note: "s3-cleanup-queue-owned-by-boot-hart-after-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            81,
            "target-executor-p8",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9003,
                owner_task: 9003,
                owner_task_generation: 1,
                owner_store: Some(cleanup_store),
                owner_store_generation: Some(cleanup_store_generation),
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            82,
            "target-executor-p8",
            SemanticCommand::EnqueueRunnable {
                queue: 9003,
                activation: 9003,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            83,
            "target-executor-p8",
            SemanticCommand::DequeueRunnable {
                queue: 9003,
                activation: 9003,
            },
        ),
        CommandEnvelope::new(
            84,
            "target-executor-p8",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9002,
                activation: 9003,
                activation_generation: 3,
                wait: 9004,
                kind: SemanticWaitKind::DeviceIrq,
                blockers: {
                    let mut blockers = Vec::new();
                    blockers.push(ContractObjectRef::new(
                        ContractObjectKind::Store,
                        cleanup_store,
                        cleanup_store_generation,
                    ));
                    blockers
                },
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                note: "p8-block-driver-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            85,
            "target-executor-p8",
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup: 9001,
                store: cleanup_store,
                store_generation: cleanup_store_generation,
                activation: 9003,
                activation_generation: 4,
                wait: Some(9004),
                wait_generation: Some(1),
                reason: "driver-store-fault".to_owned(),
                note: "p8-cleanup-dead-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90,
            "target-executor-s7",
            SemanticCommand::RecordIpiEvent {
                ipi: 9003,
                source_hart: 1,
                source_hart_generation: 4,
                target_hart: 2,
                target_hart_generation: 4,
                kind: IpiEventKind::SchedulerKick,
                reason: "s7-remote-park-ipi".to_owned(),
                note: "s7-remote-park-ipi-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            91,
            "target-executor-s7",
            SemanticCommand::RemoteParkHart {
                remote_park: 9001,
                ipi: 9003,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 4,
                target_hart: 2,
                target_hart_generation: 4,
                reason: "s7-remote-maintenance".to_owned(),
                note: "s7-remote-park-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            92,
            "target-executor-s13",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9301,
                coordinator_hart: 1,
                coordinator_hart_generation: 4,
                participants: vec![(1, 4), (2, 5)],
                reason: "s13-cleanup-quiescence-boundary".to_owned(),
                note: "s13-post-cleanup-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            93,
            "target-executor-s13",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9301,
                epoch: 2,
                safe_point: 9301,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s13-cleanup-quiescence-rendezvous".to_owned(),
                note: "s13-post-cleanup-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            94,
            "target-executor-s13",
            SemanticCommand::ValidateSmpCleanupQuiescence {
                quiescence: 9301,
                cleanup: 9001,
                cleanup_generation: 1,
                rendezvous: 9301,
                rendezvous_generation: 1,
                store: cleanup_store,
                target_store_generation: cleanup_store_generation,
                result_store_generation: cleanup_result_store_generation,
                reason: "s13-smp-cleanup-quiescence".to_owned(),
                note: "s13-dead-store-cross-hart-quiescence-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            95,
            "target-executor-s14",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9401,
                coordinator_hart: 1,
                coordinator_hart_generation: 4,
                participants: vec![(1, 4), (2, 5)],
                reason: "s14-snapshot-barrier-boundary".to_owned(),
                note: "s14-snapshot-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            96,
            "target-executor-s14",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9401,
                epoch: 3,
                safe_point: 9401,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s14-snapshot-barrier-rendezvous".to_owned(),
                note: "s14-snapshot-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            97,
            "target-executor-s14",
            SemanticCommand::ValidateSmpSnapshotBarrier {
                barrier: 9401,
                rendezvous: 9401,
                rendezvous_generation: 1,
                snapshot_state: SnapshotBarrierValidationState::default(),
                reason: "s14-smp-snapshot-barrier".to_owned(),
                note: "s14-clean-snapshot-boundary-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            98,
            "target-executor-s15",
            SemanticCommand::RecordSmpStressRun {
                run: 9501,
                scenario: "target-executor-s15-integrated-smp-sequence".to_owned(),
                iterations: 3,
                invariant_checks: 6,
                reason: "s15-smp-stress-property-tests".to_owned(),
                note: "s15-record-property-clean-smp-sequence".to_owned(),
            },
        ),
        CommandEnvelope::new(
            99,
            "target-executor-s16",
            SemanticCommand::RecordSmpScalingBenchmark {
                benchmark: 9601,
                scenario: "target-executor-s16-smp-scaling-harness".to_owned(),
                stress_run: 9501,
                stress_run_generation: 1,
                workload_units: 6,
                baseline_single_hart_nanos: 120_000,
                measured_smp_nanos: 72_000,
                budget_nanos: 90_000,
                note: "s16-record-semantic-smp-scaling-benchmark".to_owned(),
            },
        ),
        CommandEnvelope::new(
            100,
            "target-executor-i0",
            SemanticCommand::RecordDeviceObject {
                device: 9701,
                name: "fake-io0".to_owned(),
                class: "fake-device".to_owned(),
                resource: io_device_resource,
                resource_generation: io_device_resource_generation,
                backend: "fake-io-backend".to_owned(),
                bus: "semantic-harness".to_owned(),
                vendor: "vmos".to_owned(),
                model: "fake-io-v1".to_owned(),
                note: "i0-record-device-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            101,
            "target-executor-i1",
            SemanticCommand::RecordQueueObject {
                queue: 9801,
                name: "fake-io0-rx".to_owned(),
                role: QueueObjectRole::Rx,
                queue_index: 0,
                depth: 64,
                device: 9701,
                device_generation: 1,
                note: "i1-record-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            102,
            "target-executor-i2",
            SemanticCommand::RecordDescriptorObject {
                descriptor: 9901,
                queue: 9801,
                queue_generation: 1,
                slot: 0,
                access: DescriptorObjectAccess::ReadWrite,
                length: 2048,
                note: "i2-record-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            103,
            "target-executor-i3",
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer: 9911,
                descriptor: 9901,
                descriptor_generation: 1,
                resource: io_dma_buffer_resource,
                resource_generation: io_dma_buffer_resource_generation,
                access: DmaBufferObjectAccess::ReadWrite,
                length: 2048,
                note: "i3-record-dma-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            104,
            "target-executor-i4",
            SemanticCommand::RecordMmioRegionObject {
                mmio_region: 9921,
                device: 9701,
                device_generation: 1,
                resource: io_mmio_region_resource,
                resource_generation: io_mmio_region_resource_generation,
                region_index: 0,
                offset: 0x1000,
                length: 0x100,
                access: MmioRegionObjectAccess::ReadWrite,
                note: "i4-record-mmio-region-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            105,
            "target-executor-i5",
            SemanticCommand::RecordIrqLineObject {
                irq_line: 9931,
                device: 9701,
                device_generation: 1,
                resource: io_irq_line_resource,
                resource_generation: io_irq_line_resource_generation,
                irq_number: 5,
                trigger: IrqLineTrigger::Level,
                polarity: IrqLinePolarity::ActiveHigh,
                note: "i5-record-irq-line-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            106,
            "target-executor-i6",
            SemanticCommand::RecordIrqEvent {
                irq_event: 9941,
                irq_line: 9931,
                irq_line_generation: 1,
                device: 9701,
                device_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                sequence: 1,
                note: "i6-record-irq-event-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 9701, 1);
    let mmio_ref = ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 9921, 1);
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 9911, 1);
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 9931, 1);
    let device_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "device.fake-io0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "i7-device-capability",
        true,
    );
    let mmio_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio_ref),
        &["write32"],
        "store",
        "i7-device-capability",
        true,
    );
    let dma_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "i7-device-capability",
        true,
    );
    let irq_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
        &["ack"],
        "store",
        "i7-device-capability",
        true,
    );
    let capability_handle = |semantic: &SemanticGraph, capability, operation: &str| {
        semantic
            .capabilities()
            .record(capability)
            .and_then(|record| record.store_local_handle(vec![operation.to_owned()]))
            .ok_or("i7 device capability handle is missing")
    };
    let i7_commands = [
        CommandEnvelope::new(
            107,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9951,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: capability_handle(semantic, device_capability, "probe")?,
                note: "i7-record-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            108,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9952,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: mmio_ref,
                class: CapabilityClass::MmioRegion,
                operation: "write32".to_owned(),
                handle: capability_handle(semantic, mmio_capability, "write32")?,
                note: "i7-record-mmio-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            109,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9953,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: dma_ref,
                class: CapabilityClass::DmaBuffer,
                operation: "sync-for-device".to_owned(),
                handle: capability_handle(semantic, dma_capability, "sync-for-device")?,
                note: "i7-record-dma-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            110,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9954,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: irq_ref,
                class: CapabilityClass::IrqLine,
                operation: "ack".to_owned(),
                handle: capability_handle(semantic, irq_capability, "ack")?,
                note: "i7-record-irq-capability-harness".to_owned(),
            },
        ),
    ];
    for command in i7_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let i8_result = semantic.apply_envelope(CommandEnvelope::new(
        111,
        "target-executor-i8",
        SemanticCommand::BindDriverStore {
            binding: 9961,
            driver_store: io_driver_store,
            driver_store_generation: io_driver_store_generation,
            device: 9701,
            device_generation: 1,
            device_capability: 9951,
            device_capability_generation: 1,
            note: "i8-bind-driver-store-to-device-harness".to_owned(),
        },
    ));
    if i8_result.status != CommandStatus::Applied {
        return Err(format!(
            "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
            i8_result.command_id,
            i8_result.command,
            i8_result.status.as_str(),
            i8_result.violations
        )
        .into());
    }
    let i9_commands = [
        CommandEnvelope::new(
            112,
            "target-executor-i9",
            SemanticCommand::CreateWait {
                wait: 9962,
                owner_task: None,
                owner_store: Some(io_driver_store),
                owner_store_generation: Some(io_driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("i9-fake-irq-wait".to_owned()),
            },
        ),
        CommandEnvelope::new(
            113,
            "target-executor-i9",
            SemanticCommand::RecordIoWait {
                io_wait: 9963,
                wait: 9962,
                wait_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                blocker: irq_ref,
                note: "i9-io-wait-token-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            114,
            "target-executor-i9",
            SemanticCommand::RecordIrqEvent {
                irq_event: 9964,
                irq_line: 9931,
                irq_line_generation: 1,
                device: 9701,
                device_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                sequence: 2,
                note: "i9-fake-irq-event-resolves-wait".to_owned(),
            },
        ),
        CommandEnvelope::new(
            115,
            "target-executor-i9",
            SemanticCommand::ResolveIoWait {
                io_wait: 9963,
                io_wait_generation: 1,
                irq_event: 9964,
                irq_event_generation: 1,
                note: "i9-fake-irq-resolved-io-wait".to_owned(),
            },
        ),
    ];
    for command in i9_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let io_evidence_commands = [
        CommandEnvelope::new(
            116,
            "target-executor-i10",
            SemanticCommand::CreateWait {
                wait: 9965,
                owner_task: None,
                owner_store: Some(io_driver_store),
                owner_store_generation: Some(io_driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("i10-pending-io-wait-before-cleanup".to_owned()),
            },
        ),
        CommandEnvelope::new(
            117,
            "target-executor-i10",
            SemanticCommand::RecordIoWait {
                io_wait: 9966,
                wait: 9965,
                wait_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                blocker: irq_ref,
                note: "i10-pending-io-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            118,
            "target-executor-i11",
            SemanticCommand::InjectIoFault {
                fault: 9968,
                cleanup: 9967,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                target: irq_ref,
                kind: semantic_core::IoFaultInjectionKind::DeviceFault,
                note: "i11-injected-device-fault-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            119,
            "target-executor-i12",
            SemanticCommand::ValidateIoRuntime {
                report: 9969,
                note: "i12-io-validator-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            120,
            "target-executor-n0",
            SemanticCommand::RecordDeviceObject {
                device: 10_001,
                name: "virtio-net0".to_owned(),
                class: "packet-device".to_owned(),
                resource: packet_device_resource,
                resource_generation: packet_device_resource_generation,
                backend: "fake-net-backend".to_owned(),
                bus: "semantic-harness".to_owned(),
                vendor: "vmos".to_owned(),
                model: "fake-net-v1".to_owned(),
                note: "n0-record-packet-backing-device-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            121,
            "target-executor-n0",
            SemanticCommand::RecordPacketDeviceObject {
                packet_device: 10_002,
                name: "net0".to_owned(),
                device: 10_001,
                device_generation: 1,
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                note: "n0-record-packet-device-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            122,
            "target-executor-n1",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_003,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Rx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: 64,
                sequence: 1,
                state: PacketBufferObjectState::Filled,
                note: "n1-record-packet-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            123,
            "target-executor-n2",
            SemanticCommand::RecordPacketQueueObject {
                packet_queue: 10_004,
                name: "net0-rx0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                role: PacketQueueRole::Rx,
                queue_index: 0,
                depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                note: "n2-record-rx-packet-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            124,
            "target-executor-n2",
            SemanticCommand::RecordPacketQueueObject {
                packet_queue: 10_005,
                name: "net0-tx0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                role: PacketQueueRole::Tx,
                queue_index: 0,
                depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                note: "n2-record-tx-packet-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            125,
            "target-executor-n3",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_006,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                packet_buffer: 10_003,
                packet_buffer_generation: 1,
                slot: 0,
                length: 64,
                note: "n3-record-rx-packet-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            126,
            "target-executor-n4",
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend: 10_007,
                name: "fake-net0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                provider: FAKE_NET_BACKEND_PROVIDER.to_owned(),
                profile: FAKE_NET_BACKEND_PROFILE.to_owned(),
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                deterministic_seed: FAKE_NET_BACKEND_SEED,
                note: "n4-bind-fake-net-backend-object-harness".to_owned(),
            },
        ),
    ];
    for command in io_evidence_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

fn record_interface_boundary_evidence(semantic: &mut SemanticGraph) {
    semantic.record_interface_unsupported(
        "standard-wasi",
        "wasi:clocks/monotonic-clock",
        "subscribe",
        Some("target-executor-interface-probe".to_owned()),
        None,
        None,
    );
}

fn record_substrate_event(semantic: &mut SemanticGraph, event: SubstrateEvent) {
    match event {
        SubstrateEvent::Unsupported {
            authority,
            operation,
            requester,
        } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_unsupported(authority, operation, requester, artifact, store);
        }
        SubstrateEvent::CapabilityDenied {
            authority,
            operation,
            requester,
            capability,
        } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_capability_denied(
                authority,
                operation,
                requester,
                artifact,
                store,
                capability.map(|capability| capability.id),
                capability.map(|capability| capability.generation),
            );
        }
    }
}

fn substrate_requester_parts(
    requester: Option<SubstrateRequester>,
) -> (Option<String>, Option<u64>, Option<u64>) {
    let Some(requester) = requester else {
        return (None, None, None);
    };
    (
        Some(requester.subject),
        requester.artifact.map(|artifact| artifact.id),
        requester.store.map(|store| store.id),
    )
}

fn build_target_executor_v1(
    plan: &ValidatedArtifactPlan,
    semantic: &SemanticGraph,
    runtime_stores: &[runtime::LoadedRuntimeStore],
) -> Result<TargetExecutorV1Report, Box<dyn Error>> {
    let mut registry = ArtifactRegistry::with_expected(expected_target_artifacts(plan));
    let mut publisher = CodePublisher::new();
    let mut store_manager = TargetStoreManager::new();
    let mut executor = TargetExecutor::new();
    let mut ledger = CapabilityLedger::new();
    let mut report = TargetExecutorV1Report::default();
    let mut verified_artifacts = Vec::new();

    for (index, entry) in plan.modules.iter().enumerate() {
        let image = target_artifact_image((index + 1) as u64, entry, plan);
        report
            .target_artifacts
            .push(target_artifact_manifest(&image));
        let verified = registry.verify(image).map_err(|error| error.message())?;
        verified_artifacts.push(verified.clone());
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

        let code_id = publisher
            .allocate(&verified)
            .map_err(|error| error.message())?;
        publisher.fill(code_id).map_err(|error| error.message())?;
        publisher.seal(code_id).map_err(|error| error.message())?;
        publisher
            .publish_rx(code_id)
            .map_err(|error| error.message())?;
        let store = store_manager
            .record(store_id)
            .ok_or("store manager lost store after register")?;
        grant_verified_capabilities(&mut ledger, &verified, store_id, store.store.generation)?;
        publisher
            .bind_to_store(code_id, &store.store)
            .map_err(|error| error.message())?;
        if let Some(runtime_store) = runtime_stores
            .iter()
            .find(|store| store.package == entry.package)
        {
            let code_object = publisher
                .object_mut(code_id)
                .map_err(|error| error.message())?;
            append_cwasm_smoke_hostcalls(code_object, index, &runtime_store.smoke_trace);
        }
        let code = publisher
            .object(code_id)
            .ok_or("publisher lost code object after bind")?
            .clone();

        run_activation_harness(index, &mut executor, store, &code, &ledger)?;
        if let Some(runtime_store) = runtime_stores
            .iter()
            .find(|store| store.package == entry.package)
        {
            run_cwasm_smoke_evidence(
                index,
                &mut executor,
                store,
                &code,
                &ledger,
                &runtime_store.smoke_trace,
            )?;
        }
    }

    if let Some(cleanup_artifact) = verified_artifacts.first() {
        let cleanup_store_id = store_manager.register_verified_artifact(
            cleanup_artifact,
            "restartable",
            "cleanup-harness-rebuild",
        );
        store_manager
            .set_running(cleanup_store_id)
            .map_err(|error| error.message())?;
        let cleanup_store_snapshot = store_manager
            .record(cleanup_store_id)
            .ok_or("cleanup store missing after registration")?
            .store
            .clone();
        ledger
            .grant_with_authority_ref(
                &cleanup_artifact.package,
                "store-control.cleanup-harness",
                AuthorityObjectRef::internal(
                    CapabilityClass::StoreControl,
                    ContractObjectRef::new(
                        ContractObjectKind::Store,
                        cleanup_store_snapshot.id,
                        cleanup_store_snapshot.generation,
                    ),
                ),
                &["kill"],
                "store",
                Some(cleanup_store_id),
                Some(cleanup_store_snapshot.generation),
                None,
                "cleanup-harness",
                true,
            )
            .map_err(|error| error.message())?;
        let cleanup_code_id = publisher
            .allocate(cleanup_artifact)
            .map_err(|error| error.message())?;
        publisher
            .fill(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .seal(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .publish_rx(cleanup_code_id)
            .map_err(|error| error.message())?;
        publisher
            .bind_to_store(cleanup_code_id, &cleanup_store_snapshot)
            .map_err(|error| error.message())?;
        let cleanup_code_snapshot = publisher
            .object(cleanup_code_id)
            .ok_or("cleanup code object missing after bind")?
            .clone();
        let cleanup_activation = executor
            .start_activation(
                &cleanup_store_snapshot,
                &cleanup_code_snapshot,
                ActivationEntry::Symbol("cleanup_harness".to_owned()),
            )
            .map_err(|error| error.message())?;
        executor
            .acquire_dmw_lease(cleanup_activation, "dmw.cleanup.harness")
            .map_err(|error| error.message())?;
        {
            let cleanup_store = &mut store_manager
                .record_mut(cleanup_store_id)
                .map_err(|error| error.message())?
                .store;
            let cleanup_code = publisher
                .object_mut(cleanup_code_id)
                .map_err(|error| error.message())?;
            executor
                .run_fault_cleanup(
                    cleanup_store,
                    Some(cleanup_activation),
                    Some(cleanup_code),
                    &mut ledger,
                    "cleanup-harness",
                )
                .map_err(|error| error.message())?;
        }
        store_manager
            .record_current_tombstone(cleanup_store_id, "cleanup-store-dead")
            .map_err(|error| error.message())?;
        publisher
            .record_current_tombstone(cleanup_code_id, "cleanup-code-retired")
            .map_err(|error| error.message())?;
    }

    let snapshot_validation =
        SnapshotBarrierValidator::validate(&executor.snapshot_barrier_validation_state());
    report.snapshot_validation = boundary_validation_report_manifest(&snapshot_validation);
    executor
        .snapshot_barrier()
        .map_err(|error| error.message())?;
    let replay_record_modes = executor
        .hostcall_trace()
        .iter()
        .map(|trace| trace.record_mode)
        .collect::<Vec<_>>();
    let replay_state = ReplayPackageValidationState::clean(replay_record_modes);
    let replay_validation = PackageReplayValidator::validate(&replay_state);
    report.replay_validation = boundary_validation_report_manifest(&replay_validation);
    for policy in memory_class_policies() {
        report.memory_policies.push(memory_policy_manifest(policy));
    }
    for code in publisher.objects() {
        report.code_objects.push(code_object_manifest(code));
    }
    for store in store_manager.records() {
        report
            .store_records
            .push(store_record_manifest(&store.store));
    }
    for capability in ledger.records() {
        report
            .capability_records
            .push(capability_record_manifest(capability));
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
    for cleanup in executor.cleanup_transactions() {
        report
            .cleanup_transactions
            .push(cleanup_transaction_manifest(cleanup));
    }
    for tombstone in publisher
        .tombstones()
        .iter()
        .chain(store_manager.tombstones().iter())
        .chain(executor.tombstones().iter())
    {
        report.tombstones.push(tombstone_manifest(tombstone));
    }
    let external_objects = declared_authority_objects(ledger.records());
    let contract_snapshot = ContractGraphSnapshot {
        artifacts: verified_artifacts,
        code_objects: publisher.objects().to_vec(),
        stores: store_manager
            .records()
            .iter()
            .map(|record| record.store.clone())
            .collect(),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        hostcalls: executor.hostcall_trace().to_vec(),
        capabilities: ledger.records().to_vec(),
        waits: Vec::new(),
        cleanup_transactions: executor.cleanup_transactions().to_vec(),
        tombstones: publisher
            .tombstones()
            .iter()
            .chain(store_manager.tombstones().iter())
            .chain(executor.tombstones().iter())
            .cloned()
            .collect(),
        external_objects,
        explicit_edges: Vec::new(),
    };
    report.contract_violations = validate_contract_graph(&contract_snapshot)
        .iter()
        .map(contract_violation_manifest)
        .collect();
    report.target_event_tail = executor.event_log().to_vec();
    report.substrate_events = substrate_event_manifests(semantic.event_log().tail(usize::MAX));
    report.command_results = semantic
        .command_results()
        .iter()
        .map(command_result_manifest)
        .collect();
    report.interface_events = interface_event_manifests(semantic.event_log().tail(usize::MAX));
    Ok(report)
}

fn declared_authority_objects(capabilities: &[CapabilityRecord]) -> Vec<ExternalObjectDeclaration> {
    let mut declarations = Vec::new();
    for capability in capabilities {
        let Some(object_ref) = capability.object_ref else {
            continue;
        };
        let object = object_ref.object();
        if declarations
            .iter()
            .any(|declaration: &ExternalObjectDeclaration| declaration.object == object)
        {
            continue;
        }
        declarations.push(ExternalObjectDeclaration::new(
            object,
            "target-executor-authority",
            object_ref.class().as_str(),
            &capability.debug_object_label,
        ));
    }
    declarations
}

fn append_cwasm_smoke_hostcalls(
    code: &mut CodeObject,
    module_index: usize,
    smoke_trace: &[HostValidationSmokeTrace],
) {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let name = format!("cwasm.host-validation.{}", trace.export);
        let object = format!("host-validation.{}", code.package);
        code.hostcalls.push(HostcallSpec::new(
            number,
            &name,
            HostcallCategory::Service,
            &object,
            &trace.export,
            false,
        ));
    }
}

fn run_cwasm_smoke_evidence(
    module_index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
    smoke_trace: &[HostValidationSmokeTrace],
) -> Result<(), Box<dyn Error>> {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let activation = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol(format!("cwasm-smoke:{}", trace.export)),
            )
            .map_err(|error| error.message())?;
        if trace.trap.is_some() {
            executor.synthetic_trap(
                TargetTrapClass::CodeObjectTrap,
                store.store.id,
                Some(activation),
                Some(code),
                Some(&format!("cwasm.host-validation.{}", trace.export)),
                "UnknownCodeTrap: host-validation Wasmtime trap attribution unavailable",
            );
            continue;
        }
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let object = format!("host-validation.{}", code.package);
        let frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            number,
            &object,
            &trace.export,
            1,
        )
        .to_wire_frame();
        executor
            .invoke_hostcall(code, frame, ledger)
            .map_err(|error| error.message())?;
        executor
            .return_exit(activation)
            .map_err(|error| error.message())?;
    }
    Ok(())
}

fn cwasm_smoke_hostcall_number(module_index: usize, trace_index: usize) -> u32 {
    9500 + module_index as u32 * 100 + trace_index as u32
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
            .invoke_hostcall(code, frame.to_wire_frame(), ledger)
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
                HostcallFrame::new_bound(denied, &store.store, code, number, object, operation, 1)
                    .to_wire_frame(),
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
            let frame = HostcallFrame::new_bound(
                bad_abi,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.abi_version = 0;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

            let bad_frame_size = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_frame_size".to_owned()),
                )
                .map_err(|error| error.message())?;
            let frame = HostcallFrame::new_bound(
                bad_frame_size,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

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
                let _ = executor.invoke_hostcall(code, frame.to_wire_frame(), ledger);
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
            HostcallFrame::new_bound(dmw, &store.store, code, 9005, "wait.timer", "park", 1)
                .to_wire_frame(),
            ledger,
        );
        executor
            .release_dmw_lease(lease)
            .map_err(|error| error.message())?;

        let pc_trap = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol("pc_trap_ebreak".to_owned()),
            )
            .map_err(|error| error.message())?;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            RV64_ENTRY_TRAP_EBREAK_OFFSET + 4,
            TrapKindV1::WasmUnreachable,
            0,
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            0,
        )];
        executor
            .trap_exit_by_pc(
                pc_trap,
                code,
                code.text.start + RV64_ENTRY_TRAP_EBREAK_OFFSET,
                &trap_map,
            )
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
        &entry.target_artifact_sha256,
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
                &entry.target_artifact_sha256,
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
    store_generation: u64,
) -> Result<(), &'static str> {
    for capability in &verified.capabilities {
        let operations = capability
            .operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        ledger
            .grant_manifest_binding(
                &verified.package,
                &capability.object,
                &operations,
                &capability.lifetime,
                capability.class,
                Some(store_id),
                Some(store_generation),
                None,
                "target-executor-v1",
            )
            .map_err(|error| error.message())?;
    }
    Ok(())
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
    Some(CapabilityHandleArg::from_record(
        capability,
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
    semantic
        .check_invariants()
        .map_err(|error| format!("semantic invariant failed before package write: {error:?}"))?;
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
            owner_store_generation: capability.owner_store_generation,
            owner_task: capability.owner_task.map(u64::from),
            generation: capability.generation,
            revoked: capability.revoked,
        })
        .collect::<Vec<_>>();
    let capability_count = logical_capabilities.len();
    let wait_records = target_v1
        .wait_records
        .iter()
        .cloned()
        .chain(semantic.wait_records().iter().map(wait_record_manifest))
        .collect::<Vec<_>>();
    let roots = semantic_roots(&logical_capabilities, semantic, target_v1);
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
            pending_wait_count: semantic.pending_wait_count(),
            hart_count: semantic.hart_count(),
            task_count: semantic.task_count(),
            task_record_count: semantic.tasks().len(),
            runtime_activation_count: semantic.runtime_activation_count(),
            runnable_queue_count: semantic.runnable_queue_count(),
            activation_context_count: semantic.activation_context_count(),
            saved_context_count: semantic.saved_context_count(),
            timer_interrupt_count: semantic.timer_interrupt_count(),
            ipi_event_count: semantic.ipi_event_count(),
            remote_preempt_count: semantic.remote_preempt_count(),
            remote_park_count: semantic.remote_park_count(),
            preemption_count: semantic.preemption_count(),
            scheduler_decision_count: semantic.scheduler_decision_count(),
            cross_hart_scheduler_decision_count: semantic.cross_hart_scheduler_decision_count(),
            activation_migration_count: semantic.activation_migration_count(),
            smp_safe_point_count: semantic.smp_safe_point_count(),
            stop_the_world_rendezvous_count: semantic.stop_the_world_rendezvous_count(),
            smp_code_publish_barrier_count: semantic.smp_code_publish_barrier_count(),
            smp_cleanup_quiescence_count: semantic.smp_cleanup_quiescence_count(),
            smp_snapshot_barrier_count: semantic.smp_snapshot_barrier_count(),
            smp_stress_run_count: semantic.smp_stress_run_count(),
            smp_scaling_benchmark_count: semantic.smp_scaling_benchmark_count(),
            device_object_count: semantic.device_object_count(),
            queue_object_count: semantic.queue_object_count(),
            descriptor_object_count: semantic.descriptor_object_count(),
            dma_buffer_object_count: semantic.dma_buffer_object_count(),
            mmio_region_object_count: semantic.mmio_region_object_count(),
            irq_line_object_count: semantic.irq_line_object_count(),
            irq_event_count: semantic.irq_event_count(),
            device_capability_count: semantic.device_capability_count(),
            driver_store_binding_count: semantic.driver_store_binding_count(),
            io_wait_count: semantic.io_wait_count(),
            io_cleanup_count: semantic.io_cleanup_count(),
            io_fault_injection_count: semantic.io_fault_injection_count(),
            io_validation_report_count: semantic.io_validation_report_count(),
            packet_device_object_count: semantic.packet_device_object_count(),
            packet_buffer_object_count: semantic.packet_buffer_object_count(),
            packet_queue_object_count: semantic.packet_queue_object_count(),
            packet_descriptor_object_count: semantic.packet_descriptor_object_count(),
            fake_net_backend_object_count: semantic.fake_net_backend_object_count(),
            virtio_net_backend_object_count: semantic.virtio_net_backend_object_count(),
            network_rx_interrupt_count: semantic.network_rx_interrupt_count(),
            network_rx_wait_resolution_count: semantic.network_rx_wait_resolution_count(),
            network_tx_capability_gate_count: semantic.network_tx_capability_gate_count(),
            network_tx_completion_count: semantic.network_tx_completion_count(),
            network_stack_adapter_count: semantic.network_stack_adapter_count(),
            socket_object_count: semantic.socket_object_count(),
            endpoint_object_count: semantic.endpoint_object_count(),
            socket_operation_count: semantic.socket_operation_count(),
            socket_wait_count: semantic.socket_wait_count(),
            network_backpressure_count: semantic.network_backpressure_count(),
            network_driver_cleanup_count: semantic.network_driver_cleanup_count(),
            network_generation_audit_count: semantic.network_generation_audit_count(),
            network_fault_injection_count: semantic.network_fault_injection_count(),
            network_benchmark_count: semantic.network_benchmark_count(),
            network_recovery_benchmark_count: semantic.network_recovery_benchmark_count(),
            block_device_object_count: semantic.block_device_object_count(),
            block_range_object_count: semantic.block_range_object_count(),
            block_request_object_count: semantic.block_request_object_count(),
            block_completion_object_count: semantic.block_completion_object_count(),
            block_wait_count: semantic.block_wait_count(),
            fake_block_backend_object_count: semantic.fake_block_backend_object_count(),
            virtio_blk_backend_object_count: semantic.virtio_blk_backend_object_count(),
            block_read_path_count: semantic.block_read_path_count(),
            block_write_path_count: semantic.block_write_path_count(),
            block_request_queue_count: semantic.block_request_queue_count(),
            block_dma_buffer_count: semantic.block_dma_buffer_count(),
            block_page_object_count: semantic.block_page_object_count(),
            buffer_cache_object_count: semantic.buffer_cache_object_count(),
            file_object_count: semantic.file_object_count(),
            directory_object_count: semantic.directory_object_count(),
            fat_adapter_object_count: semantic.fat_adapter_object_count(),
            ext4_adapter_object_count: semantic.ext4_adapter_object_count(),
            file_handle_capability_count: semantic.file_handle_capability_count(),
            fs_wait_count: semantic.fs_wait_count(),
            activation_resume_count: semantic.activation_resume_count(),
            activation_wait_count: semantic.activation_wait_count(),
            activation_cleanup_count: semantic.activation_cleanup_count(),
            preemption_latency_sample_count: semantic.preemption_latency_sample_count(),
            hart_event_attribution_count: semantic.hart_event_attribution_count(),
            resource_count: semantic.resource_count(),
            authority_count: semantic.authority_count(),
            active_authority_count: semantic.active_authority_count(),
            wait_token_count: wait_records.len(),
            wait_record_count: wait_records.len(),
            capability_count,
            capability_record_count: target_v1.capability_records.len(),
            fault_domain_count: semantic.fault_domain_count(),
            store_count: semantic.store_count(),
            store_record_count: target_v1.store_records.len(),
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
            tombstone_count: target_v1.tombstones.len(),
            contract_violation_count: target_v1.contract_violations.len(),
            cleanup_transaction_count: target_v1.cleanup_transactions.len(),
            memory_policy_count: target_v1.memory_policies.len(),
            snapshot_validation_violation_count: target_v1.snapshot_validation.violation_count,
            replay_validation_violation_count: target_v1.replay_validation.violation_count,
            substrate_event_count: target_v1.substrate_events.len(),
            command_result_count: target_v1.command_results.len(),
            interface_event_count: target_v1.interface_events.len(),
            target_artifacts: target_v1.target_artifacts.clone(),
            hart_records: semantic.harts().iter().map(hart_record_manifest).collect(),
            task_records: semantic.tasks().iter().map(task_record_manifest).collect(),
            runtime_activation_records: semantic
                .runtime_activations()
                .iter()
                .map(runtime_activation_record_manifest)
                .collect(),
            runnable_queues: semantic
                .runnable_queues()
                .iter()
                .map(runnable_queue_manifest)
                .collect(),
            activation_contexts: semantic
                .activation_contexts()
                .iter()
                .map(activation_context_manifest)
                .collect(),
            saved_contexts: semantic
                .saved_contexts()
                .iter()
                .map(saved_context_manifest)
                .collect(),
            timer_interrupts: semantic
                .timer_interrupts()
                .iter()
                .map(timer_interrupt_manifest)
                .collect(),
            ipi_events: semantic
                .ipi_events()
                .iter()
                .map(ipi_event_manifest)
                .collect(),
            remote_preempts: semantic
                .remote_preempts()
                .iter()
                .map(remote_preempt_manifest)
                .collect(),
            remote_parks: semantic
                .remote_parks()
                .iter()
                .map(remote_park_manifest)
                .collect(),
            preemptions: semantic
                .preemptions()
                .iter()
                .map(preemption_manifest)
                .collect(),
            scheduler_decisions: semantic
                .scheduler_decisions()
                .iter()
                .map(scheduler_decision_manifest)
                .collect(),
            cross_hart_scheduler_decisions: semantic
                .cross_hart_scheduler_decisions()
                .iter()
                .map(cross_hart_scheduler_decision_manifest)
                .collect(),
            activation_migrations: semantic
                .activation_migrations()
                .iter()
                .map(activation_migration_manifest)
                .collect(),
            smp_safe_points: semantic
                .smp_safe_points()
                .iter()
                .map(smp_safe_point_manifest)
                .collect(),
            stop_the_world_rendezvous: semantic
                .stop_the_world_rendezvous()
                .iter()
                .map(stop_the_world_rendezvous_manifest)
                .collect(),
            smp_code_publish_barriers: semantic
                .smp_code_publish_barriers()
                .iter()
                .map(smp_code_publish_barrier_manifest)
                .collect(),
            smp_cleanup_quiescence: semantic
                .smp_cleanup_quiescence()
                .iter()
                .map(smp_cleanup_quiescence_manifest)
                .collect(),
            smp_snapshot_barriers: semantic
                .smp_snapshot_barriers()
                .iter()
                .map(smp_snapshot_barrier_manifest)
                .collect(),
            smp_stress_runs: semantic
                .smp_stress_runs()
                .iter()
                .map(smp_stress_run_manifest)
                .collect(),
            smp_scaling_benchmarks: semantic
                .smp_scaling_benchmarks()
                .iter()
                .map(smp_scaling_benchmark_manifest)
                .collect(),
            device_objects: semantic
                .device_objects()
                .iter()
                .map(device_object_manifest)
                .collect(),
            queue_objects: semantic
                .queue_objects()
                .iter()
                .map(queue_object_manifest)
                .collect(),
            descriptor_objects: semantic
                .descriptor_objects()
                .iter()
                .map(descriptor_object_manifest)
                .collect(),
            dma_buffer_objects: semantic
                .dma_buffer_objects()
                .iter()
                .map(dma_buffer_object_manifest)
                .collect(),
            mmio_region_objects: semantic
                .mmio_region_objects()
                .iter()
                .map(mmio_region_object_manifest)
                .collect(),
            irq_line_objects: semantic
                .irq_line_objects()
                .iter()
                .map(irq_line_object_manifest)
                .collect(),
            irq_events: semantic
                .irq_events()
                .iter()
                .map(irq_event_manifest)
                .collect(),
            device_capabilities: semantic
                .device_capabilities()
                .iter()
                .map(device_capability_manifest)
                .collect(),
            driver_store_bindings: semantic
                .driver_store_bindings()
                .iter()
                .map(driver_store_binding_manifest)
                .collect(),
            io_waits: semantic.io_waits().iter().map(io_wait_manifest).collect(),
            io_cleanups: semantic
                .io_cleanups()
                .iter()
                .map(io_cleanup_manifest)
                .collect(),
            io_fault_injections: semantic
                .io_fault_injections()
                .iter()
                .map(io_fault_injection_manifest)
                .collect(),
            io_validation_reports: semantic
                .io_validation_reports()
                .iter()
                .map(io_validation_report_manifest)
                .collect(),
            packet_device_objects: semantic
                .packet_device_objects()
                .iter()
                .map(packet_device_object_manifest)
                .collect(),
            packet_buffer_objects: semantic
                .packet_buffer_objects()
                .iter()
                .map(packet_buffer_object_manifest)
                .collect(),
            packet_queue_objects: semantic
                .packet_queue_objects()
                .iter()
                .map(packet_queue_object_manifest)
                .collect(),
            packet_descriptors: semantic
                .packet_descriptors()
                .iter()
                .map(packet_descriptor_object_manifest)
                .collect(),
            fake_net_backends: semantic
                .fake_net_backends()
                .iter()
                .map(fake_net_backend_object_manifest)
                .collect(),
            virtio_net_backends: semantic
                .virtio_net_backends()
                .iter()
                .map(virtio_net_backend_object_manifest)
                .collect(),
            network_rx_interrupts: semantic
                .network_rx_interrupts()
                .iter()
                .map(network_rx_interrupt_manifest)
                .collect(),
            network_rx_wait_resolutions: semantic
                .network_rx_wait_resolutions()
                .iter()
                .map(network_rx_wait_resolution_manifest)
                .collect(),
            network_tx_capability_gates: semantic
                .network_tx_capability_gates()
                .iter()
                .map(network_tx_capability_gate_manifest)
                .collect(),
            network_tx_completions: semantic
                .network_tx_completions()
                .iter()
                .map(network_tx_completion_manifest)
                .collect(),
            network_stack_adapters: semantic
                .network_stack_adapters()
                .iter()
                .map(network_stack_adapter_manifest)
                .collect(),
            socket_objects: semantic
                .socket_objects()
                .iter()
                .map(socket_object_manifest)
                .collect(),
            endpoint_objects: semantic
                .endpoint_objects()
                .iter()
                .map(endpoint_object_manifest)
                .collect(),
            socket_operations: semantic
                .socket_operations()
                .iter()
                .map(socket_operation_manifest)
                .collect(),
            socket_waits: semantic
                .socket_waits()
                .iter()
                .map(socket_wait_manifest)
                .collect(),
            network_backpressures: semantic
                .network_backpressures()
                .iter()
                .map(network_backpressure_manifest)
                .collect(),
            network_driver_cleanups: semantic
                .network_driver_cleanups()
                .iter()
                .map(network_driver_cleanup_manifest)
                .collect(),
            network_generation_audits: semantic
                .network_generation_audits()
                .iter()
                .map(network_generation_audit_manifest)
                .collect(),
            network_fault_injections: semantic
                .network_fault_injections()
                .iter()
                .map(network_fault_injection_manifest)
                .collect(),
            network_benchmarks: semantic
                .network_benchmarks()
                .iter()
                .map(network_benchmark_manifest)
                .collect(),
            network_recovery_benchmarks: semantic
                .network_recovery_benchmarks()
                .iter()
                .map(network_recovery_benchmark_manifest)
                .collect(),
            block_device_objects: semantic
                .block_device_objects()
                .iter()
                .map(block_device_object_manifest)
                .collect(),
            block_range_objects: semantic
                .block_range_objects()
                .iter()
                .map(block_range_object_manifest)
                .collect(),
            block_request_objects: semantic
                .block_request_objects()
                .iter()
                .map(block_request_object_manifest)
                .collect(),
            block_completion_objects: semantic
                .block_completion_objects()
                .iter()
                .map(block_completion_object_manifest)
                .collect(),
            block_waits: semantic
                .block_waits()
                .iter()
                .map(block_wait_manifest)
                .collect(),
            fake_block_backends: semantic
                .fake_block_backends()
                .iter()
                .map(fake_block_backend_object_manifest)
                .collect(),
            virtio_blk_backends: semantic
                .virtio_blk_backends()
                .iter()
                .map(virtio_blk_backend_object_manifest)
                .collect(),
            block_read_paths: semantic
                .block_read_paths()
                .iter()
                .map(block_read_path_manifest)
                .collect(),
            block_write_paths: semantic
                .block_write_paths()
                .iter()
                .map(block_write_path_manifest)
                .collect(),
            block_request_queues: semantic
                .block_request_queues()
                .iter()
                .map(block_request_queue_manifest)
                .collect(),
            block_dma_buffers: semantic
                .block_dma_buffers()
                .iter()
                .map(block_dma_buffer_manifest)
                .collect(),
            block_page_objects: semantic
                .block_page_objects()
                .iter()
                .map(block_page_object_manifest)
                .collect(),
            buffer_cache_objects: semantic
                .buffer_cache_objects()
                .iter()
                .map(buffer_cache_object_manifest)
                .collect(),
            file_objects: semantic
                .file_objects()
                .iter()
                .map(file_object_manifest)
                .collect(),
            directory_objects: semantic
                .directory_objects()
                .iter()
                .map(directory_object_manifest)
                .collect(),
            fat_adapter_objects: semantic
                .fat_adapter_objects()
                .iter()
                .map(fat_adapter_object_manifest)
                .collect(),
            ext4_adapter_objects: semantic
                .ext4_adapter_objects()
                .iter()
                .map(ext4_adapter_object_manifest)
                .collect(),
            file_handle_capabilities: semantic
                .file_handle_capabilities()
                .iter()
                .map(file_handle_capability_manifest)
                .collect(),
            fs_waits: semantic.fs_waits().iter().map(fs_wait_manifest).collect(),
            activation_resumes: semantic
                .activation_resumes()
                .iter()
                .map(activation_resume_manifest)
                .collect(),
            activation_waits: semantic
                .activation_waits()
                .iter()
                .map(activation_wait_manifest)
                .collect(),
            activation_cleanups: semantic
                .activation_cleanups()
                .iter()
                .map(activation_cleanup_manifest)
                .collect(),
            preemption_latency_samples: semantic
                .preemption_latency_samples()
                .iter()
                .map(preemption_latency_manifest)
                .collect(),
            hart_event_attributions: semantic
                .hart_event_attributions()
                .iter()
                .map(hart_event_attribution_manifest)
                .collect(),
            code_objects: target_v1.code_objects.clone(),
            store_records: target_v1.store_records.clone(),
            capability_records: target_v1.capability_records.clone(),
            wait_records,
            activation_records: target_v1.activation_records.clone(),
            trap_records: target_v1.trap_records.clone(),
            hostcall_trace: target_v1.hostcall_trace.clone(),
            migration_objects: target_v1.migration_objects.clone(),
            tombstones: target_v1.tombstones.clone(),
            contract_violations: target_v1.contract_violations.clone(),
            cleanup_transactions: target_v1.cleanup_transactions.clone(),
            memory_policies: target_v1.memory_policies.clone(),
            snapshot_validation: target_v1.snapshot_validation.clone(),
            replay_validation: target_v1.replay_validation.clone(),
            substrate_events: target_v1.substrate_events.clone(),
            command_results: target_v1.command_results.clone(),
            interface_events: target_v1.interface_events.clone(),
            network_socket_count: 1,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities,
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: semantic.timer_epoch(),
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
    capabilities: &[MigrationCapabilityManifest],
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> SemanticRootSetManifest {
    SemanticRootSetManifest {
        hart_roots: semantic
            .harts()
            .iter()
            .map(|hart| {
                format!(
                    "hart id={} hardware_id={} label={} state={} generation={} boot={} current={}@{}",
                    hart.id,
                    hart.hardware_id,
                    hart.label,
                    hart.state.as_str(),
                    hart.generation,
                    hart.boot,
                    hart.current_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    hart.current_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        task_roots: semantic
            .tasks()
            .iter()
            .map(|task| {
                format!(
                    "task:{}:{}:{}:gen{}",
                    task.id,
                    task.frontend.as_str(),
                    task.state.as_str(),
                    task.generation
                )
            })
            .collect(),
        task_record_roots: semantic
            .tasks()
            .iter()
            .map(|task| format!("task-record id={} state={} generation={}", task.id, task.state.as_str(), task.generation))
            .collect(),
        runtime_activation_roots: semantic
            .runtime_activations()
            .iter()
            .map(|activation| {
                format!(
                    "runtime-activation id={} task={}@{} state={} generation={} queue={}@{}",
                    activation.id,
                    activation.owner_task,
                    activation.owner_task_generation,
                    activation.state.as_str(),
                    activation.generation,
                    activation
                        .runnable_queue
                        .map(|queue| queue.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    activation
                        .runnable_queue_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        runnable_queue_roots: semantic
            .runnable_queues()
            .iter()
            .map(|queue| {
                format!(
                    "runnable-queue id={} label={} state={} generation={} entries={}",
                    queue.id,
                    queue.label,
                    queue.state.as_str(),
                    queue.generation,
                    queue.entries.len()
                )
            })
            .collect(),
        activation_context_roots: semantic
            .activation_contexts()
            .iter()
            .map(|context| {
                format!(
                    "activation-context id={} activation={}@{} state={} generation={} saved={}@{}",
                    context.id,
                    context.activation,
                    context.activation_generation,
                    context.state.as_str(),
                    context.generation,
                    context
                        .current_saved_context
                        .map(|saved| saved.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context
                        .current_saved_context_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        saved_context_roots: semantic
            .saved_contexts()
            .iter()
            .map(|saved| {
                format!(
                    "saved-context id={} context={}@{} activation={}@{} state={} reason={} pc={:#x} sp={:#x} generation={}",
                    saved.id,
                    saved.context,
                    saved.context_generation,
                    saved.activation,
                    saved.activation_generation,
                    saved.state.as_str(),
                    saved.reason.as_str(),
                    saved.pc,
                    saved.sp,
                    saved.generation
                )
            })
            .collect(),
        timer_interrupt_roots: semantic
            .timer_interrupts()
            .iter()
            .map(|interrupt| {
                format!(
                    "timer-interrupt id={} epoch={} hart={} target={}@{} state={} generation={}",
                    interrupt.id,
                    interrupt.timer_epoch,
                    interrupt.hart,
                    interrupt
                        .target_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt
                        .target_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt.state.as_str(),
                    interrupt.generation
                )
            })
            .collect(),
        ipi_event_roots: semantic
            .ipi_events()
            .iter()
            .map(|ipi| {
                format!(
                    "ipi-event id={} kind={} source_hart={}@{} target_hart={}@{} state={} generation={}",
                    ipi.id,
                    ipi.kind.as_str(),
                    ipi.source_hart,
                    ipi.source_hart_generation,
                    ipi.target_hart,
                    ipi.target_hart_generation,
                    ipi.state.as_str(),
                    ipi.generation
                )
            })
            .collect(),
        remote_preempt_roots: semantic
            .remote_preempts()
            .iter()
            .map(|remote| {
                format!(
                    "remote-preempt id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} activation={}@{}->{} queue={}@{} state={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.activation,
                    remote.activation_generation_before,
                    remote.activation_generation_after,
                    remote.queue,
                    remote.queue_generation,
                    remote.state.as_str(),
                    remote.generation
                )
            })
            .collect(),
        remote_park_roots: semantic
            .remote_parks()
            .iter()
            .map(|remote| {
                format!(
                    "remote-park id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} state={} reason={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.state.as_str(),
                    remote.reason,
                    remote.generation
                )
            })
            .collect(),
        preemption_roots: semantic
            .preemptions()
            .iter()
            .map(|preemption| {
                format!(
                    "preemption id={} activation={}@{}->{} timer={}@{} queue={}@{} state={} generation={}",
                    preemption.id,
                    preemption.activation,
                    preemption.activation_generation_before,
                    preemption.activation_generation_after,
                    preemption.timer_interrupt,
                    preemption.timer_interrupt_generation,
                    preemption.queue,
                    preemption.queue_generation,
                    preemption.state.as_str(),
                    preemption.generation
                )
            })
            .collect(),
        scheduler_decision_roots: semantic
            .scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "scheduler-decision id={} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect(),
        cross_hart_scheduler_decision_roots: semantic
            .cross_hart_scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "cross-hart-scheduler-decision id={} decision={}@{} deciding_hart={}@{} target_hart={}@{} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.scheduler_decision,
                    decision.scheduler_decision_generation,
                    decision.deciding_hart,
                    decision.deciding_hart_generation,
                    decision.target_hart,
                    decision.target_hart_generation,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect(),
        activation_migration_roots: semantic
            .activation_migrations()
            .iter()
            .map(|migration| {
                format!(
                    "activation-migration id={} activation={}@{}->{} source_hart={}@{} target_hart={}@{} source_queue={}@{} target_queue={}@{} state={} generation={}",
                    migration.id,
                    migration.activation,
                    migration.activation_generation_before,
                    migration.activation_generation_after,
                    migration.source_hart,
                    migration.source_hart_generation,
                    migration.target_hart,
                    migration.target_hart_generation,
                    migration.source_queue,
                    migration.source_queue_generation,
                    migration.target_queue,
                    migration.target_queue_generation,
                    migration.state.as_str(),
                    migration.generation
                )
            })
            .collect(),
        smp_safe_point_roots: semantic
            .smp_safe_points()
            .iter()
            .map(|safe_point| {
                format!(
                    "smp-safe-point id={} coordinator_hart={}@{} participants={} state={} generation={}",
                    safe_point.id,
                    safe_point.coordinator_hart,
                    safe_point.coordinator_hart_generation,
                    safe_point.participants.len(),
                    safe_point.state.as_str(),
                    safe_point.generation
                )
            })
            .collect(),
        stop_the_world_rendezvous_roots: semantic
            .stop_the_world_rendezvous()
            .iter()
            .map(|rendezvous| {
                format!(
                    "stop-the-world-rendezvous id={} epoch={} safe_point={}@{} participants={} state={} generation={}",
                    rendezvous.id,
                    rendezvous.epoch,
                    rendezvous.safe_point,
                    rendezvous.safe_point_generation,
                    rendezvous.participants.len(),
                    rendezvous.state.as_str(),
                    rendezvous.generation
                )
            })
            .collect(),
        smp_code_publish_barrier_roots: semantic
            .smp_code_publish_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-code-publish-barrier id={} rendezvous={}@{} code_publish_epoch={}->{} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.code_publish_epoch_before,
                    barrier.code_publish_epoch_after,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect(),
        smp_cleanup_quiescence_roots: semantic
            .smp_cleanup_quiescence()
            .iter()
            .map(|quiescence| {
                format!(
                    "smp-cleanup-quiescence id={} cleanup={}@{} store={}@{}->{} rendezvous={}@{} participants={} state={} generation={}",
                    quiescence.id,
                    quiescence.cleanup,
                    quiescence.cleanup_generation,
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                    quiescence.rendezvous,
                    quiescence.rendezvous_generation,
                    quiescence.participants.len(),
                    quiescence.state.as_str(),
                    quiescence.generation
                )
            })
            .collect(),
        smp_snapshot_barrier_roots: semantic
            .smp_snapshot_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-snapshot-barrier id={} rendezvous={}@{} cursor={} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.event_log_cursor,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect(),
        smp_stress_run_roots: semantic
            .smp_stress_runs()
            .iter()
            .map(|run| {
                format!(
                    "smp-stress-run id={} scenario={} iterations={} invariants={} failures={} cursor={} generation={}",
                    run.id,
                    run.scenario,
                    run.iterations,
                    run.invariant_checks,
                    run.property_failures,
                    run.event_log_cursor,
                    run.generation
                )
            })
            .collect(),
        smp_scaling_benchmark_roots: semantic
            .smp_scaling_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "smp-scaling-benchmark id={} scenario={} stress_run={}@{} harts={} workload_units={} measured_nanos={} speedup_milli={} efficiency_milli={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.stress_run,
                    benchmark.stress_run_generation,
                    benchmark.hart_count,
                    benchmark.workload_units,
                    benchmark.measured_smp_nanos,
                    benchmark.speedup_milli,
                    benchmark.efficiency_milli,
                    benchmark.generation
                )
            })
            .collect(),
        device_object_roots: semantic
            .device_objects()
            .iter()
            .map(|device| {
                format!(
                    "device-object id={} name={} class={} resource={}@{} backend={} state={} generation={}",
                    device.id,
                    device.name,
                    device.class,
                    device.resource,
                    device.resource_generation,
                    device.backend,
                    device.state.as_str(),
                    device.generation
                )
            })
            .collect(),
        queue_object_roots: semantic
            .queue_objects()
            .iter()
            .map(|queue| {
                format!(
                    "queue-object id={} name={} role={} index={} depth={} device={}@{} state={} generation={}",
                    queue.id,
                    queue.name,
                    queue.role.as_str(),
                    queue.queue_index,
                    queue.depth,
                    queue.device,
                    queue.device_generation,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect(),
        descriptor_object_roots: semantic
            .descriptor_objects()
            .iter()
            .map(|descriptor| {
                format!(
                    "descriptor-object id={} queue={}@{} slot={} access={} length={} state={} generation={}",
                    descriptor.id,
                    descriptor.queue,
                    descriptor.queue_generation,
                    descriptor.slot,
                    descriptor.access.as_str(),
                    descriptor.length,
                    descriptor.state.as_str(),
                    descriptor.generation
                )
            })
            .collect(),
        dma_buffer_object_roots: semantic
            .dma_buffer_objects()
            .iter()
            .map(|dma_buffer| {
                format!(
                    "dma-buffer-object id={} descriptor={}@{} resource={}@{} access={} length={} state={} generation={}",
                    dma_buffer.id,
                    dma_buffer.descriptor,
                    dma_buffer.descriptor_generation,
                    dma_buffer.resource,
                    dma_buffer.resource_generation,
                    dma_buffer.access.as_str(),
                    dma_buffer.length,
                    dma_buffer.state.as_str(),
                    dma_buffer.generation
                )
            })
            .collect(),
        mmio_region_object_roots: semantic
            .mmio_region_objects()
            .iter()
            .map(|mmio_region| {
                format!(
                    "mmio-region-object id={} device={}@{} resource={}@{} index={} offset={} length={} access={} state={} generation={}",
                    mmio_region.id,
                    mmio_region.device,
                    mmio_region.device_generation,
                    mmio_region.resource,
                    mmio_region.resource_generation,
                    mmio_region.region_index,
                    mmio_region.offset,
                    mmio_region.length,
                    mmio_region.access.as_str(),
                    mmio_region.state.as_str(),
                    mmio_region.generation
                )
            })
            .collect(),
        irq_line_object_roots: semantic
            .irq_line_objects()
            .iter()
            .map(|irq_line| {
                format!(
                    "irq-line-object id={} device={}@{} resource={}@{} irq_number={} trigger={} polarity={} state={} generation={}",
                    irq_line.id,
                    irq_line.device,
                    irq_line.device_generation,
                    irq_line.resource,
                    irq_line.resource_generation,
                    irq_line.irq_number,
                    irq_line.trigger.as_str(),
                    irq_line.polarity.as_str(),
                    irq_line.state.as_str(),
                    irq_line.generation
                )
            })
            .collect(),
        irq_event_roots: semantic
            .irq_events()
            .iter()
            .map(|irq_event| {
                format!(
                    "irq-event id={} irq_line={}@{} device={}@{} driver_store={}@{} irq_number={} sequence={} state={} generation={}",
                    irq_event.id,
                    irq_event.irq_line,
                    irq_event.irq_line_generation,
                    irq_event.device,
                    irq_event.device_generation,
                    irq_event.driver_store,
                    irq_event.driver_store_generation,
                    irq_event.irq_number,
                    irq_event.sequence,
                    irq_event.state.as_str(),
                    irq_event.generation
                )
            })
            .collect(),
        device_capability_roots: semantic
            .device_capabilities()
            .iter()
            .map(|device_capability| {
                format!(
                    "device-capability id={} driver_store={}@{} target={} class={} operation={} capability={}@{} state={} generation={}",
                    device_capability.id,
                    device_capability.driver_store,
                    device_capability.driver_store_generation,
                    device_capability.target.summary(),
                    device_capability.class.as_str(),
                    device_capability.operation,
                    device_capability.capability,
                    device_capability.capability_generation,
                    device_capability.state.as_str(),
                    device_capability.generation
                )
            })
            .collect(),
        driver_store_binding_roots: semantic
            .driver_store_bindings()
            .iter()
            .map(|binding| {
                format!(
                    "driver-store-binding id={} driver_store={}@{} device={}@{} device_capability={}@{} capability={}@{} state={} generation={}",
                    binding.id,
                    binding.driver_store,
                    binding.driver_store_generation,
                    binding.device,
                    binding.device_generation,
                    binding.device_capability,
                    binding.device_capability_generation,
                    binding.capability,
                    binding.capability_generation,
                    binding.state.as_str(),
                    binding.generation
                )
            })
            .collect(),
        io_wait_roots: semantic
            .io_waits()
            .iter()
            .map(|io_wait| {
                format!(
                    "io-wait id={} wait={}@{} driver_store={}@{} device={}@{} binding={}@{} blocker={} state={} generation={}",
                    io_wait.id,
                    io_wait.wait,
                    io_wait.wait_generation,
                    io_wait.driver_store,
                    io_wait.driver_store_generation,
                    io_wait.device,
                    io_wait.device_generation,
                    io_wait.driver_binding,
                    io_wait.driver_binding_generation,
                    io_wait.blocker.summary(),
                    io_wait.state.as_str(),
                    io_wait.generation
                )
            })
            .collect(),
        io_cleanup_roots: semantic
            .io_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "io-cleanup id={} driver_store={}@{} device={}@{} binding={}@{} state={} generation={} cancelled_io_waits={} revoked_device_capabilities={} released_dma_buffers={} released_mmio_regions={} released_irq_lines={}",
                    cleanup.id,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_io_waits.len(),
                    cleanup.revoked_device_capabilities.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.released_mmio_regions.len(),
                    cleanup.released_irq_lines.len()
                )
            })
            .collect(),
        io_fault_injection_roots: semantic
            .io_fault_injections()
            .iter()
            .map(|fault| {
                format!(
                    "io-fault-injection id={} kind={} driver_store={}@{} device={}@{} binding={}@{} target={} cleanup={}@{} state={} generation={}",
                    fault.id,
                    fault.kind.as_str(),
                    fault.driver_store,
                    fault.driver_store_generation,
                    fault.device,
                    fault.device_generation,
                    fault.driver_binding,
                    fault.driver_binding_generation,
                    fault.target.summary(),
                    fault.cleanup,
                    fault.cleanup_generation,
                    fault.state.as_str(),
                    fault.generation
                )
            })
            .collect(),
        io_validation_report_roots: semantic
            .io_validation_reports()
            .iter()
            .map(|report| {
                format!(
                    "io-validation-report id={} state={} violations={} devices={} dma_buffers={} irq_events={} cleanups={} fault_injections={} generation={}",
                    report.id,
                    report.state.as_str(),
                    report.violations.len(),
                    report.observed_device_count,
                    report.observed_dma_buffer_count,
                    report.observed_irq_event_count,
                    report.observed_io_cleanup_count,
                    report.observed_io_fault_injection_count,
                    report.generation
                )
            })
            .collect(),
        packet_device_object_roots: semantic
            .packet_device_objects()
            .iter()
            .map(|packet_device| {
                format!(
                    "packet-device-object id={} name={} device={}@{} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} state={} generation={}",
                    packet_device.id,
                    packet_device.name,
                    packet_device.device,
                    packet_device.device_generation,
                    packet_device.mtu,
                    packet_device.rx_queue_depth,
                    packet_device.tx_queue_depth,
                    packet_device.frame_format_version,
                    packet_device.max_payload_len,
                    packet_device.state.as_str(),
                    packet_device.generation
                )
            })
            .collect(),
        packet_buffer_object_roots: semantic
            .packet_buffer_objects()
            .iter()
            .map(|packet_buffer| {
                format!(
                    "packet-buffer-object id={} packet_device={}@{} direction={} frame_format_version={} capacity={} payload_len={} sequence={} state={} generation={}",
                    packet_buffer.id,
                    packet_buffer.packet_device,
                    packet_buffer.packet_device_generation,
                    packet_buffer.direction.as_str(),
                    packet_buffer.frame_format_version,
                    packet_buffer.capacity,
                    packet_buffer.payload_len,
                    packet_buffer.sequence,
                    packet_buffer.state.as_str(),
                    packet_buffer.generation
                )
            })
            .collect(),
        packet_queue_object_roots: semantic
            .packet_queue_objects()
            .iter()
            .map(|packet_queue| {
                format!(
                    "packet-queue-object id={} name={} packet_device={}@{} role={} queue_index={} depth={} state={} generation={}",
                    packet_queue.id,
                    packet_queue.name,
                    packet_queue.packet_device,
                    packet_queue.packet_device_generation,
                    packet_queue.role.as_str(),
                    packet_queue.queue_index,
                    packet_queue.depth,
                    packet_queue.state.as_str(),
                    packet_queue.generation
                )
            })
            .collect(),
        packet_descriptor_object_roots: semantic
            .packet_descriptors()
            .iter()
            .map(|packet_descriptor| {
                format!(
                    "packet-descriptor-object id={} packet_queue={}@{} packet_buffer={}@{} slot={} length={} state={} generation={}",
                    packet_descriptor.id,
                    packet_descriptor.packet_queue,
                    packet_descriptor.packet_queue_generation,
                    packet_descriptor.packet_buffer,
                    packet_descriptor.packet_buffer_generation,
                    packet_descriptor.slot,
                    packet_descriptor.length,
                    packet_descriptor.state.as_str(),
                    packet_descriptor.generation
                )
            })
            .collect(),
        fake_net_backend_object_roots: semantic
            .fake_net_backends()
            .iter()
            .map(|backend| {
                format!(
                    "fake-net-backend-object id={} name={} packet_device={}@{} provider={} profile={} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} deterministic_seed={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.packet_device,
                    backend.packet_device_generation,
                    backend.provider,
                    backend.profile,
                    backend.mtu,
                    backend.rx_queue_depth,
                    backend.tx_queue_depth,
                    backend.frame_format_version,
                    backend.max_payload_len,
                    backend.deterministic_seed,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        virtio_net_backend_object_roots: semantic
            .virtio_net_backends()
            .iter()
            .map(|backend| {
                format!(
                    "virtio-net-backend-object id={} name={} packet_device={}@{} driver_binding={}@{} device={}@{} provider={} profile={} model={} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} device_features={} driver_features={} negotiated_features={} rx_queue_index={} tx_queue_index={} queue_size={} irq_vector={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.packet_device,
                    backend.packet_device_generation,
                    backend.driver_binding,
                    backend.driver_binding_generation,
                    backend.device,
                    backend.device_generation,
                    backend.provider,
                    backend.profile,
                    backend.model,
                    backend.mtu,
                    backend.rx_queue_depth,
                    backend.tx_queue_depth,
                    backend.frame_format_version,
                    backend.max_payload_len,
                    backend.device_features,
                    backend.driver_features,
                    backend.negotiated_features,
                    backend.rx_queue_index,
                    backend.tx_queue_index,
                    backend.queue_size,
                    backend.irq_vector,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        network_rx_interrupt_roots: semantic
            .network_rx_interrupts()
            .iter()
            .map(|rx_interrupt| {
                format!(
                    "network-rx-interrupt id={} virtio_net_backend={}@{} irq_event={}@{} packet_device={}@{} rx_queue={}@{} ready_descriptors={} sequence={} state={} generation={}",
                    rx_interrupt.id,
                    rx_interrupt.virtio_net_backend,
                    rx_interrupt.virtio_net_backend_generation,
                    rx_interrupt.irq_event,
                    rx_interrupt.irq_event_generation,
                    rx_interrupt.packet_device,
                    rx_interrupt.packet_device_generation,
                    rx_interrupt.rx_queue,
                    rx_interrupt.rx_queue_generation,
                    rx_interrupt.ready_descriptors,
                    rx_interrupt.sequence,
                    rx_interrupt.state.as_str(),
                    rx_interrupt.generation
                )
            })
            .collect(),
        network_rx_wait_resolution_roots: semantic
            .network_rx_wait_resolutions()
            .iter()
            .map(|resolution| {
                format!(
                    "network-rx-wait-resolution id={} io_wait={}@{} wait={}@{} rx_interrupt={}@{} irq_event={}@{} rx_queue={}@{} ready_descriptors={} state={} generation={}",
                    resolution.id,
                    resolution.io_wait,
                    resolution.io_wait_generation,
                    resolution.wait,
                    resolution.wait_generation,
                    resolution.rx_interrupt,
                    resolution.rx_interrupt_generation,
                    resolution.irq_event,
                    resolution.irq_event_generation,
                    resolution.rx_queue,
                    resolution.rx_queue_generation,
                    resolution.ready_descriptors,
                    resolution.state.as_str(),
                    resolution.generation
                )
            })
            .collect(),
        network_tx_capability_gate_roots: semantic
            .network_tx_capability_gates()
            .iter()
            .map(|gate| {
                format!(
                    "network-tx-capability-gate id={} driver_store={}@{} packet_device={}@{} tx_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} device_capability={}@{} capability={}@{} operation={} byte_len={} sequence={} state={} generation={}",
                    gate.id,
                    gate.driver_store,
                    gate.driver_store_generation,
                    gate.packet_device,
                    gate.packet_device_generation,
                    gate.tx_queue,
                    gate.tx_queue_generation,
                    gate.packet_descriptor,
                    gate.packet_descriptor_generation,
                    gate.packet_buffer,
                    gate.packet_buffer_generation,
                    gate.device_capability,
                    gate.device_capability_generation,
                    gate.capability,
                    gate.capability_generation,
                    gate.operation,
                    gate.byte_len,
                    gate.sequence,
                    gate.state.as_str(),
                    gate.generation
                )
            })
            .collect(),
        network_tx_completion_roots: semantic
            .network_tx_completions()
            .iter()
            .map(|completion| {
                format!(
                    "network-tx-completion id={} tx_gate={}@{} backend={} driver_store={}@{} packet_device={}@{} tx_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} byte_len={} sequence={} completion_sequence={} state={} generation={}",
                    completion.id,
                    completion.tx_gate,
                    completion.tx_gate_generation,
                    completion.backend.summary(),
                    completion.driver_store,
                    completion.driver_store_generation,
                    completion.packet_device,
                    completion.packet_device_generation,
                    completion.tx_queue,
                    completion.tx_queue_generation,
                    completion.packet_descriptor,
                    completion.packet_descriptor_generation,
                    completion.packet_buffer,
                    completion.packet_buffer_generation,
                    completion.byte_len,
                    completion.sequence,
                    completion.completion_sequence,
                    completion.state.as_str(),
                    completion.generation
                )
            })
            .collect(),
        network_stack_adapter_roots: semantic
            .network_stack_adapters()
            .iter()
            .map(|adapter| {
                format!(
                    "network-stack-adapter id={} implementation={} version={} profile={} medium={} backend={} packet_device={}@{} rx_queue={}@{} tx_queue={}@{} ipv4={}.{}.{}.{}/{} mtu={} rx_queue_depth={} tx_queue_depth={} max_payload_len={} socket_capacity={} state={} generation={}",
                    adapter.id,
                    adapter.implementation,
                    adapter.implementation_version,
                    adapter.profile,
                    adapter.medium,
                    adapter.backend.summary(),
                    adapter.packet_device,
                    adapter.packet_device_generation,
                    adapter.rx_queue,
                    adapter.rx_queue_generation,
                    adapter.tx_queue,
                    adapter.tx_queue_generation,
                    adapter.ipv4_addr[0],
                    adapter.ipv4_addr[1],
                    adapter.ipv4_addr[2],
                    adapter.ipv4_addr[3],
                    adapter.ipv4_prefix_len,
                    adapter.mtu,
                    adapter.rx_queue_depth,
                    adapter.tx_queue_depth,
                    adapter.max_payload_len,
                    adapter.socket_capacity,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        socket_object_roots: semantic
            .socket_objects()
            .iter()
            .map(|socket| {
                format!(
                    "socket-object id={} adapter={}@{} owner_store={}@{} domain={} type={} protocol={} canonical_protocol={} family={} transport={} state={} generation={}",
                    socket.id,
                    socket.adapter,
                    socket.adapter_generation,
                    socket.owner_store,
                    socket.owner_store_generation,
                    socket.domain,
                    socket.socket_type,
                    socket.protocol,
                    socket.canonical_protocol,
                    socket.family,
                    socket.transport,
                    socket.state.as_str(),
                    socket.generation
                )
            })
            .collect(),
        endpoint_object_roots: semantic
            .endpoint_objects()
            .iter()
            .map(|endpoint| {
                format!(
                    "endpoint-object id={} socket={}@{} adapter={}@{} owner_store={}@{} family={} transport={} local={}.{}.{}.{}:{} remote={}.{}.{}.{}:{} state={} generation={}",
                    endpoint.id,
                    endpoint.socket,
                    endpoint.socket_generation,
                    endpoint.adapter,
                    endpoint.adapter_generation,
                    endpoint.owner_store,
                    endpoint.owner_store_generation,
                    endpoint.family,
                    endpoint.transport,
                    endpoint.local_addr[0],
                    endpoint.local_addr[1],
                    endpoint.local_addr[2],
                    endpoint.local_addr[3],
                    endpoint.local_port,
                    endpoint.remote_addr[0],
                    endpoint.remote_addr[1],
                    endpoint.remote_addr[2],
                    endpoint.remote_addr[3],
                    endpoint.remote_port,
                    endpoint.state.as_str(),
                    endpoint.generation
                )
            })
            .collect(),
        socket_operation_roots: semantic
            .socket_operations()
            .iter()
            .map(|operation| {
                format!(
                    "socket-operation id={} operation={} endpoint={}@{} socket={}@{} adapter={}@{} owner_store={}@{} local={}.{}.{}.{}:{} remote={}.{}.{}.{}:{} backlog={} byte_len={} sequence={} state={} generation={}",
                    operation.id,
                    operation.operation.as_str(),
                    operation.endpoint,
                    operation.endpoint_generation,
                    operation.socket,
                    operation.socket_generation,
                    operation.adapter,
                    operation.adapter_generation,
                    operation.owner_store,
                    operation.owner_store_generation,
                    operation.local_addr[0],
                    operation.local_addr[1],
                    operation.local_addr[2],
                    operation.local_addr[3],
                    operation.local_port,
                    operation.remote_addr[0],
                    operation.remote_addr[1],
                    operation.remote_addr[2],
                    operation.remote_addr[3],
                    operation.remote_port,
                    operation.backlog,
                    operation.byte_len,
                    operation.sequence,
                    operation.state.as_str(),
                    operation.generation
                )
            })
            .collect(),
        socket_wait_roots: semantic
            .socket_waits()
            .iter()
            .map(|wait| {
                format!(
                    "socket-wait id={} wait={}@{} kind={} endpoint={}@{} socket={}@{} adapter={}@{} owner_store={}@{} blocker={}:{}@{} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.wait_kind.as_str(),
                    wait.endpoint,
                    wait.endpoint_generation,
                    wait.socket,
                    wait.socket_generation,
                    wait.adapter,
                    wait.adapter_generation,
                    wait.owner_store,
                    wait.owner_store_generation,
                    wait.blocker.kind.as_str(),
                    wait.blocker.id,
                    wait.blocker.generation,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        network_backpressure_roots: semantic
            .network_backpressures()
            .iter()
            .map(|backpressure| {
                let endpoint =
                    optional_generation_ref(backpressure.endpoint, backpressure.endpoint_generation);
                let socket =
                    optional_generation_ref(backpressure.socket, backpressure.socket_generation);
                let owner_store = optional_generation_ref(
                    backpressure.owner_store,
                    backpressure.owner_store_generation,
                );
                format!(
                    "network-backpressure id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} endpoint={} socket={} owner_store={} direction={} reason={} action={} queue_depth={} queue_limit={} dropped_packets={} dropped_bytes={} sequence={} state={} generation={}",
                    backpressure.id,
                    backpressure.adapter,
                    backpressure.adapter_generation,
                    backpressure.packet_device,
                    backpressure.packet_device_generation,
                    backpressure.packet_queue,
                    backpressure.packet_queue_generation,
                    endpoint,
                    socket,
                    owner_store,
                    backpressure.direction.as_str(),
                    backpressure.reason.as_str(),
                    backpressure.action.as_str(),
                    backpressure.queue_depth,
                    backpressure.queue_limit,
                    backpressure.dropped_packets,
                    backpressure.dropped_bytes,
                    backpressure.sequence,
                    backpressure.state.as_str(),
                    backpressure.generation
                )
            })
            .collect(),
        network_driver_cleanup_roots: semantic
            .network_driver_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "network-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} binding={}@{} packet_device={}@{} adapter={}@{} backend={}:{}@{} state={} generation={} cancelled_socket_waits={} revoked_packet_capabilities={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.packet_device,
                    cleanup.packet_device_generation,
                    cleanup.adapter,
                    cleanup.adapter_generation,
                    cleanup.backend.kind.as_str(),
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_socket_waits.len(),
                    cleanup.revoked_packet_capabilities.len()
                )
            })
            .collect(),
        network_generation_audit_roots: semantic
            .network_generation_audits()
            .iter()
            .map(|audit| {
                format!(
                    "network-generation-audit id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} dma_buffer={}:{}@{} device_capability={}:{}@{} rejected_packet_generation_probes={} rejected_dma_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.adapter,
                    audit.adapter_generation,
                    audit.packet_device,
                    audit.packet_device_generation,
                    audit.packet_queue,
                    audit.packet_queue_generation,
                    audit.packet_descriptor,
                    audit.packet_descriptor_generation,
                    audit.packet_buffer,
                    audit.packet_buffer_generation,
                    audit.dma_buffer.kind.as_str(),
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.device_capability.kind.as_str(),
                    audit.device_capability.id,
                    audit.device_capability.generation,
                    audit.rejected_packet_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.state.as_str(),
                    audit.generation
                )
            })
            .collect(),
        network_fault_injection_roots: semantic
            .network_fault_injections()
            .iter()
            .map(|injection| {
                format!(
                    "network-fault-injection id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} packet_descriptor={} packet_buffer={} endpoint={} direction={} kind={} effect={} injected_packets={} dropped_packets={} error_packets={} error_code={} sequence={} state={} generation={}",
                    injection.id,
                    injection.adapter,
                    injection.adapter_generation,
                    injection.packet_device,
                    injection.packet_device_generation,
                    injection.packet_queue,
                    injection.packet_queue_generation,
                    optional_generation_ref(injection.packet_descriptor, injection.packet_descriptor_generation),
                    optional_generation_ref(injection.packet_buffer, injection.packet_buffer_generation),
                    optional_generation_ref(injection.endpoint, injection.endpoint_generation),
                    injection.direction.as_str(),
                    injection.kind.as_str(),
                    injection.effect.as_str(),
                    injection.injected_packets,
                    injection.dropped_packets,
                    injection.error_packets,
                    injection.error_code,
                    injection.sequence,
                    injection.state.as_str(),
                    injection.generation
                )
            })
            .collect(),
        network_benchmark_roots: semantic
            .network_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "network-benchmark id={} scenario={} adapter={}@{} packet_device={}@{} tx_queue={}@{} rx_queue={}@{} tx_completion={}@{} rx_wait_resolution={}@{} endpoint={}@{} socket={}@{} owner_store={}@{} backpressure={} sample_packets={} sample_bytes={} tx_completed_packets={} rx_resolved_packets={} dropped_packets={} measured_nanos={} budget_nanos={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.adapter,
                    benchmark.adapter_generation,
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                    benchmark.tx_queue,
                    benchmark.tx_queue_generation,
                    benchmark.rx_queue,
                    benchmark.rx_queue_generation,
                    benchmark.tx_completion,
                    benchmark.tx_completion_generation,
                    benchmark.rx_wait_resolution,
                    benchmark.rx_wait_resolution_generation,
                    benchmark.endpoint,
                    benchmark.endpoint_generation,
                    benchmark.socket,
                    benchmark.socket_generation,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                    optional_generation_ref(benchmark.backpressure, benchmark.backpressure_generation),
                    benchmark.sample_packets,
                    benchmark.sample_bytes,
                    benchmark.tx_completed_packets,
                    benchmark.rx_resolved_packets,
                    benchmark.dropped_packets,
                    benchmark.measured_nanos,
                    benchmark.budget_nanos,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        network_recovery_benchmark_roots: semantic
            .network_recovery_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "network-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} adapter={}@{} packet_device={}@{} backend={}:{}@{} driver_store={}@{} fault_injection={} recovery_start_event={} recovery_complete_event={} cancelled_socket_waits={} revoked_packet_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.adapter,
                    benchmark.adapter_generation,
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    optional_generation_ref(benchmark.fault_injection, benchmark.fault_injection_generation),
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_socket_waits,
                    benchmark.revoked_packet_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        block_device_object_roots: semantic
            .block_device_objects()
            .iter()
            .map(|block_device| {
                format!(
                    "block-device-object id={} name={} device={}@{} sector_size={} sector_count={} read_only={} max_transfer_sectors={} state={} generation={}",
                    block_device.id,
                    block_device.name,
                    block_device.device,
                    block_device.device_generation,
                    block_device.sector_size,
                    block_device.sector_count,
                    block_device.read_only,
                    block_device.max_transfer_sectors,
                    block_device.state.as_str(),
                    block_device.generation
                )
            })
            .collect(),
        block_range_object_roots: semantic
            .block_range_objects()
            .iter()
            .map(|block_range| {
                format!(
                    "block-range-object id={} block_device={}@{} start_sector={} sector_count={} byte_offset={} byte_len={} state={} generation={}",
                    block_range.id,
                    block_range.block_device,
                    block_range.block_device_generation,
                    block_range.start_sector,
                    block_range.sector_count,
                    block_range.byte_offset,
                    block_range.byte_len,
                    block_range.state.as_str(),
                    block_range.generation
                )
            })
            .collect(),
        block_request_object_roots: semantic
            .block_request_objects()
            .iter()
            .map(|request| {
                format!(
                    "block-request-object id={} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    request.id,
                    request.block_device,
                    request.block_device_generation,
                    request.block_range,
                    request.block_range_generation,
                    request.operation.as_str(),
                    request.sequence,
                    request.byte_len,
                    request.state.as_str(),
                    request.generation
                )
            })
            .collect(),
        block_completion_object_roots: semantic
            .block_completion_objects()
            .iter()
            .map(|completion| {
                format!(
                    "block-completion-object id={} block_request={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} status={} state={} generation={}",
                    completion.id,
                    completion.block_request,
                    completion.block_request_generation,
                    completion.block_device,
                    completion.block_device_generation,
                    completion.block_range,
                    completion.block_range_generation,
                    completion.sequence,
                    completion.completed_bytes,
                    completion.status.as_str(),
                    completion.state.as_str(),
                    completion.generation
                )
            })
            .collect(),
        block_wait_roots: semantic
            .block_waits()
            .iter()
            .map(|wait| {
                format!(
                    "block-wait id={} wait={}@{} block_request={}@{} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.block_request,
                    wait.block_request_generation,
                    wait.block_device,
                    wait.block_device_generation,
                    wait.block_range,
                    wait.block_range_generation,
                    wait.operation.as_str(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        fake_block_backend_object_roots: semantic
            .fake_block_backends()
            .iter()
            .map(|backend| {
                format!(
                    "fake-block-backend-object id={} name={} block_device={}@{} provider={} profile={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} deterministic_seed={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.provider,
                    backend.profile,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.deterministic_seed,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        virtio_blk_backend_object_roots: semantic
            .virtio_blk_backends()
            .iter()
            .map(|backend| {
                format!(
                    "virtio-blk-backend-object id={} name={} block_device={}@{} driver_binding={}@{} device={}@{} provider={} profile={} model={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} device_features={} driver_features={} negotiated_features={} request_queue_index={} queue_size={} irq_vector={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.driver_binding,
                    backend.driver_binding_generation,
                    backend.device,
                    backend.device_generation,
                    backend.provider,
                    backend.profile,
                    backend.model,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.device_features,
                    backend.driver_features,
                    backend.negotiated_features,
                    backend.request_queue_index,
                    backend.queue_size,
                    backend.irq_vector,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        block_read_path_roots: semantic
            .block_read_paths()
            .iter()
            .map(|read_path| {
                format!(
                    "block-read-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} data_digest={} state={} generation={}",
                    read_path.id,
                    read_path.backend.summary(),
                    read_path.block_request,
                    read_path.block_request_generation,
                    read_path.block_completion,
                    read_path.block_completion_generation,
                    read_path.block_device,
                    read_path.block_device_generation,
                    read_path.block_range,
                    read_path.block_range_generation,
                    read_path.sequence,
                    read_path.completed_bytes,
                    read_path.data_digest,
                    read_path.state.as_str(),
                    read_path.generation
                )
            })
            .collect(),
        block_write_path_roots: semantic
            .block_write_paths()
            .iter()
            .map(|write_path| {
                format!(
                    "block-write-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} payload_digest={} state={} generation={}",
                    write_path.id,
                    write_path.backend.summary(),
                    write_path.block_request,
                    write_path.block_request_generation,
                    write_path.block_completion,
                    write_path.block_completion_generation,
                    write_path.block_device,
                    write_path.block_device_generation,
                    write_path.block_range,
                    write_path.block_range_generation,
                    write_path.sequence,
                    write_path.completed_bytes,
                    write_path.payload_digest,
                    write_path.state.as_str(),
                    write_path.generation
                )
            })
            .collect(),
        block_request_queue_roots: semantic
            .block_request_queues()
            .iter()
            .map(|queue| {
                format!(
                    "block-request-queue id={} backend={} block_device={}@{} depth={} entries={} pending={} completed={} first_sequence={} last_sequence={} state={} generation={}",
                    queue.id,
                    queue.backend.summary(),
                    queue.block_device,
                    queue.block_device_generation,
                    queue.depth,
                    queue.entries.len(),
                    queue.pending_count,
                    queue.completed_count,
                    queue.first_sequence,
                    queue.last_sequence,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect(),
        block_dma_buffer_roots: semantic
            .block_dma_buffers()
            .iter()
            .map(|buffer| {
                format!(
                    "block-dma-buffer id={} backend={} block_request={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} descriptor={}@{} queue={}@{} operation={} access={} byte_len={} buffer_len={} buffer_digest={} state={} generation={}",
                    buffer.id,
                    buffer.backend.summary(),
                    buffer.block_request,
                    buffer.block_request_generation,
                    buffer.dma_buffer,
                    buffer.dma_buffer_generation,
                    buffer.block_device,
                    buffer.block_device_generation,
                    buffer.block_range,
                    buffer.block_range_generation,
                    buffer.descriptor,
                    buffer.descriptor_generation,
                    buffer.queue,
                    buffer.queue_generation,
                    buffer.operation.as_str(),
                    buffer.access.as_str(),
                    buffer.byte_len,
                    buffer.buffer_len,
                    buffer.buffer_digest,
                    buffer.state.as_str(),
                    buffer.generation
                )
            })
            .collect(),
        block_page_object_roots: semantic
            .block_page_objects()
            .iter()
            .map(|page| {
                format!(
                    "block-page-object id={} block_dma_buffer={}@{} block_request={}@{} block_completion={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_backing={} cow_state={} page_state={} page_offset={} byte_len={} operation={} state={} generation={}",
                    page.id,
                    page.block_dma_buffer,
                    page.block_dma_buffer_generation,
                    page.block_request,
                    page.block_request_generation,
                    page.block_completion,
                    page.block_completion_generation,
                    page.dma_buffer,
                    page.dma_buffer_generation,
                    page.block_device,
                    page.block_device_generation,
                    page.block_range,
                    page.block_range_generation,
                    page.aspace.summary(),
                    page.vma_region.summary(),
                    page.page.summary(),
                    page.page_dirty_generation,
                    page.page_backing.as_str(),
                    page.cow_state.as_str(),
                    page.page_state.as_str(),
                    page.page_offset,
                    page.byte_len,
                    page.operation.as_str(),
                    page.state.as_str(),
                    page.generation
                )
            })
            .collect(),
        buffer_cache_object_roots: semantic
            .buffer_cache_objects()
            .iter()
            .map(|cache| {
                format!(
                    "buffer-cache-object id={} block_page_object={}@{} block_dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_offset={} block_offset={} byte_len={} operation={} cache_state={} coherency_epoch={} state={} generation={}",
                    cache.id,
                    cache.block_page_object,
                    cache.block_page_object_generation,
                    cache.block_dma_buffer,
                    cache.block_dma_buffer_generation,
                    cache.block_device,
                    cache.block_device_generation,
                    cache.block_range,
                    cache.block_range_generation,
                    cache.aspace.summary(),
                    cache.vma_region.summary(),
                    cache.page.summary(),
                    cache.page_dirty_generation,
                    cache.page_offset,
                    cache.block_offset,
                    cache.byte_len,
                    cache.operation.as_str(),
                    cache.cache_state.as_str(),
                    cache.coherency_epoch,
                    cache.state.as_str(),
                    cache.generation
                )
            })
            .collect(),
        file_object_roots: semantic
            .file_objects()
            .iter()
            .map(|file| {
                format!(
                    "file-object id={} buffer_cache_object={}@{} block_device={}@{} block_range={}@{} page={} page_dirty_generation={} namespace={} file_key={} path={} file_offset={} byte_len={} file_size={} content_digest={} cache_state={} state={} generation={}",
                    file.id,
                    file.buffer_cache_object,
                    file.buffer_cache_object_generation,
                    file.block_device,
                    file.block_device_generation,
                    file.block_range,
                    file.block_range_generation,
                    file.page.summary(),
                    file.page_dirty_generation,
                    file.namespace,
                    file.file_key,
                    file.path,
                    file.file_offset,
                    file.byte_len,
                    file.file_size,
                    file.content_digest,
                    file.cache_state.as_str(),
                    file.state.as_str(),
                    file.generation
                )
            })
            .collect(),
        directory_object_roots: semantic
            .directory_objects()
            .iter()
            .map(|directory| {
                format!(
                    "directory-object id={} file_object={}@{} namespace={} directory_key={} directory_path={} entry_name={} child_file_key={} child_path={} entry_kind={} file_size={} content_digest={} state={} generation={}",
                    directory.id,
                    directory.file_object,
                    directory.file_object_generation,
                    directory.namespace,
                    directory.directory_key,
                    directory.directory_path,
                    directory.entry_name,
                    directory.child_file_key,
                    directory.child_path,
                    directory.entry_kind.as_str(),
                    directory.file_size,
                    directory.content_digest,
                    directory.state.as_str(),
                    directory.generation
                )
            })
            .collect(),
        fat_adapter_object_roots: semantic
            .fat_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "fat-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_written={} bytes_read={} write_digest={} read_digest={} file_content_digest={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_written,
                    adapter.bytes_read,
                    adapter.write_digest,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        ext4_adapter_object_roots: semantic
            .ext4_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "ext4-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_read={} read_digest={} file_content_digest={} directory_entries={} read_only_enforced={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_read,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.directory_entries,
                    adapter.read_only_enforced,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        file_handle_capability_roots: semantic
            .file_handle_capabilities()
            .iter()
            .map(|capability| {
                format!(
                    "file-handle-capability id={} owner_store={}@{} file_object={}@{} directory_object={}@{} capability={}@{} handle_slot={} handle_generation={} handle_tag={} operation={} file_offset={} byte_len={} content_digest={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.file_object,
                    capability.file_object_generation,
                    capability.directory_object,
                    capability.directory_object_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.handle_tag,
                    capability.operation,
                    capability.file_offset,
                    capability.byte_len,
                    capability.content_digest,
                    capability.state.as_str(),
                    capability.generation
                )
            })
            .collect(),
        fs_wait_roots: semantic
            .fs_waits()
            .iter()
            .map(|wait| {
                format!(
                    "fs-wait id={} wait={}@{} owner_store={}@{} file_object={}@{} directory_object={}@{} file_handle_capability={}@{} operation={} blocker={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.owner_store,
                    wait.owner_store_generation,
                    wait.file_object,
                    wait.file_object_generation,
                    wait.directory_object,
                    wait.directory_object_generation,
                    wait.file_handle_capability,
                    wait.file_handle_capability_generation,
                    wait.operation,
                    wait.blocker.summary(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        activation_resume_roots: semantic
            .activation_resumes()
            .iter()
            .map(|resume| {
                format!(
                    "activation-resume id={} decision={}@{} activation={}@{}->{} state={} generation={}",
                    resume.id,
                    resume.scheduler_decision,
                    resume.scheduler_decision_generation,
                    resume.activation,
                    resume.activation_generation_before,
                    resume.activation_generation_after,
                    resume.state.as_str(),
                    resume.generation
                )
            })
            .collect(),
        activation_wait_roots: semantic
            .activation_waits()
            .iter()
            .map(|activation_wait| {
                format!(
                    "activation-wait id={} activation={}@{}->{} wait={}@{} state={} generation={}",
                    activation_wait.id,
                    activation_wait.activation,
                    activation_wait.activation_generation_before,
                    activation_wait.activation_generation_after_block,
                    activation_wait.wait,
                    activation_wait.wait_generation,
                    activation_wait.state.as_str(),
                    activation_wait.generation
                )
            })
            .collect(),
        activation_cleanup_roots: semantic
            .activation_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "activation-cleanup id={} store={}@{}->{} activation={}@{}->{} wait={}@{} state={} generation={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.target_store_generation,
                    cleanup.result_store_generation,
                    cleanup.activation,
                    cleanup.activation_generation_before,
                    cleanup.activation_generation_after,
                    cleanup
                        .wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .wait_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.state.as_str(),
                    cleanup.generation
                )
            })
            .collect(),
        preemption_latency_roots: semantic
            .preemption_latency_samples()
            .iter()
            .map(|sample| {
                format!(
                    "preemption-latency id={} timer={}@{} preemption={}@{} decision={}@{} resume={}@{} events={} measured_nanos={} budget_nanos={} state={} generation={}",
                    sample.id,
                    sample.timer_interrupt,
                    sample.timer_interrupt_generation,
                    sample.preemption,
                    sample.preemption_generation,
                    sample.scheduler_decision,
                    sample.scheduler_decision_generation,
                    sample.activation_resume,
                    sample.activation_resume_generation,
                    sample.interrupt_to_resume_events,
                    sample.measured_nanos,
                    sample.budget_nanos,
                    sample.state.as_str(),
                    sample.generation
                )
            })
            .collect(),
        hart_event_attribution_roots: semantic
            .hart_event_attributions()
            .iter()
            .map(|attribution| {
                format!(
                    "hart-event-attribution id={} hart={}@{} hardware_id={} event={} kind={} generation={}",
                    attribution.id,
                    attribution.hart,
                    attribution.hart_generation,
                    attribution.hardware_hart,
                    attribution.event,
                    attribution.event_kind,
                    attribution.generation
                )
            })
            .collect(),
        resource_roots: semantic
            .resources()
            .iter()
            .map(|resource| {
                format!(
                    "resource id={} kind={} generation={} live={}",
                    resource.id,
                    resource.kind.as_str(),
                    resource.generation,
                    resource.live
                )
            })
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
        wait_roots: target_v1
            .wait_records
            .iter()
            .map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id, wait.state, wait.generation
                )
            })
            .chain(semantic.wait_records().iter().map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id,
                    wait.state.as_str(),
                    wait.generation
                )
            }))
            .collect(),
        store_roots: semantic
            .stores()
            .iter()
            .map(|store| {
                format!(
                    "store id={} package={} state={} generation={}",
                    store.id,
                    store.package,
                    store.state.as_str(),
                    store.generation
                )
            })
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
        target_store_record_roots: target_v1
            .store_records
            .iter()
            .map(|store| {
                format!(
                    "target-store id={} package={} artifact={} state={} generation={} fault_domain={}",
                    store.id,
                    store.package,
                    store.artifact,
                    store.state,
                    store.generation,
                    store.fault_domain
                )
            })
            .collect(),
        target_capability_record_roots: target_v1
            .capability_records
            .iter()
            .map(|capability| {
                format!(
                    "target-capability id={} subject={} object={} class={} rights={} generation={} owner_store={}@{} revoked={} source={}",
                    capability.id,
                    capability.subject,
                    capability.object,
                    capability.class,
                    capability.rights.join("+"),
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability
                        .owner_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked,
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
                    "target-artifact id={} package={} artifact={} profile={} artifact_hash={} abi={} code_hash={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.target_profile,
                    artifact.artifact_hash,
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
                    .map(|store| {
                        format!(
                            "{store}@{}",
                            code.bound_store_generation
                                .map(|generation| generation.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )
                    })
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
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} code={} artifact={}@{} number={} category={} subject={} object={} op={} cap_args={} allowed={} result={} ret={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    trace.record_mode,
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.code_object,
                    trace.artifact,
                    trace.artifact_generation,
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
        tombstone_roots: target_v1
            .tombstones
            .iter()
            .map(|tombstone| {
                format!(
                    "tombstone kind={} id={} generation={} died_at={} reason={}",
                    tombstone.kind,
                    tombstone.id,
                    tombstone.generation,
                    tombstone.died_at,
                    tombstone.reason
                )
            })
            .collect(),
        contract_violation_roots: target_v1
            .contract_violations
            .iter()
            .map(|violation| {
                let to = violation.to.as_ref().map_or_else(
                    || "none".to_owned(),
                    |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
                );
                format!(
                    "contract-violation kind={} edge={} from={}:{}@{} to={} detail={}",
                    violation.kind,
                    violation.edge,
                    violation.from.kind,
                    violation.from.id,
                    violation.from.generation,
                    to,
                    violation.detail
                )
            })
            .collect(),
        cleanup_roots: target_v1
            .cleanup_transactions
            .iter()
            .map(|cleanup| {
                format!(
                    "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.store_generation,
                    cleanup
                        .result_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .activation
                        .zip(cleanup.activation_generation)
                        .map(|(activation, generation)| format!("{activation}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .code_object
                        .zip(cleanup.code_generation)
                        .map(|(code, generation)| format!("{code}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    cleanup
                        .steps
                        .iter()
                        .map(|step| format!("{}:{}", step.step, step.state))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect(),
        memory_policy_roots: target_v1
            .memory_policies
            .iter()
            .map(|policy| {
                format!(
                    "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
                    policy.class,
                    policy.owner_kind,
                    policy.permissions,
                    policy.migration_policy,
                    policy.snapshot_policy,
                    policy.cleanup_policy,
                    policy.can_alias_guest_memory,
                    policy.can_cross_pending,
                    policy.can_be_executable
                )
            })
            .collect(),
        snapshot_validation_roots: validation_roots(&target_v1.snapshot_validation),
        replay_validation_roots: validation_roots(&target_v1.replay_validation),
        substrate_event_roots: target_v1
            .substrate_events
            .iter()
            .map(|event| {
                format!(
                    "substrate-event:{}:{}:{} requester={}",
                    event.event_kind,
                    event.authority,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
                )
            })
            .collect(),
        command_result_roots: target_v1
            .command_results
            .iter()
            .map(|result| {
                format!(
                    "command-result:{}:{}:{} issuer={}",
                    result.id, result.command, result.status, result.issuer
                )
            })
            .collect(),
        interface_event_roots: target_v1
            .interface_events
            .iter()
            .map(|event| {
                format!(
                    "interface-event:{}:{}:{} requester={}",
                    event.interface_kind,
                    event.interface,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
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
        artifact_hash: image.artifact_hash.clone(),
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
        bound_store_generation: code.bound_store_generation,
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

fn store_record_manifest(store: &StoreRecord) -> StoreRecordManifest {
    StoreRecordManifest {
        id: store.id,
        package: store.package.clone(),
        artifact: store.artifact.clone(),
        role: store.role.clone(),
        fault_policy: store.fault_policy.clone(),
        fault_domain: store.fault_domain,
        resource: store.resource,
        state: store.state.as_str().to_owned(),
        generation: store.generation,
        restart_count: store.restart_count,
    }
}

fn hart_record_manifest(hart: &semantic_core::HartRecord) -> HartRecordManifest {
    HartRecordManifest {
        id: u64::from(hart.id),
        hardware_id: hart.hardware_id,
        label: hart.label.clone(),
        state: hart.state.as_str().to_owned(),
        generation: hart.generation,
        boot: hart.boot,
        current_activation: hart.current_activation,
        current_activation_generation: hart.current_activation_generation,
        current_task: hart.current_task.map(u64::from),
        current_task_generation: hart.current_task_generation,
        current_store: hart.current_store,
        current_store_generation: hart.current_store_generation,
        last_event: hart.last_event,
        last_current_event: hart.last_current_event,
        note: hart.note.clone(),
    }
}

fn task_record_manifest(task: &semantic_core::TaskRecord) -> TaskRecordManifest {
    TaskRecordManifest {
        id: u64::from(task.id),
        label: task.label.clone(),
        frontend: task.frontend.as_str().to_owned(),
        state: task.state.as_str().to_owned(),
        generation: task.generation,
        fault_domain: task.fault_domain,
        pending_wait: task.pending_wait,
        resources: task.resources.clone(),
    }
}

fn runtime_activation_record_manifest(
    activation: &semantic_core::RuntimeActivationRecord,
) -> RuntimeActivationRecordManifest {
    RuntimeActivationRecordManifest {
        id: activation.id,
        owner_task: u64::from(activation.owner_task),
        owner_task_generation: activation.owner_task_generation,
        owner_store: activation.owner_store,
        owner_store_generation: activation.owner_store_generation,
        code_object: activation.code_object.map(contract_object_ref_manifest),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        runnable_queue: activation.runnable_queue,
        runnable_queue_generation: activation.runnable_queue_generation,
        last_event: activation.last_event,
    }
}

fn runnable_queue_manifest(queue: &semantic_core::RunnableQueueRecord) -> RunnableQueueManifest {
    RunnableQueueManifest {
        id: queue.id,
        label: queue.label.clone(),
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        owner_hart: queue.owner_hart,
        owner_hart_generation: queue.owner_hart_generation,
        entries: queue
            .entries
            .iter()
            .map(|entry| RunnableQueueEntryManifest {
                activation: entry.activation,
                activation_generation: entry.activation_generation,
                enqueued_at: entry.enqueued_at,
            })
            .collect(),
    }
}

fn activation_context_manifest(
    context: &semantic_core::ActivationContextRecord,
) -> ActivationContextManifest {
    ActivationContextManifest {
        id: context.id,
        activation: context.activation,
        activation_generation: context.activation_generation,
        owner_task: u64::from(context.owner_task),
        owner_task_generation: context.owner_task_generation,
        owner_store: context.owner_store,
        owner_store_generation: context.owner_store_generation,
        generation: context.generation,
        state: context.state.as_str().to_owned(),
        current_saved_context: context.current_saved_context,
        current_saved_context_generation: context.current_saved_context_generation,
        last_event: context.last_event,
    }
}

fn saved_context_manifest(saved: &semantic_core::SavedContextRecord) -> SavedContextManifest {
    SavedContextManifest {
        id: saved.id,
        context: saved.context,
        context_generation: saved.context_generation,
        activation: saved.activation,
        activation_generation: saved.activation_generation,
        owner_task: u64::from(saved.owner_task),
        owner_task_generation: saved.owner_task_generation,
        source_preemption: saved.source_preemption,
        source_preemption_generation: saved.source_preemption_generation,
        generation: saved.generation,
        state: saved.state.as_str().to_owned(),
        reason: saved.reason.as_str().to_owned(),
        pc: saved.pc,
        sp: saved.sp,
        flags: saved.flags,
        integer_registers: saved.integer_registers,
        saved_at_event: saved.saved_at_event,
        note: saved.note.clone(),
    }
}

fn timer_interrupt_manifest(
    interrupt: &semantic_core::TimerInterruptRecord,
) -> TimerInterruptManifest {
    TimerInterruptManifest {
        id: interrupt.id,
        timer_epoch: interrupt.timer_epoch,
        hart: u64::from(interrupt.hart),
        hart_generation: Some(interrupt.hart_generation),
        hardware_hart: Some(interrupt.hardware_hart),
        target_activation: interrupt.target_activation,
        target_activation_generation: interrupt.target_activation_generation,
        target_task: interrupt.target_task.map(u64::from),
        target_task_generation: interrupt.target_task_generation,
        generation: interrupt.generation,
        state: interrupt.state.as_str().to_owned(),
        recorded_at_event: interrupt.recorded_at_event,
        note: interrupt.note.clone(),
    }
}

fn ipi_event_manifest(ipi: &semantic_core::IpiEventRecord) -> IpiEventManifest {
    IpiEventManifest {
        id: ipi.id,
        source_hart: u64::from(ipi.source_hart),
        source_hart_generation: ipi.source_hart_generation,
        source_hardware_hart: ipi.source_hardware_hart,
        target_hart: u64::from(ipi.target_hart),
        target_hart_generation: ipi.target_hart_generation,
        target_hardware_hart: ipi.target_hardware_hart,
        kind: ipi.kind.as_str().to_owned(),
        generation: ipi.generation,
        state: ipi.state.as_str().to_owned(),
        recorded_at_event: ipi.recorded_at_event,
        reason: ipi.reason.clone(),
        note: ipi.note.clone(),
    }
}

fn remote_preempt_manifest(remote: &semantic_core::RemotePreemptRecord) -> RemotePreemptManifest {
    RemotePreemptManifest {
        id: remote.id,
        ipi: remote.ipi,
        ipi_generation: remote.ipi_generation,
        source_hart: u64::from(remote.source_hart),
        source_hart_generation: remote.source_hart_generation,
        target_hart: u64::from(remote.target_hart),
        target_hart_generation_before: remote.target_hart_generation_before,
        target_hart_generation_after: remote.target_hart_generation_after,
        activation: remote.activation,
        activation_generation_before: remote.activation_generation_before,
        activation_generation_after: remote.activation_generation_after,
        queue: remote.queue,
        queue_generation: remote.queue_generation,
        generation: remote.generation,
        state: remote.state.as_str().to_owned(),
        preempted_at_event: remote.preempted_at_event,
        note: remote.note.clone(),
    }
}

fn remote_park_manifest(remote: &semantic_core::RemoteParkRecord) -> RemoteParkManifest {
    RemoteParkManifest {
        id: remote.id,
        ipi: remote.ipi,
        ipi_generation: remote.ipi_generation,
        source_hart: u64::from(remote.source_hart),
        source_hart_generation: remote.source_hart_generation,
        target_hart: u64::from(remote.target_hart),
        target_hart_generation_before: remote.target_hart_generation_before,
        target_hart_generation_after: remote.target_hart_generation_after,
        generation: remote.generation,
        state: remote.state.as_str().to_owned(),
        parked_at_event: remote.parked_at_event,
        reason: remote.reason.clone(),
        note: remote.note.clone(),
    }
}

fn hart_event_attribution_manifest(
    attribution: &semantic_core::HartEventAttributionRecord,
) -> HartEventAttributionManifest {
    HartEventAttributionManifest {
        id: attribution.id,
        hart: u64::from(attribution.hart),
        hart_generation: attribution.hart_generation,
        hardware_hart: attribution.hardware_hart,
        event: attribution.event,
        event_source: attribution.event_source.clone(),
        event_kind: attribution.event_kind.clone(),
        activation: attribution.activation,
        activation_generation: attribution.activation_generation,
        task: attribution.task.map(u64::from),
        task_generation: attribution.task_generation,
        store: attribution.store,
        store_generation: attribution.store_generation,
        generation: attribution.generation,
        state: attribution.state.as_str().to_owned(),
        note: attribution.note.clone(),
    }
}

fn preemption_manifest(preemption: &semantic_core::PreemptionRecord) -> PreemptionManifest {
    PreemptionManifest {
        id: preemption.id,
        activation: preemption.activation,
        activation_generation_before: preemption.activation_generation_before,
        activation_generation_after: preemption.activation_generation_after,
        timer_interrupt: preemption.timer_interrupt,
        timer_interrupt_generation: preemption.timer_interrupt_generation,
        queue: preemption.queue,
        queue_generation: preemption.queue_generation,
        generation: preemption.generation,
        state: preemption.state.as_str().to_owned(),
        preempted_at_event: preemption.preempted_at_event,
        note: preemption.note.clone(),
    }
}

fn scheduler_decision_manifest(
    decision: &semantic_core::SchedulerDecisionRecord,
) -> SchedulerDecisionManifest {
    SchedulerDecisionManifest {
        id: decision.id,
        queue: decision.queue,
        queue_generation: decision.queue_generation,
        selected_activation: decision.selected_activation,
        selected_activation_generation: decision.selected_activation_generation,
        owner_task: u64::from(decision.owner_task),
        owner_task_generation: decision.owner_task_generation,
        generation: decision.generation,
        state: decision.state.as_str().to_owned(),
        decided_at_event: decision.decided_at_event,
        reason: decision.reason.clone(),
        note: decision.note.clone(),
    }
}

fn cross_hart_scheduler_decision_manifest(
    decision: &semantic_core::CrossHartSchedulerDecisionRecord,
) -> CrossHartSchedulerDecisionManifest {
    CrossHartSchedulerDecisionManifest {
        id: decision.id,
        scheduler_decision: decision.scheduler_decision,
        scheduler_decision_generation: decision.scheduler_decision_generation,
        deciding_hart: u64::from(decision.deciding_hart),
        deciding_hart_generation: decision.deciding_hart_generation,
        target_hart: u64::from(decision.target_hart),
        target_hart_generation: decision.target_hart_generation,
        queue: decision.queue,
        queue_generation: decision.queue_generation,
        queue_owner_hart_generation: decision.queue_owner_hart_generation,
        selected_activation: decision.selected_activation,
        selected_activation_generation: decision.selected_activation_generation,
        generation: decision.generation,
        state: decision.state.as_str().to_owned(),
        decided_at_event: decision.decided_at_event,
        reason: decision.reason.clone(),
        note: decision.note.clone(),
    }
}

fn activation_migration_manifest(
    migration: &semantic_core::ActivationMigrationRecord,
) -> ActivationMigrationManifest {
    ActivationMigrationManifest {
        id: migration.id,
        activation: migration.activation,
        activation_generation_before: migration.activation_generation_before,
        activation_generation_after: migration.activation_generation_after,
        owner_task: u64::from(migration.owner_task),
        owner_task_generation: migration.owner_task_generation,
        source_hart: u64::from(migration.source_hart),
        source_hart_generation: migration.source_hart_generation,
        target_hart: u64::from(migration.target_hart),
        target_hart_generation: migration.target_hart_generation,
        source_queue: migration.source_queue,
        source_queue_generation: migration.source_queue_generation,
        source_queue_owner_hart_generation: migration.source_queue_owner_hart_generation,
        target_queue: migration.target_queue,
        target_queue_generation: migration.target_queue_generation,
        target_queue_owner_hart_generation: migration.target_queue_owner_hart_generation,
        generation: migration.generation,
        state: migration.state.as_str().to_owned(),
        migrated_at_event: migration.migrated_at_event,
        reason: migration.reason.clone(),
        note: migration.note.clone(),
    }
}

fn smp_safe_point_manifest(safe_point: &semantic_core::SmpSafePointRecord) -> SmpSafePointManifest {
    SmpSafePointManifest {
        id: safe_point.id,
        coordinator_hart: u64::from(safe_point.coordinator_hart),
        coordinator_hart_generation: safe_point.coordinator_hart_generation,
        participants: safe_point
            .participants
            .iter()
            .map(|participant| SmpSafePointParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                current_activation: participant.current_activation,
                current_activation_generation: participant.current_activation_generation,
            })
            .collect(),
        generation: safe_point.generation,
        state: safe_point.state.as_str().to_owned(),
        recorded_at_event: safe_point.recorded_at_event,
        reason: safe_point.reason.clone(),
        note: safe_point.note.clone(),
    }
}

fn stop_the_world_rendezvous_manifest(
    rendezvous: &semantic_core::StopTheWorldRendezvousRecord,
) -> StopTheWorldRendezvousManifest {
    StopTheWorldRendezvousManifest {
        id: rendezvous.id,
        epoch: rendezvous.epoch,
        safe_point: rendezvous.safe_point,
        safe_point_generation: rendezvous.safe_point_generation,
        coordinator_hart: u64::from(rendezvous.coordinator_hart),
        coordinator_hart_generation: rendezvous.coordinator_hart_generation,
        participants: rendezvous
            .participants
            .iter()
            .map(|participant| StopTheWorldRendezvousParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
            })
            .collect(),
        stop_new_activations: rendezvous.stop_new_activations,
        generation: rendezvous.generation,
        state: rendezvous.state.as_str().to_owned(),
        completed_at_event: rendezvous.completed_at_event,
        reason: rendezvous.reason.clone(),
        note: rendezvous.note.clone(),
    }
}

fn smp_code_publish_barrier_manifest(
    barrier: &semantic_core::SmpCodePublishBarrierRecord,
) -> SmpCodePublishBarrierManifest {
    SmpCodePublishBarrierManifest {
        id: barrier.id,
        rendezvous: barrier.rendezvous,
        rendezvous_generation: barrier.rendezvous_generation,
        rendezvous_epoch: barrier.rendezvous_epoch,
        code_publish_epoch_before: barrier.code_publish_epoch_before,
        code_publish_epoch_after: barrier.code_publish_epoch_after,
        participants: barrier
            .participants
            .iter()
            .map(|participant| SmpCodePublishBarrierParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                last_seen_code_epoch_before: participant.last_seen_code_epoch_before,
                last_seen_code_epoch_after: participant.last_seen_code_epoch_after,
                semantic_icache_sync: participant.semantic_icache_sync,
            })
            .collect(),
        remote_icache_sync_required: barrier.remote_icache_sync_required,
        code_publish_executed: barrier.code_publish_executed,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

fn smp_cleanup_quiescence_manifest(
    quiescence: &semantic_core::SmpCleanupQuiescenceRecord,
) -> SmpCleanupQuiescenceManifest {
    SmpCleanupQuiescenceManifest {
        id: quiescence.id,
        cleanup: quiescence.cleanup,
        cleanup_generation: quiescence.cleanup_generation,
        store: quiescence.store,
        target_store_generation: quiescence.target_store_generation,
        result_store_generation: quiescence.result_store_generation,
        activation: quiescence.activation,
        activation_generation_after: quiescence.activation_generation_after,
        rendezvous: quiescence.rendezvous,
        rendezvous_generation: quiescence.rendezvous_generation,
        rendezvous_epoch: quiescence.rendezvous_epoch,
        participants: quiescence
            .participants
            .iter()
            .map(|participant| SmpCleanupQuiescenceParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                current_activation: participant.current_activation,
                current_activation_generation: participant.current_activation_generation,
                current_store: participant.current_store,
                current_store_generation: participant.current_store_generation,
                quiesced: participant.quiesced,
            })
            .collect(),
        no_running_activation: quiescence.no_running_activation,
        no_pending_wait: quiescence.no_pending_wait,
        no_live_capability: quiescence.no_live_capability,
        no_live_resource: quiescence.no_live_resource,
        generation: quiescence.generation,
        state: quiescence.state.as_str().to_owned(),
        validated_at_event: quiescence.validated_at_event,
        reason: quiescence.reason.clone(),
        note: quiescence.note.clone(),
    }
}

fn smp_snapshot_barrier_manifest(
    barrier: &semantic_core::SmpSnapshotBarrierRecord,
) -> SmpSnapshotBarrierManifest {
    SmpSnapshotBarrierManifest {
        id: barrier.id,
        rendezvous: barrier.rendezvous,
        rendezvous_generation: barrier.rendezvous_generation,
        rendezvous_epoch: barrier.rendezvous_epoch,
        event_log_cursor: barrier.event_log_cursor,
        participants: barrier
            .participants
            .iter()
            .map(|participant| SmpSnapshotBarrierParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                event_log_cursor_observed: participant.event_log_cursor_observed,
                snapshot_safe: participant.snapshot_safe,
            })
            .collect(),
        pending_wait_count: barrier.pending_wait_count,
        active_transaction_count: barrier.active_transaction_count,
        active_dmw_lease_count: barrier.active_dmw_lease_count,
        active_nonconvertible_activation_count: barrier.active_nonconvertible_activation_count,
        in_flight_dma_count: barrier.in_flight_dma_count,
        unsealed_event_log: barrier.unsealed_event_log,
        unflushed_trap_record_count: barrier.unflushed_trap_record_count,
        pending_cleanup_count: barrier.pending_cleanup_count,
        native_activation_stack_live: barrier.native_activation_stack_live,
        raw_dma_binding_count: barrier.raw_dma_binding_count,
        raw_mmio_binding_count: barrier.raw_mmio_binding_count,
        snapshot_validation_ok: barrier.snapshot_validation_ok,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

fn smp_stress_run_manifest(run: &semantic_core::SmpStressRunRecord) -> SmpStressRunManifest {
    SmpStressRunManifest {
        id: run.id,
        scenario: run.scenario.clone(),
        iterations: run.iterations,
        hart_count: run.hart_count,
        event_log_cursor: run.event_log_cursor,
        observed_safe_point_count: run.observed_safe_point_count,
        observed_rendezvous_count: run.observed_rendezvous_count,
        observed_code_publish_barrier_count: run.observed_code_publish_barrier_count,
        observed_cleanup_quiescence_count: run.observed_cleanup_quiescence_count,
        observed_snapshot_barrier_count: run.observed_snapshot_barrier_count,
        observed_activation_migration_count: run.observed_activation_migration_count,
        observed_remote_preempt_count: run.observed_remote_preempt_count,
        observed_remote_park_count: run.observed_remote_park_count,
        invariant_checks: run.invariant_checks,
        property_failures: run.property_failures,
        last_safe_point: run.last_safe_point,
        last_safe_point_generation: run.last_safe_point_generation,
        last_rendezvous: run.last_rendezvous,
        last_rendezvous_generation: run.last_rendezvous_generation,
        last_code_publish_barrier: run.last_code_publish_barrier,
        last_code_publish_barrier_generation: run.last_code_publish_barrier_generation,
        last_cleanup_quiescence: run.last_cleanup_quiescence,
        last_cleanup_quiescence_generation: run.last_cleanup_quiescence_generation,
        last_snapshot_barrier: run.last_snapshot_barrier,
        last_snapshot_barrier_generation: run.last_snapshot_barrier_generation,
        last_activation_migration: run.last_activation_migration,
        last_activation_migration_generation: run.last_activation_migration_generation,
        last_remote_preempt: run.last_remote_preempt,
        last_remote_preempt_generation: run.last_remote_preempt_generation,
        last_remote_park: run.last_remote_park,
        last_remote_park_generation: run.last_remote_park_generation,
        generation: run.generation,
        state: run.state.as_str().to_owned(),
        recorded_at_event: run.recorded_at_event,
        reason: run.reason.clone(),
        note: run.note.clone(),
    }
}

fn smp_scaling_benchmark_manifest(
    benchmark: &semantic_core::SmpScalingBenchmarkRecord,
) -> SmpScalingBenchmarkManifest {
    SmpScalingBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        stress_run: benchmark.stress_run,
        stress_run_generation: benchmark.stress_run_generation,
        hart_count: benchmark.hart_count,
        workload_units: benchmark.workload_units,
        baseline_single_hart_nanos: benchmark.baseline_single_hart_nanos,
        measured_smp_nanos: benchmark.measured_smp_nanos,
        budget_nanos: benchmark.budget_nanos,
        speedup_milli: benchmark.speedup_milli,
        efficiency_milli: benchmark.efficiency_milli,
        event_log_cursor: benchmark.event_log_cursor,
        stress_safe_point_count: benchmark.stress_safe_point_count,
        stress_rendezvous_count: benchmark.stress_rendezvous_count,
        stress_property_failures: benchmark.stress_property_failures,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

fn device_object_manifest(device: &semantic_core::DeviceObjectRecord) -> DeviceObjectManifest {
    DeviceObjectManifest {
        id: device.id,
        name: device.name.clone(),
        class: device.class.clone(),
        resource: device.resource,
        resource_generation: device.resource_generation,
        backend: device.backend.clone(),
        bus: device.bus.clone(),
        vendor: device.vendor.clone(),
        model: device.model.clone(),
        generation: device.generation,
        state: device.state.as_str().to_owned(),
        recorded_at_event: device.recorded_at_event,
        note: device.note.clone(),
    }
}

fn block_device_object_manifest(
    block_device: &semantic_core::BlockDeviceObjectRecord,
) -> BlockDeviceObjectManifest {
    BlockDeviceObjectManifest {
        id: block_device.id,
        name: block_device.name.clone(),
        device: block_device.device,
        device_generation: block_device.device_generation,
        sector_size: block_device.sector_size,
        sector_count: block_device.sector_count,
        read_only: block_device.read_only,
        max_transfer_sectors: block_device.max_transfer_sectors,
        generation: block_device.generation,
        state: block_device.state.as_str().to_owned(),
        recorded_at_event: block_device.recorded_at_event,
        note: block_device.note.clone(),
    }
}

fn block_range_object_manifest(
    block_range: &semantic_core::BlockRangeObjectRecord,
) -> BlockRangeObjectManifest {
    BlockRangeObjectManifest {
        id: block_range.id,
        block_device: block_range.block_device,
        block_device_generation: block_range.block_device_generation,
        start_sector: block_range.start_sector,
        sector_count: block_range.sector_count,
        byte_offset: block_range.byte_offset,
        byte_len: block_range.byte_len,
        generation: block_range.generation,
        state: block_range.state.as_str().to_owned(),
        recorded_at_event: block_range.recorded_at_event,
        note: block_range.note.clone(),
    }
}

fn block_request_object_manifest(
    request: &semantic_core::BlockRequestObjectRecord,
) -> BlockRequestObjectManifest {
    BlockRequestObjectManifest {
        id: request.id,
        block_device: request.block_device,
        block_device_generation: request.block_device_generation,
        block_range: request.block_range,
        block_range_generation: request.block_range_generation,
        operation: request.operation.as_str().to_owned(),
        sequence: request.sequence,
        byte_len: request.byte_len,
        generation: request.generation,
        state: request.state.as_str().to_owned(),
        recorded_at_event: request.recorded_at_event,
        note: request.note.clone(),
    }
}

fn block_completion_object_manifest(
    completion: &semantic_core::BlockCompletionObjectRecord,
) -> BlockCompletionObjectManifest {
    BlockCompletionObjectManifest {
        id: completion.id,
        block_request: completion.block_request,
        block_request_generation: completion.block_request_generation,
        block_device: completion.block_device,
        block_device_generation: completion.block_device_generation,
        block_range: completion.block_range,
        block_range_generation: completion.block_range_generation,
        sequence: completion.sequence,
        completed_bytes: completion.completed_bytes,
        status: completion.status.as_str().to_owned(),
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        recorded_at_event: completion.recorded_at_event,
        note: completion.note.clone(),
    }
}

fn block_wait_manifest(wait: &semantic_core::BlockWaitRecord) -> BlockWaitManifest {
    BlockWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        block_request: wait.block_request,
        block_request_generation: wait.block_request_generation,
        block_device: wait.block_device,
        block_device_generation: wait.block_device_generation,
        block_range: wait.block_range,
        block_range_generation: wait.block_range_generation,
        operation: wait.operation.as_str().to_owned(),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        completion: wait.completion,
        completion_generation: wait.completion_generation,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

fn fake_block_backend_object_manifest(
    backend: &semantic_core::FakeBlockBackendObjectRecord,
) -> FakeBlockBackendObjectManifest {
    FakeBlockBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

fn virtio_blk_backend_object_manifest(
    backend: &semantic_core::VirtioBlkBackendObjectRecord,
) -> VirtioBlkBackendObjectManifest {
    VirtioBlkBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        request_queue_index: backend.request_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

fn block_read_path_manifest(
    read_path: &semantic_core::BlockReadPathRecord,
) -> BlockReadPathManifest {
    BlockReadPathManifest {
        id: read_path.id,
        backend_kind: read_path.backend.kind.as_str().to_owned(),
        backend: read_path.backend.id,
        backend_generation: read_path.backend.generation,
        block_request: read_path.block_request,
        block_request_generation: read_path.block_request_generation,
        block_completion: read_path.block_completion,
        block_completion_generation: read_path.block_completion_generation,
        block_device: read_path.block_device,
        block_device_generation: read_path.block_device_generation,
        block_range: read_path.block_range,
        block_range_generation: read_path.block_range_generation,
        sequence: read_path.sequence,
        completed_bytes: read_path.completed_bytes,
        data_digest: read_path.data_digest,
        generation: read_path.generation,
        state: read_path.state.as_str().to_owned(),
        recorded_at_event: read_path.recorded_at_event,
        note: read_path.note.clone(),
    }
}

fn block_write_path_manifest(
    write_path: &semantic_core::BlockWritePathRecord,
) -> BlockWritePathManifest {
    BlockWritePathManifest {
        id: write_path.id,
        backend_kind: write_path.backend.kind.as_str().to_owned(),
        backend: write_path.backend.id,
        backend_generation: write_path.backend.generation,
        block_request: write_path.block_request,
        block_request_generation: write_path.block_request_generation,
        block_completion: write_path.block_completion,
        block_completion_generation: write_path.block_completion_generation,
        block_device: write_path.block_device,
        block_device_generation: write_path.block_device_generation,
        block_range: write_path.block_range,
        block_range_generation: write_path.block_range_generation,
        sequence: write_path.sequence,
        completed_bytes: write_path.completed_bytes,
        payload_digest: write_path.payload_digest,
        generation: write_path.generation,
        state: write_path.state.as_str().to_owned(),
        recorded_at_event: write_path.recorded_at_event,
        note: write_path.note.clone(),
    }
}

fn block_request_queue_manifest(
    queue: &semantic_core::BlockRequestQueueRecord,
) -> BlockRequestQueueManifest {
    BlockRequestQueueManifest {
        id: queue.id,
        backend_kind: queue.backend.kind.as_str().to_owned(),
        backend: queue.backend.id,
        backend_generation: queue.backend.generation,
        block_device: queue.block_device,
        block_device_generation: queue.block_device_generation,
        depth: queue.depth,
        entries: queue
            .entries
            .iter()
            .map(|entry| BlockRequestQueueEntryManifest {
                request: entry.request,
                request_generation: entry.request_generation,
                completion: entry.completion,
                completion_generation: entry.completion_generation,
                sequence: entry.sequence,
                operation: entry.operation.as_str().to_owned(),
                byte_len: entry.byte_len,
                state: entry.state.as_str().to_owned(),
            })
            .collect(),
        pending_count: queue.pending_count,
        completed_count: queue.completed_count,
        first_sequence: queue.first_sequence,
        last_sequence: queue.last_sequence,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

fn block_dma_buffer_manifest(
    buffer: &semantic_core::BlockDmaBufferRecord,
) -> BlockDmaBufferManifest {
    BlockDmaBufferManifest {
        id: buffer.id,
        backend_kind: buffer.backend.kind.as_str().to_owned(),
        backend: buffer.backend.id,
        backend_generation: buffer.backend.generation,
        block_request: buffer.block_request,
        block_request_generation: buffer.block_request_generation,
        dma_buffer: buffer.dma_buffer,
        dma_buffer_generation: buffer.dma_buffer_generation,
        block_device: buffer.block_device,
        block_device_generation: buffer.block_device_generation,
        block_range: buffer.block_range,
        block_range_generation: buffer.block_range_generation,
        descriptor: buffer.descriptor,
        descriptor_generation: buffer.descriptor_generation,
        queue: buffer.queue,
        queue_generation: buffer.queue_generation,
        operation: buffer.operation.as_str().to_owned(),
        access: buffer.access.as_str().to_owned(),
        byte_len: buffer.byte_len,
        buffer_len: buffer.buffer_len,
        buffer_digest: buffer.buffer_digest,
        generation: buffer.generation,
        state: buffer.state.as_str().to_owned(),
        recorded_at_event: buffer.recorded_at_event,
        note: buffer.note.clone(),
    }
}

fn block_page_object_manifest(
    page: &semantic_core::BlockPageObjectRecord,
) -> BlockPageObjectManifest {
    BlockPageObjectManifest {
        id: page.id,
        block_dma_buffer: page.block_dma_buffer,
        block_dma_buffer_generation: page.block_dma_buffer_generation,
        block_request: page.block_request,
        block_request_generation: page.block_request_generation,
        block_completion: page.block_completion,
        block_completion_generation: page.block_completion_generation,
        dma_buffer: page.dma_buffer,
        dma_buffer_generation: page.dma_buffer_generation,
        block_device: page.block_device,
        block_device_generation: page.block_device_generation,
        block_range: page.block_range,
        block_range_generation: page.block_range_generation,
        aspace: contract_object_ref_manifest(page.aspace),
        vma_region: contract_object_ref_manifest(page.vma_region),
        page: contract_object_ref_manifest(page.page),
        page_dirty_generation: page.page_dirty_generation,
        page_backing: page.page_backing.as_str().to_owned(),
        cow_state: page.cow_state.as_str().to_owned(),
        page_state: page.page_state.as_str().to_owned(),
        page_offset: page.page_offset,
        byte_len: page.byte_len,
        operation: page.operation.as_str().to_owned(),
        generation: page.generation,
        state: page.state.as_str().to_owned(),
        recorded_at_event: page.recorded_at_event,
        note: page.note.clone(),
    }
}

fn buffer_cache_object_manifest(
    cache: &semantic_core::BufferCacheObjectRecord,
) -> BufferCacheObjectManifest {
    BufferCacheObjectManifest {
        id: cache.id,
        block_page_object: cache.block_page_object,
        block_page_object_generation: cache.block_page_object_generation,
        block_dma_buffer: cache.block_dma_buffer,
        block_dma_buffer_generation: cache.block_dma_buffer_generation,
        block_device: cache.block_device,
        block_device_generation: cache.block_device_generation,
        block_range: cache.block_range,
        block_range_generation: cache.block_range_generation,
        aspace: contract_object_ref_manifest(cache.aspace),
        vma_region: contract_object_ref_manifest(cache.vma_region),
        page: contract_object_ref_manifest(cache.page),
        page_dirty_generation: cache.page_dirty_generation,
        page_offset: cache.page_offset,
        block_offset: cache.block_offset,
        byte_len: cache.byte_len,
        operation: cache.operation.as_str().to_owned(),
        cache_state: cache.cache_state.as_str().to_owned(),
        coherency_epoch: cache.coherency_epoch,
        generation: cache.generation,
        state: cache.state.as_str().to_owned(),
        recorded_at_event: cache.recorded_at_event,
        note: cache.note.clone(),
    }
}

fn file_object_manifest(file: &semantic_core::FileObjectRecord) -> FileObjectManifest {
    FileObjectManifest {
        id: file.id,
        buffer_cache_object: file.buffer_cache_object,
        buffer_cache_object_generation: file.buffer_cache_object_generation,
        block_device: file.block_device,
        block_device_generation: file.block_device_generation,
        block_range: file.block_range,
        block_range_generation: file.block_range_generation,
        page: contract_object_ref_manifest(file.page),
        page_dirty_generation: file.page_dirty_generation,
        namespace: file.namespace.clone(),
        file_key: file.file_key.clone(),
        path: file.path.clone(),
        file_offset: file.file_offset,
        byte_len: file.byte_len,
        file_size: file.file_size,
        content_digest: file.content_digest,
        cache_state: file.cache_state.as_str().to_owned(),
        generation: file.generation,
        state: file.state.as_str().to_owned(),
        recorded_at_event: file.recorded_at_event,
        note: file.note.clone(),
    }
}

fn directory_object_manifest(
    directory: &semantic_core::DirectoryObjectRecord,
) -> DirectoryObjectManifest {
    DirectoryObjectManifest {
        id: directory.id,
        file_object: directory.file_object,
        file_object_generation: directory.file_object_generation,
        namespace: directory.namespace.clone(),
        directory_key: directory.directory_key.clone(),
        directory_path: directory.directory_path.clone(),
        entry_name: directory.entry_name.clone(),
        child_file_key: directory.child_file_key.clone(),
        child_path: directory.child_path.clone(),
        entry_kind: directory.entry_kind.as_str().to_owned(),
        file_size: directory.file_size,
        content_digest: directory.content_digest,
        generation: directory.generation,
        state: directory.state.as_str().to_owned(),
        recorded_at_event: directory.recorded_at_event,
        note: directory.note.clone(),
    }
}

fn fat_adapter_object_manifest(
    adapter: &semantic_core::FatAdapterObjectRecord,
) -> FatAdapterObjectManifest {
    FatAdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_written: adapter.bytes_written,
        bytes_read: adapter.bytes_read,
        write_digest: adapter.write_digest,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

fn ext4_adapter_object_manifest(
    adapter: &semantic_core::Ext4AdapterObjectRecord,
) -> Ext4AdapterObjectManifest {
    Ext4AdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_read: adapter.bytes_read,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        directory_entries: adapter.directory_entries,
        read_only_enforced: adapter.read_only_enforced,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

fn file_handle_capability_manifest(
    capability: &semantic_core::FileHandleCapabilityRecord,
) -> FileHandleCapabilityManifest {
    FileHandleCapabilityManifest {
        id: capability.id,
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        file_object: capability.file_object,
        file_object_generation: capability.file_object_generation,
        directory_object: capability.directory_object,
        directory_object_generation: capability.directory_object_generation,
        capability: capability.capability,
        capability_generation: capability.capability_generation,
        handle_slot: capability.handle_slot,
        handle_generation: capability.handle_generation,
        handle_tag: capability.handle_tag,
        operation: capability.operation.clone(),
        file_offset: capability.file_offset,
        byte_len: capability.byte_len,
        content_digest: capability.content_digest,
        generation: capability.generation,
        state: capability.state.as_str().to_owned(),
        recorded_at_event: capability.recorded_at_event,
        note: capability.note.clone(),
    }
}

fn fs_wait_manifest(wait: &semantic_core::FsWaitRecord) -> FsWaitManifest {
    FsWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        file_object: wait.file_object,
        file_object_generation: wait.file_object_generation,
        directory_object: wait.directory_object,
        directory_object_generation: wait.directory_object_generation,
        file_handle_capability: wait.file_handle_capability,
        file_handle_capability_generation: wait.file_handle_capability_generation,
        operation: wait.operation.clone(),
        blocker: contract_object_ref_manifest(wait.blocker),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

fn queue_object_manifest(queue: &semantic_core::QueueObjectRecord) -> QueueObjectManifest {
    QueueObjectManifest {
        id: queue.id,
        name: queue.name.clone(),
        role: queue.role.as_str().to_owned(),
        queue_index: queue.queue_index,
        depth: queue.depth,
        device: queue.device,
        device_generation: queue.device_generation,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

fn descriptor_object_manifest(
    descriptor: &semantic_core::DescriptorObjectRecord,
) -> DescriptorObjectManifest {
    DescriptorObjectManifest {
        id: descriptor.id,
        queue: descriptor.queue,
        queue_generation: descriptor.queue_generation,
        slot: descriptor.slot,
        access: descriptor.access.as_str().to_owned(),
        length: descriptor.length,
        generation: descriptor.generation,
        state: descriptor.state.as_str().to_owned(),
        recorded_at_event: descriptor.recorded_at_event,
        note: descriptor.note.clone(),
    }
}

fn dma_buffer_object_manifest(
    dma_buffer: &semantic_core::DmaBufferObjectRecord,
) -> DmaBufferObjectManifest {
    DmaBufferObjectManifest {
        id: dma_buffer.id,
        descriptor: dma_buffer.descriptor,
        descriptor_generation: dma_buffer.descriptor_generation,
        resource: dma_buffer.resource,
        resource_generation: dma_buffer.resource_generation,
        access: dma_buffer.access.as_str().to_owned(),
        length: dma_buffer.length,
        generation: dma_buffer.generation,
        state: dma_buffer.state.as_str().to_owned(),
        recorded_at_event: dma_buffer.recorded_at_event,
        note: dma_buffer.note.clone(),
    }
}

fn mmio_region_object_manifest(
    mmio_region: &semantic_core::MmioRegionObjectRecord,
) -> MmioRegionObjectManifest {
    MmioRegionObjectManifest {
        id: mmio_region.id,
        device: mmio_region.device,
        device_generation: mmio_region.device_generation,
        resource: mmio_region.resource,
        resource_generation: mmio_region.resource_generation,
        region_index: mmio_region.region_index,
        offset: mmio_region.offset,
        length: mmio_region.length,
        access: mmio_region.access.as_str().to_owned(),
        generation: mmio_region.generation,
        state: mmio_region.state.as_str().to_owned(),
        recorded_at_event: mmio_region.recorded_at_event,
        note: mmio_region.note.clone(),
    }
}

fn irq_line_object_manifest(
    irq_line: &semantic_core::IrqLineObjectRecord,
) -> IrqLineObjectManifest {
    IrqLineObjectManifest {
        id: irq_line.id,
        device: irq_line.device,
        device_generation: irq_line.device_generation,
        resource: irq_line.resource,
        resource_generation: irq_line.resource_generation,
        irq_number: irq_line.irq_number,
        trigger: irq_line.trigger.as_str().to_owned(),
        polarity: irq_line.polarity.as_str().to_owned(),
        generation: irq_line.generation,
        state: irq_line.state.as_str().to_owned(),
        recorded_at_event: irq_line.recorded_at_event,
        note: irq_line.note.clone(),
    }
}

fn irq_event_manifest(irq_event: &semantic_core::IrqEventRecord) -> IrqEventManifest {
    IrqEventManifest {
        id: irq_event.id,
        irq_line: irq_event.irq_line,
        irq_line_generation: irq_event.irq_line_generation,
        device: irq_event.device,
        device_generation: irq_event.device_generation,
        driver_store: irq_event.driver_store,
        driver_store_generation: irq_event.driver_store_generation,
        irq_number: irq_event.irq_number,
        sequence: irq_event.sequence,
        generation: irq_event.generation,
        state: irq_event.state.as_str().to_owned(),
        recorded_at_event: irq_event.recorded_at_event,
        note: irq_event.note.clone(),
    }
}

fn device_capability_manifest(
    device_capability: &semantic_core::DeviceCapabilityRecord,
) -> DeviceCapabilityManifest {
    DeviceCapabilityManifest {
        id: device_capability.id,
        driver_store: device_capability.driver_store,
        driver_store_generation: device_capability.driver_store_generation,
        target: contract_object_ref_manifest(device_capability.target),
        class: device_capability.class.as_str().to_owned(),
        operation: device_capability.operation.clone(),
        capability: device_capability.capability,
        capability_generation: device_capability.capability_generation,
        handle_slot: device_capability.handle_slot,
        handle_generation: device_capability.handle_generation,
        handle_tag: device_capability.handle_tag,
        generation: device_capability.generation,
        state: device_capability.state.as_str().to_owned(),
        recorded_at_event: device_capability.recorded_at_event,
        note: device_capability.note.clone(),
    }
}

fn driver_store_binding_manifest(
    binding: &semantic_core::DriverStoreBindingRecord,
) -> DriverStoreBindingManifest {
    DriverStoreBindingManifest {
        id: binding.id,
        driver_store: binding.driver_store,
        driver_store_generation: binding.driver_store_generation,
        device: binding.device,
        device_generation: binding.device_generation,
        device_capability: binding.device_capability,
        device_capability_generation: binding.device_capability_generation,
        capability: binding.capability,
        capability_generation: binding.capability_generation,
        generation: binding.generation,
        state: binding.state.as_str().to_owned(),
        recorded_at_event: binding.recorded_at_event,
        note: binding.note.clone(),
    }
}

fn io_wait_manifest(io_wait: &semantic_core::IoWaitRecord) -> IoWaitManifest {
    IoWaitManifest {
        id: io_wait.id,
        wait: io_wait.wait,
        wait_generation: io_wait.wait_generation,
        driver_store: io_wait.driver_store,
        driver_store_generation: io_wait.driver_store_generation,
        device: io_wait.device,
        device_generation: io_wait.device_generation,
        driver_binding: io_wait.driver_binding,
        driver_binding_generation: io_wait.driver_binding_generation,
        blocker: contract_object_ref_manifest(io_wait.blocker),
        generation: io_wait.generation,
        state: io_wait.state.as_str().to_owned(),
        created_at_event: io_wait.created_at_event,
        completed_at_event: io_wait.completed_at_event,
        completion_irq_event: io_wait.completion_irq_event,
        completion_irq_event_generation: io_wait.completion_irq_event_generation,
        cancel_reason: io_wait
            .cancel_reason
            .map(|reason| reason.as_str().to_owned()),
        note: io_wait.note.clone(),
    }
}

fn io_cleanup_manifest(cleanup: &semantic_core::IoCleanupRecord) -> IoCleanupManifest {
    IoCleanupManifest {
        id: cleanup.id,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        cancelled_io_waits: cleanup
            .cancelled_io_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_device_capabilities: cleanup
            .revoked_device_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_capabilities: cleanup
            .revoked_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_dma_buffers: cleanup
            .released_dma_buffers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_mmio_regions: cleanup
            .released_mmio_regions
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_irq_lines: cleanup
            .released_irq_lines
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| IoCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

fn io_fault_injection_manifest(
    fault: &semantic_core::IoFaultInjectionRecord,
) -> IoFaultInjectionManifest {
    IoFaultInjectionManifest {
        id: fault.id,
        driver_store: fault.driver_store,
        driver_store_generation: fault.driver_store_generation,
        device: fault.device,
        device_generation: fault.device_generation,
        driver_binding: fault.driver_binding,
        driver_binding_generation: fault.driver_binding_generation,
        target: contract_object_ref_manifest(fault.target),
        cleanup: fault.cleanup,
        cleanup_generation: fault.cleanup_generation,
        generation: fault.generation,
        kind: fault.kind.as_str().to_owned(),
        state: fault.state.as_str().to_owned(),
        injected_at_event: fault.injected_at_event,
        note: fault.note.clone(),
    }
}

fn io_validation_report_manifest(
    report: &semantic_core::IoValidationReportRecord,
) -> IoValidationReportManifest {
    IoValidationReportManifest {
        id: report.id,
        generation: report.generation,
        state: report.state.as_str().to_owned(),
        validated_at_event: report.validated_at_event,
        event_log_cursor: report.event_log_cursor,
        observed_device_count: report.observed_device_count,
        observed_queue_count: report.observed_queue_count,
        observed_descriptor_count: report.observed_descriptor_count,
        observed_dma_buffer_count: report.observed_dma_buffer_count,
        observed_mmio_region_count: report.observed_mmio_region_count,
        observed_irq_line_count: report.observed_irq_line_count,
        observed_irq_event_count: report.observed_irq_event_count,
        observed_device_capability_count: report.observed_device_capability_count,
        observed_driver_binding_count: report.observed_driver_binding_count,
        observed_io_wait_count: report.observed_io_wait_count,
        observed_io_cleanup_count: report.observed_io_cleanup_count,
        observed_io_fault_injection_count: report.observed_io_fault_injection_count,
        violation_count: report.violations.len(),
        violations: report
            .violations
            .iter()
            .map(|violation| IoValidationViolationManifest {
                code: violation.code.as_str().to_owned(),
                subject: contract_object_ref_manifest(violation.subject),
                relation: violation.relation.clone(),
                message: violation.message.clone(),
            })
            .collect(),
        note: report.note.clone(),
    }
}

fn packet_device_object_manifest(
    packet_device: &semantic_core::PacketDeviceObjectRecord,
) -> PacketDeviceObjectManifest {
    PacketDeviceObjectManifest {
        id: packet_device.id,
        name: packet_device.name.clone(),
        device: packet_device.device,
        device_generation: packet_device.device_generation,
        mtu: packet_device.mtu,
        rx_queue_depth: packet_device.rx_queue_depth,
        tx_queue_depth: packet_device.tx_queue_depth,
        mac: packet_device.mac,
        frame_format_version: packet_device.frame_format_version,
        max_payload_len: packet_device.max_payload_len,
        generation: packet_device.generation,
        state: packet_device.state.as_str().to_owned(),
        recorded_at_event: packet_device.recorded_at_event,
        note: packet_device.note.clone(),
    }
}

fn packet_buffer_object_manifest(
    packet_buffer: &semantic_core::PacketBufferObjectRecord,
) -> PacketBufferObjectManifest {
    PacketBufferObjectManifest {
        id: packet_buffer.id,
        packet_device: packet_buffer.packet_device,
        packet_device_generation: packet_buffer.packet_device_generation,
        direction: packet_buffer.direction.as_str().to_owned(),
        frame_format_version: packet_buffer.frame_format_version,
        capacity: packet_buffer.capacity,
        payload_len: packet_buffer.payload_len,
        sequence: packet_buffer.sequence,
        generation: packet_buffer.generation,
        state: packet_buffer.state.as_str().to_owned(),
        recorded_at_event: packet_buffer.recorded_at_event,
        note: packet_buffer.note.clone(),
    }
}

fn packet_queue_object_manifest(
    packet_queue: &semantic_core::PacketQueueObjectRecord,
) -> PacketQueueObjectManifest {
    PacketQueueObjectManifest {
        id: packet_queue.id,
        name: packet_queue.name.clone(),
        packet_device: packet_queue.packet_device,
        packet_device_generation: packet_queue.packet_device_generation,
        role: packet_queue.role.as_str().to_owned(),
        queue_index: packet_queue.queue_index,
        depth: packet_queue.depth,
        generation: packet_queue.generation,
        state: packet_queue.state.as_str().to_owned(),
        recorded_at_event: packet_queue.recorded_at_event,
        note: packet_queue.note.clone(),
    }
}

fn packet_descriptor_object_manifest(
    packet_descriptor: &semantic_core::PacketDescriptorObjectRecord,
) -> PacketDescriptorObjectManifest {
    PacketDescriptorObjectManifest {
        id: packet_descriptor.id,
        packet_queue: packet_descriptor.packet_queue,
        packet_queue_generation: packet_descriptor.packet_queue_generation,
        packet_buffer: packet_descriptor.packet_buffer,
        packet_buffer_generation: packet_descriptor.packet_buffer_generation,
        slot: packet_descriptor.slot,
        length: packet_descriptor.length,
        generation: packet_descriptor.generation,
        state: packet_descriptor.state.as_str().to_owned(),
        recorded_at_event: packet_descriptor.recorded_at_event,
        note: packet_descriptor.note.clone(),
    }
}

fn fake_net_backend_object_manifest(
    backend: &semantic_core::FakeNetBackendObjectRecord,
) -> FakeNetBackendObjectManifest {
    FakeNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

fn virtio_net_backend_object_manifest(
    backend: &semantic_core::VirtioNetBackendObjectRecord,
) -> VirtioNetBackendObjectManifest {
    VirtioNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        rx_queue_index: backend.rx_queue_index,
        tx_queue_index: backend.tx_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

fn network_rx_interrupt_manifest(
    rx_interrupt: &semantic_core::NetworkRxInterruptRecord,
) -> NetworkRxInterruptManifest {
    NetworkRxInterruptManifest {
        id: rx_interrupt.id,
        virtio_net_backend: rx_interrupt.virtio_net_backend,
        virtio_net_backend_generation: rx_interrupt.virtio_net_backend_generation,
        irq_event: rx_interrupt.irq_event,
        irq_event_generation: rx_interrupt.irq_event_generation,
        packet_device: rx_interrupt.packet_device,
        packet_device_generation: rx_interrupt.packet_device_generation,
        rx_queue: rx_interrupt.rx_queue,
        rx_queue_generation: rx_interrupt.rx_queue_generation,
        ready_descriptors: rx_interrupt.ready_descriptors,
        sequence: rx_interrupt.sequence,
        generation: rx_interrupt.generation,
        state: rx_interrupt.state.as_str().to_owned(),
        recorded_at_event: rx_interrupt.recorded_at_event,
        note: rx_interrupt.note.clone(),
    }
}

fn network_rx_wait_resolution_manifest(
    resolution: &semantic_core::NetworkRxWaitResolutionRecord,
) -> NetworkRxWaitResolutionManifest {
    NetworkRxWaitResolutionManifest {
        id: resolution.id,
        io_wait: resolution.io_wait,
        io_wait_generation: resolution.io_wait_generation,
        wait: resolution.wait,
        wait_generation: resolution.wait_generation,
        rx_interrupt: resolution.rx_interrupt,
        rx_interrupt_generation: resolution.rx_interrupt_generation,
        irq_event: resolution.irq_event,
        irq_event_generation: resolution.irq_event_generation,
        packet_device: resolution.packet_device,
        packet_device_generation: resolution.packet_device_generation,
        rx_queue: resolution.rx_queue,
        rx_queue_generation: resolution.rx_queue_generation,
        ready_descriptors: resolution.ready_descriptors,
        sequence: resolution.sequence,
        generation: resolution.generation,
        state: resolution.state.as_str().to_owned(),
        resolved_at_event: resolution.resolved_at_event,
        note: resolution.note.clone(),
    }
}

fn network_tx_capability_gate_manifest(
    gate: &semantic_core::NetworkTxCapabilityGateRecord,
) -> NetworkTxCapabilityGateManifest {
    NetworkTxCapabilityGateManifest {
        id: gate.id,
        driver_store: gate.driver_store,
        driver_store_generation: gate.driver_store_generation,
        packet_device: gate.packet_device,
        packet_device_generation: gate.packet_device_generation,
        tx_queue: gate.tx_queue,
        tx_queue_generation: gate.tx_queue_generation,
        packet_descriptor: gate.packet_descriptor,
        packet_descriptor_generation: gate.packet_descriptor_generation,
        packet_buffer: gate.packet_buffer,
        packet_buffer_generation: gate.packet_buffer_generation,
        device_capability: gate.device_capability,
        device_capability_generation: gate.device_capability_generation,
        capability: gate.capability,
        capability_generation: gate.capability_generation,
        handle_slot: gate.handle_slot,
        handle_generation: gate.handle_generation,
        handle_tag: gate.handle_tag,
        operation: gate.operation.clone(),
        byte_len: gate.byte_len,
        sequence: gate.sequence,
        generation: gate.generation,
        state: gate.state.as_str().to_owned(),
        recorded_at_event: gate.recorded_at_event,
        note: gate.note.clone(),
    }
}

fn network_tx_completion_manifest(
    completion: &semantic_core::NetworkTxCompletionRecord,
) -> NetworkTxCompletionManifest {
    NetworkTxCompletionManifest {
        id: completion.id,
        tx_gate: completion.tx_gate,
        tx_gate_generation: completion.tx_gate_generation,
        backend_kind: completion.backend.kind.as_str().to_owned(),
        backend: completion.backend.id,
        backend_generation: completion.backend.generation,
        driver_store: completion.driver_store,
        driver_store_generation: completion.driver_store_generation,
        packet_device: completion.packet_device,
        packet_device_generation: completion.packet_device_generation,
        tx_queue: completion.tx_queue,
        tx_queue_generation: completion.tx_queue_generation,
        packet_descriptor: completion.packet_descriptor,
        packet_descriptor_generation: completion.packet_descriptor_generation,
        packet_buffer: completion.packet_buffer,
        packet_buffer_generation: completion.packet_buffer_generation,
        byte_len: completion.byte_len,
        sequence: completion.sequence,
        completion_sequence: completion.completion_sequence,
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        completed_at_event: completion.completed_at_event,
        note: completion.note.clone(),
    }
}

fn network_stack_adapter_manifest(
    adapter: &semantic_core::NetworkStackAdapterRecord,
) -> NetworkStackAdapterManifest {
    NetworkStackAdapterManifest {
        id: adapter.id,
        implementation: adapter.implementation.clone(),
        implementation_version: adapter.implementation_version.clone(),
        profile: adapter.profile.clone(),
        medium: adapter.medium.clone(),
        backend_kind: adapter.backend.kind.as_str().to_owned(),
        backend: adapter.backend.id,
        backend_generation: adapter.backend.generation,
        packet_device: adapter.packet_device,
        packet_device_generation: adapter.packet_device_generation,
        rx_queue: adapter.rx_queue,
        rx_queue_generation: adapter.rx_queue_generation,
        tx_queue: adapter.tx_queue,
        tx_queue_generation: adapter.tx_queue_generation,
        mac: adapter.mac,
        ipv4_addr: adapter.ipv4_addr,
        ipv4_prefix_len: adapter.ipv4_prefix_len,
        mtu: adapter.mtu,
        rx_queue_depth: adapter.rx_queue_depth,
        tx_queue_depth: adapter.tx_queue_depth,
        max_payload_len: adapter.max_payload_len,
        socket_capacity: adapter.socket_capacity,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

fn socket_object_manifest(socket: &semantic_core::SocketObjectRecord) -> SocketObjectManifest {
    SocketObjectManifest {
        id: socket.id,
        adapter: socket.adapter,
        adapter_generation: socket.adapter_generation,
        owner_store: socket.owner_store,
        owner_store_generation: socket.owner_store_generation,
        domain: socket.domain,
        socket_type: socket.socket_type,
        protocol: socket.protocol,
        canonical_protocol: socket.canonical_protocol,
        family: socket.family.clone(),
        transport: socket.transport.clone(),
        generation: socket.generation,
        state: socket.state.as_str().to_owned(),
        created_at_event: socket.created_at_event,
        note: socket.note.clone(),
    }
}

fn endpoint_object_manifest(
    endpoint: &semantic_core::EndpointObjectRecord,
) -> EndpointObjectManifest {
    EndpointObjectManifest {
        id: endpoint.id,
        socket: endpoint.socket,
        socket_generation: endpoint.socket_generation,
        adapter: endpoint.adapter,
        adapter_generation: endpoint.adapter_generation,
        owner_store: endpoint.owner_store,
        owner_store_generation: endpoint.owner_store_generation,
        family: endpoint.family.clone(),
        transport: endpoint.transport.clone(),
        local_addr: endpoint.local_addr,
        local_port: endpoint.local_port,
        remote_addr: endpoint.remote_addr,
        remote_port: endpoint.remote_port,
        generation: endpoint.generation,
        state: endpoint.state.as_str().to_owned(),
        created_at_event: endpoint.created_at_event,
        note: endpoint.note.clone(),
    }
}

fn socket_operation_manifest(
    operation: &semantic_core::SocketOperationRecord,
) -> SocketOperationManifest {
    SocketOperationManifest {
        id: operation.id,
        endpoint: operation.endpoint,
        endpoint_generation: operation.endpoint_generation,
        socket: operation.socket,
        socket_generation: operation.socket_generation,
        adapter: operation.adapter,
        adapter_generation: operation.adapter_generation,
        owner_store: operation.owner_store,
        owner_store_generation: operation.owner_store_generation,
        operation: operation.operation.as_str().to_owned(),
        local_addr: operation.local_addr,
        local_port: operation.local_port,
        remote_addr: operation.remote_addr,
        remote_port: operation.remote_port,
        backlog: operation.backlog,
        byte_len: operation.byte_len,
        sequence: operation.sequence,
        generation: operation.generation,
        state: operation.state.as_str().to_owned(),
        recorded_at_event: operation.recorded_at_event,
        note: operation.note.clone(),
    }
}

fn socket_wait_manifest(wait: &semantic_core::SocketWaitRecord) -> SocketWaitManifest {
    SocketWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        endpoint: wait.endpoint,
        endpoint_generation: wait.endpoint_generation,
        socket: wait.socket,
        socket_generation: wait.socket_generation,
        adapter: wait.adapter,
        adapter_generation: wait.adapter_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        wait_kind: wait.wait_kind.as_str().to_owned(),
        blocker: contract_object_ref_manifest(wait.blocker),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        ready_sequence: wait.ready_sequence,
        byte_len: wait.byte_len,
        note: wait.note.clone(),
    }
}

fn network_backpressure_manifest(
    backpressure: &semantic_core::NetworkBackpressureRecord,
) -> NetworkBackpressureManifest {
    NetworkBackpressureManifest {
        id: backpressure.id,
        adapter: backpressure.adapter,
        adapter_generation: backpressure.adapter_generation,
        packet_device: backpressure.packet_device,
        packet_device_generation: backpressure.packet_device_generation,
        packet_queue: backpressure.packet_queue,
        packet_queue_generation: backpressure.packet_queue_generation,
        endpoint: backpressure.endpoint,
        endpoint_generation: backpressure.endpoint_generation,
        socket: backpressure.socket,
        socket_generation: backpressure.socket_generation,
        owner_store: backpressure.owner_store,
        owner_store_generation: backpressure.owner_store_generation,
        direction: backpressure.direction.as_str().to_owned(),
        reason: backpressure.reason.as_str().to_owned(),
        action: backpressure.action.as_str().to_owned(),
        queue_depth: backpressure.queue_depth,
        queue_limit: backpressure.queue_limit,
        dropped_packets: backpressure.dropped_packets,
        dropped_bytes: backpressure.dropped_bytes,
        sequence: backpressure.sequence,
        generation: backpressure.generation,
        state: backpressure.state.as_str().to_owned(),
        recorded_at_event: backpressure.recorded_at_event,
        note: backpressure.note.clone(),
    }
}

fn network_driver_cleanup_manifest(
    cleanup: &semantic_core::NetworkDriverCleanupRecord,
) -> NetworkDriverCleanupManifest {
    NetworkDriverCleanupManifest {
        id: cleanup.id,
        io_cleanup: cleanup.io_cleanup,
        io_cleanup_generation: cleanup.io_cleanup_generation,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        packet_device: cleanup.packet_device,
        packet_device_generation: cleanup.packet_device_generation,
        adapter: cleanup.adapter,
        adapter_generation: cleanup.adapter_generation,
        backend: contract_object_ref_manifest(cleanup.backend),
        cancelled_socket_waits: cleanup
            .cancelled_socket_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        cancelled_wait_tokens: cleanup
            .cancelled_wait_tokens
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_packet_capabilities: cleanup
            .revoked_packet_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        reason: cleanup.reason.clone(),
        note: cleanup.note.clone(),
    }
}

fn network_generation_audit_manifest(
    audit: &semantic_core::NetworkGenerationAuditRecord,
) -> NetworkGenerationAuditManifest {
    NetworkGenerationAuditManifest {
        id: audit.id,
        adapter: audit.adapter,
        adapter_generation: audit.adapter_generation,
        packet_device: audit.packet_device,
        packet_device_generation: audit.packet_device_generation,
        packet_queue: audit.packet_queue,
        packet_queue_generation: audit.packet_queue_generation,
        packet_descriptor: audit.packet_descriptor,
        packet_descriptor_generation: audit.packet_descriptor_generation,
        packet_buffer: audit.packet_buffer,
        packet_buffer_generation: audit.packet_buffer_generation,
        dma_buffer: contract_object_ref_manifest(audit.dma_buffer),
        device_capability: contract_object_ref_manifest(audit.device_capability),
        rejected_packet_generation_probes: audit.rejected_packet_generation_probes,
        rejected_dma_generation_probes: audit.rejected_dma_generation_probes,
        generation: audit.generation,
        state: audit.state.as_str().to_owned(),
        recorded_at_event: audit.recorded_at_event,
        note: audit.note.clone(),
    }
}

fn network_fault_injection_manifest(
    injection: &semantic_core::NetworkFaultInjectionRecord,
) -> NetworkFaultInjectionManifest {
    NetworkFaultInjectionManifest {
        id: injection.id,
        adapter: injection.adapter,
        adapter_generation: injection.adapter_generation,
        packet_device: injection.packet_device,
        packet_device_generation: injection.packet_device_generation,
        packet_queue: injection.packet_queue,
        packet_queue_generation: injection.packet_queue_generation,
        packet_descriptor: injection.packet_descriptor,
        packet_descriptor_generation: injection.packet_descriptor_generation,
        packet_buffer: injection.packet_buffer,
        packet_buffer_generation: injection.packet_buffer_generation,
        endpoint: injection.endpoint,
        endpoint_generation: injection.endpoint_generation,
        socket: injection.socket,
        socket_generation: injection.socket_generation,
        owner_store: injection.owner_store,
        owner_store_generation: injection.owner_store_generation,
        direction: injection.direction.as_str().to_owned(),
        kind: injection.kind.as_str().to_owned(),
        effect: injection.effect.as_str().to_owned(),
        injected_packets: injection.injected_packets,
        dropped_packets: injection.dropped_packets,
        error_packets: injection.error_packets,
        error_code: injection.error_code.clone(),
        sequence: injection.sequence,
        generation: injection.generation,
        state: injection.state.as_str().to_owned(),
        recorded_at_event: injection.recorded_at_event,
        note: injection.note.clone(),
    }
}

fn network_benchmark_manifest(
    benchmark: &semantic_core::NetworkBenchmarkRecord,
) -> NetworkBenchmarkManifest {
    NetworkBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        tx_queue: benchmark.tx_queue,
        tx_queue_generation: benchmark.tx_queue_generation,
        rx_queue: benchmark.rx_queue,
        rx_queue_generation: benchmark.rx_queue_generation,
        tx_completion: benchmark.tx_completion,
        tx_completion_generation: benchmark.tx_completion_generation,
        rx_wait_resolution: benchmark.rx_wait_resolution,
        rx_wait_resolution_generation: benchmark.rx_wait_resolution_generation,
        endpoint: benchmark.endpoint,
        endpoint_generation: benchmark.endpoint_generation,
        socket: benchmark.socket,
        socket_generation: benchmark.socket_generation,
        owner_store: benchmark.owner_store,
        owner_store_generation: benchmark.owner_store_generation,
        backpressure: benchmark.backpressure,
        backpressure_generation: benchmark.backpressure_generation,
        sample_packets: benchmark.sample_packets,
        sample_bytes: benchmark.sample_bytes,
        tx_completed_packets: benchmark.tx_completed_packets,
        rx_resolved_packets: benchmark.rx_resolved_packets,
        dropped_packets: benchmark.dropped_packets,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

fn network_recovery_benchmark_manifest(
    benchmark: &semantic_core::NetworkRecoveryBenchmarkRecord,
) -> NetworkRecoveryBenchmarkManifest {
    NetworkRecoveryBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        cleanup: benchmark.cleanup,
        cleanup_generation: benchmark.cleanup_generation,
        io_cleanup: benchmark.io_cleanup,
        io_cleanup_generation: benchmark.io_cleanup_generation,
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        backend: contract_object_ref_manifest(benchmark.backend),
        driver_store: benchmark.driver_store,
        driver_store_generation: benchmark.driver_store_generation,
        fault_injection: benchmark.fault_injection,
        fault_injection_generation: benchmark.fault_injection_generation,
        recovery_start_event: benchmark.recovery_start_event,
        recovery_complete_event: benchmark.recovery_complete_event,
        cancelled_socket_waits: benchmark.cancelled_socket_waits,
        revoked_packet_capabilities: benchmark.revoked_packet_capabilities,
        recovery_nanos: benchmark.recovery_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

fn activation_resume_manifest(
    resume: &semantic_core::ActivationResumeRecord,
) -> ActivationResumeManifest {
    ActivationResumeManifest {
        id: resume.id,
        scheduler_decision: resume.scheduler_decision,
        scheduler_decision_generation: resume.scheduler_decision_generation,
        activation: resume.activation,
        activation_generation_before: resume.activation_generation_before,
        activation_generation_after: resume.activation_generation_after,
        owner_task: u64::from(resume.owner_task),
        owner_task_generation: resume.owner_task_generation,
        queue: resume.queue,
        queue_generation: resume.queue_generation,
        context: resume.context,
        context_generation_before: resume.context_generation_before,
        context_generation_after: resume.context_generation_after,
        saved_context: resume.saved_context,
        saved_context_generation: resume.saved_context_generation,
        generation: resume.generation,
        state: resume.state.as_str().to_owned(),
        resumed_at_event: resume.resumed_at_event,
        note: resume.note.clone(),
    }
}

fn activation_wait_manifest(wait: &semantic_core::ActivationWaitRecord) -> ActivationWaitManifest {
    ActivationWaitManifest {
        id: wait.id,
        activation: wait.activation,
        activation_generation_before: wait.activation_generation_before,
        activation_generation_after_block: wait.activation_generation_after_block,
        activation_generation_after_cancel: wait.activation_generation_after_cancel,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_task: u64::from(wait.owner_task),
        owner_task_generation: wait.owner_task_generation,
        queue: wait.queue,
        queue_generation: wait.queue_generation,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blocked_at_event: wait.blocked_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

fn activation_cleanup_manifest(
    cleanup: &semantic_core::ActivationCleanupRecord,
) -> ActivationCleanupManifest {
    ActivationCleanupManifest {
        id: cleanup.id,
        store: cleanup.store,
        target_store_generation: cleanup.target_store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation_before: cleanup.activation_generation_before,
        activation_generation_after: cleanup.activation_generation_after,
        wait: cleanup.wait,
        wait_generation: cleanup.wait_generation,
        owner_task: u64::from(cleanup.owner_task),
        owner_task_generation_before: cleanup.owner_task_generation_before,
        owner_task_generation_after: cleanup.owner_task_generation_after,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        steps: cleanup
            .steps
            .iter()
            .map(|step| ActivationCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

fn preemption_latency_manifest(
    sample: &semantic_core::PreemptionLatencySampleRecord,
) -> PreemptionLatencySampleManifest {
    PreemptionLatencySampleManifest {
        id: sample.id,
        timer_interrupt: sample.timer_interrupt,
        timer_interrupt_generation: sample.timer_interrupt_generation,
        preemption: sample.preemption,
        preemption_generation: sample.preemption_generation,
        scheduler_decision: sample.scheduler_decision,
        scheduler_decision_generation: sample.scheduler_decision_generation,
        activation_resume: sample.activation_resume,
        activation_resume_generation: sample.activation_resume_generation,
        activation: sample.activation,
        activation_generation_before: sample.activation_generation_before,
        activation_generation_after: sample.activation_generation_after,
        queue: sample.queue,
        queue_generation: sample.queue_generation,
        interrupt_recorded_at_event: sample.interrupt_recorded_at_event,
        preempted_at_event: sample.preempted_at_event,
        decided_at_event: sample.decided_at_event,
        resumed_at_event: sample.resumed_at_event,
        interrupt_to_preempt_events: sample.interrupt_to_preempt_events,
        preempt_to_decision_events: sample.preempt_to_decision_events,
        decision_to_resume_events: sample.decision_to_resume_events,
        interrupt_to_resume_events: sample.interrupt_to_resume_events,
        measured_nanos: sample.measured_nanos,
        budget_nanos: sample.budget_nanos,
        generation: sample.generation,
        state: sample.state.as_str().to_owned(),
        recorded_at_event: sample.recorded_at_event,
        note: sample.note.clone(),
    }
}

fn wait_record_manifest(wait: &semantic_core::WaitRecord) -> WaitRecordManifest {
    WaitRecordManifest {
        id: wait.id,
        owner_task: wait.owner_task.map(u64::from),
        owner_task_generation: wait.owner_task_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        kind: wait.kind.as_str().to_owned(),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blockers: wait
            .blockers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        deadline: wait.deadline,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        restart_policy: wait.restart_policy.as_str().to_owned(),
        saved_context: wait.saved_context.clone(),
    }
}

fn capability_record_manifest(capability: &CapabilityRecord) -> CapabilityRecordManifest {
    CapabilityRecordManifest {
        id: capability.id,
        subject: capability.subject.clone(),
        object: capability.object.clone(),
        object_ref: capability.object_ref.map(authority_object_ref_manifest),
        rights: capability.operations.as_slice().to_vec(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        owner_task: capability.owner_task.map(u64::from),
        source: capability.source.clone(),
        generation: capability.generation,
        parent: capability.parent,
        manifest_decl: capability.manifest_decl,
        debug_object_label: capability.debug_object_label.clone(),
        revoked: capability.revoked,
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
        generation: trap.generation,
        class: trap.class.as_str().to_owned(),
        store: trap.store,
        store_generation: trap.store_generation,
        activation: trap.activation,
        activation_generation: trap.activation_generation,
        code_object: trap.code_object,
        code_generation: trap.code_generation,
        artifact: trap.artifact,
        artifact_generation: trap.artifact_generation,
        offset: trap.offset,
        target_pc: trap.target_pc,
        trap_kind: trap.trap_kind.clone(),
        function_index: trap.function_index,
        wasm_offset: trap.wasm_offset,
        debug_symbol: trap.debug_symbol,
        classification_status: trap.classification_status.clone(),
        hostcall: trap.hostcall.clone(),
        fault_policy: trap.fault_policy.clone(),
        effect: trap.effect.summary(),
        detail: trap.detail.clone(),
    }
}

fn hostcall_trace_manifest(trace: &HostcallTraceRecord) -> HostcallTraceManifest {
    HostcallTraceManifest {
        id: trace.id,
        generation: trace.generation,
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
        artifact_generation: trace.artifact_generation,
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
        trap_generation_out: trace.trap_generation_out,
        wait_token_out: trace.wait_token_out,
        wait_token_generation_out: trace.wait_token_generation_out,
    }
}

fn cap_arg_manifest(arg: &CapabilityHandleArg) -> CapabilityHandleArgManifest {
    CapabilityHandleArgManifest {
        id: arg.id,
        object: arg.object.clone(),
        generation: arg.generation,
        owner_store: arg.owner_store,
        owner_store_generation: arg.owner_store_generation,
        handle_slot: arg.handle_slot,
        handle_generation: arg.handle_generation,
        handle_tag: arg.handle_tag,
        rights_mask: arg.rights_mask,
        rights: arg.rights.clone(),
    }
}

fn substrate_event_manifests(events: &[EventRecord]) -> Vec<SubstrateEventManifest> {
    events.iter().filter_map(substrate_event_manifest).collect()
}

fn substrate_event_manifest(event: &EventRecord) -> Option<SubstrateEventManifest> {
    match &event.kind {
        EventKind::SubstrateUnsupported {
            authority,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "unsupported".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} observed {authority}::{operation} as unsupported"
                ),
            })
        }
        EventKind::SubstrateCapabilityDenied {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            let capability_manifest = match (*capability, *capability_generation) {
                (Some(id), Some(generation)) => Some(CapabilityHandleArgManifest {
                    id,
                    object: "substrate-capability".to_owned(),
                    generation,
                    owner_store: None,
                    owner_store_generation: None,
                    handle_slot: 0,
                    handle_generation: 0,
                    handle_tag: 0,
                    rights_mask: 0,
                    rights: Vec::new(),
                }),
                _ => None,
            };
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "capability-denied".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: capability_manifest,
                explanation: format!(
                    "{requester_label} was denied {authority}::{operation} by capability gate"
                ),
            })
        }
        _ => None,
    }
}

fn command_result_manifest(result: &CommandResult) -> CommandResultManifest {
    CommandResultManifest {
        id: result.command_id,
        issuer: result.issuer.clone(),
        command: result.command.to_owned(),
        status: result.status.as_str().to_owned(),
        events: result.events.clone(),
        effects: result
            .effects
            .iter()
            .map(|effect| CommandEffectManifest {
                kind: effect.kind.clone(),
                target: effect.target.map(contract_object_ref_manifest),
            })
            .collect(),
        violations: result.violations.clone(),
    }
}

fn interface_event_manifests(events: &[EventRecord]) -> Vec<InterfaceEventManifest> {
    events.iter().filter_map(interface_event_manifest).collect()
}

fn interface_event_manifest(event: &EventRecord) -> Option<InterfaceEventManifest> {
    match &event.kind {
        EventKind::InterfaceUnsupported {
            interface_kind,
            interface,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(InterfaceEventManifest {
                id: event.id,
                epoch: event.epoch,
                interface_kind: interface_kind.clone(),
                interface: interface.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                explanation: format!(
                    "{requester_label} observed {interface_kind} {interface}::{operation} as unsupported"
                ),
            })
        }
        _ => None,
    }
}

fn migration_object_manifest(record: &MigrationObjectRecord) -> MigrationObjectManifest {
    MigrationObjectManifest {
        object: record.object.clone(),
        class: record.class.as_str().to_owned(),
        reason: record.reason.clone(),
    }
}

fn tombstone_manifest(record: &TombstoneRecord) -> TombstoneManifest {
    TombstoneManifest {
        kind: record.kind.as_str().to_owned(),
        id: record.id,
        generation: record.generation,
        died_at: record.died_at,
        reason: record.reason.clone(),
    }
}

fn contract_object_ref_manifest(reference: ContractObjectRef) -> ContractObjectRefManifest {
    ContractObjectRefManifest {
        kind: reference.kind.as_str().to_owned(),
        id: reference.id,
        generation: reference.generation,
    }
}

fn optional_generation_ref(id: Option<u64>, generation: Option<u64>) -> String {
    match (id, generation) {
        (Some(id), Some(generation)) => format!("{id}@{generation}"),
        _ => "none".to_owned(),
    }
}

fn authority_object_ref_manifest(reference: AuthorityObjectRef) -> AuthorityObjectRefManifest {
    match reference {
        AuthorityObjectRef::Internal { class, object } => AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
        AuthorityObjectRef::External { class, object } => AuthorityObjectRefManifest {
            scope: "external".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
    }
}

fn contract_violation_manifest(violation: &ContractViolation) -> ContractViolationManifest {
    ContractViolationManifest {
        kind: violation.kind.as_str().to_owned(),
        edge: violation.edge.clone(),
        from: contract_object_ref_manifest(violation.from),
        to: violation.to.map(contract_object_ref_manifest),
        detail: violation.detail.clone(),
    }
}

fn cleanup_transaction_manifest(
    cleanup: &semantic_core::FaultCleanupTransaction,
) -> CleanupTransactionManifest {
    CleanupTransactionManifest {
        id: cleanup.id,
        store: cleanup.store,
        store_generation: cleanup.store_generation,
        target_store_generation: cleanup.store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation: cleanup.activation_generation,
        code_object: cleanup.code_object,
        code_generation: cleanup.code_generation,
        generation: cleanup.generation,
        started_at: cleanup.started_at,
        finished_at: cleanup.finished_at,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        released_dmw_leases: cleanup.released_dmw_leases,
        cancelled_waits: cleanup.cancelled_waits,
        revoked_capabilities: cleanup.revoked_capabilities.clone(),
        revoked_capability_refs: cleanup
            .revoked_capability_refs
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        dropped_resources: cleanup.dropped_resources,
        unbound_code_object: cleanup.unbound_code_object,
        effect: cleanup.effect.summary(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| CleanupStepManifest {
                step: step.step.as_str().to_owned(),
                state: step.state.as_str().to_owned(),
                detail: step.detail.clone(),
                target: step.target.map(contract_object_ref_manifest),
                observed_generation: step.observed_generation,
                error: step.error.clone(),
                idempotency_key: step.idempotency_key.clone(),
                event_seq: step.event_seq,
            })
            .collect(),
        effects: cleanup
            .effects
            .iter()
            .map(|effect| CleanupEffectManifest {
                kind: effect.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(effect.target),
                expected_generation: effect.expected_generation,
                status: effect.status.as_str().to_owned(),
                event_seq: effect.event_seq,
            })
            .collect(),
    }
}

fn memory_policy_manifest(policy: &MemoryClassPolicy) -> MemoryClassPolicyManifest {
    MemoryClassPolicyManifest {
        class: policy.class.as_str().to_owned(),
        owner_kind: policy.owner_kind.as_str().to_owned(),
        permissions: policy.permissions.summary(),
        migration_policy: policy.migratable.as_str().to_owned(),
        snapshot_policy: policy.snapshot_policy.as_str().to_owned(),
        cleanup_policy: policy.cleanup_policy.as_str().to_owned(),
        can_alias_guest_memory: policy.can_alias_guest_memory,
        can_cross_pending: policy.can_cross_pending,
        can_be_executable: policy.can_be_executable,
    }
}

fn boundary_validation_report_manifest(
    report: &BoundaryValidationReport,
) -> BoundaryValidationReportManifest {
    BoundaryValidationReportManifest {
        validator: report.validator.as_str().to_owned(),
        ok: report.is_ok(),
        violation_count: report.violations.len(),
        violations: report
            .violations
            .iter()
            .map(boundary_validation_violation_manifest)
            .collect(),
    }
}

fn boundary_validation_violation_manifest(
    violation: &BoundaryValidationViolation,
) -> BoundaryValidationViolationManifest {
    BoundaryValidationViolationManifest {
        validator: violation.validator.as_str().to_owned(),
        kind: violation.kind.as_str().to_owned(),
        object: violation.object.clone(),
        detail: violation.detail.clone(),
    }
}

fn validation_roots(report: &BoundaryValidationReportManifest) -> Vec<String> {
    let mut roots = Vec::new();
    roots.push(format!(
        "boundary-validation validator={} ok={} violations={}",
        report.validator, report.ok, report.violation_count
    ));
    roots.extend(report.violations.iter().map(|violation| {
        format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            violation.validator, violation.kind, violation.object, violation.detail
        )
    }));
    roots
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
    if package.semantic.capability_count > semantic.capabilities().records().len() {
        return Err(
            "migration package requires more capabilities than the executor rebound".into(),
        );
    }
    for capability in &package.logical_capabilities {
        if is_semantic_evidence_capability(capability) {
            continue;
        }
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
        "restore plan: import semantic roots harts={} tasks={} resources={} authorities={}/{} waits={} pending_waits={} transactions={} active_transactions={} fastpath={}/{} boundaries={} artifacts={} activations={} executor_transitions={} sockets={} rx_bytes={} event_cursor={}",
        package.semantic.hart_count,
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

fn is_semantic_evidence_capability(capability: &MigrationCapabilityManifest) -> bool {
    SEMANTIC_EVIDENCE_CAPABILITY_SOURCES.contains(&capability.source.as_str())
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
