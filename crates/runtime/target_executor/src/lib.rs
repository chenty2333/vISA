//! Runtime bridge from Semantic Virtual ISA artifacts to contract effects.
//!
//! This crate validates artifact/runtime identity, drives HostcallFrame and
//! TrapMap attribution, records contract-visible vISA effects, and dispatches to
//! substrate traits only after profile, capability, and generation gates pass.
//!
//! It is not a Linux/WASI frontend and not the substrate itself.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};
#[cfg(all(feature = "host-tap", target_os = "linux"))]
use std::{thread, time::Duration};

mod evidence_scenarios;
mod package_projection;
mod runtime;

use artifact_manifest::{
    ActivationCleanupManifest, ActivationCleanupStepManifest, ActivationContextManifest,
    ActivationMigrationManifest, ActivationRecordManifest, ActivationResumeManifest,
    ActivationWaitManifest, ArtifactBundleManifest, AuthorityObjectRefManifest,
    BlockBenchmarkManifest, BlockCompletionObjectManifest, BlockDeviceObjectManifest,
    BlockDmaBufferManifest, BlockDriverCleanupManifest, BlockPageObjectManifest,
    BlockPendingIoPolicyManifest, BlockRangeObjectManifest, BlockReadPathManifest,
    BlockRecoveryBenchmarkManifest, BlockRequestGenerationAuditManifest,
    BlockRequestObjectManifest, BlockRequestQueueEntryManifest, BlockRequestQueueManifest,
    BlockWaitManifest, BlockWritePathManifest, BoundaryValidationReportManifest,
    BoundaryValidationViolationManifest, BufferCacheObjectManifest, CapabilityHandleArgManifest,
    CapabilityRecordManifest, CleanupEffectManifest, CleanupStepManifest,
    CleanupTransactionManifest, CodeObjectManifest, CodeObjectSimdRequirementManifest,
    CommandEffectManifest, CommandResultManifest, ContractObjectRefManifest,
    ContractViolationManifest, CrossHartSchedulerDecisionManifest, DescriptorObjectManifest,
    DeviceCapabilityManifest, DeviceObjectManifest, DirectoryObjectManifest,
    DisplayCapabilityManifest, DisplayCleanupManifest, DisplayCleanupStepManifest,
    DisplayEventLogManifest, DisplayObjectManifest, DisplayPanicLastFrameManifest,
    DisplaySnapshotBarrierManifest, DmaBufferObjectManifest, DriverStoreBindingManifest,
    EndpointObjectManifest, Ext4AdapterObjectManifest, FakeBlockBackendObjectManifest,
    FakeNetBackendObjectManifest, FatAdapterObjectManifest, FileHandleCapabilityManifest,
    FileObjectManifest, FramebufferBenchmarkManifest, FramebufferDirtyRegionManifest,
    FramebufferFlushRegionManifest, FramebufferMappingManifest, FramebufferObjectManifest,
    FramebufferWindowLeaseManifest, FramebufferWriteManifest, FsWaitManifest, GuestStateManifest,
    HartEventAttributionManifest, HartRecordManifest, HostcallSpecManifest, HostcallTraceManifest,
    IntegratedCodePublishSmpWorkloadManifest, IntegratedDiskPreemptFaultManifest,
    IntegratedDisplayPanicManifest, IntegratedDisplaySchedulerLoadManifest,
    IntegratedNetworkDiskIoManifest, IntegratedOsctlTraceReplayManifest,
    IntegratedSimdMigrationManifest, IntegratedSmpNetworkFaultManifest,
    IntegratedSmpPreemptionCleanupManifest, IntegratedSnapshotIoLeaseBarrierManifest,
    InterfaceEventManifest, IoCleanupManifest, IoCleanupStepManifest, IoFaultInjectionManifest,
    IoValidationReportManifest, IoValidationViolationManifest, IoWaitManifest, IpiEventManifest,
    IrqEventManifest, IrqLineObjectManifest, MemoryClassPolicyManifest,
    MigrationCapabilityManifest, MigrationHostManifest, MigrationObjectManifest,
    MigrationPackageManifest, MigrationTargetManifest, MmioRegionObjectManifest,
    NetworkBackpressureManifest, NetworkBenchmarkManifest, NetworkDriverCleanupManifest,
    NetworkFaultInjectionManifest, NetworkGenerationAuditManifest,
    NetworkRecoveryBenchmarkManifest, NetworkRxInterruptManifest, NetworkRxWaitResolutionManifest,
    NetworkStackAdapterManifest, NetworkTxCapabilityGateManifest, NetworkTxCompletionManifest,
    PacketBufferObjectManifest, PacketDescriptorObjectManifest, PacketDeviceObjectManifest,
    PacketQueueObjectManifest, PreemptionLatencySampleManifest, PreemptionManifest,
    QueueObjectManifest, RemoteParkManifest, RemotePreemptManifest,
    RequiredArtifactProfileManifest, RunnableQueueEntryManifest, RunnableQueueManifest,
    RuntimeActivationRecordManifest, SavedContextManifest, SchedulerDecisionManifest,
    SemanticRootSetManifest, SemanticSnapshotManifest, SimdBenchmarkManifest,
    SimdContextSwitchBenchmarkManifest, SimdFaultInjectionManifest, SimdTrapAttributionManifest,
    SmpCleanupQuiescenceManifest, SmpCleanupQuiescenceParticipantManifest,
    SmpCodePublishBarrierManifest, SmpCodePublishBarrierParticipantManifest, SmpSafePointManifest,
    SmpSafePointParticipantManifest, SmpScalingBenchmarkManifest, SmpSnapshotBarrierManifest,
    SmpSnapshotBarrierParticipantManifest, SmpStressRunManifest, SocketObjectManifest,
    SocketOperationManifest, SocketWaitManifest, StopTheWorldRendezvousManifest,
    StopTheWorldRendezvousParticipantManifest, StoreRecordManifest, SubstrateBoundaryManifest,
    SubstrateEventManifest, TargetAddressMapEntryManifest, TargetArtifactImageManifest,
    TargetCapabilitySpecManifest, TargetFeatureSetManifest, TargetMemoryPlanManifest,
    TargetTrapMetadataManifest, TaskRecordManifest, TimerInterruptManifest, TombstoneManifest,
    TrapRecordManifest, VectorStateManifest, VirtioBlkBackendObjectManifest,
    VirtioNetBackendObjectManifest, WaitRecordManifest,
};
use contract_validate::{
    ValidatedArtifactEntry, ValidatedArtifactPlan, audit_migration_package,
    build_validated_artifact_plan, validate_migration_against_manifest, validate_replay_quiescent,
};
use evidence_scenarios::*;
use fs_adapter::{
    Ext4AdapterConfig, FatAdapterConfig, build_ext4_read_only_evidence,
    build_fat_read_write_evidence,
};
use net_stack_adapter::{SmoltcpAdapterConfig, build_smoltcp_adapter_evidence};
#[cfg(all(feature = "host-tap", target_os = "linux"))]
use net_stack_adapter::{SmoltcpPacketStack, pump_stack_driver_backend};
use package_projection::*;
pub use package_projection::{
    RuntimeEvidenceTargetRuntimeManifests, runtime_evidence_substrate_event_manifests,
    runtime_evidence_target_artifact_manifests, runtime_evidence_target_runtime_manifests,
};
use runtime::{HostValidationSmokeTrace, RuntimeOnlyExecutor};
use semantic_core::{
    ActivationContextState, ActivationVectorState, ArtifactVerificationState, AuthorityObjectRef,
    BlockCompletionStatus, BlockPendingIoAction, BlockRequestOperation, BlockRequestQueueEntryRef,
    BoundaryKind, BoundaryStatus, BoundaryValidationReport, BoundaryValidationViolation,
    BufferCacheObjectState, CapabilityClass, CapabilityLedger, CapabilityRecord, CodePublishState,
    CommandEnvelope, CommandResult, CommandStatus, ContractGraphSnapshotInputs, ContractViolation,
    CowState, DescriptorObjectAccess, DirectoryEntryKind, DirectoryObjectState,
    DmaBufferObjectAccess, EntrypointState, EventKind, EventRecord, EvidenceBoundaryLevel,
    Ext4AdapterObjectState, ExternalObjectDeclaration, FatAdapterObjectState, FileObjectState,
    FrontendKind, HartState, HostcallLinkState, IpiEventKind, IrqLinePolarity, IrqLineTrigger,
    MemoryClassPolicy, MemoryLayoutState, MmioRegionObjectAccess, NetworkBackpressureAction,
    NetworkBackpressureReason, NetworkFaultInjectionEffect, NetworkFaultInjectionKind,
    PackageReplayValidator, PacketBufferDirection, PacketBufferObjectState, PacketQueueRole,
    PageBacking, PageObjectState, QueueObjectRole, ReplayPackageValidationState, ResourceKind,
    RestartPolicy, RuntimeActivationState, RuntimeMode, SavedContextReason, SemanticCommand,
    SemanticGraph, SemanticWaitKind, SimdFaultInjectionEffect, SimdFaultInjectionKind,
    SnapshotBarrierValidationState, SnapshotBarrierValidator, StoreRecord, StoreState, TaskState,
    TrapSurfaceState, VectorStateState, WaitCancelReason, memory_class_policies,
    target_executor::{
        ActivationEntry, ArtifactRegistry, CapabilityHandleArg, CodeObject, CodePublisher,
        ContractObjectKind, ContractObjectRef, ExpectedTargetArtifact, HostcallCategory,
        HostcallFrame, HostcallSpec, HostcallTraceRecord, ManagedStoreRecord,
        MigrationObjectRecord, TargetAddressMapEntry, TargetArtifactImage, TargetCapabilitySpec,
        TargetExecutor, TargetMemoryPlan, TargetStoreManager, TargetTrapClass, TargetTrapMetadata,
        TombstoneRecord, VerifiedArtifact,
    },
    validate_contract_graph,
};
#[cfg(all(feature = "host-tap", target_os = "linux"))]
use service_core::driver::DriverVirtioNetState;
use service_core::{
    fake_block::{FAKE_BLOCK_BACKEND_PROFILE, FAKE_BLOCK_BACKEND_PROVIDER, FakeBlockBackendConfig},
    fake_net::{FAKE_NET_BACKEND_PROFILE, FAKE_NET_BACKEND_PROVIDER, FAKE_NET_BACKEND_SEED},
    net_contract::{PACKET_FRAME_FORMAT_VERSION, PACKET_MAX_PAYLOAD_LEN, VIRTIO_NET0_CONTRACT},
};
#[cfg(all(feature = "host-tap", target_os = "linux"))]
use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateResult};
use substrate_api::{SubstrateEvent, SubstrateRequester};
#[cfg(all(feature = "host-tap", target_os = "linux"))]
use substrate_virtio::net::HostTapPacketDeviceBackend;
use substrate_virtio::{
    block::{
        VIRTIO_BLK_BACKEND_MODEL, VIRTIO_BLK_BACKEND_PROFILE, VIRTIO_BLK_BACKEND_PROVIDER,
        VirtioBlkBackendConfig,
    },
    net::{
        VIRTIO_NET_BACKEND_MODEL, VIRTIO_NET_BACKEND_PROFILE, VIRTIO_NET_BACKEND_PROVIDER,
        VirtioNetBackendConfig,
    },
};
use target_abi::{
    OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, PANIC_RECORD_MAX_LEN, PANIC_RING_SIZE,
    PanicRecordKindV1, PanicRingV1, RV64_ENTRY_TRAP_EBREAK_OFFSET, TrapKindV1, TrapMapEntryV1,
};

const DEFAULT_ARTIFACT_ROOT: &str = "target/aotc/wasmtime/host-validation/debug";
const HOST_TAP_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_REMOTE_IPV4_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REMOTE_IPV4";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_REMOTE_PORT_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REMOTE_PORT";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_PUMP_STEPS_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_PUMP_STEPS";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_PUMP_SLEEP_MS_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_PUMP_SLEEP_MS";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_REQUIRE_ESTABLISHED_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REQUIRE_ESTABLISHED";
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_DEFAULT_REMOTE_IPV4: [u8; 4] = [10, 0, 2, 2];
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_DEFAULT_REMOTE_PORT: u16 = 80;
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_DEFAULT_PUMP_STEPS: u32 = 16;
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_MAX_PUMP_STEPS: u32 = 1024;
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_DEFAULT_PUMP_SLEEP_MS: u64 = 10;
#[cfg(all(feature = "host-tap", target_os = "linux"))]
const HOST_TAP_MAX_PUMP_SLEEP_MS: u64 = 1000;
const SEMANTIC_EVIDENCE_CAPABILITY_SOURCES: &[&str] = &[
    "i7-device-capability",
    "n17-dma-generation-capability",
    "b6-virtio-blk-device-capability",
    "target-executor-b17",
    "display-runtime-g2",
];

#[derive(Clone, Debug, Default)]
pub(crate) struct TargetExecutorV1Report {
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

pub fn run() -> Result<(), Box<dyn Error>> {
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
                    &entry.hash_status,
                    &entry.abi_fingerprint,
                    &entry.signature_scheme,
                    &entry.signature_status,
                    entry.signature_verified,
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
    record_network_runtime_n21_evidence(&mut semantic)?;
    record_network_runtime_n10_evidence(&mut semantic)?;
    record_network_runtime_n11_evidence(&mut semantic)?;
    record_network_runtime_n12_evidence(&mut semantic)?;
    record_network_runtime_n13_evidence(&mut semantic)?;
    record_network_runtime_n14_evidence(&mut semantic)?;
    record_linux_wait_service_d1_evidence(&mut semantic)?;
    record_network_runtime_n15_evidence(&mut semantic)?;
    record_network_runtime_n22_evidence(&mut semantic)?;
    record_network_runtime_n23_evidence(&mut semantic)?;
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
    record_block_runtime_b19_evidence(&mut semantic)?;
    record_block_runtime_b20_evidence(&mut semantic)?;
    record_block_runtime_b21_evidence(&mut semantic)?;
    record_block_runtime_b22_evidence(&mut semantic)?;
    record_block_runtime_b23_evidence(&mut semantic)?;
    record_simd_runtime_v0_evidence(&mut semantic)?;
    record_substrate_conformance_evidence(&mut semantic);
    record_page_table_backend_evidence(&mut semantic)?;
    record_command_surface_evidence(&mut semantic);
    record_interface_boundary_evidence(&mut semantic);
    maybe_run_host_tap_runtime_probe(&mut semantic)?;
    let target_v1 = build_target_executor_v1(&plan, &mut semantic, &stores)?;

    println!(
        "target executor loaded {} runtime-only stores with {} capability grants across {} fault domains in {} mode",
        stores.len(),
        semantic.capability_count(),
        semantic.fault_domain_count(),
        semantic.runtime_mode().as_str()
    );
    println!("semantic store graph contains {} stores", semantic.store_count());
    println!("semantic event log contains {} events", semantic.event_count());
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
    validate_external_audit(&migration)?;
    restore_migration_package(&migration, &semantic, &plan)?;

    Ok(())
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn maybe_run_host_tap_runtime_probe(semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    let Some(tap_name) = env::var_os(HOST_TAP_ENV) else {
        return Ok(());
    };
    let tap_name =
        tap_name.into_string().map_err(|_| format!("{HOST_TAP_ENV} must be valid UTF-8"))?;

    let mut stack = SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos())
        .map_err(|error| format!("host TAP smoltcp stack init failed: {error}"))?;
    let mut driver = DriverVirtioNetState::new();
    let mut backend = CountingHostTapBackend::open(&tap_name)?;
    stack
        .init_backend(&mut backend)
        .map_err(|error| format!("host TAP backend init failed: {error:?}"))?;

    let socket_id = stack
        .create_tcp_socket()
        .map_err(|error| format!("host TAP probe tcp socket creation failed: {error}"))?;
    stack
        .connect_tcp_ipv4(socket_id, host_tap_remote_ipv4()?, host_tap_remote_port()?)
        .map_err(|error| format!("host TAP probe tcp connect setup failed: {error}"))?;

    let pump_steps = host_tap_pump_steps()?;
    let pump_sleep_ms = host_tap_pump_sleep_ms()?;
    let require_established = host_tap_require_established()?;
    let mut totals = HostTapPumpTotals::default();
    let mut final_state = "unknown";
    let mut final_can_send = false;
    let mut completed_steps = 0u32;
    for step in 0..pump_steps {
        completed_steps = step.saturating_add(1);
        let tick = u64::from(step).saturating_add(1);
        let pump =
            pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, tick as i64, tick)
                .map_err(|error| format!("host TAP stack/driver/backend pump failed: {error:?}"))?;
        totals.add(&pump);
        let snapshot = stack
            .tcp_snapshot(socket_id)
            .map_err(|error| format!("host TAP tcp snapshot failed: {error}"))?;
        final_state = snapshot.state;
        final_can_send = snapshot.can_send;
        if require_established && final_state == "established" {
            break;
        }
        if pump_sleep_ms != 0 && completed_steps < pump_steps {
            thread::sleep(Duration::from_millis(pump_sleep_ms));
        }
    }
    if backend.tx_frames == 0 {
        return Err("host TAP probe produced no backend TX frame".into());
    }
    if require_established && final_state != "established" {
        return Err(
            format!("host TAP probe did not establish TCP socket: state={final_state}").into()
        );
    }

    let interface = semantic.register_resource(
        ResourceKind::NetInterface,
        None,
        &format!("host-tap:{tap_name}"),
    );
    semantic.record_net_interface_state_changed(interface, true);
    for len in backend.tx_lengths.iter().copied() {
        semantic.record_packet_transmitted(interface, None, 0, len);
    }
    println!(
        "host TAP runtime probe tap={} pump_steps={} completed_steps={} pump_sleep_ms={} require_established={} final_state={} final_can_send={} tx_frames={} tx_bytes={} rx_frames={} pump_backend_rx={} pump_driver_rx={} pump_stack_tx={} pump_driver_tx={}",
        tap_name,
        pump_steps,
        completed_steps,
        pump_sleep_ms,
        require_established,
        final_state,
        final_can_send,
        backend.tx_frames,
        backend.tx_bytes,
        backend.rx_frames,
        totals.backend_rx_frames_delivered_to_driver,
        totals.driver_rx_frames_delivered_to_stack,
        totals.stack_tx_frames_submitted_to_driver,
        totals.driver_tx_frames_submitted_to_backend
    );
    Ok(())
}

#[cfg(not(all(feature = "host-tap", target_os = "linux")))]
fn maybe_run_host_tap_runtime_probe(_semantic: &mut SemanticGraph) -> Result<(), Box<dyn Error>> {
    if env::var_os(HOST_TAP_ENV).is_some() {
        return Err(format!(
            "{HOST_TAP_ENV} requires target_executor built with --features host-tap on Linux"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
struct CountingHostTapBackend {
    inner: HostTapPacketDeviceBackend,
    tx_frames: usize,
    tx_bytes: usize,
    tx_lengths: Vec<usize>,
    rx_frames: usize,
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
impl CountingHostTapBackend {
    fn open(name: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            inner: HostTapPacketDeviceBackend::open(name)
                .map_err(|error| format!("host TAP open failed: {error:?}"))?,
            tx_frames: 0,
            tx_bytes: 0,
            tx_lengths: Vec::new(),
            rx_frames: 0,
        })
    }
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
impl PacketDeviceBackend for CountingHostTapBackend {
    fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
        self.inner.init(mac)
    }

    fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
        self.inner.submit_tx(frame)?;
        self.tx_frames += 1;
        self.tx_bytes = self.tx_bytes.saturating_add(frame.len());
        self.tx_lengths.push(frame.len());
        Ok(())
    }

    fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
        let count = self.inner.poll_rx(out)?;
        self.rx_frames = self.rx_frames.saturating_add(count);
        Ok(count)
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
#[derive(Default)]
struct HostTapPumpTotals {
    backend_rx_frames_delivered_to_driver: usize,
    driver_rx_frames_delivered_to_stack: usize,
    stack_tx_frames_submitted_to_driver: usize,
    driver_tx_frames_submitted_to_backend: usize,
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
impl HostTapPumpTotals {
    fn add(&mut self, pump: &net_stack_adapter::StackDriverBackendPumpEvidence) {
        self.backend_rx_frames_delivered_to_driver = self
            .backend_rx_frames_delivered_to_driver
            .saturating_add(pump.backend_rx_frames_delivered_to_driver);
        self.driver_rx_frames_delivered_to_stack = self
            .driver_rx_frames_delivered_to_stack
            .saturating_add(pump.driver_rx_frames_delivered_to_stack);
        self.stack_tx_frames_submitted_to_driver = self
            .stack_tx_frames_submitted_to_driver
            .saturating_add(pump.stack_tx_frames_submitted_to_driver);
        self.driver_tx_frames_submitted_to_backend = self
            .driver_tx_frames_submitted_to_backend
            .saturating_add(pump.driver_tx_frames_submitted_to_backend);
    }
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn host_tap_remote_ipv4() -> Result<[u8; 4], Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REMOTE_IPV4_ENV) else {
        return Ok(HOST_TAP_DEFAULT_REMOTE_IPV4);
    };
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for (index, part) in raw.split('.').enumerate() {
        if index >= out.len() {
            return Err(format!("{HOST_TAP_REMOTE_IPV4_ENV} has too many octets").into());
        }
        out[index] = part
            .parse::<u8>()
            .map_err(|_| format!("{HOST_TAP_REMOTE_IPV4_ENV} contains invalid octet"))?;
        count += 1;
    }
    if count != out.len() {
        return Err(format!("{HOST_TAP_REMOTE_IPV4_ENV} must contain four octets").into());
    }
    Ok(out)
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn host_tap_remote_port() -> Result<u16, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REMOTE_PORT_ENV) else {
        return Ok(HOST_TAP_DEFAULT_REMOTE_PORT);
    };
    let port = raw
        .parse::<u16>()
        .map_err(|_| format!("{HOST_TAP_REMOTE_PORT_ENV} must be a u16 TCP port"))?;
    if port == 0 {
        return Err(format!("{HOST_TAP_REMOTE_PORT_ENV} must be nonzero").into());
    }
    Ok(port)
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn host_tap_pump_steps() -> Result<u32, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_PUMP_STEPS_ENV) else {
        return Ok(HOST_TAP_DEFAULT_PUMP_STEPS);
    };
    let steps =
        raw.parse::<u32>().map_err(|_| format!("{HOST_TAP_PUMP_STEPS_ENV} must be a u32"))?;
    if steps == 0 || steps > HOST_TAP_MAX_PUMP_STEPS {
        return Err(
            format!("{HOST_TAP_PUMP_STEPS_ENV} must be in 1..={HOST_TAP_MAX_PUMP_STEPS}").into()
        );
    }
    Ok(steps)
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn host_tap_pump_sleep_ms() -> Result<u64, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_PUMP_SLEEP_MS_ENV) else {
        return Ok(HOST_TAP_DEFAULT_PUMP_SLEEP_MS);
    };
    let sleep_ms =
        raw.parse::<u64>().map_err(|_| format!("{HOST_TAP_PUMP_SLEEP_MS_ENV} must be a u64"))?;
    if sleep_ms > HOST_TAP_MAX_PUMP_SLEEP_MS {
        return Err(format!(
            "{HOST_TAP_PUMP_SLEEP_MS_ENV} must be <= {HOST_TAP_MAX_PUMP_SLEEP_MS}"
        )
        .into());
    }
    Ok(sleep_ms)
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
fn host_tap_require_established() -> Result<bool, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REQUIRE_ESTABLISHED_ENV) else {
        return Ok(false);
    };
    match raw.as_str() {
        "0" | "false" | "FALSE" | "False" => Ok(false),
        "1" | "true" | "TRUE" | "True" => Ok(true),
        _ => Err(format!("{HOST_TAP_REQUIRE_ESTABLISHED_ENV} must be boolean").into()),
    }
}

fn validate_external_audit(package: &MigrationPackageManifest) -> Result<(), Box<dyn Error>> {
    let report = audit_migration_package(package);
    println!(
        "external audit package={} ok={} portable_artifact_execution={} visa_native_portable_artifact_execution={} real_target_substrate={} visa_native_artifacts={} findings={}",
        report.package_id,
        report.ok(),
        report.portable_artifact_execution_claim,
        report.visa_native_portable_artifact_execution_claim,
        report.real_target_substrate_claim,
        report.visa_native_artifact_count,
        report.findings.len()
    );
    if !report.ok() {
        Err(format!("external audit failed: {}", external_audit_error_summary(&report)).into())
    } else if !report.visa_native_portable_artifact_execution_claim {
        Err("external audit failed: missing-visa-native-portable-artifact-execution".into())
    } else {
        Ok(())
    }
}

fn external_audit_error_summary(
    report: &contract_validate::ExternalMigrationAuditReport,
) -> String {
    let errors = report.errors().map(|finding| finding.code).collect::<Vec<_>>();
    if errors.is_empty() { "unknown-error".to_owned() } else { errors.join(",") }
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
        &entry.hash_status,
        &entry.abi_fingerprint,
        &entry.signature_scheme,
        &entry.signature_status,
        entry.signature_verified,
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
        let rights = capability.rights.iter().map(String::as_str).collect::<Vec<_>>();
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
        EvidenceBoundaryLevel::SemanticModel,
        &manifest.artifact_profile,
        None,
    );
    semantic.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::HostSide,
        EvidenceBoundaryLevel::ReferenceService,
        &manifest.compiler.runtime_executor_abi,
        Some("bare-metal-cwasm-loader"),
    );
    semantic.publish_boundary(
        "hostcall-table",
        BoundaryKind::HostcallTable,
        BoundaryStatus::HostSide,
        EvidenceBoundaryLevel::ReferenceService,
        &manifest.compiler.runtime_executor_abi,
        Some("target-hostcall-trampoline"),
    );
    semantic.publish_boundary(
        "target-executor",
        BoundaryKind::TargetExecutor,
        BoundaryStatus::HostSide,
        EvidenceBoundaryLevel::ReferenceService,
        "wasmtime-host-validator",
        Some("target-runtime-only-executor"),
    );
    semantic.publish_boundary(
        "store-lifecycle",
        BoundaryKind::StoreLifecycle,
        BoundaryStatus::LifecycleObject,
        EvidenceBoundaryLevel::SemanticModel,
        "target_executor-host-validation",
        Some("target-store-memory-stack-code-object"),
    );
    semantic.publish_boundary(
        "snapshot-replay",
        BoundaryKind::SnapshotReplay,
        BoundaryStatus::PackageOnly,
        EvidenceBoundaryLevel::SemanticModel,
        "semantic-package-v1",
        Some("target-replay-runner"),
    );
}

fn build_target_executor_v1(
    plan: &ValidatedArtifactPlan,
    semantic: &mut SemanticGraph,
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
        let mut image = target_artifact_image((index + 1) as u64, entry, plan);
        let runtime_store = runtime_stores.iter().find(|store| store.package == entry.package);
        if let Some(runtime_store) = runtime_store {
            append_cwasm_smoke_hostcall_specs(
                &mut image.hostcalls,
                index,
                &entry.package,
                &runtime_store.smoke_trace,
            );
        }
        report.target_artifacts.push(target_artifact_manifest(&image));
        let verified = registry.verify(image).map_err(|error| error.message())?;
        verified_artifacts.push(verified.clone());
        let store_id = semantic_store_id(semantic, &entry.package)?;
        let store_id = store_manager.register_verified_artifact_with_id(
            store_id,
            &verified,
            &entry.fault_policy,
            "rebuild-from-verified-artifact",
        );
        store_manager.set_running(store_id).map_err(|error| error.message())?;

        let code_id = publisher.allocate(&verified).map_err(|error| error.message())?;
        publisher.fill(code_id).map_err(|error| error.message())?;
        publisher.seal(code_id).map_err(|error| error.message())?;
        publisher.publish_rx(code_id).map_err(|error| error.message())?;
        let store =
            store_manager.record(store_id).ok_or("store manager lost store after register")?;
        grant_verified_capabilities(&mut ledger, &verified, store_id, store.store.generation)?;
        publisher.bind_to_store(code_id, &store.store).map_err(|error| error.message())?;
        let code =
            publisher.object(code_id).ok_or("publisher lost code object after bind")?.clone();

        run_activation_harness(index, &mut executor, store, &code, &ledger)?;
        if let Some(runtime_store) = runtime_store {
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
        store_manager.set_running(cleanup_store_id).map_err(|error| error.message())?;
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
        let cleanup_code_id =
            publisher.allocate(cleanup_artifact).map_err(|error| error.message())?;
        publisher.fill(cleanup_code_id).map_err(|error| error.message())?;
        publisher.seal(cleanup_code_id).map_err(|error| error.message())?;
        publisher.publish_rx(cleanup_code_id).map_err(|error| error.message())?;
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
            let cleanup_code =
                publisher.object_mut(cleanup_code_id).map_err(|error| error.message())?;
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
    run_simd_trap_classification_harness(
        &verified_artifacts,
        semantic,
        &mut publisher,
        &mut store_manager,
        &mut executor,
    )?;
    run_simd_vector_state_harness(semantic, &publisher, &executor)?;
    run_simd_activation_context_vector_harness(semantic)?;
    run_simd_lazy_vector_enable_harness(
        &verified_artifacts,
        semantic,
        &mut publisher,
        &mut store_manager,
        &mut executor,
    )?;
    run_simd_preempt_vector_save_harness(
        &verified_artifacts,
        semantic,
        &mut publisher,
        &mut store_manager,
        &mut executor,
        &mut ledger,
    )?;
    run_simd_resume_vector_restore_harness(
        semantic,
        &publisher,
        &store_manager,
        &mut executor,
        &mut ledger,
    )?;
    run_simd_cross_hart_vector_migration_harness(
        &verified_artifacts,
        semantic,
        &mut publisher,
        &mut store_manager,
        &mut executor,
        &mut ledger,
    )?;
    run_simd_fault_injection_harness(
        &verified_artifacts,
        semantic,
        &mut publisher,
        &mut store_manager,
        &mut executor,
    )?;
    run_simd_benchmark_harness(&verified_artifacts, semantic, &mut publisher, &mut store_manager)?;
    run_simd_context_switch_benchmark_harness(semantic)?;
    run_framebuffer_object_harness(semantic)?;
    run_display_object_harness(semantic)?;
    run_display_capability_harness(semantic)?;
    run_framebuffer_window_lease_harness(semantic)?;
    run_framebuffer_mapping_harness(semantic)?;
    run_framebuffer_write_harness(semantic)?;
    run_framebuffer_flush_region_harness(semantic)?;
    run_framebuffer_dirty_region_harness(semantic)?;
    run_display_event_log_harness(semantic)?;
    run_display_cleanup_harness(semantic)?;
    run_display_snapshot_barrier_harness(semantic)?;
    run_display_panic_last_frame_harness(semantic)?;
    run_framebuffer_benchmark_harness(semantic)?;
    run_integrated_smp_preemption_cleanup_harness(semantic)?;
    run_integrated_smp_network_fault_harness(semantic)?;
    run_integrated_disk_preempt_fault_harness(semantic)?;
    run_integrated_simd_migration_harness(semantic)?;
    run_integrated_network_disk_io_harness(semantic)?;
    run_integrated_display_scheduler_load_harness(semantic)?;
    run_integrated_snapshot_io_lease_barrier_harness(semantic)?;
    run_integrated_code_publish_smp_workload_harness(semantic)?;
    run_integrated_display_panic_harness(semantic)?;
    run_integrated_osctl_trace_replay_harness(semantic)?;

    let snapshot_validation = portable_artifact_validation_report(
        SnapshotBarrierValidator::validate(&executor.snapshot_barrier_validation_state()),
    );
    report.snapshot_validation = boundary_validation_report_manifest(&snapshot_validation);
    executor.snapshot_barrier().map_err(|error| error.message())?;
    let replay_record_modes =
        executor.hostcall_trace().iter().map(|trace| trace.record_mode).collect::<Vec<_>>();
    let replay_state = ReplayPackageValidationState::clean(replay_record_modes);
    let replay_validation =
        portable_artifact_validation_report(PackageReplayValidator::validate(&replay_state));
    report.replay_validation = boundary_validation_report_manifest(&replay_validation);
    for policy in memory_class_policies() {
        report.memory_policies.push(memory_policy_manifest(policy));
    }
    for code in publisher.objects() {
        report.code_objects.push(code_object_manifest(code));
    }
    for store in store_manager.records() {
        report.store_records.push(store_record_manifest(&store.store));
    }
    for capability in ledger.records() {
        report.capability_records.push(capability_record_manifest(capability));
    }
    let semantic_cleanup_tombstones = semantic_cleanup_tombstones(semantic);
    append_display_capability_contract_evidence(
        semantic,
        &mut report.store_records,
        &mut report.capability_records,
    );
    for activation in executor.activations() {
        report.activation_records.push(activation_record_manifest(activation));
    }
    for trap in executor.traps() {
        report.trap_records.push(trap_record_manifest(trap));
    }
    for trace in executor.hostcall_trace() {
        report.hostcall_trace.push(hostcall_trace_manifest(trace));
    }
    for object in executor.classify_migration_objects(publisher.objects()) {
        report.migration_objects.push(migration_object_manifest(&object));
    }
    for cleanup in executor.cleanup_transactions() {
        report.cleanup_transactions.push(cleanup_transaction_manifest(cleanup));
    }
    for tombstone in publisher
        .tombstones()
        .iter()
        .chain(store_manager.tombstones().iter())
        .chain(executor.tombstones().iter())
        .chain(semantic_cleanup_tombstones.iter())
    {
        report.tombstones.push(tombstone_manifest(tombstone));
    }
    let external_objects = declared_authority_objects(ledger.records());
    let contract_stores = contract_graph_store_records(semantic, &store_manager);
    let contract_capabilities = contract_graph_capability_records(semantic, &ledger);
    let merged_tombstones: Vec<TombstoneRecord> = publisher
        .tombstones()
        .iter()
        .chain(store_manager.tombstones().iter())
        .chain(executor.tombstones().iter())
        .chain(semantic_cleanup_tombstones.iter())
        .cloned()
        .collect();
    let snapshot_inputs = ContractGraphSnapshotInputs {
        claimed_evidence_level: EvidenceBoundaryLevel::ReferenceService,
        artifacts: &verified_artifacts,
        code_objects: publisher.objects(),
        activations: executor.activations(),
        traps: executor.traps(),
        hostcalls: executor.hostcall_trace(),
        capabilities: &contract_capabilities,
        cleanup_transactions: executor.cleanup_transactions(),
        tombstones: &merged_tombstones,
        external_objects: &external_objects,
        explicit_edges: &[],
    };
    let mut contract_snapshot = semantic.snapshot_with(snapshot_inputs);
    contract_snapshot.stores = contract_stores;
    contract_snapshot.capabilities = contract_capabilities;
    contract_snapshot.tombstones = merged_tombstones;
    contract_snapshot.external_objects = external_objects;
    report.contract_violations = validate_contract_graph(&contract_snapshot)
        .iter()
        .map(contract_violation_manifest)
        .collect();
    report.target_event_tail = executor.event_log().to_vec();
    report.substrate_events = substrate_event_manifests(semantic.event_log().tail(usize::MAX));
    report.command_results =
        semantic.command_results().iter().map(command_result_manifest).collect();
    report.interface_events = interface_event_manifests(semantic.event_log().tail(usize::MAX));
    Ok(report)
}

fn portable_artifact_validation_report(
    report: BoundaryValidationReport,
) -> BoundaryValidationReport {
    BoundaryValidationReport::with_evidence_boundary(
        report.validator,
        EvidenceBoundaryLevel::PortableArtifactExecution,
        report.violations,
    )
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
    image.hash_status = entry.hash_status.clone();
    image.signature_scheme = entry.signature_scheme.clone();
    image.signature_status = entry.signature_status.clone();
    image.signature_verified = entry.signature_verified;
    image.signer = entry.signer.clone();
    image.exports = entry.expected_exports.clone();
    if !image.exports.iter().any(|export| export == "vmos_service_entry") {
        image.exports.push("vmos_service_entry".to_owned());
    }
    image.payload_len = entry.cwasm_sha256.len();
    image.address_map.push(TargetAddressMapEntry::new("vmos_service_entry", 0, 64));
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
            .with_policy_status(
                &entry.hash_status,
                &entry.signature_scheme,
                &entry.signature_status,
                entry.signature_verified,
                &entry.signer,
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
        let operations = capability.operations.iter().map(String::as_str).collect::<Vec<_>>();
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
    let index =
        capability.operations.as_slice().iter().position(|right| right == &spec.operation)?;
    Some(CapabilityHandleArg::from_record(capability, 1u64 << index, &[spec.operation.as_str()]))
}

fn semantic_store_id(semantic: &SemanticGraph, package: &str) -> Result<u64, Box<dyn Error>> {
    semantic
        .stores()
        .iter()
        .find(|store| store.package == package)
        .map(|store| store.id)
        .ok_or_else(|| format!("semantic graph missing store {package}").into())
}

fn semantic_capability_ref(
    semantic: &SemanticGraph,
    subject: &str,
    object: &str,
    operation: &str,
) -> Result<ContractObjectRef, Box<dyn Error>> {
    semantic
        .capabilities()
        .records()
        .iter()
        .find(|record| {
            record.subject == subject
                && record.object == object
                && !record.revoked
                && record.operations.as_slice().iter().any(|right| right == operation)
        })
        .map(|record| {
            ContractObjectRef::new(ContractObjectKind::Capability, record.id, record.generation)
        })
        .ok_or_else(|| {
            format!("semantic graph missing capability {subject}:{object}:{operation}").into()
        })
}

fn semantic_store_resource_ref(
    semantic: &SemanticGraph,
    store: u64,
) -> Result<ContractObjectRef, Box<dyn Error>> {
    let resource = semantic
        .store_resource(store)
        .ok_or_else(|| format!("semantic graph missing resource for store {store}"))?;
    let generation = semantic
        .resource_handle(resource)
        .map(|handle| handle.generation)
        .ok_or_else(|| format!("semantic graph missing resource handle for store {store}"))?;
    Ok(ContractObjectRef::new(ContractObjectKind::Resource, resource, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_package_projects_visa_native_portable_execution_evidence() {
        let manifest = test_manifest();
        let entry = test_visa_native_entry();
        let plan = ValidatedArtifactPlan {
            artifact_profile: "host-validation".to_owned(),
            runtime_mode: "research".to_owned(),
            contract_version: "test-contract".to_owned(),
            supervisor_world: "test-world".to_owned(),
            target_arch: "x86_64".to_owned(),
            compiler_engine: manifest.compiler.engine.clone(),
            compiler_execution_mode: manifest.compiler.execution_mode.clone(),
            artifact_format: manifest.compiler.artifact_format.clone(),
            target_artifact_format: manifest.compiler.target_artifact_format.clone(),
            runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
            modules: vec![entry.clone()],
        };
        let image = target_artifact_image(1, &entry, &plan);
        let artifact = target_artifact_manifest(&image);
        let hostcall = artifact.hostcalls.first().expect("visa native hostcall").clone();
        let report = TargetExecutorV1Report {
            target_artifacts: vec![artifact.clone()],
            code_objects: vec![CodeObjectManifest {
                id: 1,
                artifact_id: artifact.id,
                package: artifact.package.clone(),
                owner_profile: artifact.target_profile.clone(),
                generation: 1,
                state: "bound-to-store".to_owned(),
                bound_store: Some(1),
                bound_store_generation: Some(1),
                text_permission: "rx".to_owned(),
                rodata_permission: "ro".to_owned(),
                code_hash: artifact.code_hash.clone(),
                hostcalls: artifact.hostcalls.clone(),
                trap_metadata: artifact.trap_metadata.clone(),
                address_map: artifact.address_map.clone(),
                ..Default::default()
            }],
            activation_records: vec![ActivationRecordManifest {
                id: 1,
                store: 1,
                store_generation: 1,
                code_object: 1,
                code_generation: 1,
                artifact: artifact.id,
                entry: "run".to_owned(),
                generation: 1,
                state: "exited".to_owned(),
                ..Default::default()
            }],
            hostcall_trace: vec![HostcallTraceManifest {
                id: 1,
                generation: 1,
                activation: 1,
                activation_generation: 1,
                store: 1,
                store_generation: 1,
                code_object: 1,
                code_generation: 1,
                artifact: artifact.id,
                artifact_generation: 1,
                hostcall_number: hostcall.number,
                name: hostcall.name,
                category: hostcall.category,
                subject: entry.package.clone(),
                subject_source: "artifact".to_owned(),
                object: hostcall.object,
                operation: hostcall.operation,
                record_mode: "live".to_owned(),
                allowed: true,
                gate_status: "allowed".to_owned(),
                result: "ok".to_owned(),
                ret_tag: "ok".to_owned(),
                ..Default::default()
            }],
            snapshot_validation: test_boundary_validation_report("snapshot-barrier"),
            replay_validation: test_boundary_validation_report("package-replay"),
            ..Default::default()
        };
        let semantic = SemanticGraph::new();
        let package = demo_migration_package(&manifest, &semantic, &report);
        let audit = contract_validate::audit_migration_package(&package);

        assert!(audit.ok(), "{:#?}", audit.findings);
        assert!(audit.contract_package_valid);
        assert!(audit.replay_quiescent);
        assert!(audit.portable_artifact_execution_claim);
        assert!(audit.visa_native_portable_artifact_execution_claim);
        assert_eq!(audit.visa_native_artifact_count, 1);
        assert_eq!(audit.linux_weighted_artifact_count, 0);
        validate_external_audit(&package).expect("generated package should pass audit gate");
    }

    #[test]
    fn external_audit_gate_rejects_generic_portable_execution_without_native_chain() {
        let manifest = test_manifest();
        let mut entry = test_visa_native_entry();
        entry.package = "frontend_app".to_owned();
        entry.artifact_name = "frontend_app".to_owned();
        entry.role = "frontend-personality".to_owned();
        entry.capabilities[0].name = "wasi.console".to_owned();
        let plan = ValidatedArtifactPlan {
            artifact_profile: "host-validation".to_owned(),
            runtime_mode: "research".to_owned(),
            contract_version: "test-contract".to_owned(),
            supervisor_world: "test-world".to_owned(),
            target_arch: "x86_64".to_owned(),
            compiler_engine: manifest.compiler.engine.clone(),
            compiler_execution_mode: manifest.compiler.execution_mode.clone(),
            artifact_format: manifest.compiler.artifact_format.clone(),
            target_artifact_format: manifest.compiler.target_artifact_format.clone(),
            runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
            modules: vec![entry.clone()],
        };
        let image = target_artifact_image(1, &entry, &plan);
        let artifact = target_artifact_manifest(&image);
        let hostcall = artifact.hostcalls.first().expect("generic hostcall").clone();
        let report = TargetExecutorV1Report {
            target_artifacts: vec![artifact.clone()],
            code_objects: vec![CodeObjectManifest {
                id: 1,
                artifact_id: artifact.id,
                package: artifact.package.clone(),
                owner_profile: artifact.target_profile.clone(),
                generation: 1,
                state: "bound-to-store".to_owned(),
                bound_store: Some(1),
                bound_store_generation: Some(1),
                text_permission: "rx".to_owned(),
                rodata_permission: "ro".to_owned(),
                code_hash: artifact.code_hash.clone(),
                hostcalls: artifact.hostcalls.clone(),
                trap_metadata: artifact.trap_metadata.clone(),
                address_map: artifact.address_map.clone(),
                ..Default::default()
            }],
            activation_records: vec![ActivationRecordManifest {
                id: 1,
                store: 1,
                store_generation: 1,
                code_object: 1,
                code_generation: 1,
                artifact: artifact.id,
                entry: "run".to_owned(),
                generation: 1,
                state: "exited".to_owned(),
                ..Default::default()
            }],
            hostcall_trace: vec![HostcallTraceManifest {
                id: 1,
                generation: 1,
                activation: 1,
                activation_generation: 1,
                store: 1,
                store_generation: 1,
                code_object: 1,
                code_generation: 1,
                artifact: artifact.id,
                artifact_generation: 1,
                hostcall_number: hostcall.number,
                name: hostcall.name,
                category: hostcall.category,
                subject: entry.package.clone(),
                subject_source: "artifact".to_owned(),
                object: hostcall.object,
                operation: hostcall.operation,
                record_mode: "live".to_owned(),
                allowed: true,
                gate_status: "allowed".to_owned(),
                result: "ok".to_owned(),
                ret_tag: "ok".to_owned(),
                ..Default::default()
            }],
            snapshot_validation: test_boundary_validation_report("snapshot-barrier"),
            replay_validation: test_boundary_validation_report("package-replay"),
            ..Default::default()
        };
        let semantic = SemanticGraph::new();
        let package = demo_migration_package(&manifest, &semantic, &report);
        let audit = contract_validate::audit_migration_package(&package);

        assert!(audit.ok(), "{:#?}", audit.findings);
        assert!(audit.portable_artifact_execution_claim);
        assert!(!audit.visa_native_portable_artifact_execution_claim);

        let error =
            validate_external_audit(&package).expect_err("target executor gate should fail");
        assert!(error.to_string().contains("missing-visa-native-portable-artifact-execution"));
    }

    #[test]
    fn external_audit_gate_rejects_structurally_invalid_package() {
        let manifest = test_manifest();
        let semantic = SemanticGraph::new();
        let package =
            demo_migration_package(&manifest, &semantic, &TargetExecutorV1Report::default());

        let error = validate_external_audit(&package).expect_err("audit gate should fail");
        let message = error.to_string();

        assert!(message.contains("external audit failed"));
        assert!(message.contains("contract-package-invalid"));
    }

    fn test_visa_native_entry() -> ValidatedArtifactEntry {
        ValidatedArtifactEntry {
            package: "wasm_app".to_owned(),
            artifact_name: "wasm_app_frontend".to_owned(),
            role: "visa-native-workload".to_owned(),
            fault_policy: "kill-on-trap".to_owned(),
            wasm_path: "target/test/wasm_app.wasm".to_owned(),
            cwasm_path: "target/test/wasm_app.cwasm".to_owned(),
            target_artifact_path: "target/test/wasm_app.tart".to_owned(),
            wasm_sha256: "wasm-app-wasm".to_owned(),
            cwasm_sha256: "wasm-app-cwasm".to_owned(),
            target_artifact_sha256: "wasm-app-target-artifact".to_owned(),
            code_payload_format: "cwasm".to_owned(),
            expected_exports: vec!["memory".to_owned(), "run".to_owned()],
            capabilities: vec![artifact_manifest::CapabilityManifest {
                name: "visa.console".to_owned(),
                rights: vec!["write".to_owned()],
                lifetime: "activation".to_owned(),
            }],
            abi_fingerprint: "wasm-app-abi".to_owned(),
            service_dependencies: vec!["console_service".to_owned()],
            resource_limits: artifact_manifest::ResourceLimitsManifest {
                max_memory_pages: 16,
                max_table_elements: 0,
                max_hostcalls_per_activation: 16,
            },
            interfaces: artifact_manifest::InterfaceRequirementManifest::default(),
            signature_scheme: "profile-bound-unverified".to_owned(),
            signer: "test-signer".to_owned(),
            manifest_binding_hash: "wasm-app-binding".to_owned(),
            hash_status: "manifest-bound".to_owned(),
            signature_status: "profile-bound-unverified".to_owned(),
            signature_verified: false,
        }
    }

    fn test_manifest() -> ArtifactBundleManifest {
        ArtifactBundleManifest {
            schema_version: 1,
            artifact_profile: "host-validation".to_owned(),
            runtime_mode: "research".to_owned(),
            contract: artifact_manifest::SupervisorContractManifest::default(),
            target: artifact_manifest::TargetManifest {
                arch: "x86_64".to_owned(),
                machine_abi_version: "test-machine-abi".to_owned(),
                supervisor_abi_version: "test-supervisor-abi".to_owned(),
                wasm_feature_profile: "test-wasm-profile".to_owned(),
                memory64: false,
                multi_memory: false,
                dmw_layout: "logical".to_owned(),
                linux_abi_profile: "none".to_owned(),
                artifact_signature_profile: "profile-bound-unverified".to_owned(),
                network_contract_version: "test-network".to_owned(),
            },
            compiler: artifact_manifest::CompilerManifest {
                engine: "wasmtime".to_owned(),
                engine_version: "test".to_owned(),
                execution_mode: "precompiled-core-module".to_owned(),
                artifact_format: "target-artifact-image-v1".to_owned(),
                target_artifact_format: "target-artifact-image-v1".to_owned(),
                runtime_executor_abi: "vmos-runtime-only-executor-v0".to_owned(),
            },
            modules: Vec::new(),
        }
    }

    fn test_boundary_validation_report(validator: &str) -> BoundaryValidationReportManifest {
        BoundaryValidationReportManifest {
            validator: validator.to_owned(),
            evidence_boundary: EvidenceBoundaryLevel::PortableArtifactExecution.as_str().to_owned(),
            ok: true,
            violation_count: 0,
            violations: Vec::new(),
        }
    }
}
