use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractViolationKind {
    DanglingEdge,
    GenerationMismatch,
    LiveObjectReferencesDeadObject,
    LiveEdgeReferencesInactiveObject,
    TombstoneReferencedByLiveEdge,
    HistoricalEdgeMissingGeneration,
    CleanupEffectCreatesLiveOwnership,
    ExternalEdgeMissingDeclaration,
    ExternalEdgeMetadataMismatch,
}

impl ContractViolationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DanglingEdge => "dangling-edge",
            Self::GenerationMismatch => "generation-mismatch",
            Self::LiveObjectReferencesDeadObject => "live-object-references-dead-object",
            Self::LiveEdgeReferencesInactiveObject => "live-edge-references-inactive-object",
            Self::TombstoneReferencedByLiveEdge => "tombstone-referenced-by-live-edge",
            Self::HistoricalEdgeMissingGeneration => "historical-edge-missing-generation",
            Self::CleanupEffectCreatesLiveOwnership => "cleanup-effect-creates-live-ownership",
            Self::ExternalEdgeMissingDeclaration => "external-edge-missing-declaration",
            Self::ExternalEdgeMetadataMismatch => "external-edge-metadata-mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractViolation {
    pub kind: ContractViolationKind,
    pub edge: String,
    pub from: ContractObjectRef,
    pub to: Option<ContractObjectRef>,
    pub detail: String,
}

impl ContractViolation {
    pub fn new(
        kind: ContractViolationKind,
        edge: &str,
        from: ContractObjectRef,
        to: Option<ContractObjectRef>,
        detail: &str,
    ) -> Self {
        Self { kind, edge: edge.to_string(), from, to, detail: detail.to_string() }
    }

    pub fn summary(&self) -> String {
        let to = self.to.map(ContractObjectRef::summary).unwrap_or_else(|| "none".to_string());
        format!(
            "contract-violation kind={} edge={} from={} to={} detail={}",
            self.kind.as_str(),
            self.edge,
            self.from.summary(),
            to,
            self.detail
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContractGraphSnapshot {
    pub artifacts: Vec<VerifiedArtifact>,
    pub code_objects: Vec<CodeObject>,
    pub target_feature_sets: Vec<TargetFeatureSetRecord>,
    pub vector_states: Vec<VectorStateRecord>,
    pub simd_fault_injections: Vec<SimdFaultInjectionRecord>,
    pub simd_benchmarks: Vec<SimdBenchmarkRecord>,
    pub simd_context_switch_benchmarks: Vec<SimdContextSwitchBenchmarkRecord>,
    pub framebuffer_objects: Vec<FramebufferObjectRecord>,
    pub display_objects: Vec<DisplayObjectRecord>,
    pub display_capabilities: Vec<DisplayCapabilityRecord>,
    pub framebuffer_window_leases: Vec<FramebufferWindowLeaseRecord>,
    pub framebuffer_mappings: Vec<FramebufferMappingRecord>,
    pub framebuffer_writes: Vec<FramebufferWriteRecord>,
    pub framebuffer_flush_regions: Vec<FramebufferFlushRegionRecord>,
    pub framebuffer_dirty_regions: Vec<FramebufferDirtyRegionRecord>,
    pub display_event_logs: Vec<DisplayEventLogRecord>,
    pub display_cleanups: Vec<DisplayCleanupRecord>,
    pub display_snapshot_barriers: Vec<DisplaySnapshotBarrierRecord>,
    pub display_panic_last_frames: Vec<DisplayPanicLastFrameRecord>,
    pub framebuffer_benchmarks: Vec<FramebufferBenchmarkRecord>,
    pub integrated_display_scheduler_loads: Vec<IntegratedDisplaySchedulerLoadRecord>,
    pub integrated_snapshot_io_lease_barriers: Vec<IntegratedSnapshotIoLeaseBarrierRecord>,
    pub integrated_code_publish_smp_workloads: Vec<IntegratedCodePublishSmpWorkloadRecord>,
    pub integrated_display_panics: Vec<IntegratedDisplayPanicRecord>,
    pub integrated_osctl_trace_replays: Vec<IntegratedOsctlTraceReplayRecord>,
    pub integrated_smp_preemption_cleanups: Vec<IntegratedSmpPreemptionCleanupRecord>,
    pub integrated_smp_network_faults: Vec<IntegratedSmpNetworkFaultRecord>,
    pub integrated_disk_preempt_faults: Vec<IntegratedDiskPreemptFaultRecord>,
    pub integrated_simd_migrations: Vec<IntegratedSimdMigrationRecord>,
    pub integrated_network_disk_ios: Vec<IntegratedNetworkDiskIoRecord>,
    pub network_benchmarks: Vec<NetworkBenchmarkRecord>,
    pub block_benchmarks: Vec<BlockBenchmarkRecord>,
    pub fake_block_backends: Vec<FakeBlockBackendObjectRecord>,
    pub network_driver_cleanups: Vec<NetworkDriverCleanupRecord>,
    pub device_objects: Vec<DeviceObjectRecord>,
    pub packet_device_objects: Vec<PacketDeviceObjectRecord>,
    pub network_stack_adapters: Vec<NetworkStackAdapterRecord>,
    pub socket_objects: Vec<SocketObjectRecord>,
    pub virtio_net_backends: Vec<VirtioNetBackendObjectRecord>,
    pub io_cleanups: Vec<IoCleanupRecord>,
    pub block_pending_io_policies: Vec<BlockPendingIoPolicyRecord>,
    pub block_waits: Vec<BlockWaitRecord>,
    pub block_request_objects: Vec<BlockRequestObjectRecord>,
    pub block_device_objects: Vec<BlockDeviceObjectRecord>,
    pub block_range_objects: Vec<BlockRangeObjectRecord>,
    pub block_request_queues: Vec<BlockRequestQueueRecord>,
    pub block_dma_buffers: Vec<BlockDmaBufferRecord>,
    pub harts: Vec<HartRecord>,
    pub tasks: Vec<TaskRecord>,
    pub runtime_activations: Vec<RuntimeActivationRecord>,
    pub runnable_queues: Vec<RunnableQueueRecord>,
    pub scheduler_decisions: Vec<SchedulerDecisionRecord>,
    pub activation_contexts: Vec<ActivationContextRecord>,
    pub activation_migrations: Vec<ActivationMigrationRecord>,
    pub smp_safe_points: Vec<SmpSafePointRecord>,
    pub stop_the_world_rendezvous: Vec<StopTheWorldRendezvousRecord>,
    pub smp_code_publish_barriers: Vec<SmpCodePublishBarrierRecord>,
    pub saved_contexts: Vec<SavedContextRecord>,
    pub timer_interrupts: Vec<TimerInterruptRecord>,
    pub remote_preempts: Vec<RemotePreemptRecord>,
    pub activation_cleanups: Vec<ActivationCleanupRecord>,
    pub smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceRecord>,
    pub smp_snapshot_barriers: Vec<SmpSnapshotBarrierRecord>,
    pub smp_stress_runs: Vec<SmpStressRunRecord>,
    pub preemptions: Vec<PreemptionRecord>,
    pub activation_resumes: Vec<ActivationResumeRecord>,
    pub stores: Vec<StoreRecord>,
    pub activations: Vec<ActivationRecord>,
    pub traps: Vec<TargetTrapRecord>,
    pub hostcalls: Vec<HostcallTraceRecord>,
    pub capabilities: Vec<CapabilityRecord>,
    pub waits: Vec<WaitRecord>,
    pub cleanup_transactions: Vec<FaultCleanupTransaction>,
    pub tombstones: Vec<TombstoneRecord>,
    pub external_objects: Vec<ExternalObjectDeclaration>,
    pub explicit_edges: Vec<ContractEdgeRecord>,
}

pub fn validate_contract_graph(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
    ContractGraphValidator::validate(snapshot)
}

pub struct ContractGraphValidator;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractEdgeMode {
    Live,
    Historical,
    CleanupEffect,
    External,
}

impl ContractEdgeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Historical => "historical",
            Self::CleanupEffect => "cleanup-effect",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalObjectDeclaration {
    pub object: ContractObjectRef,
    pub provider: String,
    pub class: String,
    pub debug_label: String,
}

impl ExternalObjectDeclaration {
    pub fn new(object: ContractObjectRef, provider: &str, class: &str, debug_label: &str) -> Self {
        Self {
            object,
            provider: provider.to_string(),
            class: class.to_string(),
            debug_label: debug_label.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractEdgeRecord {
    pub from: ContractObjectRef,
    pub to: ContractObjectRef,
    pub mode: ContractEdgeMode,
    pub label: String,
    pub epoch: EventId,
    pub provider: Option<String>,
    pub class: Option<String>,
}

impl ContractEdgeRecord {
    pub fn new(
        from: ContractObjectRef,
        to: ContractObjectRef,
        mode: ContractEdgeMode,
        label: &str,
        epoch: EventId,
    ) -> Self {
        Self { from, to, mode, label: label.to_string(), epoch, provider: None, class: None }
    }

    pub fn with_external_metadata(mut self, provider: &str, class: &str) -> Self {
        self.provider = Some(provider.to_string());
        self.class = Some(class.to_string());
        self
    }
}

mod object_ref;
mod validator_core;
mod validator_display;
mod validator_integrated;
mod validator_lookup;
mod validator_runtime;
