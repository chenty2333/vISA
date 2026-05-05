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
    EvidenceBoundaryOverclaim,
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
            Self::EvidenceBoundaryOverclaim => "evidence-boundary-overclaim",
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
    pub claimed_evidence_level: EvidenceBoundaryLevel,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonPortableStateKind {
    MmioBindings,
    DmaPages,
    IrqLines,
    TranslatedCodeCache,
    NativeStackFrames,
    DmwWindowState,
    PacketDeviceBindings,
    BlockDeviceBackendBindings,
    DriverDeviceBindings,
}

impl NonPortableStateKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MmioBindings => "mmio-bindings",
            Self::DmaPages => "dma-pages",
            Self::IrqLines => "irq-lines",
            Self::TranslatedCodeCache => "translated-code-cache",
            Self::NativeStackFrames => "native-stack-frames",
            Self::DmwWindowState => "dmw-window-state",
            Self::PacketDeviceBindings => "packet-device-bindings",
            Self::BlockDeviceBackendBindings => "block-device-backend-bindings",
            Self::DriverDeviceBindings => "driver-device-bindings",
        }
    }
}

impl ContractGraphSnapshot {
    /// Return a new snapshot containing only portable records.
    /// Non-portable hardware binding records are cleared.
    /// Artifacts and code_objects are kept — identity and manifest metadata
    /// are portable per the vISA spec.
    pub fn portable_subset(&self) -> Self {
        Self {
            // Non-portable: device/IO/backend bindings
            device_objects: Vec::new(),
            io_cleanups: Vec::new(),
            // Non-portable: device-backed objects
            virtio_net_backends: Vec::new(),
            fake_block_backends: Vec::new(),
            // Non-portable: DMA pages
            block_dma_buffers: Vec::new(),
            // Non-portable: window leases/mappings
            framebuffer_window_leases: Vec::new(),
            framebuffer_mappings: Vec::new(),
            // Non-portable: native frames and host-specific state
            saved_contexts: Vec::new(),
            // Non-portable: packet/block backend state
            packet_device_objects: Vec::new(),
            block_device_objects: Vec::new(),
            block_range_objects: Vec::new(),
            // Non-portable: records that reference cleared objects above
            // (block requests/waits/queues reference block_device/range;
            //  packet descriptors/queues reference packet_device)
            block_request_objects: Vec::new(),
            block_waits: Vec::new(),
            block_request_queues: Vec::new(),
            // Portable: keep everything else (incl. artifacts, code_objects, stores, capabilities)
            ..self.clone()
        }
    }

    /// List non-portable record categories present in this snapshot.
    pub fn non_portable_summary(&self) -> Vec<NonPortableStateKind> {
        let mut out = Vec::new();
        if !self.device_objects.is_empty() {
            out.push(NonPortableStateKind::MmioBindings);
        }
        if !self.block_dma_buffers.is_empty() {
            out.push(NonPortableStateKind::DmaPages);
        }
        if !self.saved_contexts.is_empty() {
            out.push(NonPortableStateKind::NativeStackFrames);
        }
        if !self.framebuffer_window_leases.is_empty() || !self.framebuffer_mappings.is_empty() {
            out.push(NonPortableStateKind::DmwWindowState);
        }
        if !self.packet_device_objects.is_empty() {
            out.push(NonPortableStateKind::PacketDeviceBindings);
        }
        if !self.block_device_objects.is_empty()
            || !self.block_range_objects.is_empty()
            || !self.block_request_objects.is_empty()
            || !self.block_waits.is_empty()
        {
            out.push(NonPortableStateKind::BlockDeviceBackendBindings);
        }
        out
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContractGraphSnapshotInputs<'a> {
    pub claimed_evidence_level: EvidenceBoundaryLevel,
    pub artifacts: &'a [VerifiedArtifact],
    pub code_objects: &'a [CodeObject],
    pub activations: &'a [ActivationRecord],
    pub traps: &'a [TargetTrapRecord],
    pub hostcalls: &'a [HostcallTraceRecord],
    pub capabilities: &'a [CapabilityRecord],
    pub cleanup_transactions: &'a [FaultCleanupTransaction],
    pub tombstones: &'a [TombstoneRecord],
    pub external_objects: &'a [ExternalObjectDeclaration],
    pub explicit_edges: &'a [ContractEdgeRecord],
}

pub fn validate_contract_graph(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
    ContractGraphValidator::validate(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrontendKind, SemanticGraph};

    fn fixture_with_devices_and_stores() -> SemanticGraph {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "test");
        let store = graph.register_store("test", "art", "role", "restartable");
        let dev_res = graph.register_resource(crate::ResourceKind::BlockDevice, Some(1), "blk-dev");
        graph.record_device_object_with_id(
            1,
            "dev0",
            "block-device",
            dev_res,
            1,
            "virtio-blk",
            "pci",
            "vmos",
            "bench",
            "test",
        );
        graph.record_block_device_object_with_id(1, "blk0", 1, 1, 512, 1024, false, 256, "test");
        graph.record_block_range_object_with_id(1, 1, 1, 0, 256, "test");
        graph.record_fake_block_backend_object_with_id(
            1,
            "fake-blk",
            1,
            1,
            "service_core",
            "fake-block-v1",
            512,
            1024,
            false,
            256,
            42,
            "test",
        );
        let _ = store;
        graph
    }

    #[test]
    fn portable_subset_preserves_stores_and_capabilities() {
        let graph = fixture_with_devices_and_stores();
        let snapshot = graph.snapshot();
        assert!(!snapshot.stores.is_empty());

        let portable = snapshot.portable_subset();
        assert_eq!(portable.stores.len(), snapshot.stores.len());
    }

    #[test]
    fn portable_subset_strips_device_bindings() {
        let graph = fixture_with_devices_and_stores();
        let snapshot = graph.snapshot();
        assert!(!snapshot.device_objects.is_empty());

        let portable = snapshot.portable_subset();
        assert!(portable.device_objects.is_empty());
        assert!(portable.block_device_objects.is_empty());
        assert!(portable.fake_block_backends.is_empty());
        assert!(!portable.stores.is_empty());
    }

    #[test]
    fn portable_subset_is_self_consistent() {
        let graph = fixture_with_devices_and_stores();
        let snapshot = graph.snapshot();
        let portable = snapshot.portable_subset();
        assert!(
            portable.non_portable_summary().is_empty(),
            "portable subset must self-report zero non-portable state: {:?}",
            portable.non_portable_summary()
        );
    }

    #[test]
    fn portable_subset_passes_contract_graph_validation() {
        let graph = fixture_with_devices_and_stores();
        let snapshot = graph.snapshot();
        let portable = snapshot.portable_subset();
        let violations = validate_contract_graph(&portable);
        assert!(violations.is_empty(), "portable subset must be contract-valid: {violations:?}");
    }

    #[test]
    fn non_portable_summary_reports_present_categories() {
        let graph = fixture_with_devices_and_stores();
        let snapshot = graph.snapshot();
        let summary = snapshot.non_portable_summary();
        assert!(summary.contains(&NonPortableStateKind::MmioBindings));
        assert!(summary.contains(&NonPortableStateKind::BlockDeviceBackendBindings));
    }
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
    pub evidence_level: EvidenceBoundaryLevel,
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
        Self {
            from,
            to,
            mode,
            evidence_level: EvidenceBoundaryLevel::SemanticModel,
            label: label.to_string(),
            epoch,
            provider: None,
            class: None,
        }
    }

    pub fn with_evidence_level(mut self, evidence_level: EvidenceBoundaryLevel) -> Self {
        self.evidence_level = evidence_level;
        self
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
