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
    pub virtio_blk_backends: Vec<VirtioBlkBackendObjectRecord>,
    pub network_driver_cleanups: Vec<NetworkDriverCleanupRecord>,
    pub device_objects: Vec<DeviceObjectRecord>,
    pub packet_device_objects: Vec<PacketDeviceObjectRecord>,
    pub network_stack_adapters: Vec<NetworkStackAdapterRecord>,
    pub socket_objects: Vec<SocketObjectRecord>,
    pub fake_net_backends: Vec<FakeNetBackendObjectRecord>,
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
    pub processes: Vec<ProcessRecord>,
    pub threads: Vec<ThreadRecord>,
    pub thread_groups: Vec<ThreadGroupRecord>,
    pub fd_tables: Vec<FdTableRecord>,
    pub open_file_descriptions: Vec<OpenFileDescriptionRecord>,
    pub credentials: Vec<CredentialRecord>,
    pub credential_transitions: Vec<CredentialTransitionRecord>,
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
    /// Return a new snapshot containing portable records that the runtime
    /// restore path can rebuild without identity remapping.
    /// Hardware bindings and restore-unsupported semantic projections are
    /// cleared.
    /// Artifacts and code_objects are kept — identity and manifest metadata
    /// are portable per the vISA spec.
    pub fn portable_subset(&self) -> Self {
        Self {
            // Not restored yet: SIMD execution and benchmark projections
            target_feature_sets: Vec::new(),
            vector_states: Vec::new(),
            simd_fault_injections: Vec::new(),
            simd_benchmarks: Vec::new(),
            simd_context_switch_benchmarks: Vec::new(),
            integrated_simd_migrations: Vec::new(),
            // Not restored yet: display roots and code-publish integrated projections
            framebuffer_objects: Vec::new(),
            display_objects: Vec::new(),
            display_capabilities: Vec::new(),
            integrated_code_publish_smp_workloads: Vec::new(),
            // Non-portable: device/IO/backend bindings
            device_objects: Vec::new(),
            io_cleanups: Vec::new(),
            // Non-portable: device-backed objects
            fake_net_backends: Vec::new(),
            virtio_net_backends: Vec::new(),
            fake_block_backends: Vec::new(),
            virtio_blk_backends: Vec::new(),
            // Non-portable: DMA pages
            block_dma_buffers: Vec::new(),
            // Non-portable: window leases/mappings
            framebuffer_window_leases: Vec::new(),
            framebuffer_mappings: Vec::new(),
            framebuffer_writes: Vec::new(),
            framebuffer_flush_regions: Vec::new(),
            framebuffer_dirty_regions: Vec::new(),
            display_event_logs: Vec::new(),
            display_cleanups: Vec::new(),
            display_snapshot_barriers: Vec::new(),
            display_panic_last_frames: Vec::new(),
            framebuffer_benchmarks: Vec::new(),
            // Non-portable: native frames and host-specific state
            saved_contexts: Vec::new(),
            integrated_smp_preemption_cleanups: Vec::new(),
            // Non-portable: packet/block backend state
            packet_device_objects: Vec::new(),
            // Non-portable: records that reference cleared packet_device
            network_stack_adapters: Vec::new(),
            socket_objects: Vec::new(),
            network_benchmarks: Vec::new(),
            network_driver_cleanups: Vec::new(),
            integrated_smp_network_faults: Vec::new(),
            // Non-portable: block root objects
            block_device_objects: Vec::new(),
            block_range_objects: Vec::new(),
            // Non-portable: records that reference cleared block objects
            block_pending_io_policies: Vec::new(),
            block_request_objects: Vec::new(),
            block_waits: Vec::new(),
            block_request_queues: Vec::new(),
            block_benchmarks: Vec::new(),
            integrated_disk_preempt_faults: Vec::new(),
            integrated_network_disk_ios: Vec::new(),
            // Non-portable: integrated views that aggregate removed IO/display evidence.
            integrated_display_scheduler_loads: Vec::new(),
            integrated_snapshot_io_lease_barriers: Vec::new(),
            integrated_display_panics: Vec::new(),
            integrated_osctl_trace_replays: Vec::new(),
            // Not restored yet: scheduler execution projections beyond task/runtime activation
            harts: Vec::new(),
            runnable_queues: Vec::new(),
            scheduler_decisions: Vec::new(),
            activation_contexts: Vec::new(),
            activation_migrations: Vec::new(),
            smp_safe_points: Vec::new(),
            stop_the_world_rendezvous: Vec::new(),
            smp_code_publish_barriers: Vec::new(),
            timer_interrupts: Vec::new(),
            remote_preempts: Vec::new(),
            activation_cleanups: Vec::new(),
            smp_cleanup_quiescence: Vec::new(),
            smp_snapshot_barriers: Vec::new(),
            smp_stress_runs: Vec::new(),
            preemptions: Vec::new(),
            activation_resumes: Vec::new(),
            waits: Vec::new(),
            // Not restored yet: external declarations and explicit audit edges
            external_objects: Vec::new(),
            explicit_edges: Vec::new(),
            // Portable: keep everything else (incl. artifacts, code_objects, stores, capabilities)
            ..self.clone()
        }
    }

    /// Return the first field that is portable in the abstract contract graph
    /// but not currently rebuilt by `VisaRuntime::restore_portable_subset`.
    pub fn unsupported_runtime_restore_record(&self) -> Option<&'static str> {
        macro_rules! reject {
            ($field:ident) => {
                if !self.$field.is_empty() {
                    return Some(concat!("unsupported portable record: ", stringify!($field)));
                }
            };
        }

        reject!(target_feature_sets);
        reject!(vector_states);
        reject!(simd_fault_injections);
        reject!(simd_benchmarks);
        reject!(simd_context_switch_benchmarks);
        reject!(framebuffer_objects);
        reject!(display_objects);
        reject!(display_capabilities);
        reject!(framebuffer_window_leases);
        reject!(framebuffer_mappings);
        reject!(framebuffer_writes);
        reject!(framebuffer_flush_regions);
        reject!(framebuffer_dirty_regions);
        reject!(display_event_logs);
        reject!(display_cleanups);
        reject!(display_snapshot_barriers);
        reject!(display_panic_last_frames);
        reject!(framebuffer_benchmarks);
        reject!(integrated_display_scheduler_loads);
        reject!(integrated_snapshot_io_lease_barriers);
        reject!(integrated_code_publish_smp_workloads);
        reject!(integrated_display_panics);
        reject!(integrated_osctl_trace_replays);
        reject!(integrated_smp_preemption_cleanups);
        reject!(integrated_smp_network_faults);
        reject!(integrated_disk_preempt_faults);
        reject!(integrated_simd_migrations);
        reject!(integrated_network_disk_ios);
        reject!(network_benchmarks);
        reject!(block_benchmarks);
        reject!(fake_block_backends);
        reject!(virtio_blk_backends);
        reject!(network_driver_cleanups);
        reject!(device_objects);
        reject!(packet_device_objects);
        reject!(network_stack_adapters);
        reject!(socket_objects);
        reject!(fake_net_backends);
        reject!(virtio_net_backends);
        reject!(io_cleanups);
        reject!(block_pending_io_policies);
        reject!(block_waits);
        reject!(block_request_objects);
        reject!(block_device_objects);
        reject!(block_range_objects);
        reject!(block_request_queues);
        reject!(block_dma_buffers);
        reject!(harts);
        reject!(runnable_queues);
        reject!(scheduler_decisions);
        reject!(activation_contexts);
        reject!(activation_migrations);
        reject!(smp_safe_points);
        reject!(stop_the_world_rendezvous);
        reject!(smp_code_publish_barriers);
        reject!(saved_contexts);
        reject!(timer_interrupts);
        reject!(remote_preempts);
        reject!(activation_cleanups);
        reject!(smp_cleanup_quiescence);
        reject!(smp_snapshot_barriers);
        reject!(smp_stress_runs);
        reject!(preemptions);
        reject!(activation_resumes);
        reject!(waits);
        reject!(external_objects);
        reject!(explicit_edges);
        None
    }

    /// List non-portable record categories present in this snapshot.
    pub fn non_portable_summary(&self) -> Vec<NonPortableStateKind> {
        let mut out = Vec::new();
        if !self.device_objects.is_empty() {
            push_non_portable_kind(&mut out, NonPortableStateKind::MmioBindings);
            push_non_portable_kind(&mut out, NonPortableStateKind::DriverDeviceBindings);
        }
        if !self.block_dma_buffers.is_empty()
            || self.io_cleanups.iter().any(|cleanup| !cleanup.released_dma_buffers.is_empty())
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::DmaPages);
        }
        if self.io_cleanups.iter().any(|cleanup| !cleanup.released_irq_lines.is_empty())
            || !self.virtio_net_backends.is_empty()
            || !self.virtio_blk_backends.is_empty()
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::IrqLines);
        }
        if !self.saved_contexts.is_empty() || !self.integrated_smp_preemption_cleanups.is_empty() {
            push_non_portable_kind(&mut out, NonPortableStateKind::NativeStackFrames);
        }
        if !self.framebuffer_window_leases.is_empty()
            || !self.framebuffer_mappings.is_empty()
            || !self.framebuffer_writes.is_empty()
            || !self.framebuffer_flush_regions.is_empty()
            || !self.framebuffer_dirty_regions.is_empty()
            || !self.display_event_logs.is_empty()
            || !self.display_cleanups.is_empty()
            || !self.display_snapshot_barriers.is_empty()
            || !self.display_panic_last_frames.is_empty()
            || !self.framebuffer_benchmarks.is_empty()
            || !self.integrated_display_scheduler_loads.is_empty()
            || !self.integrated_snapshot_io_lease_barriers.is_empty()
            || !self.integrated_display_panics.is_empty()
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::DmwWindowState);
        }
        if !self.packet_device_objects.is_empty()
            || !self.network_stack_adapters.is_empty()
            || !self.socket_objects.is_empty()
            || !self.fake_net_backends.is_empty()
            || !self.virtio_net_backends.is_empty()
            || !self.network_benchmarks.is_empty()
            || !self.network_driver_cleanups.is_empty()
            || !self.integrated_smp_network_faults.is_empty()
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::PacketDeviceBindings);
        }
        if !self.block_device_objects.is_empty()
            || !self.block_range_objects.is_empty()
            || !self.fake_block_backends.is_empty()
            || !self.virtio_blk_backends.is_empty()
            || !self.block_pending_io_policies.is_empty()
            || !self.block_request_objects.is_empty()
            || !self.block_waits.is_empty()
            || !self.block_request_queues.is_empty()
            || !self.block_benchmarks.is_empty()
            || !self.integrated_disk_preempt_faults.is_empty()
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::BlockDeviceBackendBindings);
        }
        if !self.io_cleanups.is_empty()
            || !self.fake_net_backends.is_empty()
            || !self.virtio_net_backends.is_empty()
            || !self.fake_block_backends.is_empty()
            || !self.virtio_blk_backends.is_empty()
        {
            push_non_portable_kind(&mut out, NonPortableStateKind::DriverDeviceBindings);
        }
        if self.io_cleanups.iter().any(|cleanup| !cleanup.released_mmio_regions.is_empty()) {
            push_non_portable_kind(&mut out, NonPortableStateKind::MmioBindings);
        }
        if !self.integrated_network_disk_ios.is_empty() {
            push_non_portable_kind(&mut out, NonPortableStateKind::PacketDeviceBindings);
            push_non_portable_kind(&mut out, NonPortableStateKind::BlockDeviceBackendBindings);
            push_non_portable_kind(&mut out, NonPortableStateKind::DmaPages);
        }
        if !self.integrated_osctl_trace_replays.is_empty() {
            push_non_portable_kind(&mut out, NonPortableStateKind::DmwWindowState);
            push_non_portable_kind(&mut out, NonPortableStateKind::PacketDeviceBindings);
            push_non_portable_kind(&mut out, NonPortableStateKind::BlockDeviceBackendBindings);
            push_non_portable_kind(&mut out, NonPortableStateKind::NativeStackFrames);
        }
        out
    }
}

fn push_non_portable_kind(out: &mut Vec<NonPortableStateKind>, kind: NonPortableStateKind) {
    if !out.contains(&kind) {
        out.push(kind);
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
    use alloc::vec;

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
            "visa",
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

    fn fake_net_backend_record() -> FakeNetBackendObjectRecord {
        FakeNetBackendObjectRecord {
            id: 1,
            name: "fake-net".to_string(),
            packet_device: 8,
            packet_device_generation: 1,
            provider: "test".to_string(),
            profile: "fake".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0; 6],
            frame_format_version: 1,
            max_payload_len: 1500,
            deterministic_seed: 0,
            generation: 1,
            state: FakeNetBackendObjectState::Bound,
            recorded_at_event: 1,
            note: "test".to_string(),
        }
    }

    fn virtio_blk_backend_record() -> VirtioBlkBackendObjectRecord {
        VirtioBlkBackendObjectRecord {
            id: 1,
            name: "virtio-blk".to_string(),
            block_device: 7,
            block_device_generation: 1,
            driver_binding: 9,
            driver_binding_generation: 1,
            device: 10,
            device_generation: 1,
            provider: "test".to_string(),
            profile: "virtio".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 8,
            read_only: false,
            max_transfer_sectors: 1,
            device_features: 0,
            driver_features: 0,
            negotiated_features: 0,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 3,
            generation: 1,
            state: VirtioBlkBackendObjectState::SkeletonReady,
            recorded_at_event: 1,
            note: "test".to_string(),
        }
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
        let mut snapshot = graph.snapshot();
        snapshot.fake_net_backends.push(fake_net_backend_record());
        snapshot.virtio_blk_backends.push(virtio_blk_backend_record());
        assert!(!snapshot.device_objects.is_empty());

        let portable = snapshot.portable_subset();
        assert!(portable.device_objects.is_empty());
        assert!(portable.block_device_objects.is_empty());
        assert!(portable.fake_net_backends.is_empty());
        assert!(portable.fake_block_backends.is_empty());
        assert!(portable.virtio_blk_backends.is_empty());
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
        assert!(
            portable.unsupported_runtime_restore_record().is_none(),
            "portable subset must not retain runtime restore-unsupported records: {:?}",
            portable.unsupported_runtime_restore_record()
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
        assert!(summary.contains(&NonPortableStateKind::DriverDeviceBindings));
    }

    #[test]
    fn non_portable_summary_reports_backend_records_without_roots() {
        let mut snapshot = ContractGraphSnapshot::default();
        snapshot.fake_block_backends.push(FakeBlockBackendObjectRecord {
            id: 1,
            name: "fake-blk".to_string(),
            block_device: 7,
            block_device_generation: 1,
            provider: "test".to_string(),
            profile: "fake".to_string(),
            sector_size: 512,
            sector_count: 8,
            read_only: false,
            max_transfer_sectors: 1,
            deterministic_seed: 0,
            generation: 1,
            state: FakeBlockBackendObjectState::Bound,
            recorded_at_event: 1,
            note: "test".to_string(),
        });
        snapshot.virtio_net_backends.push(VirtioNetBackendObjectRecord {
            id: 1,
            name: "virtio-net".to_string(),
            packet_device: 8,
            packet_device_generation: 1,
            driver_binding: 9,
            driver_binding_generation: 1,
            device: 10,
            device_generation: 1,
            provider: "test".to_string(),
            profile: "virtio".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0; 6],
            frame_format_version: 1,
            max_payload_len: 1500,
            device_features: 0,
            driver_features: 0,
            negotiated_features: 0,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 8,
            irq_vector: 3,
            generation: 1,
            state: VirtioNetBackendObjectState::SkeletonReady,
            recorded_at_event: 1,
            note: "test".to_string(),
        });
        snapshot.fake_net_backends.push(fake_net_backend_record());
        snapshot.virtio_blk_backends.push(virtio_blk_backend_record());

        let summary = snapshot.non_portable_summary();
        assert!(summary.contains(&NonPortableStateKind::BlockDeviceBackendBindings));
        assert!(summary.contains(&NonPortableStateKind::PacketDeviceBindings));
        assert!(summary.contains(&NonPortableStateKind::DriverDeviceBindings));
        assert!(summary.contains(&NonPortableStateKind::IrqLines));
    }

    #[test]
    fn non_portable_summary_reports_io_cleanup_dependencies() {
        let mut snapshot = ContractGraphSnapshot::default();
        snapshot.io_cleanups.push(IoCleanupRecord {
            id: 1,
            driver_store: 2,
            driver_store_generation: 1,
            device: 3,
            device_generation: 1,
            driver_binding: 4,
            driver_binding_generation: 1,
            generation: 1,
            state: IoCleanupState::Completed,
            reason: "test".to_string(),
            started_at_event: 1,
            completed_at_event: 2,
            cancelled_io_waits: Vec::new(),
            revoked_device_capabilities: Vec::new(),
            revoked_capabilities: Vec::new(),
            released_dma_buffers: vec![ContractObjectRef::new(
                ContractObjectKind::DmaBufferObject,
                10,
                1,
            )],
            released_mmio_regions: vec![ContractObjectRef::new(
                ContractObjectKind::MmioRegionObject,
                11,
                1,
            )],
            released_irq_lines: vec![ContractObjectRef::new(
                ContractObjectKind::IrqLineObject,
                12,
                1,
            )],
            steps: Vec::new(),
            note: "test".to_string(),
        });

        let summary = snapshot.non_portable_summary();
        assert!(summary.contains(&NonPortableStateKind::DriverDeviceBindings));
        assert!(summary.contains(&NonPortableStateKind::DmaPages));
        assert!(summary.contains(&NonPortableStateKind::MmioBindings));
        assert!(summary.contains(&NonPortableStateKind::IrqLines));
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
