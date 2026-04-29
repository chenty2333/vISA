use alloc::vec::Vec;

use super::*;

impl ContractGraphValidator {
    pub(super) fn object_ref_by_id_generation(
        snapshot: &ContractGraphSnapshot,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
    ) -> Option<ContractObjectRef> {
        match kind {
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| u64::from(task.id) == id && task.generation == generation)
                .map(TaskRecord::object_ref),
            ContractObjectKind::Activation => snapshot
                .runtime_activations
                .iter()
                .find(|activation| activation.id == id && activation.generation == generation)
                .map(RuntimeActivationRecord::object_ref)
                .or_else(|| {
                    snapshot
                        .activations
                        .iter()
                        .find(|activation| {
                            activation.id == id && activation.generation == generation
                        })
                        .map(ActivationRecord::object_ref)
                }),
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == id && store.generation == generation)
                .map(StoreRecord::object_ref),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == id && code.generation == generation)
                .map(CodeObject::object_ref),
            ContractObjectKind::TargetFeatureSet => snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.id == id && feature.generation == generation)
                .map(TargetFeatureSetRecord::object_ref),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| vector_state.id == id && vector_state.generation == generation)
                .map(VectorStateRecord::object_ref),
            ContractObjectKind::SimdFaultInjection => snapshot
                .simd_fault_injections
                .iter()
                .find(|injection| injection.id == id && injection.generation == generation)
                .map(SimdFaultInjectionRecord::object_ref),
            ContractObjectKind::SimdBenchmark => snapshot
                .simd_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(SimdBenchmarkRecord::object_ref),
            ContractObjectKind::SimdContextSwitchBenchmark => snapshot
                .simd_context_switch_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(SimdContextSwitchBenchmarkRecord::object_ref),
            ContractObjectKind::SmpStressRun => snapshot
                .smp_stress_runs
                .iter()
                .find(|run| run.id == id && run.generation == generation)
                .map(SmpStressRunRecord::object_ref),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| decision.id == id && decision.generation == generation)
                .map(SchedulerDecisionRecord::object_ref),
            ContractObjectKind::SmpSnapshotBarrier => snapshot
                .smp_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(SmpSnapshotBarrierRecord::object_ref),
            ContractObjectKind::RemotePreempt => snapshot
                .remote_preempts
                .iter()
                .find(|remote| remote.id == id && remote.generation == generation)
                .map(RemotePreemptRecord::object_ref),
            ContractObjectKind::SavedContext => snapshot
                .saved_contexts
                .iter()
                .find(|context| context.id == id && context.generation == generation)
                .map(SavedContextRecord::object_ref),
            ContractObjectKind::TimerInterrupt => snapshot
                .timer_interrupts
                .iter()
                .find(|timer| timer.id == id && timer.generation == generation)
                .map(TimerInterruptRecord::object_ref),
            ContractObjectKind::ActivationCleanup => snapshot
                .activation_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(ActivationCleanupRecord::object_ref),
            ContractObjectKind::SmpCleanupQuiescence => snapshot
                .smp_cleanup_quiescence
                .iter()
                .find(|quiescence| quiescence.id == id && quiescence.generation == generation)
                .map(SmpCleanupQuiescenceRecord::object_ref),
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| framebuffer.id == id && framebuffer.generation == generation)
                .map(FramebufferObjectRecord::object_ref),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == id && display.generation == generation)
                .map(DisplayObjectRecord::object_ref),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| capability.id == id && capability.generation == generation)
                .map(DisplayCapabilityRecord::object_ref),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == id && lease.generation == generation)
                .map(FramebufferWindowLeaseRecord::object_ref),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == id && mapping.generation == generation)
                .map(FramebufferMappingRecord::object_ref),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == id && write.generation == generation)
                .map(FramebufferWriteRecord::object_ref),
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == id && flush.generation == generation)
                .map(FramebufferFlushRegionRecord::object_ref),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == id && dirty.generation == generation)
                .map(FramebufferDirtyRegionRecord::object_ref),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == id && log.generation == generation)
                .map(DisplayEventLogRecord::object_ref),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(DisplayCleanupRecord::object_ref),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(DisplaySnapshotBarrierRecord::object_ref),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == id && frame.generation == generation)
                .map(DisplayPanicLastFrameRecord::object_ref),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(FramebufferBenchmarkRecord::object_ref),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSmpPreemptionCleanupRecord::object_ref),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSmpNetworkFaultRecord::object_ref),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDiskPreemptFaultRecord::object_ref),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSimdMigrationRecord::object_ref),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedNetworkDiskIoRecord::object_ref),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDisplaySchedulerLoadRecord::object_ref),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSnapshotIoLeaseBarrierRecord::object_ref),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedCodePublishSmpWorkloadRecord::object_ref),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDisplayPanicRecord::object_ref),
            ContractObjectKind::IntegratedOsctlTraceReplay => snapshot
                .integrated_osctl_trace_replays
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedOsctlTraceReplayRecord::object_ref),
            ContractObjectKind::SmpSafePoint => snapshot
                .smp_safe_points
                .iter()
                .find(|safe_point| safe_point.id == id && safe_point.generation == generation)
                .map(SmpSafePointRecord::object_ref),
            ContractObjectKind::StopTheWorldRendezvous => snapshot
                .stop_the_world_rendezvous
                .iter()
                .find(|rendezvous| rendezvous.id == id && rendezvous.generation == generation)
                .map(StopTheWorldRendezvousRecord::object_ref),
            ContractObjectKind::DeviceObject => snapshot
                .device_objects
                .iter()
                .find(|device| device.id == id && device.generation == generation)
                .map(DeviceObjectRecord::object_ref),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(SmpCodePublishBarrierRecord::object_ref),
            ContractObjectKind::NetworkDriverCleanup => snapshot
                .network_driver_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(NetworkDriverCleanupRecord::object_ref),
            ContractObjectKind::PacketDeviceObject => snapshot
                .packet_device_objects
                .iter()
                .find(|packet_device| {
                    packet_device.id == id && packet_device.generation == generation
                })
                .map(PacketDeviceObjectRecord::object_ref),
            ContractObjectKind::NetworkStackAdapter => snapshot
                .network_stack_adapters
                .iter()
                .find(|adapter| adapter.id == id && adapter.generation == generation)
                .map(NetworkStackAdapterRecord::object_ref),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|socket| socket.id == id && socket.generation == generation)
                .map(SocketObjectRecord::object_ref),
            ContractObjectKind::VirtioNetBackendObject => snapshot
                .virtio_net_backends
                .iter()
                .find(|backend| backend.id == id && backend.generation == generation)
                .map(VirtioNetBackendObjectRecord::object_ref),
            ContractObjectKind::IoCleanup => snapshot
                .io_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(IoCleanupRecord::object_ref),
            ContractObjectKind::BlockPendingIoPolicy => snapshot
                .block_pending_io_policies
                .iter()
                .find(|policy| policy.id == id && policy.generation == generation)
                .map(BlockPendingIoPolicyRecord::object_ref),
            ContractObjectKind::BlockWait => snapshot
                .block_waits
                .iter()
                .find(|wait| wait.id == id && wait.generation == generation)
                .map(BlockWaitRecord::object_ref),
            ContractObjectKind::BlockRequestObject => snapshot
                .block_request_objects
                .iter()
                .find(|request| request.id == id && request.generation == generation)
                .map(BlockRequestObjectRecord::object_ref),
            ContractObjectKind::BlockDeviceObject => snapshot
                .block_device_objects
                .iter()
                .find(|device| device.id == id && device.generation == generation)
                .map(BlockDeviceObjectRecord::object_ref),
            ContractObjectKind::BlockRangeObject => snapshot
                .block_range_objects
                .iter()
                .find(|range| range.id == id && range.generation == generation)
                .map(BlockRangeObjectRecord::object_ref),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|queue| queue.id == id && queue.generation == generation)
                .map(BlockRequestQueueRecord::object_ref),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|buffer| buffer.id == id && buffer.generation == generation)
                .map(BlockDmaBufferRecord::object_ref),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|backend| backend.id == id && backend.generation == generation)
                .map(FakeBlockBackendObjectRecord::object_ref),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(NetworkBenchmarkRecord::object_ref),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(BlockBenchmarkRecord::object_ref),
            ContractObjectKind::Hart => snapshot
                .harts
                .iter()
                .find(|hart| u64::from(hart.id) == id && hart.generation == generation)
                .map(HartRecord::object_ref),
            ContractObjectKind::RunnableQueue => snapshot
                .runnable_queues
                .iter()
                .find(|queue| queue.id == id && queue.generation == generation)
                .map(RunnableQueueRecord::object_ref),
            ContractObjectKind::ActivationContext => snapshot
                .activation_contexts
                .iter()
                .find(|context| context.id == id && context.generation == generation)
                .map(ActivationContextRecord::object_ref),
            ContractObjectKind::ActivationMigration => snapshot
                .activation_migrations
                .iter()
                .find(|migration| migration.id == id && migration.generation == generation)
                .map(ActivationMigrationRecord::object_ref),
            ContractObjectKind::Preemption => snapshot
                .preemptions
                .iter()
                .find(|preemption| preemption.id == id && preemption.generation == generation)
                .map(PreemptionRecord::object_ref),
            ContractObjectKind::ActivationResume => snapshot
                .activation_resumes
                .iter()
                .find(|resume| resume.id == id && resume.generation == generation)
                .map(ActivationResumeRecord::object_ref),
            ContractObjectKind::Artifact => snapshot
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == id && artifact.generation == generation)
                .map(VerifiedArtifact::object_ref),
            ContractObjectKind::Trap => snapshot
                .traps
                .iter()
                .find(|trap| trap.id == id && trap.generation == generation)
                .map(TargetTrapRecord::object_ref),
            ContractObjectKind::Hostcall => snapshot
                .hostcalls
                .iter()
                .find(|hostcall| hostcall.id == id && hostcall.generation == generation)
                .map(HostcallTraceRecord::object_ref),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| capability.id == id && capability.generation == generation)
                .map(CapabilityRecord::object_ref),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == id && wait.generation == generation)
                .map(WaitRecord::object_ref),
            ContractObjectKind::CleanupTransaction => snapshot
                .cleanup_transactions
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(FaultCleanupTransaction::object_ref),
            ContractObjectKind::ExternalObject => snapshot
                .external_objects
                .iter()
                .find(|external| {
                    external.object.id == id && external.object.generation == generation
                })
                .map(|external| external.object),
            _ => None,
        }
    }

    pub(super) fn check_tombstone_live_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        to: ContractObjectRef,
        live_edge: bool,
    ) {
        if !live_edge {
            return;
        }
        if snapshot.tombstones.iter().any(|tombstone| tombstone.object_ref() == to) {
            violations.push(ContractViolation::new(
                ContractViolationKind::TombstoneReferencedByLiveEdge,
                edge,
                from,
                Some(to),
                "live edge references a tombstoned generation",
            ));
        }
    }

    pub(super) fn is_live_activation(activation: &ActivationRecord) -> bool {
        matches!(activation.state, ActivationState::Running | ActivationState::Pending)
    }

    pub(super) fn current_object_ref(
        snapshot: &ContractGraphSnapshot,
        kind: ContractObjectKind,
        id: u64,
    ) -> Option<ContractObjectRef> {
        match kind {
            ContractObjectKind::Artifact => snapshot
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == id)
                .map(VerifiedArtifact::object_ref),
            ContractObjectKind::CodeObject => {
                snapshot.code_objects.iter().find(|code| code.id == id).map(CodeObject::object_ref)
            }
            ContractObjectKind::TargetFeatureSet => snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.id == id)
                .map(TargetFeatureSetRecord::object_ref),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| vector_state.id == id)
                .map(VectorStateRecord::object_ref),
            ContractObjectKind::SimdFaultInjection => snapshot
                .simd_fault_injections
                .iter()
                .find(|injection| injection.id == id)
                .map(SimdFaultInjectionRecord::object_ref),
            ContractObjectKind::SimdBenchmark => snapshot
                .simd_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(SimdBenchmarkRecord::object_ref),
            ContractObjectKind::SimdContextSwitchBenchmark => snapshot
                .simd_context_switch_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(SimdContextSwitchBenchmarkRecord::object_ref),
            ContractObjectKind::SmpStressRun => snapshot
                .smp_stress_runs
                .iter()
                .find(|run| run.id == id)
                .map(SmpStressRunRecord::object_ref),
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| u64::from(task.id) == id)
                .map(TaskRecord::object_ref),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| decision.id == id)
                .map(SchedulerDecisionRecord::object_ref),
            ContractObjectKind::SmpSnapshotBarrier => snapshot
                .smp_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(SmpSnapshotBarrierRecord::object_ref),
            ContractObjectKind::RemotePreempt => snapshot
                .remote_preempts
                .iter()
                .find(|remote| remote.id == id)
                .map(RemotePreemptRecord::object_ref),
            ContractObjectKind::SavedContext => snapshot
                .saved_contexts
                .iter()
                .find(|context| context.id == id)
                .map(SavedContextRecord::object_ref),
            ContractObjectKind::TimerInterrupt => snapshot
                .timer_interrupts
                .iter()
                .find(|timer| timer.id == id)
                .map(TimerInterruptRecord::object_ref),
            ContractObjectKind::ActivationCleanup => snapshot
                .activation_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(ActivationCleanupRecord::object_ref),
            ContractObjectKind::SmpCleanupQuiescence => snapshot
                .smp_cleanup_quiescence
                .iter()
                .find(|quiescence| quiescence.id == id)
                .map(SmpCleanupQuiescenceRecord::object_ref),
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| framebuffer.id == id)
                .map(FramebufferObjectRecord::object_ref),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == id)
                .map(DisplayObjectRecord::object_ref),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| capability.id == id)
                .map(DisplayCapabilityRecord::object_ref),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == id)
                .map(FramebufferWindowLeaseRecord::object_ref),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == id)
                .map(FramebufferMappingRecord::object_ref),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == id)
                .map(FramebufferWriteRecord::object_ref),
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == id)
                .map(FramebufferFlushRegionRecord::object_ref),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == id)
                .map(FramebufferDirtyRegionRecord::object_ref),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == id)
                .map(DisplayEventLogRecord::object_ref),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(DisplayCleanupRecord::object_ref),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(DisplaySnapshotBarrierRecord::object_ref),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == id)
                .map(DisplayPanicLastFrameRecord::object_ref),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(FramebufferBenchmarkRecord::object_ref),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSmpPreemptionCleanupRecord::object_ref),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSmpNetworkFaultRecord::object_ref),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDiskPreemptFaultRecord::object_ref),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSimdMigrationRecord::object_ref),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedNetworkDiskIoRecord::object_ref),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDisplaySchedulerLoadRecord::object_ref),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSnapshotIoLeaseBarrierRecord::object_ref),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedCodePublishSmpWorkloadRecord::object_ref),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDisplayPanicRecord::object_ref),
            ContractObjectKind::IntegratedOsctlTraceReplay => snapshot
                .integrated_osctl_trace_replays
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedOsctlTraceReplayRecord::object_ref),
            ContractObjectKind::SmpSafePoint => snapshot
                .smp_safe_points
                .iter()
                .find(|safe_point| safe_point.id == id)
                .map(SmpSafePointRecord::object_ref),
            ContractObjectKind::StopTheWorldRendezvous => snapshot
                .stop_the_world_rendezvous
                .iter()
                .find(|rendezvous| rendezvous.id == id)
                .map(StopTheWorldRendezvousRecord::object_ref),
            ContractObjectKind::DeviceObject => snapshot
                .device_objects
                .iter()
                .find(|device| device.id == id)
                .map(DeviceObjectRecord::object_ref),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(SmpCodePublishBarrierRecord::object_ref),
            ContractObjectKind::NetworkDriverCleanup => snapshot
                .network_driver_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(NetworkDriverCleanupRecord::object_ref),
            ContractObjectKind::PacketDeviceObject => snapshot
                .packet_device_objects
                .iter()
                .find(|packet_device| packet_device.id == id)
                .map(PacketDeviceObjectRecord::object_ref),
            ContractObjectKind::NetworkStackAdapter => snapshot
                .network_stack_adapters
                .iter()
                .find(|adapter| adapter.id == id)
                .map(NetworkStackAdapterRecord::object_ref),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|socket| socket.id == id)
                .map(SocketObjectRecord::object_ref),
            ContractObjectKind::VirtioNetBackendObject => snapshot
                .virtio_net_backends
                .iter()
                .find(|backend| backend.id == id)
                .map(VirtioNetBackendObjectRecord::object_ref),
            ContractObjectKind::IoCleanup => snapshot
                .io_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(IoCleanupRecord::object_ref),
            ContractObjectKind::BlockPendingIoPolicy => snapshot
                .block_pending_io_policies
                .iter()
                .find(|policy| policy.id == id)
                .map(BlockPendingIoPolicyRecord::object_ref),
            ContractObjectKind::BlockWait => snapshot
                .block_waits
                .iter()
                .find(|wait| wait.id == id)
                .map(BlockWaitRecord::object_ref),
            ContractObjectKind::BlockRequestObject => snapshot
                .block_request_objects
                .iter()
                .find(|request| request.id == id)
                .map(BlockRequestObjectRecord::object_ref),
            ContractObjectKind::BlockDeviceObject => snapshot
                .block_device_objects
                .iter()
                .find(|device| device.id == id)
                .map(BlockDeviceObjectRecord::object_ref),
            ContractObjectKind::BlockRangeObject => snapshot
                .block_range_objects
                .iter()
                .find(|range| range.id == id)
                .map(BlockRangeObjectRecord::object_ref),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|queue| queue.id == id)
                .map(BlockRequestQueueRecord::object_ref),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|buffer| buffer.id == id)
                .map(BlockDmaBufferRecord::object_ref),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|backend| backend.id == id)
                .map(FakeBlockBackendObjectRecord::object_ref),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(NetworkBenchmarkRecord::object_ref),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(BlockBenchmarkRecord::object_ref),
            ContractObjectKind::Hart => snapshot
                .harts
                .iter()
                .find(|hart| u64::from(hart.id) == id)
                .map(HartRecord::object_ref),
            ContractObjectKind::RunnableQueue => snapshot
                .runnable_queues
                .iter()
                .find(|queue| queue.id == id)
                .map(RunnableQueueRecord::object_ref),
            ContractObjectKind::ActivationContext => snapshot
                .activation_contexts
                .iter()
                .find(|context| context.id == id)
                .map(ActivationContextRecord::object_ref),
            ContractObjectKind::ActivationMigration => snapshot
                .activation_migrations
                .iter()
                .find(|migration| migration.id == id)
                .map(ActivationMigrationRecord::object_ref),
            ContractObjectKind::Preemption => snapshot
                .preemptions
                .iter()
                .find(|preemption| preemption.id == id)
                .map(PreemptionRecord::object_ref),
            ContractObjectKind::ActivationResume => snapshot
                .activation_resumes
                .iter()
                .find(|resume| resume.id == id)
                .map(ActivationResumeRecord::object_ref),
            ContractObjectKind::Store => {
                snapshot.stores.iter().find(|store| store.id == id).map(StoreRecord::object_ref)
            }
            ContractObjectKind::Activation => snapshot
                .runtime_activations
                .iter()
                .find(|activation| activation.id == id)
                .map(RuntimeActivationRecord::object_ref)
                .or_else(|| {
                    snapshot
                        .activations
                        .iter()
                        .find(|activation| activation.id == id)
                        .map(ActivationRecord::object_ref)
                }),
            ContractObjectKind::Trap => {
                snapshot.traps.iter().find(|trap| trap.id == id).map(TargetTrapRecord::object_ref)
            }
            ContractObjectKind::Hostcall => snapshot
                .hostcalls
                .iter()
                .find(|hostcall| hostcall.id == id)
                .map(HostcallTraceRecord::object_ref),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .map(CapabilityRecord::object_ref),
            ContractObjectKind::WaitToken => {
                snapshot.waits.iter().find(|wait| wait.id == id).map(WaitRecord::object_ref)
            }
            ContractObjectKind::CleanupTransaction => snapshot
                .cleanup_transactions
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(FaultCleanupTransaction::object_ref),
            ContractObjectKind::ExternalObject => snapshot
                .external_objects
                .iter()
                .find(|external| external.object.id == id)
                .map(|external| external.object),
            ContractObjectKind::IpiEvent
            | ContractObjectKind::RemotePark
            | ContractObjectKind::CrossHartSchedulerDecision
            | ContractObjectKind::SmpScalingBenchmark
            | ContractObjectKind::QueueObject
            | ContractObjectKind::DescriptorObject
            | ContractObjectKind::DmaBufferObject
            | ContractObjectKind::MmioRegionObject
            | ContractObjectKind::IrqLineObject
            | ContractObjectKind::IrqEvent
            | ContractObjectKind::DeviceCapability
            | ContractObjectKind::DriverStoreBinding
            | ContractObjectKind::IoWait
            | ContractObjectKind::IoFaultInjection
            | ContractObjectKind::IoValidationReport
            | ContractObjectKind::PacketBufferObject
            | ContractObjectKind::PacketQueueObject
            | ContractObjectKind::PacketDescriptorObject
            | ContractObjectKind::FakeNetBackendObject
            | ContractObjectKind::VirtioBlkBackendObject
            | ContractObjectKind::NetworkRxInterrupt
            | ContractObjectKind::NetworkRxWaitResolution
            | ContractObjectKind::NetworkTxCapabilityGate
            | ContractObjectKind::NetworkTxCompletion
            | ContractObjectKind::EndpointObject
            | ContractObjectKind::SocketOperation
            | ContractObjectKind::SocketWait
            | ContractObjectKind::NetworkBackpressure
            | ContractObjectKind::NetworkGenerationAudit
            | ContractObjectKind::NetworkFaultInjection
            | ContractObjectKind::NetworkRecoveryBenchmark
            | ContractObjectKind::BlockCompletionObject
            | ContractObjectKind::BlockReadPath
            | ContractObjectKind::BlockWritePath
            | ContractObjectKind::BlockPageObject
            | ContractObjectKind::BufferCacheObject
            | ContractObjectKind::FileObject
            | ContractObjectKind::DirectoryObject
            | ContractObjectKind::FatAdapterObject
            | ContractObjectKind::Ext4AdapterObject
            | ContractObjectKind::FileHandleCapability
            | ContractObjectKind::FsWait
            | ContractObjectKind::BlockDriverCleanup
            | ContractObjectKind::BlockRequestGenerationAudit
            | ContractObjectKind::BlockRecoveryBenchmark
            | ContractObjectKind::ActivationWait
            | ContractObjectKind::PreemptionLatencySample
            | ContractObjectKind::HartEventAttribution
            | ContractObjectKind::Resource
            | ContractObjectKind::FaultDomain
            | ContractObjectKind::MemoryObject
            | ContractObjectKind::GuestAddressSpace
            | ContractObjectKind::VmaRegion
            | ContractObjectKind::PageObject
            | ContractObjectKind::EventLog
            | ContractObjectKind::Tombstone => None,
        }
    }

    pub(super) fn is_graph_modeled_kind(kind: ContractObjectKind) -> bool {
        matches!(
            kind,
            ContractObjectKind::Artifact
                | ContractObjectKind::CodeObject
                | ContractObjectKind::TargetFeatureSet
                | ContractObjectKind::VectorState
                | ContractObjectKind::SimdFaultInjection
                | ContractObjectKind::SimdBenchmark
                | ContractObjectKind::SimdContextSwitchBenchmark
                | ContractObjectKind::FramebufferObject
                | ContractObjectKind::DisplayObject
                | ContractObjectKind::DisplayCapability
                | ContractObjectKind::FramebufferWindowLease
                | ContractObjectKind::FramebufferMapping
                | ContractObjectKind::FramebufferWrite
                | ContractObjectKind::FramebufferFlushRegion
                | ContractObjectKind::FramebufferDirtyRegion
                | ContractObjectKind::DisplayEventLog
                | ContractObjectKind::DisplayCleanup
                | ContractObjectKind::DisplaySnapshotBarrier
                | ContractObjectKind::DisplayPanicLastFrame
                | ContractObjectKind::FramebufferBenchmark
                | ContractObjectKind::IntegratedDisplaySchedulerLoad
                | ContractObjectKind::IntegratedSnapshotIoLeaseBarrier
                | ContractObjectKind::IntegratedSmpPreemptionCleanup
                | ContractObjectKind::IntegratedSmpNetworkFault
                | ContractObjectKind::IntegratedDiskPreemptFault
                | ContractObjectKind::IntegratedSimdMigration
                | ContractObjectKind::IntegratedNetworkDiskIo
                | ContractObjectKind::BlockPendingIoPolicy
                | ContractObjectKind::BlockWait
                | ContractObjectKind::BlockRequestObject
                | ContractObjectKind::BlockDeviceObject
                | ContractObjectKind::BlockRangeObject
                | ContractObjectKind::SmpSnapshotBarrier
                | ContractObjectKind::DeviceObject
                | ContractObjectKind::Task
                | ContractObjectKind::SchedulerDecision
                | ContractObjectKind::RunnableQueue
                | ContractObjectKind::Preemption
                | ContractObjectKind::ActivationResume
                | ContractObjectKind::Store
                | ContractObjectKind::Activation
                | ContractObjectKind::Trap
                | ContractObjectKind::Hostcall
                | ContractObjectKind::Capability
                | ContractObjectKind::WaitToken
                | ContractObjectKind::CleanupTransaction
                | ContractObjectKind::ExternalObject
        )
    }

    pub(super) fn has_declared_object(
        snapshot: &ContractGraphSnapshot,
        object: ContractObjectRef,
        class: Option<&str>,
    ) -> bool {
        snapshot.external_objects.iter().any(|declaration| {
            declaration.object == object && class.is_none_or(|class| declaration.class == class)
        })
    }

    pub(super) fn has_tombstone(
        snapshot: &ContractGraphSnapshot,
        object: ContractObjectRef,
    ) -> bool {
        snapshot.tombstones.iter().any(|tombstone| tombstone.object_ref() == object)
    }

    pub(super) fn inactive_reason(
        snapshot: &ContractGraphSnapshot,
        object: ContractObjectRef,
    ) -> Option<&'static str> {
        match object.kind {
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == object.id && store.generation == object.generation)
                .and_then(|store| {
                    (store.state == StoreState::Dead).then_some("live edge references dead store")
                }),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == object.id && code.generation == object.generation)
                .and_then(|code| {
                    matches!(
                        code.state,
                        CodeObjectState::Faulted
                            | CodeObjectState::Retired
                            | CodeObjectState::Unpublished
                    )
                    .then_some("live edge references inactive code object")
                }),
            ContractObjectKind::Activation => snapshot
                .activations
                .iter()
                .find(|activation| {
                    activation.id == object.id && activation.generation == object.generation
                })
                .and_then(|activation| {
                    (!Self::is_live_activation(activation))
                        .then_some("live edge references inactive activation")
                }),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| {
                    capability.id == object.id && capability.generation == object.generation
                })
                .and_then(|capability| {
                    capability
                        .revoked
                        .then_some("live edge references revoked capability")
                }),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == object.id && wait.generation == object.generation)
                .and_then(|wait| {
                    (wait.state != WaitState::Pending)
                        .then_some("live edge references inactive wait token")
                }),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| {
                    vector_state.id == object.id && vector_state.generation == object.generation
                })
                .and_then(|vector_state| {
                    (!vector_state.state.is_live_owned())
                        .then_some("live edge references inactive vector state")
                }),
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| {
                    framebuffer.id == object.id && framebuffer.generation == object.generation
                })
                .and_then(|framebuffer| {
                    (framebuffer.state != FramebufferObjectState::Registered)
                        .then_some("live edge references inactive framebuffer object")
                }),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == object.id && display.generation == object.generation)
                .and_then(|display| {
                    (display.state != DisplayObjectState::Registered)
                        .then_some("live edge references inactive display object")
                }),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| {
                    capability.id == object.id && capability.generation == object.generation
                })
                .and_then(|capability| {
                    (capability.state != DisplayCapabilityState::Active)
                        .then_some("live edge references inactive display capability")
                }),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == object.id && lease.generation == object.generation)
                .and_then(|lease| {
                    (lease.state != FramebufferWindowLeaseState::Active)
                        .then_some("live edge references inactive framebuffer window lease")
                }),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == object.id && mapping.generation == object.generation)
                .and_then(|mapping| {
                    (mapping.state != FramebufferMappingState::Active)
                        .then_some("live edge references inactive framebuffer mapping")
                }),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == object.id && write.generation == object.generation)
                .and_then(|write| {
                    (write.state != FramebufferWriteState::Applied)
                        .then_some("live edge references unapplied framebuffer write")
                }),
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == object.id && flush.generation == object.generation)
                .and_then(|flush| {
                    (flush.state != FramebufferFlushRegionState::Applied)
                        .then_some("live edge references unapplied framebuffer flush region")
                }),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == object.id && dirty.generation == object.generation)
                .and_then(|dirty| {
                    (dirty.state != FramebufferDirtyRegionState::Dirty)
                        .then_some("live edge references clean framebuffer dirty region")
                }),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == object.id && log.generation == object.generation)
                .and_then(|log| {
                    (log.state != DisplayEventLogState::Recorded)
                        .then_some("live edge references unrecorded display event log")
                }),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == object.id && cleanup.generation == object.generation)
                .and_then(|cleanup| {
                    (cleanup.state != DisplayCleanupState::Completed)
                        .then_some("live edge references incomplete display cleanup")
                }),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == object.id && barrier.generation == object.generation)
                .and_then(|barrier| {
                    (barrier.state != DisplaySnapshotBarrierState::Validated)
                        .then_some("live edge references unvalidated display snapshot barrier")
                }),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == object.id && frame.generation == object.generation)
                .and_then(|frame| {
                    (frame.state != DisplayPanicLastFrameState::Recorded)
                        .then_some("live edge references unrecorded display panic last-frame")
                }),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| {
                    benchmark.id == object.id && benchmark.generation == object.generation
                })
                .and_then(|benchmark| {
                    (benchmark.state != FramebufferBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded framebuffer benchmark")
                }),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSmpPreemptionCleanupState::Recorded).then_some(
                        "live edge references unrecorded integrated SMP/preemption/cleanup evidence",
                    )
                }),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSmpNetworkFaultState::Recorded).then_some(
                        "live edge references unrecorded integrated SMP/network-fault evidence",
                    )
                }),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDiskPreemptFaultState::Recorded).then_some(
                        "live edge references unrecorded integrated disk/preempt fault evidence",
                    )
                }),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSimdMigrationState::Recorded)
                        .then_some("live edge references unrecorded integrated SIMD migration evidence")
                }),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedNetworkDiskIoState::Recorded)
                        .then_some("live edge references unrecorded integrated network/disk IO evidence")
                }),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDisplaySchedulerLoadState::Recorded).then_some(
                        "live edge references unrecorded integrated display/scheduler load evidence",
                    )
                }),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSnapshotIoLeaseBarrierState::Recorded).then_some(
                        "live edge references unrecorded integrated snapshot/io lease barrier evidence",
                    )
                }),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedCodePublishSmpWorkloadState::Recorded).then_some(
                        "live edge references unrecorded integrated code publish/SMP workload evidence",
                    )
                }),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDisplayPanicState::Recorded)
                        .then_some("live edge references unrecorded integrated display panic evidence")
                }),
            ContractObjectKind::IntegratedOsctlTraceReplay => snapshot
                .integrated_osctl_trace_replays
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedOsctlTraceReplayState::Recorded).then_some(
                        "live edge references unrecorded integrated osctl trace replay evidence",
                    )
                }),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == object.id && barrier.generation == object.generation)
                .and_then(|barrier| {
                    (barrier.state != SmpCodePublishBarrierState::Validated)
                        .then_some("live edge references invalid SMP code publish barrier")
                }),
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| {
                    u64::from(task.id) == object.id && task.generation == object.generation
                })
                .and_then(|task| {
                    matches!(
                        task.state,
                        TaskState::Cancelled | TaskState::Faulted | TaskState::Exited
                    )
                    .then_some("live edge references inactive task")
                }),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| {
                    decision.id == object.id && decision.generation == object.generation
                })
                .and_then(|decision| {
                    (decision.state == SchedulerDecisionState::Dropped)
                        .then_some("live edge references dropped scheduler decision")
                }),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != SocketObjectState::Created)
                        .then_some("live edge references inactive socket object")
                }),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockRequestQueueState::Active)
                        .then_some("live edge references inactive block request queue")
                }),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockDmaBufferState::Bound)
                        .then_some("live edge references inactive block DMA buffer")
                }),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != NetworkBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded network benchmark evidence")
                }),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded block benchmark evidence")
                }),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != FakeBlockBackendObjectState::Bound)
                        .then_some("live edge references inactive fake block backend evidence")
                }),
            _ => None,
        }
    }

    pub(super) fn cleanup_effect_label_creates_live_ownership(label: &str) -> bool {
        matches!(
            label,
            "owns"
                | "owner"
                | "owner-store"
                | "bound-to"
                | "blocks-on"
                | "authorizes"
                | "live"
                | "live-owner"
        ) || label.starts_with("live:")
    }
}
