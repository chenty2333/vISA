use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct SemanticDomains {
    pub(crate) capability: CapabilityDomain,
    pub(crate) resource: ResourceDomain,
    pub(crate) device: DeviceDomain,
    pub(crate) network: NetworkDomain,
    pub(crate) block: BlockDomain,
    pub(crate) wait: WaitDomain,
    pub(crate) io: IoDomain,
    pub(crate) runtime: RuntimeDomain,
    pub(crate) lifecycle: LifecycleDomain,
    pub(crate) display: DisplayDomain,
    pub(crate) scheduler: SchedulerDomain,
    pub(crate) simd: SimdDomain,
    pub(crate) integrated: IntegratedDomain,
    pub(crate) process: ProcessDomain,
    #[allow(dead_code)]
    pub(crate) memory: MemoryDomain,
}

impl SemanticDomains {
    pub(crate) fn new() -> Self {
        Self {
            capability: CapabilityDomain::new(),
            resource: ResourceDomain::new(),
            device: DeviceDomain::new(),
            network: NetworkDomain::new(),
            block: BlockDomain::new(),
            wait: WaitDomain::new(),
            io: IoDomain::new(),
            runtime: RuntimeDomain::new(),
            lifecycle: LifecycleDomain::new(),
            display: DisplayDomain::new(),
            scheduler: SchedulerDomain::new(),
            simd: SimdDomain::new(),
            integrated: IntegratedDomain::new(),
            process: ProcessDomain::new(),
            memory: MemoryDomain::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CapabilityDomain {
    pub(crate) capabilities: CapabilityLedger,
}

impl CapabilityDomain {
    fn new() -> Self {
        Self { capabilities: CapabilityLedger::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResourceDomain {
    pub(crate) resources: Vec<ResourceRecord>,
    pub(crate) authority_bindings: Vec<AuthorityBindingRecord>,
    pub(crate) next_resource_id: ResourceId,
    pub(crate) next_authority_id: AuthorityId,
}

impl ResourceDomain {
    fn new() -> Self {
        Self {
            resources: Vec::new(),
            authority_bindings: Vec::new(),
            next_resource_id: 1,
            next_authority_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceDomain {
    pub(crate) device_objects: Vec<DeviceObjectRecord>,
    pub(crate) queue_objects: Vec<QueueObjectRecord>,
    pub(crate) descriptor_objects: Vec<DescriptorObjectRecord>,
    pub(crate) dma_buffer_objects: Vec<DmaBufferObjectRecord>,
    pub(crate) mmio_region_objects: Vec<MmioRegionObjectRecord>,
    pub(crate) irq_line_objects: Vec<IrqLineObjectRecord>,
    pub(crate) irq_events: Vec<IrqEventRecord>,
    pub(crate) device_capabilities: Vec<DeviceCapabilityRecord>,
    pub(crate) driver_store_bindings: Vec<DriverStoreBindingRecord>,
    pub(crate) next_device_object_id: DeviceObjectId,
    pub(crate) next_queue_object_id: QueueObjectId,
    pub(crate) next_descriptor_object_id: DescriptorObjectId,
    pub(crate) next_dma_buffer_object_id: DmaBufferObjectId,
    pub(crate) next_mmio_region_object_id: MmioRegionObjectId,
    pub(crate) next_irq_line_object_id: IrqLineObjectId,
    pub(crate) next_irq_event_id: IrqEventId,
    pub(crate) next_device_capability_id: DeviceCapabilityId,
    pub(crate) next_driver_store_binding_id: DriverStoreBindingId,
}

impl DeviceDomain {
    fn new() -> Self {
        Self {
            device_objects: Vec::new(),
            queue_objects: Vec::new(),
            descriptor_objects: Vec::new(),
            dma_buffer_objects: Vec::new(),
            mmio_region_objects: Vec::new(),
            irq_line_objects: Vec::new(),
            irq_events: Vec::new(),
            device_capabilities: Vec::new(),
            driver_store_bindings: Vec::new(),
            next_device_object_id: 1,
            next_queue_object_id: 1,
            next_descriptor_object_id: 1,
            next_dma_buffer_object_id: 1,
            next_mmio_region_object_id: 1,
            next_irq_line_object_id: 1,
            next_irq_event_id: 1,
            next_device_capability_id: 1,
            next_driver_store_binding_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NetworkDomain {
    pub(crate) packet_device_objects: Vec<PacketDeviceObjectRecord>,
    pub(crate) packet_buffer_objects: Vec<PacketBufferObjectRecord>,
    pub(crate) packet_queue_objects: Vec<PacketQueueObjectRecord>,
    pub(crate) packet_descriptors: Vec<PacketDescriptorObjectRecord>,
    pub(crate) fake_net_backends: Vec<FakeNetBackendObjectRecord>,
    pub(crate) virtio_net_backends: Vec<VirtioNetBackendObjectRecord>,
    pub(crate) network_rx_interrupts: Vec<NetworkRxInterruptRecord>,
    pub(crate) network_rx_wait_resolutions: Vec<NetworkRxWaitResolutionRecord>,
    pub(crate) network_tx_capability_gates: Vec<NetworkTxCapabilityGateRecord>,
    pub(crate) network_tx_completions: Vec<NetworkTxCompletionRecord>,
    pub(crate) network_stack_adapters: Vec<NetworkStackAdapterRecord>,
    pub(crate) socket_objects: Vec<SocketObjectRecord>,
    pub(crate) endpoint_objects: Vec<EndpointObjectRecord>,
    pub(crate) socket_operations: Vec<SocketOperationRecord>,
    pub(crate) socket_waits: Vec<SocketWaitRecord>,
    pub(crate) network_backpressures: Vec<NetworkBackpressureRecord>,
    pub(crate) network_benchmarks: Vec<NetworkBenchmarkRecord>,
    pub(crate) network_recovery_benchmarks: Vec<NetworkRecoveryBenchmarkRecord>,
    pub(crate) network_driver_cleanups: Vec<NetworkDriverCleanupRecord>,
    pub(crate) network_generation_audits: Vec<NetworkGenerationAuditRecord>,
    pub(crate) network_fault_injections: Vec<NetworkFaultInjectionRecord>,
    pub(crate) next_packet_device_object_id: PacketDeviceObjectId,
    pub(crate) next_packet_buffer_object_id: PacketBufferObjectId,
    pub(crate) next_packet_queue_object_id: PacketQueueObjectId,
    pub(crate) next_packet_descriptor_object_id: PacketDescriptorObjectId,
    pub(crate) next_fake_net_backend_object_id: FakeNetBackendObjectId,
    pub(crate) next_virtio_net_backend_object_id: VirtioNetBackendObjectId,
    pub(crate) next_network_rx_interrupt_id: NetworkRxInterruptId,
    pub(crate) next_network_rx_wait_resolution_id: NetworkRxWaitResolutionId,
    pub(crate) next_network_tx_capability_gate_id: NetworkTxCapabilityGateId,
    pub(crate) next_network_tx_completion_id: NetworkTxCompletionId,
    pub(crate) next_network_stack_adapter_id: NetworkStackAdapterId,
    pub(crate) next_socket_object_id: SocketObjectId,
    pub(crate) next_endpoint_object_id: EndpointObjectId,
    pub(crate) next_socket_operation_id: SocketOperationId,
    pub(crate) next_socket_wait_id: SocketWaitId,
    pub(crate) next_network_backpressure_id: NetworkBackpressureId,
    pub(crate) next_network_benchmark_id: NetworkBenchmarkId,
    pub(crate) next_network_recovery_benchmark_id: NetworkRecoveryBenchmarkId,
    pub(crate) next_network_driver_cleanup_id: NetworkDriverCleanupId,
    pub(crate) next_network_generation_audit_id: NetworkGenerationAuditId,
    pub(crate) next_network_fault_injection_id: NetworkFaultInjectionId,
}

impl NetworkDomain {
    fn new() -> Self {
        Self {
            packet_device_objects: Vec::new(),
            packet_buffer_objects: Vec::new(),
            packet_queue_objects: Vec::new(),
            packet_descriptors: Vec::new(),
            fake_net_backends: Vec::new(),
            virtio_net_backends: Vec::new(),
            network_rx_interrupts: Vec::new(),
            network_rx_wait_resolutions: Vec::new(),
            network_tx_capability_gates: Vec::new(),
            network_tx_completions: Vec::new(),
            network_stack_adapters: Vec::new(),
            socket_objects: Vec::new(),
            endpoint_objects: Vec::new(),
            socket_operations: Vec::new(),
            socket_waits: Vec::new(),
            network_backpressures: Vec::new(),
            network_benchmarks: Vec::new(),
            network_recovery_benchmarks: Vec::new(),
            network_driver_cleanups: Vec::new(),
            network_generation_audits: Vec::new(),
            network_fault_injections: Vec::new(),
            next_packet_device_object_id: 1,
            next_packet_buffer_object_id: 1,
            next_packet_queue_object_id: 1,
            next_packet_descriptor_object_id: 1,
            next_fake_net_backend_object_id: 1,
            next_virtio_net_backend_object_id: 1,
            next_network_rx_interrupt_id: 1,
            next_network_rx_wait_resolution_id: 1,
            next_network_tx_capability_gate_id: 1,
            next_network_tx_completion_id: 1,
            next_network_stack_adapter_id: 1,
            next_socket_object_id: 1,
            next_endpoint_object_id: 1,
            next_socket_operation_id: 1,
            next_socket_wait_id: 1,
            next_network_backpressure_id: 1,
            next_network_benchmark_id: 1,
            next_network_recovery_benchmark_id: 1,
            next_network_driver_cleanup_id: 1,
            next_network_generation_audit_id: 1,
            next_network_fault_injection_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlockDomain {
    pub(crate) block_device_objects: Vec<BlockDeviceObjectRecord>,
    pub(crate) block_range_objects: Vec<BlockRangeObjectRecord>,
    pub(crate) block_request_objects: Vec<BlockRequestObjectRecord>,
    pub(crate) block_completion_objects: Vec<BlockCompletionObjectRecord>,
    pub(crate) block_waits: Vec<BlockWaitRecord>,
    pub(crate) fake_block_backends: Vec<FakeBlockBackendObjectRecord>,
    pub(crate) virtio_blk_backends: Vec<VirtioBlkBackendObjectRecord>,
    pub(crate) block_read_paths: Vec<BlockReadPathRecord>,
    pub(crate) block_write_paths: Vec<BlockWritePathRecord>,
    pub(crate) block_request_queues: Vec<BlockRequestQueueRecord>,
    pub(crate) block_dma_buffers: Vec<BlockDmaBufferRecord>,
    pub(crate) block_page_objects: Vec<BlockPageObjectRecord>,
    pub(crate) buffer_cache_objects: Vec<BufferCacheObjectRecord>,
    pub(crate) file_objects: Vec<FileObjectRecord>,
    pub(crate) directory_objects: Vec<DirectoryObjectRecord>,
    pub(crate) fat_adapter_objects: Vec<FatAdapterObjectRecord>,
    pub(crate) ext4_adapter_objects: Vec<Ext4AdapterObjectRecord>,
    pub(crate) file_handle_capabilities: Vec<FileHandleCapabilityRecord>,
    pub(crate) fs_waits: Vec<FsWaitRecord>,
    pub(crate) block_driver_cleanups: Vec<BlockDriverCleanupRecord>,
    pub(crate) block_pending_io_policies: Vec<BlockPendingIoPolicyRecord>,
    pub(crate) block_request_generation_audits: Vec<BlockRequestGenerationAuditRecord>,
    pub(crate) block_benchmarks: Vec<BlockBenchmarkRecord>,
    pub(crate) block_recovery_benchmarks: Vec<BlockRecoveryBenchmarkRecord>,
    pub(crate) next_block_device_object_id: BlockDeviceObjectId,
    pub(crate) next_block_range_object_id: BlockRangeObjectId,
    pub(crate) next_block_request_object_id: BlockRequestObjectId,
    pub(crate) next_block_completion_object_id: BlockCompletionObjectId,
    pub(crate) next_block_wait_id: BlockWaitId,
    pub(crate) next_fake_block_backend_object_id: FakeBlockBackendObjectId,
    pub(crate) next_virtio_blk_backend_object_id: VirtioBlkBackendObjectId,
    pub(crate) next_block_read_path_id: BlockReadPathId,
    pub(crate) next_block_write_path_id: BlockWritePathId,
    pub(crate) next_block_request_queue_id: BlockRequestQueueId,
    pub(crate) next_block_dma_buffer_id: BlockDmaBufferId,
    pub(crate) next_block_page_object_id: BlockPageObjectId,
    pub(crate) next_buffer_cache_object_id: BufferCacheObjectId,
    pub(crate) next_file_object_id: FileObjectId,
    pub(crate) next_directory_object_id: DirectoryObjectId,
    pub(crate) next_fat_adapter_object_id: FatAdapterObjectId,
    pub(crate) next_ext4_adapter_object_id: Ext4AdapterObjectId,
    pub(crate) next_file_handle_capability_id: FileHandleCapabilityId,
    pub(crate) next_fs_wait_id: FsWaitId,
    pub(crate) next_block_driver_cleanup_id: BlockDriverCleanupId,
    pub(crate) next_block_pending_io_policy_id: BlockPendingIoPolicyId,
    pub(crate) next_block_request_generation_audit_id: BlockRequestGenerationAuditId,
    pub(crate) next_block_benchmark_id: BlockBenchmarkId,
    pub(crate) next_block_recovery_benchmark_id: BlockRecoveryBenchmarkId,
}

impl BlockDomain {
    fn new() -> Self {
        Self {
            block_device_objects: Vec::new(),
            block_range_objects: Vec::new(),
            block_request_objects: Vec::new(),
            block_completion_objects: Vec::new(),
            block_waits: Vec::new(),
            fake_block_backends: Vec::new(),
            virtio_blk_backends: Vec::new(),
            block_read_paths: Vec::new(),
            block_write_paths: Vec::new(),
            block_request_queues: Vec::new(),
            block_dma_buffers: Vec::new(),
            block_page_objects: Vec::new(),
            buffer_cache_objects: Vec::new(),
            file_objects: Vec::new(),
            directory_objects: Vec::new(),
            fat_adapter_objects: Vec::new(),
            ext4_adapter_objects: Vec::new(),
            file_handle_capabilities: Vec::new(),
            fs_waits: Vec::new(),
            block_driver_cleanups: Vec::new(),
            block_pending_io_policies: Vec::new(),
            block_request_generation_audits: Vec::new(),
            block_benchmarks: Vec::new(),
            block_recovery_benchmarks: Vec::new(),
            next_block_device_object_id: 1,
            next_block_range_object_id: 1,
            next_block_request_object_id: 1,
            next_block_completion_object_id: 1,
            next_block_wait_id: 1,
            next_fake_block_backend_object_id: 1,
            next_virtio_blk_backend_object_id: 1,
            next_block_read_path_id: 1,
            next_block_write_path_id: 1,
            next_block_request_queue_id: 1,
            next_block_dma_buffer_id: 1,
            next_block_page_object_id: 1,
            next_buffer_cache_object_id: 1,
            next_file_object_id: 1,
            next_directory_object_id: 1,
            next_fat_adapter_object_id: 1,
            next_ext4_adapter_object_id: 1,
            next_file_handle_capability_id: 1,
            next_fs_wait_id: 1,
            next_block_driver_cleanup_id: 1,
            next_block_pending_io_policy_id: 1,
            next_block_request_generation_audit_id: 1,
            next_block_benchmark_id: 1,
            next_block_recovery_benchmark_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WaitDomain {
    pub(crate) waits: Vec<WaitRecord>,
}

impl WaitDomain {
    fn new() -> Self {
        Self { waits: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IoDomain {
    pub(crate) io_waits: Vec<IoWaitRecord>,
    pub(crate) io_cleanups: Vec<IoCleanupRecord>,
    pub(crate) io_fault_injections: Vec<IoFaultInjectionRecord>,
    pub(crate) io_validation_reports: Vec<IoValidationReportRecord>,
    pub(crate) next_io_wait_id: IoWaitId,
    pub(crate) next_io_cleanup_id: IoCleanupId,
    pub(crate) next_io_fault_injection_id: IoFaultInjectionId,
    pub(crate) next_io_validation_report_id: IoValidationReportId,
}

impl IoDomain {
    fn new() -> Self {
        Self {
            io_waits: Vec::new(),
            io_cleanups: Vec::new(),
            io_fault_injections: Vec::new(),
            io_validation_reports: Vec::new(),
            next_io_wait_id: 1,
            next_io_cleanup_id: 1,
            next_io_fault_injection_id: 1,
            next_io_validation_report_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LifecycleDomain {
    pub(crate) fault_domains: Vec<FaultDomainRecord>,
    pub(crate) stores: Vec<StoreRecord>,
    pub(crate) transactions: Vec<SemanticTransactionRecord>,
    pub(crate) fast_path_plans: Vec<FastPathPlanRecord>,
    pub(crate) next_fault_domain_id: FaultDomainId,
    pub(crate) next_store_id: StoreId,
    pub(crate) next_transaction_id: TransactionId,
    pub(crate) next_plan_id: PlanId,
}

impl LifecycleDomain {
    fn new() -> Self {
        Self {
            fault_domains: Vec::new(),
            stores: Vec::new(),
            transactions: Vec::new(),
            fast_path_plans: Vec::new(),
            next_fault_domain_id: 1,
            next_store_id: 1,
            next_transaction_id: 1,
            next_plan_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DisplayDomain {
    pub(crate) framebuffer_objects: Vec<FramebufferObjectRecord>,
    pub(crate) display_objects: Vec<DisplayObjectRecord>,
    pub(crate) display_capabilities: Vec<DisplayCapabilityRecord>,
    pub(crate) framebuffer_window_leases: Vec<FramebufferWindowLeaseRecord>,
    pub(crate) framebuffer_mappings: Vec<FramebufferMappingRecord>,
    pub(crate) framebuffer_writes: Vec<FramebufferWriteRecord>,
    pub(crate) framebuffer_flush_regions: Vec<FramebufferFlushRegionRecord>,
    pub(crate) framebuffer_dirty_regions: Vec<FramebufferDirtyRegionRecord>,
    pub(crate) display_event_logs: Vec<DisplayEventLogRecord>,
    pub(crate) display_cleanups: Vec<DisplayCleanupRecord>,
    pub(crate) display_snapshot_barriers: Vec<DisplaySnapshotBarrierRecord>,
    pub(crate) display_panic_last_frames: Vec<DisplayPanicLastFrameRecord>,
    pub(crate) framebuffer_benchmarks: Vec<FramebufferBenchmarkRecord>,
    pub(crate) next_framebuffer_object_id: FramebufferObjectId,
    pub(crate) next_display_object_id: DisplayObjectId,
    pub(crate) next_display_capability_id: DisplayCapabilityId,
    pub(crate) next_framebuffer_window_lease_id: FramebufferWindowLeaseId,
    pub(crate) next_framebuffer_mapping_id: FramebufferMappingId,
    pub(crate) next_framebuffer_write_id: FramebufferWriteId,
    pub(crate) next_framebuffer_flush_region_id: FramebufferFlushRegionId,
    pub(crate) next_framebuffer_dirty_region_id: FramebufferDirtyRegionId,
    pub(crate) next_display_event_log_id: DisplayEventLogId,
    pub(crate) next_display_cleanup_id: DisplayCleanupId,
    pub(crate) next_display_snapshot_barrier_id: DisplaySnapshotBarrierId,
    pub(crate) next_display_panic_last_frame_id: DisplayPanicLastFrameId,
    pub(crate) next_framebuffer_benchmark_id: FramebufferBenchmarkId,
}

impl DisplayDomain {
    fn new() -> Self {
        Self {
            framebuffer_objects: Vec::new(),
            display_objects: Vec::new(),
            display_capabilities: Vec::new(),
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
            next_framebuffer_object_id: 1,
            next_display_object_id: 1,
            next_display_capability_id: 1,
            next_framebuffer_window_lease_id: 1,
            next_framebuffer_mapping_id: 1,
            next_framebuffer_write_id: 1,
            next_framebuffer_flush_region_id: 1,
            next_framebuffer_dirty_region_id: 1,
            next_display_event_log_id: 1,
            next_display_cleanup_id: 1,
            next_display_snapshot_barrier_id: 1,
            next_display_panic_last_frame_id: 1,
            next_framebuffer_benchmark_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SchedulerDomain {
    pub(crate) harts: Vec<HartRecord>,
    pub(crate) tasks: Vec<TaskRecord>,
    pub(crate) runtime_activations: Vec<RuntimeActivationRecord>,
    pub(crate) runnable_queues: Vec<RunnableQueueRecord>,
    pub(crate) activation_contexts: Vec<ActivationContextRecord>,
    pub(crate) saved_contexts: Vec<SavedContextRecord>,
    pub(crate) timer_interrupts: Vec<TimerInterruptRecord>,
    pub(crate) ipi_events: Vec<IpiEventRecord>,
    pub(crate) remote_preempts: Vec<RemotePreemptRecord>,
    pub(crate) remote_parks: Vec<RemoteParkRecord>,
    pub(crate) preemptions: Vec<PreemptionRecord>,
    pub(crate) scheduler_decisions: Vec<SchedulerDecisionRecord>,
    pub(crate) cross_hart_scheduler_decisions: Vec<CrossHartSchedulerDecisionRecord>,
    pub(crate) activation_migrations: Vec<ActivationMigrationRecord>,
    pub(crate) smp_safe_points: Vec<SmpSafePointRecord>,
    pub(crate) stop_the_world_rendezvous: Vec<StopTheWorldRendezvousRecord>,
    pub(crate) smp_code_publish_barriers: Vec<SmpCodePublishBarrierRecord>,
    pub(crate) smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceRecord>,
    pub(crate) smp_snapshot_barriers: Vec<SmpSnapshotBarrierRecord>,
    pub(crate) smp_stress_runs: Vec<SmpStressRunRecord>,
    pub(crate) smp_scaling_benchmarks: Vec<SmpScalingBenchmarkRecord>,
    pub(crate) activation_resumes: Vec<ActivationResumeRecord>,
    pub(crate) activation_waits: Vec<ActivationWaitRecord>,
    pub(crate) activation_cleanups: Vec<ActivationCleanupRecord>,
    pub(crate) preemption_latency_samples: Vec<PreemptionLatencySampleRecord>,
    pub(crate) hart_event_attributions: Vec<HartEventAttributionRecord>,
    pub(crate) next_runtime_activation_id: ActivationId,
    pub(crate) next_runnable_queue_id: RunnableQueueId,
    pub(crate) next_activation_context_id: ActivationContextId,
    pub(crate) next_saved_context_id: SavedContextId,
    pub(crate) next_timer_interrupt_id: TimerInterruptId,
    pub(crate) next_ipi_event_id: IpiEventId,
    pub(crate) next_remote_preempt_id: RemotePreemptId,
    pub(crate) next_remote_park_id: RemoteParkId,
    pub(crate) next_preemption_id: PreemptionId,
    pub(crate) next_scheduler_decision_id: SchedulerDecisionId,
    pub(crate) next_cross_hart_scheduler_decision_id: CrossHartSchedulerDecisionId,
    pub(crate) next_activation_migration_id: ActivationMigrationId,
    pub(crate) next_smp_safe_point_id: SmpSafePointId,
    pub(crate) next_stop_the_world_rendezvous_id: StopTheWorldRendezvousId,
    pub(crate) next_smp_code_publish_barrier_id: SmpCodePublishBarrierId,
    pub(crate) next_smp_cleanup_quiescence_id: SmpCleanupQuiescenceId,
    pub(crate) next_smp_snapshot_barrier_id: SmpSnapshotBarrierId,
    pub(crate) next_smp_stress_run_id: SmpStressRunId,
    pub(crate) next_smp_scaling_benchmark_id: SmpScalingBenchmarkId,
    pub(crate) next_activation_resume_id: ActivationResumeId,
    pub(crate) next_activation_wait_id: ActivationWaitId,
    pub(crate) next_activation_cleanup_id: ActivationCleanupId,
    pub(crate) next_preemption_latency_sample_id: PreemptionLatencySampleId,
    pub(crate) next_hart_event_attribution_id: HartEventAttributionId,
}

impl SchedulerDomain {
    fn new() -> Self {
        Self {
            harts: Vec::new(),
            tasks: Vec::new(),
            runtime_activations: Vec::new(),
            runnable_queues: Vec::new(),
            activation_contexts: Vec::new(),
            saved_contexts: Vec::new(),
            timer_interrupts: Vec::new(),
            ipi_events: Vec::new(),
            remote_preempts: Vec::new(),
            remote_parks: Vec::new(),
            preemptions: Vec::new(),
            scheduler_decisions: Vec::new(),
            cross_hart_scheduler_decisions: Vec::new(),
            activation_migrations: Vec::new(),
            smp_safe_points: Vec::new(),
            stop_the_world_rendezvous: Vec::new(),
            smp_code_publish_barriers: Vec::new(),
            smp_cleanup_quiescence: Vec::new(),
            smp_snapshot_barriers: Vec::new(),
            smp_stress_runs: Vec::new(),
            smp_scaling_benchmarks: Vec::new(),
            activation_resumes: Vec::new(),
            activation_waits: Vec::new(),
            activation_cleanups: Vec::new(),
            preemption_latency_samples: Vec::new(),
            hart_event_attributions: Vec::new(),
            next_runtime_activation_id: 1,
            next_runnable_queue_id: 1,
            next_activation_context_id: 1,
            next_saved_context_id: 1,
            next_timer_interrupt_id: 1,
            next_ipi_event_id: 1,
            next_remote_preempt_id: 1,
            next_remote_park_id: 1,
            next_preemption_id: 1,
            next_scheduler_decision_id: 1,
            next_cross_hart_scheduler_decision_id: 1,
            next_activation_migration_id: 1,
            next_smp_safe_point_id: 1,
            next_stop_the_world_rendezvous_id: 1,
            next_smp_code_publish_barrier_id: 1,
            next_smp_cleanup_quiescence_id: 1,
            next_smp_snapshot_barrier_id: 1,
            next_smp_stress_run_id: 1,
            next_smp_scaling_benchmark_id: 1,
            next_activation_resume_id: 1,
            next_activation_wait_id: 1,
            next_activation_cleanup_id: 1,
            next_preemption_latency_sample_id: 1,
            next_hart_event_attribution_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SimdDomain {
    pub(crate) target_feature_sets: Vec<TargetFeatureSetRecord>,
    pub(crate) vector_states: Vec<VectorStateRecord>,
    pub(crate) simd_fault_injections: Vec<SimdFaultInjectionRecord>,
    pub(crate) simd_benchmarks: Vec<SimdBenchmarkRecord>,
    pub(crate) simd_context_switch_benchmarks: Vec<SimdContextSwitchBenchmarkRecord>,
    pub(crate) next_target_feature_set_id: TargetFeatureSetId,
    pub(crate) next_vector_state_id: VectorStateId,
    pub(crate) next_simd_fault_injection_id: SimdFaultInjectionId,
    pub(crate) next_simd_benchmark_id: SimdBenchmarkId,
    pub(crate) next_simd_context_switch_benchmark_id: SimdContextSwitchBenchmarkId,
}

impl SimdDomain {
    fn new() -> Self {
        Self {
            target_feature_sets: Vec::new(),
            vector_states: Vec::new(),
            simd_fault_injections: Vec::new(),
            simd_benchmarks: Vec::new(),
            simd_context_switch_benchmarks: Vec::new(),
            next_target_feature_set_id: 1,
            next_vector_state_id: 1,
            next_simd_fault_injection_id: 1,
            next_simd_benchmark_id: 1,
            next_simd_context_switch_benchmark_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IntegratedDomain {
    pub(crate) integrated_smp_preemption_cleanups: Vec<IntegratedSmpPreemptionCleanupRecord>,
    pub(crate) integrated_smp_network_faults: Vec<IntegratedSmpNetworkFaultRecord>,
    pub(crate) integrated_disk_preempt_faults: Vec<IntegratedDiskPreemptFaultRecord>,
    pub(crate) integrated_simd_migrations: Vec<IntegratedSimdMigrationRecord>,
    pub(crate) integrated_network_disk_ios: Vec<IntegratedNetworkDiskIoRecord>,
    pub(crate) integrated_display_scheduler_loads: Vec<IntegratedDisplaySchedulerLoadRecord>,
    pub(crate) integrated_snapshot_io_lease_barriers: Vec<IntegratedSnapshotIoLeaseBarrierRecord>,
    pub(crate) integrated_code_publish_smp_workloads: Vec<IntegratedCodePublishSmpWorkloadRecord>,
    pub(crate) integrated_display_panics: Vec<IntegratedDisplayPanicRecord>,
    pub(crate) integrated_osctl_trace_replays: Vec<IntegratedOsctlTraceReplayRecord>,
    pub(crate) next_integrated_smp_preemption_cleanup_id: IntegratedSmpPreemptionCleanupId,
    pub(crate) next_integrated_smp_network_fault_id: IntegratedSmpNetworkFaultId,
    pub(crate) next_integrated_disk_preempt_fault_id: IntegratedDiskPreemptFaultId,
    pub(crate) next_integrated_simd_migration_id: IntegratedSimdMigrationId,
    pub(crate) next_integrated_network_disk_io_id: IntegratedNetworkDiskIoId,
    pub(crate) next_integrated_display_scheduler_load_id: IntegratedDisplaySchedulerLoadId,
    pub(crate) next_integrated_snapshot_io_lease_barrier_id: IntegratedSnapshotIoLeaseBarrierId,
    pub(crate) next_integrated_code_publish_smp_workload_id: IntegratedCodePublishSmpWorkloadId,
    pub(crate) next_integrated_display_panic_id: IntegratedDisplayPanicId,
    pub(crate) next_integrated_osctl_trace_replay_id: IntegratedOsctlTraceReplayId,
}

impl IntegratedDomain {
    fn new() -> Self {
        Self {
            integrated_smp_preemption_cleanups: Vec::new(),
            integrated_smp_network_faults: Vec::new(),
            integrated_disk_preempt_faults: Vec::new(),
            integrated_simd_migrations: Vec::new(),
            integrated_network_disk_ios: Vec::new(),
            integrated_display_scheduler_loads: Vec::new(),
            integrated_snapshot_io_lease_barriers: Vec::new(),
            integrated_code_publish_smp_workloads: Vec::new(),
            integrated_display_panics: Vec::new(),
            integrated_osctl_trace_replays: Vec::new(),
            next_integrated_smp_preemption_cleanup_id: 1,
            next_integrated_smp_network_fault_id: 1,
            next_integrated_disk_preempt_fault_id: 1,
            next_integrated_simd_migration_id: 1,
            next_integrated_network_disk_io_id: 1,
            next_integrated_display_scheduler_load_id: 1,
            next_integrated_snapshot_io_lease_barrier_id: 1,
            next_integrated_code_publish_smp_workload_id: 1,
            next_integrated_display_panic_id: 1,
            next_integrated_osctl_trace_replay_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeDomain {
    pub(crate) boundaries: Vec<BoundaryRecord>,
    pub(crate) artifact_verifications: Vec<ArtifactVerificationRecord>,
    pub(crate) store_activations: Vec<StoreActivationRecord>,
    pub(crate) next_boundary_id: BoundaryId,
    pub(crate) next_artifact_id: ArtifactId,
    pub(crate) next_activation_id: StoreActivationId,
}

impl RuntimeDomain {
    fn new() -> Self {
        Self {
            boundaries: Vec::new(),
            artifact_verifications: Vec::new(),
            store_activations: Vec::new(),
            next_boundary_id: 1,
            next_artifact_id: 1,
            next_activation_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessDomain {
    pub(crate) processes: Vec<ProcessRecord>,
    pub(crate) threads: Vec<ThreadRecord>,
    pub(crate) thread_groups: Vec<ThreadGroupRecord>,
    pub(crate) fd_tables: Vec<FdTableRecord>,
    pub(crate) open_file_descriptions: Vec<OpenFileDescriptionRecord>,
    pub(crate) credentials: Vec<CredentialRecord>,
    pub(crate) credential_transitions: Vec<CredentialTransitionRecord>,
    pub(crate) next_process_id: ProcessId,
    pub(crate) next_thread_id: ThreadId,
    pub(crate) next_thread_group_id: ThreadGroupId,
    pub(crate) next_fd_table_id: FdTableId,
    pub(crate) next_open_file_description_id: OpenFileDescriptionId,
    pub(crate) next_credential_id: CredentialId,
    pub(crate) next_credential_transition_id: CredentialTransitionId,
}

impl ProcessDomain {
    fn new() -> Self {
        Self {
            processes: Vec::new(),
            threads: Vec::new(),
            thread_groups: Vec::new(),
            fd_tables: Vec::new(),
            open_file_descriptions: Vec::new(),
            credentials: Vec::new(),
            credential_transitions: Vec::new(),
            next_process_id: 1,
            next_thread_id: 1,
            next_thread_group_id: 1,
            next_fd_table_id: 1,
            next_open_file_description_id: 1,
            next_credential_id: 1,
            next_credential_transition_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryDomain;

impl MemoryDomain {
    fn new() -> Self {
        Self
    }
}
