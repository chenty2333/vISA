use serde::{Deserialize, Serialize};

use crate::{boundary::*, target_runtime::*, views_events::*};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationPackageManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub package_format: String,
    pub package_id: String,
    pub source: MigrationHostManifest,
    pub target: MigrationTargetManifest,
    pub required_artifact_profile: RequiredArtifactProfileManifest,
    pub guest: GuestStateManifest,
    pub semantic: SemanticSnapshotManifest,
    pub logical_capabilities: Vec<MigrationCapabilityManifest>,
    pub substrate_boundary: SubstrateBoundaryManifest,
    pub not_migrated: Vec<String>,
    #[serde(default)]
    pub contract_core_evidence: Option<ContractCoreEvidenceManifest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationHostManifest {
    pub arch: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationTargetManifest {
    pub arch_requirement: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequiredArtifactProfileManifest {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub network_contract_version: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuestStateManifest {
    pub canonical_isa: String,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SemanticSnapshotManifest {
    pub barrier_id: u64,
    pub event_log_cursor: u64,
    #[serde(default)]
    pub roots: SemanticRootSetManifest,
    #[serde(default)]
    pub pending_wait_count: usize,
    #[serde(default)]
    pub hart_count: usize,
    pub task_count: usize,
    #[serde(default)]
    pub task_record_count: usize,
    #[serde(default)]
    pub runtime_activation_count: usize,
    #[serde(default)]
    pub runnable_queue_count: usize,
    #[serde(default)]
    pub activation_context_count: usize,
    #[serde(default)]
    pub saved_context_count: usize,
    #[serde(default)]
    pub timer_interrupt_count: usize,
    #[serde(default)]
    pub ipi_event_count: usize,
    #[serde(default)]
    pub remote_preempt_count: usize,
    #[serde(default)]
    pub remote_park_count: usize,
    #[serde(default)]
    pub preemption_count: usize,
    #[serde(default)]
    pub scheduler_decision_count: usize,
    #[serde(default)]
    pub cross_hart_scheduler_decision_count: usize,
    #[serde(default)]
    pub activation_migration_count: usize,
    #[serde(default)]
    pub smp_safe_point_count: usize,
    #[serde(default)]
    pub stop_the_world_rendezvous_count: usize,
    #[serde(default)]
    pub smp_code_publish_barrier_count: usize,
    #[serde(default)]
    pub smp_cleanup_quiescence_count: usize,
    #[serde(default)]
    pub smp_snapshot_barrier_count: usize,
    #[serde(default)]
    pub smp_stress_run_count: usize,
    #[serde(default)]
    pub smp_scaling_benchmark_count: usize,
    #[serde(default)]
    pub integrated_smp_preemption_cleanup_count: usize,
    #[serde(default)]
    pub integrated_smp_network_fault_count: usize,
    #[serde(default)]
    pub integrated_disk_preempt_fault_count: usize,
    #[serde(default)]
    pub integrated_simd_migration_count: usize,
    #[serde(default)]
    pub integrated_network_disk_io_count: usize,
    #[serde(default)]
    pub integrated_display_scheduler_load_count: usize,
    #[serde(default)]
    pub integrated_snapshot_io_lease_barrier_count: usize,
    #[serde(default)]
    pub integrated_code_publish_smp_workload_count: usize,
    #[serde(default)]
    pub integrated_display_panic_count: usize,
    #[serde(default)]
    pub integrated_osctl_trace_replay_count: usize,
    #[serde(default)]
    pub device_object_count: usize,
    #[serde(default)]
    pub queue_object_count: usize,
    #[serde(default)]
    pub descriptor_object_count: usize,
    #[serde(default)]
    pub dma_buffer_object_count: usize,
    #[serde(default)]
    pub mmio_region_object_count: usize,
    #[serde(default)]
    pub irq_line_object_count: usize,
    #[serde(default)]
    pub irq_event_count: usize,
    #[serde(default)]
    pub device_capability_count: usize,
    #[serde(default)]
    pub driver_store_binding_count: usize,
    #[serde(default)]
    pub io_wait_count: usize,
    #[serde(default)]
    pub io_cleanup_count: usize,
    #[serde(default)]
    pub io_fault_injection_count: usize,
    #[serde(default)]
    pub io_validation_report_count: usize,
    #[serde(default)]
    pub packet_device_object_count: usize,
    #[serde(default)]
    pub packet_buffer_object_count: usize,
    #[serde(default)]
    pub packet_queue_object_count: usize,
    #[serde(default)]
    pub packet_descriptor_object_count: usize,
    #[serde(default)]
    pub fake_net_backend_object_count: usize,
    #[serde(default)]
    pub virtio_net_backend_object_count: usize,
    #[serde(default)]
    pub network_rx_interrupt_count: usize,
    #[serde(default)]
    pub network_rx_wait_resolution_count: usize,
    #[serde(default)]
    pub network_tx_capability_gate_count: usize,
    #[serde(default)]
    pub network_tx_completion_count: usize,
    #[serde(default)]
    pub network_stack_adapter_count: usize,
    #[serde(default)]
    pub socket_object_count: usize,
    #[serde(default)]
    pub endpoint_object_count: usize,
    #[serde(default)]
    pub socket_operation_count: usize,
    #[serde(default)]
    pub socket_wait_count: usize,
    #[serde(default)]
    pub network_backpressure_count: usize,
    #[serde(default)]
    pub network_driver_cleanup_count: usize,
    #[serde(default)]
    pub network_generation_audit_count: usize,
    #[serde(default)]
    pub network_fault_injection_count: usize,
    #[serde(default)]
    pub network_benchmark_count: usize,
    #[serde(default)]
    pub network_recovery_benchmark_count: usize,
    #[serde(default)]
    pub block_device_object_count: usize,
    #[serde(default)]
    pub block_range_object_count: usize,
    #[serde(default)]
    pub block_request_object_count: usize,
    #[serde(default)]
    pub block_completion_object_count: usize,
    #[serde(default)]
    pub block_wait_count: usize,
    #[serde(default)]
    pub fake_block_backend_object_count: usize,
    #[serde(default)]
    pub virtio_blk_backend_object_count: usize,
    #[serde(default)]
    pub block_read_path_count: usize,
    #[serde(default)]
    pub block_write_path_count: usize,
    #[serde(default)]
    pub block_request_queue_count: usize,
    #[serde(default)]
    pub block_dma_buffer_count: usize,
    #[serde(default)]
    pub block_page_object_count: usize,
    #[serde(default)]
    pub guest_address_space_count: usize,
    #[serde(default)]
    pub vma_region_count: usize,
    #[serde(default)]
    pub page_object_count: usize,
    #[serde(default)]
    pub guest_memory_fault_count: usize,
    #[serde(default)]
    pub guest_memory_operation_count: usize,
    #[serde(default)]
    pub buffer_cache_object_count: usize,
    #[serde(default)]
    pub file_object_count: usize,
    #[serde(default)]
    pub directory_object_count: usize,
    #[serde(default)]
    pub fat_adapter_object_count: usize,
    #[serde(default)]
    pub ext4_adapter_object_count: usize,
    #[serde(default)]
    pub file_handle_capability_count: usize,
    #[serde(default)]
    pub fs_wait_count: usize,
    #[serde(default)]
    pub block_driver_cleanup_count: usize,
    #[serde(default)]
    pub block_pending_io_policy_count: usize,
    #[serde(default)]
    pub block_request_generation_audit_count: usize,
    #[serde(default)]
    pub block_benchmark_count: usize,
    #[serde(default)]
    pub block_recovery_benchmark_count: usize,
    #[serde(default)]
    pub target_feature_set_count: usize,
    #[serde(default)]
    pub vector_state_count: usize,
    #[serde(default)]
    pub simd_fault_injection_count: usize,
    #[serde(default)]
    pub simd_benchmark_count: usize,
    #[serde(default)]
    pub simd_context_switch_benchmark_count: usize,
    #[serde(default)]
    pub framebuffer_object_count: usize,
    #[serde(default)]
    pub display_object_count: usize,
    #[serde(default)]
    pub display_capability_count: usize,
    #[serde(default)]
    pub framebuffer_window_lease_count: usize,
    #[serde(default)]
    pub framebuffer_mapping_count: usize,
    #[serde(default)]
    pub framebuffer_write_count: usize,
    #[serde(default)]
    pub framebuffer_flush_region_count: usize,
    #[serde(default)]
    pub framebuffer_dirty_region_count: usize,
    #[serde(default)]
    pub display_event_log_count: usize,
    #[serde(default)]
    pub display_cleanup_count: usize,
    #[serde(default)]
    pub display_snapshot_barrier_count: usize,
    #[serde(default)]
    pub display_panic_last_frame_count: usize,
    #[serde(default)]
    pub framebuffer_benchmark_count: usize,
    #[serde(default)]
    pub activation_resume_count: usize,
    #[serde(default)]
    pub activation_wait_count: usize,
    #[serde(default)]
    pub activation_cleanup_count: usize,
    #[serde(default)]
    pub preemption_latency_sample_count: usize,
    #[serde(default)]
    pub hart_event_attribution_count: usize,
    pub resource_count: usize,
    #[serde(default)]
    pub authority_count: usize,
    #[serde(default)]
    pub active_authority_count: usize,
    pub wait_token_count: usize,
    #[serde(default)]
    pub wait_record_count: usize,
    pub capability_count: usize,
    #[serde(default)]
    pub capability_record_count: usize,
    pub fault_domain_count: usize,
    #[serde(default)]
    pub store_count: usize,
    #[serde(default)]
    pub store_record_count: usize,
    #[serde(default)]
    pub transaction_count: usize,
    #[serde(default)]
    pub active_transaction_count: usize,
    #[serde(default)]
    pub fast_path_plan_count: usize,
    #[serde(default)]
    pub active_fast_path_plan_count: usize,
    #[serde(default)]
    pub boundary_count: usize,
    #[serde(default)]
    pub artifact_verification_count: usize,
    #[serde(default)]
    pub store_activation_count: usize,
    #[serde(default)]
    pub executor_transition_count: usize,
    #[serde(default)]
    pub target_artifact_count: usize,
    #[serde(default)]
    pub code_object_count: usize,
    #[serde(default)]
    pub activation_record_count: usize,
    #[serde(default)]
    pub trap_record_count: usize,
    #[serde(default)]
    pub hostcall_trace_count: usize,
    #[serde(default)]
    pub migration_object_count: usize,
    #[serde(default)]
    pub tombstone_count: usize,
    #[serde(default)]
    pub contract_violation_count: usize,
    #[serde(default)]
    pub cleanup_transaction_count: usize,
    #[serde(default)]
    pub memory_policy_count: usize,
    #[serde(default)]
    pub snapshot_validation_violation_count: usize,
    #[serde(default)]
    pub replay_validation_violation_count: usize,
    #[serde(default)]
    pub substrate_event_count: usize,
    #[serde(default)]
    pub profile_gate_event_count: usize,
    #[serde(default)]
    pub command_result_count: usize,
    #[serde(default)]
    pub interface_event_count: usize,
    #[serde(default)]
    pub target_artifacts: Vec<TargetArtifactImageManifest>,
    #[serde(default)]
    pub hart_records: Vec<HartRecordManifest>,
    #[serde(default)]
    pub task_records: Vec<TaskRecordManifest>,
    #[serde(default)]
    pub runtime_activation_records: Vec<RuntimeActivationRecordManifest>,
    #[serde(default)]
    pub runnable_queues: Vec<RunnableQueueManifest>,
    #[serde(default)]
    pub activation_contexts: Vec<ActivationContextManifest>,
    #[serde(default)]
    pub saved_contexts: Vec<SavedContextManifest>,
    #[serde(default)]
    pub timer_interrupts: Vec<TimerInterruptManifest>,
    #[serde(default)]
    pub ipi_events: Vec<IpiEventManifest>,
    #[serde(default)]
    pub remote_preempts: Vec<RemotePreemptManifest>,
    #[serde(default)]
    pub remote_parks: Vec<RemoteParkManifest>,
    #[serde(default)]
    pub preemptions: Vec<PreemptionManifest>,
    #[serde(default)]
    pub scheduler_decisions: Vec<SchedulerDecisionManifest>,
    #[serde(default)]
    pub cross_hart_scheduler_decisions: Vec<CrossHartSchedulerDecisionManifest>,
    #[serde(default)]
    pub activation_migrations: Vec<ActivationMigrationManifest>,
    #[serde(default)]
    pub smp_safe_points: Vec<SmpSafePointManifest>,
    #[serde(default)]
    pub stop_the_world_rendezvous: Vec<StopTheWorldRendezvousManifest>,
    #[serde(default)]
    pub smp_code_publish_barriers: Vec<SmpCodePublishBarrierManifest>,
    #[serde(default)]
    pub smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceManifest>,
    #[serde(default)]
    pub smp_snapshot_barriers: Vec<SmpSnapshotBarrierManifest>,
    #[serde(default)]
    pub smp_stress_runs: Vec<SmpStressRunManifest>,
    #[serde(default)]
    pub smp_scaling_benchmarks: Vec<SmpScalingBenchmarkManifest>,
    #[serde(default)]
    pub integrated_smp_preemption_cleanups: Vec<IntegratedSmpPreemptionCleanupManifest>,
    #[serde(default)]
    pub integrated_smp_network_faults: Vec<IntegratedSmpNetworkFaultManifest>,
    #[serde(default)]
    pub integrated_disk_preempt_faults: Vec<IntegratedDiskPreemptFaultManifest>,
    #[serde(default)]
    pub integrated_simd_migrations: Vec<IntegratedSimdMigrationManifest>,
    #[serde(default)]
    pub integrated_network_disk_ios: Vec<IntegratedNetworkDiskIoManifest>,
    #[serde(default)]
    pub integrated_display_scheduler_loads: Vec<IntegratedDisplaySchedulerLoadManifest>,
    #[serde(default)]
    pub integrated_snapshot_io_lease_barriers: Vec<IntegratedSnapshotIoLeaseBarrierManifest>,
    #[serde(default)]
    pub integrated_code_publish_smp_workloads: Vec<IntegratedCodePublishSmpWorkloadManifest>,
    #[serde(default)]
    pub integrated_display_panics: Vec<IntegratedDisplayPanicManifest>,
    #[serde(default)]
    pub integrated_osctl_trace_replays: Vec<IntegratedOsctlTraceReplayManifest>,
    #[serde(default)]
    pub device_objects: Vec<DeviceObjectManifest>,
    #[serde(default)]
    pub queue_objects: Vec<QueueObjectManifest>,
    #[serde(default)]
    pub descriptor_objects: Vec<DescriptorObjectManifest>,
    #[serde(default)]
    pub dma_buffer_objects: Vec<DmaBufferObjectManifest>,
    #[serde(default)]
    pub mmio_region_objects: Vec<MmioRegionObjectManifest>,
    #[serde(default)]
    pub irq_line_objects: Vec<IrqLineObjectManifest>,
    #[serde(default)]
    pub irq_events: Vec<IrqEventManifest>,
    #[serde(default)]
    pub device_capabilities: Vec<DeviceCapabilityManifest>,
    #[serde(default)]
    pub driver_store_bindings: Vec<DriverStoreBindingManifest>,
    #[serde(default)]
    pub io_waits: Vec<IoWaitManifest>,
    #[serde(default)]
    pub io_cleanups: Vec<IoCleanupManifest>,
    #[serde(default)]
    pub io_fault_injections: Vec<IoFaultInjectionManifest>,
    #[serde(default)]
    pub io_validation_reports: Vec<IoValidationReportManifest>,
    #[serde(default)]
    pub packet_device_objects: Vec<PacketDeviceObjectManifest>,
    #[serde(default)]
    pub packet_buffer_objects: Vec<PacketBufferObjectManifest>,
    #[serde(default)]
    pub packet_queue_objects: Vec<PacketQueueObjectManifest>,
    #[serde(default)]
    pub packet_descriptors: Vec<PacketDescriptorObjectManifest>,
    #[serde(default)]
    pub fake_net_backends: Vec<FakeNetBackendObjectManifest>,
    #[serde(default)]
    pub virtio_net_backends: Vec<VirtioNetBackendObjectManifest>,
    #[serde(default)]
    pub network_rx_interrupts: Vec<NetworkRxInterruptManifest>,
    #[serde(default)]
    pub network_rx_wait_resolutions: Vec<NetworkRxWaitResolutionManifest>,
    #[serde(default)]
    pub network_tx_capability_gates: Vec<NetworkTxCapabilityGateManifest>,
    #[serde(default)]
    pub network_tx_completions: Vec<NetworkTxCompletionManifest>,
    #[serde(default)]
    pub network_stack_adapters: Vec<NetworkStackAdapterManifest>,
    #[serde(default)]
    pub socket_objects: Vec<SocketObjectManifest>,
    #[serde(default)]
    pub endpoint_objects: Vec<EndpointObjectManifest>,
    #[serde(default)]
    pub socket_operations: Vec<SocketOperationManifest>,
    #[serde(default)]
    pub socket_waits: Vec<SocketWaitManifest>,
    #[serde(default)]
    pub network_backpressures: Vec<NetworkBackpressureManifest>,
    #[serde(default)]
    pub network_driver_cleanups: Vec<NetworkDriverCleanupManifest>,
    #[serde(default)]
    pub network_generation_audits: Vec<NetworkGenerationAuditManifest>,
    #[serde(default)]
    pub network_fault_injections: Vec<NetworkFaultInjectionManifest>,
    #[serde(default)]
    pub network_benchmarks: Vec<NetworkBenchmarkManifest>,
    #[serde(default)]
    pub network_recovery_benchmarks: Vec<NetworkRecoveryBenchmarkManifest>,
    #[serde(default)]
    pub block_device_objects: Vec<BlockDeviceObjectManifest>,
    #[serde(default)]
    pub block_range_objects: Vec<BlockRangeObjectManifest>,
    #[serde(default)]
    pub block_request_objects: Vec<BlockRequestObjectManifest>,
    #[serde(default)]
    pub block_completion_objects: Vec<BlockCompletionObjectManifest>,
    #[serde(default)]
    pub block_waits: Vec<BlockWaitManifest>,
    #[serde(default)]
    pub fake_block_backends: Vec<FakeBlockBackendObjectManifest>,
    #[serde(default)]
    pub virtio_blk_backends: Vec<VirtioBlkBackendObjectManifest>,
    #[serde(default)]
    pub block_read_paths: Vec<BlockReadPathManifest>,
    #[serde(default)]
    pub block_write_paths: Vec<BlockWritePathManifest>,
    #[serde(default)]
    pub block_request_queues: Vec<BlockRequestQueueManifest>,
    #[serde(default)]
    pub block_dma_buffers: Vec<BlockDmaBufferManifest>,
    #[serde(default)]
    pub block_page_objects: Vec<BlockPageObjectManifest>,
    #[serde(default)]
    pub guest_address_spaces: Vec<GuestAddressSpaceManifest>,
    #[serde(default)]
    pub vma_regions: Vec<VmaRegionManifest>,
    #[serde(default)]
    pub page_objects: Vec<PageObjectManifest>,
    #[serde(default)]
    pub guest_memory_faults: Vec<GuestMemoryFaultManifest>,
    #[serde(default)]
    pub guest_memory_operations: Vec<GuestMemoryOperationManifest>,
    #[serde(default)]
    pub buffer_cache_objects: Vec<BufferCacheObjectManifest>,
    #[serde(default)]
    pub file_objects: Vec<FileObjectManifest>,
    #[serde(default)]
    pub directory_objects: Vec<DirectoryObjectManifest>,
    #[serde(default)]
    pub fat_adapter_objects: Vec<FatAdapterObjectManifest>,
    #[serde(default)]
    pub ext4_adapter_objects: Vec<Ext4AdapterObjectManifest>,
    #[serde(default)]
    pub file_handle_capabilities: Vec<FileHandleCapabilityManifest>,
    #[serde(default)]
    pub fs_waits: Vec<FsWaitManifest>,
    #[serde(default)]
    pub block_driver_cleanups: Vec<BlockDriverCleanupManifest>,
    #[serde(default)]
    pub block_pending_io_policies: Vec<BlockPendingIoPolicyManifest>,
    #[serde(default)]
    pub block_request_generation_audits: Vec<BlockRequestGenerationAuditManifest>,
    #[serde(default)]
    pub block_benchmarks: Vec<BlockBenchmarkManifest>,
    #[serde(default)]
    pub block_recovery_benchmarks: Vec<BlockRecoveryBenchmarkManifest>,
    #[serde(default)]
    pub target_feature_sets: Vec<TargetFeatureSetManifest>,
    #[serde(default)]
    pub vector_states: Vec<VectorStateManifest>,
    #[serde(default)]
    pub simd_fault_injections: Vec<SimdFaultInjectionManifest>,
    #[serde(default)]
    pub simd_benchmarks: Vec<SimdBenchmarkManifest>,
    #[serde(default)]
    pub simd_context_switch_benchmarks: Vec<SimdContextSwitchBenchmarkManifest>,
    #[serde(default)]
    pub framebuffer_objects: Vec<FramebufferObjectManifest>,
    #[serde(default)]
    pub display_objects: Vec<DisplayObjectManifest>,
    #[serde(default)]
    pub display_capabilities: Vec<DisplayCapabilityManifest>,
    #[serde(default)]
    pub framebuffer_window_leases: Vec<FramebufferWindowLeaseManifest>,
    #[serde(default)]
    pub framebuffer_mappings: Vec<FramebufferMappingManifest>,
    #[serde(default)]
    pub framebuffer_writes: Vec<FramebufferWriteManifest>,
    #[serde(default)]
    pub framebuffer_flush_regions: Vec<FramebufferFlushRegionManifest>,
    #[serde(default)]
    pub framebuffer_dirty_regions: Vec<FramebufferDirtyRegionManifest>,
    #[serde(default)]
    pub display_event_logs: Vec<DisplayEventLogManifest>,
    #[serde(default)]
    pub display_cleanups: Vec<DisplayCleanupManifest>,
    #[serde(default)]
    pub display_snapshot_barriers: Vec<DisplaySnapshotBarrierManifest>,
    #[serde(default)]
    pub display_panic_last_frames: Vec<DisplayPanicLastFrameManifest>,
    #[serde(default)]
    pub framebuffer_benchmarks: Vec<FramebufferBenchmarkManifest>,
    #[serde(default)]
    pub activation_resumes: Vec<ActivationResumeManifest>,
    #[serde(default)]
    pub activation_waits: Vec<ActivationWaitManifest>,
    #[serde(default)]
    pub activation_cleanups: Vec<ActivationCleanupManifest>,
    #[serde(default)]
    pub preemption_latency_samples: Vec<PreemptionLatencySampleManifest>,
    #[serde(default)]
    pub hart_event_attributions: Vec<HartEventAttributionManifest>,
    #[serde(default)]
    pub code_objects: Vec<CodeObjectManifest>,
    #[serde(default)]
    pub store_records: Vec<StoreRecordManifest>,
    #[serde(default)]
    pub capability_records: Vec<CapabilityRecordManifest>,
    #[serde(default)]
    pub wait_records: Vec<WaitRecordManifest>,
    #[serde(default)]
    pub activation_records: Vec<ActivationRecordManifest>,
    #[serde(default)]
    pub trap_records: Vec<TrapRecordManifest>,
    #[serde(default)]
    pub hostcall_trace: Vec<HostcallTraceManifest>,
    #[serde(default)]
    pub migration_objects: Vec<MigrationObjectManifest>,
    #[serde(default)]
    pub tombstones: Vec<TombstoneManifest>,
    #[serde(default)]
    pub contract_violations: Vec<ContractViolationManifest>,
    #[serde(default)]
    pub cleanup_transactions: Vec<CleanupTransactionManifest>,
    #[serde(default)]
    pub memory_policies: Vec<MemoryClassPolicyManifest>,
    #[serde(default)]
    pub snapshot_validation: BoundaryValidationReportManifest,
    #[serde(default)]
    pub replay_validation: BoundaryValidationReportManifest,
    #[serde(default)]
    pub substrate_events: Vec<SubstrateEventManifest>,
    #[serde(default)]
    pub profile_gate_events: Vec<ProfileGateEventManifest>,
    #[serde(default)]
    pub command_results: Vec<CommandResultManifest>,
    #[serde(default)]
    pub interface_events: Vec<InterfaceEventManifest>,
    #[serde(default)]
    pub network_socket_count: u32,
    #[serde(default)]
    pub network_rx_queue_bytes: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SemanticRootSetManifest {
    #[serde(default)]
    pub hart_roots: Vec<String>,
    #[serde(default)]
    pub task_roots: Vec<String>,
    #[serde(default)]
    pub task_record_roots: Vec<String>,
    #[serde(default)]
    pub runtime_activation_roots: Vec<String>,
    #[serde(default)]
    pub runnable_queue_roots: Vec<String>,
    #[serde(default)]
    pub activation_context_roots: Vec<String>,
    #[serde(default)]
    pub saved_context_roots: Vec<String>,
    #[serde(default)]
    pub timer_interrupt_roots: Vec<String>,
    #[serde(default)]
    pub ipi_event_roots: Vec<String>,
    #[serde(default)]
    pub remote_preempt_roots: Vec<String>,
    #[serde(default)]
    pub remote_park_roots: Vec<String>,
    #[serde(default)]
    pub preemption_roots: Vec<String>,
    #[serde(default)]
    pub scheduler_decision_roots: Vec<String>,
    #[serde(default)]
    pub cross_hart_scheduler_decision_roots: Vec<String>,
    #[serde(default)]
    pub activation_migration_roots: Vec<String>,
    #[serde(default)]
    pub smp_safe_point_roots: Vec<String>,
    #[serde(default)]
    pub stop_the_world_rendezvous_roots: Vec<String>,
    #[serde(default)]
    pub smp_code_publish_barrier_roots: Vec<String>,
    #[serde(default)]
    pub smp_cleanup_quiescence_roots: Vec<String>,
    #[serde(default)]
    pub smp_snapshot_barrier_roots: Vec<String>,
    #[serde(default)]
    pub smp_stress_run_roots: Vec<String>,
    #[serde(default)]
    pub smp_scaling_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub integrated_smp_preemption_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub integrated_smp_network_fault_roots: Vec<String>,
    #[serde(default)]
    pub integrated_disk_preempt_fault_roots: Vec<String>,
    #[serde(default)]
    pub integrated_simd_migration_roots: Vec<String>,
    #[serde(default)]
    pub integrated_network_disk_io_roots: Vec<String>,
    #[serde(default)]
    pub integrated_display_scheduler_load_roots: Vec<String>,
    #[serde(default)]
    pub integrated_snapshot_io_lease_barrier_roots: Vec<String>,
    #[serde(default)]
    pub integrated_code_publish_smp_workload_roots: Vec<String>,
    #[serde(default)]
    pub integrated_display_panic_roots: Vec<String>,
    #[serde(default)]
    pub integrated_osctl_trace_replay_roots: Vec<String>,
    #[serde(default)]
    pub device_object_roots: Vec<String>,
    #[serde(default)]
    pub queue_object_roots: Vec<String>,
    #[serde(default)]
    pub descriptor_object_roots: Vec<String>,
    #[serde(default)]
    pub dma_buffer_object_roots: Vec<String>,
    #[serde(default)]
    pub mmio_region_object_roots: Vec<String>,
    #[serde(default)]
    pub irq_line_object_roots: Vec<String>,
    #[serde(default)]
    pub irq_event_roots: Vec<String>,
    #[serde(default)]
    pub device_capability_roots: Vec<String>,
    #[serde(default)]
    pub driver_store_binding_roots: Vec<String>,
    #[serde(default)]
    pub io_wait_roots: Vec<String>,
    #[serde(default)]
    pub io_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub io_fault_injection_roots: Vec<String>,
    #[serde(default)]
    pub io_validation_report_roots: Vec<String>,
    #[serde(default)]
    pub packet_device_object_roots: Vec<String>,
    #[serde(default)]
    pub packet_buffer_object_roots: Vec<String>,
    #[serde(default)]
    pub packet_queue_object_roots: Vec<String>,
    #[serde(default)]
    pub packet_descriptor_object_roots: Vec<String>,
    #[serde(default)]
    pub fake_net_backend_object_roots: Vec<String>,
    #[serde(default)]
    pub virtio_net_backend_object_roots: Vec<String>,
    #[serde(default)]
    pub network_rx_interrupt_roots: Vec<String>,
    #[serde(default)]
    pub network_rx_wait_resolution_roots: Vec<String>,
    #[serde(default)]
    pub network_tx_capability_gate_roots: Vec<String>,
    #[serde(default)]
    pub network_tx_completion_roots: Vec<String>,
    #[serde(default)]
    pub network_stack_adapter_roots: Vec<String>,
    #[serde(default)]
    pub socket_object_roots: Vec<String>,
    #[serde(default)]
    pub endpoint_object_roots: Vec<String>,
    #[serde(default)]
    pub socket_operation_roots: Vec<String>,
    #[serde(default)]
    pub socket_wait_roots: Vec<String>,
    #[serde(default)]
    pub network_backpressure_roots: Vec<String>,
    #[serde(default)]
    pub network_driver_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub network_generation_audit_roots: Vec<String>,
    #[serde(default)]
    pub network_fault_injection_roots: Vec<String>,
    #[serde(default)]
    pub network_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub network_recovery_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub block_device_object_roots: Vec<String>,
    #[serde(default)]
    pub block_range_object_roots: Vec<String>,
    #[serde(default)]
    pub block_request_object_roots: Vec<String>,
    #[serde(default)]
    pub block_completion_object_roots: Vec<String>,
    #[serde(default)]
    pub block_wait_roots: Vec<String>,
    #[serde(default)]
    pub fake_block_backend_object_roots: Vec<String>,
    #[serde(default)]
    pub virtio_blk_backend_object_roots: Vec<String>,
    #[serde(default)]
    pub block_read_path_roots: Vec<String>,
    #[serde(default)]
    pub block_write_path_roots: Vec<String>,
    #[serde(default)]
    pub block_request_queue_roots: Vec<String>,
    #[serde(default)]
    pub block_dma_buffer_roots: Vec<String>,
    #[serde(default)]
    pub block_page_object_roots: Vec<String>,
    #[serde(default)]
    pub guest_address_space_roots: Vec<String>,
    #[serde(default)]
    pub vma_region_roots: Vec<String>,
    #[serde(default)]
    pub page_object_roots: Vec<String>,
    #[serde(default)]
    pub guest_memory_fault_roots: Vec<String>,
    #[serde(default)]
    pub guest_memory_operation_roots: Vec<String>,
    #[serde(default)]
    pub buffer_cache_object_roots: Vec<String>,
    #[serde(default)]
    pub file_object_roots: Vec<String>,
    #[serde(default)]
    pub directory_object_roots: Vec<String>,
    #[serde(default)]
    pub fat_adapter_object_roots: Vec<String>,
    #[serde(default)]
    pub ext4_adapter_object_roots: Vec<String>,
    #[serde(default)]
    pub file_handle_capability_roots: Vec<String>,
    #[serde(default)]
    pub fs_wait_roots: Vec<String>,
    #[serde(default)]
    pub block_driver_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub block_pending_io_policy_roots: Vec<String>,
    #[serde(default)]
    pub block_request_generation_audit_roots: Vec<String>,
    #[serde(default)]
    pub block_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub block_recovery_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub target_feature_set_roots: Vec<String>,
    #[serde(default)]
    pub vector_state_roots: Vec<String>,
    #[serde(default)]
    pub simd_fault_injection_roots: Vec<String>,
    #[serde(default)]
    pub simd_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub simd_context_switch_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_object_roots: Vec<String>,
    #[serde(default)]
    pub display_object_roots: Vec<String>,
    #[serde(default)]
    pub display_capability_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_window_lease_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_mapping_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_write_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_flush_region_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_dirty_region_roots: Vec<String>,
    #[serde(default)]
    pub display_event_log_roots: Vec<String>,
    #[serde(default)]
    pub display_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub display_snapshot_barrier_roots: Vec<String>,
    #[serde(default)]
    pub display_panic_last_frame_roots: Vec<String>,
    #[serde(default)]
    pub framebuffer_benchmark_roots: Vec<String>,
    #[serde(default)]
    pub activation_resume_roots: Vec<String>,
    #[serde(default)]
    pub activation_wait_roots: Vec<String>,
    #[serde(default)]
    pub activation_cleanup_roots: Vec<String>,
    #[serde(default)]
    pub preemption_latency_roots: Vec<String>,
    #[serde(default)]
    pub hart_event_attribution_roots: Vec<String>,
    #[serde(default)]
    pub resource_roots: Vec<String>,
    #[serde(default)]
    pub authority_roots: Vec<String>,
    #[serde(default)]
    pub wait_roots: Vec<String>,
    #[serde(default)]
    pub store_roots: Vec<String>,
    #[serde(default)]
    pub capability_roots: Vec<String>,
    #[serde(default)]
    pub target_store_record_roots: Vec<String>,
    #[serde(default)]
    pub target_capability_record_roots: Vec<String>,
    #[serde(default)]
    pub fast_path_roots: Vec<String>,
    #[serde(default)]
    pub boundary_roots: Vec<String>,
    #[serde(default)]
    pub artifact_verification_roots: Vec<String>,
    #[serde(default)]
    pub store_activation_roots: Vec<String>,
    #[serde(default)]
    pub executor_transition_roots: Vec<String>,
    #[serde(default)]
    pub target_artifact_roots: Vec<String>,
    #[serde(default)]
    pub code_object_roots: Vec<String>,
    #[serde(default)]
    pub activation_record_roots: Vec<String>,
    #[serde(default)]
    pub trap_roots: Vec<String>,
    #[serde(default)]
    pub hostcall_trace_roots: Vec<String>,
    #[serde(default)]
    pub migration_object_roots: Vec<String>,
    #[serde(default)]
    pub tombstone_roots: Vec<String>,
    #[serde(default)]
    pub contract_violation_roots: Vec<String>,
    #[serde(default)]
    pub cleanup_roots: Vec<String>,
    #[serde(default)]
    pub memory_policy_roots: Vec<String>,
    #[serde(default)]
    pub snapshot_validation_roots: Vec<String>,
    #[serde(default)]
    pub replay_validation_roots: Vec<String>,
    #[serde(default)]
    pub substrate_event_roots: Vec<String>,
    #[serde(default)]
    pub profile_gate_event_roots: Vec<String>,
    #[serde(default)]
    pub command_result_roots: Vec<String>,
    #[serde(default)]
    pub interface_event_roots: Vec<String>,
    #[serde(default)]
    pub event_log_tail: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature_002_envelope(carrier_kind: &str) -> ContractCoreEvidenceManifest {
        ContractCoreEvidenceManifest {
            feature_id: "002-contract-core-stabilization".to_owned(),
            evidence_boundary: "semantic-model".to_owned(),
            carrier_kind: carrier_kind.to_owned(),
            evidence_shape_status: "feature-local".to_owned(),
            contract_facts: vec![ContractCoreFactManifest {
                kind: "semantic-family".to_owned(),
                subject: "phase2.object-identity".to_owned(),
                relation: "covers".to_owned(),
                detail: "stable object kind and generation-bearing identity".to_owned(),
                evidence_boundary: "semantic-model".to_owned(),
            }],
            coverage_matrix: vec![ContractCoreCoverageUnitManifest {
                unit_id: "phase2.object-identity".to_owned(),
                semantic_family: "object-identity".to_owned(),
                owned_surface: "stable-object-kind-and-nonzero-id".to_owned(),
                positive_scenario: "object ref has a stable kind and nonzero identity".to_owned(),
                negative_scenario: "object ref with id=0 is rejected".to_owned(),
                coverage_status: "covered".to_owned(),
            }],
            overclaim_guards: vec![
                "artifact-profile-completion".to_owned(),
                "frontend-personality-breadth".to_owned(),
                "real-target-substrate-behavior".to_owned(),
                "migration-restoration".to_owned(),
                "cross-isa-portability".to_owned(),
            ],
        }
    }

    #[test]
    fn contract_core_evidence_envelope_serializes_as_feature_local_shape() {
        let envelope = feature_002_envelope("migration-shaped");

        let encoded = serde_json::to_string(&envelope).expect("serialize Feature 002 envelope");
        assert!(encoded.contains("\"feature_id\":\"002-contract-core-stabilization\""));
        assert!(encoded.contains("\"evidence_shape_status\":\"feature-local\""));
        assert!(encoded.contains("\"carrier_kind\":\"migration-shaped\""));

        let decoded: ContractCoreEvidenceManifest =
            serde_json::from_str(&encoded).expect("deserialize Feature 002 envelope");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn feature_local_evidence_shape_keeps_post_completion_claims_explicitly_guarded() {
        let envelope = feature_002_envelope("artifact-shaped");

        assert_eq!(envelope.evidence_boundary, "semantic-model");
        assert_eq!(envelope.evidence_shape_status, "feature-local");
        for guard in [
            "artifact-profile-completion",
            "frontend-personality-breadth",
            "real-target-substrate-behavior",
            "migration-restoration",
            "cross-isa-portability",
        ] {
            assert!(envelope.overclaim_guards.iter().any(|entry| entry == guard));
        }
    }
}
