use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactBundleManifest {
    pub schema_version: u32,
    pub artifact_profile: String,
    #[serde(default)]
    pub runtime_mode: String,
    #[serde(default)]
    pub contract: SupervisorContractManifest,
    pub target: TargetManifest,
    pub compiler: CompilerManifest,
    pub modules: Vec<ModuleArtifactManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SupervisorContractManifest {
    pub contract_version: String,
    pub supervisor_world: String,
    pub catalog_fingerprint: String,
    pub package_set_fingerprint: String,
    pub module_count: usize,
    pub required_packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetManifest {
    pub arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    #[serde(default)]
    pub linux_abi_profile: String,
    #[serde(default)]
    pub artifact_signature_profile: String,
    #[serde(default)]
    pub network_contract_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompilerManifest {
    pub engine: String,
    pub engine_version: String,
    pub execution_mode: String,
    pub artifact_format: String,
    #[serde(default)]
    pub target_artifact_format: String,
    #[serde(default)]
    pub runtime_executor_abi: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModuleArtifactManifest {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    #[serde(default)]
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    #[serde(default)]
    pub target_artifact_sha256: String,
    #[serde(default)]
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub exports: Vec<ExternManifest>,
    pub imports: Vec<ImportManifest>,
    pub capabilities: Vec<CapabilityManifest>,
    #[serde(default)]
    pub abi_fingerprint: String,
    #[serde(default)]
    pub service_dependencies: Vec<String>,
    #[serde(default)]
    pub resource_limits: ResourceLimitsManifest,
    #[serde(default)]
    pub interfaces: InterfaceRequirementManifest,
    pub signature: SignatureManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ResourceLimitsManifest {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternManifest {
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportManifest {
    pub module: String,
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CapabilityManifest {
    pub name: String,
    pub rights: Vec<String>,
    pub lifetime: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct InterfaceRequirementManifest {
    #[serde(default)]
    pub required_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub optional_wasi_worlds: Vec<String>,
    #[serde(default)]
    pub custom_wit_worlds: Vec<String>,
    #[serde(default)]
    pub wit_package_versions: Vec<String>,
    #[serde(default)]
    pub component_model_version: String,
    #[serde(default)]
    pub wasi_profile: String,
    #[serde(default)]
    pub hostcall_abi_version: String,
    #[serde(default)]
    pub capability_abi_version: String,
    #[serde(default)]
    pub semantic_contract_version: String,
    #[serde(default)]
    pub substrate_profile_required: String,
    #[serde(default)]
    pub substrate_authorities: SubstrateAuthorityRequirementManifest,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubstrateAuthorityRequirementManifest {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureManifest {
    pub scheme: String,
    pub artifact_hash: String,
    pub manifest_binding_hash: String,
    pub signer: String,
    #[serde(default)]
    pub public_key_hint: String,
    #[serde(default)]
    pub signature: String,
}

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
    pub command_result_roots: Vec<String>,
    #[serde(default)]
    pub interface_event_roots: Vec<String>,
    #[serde(default)]
    pub event_log_tail: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HartRecordManifest {
    pub id: u64,
    pub hardware_id: u32,
    pub label: String,
    pub state: String,
    pub generation: u64,
    pub boot: bool,
    #[serde(default)]
    pub current_activation: Option<u64>,
    #[serde(default)]
    pub current_activation_generation: Option<u64>,
    #[serde(default)]
    pub current_task: Option<u64>,
    #[serde(default)]
    pub current_task_generation: Option<u64>,
    #[serde(default)]
    pub current_store: Option<u64>,
    #[serde(default)]
    pub current_store_generation: Option<u64>,
    pub last_event: Option<u64>,
    #[serde(default)]
    pub last_current_event: Option<u64>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubstrateEventManifest {
    pub id: u64,
    pub epoch: u64,
    pub event_kind: String,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact: Option<u64>,
    pub store: Option<u64>,
    #[serde(default)]
    pub capability: Option<CapabilityHandleArgManifest>,
    pub explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CommandResultManifest {
    pub id: u64,
    pub issuer: String,
    pub command: String,
    pub status: String,
    pub events: Vec<u64>,
    #[serde(default)]
    pub effects: Vec<CommandEffectManifest>,
    #[serde(default)]
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CommandEffectManifest {
    pub kind: String,
    #[serde(default)]
    pub target: Option<ContractObjectRefManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InterfaceEventManifest {
    pub id: u64,
    pub epoch: u64,
    pub interface_kind: String,
    pub interface: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact: Option<u64>,
    pub store: Option<u64>,
    pub explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TaskRecordManifest {
    pub id: u64,
    pub label: String,
    pub frontend: String,
    pub state: String,
    pub generation: u64,
    pub fault_domain: Option<u64>,
    pub pending_wait: Option<u64>,
    #[serde(default)]
    pub resources: Vec<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeActivationRecordManifest {
    pub id: u64,
    pub owner_task: u64,
    #[serde(default)]
    pub owner_task_generation: u64,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub code_object: Option<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub runnable_queue: Option<u64>,
    #[serde(default)]
    pub runnable_queue_generation: Option<u64>,
    pub last_event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RunnableQueueEntryManifest {
    pub activation: u64,
    pub activation_generation: u64,
    pub enqueued_at: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RunnableQueueManifest {
    pub id: u64,
    pub label: String,
    pub generation: u64,
    pub state: String,
    #[serde(default)]
    pub owner_hart: Option<u32>,
    #[serde(default)]
    pub owner_hart_generation: Option<u64>,
    #[serde(default)]
    pub entries: Vec<RunnableQueueEntryManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationContextManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub current_saved_context: Option<u64>,
    #[serde(default)]
    pub current_saved_context_generation: Option<u64>,
    #[serde(default)]
    pub vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub vector_status: String,
    #[serde(default)]
    pub vector_state_event: Option<u64>,
    pub last_event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SavedContextManifest {
    pub id: u64,
    pub context: u64,
    pub context_generation: u64,
    pub activation: u64,
    pub activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    #[serde(default)]
    pub source_preemption: Option<u64>,
    #[serde(default)]
    pub source_preemption_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub pc: u64,
    pub sp: u64,
    pub flags: u64,
    pub integer_registers: u16,
    #[serde(default)]
    pub vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub vector_status: String,
    #[serde(default)]
    pub vector_saved_at_event: Option<u64>,
    pub saved_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TimerInterruptManifest {
    pub id: u64,
    pub timer_epoch: u64,
    pub hart: u64,
    #[serde(default)]
    pub hart_generation: Option<u64>,
    #[serde(default)]
    pub hardware_hart: Option<u32>,
    pub target_activation: Option<u64>,
    #[serde(default)]
    pub target_activation_generation: Option<u64>,
    pub target_task: Option<u64>,
    #[serde(default)]
    pub target_task_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IpiEventManifest {
    pub id: u64,
    pub source_hart: u64,
    pub source_hart_generation: u64,
    pub source_hardware_hart: u32,
    pub target_hart: u64,
    pub target_hart_generation: u64,
    pub target_hardware_hart: u32,
    pub kind: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RemotePreemptManifest {
    pub id: u64,
    pub ipi: u64,
    pub ipi_generation: u64,
    pub source_hart: u64,
    pub source_hart_generation: u64,
    pub target_hart: u64,
    pub target_hart_generation_before: u64,
    pub target_hart_generation_after: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub generation: u64,
    pub state: String,
    pub preempted_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RemoteParkManifest {
    pub id: u64,
    pub ipi: u64,
    pub ipi_generation: u64,
    pub source_hart: u64,
    pub source_hart_generation: u64,
    pub target_hart: u64,
    pub target_hart_generation_before: u64,
    pub target_hart_generation_after: u64,
    pub generation: u64,
    pub state: String,
    pub parked_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HartEventAttributionManifest {
    pub id: u64,
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub event: u64,
    pub event_source: String,
    pub event_kind: String,
    pub activation: Option<u64>,
    #[serde(default)]
    pub activation_generation: Option<u64>,
    pub task: Option<u64>,
    #[serde(default)]
    pub task_generation: Option<u64>,
    pub store: Option<u64>,
    #[serde(default)]
    pub store_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PreemptionManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub generation: u64,
    pub state: String,
    pub preempted_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SchedulerDecisionManifest {
    pub id: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub selected_activation: u64,
    pub selected_activation_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub generation: u64,
    pub state: String,
    pub decided_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CrossHartSchedulerDecisionManifest {
    pub id: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub deciding_hart: u64,
    pub deciding_hart_generation: u64,
    pub target_hart: u64,
    pub target_hart_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub queue_owner_hart_generation: u64,
    pub selected_activation: u64,
    pub selected_activation_generation: u64,
    pub generation: u64,
    pub state: String,
    pub decided_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationMigrationManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub source_hart: u64,
    pub source_hart_generation: u64,
    pub target_hart: u64,
    pub target_hart_generation: u64,
    pub source_queue: u64,
    pub source_queue_generation: u64,
    pub source_queue_owner_hart_generation: u64,
    pub target_queue: u64,
    pub target_queue_generation: u64,
    pub target_queue_owner_hart_generation: u64,
    #[serde(default)]
    pub context: Option<u64>,
    #[serde(default)]
    pub context_generation_before: Option<u64>,
    #[serde(default)]
    pub context_generation_after: Option<u64>,
    #[serde(default)]
    pub source_vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub migrated_vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub vector_status: String,
    #[serde(default)]
    pub vector_migrated_at_event: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub migrated_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpSafePointParticipantManifest {
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub hart_state: String,
    pub current_activation: Option<u64>,
    pub current_activation_generation: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpSafePointManifest {
    pub id: u64,
    pub coordinator_hart: u64,
    pub coordinator_hart_generation: u64,
    pub participants: Vec<SmpSafePointParticipantManifest>,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StopTheWorldRendezvousParticipantManifest {
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub hart_state: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StopTheWorldRendezvousManifest {
    pub id: u64,
    pub epoch: u64,
    pub safe_point: u64,
    pub safe_point_generation: u64,
    pub coordinator_hart: u64,
    pub coordinator_hart_generation: u64,
    pub participants: Vec<StopTheWorldRendezvousParticipantManifest>,
    pub stop_new_activations: bool,
    pub generation: u64,
    pub state: String,
    pub completed_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpCodePublishBarrierParticipantManifest {
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub last_seen_code_epoch_before: u64,
    pub last_seen_code_epoch_after: u64,
    pub semantic_icache_sync: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpCodePublishBarrierManifest {
    pub id: u64,
    pub rendezvous: u64,
    pub rendezvous_generation: u64,
    pub rendezvous_epoch: u64,
    pub code_publish_epoch_before: u64,
    pub code_publish_epoch_after: u64,
    pub participants: Vec<SmpCodePublishBarrierParticipantManifest>,
    pub remote_icache_sync_required: bool,
    pub code_publish_executed: bool,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpCleanupQuiescenceParticipantManifest {
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub hart_state: String,
    pub current_activation: Option<u64>,
    #[serde(default)]
    pub current_activation_generation: Option<u64>,
    pub current_store: Option<u64>,
    #[serde(default)]
    pub current_store_generation: Option<u64>,
    pub quiesced: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpCleanupQuiescenceManifest {
    pub id: u64,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub store: u64,
    pub target_store_generation: u64,
    pub result_store_generation: u64,
    pub activation: u64,
    pub activation_generation_after: u64,
    pub rendezvous: u64,
    pub rendezvous_generation: u64,
    pub rendezvous_epoch: u64,
    pub participants: Vec<SmpCleanupQuiescenceParticipantManifest>,
    pub no_running_activation: bool,
    pub no_pending_wait: bool,
    pub no_live_capability: bool,
    pub no_live_resource: bool,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpSnapshotBarrierParticipantManifest {
    pub hart: u64,
    pub hart_generation: u64,
    pub hardware_hart: u32,
    pub hart_state: String,
    pub event_log_cursor_observed: u64,
    pub snapshot_safe: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpSnapshotBarrierManifest {
    pub id: u64,
    pub rendezvous: u64,
    pub rendezvous_generation: u64,
    pub rendezvous_epoch: u64,
    pub event_log_cursor: u64,
    pub participants: Vec<SmpSnapshotBarrierParticipantManifest>,
    pub pending_wait_count: u32,
    pub active_transaction_count: u32,
    pub active_dmw_lease_count: u32,
    pub active_nonconvertible_activation_count: u32,
    pub in_flight_dma_count: u32,
    pub unsealed_event_log: bool,
    pub unflushed_trap_record_count: u32,
    pub pending_cleanup_count: u32,
    pub native_activation_stack_live: bool,
    pub raw_dma_binding_count: u32,
    pub raw_mmio_binding_count: u32,
    pub snapshot_validation_ok: bool,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpStressRunManifest {
    pub id: u64,
    pub scenario: String,
    pub iterations: u32,
    pub hart_count: u32,
    pub event_log_cursor: u64,
    pub observed_safe_point_count: u32,
    pub observed_rendezvous_count: u32,
    pub observed_code_publish_barrier_count: u32,
    pub observed_cleanup_quiescence_count: u32,
    pub observed_snapshot_barrier_count: u32,
    pub observed_activation_migration_count: u32,
    pub observed_remote_preempt_count: u32,
    pub observed_remote_park_count: u32,
    pub invariant_checks: u32,
    pub property_failures: u32,
    pub last_safe_point: u64,
    pub last_safe_point_generation: u64,
    pub last_rendezvous: u64,
    pub last_rendezvous_generation: u64,
    pub last_code_publish_barrier: u64,
    pub last_code_publish_barrier_generation: u64,
    pub last_cleanup_quiescence: u64,
    pub last_cleanup_quiescence_generation: u64,
    pub last_snapshot_barrier: u64,
    pub last_snapshot_barrier_generation: u64,
    pub last_activation_migration: u64,
    pub last_activation_migration_generation: u64,
    pub last_remote_preempt: u64,
    pub last_remote_preempt_generation: u64,
    pub last_remote_park: u64,
    pub last_remote_park_generation: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmpScalingBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub stress_run: u64,
    pub stress_run_generation: u64,
    pub hart_count: u32,
    pub workload_units: u64,
    pub baseline_single_hart_nanos: u64,
    pub measured_smp_nanos: u64,
    pub budget_nanos: u64,
    pub speedup_milli: u64,
    pub efficiency_milli: u64,
    pub event_log_cursor: u64,
    pub stress_safe_point_count: u32,
    pub stress_rendezvous_count: u32,
    pub stress_property_failures: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub class: String,
    pub resource: u64,
    pub resource_generation: u64,
    pub backend: String,
    pub bus: String,
    pub vendor: String,
    pub model: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueueObjectManifest {
    pub id: u64,
    pub name: String,
    pub role: String,
    pub queue_index: u16,
    pub depth: u32,
    pub device: u64,
    pub device_generation: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DescriptorObjectManifest {
    pub id: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub slot: u16,
    pub access: String,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DmaBufferObjectManifest {
    pub id: u64,
    pub descriptor: u64,
    pub descriptor_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub access: String,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MmioRegionObjectManifest {
    pub id: u64,
    pub device: u64,
    pub device_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub region_index: u16,
    pub offset: u64,
    pub length: u64,
    pub access: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IrqLineObjectManifest {
    pub id: u64,
    pub device: u64,
    pub device_generation: u64,
    pub resource: u64,
    pub resource_generation: u64,
    pub irq_number: u32,
    pub trigger: String,
    pub polarity: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IrqEventManifest {
    pub id: u64,
    pub irq_line: u64,
    pub irq_line_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub irq_number: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeviceCapabilityManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub target: ContractObjectRefManifest,
    pub class: String,
    pub operation: String,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DriverStoreBindingManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub device_capability: u64,
    pub device_capability_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub blocker: ContractObjectRefManifest,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub completion_irq_event: Option<u64>,
    #[serde(default)]
    pub completion_irq_event_generation: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoCleanupManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub started_at_event: u64,
    pub completed_at_event: u64,
    #[serde(default)]
    pub cancelled_io_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_device_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_dma_buffers: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_mmio_regions: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_irq_lines: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub steps: Vec<IoCleanupStepManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoCleanupStepManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub observed_generation: u64,
    pub status: String,
    #[serde(default)]
    pub event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoFaultInjectionManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub target: ContractObjectRefManifest,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub generation: u64,
    pub kind: String,
    pub state: String,
    pub injected_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoValidationViolationManifest {
    pub code: String,
    pub subject: ContractObjectRefManifest,
    pub relation: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IoValidationReportManifest {
    pub id: u64,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub event_log_cursor: u64,
    pub observed_device_count: usize,
    pub observed_queue_count: usize,
    pub observed_descriptor_count: usize,
    pub observed_dma_buffer_count: usize,
    pub observed_mmio_region_count: usize,
    pub observed_irq_line_count: usize,
    pub observed_irq_event_count: usize,
    pub observed_device_capability_count: usize,
    pub observed_driver_binding_count: usize,
    pub observed_io_wait_count: usize,
    pub observed_io_cleanup_count: usize,
    pub observed_io_fault_injection_count: usize,
    pub violation_count: usize,
    pub violations: Vec<IoValidationViolationManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketDeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub device: u64,
    pub device_generation: u64,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketBufferObjectManifest {
    pub id: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub direction: String,
    pub frame_format_version: u32,
    pub capacity: u32,
    pub payload_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketQueueObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub role: String,
    pub queue_index: u16,
    pub depth: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketDescriptorObjectManifest {
    pub id: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub slot: u16,
    pub length: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FakeNetBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub deterministic_seed: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirtioNetBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub model: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub rx_queue_index: u16,
    pub tx_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRxInterruptManifest {
    pub id: u64,
    pub virtio_net_backend: u64,
    pub virtio_net_backend_generation: u64,
    pub irq_event: u64,
    pub irq_event_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRxWaitResolutionManifest {
    pub id: u64,
    pub io_wait: u64,
    pub io_wait_generation: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub rx_interrupt: u64,
    pub rx_interrupt_generation: u64,
    pub irq_event: u64,
    pub irq_event_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub resolved_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkTxCapabilityGateManifest {
    pub id: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub device_capability: u64,
    pub device_capability_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkTxCompletionManifest {
    pub id: u64,
    pub tx_gate: u64,
    pub tx_gate_generation: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub byte_len: u32,
    pub sequence: u64,
    pub completion_sequence: u64,
    pub generation: u64,
    pub state: String,
    pub completed_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkStackAdapterManifest {
    pub id: u64,
    pub implementation: String,
    pub implementation_version: String,
    pub profile: String,
    pub medium: String,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketObjectManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub domain: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub canonical_protocol: u16,
    pub family: String,
    pub transport: String,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EndpointObjectManifest {
    pub id: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub family: String,
    pub transport: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketOperationManifest {
    pub id: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub operation: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub backlog: u16,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SocketWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub wait_kind: String,
    pub blocker: ContractObjectRefManifest,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    pub completed_at_event: Option<u64>,
    pub cancel_reason: Option<String>,
    pub ready_sequence: Option<u64>,
    pub byte_len: Option<u32>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkBackpressureManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub endpoint: Option<u64>,
    pub endpoint_generation: Option<u64>,
    pub socket: Option<u64>,
    pub socket_generation: Option<u64>,
    pub owner_store: Option<u64>,
    pub owner_store_generation: Option<u64>,
    pub direction: String,
    pub reason: String,
    pub action: String,
    pub queue_depth: u32,
    pub queue_limit: u32,
    pub dropped_packets: u32,
    pub dropped_bytes: u32,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkDriverCleanupManifest {
    pub id: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub backend: ContractObjectRefManifest,
    #[serde(default)]
    pub cancelled_socket_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub cancelled_wait_tokens: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_packet_capabilities: Vec<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub started_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkGenerationAuditManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_descriptor: u64,
    pub packet_descriptor_generation: u64,
    pub packet_buffer: u64,
    pub packet_buffer_generation: u64,
    pub dma_buffer: ContractObjectRefManifest,
    pub device_capability: ContractObjectRefManifest,
    pub rejected_packet_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkFaultInjectionManifest {
    pub id: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub packet_queue: u64,
    pub packet_queue_generation: u64,
    pub packet_descriptor: Option<u64>,
    pub packet_descriptor_generation: Option<u64>,
    pub packet_buffer: Option<u64>,
    pub packet_buffer_generation: Option<u64>,
    pub endpoint: Option<u64>,
    pub endpoint_generation: Option<u64>,
    pub socket: Option<u64>,
    pub socket_generation: Option<u64>,
    pub owner_store: Option<u64>,
    pub owner_store_generation: Option<u64>,
    pub direction: String,
    pub kind: String,
    pub effect: String,
    pub injected_packets: u32,
    pub dropped_packets: u32,
    pub error_packets: u32,
    pub error_code: String,
    pub sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub tx_queue: u64,
    pub tx_queue_generation: u64,
    pub rx_queue: u64,
    pub rx_queue_generation: u64,
    pub tx_completion: u64,
    pub tx_completion_generation: u64,
    pub rx_wait_resolution: u64,
    pub rx_wait_resolution_generation: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub backpressure: Option<u64>,
    pub backpressure_generation: Option<u64>,
    pub sample_packets: u32,
    pub sample_bytes: u64,
    pub tx_completed_packets: u32,
    pub rx_resolved_packets: u32,
    pub dropped_packets: u32,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub throughput_bytes_per_sec: u64,
    pub p50_latency_nanos: u64,
    pub p99_latency_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkRecoveryBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    #[serde(default)]
    pub fault_injection: Option<u64>,
    #[serde(default)]
    pub fault_injection_generation: Option<u64>,
    pub recovery_start_event: u64,
    pub recovery_complete_event: u64,
    pub cancelled_socket_waits: u32,
    pub revoked_packet_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDeviceObjectManifest {
    pub id: u64,
    pub name: String,
    pub device: u64,
    pub device_generation: u64,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRangeObjectManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub start_sector: u64,
    pub sector_count: u64,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestObjectManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockCompletionObjectManifest {
    pub id: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub status: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub completion: Option<u64>,
    #[serde(default)]
    pub completion_generation: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FakeBlockBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub deterministic_seed: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VirtioBlkBackendObjectManifest {
    pub id: u64,
    pub name: String,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub provider: String,
    pub profile: String,
    pub model: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub request_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockReadPathManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub data_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockWritePathManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub payload_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestQueueEntryManifest {
    pub request: u64,
    pub request_generation: u64,
    #[serde(default)]
    pub completion: Option<u64>,
    #[serde(default)]
    pub completion_generation: Option<u64>,
    pub sequence: u64,
    pub operation: String,
    pub byte_len: u64,
    pub state: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestQueueManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub depth: u32,
    #[serde(default)]
    pub entries: Vec<BlockRequestQueueEntryManifest>,
    pub pending_count: u32,
    pub completed_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDmaBufferManifest {
    pub id: u64,
    pub backend_kind: String,
    pub backend: u64,
    pub backend_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub dma_buffer: u64,
    pub dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub descriptor: u64,
    pub descriptor_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub operation: String,
    pub access: String,
    pub byte_len: u64,
    pub buffer_len: u32,
    pub buffer_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockPageObjectManifest {
    pub id: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub block_completion: u64,
    pub block_completion_generation: u64,
    pub dma_buffer: u64,
    pub dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub aspace: ContractObjectRefManifest,
    pub vma_region: ContractObjectRefManifest,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub page_backing: String,
    pub cow_state: String,
    pub page_state: String,
    pub page_offset: u64,
    pub byte_len: u64,
    pub operation: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BufferCacheObjectManifest {
    pub id: u64,
    pub block_page_object: u64,
    pub block_page_object_generation: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub aspace: ContractObjectRefManifest,
    pub vma_region: ContractObjectRefManifest,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub page_offset: u64,
    pub block_offset: u64,
    pub byte_len: u64,
    pub operation: String,
    pub cache_state: String,
    pub coherency_epoch: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FileObjectManifest {
    pub id: u64,
    pub buffer_cache_object: u64,
    pub buffer_cache_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub page: ContractObjectRefManifest,
    pub page_dirty_generation: u64,
    pub namespace: String,
    pub file_key: String,
    pub path: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub file_size: u64,
    pub content_digest: u64,
    pub cache_state: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DirectoryObjectManifest {
    pub id: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub namespace: String,
    pub directory_key: String,
    pub directory_path: String,
    pub entry_name: String,
    pub child_file_key: String,
    pub child_path: String,
    pub entry_kind: String,
    pub file_size: u64,
    pub content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FatAdapterObjectManifest {
    pub id: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub implementation: String,
    pub version: String,
    pub profile: String,
    pub volume_label: String,
    pub image_bytes: u64,
    pub adapter_path: String,
    pub semantic_path: String,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub write_digest: u64,
    pub read_digest: u64,
    pub file_content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ext4AdapterObjectManifest {
    pub id: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub implementation: String,
    pub version: String,
    pub profile: String,
    pub volume_label: String,
    pub image_bytes: u64,
    pub adapter_path: String,
    pub semantic_path: String,
    pub bytes_read: u64,
    pub read_digest: u64,
    pub file_content_digest: u64,
    pub directory_entries: u64,
    pub read_only_enforced: bool,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FileHandleCapabilityManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub content_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FsWaitManifest {
    pub id: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub file_object: u64,
    pub file_object_generation: u64,
    pub directory_object: u64,
    pub directory_object_generation: u64,
    pub file_handle_capability: u64,
    pub file_handle_capability_generation: u64,
    pub operation: String,
    pub blocker: ContractObjectRefManifest,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub created_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockDriverCleanupManifest {
    pub id: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub backend: ContractObjectRefManifest,
    #[serde(default)]
    pub cancelled_block_waits: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub cancelled_wait_tokens: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub revoked_device_capabilities: Vec<ContractObjectRefManifest>,
    #[serde(default)]
    pub released_dma_buffers: Vec<ContractObjectRefManifest>,
    pub generation: u64,
    pub state: String,
    pub started_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockPendingIoPolicyManifest {
    pub id: u64,
    pub block_wait: u64,
    pub block_wait_generation: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    #[serde(default)]
    pub retry_request: Option<u64>,
    #[serde(default)]
    pub retry_request_generation: Option<u64>,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub operation: String,
    pub sequence: u64,
    pub byte_len: u64,
    pub action: String,
    pub errno: i32,
    pub retry_attempt: u32,
    pub max_retries: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRequestGenerationAuditManifest {
    pub id: u64,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub dma_buffer: ContractObjectRefManifest,
    pub rejected_completion_generation_probes: u32,
    pub rejected_wait_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub rejected_queue_generation_probes: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub backend: ContractObjectRefManifest,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub read_path: u64,
    pub read_path_generation: u64,
    pub write_path: u64,
    pub write_path_generation: u64,
    pub request_queue: u64,
    pub request_queue_generation: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub sample_requests: u32,
    pub sample_bytes: u64,
    pub read_completed_requests: u32,
    pub write_completed_requests: u32,
    pub queue_completed_requests: u32,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub iops: u64,
    pub throughput_bytes_per_sec: u64,
    pub p50_latency_nanos: u64,
    pub p99_latency_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlockRecoveryBenchmarkManifest {
    pub id: u64,
    pub scenario: String,
    pub cleanup: u64,
    pub cleanup_generation: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub driver_binding: u64,
    pub driver_binding_generation: u64,
    pub recovery_start_event: u64,
    pub recovery_complete_event: u64,
    pub cancelled_block_waits: u32,
    pub cancelled_wait_tokens: u32,
    pub released_dma_buffers: u32,
    pub revoked_device_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetFeatureSetManifest {
    pub id: u64,
    pub name: String,
    pub discovery_source: String,
    pub target_profile: String,
    pub target_arch: String,
    pub base_isa: String,
    pub simd_abi: String,
    pub simd_supported: bool,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub scalar_fallback: bool,
    pub unsupported_reason: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VectorStateManifest {
    pub id: u64,
    pub owner_activation: ContractObjectRefManifest,
    pub owner_store: ContractObjectRefManifest,
    pub code_object: ContractObjectRefManifest,
    pub target_feature_set: ContractObjectRefManifest,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub register_bytes: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SimdFaultInjectionManifest {
    pub id: u64,
    pub activation: ContractObjectRefManifest,
    pub code_object: ContractObjectRefManifest,
    pub trap: ContractObjectRefManifest,
    pub target_feature_set: ContractObjectRefManifest,
    pub vector_state: Option<ContractObjectRefManifest>,
    pub kind: String,
    pub effect: String,
    pub required_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub injected_faults: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SimdBenchmarkManifest {
    pub id: u64,
    pub target_feature_set: ContractObjectRefManifest,
    pub scalar_code_object: ContractObjectRefManifest,
    pub vector_code_object: ContractObjectRefManifest,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub workload_units: u64,
    pub scalar_nanos: u64,
    pub vector_nanos: u64,
    pub speedup_milli: u64,
    pub context_overhead_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SimdContextSwitchBenchmarkManifest {
    pub id: u64,
    pub preemption: ContractObjectRefManifest,
    pub activation_resume: ContractObjectRefManifest,
    pub saved_vector_state: ContractObjectRefManifest,
    pub restored_vector_state: ContractObjectRefManifest,
    pub target_feature_set: ContractObjectRefManifest,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub sample_count: u64,
    pub scalar_context_switch_nanos: u64,
    pub vector_context_switch_nanos: u64,
    pub overhead_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferObjectManifest {
    pub id: u64,
    pub name: String,
    pub resource: u64,
    pub resource_generation: u64,
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub pixel_format: String,
    pub byte_len: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplayObjectManifest {
    pub id: u64,
    pub name: String,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub mode_name: String,
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplayCapabilityManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub capability: u64,
    pub capability_generation: u64,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operations: Vec<String>,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferWindowLeaseManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub access: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferMappingManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub framebuffer_window_lease: u64,
    pub framebuffer_window_lease_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub map_handle_slot: u32,
    pub map_handle_generation: u32,
    pub map_handle_tag: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub access: String,
    pub mode: String,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferWriteManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub framebuffer_mapping: u64,
    pub framebuffer_mapping_generation: u64,
    pub framebuffer_window_lease: u64,
    pub framebuffer_window_lease_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub map_handle_slot: u32,
    pub map_handle_generation: u32,
    pub map_handle_tag: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferFlushRegionManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub framebuffer_write: u64,
    pub framebuffer_write_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FramebufferDirtyRegionManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub framebuffer_write: u64,
    pub framebuffer_write_generation: u64,
    pub framebuffer_flush_region: Option<u64>,
    pub framebuffer_flush_region_generation: Option<u64>,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub generation: u64,
    pub state: String,
    pub dirty_at_event: u64,
    pub cleaned_at_event: Option<u64>,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplayEventLogManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub framebuffer_dirty_region: u64,
    pub framebuffer_dirty_region_generation: u64,
    pub first_event: u64,
    pub last_event: u64,
    pub event_count: u64,
    pub flush_count: u64,
    pub dirty_region_count: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplayCleanupStepManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub observed_generation: u64,
    pub status: String,
    pub event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplayCleanupManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub started_at_event: u64,
    pub completed_at_event: u64,
    pub unmapped_framebuffer_mappings: Vec<ContractObjectRefManifest>,
    pub released_framebuffer_window_leases: Vec<ContractObjectRefManifest>,
    pub revoked_display_capabilities: Vec<ContractObjectRefManifest>,
    pub revoked_capabilities: Vec<ContractObjectRefManifest>,
    pub steps: Vec<DisplayCleanupStepManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DisplaySnapshotBarrierManifest {
    pub id: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub display_cleanup: Option<u64>,
    pub display_cleanup_generation: Option<u64>,
    pub active_framebuffer_window_lease_count: u32,
    pub active_framebuffer_mapping_count: u32,
    pub dirty_framebuffer_region_count: u32,
    pub snapshot_validation_ok: bool,
    pub generation: u64,
    pub state: String,
    pub validated_at_event: u64,
    pub reason: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationResumeManifest {
    pub id: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub context: Option<u64>,
    #[serde(default)]
    pub context_generation_before: Option<u64>,
    #[serde(default)]
    pub context_generation_after: Option<u64>,
    pub saved_context: Option<u64>,
    #[serde(default)]
    pub saved_context_generation: Option<u64>,
    #[serde(default)]
    pub saved_vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub restored_vector_state: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub vector_status: String,
    #[serde(default)]
    pub vector_restored_at_event: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub resumed_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationWaitManifest {
    pub id: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after_block: u64,
    #[serde(default)]
    pub activation_generation_after_cancel: Option<u64>,
    pub wait: u64,
    pub wait_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub queue: Option<u64>,
    #[serde(default)]
    pub queue_generation: Option<u64>,
    pub generation: u64,
    pub state: String,
    pub blocked_at_event: u64,
    #[serde(default)]
    pub completed_at_event: Option<u64>,
    #[serde(default)]
    pub cancel_reason: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationCleanupManifest {
    pub id: u64,
    pub store: u64,
    pub target_store_generation: u64,
    pub result_store_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub wait: Option<u64>,
    #[serde(default)]
    pub wait_generation: Option<u64>,
    pub owner_task: u64,
    pub owner_task_generation_before: u64,
    pub owner_task_generation_after: u64,
    pub generation: u64,
    pub state: String,
    pub reason: String,
    pub started_at_event: u64,
    pub completed_at_event: u64,
    #[serde(default)]
    pub steps: Vec<ActivationCleanupStepManifest>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationCleanupStepManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub observed_generation: u64,
    pub status: String,
    #[serde(default)]
    pub event: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PreemptionLatencySampleManifest {
    pub id: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub preemption: u64,
    pub preemption_generation: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub activation_resume: u64,
    pub activation_resume_generation: u64,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub interrupt_recorded_at_event: u64,
    pub preempted_at_event: u64,
    pub decided_at_event: u64,
    pub resumed_at_event: u64,
    pub interrupt_to_preempt_events: u64,
    pub preempt_to_decision_events: u64,
    pub decision_to_resume_events: u64,
    pub interrupt_to_resume_events: u64,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetArtifactImageManifest {
    pub id: u64,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub kind: String,
    pub target_profile: String,
    #[serde(default)]
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub exports: Vec<String>,
    pub imports: Vec<String>,
    pub hostcalls: Vec<HostcallSpecManifest>,
    pub capabilities: Vec<TargetCapabilitySpecManifest>,
    pub memory_plan: TargetMemoryPlanManifest,
    pub trap_metadata: Vec<TargetTrapMetadataManifest>,
    pub address_map: Vec<TargetAddressMapEntryManifest>,
    pub payload_len: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetMemoryPlanManifest {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HostcallSpecManifest {
    pub number: u32,
    pub name: String,
    pub category: String,
    pub object: String,
    pub operation: String,
    pub may_pending: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetCapabilitySpecManifest {
    pub object: String,
    pub operations: Vec<String>,
    pub lifetime: String,
    pub class: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetTrapMetadataManifest {
    pub class: String,
    pub symbol: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetAddressMapEntryManifest {
    pub symbol: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeObjectManifest {
    pub id: u64,
    pub artifact_id: u64,
    pub package: String,
    pub owner_profile: String,
    pub generation: u64,
    pub state: String,
    pub bound_store: Option<u64>,
    #[serde(default)]
    pub bound_store_generation: Option<u64>,
    pub hostcall_table: Option<u64>,
    pub text_start: u64,
    pub text_len: u64,
    pub text_permission: String,
    pub rodata_start: u64,
    pub rodata_len: u64,
    pub rodata_permission: String,
    pub code_hash: String,
    pub hostcalls: Vec<HostcallSpecManifest>,
    pub trap_metadata: Vec<TargetTrapMetadataManifest>,
    pub address_map: Vec<TargetAddressMapEntryManifest>,
    #[serde(default)]
    pub simd_requirement: CodeObjectSimdRequirementManifest,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeObjectSimdRequirementManifest {
    pub uses_simd: bool,
    pub declared: bool,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRefManifest>,
    pub status: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoreRecordManifest {
    pub id: u64,
    pub package: String,
    pub artifact: String,
    pub role: String,
    pub fault_policy: String,
    pub fault_domain: u64,
    pub resource: Option<u64>,
    pub state: String,
    pub generation: u64,
    pub restart_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityRecordManifest {
    pub id: u64,
    pub subject: String,
    pub object: String,
    #[serde(default)]
    pub object_ref: Option<AuthorityObjectRefManifest>,
    pub rights: Vec<String>,
    pub lifetime: String,
    pub class: String,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub owner_task: Option<u64>,
    pub source: String,
    pub generation: u64,
    #[serde(default)]
    pub parent: Option<u64>,
    #[serde(default)]
    pub manifest_decl: bool,
    #[serde(default)]
    pub debug_object_label: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthorityObjectRefManifest {
    pub scope: String,
    pub class: String,
    pub object: ContractObjectRefManifest,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WaitRecordManifest {
    pub id: u64,
    pub owner_task: Option<u64>,
    #[serde(default)]
    pub owner_task_generation: Option<u64>,
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    pub kind: String,
    pub generation: u64,
    pub state: String,
    #[serde(default)]
    pub blockers: Vec<ContractObjectRefManifest>,
    pub deadline: Option<u64>,
    pub cancel_reason: Option<String>,
    pub restart_policy: String,
    pub saved_context: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationRecordManifest {
    pub id: u64,
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    pub code_object: u64,
    #[serde(default)]
    pub code_generation: u64,
    pub artifact: u64,
    pub entry: String,
    pub generation: u64,
    pub state: String,
    pub start_event: u64,
    pub exit_event: Option<u64>,
    pub active_dmw_leases: u32,
    pub blocked_wait: Option<u64>,
    pub trap: Option<u64>,
    pub return_tag: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SimdTrapAttributionManifest {
    pub classification: String,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRefManifest>,
    pub code_requirement_status: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TrapRecordManifest {
    pub id: u64,
    #[serde(default)]
    pub generation: u64,
    pub class: String,
    pub store: Option<u64>,
    #[serde(default)]
    pub store_generation: Option<u64>,
    pub activation: Option<u64>,
    #[serde(default)]
    pub activation_generation: Option<u64>,
    pub code_object: Option<u64>,
    #[serde(default)]
    pub code_generation: Option<u64>,
    pub artifact: Option<u64>,
    #[serde(default)]
    pub artifact_generation: Option<u64>,
    pub offset: Option<u64>,
    #[serde(default)]
    pub target_pc: Option<u64>,
    #[serde(default)]
    pub trap_kind: Option<String>,
    #[serde(default)]
    pub function_index: Option<u32>,
    #[serde(default)]
    pub wasm_offset: Option<u64>,
    #[serde(default)]
    pub debug_symbol: Option<u32>,
    #[serde(default)]
    pub classification_status: Option<String>,
    #[serde(default)]
    pub simd_attribution: Option<SimdTrapAttributionManifest>,
    pub hostcall: Option<String>,
    pub fault_policy: String,
    pub effect: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HostcallTraceManifest {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub abi_version: String,
    #[serde(default)]
    pub frame_size: u16,
    #[serde(default)]
    pub flags: u32,
    pub activation: u64,
    #[serde(default)]
    pub activation_generation: u64,
    #[serde(default)]
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    #[serde(default)]
    pub code_object: u64,
    #[serde(default)]
    pub code_generation: u64,
    #[serde(default)]
    pub artifact: u64,
    #[serde(default)]
    pub artifact_generation: u64,
    pub hostcall_number: u32,
    #[serde(default)]
    pub hostcall_seq: u64,
    #[serde(default)]
    pub caller_offset: u64,
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub subject: String,
    pub object: String,
    pub operation: String,
    #[serde(default)]
    pub args: [u64; 6],
    #[serde(default)]
    pub cap_args: Vec<CapabilityHandleArgManifest>,
    #[serde(default)]
    pub record_mode: String,
    pub allowed: bool,
    pub result: String,
    #[serde(default)]
    pub ret_tag: String,
    #[serde(default)]
    pub ret0: u64,
    #[serde(default)]
    pub ret1: u64,
    #[serde(default)]
    pub trap_out: Option<u64>,
    #[serde(default)]
    pub trap_generation_out: Option<u64>,
    #[serde(default)]
    pub wait_token_out: Option<u64>,
    #[serde(default)]
    pub wait_token_generation_out: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CapabilityHandleArgManifest {
    pub id: u64,
    pub object: String,
    pub generation: u64,
    #[serde(default)]
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub handle_slot: u32,
    #[serde(default)]
    pub handle_generation: u32,
    #[serde(default)]
    pub handle_tag: u64,
    pub rights_mask: u64,
    pub rights: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MigrationObjectManifest {
    pub object: String,
    pub class: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TombstoneManifest {
    pub kind: String,
    pub id: u64,
    pub generation: u64,
    pub died_at: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContractObjectRefManifest {
    pub kind: String,
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContractViolationManifest {
    pub kind: String,
    pub edge: String,
    pub from: ContractObjectRefManifest,
    pub to: Option<ContractObjectRefManifest>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupStepManifest {
    pub step: String,
    pub state: String,
    pub detail: String,
    #[serde(default)]
    pub target: Option<ContractObjectRefManifest>,
    #[serde(default)]
    pub observed_generation: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub event_seq: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupEffectManifest {
    pub kind: String,
    pub target: ContractObjectRefManifest,
    pub expected_generation: u64,
    pub status: String,
    pub event_seq: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CleanupTransactionManifest {
    pub id: u64,
    pub store: u64,
    #[serde(default)]
    pub store_generation: u64,
    #[serde(default)]
    pub target_store_generation: u64,
    #[serde(default)]
    pub result_store_generation: Option<u64>,
    pub activation: Option<u64>,
    #[serde(default)]
    pub activation_generation: Option<u64>,
    pub code_object: Option<u64>,
    #[serde(default)]
    pub code_generation: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub started_at: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    pub state: String,
    pub reason: String,
    pub released_dmw_leases: u32,
    pub cancelled_waits: u32,
    pub revoked_capabilities: Vec<u64>,
    #[serde(default)]
    pub revoked_capability_refs: Vec<ContractObjectRefManifest>,
    pub dropped_resources: u32,
    pub unbound_code_object: bool,
    pub effect: String,
    pub steps: Vec<CleanupStepManifest>,
    #[serde(default)]
    pub effects: Vec<CleanupEffectManifest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MemoryClassPolicyManifest {
    pub class: String,
    pub owner_kind: String,
    pub permissions: String,
    pub migration_policy: String,
    pub snapshot_policy: String,
    pub cleanup_policy: String,
    pub can_alias_guest_memory: bool,
    pub can_cross_pending: bool,
    pub can_be_executable: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BoundaryValidationViolationManifest {
    pub validator: String,
    pub kind: String,
    pub object: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BoundaryValidationReportManifest {
    pub validator: String,
    pub ok: bool,
    pub violation_count: usize,
    pub violations: Vec<BoundaryValidationViolationManifest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubstrateBoundaryManifest {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    #[serde(default)]
    pub active_mmio_authority_count: u32,
    #[serde(default)]
    pub active_dma_authority_count: u32,
    #[serde(default)]
    pub active_irq_authority_count: u32,
    #[serde(default)]
    pub active_packet_device_authority_count: u32,
    #[serde(default)]
    pub active_virtio_queue_authority_count: u32,
    #[serde(default)]
    pub pending_network_inputs: u32,
    #[serde(default)]
    pub random_epoch: u64,
    #[serde(default)]
    pub scheduler_decision_cursor: u64,
    #[serde(default)]
    pub cow_epoch: u64,
    #[serde(default)]
    pub background_copy_pages: u64,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationCapabilityManifest {
    pub subject: String,
    pub object: String,
    pub rights: Vec<String>,
    pub lifetime: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub owner_store: Option<u64>,
    #[serde(default)]
    pub owner_store_generation: Option<u64>,
    #[serde(default)]
    pub owner_task: Option<u64>,
    pub generation: u64,
    #[serde(default)]
    pub revoked: bool,
}
