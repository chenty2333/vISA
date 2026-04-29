use serde::{Deserialize, Serialize};

use crate::target_runtime::{CapabilityHandleArgManifest, ContractObjectRefManifest};

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
pub struct IntegratedSmpPreemptionCleanupManifest {
    pub id: u64,
    pub scenario: String,
    pub stress_run: u64,
    pub stress_run_generation: u64,
    pub preemption: u64,
    pub preemption_generation: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub saved_context: u64,
    pub saved_context_generation: u64,
    pub remote_preempt: u64,
    pub remote_preempt_generation: u64,
    pub activation_cleanup: u64,
    pub activation_cleanup_generation: u64,
    pub smp_cleanup_quiescence: u64,
    pub smp_cleanup_quiescence_generation: u64,
    pub cleanup_store: u64,
    pub target_store_generation: u64,
    pub result_store_generation: u64,
    pub cleanup_activation: u64,
    pub cleanup_activation_generation_after: u64,
    pub hart_count: u32,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedSmpNetworkFaultManifest {
    pub id: u64,
    pub scenario: String,
    pub network_driver_cleanup: u64,
    pub network_driver_cleanup_generation: u64,
    pub smp_stress_run: u64,
    pub smp_stress_run_generation: u64,
    pub remote_preempt: u64,
    pub remote_preempt_generation: u64,
    pub smp_cleanup_quiescence: u64,
    pub smp_cleanup_quiescence_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub adapter: u64,
    pub adapter_generation: u64,
    pub backend: ContractObjectRefManifest,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub cancelled_socket_wait_count: u32,
    pub cancelled_wait_token_count: u32,
    pub revoked_packet_capability_count: u32,
    pub hart_count: u32,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedDiskPreemptFaultManifest {
    pub id: u64,
    pub scenario: String,
    pub preemption: u64,
    pub preemption_generation: u64,
    pub timer_interrupt: u64,
    pub timer_interrupt_generation: u64,
    pub block_pending_io_policy: u64,
    pub block_pending_io_policy_generation: u64,
    pub block_wait: u64,
    pub block_wait_generation: u64,
    pub wait: u64,
    pub wait_generation: u64,
    pub block_request: u64,
    pub block_request_generation: u64,
    pub retry_request: Option<u64>,
    pub retry_request_generation: Option<u64>,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_range: u64,
    pub block_range_generation: u64,
    pub driver_store: Option<u64>,
    pub driver_store_generation: Option<u64>,
    pub action: String,
    pub errno: i32,
    pub preempted_activation: u64,
    pub preempted_activation_generation_after: u64,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedSimdMigrationManifest {
    pub id: u64,
    pub scenario: String,
    pub activation_migration: u64,
    pub activation_migration_generation: u64,
    pub target_feature_set: u64,
    pub target_feature_set_generation: u64,
    pub source_vector_state: ContractObjectRefManifest,
    pub migrated_vector_state: ContractObjectRefManifest,
    pub activation: u64,
    pub activation_generation_before: u64,
    pub activation_generation_after: u64,
    pub context: u64,
    pub context_generation_after: u64,
    pub source_hart: u64,
    pub source_hart_generation: u64,
    pub target_hart: u64,
    pub target_hart_generation: u64,
    pub source_queue: u64,
    pub source_queue_generation: u64,
    pub target_queue: u64,
    pub target_queue_generation: u64,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedNetworkDiskIoManifest {
    pub id: u64,
    pub scenario: String,
    pub network_benchmark: u64,
    pub network_benchmark_generation: u64,
    pub block_benchmark: u64,
    pub block_benchmark_generation: u64,
    pub network_owner_store: u64,
    pub network_owner_store_generation: u64,
    pub network_adapter: u64,
    pub network_adapter_generation: u64,
    pub packet_device: u64,
    pub packet_device_generation: u64,
    pub socket: u64,
    pub socket_generation: u64,
    pub block_backend: ContractObjectRefManifest,
    pub block_device: u64,
    pub block_device_generation: u64,
    pub block_request_queue: u64,
    pub block_request_queue_generation: u64,
    pub block_dma_buffer: u64,
    pub block_dma_buffer_generation: u64,
    pub network_sample_bytes: u64,
    pub block_sample_bytes: u64,
    pub network_sample_packets: u32,
    pub block_sample_requests: u32,
    pub concurrent_window_nanos: u64,
    pub combined_throughput_bytes_per_sec: u64,
    pub max_p99_latency_nanos: u64,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedDisplaySchedulerLoadManifest {
    pub id: u64,
    pub scenario: String,
    pub framebuffer_benchmark: u64,
    pub framebuffer_benchmark_generation: u64,
    pub scheduler_decision: u64,
    pub scheduler_decision_generation: u64,
    pub owner_store: u64,
    pub owner_store_generation: u64,
    pub owner_task: u64,
    pub owner_task_generation: u64,
    pub queue: u64,
    pub queue_generation: u64,
    pub selected_activation: u64,
    pub selected_activation_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub display_capability: u64,
    pub display_capability_generation: u64,
    pub framebuffer_write: u64,
    pub framebuffer_write_generation: u64,
    pub framebuffer_flush_region: u64,
    pub framebuffer_flush_region_generation: u64,
    pub display_event_log: u64,
    pub display_event_log_generation: u64,
    pub sample_frames: u32,
    pub sample_bytes: u64,
    pub scheduler_load_units: u64,
    pub display_measured_nanos: u64,
    pub scheduler_decided_at_event: u64,
    pub display_recorded_at_event: u64,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedSnapshotIoLeaseBarrierManifest {
    pub id: u64,
    pub scenario: String,
    pub smp_snapshot_barrier: u64,
    pub smp_snapshot_barrier_generation: u64,
    pub io_cleanup: u64,
    pub io_cleanup_generation: u64,
    pub display_snapshot_barrier: u64,
    pub display_snapshot_barrier_generation: u64,
    pub driver_store: u64,
    pub driver_store_generation: u64,
    pub device: u64,
    pub device_generation: u64,
    pub display: u64,
    pub display_generation: u64,
    pub framebuffer: u64,
    pub framebuffer_generation: u64,
    pub active_dmw_lease_count: u32,
    pub in_flight_dma_count: u32,
    pub raw_dma_binding_count: u32,
    pub raw_mmio_binding_count: u32,
    pub active_framebuffer_window_lease_count: u32,
    pub active_framebuffer_mapping_count: u32,
    pub dirty_framebuffer_region_count: u32,
    pub released_dma_buffers: u32,
    pub released_mmio_regions: u32,
    pub released_irq_lines: u32,
    pub released_framebuffer_window_leases: u32,
    pub revoked_device_capabilities: u32,
    pub revoked_display_capabilities: u32,
    pub smp_barrier_event: u64,
    pub io_cleanup_completed_event: u64,
    pub display_barrier_event: u64,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedCodePublishSmpWorkloadManifest {
    pub id: u64,
    pub scenario: String,
    pub smp_stress_run: u64,
    pub smp_stress_run_generation: u64,
    pub smp_code_publish_barrier: u64,
    pub smp_code_publish_barrier_generation: u64,
    pub publish_rendezvous: u64,
    pub publish_rendezvous_generation: u64,
    pub publish_safe_point: u64,
    pub publish_safe_point_generation: u64,
    pub hart_count: u32,
    pub workload_iterations: u32,
    pub observed_safe_point_count: u32,
    pub observed_rendezvous_count: u32,
    pub observed_code_publish_barrier_count: u32,
    pub code_publish_epoch_before: u64,
    pub code_publish_epoch_after: u64,
    pub remote_icache_sync_required: bool,
    pub code_publish_executed: bool,
    pub participant_count: u32,
    pub stress_event_log_cursor: u64,
    pub barrier_event: u64,
    pub stress_recorded_at_event: u64,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedDisplayPanicManifest {
    pub id: u64,
    pub scenario: String,
    pub substrate_panic_event: u64,
    pub substrate_panic_epoch: u64,
    pub substrate_panic_cpu: u32,
    pub substrate_panic_reason_code: u32,
    pub display_panic_last_frame: u64,
    pub display_panic_last_frame_generation: u64,
    pub panic_ring_bytes: u32,
    pub panic_record_max_bytes: u32,
    pub panic_ring_oldest_seq: u64,
    pub panic_ring_newest_seq: u64,
    pub panic_ring_record_count: u32,
    pub panic_ring_lost_count: u64,
    pub jsonl_frame_count: u32,
    pub contract_panic_summary_records: u32,
    pub last_frame_summary_records: u32,
    pub corrupt_record_count: u32,
    pub truncated_record_count: u32,
    pub summary_record_bytes: u32,
    pub raw_framebuffer_bytes_exported: bool,
    pub panic_path_allocates: bool,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegratedOsctlTraceReplayManifest {
    pub id: u64,
    pub scenario: String,
    pub integrated_smp_preemption_cleanup: u64,
    pub integrated_smp_preemption_cleanup_generation: u64,
    pub integrated_smp_network_fault: u64,
    pub integrated_smp_network_fault_generation: u64,
    pub integrated_disk_preempt_fault: u64,
    pub integrated_disk_preempt_fault_generation: u64,
    pub integrated_simd_migration: u64,
    pub integrated_simd_migration_generation: u64,
    pub integrated_network_disk_io: u64,
    pub integrated_network_disk_io_generation: u64,
    pub integrated_display_scheduler_load: u64,
    pub integrated_display_scheduler_load_generation: u64,
    pub integrated_snapshot_io_lease_barrier: u64,
    pub integrated_snapshot_io_lease_barrier_generation: u64,
    pub integrated_code_publish_smp_workload: u64,
    pub integrated_code_publish_smp_workload_generation: u64,
    pub integrated_display_panic: u64,
    pub integrated_display_panic_generation: u64,
    pub replay_event_cursor: u64,
    pub stable_view_count: u32,
    pub historical_edge_count: u32,
    pub replayed_root_count: u32,
    pub integrated_scenario_count: u32,
    pub replay_fixture_count: u32,
    pub contract_validation_ok: bool,
    pub replay_validation_ok: bool,
    pub graph_history_ok: bool,
    pub roots_match_counts: bool,
    pub invariant_checks: u32,
    pub generation: u64,
    pub state: String,
    pub recorded_at_event: u64,
    pub note: String,
}
