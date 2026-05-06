use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetFeatureSetRecord {
    pub id: TargetFeatureSetId,
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
    pub generation: Generation,
    pub state: TargetFeatureSetState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl TargetFeatureSetRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorStateRecord {
    pub id: VectorStateId,
    pub owner_activation: ContractObjectRef,
    pub owner_store: ContractObjectRef,
    pub code_object: ContractObjectRef,
    pub target_feature_set: ContractObjectRef,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub register_bytes: u32,
    pub generation: Generation,
    pub state: VectorStateState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl VectorStateRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::VectorState, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimdFaultInjectionRecord {
    pub id: SimdFaultInjectionId,
    pub activation: ContractObjectRef,
    pub code_object: ContractObjectRef,
    pub trap: ContractObjectRef,
    pub target_feature_set: ContractObjectRef,
    pub vector_state: Option<ContractObjectRef>,
    pub kind: SimdFaultInjectionKind,
    pub effect: SimdFaultInjectionEffect,
    pub required_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub injected_faults: u32,
    pub generation: Generation,
    pub state: SimdFaultInjectionState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SimdFaultInjectionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SimdFaultInjection, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimdBenchmarkRecord {
    pub id: SimdBenchmarkId,
    pub target_feature_set: ContractObjectRef,
    pub scalar_code_object: ContractObjectRef,
    pub vector_code_object: ContractObjectRef,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub workload_units: u64,
    pub scalar_nanos: u64,
    pub vector_nanos: u64,
    pub speedup_milli: u64,
    pub context_overhead_nanos: u64,
    pub generation: Generation,
    pub state: SimdBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SimdBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SimdBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimdContextSwitchBenchmarkRecord {
    pub id: SimdContextSwitchBenchmarkId,
    pub preemption: ContractObjectRef,
    pub activation_resume: ContractObjectRef,
    pub saved_vector_state: ContractObjectRef,
    pub restored_vector_state: ContractObjectRef,
    pub target_feature_set: ContractObjectRef,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub sample_count: u64,
    pub scalar_context_switch_nanos: u64,
    pub vector_context_switch_nanos: u64,
    pub overhead_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: SimdContextSwitchBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SimdContextSwitchBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::SimdContextSwitchBenchmark,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferObjectRecord {
    pub id: FramebufferObjectId,
    pub name: String,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub pixel_format: String,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: FramebufferObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayObjectRecord {
    pub id: DisplayObjectId,
    pub name: String,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub mode_name: String,
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
    pub generation: Generation,
    pub state: DisplayObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DisplayObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplayObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayCapabilityRecord {
    pub id: DisplayCapabilityId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operations: Vec<String>,
    pub generation: Generation,
    pub state: DisplayCapabilityState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DisplayCapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplayCapability, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferWindowLeaseRecord {
    pub id: FramebufferWindowLeaseId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub access: String,
    pub generation: Generation,
    pub state: FramebufferWindowLeaseState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferWindowLeaseRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferWindowLease, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferMappingRecord {
    pub id: FramebufferMappingId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub framebuffer_window_lease: FramebufferWindowLeaseId,
    pub framebuffer_window_lease_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
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
    pub generation: Generation,
    pub state: FramebufferMappingState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferMappingRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferMapping, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferWriteRecord {
    pub id: FramebufferWriteId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub framebuffer_mapping: FramebufferMappingId,
    pub framebuffer_mapping_generation: Generation,
    pub framebuffer_window_lease: FramebufferWindowLeaseId,
    pub framebuffer_window_lease_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
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
    pub generation: Generation,
    pub state: FramebufferWriteState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferWriteRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferWrite, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferFlushRegionRecord {
    pub id: FramebufferFlushRegionId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub framebuffer_write: FramebufferWriteId,
    pub framebuffer_write_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub generation: Generation,
    pub state: FramebufferFlushRegionState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferFlushRegionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferFlushRegion, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferDirtyRegionRecord {
    pub id: FramebufferDirtyRegionId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub framebuffer_write: FramebufferWriteId,
    pub framebuffer_write_generation: Generation,
    pub framebuffer_flush_region: Option<FramebufferFlushRegionId>,
    pub framebuffer_flush_region_generation: Option<Generation>,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub generation: Generation,
    pub state: FramebufferDirtyRegionState,
    pub dirty_at_event: EventId,
    pub cleaned_at_event: Option<EventId>,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferDirtyRegionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferDirtyRegion, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayEventLogRecord {
    pub id: DisplayEventLogId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub framebuffer_dirty_region: FramebufferDirtyRegionId,
    pub framebuffer_dirty_region_generation: Generation,
    pub first_event: EventId,
    pub last_event: EventId,
    pub event_count: u64,
    pub flush_count: u64,
    pub dirty_region_count: u64,
    pub generation: Generation,
    pub state: DisplayEventLogState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DisplayEventLogRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplayEventLog, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayCleanupStepRecord {
    pub kind: DisplayCleanupStepKind,
    pub target: ContractObjectRef,
    pub observed_generation: Generation,
    pub status: DisplayCleanupStepStatus,
    pub event: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayCleanupRecord {
    pub id: DisplayCleanupId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub generation: Generation,
    pub state: DisplayCleanupState,
    pub reason: String,
    pub started_at_event: EventId,
    pub completed_at_event: EventId,
    pub unmapped_framebuffer_mappings: Vec<ContractObjectRef>,
    pub released_framebuffer_window_leases: Vec<ContractObjectRef>,
    pub revoked_display_capabilities: Vec<ContractObjectRef>,
    pub revoked_capabilities: Vec<ContractObjectRef>,
    pub steps: Vec<DisplayCleanupStepRecord>,
    pub note: String,
}

impl DisplayCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplayCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplaySnapshotBarrierRecord {
    pub id: DisplaySnapshotBarrierId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub display_cleanup: Option<DisplayCleanupId>,
    pub display_cleanup_generation: Option<Generation>,
    pub active_framebuffer_window_lease_count: u32,
    pub active_framebuffer_mapping_count: u32,
    pub dirty_framebuffer_region_count: u32,
    pub snapshot_validation_ok: bool,
    pub generation: Generation,
    pub state: DisplaySnapshotBarrierState,
    pub validated_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl DisplaySnapshotBarrierRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplaySnapshotBarrier, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayPanicLastFrameRecord {
    pub id: DisplayPanicLastFrameId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub display_snapshot_barrier: DisplaySnapshotBarrierId,
    pub display_snapshot_barrier_generation: Generation,
    pub display_event_log: DisplayEventLogId,
    pub display_event_log_generation: Generation,
    pub framebuffer_write: FramebufferWriteId,
    pub framebuffer_write_generation: Generation,
    pub framebuffer_flush_region: FramebufferFlushRegionId,
    pub framebuffer_flush_region_generation: Generation,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub pixel_format: String,
    pub payload_digest: u64,
    pub summary_digest: u64,
    pub summary_record_bytes: u32,
    pub panic_epoch: u64,
    pub panic_cpu: u32,
    pub panic_reason_code: u32,
    pub panic_record_kind: String,
    pub raw_framebuffer_bytes_exported: bool,
    pub generation: Generation,
    pub state: DisplayPanicLastFrameState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DisplayPanicLastFrameRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DisplayPanicLastFrame, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramebufferBenchmarkRecord {
    pub id: FramebufferBenchmarkId,
    pub scenario: String,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
    pub display_capability: DisplayCapabilityId,
    pub display_capability_generation: Generation,
    pub framebuffer_write: FramebufferWriteId,
    pub framebuffer_write_generation: Generation,
    pub framebuffer_flush_region: FramebufferFlushRegionId,
    pub framebuffer_flush_region_generation: Generation,
    pub display_event_log: DisplayEventLogId,
    pub display_event_log_generation: Generation,
    pub display_snapshot_barrier: DisplaySnapshotBarrierId,
    pub display_snapshot_barrier_generation: Generation,
    pub sample_frames: u32,
    pub sample_bytes: u64,
    pub frame_area_pixels: u64,
    pub write_nanos: u64,
    pub flush_nanos: u64,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub throughput_bytes_per_sec: u64,
    pub flushes_per_sec_milli: u64,
    pub p50_latency_nanos: u64,
    pub p99_latency_nanos: u64,
    pub generation: Generation,
    pub state: FramebufferBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FramebufferBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FramebufferBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDriverCleanupRecord {
    pub id: NetworkDriverCleanupId,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub backend: ContractObjectRef,
    pub cancelled_socket_waits: Vec<ContractObjectRef>,
    pub cancelled_wait_tokens: Vec<ContractObjectRef>,
    pub revoked_packet_capabilities: Vec<ContractObjectRef>,
    pub generation: Generation,
    pub state: NetworkDriverCleanupState,
    pub started_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub reason: String,
    pub note: String,
}

impl NetworkDriverCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkDriverCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkGenerationAuditRecord {
    pub id: NetworkGenerationAuditId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub packet_descriptor: PacketDescriptorObjectId,
    pub packet_descriptor_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub dma_buffer: ContractObjectRef,
    pub device_capability: ContractObjectRef,
    pub rejected_packet_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub generation: Generation,
    pub state: NetworkGenerationAuditState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkGenerationAuditRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkGenerationAudit, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFaultInjectionRecord {
    pub id: NetworkFaultInjectionId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub packet_descriptor: Option<PacketDescriptorObjectId>,
    pub packet_descriptor_generation: Option<Generation>,
    pub packet_buffer: Option<PacketBufferObjectId>,
    pub packet_buffer_generation: Option<Generation>,
    pub endpoint: Option<EndpointObjectId>,
    pub endpoint_generation: Option<Generation>,
    pub socket: Option<SocketObjectId>,
    pub socket_generation: Option<Generation>,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub direction: PacketBufferDirection,
    pub kind: NetworkFaultInjectionKind,
    pub effect: NetworkFaultInjectionEffect,
    pub injected_packets: u32,
    pub dropped_packets: u32,
    pub error_packets: u32,
    pub error_code: String,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkFaultInjectionState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkFaultInjectionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::NetworkFaultInjection, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationResumeRecord {
    pub id: ActivationResumeId,
    pub scheduler_decision: SchedulerDecisionId,
    pub scheduler_decision_generation: Generation,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub context: Option<ActivationContextId>,
    pub context_generation_before: Option<Generation>,
    pub context_generation_after: Option<Generation>,
    pub saved_context: Option<SavedContextId>,
    pub saved_context_generation: Option<Generation>,
    pub saved_vector_state: Option<ContractObjectRef>,
    pub restored_vector_state: Option<ContractObjectRef>,
    pub vector_status: ActivationVectorState,
    pub vector_restored_at_event: Option<EventId>,
    pub generation: Generation,
    pub state: ActivationResumeState,
    pub resumed_at_event: EventId,
    pub note: String,
}

impl ActivationResumeRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ActivationResume, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreemptionLatencySampleRecord {
    pub id: PreemptionLatencySampleId,
    pub timer_interrupt: TimerInterruptId,
    pub timer_interrupt_generation: Generation,
    pub preemption: PreemptionId,
    pub preemption_generation: Generation,
    pub scheduler_decision: SchedulerDecisionId,
    pub scheduler_decision_generation: Generation,
    pub activation_resume: ActivationResumeId,
    pub activation_resume_generation: Generation,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub interrupt_recorded_at_event: EventId,
    pub preempted_at_event: EventId,
    pub decided_at_event: EventId,
    pub resumed_at_event: EventId,
    pub interrupt_to_preempt_events: u64,
    pub preempt_to_decision_events: u64,
    pub decision_to_resume_events: u64,
    pub interrupt_to_resume_events: u64,
    pub measured_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: PreemptionLatencySampleState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PreemptionLatencySampleRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::PreemptionLatencySample,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationWaitRecord {
    pub id: ActivationWaitId,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after_block: Generation,
    pub activation_generation_after_cancel: Option<Generation>,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub queue: Option<RunnableQueueId>,
    pub queue_generation: Option<Generation>,
    pub generation: Generation,
    pub state: ActivationWaitState,
    pub blocked_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl ActivationWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ActivationWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationCleanupStepRecord {
    pub kind: ActivationCleanupStepKind,
    pub target: ContractObjectRef,
    pub observed_generation: Generation,
    pub status: ActivationCleanupStepStatus,
    pub event: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationCleanupRecord {
    pub id: ActivationCleanupId,
    pub store: StoreId,
    pub target_store_generation: Generation,
    pub result_store_generation: Generation,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub wait: Option<WaitId>,
    pub wait_generation: Option<Generation>,
    pub owner_task: TaskId,
    pub owner_task_generation_before: Generation,
    pub owner_task_generation_after: Generation,
    pub generation: Generation,
    pub state: ActivationCleanupState,
    pub reason: String,
    pub started_at_event: EventId,
    pub completed_at_event: EventId,
    pub steps: Vec<ActivationCleanupStepRecord>,
    pub note: String,
}

impl ActivationCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ActivationCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub id: ResourceId,
    pub label: String,
    pub kind: ResourceKind,
    pub owner_task: Option<TaskId>,
    pub owner_store: Option<StoreId>,
    pub generation: Generation,
    pub live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBindingRecord {
    pub id: AuthorityId,
    pub resource: ResourceId,
    pub kind: AuthorityKind,
    pub subject: String,
    pub object: String,
    pub object_ref: AuthorityObjectRef,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub operations: OperationSet,
    pub lifetime: String,
    pub generation: Generation,
    pub state: AuthorityState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitRecord {
    pub id: WaitId,
    pub owner_task: Option<TaskId>,
    pub owner_task_generation: Option<Generation>,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub kind: SemanticWaitKind,
    pub generation: Generation,
    pub state: WaitState,
    pub blockers: Vec<ContractObjectRef>,
    pub deadline: Option<u64>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub restart_policy: RestartPolicy,
    pub saved_context: Option<String>,
}

impl WaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::WaitToken, self.id, self.generation)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WaitIndex {
    pub by_resource: Vec<(ContractObjectRef, WaitId)>,
    pub by_task: Vec<(TaskId, Generation, WaitId)>,
    pub by_store: Vec<(StoreId, Generation, WaitId)>,
    pub by_deadline: Vec<(u64, WaitId)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultDomainRecord {
    pub id: FaultDomainId,
    pub name: String,
    pub role: String,
    pub state: FaultDomainState,
    pub generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRecord {
    pub id: StoreId,
    pub package: String,
    pub artifact: String,
    pub role: String,
    pub fault_policy: String,
    pub fault_domain: FaultDomainId,
    pub resource: Option<ResourceId>,
    pub state: StoreState,
    pub generation: Generation,
    pub restart_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreDropReport {
    pub store: StoreId,
    pub generation: Generation,
    pub previous_resource: Option<ResourceId>,
    pub closed_resources: usize,
    pub revoked_authorities: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreRebindReport {
    pub store: StoreId,
    pub generation: Generation,
    pub resource: ResourceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreResourceCleanupReport {
    pub store: StoreId,
    pub closed_resources: usize,
    pub revoked_authorities: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Begun,
    Committed,
    RolledBack,
}

impl TransactionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Begun => "begun",
            Self::Committed => "committed",
            Self::RolledBack => "rolled-back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticTransactionRecord {
    pub id: TransactionId,
    pub label: String,
    pub store: Option<StoreId>,
    pub task: Option<TaskId>,
    pub state: TransactionState,
    pub generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathPlanRecord {
    pub id: PlanId,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub generation: Generation,
    pub valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureEffect {
    CompleteWithErrno(i32),
    RetryTransparent,
    RestartSyscall { wait: Option<WaitId> },
    CancelWaitToken { wait: WaitId, errno: i32 },
    MarkResourceDead(ResourceId),
    KillTask(TaskId),
    RebootFaultDomain(FaultDomainId),
}

impl FailureEffect {
    pub fn summary(self) -> String {
        match self {
            Self::CompleteWithErrno(errno) => format!("complete-with-errno({errno})"),
            Self::RetryTransparent => "retry-transparent".to_string(),
            Self::RestartSyscall { wait: Some(wait) } => format!("restart-syscall(wait={wait})"),
            Self::RestartSyscall { wait: None } => "restart-syscall".to_string(),
            Self::CancelWaitToken { wait, errno } => {
                format!("cancel-wait-token(wait={wait}, errno={errno})")
            }
            Self::MarkResourceDead(resource) => format!("mark-resource-dead({resource})"),
            Self::KillTask(task) => format!("kill-task({task})"),
            Self::RebootFaultDomain(domain) => format!("reboot-fault-domain({domain})"),
        }
    }
}
