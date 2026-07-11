use alloc::{string::String, vec::Vec};

use super::super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HartRecord {
    pub id: HartId,
    pub hardware_id: u32,
    pub label: String,
    pub state: HartState,
    pub generation: Generation,
    pub boot: bool,
    pub current_activation: Option<ActivationId>,
    pub current_activation_generation: Option<Generation>,
    pub current_task: Option<TaskId>,
    pub current_task_generation: Option<Generation>,
    pub current_store: Option<StoreId>,
    pub current_store_generation: Option<Generation>,
    pub last_event: Option<EventId>,
    pub last_current_event: Option<EventId>,
    pub note: String,
}

impl HartRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Hart, self.id as u64, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: TaskId,
    pub label: String,
    pub frontend: FrontendKind,
    pub state: TaskState,
    pub fault_domain: Option<FaultDomainId>,
    pub pending_wait: Option<WaitId>,
    pub generation: Generation,
    pub resources: Vec<ResourceId>,
}

impl TaskRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Task, self.id as u64, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeActivationRecord {
    pub id: ActivationId,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub code_object: Option<ContractObjectRef>,
    pub generation: Generation,
    pub state: RuntimeActivationState,
    pub runnable_queue: Option<RunnableQueueId>,
    pub runnable_queue_generation: Option<Generation>,
    pub last_event: Option<EventId>,
}

impl RuntimeActivationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Activation, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpiEventRecord {
    pub id: IpiEventId,
    pub source_hart: HartId,
    pub source_hart_generation: Generation,
    pub source_hardware_hart: u32,
    pub target_hart: HartId,
    pub target_hart_generation: Generation,
    pub target_hardware_hart: u32,
    pub kind: IpiEventKind,
    pub generation: Generation,
    pub state: IpiEventState,
    pub recorded_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl IpiEventRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IpiEvent, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePreemptRecord {
    pub id: RemotePreemptId,
    pub ipi: IpiEventId,
    pub ipi_generation: Generation,
    pub source_hart: HartId,
    pub source_hart_generation: Generation,
    pub target_hart: HartId,
    pub target_hart_generation_before: Generation,
    pub target_hart_generation_after: Generation,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub generation: Generation,
    pub state: RemotePreemptState,
    pub preempted_at_event: EventId,
    pub note: String,
}

impl RemotePreemptRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::RemotePreempt, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteParkRecord {
    pub id: RemoteParkId,
    pub ipi: IpiEventId,
    pub ipi_generation: Generation,
    pub source_hart: HartId,
    pub source_hart_generation: Generation,
    pub target_hart: HartId,
    pub target_hart_generation_before: Generation,
    pub target_hart_generation_after: Generation,
    pub generation: Generation,
    pub state: RemoteParkState,
    pub parked_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl RemoteParkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::RemotePark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnableQueueEntry {
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub enqueued_at: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnableQueueRecord {
    pub id: RunnableQueueId,
    pub label: String,
    pub generation: Generation,
    pub state: RunnableQueueState,
    pub owner_hart: Option<HartId>,
    pub owner_hart_generation: Option<Generation>,
    pub entries: Vec<RunnableQueueEntry>,
}

impl RunnableQueueRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::RunnableQueue, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationContextRecord {
    pub id: ActivationContextId,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub generation: Generation,
    pub state: ActivationContextState,
    pub current_saved_context: Option<SavedContextId>,
    pub current_saved_context_generation: Option<Generation>,
    pub vector_state: Option<ContractObjectRef>,
    pub vector_status: ActivationVectorState,
    pub vector_state_event: Option<EventId>,
    pub last_event: Option<EventId>,
}

impl ActivationContextRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ActivationContext, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedContextRecord {
    pub id: SavedContextId,
    pub context: ActivationContextId,
    pub context_generation: Generation,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub source_preemption: Option<PreemptionId>,
    pub source_preemption_generation: Option<Generation>,
    pub generation: Generation,
    pub state: SavedContextState,
    pub reason: SavedContextReason,
    pub pc: u64,
    pub sp: u64,
    pub flags: u64,
    pub integer_registers: u16,
    pub vector_state: Option<ContractObjectRef>,
    pub vector_status: ActivationVectorState,
    pub vector_saved_at_event: Option<EventId>,
    pub saved_at_event: EventId,
    pub note: String,
}

impl SavedContextRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SavedContext, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerInterruptRecord {
    pub id: TimerInterruptId,
    pub timer_epoch: u64,
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub target_activation: Option<ActivationId>,
    pub target_activation_generation: Option<Generation>,
    pub target_task: Option<TaskId>,
    pub target_task_generation: Option<Generation>,
    pub generation: Generation,
    pub state: TimerInterruptState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl TimerInterruptRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::TimerInterrupt, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HartEventAttributionRecord {
    pub id: HartEventAttributionId,
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub event: EventId,
    pub event_source: String,
    pub event_kind: String,
    pub activation: Option<ActivationId>,
    pub activation_generation: Option<Generation>,
    pub task: Option<TaskId>,
    pub task_generation: Option<Generation>,
    pub store: Option<StoreId>,
    pub store_generation: Option<Generation>,
    pub generation: Generation,
    pub state: HartEventAttributionState,
    pub note: String,
}

impl HartEventAttributionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::HartEventAttribution, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreemptionRecord {
    pub id: PreemptionId,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub timer_interrupt: TimerInterruptId,
    pub timer_interrupt_generation: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub generation: Generation,
    pub state: PreemptionState,
    pub preempted_at_event: EventId,
    pub note: String,
}

impl PreemptionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Preemption, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerDecisionRecord {
    pub id: SchedulerDecisionId,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub selected_activation: ActivationId,
    pub selected_activation_generation: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub generation: Generation,
    pub state: SchedulerDecisionState,
    pub decided_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SchedulerDecisionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SchedulerDecision, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossHartSchedulerDecisionRecord {
    pub id: CrossHartSchedulerDecisionId,
    pub scheduler_decision: SchedulerDecisionId,
    pub scheduler_decision_generation: Generation,
    pub deciding_hart: HartId,
    pub deciding_hart_generation: Generation,
    pub target_hart: HartId,
    pub target_hart_generation: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub queue_owner_hart_generation: Generation,
    pub selected_activation: ActivationId,
    pub selected_activation_generation: Generation,
    pub generation: Generation,
    pub state: CrossHartSchedulerDecisionState,
    pub decided_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl CrossHartSchedulerDecisionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::CrossHartSchedulerDecision,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationMigrationRecord {
    pub id: ActivationMigrationId,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub source_hart: HartId,
    pub source_hart_generation: Generation,
    pub target_hart: HartId,
    pub target_hart_generation: Generation,
    pub source_queue: RunnableQueueId,
    pub source_queue_generation: Generation,
    pub source_queue_owner_hart_generation: Generation,
    pub target_queue: RunnableQueueId,
    pub target_queue_generation: Generation,
    pub target_queue_owner_hart_generation: Generation,
    pub context: Option<ActivationContextId>,
    pub context_generation_before: Option<Generation>,
    pub context_generation_after: Option<Generation>,
    pub source_vector_state: Option<ContractObjectRef>,
    pub migrated_vector_state: Option<ContractObjectRef>,
    pub vector_status: ActivationVectorState,
    pub vector_migrated_at_event: Option<EventId>,
    pub generation: Generation,
    pub state: ActivationMigrationState,
    pub migrated_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl ActivationMigrationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ActivationMigration, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpSafePointParticipantRecord {
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub hart_state: HartState,
    pub current_activation: Option<ActivationId>,
    pub current_activation_generation: Option<Generation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpSafePointRecord {
    pub id: SmpSafePointId,
    pub coordinator_hart: HartId,
    pub coordinator_hart_generation: Generation,
    pub participants: Vec<SmpSafePointParticipantRecord>,
    pub generation: Generation,
    pub state: SmpSafePointState,
    pub recorded_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SmpSafePointRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpSafePoint, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopTheWorldRendezvousParticipantRecord {
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub hart_state: HartState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopTheWorldRendezvousRecord {
    pub id: StopTheWorldRendezvousId,
    pub epoch: u64,
    pub safe_point: SmpSafePointId,
    pub safe_point_generation: Generation,
    pub coordinator_hart: HartId,
    pub coordinator_hart_generation: Generation,
    pub participants: Vec<StopTheWorldRendezvousParticipantRecord>,
    pub stop_new_activations: bool,
    pub generation: Generation,
    pub state: StopTheWorldRendezvousState,
    pub completed_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl StopTheWorldRendezvousRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::StopTheWorldRendezvous, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpCodePublishBarrierParticipantRecord {
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub last_seen_code_epoch_before: u64,
    pub last_seen_code_epoch_after: u64,
    pub semantic_icache_sync: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpCodePublishBarrierRecord {
    pub id: SmpCodePublishBarrierId,
    pub rendezvous: StopTheWorldRendezvousId,
    pub rendezvous_generation: Generation,
    pub rendezvous_epoch: u64,
    pub code_publish_epoch_before: u64,
    pub code_publish_epoch_after: u64,
    pub participants: Vec<SmpCodePublishBarrierParticipantRecord>,
    pub remote_icache_sync_required: bool,
    pub code_publish_executed: bool,
    pub generation: Generation,
    pub state: SmpCodePublishBarrierState,
    pub validated_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SmpCodePublishBarrierRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpCodePublishBarrier, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpCleanupQuiescenceParticipantRecord {
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub hart_state: HartState,
    pub current_activation: Option<ActivationId>,
    pub current_activation_generation: Option<Generation>,
    pub current_store: Option<StoreId>,
    pub current_store_generation: Option<Generation>,
    pub quiesced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpCleanupQuiescenceRecord {
    pub id: SmpCleanupQuiescenceId,
    pub cleanup: ActivationCleanupId,
    pub cleanup_generation: Generation,
    pub store: StoreId,
    pub target_store_generation: Generation,
    pub result_store_generation: Generation,
    pub activation: ActivationId,
    pub activation_generation_after: Generation,
    pub rendezvous: StopTheWorldRendezvousId,
    pub rendezvous_generation: Generation,
    pub rendezvous_epoch: u64,
    pub participants: Vec<SmpCleanupQuiescenceParticipantRecord>,
    pub no_running_activation: bool,
    pub no_pending_wait: bool,
    pub no_live_capability: bool,
    pub no_live_resource: bool,
    pub generation: Generation,
    pub state: SmpCleanupQuiescenceState,
    pub validated_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SmpCleanupQuiescenceRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpCleanupQuiescence, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpSnapshotBarrierParticipantRecord {
    pub hart: HartId,
    pub hart_generation: Generation,
    pub hardware_hart: u32,
    pub hart_state: HartState,
    pub event_log_cursor_observed: EventId,
    pub snapshot_safe: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpSnapshotBarrierRecord {
    pub id: SmpSnapshotBarrierId,
    pub rendezvous: StopTheWorldRendezvousId,
    pub rendezvous_generation: Generation,
    pub rendezvous_epoch: u64,
    pub event_log_cursor: EventId,
    pub participants: Vec<SmpSnapshotBarrierParticipantRecord>,
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
    pub generation: Generation,
    pub state: SmpSnapshotBarrierState,
    pub validated_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SmpSnapshotBarrierRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpSnapshotBarrier, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpStressRunRecord {
    pub id: SmpStressRunId,
    pub scenario: String,
    pub iterations: u32,
    pub hart_count: u32,
    pub event_log_cursor: EventId,
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
    pub last_safe_point: SmpSafePointId,
    pub last_safe_point_generation: Generation,
    pub last_rendezvous: StopTheWorldRendezvousId,
    pub last_rendezvous_generation: Generation,
    pub last_code_publish_barrier: SmpCodePublishBarrierId,
    pub last_code_publish_barrier_generation: Generation,
    pub last_cleanup_quiescence: SmpCleanupQuiescenceId,
    pub last_cleanup_quiescence_generation: Generation,
    pub last_snapshot_barrier: SmpSnapshotBarrierId,
    pub last_snapshot_barrier_generation: Generation,
    pub last_activation_migration: ActivationMigrationId,
    pub last_activation_migration_generation: Generation,
    pub last_remote_preempt: RemotePreemptId,
    pub last_remote_preempt_generation: Generation,
    pub last_remote_park: RemoteParkId,
    pub last_remote_park_generation: Generation,
    pub generation: Generation,
    pub state: SmpStressRunState,
    pub recorded_at_event: EventId,
    pub reason: String,
    pub note: String,
}

impl SmpStressRunRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpStressRun, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmpScalingBenchmarkRecord {
    pub id: SmpScalingBenchmarkId,
    pub scenario: String,
    pub stress_run: SmpStressRunId,
    pub stress_run_generation: Generation,
    pub hart_count: u32,
    pub workload_units: u64,
    pub baseline_single_hart_nanos: u64,
    pub measured_smp_nanos: u64,
    pub budget_nanos: u64,
    pub speedup_milli: u64,
    pub efficiency_milli: u64,
    pub event_log_cursor: EventId,
    pub stress_safe_point_count: u32,
    pub stress_rendezvous_count: u32,
    pub stress_property_failures: u32,
    pub generation: Generation,
    pub state: SmpScalingBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SmpScalingBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SmpScalingBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedSmpPreemptionCleanupRecord {
    pub id: IntegratedSmpPreemptionCleanupId,
    pub scenario: String,
    pub stress_run: SmpStressRunId,
    pub stress_run_generation: Generation,
    pub preemption: PreemptionId,
    pub preemption_generation: Generation,
    pub timer_interrupt: TimerInterruptId,
    pub timer_interrupt_generation: Generation,
    pub saved_context: SavedContextId,
    pub saved_context_generation: Generation,
    pub remote_preempt: RemotePreemptId,
    pub remote_preempt_generation: Generation,
    pub activation_cleanup: ActivationCleanupId,
    pub activation_cleanup_generation: Generation,
    pub smp_cleanup_quiescence: SmpCleanupQuiescenceId,
    pub smp_cleanup_quiescence_generation: Generation,
    pub cleanup_store: StoreId,
    pub target_store_generation: Generation,
    pub result_store_generation: Generation,
    pub cleanup_activation: ActivationId,
    pub cleanup_activation_generation_after: Generation,
    pub hart_count: u32,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedSmpPreemptionCleanupState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedSmpPreemptionCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedSmpPreemptionCleanup,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedSmpNetworkFaultRecord {
    pub id: IntegratedSmpNetworkFaultId,
    pub scenario: String,
    pub network_driver_cleanup: NetworkDriverCleanupId,
    pub network_driver_cleanup_generation: Generation,
    pub smp_stress_run: SmpStressRunId,
    pub smp_stress_run_generation: Generation,
    pub remote_preempt: RemotePreemptId,
    pub remote_preempt_generation: Generation,
    pub smp_cleanup_quiescence: SmpCleanupQuiescenceId,
    pub smp_cleanup_quiescence_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub backend: ContractObjectRef,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub cancelled_socket_wait_count: u32,
    pub cancelled_wait_token_count: u32,
    pub revoked_packet_capability_count: u32,
    pub hart_count: u32,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedSmpNetworkFaultState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedSmpNetworkFaultRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedSmpNetworkFault,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedDiskPreemptFaultRecord {
    pub id: IntegratedDiskPreemptFaultId,
    pub scenario: String,
    pub preemption: PreemptionId,
    pub preemption_generation: Generation,
    pub timer_interrupt: TimerInterruptId,
    pub timer_interrupt_generation: Generation,
    pub block_pending_io_policy: BlockPendingIoPolicyId,
    pub block_pending_io_policy_generation: Generation,
    pub block_wait: BlockWaitId,
    pub block_wait_generation: Generation,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub retry_request: Option<BlockRequestObjectId>,
    pub retry_request_generation: Option<Generation>,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub driver_store: Option<StoreId>,
    pub driver_store_generation: Option<Generation>,
    pub action: BlockPendingIoAction,
    pub errno: i32,
    pub preempted_activation: ActivationId,
    pub preempted_activation_generation_after: Generation,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedDiskPreemptFaultState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedDiskPreemptFaultRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedDiskPreemptFault,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedSimdMigrationRecord {
    pub id: IntegratedSimdMigrationId,
    pub scenario: String,
    pub activation_migration: ActivationMigrationId,
    pub activation_migration_generation: Generation,
    pub target_feature_set: TargetFeatureSetId,
    pub target_feature_set_generation: Generation,
    pub source_vector_state: ContractObjectRef,
    pub migrated_vector_state: ContractObjectRef,
    pub activation: ActivationId,
    pub activation_generation_before: Generation,
    pub activation_generation_after: Generation,
    pub context: ActivationContextId,
    pub context_generation_after: Generation,
    pub source_hart: HartId,
    pub source_hart_generation: Generation,
    pub target_hart: HartId,
    pub target_hart_generation: Generation,
    pub source_queue: RunnableQueueId,
    pub source_queue_generation: Generation,
    pub target_queue: RunnableQueueId,
    pub target_queue_generation: Generation,
    pub simd_abi: String,
    pub vector_register_count: u16,
    pub vector_register_bits: u16,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedSimdMigrationState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedSimdMigrationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedSimdMigration,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedNetworkDiskIoRecord {
    pub id: IntegratedNetworkDiskIoId,
    pub scenario: String,
    pub network_benchmark: NetworkBenchmarkId,
    pub network_benchmark_generation: Generation,
    pub block_benchmark: BlockBenchmarkId,
    pub block_benchmark_generation: Generation,
    pub network_owner_store: StoreId,
    pub network_owner_store_generation: Generation,
    pub network_adapter: NetworkStackAdapterId,
    pub network_adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub block_backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_request_queue: BlockRequestQueueId,
    pub block_request_queue_generation: Generation,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
    pub network_sample_bytes: u64,
    pub block_sample_bytes: u64,
    pub network_sample_packets: u32,
    pub block_sample_requests: u32,
    pub concurrent_window_nanos: u64,
    pub combined_throughput_bytes_per_sec: u64,
    pub max_p99_latency_nanos: u64,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedNetworkDiskIoState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedNetworkDiskIoRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedNetworkDiskIo,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedDisplaySchedulerLoadRecord {
    pub id: IntegratedDisplaySchedulerLoadId,
    pub scenario: String,
    pub framebuffer_benchmark: FramebufferBenchmarkId,
    pub framebuffer_benchmark_generation: Generation,
    pub scheduler_decision: SchedulerDecisionId,
    pub scheduler_decision_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub owner_task: TaskId,
    pub owner_task_generation: Generation,
    pub queue: RunnableQueueId,
    pub queue_generation: Generation,
    pub selected_activation: ActivationId,
    pub selected_activation_generation: Generation,
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
    pub sample_frames: u32,
    pub sample_bytes: u64,
    pub scheduler_load_units: u64,
    pub display_measured_nanos: u64,
    pub scheduler_decided_at_event: EventId,
    pub display_recorded_at_event: EventId,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedDisplaySchedulerLoadState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedDisplaySchedulerLoadRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedDisplaySchedulerLoad,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedSnapshotIoLeaseBarrierRecord {
    pub id: IntegratedSnapshotIoLeaseBarrierId,
    pub scenario: String,
    pub smp_snapshot_barrier: SmpSnapshotBarrierId,
    pub smp_snapshot_barrier_generation: Generation,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub display_snapshot_barrier: DisplaySnapshotBarrierId,
    pub display_snapshot_barrier_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub display: DisplayObjectId,
    pub display_generation: Generation,
    pub framebuffer: FramebufferObjectId,
    pub framebuffer_generation: Generation,
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
    pub smp_barrier_event: EventId,
    pub io_cleanup_completed_event: EventId,
    pub display_barrier_event: EventId,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedSnapshotIoLeaseBarrierState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedSnapshotIoLeaseBarrierRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedCodePublishSmpWorkloadRecord {
    pub id: IntegratedCodePublishSmpWorkloadId,
    pub scenario: String,
    pub smp_stress_run: SmpStressRunId,
    pub smp_stress_run_generation: Generation,
    pub smp_code_publish_barrier: SmpCodePublishBarrierId,
    pub smp_code_publish_barrier_generation: Generation,
    pub publish_rendezvous: StopTheWorldRendezvousId,
    pub publish_rendezvous_generation: Generation,
    pub publish_safe_point: SmpSafePointId,
    pub publish_safe_point_generation: Generation,
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
    pub stress_event_log_cursor: EventId,
    pub barrier_event: EventId,
    pub stress_recorded_at_event: EventId,
    pub invariant_checks: u32,
    pub generation: Generation,
    pub state: IntegratedCodePublishSmpWorkloadState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedCodePublishSmpWorkloadRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedCodePublishSmpWorkload,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedDisplayPanicRecord {
    pub id: IntegratedDisplayPanicId,
    pub scenario: String,
    pub substrate_panic_event: EventId,
    pub substrate_panic_epoch: u64,
    pub substrate_panic_cpu: u32,
    pub substrate_panic_reason_code: u32,
    pub display_panic_last_frame: DisplayPanicLastFrameId,
    pub display_panic_last_frame_generation: Generation,
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
    pub generation: Generation,
    pub state: IntegratedDisplayPanicState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedDisplayPanicRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IntegratedDisplayPanic, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegratedOsctlTraceReplayRecord {
    pub id: IntegratedOsctlTraceReplayId,
    pub scenario: String,
    pub integrated_smp_preemption_cleanup: IntegratedSmpPreemptionCleanupId,
    pub integrated_smp_preemption_cleanup_generation: Generation,
    pub integrated_smp_network_fault: IntegratedSmpNetworkFaultId,
    pub integrated_smp_network_fault_generation: Generation,
    pub integrated_disk_preempt_fault: IntegratedDiskPreemptFaultId,
    pub integrated_disk_preempt_fault_generation: Generation,
    pub integrated_simd_migration: IntegratedSimdMigrationId,
    pub integrated_simd_migration_generation: Generation,
    pub integrated_network_disk_io: IntegratedNetworkDiskIoId,
    pub integrated_network_disk_io_generation: Generation,
    pub integrated_display_scheduler_load: IntegratedDisplaySchedulerLoadId,
    pub integrated_display_scheduler_load_generation: Generation,
    pub integrated_snapshot_io_lease_barrier: IntegratedSnapshotIoLeaseBarrierId,
    pub integrated_snapshot_io_lease_barrier_generation: Generation,
    pub integrated_code_publish_smp_workload: IntegratedCodePublishSmpWorkloadId,
    pub integrated_code_publish_smp_workload_generation: Generation,
    pub integrated_display_panic: IntegratedDisplayPanicId,
    pub integrated_display_panic_generation: Generation,
    pub replay_event_cursor: EventId,
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
    pub generation: Generation,
    pub state: IntegratedOsctlTraceReplayState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IntegratedOsctlTraceReplayRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IntegratedOsctlTraceReplay,
            self.id,
            self.generation,
        )
    }
}
