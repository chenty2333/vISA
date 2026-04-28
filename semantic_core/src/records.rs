use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

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
        ContractObjectRef::new(
            ContractObjectKind::ActivationContext,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::HartEventAttribution,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SchedulerDecision,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::ActivationMigration,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::StopTheWorldRendezvous,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SmpCodePublishBarrier,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SmpCleanupQuiescence,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SmpSnapshotBarrier,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SmpScalingBenchmark,
            self.id,
            self.generation,
        )
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
pub struct DeviceObjectRecord {
    pub id: DeviceObjectId,
    pub name: String,
    pub class: String,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub backend: String,
    pub bus: String,
    pub vendor: String,
    pub model: String,
    pub generation: Generation,
    pub state: DeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::DeviceObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueObjectRecord {
    pub id: QueueObjectId,
    pub name: String,
    pub role: QueueObjectRole,
    pub queue_index: u16,
    pub depth: u32,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub generation: Generation,
    pub state: QueueObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl QueueObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::QueueObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorObjectRecord {
    pub id: DescriptorObjectId,
    pub queue: QueueObjectId,
    pub queue_generation: Generation,
    pub slot: u16,
    pub access: DescriptorObjectAccess,
    pub length: u32,
    pub generation: Generation,
    pub state: DescriptorObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DescriptorObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::DescriptorObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmaBufferObjectRecord {
    pub id: DmaBufferObjectId,
    pub descriptor: DescriptorObjectId,
    pub descriptor_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub access: DmaBufferObjectAccess,
    pub length: u32,
    pub generation: Generation,
    pub state: DmaBufferObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DmaBufferObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::DmaBufferObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmioRegionObjectRecord {
    pub id: MmioRegionObjectId,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub region_index: u16,
    pub offset: u64,
    pub length: u64,
    pub access: MmioRegionObjectAccess,
    pub generation: Generation,
    pub state: MmioRegionObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl MmioRegionObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::MmioRegionObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqLineObjectRecord {
    pub id: IrqLineObjectId,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub resource: ResourceId,
    pub resource_generation: Generation,
    pub irq_number: u32,
    pub trigger: IrqLineTrigger,
    pub polarity: IrqLinePolarity,
    pub generation: Generation,
    pub state: IrqLineObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IrqLineObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqEventRecord {
    pub id: IrqEventId,
    pub irq_line: IrqLineObjectId,
    pub irq_line_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub irq_number: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: IrqEventState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl IrqEventRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IrqEvent, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCapabilityRecord {
    pub id: DeviceCapabilityId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub target: ContractObjectRef,
    pub class: CapabilityClass,
    pub operation: String,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub generation: Generation,
    pub state: DeviceCapabilityState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DeviceCapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::DeviceCapability,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverStoreBindingRecord {
    pub id: DriverStoreBindingId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub device_capability: DeviceCapabilityId,
    pub device_capability_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub generation: Generation,
    pub state: DriverStoreBindingState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DriverStoreBindingRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::DriverStoreBinding,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoWaitRecord {
    pub id: IoWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub blocker: ContractObjectRef,
    pub generation: Generation,
    pub state: IoWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub completion_irq_event: Option<IrqEventId>,
    pub completion_irq_event_generation: Option<Generation>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl IoWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCleanupStepRecord {
    pub kind: IoCleanupStepKind,
    pub target: ContractObjectRef,
    pub observed_generation: Generation,
    pub status: IoCleanupStepStatus,
    pub event: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCleanupRecord {
    pub id: IoCleanupId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub generation: Generation,
    pub state: IoCleanupState,
    pub reason: String,
    pub started_at_event: EventId,
    pub completed_at_event: EventId,
    pub cancelled_io_waits: Vec<ContractObjectRef>,
    pub revoked_device_capabilities: Vec<ContractObjectRef>,
    pub revoked_capabilities: Vec<ContractObjectRef>,
    pub released_dma_buffers: Vec<ContractObjectRef>,
    pub released_mmio_regions: Vec<ContractObjectRef>,
    pub released_irq_lines: Vec<ContractObjectRef>,
    pub steps: Vec<IoCleanupStepRecord>,
    pub note: String,
}

impl IoCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::IoCleanup, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoFaultInjectionRecord {
    pub id: IoFaultInjectionId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub target: ContractObjectRef,
    pub cleanup: IoCleanupId,
    pub cleanup_generation: Generation,
    pub generation: Generation,
    pub kind: IoFaultInjectionKind,
    pub state: IoFaultInjectionState,
    pub injected_at_event: EventId,
    pub note: String,
}

impl IoFaultInjectionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IoFaultInjection,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoValidationViolationRecord {
    pub code: IoValidationViolationCode,
    pub subject: ContractObjectRef,
    pub relation: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoValidationReportRecord {
    pub id: IoValidationReportId,
    pub generation: Generation,
    pub state: IoValidationReportState,
    pub validated_at_event: EventId,
    pub event_log_cursor: EventId,
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
    pub violations: Vec<IoValidationViolationRecord>,
    pub note: String,
}

impl IoValidationReportRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::IoValidationReport,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketDeviceObjectRecord {
    pub id: PacketDeviceObjectId,
    pub name: String,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub generation: Generation,
    pub state: PacketDeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketDeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::PacketDeviceObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketBufferObjectRecord {
    pub id: PacketBufferObjectId,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub direction: PacketBufferDirection,
    pub frame_format_version: u32,
    pub capacity: u32,
    pub payload_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: PacketBufferObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketBufferObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::PacketBufferObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketQueueObjectRecord {
    pub id: PacketQueueObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub role: PacketQueueRole,
    pub queue_index: u16,
    pub depth: u32,
    pub generation: Generation,
    pub state: PacketQueueObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketQueueObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::PacketQueueObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketDescriptorObjectRecord {
    pub id: PacketDescriptorObjectId,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub slot: u16,
    pub length: u32,
    pub generation: Generation,
    pub state: PacketDescriptorObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl PacketDescriptorObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::PacketDescriptorObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeNetBackendObjectRecord {
    pub id: FakeNetBackendObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub provider: String,
    pub profile: String,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub mac: [u8; 6],
    pub frame_format_version: u32,
    pub max_payload_len: u32,
    pub deterministic_seed: u64,
    pub generation: Generation,
    pub state: FakeNetBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FakeNetBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::FakeNetBackendObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioNetBackendObjectRecord {
    pub id: VirtioNetBackendObjectId,
    pub name: String,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
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
    pub generation: Generation,
    pub state: VirtioNetBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl VirtioNetBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::VirtioNetBackendObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRxInterruptRecord {
    pub id: NetworkRxInterruptId,
    pub virtio_net_backend: VirtioNetBackendObjectId,
    pub virtio_net_backend_generation: Generation,
    pub irq_event: IrqEventId,
    pub irq_event_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkRxInterruptState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkRxInterruptRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkRxInterrupt,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRxWaitResolutionRecord {
    pub id: NetworkRxWaitResolutionId,
    pub io_wait: IoWaitId,
    pub io_wait_generation: Generation,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub rx_interrupt: NetworkRxInterruptId,
    pub rx_interrupt_generation: Generation,
    pub irq_event: IrqEventId,
    pub irq_event_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub ready_descriptors: u16,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkRxWaitResolutionState,
    pub resolved_at_event: EventId,
    pub note: String,
}

impl NetworkRxWaitResolutionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkRxWaitResolution,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTxCapabilityGateRecord {
    pub id: NetworkTxCapabilityGateId,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub packet_descriptor: PacketDescriptorObjectId,
    pub packet_descriptor_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub device_capability: DeviceCapabilityId,
    pub device_capability_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkTxCapabilityGateState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkTxCapabilityGateRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkTxCapabilityGate,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTxCompletionRecord {
    pub id: NetworkTxCompletionId,
    pub tx_gate: NetworkTxCapabilityGateId,
    pub tx_gate_generation: Generation,
    pub backend: ContractObjectRef,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub packet_descriptor: PacketDescriptorObjectId,
    pub packet_descriptor_generation: Generation,
    pub packet_buffer: PacketBufferObjectId,
    pub packet_buffer_generation: Generation,
    pub byte_len: u32,
    pub sequence: u64,
    pub completion_sequence: u64,
    pub generation: Generation,
    pub state: NetworkTxCompletionState,
    pub completed_at_event: EventId,
    pub note: String,
}

impl NetworkTxCompletionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkTxCompletion,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkStackAdapterRecord {
    pub id: NetworkStackAdapterId,
    pub implementation: String,
    pub implementation_version: String,
    pub profile: String,
    pub medium: String,
    pub backend: ContractObjectRef,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub generation: Generation,
    pub state: NetworkStackAdapterState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkStackAdapterRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkStackAdapter,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketObjectRecord {
    pub id: SocketObjectId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub domain: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub canonical_protocol: u16,
    pub family: String,
    pub transport: String,
    pub generation: Generation,
    pub state: SocketObjectState,
    pub created_at_event: EventId,
    pub note: String,
}

impl SocketObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SocketObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointObjectRecord {
    pub id: EndpointObjectId,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub family: String,
    pub transport: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub generation: Generation,
    pub state: EndpointObjectState,
    pub created_at_event: EventId,
    pub note: String,
}

impl EndpointObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::EndpointObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketOperationRecord {
    pub id: SocketOperationId,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub operation: SocketOperationKind,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub backlog: u16,
    pub byte_len: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: SocketOperationState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl SocketOperationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::SocketOperation,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketWaitRecord {
    pub id: SocketWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub wait_kind: SemanticWaitKind,
    pub blocker: ContractObjectRef,
    pub generation: Generation,
    pub state: SocketWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub ready_sequence: Option<u64>,
    pub byte_len: Option<u32>,
    pub note: String,
}

impl SocketWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::SocketWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBackpressureRecord {
    pub id: NetworkBackpressureId,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub packet_queue: PacketQueueObjectId,
    pub packet_queue_generation: Generation,
    pub endpoint: Option<EndpointObjectId>,
    pub endpoint_generation: Option<Generation>,
    pub socket: Option<SocketObjectId>,
    pub socket_generation: Option<Generation>,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub direction: PacketBufferDirection,
    pub reason: NetworkBackpressureReason,
    pub action: NetworkBackpressureAction,
    pub queue_depth: u32,
    pub queue_limit: u32,
    pub dropped_packets: u32,
    pub dropped_bytes: u32,
    pub sequence: u64,
    pub generation: Generation,
    pub state: NetworkBackpressureState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkBackpressureRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkBackpressure,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBenchmarkRecord {
    pub id: NetworkBenchmarkId,
    pub scenario: String,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub tx_queue: PacketQueueObjectId,
    pub tx_queue_generation: Generation,
    pub rx_queue: PacketQueueObjectId,
    pub rx_queue_generation: Generation,
    pub tx_completion: NetworkTxCompletionId,
    pub tx_completion_generation: Generation,
    pub rx_wait_resolution: NetworkRxWaitResolutionId,
    pub rx_wait_resolution_generation: Generation,
    pub endpoint: EndpointObjectId,
    pub endpoint_generation: Generation,
    pub socket: SocketObjectId,
    pub socket_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub backpressure: Option<NetworkBackpressureId>,
    pub backpressure_generation: Option<Generation>,
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
    pub generation: Generation,
    pub state: NetworkBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkBenchmark,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRecoveryBenchmarkRecord {
    pub id: NetworkRecoveryBenchmarkId,
    pub scenario: String,
    pub cleanup: NetworkDriverCleanupId,
    pub cleanup_generation: Generation,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub adapter: NetworkStackAdapterId,
    pub adapter_generation: Generation,
    pub packet_device: PacketDeviceObjectId,
    pub packet_device_generation: Generation,
    pub backend: ContractObjectRef,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub fault_injection: Option<NetworkFaultInjectionId>,
    pub fault_injection_generation: Option<Generation>,
    pub recovery_start_event: EventId,
    pub recovery_complete_event: EventId,
    pub cancelled_socket_waits: u32,
    pub revoked_packet_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: NetworkRecoveryBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl NetworkRecoveryBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::NetworkRecoveryBenchmark,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDeviceObjectRecord {
    pub id: BlockDeviceObjectId,
    pub name: String,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub generation: Generation,
    pub state: BlockDeviceObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockDeviceObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockDeviceObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRangeObjectRecord {
    pub id: BlockRangeObjectId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub start_sector: u64,
    pub sector_count: u64,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockRangeObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRangeObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRangeObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestObjectRecord {
    pub id: BlockRequestObjectId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockRequestObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRequestObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockCompletionObjectRecord {
    pub id: BlockCompletionObjectId,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub status: BlockCompletionStatus,
    pub generation: Generation,
    pub state: BlockCompletionObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockCompletionObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockCompletionObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWaitRecord {
    pub id: BlockWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: BlockWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl BlockWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeBlockBackendObjectRecord {
    pub id: FakeBlockBackendObjectId,
    pub name: String,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub provider: String,
    pub profile: String,
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub deterministic_seed: u64,
    pub generation: Generation,
    pub state: FakeBlockBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FakeBlockBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::FakeBlockBackendObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioBlkBackendObjectRecord {
    pub id: VirtioBlkBackendObjectId,
    pub name: String,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
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
    pub generation: Generation,
    pub state: VirtioBlkBackendObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl VirtioBlkBackendObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::VirtioBlkBackendObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReadPathRecord {
    pub id: BlockReadPathId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub data_digest: u64,
    pub generation: Generation,
    pub state: BlockReadPathState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockReadPathRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockReadPath, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWritePathRecord {
    pub id: BlockWritePathId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub sequence: u64,
    pub completed_bytes: u64,
    pub payload_digest: u64,
    pub generation: Generation,
    pub state: BlockWritePathState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockWritePathRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockWritePath, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueEntryRef {
    pub request: BlockRequestObjectId,
    pub request_generation: Generation,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
}

impl BlockRequestQueueEntryRef {
    pub const fn pending(request: BlockRequestObjectId, request_generation: Generation) -> Self {
        Self {
            request,
            request_generation,
            completion: None,
            completion_generation: None,
        }
    }

    pub const fn completed(
        request: BlockRequestObjectId,
        request_generation: Generation,
        completion: BlockCompletionObjectId,
        completion_generation: Generation,
    ) -> Self {
        Self {
            request,
            request_generation,
            completion: Some(completion),
            completion_generation: Some(completion_generation),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueEntryRecord {
    pub request: BlockRequestObjectId,
    pub request_generation: Generation,
    pub completion: Option<BlockCompletionObjectId>,
    pub completion_generation: Option<Generation>,
    pub sequence: u64,
    pub operation: BlockRequestOperation,
    pub byte_len: u64,
    pub state: BlockRequestQueueEntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestQueueRecord {
    pub id: BlockRequestQueueId,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub depth: u32,
    pub entries: Vec<BlockRequestQueueEntryRecord>,
    pub pending_count: u32,
    pub completed_count: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub generation: Generation,
    pub state: BlockRequestQueueState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestQueueRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRequestQueue,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDmaBufferRecord {
    pub id: BlockDmaBufferId,
    pub backend: ContractObjectRef,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub dma_buffer: DmaBufferObjectId,
    pub dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub descriptor: DescriptorObjectId,
    pub descriptor_generation: Generation,
    pub queue: QueueObjectId,
    pub queue_generation: Generation,
    pub operation: BlockRequestOperation,
    pub access: DmaBufferObjectAccess,
    pub byte_len: u64,
    pub buffer_len: u32,
    pub buffer_digest: u64,
    pub generation: Generation,
    pub state: BlockDmaBufferState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockDmaBufferRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockDmaBuffer, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPageObjectRecord {
    pub id: BlockPageObjectId,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub block_completion: BlockCompletionObjectId,
    pub block_completion_generation: Generation,
    pub dma_buffer: DmaBufferObjectId,
    pub dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub aspace: ContractObjectRef,
    pub vma_region: ContractObjectRef,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub page_backing: PageBacking,
    pub cow_state: CowState,
    pub page_state: PageObjectState,
    pub page_offset: u64,
    pub byte_len: u64,
    pub operation: BlockRequestOperation,
    pub generation: Generation,
    pub state: BlockPageObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockPageObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockPageObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferCacheObjectRecord {
    pub id: BufferCacheObjectId,
    pub block_page_object: BlockPageObjectId,
    pub block_page_object_generation: Generation,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub aspace: ContractObjectRef,
    pub vma_region: ContractObjectRef,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub page_offset: u64,
    pub block_offset: u64,
    pub byte_len: u64,
    pub operation: BlockRequestOperation,
    pub cache_state: BufferCacheObjectState,
    pub coherency_epoch: u64,
    pub generation: Generation,
    pub state: BufferCacheObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BufferCacheObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BufferCacheObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileObjectRecord {
    pub id: FileObjectId,
    pub buffer_cache_object: BufferCacheObjectId,
    pub buffer_cache_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub page: ContractObjectRef,
    pub page_dirty_generation: Generation,
    pub namespace: String,
    pub file_key: String,
    pub path: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub file_size: u64,
    pub content_digest: u64,
    pub cache_state: BufferCacheObjectState,
    pub generation: Generation,
    pub state: FileObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FileObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FileObject, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryObjectRecord {
    pub id: DirectoryObjectId,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub namespace: String,
    pub directory_key: String,
    pub directory_path: String,
    pub entry_name: String,
    pub child_file_key: String,
    pub child_path: String,
    pub entry_kind: DirectoryEntryKind,
    pub file_size: u64,
    pub content_digest: u64,
    pub generation: Generation,
    pub state: DirectoryObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl DirectoryObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::DirectoryObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatAdapterObjectRecord {
    pub id: FatAdapterObjectId,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
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
    pub generation: Generation,
    pub state: FatAdapterObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FatAdapterObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::FatAdapterObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4AdapterObjectRecord {
    pub id: Ext4AdapterObjectId,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
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
    pub generation: Generation,
    pub state: Ext4AdapterObjectState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl Ext4AdapterObjectRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::Ext4AdapterObject,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHandleCapabilityRecord {
    pub id: FileHandleCapabilityId,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub capability: CapabilityId,
    pub capability_generation: Generation,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub operation: String,
    pub file_offset: u64,
    pub byte_len: u64,
    pub content_digest: u64,
    pub generation: Generation,
    pub state: FileHandleCapabilityState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl FileHandleCapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::FileHandleCapability,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsWaitRecord {
    pub id: FsWaitId,
    pub wait: WaitId,
    pub wait_generation: Generation,
    pub owner_store: StoreId,
    pub owner_store_generation: Generation,
    pub file_object: FileObjectId,
    pub file_object_generation: Generation,
    pub directory_object: DirectoryObjectId,
    pub directory_object_generation: Generation,
    pub file_handle_capability: FileHandleCapabilityId,
    pub file_handle_capability_generation: Generation,
    pub operation: String,
    pub blocker: ContractObjectRef,
    pub sequence: u64,
    pub byte_len: u64,
    pub generation: Generation,
    pub state: FsWaitState,
    pub created_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub cancel_reason: Option<WaitCancelReason>,
    pub note: String,
}

impl FsWaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FsWait, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDriverCleanupRecord {
    pub id: BlockDriverCleanupId,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub backend: ContractObjectRef,
    pub cancelled_block_waits: Vec<ContractObjectRef>,
    pub cancelled_wait_tokens: Vec<ContractObjectRef>,
    pub revoked_device_capabilities: Vec<ContractObjectRef>,
    pub released_dma_buffers: Vec<ContractObjectRef>,
    pub generation: Generation,
    pub state: BlockDriverCleanupState,
    pub started_at_event: EventId,
    pub completed_at_event: Option<EventId>,
    pub reason: String,
    pub note: String,
}

impl BlockDriverCleanupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockDriverCleanup,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPendingIoPolicyRecord {
    pub id: BlockPendingIoPolicyId,
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
    pub operation: BlockRequestOperation,
    pub sequence: u64,
    pub byte_len: u64,
    pub action: BlockPendingIoAction,
    pub errno: i32,
    pub retry_attempt: u32,
    pub max_retries: u32,
    pub generation: Generation,
    pub state: BlockPendingIoPolicyState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockPendingIoPolicyRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockPendingIoPolicy,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestGenerationAuditRecord {
    pub id: BlockRequestGenerationAuditId,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub block_request: BlockRequestObjectId,
    pub block_request_generation: Generation,
    pub backend: ContractObjectRef,
    pub dma_buffer: ContractObjectRef,
    pub rejected_completion_generation_probes: u32,
    pub rejected_wait_generation_probes: u32,
    pub rejected_dma_generation_probes: u32,
    pub rejected_queue_generation_probes: u32,
    pub generation: Generation,
    pub state: BlockRequestGenerationAuditState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRequestGenerationAuditRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRequestGenerationAudit,
            self.id,
            self.generation,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBenchmarkRecord {
    pub id: BlockBenchmarkId,
    pub scenario: String,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub block_range: BlockRangeObjectId,
    pub block_range_generation: Generation,
    pub read_path: BlockReadPathId,
    pub read_path_generation: Generation,
    pub write_path: BlockWritePathId,
    pub write_path_generation: Generation,
    pub request_queue: BlockRequestQueueId,
    pub request_queue_generation: Generation,
    pub block_dma_buffer: BlockDmaBufferId,
    pub block_dma_buffer_generation: Generation,
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
    pub generation: Generation,
    pub state: BlockBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::BlockBenchmark, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecoveryBenchmarkRecord {
    pub id: BlockRecoveryBenchmarkId,
    pub scenario: String,
    pub cleanup: BlockDriverCleanupId,
    pub cleanup_generation: Generation,
    pub io_cleanup: IoCleanupId,
    pub io_cleanup_generation: Generation,
    pub backend: ContractObjectRef,
    pub block_device: BlockDeviceObjectId,
    pub block_device_generation: Generation,
    pub driver_store: StoreId,
    pub driver_store_generation: Generation,
    pub device: DeviceObjectId,
    pub device_generation: Generation,
    pub driver_binding: DriverStoreBindingId,
    pub driver_binding_generation: Generation,
    pub recovery_start_event: EventId,
    pub recovery_complete_event: EventId,
    pub cancelled_block_waits: u32,
    pub cancelled_wait_tokens: u32,
    pub released_dma_buffers: u32,
    pub revoked_device_capabilities: u32,
    pub recovery_nanos: u64,
    pub budget_nanos: u64,
    pub generation: Generation,
    pub state: BlockRecoveryBenchmarkState,
    pub recorded_at_event: EventId,
    pub note: String,
}

impl BlockRecoveryBenchmarkRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::BlockRecoveryBenchmark,
            self.id,
            self.generation,
        )
    }
}

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
        ContractObjectRef::new(
            ContractObjectKind::TargetFeatureSet,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::SimdFaultInjection,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferObject,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::DisplayCapability,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferWindowLease,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferMapping,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferWrite,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferFlushRegion,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferDirtyRegion,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::DisplayEventLog,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::DisplaySnapshotBarrier,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::DisplayPanicLastFrame,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::FramebufferBenchmark,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::NetworkDriverCleanup,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::NetworkGenerationAudit,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::NetworkFaultInjection,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::ActivationResume,
            self.id,
            self.generation,
        )
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
        ContractObjectRef::new(
            ContractObjectKind::ActivationCleanup,
            self.id,
            self.generation,
        )
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
