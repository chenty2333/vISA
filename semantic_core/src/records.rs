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
