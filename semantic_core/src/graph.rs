use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    harts: Vec<HartRecord>,
    tasks: Vec<TaskRecord>,
    runtime_activations: Vec<RuntimeActivationRecord>,
    runnable_queues: Vec<RunnableQueueRecord>,
    activation_contexts: Vec<ActivationContextRecord>,
    saved_contexts: Vec<SavedContextRecord>,
    timer_interrupts: Vec<TimerInterruptRecord>,
    ipi_events: Vec<IpiEventRecord>,
    remote_preempts: Vec<RemotePreemptRecord>,
    remote_parks: Vec<RemoteParkRecord>,
    preemptions: Vec<PreemptionRecord>,
    scheduler_decisions: Vec<SchedulerDecisionRecord>,
    cross_hart_scheduler_decisions: Vec<CrossHartSchedulerDecisionRecord>,
    activation_migrations: Vec<ActivationMigrationRecord>,
    smp_safe_points: Vec<SmpSafePointRecord>,
    stop_the_world_rendezvous: Vec<StopTheWorldRendezvousRecord>,
    smp_code_publish_barriers: Vec<SmpCodePublishBarrierRecord>,
    smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceRecord>,
    smp_snapshot_barriers: Vec<SmpSnapshotBarrierRecord>,
    smp_stress_runs: Vec<SmpStressRunRecord>,
    smp_scaling_benchmarks: Vec<SmpScalingBenchmarkRecord>,
    device_objects: Vec<DeviceObjectRecord>,
    activation_resumes: Vec<ActivationResumeRecord>,
    activation_waits: Vec<ActivationWaitRecord>,
    activation_cleanups: Vec<ActivationCleanupRecord>,
    preemption_latency_samples: Vec<PreemptionLatencySampleRecord>,
    hart_event_attributions: Vec<HartEventAttributionRecord>,
    resources: Vec<ResourceRecord>,
    authority_bindings: Vec<AuthorityBindingRecord>,
    waits: Vec<WaitRecord>,
    fault_domains: Vec<FaultDomainRecord>,
    stores: Vec<StoreRecord>,
    transactions: Vec<SemanticTransactionRecord>,
    fast_path_plans: Vec<FastPathPlanRecord>,
    boundaries: Vec<BoundaryRecord>,
    artifact_verifications: Vec<ArtifactVerificationRecord>,
    store_activations: Vec<StoreActivationRecord>,
    command_results: Vec<CommandResult>,
    capabilities: CapabilityLedger,
    event_log: EventLog,
    next_resource_id: ResourceId,
    next_runtime_activation_id: ActivationId,
    next_runnable_queue_id: RunnableQueueId,
    next_activation_context_id: ActivationContextId,
    next_saved_context_id: SavedContextId,
    next_timer_interrupt_id: TimerInterruptId,
    next_ipi_event_id: IpiEventId,
    next_remote_preempt_id: RemotePreemptId,
    next_remote_park_id: RemoteParkId,
    next_preemption_id: PreemptionId,
    next_scheduler_decision_id: SchedulerDecisionId,
    next_cross_hart_scheduler_decision_id: CrossHartSchedulerDecisionId,
    next_activation_migration_id: ActivationMigrationId,
    next_smp_safe_point_id: SmpSafePointId,
    next_stop_the_world_rendezvous_id: StopTheWorldRendezvousId,
    next_smp_code_publish_barrier_id: SmpCodePublishBarrierId,
    next_smp_cleanup_quiescence_id: SmpCleanupQuiescenceId,
    next_smp_snapshot_barrier_id: SmpSnapshotBarrierId,
    next_smp_stress_run_id: SmpStressRunId,
    next_smp_scaling_benchmark_id: SmpScalingBenchmarkId,
    next_device_object_id: DeviceObjectId,
    next_activation_resume_id: ActivationResumeId,
    next_activation_wait_id: ActivationWaitId,
    next_activation_cleanup_id: ActivationCleanupId,
    next_preemption_latency_sample_id: PreemptionLatencySampleId,
    next_hart_event_attribution_id: HartEventAttributionId,
    next_authority_id: AuthorityId,
    next_fault_domain_id: FaultDomainId,
    next_store_id: StoreId,
    next_transaction_id: TransactionId,
    next_plan_id: PlanId,
    next_boundary_id: BoundaryId,
    next_artifact_id: ArtifactId,
    next_activation_id: StoreActivationId,
}

mod activation_migration;
mod authority;
mod boundary;
mod capability;
mod cleanup;
mod command;
mod context;
mod cross_scheduler;
mod device_object;
mod hart;
mod hart_event;
mod interface;
mod ipi;
mod latency;
mod network;
mod query;
mod remote;
mod remote_park;
mod resource;
mod scheduler;
mod smp_cleanup_quiescence;
mod smp_code_publish;
mod smp_safe_point;
mod smp_scaling;
mod smp_snapshot_barrier;
mod smp_stress;
mod snapshot;
mod stop_the_world;
mod store;
mod substrate;
mod task;
mod timer;
mod transaction;
mod wait;

pub use command::*;

impl SemanticGraph {
    pub fn new() -> Self {
        Self::with_runtime_mode(RuntimeMode::Research)
    }
    pub fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
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
            device_objects: Vec::new(),
            activation_resumes: Vec::new(),
            activation_waits: Vec::new(),
            activation_cleanups: Vec::new(),
            preemption_latency_samples: Vec::new(),
            hart_event_attributions: Vec::new(),
            resources: Vec::new(),
            authority_bindings: Vec::new(),
            waits: Vec::new(),
            fault_domains: Vec::new(),
            stores: Vec::new(),
            transactions: Vec::new(),
            fast_path_plans: Vec::new(),
            boundaries: Vec::new(),
            artifact_verifications: Vec::new(),
            store_activations: Vec::new(),
            command_results: Vec::new(),
            capabilities: CapabilityLedger::new(),
            event_log: EventLog::with_runtime_mode(runtime_mode),
            next_resource_id: 1,
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
            next_device_object_id: 1,
            next_activation_resume_id: 1,
            next_activation_wait_id: 1,
            next_activation_cleanup_id: 1,
            next_preemption_latency_sample_id: 1,
            next_hart_event_attribution_id: 1,
            next_authority_id: 1,
            next_fault_domain_id: 1,
            next_store_id: 1,
            next_transaction_id: 1,
            next_plan_id: 1,
            next_boundary_id: 1,
            next_artifact_id: 1,
            next_activation_id: 1,
        }
    }
    pub fn runtime_mode(&self) -> RuntimeMode {
        self.event_log.runtime_mode()
    }
}

impl Default for SemanticGraph {
    fn default() -> Self {
        Self::new()
    }
}
