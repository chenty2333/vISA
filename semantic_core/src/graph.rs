use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    tasks: Vec<TaskRecord>,
    runtime_activations: Vec<RuntimeActivationRecord>,
    runnable_queues: Vec<RunnableQueueRecord>,
    activation_contexts: Vec<ActivationContextRecord>,
    saved_contexts: Vec<SavedContextRecord>,
    timer_interrupts: Vec<TimerInterruptRecord>,
    preemptions: Vec<PreemptionRecord>,
    scheduler_decisions: Vec<SchedulerDecisionRecord>,
    activation_resumes: Vec<ActivationResumeRecord>,
    activation_waits: Vec<ActivationWaitRecord>,
    activation_cleanups: Vec<ActivationCleanupRecord>,
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
    next_preemption_id: PreemptionId,
    next_scheduler_decision_id: SchedulerDecisionId,
    next_activation_resume_id: ActivationResumeId,
    next_activation_wait_id: ActivationWaitId,
    next_activation_cleanup_id: ActivationCleanupId,
    next_authority_id: AuthorityId,
    next_fault_domain_id: FaultDomainId,
    next_store_id: StoreId,
    next_transaction_id: TransactionId,
    next_plan_id: PlanId,
    next_boundary_id: BoundaryId,
    next_artifact_id: ArtifactId,
    next_activation_id: StoreActivationId,
}

mod authority;
mod boundary;
mod capability;
mod cleanup;
mod command;
mod context;
mod interface;
mod network;
mod query;
mod resource;
mod scheduler;
mod snapshot;
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
            tasks: Vec::new(),
            runtime_activations: Vec::new(),
            runnable_queues: Vec::new(),
            activation_contexts: Vec::new(),
            saved_contexts: Vec::new(),
            timer_interrupts: Vec::new(),
            preemptions: Vec::new(),
            scheduler_decisions: Vec::new(),
            activation_resumes: Vec::new(),
            activation_waits: Vec::new(),
            activation_cleanups: Vec::new(),
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
            next_preemption_id: 1,
            next_scheduler_decision_id: 1,
            next_activation_resume_id: 1,
            next_activation_wait_id: 1,
            next_activation_cleanup_id: 1,
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
