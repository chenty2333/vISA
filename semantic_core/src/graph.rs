use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    tasks: Vec<TaskRecord>,
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
    capabilities: CapabilityLedger,
    event_log: EventLog,
    next_resource_id: ResourceId,
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
mod command;
mod network;
mod query;
mod resource;
mod snapshot;
mod store;
mod task;
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
            capabilities: CapabilityLedger::new(),
            event_log: EventLog::with_runtime_mode(runtime_mode),
            next_resource_id: 1,
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
