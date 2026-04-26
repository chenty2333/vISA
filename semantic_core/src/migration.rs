use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactProfile {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    pub network_contract_version: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    pub runtime_executor_abi: String,
}

impl ArtifactProfile {
    pub fn summary(&self) -> String {
        format!(
            "artifact_profile={} target_arch={} machine_abi={} supervisor_abi={} wasm_profile={} dmw_layout={} network={} engine={} mode={} format={} runtime_executor={}",
            self.artifact_profile,
            self.target_arch,
            self.machine_abi_version,
            self.supervisor_abi_version,
            self.wasm_feature_profile,
            self.dmw_layout,
            self.network_contract_version,
            self.compiler_engine,
            self.compiler_execution_mode,
            self.artifact_format,
            self.runtime_executor_abi
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestStateSnapshot {
    pub canonical_isa: CanonicalGuestIsa,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

impl GuestStateSnapshot {
    pub fn riscv64_placeholder() -> Self {
        Self {
            canonical_isa: CanonicalGuestIsa::Riscv64,
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "placeholder canonical guest state; real VM state is not implemented in prototype v0"
                .to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateBoundarySnapshot {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    pub active_mmio_authority_count: u32,
    pub active_dma_authority_count: u32,
    pub active_irq_authority_count: u32,
    pub active_packet_device_authority_count: u32,
    pub active_virtio_queue_authority_count: u32,
    pub pending_network_inputs: u32,
    pub random_epoch: u64,
    pub scheduler_decision_cursor: u64,
    pub cow_epoch: u64,
    pub background_copy_pages: u64,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBarrierSnapshot {
    pub id: SnapshotBarrierId,
    pub event_log_cursor: EventId,
    pub pending_wait_count: usize,
    pub live_resource_count: usize,
    pub active_transaction_count: usize,
    pub active_dmw_lease_count: u32,
    pub dmw_quiescent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticSnapshot {
    pub harts: Vec<HartRecord>,
    pub barrier: SnapshotBarrierSnapshot,
    pub tasks: Vec<TaskRecord>,
    pub resources: Vec<ResourceRecord>,
    pub authority_bindings: Vec<AuthorityBindingRecord>,
    pub waits: Vec<WaitRecord>,
    pub fault_domains: Vec<FaultDomainRecord>,
    pub stores: Vec<StoreRecord>,
    pub transactions: Vec<SemanticTransactionRecord>,
    pub fast_path_plans: Vec<FastPathPlanRecord>,
    pub boundaries: Vec<BoundaryRecord>,
    pub artifact_verifications: Vec<ArtifactVerificationRecord>,
    pub store_activations: Vec<StoreActivationRecord>,
    pub capabilities: Vec<CapabilityRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPackage {
    pub schema_version: u32,
    pub package_id: String,
    pub source_host_arch: String,
    pub target_host_arch_hint: String,
    pub required_artifact_profile: ArtifactProfile,
    pub guest: GuestStateSnapshot,
    pub substrate_boundary: SubstrateBoundarySnapshot,
    pub semantic: SemanticSnapshot,
}

impl MigrationPackage {
    pub fn validate_portability(&self) -> Result<(), MigrationValidationError> {
        if self.schema_version != 1 {
            return Err(MigrationValidationError::UnsupportedSchema);
        }
        if self.semantic.barrier.active_dmw_lease_count != 0 || !self.semantic.barrier.dmw_quiescent
        {
            return Err(MigrationValidationError::ActiveDmwLease);
        }
        if self.substrate_boundary.pending_dma_completions != 0 {
            return Err(MigrationValidationError::InFlightDma);
        }
        if self.substrate_boundary.active_mmio_authority_count != 0 {
            return Err(MigrationValidationError::ActiveMmioAuthority);
        }
        if self.substrate_boundary.active_dma_authority_count != 0 {
            return Err(MigrationValidationError::ActiveDmaAuthority);
        }
        if self.substrate_boundary.active_irq_authority_count != 0 {
            return Err(MigrationValidationError::ActiveIrqAuthority);
        }
        if self.substrate_boundary.active_packet_device_authority_count != 0 {
            return Err(MigrationValidationError::ActivePacketDeviceAuthority);
        }
        if self.substrate_boundary.active_virtio_queue_authority_count != 0 {
            return Err(MigrationValidationError::ActiveVirtioQueueAuthority);
        }
        if self.semantic.barrier.active_transaction_count != 0 {
            return Err(MigrationValidationError::ActiveSemanticTransaction);
        }
        if self.guest.canonical_isa != CanonicalGuestIsa::Riscv64 {
            return Err(MigrationValidationError::UnsupportedGuestIsa);
        }
        Ok(())
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "migration package: id={} source_host={} target_hint={} guest_isa={}",
            self.package_id,
            self.source_host_arch,
            self.target_host_arch_hint,
            self.guest.canonical_isa.as_str()
        ));
        lines.push(format!(
            "snapshot barrier: id={} cursor={} pending_waits={} live_resources={} active_transactions={} active_dmw_leases={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} pending_net={} cow_epoch={} background_pages={}",
            self.semantic.barrier.id,
            self.semantic.barrier.event_log_cursor,
            self.semantic.barrier.pending_wait_count,
            self.semantic.barrier.live_resource_count,
            self.semantic.barrier.active_transaction_count,
            self.semantic.barrier.active_dmw_lease_count,
            self.substrate_boundary.active_mmio_authority_count,
            self.substrate_boundary.active_dma_authority_count,
            self.substrate_boundary.active_irq_authority_count,
            self.substrate_boundary.active_packet_device_authority_count,
            self.substrate_boundary.active_virtio_queue_authority_count,
            self.substrate_boundary.pending_network_inputs,
            self.substrate_boundary.cow_epoch,
            self.substrate_boundary.background_copy_pages
        ));
        lines.push(format!(
            "semantic roots: harts={} tasks={} resources={} authorities={} waits={} capabilities={} fault_domains={} stores={} transactions={} fastpath_plans={} boundaries={} artifacts={} activations={}",
            self.semantic.harts.len(),
            self.semantic.tasks.len(),
            self.semantic.resources.len(),
            self.semantic.authority_bindings.len(),
            self.semantic.waits.len(),
            self.semantic.capabilities.len(),
            self.semantic.fault_domains.len(),
            self.semantic.stores.len(),
            self.semantic.transactions.len(),
            self.semantic.fast_path_plans.len(),
            self.semantic.boundaries.len(),
            self.semantic.artifact_verifications.len(),
            self.semantic.store_activations.len()
        ));
        lines.push(format!(
            "required artifacts: {}",
            self.required_artifact_profile.summary()
        ));
        lines.push(
            "not migrated: raw pointers, native stacks, active semantic transactions, active DMW leases, DMA mappings, MMIO mappings, IRQ registrations, translated code cache"
                .to_string(),
        );
        lines
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationValidationError {
    UnsupportedSchema,
    ActiveDmwLease,
    InFlightDma,
    ActiveMmioAuthority,
    ActiveDmaAuthority,
    ActiveIrqAuthority,
    ActivePacketDeviceAuthority,
    ActiveVirtioQueueAuthority,
    ActiveSemanticTransaction,
    UnsupportedGuestIsa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticInvariantError {
    HartInvalidObjectIdentity {
        hart: HartId,
    },
    DuplicateHart {
        hart: HartId,
    },
    DuplicateHardwareHart {
        hardware_id: u32,
    },
    MultipleBootHarts,
    HartRunningWithoutCurrentActivation {
        hart: HartId,
    },
    HartInactiveOwnsCurrentActivation {
        hart: HartId,
        activation: ActivationId,
    },
    HartCurrentActivationGenerationMissing {
        hart: HartId,
    },
    HartCurrentActivationMissing {
        hart: HartId,
        activation: ActivationId,
    },
    HartCurrentTaskMismatch {
        hart: HartId,
        activation: ActivationId,
    },
    HartCurrentStoreMismatch {
        hart: HartId,
        activation: ActivationId,
    },
    ActivationCurrentOnMultipleHarts {
        activation: ActivationId,
        first_hart: HartId,
        second_hart: HartId,
    },
    HartEventAttributionInvalid {
        attribution: HartEventAttributionId,
    },
    HartEventAttributionMissingHart {
        attribution: HartEventAttributionId,
        hart: HartId,
    },
    HartEventAttributionHartGenerationMismatch {
        attribution: HartEventAttributionId,
        hart: HartId,
    },
    HartEventAttributionMissingEvent {
        attribution: HartEventAttributionId,
        event: EventId,
    },
    HartEventAttributionEventMismatch {
        attribution: HartEventAttributionId,
        event: EventId,
    },
    HartEventAttributionActivationMismatch {
        attribution: HartEventAttributionId,
        activation: ActivationId,
    },
    TaskReferencesMissingResource {
        task: TaskId,
        resource: ResourceId,
    },
    ResourceReferencesMissingTask {
        resource: ResourceId,
        task: TaskId,
    },
    ResourceReferencesMissingStore {
        resource: ResourceId,
        store: StoreId,
    },
    WaitReferencesMissingTask {
        wait: WaitId,
        task: TaskId,
    },
    WaitReferencesMissingStore {
        wait: WaitId,
        store: StoreId,
    },
    WaitMissingBlocker {
        wait: WaitId,
    },
    ActivationReferencesMissingTask {
        activation: ActivationId,
        task: TaskId,
    },
    ActivationReferencesMissingStore {
        activation: ActivationId,
        store: StoreId,
    },
    DeadStoreOwnsLiveActivation {
        store: StoreId,
        activation: ActivationId,
    },
    PendingTaskHasRunnableActivation {
        task: TaskId,
        activation: ActivationId,
    },
    InactiveRunnableQueueHasEntries {
        queue: RunnableQueueId,
    },
    RunnableQueueOwnerFieldMismatch {
        queue: RunnableQueueId,
    },
    RunnableQueueOwnerMissingHart {
        queue: RunnableQueueId,
        hart: HartId,
    },
    RunnableQueueOwnerHartGenerationMismatch {
        queue: RunnableQueueId,
        hart: HartId,
        expected: Generation,
        actual: Generation,
    },
    RunnableQueueOwnerHartUnavailable {
        queue: RunnableQueueId,
        hart: HartId,
        state: HartState,
    },
    RunnableQueueReferencesMissingActivation {
        queue: RunnableQueueId,
        activation: ActivationId,
    },
    RunnableQueueActivationGenerationMismatch {
        queue: RunnableQueueId,
        activation: ActivationId,
        expected: Generation,
        actual: Generation,
    },
    RunnableQueueContainsNonRunnableActivation {
        queue: RunnableQueueId,
        activation: ActivationId,
        state: RuntimeActivationState,
    },
    RunnableQueueOwnershipMismatch {
        queue: RunnableQueueId,
        activation: ActivationId,
    },
    RunnableActivationQueueCountMismatch {
        activation: ActivationId,
        queue_refs: usize,
    },
    RunningActivationStillQueued {
        activation: ActivationId,
    },
    ActivationContextMissingActivation {
        context: ActivationContextId,
        activation: ActivationId,
    },
    ActivationContextMissingTask {
        context: ActivationContextId,
        task: TaskId,
    },
    ActivationContextMissingStore {
        context: ActivationContextId,
        store: StoreId,
    },
    DeadActivationOwnsLiveContext {
        activation: ActivationId,
        context: ActivationContextId,
    },
    ActivationContextSavedGenerationMissing {
        context: ActivationContextId,
        saved_context: SavedContextId,
    },
    ActivationContextMissingSavedContext {
        context: ActivationContextId,
        saved_context: SavedContextId,
    },
    ActivationContextSavedContextMismatch {
        context: ActivationContextId,
        saved_context: SavedContextId,
    },
    ActivationHasMultipleLiveContexts {
        activation: ActivationId,
        contexts: usize,
    },
    SavedContextMachineFrameMissing {
        saved_context: SavedContextId,
    },
    SavedContextMissingContext {
        saved_context: SavedContextId,
        context: ActivationContextId,
    },
    SavedContextMissingActivation {
        saved_context: SavedContextId,
        activation: ActivationId,
    },
    SavedContextMissingTask {
        saved_context: SavedContextId,
        task: TaskId,
    },
    SavedContextMissingPreemption {
        saved_context: SavedContextId,
        preemption: PreemptionId,
    },
    SavedContextMissingPreemptionGeneration {
        saved_context: SavedContextId,
    },
    SavedContextPreemptionMismatch {
        saved_context: SavedContextId,
        preemption: PreemptionId,
    },
    TimerInterruptEpochNonMonotonic {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
    },
    TimerInterruptMissingHart {
        interrupt: TimerInterruptId,
        hart: HartId,
    },
    TimerInterruptHartMismatch {
        interrupt: TimerInterruptId,
        hart: HartId,
    },
    TimerInterruptMissingHartEventAttribution {
        interrupt: TimerInterruptId,
        event: EventId,
    },
    TimerInterruptMissingActivationGeneration {
        interrupt: TimerInterruptId,
    },
    TimerInterruptMissingActivation {
        interrupt: TimerInterruptId,
        activation: ActivationId,
    },
    TimerInterruptTargetsDeadActivation {
        interrupt: TimerInterruptId,
        activation: ActivationId,
    },
    TimerInterruptTargetTaskMismatch {
        interrupt: TimerInterruptId,
        activation: ActivationId,
    },
    IpiEventInvalid {
        ipi: IpiEventId,
    },
    IpiEventMissingHart {
        ipi: IpiEventId,
        hart: HartId,
    },
    IpiEventHartGenerationMismatch {
        ipi: IpiEventId,
        hart: HartId,
    },
    IpiEventMissingEvent {
        ipi: IpiEventId,
    },
    IpiEventMissingHartEventAttribution {
        ipi: IpiEventId,
        event: EventId,
    },
    RemotePreemptInvalid {
        remote_preempt: RemotePreemptId,
    },
    RemotePreemptMissingIpi {
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
    },
    RemotePreemptIpiMismatch {
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
    },
    RemotePreemptMissingHart {
        remote_preempt: RemotePreemptId,
        hart: HartId,
    },
    RemotePreemptHartGenerationMismatch {
        remote_preempt: RemotePreemptId,
        hart: HartId,
    },
    RemotePreemptMissingActivation {
        remote_preempt: RemotePreemptId,
        activation: ActivationId,
    },
    RemotePreemptMissingQueue {
        remote_preempt: RemotePreemptId,
        queue: RunnableQueueId,
    },
    RemotePreemptQueueEntryMismatch {
        remote_preempt: RemotePreemptId,
        activation: ActivationId,
    },
    RemotePreemptMissingEvent {
        remote_preempt: RemotePreemptId,
    },
    RemotePreemptMissingHartEventAttribution {
        remote_preempt: RemotePreemptId,
        event: EventId,
    },
    RemoteParkInvalid {
        remote_park: RemoteParkId,
    },
    RemoteParkMissingIpi {
        remote_park: RemoteParkId,
        ipi: IpiEventId,
    },
    RemoteParkIpiMismatch {
        remote_park: RemoteParkId,
        ipi: IpiEventId,
    },
    RemoteParkMissingHart {
        remote_park: RemoteParkId,
        hart: HartId,
    },
    RemoteParkHartGenerationMismatch {
        remote_park: RemoteParkId,
        hart: HartId,
    },
    RemoteParkMissingEvent {
        remote_park: RemoteParkId,
    },
    RemoteParkMissingHartEventAttribution {
        remote_park: RemoteParkId,
        event: EventId,
    },
    PreemptionMissingTimerInterrupt {
        preemption: PreemptionId,
        interrupt: TimerInterruptId,
    },
    PreemptionTimerTargetMismatch {
        preemption: PreemptionId,
        interrupt: TimerInterruptId,
        activation: ActivationId,
    },
    PreemptionMissingActivation {
        preemption: PreemptionId,
        activation: ActivationId,
    },
    PreemptionMissingQueue {
        preemption: PreemptionId,
        queue: RunnableQueueId,
    },
    PreemptionQueueEntryMismatch {
        preemption: PreemptionId,
        activation: ActivationId,
    },
    SchedulerDecisionMissingQueue {
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
    },
    SchedulerDecisionMissingActivation {
        decision: SchedulerDecisionId,
        activation: ActivationId,
    },
    SchedulerDecisionQueueEntryMismatch {
        decision: SchedulerDecisionId,
        activation: ActivationId,
    },
    SchedulerDecisionMissingTask {
        decision: SchedulerDecisionId,
        task: TaskId,
    },
    CrossHartSchedulerDecisionInvalid {
        cross_decision: CrossHartSchedulerDecisionId,
    },
    CrossHartSchedulerDecisionMissingDecision {
        cross_decision: CrossHartSchedulerDecisionId,
        decision: SchedulerDecisionId,
    },
    CrossHartSchedulerDecisionMissingHart {
        cross_decision: CrossHartSchedulerDecisionId,
        hart: HartId,
    },
    CrossHartSchedulerDecisionHartGenerationMismatch {
        cross_decision: CrossHartSchedulerDecisionId,
        hart: HartId,
    },
    CrossHartSchedulerDecisionQueueOwnerMismatch {
        cross_decision: CrossHartSchedulerDecisionId,
        queue: RunnableQueueId,
    },
    CrossHartSchedulerDecisionMissingEvent {
        cross_decision: CrossHartSchedulerDecisionId,
    },
    CrossHartSchedulerDecisionMissingHartEventAttribution {
        cross_decision: CrossHartSchedulerDecisionId,
        event: EventId,
    },
    ActivationMigrationInvalid {
        migration: ActivationMigrationId,
    },
    ActivationMigrationMissingHart {
        migration: ActivationMigrationId,
        hart: HartId,
    },
    ActivationMigrationHartGenerationMismatch {
        migration: ActivationMigrationId,
        hart: HartId,
    },
    ActivationMigrationMissingQueue {
        migration: ActivationMigrationId,
        queue: RunnableQueueId,
    },
    ActivationMigrationQueueOwnerMismatch {
        migration: ActivationMigrationId,
        queue: RunnableQueueId,
    },
    ActivationMigrationMissingActivation {
        migration: ActivationMigrationId,
        activation: ActivationId,
    },
    ActivationMigrationQueueEntryMismatch {
        migration: ActivationMigrationId,
        activation: ActivationId,
    },
    ActivationMigrationMissingEvent {
        migration: ActivationMigrationId,
    },
    ActivationMigrationMissingHartEventAttribution {
        migration: ActivationMigrationId,
        event: EventId,
    },
    SmpSafePointInvalid {
        safe_point: SmpSafePointId,
    },
    SmpSafePointMissingHart {
        safe_point: SmpSafePointId,
        hart: HartId,
    },
    SmpSafePointHartGenerationMismatch {
        safe_point: SmpSafePointId,
        hart: HartId,
    },
    SmpSafePointParticipantNotQuiesced {
        safe_point: SmpSafePointId,
        hart: HartId,
    },
    SmpSafePointMissingEvent {
        safe_point: SmpSafePointId,
    },
    SmpSafePointMissingHartEventAttribution {
        safe_point: SmpSafePointId,
        event: EventId,
    },
    StopTheWorldRendezvousInvalid {
        rendezvous: StopTheWorldRendezvousId,
    },
    StopTheWorldRendezvousSafePointMissing {
        rendezvous: StopTheWorldRendezvousId,
        safe_point: SmpSafePointId,
    },
    StopTheWorldRendezvousParticipantMismatch {
        rendezvous: StopTheWorldRendezvousId,
        hart: HartId,
    },
    StopTheWorldRendezvousMissingEvent {
        rendezvous: StopTheWorldRendezvousId,
    },
    StopTheWorldRendezvousMissingHartEventAttribution {
        rendezvous: StopTheWorldRendezvousId,
        event: EventId,
    },
    SmpCodePublishBarrierInvalid {
        barrier: SmpCodePublishBarrierId,
    },
    SmpCodePublishBarrierRendezvousMissing {
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
    },
    SmpCodePublishBarrierParticipantMismatch {
        barrier: SmpCodePublishBarrierId,
        hart: HartId,
    },
    SmpCodePublishBarrierMissingEvent {
        barrier: SmpCodePublishBarrierId,
    },
    SmpCodePublishBarrierMissingHartEventAttribution {
        barrier: SmpCodePublishBarrierId,
        event: EventId,
    },
    SmpCleanupQuiescenceInvalid {
        quiescence: SmpCleanupQuiescenceId,
    },
    SmpCleanupQuiescenceCleanupMissing {
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
    },
    SmpCleanupQuiescenceRendezvousMissing {
        quiescence: SmpCleanupQuiescenceId,
        rendezvous: StopTheWorldRendezvousId,
    },
    SmpCleanupQuiescenceParticipantMismatch {
        quiescence: SmpCleanupQuiescenceId,
        hart: HartId,
    },
    SmpCleanupQuiescenceStoreLeak {
        quiescence: SmpCleanupQuiescenceId,
        store: StoreId,
    },
    SmpCleanupQuiescenceMissingEvent {
        quiescence: SmpCleanupQuiescenceId,
    },
    SmpCleanupQuiescenceMissingHartEventAttribution {
        quiescence: SmpCleanupQuiescenceId,
        event: EventId,
    },
    SmpSnapshotBarrierInvalid {
        barrier: SmpSnapshotBarrierId,
    },
    SmpSnapshotBarrierRendezvousMissing {
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
    },
    SmpSnapshotBarrierParticipantMismatch {
        barrier: SmpSnapshotBarrierId,
        hart: HartId,
    },
    SmpSnapshotBarrierMissingEvent {
        barrier: SmpSnapshotBarrierId,
    },
    SmpSnapshotBarrierMissingHartEventAttribution {
        barrier: SmpSnapshotBarrierId,
        event: EventId,
    },
    SmpSnapshotBarrierBoundaryViolation {
        barrier: SmpSnapshotBarrierId,
    },
    ActivationResumeMissingDecision {
        resume: ActivationResumeId,
        decision: SchedulerDecisionId,
    },
    ActivationResumeMissingActivation {
        resume: ActivationResumeId,
        activation: ActivationId,
    },
    ActivationResumeQueueEntryMismatch {
        resume: ActivationResumeId,
        activation: ActivationId,
    },
    ActivationResumeMissingTask {
        resume: ActivationResumeId,
        task: TaskId,
    },
    PreemptionLatencyMissingTimerInterrupt {
        sample: PreemptionLatencySampleId,
        interrupt: TimerInterruptId,
    },
    PreemptionLatencyMissingPreemption {
        sample: PreemptionLatencySampleId,
        preemption: PreemptionId,
    },
    PreemptionLatencyMissingDecision {
        sample: PreemptionLatencySampleId,
        decision: SchedulerDecisionId,
    },
    PreemptionLatencyMissingResume {
        sample: PreemptionLatencySampleId,
        resume: ActivationResumeId,
    },
    PreemptionLatencyTimelineMismatch {
        sample: PreemptionLatencySampleId,
    },
    ActivationWaitMissingActivation {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
    },
    ActivationWaitMissingWait {
        activation_wait: ActivationWaitId,
        wait: WaitId,
    },
    ActivationWaitMissingTask {
        activation_wait: ActivationWaitId,
        task: TaskId,
    },
    ActivationWaitRunnableLeak {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
    },
    ActivationCleanupMissingStore {
        cleanup: ActivationCleanupId,
        store: StoreId,
    },
    ActivationCleanupMissingActivation {
        cleanup: ActivationCleanupId,
        activation: ActivationId,
    },
    ActivationCleanupMissingWait {
        cleanup: ActivationCleanupId,
        wait: WaitId,
    },
    ActivationCleanupMissingTask {
        cleanup: ActivationCleanupId,
        task: TaskId,
    },
    StoreReferencesMissingFaultDomain {
        store: StoreId,
        fault_domain: FaultDomainId,
    },
    LiveStoreMissingResource {
        store: StoreId,
    },
    StoreReferencesDeadResource {
        store: StoreId,
        resource: ResourceId,
    },
    AuthorityReferencesMissingResource {
        authority: AuthorityId,
        resource: ResourceId,
    },
    AuthorityReferencesDeadResource {
        authority: AuthorityId,
        resource: ResourceId,
    },
    AuthorityCapabilityMissing {
        authority: AuthorityId,
    },
}
