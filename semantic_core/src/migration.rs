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
    ActivationContextVectorStateInvalid {
        context: ActivationContextId,
    },
    ActivationContextVectorStateMissing {
        context: ActivationContextId,
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
    SavedContextVectorStateInvalid {
        saved_context: SavedContextId,
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
    SmpStressRunInvalid {
        run: SmpStressRunId,
    },
    SmpStressRunMissingEvidence {
        run: SmpStressRunId,
        evidence: &'static str,
    },
    SmpStressRunMissingEvent {
        run: SmpStressRunId,
    },
    SmpScalingBenchmarkInvalid {
        benchmark: SmpScalingBenchmarkId,
    },
    SmpScalingBenchmarkMissingStressRun {
        benchmark: SmpScalingBenchmarkId,
        stress_run: SmpStressRunId,
    },
    SmpScalingBenchmarkMissingEvent {
        benchmark: SmpScalingBenchmarkId,
    },
    IntegratedSmpPreemptionCleanupInvalid {
        integrated: IntegratedSmpPreemptionCleanupId,
    },
    IntegratedSmpPreemptionCleanupMissingEvidence {
        integrated: IntegratedSmpPreemptionCleanupId,
        evidence: &'static str,
    },
    IntegratedSmpPreemptionCleanupMissingEvent {
        integrated: IntegratedSmpPreemptionCleanupId,
    },
    IntegratedSmpNetworkFaultInvalid {
        integrated: IntegratedSmpNetworkFaultId,
    },
    IntegratedSmpNetworkFaultMissingEvidence {
        integrated: IntegratedSmpNetworkFaultId,
        evidence: &'static str,
    },
    IntegratedSmpNetworkFaultMissingEvent {
        integrated: IntegratedSmpNetworkFaultId,
    },
    IntegratedDiskPreemptFaultInvalid {
        integrated: IntegratedDiskPreemptFaultId,
    },
    IntegratedDiskPreemptFaultMissingEvidence {
        integrated: IntegratedDiskPreemptFaultId,
        evidence: &'static str,
    },
    IntegratedDiskPreemptFaultMissingEvent {
        integrated: IntegratedDiskPreemptFaultId,
    },
    IntegratedSimdMigrationInvalid {
        integrated: IntegratedSimdMigrationId,
    },
    IntegratedSimdMigrationMissingEvidence {
        integrated: IntegratedSimdMigrationId,
        evidence: &'static str,
    },
    IntegratedSimdMigrationMissingEvent {
        integrated: IntegratedSimdMigrationId,
    },
    IntegratedNetworkDiskIoInvalid {
        integrated: IntegratedNetworkDiskIoId,
    },
    IntegratedNetworkDiskIoMissingEvidence {
        integrated: IntegratedNetworkDiskIoId,
        evidence: &'static str,
    },
    IntegratedNetworkDiskIoMissingEvent {
        integrated: IntegratedNetworkDiskIoId,
    },
    IntegratedDisplaySchedulerLoadInvalid {
        integrated: IntegratedDisplaySchedulerLoadId,
    },
    IntegratedDisplaySchedulerLoadMissingEvidence {
        integrated: IntegratedDisplaySchedulerLoadId,
        evidence: &'static str,
    },
    IntegratedDisplaySchedulerLoadMissingEvent {
        integrated: IntegratedDisplaySchedulerLoadId,
    },
    IntegratedSnapshotIoLeaseBarrierInvalid {
        integrated: IntegratedSnapshotIoLeaseBarrierId,
    },
    IntegratedSnapshotIoLeaseBarrierMissingEvidence {
        integrated: IntegratedSnapshotIoLeaseBarrierId,
        evidence: &'static str,
    },
    IntegratedSnapshotIoLeaseBarrierMissingEvent {
        integrated: IntegratedSnapshotIoLeaseBarrierId,
    },
    DeviceObjectInvalid {
        device: DeviceObjectId,
    },
    DeviceObjectMissingResource {
        device: DeviceObjectId,
        resource: ResourceId,
    },
    DeviceObjectMissingEvent {
        device: DeviceObjectId,
    },
    QueueObjectInvalid {
        queue: QueueObjectId,
    },
    QueueObjectMissingDevice {
        queue: QueueObjectId,
        device: DeviceObjectId,
    },
    QueueObjectDuplicateIndex {
        queue: QueueObjectId,
        device: DeviceObjectId,
        queue_index: u16,
    },
    QueueObjectMissingEvent {
        queue: QueueObjectId,
    },
    DescriptorObjectInvalid {
        descriptor: DescriptorObjectId,
    },
    DescriptorObjectMissingQueue {
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
    },
    DescriptorObjectDuplicateSlot {
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        slot: u16,
    },
    DescriptorObjectMissingEvent {
        descriptor: DescriptorObjectId,
    },
    DmaBufferObjectInvalid {
        dma_buffer: DmaBufferObjectId,
    },
    DmaBufferObjectMissingDescriptor {
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
    },
    DmaBufferObjectMissingResource {
        dma_buffer: DmaBufferObjectId,
        resource: ResourceId,
    },
    DmaBufferObjectDuplicateDescriptor {
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
    },
    DmaBufferObjectMissingEvent {
        dma_buffer: DmaBufferObjectId,
    },
    MmioRegionObjectInvalid {
        mmio_region: MmioRegionObjectId,
    },
    MmioRegionObjectMissingDevice {
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
    },
    MmioRegionObjectMissingResource {
        mmio_region: MmioRegionObjectId,
        resource: ResourceId,
    },
    MmioRegionObjectDuplicateIndex {
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        region_index: u16,
    },
    MmioRegionObjectMissingEvent {
        mmio_region: MmioRegionObjectId,
    },
    IrqLineObjectInvalid {
        irq_line: IrqLineObjectId,
    },
    IrqLineObjectMissingDevice {
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
    },
    IrqLineObjectMissingResource {
        irq_line: IrqLineObjectId,
        resource: ResourceId,
    },
    IrqLineObjectDuplicateNumber {
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        irq_number: u32,
    },
    IrqLineObjectMissingEvent {
        irq_line: IrqLineObjectId,
    },
    IrqEventInvalid {
        irq_event: IrqEventId,
    },
    IrqEventMissingLine {
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
    },
    IrqEventMissingDevice {
        irq_event: IrqEventId,
        device: DeviceObjectId,
    },
    IrqEventMissingDriverStore {
        irq_event: IrqEventId,
        store: StoreId,
    },
    IrqEventDuplicateSequence {
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        sequence: u64,
    },
    IrqEventMissingEvent {
        irq_event: IrqEventId,
    },
    DeviceCapabilityInvalid {
        device_capability: DeviceCapabilityId,
    },
    DeviceCapabilityMissingStore {
        device_capability: DeviceCapabilityId,
        store: StoreId,
    },
    DeviceCapabilityMissingTarget {
        device_capability: DeviceCapabilityId,
        target: ContractObjectRef,
    },
    DeviceCapabilityMissingCapability {
        device_capability: DeviceCapabilityId,
        capability: CapabilityId,
    },
    DeviceCapabilityDuplicateTarget {
        device_capability: DeviceCapabilityId,
        target: ContractObjectRef,
    },
    DeviceCapabilityMissingEvent {
        device_capability: DeviceCapabilityId,
    },
    DriverStoreBindingInvalid {
        binding: DriverStoreBindingId,
    },
    DriverStoreBindingMissingStore {
        binding: DriverStoreBindingId,
        store: StoreId,
    },
    DriverStoreBindingMissingDevice {
        binding: DriverStoreBindingId,
        device: DeviceObjectId,
    },
    DriverStoreBindingMissingCapabilityEvidence {
        binding: DriverStoreBindingId,
        device_capability: DeviceCapabilityId,
    },
    DriverStoreBindingDuplicateDevice {
        binding: DriverStoreBindingId,
        device: DeviceObjectId,
    },
    DriverStoreBindingMissingEvent {
        binding: DriverStoreBindingId,
    },
    IoWaitInvalid {
        io_wait: IoWaitId,
    },
    IoWaitMissingWait {
        io_wait: IoWaitId,
        wait: WaitId,
    },
    IoWaitMissingStore {
        io_wait: IoWaitId,
        store: StoreId,
    },
    IoWaitMissingDevice {
        io_wait: IoWaitId,
        device: DeviceObjectId,
    },
    IoWaitMissingDriverBinding {
        io_wait: IoWaitId,
        binding: DriverStoreBindingId,
    },
    IoWaitMissingBlocker {
        io_wait: IoWaitId,
        blocker: ContractObjectRef,
    },
    IoWaitDuplicateWait {
        io_wait: IoWaitId,
        wait: WaitId,
    },
    IoWaitMissingEvent {
        io_wait: IoWaitId,
        event: EventId,
    },
    IoCleanupInvalid {
        cleanup: IoCleanupId,
    },
    IoCleanupMissingStore {
        cleanup: IoCleanupId,
        store: StoreId,
    },
    IoCleanupMissingDevice {
        cleanup: IoCleanupId,
        device: DeviceObjectId,
    },
    IoCleanupMissingDriverBinding {
        cleanup: IoCleanupId,
        binding: DriverStoreBindingId,
    },
    IoCleanupMissingEffectTarget {
        cleanup: IoCleanupId,
        target: ContractObjectRef,
    },
    IoCleanupLiveLeak {
        cleanup: IoCleanupId,
    },
    IoCleanupMissingEvent {
        cleanup: IoCleanupId,
    },
    IoFaultInjectionInvalid {
        fault: IoFaultInjectionId,
    },
    IoFaultInjectionMissingStore {
        fault: IoFaultInjectionId,
        store: StoreId,
    },
    IoFaultInjectionMissingDevice {
        fault: IoFaultInjectionId,
        device: DeviceObjectId,
    },
    IoFaultInjectionMissingDriverBinding {
        fault: IoFaultInjectionId,
        binding: DriverStoreBindingId,
    },
    IoFaultInjectionMissingTarget {
        fault: IoFaultInjectionId,
        target: ContractObjectRef,
    },
    IoFaultInjectionMissingCleanup {
        fault: IoFaultInjectionId,
        cleanup: IoCleanupId,
    },
    IoFaultInjectionMissingEvent {
        fault: IoFaultInjectionId,
    },
    IoValidationReportInvalid {
        report: IoValidationReportId,
    },
    IoValidationReportMissingEvent {
        report: IoValidationReportId,
    },
    PacketDeviceObjectInvalid {
        packet_device: PacketDeviceObjectId,
    },
    PacketDeviceObjectMissingDevice {
        packet_device: PacketDeviceObjectId,
        device: DeviceObjectId,
    },
    PacketDeviceObjectMissingEvent {
        packet_device: PacketDeviceObjectId,
    },
    PacketBufferObjectInvalid {
        packet_buffer: PacketBufferObjectId,
    },
    PacketBufferObjectMissingDevice {
        packet_buffer: PacketBufferObjectId,
        packet_device: PacketDeviceObjectId,
    },
    PacketBufferObjectMissingEvent {
        packet_buffer: PacketBufferObjectId,
    },
    PacketQueueObjectInvalid {
        packet_queue: PacketQueueObjectId,
    },
    PacketQueueObjectMissingDevice {
        packet_queue: PacketQueueObjectId,
        packet_device: PacketDeviceObjectId,
    },
    PacketQueueObjectDuplicateIndex {
        packet_queue: PacketQueueObjectId,
        packet_device: PacketDeviceObjectId,
        role: PacketQueueRole,
        queue_index: u16,
    },
    PacketQueueObjectMissingEvent {
        packet_queue: PacketQueueObjectId,
    },
    PacketDescriptorObjectInvalid {
        packet_descriptor: PacketDescriptorObjectId,
    },
    PacketDescriptorObjectMissingQueue {
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
    },
    PacketDescriptorObjectMissingBuffer {
        packet_descriptor: PacketDescriptorObjectId,
        packet_buffer: PacketBufferObjectId,
    },
    PacketDescriptorObjectDuplicateSlot {
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
        slot: u16,
    },
    PacketDescriptorObjectDuplicateBuffer {
        packet_descriptor: PacketDescriptorObjectId,
        packet_buffer: PacketBufferObjectId,
    },
    PacketDescriptorObjectMissingEvent {
        packet_descriptor: PacketDescriptorObjectId,
    },
    FakeNetBackendObjectInvalid {
        fake_net_backend: FakeNetBackendObjectId,
    },
    FakeNetBackendObjectMissingPacketDevice {
        fake_net_backend: FakeNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
    },
    FakeNetBackendObjectDuplicateBinding {
        fake_net_backend: FakeNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
    },
    FakeNetBackendObjectMissingEvent {
        fake_net_backend: FakeNetBackendObjectId,
    },
    FakeBlockBackendObjectInvalid {
        fake_block_backend: FakeBlockBackendObjectId,
    },
    FakeBlockBackendObjectMissingBlockDevice {
        fake_block_backend: FakeBlockBackendObjectId,
        block_device: BlockDeviceObjectId,
    },
    FakeBlockBackendObjectDuplicateBinding {
        fake_block_backend: FakeBlockBackendObjectId,
        block_device: BlockDeviceObjectId,
    },
    FakeBlockBackendObjectMissingEvent {
        fake_block_backend: FakeBlockBackendObjectId,
    },
    VirtioBlkBackendObjectInvalid {
        virtio_blk_backend: VirtioBlkBackendObjectId,
    },
    VirtioBlkBackendObjectMissingBlockDevice {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        block_device: BlockDeviceObjectId,
    },
    VirtioBlkBackendObjectMissingDriverBinding {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        driver_binding: DriverStoreBindingId,
    },
    VirtioBlkBackendObjectDuplicateBinding {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        block_device: BlockDeviceObjectId,
    },
    VirtioBlkBackendObjectDuplicateDriverBinding {
        virtio_blk_backend: VirtioBlkBackendObjectId,
        driver_binding: DriverStoreBindingId,
    },
    VirtioBlkBackendObjectMissingEvent {
        virtio_blk_backend: VirtioBlkBackendObjectId,
    },
    BlockReadPathInvalid {
        read_path: BlockReadPathId,
    },
    BlockReadPathMissingBackend {
        read_path: BlockReadPathId,
        backend: ContractObjectRef,
    },
    BlockReadPathMissingRequest {
        read_path: BlockReadPathId,
        block_request: BlockRequestObjectId,
    },
    BlockReadPathMissingCompletion {
        read_path: BlockReadPathId,
        block_completion: BlockCompletionObjectId,
    },
    BlockReadPathDuplicateRequest {
        read_path: BlockReadPathId,
        block_request: BlockRequestObjectId,
    },
    BlockReadPathMissingEvent {
        read_path: BlockReadPathId,
    },
    BlockWritePathInvalid {
        write_path: BlockWritePathId,
    },
    BlockWritePathMissingBackend {
        write_path: BlockWritePathId,
        backend: ContractObjectRef,
    },
    BlockWritePathMissingRequest {
        write_path: BlockWritePathId,
        block_request: BlockRequestObjectId,
    },
    BlockWritePathMissingCompletion {
        write_path: BlockWritePathId,
        block_completion: BlockCompletionObjectId,
    },
    BlockWritePathDuplicateRequest {
        write_path: BlockWritePathId,
        block_request: BlockRequestObjectId,
    },
    BlockWritePathMissingEvent {
        write_path: BlockWritePathId,
    },
    BlockRequestQueueInvalid {
        queue: BlockRequestQueueId,
    },
    BlockRequestQueueMissingBackend {
        queue: BlockRequestQueueId,
        backend: ContractObjectRef,
    },
    BlockRequestQueueMissingBlockDevice {
        queue: BlockRequestQueueId,
        block_device: BlockDeviceObjectId,
    },
    BlockRequestQueueMissingRequest {
        queue: BlockRequestQueueId,
        block_request: BlockRequestObjectId,
    },
    BlockRequestQueueMissingCompletion {
        queue: BlockRequestQueueId,
        block_completion: BlockCompletionObjectId,
    },
    BlockRequestQueueDuplicateRequest {
        queue: BlockRequestQueueId,
        block_request: BlockRequestObjectId,
    },
    BlockRequestQueueDuplicateSequence {
        queue: BlockRequestQueueId,
        sequence: u64,
    },
    BlockRequestQueueMissingEvent {
        queue: BlockRequestQueueId,
    },
    BlockDmaBufferInvalid {
        block_dma_buffer: BlockDmaBufferId,
    },
    BlockDmaBufferMissingBackend {
        block_dma_buffer: BlockDmaBufferId,
        backend: ContractObjectRef,
    },
    BlockDmaBufferMissingRequest {
        block_dma_buffer: BlockDmaBufferId,
        block_request: BlockRequestObjectId,
    },
    BlockDmaBufferMissingDmaBuffer {
        block_dma_buffer: BlockDmaBufferId,
        dma_buffer: DmaBufferObjectId,
    },
    BlockDmaBufferDuplicateRequest {
        block_dma_buffer: BlockDmaBufferId,
        block_request: BlockRequestObjectId,
    },
    BlockDmaBufferDuplicateDmaBuffer {
        block_dma_buffer: BlockDmaBufferId,
        dma_buffer: DmaBufferObjectId,
    },
    BlockDmaBufferMissingEvent {
        block_dma_buffer: BlockDmaBufferId,
    },
    BlockPageObjectInvalid {
        block_page_object: BlockPageObjectId,
    },
    BlockPageObjectMissingDmaBuffer {
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
    },
    BlockPageObjectMissingCompletion {
        block_page_object: BlockPageObjectId,
        block_completion: BlockCompletionObjectId,
    },
    BlockPageObjectDuplicateDmaBuffer {
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
    },
    BlockPageObjectDuplicatePageRange {
        block_page_object: BlockPageObjectId,
        page: ContractObjectRef,
    },
    BlockPageObjectMissingEvent {
        block_page_object: BlockPageObjectId,
    },
    BufferCacheObjectInvalid {
        buffer_cache_object: BufferCacheObjectId,
    },
    BufferCacheObjectMissingBlockPageObject {
        buffer_cache_object: BufferCacheObjectId,
        block_page_object: BlockPageObjectId,
    },
    BufferCacheObjectDuplicateBlockRange {
        buffer_cache_object: BufferCacheObjectId,
        block_range: BlockRangeObjectId,
    },
    BufferCacheObjectDuplicatePageRange {
        buffer_cache_object: BufferCacheObjectId,
        page: ContractObjectRef,
    },
    BufferCacheObjectMissingEvent {
        buffer_cache_object: BufferCacheObjectId,
    },
    FileObjectInvalid {
        file_object: FileObjectId,
    },
    FileObjectMissingBufferCacheObject {
        file_object: FileObjectId,
        buffer_cache_object: BufferCacheObjectId,
    },
    FileObjectDuplicateFileRange {
        file_object: FileObjectId,
    },
    FileObjectMissingEvent {
        file_object: FileObjectId,
    },
    DirectoryObjectInvalid {
        directory_object: DirectoryObjectId,
    },
    DirectoryObjectMissingFileObject {
        directory_object: DirectoryObjectId,
        file_object: FileObjectId,
    },
    DirectoryObjectDuplicateEntry {
        directory_object: DirectoryObjectId,
    },
    DirectoryObjectMissingEvent {
        directory_object: DirectoryObjectId,
    },
    FatAdapterObjectInvalid {
        fat_adapter_object: FatAdapterObjectId,
    },
    FatAdapterObjectMissingDirectoryObject {
        fat_adapter_object: FatAdapterObjectId,
        directory_object: DirectoryObjectId,
    },
    FatAdapterObjectMissingFileObject {
        fat_adapter_object: FatAdapterObjectId,
        file_object: FileObjectId,
    },
    FatAdapterObjectDuplicateBinding {
        fat_adapter_object: FatAdapterObjectId,
    },
    FatAdapterObjectMissingEvent {
        fat_adapter_object: FatAdapterObjectId,
    },
    Ext4AdapterObjectInvalid {
        ext4_adapter_object: Ext4AdapterObjectId,
    },
    Ext4AdapterObjectMissingDirectoryObject {
        ext4_adapter_object: Ext4AdapterObjectId,
        directory_object: DirectoryObjectId,
    },
    Ext4AdapterObjectMissingFileObject {
        ext4_adapter_object: Ext4AdapterObjectId,
        file_object: FileObjectId,
    },
    Ext4AdapterObjectDuplicateBinding {
        ext4_adapter_object: Ext4AdapterObjectId,
    },
    Ext4AdapterObjectMissingEvent {
        ext4_adapter_object: Ext4AdapterObjectId,
    },
    FileHandleCapabilityInvalid {
        file_handle_capability: FileHandleCapabilityId,
    },
    FileHandleCapabilityMissingStore {
        file_handle_capability: FileHandleCapabilityId,
        store: StoreId,
    },
    FileHandleCapabilityMissingFileObject {
        file_handle_capability: FileHandleCapabilityId,
        file_object: FileObjectId,
    },
    FileHandleCapabilityMissingDirectoryObject {
        file_handle_capability: FileHandleCapabilityId,
        directory_object: DirectoryObjectId,
    },
    FileHandleCapabilityMissingCapability {
        file_handle_capability: FileHandleCapabilityId,
        capability: CapabilityId,
    },
    FileHandleCapabilityDuplicateGrant {
        file_handle_capability: FileHandleCapabilityId,
        file_object: FileObjectId,
    },
    FileHandleCapabilityMissingEvent {
        file_handle_capability: FileHandleCapabilityId,
    },
    FsWaitInvalid {
        fs_wait: FsWaitId,
    },
    FsWaitMissingWait {
        fs_wait: FsWaitId,
        wait: WaitId,
    },
    FsWaitMissingStore {
        fs_wait: FsWaitId,
        store: StoreId,
    },
    FsWaitMissingFileObject {
        fs_wait: FsWaitId,
        file_object: FileObjectId,
    },
    FsWaitMissingDirectoryObject {
        fs_wait: FsWaitId,
        directory_object: DirectoryObjectId,
    },
    FsWaitMissingFileHandleCapability {
        fs_wait: FsWaitId,
        file_handle_capability: FileHandleCapabilityId,
    },
    FsWaitDuplicateWait {
        fs_wait: FsWaitId,
        wait: WaitId,
    },
    FsWaitMissingEvent {
        fs_wait: FsWaitId,
        event: EventId,
    },
    BlockDriverCleanupInvalid {
        cleanup: BlockDriverCleanupId,
    },
    BlockDriverCleanupMissingIoCleanup {
        cleanup: BlockDriverCleanupId,
        io_cleanup: IoCleanupId,
    },
    BlockDriverCleanupMissingBlockDevice {
        cleanup: BlockDriverCleanupId,
        block_device: BlockDeviceObjectId,
    },
    BlockDriverCleanupMissingBackend {
        cleanup: BlockDriverCleanupId,
        backend: ContractObjectRef,
    },
    BlockDriverCleanupMissingEffectTarget {
        cleanup: BlockDriverCleanupId,
        target: ContractObjectRef,
    },
    BlockDriverCleanupLiveLeak {
        cleanup: BlockDriverCleanupId,
    },
    BlockDriverCleanupMissingEvent {
        cleanup: BlockDriverCleanupId,
        event: EventId,
    },
    BlockPendingIoPolicyInvalid {
        policy: BlockPendingIoPolicyId,
    },
    BlockPendingIoPolicyMissingBlockWait {
        policy: BlockPendingIoPolicyId,
        block_wait: BlockWaitId,
    },
    BlockPendingIoPolicyMissingRequest {
        policy: BlockPendingIoPolicyId,
        block_request: BlockRequestObjectId,
    },
    BlockPendingIoPolicyMissingRetryRequest {
        policy: BlockPendingIoPolicyId,
        block_request: BlockRequestObjectId,
    },
    BlockPendingIoPolicyMissingEvent {
        policy: BlockPendingIoPolicyId,
        event: EventId,
    },
    BlockRequestGenerationAuditInvalid {
        audit: BlockRequestGenerationAuditId,
    },
    BlockRequestGenerationAuditMissingTarget {
        audit: BlockRequestGenerationAuditId,
        target: ContractObjectRef,
    },
    BlockRequestGenerationAuditMissingEvent {
        audit: BlockRequestGenerationAuditId,
        event: EventId,
    },
    BlockBenchmarkInvalid {
        benchmark: BlockBenchmarkId,
    },
    BlockBenchmarkMissingTarget {
        benchmark: BlockBenchmarkId,
        target: ContractObjectRef,
    },
    BlockBenchmarkMetricMismatch {
        benchmark: BlockBenchmarkId,
    },
    BlockBenchmarkMissingEvent {
        benchmark: BlockBenchmarkId,
        event: EventId,
    },
    BlockRecoveryBenchmarkInvalid {
        benchmark: BlockRecoveryBenchmarkId,
    },
    BlockRecoveryBenchmarkMissingTarget {
        benchmark: BlockRecoveryBenchmarkId,
        target: ContractObjectRef,
    },
    BlockRecoveryBenchmarkMetricMismatch {
        benchmark: BlockRecoveryBenchmarkId,
    },
    BlockRecoveryBenchmarkMissingEvent {
        benchmark: BlockRecoveryBenchmarkId,
        event: EventId,
    },
    TargetFeatureSetInvalid {
        feature_set: TargetFeatureSetId,
    },
    TargetFeatureSetMissingEvent {
        feature_set: TargetFeatureSetId,
        event: EventId,
    },
    VectorStateInvalid {
        vector_state: VectorStateId,
    },
    VectorStateMissingTargetFeatureSet {
        vector_state: VectorStateId,
        target_feature_set: ContractObjectRef,
    },
    VectorStateMissingEvent {
        vector_state: VectorStateId,
        event: EventId,
    },
    SimdFaultInjectionInvalid {
        injection: SimdFaultInjectionId,
    },
    SimdFaultInjectionMissingTarget {
        injection: SimdFaultInjectionId,
        target: ContractObjectRef,
    },
    SimdFaultInjectionMissingEvent {
        injection: SimdFaultInjectionId,
        event: EventId,
    },
    SimdBenchmarkInvalid {
        benchmark: SimdBenchmarkId,
    },
    SimdBenchmarkMissingTarget {
        benchmark: SimdBenchmarkId,
        target: ContractObjectRef,
    },
    SimdBenchmarkMetricMismatch {
        benchmark: SimdBenchmarkId,
    },
    SimdBenchmarkMissingEvent {
        benchmark: SimdBenchmarkId,
        event: EventId,
    },
    SimdContextSwitchBenchmarkInvalid {
        benchmark: SimdContextSwitchBenchmarkId,
    },
    SimdContextSwitchBenchmarkMissingEvent {
        benchmark: SimdContextSwitchBenchmarkId,
        event: EventId,
    },
    FramebufferObjectInvalid {
        framebuffer: FramebufferObjectId,
    },
    FramebufferObjectMissingResource {
        framebuffer: FramebufferObjectId,
        resource: ResourceId,
    },
    FramebufferObjectMissingEvent {
        framebuffer: FramebufferObjectId,
    },
    DisplayObjectInvalid {
        display: DisplayObjectId,
    },
    DisplayObjectMissingFramebuffer {
        display: DisplayObjectId,
        framebuffer: FramebufferObjectId,
    },
    DisplayObjectMissingEvent {
        display: DisplayObjectId,
    },
    DisplayCapabilityInvalid {
        display_capability: DisplayCapabilityId,
    },
    DisplayCapabilityMissingStore {
        display_capability: DisplayCapabilityId,
        store: StoreId,
    },
    DisplayCapabilityMissingDisplay {
        display_capability: DisplayCapabilityId,
        display: DisplayObjectId,
    },
    DisplayCapabilityMissingFramebuffer {
        display_capability: DisplayCapabilityId,
        framebuffer: FramebufferObjectId,
    },
    DisplayCapabilityMissingCapability {
        display_capability: DisplayCapabilityId,
        capability: CapabilityId,
    },
    DisplayCapabilityDuplicateGrant {
        display_capability: DisplayCapabilityId,
        display: DisplayObjectId,
    },
    DisplayCapabilityMissingEvent {
        display_capability: DisplayCapabilityId,
    },
    FramebufferWindowLeaseInvalid {
        framebuffer_window_lease: FramebufferWindowLeaseId,
    },
    FramebufferWindowLeaseMissingStore {
        framebuffer_window_lease: FramebufferWindowLeaseId,
        store: StoreId,
    },
    FramebufferWindowLeaseMissingDisplayCapability {
        framebuffer_window_lease: FramebufferWindowLeaseId,
        display_capability: DisplayCapabilityId,
    },
    FramebufferWindowLeaseMissingDisplay {
        framebuffer_window_lease: FramebufferWindowLeaseId,
        display: DisplayObjectId,
    },
    FramebufferWindowLeaseMissingFramebuffer {
        framebuffer_window_lease: FramebufferWindowLeaseId,
        framebuffer: FramebufferObjectId,
    },
    FramebufferWindowLeaseDuplicateActive {
        framebuffer_window_lease: FramebufferWindowLeaseId,
        framebuffer: FramebufferObjectId,
    },
    FramebufferWindowLeaseMissingEvent {
        framebuffer_window_lease: FramebufferWindowLeaseId,
    },
    FramebufferMappingInvalid {
        framebuffer_mapping: FramebufferMappingId,
    },
    FramebufferMappingMissingStore {
        framebuffer_mapping: FramebufferMappingId,
        store: StoreId,
    },
    FramebufferMappingMissingLease {
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_window_lease: FramebufferWindowLeaseId,
    },
    FramebufferMappingDuplicateActive {
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_window_lease: FramebufferWindowLeaseId,
    },
    FramebufferMappingMissingEvent {
        framebuffer_mapping: FramebufferMappingId,
    },
    FramebufferWriteInvalid {
        framebuffer_write: FramebufferWriteId,
    },
    FramebufferWriteMissingStore {
        framebuffer_write: FramebufferWriteId,
        store: StoreId,
    },
    FramebufferWriteMissingMapping {
        framebuffer_write: FramebufferWriteId,
        framebuffer_mapping: FramebufferMappingId,
    },
    FramebufferWriteMissingEvent {
        framebuffer_write: FramebufferWriteId,
    },
    FramebufferFlushRegionInvalid {
        framebuffer_flush_region: FramebufferFlushRegionId,
    },
    FramebufferFlushRegionMissingStore {
        framebuffer_flush_region: FramebufferFlushRegionId,
        store: StoreId,
    },
    FramebufferFlushRegionMissingWrite {
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_write: FramebufferWriteId,
    },
    FramebufferFlushRegionMissingEvent {
        framebuffer_flush_region: FramebufferFlushRegionId,
    },
    FramebufferDirtyRegionInvalid {
        framebuffer_dirty_region: FramebufferDirtyRegionId,
    },
    FramebufferDirtyRegionMissingStore {
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        store: StoreId,
    },
    FramebufferDirtyRegionMissingWrite {
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        framebuffer_write: FramebufferWriteId,
    },
    FramebufferDirtyRegionMissingFlush {
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        framebuffer_flush_region: FramebufferFlushRegionId,
    },
    FramebufferDirtyRegionMissingEvent {
        framebuffer_dirty_region: FramebufferDirtyRegionId,
    },
    DisplayEventLogInvalid {
        display_event_log: DisplayEventLogId,
    },
    DisplayEventLogMissingStore {
        display_event_log: DisplayEventLogId,
        store: StoreId,
    },
    DisplayEventLogMissingDirtyRegion {
        display_event_log: DisplayEventLogId,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
    },
    DisplayEventLogMissingEvent {
        display_event_log: DisplayEventLogId,
    },
    DisplayCleanupInvalid {
        cleanup: DisplayCleanupId,
    },
    DisplayCleanupMissingStore {
        cleanup: DisplayCleanupId,
        store: StoreId,
    },
    DisplayCleanupMissingDisplayCapability {
        cleanup: DisplayCleanupId,
        display_capability: DisplayCapabilityId,
    },
    DisplayCleanupMissingEffectTarget {
        cleanup: DisplayCleanupId,
        target: ContractObjectRef,
    },
    DisplayCleanupMissingEvent {
        cleanup: DisplayCleanupId,
    },
    DisplaySnapshotBarrierInvalid {
        barrier: DisplaySnapshotBarrierId,
    },
    DisplaySnapshotBarrierMissingStore {
        barrier: DisplaySnapshotBarrierId,
        store: StoreId,
    },
    DisplaySnapshotBarrierMissingDisplay {
        barrier: DisplaySnapshotBarrierId,
        display: DisplayObjectId,
    },
    DisplaySnapshotBarrierMissingFramebuffer {
        barrier: DisplaySnapshotBarrierId,
        framebuffer: FramebufferObjectId,
    },
    DisplaySnapshotBarrierMissingCleanup {
        barrier: DisplaySnapshotBarrierId,
        cleanup: DisplayCleanupId,
    },
    DisplaySnapshotBarrierMissingEvent {
        barrier: DisplaySnapshotBarrierId,
    },
    DisplayPanicLastFrameInvalid {
        panic_last_frame: DisplayPanicLastFrameId,
    },
    DisplayPanicLastFrameMissingStore {
        panic_last_frame: DisplayPanicLastFrameId,
        store: StoreId,
    },
    DisplayPanicLastFrameMissingDisplay {
        panic_last_frame: DisplayPanicLastFrameId,
        display: DisplayObjectId,
    },
    DisplayPanicLastFrameMissingFramebuffer {
        panic_last_frame: DisplayPanicLastFrameId,
        framebuffer: FramebufferObjectId,
    },
    DisplayPanicLastFrameMissingBarrier {
        panic_last_frame: DisplayPanicLastFrameId,
        barrier: DisplaySnapshotBarrierId,
    },
    DisplayPanicLastFrameMissingEventLog {
        panic_last_frame: DisplayPanicLastFrameId,
        display_event_log: DisplayEventLogId,
    },
    DisplayPanicLastFrameMissingWrite {
        panic_last_frame: DisplayPanicLastFrameId,
        framebuffer_write: FramebufferWriteId,
    },
    DisplayPanicLastFrameMissingFlush {
        panic_last_frame: DisplayPanicLastFrameId,
        framebuffer_flush_region: FramebufferFlushRegionId,
    },
    DisplayPanicLastFrameMissingEvent {
        panic_last_frame: DisplayPanicLastFrameId,
    },
    FramebufferBenchmarkInvalid {
        benchmark: FramebufferBenchmarkId,
    },
    FramebufferBenchmarkMissingTarget {
        benchmark: FramebufferBenchmarkId,
        target: ContractObjectRef,
    },
    FramebufferBenchmarkMetricMismatch {
        benchmark: FramebufferBenchmarkId,
    },
    FramebufferBenchmarkMissingEvent {
        benchmark: FramebufferBenchmarkId,
        event: EventId,
    },
    VirtioNetBackendObjectInvalid {
        virtio_net_backend: VirtioNetBackendObjectId,
    },
    VirtioNetBackendObjectMissingPacketDevice {
        virtio_net_backend: VirtioNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
    },
    VirtioNetBackendObjectMissingDriverBinding {
        virtio_net_backend: VirtioNetBackendObjectId,
        driver_binding: DriverStoreBindingId,
    },
    VirtioNetBackendObjectDuplicateBinding {
        virtio_net_backend: VirtioNetBackendObjectId,
        packet_device: PacketDeviceObjectId,
    },
    VirtioNetBackendObjectDuplicateDriverBinding {
        virtio_net_backend: VirtioNetBackendObjectId,
        driver_binding: DriverStoreBindingId,
    },
    VirtioNetBackendObjectMissingEvent {
        virtio_net_backend: VirtioNetBackendObjectId,
    },
    NetworkRxInterruptInvalid {
        rx_interrupt: NetworkRxInterruptId,
    },
    NetworkRxInterruptMissingBackend {
        rx_interrupt: NetworkRxInterruptId,
        virtio_net_backend: VirtioNetBackendObjectId,
    },
    NetworkRxInterruptMissingIrqEvent {
        rx_interrupt: NetworkRxInterruptId,
        irq_event: IrqEventId,
    },
    NetworkRxInterruptMissingPacketDevice {
        rx_interrupt: NetworkRxInterruptId,
        packet_device: PacketDeviceObjectId,
    },
    NetworkRxInterruptMissingRxQueue {
        rx_interrupt: NetworkRxInterruptId,
        rx_queue: PacketQueueObjectId,
    },
    NetworkRxInterruptMissingIrqCapability {
        rx_interrupt: NetworkRxInterruptId,
        irq_line: IrqLineObjectId,
    },
    NetworkRxInterruptDuplicateIrqEvent {
        rx_interrupt: NetworkRxInterruptId,
        irq_event: IrqEventId,
    },
    NetworkRxInterruptMissingEvent {
        rx_interrupt: NetworkRxInterruptId,
    },
    NetworkRxWaitResolutionInvalid {
        resolution: NetworkRxWaitResolutionId,
    },
    NetworkRxWaitResolutionMissingIoWait {
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
    },
    NetworkRxWaitResolutionMissingInterrupt {
        resolution: NetworkRxWaitResolutionId,
        rx_interrupt: NetworkRxInterruptId,
    },
    NetworkRxWaitResolutionMissingRxQueue {
        resolution: NetworkRxWaitResolutionId,
        rx_queue: PacketQueueObjectId,
    },
    NetworkRxWaitResolutionDuplicateIoWait {
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
    },
    NetworkRxWaitResolutionMissingEvent {
        resolution: NetworkRxWaitResolutionId,
    },
    NetworkTxCapabilityGateInvalid {
        tx_gate: NetworkTxCapabilityGateId,
    },
    NetworkTxCapabilityGateMissingDescriptor {
        tx_gate: NetworkTxCapabilityGateId,
        packet_descriptor: PacketDescriptorObjectId,
    },
    NetworkTxCapabilityGateMissingCapability {
        tx_gate: NetworkTxCapabilityGateId,
        device_capability: DeviceCapabilityId,
    },
    NetworkTxCapabilityGateDuplicateDescriptor {
        tx_gate: NetworkTxCapabilityGateId,
        packet_descriptor: PacketDescriptorObjectId,
    },
    NetworkTxCapabilityGateMissingEvent {
        tx_gate: NetworkTxCapabilityGateId,
    },
    NetworkTxCompletionInvalid {
        completion: NetworkTxCompletionId,
    },
    NetworkTxCompletionMissingGate {
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
    },
    NetworkTxCompletionMissingBackend {
        completion: NetworkTxCompletionId,
        backend: ContractObjectRef,
    },
    NetworkTxCompletionDuplicateGate {
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
    },
    NetworkTxCompletionDuplicateSequence {
        completion: NetworkTxCompletionId,
        tx_queue: PacketQueueObjectId,
        completion_sequence: u64,
    },
    NetworkTxCompletionMissingEvent {
        completion: NetworkTxCompletionId,
    },
    NetworkStackAdapterInvalid {
        adapter: NetworkStackAdapterId,
    },
    NetworkStackAdapterMissingPacketDevice {
        adapter: NetworkStackAdapterId,
        packet_device: PacketDeviceObjectId,
    },
    NetworkStackAdapterMissingBackend {
        adapter: NetworkStackAdapterId,
        backend: ContractObjectRef,
    },
    NetworkStackAdapterMissingQueue {
        adapter: NetworkStackAdapterId,
        packet_queue: PacketQueueObjectId,
    },
    NetworkStackAdapterDuplicatePacketDevice {
        adapter: NetworkStackAdapterId,
        packet_device: PacketDeviceObjectId,
    },
    NetworkStackAdapterMissingEvent {
        adapter: NetworkStackAdapterId,
    },
    SocketObjectInvalid {
        socket: SocketObjectId,
    },
    SocketObjectMissingAdapter {
        socket: SocketObjectId,
        adapter: NetworkStackAdapterId,
    },
    SocketObjectMissingOwnerStore {
        socket: SocketObjectId,
        store: StoreId,
    },
    SocketObjectDuplicate {
        socket: SocketObjectId,
    },
    SocketObjectMissingEvent {
        socket: SocketObjectId,
    },
    EndpointObjectInvalid {
        endpoint: EndpointObjectId,
    },
    EndpointObjectMissingSocket {
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
    },
    EndpointObjectMissingAdapter {
        endpoint: EndpointObjectId,
        adapter: NetworkStackAdapterId,
    },
    EndpointObjectMissingOwnerStore {
        endpoint: EndpointObjectId,
        store: StoreId,
    },
    EndpointObjectDuplicate {
        endpoint: EndpointObjectId,
    },
    EndpointObjectDuplicateSocket {
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
    },
    EndpointObjectMissingEvent {
        endpoint: EndpointObjectId,
    },
    SocketOperationInvalid {
        operation: SocketOperationId,
    },
    SocketOperationMissingEndpoint {
        operation: SocketOperationId,
        endpoint: EndpointObjectId,
    },
    SocketOperationMissingSocket {
        operation: SocketOperationId,
        socket: SocketObjectId,
    },
    SocketOperationMissingAdapter {
        operation: SocketOperationId,
        adapter: NetworkStackAdapterId,
    },
    SocketOperationMissingOwnerStore {
        operation: SocketOperationId,
        store: StoreId,
    },
    SocketOperationDuplicate {
        operation: SocketOperationId,
    },
    SocketOperationOrderingInvalid {
        operation: SocketOperationId,
    },
    SocketOperationMissingEvent {
        operation: SocketOperationId,
    },
    SocketWaitInvalid {
        socket_wait: SocketWaitId,
    },
    SocketWaitMissingWait {
        socket_wait: SocketWaitId,
        wait: WaitId,
    },
    SocketWaitMissingEndpoint {
        socket_wait: SocketWaitId,
        endpoint: EndpointObjectId,
    },
    SocketWaitMissingSocket {
        socket_wait: SocketWaitId,
        socket: SocketObjectId,
    },
    SocketWaitMissingAdapter {
        socket_wait: SocketWaitId,
        adapter: NetworkStackAdapterId,
    },
    SocketWaitMissingOwnerStore {
        socket_wait: SocketWaitId,
        store: StoreId,
    },
    SocketWaitMissingBlocker {
        socket_wait: SocketWaitId,
        blocker: ContractObjectRef,
    },
    SocketWaitDuplicateWait {
        socket_wait: SocketWaitId,
        wait: WaitId,
    },
    SocketWaitMissingEvent {
        socket_wait: SocketWaitId,
        event: EventId,
    },
    NetworkBackpressureInvalid {
        backpressure: NetworkBackpressureId,
    },
    NetworkBackpressureMissingAdapter {
        backpressure: NetworkBackpressureId,
        adapter: NetworkStackAdapterId,
    },
    NetworkBackpressureMissingPacketDevice {
        backpressure: NetworkBackpressureId,
        packet_device: PacketDeviceObjectId,
    },
    NetworkBackpressureMissingQueue {
        backpressure: NetworkBackpressureId,
        packet_queue: PacketQueueObjectId,
    },
    NetworkBackpressureMissingEndpoint {
        backpressure: NetworkBackpressureId,
        endpoint: EndpointObjectId,
    },
    NetworkBackpressureMissingSocket {
        backpressure: NetworkBackpressureId,
        socket: SocketObjectId,
    },
    NetworkBackpressureMissingOwnerStore {
        backpressure: NetworkBackpressureId,
        store: StoreId,
    },
    NetworkBackpressureDuplicateSequence {
        backpressure: NetworkBackpressureId,
        packet_queue: PacketQueueObjectId,
        sequence: u64,
    },
    NetworkBackpressureMissingEvent {
        backpressure: NetworkBackpressureId,
        event: EventId,
    },
    NetworkDriverCleanupInvalid {
        cleanup: NetworkDriverCleanupId,
    },
    NetworkDriverCleanupMissingIoCleanup {
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
    },
    NetworkDriverCleanupMissingAdapter {
        cleanup: NetworkDriverCleanupId,
        adapter: NetworkStackAdapterId,
    },
    NetworkDriverCleanupMissingPacketDevice {
        cleanup: NetworkDriverCleanupId,
        packet_device: PacketDeviceObjectId,
    },
    NetworkDriverCleanupMissingBackend {
        cleanup: NetworkDriverCleanupId,
        backend: ContractObjectRef,
    },
    NetworkDriverCleanupMissingEffectTarget {
        cleanup: NetworkDriverCleanupId,
        target: ContractObjectRef,
    },
    NetworkDriverCleanupLiveLeak {
        cleanup: NetworkDriverCleanupId,
    },
    NetworkDriverCleanupMissingEvent {
        cleanup: NetworkDriverCleanupId,
        event: EventId,
    },
    NetworkGenerationAuditInvalid {
        audit: NetworkGenerationAuditId,
    },
    NetworkGenerationAuditMissingTarget {
        audit: NetworkGenerationAuditId,
        target: ContractObjectRef,
    },
    NetworkGenerationAuditMissingEvent {
        audit: NetworkGenerationAuditId,
        event: EventId,
    },
    NetworkFaultInjectionInvalid {
        injection: NetworkFaultInjectionId,
    },
    NetworkFaultInjectionMissingTarget {
        injection: NetworkFaultInjectionId,
        target: ContractObjectRef,
    },
    NetworkFaultInjectionDuplicateSequence {
        injection: NetworkFaultInjectionId,
        packet_queue: PacketQueueObjectId,
        sequence: u64,
    },
    NetworkFaultInjectionMissingEvent {
        injection: NetworkFaultInjectionId,
        event: EventId,
    },
    NetworkBenchmarkInvalid {
        benchmark: NetworkBenchmarkId,
    },
    NetworkBenchmarkMissingTarget {
        benchmark: NetworkBenchmarkId,
        target: ContractObjectRef,
    },
    NetworkBenchmarkMetricMismatch {
        benchmark: NetworkBenchmarkId,
    },
    NetworkBenchmarkMissingEvent {
        benchmark: NetworkBenchmarkId,
        event: EventId,
    },
    NetworkRecoveryBenchmarkInvalid {
        benchmark: NetworkRecoveryBenchmarkId,
    },
    NetworkRecoveryBenchmarkMissingTarget {
        benchmark: NetworkRecoveryBenchmarkId,
        target: ContractObjectRef,
    },
    NetworkRecoveryBenchmarkMetricMismatch {
        benchmark: NetworkRecoveryBenchmarkId,
    },
    NetworkRecoveryBenchmarkMissingEvent {
        benchmark: NetworkRecoveryBenchmarkId,
        event: EventId,
    },
    BlockDeviceObjectInvalid {
        block_device: BlockDeviceObjectId,
    },
    BlockDeviceObjectMissingDevice {
        block_device: BlockDeviceObjectId,
        device: DeviceObjectId,
    },
    BlockDeviceObjectMissingEvent {
        block_device: BlockDeviceObjectId,
    },
    BlockRangeObjectInvalid {
        block_range: BlockRangeObjectId,
    },
    BlockRangeObjectMissingDevice {
        block_range: BlockRangeObjectId,
        block_device: BlockDeviceObjectId,
    },
    BlockRangeObjectMissingEvent {
        block_range: BlockRangeObjectId,
    },
    BlockRequestObjectInvalid {
        block_request: BlockRequestObjectId,
    },
    BlockRequestObjectMissingDevice {
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
    },
    BlockRequestObjectMissingRange {
        block_request: BlockRequestObjectId,
        block_range: BlockRangeObjectId,
    },
    BlockRequestObjectDuplicateSequence {
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
        sequence: u64,
    },
    BlockRequestObjectMissingEvent {
        block_request: BlockRequestObjectId,
    },
    BlockCompletionObjectInvalid {
        block_completion: BlockCompletionObjectId,
    },
    BlockCompletionObjectMissingRequest {
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
    },
    BlockCompletionObjectDuplicateRequest {
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
    },
    BlockCompletionObjectMissingEvent {
        block_completion: BlockCompletionObjectId,
    },
    BlockWaitInvalid {
        block_wait: BlockWaitId,
    },
    BlockWaitMissingWait {
        block_wait: BlockWaitId,
        wait: WaitId,
    },
    BlockWaitMissingRequest {
        block_wait: BlockWaitId,
        block_request: BlockRequestObjectId,
    },
    BlockWaitMissingCompletion {
        block_wait: BlockWaitId,
        block_completion: BlockCompletionObjectId,
    },
    BlockWaitDuplicateWait {
        block_wait: BlockWaitId,
        wait: WaitId,
    },
    BlockWaitMissingEvent {
        block_wait: BlockWaitId,
        event: EventId,
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
    ActivationResumeVectorStateInvalid {
        resume: ActivationResumeId,
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
