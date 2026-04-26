use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    HartRegistered {
        hart: HartId,
        hardware_id: u32,
        label: String,
        boot: bool,
        generation: Generation,
    },
    HartStateChanged {
        hart: HartId,
        from: HartState,
        to: HartState,
        reason: String,
        generation: Generation,
    },
    HartCurrentActivationBound {
        hart: HartId,
        from: HartState,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    HartCurrentActivationCleared {
        hart: HartId,
        activation: ActivationId,
        activation_generation: Generation,
        reason: String,
        generation: Generation,
    },
    TaskCreated {
        task: TaskId,
        frontend: FrontendKind,
    },
    TaskStateChanged {
        task: TaskId,
        from: TaskState,
        to: TaskState,
    },
    RuntimeActivationCreated {
        activation: ActivationId,
        task: TaskId,
        generation: Generation,
    },
    RuntimeActivationStateChanged {
        activation: ActivationId,
        from: RuntimeActivationState,
        to: RuntimeActivationState,
        generation: Generation,
    },
    RunnableQueueCreated {
        queue: RunnableQueueId,
        label: String,
        generation: Generation,
    },
    RunnableQueueOwnerBound {
        queue: RunnableQueueId,
        hart: HartId,
        hart_generation: Generation,
        generation: Generation,
        note: String,
    },
    RunnableQueued {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    RunnableDequeued {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    ActivationContextCreated {
        context: ActivationContextId,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    SavedContextCaptured {
        saved_context: SavedContextId,
        context: ActivationContextId,
        context_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        reason: SavedContextReason,
        generation: Generation,
    },
    TimerInterruptRecorded {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: HartId,
        hart_generation: Generation,
        hardware_hart: u32,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
        generation: Generation,
    },
    IpiEventRecorded {
        ipi: IpiEventId,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        kind: IpiEventKind,
        generation: Generation,
    },
    RemoteActivationPreempted {
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation_before: Generation,
        target_hart_generation_after: Generation,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    RemoteHartParked {
        remote_park: RemoteParkId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation_before: Generation,
        target_hart_generation_after: Generation,
        reason: String,
        generation: Generation,
    },
    RuntimeActivationPreempted {
        preemption: PreemptionId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    SchedulerDecisionRecorded {
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    CrossHartSchedulerDecisionRecorded {
        cross_decision: CrossHartSchedulerDecisionId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        deciding_hart: HartId,
        deciding_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    ActivationMigrated {
        migration: ActivationMigrationId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        source_queue: RunnableQueueId,
        source_queue_generation: Generation,
        target_queue: RunnableQueueId,
        target_queue_generation: Generation,
        generation: Generation,
    },
    SmpSafePointRecorded {
        safe_point: SmpSafePointId,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    StopTheWorldRendezvousCompleted {
        rendezvous: StopTheWorldRendezvousId,
        epoch: u64,
        safe_point: SmpSafePointId,
        safe_point_generation: Generation,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    SmpCodePublishBarrierValidated {
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        code_publish_epoch_before: u64,
        code_publish_epoch_after: u64,
        participant_count: u32,
        generation: Generation,
    },
    SmpCleanupQuiescenceValidated {
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
        cleanup_generation: Generation,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        participant_count: u32,
        generation: Generation,
    },
    SmpSnapshotBarrierValidated {
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        event_log_cursor: EventId,
        participant_count: u32,
        generation: Generation,
    },
    SmpStressRunRecorded {
        run: SmpStressRunId,
        scenario: String,
        iterations: u32,
        hart_count: u32,
        safe_point_count: u32,
        rendezvous_count: u32,
        property_failures: u32,
        generation: Generation,
    },
    SmpScalingBenchmarkRecorded {
        benchmark: SmpScalingBenchmarkId,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        hart_count: u32,
        workload_units: u64,
        measured_smp_nanos: u64,
        budget_nanos: u64,
        speedup_milli: u64,
        efficiency_milli: u64,
        generation: Generation,
    },
    DeviceObjectRecorded {
        device: DeviceObjectId,
        resource: ResourceId,
        resource_generation: Generation,
        class: String,
        backend: String,
        generation: Generation,
    },
    QueueObjectRecorded {
        queue: QueueObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        role: QueueObjectRole,
        queue_index: u16,
        depth: u32,
        generation: Generation,
    },
    DescriptorObjectRecorded {
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        queue_generation: Generation,
        slot: u16,
        access: DescriptorObjectAccess,
        length: u32,
        generation: Generation,
    },
    DmaBufferObjectRecorded {
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        access: DmaBufferObjectAccess,
        length: u32,
        generation: Generation,
    },
    MmioRegionObjectRecorded {
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        region_index: u16,
        offset: u64,
        length: u64,
        access: MmioRegionObjectAccess,
        generation: Generation,
    },
    IrqLineObjectRecorded {
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        irq_number: u32,
        trigger: IrqLineTrigger,
        polarity: IrqLinePolarity,
        generation: Generation,
    },
    IrqEventRecorded {
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        irq_line_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        irq_number: u32,
        sequence: u64,
        generation: Generation,
    },
    DeviceCapabilityRecorded {
        device_capability: DeviceCapabilityId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        target: ContractObjectRef,
        class: CapabilityClass,
        operation: String,
        capability: CapabilityId,
        capability_generation: Generation,
        handle_slot: u32,
        handle_generation: u32,
        generation: Generation,
    },
    DriverStoreBound {
        binding: DriverStoreBindingId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        generation: Generation,
    },
    IoWaitCreated {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        blocker: ContractObjectRef,
        generation: Generation,
    },
    IoWaitResolved {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        generation: Generation,
    },
    IoWaitCancelled {
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    RuntimeActivationResumed {
        resume: ActivationResumeId,
        decision: SchedulerDecisionId,
        decision_generation: Generation,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        queue: RunnableQueueId,
        queue_generation: Generation,
        generation: Generation,
    },
    PreemptionLatencySampleRecorded {
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
        measured_nanos: u64,
        budget_nanos: u64,
        generation: Generation,
    },
    RuntimeActivationWaitBlocked {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        wait: WaitId,
        wait_generation: Generation,
        generation: Generation,
    },
    RuntimeActivationWaitCancelled {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        from_generation: Generation,
        to_generation: Generation,
        wait: WaitId,
        wait_generation: Generation,
        reason: WaitCancelReason,
        generation: Generation,
    },
    RuntimeActivationCleanupStarted {
        cleanup: ActivationCleanupId,
        store: StoreId,
        store_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        generation: Generation,
    },
    RuntimeActivationCleanupCompleted {
        cleanup: ActivationCleanupId,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        activation: ActivationId,
        activation_generation_before: Generation,
        activation_generation_after: Generation,
        generation: Generation,
    },
    ResourceCreated {
        resource: ResourceId,
        kind: ResourceKind,
        generation: Generation,
    },
    ResourceClosed {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleValidated {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleRejected {
        resource: ResourceId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    AuthorityBound {
        authority: AuthorityId,
        resource: ResourceId,
        kind: AuthorityKind,
        subject: String,
        object: String,
        generation: Generation,
    },
    AuthorityReleased {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    AuthorityRevoked {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    BoundaryPublished {
        boundary: BoundaryId,
        name: String,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: String,
        blocked_by: Option<String>,
        generation: Generation,
    },
    ArtifactVerificationRecorded {
        artifact: ArtifactId,
        package: String,
        artifact_name: String,
        state: ArtifactVerificationState,
        manifest_binding_hash: String,
        blocked_by: Option<String>,
        generation: Generation,
    },
    WaitCreated {
        wait: WaitId,
        task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    },
    WaitPending {
        wait: WaitId,
        generation: Generation,
    },
    WaitResolved {
        wait: WaitId,
        reason: String,
    },
    WaitConsumed {
        wait: WaitId,
    },
    WaitCancelled {
        wait: WaitId,
        errno: i32,
        reason: WaitCancelReason,
    },
    WaitInterrupted {
        wait: WaitId,
        reason: WaitCancelReason,
    },
    WaitRestarted {
        wait: WaitId,
        class: String,
    },
    WaitTokenValidated {
        wait: WaitId,
        generation: Generation,
    },
    WaitTokenRejected {
        wait: WaitId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    CapabilityGranted {
        cap: CapabilityId,
    },
    CapabilityRevoked {
        cap: CapabilityId,
    },
    CapabilityUsed {
        cap: CapabilityId,
        subject: String,
        object: String,
        operation: String,
        generation: Generation,
    },
    CapabilityDenied {
        subject: String,
        object: String,
        operation: String,
        reason: CapabilityDenyReason,
    },
    CapabilityGenerationMismatch {
        subject: String,
        object: String,
        operation: String,
        expected: Generation,
        actual: Option<Generation>,
    },
    HostcallEntered {
        label: String,
        class: HostcallClass,
        subject: String,
        object: String,
        operation: String,
    },
    SubstrateUnsupported {
        authority: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    },
    SubstrateCapabilityDenied {
        authority: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
        capability: Option<CapabilityId>,
        capability_generation: Option<Generation>,
    },
    InterfaceUnsupported {
        interface_kind: String,
        interface: String,
        operation: String,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    },
    FaultDomainRegistered {
        domain: FaultDomainId,
    },
    FaultDomainStateChanged {
        domain: FaultDomainId,
        from: FaultDomainState,
        to: FaultDomainState,
        generation: Generation,
    },
    FaultClassified {
        trap: TrapClass,
        class: FaultClass,
        store: Option<StoreId>,
        task: Option<TaskId>,
        detail: String,
    },
    DriverTrap {
        domain: Option<FaultDomainId>,
        trap: TrapClass,
        detail: String,
    },
    PacketReceived {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    PacketTransmitted {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    NetInterfaceStateChanged {
        interface: ResourceId,
        up: bool,
    },
    SocketStateChanged {
        socket: ResourceId,
        state: String,
    },
    DeviceIrqDelivered {
        irq: ResourceId,
        device: ResourceId,
        cause: String,
    },
    DriverCompletion {
        device: ResourceId,
        operation: String,
    },
    DmaSubmitted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    DmaCompleted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    FaultDomainRestarted {
        domain: FaultDomainId,
    },
    StoreRegistered {
        store: StoreId,
        domain: FaultDomainId,
        resource: ResourceId,
        generation: Generation,
    },
    StoreStateChanged {
        store: StoreId,
        from: StoreState,
        to: StoreState,
        generation: Generation,
    },
    StoreExecutorTransition {
        store: StoreId,
        from: String,
        to: String,
        blocked_by: Option<String>,
        hostcall_table: String,
        trap_surface: String,
    },
    StoreActivationRecorded {
        activation: StoreActivationId,
        store: StoreId,
        package: String,
        code_publish_state: CodePublishState,
        memory_layout_state: MemoryLayoutState,
        hostcall_table_state: HostcallLinkState,
        trap_surface_state: TrapSurfaceState,
        entrypoint_state: EntrypointState,
        blocked_by: Option<String>,
        generation: Generation,
    },
    StoreActivationHandleValidated {
        store: StoreId,
        generation: Generation,
    },
    StoreActivationHandleRejected {
        store: StoreId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    StoreTrap {
        store: StoreId,
        trap: TrapClass,
        detail: String,
    },
    StoreDropped {
        store: StoreId,
        generation: Generation,
        resource: Option<ResourceId>,
    },
    StoreRebound {
        store: StoreId,
        generation: Generation,
        resource: ResourceId,
    },
    WindowLeaseCreated {
        lease: ResourceId,
        generation: Generation,
    },
    WindowLeaseDestroyed {
        lease: ResourceId,
        generation: Generation,
    },
    SnapshotBarrierEnter {
        barrier: u64,
    },
    SnapshotBarrierExit {
        barrier: u64,
    },
    FastPathPlanInstalled {
        plan: u64,
    },
    FastPathPlanInvalidated {
        plan: u64,
    },
    TransactionBegan {
        transaction: TransactionId,
        store: Option<StoreId>,
        task: Option<TaskId>,
        label: String,
    },
    TransactionCommitted {
        transaction: TransactionId,
        generation: Generation,
    },
    TransactionRolledBack {
        transaction: TransactionId,
        reason: String,
        generation: Generation,
    },
    CleanupStepApplied {
        cleanup: TransactionId,
        step: String,
        target: String,
        observed_generation: Generation,
    },
    FailureEffect {
        effect: FailureEffect,
    },
}

impl EventKind {
    pub fn summary(&self) -> String {
        match self {
            Self::HartRegistered {
                hart,
                hardware_id,
                label,
                boot,
                generation,
            } => format!(
                "HartRegistered hart={hart} hardware_id={hardware_id} label={label} boot={boot} generation={generation}"
            ),
            Self::HartStateChanged {
                hart,
                from,
                to,
                reason,
                generation,
            } => format!(
                "HartStateChanged hart={hart} from={} to={} reason={reason} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::HartCurrentActivationBound {
                hart,
                from,
                activation,
                activation_generation,
                generation,
            } => format!(
                "HartCurrentActivationBound hart={hart} from={} activation={activation}@{activation_generation} generation={generation}",
                from.as_str()
            ),
            Self::HartCurrentActivationCleared {
                hart,
                activation,
                activation_generation,
                reason,
                generation,
            } => format!(
                "HartCurrentActivationCleared hart={hart} activation={activation}@{activation_generation} reason={reason} generation={generation}"
            ),
            Self::TaskCreated { task, frontend } => {
                format!("TaskCreated task={task} frontend={}", frontend.as_str())
            }
            Self::TaskStateChanged { task, from, to } => {
                format!(
                    "TaskStateChanged task={task} {}->{}",
                    from.as_str(),
                    to.as_str()
                )
            }
            Self::RuntimeActivationCreated {
                activation,
                task,
                generation,
            } => format!(
                "RuntimeActivationCreated activation={activation} task={task} generation={generation}"
            ),
            Self::RuntimeActivationStateChanged {
                activation,
                from,
                to,
                generation,
            } => format!(
                "RuntimeActivationStateChanged activation={activation} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::RunnableQueueCreated {
                queue,
                label,
                generation,
            } => {
                format!("RunnableQueueCreated queue={queue} label={label} generation={generation}")
            }
            Self::RunnableQueueOwnerBound {
                queue,
                hart,
                hart_generation,
                generation,
                note,
            } => format!(
                "RunnableQueueOwnerBound queue={queue} hart={hart}@{hart_generation} generation={generation} note={note}"
            ),
            Self::RunnableQueued {
                queue,
                activation,
                activation_generation,
            } => format!(
                "RunnableQueued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::RunnableDequeued {
                queue,
                activation,
                activation_generation,
            } => format!(
                "RunnableDequeued queue={queue} activation={activation}@{activation_generation}"
            ),
            Self::ActivationContextCreated {
                context,
                activation,
                activation_generation,
                generation,
            } => format!(
                "ActivationContextCreated context={context} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::SavedContextCaptured {
                saved_context,
                context,
                context_generation,
                activation,
                activation_generation,
                reason,
                generation,
            } => format!(
                "SavedContextCaptured saved_context={saved_context} context={context}@{context_generation} activation={activation}@{activation_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::TimerInterruptRecorded {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                hardware_hart,
                target_activation,
                target_activation_generation,
                generation,
            } => format!(
                "TimerInterruptRecorded interrupt={interrupt} epoch={timer_epoch} hart={hart}@{hart_generation} hardware_id={hardware_hart} target={}@{} generation={generation}",
                target_activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                target_activation_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            Self::IpiEventRecorded {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                kind,
                generation,
            } => format!(
                "IpiEventRecorded ipi={ipi} kind={} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} generation={generation}",
                kind.as_str()
            ),
            Self::RemoteActivationPreempted {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before,
                target_hart_generation_after,
                activation,
                from_generation,
                to_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RemoteActivationPreempted remote_preempt={remote_preempt} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
            ),
            Self::RemoteHartParked {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before,
                target_hart_generation_after,
                reason,
                generation,
            } => format!(
                "RemoteHartParked remote_park={remote_park} ipi={ipi}@{ipi_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation_before}->{target_hart_generation_after} reason={reason} generation={generation}"
            ),
            Self::RuntimeActivationPreempted {
                preemption,
                activation,
                from_generation,
                to_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RuntimeActivationPreempted preemption={preemption} activation={activation}@{from_generation}->{to_generation} timer={timer_interrupt}@{timer_interrupt_generation} queue={queue}@{queue_generation} generation={generation}",
            ),
            Self::SchedulerDecisionRecorded {
                decision,
                queue,
                queue_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "SchedulerDecisionRecorded decision={decision} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::CrossHartSchedulerDecisionRecorded {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                queue,
                queue_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "CrossHartSchedulerDecisionRecorded cross_decision={cross_decision} decision={scheduler_decision}@{scheduler_decision_generation} deciding_hart={deciding_hart}@{deciding_hart_generation} target_hart={target_hart}@{target_hart_generation} queue={queue}@{queue_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::ActivationMigrated {
                migration,
                activation,
                from_generation,
                to_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                generation,
            } => format!(
                "ActivationMigrated migration={migration} activation={activation}@{from_generation}->{to_generation} source_hart={source_hart}@{source_hart_generation} target_hart={target_hart}@{target_hart_generation} source_queue={source_queue}@{source_queue_generation} target_queue={target_queue}@{target_queue_generation} generation={generation}"
            ),
            Self::SmpSafePointRecorded {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count,
                generation,
            } => format!(
                "SmpSafePointRecorded safe_point={safe_point} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
            ),
            Self::StopTheWorldRendezvousCompleted {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count,
                generation,
            } => format!(
                "StopTheWorldRendezvousCompleted rendezvous={rendezvous} epoch={epoch} safe_point={safe_point}@{safe_point_generation} coordinator_hart={coordinator_hart}@{coordinator_hart_generation} participants={participant_count} generation={generation}"
            ),
            Self::SmpCodePublishBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                participant_count,
                generation,
            } => format!(
                "SmpCodePublishBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} code_publish_epoch={code_publish_epoch_before}->{code_publish_epoch_after} participants={participant_count} generation={generation}"
            ),
            Self::SmpCleanupQuiescenceValidated {
                quiescence,
                cleanup,
                cleanup_generation,
                store,
                target_store_generation,
                result_store_generation,
                rendezvous,
                rendezvous_generation,
                participant_count,
                generation,
            } => format!(
                "SmpCleanupQuiescenceValidated quiescence={quiescence} cleanup={cleanup}@{cleanup_generation} store={store}@{target_store_generation}->{result_store_generation} rendezvous={rendezvous}@{rendezvous_generation} participants={participant_count} generation={generation}"
            ),
            Self::SmpSnapshotBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                event_log_cursor,
                participant_count,
                generation,
            } => format!(
                "SmpSnapshotBarrierValidated barrier={barrier} rendezvous={rendezvous}@{rendezvous_generation} cursor={event_log_cursor} participants={participant_count} generation={generation}"
            ),
            Self::SmpStressRunRecorded {
                run,
                scenario,
                iterations,
                hart_count,
                safe_point_count,
                rendezvous_count,
                property_failures,
                generation,
            } => format!(
                "SmpStressRunRecorded run={run} scenario={scenario} iterations={iterations} harts={hart_count} safe_points={safe_point_count} rendezvous={rendezvous_count} property_failures={property_failures} generation={generation}"
            ),
            Self::SmpScalingBenchmarkRecorded {
                benchmark,
                stress_run,
                stress_run_generation,
                hart_count,
                workload_units,
                measured_smp_nanos,
                budget_nanos,
                speedup_milli,
                efficiency_milli,
                generation,
            } => format!(
                "SmpScalingBenchmarkRecorded benchmark={benchmark} stress_run={stress_run}@{stress_run_generation} harts={hart_count} workload_units={workload_units} measured_nanos={measured_smp_nanos} budget_nanos={budget_nanos} speedup_milli={speedup_milli} efficiency_milli={efficiency_milli} generation={generation}"
            ),
            Self::DeviceObjectRecorded {
                device,
                resource,
                resource_generation,
                class,
                backend,
                generation,
            } => format!(
                "DeviceObjectRecorded device={device} resource={resource}@{resource_generation} class={class} backend={backend} generation={generation}"
            ),
            Self::QueueObjectRecorded {
                queue,
                device,
                device_generation,
                role,
                queue_index,
                depth,
                generation,
            } => format!(
                "QueueObjectRecorded queue={queue} device={device}@{device_generation} role={} index={queue_index} depth={depth} generation={generation}",
                role.as_str()
            ),
            Self::DescriptorObjectRecorded {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                generation,
            } => format!(
                "DescriptorObjectRecorded descriptor={descriptor} queue={queue}@{queue_generation} slot={slot} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::DmaBufferObjectRecorded {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                generation,
            } => format!(
                "DmaBufferObjectRecorded dma_buffer={dma_buffer} descriptor={descriptor}@{descriptor_generation} resource={resource}@{resource_generation} access={} length={length} generation={generation}",
                access.as_str()
            ),
            Self::MmioRegionObjectRecorded {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                generation,
            } => format!(
                "MmioRegionObjectRecorded mmio_region={mmio_region} device={device}@{device_generation} resource={resource}@{resource_generation} index={region_index} offset={offset} length={length} access={} generation={generation}",
                access.as_str()
            ),
            Self::IrqLineObjectRecorded {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                generation,
            } => format!(
                "IrqLineObjectRecorded irq_line={irq_line} device={device}@{device_generation} resource={resource}@{resource_generation} irq_number={irq_number} trigger={} polarity={} generation={generation}",
                trigger.as_str(),
                polarity.as_str()
            ),
            Self::IrqEventRecorded {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                irq_number,
                sequence,
                generation,
            } => format!(
                "IrqEventRecorded irq_event={irq_event} irq_line={irq_line}@{irq_line_generation} device={device}@{device_generation} driver_store={driver_store}@{driver_store_generation} irq_number={irq_number} sequence={sequence} generation={generation}"
            ),
            Self::DeviceCapabilityRecorded {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                capability,
                capability_generation,
                handle_slot,
                handle_generation,
                generation,
            } => format!(
                "DeviceCapabilityRecorded device_capability={device_capability} driver_store={driver_store}@{driver_store_generation} target={} class={} operation={operation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} generation={generation}",
                target.summary(),
                class.as_str()
            ),
            Self::DriverStoreBound {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                generation,
            } => format!(
                "DriverStoreBound binding={binding} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} generation={generation}"
            ),
            Self::IoWaitCreated {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                generation,
            } => format!(
                "IoWaitCreated io_wait={io_wait} wait={wait}@{wait_generation} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} blocker={} generation={generation}",
                blocker.summary()
            ),
            Self::IoWaitResolved {
                io_wait,
                wait,
                wait_generation,
                irq_event,
                irq_event_generation,
                generation,
            } => format!(
                "IoWaitResolved io_wait={io_wait} wait={wait}@{wait_generation} irq_event={irq_event}@{irq_event_generation} generation={generation}"
            ),
            Self::IoWaitCancelled {
                io_wait,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "IoWaitCancelled io_wait={io_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::RuntimeActivationResumed {
                resume,
                decision,
                decision_generation,
                activation,
                from_generation,
                to_generation,
                queue,
                queue_generation,
                generation,
            } => format!(
                "RuntimeActivationResumed resume={resume} decision={decision}@{decision_generation} activation={activation}@{from_generation}->{to_generation} queue={queue}@{queue_generation} generation={generation}"
            ),
            Self::PreemptionLatencySampleRecorded {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                generation,
            } => format!(
                "PreemptionLatencySampleRecorded sample={sample} timer={timer_interrupt}@{timer_interrupt_generation} preemption={preemption}@{preemption_generation} decision={scheduler_decision}@{scheduler_decision_generation} resume={activation_resume}@{activation_resume_generation} measured_nanos={measured_nanos} budget_nanos={budget_nanos} generation={generation}"
            ),
            Self::RuntimeActivationWaitBlocked {
                activation_wait,
                activation,
                from_generation,
                to_generation,
                wait,
                wait_generation,
                generation,
            } => format!(
                "RuntimeActivationWaitBlocked activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} generation={generation}"
            ),
            Self::RuntimeActivationWaitCancelled {
                activation_wait,
                activation,
                from_generation,
                to_generation,
                wait,
                wait_generation,
                reason,
                generation,
            } => format!(
                "RuntimeActivationWaitCancelled activation_wait={activation_wait} activation={activation}@{from_generation}->{to_generation} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            ),
            Self::RuntimeActivationCleanupStarted {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                generation,
            } => format!(
                "RuntimeActivationCleanupStarted cleanup={cleanup} store={store}@{store_generation} activation={activation}@{activation_generation} generation={generation}"
            ),
            Self::RuntimeActivationCleanupCompleted {
                cleanup,
                store,
                target_store_generation,
                result_store_generation,
                activation,
                activation_generation_before,
                activation_generation_after,
                generation,
            } => format!(
                "RuntimeActivationCleanupCompleted cleanup={cleanup} store={store}@{target_store_generation}->{result_store_generation} activation={activation}@{activation_generation_before}->{activation_generation_after} generation={generation}"
            ),
            Self::ResourceCreated {
                resource,
                kind,
                generation,
            } => format!(
                "ResourceCreated resource={resource} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::ResourceClosed {
                resource,
                generation,
            } => format!("ResourceClosed resource={resource} generation={generation}"),
            Self::ResourceHandleValidated {
                resource,
                generation,
            } => format!("ResourceHandleValidated resource={resource} generation={generation}"),
            Self::ResourceHandleRejected {
                resource,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::AuthorityBound {
                authority,
                resource,
                kind,
                subject,
                object,
                generation,
            } => format!(
                "AuthorityBound authority={authority} resource={resource} kind={} subject={subject} object={object} generation={generation}",
                kind.as_str()
            ),
            Self::AuthorityReleased {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityReleased authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::AuthorityRevoked {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityRevoked authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::BoundaryPublished {
                boundary,
                name,
                kind,
                status,
                backend,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "BoundaryPublished boundary={boundary} name={name} kind={} status={} backend={backend} blocked={blocked_by} generation={generation}",
                    kind.as_str(),
                    status.as_str()
                )
            }
            Self::ArtifactVerificationRecorded {
                artifact,
                package,
                artifact_name,
                state,
                manifest_binding_hash,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "ArtifactVerificationRecorded artifact={artifact} package={package} name={artifact_name} state={} binding={manifest_binding_hash} blocked={blocked_by} generation={generation}",
                    state.as_str()
                )
            }
            Self::WaitCreated {
                wait,
                task,
                kind,
                generation,
            } => format!(
                "WaitCreated wait={wait} task={task} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::WaitPending { wait, generation } => {
                format!("WaitPending wait={wait} generation={generation}")
            }
            Self::WaitResolved { wait, reason } => {
                format!("WaitResolved wait={wait} reason={reason}")
            }
            Self::WaitConsumed { wait } => {
                format!("WaitConsumed wait={wait}")
            }
            Self::WaitCancelled {
                wait,
                errno,
                reason,
            } => {
                format!(
                    "WaitCancelled wait={wait} errno={errno} reason={}",
                    reason.as_str()
                )
            }
            Self::WaitInterrupted { wait, reason } => {
                format!("WaitInterrupted wait={wait} reason={}", reason.as_str())
            }
            Self::WaitRestarted { wait, class } => {
                format!("WaitRestarted wait={wait} class={class}")
            }
            Self::WaitTokenValidated { wait, generation } => {
                format!("WaitTokenValidated wait={wait} generation={generation}")
            }
            Self::WaitTokenRejected {
                wait,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
            Self::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
            Self::CapabilityUsed {
                cap,
                subject,
                object,
                operation,
                generation,
            } => format!(
                "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
            ),
            Self::CapabilityDenied {
                subject,
                object,
                operation,
                reason,
            } => format!(
                "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
                reason.as_str()
            ),
            Self::CapabilityGenerationMismatch {
                subject,
                object,
                operation,
                expected,
                actual,
            } => match actual {
                Some(actual) => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
                ),
                None => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
                ),
            },
            Self::HostcallEntered {
                label,
                class,
                subject,
                object,
                operation,
            } => format!(
                "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
                class.as_str()
            ),
            Self::SubstrateUnsupported {
                authority,
                operation,
                requester,
                artifact,
                store,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstrateUnsupported authority={authority} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::SubstrateCapabilityDenied {
                authority,
                operation,
                requester,
                artifact,
                store,
                capability,
                capability_generation,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let capability = capability
                    .map(|capability| capability.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let generation = capability_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "SubstrateCapabilityDenied authority={authority} op={operation} requester={requester} artifact={artifact} store={store} capability={capability} generation={generation}"
                )
            }
            Self::InterfaceUnsupported {
                interface_kind,
                interface,
                operation,
                requester,
                artifact,
                store,
            } => {
                let requester = requester.as_deref().unwrap_or("none");
                let artifact = artifact
                    .map(|artifact| artifact.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "InterfaceUnsupported kind={interface_kind} interface={interface} op={operation} requester={requester} artifact={artifact} store={store}"
                )
            }
            Self::FaultDomainRegistered { domain } => {
                format!("FaultDomainRegistered domain={domain}")
            }
            Self::FaultDomainStateChanged {
                domain,
                from,
                to,
                generation,
            } => format!(
                "FaultDomainStateChanged domain={domain} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::FaultClassified {
                trap,
                class,
                store,
                task,
                detail,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "FaultClassified trap={} class={} store={store} task={task} detail={detail}",
                    trap.as_str(),
                    class.as_str()
                )
            }
            Self::DriverTrap {
                domain,
                trap,
                detail,
            } => match domain {
                Some(domain) => format!(
                    "DriverTrap domain={domain} trap={} detail={detail}",
                    trap.as_str()
                ),
                None => format!("DriverTrap trap={} detail={detail}", trap.as_str()),
            },
            Self::PacketReceived {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketReceived interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::PacketTransmitted {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketTransmitted interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::NetInterfaceStateChanged { interface, up } => {
                let state = if *up { "up" } else { "down" };
                format!("NetInterfaceStateChanged interface={interface} state={state}")
            }
            Self::SocketStateChanged { socket, state } => {
                format!("SocketStateChanged socket={socket} state={state}")
            }
            Self::DeviceIrqDelivered { irq, device, cause } => {
                format!("DeviceIrqDelivered irq={irq} device={device} cause={cause}")
            }
            Self::DriverCompletion { device, operation } => {
                format!("DriverCompletion device={device} operation={operation}")
            }
            Self::DmaSubmitted {
                buffer,
                device,
                len,
            } => format!("DmaSubmitted buffer={buffer} device={device} len={len}"),
            Self::DmaCompleted {
                buffer,
                device,
                len,
            } => format!("DmaCompleted buffer={buffer} device={device} len={len}"),
            Self::FaultDomainRestarted { domain } => {
                format!("FaultDomainRestarted domain={domain}")
            }
            Self::StoreRegistered {
                store,
                domain,
                resource,
                generation,
            } => format!(
                "StoreRegistered store={store} domain={domain} resource={resource} generation={generation}"
            ),
            Self::StoreStateChanged {
                store,
                from,
                to,
                generation,
            } => format!(
                "StoreStateChanged store={store} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::StoreExecutorTransition {
                store,
                from,
                to,
                blocked_by,
                hostcall_table,
                trap_surface,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "StoreExecutorTransition store={store} {from}->{to} blocked={blocked_by} hostcalls={hostcall_table} traps={trap_surface}"
                )
            }
            Self::StoreActivationRecorded {
                activation,
                store,
                package,
                code_publish_state,
                memory_layout_state,
                hostcall_table_state,
                trap_surface_state,
                entrypoint_state,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "StoreActivationRecorded activation={activation} store={store} package={package} code={} memory={} hostcalls={} traps={} entry={} blocked={blocked_by} generation={generation}",
                    code_publish_state.as_str(),
                    memory_layout_state.as_str(),
                    hostcall_table_state.as_str(),
                    trap_surface_state.as_str(),
                    entrypoint_state.as_str()
                )
            }
            Self::StoreActivationHandleValidated { store, generation } => {
                format!("StoreActivationHandleValidated store={store} generation={generation}")
            }
            Self::StoreActivationHandleRejected {
                store,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "StoreActivationHandleRejected store={store} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::StoreTrap {
                store,
                trap,
                detail,
            } => {
                format!(
                    "StoreTrap store={store} trap={} detail={detail}",
                    trap.as_str()
                )
            }
            Self::StoreDropped {
                store,
                generation,
                resource,
            } => match resource {
                Some(resource) => format!(
                    "StoreDropped store={store} generation={generation} resource={resource}"
                ),
                None => format!("StoreDropped store={store} generation={generation}"),
            },
            Self::StoreRebound {
                store,
                generation,
                resource,
            } => format!("StoreRebound store={store} generation={generation} resource={resource}"),
            Self::WindowLeaseCreated { lease, generation } => {
                format!("WindowLeaseCreated lease={lease} generation={generation}")
            }
            Self::WindowLeaseDestroyed { lease, generation } => {
                format!("WindowLeaseDestroyed lease={lease} generation={generation}")
            }
            Self::SnapshotBarrierEnter { barrier } => {
                format!("SnapshotBarrierEnter barrier={barrier}")
            }
            Self::SnapshotBarrierExit { barrier } => {
                format!("SnapshotBarrierExit barrier={barrier}")
            }
            Self::FastPathPlanInstalled { plan } => {
                format!("FastPathPlanInstalled plan={plan}")
            }
            Self::FastPathPlanInvalidated { plan } => {
                format!("FastPathPlanInvalidated plan={plan}")
            }
            Self::TransactionBegan {
                transaction,
                store,
                task,
                label,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "TransactionBegan transaction={transaction} store={store} task={task} label={label}"
                )
            }
            Self::TransactionCommitted {
                transaction,
                generation,
            } => {
                format!("TransactionCommitted transaction={transaction} generation={generation}")
            }
            Self::TransactionRolledBack {
                transaction,
                reason,
                generation,
            } => {
                format!(
                    "TransactionRolledBack transaction={transaction} reason={reason} generation={generation}"
                )
            }
            Self::CleanupStepApplied {
                cleanup,
                step,
                target,
                observed_generation,
            } => {
                format!(
                    "CleanupStepApplied cleanup={cleanup} step={step} target={target} observed_generation={observed_generation}"
                )
            }
            Self::FailureEffect { effect } => {
                format!("FailureEffect {}", effect.summary())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub epoch: u64,
    pub source: String,
    pub causal_parent: Option<EventId>,
    pub kind: EventKind,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        format!(
            "#{} epoch={} source={} {}",
            self.id,
            self.epoch,
            self.source,
            self.kind.summary()
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventLog {
    next_id: EventId,
    epoch: u64,
    runtime_mode: RuntimeMode,
    pub(crate) events: Vec<EventRecord>,
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode: RuntimeMode::Research,
            events: Vec::new(),
        }
    }

    pub const fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode,
            events: Vec::new(),
        }
    }

    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }

    pub fn push(&mut self, source: &str, kind: EventKind) -> EventId {
        let id = self.next_id;
        self.next_id += 1;
        self.epoch += 1;
        self.events.push(EventRecord {
            id,
            epoch: self.epoch,
            source: source.to_string(),
            causal_parent: None,
            kind,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn cursor(&self) -> EventId {
        self.next_id.saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn tail(&self, count: usize) -> &[EventRecord] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}
