use super::super::*;

pub(crate) fn record_simd_runtime_v0_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let feature_set = semantic.apply_envelope(CommandEnvelope::new(
        333,
        "target-executor-v0",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_000,
            name: "riscv64-qemu-virt-research-target".to_owned(),
            discovery_source: "target-runtime-default-profile".to_owned(),
            target_profile: "riscv64-qemu-virt-research".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64imac".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "default profile does not declare RVV/SIMD".to_owned(),
            note: "v0-record-default-target-feature-set".to_owned(),
        },
    ));
    if feature_set.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v0 feature set command {} ({}) failed: status={} violations={:?}",
            feature_set.command_id,
            feature_set.command,
            feature_set.status.as_str(),
            feature_set.violations
        )
        .into());
    }

    let bad_supported_shape = semantic.apply_envelope(CommandEnvelope::new(
        334,
        "target-executor-v0",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_001,
            name: "bad-supported-simd-discovery".to_owned(),
            discovery_source: "target-runtime-default-profile".to_owned(),
            target_profile: "riscv64-qemu-virt-research".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64imac".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: true,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_owned(),
            note: "v0-reject-supported-simd-without-vector-shape".to_owned(),
        },
    ));
    if bad_supported_shape.status != CommandStatus::Rejected
        || !bad_supported_shape
            .violations
            .iter()
            .any(|violation| violation.contains("vector register shape"))
    {
        return Err(format!(
            "simd runtime v0 bad supported shape command {} ({}) was not rejected: status={} violations={:?}",
            bad_supported_shape.command_id,
            bad_supported_shape.command,
            bad_supported_shape.status.as_str(),
            bad_supported_shape.violations
        )
        .into());
    }

    let bad_unsupported_reason = semantic.apply_envelope(CommandEnvelope::new(
        335,
        "target-executor-v0",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_001,
            name: "bad-unsupported-simd-discovery".to_owned(),
            discovery_source: "target-runtime-default-profile".to_owned(),
            target_profile: "riscv64-qemu-virt-research".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64imac".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_owned(),
            note: "v0-reject-unsupported-simd-without-reason".to_owned(),
        },
    ));
    if bad_unsupported_reason.status != CommandStatus::Rejected
        || !bad_unsupported_reason
            .violations
            .iter()
            .any(|violation| violation.contains("requires a reason"))
    {
        return Err(format!(
            "simd runtime v0 bad unsupported reason command {} ({}) was not rejected: status={} violations={:?}",
            bad_unsupported_reason.command_id,
            bad_unsupported_reason.command,
            bad_unsupported_reason.status.as_str(),
            bad_unsupported_reason.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_substrate_conformance_evidence(semantic: &mut SemanticGraph) {
    record_substrate_event(
        semantic,
        SubstrateEvent::unsupported(
            "DmaAuthority",
            "dma_alloc",
            Some(SubstrateRequester::new("target-executor-substrate-probe")),
        ),
    );
}

pub(crate) fn record_command_surface_evidence(semantic: &mut SemanticGraph) {
    let command = CommandEnvelope::new(
        1,
        "target-executor-command-probe",
        SemanticCommand::CreateWait {
            wait: 9000,
            owner_task: None,
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Timer,
            generation: 1,
            blockers: Vec::new(),
            deadline: None,
            restart_policy: RestartPolicy::Never,
            saved_context: None,
        },
    );
    let _ = semantic.apply_envelope(command);
}

pub(crate) fn record_preemptive_runtime_context_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    semantic.ensure_task(9001, FrontendKind::LinuxElf, "p0-preemptive-demo-task");
    semantic.ensure_task(9002, FrontendKind::LinuxElf, "p2-timer-demo-task");
    semantic.ensure_task(9003, FrontendKind::LinuxElf, "p8-cleanup-demo-task");
    semantic.ensure_task(9004, FrontendKind::LinuxElf, "s6-remote-preempt-task");
    let cleanup_store = semantic.register_store(
        "p8.cleanup.driver",
        "p8-cleanup-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(cleanup_store, StoreState::Running);
    let cleanup_store_generation = semantic
        .store_handle(cleanup_store)
        .map(|handle| handle.generation)
        .ok_or("p8 cleanup store handle is missing")?;
    let io_device_resource =
        semantic.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let io_device_resource_generation = semantic
        .resource_handle(io_device_resource)
        .map(|handle| handle.generation)
        .ok_or("i0 device resource handle is missing")?;
    let io_dma_buffer_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let io_dma_buffer_resource_generation = semantic
        .resource_handle(io_dma_buffer_resource)
        .map(|handle| handle.generation)
        .ok_or("i3 dma buffer resource handle is missing")?;
    let io_mmio_region_resource =
        semantic.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let io_mmio_region_resource_generation = semantic
        .resource_handle(io_mmio_region_resource)
        .map(|handle| handle.generation)
        .ok_or("i4 mmio region resource handle is missing")?;
    let io_irq_line_resource =
        semantic.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let io_irq_line_resource_generation = semantic
        .resource_handle(io_irq_line_resource)
        .map(|handle| handle.generation)
        .ok_or("i5 irq line resource handle is missing")?;
    let packet_device_resource =
        semantic.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let packet_device_resource_generation = semantic
        .resource_handle(packet_device_resource)
        .map(|handle| handle.generation)
        .ok_or("n0 packet device resource handle is missing")?;
    let io_driver_store =
        semantic.register_store("i6.irq.driver", "i6-irq-driver.fake-aot", "driver", "restartable");
    semantic.set_store_state(io_driver_store, StoreState::Running);
    let io_driver_store_generation = semantic
        .store_handle(io_driver_store)
        .map(|handle| handle.generation)
        .ok_or("i6 driver store handle is missing")?;
    // The P8 cleanup command moves the store through Cleaning and Dead, bumping
    // the semantic generation once for each transition before S13 validates it.
    let cleanup_result_store_generation = cleanup_store_generation + 2;
    let commands = [
        CommandEnvelope::new(
            1,
            "target-executor-s0",
            SemanticCommand::RegisterHart {
                hart: 1,
                hardware_id: 0,
                label: "boot-hart0".to_owned(),
                boot: true,
                note: "s0-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            2,
            "target-executor-s0",
            SemanticCommand::SetHartState {
                hart: 1,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "scheduler-ready".to_owned(),
                note: "s0-hart-state-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            3,
            "target-executor-s4",
            SemanticCommand::RegisterHart {
                hart: 2,
                hardware_id: 1,
                label: "secondary-hart1".to_owned(),
                boot: false,
                note: "s4-secondary-hart-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            4,
            "target-executor-s4",
            SemanticCommand::SetHartState {
                hart: 2,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "secondary-scheduler-ready".to_owned(),
                note: "s4-secondary-hart-idle-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            5,
            "target-executor-s5",
            SemanticCommand::RecordIpiEvent {
                ipi: 9001,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 2,
                kind: IpiEventKind::SchedulerKick,
                reason: "s5-scheduler-kick".to_owned(),
                note: "s5-ipi-event-model-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            6,
            "target-executor-s6",
            SemanticCommand::CreateRunnableQueue {
                queue: 9004,
                label: "remote-preempt-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            7,
            "target-executor-s6",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9004,
                queue_generation: 1,
                hart: 2,
                hart_generation: 2,
                note: "s6-target-queue-owned-by-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            8,
            "target-executor-s6",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9004,
                owner_task: 9004,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            9,
            "target-executor-s6",
            SemanticCommand::EnqueueRunnable {
                queue: 9004,
                activation: 9004,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            9_001,
            "target-executor-s6",
            SemanticCommand::DequeueRunnable { queue: 9004, activation: 9004 },
        ),
        CommandEnvelope::new(
            9_002,
            "target-executor-s6",
            SemanticCommand::BindHartCurrentActivation {
                hart: 2,
                hart_generation: 2,
                activation: 9004,
                activation_generation: 3,
                note: "s6-dispatch-target-on-secondary-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_003,
            "target-executor-s6",
            SemanticCommand::RecordIpiEvent {
                ipi: 9002,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                kind: IpiEventKind::SchedulerKick,
                reason: "s6-remote-preempt-ipi".to_owned(),
                note: "s6-remote-preempt-ipi-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_004,
            "target-executor-s6",
            SemanticCommand::RemotePreemptActivation {
                remote_preempt: 9001,
                ipi: 9002,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 3,
                activation: 9004,
                activation_generation: 3,
                queue: 9004,
                note: "s6-remote-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_005,
            "target-executor-s8",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9004,
                queue: 9004,
                queue_generation: 2,
                selected_activation: 9004,
                selected_activation_generation: 4,
                reason: "s8-cross-hart-runnable".to_owned(),
                note: "s8-cross-hart-base-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_006,
            "target-executor-s8",
            SemanticCommand::RecordCrossHartSchedulerDecision {
                cross_decision: 9001,
                scheduler_decision: 9004,
                scheduler_decision_generation: 1,
                deciding_hart: 1,
                deciding_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 4,
                reason: "s8-remote-runnable-selected".to_owned(),
                note: "s8-cross-hart-scheduler-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_007,
            "target-executor-s9",
            SemanticCommand::CreateRunnableQueue {
                queue: 9005,
                label: "s9-migration-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_008,
            "target-executor-s9",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9005,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s9-target-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_009,
            "target-executor-s9",
            SemanticCommand::MigrateRunnableActivation {
                migration: 9001,
                activation: 9004,
                activation_generation: 4,
                source_queue: 9004,
                source_queue_generation: 2,
                target_queue: 9005,
                target_queue_generation: 2,
                source_hart: 2,
                source_hart_generation: 4,
                target_hart: 1,
                target_hart_generation: 2,
                reason: "s9-cross-hart-rebalance".to_owned(),
                note: "s9-activation-migration-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_010,
            "target-executor-s10",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9001,
                coordinator_hart: 1,
                coordinator_hart_generation: 2,
                participants: vec![(1, 2), (2, 4)],
                reason: "s10-quiescent-boundary".to_owned(),
                note: "s10-smp-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_011,
            "target-executor-s11",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9101,
                epoch: 1,
                safe_point: 9001,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s11-stop-the-world-code-publish-boundary".to_owned(),
                note: "s11-stop-the-world-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            9_012,
            "target-executor-s12",
            SemanticCommand::ValidateSmpCodePublishBarrier {
                barrier: 9201,
                rendezvous: 9101,
                rendezvous_generation: 1,
                code_publish_epoch_before: 0,
                code_publish_epoch_after: 1,
                remote_icache_sync_required: true,
                code_publish_executed: false,
                reason: "s12-smp-code-publish-barrier".to_owned(),
                note: "s12-semantic-code-publish-barrier-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10,
            "target-executor-p0",
            SemanticCommand::CreateRunnableQueue {
                queue: 9001,
                label: "bootstrap-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            10_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9001,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-bootstrap-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            11,
            "target-executor-p0",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9001,
                owner_task: 9001,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            12,
            "target-executor-p0",
            SemanticCommand::EnqueueRunnable {
                queue: 9001,
                activation: 9001,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            13,
            "target-executor-p1",
            SemanticCommand::CreateActivationContext {
                context: 9001,
                activation: 9001,
                activation_generation: 2,
            },
        ),
        CommandEnvelope::new(
            14,
            "target-executor-p1",
            SemanticCommand::CaptureSavedContext {
                saved_context: 9001,
                context: 9001,
                context_generation: 1,
                reason: SavedContextReason::Initial,
                pc: 0x1000,
                sp: 0x8000,
                flags: 0,
                note: "p1-initial-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20,
            "target-executor-p2",
            SemanticCommand::CreateRunnableQueue {
                queue: 9002,
                label: "timer-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            20_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9002,
                queue_generation: 1,
                hart: 1,
                hart_generation: 2,
                note: "s3-timer-queue-owned-by-boot-hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            21,
            "target-executor-p2",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9002,
                owner_task: 9002,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            22,
            "target-executor-p2",
            SemanticCommand::EnqueueRunnable {
                queue: 9002,
                activation: 9002,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            23,
            "target-executor-p2",
            SemanticCommand::DequeueRunnable { queue: 9002, activation: 9002 },
        ),
        CommandEnvelope::new(
            24,
            "target-executor-s1",
            SemanticCommand::BindHartCurrentActivation {
                hart: 1,
                hart_generation: 2,
                activation: 9002,
                activation_generation: 3,
                note: "s1-hart-current-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            25,
            "target-executor-p2",
            SemanticCommand::RecordTimerInterrupt {
                interrupt: 9001,
                timer_epoch: 1,
                hart: 1,
                hart_generation: 3,
                target_activation: Some(9002),
                target_activation_generation: Some(3),
                note: "p2-timer-interrupt-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            29,
            "target-executor-s1",
            SemanticCommand::ClearHartCurrentActivation {
                hart: 1,
                hart_generation: 3,
                activation: 9002,
                activation_generation: 3,
                reason: "timer-preempt".to_owned(),
                note: "s1-clear-current-before-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            30,
            "target-executor-p3",
            SemanticCommand::PreemptActivation {
                preemption: 9001,
                activation: 9002,
                activation_generation: 3,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                queue: 9002,
                note: "p3-preempt-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            40,
            "target-executor-p4",
            SemanticCommand::SavePreemptedContext {
                context: 9002,
                saved_context: 9002,
                preemption: 9001,
                preemption_generation: 1,
                pc: 0x2000,
                sp: 0x9000,
                flags: 0,
                note: "p4-save-preempted-context-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            50,
            "target-executor-p5",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9001,
                queue: 9002,
                queue_generation: 2,
                selected_activation: 9002,
                selected_activation_generation: 4,
                reason: "runnable-available".to_owned(),
                note: "p5-scheduler-decision-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            60,
            "target-executor-p6",
            SemanticCommand::ResumeActivation {
                resume: 9001,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation: 9002,
                activation_generation: 4,
                note: "p6-resume-activation-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            61,
            "target-executor-p9",
            SemanticCommand::RecordPreemptionLatencySample {
                sample: 9001,
                timer_interrupt: 9001,
                timer_interrupt_generation: 1,
                preemption: 9001,
                preemption_generation: 1,
                scheduler_decision: 9001,
                scheduler_decision_generation: 1,
                activation_resume: 9001,
                activation_resume_generation: 1,
                measured_nanos: 8_500,
                budget_nanos: 50_000,
                note: "p9-host-validation-preemption-latency-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70,
            "target-executor-p7",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9001,
                activation: 9002,
                activation_generation: 5,
                wait: 9003,
                kind: SemanticWaitKind::Timer,
                blockers: vec![ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 9001, 1)],
                deadline: Some(200),
                restart_policy: RestartPolicy::RestartIfAllowed,
                note: "p7-block-on-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            71,
            "target-executor-p7",
            SemanticCommand::CancelActivationWait {
                activation_wait: 9001,
                activation_wait_generation: 1,
                wait_generation: 1,
                errno: 110,
                reason: semantic_core::WaitCancelReason::Timeout,
                note: "p7-cancel-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80,
            "target-executor-p8",
            SemanticCommand::CreateRunnableQueue {
                queue: 9003,
                label: "cleanup-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80_001,
            "target-executor-s3",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9003,
                queue_generation: 1,
                hart: 1,
                hart_generation: 4,
                note: "s3-cleanup-queue-owned-by-boot-hart-after-preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            81,
            "target-executor-p8",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9003,
                owner_task: 9003,
                owner_task_generation: 1,
                owner_store: Some(cleanup_store),
                owner_store_generation: Some(cleanup_store_generation),
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            82,
            "target-executor-p8",
            SemanticCommand::EnqueueRunnable {
                queue: 9003,
                activation: 9003,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            83,
            "target-executor-p8",
            SemanticCommand::DequeueRunnable { queue: 9003, activation: 9003 },
        ),
        CommandEnvelope::new(
            84,
            "target-executor-p8",
            SemanticCommand::BlockActivationOnWait {
                activation_wait: 9002,
                activation: 9003,
                activation_generation: 3,
                wait: 9004,
                kind: SemanticWaitKind::DeviceIrq,
                blockers: vec![ContractObjectRef::new(
                    ContractObjectKind::Store,
                    cleanup_store,
                    cleanup_store_generation,
                )],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                note: "p8-block-driver-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            85,
            "target-executor-p8",
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup: 9001,
                store: cleanup_store,
                store_generation: cleanup_store_generation,
                activation: 9003,
                activation_generation: 4,
                wait: Some(9004),
                wait_generation: Some(1),
                reason: "driver-store-fault".to_owned(),
                note: "p8-cleanup-dead-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90,
            "target-executor-s7",
            SemanticCommand::RecordIpiEvent {
                ipi: 9003,
                source_hart: 1,
                source_hart_generation: 4,
                target_hart: 2,
                target_hart_generation: 4,
                kind: IpiEventKind::SchedulerKick,
                reason: "s7-remote-park-ipi".to_owned(),
                note: "s7-remote-park-ipi-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            91,
            "target-executor-s7",
            SemanticCommand::RemoteParkHart {
                remote_park: 9001,
                ipi: 9003,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 4,
                target_hart: 2,
                target_hart_generation: 4,
                reason: "s7-remote-maintenance".to_owned(),
                note: "s7-remote-park-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            92,
            "target-executor-s13",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9301,
                coordinator_hart: 1,
                coordinator_hart_generation: 4,
                participants: vec![(1, 4), (2, 5)],
                reason: "s13-cleanup-quiescence-boundary".to_owned(),
                note: "s13-post-cleanup-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            93,
            "target-executor-s13",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9301,
                epoch: 2,
                safe_point: 9301,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s13-cleanup-quiescence-rendezvous".to_owned(),
                note: "s13-post-cleanup-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            94,
            "target-executor-s13",
            SemanticCommand::ValidateSmpCleanupQuiescence {
                quiescence: 9301,
                cleanup: 9001,
                cleanup_generation: 1,
                rendezvous: 9301,
                rendezvous_generation: 1,
                store: cleanup_store,
                target_store_generation: cleanup_store_generation,
                result_store_generation: cleanup_result_store_generation,
                reason: "s13-smp-cleanup-quiescence".to_owned(),
                note: "s13-dead-store-cross-hart-quiescence-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            95,
            "target-executor-s14",
            SemanticCommand::RecordSmpSafePoint {
                safe_point: 9401,
                coordinator_hart: 1,
                coordinator_hart_generation: 4,
                participants: vec![(1, 4), (2, 5)],
                reason: "s14-snapshot-barrier-boundary".to_owned(),
                note: "s14-snapshot-safe-point-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            96,
            "target-executor-s14",
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous: 9401,
                epoch: 3,
                safe_point: 9401,
                safe_point_generation: 1,
                stop_new_activations: true,
                reason: "s14-snapshot-barrier-rendezvous".to_owned(),
                note: "s14-snapshot-rendezvous-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            97,
            "target-executor-s14",
            SemanticCommand::ValidateSmpSnapshotBarrier {
                barrier: 9401,
                rendezvous: 9401,
                rendezvous_generation: 1,
                snapshot_state: SnapshotBarrierValidationState::default(),
                reason: "s14-smp-snapshot-barrier".to_owned(),
                note: "s14-clean-snapshot-boundary-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            98,
            "target-executor-s15",
            SemanticCommand::RecordSmpStressRun {
                run: 9501,
                scenario: "target-executor-s15-integrated-smp-sequence".to_owned(),
                iterations: 3,
                invariant_checks: 6,
                reason: "s15-smp-stress-property-tests".to_owned(),
                note: "s15-record-property-clean-smp-sequence".to_owned(),
            },
        ),
        CommandEnvelope::new(
            99,
            "target-executor-s16",
            SemanticCommand::RecordSmpScalingBenchmark {
                benchmark: 9601,
                scenario: "target-executor-s16-smp-scaling-harness".to_owned(),
                stress_run: 9501,
                stress_run_generation: 1,
                workload_units: 6,
                baseline_single_hart_nanos: 120_000,
                measured_smp_nanos: 72_000,
                budget_nanos: 90_000,
                note: "s16-record-semantic-smp-scaling-benchmark".to_owned(),
            },
        ),
        CommandEnvelope::new(
            100,
            "target-executor-i0",
            SemanticCommand::RecordDeviceObject {
                device: 9701,
                name: "fake-io0".to_owned(),
                class: "fake-device".to_owned(),
                resource: io_device_resource,
                resource_generation: io_device_resource_generation,
                backend: "fake-io-backend".to_owned(),
                bus: "semantic-harness".to_owned(),
                vendor: "vmos".to_owned(),
                model: "fake-io-v1".to_owned(),
                note: "i0-record-device-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            101,
            "target-executor-i1",
            SemanticCommand::RecordQueueObject {
                queue: 9801,
                name: "fake-io0-rx".to_owned(),
                role: QueueObjectRole::Rx,
                queue_index: 0,
                depth: 64,
                device: 9701,
                device_generation: 1,
                note: "i1-record-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            102,
            "target-executor-i2",
            SemanticCommand::RecordDescriptorObject {
                descriptor: 9901,
                queue: 9801,
                queue_generation: 1,
                slot: 0,
                access: DescriptorObjectAccess::ReadWrite,
                length: 2048,
                note: "i2-record-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            103,
            "target-executor-i3",
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer: 9911,
                descriptor: 9901,
                descriptor_generation: 1,
                resource: io_dma_buffer_resource,
                resource_generation: io_dma_buffer_resource_generation,
                access: DmaBufferObjectAccess::ReadWrite,
                length: 2048,
                note: "i3-record-dma-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            104,
            "target-executor-i4",
            SemanticCommand::RecordMmioRegionObject {
                mmio_region: 9921,
                device: 9701,
                device_generation: 1,
                resource: io_mmio_region_resource,
                resource_generation: io_mmio_region_resource_generation,
                region_index: 0,
                offset: 0x1000,
                length: 0x100,
                access: MmioRegionObjectAccess::ReadWrite,
                note: "i4-record-mmio-region-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            105,
            "target-executor-i5",
            SemanticCommand::RecordIrqLineObject {
                irq_line: 9931,
                device: 9701,
                device_generation: 1,
                resource: io_irq_line_resource,
                resource_generation: io_irq_line_resource_generation,
                irq_number: 5,
                trigger: IrqLineTrigger::Level,
                polarity: IrqLinePolarity::ActiveHigh,
                note: "i5-record-irq-line-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            106,
            "target-executor-i6",
            SemanticCommand::RecordIrqEvent {
                irq_event: 9941,
                irq_line: 9931,
                irq_line_generation: 1,
                device: 9701,
                device_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                sequence: 1,
                note: "i6-record-irq-event-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 9701, 1);
    let mmio_ref = ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 9921, 1);
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 9911, 1);
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 9931, 1);
    let device_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "device.fake-io0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "i7-device-capability",
        true,
    );
    let mmio_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio_ref),
        &["write32"],
        "store",
        "i7-device-capability",
        true,
    );
    let dma_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "i7-device-capability",
        true,
    );
    let irq_capability = semantic.grant_capability_with_authority_ref(
        "i6.irq.driver",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
        &["ack"],
        "store",
        "i7-device-capability",
        true,
    );
    let capability_handle = |semantic: &SemanticGraph, capability, operation: &str| {
        semantic
            .capabilities()
            .record(capability)
            .and_then(|record| record.store_local_handle(vec![operation.to_owned()]))
            .ok_or("i7 device capability handle is missing")
    };
    let i7_commands = [
        CommandEnvelope::new(
            107,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9951,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: capability_handle(semantic, device_capability, "probe")?,
                note: "i7-record-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            108,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9952,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: mmio_ref,
                class: CapabilityClass::MmioRegion,
                operation: "write32".to_owned(),
                handle: capability_handle(semantic, mmio_capability, "write32")?,
                note: "i7-record-mmio-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            109,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9953,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: dma_ref,
                class: CapabilityClass::DmaBuffer,
                operation: "sync-for-device".to_owned(),
                handle: capability_handle(semantic, dma_capability, "sync-for-device")?,
                note: "i7-record-dma-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            110,
            "target-executor-i7",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 9954,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                target: irq_ref,
                class: CapabilityClass::IrqLine,
                operation: "ack".to_owned(),
                handle: capability_handle(semantic, irq_capability, "ack")?,
                note: "i7-record-irq-capability-harness".to_owned(),
            },
        ),
    ];
    for command in i7_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let i8_result = semantic.apply_envelope(CommandEnvelope::new(
        111,
        "target-executor-i8",
        SemanticCommand::BindDriverStore {
            binding: 9961,
            driver_store: io_driver_store,
            driver_store_generation: io_driver_store_generation,
            device: 9701,
            device_generation: 1,
            device_capability: 9951,
            device_capability_generation: 1,
            note: "i8-bind-driver-store-to-device-harness".to_owned(),
        },
    ));
    if i8_result.status != CommandStatus::Applied {
        return Err(format!(
            "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
            i8_result.command_id,
            i8_result.command,
            i8_result.status.as_str(),
            i8_result.violations
        )
        .into());
    }
    let i9_commands = [
        CommandEnvelope::new(
            112,
            "target-executor-i9",
            SemanticCommand::CreateWait {
                wait: 9962,
                owner_task: None,
                owner_store: Some(io_driver_store),
                owner_store_generation: Some(io_driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("i9-fake-irq-wait".to_owned()),
            },
        ),
        CommandEnvelope::new(
            113,
            "target-executor-i9",
            SemanticCommand::RecordIoWait {
                io_wait: 9963,
                wait: 9962,
                wait_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                blocker: irq_ref,
                note: "i9-io-wait-token-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            114,
            "target-executor-i9",
            SemanticCommand::RecordIrqEvent {
                irq_event: 9964,
                irq_line: 9931,
                irq_line_generation: 1,
                device: 9701,
                device_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                sequence: 2,
                note: "i9-fake-irq-event-resolves-wait".to_owned(),
            },
        ),
        CommandEnvelope::new(
            115,
            "target-executor-i9",
            SemanticCommand::ResolveIoWait {
                io_wait: 9963,
                io_wait_generation: 1,
                irq_event: 9964,
                irq_event_generation: 1,
                note: "i9-fake-irq-resolved-io-wait".to_owned(),
            },
        ),
    ];
    for command in i9_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let io_evidence_commands = [
        CommandEnvelope::new(
            116,
            "target-executor-i10",
            SemanticCommand::CreateWait {
                wait: 9965,
                owner_task: None,
                owner_store: Some(io_driver_store),
                owner_store_generation: Some(io_driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("i10-pending-io-wait-before-cleanup".to_owned()),
            },
        ),
        CommandEnvelope::new(
            117,
            "target-executor-i10",
            SemanticCommand::RecordIoWait {
                io_wait: 9966,
                wait: 9965,
                wait_generation: 1,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                blocker: irq_ref,
                note: "i10-pending-io-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            118,
            "target-executor-i11",
            SemanticCommand::InjectIoFault {
                fault: 9968,
                cleanup: 9967,
                driver_store: io_driver_store,
                driver_store_generation: io_driver_store_generation,
                device: 9701,
                device_generation: 1,
                driver_binding: 9961,
                driver_binding_generation: 1,
                target: irq_ref,
                kind: semantic_core::IoFaultInjectionKind::DeviceFault,
                note: "i11-injected-device-fault-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            119,
            "target-executor-i12",
            SemanticCommand::ValidateIoRuntime {
                report: 9969,
                note: "i12-io-validator-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            120,
            "target-executor-n0",
            SemanticCommand::RecordDeviceObject {
                device: 10_001,
                name: "virtio-net0".to_owned(),
                class: "packet-device".to_owned(),
                resource: packet_device_resource,
                resource_generation: packet_device_resource_generation,
                backend: "fake-net-backend".to_owned(),
                bus: "semantic-harness".to_owned(),
                vendor: "vmos".to_owned(),
                model: "fake-net-v1".to_owned(),
                note: "n0-record-packet-backing-device-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            121,
            "target-executor-n0",
            SemanticCommand::RecordPacketDeviceObject {
                packet_device: 10_002,
                name: "net0".to_owned(),
                device: 10_001,
                device_generation: 1,
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                note: "n0-record-packet-device-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            122,
            "target-executor-n1",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_003,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Rx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: 64,
                sequence: 1,
                state: PacketBufferObjectState::Filled,
                note: "n1-record-packet-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            123,
            "target-executor-n2",
            SemanticCommand::RecordPacketQueueObject {
                packet_queue: 10_004,
                name: "net0-rx0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                role: PacketQueueRole::Rx,
                queue_index: 0,
                depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                note: "n2-record-rx-packet-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            124,
            "target-executor-n2",
            SemanticCommand::RecordPacketQueueObject {
                packet_queue: 10_005,
                name: "net0-tx0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                role: PacketQueueRole::Tx,
                queue_index: 0,
                depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                note: "n2-record-tx-packet-queue-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            125,
            "target-executor-n3",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_006,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                packet_buffer: 10_003,
                packet_buffer_generation: 1,
                slot: 0,
                length: 64,
                note: "n3-record-rx-packet-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            126,
            "target-executor-n4",
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend: 10_007,
                name: "fake-net0".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                provider: FAKE_NET_BACKEND_PROVIDER.to_owned(),
                profile: FAKE_NET_BACKEND_PROFILE.to_owned(),
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                deterministic_seed: FAKE_NET_BACKEND_SEED,
                note: "n4-bind-fake-net-backend-object-harness".to_owned(),
            },
        ),
    ];
    for command in io_evidence_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "preemptive runtime evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn record_interface_boundary_evidence(semantic: &mut SemanticGraph) {
    semantic.record_interface_unsupported(
        "standard-wasi",
        "wasi:clocks/monotonic-clock",
        "subscribe",
        Some("target-executor-interface-probe".to_owned()),
        None,
        None,
    );
}

pub(crate) fn record_substrate_event(semantic: &mut SemanticGraph, event: SubstrateEvent) {
    match event {
        SubstrateEvent::Unsupported { authority, operation, requester } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_unsupported(authority, operation, requester, artifact, store);
        }
        SubstrateEvent::CapabilityDenied { authority, operation, requester, capability } => {
            let (requester, artifact, store) = substrate_requester_parts(requester);
            semantic.record_substrate_capability_denied(
                authority,
                operation,
                requester,
                artifact,
                store,
                capability.map(|capability| capability.id),
                capability.map(|capability| capability.generation),
            );
        }
    }
}

pub(crate) fn substrate_requester_parts(
    requester: Option<SubstrateRequester>,
) -> (Option<String>, Option<u64>, Option<u64>) {
    let Some(requester) = requester else {
        return (None, None, None);
    };
    (
        Some(requester.subject),
        requester.artifact.map(|artifact| artifact.id),
        requester.store.map(|store| store.id),
    )
}
