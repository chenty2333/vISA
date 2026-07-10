use super::{super::super::*, *};

pub(crate) fn hart_record_manifest(hart: &semantic_core::HartRecord) -> HartRecordManifest {
    HartRecordManifest {
        id: u64::from(hart.id),
        hardware_id: hart.hardware_id,
        label: hart.label.clone(),
        state: hart.state.as_str().to_owned(),
        generation: hart.generation,
        boot: hart.boot,
        current_activation: hart.current_activation,
        current_activation_generation: hart.current_activation_generation,
        current_task: hart.current_task.map(u64::from),
        current_task_generation: hart.current_task_generation,
        current_store: hart.current_store,
        current_store_generation: hart.current_store_generation,
        last_event: hart.last_event,
        last_current_event: hart.last_current_event,
        note: hart.note.clone(),
    }
}

pub(crate) fn task_record_manifest(task: &semantic_core::TaskRecord) -> TaskRecordManifest {
    TaskRecordManifest {
        id: u64::from(task.id),
        label: task.label.clone(),
        frontend: task.frontend.as_str().to_owned(),
        state: task.state.as_str().to_owned(),
        generation: task.generation,
        fault_domain: task.fault_domain,
        pending_wait: task.pending_wait,
        resources: task.resources.clone(),
    }
}

pub(crate) fn runtime_activation_record_manifest(
    activation: &semantic_core::RuntimeActivationRecord,
) -> RuntimeActivationRecordManifest {
    RuntimeActivationRecordManifest {
        id: activation.id,
        owner_task: u64::from(activation.owner_task),
        owner_task_generation: activation.owner_task_generation,
        owner_store: activation.owner_store,
        owner_store_generation: activation.owner_store_generation,
        code_object: activation.code_object.map(contract_object_ref_manifest),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        runnable_queue: activation.runnable_queue,
        runnable_queue_generation: activation.runnable_queue_generation,
        last_event: activation.last_event,
    }
}

pub(crate) fn guest_address_space_manifest(
    aspace: &semantic_core::GuestAddressSpaceRecord,
) -> GuestAddressSpaceManifest {
    GuestAddressSpaceManifest {
        id: aspace.aspace.id(),
        owner: contract_object_ref_manifest(aspace.owner),
        generation: aspace.generation,
        state: aspace.state.as_str().to_owned(),
        root_region: aspace
            .root_region
            .map(|region| contract_object_ref_manifest(region.object_ref())),
        vma_generation: aspace.vma_generation,
        page_map_generation: aspace.page_map_generation,
    }
}

pub(crate) fn vma_region_manifest(region: &semantic_core::VmaRegionRecord) -> VmaRegionManifest {
    VmaRegionManifest {
        id: region.region.id(),
        aspace: contract_object_ref_manifest(region.aspace.object_ref()),
        range: GuestVaRangeManifest { start: region.range.start, len: region.range.len },
        perms: GuestPermsManifest {
            readable: region.perms.contains(semantic_core::GuestPerms::READ),
            writable: region.perms.contains(semantic_core::GuestPerms::WRITE),
            executable: region.perms.contains(semantic_core::GuestPerms::EXEC),
        },
        flags: VmaFlagsManifest {
            cow: region.flags.cow,
            shared: region.flags.shared,
            device: region.flags.device,
        },
        backing: contract_object_ref_manifest(region.backing.object_ref()),
        generation: region.generation,
        state: region.state.as_str().to_owned(),
    }
}

pub(crate) fn page_object_manifest(page: &semantic_core::PageObjectRecord) -> PageObjectManifest {
    PageObjectManifest {
        id: page.page.id(),
        backing: page.backing.as_str().to_owned(),
        cow: page.cow.as_str().to_owned(),
        dirty_generation: page.dirty_generation,
        generation: page.generation,
        state: page.state.as_str().to_owned(),
    }
}

pub(crate) fn guest_memory_fault_manifest(
    fault: &semantic_core::GuestMemoryFaultRecord,
) -> GuestMemoryFaultManifest {
    GuestMemoryFaultManifest {
        id: fault.id,
        generation: fault.generation,
        page: contract_object_ref_manifest(fault.page.object_ref()),
        reason: fault.reason.clone(),
        historical: fault.historical,
    }
}

pub(crate) fn guest_memory_operation_manifest(
    operation: &semantic_core::GuestMemoryOperationRecord,
) -> artifact_manifest::GuestMemoryOperationManifest {
    let perms = |value: semantic_core::GuestPerms| GuestPermsManifest {
        readable: value.contains(semantic_core::GuestPerms::READ),
        writable: value.contains(semantic_core::GuestPerms::WRITE),
        executable: value.contains(semantic_core::GuestPerms::EXEC),
    };

    artifact_manifest::GuestMemoryOperationManifest {
        id: operation.operation_ref.id(),
        generation: operation.generation,
        operation: operation.operation.as_str().to_owned(),
        status: operation.status.as_str().to_owned(),
        aspace: contract_object_ref_manifest(operation.aspace.object_ref()),
        range: GuestVaRangeManifest { start: operation.range.start, len: operation.range.len },
        region_before: operation
            .region_before
            .map(|value| contract_object_ref_manifest(value.object_ref())),
        region_after: operation
            .region_after
            .map(|value| contract_object_ref_manifest(value.object_ref())),
        page_before: operation
            .page_before
            .map(|value| contract_object_ref_manifest(value.object_ref())),
        page_after: operation
            .page_after
            .map(|value| contract_object_ref_manifest(value.object_ref())),
        perms_before: operation.perms_before.map(perms),
        perms_after: operation.perms_after.map(perms),
        brk_before: operation.brk_before,
        brk_after: operation.brk_after,
        reason: operation.reason.clone(),
    }
}

pub(crate) fn runnable_queue_manifest(
    queue: &semantic_core::RunnableQueueRecord,
) -> RunnableQueueManifest {
    RunnableQueueManifest {
        id: queue.id,
        label: queue.label.clone(),
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        owner_hart: queue.owner_hart,
        owner_hart_generation: queue.owner_hart_generation,
        entries: queue
            .entries
            .iter()
            .map(|entry| RunnableQueueEntryManifest {
                activation: entry.activation,
                activation_generation: entry.activation_generation,
                enqueued_at: entry.enqueued_at,
            })
            .collect(),
    }
}

pub(crate) fn activation_context_manifest(
    context: &semantic_core::ActivationContextRecord,
) -> ActivationContextManifest {
    ActivationContextManifest {
        id: context.id,
        activation: context.activation,
        activation_generation: context.activation_generation,
        owner_task: u64::from(context.owner_task),
        owner_task_generation: context.owner_task_generation,
        owner_store: context.owner_store,
        owner_store_generation: context.owner_store_generation,
        generation: context.generation,
        state: context.state.as_str().to_owned(),
        current_saved_context: context.current_saved_context,
        current_saved_context_generation: context.current_saved_context_generation,
        vector_state: context.vector_state.map(contract_object_ref_manifest),
        vector_status: context.vector_status.as_str().to_owned(),
        vector_state_event: context.vector_state_event,
        last_event: context.last_event,
    }
}

pub(crate) fn saved_context_manifest(
    saved: &semantic_core::SavedContextRecord,
) -> SavedContextManifest {
    SavedContextManifest {
        id: saved.id,
        context: saved.context,
        context_generation: saved.context_generation,
        activation: saved.activation,
        activation_generation: saved.activation_generation,
        owner_task: u64::from(saved.owner_task),
        owner_task_generation: saved.owner_task_generation,
        source_preemption: saved.source_preemption,
        source_preemption_generation: saved.source_preemption_generation,
        generation: saved.generation,
        state: saved.state.as_str().to_owned(),
        reason: saved.reason.as_str().to_owned(),
        pc: saved.pc,
        sp: saved.sp,
        flags: saved.flags,
        integer_registers: saved.integer_registers,
        vector_state: saved.vector_state.map(contract_object_ref_manifest),
        vector_status: saved.vector_status.as_str().to_owned(),
        vector_saved_at_event: saved.vector_saved_at_event,
        saved_at_event: saved.saved_at_event,
        note: saved.note.clone(),
    }
}

pub(crate) fn timer_interrupt_manifest(
    interrupt: &semantic_core::TimerInterruptRecord,
) -> TimerInterruptManifest {
    TimerInterruptManifest {
        id: interrupt.id,
        timer_epoch: interrupt.timer_epoch,
        hart: u64::from(interrupt.hart),
        hart_generation: Some(interrupt.hart_generation),
        hardware_hart: Some(interrupt.hardware_hart),
        target_activation: interrupt.target_activation,
        target_activation_generation: interrupt.target_activation_generation,
        target_task: interrupt.target_task.map(u64::from),
        target_task_generation: interrupt.target_task_generation,
        generation: interrupt.generation,
        state: interrupt.state.as_str().to_owned(),
        recorded_at_event: interrupt.recorded_at_event,
        note: interrupt.note.clone(),
    }
}

pub(crate) fn ipi_event_manifest(ipi: &semantic_core::IpiEventRecord) -> IpiEventManifest {
    IpiEventManifest {
        id: ipi.id,
        source_hart: u64::from(ipi.source_hart),
        source_hart_generation: ipi.source_hart_generation,
        source_hardware_hart: ipi.source_hardware_hart,
        target_hart: u64::from(ipi.target_hart),
        target_hart_generation: ipi.target_hart_generation,
        target_hardware_hart: ipi.target_hardware_hart,
        kind: ipi.kind.as_str().to_owned(),
        generation: ipi.generation,
        state: ipi.state.as_str().to_owned(),
        recorded_at_event: ipi.recorded_at_event,
        reason: ipi.reason.clone(),
        note: ipi.note.clone(),
    }
}

pub(crate) fn remote_preempt_manifest(
    remote: &semantic_core::RemotePreemptRecord,
) -> RemotePreemptManifest {
    RemotePreemptManifest {
        id: remote.id,
        ipi: remote.ipi,
        ipi_generation: remote.ipi_generation,
        source_hart: u64::from(remote.source_hart),
        source_hart_generation: remote.source_hart_generation,
        target_hart: u64::from(remote.target_hart),
        target_hart_generation_before: remote.target_hart_generation_before,
        target_hart_generation_after: remote.target_hart_generation_after,
        activation: remote.activation,
        activation_generation_before: remote.activation_generation_before,
        activation_generation_after: remote.activation_generation_after,
        queue: remote.queue,
        queue_generation: remote.queue_generation,
        generation: remote.generation,
        state: remote.state.as_str().to_owned(),
        preempted_at_event: remote.preempted_at_event,
        note: remote.note.clone(),
    }
}

pub(crate) fn remote_park_manifest(remote: &semantic_core::RemoteParkRecord) -> RemoteParkManifest {
    RemoteParkManifest {
        id: remote.id,
        ipi: remote.ipi,
        ipi_generation: remote.ipi_generation,
        source_hart: u64::from(remote.source_hart),
        source_hart_generation: remote.source_hart_generation,
        target_hart: u64::from(remote.target_hart),
        target_hart_generation_before: remote.target_hart_generation_before,
        target_hart_generation_after: remote.target_hart_generation_after,
        generation: remote.generation,
        state: remote.state.as_str().to_owned(),
        parked_at_event: remote.parked_at_event,
        reason: remote.reason.clone(),
        note: remote.note.clone(),
    }
}

pub(crate) fn hart_event_attribution_manifest(
    attribution: &semantic_core::HartEventAttributionRecord,
) -> HartEventAttributionManifest {
    HartEventAttributionManifest {
        id: attribution.id,
        hart: u64::from(attribution.hart),
        hart_generation: attribution.hart_generation,
        hardware_hart: attribution.hardware_hart,
        event: attribution.event,
        event_source: attribution.event_source.clone(),
        event_kind: attribution.event_kind.clone(),
        activation: attribution.activation,
        activation_generation: attribution.activation_generation,
        task: attribution.task.map(u64::from),
        task_generation: attribution.task_generation,
        store: attribution.store,
        store_generation: attribution.store_generation,
        generation: attribution.generation,
        state: attribution.state.as_str().to_owned(),
        note: attribution.note.clone(),
    }
}

pub(crate) fn preemption_manifest(
    preemption: &semantic_core::PreemptionRecord,
) -> PreemptionManifest {
    PreemptionManifest {
        id: preemption.id,
        activation: preemption.activation,
        activation_generation_before: preemption.activation_generation_before,
        activation_generation_after: preemption.activation_generation_after,
        timer_interrupt: preemption.timer_interrupt,
        timer_interrupt_generation: preemption.timer_interrupt_generation,
        queue: preemption.queue,
        queue_generation: preemption.queue_generation,
        generation: preemption.generation,
        state: preemption.state.as_str().to_owned(),
        preempted_at_event: preemption.preempted_at_event,
        note: preemption.note.clone(),
    }
}

pub(crate) fn scheduler_decision_manifest(
    decision: &semantic_core::SchedulerDecisionRecord,
) -> SchedulerDecisionManifest {
    SchedulerDecisionManifest {
        id: decision.id,
        queue: decision.queue,
        queue_generation: decision.queue_generation,
        selected_activation: decision.selected_activation,
        selected_activation_generation: decision.selected_activation_generation,
        owner_task: u64::from(decision.owner_task),
        owner_task_generation: decision.owner_task_generation,
        generation: decision.generation,
        state: decision.state.as_str().to_owned(),
        decided_at_event: decision.decided_at_event,
        reason: decision.reason.clone(),
        note: decision.note.clone(),
    }
}

pub(crate) fn cross_hart_scheduler_decision_manifest(
    decision: &semantic_core::CrossHartSchedulerDecisionRecord,
) -> CrossHartSchedulerDecisionManifest {
    CrossHartSchedulerDecisionManifest {
        id: decision.id,
        scheduler_decision: decision.scheduler_decision,
        scheduler_decision_generation: decision.scheduler_decision_generation,
        deciding_hart: u64::from(decision.deciding_hart),
        deciding_hart_generation: decision.deciding_hart_generation,
        target_hart: u64::from(decision.target_hart),
        target_hart_generation: decision.target_hart_generation,
        queue: decision.queue,
        queue_generation: decision.queue_generation,
        queue_owner_hart_generation: decision.queue_owner_hart_generation,
        selected_activation: decision.selected_activation,
        selected_activation_generation: decision.selected_activation_generation,
        generation: decision.generation,
        state: decision.state.as_str().to_owned(),
        decided_at_event: decision.decided_at_event,
        reason: decision.reason.clone(),
        note: decision.note.clone(),
    }
}

pub(crate) fn activation_migration_manifest(
    migration: &semantic_core::ActivationMigrationRecord,
) -> ActivationMigrationManifest {
    ActivationMigrationManifest {
        id: migration.id,
        activation: migration.activation,
        activation_generation_before: migration.activation_generation_before,
        activation_generation_after: migration.activation_generation_after,
        owner_task: u64::from(migration.owner_task),
        owner_task_generation: migration.owner_task_generation,
        source_hart: u64::from(migration.source_hart),
        source_hart_generation: migration.source_hart_generation,
        target_hart: u64::from(migration.target_hart),
        target_hart_generation: migration.target_hart_generation,
        source_queue: migration.source_queue,
        source_queue_generation: migration.source_queue_generation,
        source_queue_owner_hart_generation: migration.source_queue_owner_hart_generation,
        target_queue: migration.target_queue,
        target_queue_generation: migration.target_queue_generation,
        target_queue_owner_hart_generation: migration.target_queue_owner_hart_generation,
        context: migration.context,
        context_generation_before: migration.context_generation_before,
        context_generation_after: migration.context_generation_after,
        source_vector_state: migration.source_vector_state.map(contract_object_ref_manifest),
        migrated_vector_state: migration.migrated_vector_state.map(contract_object_ref_manifest),
        vector_status: migration.vector_status.as_str().to_owned(),
        vector_migrated_at_event: migration.vector_migrated_at_event,
        generation: migration.generation,
        state: migration.state.as_str().to_owned(),
        migrated_at_event: migration.migrated_at_event,
        reason: migration.reason.clone(),
        note: migration.note.clone(),
    }
}

pub(crate) fn smp_safe_point_manifest(
    safe_point: &semantic_core::SmpSafePointRecord,
) -> SmpSafePointManifest {
    SmpSafePointManifest {
        id: safe_point.id,
        coordinator_hart: u64::from(safe_point.coordinator_hart),
        coordinator_hart_generation: safe_point.coordinator_hart_generation,
        participants: safe_point
            .participants
            .iter()
            .map(|participant| SmpSafePointParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                current_activation: participant.current_activation,
                current_activation_generation: participant.current_activation_generation,
            })
            .collect(),
        generation: safe_point.generation,
        state: safe_point.state.as_str().to_owned(),
        recorded_at_event: safe_point.recorded_at_event,
        reason: safe_point.reason.clone(),
        note: safe_point.note.clone(),
    }
}

pub(crate) fn stop_the_world_rendezvous_manifest(
    rendezvous: &semantic_core::StopTheWorldRendezvousRecord,
) -> StopTheWorldRendezvousManifest {
    StopTheWorldRendezvousManifest {
        id: rendezvous.id,
        epoch: rendezvous.epoch,
        safe_point: rendezvous.safe_point,
        safe_point_generation: rendezvous.safe_point_generation,
        coordinator_hart: u64::from(rendezvous.coordinator_hart),
        coordinator_hart_generation: rendezvous.coordinator_hart_generation,
        participants: rendezvous
            .participants
            .iter()
            .map(|participant| StopTheWorldRendezvousParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
            })
            .collect(),
        stop_new_activations: rendezvous.stop_new_activations,
        generation: rendezvous.generation,
        state: rendezvous.state.as_str().to_owned(),
        completed_at_event: rendezvous.completed_at_event,
        reason: rendezvous.reason.clone(),
        note: rendezvous.note.clone(),
    }
}

pub(crate) fn smp_code_publish_barrier_manifest(
    barrier: &semantic_core::SmpCodePublishBarrierRecord,
) -> SmpCodePublishBarrierManifest {
    SmpCodePublishBarrierManifest {
        id: barrier.id,
        rendezvous: barrier.rendezvous,
        rendezvous_generation: barrier.rendezvous_generation,
        rendezvous_epoch: barrier.rendezvous_epoch,
        code_publish_epoch_before: barrier.code_publish_epoch_before,
        code_publish_epoch_after: barrier.code_publish_epoch_after,
        participants: barrier
            .participants
            .iter()
            .map(|participant| SmpCodePublishBarrierParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                last_seen_code_epoch_before: participant.last_seen_code_epoch_before,
                last_seen_code_epoch_after: participant.last_seen_code_epoch_after,
                semantic_icache_sync: participant.semantic_icache_sync,
            })
            .collect(),
        remote_icache_sync_required: barrier.remote_icache_sync_required,
        code_publish_executed: barrier.code_publish_executed,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

pub(crate) fn smp_cleanup_quiescence_manifest(
    quiescence: &semantic_core::SmpCleanupQuiescenceRecord,
) -> SmpCleanupQuiescenceManifest {
    SmpCleanupQuiescenceManifest {
        id: quiescence.id,
        cleanup: quiescence.cleanup,
        cleanup_generation: quiescence.cleanup_generation,
        store: quiescence.store,
        target_store_generation: quiescence.target_store_generation,
        result_store_generation: quiescence.result_store_generation,
        activation: quiescence.activation,
        activation_generation_after: quiescence.activation_generation_after,
        rendezvous: quiescence.rendezvous,
        rendezvous_generation: quiescence.rendezvous_generation,
        rendezvous_epoch: quiescence.rendezvous_epoch,
        participants: quiescence
            .participants
            .iter()
            .map(|participant| SmpCleanupQuiescenceParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                current_activation: participant.current_activation,
                current_activation_generation: participant.current_activation_generation,
                current_store: participant.current_store,
                current_store_generation: participant.current_store_generation,
                quiesced: participant.quiesced,
            })
            .collect(),
        no_running_activation: quiescence.no_running_activation,
        no_pending_wait: quiescence.no_pending_wait,
        no_live_capability: quiescence.no_live_capability,
        no_live_resource: quiescence.no_live_resource,
        generation: quiescence.generation,
        state: quiescence.state.as_str().to_owned(),
        validated_at_event: quiescence.validated_at_event,
        reason: quiescence.reason.clone(),
        note: quiescence.note.clone(),
    }
}

pub(crate) fn smp_snapshot_barrier_manifest(
    barrier: &semantic_core::SmpSnapshotBarrierRecord,
) -> SmpSnapshotBarrierManifest {
    SmpSnapshotBarrierManifest {
        id: barrier.id,
        rendezvous: barrier.rendezvous,
        rendezvous_generation: barrier.rendezvous_generation,
        rendezvous_epoch: barrier.rendezvous_epoch,
        event_log_cursor: barrier.event_log_cursor,
        participants: barrier
            .participants
            .iter()
            .map(|participant| SmpSnapshotBarrierParticipantManifest {
                hart: u64::from(participant.hart),
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state.as_str().to_owned(),
                event_log_cursor_observed: participant.event_log_cursor_observed,
                snapshot_safe: participant.snapshot_safe,
            })
            .collect(),
        pending_wait_count: barrier.pending_wait_count,
        active_transaction_count: barrier.active_transaction_count,
        active_dmw_lease_count: barrier.active_dmw_lease_count,
        active_nonconvertible_activation_count: barrier.active_nonconvertible_activation_count,
        in_flight_dma_count: barrier.in_flight_dma_count,
        unsealed_event_log: barrier.unsealed_event_log,
        unflushed_trap_record_count: barrier.unflushed_trap_record_count,
        pending_cleanup_count: barrier.pending_cleanup_count,
        native_activation_stack_live: barrier.native_activation_stack_live,
        raw_dma_binding_count: barrier.raw_dma_binding_count,
        raw_mmio_binding_count: barrier.raw_mmio_binding_count,
        snapshot_validation_ok: barrier.snapshot_validation_ok,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

pub(crate) fn smp_stress_run_manifest(
    run: &semantic_core::SmpStressRunRecord,
) -> SmpStressRunManifest {
    SmpStressRunManifest {
        id: run.id,
        scenario: run.scenario.clone(),
        iterations: run.iterations,
        hart_count: run.hart_count,
        event_log_cursor: run.event_log_cursor,
        observed_safe_point_count: run.observed_safe_point_count,
        observed_rendezvous_count: run.observed_rendezvous_count,
        observed_code_publish_barrier_count: run.observed_code_publish_barrier_count,
        observed_cleanup_quiescence_count: run.observed_cleanup_quiescence_count,
        observed_snapshot_barrier_count: run.observed_snapshot_barrier_count,
        observed_activation_migration_count: run.observed_activation_migration_count,
        observed_remote_preempt_count: run.observed_remote_preempt_count,
        observed_remote_park_count: run.observed_remote_park_count,
        invariant_checks: run.invariant_checks,
        property_failures: run.property_failures,
        last_safe_point: run.last_safe_point,
        last_safe_point_generation: run.last_safe_point_generation,
        last_rendezvous: run.last_rendezvous,
        last_rendezvous_generation: run.last_rendezvous_generation,
        last_code_publish_barrier: run.last_code_publish_barrier,
        last_code_publish_barrier_generation: run.last_code_publish_barrier_generation,
        last_cleanup_quiescence: run.last_cleanup_quiescence,
        last_cleanup_quiescence_generation: run.last_cleanup_quiescence_generation,
        last_snapshot_barrier: run.last_snapshot_barrier,
        last_snapshot_barrier_generation: run.last_snapshot_barrier_generation,
        last_activation_migration: run.last_activation_migration,
        last_activation_migration_generation: run.last_activation_migration_generation,
        last_remote_preempt: run.last_remote_preempt,
        last_remote_preempt_generation: run.last_remote_preempt_generation,
        last_remote_park: run.last_remote_park,
        last_remote_park_generation: run.last_remote_park_generation,
        generation: run.generation,
        state: run.state.as_str().to_owned(),
        recorded_at_event: run.recorded_at_event,
        reason: run.reason.clone(),
        note: run.note.clone(),
    }
}

pub(crate) fn smp_scaling_benchmark_manifest(
    benchmark: &semantic_core::SmpScalingBenchmarkRecord,
) -> SmpScalingBenchmarkManifest {
    SmpScalingBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        stress_run: benchmark.stress_run,
        stress_run_generation: benchmark.stress_run_generation,
        hart_count: benchmark.hart_count,
        workload_units: benchmark.workload_units,
        baseline_single_hart_nanos: benchmark.baseline_single_hart_nanos,
        measured_smp_nanos: benchmark.measured_smp_nanos,
        budget_nanos: benchmark.budget_nanos,
        speedup_milli: benchmark.speedup_milli,
        efficiency_milli: benchmark.efficiency_milli,
        event_log_cursor: benchmark.event_log_cursor,
        stress_safe_point_count: benchmark.stress_safe_point_count,
        stress_rendezvous_count: benchmark.stress_rendezvous_count,
        stress_property_failures: benchmark.stress_property_failures,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}
