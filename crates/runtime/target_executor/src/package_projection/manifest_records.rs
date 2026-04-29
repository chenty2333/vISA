use super::super::*;
pub(crate) fn target_artifact_manifest(image: &TargetArtifactImage) -> TargetArtifactImageManifest {
    TargetArtifactImageManifest {
        id: image.id,
        package: image.package.clone(),
        artifact_name: image.artifact_name.clone(),
        role: image.role.clone(),
        kind: image.kind.as_str().to_owned(),
        target_profile: image.target_profile.clone(),
        artifact_hash: image.artifact_hash.clone(),
        hash_status: image.hash_status.clone(),
        abi_fingerprint: image.abi_fingerprint.clone(),
        manifest_binding_hash: image.manifest_binding_hash.clone(),
        code_hash: image.code_hash.clone(),
        signature_scheme: image.signature_scheme.clone(),
        signature_status: image.signature_status.clone(),
        signature_verified: image.signature_verified,
        signer: image.signer.clone(),
        exports: image.exports.clone(),
        imports: image.imports.clone(),
        hostcalls: image.hostcalls.iter().map(hostcall_manifest).collect(),
        capabilities: image.capabilities.iter().map(target_capability_manifest).collect(),
        memory_plan: TargetMemoryPlanManifest {
            max_memory_pages: image.memory_plan.max_memory_pages,
            max_table_elements: image.memory_plan.max_table_elements,
            max_hostcalls_per_activation: image.memory_plan.max_hostcalls_per_activation,
        },
        trap_metadata: image.trap_metadata.iter().map(trap_metadata_manifest).collect(),
        address_map: image.address_map.iter().map(address_map_manifest).collect(),
        payload_len: image.payload_len,
    }
}

pub(crate) fn code_object_manifest(code: &CodeObject) -> CodeObjectManifest {
    CodeObjectManifest {
        id: code.id,
        artifact_id: code.artifact_id,
        package: code.package.clone(),
        owner_profile: code.owner_profile.clone(),
        generation: code.generation,
        state: code.state.as_str().to_owned(),
        bound_store: code.bound_store,
        bound_store_generation: code.bound_store_generation,
        hostcall_table: code.hostcall_table,
        text_start: code.text.start,
        text_len: code.text.len,
        text_permission: code.text.permission.as_str().to_owned(),
        rodata_start: code.rodata.start,
        rodata_len: code.rodata.len,
        rodata_permission: code.rodata.permission.as_str().to_owned(),
        code_hash: code.code_hash.clone(),
        hostcalls: code.hostcalls.iter().map(hostcall_manifest).collect(),
        trap_metadata: code.trap_metadata.iter().map(trap_metadata_manifest).collect(),
        address_map: code.address_map.iter().map(address_map_manifest).collect(),
        simd_requirement: CodeObjectSimdRequirementManifest {
            uses_simd: code.simd_requirement.uses_simd,
            declared: code.simd_requirement.declared,
            required_abi: code.simd_requirement.required_abi.clone(),
            min_vector_register_count: code.simd_requirement.min_vector_register_count,
            min_vector_register_bits: code.simd_requirement.min_vector_register_bits,
            target_feature_set: code
                .simd_requirement
                .target_feature_set
                .map(contract_object_ref_manifest),
            status: code.simd_requirement.status.as_str().to_owned(),
            note: code.simd_requirement.note.clone(),
        },
    }
}

pub(crate) fn store_record_manifest(store: &StoreRecord) -> StoreRecordManifest {
    StoreRecordManifest {
        id: store.id,
        package: store.package.clone(),
        artifact: store.artifact.clone(),
        role: store.role.clone(),
        fault_policy: store.fault_policy.clone(),
        fault_domain: store.fault_domain,
        resource: store.resource,
        state: store.state.as_str().to_owned(),
        generation: store.generation,
        restart_count: store.restart_count,
    }
}

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

pub(crate) fn integrated_smp_preemption_cleanup_manifest(
    record: &semantic_core::IntegratedSmpPreemptionCleanupRecord,
) -> IntegratedSmpPreemptionCleanupManifest {
    IntegratedSmpPreemptionCleanupManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        stress_run: record.stress_run,
        stress_run_generation: record.stress_run_generation,
        preemption: record.preemption,
        preemption_generation: record.preemption_generation,
        timer_interrupt: record.timer_interrupt,
        timer_interrupt_generation: record.timer_interrupt_generation,
        saved_context: record.saved_context,
        saved_context_generation: record.saved_context_generation,
        remote_preempt: record.remote_preempt,
        remote_preempt_generation: record.remote_preempt_generation,
        activation_cleanup: record.activation_cleanup,
        activation_cleanup_generation: record.activation_cleanup_generation,
        smp_cleanup_quiescence: record.smp_cleanup_quiescence,
        smp_cleanup_quiescence_generation: record.smp_cleanup_quiescence_generation,
        cleanup_store: record.cleanup_store,
        target_store_generation: record.target_store_generation,
        result_store_generation: record.result_store_generation,
        cleanup_activation: record.cleanup_activation,
        cleanup_activation_generation_after: record.cleanup_activation_generation_after,
        hart_count: record.hart_count,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_smp_network_fault_manifest(
    record: &semantic_core::IntegratedSmpNetworkFaultRecord,
) -> IntegratedSmpNetworkFaultManifest {
    IntegratedSmpNetworkFaultManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        network_driver_cleanup: record.network_driver_cleanup,
        network_driver_cleanup_generation: record.network_driver_cleanup_generation,
        smp_stress_run: record.smp_stress_run,
        smp_stress_run_generation: record.smp_stress_run_generation,
        remote_preempt: record.remote_preempt,
        remote_preempt_generation: record.remote_preempt_generation,
        smp_cleanup_quiescence: record.smp_cleanup_quiescence,
        smp_cleanup_quiescence_generation: record.smp_cleanup_quiescence_generation,
        driver_store: record.driver_store,
        driver_store_generation: record.driver_store_generation,
        packet_device: record.packet_device,
        packet_device_generation: record.packet_device_generation,
        adapter: record.adapter,
        adapter_generation: record.adapter_generation,
        backend: contract_object_ref_manifest(record.backend),
        io_cleanup: record.io_cleanup,
        io_cleanup_generation: record.io_cleanup_generation,
        cancelled_socket_wait_count: record.cancelled_socket_wait_count,
        cancelled_wait_token_count: record.cancelled_wait_token_count,
        revoked_packet_capability_count: record.revoked_packet_capability_count,
        hart_count: record.hart_count,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_disk_preempt_fault_manifest(
    record: &semantic_core::IntegratedDiskPreemptFaultRecord,
) -> IntegratedDiskPreemptFaultManifest {
    IntegratedDiskPreemptFaultManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        preemption: record.preemption,
        preemption_generation: record.preemption_generation,
        timer_interrupt: record.timer_interrupt,
        timer_interrupt_generation: record.timer_interrupt_generation,
        block_pending_io_policy: record.block_pending_io_policy,
        block_pending_io_policy_generation: record.block_pending_io_policy_generation,
        block_wait: record.block_wait,
        block_wait_generation: record.block_wait_generation,
        wait: record.wait,
        wait_generation: record.wait_generation,
        block_request: record.block_request,
        block_request_generation: record.block_request_generation,
        retry_request: record.retry_request,
        retry_request_generation: record.retry_request_generation,
        block_device: record.block_device,
        block_device_generation: record.block_device_generation,
        block_range: record.block_range,
        block_range_generation: record.block_range_generation,
        driver_store: record.driver_store,
        driver_store_generation: record.driver_store_generation,
        action: record.action.as_str().to_owned(),
        errno: record.errno,
        preempted_activation: record.preempted_activation,
        preempted_activation_generation_after: record.preempted_activation_generation_after,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_simd_migration_manifest(
    record: &semantic_core::IntegratedSimdMigrationRecord,
) -> IntegratedSimdMigrationManifest {
    IntegratedSimdMigrationManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        activation_migration: record.activation_migration,
        activation_migration_generation: record.activation_migration_generation,
        target_feature_set: record.target_feature_set,
        target_feature_set_generation: record.target_feature_set_generation,
        source_vector_state: contract_object_ref_manifest(record.source_vector_state),
        migrated_vector_state: contract_object_ref_manifest(record.migrated_vector_state),
        activation: record.activation,
        activation_generation_before: record.activation_generation_before,
        activation_generation_after: record.activation_generation_after,
        context: record.context,
        context_generation_after: record.context_generation_after,
        source_hart: u64::from(record.source_hart),
        source_hart_generation: record.source_hart_generation,
        target_hart: u64::from(record.target_hart),
        target_hart_generation: record.target_hart_generation,
        source_queue: record.source_queue,
        source_queue_generation: record.source_queue_generation,
        target_queue: record.target_queue,
        target_queue_generation: record.target_queue_generation,
        simd_abi: record.simd_abi.clone(),
        vector_register_count: record.vector_register_count,
        vector_register_bits: record.vector_register_bits,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_network_disk_io_manifest(
    record: &semantic_core::IntegratedNetworkDiskIoRecord,
) -> IntegratedNetworkDiskIoManifest {
    IntegratedNetworkDiskIoManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        network_benchmark: record.network_benchmark,
        network_benchmark_generation: record.network_benchmark_generation,
        block_benchmark: record.block_benchmark,
        block_benchmark_generation: record.block_benchmark_generation,
        network_owner_store: record.network_owner_store,
        network_owner_store_generation: record.network_owner_store_generation,
        network_adapter: record.network_adapter,
        network_adapter_generation: record.network_adapter_generation,
        packet_device: record.packet_device,
        packet_device_generation: record.packet_device_generation,
        socket: record.socket,
        socket_generation: record.socket_generation,
        block_backend: contract_object_ref_manifest(record.block_backend),
        block_device: record.block_device,
        block_device_generation: record.block_device_generation,
        block_request_queue: record.block_request_queue,
        block_request_queue_generation: record.block_request_queue_generation,
        block_dma_buffer: record.block_dma_buffer,
        block_dma_buffer_generation: record.block_dma_buffer_generation,
        network_sample_bytes: record.network_sample_bytes,
        block_sample_bytes: record.block_sample_bytes,
        network_sample_packets: record.network_sample_packets,
        block_sample_requests: record.block_sample_requests,
        concurrent_window_nanos: record.concurrent_window_nanos,
        combined_throughput_bytes_per_sec: record.combined_throughput_bytes_per_sec,
        max_p99_latency_nanos: record.max_p99_latency_nanos,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_display_scheduler_load_manifest(
    record: &semantic_core::IntegratedDisplaySchedulerLoadRecord,
) -> IntegratedDisplaySchedulerLoadManifest {
    IntegratedDisplaySchedulerLoadManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        framebuffer_benchmark: record.framebuffer_benchmark,
        framebuffer_benchmark_generation: record.framebuffer_benchmark_generation,
        scheduler_decision: record.scheduler_decision,
        scheduler_decision_generation: record.scheduler_decision_generation,
        owner_store: record.owner_store,
        owner_store_generation: record.owner_store_generation,
        owner_task: u64::from(record.owner_task),
        owner_task_generation: record.owner_task_generation,
        queue: record.queue,
        queue_generation: record.queue_generation,
        selected_activation: record.selected_activation,
        selected_activation_generation: record.selected_activation_generation,
        display: record.display,
        display_generation: record.display_generation,
        framebuffer: record.framebuffer,
        framebuffer_generation: record.framebuffer_generation,
        display_capability: record.display_capability,
        display_capability_generation: record.display_capability_generation,
        framebuffer_write: record.framebuffer_write,
        framebuffer_write_generation: record.framebuffer_write_generation,
        framebuffer_flush_region: record.framebuffer_flush_region,
        framebuffer_flush_region_generation: record.framebuffer_flush_region_generation,
        display_event_log: record.display_event_log,
        display_event_log_generation: record.display_event_log_generation,
        sample_frames: record.sample_frames,
        sample_bytes: record.sample_bytes,
        scheduler_load_units: record.scheduler_load_units,
        display_measured_nanos: record.display_measured_nanos,
        scheduler_decided_at_event: record.scheduler_decided_at_event,
        display_recorded_at_event: record.display_recorded_at_event,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_snapshot_io_lease_barrier_manifest(
    record: &semantic_core::IntegratedSnapshotIoLeaseBarrierRecord,
) -> IntegratedSnapshotIoLeaseBarrierManifest {
    IntegratedSnapshotIoLeaseBarrierManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        smp_snapshot_barrier: record.smp_snapshot_barrier,
        smp_snapshot_barrier_generation: record.smp_snapshot_barrier_generation,
        io_cleanup: record.io_cleanup,
        io_cleanup_generation: record.io_cleanup_generation,
        display_snapshot_barrier: record.display_snapshot_barrier,
        display_snapshot_barrier_generation: record.display_snapshot_barrier_generation,
        driver_store: record.driver_store,
        driver_store_generation: record.driver_store_generation,
        device: record.device,
        device_generation: record.device_generation,
        display: record.display,
        display_generation: record.display_generation,
        framebuffer: record.framebuffer,
        framebuffer_generation: record.framebuffer_generation,
        active_dmw_lease_count: record.active_dmw_lease_count,
        in_flight_dma_count: record.in_flight_dma_count,
        raw_dma_binding_count: record.raw_dma_binding_count,
        raw_mmio_binding_count: record.raw_mmio_binding_count,
        active_framebuffer_window_lease_count: record.active_framebuffer_window_lease_count,
        active_framebuffer_mapping_count: record.active_framebuffer_mapping_count,
        dirty_framebuffer_region_count: record.dirty_framebuffer_region_count,
        released_dma_buffers: record.released_dma_buffers,
        released_mmio_regions: record.released_mmio_regions,
        released_irq_lines: record.released_irq_lines,
        released_framebuffer_window_leases: record.released_framebuffer_window_leases,
        revoked_device_capabilities: record.revoked_device_capabilities,
        revoked_display_capabilities: record.revoked_display_capabilities,
        smp_barrier_event: record.smp_barrier_event,
        io_cleanup_completed_event: record.io_cleanup_completed_event,
        display_barrier_event: record.display_barrier_event,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_code_publish_smp_workload_manifest(
    record: &semantic_core::IntegratedCodePublishSmpWorkloadRecord,
) -> IntegratedCodePublishSmpWorkloadManifest {
    IntegratedCodePublishSmpWorkloadManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        smp_stress_run: record.smp_stress_run,
        smp_stress_run_generation: record.smp_stress_run_generation,
        smp_code_publish_barrier: record.smp_code_publish_barrier,
        smp_code_publish_barrier_generation: record.smp_code_publish_barrier_generation,
        publish_rendezvous: record.publish_rendezvous,
        publish_rendezvous_generation: record.publish_rendezvous_generation,
        publish_safe_point: record.publish_safe_point,
        publish_safe_point_generation: record.publish_safe_point_generation,
        hart_count: record.hart_count,
        workload_iterations: record.workload_iterations,
        observed_safe_point_count: record.observed_safe_point_count,
        observed_rendezvous_count: record.observed_rendezvous_count,
        observed_code_publish_barrier_count: record.observed_code_publish_barrier_count,
        code_publish_epoch_before: record.code_publish_epoch_before,
        code_publish_epoch_after: record.code_publish_epoch_after,
        remote_icache_sync_required: record.remote_icache_sync_required,
        code_publish_executed: record.code_publish_executed,
        participant_count: record.participant_count,
        stress_event_log_cursor: record.stress_event_log_cursor,
        barrier_event: record.barrier_event,
        stress_recorded_at_event: record.stress_recorded_at_event,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_display_panic_manifest(
    record: &semantic_core::IntegratedDisplayPanicRecord,
) -> IntegratedDisplayPanicManifest {
    IntegratedDisplayPanicManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        substrate_panic_event: record.substrate_panic_event,
        substrate_panic_epoch: record.substrate_panic_epoch,
        substrate_panic_cpu: record.substrate_panic_cpu,
        substrate_panic_reason_code: record.substrate_panic_reason_code,
        display_panic_last_frame: record.display_panic_last_frame,
        display_panic_last_frame_generation: record.display_panic_last_frame_generation,
        panic_ring_bytes: record.panic_ring_bytes,
        panic_record_max_bytes: record.panic_record_max_bytes,
        panic_ring_oldest_seq: record.panic_ring_oldest_seq,
        panic_ring_newest_seq: record.panic_ring_newest_seq,
        panic_ring_record_count: record.panic_ring_record_count,
        panic_ring_lost_count: record.panic_ring_lost_count,
        jsonl_frame_count: record.jsonl_frame_count,
        contract_panic_summary_records: record.contract_panic_summary_records,
        last_frame_summary_records: record.last_frame_summary_records,
        corrupt_record_count: record.corrupt_record_count,
        truncated_record_count: record.truncated_record_count,
        summary_record_bytes: record.summary_record_bytes,
        raw_framebuffer_bytes_exported: record.raw_framebuffer_bytes_exported,
        panic_path_allocates: record.panic_path_allocates,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn integrated_osctl_trace_replay_manifest(
    record: &semantic_core::IntegratedOsctlTraceReplayRecord,
) -> IntegratedOsctlTraceReplayManifest {
    IntegratedOsctlTraceReplayManifest {
        id: record.id,
        scenario: record.scenario.clone(),
        integrated_smp_preemption_cleanup: record.integrated_smp_preemption_cleanup,
        integrated_smp_preemption_cleanup_generation: record
            .integrated_smp_preemption_cleanup_generation,
        integrated_smp_network_fault: record.integrated_smp_network_fault,
        integrated_smp_network_fault_generation: record.integrated_smp_network_fault_generation,
        integrated_disk_preempt_fault: record.integrated_disk_preempt_fault,
        integrated_disk_preempt_fault_generation: record.integrated_disk_preempt_fault_generation,
        integrated_simd_migration: record.integrated_simd_migration,
        integrated_simd_migration_generation: record.integrated_simd_migration_generation,
        integrated_network_disk_io: record.integrated_network_disk_io,
        integrated_network_disk_io_generation: record.integrated_network_disk_io_generation,
        integrated_display_scheduler_load: record.integrated_display_scheduler_load,
        integrated_display_scheduler_load_generation: record
            .integrated_display_scheduler_load_generation,
        integrated_snapshot_io_lease_barrier: record.integrated_snapshot_io_lease_barrier,
        integrated_snapshot_io_lease_barrier_generation: record
            .integrated_snapshot_io_lease_barrier_generation,
        integrated_code_publish_smp_workload: record.integrated_code_publish_smp_workload,
        integrated_code_publish_smp_workload_generation: record
            .integrated_code_publish_smp_workload_generation,
        integrated_display_panic: record.integrated_display_panic,
        integrated_display_panic_generation: record.integrated_display_panic_generation,
        replay_event_cursor: record.replay_event_cursor,
        stable_view_count: record.stable_view_count,
        historical_edge_count: record.historical_edge_count,
        replayed_root_count: record.replayed_root_count,
        integrated_scenario_count: record.integrated_scenario_count,
        replay_fixture_count: record.replay_fixture_count,
        contract_validation_ok: record.contract_validation_ok,
        replay_validation_ok: record.replay_validation_ok,
        graph_history_ok: record.graph_history_ok,
        roots_match_counts: record.roots_match_counts,
        invariant_checks: record.invariant_checks,
        generation: record.generation,
        state: record.state.as_str().to_owned(),
        recorded_at_event: record.recorded_at_event,
        note: record.note.clone(),
    }
}

pub(crate) fn device_object_manifest(
    device: &semantic_core::DeviceObjectRecord,
) -> DeviceObjectManifest {
    DeviceObjectManifest {
        id: device.id,
        name: device.name.clone(),
        class: device.class.clone(),
        resource: device.resource,
        resource_generation: device.resource_generation,
        backend: device.backend.clone(),
        bus: device.bus.clone(),
        vendor: device.vendor.clone(),
        model: device.model.clone(),
        generation: device.generation,
        state: device.state.as_str().to_owned(),
        recorded_at_event: device.recorded_at_event,
        note: device.note.clone(),
    }
}

pub(crate) fn block_device_object_manifest(
    block_device: &semantic_core::BlockDeviceObjectRecord,
) -> BlockDeviceObjectManifest {
    BlockDeviceObjectManifest {
        id: block_device.id,
        name: block_device.name.clone(),
        device: block_device.device,
        device_generation: block_device.device_generation,
        sector_size: block_device.sector_size,
        sector_count: block_device.sector_count,
        read_only: block_device.read_only,
        max_transfer_sectors: block_device.max_transfer_sectors,
        generation: block_device.generation,
        state: block_device.state.as_str().to_owned(),
        recorded_at_event: block_device.recorded_at_event,
        note: block_device.note.clone(),
    }
}

pub(crate) fn block_range_object_manifest(
    block_range: &semantic_core::BlockRangeObjectRecord,
) -> BlockRangeObjectManifest {
    BlockRangeObjectManifest {
        id: block_range.id,
        block_device: block_range.block_device,
        block_device_generation: block_range.block_device_generation,
        start_sector: block_range.start_sector,
        sector_count: block_range.sector_count,
        byte_offset: block_range.byte_offset,
        byte_len: block_range.byte_len,
        generation: block_range.generation,
        state: block_range.state.as_str().to_owned(),
        recorded_at_event: block_range.recorded_at_event,
        note: block_range.note.clone(),
    }
}

pub(crate) fn block_request_object_manifest(
    request: &semantic_core::BlockRequestObjectRecord,
) -> BlockRequestObjectManifest {
    BlockRequestObjectManifest {
        id: request.id,
        block_device: request.block_device,
        block_device_generation: request.block_device_generation,
        block_range: request.block_range,
        block_range_generation: request.block_range_generation,
        operation: request.operation.as_str().to_owned(),
        sequence: request.sequence,
        byte_len: request.byte_len,
        generation: request.generation,
        state: request.state.as_str().to_owned(),
        recorded_at_event: request.recorded_at_event,
        note: request.note.clone(),
    }
}

pub(crate) fn block_completion_object_manifest(
    completion: &semantic_core::BlockCompletionObjectRecord,
) -> BlockCompletionObjectManifest {
    BlockCompletionObjectManifest {
        id: completion.id,
        block_request: completion.block_request,
        block_request_generation: completion.block_request_generation,
        block_device: completion.block_device,
        block_device_generation: completion.block_device_generation,
        block_range: completion.block_range,
        block_range_generation: completion.block_range_generation,
        sequence: completion.sequence,
        completed_bytes: completion.completed_bytes,
        status: completion.status.as_str().to_owned(),
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        recorded_at_event: completion.recorded_at_event,
        note: completion.note.clone(),
    }
}

pub(crate) fn block_wait_manifest(wait: &semantic_core::BlockWaitRecord) -> BlockWaitManifest {
    BlockWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        block_request: wait.block_request,
        block_request_generation: wait.block_request_generation,
        block_device: wait.block_device,
        block_device_generation: wait.block_device_generation,
        block_range: wait.block_range,
        block_range_generation: wait.block_range_generation,
        operation: wait.operation.as_str().to_owned(),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        completion: wait.completion,
        completion_generation: wait.completion_generation,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn fake_block_backend_object_manifest(
    backend: &semantic_core::FakeBlockBackendObjectRecord,
) -> FakeBlockBackendObjectManifest {
    FakeBlockBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn virtio_blk_backend_object_manifest(
    backend: &semantic_core::VirtioBlkBackendObjectRecord,
) -> VirtioBlkBackendObjectManifest {
    VirtioBlkBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        request_queue_index: backend.request_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn block_read_path_manifest(
    read_path: &semantic_core::BlockReadPathRecord,
) -> BlockReadPathManifest {
    BlockReadPathManifest {
        id: read_path.id,
        backend_kind: read_path.backend.kind.as_str().to_owned(),
        backend: read_path.backend.id,
        backend_generation: read_path.backend.generation,
        block_request: read_path.block_request,
        block_request_generation: read_path.block_request_generation,
        block_completion: read_path.block_completion,
        block_completion_generation: read_path.block_completion_generation,
        block_device: read_path.block_device,
        block_device_generation: read_path.block_device_generation,
        block_range: read_path.block_range,
        block_range_generation: read_path.block_range_generation,
        sequence: read_path.sequence,
        completed_bytes: read_path.completed_bytes,
        data_digest: read_path.data_digest,
        generation: read_path.generation,
        state: read_path.state.as_str().to_owned(),
        recorded_at_event: read_path.recorded_at_event,
        note: read_path.note.clone(),
    }
}

pub(crate) fn block_write_path_manifest(
    write_path: &semantic_core::BlockWritePathRecord,
) -> BlockWritePathManifest {
    BlockWritePathManifest {
        id: write_path.id,
        backend_kind: write_path.backend.kind.as_str().to_owned(),
        backend: write_path.backend.id,
        backend_generation: write_path.backend.generation,
        block_request: write_path.block_request,
        block_request_generation: write_path.block_request_generation,
        block_completion: write_path.block_completion,
        block_completion_generation: write_path.block_completion_generation,
        block_device: write_path.block_device,
        block_device_generation: write_path.block_device_generation,
        block_range: write_path.block_range,
        block_range_generation: write_path.block_range_generation,
        sequence: write_path.sequence,
        completed_bytes: write_path.completed_bytes,
        payload_digest: write_path.payload_digest,
        generation: write_path.generation,
        state: write_path.state.as_str().to_owned(),
        recorded_at_event: write_path.recorded_at_event,
        note: write_path.note.clone(),
    }
}

pub(crate) fn block_request_queue_manifest(
    queue: &semantic_core::BlockRequestQueueRecord,
) -> BlockRequestQueueManifest {
    BlockRequestQueueManifest {
        id: queue.id,
        backend_kind: queue.backend.kind.as_str().to_owned(),
        backend: queue.backend.id,
        backend_generation: queue.backend.generation,
        block_device: queue.block_device,
        block_device_generation: queue.block_device_generation,
        depth: queue.depth,
        entries: queue
            .entries
            .iter()
            .map(|entry| BlockRequestQueueEntryManifest {
                request: entry.request,
                request_generation: entry.request_generation,
                completion: entry.completion,
                completion_generation: entry.completion_generation,
                sequence: entry.sequence,
                operation: entry.operation.as_str().to_owned(),
                byte_len: entry.byte_len,
                state: entry.state.as_str().to_owned(),
            })
            .collect(),
        pending_count: queue.pending_count,
        completed_count: queue.completed_count,
        first_sequence: queue.first_sequence,
        last_sequence: queue.last_sequence,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

pub(crate) fn block_dma_buffer_manifest(
    buffer: &semantic_core::BlockDmaBufferRecord,
) -> BlockDmaBufferManifest {
    BlockDmaBufferManifest {
        id: buffer.id,
        backend_kind: buffer.backend.kind.as_str().to_owned(),
        backend: buffer.backend.id,
        backend_generation: buffer.backend.generation,
        block_request: buffer.block_request,
        block_request_generation: buffer.block_request_generation,
        dma_buffer: buffer.dma_buffer,
        dma_buffer_generation: buffer.dma_buffer_generation,
        block_device: buffer.block_device,
        block_device_generation: buffer.block_device_generation,
        block_range: buffer.block_range,
        block_range_generation: buffer.block_range_generation,
        descriptor: buffer.descriptor,
        descriptor_generation: buffer.descriptor_generation,
        queue: buffer.queue,
        queue_generation: buffer.queue_generation,
        operation: buffer.operation.as_str().to_owned(),
        access: buffer.access.as_str().to_owned(),
        byte_len: buffer.byte_len,
        buffer_len: buffer.buffer_len,
        buffer_digest: buffer.buffer_digest,
        generation: buffer.generation,
        state: buffer.state.as_str().to_owned(),
        recorded_at_event: buffer.recorded_at_event,
        note: buffer.note.clone(),
    }
}

pub(crate) fn block_page_object_manifest(
    page: &semantic_core::BlockPageObjectRecord,
) -> BlockPageObjectManifest {
    BlockPageObjectManifest {
        id: page.id,
        block_dma_buffer: page.block_dma_buffer,
        block_dma_buffer_generation: page.block_dma_buffer_generation,
        block_request: page.block_request,
        block_request_generation: page.block_request_generation,
        block_completion: page.block_completion,
        block_completion_generation: page.block_completion_generation,
        dma_buffer: page.dma_buffer,
        dma_buffer_generation: page.dma_buffer_generation,
        block_device: page.block_device,
        block_device_generation: page.block_device_generation,
        block_range: page.block_range,
        block_range_generation: page.block_range_generation,
        aspace: contract_object_ref_manifest(page.aspace),
        vma_region: contract_object_ref_manifest(page.vma_region),
        page: contract_object_ref_manifest(page.page),
        page_dirty_generation: page.page_dirty_generation,
        page_backing: page.page_backing.as_str().to_owned(),
        cow_state: page.cow_state.as_str().to_owned(),
        page_state: page.page_state.as_str().to_owned(),
        page_offset: page.page_offset,
        byte_len: page.byte_len,
        operation: page.operation.as_str().to_owned(),
        generation: page.generation,
        state: page.state.as_str().to_owned(),
        recorded_at_event: page.recorded_at_event,
        note: page.note.clone(),
    }
}

pub(crate) fn buffer_cache_object_manifest(
    cache: &semantic_core::BufferCacheObjectRecord,
) -> BufferCacheObjectManifest {
    BufferCacheObjectManifest {
        id: cache.id,
        block_page_object: cache.block_page_object,
        block_page_object_generation: cache.block_page_object_generation,
        block_dma_buffer: cache.block_dma_buffer,
        block_dma_buffer_generation: cache.block_dma_buffer_generation,
        block_device: cache.block_device,
        block_device_generation: cache.block_device_generation,
        block_range: cache.block_range,
        block_range_generation: cache.block_range_generation,
        aspace: contract_object_ref_manifest(cache.aspace),
        vma_region: contract_object_ref_manifest(cache.vma_region),
        page: contract_object_ref_manifest(cache.page),
        page_dirty_generation: cache.page_dirty_generation,
        page_offset: cache.page_offset,
        block_offset: cache.block_offset,
        byte_len: cache.byte_len,
        operation: cache.operation.as_str().to_owned(),
        cache_state: cache.cache_state.as_str().to_owned(),
        coherency_epoch: cache.coherency_epoch,
        generation: cache.generation,
        state: cache.state.as_str().to_owned(),
        recorded_at_event: cache.recorded_at_event,
        note: cache.note.clone(),
    }
}

pub(crate) fn file_object_manifest(file: &semantic_core::FileObjectRecord) -> FileObjectManifest {
    FileObjectManifest {
        id: file.id,
        buffer_cache_object: file.buffer_cache_object,
        buffer_cache_object_generation: file.buffer_cache_object_generation,
        block_device: file.block_device,
        block_device_generation: file.block_device_generation,
        block_range: file.block_range,
        block_range_generation: file.block_range_generation,
        page: contract_object_ref_manifest(file.page),
        page_dirty_generation: file.page_dirty_generation,
        namespace: file.namespace.clone(),
        file_key: file.file_key.clone(),
        path: file.path.clone(),
        file_offset: file.file_offset,
        byte_len: file.byte_len,
        file_size: file.file_size,
        content_digest: file.content_digest,
        cache_state: file.cache_state.as_str().to_owned(),
        generation: file.generation,
        state: file.state.as_str().to_owned(),
        recorded_at_event: file.recorded_at_event,
        note: file.note.clone(),
    }
}

pub(crate) fn directory_object_manifest(
    directory: &semantic_core::DirectoryObjectRecord,
) -> DirectoryObjectManifest {
    DirectoryObjectManifest {
        id: directory.id,
        file_object: directory.file_object,
        file_object_generation: directory.file_object_generation,
        namespace: directory.namespace.clone(),
        directory_key: directory.directory_key.clone(),
        directory_path: directory.directory_path.clone(),
        entry_name: directory.entry_name.clone(),
        child_file_key: directory.child_file_key.clone(),
        child_path: directory.child_path.clone(),
        entry_kind: directory.entry_kind.as_str().to_owned(),
        file_size: directory.file_size,
        content_digest: directory.content_digest,
        generation: directory.generation,
        state: directory.state.as_str().to_owned(),
        recorded_at_event: directory.recorded_at_event,
        note: directory.note.clone(),
    }
}

pub(crate) fn fat_adapter_object_manifest(
    adapter: &semantic_core::FatAdapterObjectRecord,
) -> FatAdapterObjectManifest {
    FatAdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_written: adapter.bytes_written,
        bytes_read: adapter.bytes_read,
        write_digest: adapter.write_digest,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn ext4_adapter_object_manifest(
    adapter: &semantic_core::Ext4AdapterObjectRecord,
) -> Ext4AdapterObjectManifest {
    Ext4AdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_read: adapter.bytes_read,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        directory_entries: adapter.directory_entries,
        read_only_enforced: adapter.read_only_enforced,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn file_handle_capability_manifest(
    capability: &semantic_core::FileHandleCapabilityRecord,
) -> FileHandleCapabilityManifest {
    FileHandleCapabilityManifest {
        id: capability.id,
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        file_object: capability.file_object,
        file_object_generation: capability.file_object_generation,
        directory_object: capability.directory_object,
        directory_object_generation: capability.directory_object_generation,
        capability: capability.capability,
        capability_generation: capability.capability_generation,
        handle_slot: capability.handle_slot,
        handle_generation: capability.handle_generation,
        handle_tag: capability.handle_tag,
        operation: capability.operation.clone(),
        file_offset: capability.file_offset,
        byte_len: capability.byte_len,
        content_digest: capability.content_digest,
        generation: capability.generation,
        state: capability.state.as_str().to_owned(),
        recorded_at_event: capability.recorded_at_event,
        note: capability.note.clone(),
    }
}

pub(crate) fn fs_wait_manifest(wait: &semantic_core::FsWaitRecord) -> FsWaitManifest {
    FsWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        file_object: wait.file_object,
        file_object_generation: wait.file_object_generation,
        directory_object: wait.directory_object,
        directory_object_generation: wait.directory_object_generation,
        file_handle_capability: wait.file_handle_capability,
        file_handle_capability_generation: wait.file_handle_capability_generation,
        operation: wait.operation.clone(),
        blocker: contract_object_ref_manifest(wait.blocker),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn block_driver_cleanup_manifest(
    cleanup: &semantic_core::BlockDriverCleanupRecord,
) -> BlockDriverCleanupManifest {
    BlockDriverCleanupManifest {
        id: cleanup.id,
        io_cleanup: cleanup.io_cleanup,
        io_cleanup_generation: cleanup.io_cleanup_generation,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        block_device: cleanup.block_device,
        block_device_generation: cleanup.block_device_generation,
        backend: contract_object_ref_manifest(cleanup.backend),
        cancelled_block_waits: cleanup
            .cancelled_block_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        cancelled_wait_tokens: cleanup
            .cancelled_wait_tokens
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_device_capabilities: cleanup
            .revoked_device_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_dma_buffers: cleanup
            .released_dma_buffers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        reason: cleanup.reason.clone(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn queue_object_manifest(
    queue: &semantic_core::QueueObjectRecord,
) -> QueueObjectManifest {
    QueueObjectManifest {
        id: queue.id,
        name: queue.name.clone(),
        role: queue.role.as_str().to_owned(),
        queue_index: queue.queue_index,
        depth: queue.depth,
        device: queue.device,
        device_generation: queue.device_generation,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

pub(crate) fn descriptor_object_manifest(
    descriptor: &semantic_core::DescriptorObjectRecord,
) -> DescriptorObjectManifest {
    DescriptorObjectManifest {
        id: descriptor.id,
        queue: descriptor.queue,
        queue_generation: descriptor.queue_generation,
        slot: descriptor.slot,
        access: descriptor.access.as_str().to_owned(),
        length: descriptor.length,
        generation: descriptor.generation,
        state: descriptor.state.as_str().to_owned(),
        recorded_at_event: descriptor.recorded_at_event,
        note: descriptor.note.clone(),
    }
}

pub(crate) fn dma_buffer_object_manifest(
    dma_buffer: &semantic_core::DmaBufferObjectRecord,
) -> DmaBufferObjectManifest {
    DmaBufferObjectManifest {
        id: dma_buffer.id,
        descriptor: dma_buffer.descriptor,
        descriptor_generation: dma_buffer.descriptor_generation,
        resource: dma_buffer.resource,
        resource_generation: dma_buffer.resource_generation,
        access: dma_buffer.access.as_str().to_owned(),
        length: dma_buffer.length,
        generation: dma_buffer.generation,
        state: dma_buffer.state.as_str().to_owned(),
        recorded_at_event: dma_buffer.recorded_at_event,
        note: dma_buffer.note.clone(),
    }
}

pub(crate) fn mmio_region_object_manifest(
    mmio_region: &semantic_core::MmioRegionObjectRecord,
) -> MmioRegionObjectManifest {
    MmioRegionObjectManifest {
        id: mmio_region.id,
        device: mmio_region.device,
        device_generation: mmio_region.device_generation,
        resource: mmio_region.resource,
        resource_generation: mmio_region.resource_generation,
        region_index: mmio_region.region_index,
        offset: mmio_region.offset,
        length: mmio_region.length,
        access: mmio_region.access.as_str().to_owned(),
        generation: mmio_region.generation,
        state: mmio_region.state.as_str().to_owned(),
        recorded_at_event: mmio_region.recorded_at_event,
        note: mmio_region.note.clone(),
    }
}

pub(crate) fn irq_line_object_manifest(
    irq_line: &semantic_core::IrqLineObjectRecord,
) -> IrqLineObjectManifest {
    IrqLineObjectManifest {
        id: irq_line.id,
        device: irq_line.device,
        device_generation: irq_line.device_generation,
        resource: irq_line.resource,
        resource_generation: irq_line.resource_generation,
        irq_number: irq_line.irq_number,
        trigger: irq_line.trigger.as_str().to_owned(),
        polarity: irq_line.polarity.as_str().to_owned(),
        generation: irq_line.generation,
        state: irq_line.state.as_str().to_owned(),
        recorded_at_event: irq_line.recorded_at_event,
        note: irq_line.note.clone(),
    }
}

pub(crate) fn irq_event_manifest(irq_event: &semantic_core::IrqEventRecord) -> IrqEventManifest {
    IrqEventManifest {
        id: irq_event.id,
        irq_line: irq_event.irq_line,
        irq_line_generation: irq_event.irq_line_generation,
        device: irq_event.device,
        device_generation: irq_event.device_generation,
        driver_store: irq_event.driver_store,
        driver_store_generation: irq_event.driver_store_generation,
        irq_number: irq_event.irq_number,
        sequence: irq_event.sequence,
        generation: irq_event.generation,
        state: irq_event.state.as_str().to_owned(),
        recorded_at_event: irq_event.recorded_at_event,
        note: irq_event.note.clone(),
    }
}

pub(crate) fn device_capability_manifest(
    device_capability: &semantic_core::DeviceCapabilityRecord,
) -> DeviceCapabilityManifest {
    DeviceCapabilityManifest {
        id: device_capability.id,
        driver_store: device_capability.driver_store,
        driver_store_generation: device_capability.driver_store_generation,
        target: contract_object_ref_manifest(device_capability.target),
        class: device_capability.class.as_str().to_owned(),
        operation: device_capability.operation.clone(),
        capability: device_capability.capability,
        capability_generation: device_capability.capability_generation,
        handle_slot: device_capability.handle_slot,
        handle_generation: device_capability.handle_generation,
        handle_tag: device_capability.handle_tag,
        generation: device_capability.generation,
        state: device_capability.state.as_str().to_owned(),
        recorded_at_event: device_capability.recorded_at_event,
        note: device_capability.note.clone(),
    }
}

pub(crate) fn driver_store_binding_manifest(
    binding: &semantic_core::DriverStoreBindingRecord,
) -> DriverStoreBindingManifest {
    DriverStoreBindingManifest {
        id: binding.id,
        driver_store: binding.driver_store,
        driver_store_generation: binding.driver_store_generation,
        device: binding.device,
        device_generation: binding.device_generation,
        device_capability: binding.device_capability,
        device_capability_generation: binding.device_capability_generation,
        capability: binding.capability,
        capability_generation: binding.capability_generation,
        generation: binding.generation,
        state: binding.state.as_str().to_owned(),
        recorded_at_event: binding.recorded_at_event,
        note: binding.note.clone(),
    }
}

pub(crate) fn io_wait_manifest(io_wait: &semantic_core::IoWaitRecord) -> IoWaitManifest {
    IoWaitManifest {
        id: io_wait.id,
        wait: io_wait.wait,
        wait_generation: io_wait.wait_generation,
        driver_store: io_wait.driver_store,
        driver_store_generation: io_wait.driver_store_generation,
        device: io_wait.device,
        device_generation: io_wait.device_generation,
        driver_binding: io_wait.driver_binding,
        driver_binding_generation: io_wait.driver_binding_generation,
        blocker: contract_object_ref_manifest(io_wait.blocker),
        generation: io_wait.generation,
        state: io_wait.state.as_str().to_owned(),
        created_at_event: io_wait.created_at_event,
        completed_at_event: io_wait.completed_at_event,
        completion_irq_event: io_wait.completion_irq_event,
        completion_irq_event_generation: io_wait.completion_irq_event_generation,
        cancel_reason: io_wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: io_wait.note.clone(),
    }
}

pub(crate) fn io_cleanup_manifest(cleanup: &semantic_core::IoCleanupRecord) -> IoCleanupManifest {
    IoCleanupManifest {
        id: cleanup.id,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        cancelled_io_waits: cleanup
            .cancelled_io_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_device_capabilities: cleanup
            .revoked_device_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_capabilities: cleanup
            .revoked_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_dma_buffers: cleanup
            .released_dma_buffers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_mmio_regions: cleanup
            .released_mmio_regions
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_irq_lines: cleanup
            .released_irq_lines
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| IoCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn io_fault_injection_manifest(
    fault: &semantic_core::IoFaultInjectionRecord,
) -> IoFaultInjectionManifest {
    IoFaultInjectionManifest {
        id: fault.id,
        driver_store: fault.driver_store,
        driver_store_generation: fault.driver_store_generation,
        device: fault.device,
        device_generation: fault.device_generation,
        driver_binding: fault.driver_binding,
        driver_binding_generation: fault.driver_binding_generation,
        target: contract_object_ref_manifest(fault.target),
        cleanup: fault.cleanup,
        cleanup_generation: fault.cleanup_generation,
        generation: fault.generation,
        kind: fault.kind.as_str().to_owned(),
        state: fault.state.as_str().to_owned(),
        injected_at_event: fault.injected_at_event,
        note: fault.note.clone(),
    }
}

pub(crate) fn io_validation_report_manifest(
    report: &semantic_core::IoValidationReportRecord,
) -> IoValidationReportManifest {
    IoValidationReportManifest {
        id: report.id,
        generation: report.generation,
        state: report.state.as_str().to_owned(),
        validated_at_event: report.validated_at_event,
        event_log_cursor: report.event_log_cursor,
        observed_device_count: report.observed_device_count,
        observed_queue_count: report.observed_queue_count,
        observed_descriptor_count: report.observed_descriptor_count,
        observed_dma_buffer_count: report.observed_dma_buffer_count,
        observed_mmio_region_count: report.observed_mmio_region_count,
        observed_irq_line_count: report.observed_irq_line_count,
        observed_irq_event_count: report.observed_irq_event_count,
        observed_device_capability_count: report.observed_device_capability_count,
        observed_driver_binding_count: report.observed_driver_binding_count,
        observed_io_wait_count: report.observed_io_wait_count,
        observed_io_cleanup_count: report.observed_io_cleanup_count,
        observed_io_fault_injection_count: report.observed_io_fault_injection_count,
        violation_count: report.violations.len(),
        violations: report
            .violations
            .iter()
            .map(|violation| IoValidationViolationManifest {
                code: violation.code.as_str().to_owned(),
                subject: contract_object_ref_manifest(violation.subject),
                relation: violation.relation.clone(),
                message: violation.message.clone(),
            })
            .collect(),
        note: report.note.clone(),
    }
}

pub(crate) fn packet_device_object_manifest(
    packet_device: &semantic_core::PacketDeviceObjectRecord,
) -> PacketDeviceObjectManifest {
    PacketDeviceObjectManifest {
        id: packet_device.id,
        name: packet_device.name.clone(),
        device: packet_device.device,
        device_generation: packet_device.device_generation,
        mtu: packet_device.mtu,
        rx_queue_depth: packet_device.rx_queue_depth,
        tx_queue_depth: packet_device.tx_queue_depth,
        mac: packet_device.mac,
        frame_format_version: packet_device.frame_format_version,
        max_payload_len: packet_device.max_payload_len,
        generation: packet_device.generation,
        state: packet_device.state.as_str().to_owned(),
        recorded_at_event: packet_device.recorded_at_event,
        note: packet_device.note.clone(),
    }
}

pub(crate) fn packet_buffer_object_manifest(
    packet_buffer: &semantic_core::PacketBufferObjectRecord,
) -> PacketBufferObjectManifest {
    PacketBufferObjectManifest {
        id: packet_buffer.id,
        packet_device: packet_buffer.packet_device,
        packet_device_generation: packet_buffer.packet_device_generation,
        direction: packet_buffer.direction.as_str().to_owned(),
        frame_format_version: packet_buffer.frame_format_version,
        capacity: packet_buffer.capacity,
        payload_len: packet_buffer.payload_len,
        sequence: packet_buffer.sequence,
        generation: packet_buffer.generation,
        state: packet_buffer.state.as_str().to_owned(),
        recorded_at_event: packet_buffer.recorded_at_event,
        note: packet_buffer.note.clone(),
    }
}

pub(crate) fn packet_queue_object_manifest(
    packet_queue: &semantic_core::PacketQueueObjectRecord,
) -> PacketQueueObjectManifest {
    PacketQueueObjectManifest {
        id: packet_queue.id,
        name: packet_queue.name.clone(),
        packet_device: packet_queue.packet_device,
        packet_device_generation: packet_queue.packet_device_generation,
        role: packet_queue.role.as_str().to_owned(),
        queue_index: packet_queue.queue_index,
        depth: packet_queue.depth,
        generation: packet_queue.generation,
        state: packet_queue.state.as_str().to_owned(),
        recorded_at_event: packet_queue.recorded_at_event,
        note: packet_queue.note.clone(),
    }
}

pub(crate) fn packet_descriptor_object_manifest(
    packet_descriptor: &semantic_core::PacketDescriptorObjectRecord,
) -> PacketDescriptorObjectManifest {
    PacketDescriptorObjectManifest {
        id: packet_descriptor.id,
        packet_queue: packet_descriptor.packet_queue,
        packet_queue_generation: packet_descriptor.packet_queue_generation,
        packet_buffer: packet_descriptor.packet_buffer,
        packet_buffer_generation: packet_descriptor.packet_buffer_generation,
        slot: packet_descriptor.slot,
        length: packet_descriptor.length,
        generation: packet_descriptor.generation,
        state: packet_descriptor.state.as_str().to_owned(),
        recorded_at_event: packet_descriptor.recorded_at_event,
        note: packet_descriptor.note.clone(),
    }
}

pub(crate) fn fake_net_backend_object_manifest(
    backend: &semantic_core::FakeNetBackendObjectRecord,
) -> FakeNetBackendObjectManifest {
    FakeNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn virtio_net_backend_object_manifest(
    backend: &semantic_core::VirtioNetBackendObjectRecord,
) -> VirtioNetBackendObjectManifest {
    VirtioNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        rx_queue_index: backend.rx_queue_index,
        tx_queue_index: backend.tx_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn network_rx_interrupt_manifest(
    rx_interrupt: &semantic_core::NetworkRxInterruptRecord,
) -> NetworkRxInterruptManifest {
    NetworkRxInterruptManifest {
        id: rx_interrupt.id,
        virtio_net_backend: rx_interrupt.virtio_net_backend,
        virtio_net_backend_generation: rx_interrupt.virtio_net_backend_generation,
        irq_event: rx_interrupt.irq_event,
        irq_event_generation: rx_interrupt.irq_event_generation,
        packet_device: rx_interrupt.packet_device,
        packet_device_generation: rx_interrupt.packet_device_generation,
        rx_queue: rx_interrupt.rx_queue,
        rx_queue_generation: rx_interrupt.rx_queue_generation,
        ready_descriptors: rx_interrupt.ready_descriptors,
        sequence: rx_interrupt.sequence,
        generation: rx_interrupt.generation,
        state: rx_interrupt.state.as_str().to_owned(),
        recorded_at_event: rx_interrupt.recorded_at_event,
        note: rx_interrupt.note.clone(),
    }
}

pub(crate) fn network_rx_wait_resolution_manifest(
    resolution: &semantic_core::NetworkRxWaitResolutionRecord,
) -> NetworkRxWaitResolutionManifest {
    NetworkRxWaitResolutionManifest {
        id: resolution.id,
        io_wait: resolution.io_wait,
        io_wait_generation: resolution.io_wait_generation,
        wait: resolution.wait,
        wait_generation: resolution.wait_generation,
        rx_interrupt: resolution.rx_interrupt,
        rx_interrupt_generation: resolution.rx_interrupt_generation,
        irq_event: resolution.irq_event,
        irq_event_generation: resolution.irq_event_generation,
        packet_device: resolution.packet_device,
        packet_device_generation: resolution.packet_device_generation,
        rx_queue: resolution.rx_queue,
        rx_queue_generation: resolution.rx_queue_generation,
        ready_descriptors: resolution.ready_descriptors,
        sequence: resolution.sequence,
        generation: resolution.generation,
        state: resolution.state.as_str().to_owned(),
        resolved_at_event: resolution.resolved_at_event,
        note: resolution.note.clone(),
    }
}

pub(crate) fn network_tx_capability_gate_manifest(
    gate: &semantic_core::NetworkTxCapabilityGateRecord,
) -> NetworkTxCapabilityGateManifest {
    NetworkTxCapabilityGateManifest {
        id: gate.id,
        driver_store: gate.driver_store,
        driver_store_generation: gate.driver_store_generation,
        packet_device: gate.packet_device,
        packet_device_generation: gate.packet_device_generation,
        tx_queue: gate.tx_queue,
        tx_queue_generation: gate.tx_queue_generation,
        packet_descriptor: gate.packet_descriptor,
        packet_descriptor_generation: gate.packet_descriptor_generation,
        packet_buffer: gate.packet_buffer,
        packet_buffer_generation: gate.packet_buffer_generation,
        device_capability: gate.device_capability,
        device_capability_generation: gate.device_capability_generation,
        capability: gate.capability,
        capability_generation: gate.capability_generation,
        handle_slot: gate.handle_slot,
        handle_generation: gate.handle_generation,
        handle_tag: gate.handle_tag,
        operation: gate.operation.clone(),
        byte_len: gate.byte_len,
        sequence: gate.sequence,
        generation: gate.generation,
        state: gate.state.as_str().to_owned(),
        recorded_at_event: gate.recorded_at_event,
        note: gate.note.clone(),
    }
}

pub(crate) fn network_tx_completion_manifest(
    completion: &semantic_core::NetworkTxCompletionRecord,
) -> NetworkTxCompletionManifest {
    NetworkTxCompletionManifest {
        id: completion.id,
        tx_gate: completion.tx_gate,
        tx_gate_generation: completion.tx_gate_generation,
        backend_kind: completion.backend.kind.as_str().to_owned(),
        backend: completion.backend.id,
        backend_generation: completion.backend.generation,
        driver_store: completion.driver_store,
        driver_store_generation: completion.driver_store_generation,
        packet_device: completion.packet_device,
        packet_device_generation: completion.packet_device_generation,
        tx_queue: completion.tx_queue,
        tx_queue_generation: completion.tx_queue_generation,
        packet_descriptor: completion.packet_descriptor,
        packet_descriptor_generation: completion.packet_descriptor_generation,
        packet_buffer: completion.packet_buffer,
        packet_buffer_generation: completion.packet_buffer_generation,
        byte_len: completion.byte_len,
        sequence: completion.sequence,
        completion_sequence: completion.completion_sequence,
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        completed_at_event: completion.completed_at_event,
        note: completion.note.clone(),
    }
}

pub(crate) fn network_stack_adapter_manifest(
    adapter: &semantic_core::NetworkStackAdapterRecord,
) -> NetworkStackAdapterManifest {
    NetworkStackAdapterManifest {
        id: adapter.id,
        implementation: adapter.implementation.clone(),
        implementation_version: adapter.implementation_version.clone(),
        profile: adapter.profile.clone(),
        medium: adapter.medium.clone(),
        backend_kind: adapter.backend.kind.as_str().to_owned(),
        backend: adapter.backend.id,
        backend_generation: adapter.backend.generation,
        packet_device: adapter.packet_device,
        packet_device_generation: adapter.packet_device_generation,
        rx_queue: adapter.rx_queue,
        rx_queue_generation: adapter.rx_queue_generation,
        tx_queue: adapter.tx_queue,
        tx_queue_generation: adapter.tx_queue_generation,
        mac: adapter.mac,
        ipv4_addr: adapter.ipv4_addr,
        ipv4_prefix_len: adapter.ipv4_prefix_len,
        mtu: adapter.mtu,
        rx_queue_depth: adapter.rx_queue_depth,
        tx_queue_depth: adapter.tx_queue_depth,
        max_payload_len: adapter.max_payload_len,
        socket_capacity: adapter.socket_capacity,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn socket_object_manifest(
    socket: &semantic_core::SocketObjectRecord,
) -> SocketObjectManifest {
    SocketObjectManifest {
        id: socket.id,
        adapter: socket.adapter,
        adapter_generation: socket.adapter_generation,
        owner_store: socket.owner_store,
        owner_store_generation: socket.owner_store_generation,
        domain: socket.domain,
        socket_type: socket.socket_type,
        protocol: socket.protocol,
        canonical_protocol: socket.canonical_protocol,
        family: socket.family.clone(),
        transport: socket.transport.clone(),
        generation: socket.generation,
        state: socket.state.as_str().to_owned(),
        created_at_event: socket.created_at_event,
        note: socket.note.clone(),
    }
}

pub(crate) fn endpoint_object_manifest(
    endpoint: &semantic_core::EndpointObjectRecord,
) -> EndpointObjectManifest {
    EndpointObjectManifest {
        id: endpoint.id,
        socket: endpoint.socket,
        socket_generation: endpoint.socket_generation,
        adapter: endpoint.adapter,
        adapter_generation: endpoint.adapter_generation,
        owner_store: endpoint.owner_store,
        owner_store_generation: endpoint.owner_store_generation,
        family: endpoint.family.clone(),
        transport: endpoint.transport.clone(),
        local_addr: endpoint.local_addr,
        local_port: endpoint.local_port,
        remote_addr: endpoint.remote_addr,
        remote_port: endpoint.remote_port,
        generation: endpoint.generation,
        state: endpoint.state.as_str().to_owned(),
        created_at_event: endpoint.created_at_event,
        note: endpoint.note.clone(),
    }
}

pub(crate) fn socket_operation_manifest(
    operation: &semantic_core::SocketOperationRecord,
) -> SocketOperationManifest {
    SocketOperationManifest {
        id: operation.id,
        endpoint: operation.endpoint,
        endpoint_generation: operation.endpoint_generation,
        socket: operation.socket,
        socket_generation: operation.socket_generation,
        adapter: operation.adapter,
        adapter_generation: operation.adapter_generation,
        owner_store: operation.owner_store,
        owner_store_generation: operation.owner_store_generation,
        operation: operation.operation.as_str().to_owned(),
        local_addr: operation.local_addr,
        local_port: operation.local_port,
        remote_addr: operation.remote_addr,
        remote_port: operation.remote_port,
        backlog: operation.backlog,
        byte_len: operation.byte_len,
        sequence: operation.sequence,
        generation: operation.generation,
        state: operation.state.as_str().to_owned(),
        recorded_at_event: operation.recorded_at_event,
        note: operation.note.clone(),
    }
}

pub(crate) fn socket_wait_manifest(wait: &semantic_core::SocketWaitRecord) -> SocketWaitManifest {
    SocketWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        endpoint: wait.endpoint,
        endpoint_generation: wait.endpoint_generation,
        socket: wait.socket,
        socket_generation: wait.socket_generation,
        adapter: wait.adapter,
        adapter_generation: wait.adapter_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        wait_kind: wait.wait_kind.as_str().to_owned(),
        blocker: contract_object_ref_manifest(wait.blocker),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        ready_sequence: wait.ready_sequence,
        byte_len: wait.byte_len,
        note: wait.note.clone(),
    }
}

pub(crate) fn network_backpressure_manifest(
    backpressure: &semantic_core::NetworkBackpressureRecord,
) -> NetworkBackpressureManifest {
    NetworkBackpressureManifest {
        id: backpressure.id,
        adapter: backpressure.adapter,
        adapter_generation: backpressure.adapter_generation,
        packet_device: backpressure.packet_device,
        packet_device_generation: backpressure.packet_device_generation,
        packet_queue: backpressure.packet_queue,
        packet_queue_generation: backpressure.packet_queue_generation,
        endpoint: backpressure.endpoint,
        endpoint_generation: backpressure.endpoint_generation,
        socket: backpressure.socket,
        socket_generation: backpressure.socket_generation,
        owner_store: backpressure.owner_store,
        owner_store_generation: backpressure.owner_store_generation,
        direction: backpressure.direction.as_str().to_owned(),
        reason: backpressure.reason.as_str().to_owned(),
        action: backpressure.action.as_str().to_owned(),
        queue_depth: backpressure.queue_depth,
        queue_limit: backpressure.queue_limit,
        dropped_packets: backpressure.dropped_packets,
        dropped_bytes: backpressure.dropped_bytes,
        sequence: backpressure.sequence,
        generation: backpressure.generation,
        state: backpressure.state.as_str().to_owned(),
        recorded_at_event: backpressure.recorded_at_event,
        note: backpressure.note.clone(),
    }
}

pub(crate) fn network_driver_cleanup_manifest(
    cleanup: &semantic_core::NetworkDriverCleanupRecord,
) -> NetworkDriverCleanupManifest {
    NetworkDriverCleanupManifest {
        id: cleanup.id,
        io_cleanup: cleanup.io_cleanup,
        io_cleanup_generation: cleanup.io_cleanup_generation,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        packet_device: cleanup.packet_device,
        packet_device_generation: cleanup.packet_device_generation,
        adapter: cleanup.adapter,
        adapter_generation: cleanup.adapter_generation,
        backend: contract_object_ref_manifest(cleanup.backend),
        cancelled_socket_waits: cleanup
            .cancelled_socket_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        cancelled_wait_tokens: cleanup
            .cancelled_wait_tokens
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_packet_capabilities: cleanup
            .revoked_packet_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        reason: cleanup.reason.clone(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn network_generation_audit_manifest(
    audit: &semantic_core::NetworkGenerationAuditRecord,
) -> NetworkGenerationAuditManifest {
    NetworkGenerationAuditManifest {
        id: audit.id,
        adapter: audit.adapter,
        adapter_generation: audit.adapter_generation,
        packet_device: audit.packet_device,
        packet_device_generation: audit.packet_device_generation,
        packet_queue: audit.packet_queue,
        packet_queue_generation: audit.packet_queue_generation,
        packet_descriptor: audit.packet_descriptor,
        packet_descriptor_generation: audit.packet_descriptor_generation,
        packet_buffer: audit.packet_buffer,
        packet_buffer_generation: audit.packet_buffer_generation,
        dma_buffer: contract_object_ref_manifest(audit.dma_buffer),
        device_capability: contract_object_ref_manifest(audit.device_capability),
        rejected_packet_generation_probes: audit.rejected_packet_generation_probes,
        rejected_dma_generation_probes: audit.rejected_dma_generation_probes,
        generation: audit.generation,
        state: audit.state.as_str().to_owned(),
        recorded_at_event: audit.recorded_at_event,
        note: audit.note.clone(),
    }
}

pub(crate) fn network_fault_injection_manifest(
    injection: &semantic_core::NetworkFaultInjectionRecord,
) -> NetworkFaultInjectionManifest {
    NetworkFaultInjectionManifest {
        id: injection.id,
        adapter: injection.adapter,
        adapter_generation: injection.adapter_generation,
        packet_device: injection.packet_device,
        packet_device_generation: injection.packet_device_generation,
        packet_queue: injection.packet_queue,
        packet_queue_generation: injection.packet_queue_generation,
        packet_descriptor: injection.packet_descriptor,
        packet_descriptor_generation: injection.packet_descriptor_generation,
        packet_buffer: injection.packet_buffer,
        packet_buffer_generation: injection.packet_buffer_generation,
        endpoint: injection.endpoint,
        endpoint_generation: injection.endpoint_generation,
        socket: injection.socket,
        socket_generation: injection.socket_generation,
        owner_store: injection.owner_store,
        owner_store_generation: injection.owner_store_generation,
        direction: injection.direction.as_str().to_owned(),
        kind: injection.kind.as_str().to_owned(),
        effect: injection.effect.as_str().to_owned(),
        injected_packets: injection.injected_packets,
        dropped_packets: injection.dropped_packets,
        error_packets: injection.error_packets,
        error_code: injection.error_code.clone(),
        sequence: injection.sequence,
        generation: injection.generation,
        state: injection.state.as_str().to_owned(),
        recorded_at_event: injection.recorded_at_event,
        note: injection.note.clone(),
    }
}

pub(crate) fn network_benchmark_manifest(
    benchmark: &semantic_core::NetworkBenchmarkRecord,
) -> NetworkBenchmarkManifest {
    NetworkBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        tx_queue: benchmark.tx_queue,
        tx_queue_generation: benchmark.tx_queue_generation,
        rx_queue: benchmark.rx_queue,
        rx_queue_generation: benchmark.rx_queue_generation,
        tx_completion: benchmark.tx_completion,
        tx_completion_generation: benchmark.tx_completion_generation,
        rx_wait_resolution: benchmark.rx_wait_resolution,
        rx_wait_resolution_generation: benchmark.rx_wait_resolution_generation,
        endpoint: benchmark.endpoint,
        endpoint_generation: benchmark.endpoint_generation,
        socket: benchmark.socket,
        socket_generation: benchmark.socket_generation,
        owner_store: benchmark.owner_store,
        owner_store_generation: benchmark.owner_store_generation,
        backpressure: benchmark.backpressure,
        backpressure_generation: benchmark.backpressure_generation,
        sample_packets: benchmark.sample_packets,
        sample_bytes: benchmark.sample_bytes,
        tx_completed_packets: benchmark.tx_completed_packets,
        rx_resolved_packets: benchmark.rx_resolved_packets,
        dropped_packets: benchmark.dropped_packets,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn network_recovery_benchmark_manifest(
    benchmark: &semantic_core::NetworkRecoveryBenchmarkRecord,
) -> NetworkRecoveryBenchmarkManifest {
    NetworkRecoveryBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        cleanup: benchmark.cleanup,
        cleanup_generation: benchmark.cleanup_generation,
        io_cleanup: benchmark.io_cleanup,
        io_cleanup_generation: benchmark.io_cleanup_generation,
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        backend: contract_object_ref_manifest(benchmark.backend),
        driver_store: benchmark.driver_store,
        driver_store_generation: benchmark.driver_store_generation,
        fault_injection: benchmark.fault_injection,
        fault_injection_generation: benchmark.fault_injection_generation,
        recovery_start_event: benchmark.recovery_start_event,
        recovery_complete_event: benchmark.recovery_complete_event,
        cancelled_socket_waits: benchmark.cancelled_socket_waits,
        revoked_packet_capabilities: benchmark.revoked_packet_capabilities,
        recovery_nanos: benchmark.recovery_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn block_pending_io_policy_manifest(
    policy: &semantic_core::BlockPendingIoPolicyRecord,
) -> BlockPendingIoPolicyManifest {
    BlockPendingIoPolicyManifest {
        id: policy.id,
        block_wait: policy.block_wait,
        block_wait_generation: policy.block_wait_generation,
        wait: policy.wait,
        wait_generation: policy.wait_generation,
        block_request: policy.block_request,
        block_request_generation: policy.block_request_generation,
        retry_request: policy.retry_request,
        retry_request_generation: policy.retry_request_generation,
        block_device: policy.block_device,
        block_device_generation: policy.block_device_generation,
        block_range: policy.block_range,
        block_range_generation: policy.block_range_generation,
        operation: policy.operation.as_str().to_owned(),
        sequence: policy.sequence,
        byte_len: policy.byte_len,
        action: policy.action.as_str().to_owned(),
        errno: policy.errno,
        retry_attempt: policy.retry_attempt,
        max_retries: policy.max_retries,
        generation: policy.generation,
        state: policy.state.as_str().to_owned(),
        recorded_at_event: policy.recorded_at_event,
        note: policy.note.clone(),
    }
}

pub(crate) fn block_request_generation_audit_manifest(
    audit: &semantic_core::BlockRequestGenerationAuditRecord,
) -> BlockRequestGenerationAuditManifest {
    BlockRequestGenerationAuditManifest {
        id: audit.id,
        block_device: audit.block_device,
        block_device_generation: audit.block_device_generation,
        block_range: audit.block_range,
        block_range_generation: audit.block_range_generation,
        block_request: audit.block_request,
        block_request_generation: audit.block_request_generation,
        backend: contract_object_ref_manifest(audit.backend),
        dma_buffer: contract_object_ref_manifest(audit.dma_buffer),
        rejected_completion_generation_probes: audit.rejected_completion_generation_probes,
        rejected_wait_generation_probes: audit.rejected_wait_generation_probes,
        rejected_dma_generation_probes: audit.rejected_dma_generation_probes,
        rejected_queue_generation_probes: audit.rejected_queue_generation_probes,
        generation: audit.generation,
        state: audit.state.as_str().to_owned(),
        recorded_at_event: audit.recorded_at_event,
        note: audit.note.clone(),
    }
}

pub(crate) fn block_benchmark_manifest(
    benchmark: &semantic_core::BlockBenchmarkRecord,
) -> BlockBenchmarkManifest {
    BlockBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        backend: contract_object_ref_manifest(benchmark.backend),
        block_device: benchmark.block_device,
        block_device_generation: benchmark.block_device_generation,
        block_range: benchmark.block_range,
        block_range_generation: benchmark.block_range_generation,
        read_path: benchmark.read_path,
        read_path_generation: benchmark.read_path_generation,
        write_path: benchmark.write_path,
        write_path_generation: benchmark.write_path_generation,
        request_queue: benchmark.request_queue,
        request_queue_generation: benchmark.request_queue_generation,
        block_dma_buffer: benchmark.block_dma_buffer,
        block_dma_buffer_generation: benchmark.block_dma_buffer_generation,
        sample_requests: benchmark.sample_requests,
        sample_bytes: benchmark.sample_bytes,
        read_completed_requests: benchmark.read_completed_requests,
        write_completed_requests: benchmark.write_completed_requests,
        queue_completed_requests: benchmark.queue_completed_requests,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        iops: benchmark.iops,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn block_recovery_benchmark_manifest(
    benchmark: &semantic_core::BlockRecoveryBenchmarkRecord,
) -> BlockRecoveryBenchmarkManifest {
    BlockRecoveryBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        cleanup: benchmark.cleanup,
        cleanup_generation: benchmark.cleanup_generation,
        io_cleanup: benchmark.io_cleanup,
        io_cleanup_generation: benchmark.io_cleanup_generation,
        backend: contract_object_ref_manifest(benchmark.backend),
        block_device: benchmark.block_device,
        block_device_generation: benchmark.block_device_generation,
        driver_store: benchmark.driver_store,
        driver_store_generation: benchmark.driver_store_generation,
        device: benchmark.device,
        device_generation: benchmark.device_generation,
        driver_binding: benchmark.driver_binding,
        driver_binding_generation: benchmark.driver_binding_generation,
        recovery_start_event: benchmark.recovery_start_event,
        recovery_complete_event: benchmark.recovery_complete_event,
        cancelled_block_waits: benchmark.cancelled_block_waits,
        cancelled_wait_tokens: benchmark.cancelled_wait_tokens,
        released_dma_buffers: benchmark.released_dma_buffers,
        revoked_device_capabilities: benchmark.revoked_device_capabilities,
        recovery_nanos: benchmark.recovery_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn target_feature_set_manifest(
    feature: &semantic_core::TargetFeatureSetRecord,
) -> TargetFeatureSetManifest {
    TargetFeatureSetManifest {
        id: feature.id,
        name: feature.name.clone(),
        discovery_source: feature.discovery_source.clone(),
        target_profile: feature.target_profile.clone(),
        target_arch: feature.target_arch.clone(),
        base_isa: feature.base_isa.clone(),
        simd_abi: feature.simd_abi.clone(),
        simd_supported: feature.simd_supported,
        vector_register_count: feature.vector_register_count,
        vector_register_bits: feature.vector_register_bits,
        scalar_fallback: feature.scalar_fallback,
        unsupported_reason: feature.unsupported_reason.clone(),
        generation: feature.generation,
        state: feature.state.as_str().to_owned(),
        recorded_at_event: feature.recorded_at_event,
        note: feature.note.clone(),
    }
}

pub(crate) fn vector_state_manifest(
    vector_state: &semantic_core::VectorStateRecord,
) -> VectorStateManifest {
    VectorStateManifest {
        id: vector_state.id,
        owner_activation: contract_object_ref_manifest(vector_state.owner_activation),
        owner_store: contract_object_ref_manifest(vector_state.owner_store),
        code_object: contract_object_ref_manifest(vector_state.code_object),
        target_feature_set: contract_object_ref_manifest(vector_state.target_feature_set),
        simd_abi: vector_state.simd_abi.clone(),
        vector_register_count: vector_state.vector_register_count,
        vector_register_bits: vector_state.vector_register_bits,
        register_bytes: vector_state.register_bytes,
        generation: vector_state.generation,
        state: vector_state.state.as_str().to_owned(),
        recorded_at_event: vector_state.recorded_at_event,
        note: vector_state.note.clone(),
    }
}

pub(crate) fn simd_fault_injection_manifest(
    injection: &semantic_core::SimdFaultInjectionRecord,
) -> SimdFaultInjectionManifest {
    SimdFaultInjectionManifest {
        id: injection.id,
        activation: contract_object_ref_manifest(injection.activation),
        code_object: contract_object_ref_manifest(injection.code_object),
        trap: contract_object_ref_manifest(injection.trap),
        target_feature_set: contract_object_ref_manifest(injection.target_feature_set),
        vector_state: injection.vector_state.map(contract_object_ref_manifest),
        kind: injection.kind.as_str().to_owned(),
        effect: injection.effect.as_str().to_owned(),
        required_abi: injection.required_abi.clone(),
        vector_register_count: injection.vector_register_count,
        vector_register_bits: injection.vector_register_bits,
        injected_faults: injection.injected_faults,
        generation: injection.generation,
        state: injection.state.as_str().to_owned(),
        recorded_at_event: injection.recorded_at_event,
        note: injection.note.clone(),
    }
}

pub(crate) fn simd_benchmark_manifest(
    benchmark: &semantic_core::SimdBenchmarkRecord,
) -> SimdBenchmarkManifest {
    SimdBenchmarkManifest {
        id: benchmark.id,
        target_feature_set: contract_object_ref_manifest(benchmark.target_feature_set),
        scalar_code_object: contract_object_ref_manifest(benchmark.scalar_code_object),
        vector_code_object: contract_object_ref_manifest(benchmark.vector_code_object),
        simd_abi: benchmark.simd_abi.clone(),
        vector_register_count: benchmark.vector_register_count,
        vector_register_bits: benchmark.vector_register_bits,
        workload_units: benchmark.workload_units,
        scalar_nanos: benchmark.scalar_nanos,
        vector_nanos: benchmark.vector_nanos,
        speedup_milli: benchmark.speedup_milli,
        context_overhead_nanos: benchmark.context_overhead_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn simd_context_switch_benchmark_manifest(
    benchmark: &semantic_core::SimdContextSwitchBenchmarkRecord,
) -> SimdContextSwitchBenchmarkManifest {
    SimdContextSwitchBenchmarkManifest {
        id: benchmark.id,
        preemption: contract_object_ref_manifest(benchmark.preemption),
        activation_resume: contract_object_ref_manifest(benchmark.activation_resume),
        saved_vector_state: contract_object_ref_manifest(benchmark.saved_vector_state),
        restored_vector_state: contract_object_ref_manifest(benchmark.restored_vector_state),
        target_feature_set: contract_object_ref_manifest(benchmark.target_feature_set),
        simd_abi: benchmark.simd_abi.clone(),
        vector_register_count: benchmark.vector_register_count,
        vector_register_bits: benchmark.vector_register_bits,
        sample_count: benchmark.sample_count,
        scalar_context_switch_nanos: benchmark.scalar_context_switch_nanos,
        vector_context_switch_nanos: benchmark.vector_context_switch_nanos,
        overhead_nanos: benchmark.overhead_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn framebuffer_object_manifest(
    framebuffer: &semantic_core::FramebufferObjectRecord,
) -> FramebufferObjectManifest {
    FramebufferObjectManifest {
        id: framebuffer.id,
        name: framebuffer.name.clone(),
        resource: framebuffer.resource,
        resource_generation: framebuffer.resource_generation,
        width: framebuffer.width,
        height: framebuffer.height,
        stride_bytes: framebuffer.stride_bytes,
        pixel_format: framebuffer.pixel_format.clone(),
        byte_len: framebuffer.byte_len,
        generation: framebuffer.generation,
        state: framebuffer.state.as_str().to_owned(),
        recorded_at_event: framebuffer.recorded_at_event,
        note: framebuffer.note.clone(),
    }
}

pub(crate) fn display_object_manifest(
    display: &semantic_core::DisplayObjectRecord,
) -> DisplayObjectManifest {
    DisplayObjectManifest {
        id: display.id,
        name: display.name.clone(),
        framebuffer: display.framebuffer,
        framebuffer_generation: display.framebuffer_generation,
        mode_name: display.mode_name.clone(),
        width: display.width,
        height: display.height,
        refresh_millihz: display.refresh_millihz,
        generation: display.generation,
        state: display.state.as_str().to_owned(),
        recorded_at_event: display.recorded_at_event,
        note: display.note.clone(),
    }
}

pub(crate) fn display_capability_manifest(
    capability: &semantic_core::DisplayCapabilityRecord,
) -> DisplayCapabilityManifest {
    DisplayCapabilityManifest {
        id: capability.id,
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        display: capability.display,
        display_generation: capability.display_generation,
        framebuffer: capability.framebuffer,
        framebuffer_generation: capability.framebuffer_generation,
        capability: capability.capability,
        capability_generation: capability.capability_generation,
        handle_slot: capability.handle_slot,
        handle_generation: capability.handle_generation,
        handle_tag: capability.handle_tag,
        operations: capability.operations.clone(),
        generation: capability.generation,
        state: capability.state.as_str().to_owned(),
        recorded_at_event: capability.recorded_at_event,
        note: capability.note.clone(),
    }
}

pub(crate) fn framebuffer_window_lease_manifest(
    lease: &semantic_core::FramebufferWindowLeaseRecord,
) -> FramebufferWindowLeaseManifest {
    FramebufferWindowLeaseManifest {
        id: lease.id,
        owner_store: lease.owner_store,
        owner_store_generation: lease.owner_store_generation,
        display_capability: lease.display_capability,
        display_capability_generation: lease.display_capability_generation,
        display: lease.display,
        display_generation: lease.display_generation,
        framebuffer: lease.framebuffer,
        framebuffer_generation: lease.framebuffer_generation,
        x: lease.x,
        y: lease.y,
        width: lease.width,
        height: lease.height,
        byte_offset: lease.byte_offset,
        byte_len: lease.byte_len,
        access: lease.access.clone(),
        generation: lease.generation,
        state: lease.state.as_str().to_owned(),
        recorded_at_event: lease.recorded_at_event,
        note: lease.note.clone(),
    }
}

pub(crate) fn framebuffer_mapping_manifest(
    mapping: &semantic_core::FramebufferMappingRecord,
) -> FramebufferMappingManifest {
    FramebufferMappingManifest {
        id: mapping.id,
        owner_store: mapping.owner_store,
        owner_store_generation: mapping.owner_store_generation,
        framebuffer_window_lease: mapping.framebuffer_window_lease,
        framebuffer_window_lease_generation: mapping.framebuffer_window_lease_generation,
        display_capability: mapping.display_capability,
        display_capability_generation: mapping.display_capability_generation,
        display: mapping.display,
        display_generation: mapping.display_generation,
        framebuffer: mapping.framebuffer,
        framebuffer_generation: mapping.framebuffer_generation,
        map_handle_slot: mapping.map_handle_slot,
        map_handle_generation: mapping.map_handle_generation,
        map_handle_tag: mapping.map_handle_tag,
        x: mapping.x,
        y: mapping.y,
        width: mapping.width,
        height: mapping.height,
        byte_offset: mapping.byte_offset,
        byte_len: mapping.byte_len,
        access: mapping.access.clone(),
        mode: mapping.mode.clone(),
        generation: mapping.generation,
        state: mapping.state.as_str().to_owned(),
        recorded_at_event: mapping.recorded_at_event,
        note: mapping.note.clone(),
    }
}

pub(crate) fn framebuffer_write_manifest(
    write: &semantic_core::FramebufferWriteRecord,
) -> FramebufferWriteManifest {
    FramebufferWriteManifest {
        id: write.id,
        owner_store: write.owner_store,
        owner_store_generation: write.owner_store_generation,
        framebuffer_mapping: write.framebuffer_mapping,
        framebuffer_mapping_generation: write.framebuffer_mapping_generation,
        framebuffer_window_lease: write.framebuffer_window_lease,
        framebuffer_window_lease_generation: write.framebuffer_window_lease_generation,
        display_capability: write.display_capability,
        display_capability_generation: write.display_capability_generation,
        display: write.display,
        display_generation: write.display_generation,
        framebuffer: write.framebuffer,
        framebuffer_generation: write.framebuffer_generation,
        map_handle_slot: write.map_handle_slot,
        map_handle_generation: write.map_handle_generation,
        map_handle_tag: write.map_handle_tag,
        x: write.x,
        y: write.y,
        width: write.width,
        height: write.height,
        byte_offset: write.byte_offset,
        byte_len: write.byte_len,
        pixel_format: write.pixel_format.clone(),
        payload_digest: write.payload_digest,
        generation: write.generation,
        state: write.state.as_str().to_owned(),
        recorded_at_event: write.recorded_at_event,
        note: write.note.clone(),
    }
}

pub(crate) fn framebuffer_flush_region_manifest(
    flush: &semantic_core::FramebufferFlushRegionRecord,
) -> FramebufferFlushRegionManifest {
    FramebufferFlushRegionManifest {
        id: flush.id,
        owner_store: flush.owner_store,
        owner_store_generation: flush.owner_store_generation,
        framebuffer_write: flush.framebuffer_write,
        framebuffer_write_generation: flush.framebuffer_write_generation,
        display_capability: flush.display_capability,
        display_capability_generation: flush.display_capability_generation,
        display: flush.display,
        display_generation: flush.display_generation,
        framebuffer: flush.framebuffer,
        framebuffer_generation: flush.framebuffer_generation,
        x: flush.x,
        y: flush.y,
        width: flush.width,
        height: flush.height,
        byte_offset: flush.byte_offset,
        byte_len: flush.byte_len,
        pixel_format: flush.pixel_format.clone(),
        payload_digest: flush.payload_digest,
        generation: flush.generation,
        state: flush.state.as_str().to_owned(),
        recorded_at_event: flush.recorded_at_event,
        note: flush.note.clone(),
    }
}

pub(crate) fn framebuffer_dirty_region_manifest(
    dirty: &semantic_core::FramebufferDirtyRegionRecord,
) -> FramebufferDirtyRegionManifest {
    FramebufferDirtyRegionManifest {
        id: dirty.id,
        owner_store: dirty.owner_store,
        owner_store_generation: dirty.owner_store_generation,
        framebuffer_write: dirty.framebuffer_write,
        framebuffer_write_generation: dirty.framebuffer_write_generation,
        framebuffer_flush_region: dirty.framebuffer_flush_region,
        framebuffer_flush_region_generation: dirty.framebuffer_flush_region_generation,
        display_capability: dirty.display_capability,
        display_capability_generation: dirty.display_capability_generation,
        display: dirty.display,
        display_generation: dirty.display_generation,
        framebuffer: dirty.framebuffer,
        framebuffer_generation: dirty.framebuffer_generation,
        x: dirty.x,
        y: dirty.y,
        width: dirty.width,
        height: dirty.height,
        byte_offset: dirty.byte_offset,
        byte_len: dirty.byte_len,
        pixel_format: dirty.pixel_format.clone(),
        payload_digest: dirty.payload_digest,
        generation: dirty.generation,
        state: dirty.state.as_str().to_owned(),
        dirty_at_event: dirty.dirty_at_event,
        cleaned_at_event: dirty.cleaned_at_event,
        recorded_at_event: dirty.recorded_at_event,
        note: dirty.note.clone(),
    }
}

pub(crate) fn display_event_log_manifest(
    log: &semantic_core::DisplayEventLogRecord,
) -> DisplayEventLogManifest {
    DisplayEventLogManifest {
        id: log.id,
        owner_store: log.owner_store,
        owner_store_generation: log.owner_store_generation,
        display_capability: log.display_capability,
        display_capability_generation: log.display_capability_generation,
        display: log.display,
        display_generation: log.display_generation,
        framebuffer: log.framebuffer,
        framebuffer_generation: log.framebuffer_generation,
        framebuffer_dirty_region: log.framebuffer_dirty_region,
        framebuffer_dirty_region_generation: log.framebuffer_dirty_region_generation,
        first_event: log.first_event,
        last_event: log.last_event,
        event_count: log.event_count,
        flush_count: log.flush_count,
        dirty_region_count: log.dirty_region_count,
        generation: log.generation,
        state: log.state.as_str().to_owned(),
        recorded_at_event: log.recorded_at_event,
        note: log.note.clone(),
    }
}

pub(crate) fn display_cleanup_step_manifest(
    step: &semantic_core::DisplayCleanupStepRecord,
) -> DisplayCleanupStepManifest {
    DisplayCleanupStepManifest {
        kind: step.kind.as_str().to_owned(),
        target: contract_object_ref_manifest(step.target),
        observed_generation: step.observed_generation,
        status: step.status.as_str().to_owned(),
        event: step.event,
    }
}

pub(crate) fn display_cleanup_manifest(
    cleanup: &semantic_core::DisplayCleanupRecord,
) -> DisplayCleanupManifest {
    DisplayCleanupManifest {
        id: cleanup.id,
        owner_store: cleanup.owner_store,
        owner_store_generation: cleanup.owner_store_generation,
        display_capability: cleanup.display_capability,
        display_capability_generation: cleanup.display_capability_generation,
        display: cleanup.display,
        display_generation: cleanup.display_generation,
        framebuffer: cleanup.framebuffer,
        framebuffer_generation: cleanup.framebuffer_generation,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        unmapped_framebuffer_mappings: cleanup
            .unmapped_framebuffer_mappings
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_framebuffer_window_leases: cleanup
            .released_framebuffer_window_leases
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_display_capabilities: cleanup
            .revoked_display_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_capabilities: cleanup
            .revoked_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        steps: cleanup.steps.iter().map(display_cleanup_step_manifest).collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn display_snapshot_barrier_manifest(
    barrier: &semantic_core::DisplaySnapshotBarrierRecord,
) -> DisplaySnapshotBarrierManifest {
    DisplaySnapshotBarrierManifest {
        id: barrier.id,
        owner_store: barrier.owner_store,
        owner_store_generation: barrier.owner_store_generation,
        display: barrier.display,
        display_generation: barrier.display_generation,
        framebuffer: barrier.framebuffer,
        framebuffer_generation: barrier.framebuffer_generation,
        display_cleanup: barrier.display_cleanup,
        display_cleanup_generation: barrier.display_cleanup_generation,
        active_framebuffer_window_lease_count: barrier.active_framebuffer_window_lease_count,
        active_framebuffer_mapping_count: barrier.active_framebuffer_mapping_count,
        dirty_framebuffer_region_count: barrier.dirty_framebuffer_region_count,
        snapshot_validation_ok: barrier.snapshot_validation_ok,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

pub(crate) fn display_panic_last_frame_manifest(
    frame: &semantic_core::DisplayPanicLastFrameRecord,
) -> DisplayPanicLastFrameManifest {
    DisplayPanicLastFrameManifest {
        id: frame.id,
        owner_store: frame.owner_store,
        owner_store_generation: frame.owner_store_generation,
        display: frame.display,
        display_generation: frame.display_generation,
        framebuffer: frame.framebuffer,
        framebuffer_generation: frame.framebuffer_generation,
        display_snapshot_barrier: frame.display_snapshot_barrier,
        display_snapshot_barrier_generation: frame.display_snapshot_barrier_generation,
        display_event_log: frame.display_event_log,
        display_event_log_generation: frame.display_event_log_generation,
        framebuffer_write: frame.framebuffer_write,
        framebuffer_write_generation: frame.framebuffer_write_generation,
        framebuffer_flush_region: frame.framebuffer_flush_region,
        framebuffer_flush_region_generation: frame.framebuffer_flush_region_generation,
        x: frame.x,
        y: frame.y,
        width: frame.width,
        height: frame.height,
        byte_offset: frame.byte_offset,
        byte_len: frame.byte_len,
        pixel_format: frame.pixel_format.clone(),
        payload_digest: frame.payload_digest,
        summary_digest: frame.summary_digest,
        summary_record_bytes: frame.summary_record_bytes,
        panic_epoch: frame.panic_epoch,
        panic_cpu: frame.panic_cpu,
        panic_reason_code: frame.panic_reason_code,
        panic_record_kind: frame.panic_record_kind.clone(),
        raw_framebuffer_bytes_exported: frame.raw_framebuffer_bytes_exported,
        generation: frame.generation,
        state: frame.state.as_str().to_owned(),
        recorded_at_event: frame.recorded_at_event,
        note: frame.note.clone(),
    }
}

pub(crate) fn framebuffer_benchmark_manifest(
    benchmark: &semantic_core::FramebufferBenchmarkRecord,
) -> FramebufferBenchmarkManifest {
    FramebufferBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        owner_store: benchmark.owner_store,
        owner_store_generation: benchmark.owner_store_generation,
        display: benchmark.display,
        display_generation: benchmark.display_generation,
        framebuffer: benchmark.framebuffer,
        framebuffer_generation: benchmark.framebuffer_generation,
        display_capability: benchmark.display_capability,
        display_capability_generation: benchmark.display_capability_generation,
        framebuffer_write: benchmark.framebuffer_write,
        framebuffer_write_generation: benchmark.framebuffer_write_generation,
        framebuffer_flush_region: benchmark.framebuffer_flush_region,
        framebuffer_flush_region_generation: benchmark.framebuffer_flush_region_generation,
        display_event_log: benchmark.display_event_log,
        display_event_log_generation: benchmark.display_event_log_generation,
        display_snapshot_barrier: benchmark.display_snapshot_barrier,
        display_snapshot_barrier_generation: benchmark.display_snapshot_barrier_generation,
        sample_frames: benchmark.sample_frames,
        sample_bytes: benchmark.sample_bytes,
        frame_area_pixels: benchmark.frame_area_pixels,
        write_nanos: benchmark.write_nanos,
        flush_nanos: benchmark.flush_nanos,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        flushes_per_sec_milli: benchmark.flushes_per_sec_milli,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn activation_resume_manifest(
    resume: &semantic_core::ActivationResumeRecord,
) -> ActivationResumeManifest {
    ActivationResumeManifest {
        id: resume.id,
        scheduler_decision: resume.scheduler_decision,
        scheduler_decision_generation: resume.scheduler_decision_generation,
        activation: resume.activation,
        activation_generation_before: resume.activation_generation_before,
        activation_generation_after: resume.activation_generation_after,
        owner_task: u64::from(resume.owner_task),
        owner_task_generation: resume.owner_task_generation,
        queue: resume.queue,
        queue_generation: resume.queue_generation,
        context: resume.context,
        context_generation_before: resume.context_generation_before,
        context_generation_after: resume.context_generation_after,
        saved_context: resume.saved_context,
        saved_context_generation: resume.saved_context_generation,
        saved_vector_state: resume.saved_vector_state.map(contract_object_ref_manifest),
        restored_vector_state: resume.restored_vector_state.map(contract_object_ref_manifest),
        vector_status: resume.vector_status.as_str().to_owned(),
        vector_restored_at_event: resume.vector_restored_at_event,
        generation: resume.generation,
        state: resume.state.as_str().to_owned(),
        resumed_at_event: resume.resumed_at_event,
        note: resume.note.clone(),
    }
}

pub(crate) fn activation_wait_manifest(
    wait: &semantic_core::ActivationWaitRecord,
) -> ActivationWaitManifest {
    ActivationWaitManifest {
        id: wait.id,
        activation: wait.activation,
        activation_generation_before: wait.activation_generation_before,
        activation_generation_after_block: wait.activation_generation_after_block,
        activation_generation_after_cancel: wait.activation_generation_after_cancel,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_task: u64::from(wait.owner_task),
        owner_task_generation: wait.owner_task_generation,
        queue: wait.queue,
        queue_generation: wait.queue_generation,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blocked_at_event: wait.blocked_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn activation_cleanup_manifest(
    cleanup: &semantic_core::ActivationCleanupRecord,
) -> ActivationCleanupManifest {
    ActivationCleanupManifest {
        id: cleanup.id,
        store: cleanup.store,
        target_store_generation: cleanup.target_store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation_before: cleanup.activation_generation_before,
        activation_generation_after: cleanup.activation_generation_after,
        wait: cleanup.wait,
        wait_generation: cleanup.wait_generation,
        owner_task: u64::from(cleanup.owner_task),
        owner_task_generation_before: cleanup.owner_task_generation_before,
        owner_task_generation_after: cleanup.owner_task_generation_after,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        steps: cleanup
            .steps
            .iter()
            .map(|step| ActivationCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn preemption_latency_manifest(
    sample: &semantic_core::PreemptionLatencySampleRecord,
) -> PreemptionLatencySampleManifest {
    PreemptionLatencySampleManifest {
        id: sample.id,
        timer_interrupt: sample.timer_interrupt,
        timer_interrupt_generation: sample.timer_interrupt_generation,
        preemption: sample.preemption,
        preemption_generation: sample.preemption_generation,
        scheduler_decision: sample.scheduler_decision,
        scheduler_decision_generation: sample.scheduler_decision_generation,
        activation_resume: sample.activation_resume,
        activation_resume_generation: sample.activation_resume_generation,
        activation: sample.activation,
        activation_generation_before: sample.activation_generation_before,
        activation_generation_after: sample.activation_generation_after,
        queue: sample.queue,
        queue_generation: sample.queue_generation,
        interrupt_recorded_at_event: sample.interrupt_recorded_at_event,
        preempted_at_event: sample.preempted_at_event,
        decided_at_event: sample.decided_at_event,
        resumed_at_event: sample.resumed_at_event,
        interrupt_to_preempt_events: sample.interrupt_to_preempt_events,
        preempt_to_decision_events: sample.preempt_to_decision_events,
        decision_to_resume_events: sample.decision_to_resume_events,
        interrupt_to_resume_events: sample.interrupt_to_resume_events,
        measured_nanos: sample.measured_nanos,
        budget_nanos: sample.budget_nanos,
        generation: sample.generation,
        state: sample.state.as_str().to_owned(),
        recorded_at_event: sample.recorded_at_event,
        note: sample.note.clone(),
    }
}

pub(crate) fn wait_record_manifest(wait: &semantic_core::WaitRecord) -> WaitRecordManifest {
    WaitRecordManifest {
        id: wait.id,
        owner_task: wait.owner_task.map(u64::from),
        owner_task_generation: wait.owner_task_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        kind: wait.kind.as_str().to_owned(),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blockers: wait.blockers.iter().copied().map(contract_object_ref_manifest).collect(),
        deadline: wait.deadline,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        restart_policy: wait.restart_policy.as_str().to_owned(),
        saved_context: wait.saved_context.clone(),
    }
}

pub(crate) fn capability_record_manifest(
    capability: &CapabilityRecord,
) -> CapabilityRecordManifest {
    CapabilityRecordManifest {
        id: capability.id,
        subject: capability.subject.clone(),
        object: capability.object.clone(),
        object_ref: capability.object_ref.map(authority_object_ref_manifest),
        rights: capability.operations.as_slice().to_vec(),
        lifetime: capability.lifetime.clone(),
        class: capability.class.as_str().to_owned(),
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        owner_task: capability.owner_task.map(u64::from),
        source: capability.source.clone(),
        generation: capability.generation,
        parent: capability.parent,
        manifest_decl: capability.manifest_decl,
        debug_object_label: capability.debug_object_label.clone(),
        revoked: capability.revoked,
    }
}

pub(crate) fn activation_record_manifest(
    activation: &semantic_core::target_executor::ActivationRecord,
) -> ActivationRecordManifest {
    ActivationRecordManifest {
        id: activation.id,
        store: activation.store,
        store_generation: activation.store_generation,
        code_object: activation.code_object,
        code_generation: activation.code_generation,
        artifact: activation.artifact,
        entry: activation.entry.summary(),
        generation: activation.generation,
        state: activation.state.as_str().to_owned(),
        start_event: activation.start_event,
        exit_event: activation.exit_event,
        active_dmw_leases: activation.active_dmw_leases,
        blocked_wait: activation.blocked_wait,
        trap: activation.trap,
        return_tag: activation.return_tag.map(|tag| tag.as_str().to_owned()),
    }
}

pub(crate) fn trap_record_manifest(
    trap: &semantic_core::target_executor::TargetTrapRecord,
) -> TrapRecordManifest {
    TrapRecordManifest {
        id: trap.id,
        generation: trap.generation,
        class: trap.class.as_str().to_owned(),
        store: trap.store,
        store_generation: trap.store_generation,
        activation: trap.activation,
        activation_generation: trap.activation_generation,
        code_object: trap.code_object,
        code_generation: trap.code_generation,
        artifact: trap.artifact,
        artifact_generation: trap.artifact_generation,
        offset: trap.offset,
        target_pc: trap.target_pc,
        trap_kind: trap.trap_kind.clone(),
        function_index: trap.function_index,
        wasm_offset: trap.wasm_offset,
        debug_symbol: trap.debug_symbol,
        classification_status: trap.classification_status.clone(),
        attribution_status: trap.attribution_status.clone(),
        simd_attribution: trap.simd_attribution.as_ref().map(|attribution| {
            SimdTrapAttributionManifest {
                classification: attribution.classification.as_str().to_owned(),
                required_abi: attribution.required_abi.clone(),
                min_vector_register_count: attribution.min_vector_register_count,
                min_vector_register_bits: attribution.min_vector_register_bits,
                target_feature_set: attribution
                    .target_feature_set
                    .map(contract_object_ref_manifest),
                code_requirement_status: attribution.code_requirement_status.as_str().to_owned(),
                note: attribution.note.clone(),
            }
        }),
        hostcall: trap.hostcall.clone(),
        fault_policy: trap.fault_policy.clone(),
        effect: trap.effect.summary(),
        detail: trap.detail.clone(),
    }
}

pub(crate) fn hostcall_trace_manifest(trace: &HostcallTraceRecord) -> HostcallTraceManifest {
    HostcallTraceManifest {
        id: trace.id,
        generation: trace.generation,
        abi_version: trace.abi_version.clone(),
        frame_size: trace.frame_size,
        flags: trace.flags,
        activation: trace.activation,
        activation_generation: trace.activation_generation,
        store: trace.store,
        store_generation: trace.store_generation,
        code_object: trace.code_object,
        code_generation: trace.code_generation,
        artifact: trace.artifact,
        artifact_generation: trace.artifact_generation,
        hostcall_number: trace.hostcall_number,
        hostcall_seq: trace.hostcall_seq,
        caller_offset: trace.caller_offset,
        name: trace.name.clone(),
        category: trace.category.as_str().to_owned(),
        subject: trace.subject.clone(),
        subject_source: trace.subject_source.clone(),
        object: trace.object.clone(),
        operation: trace.operation.clone(),
        args: trace.args,
        cap_args: trace.cap_args.iter().map(cap_arg_manifest).collect(),
        record_mode: trace.record_mode.as_str().to_owned(),
        allowed: trace.allowed,
        gate_status: trace.gate_status.clone(),
        result: trace.result.clone(),
        denial_reason: trace.denial_reason.clone(),
        ret_tag: trace.ret_tag.as_str().to_owned(),
        ret0: trace.ret0,
        ret1: trace.ret1,
        trap_out: trace.trap_out,
        trap_generation_out: trace.trap_generation_out,
        wait_token_out: trace.wait_token_out,
        wait_token_generation_out: trace.wait_token_generation_out,
    }
}

pub(crate) fn cap_arg_manifest(arg: &CapabilityHandleArg) -> CapabilityHandleArgManifest {
    CapabilityHandleArgManifest {
        id: arg.id,
        object: arg.object.clone(),
        generation: arg.generation,
        owner_store: arg.owner_store,
        owner_store_generation: arg.owner_store_generation,
        handle_slot: arg.handle_slot,
        handle_generation: arg.handle_generation,
        handle_tag: arg.handle_tag,
        rights_mask: arg.rights_mask,
        rights: arg.rights.clone(),
    }
}

pub(crate) fn substrate_event_manifests(events: &[EventRecord]) -> Vec<SubstrateEventManifest> {
    events.iter().filter_map(substrate_event_manifest).collect()
}

pub(crate) fn substrate_event_manifest(event: &EventRecord) -> Option<SubstrateEventManifest> {
    match &event.kind {
        EventKind::SubstrateUnsupported { authority, operation, requester, artifact, store } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "unsupported".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} observed {authority}::{operation} as unsupported"
                ),
            })
        }
        EventKind::SubstrateCapabilityDenied {
            authority,
            operation,
            requester,
            artifact,
            store,
            capability,
            capability_generation,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            let capability_manifest = match (*capability, *capability_generation) {
                (Some(id), Some(generation)) => Some(CapabilityHandleArgManifest {
                    id,
                    object: "substrate-capability".to_owned(),
                    generation,
                    owner_store: None,
                    owner_store_generation: None,
                    handle_slot: 0,
                    handle_generation: 0,
                    handle_tag: 0,
                    rights_mask: 0,
                    rights: Vec::new(),
                }),
                _ => None,
            };
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "capability-denied".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: capability_manifest,
                explanation: format!(
                    "{requester_label} was denied {authority}::{operation} by capability gate"
                ),
            })
        }
        EventKind::SubstratePanic {
            authority,
            operation,
            requester,
            artifact,
            store,
            panic_epoch,
            panic_cpu,
            panic_reason_code,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(SubstrateEventManifest {
                id: event.id,
                epoch: event.epoch,
                event_kind: "panic".to_owned(),
                authority: authority.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                capability: None,
                explanation: format!(
                    "{requester_label} reported substrate panic epoch={panic_epoch} cpu={panic_cpu} reason={panic_reason_code}"
                ),
            })
        }
        _ => None,
    }
}

pub(crate) fn command_result_manifest(result: &CommandResult) -> CommandResultManifest {
    CommandResultManifest {
        id: result.command_id,
        issuer: result.issuer.clone(),
        command: result.command.to_owned(),
        status: result.status.as_str().to_owned(),
        events: result.events.clone(),
        effects: result
            .effects
            .iter()
            .map(|effect| CommandEffectManifest {
                kind: effect.kind.clone(),
                target: effect.target.map(contract_object_ref_manifest),
            })
            .collect(),
        violations: result.violations.clone(),
    }
}

pub(crate) fn interface_event_manifests(events: &[EventRecord]) -> Vec<InterfaceEventManifest> {
    events.iter().filter_map(interface_event_manifest).collect()
}

pub(crate) fn interface_event_manifest(event: &EventRecord) -> Option<InterfaceEventManifest> {
    match &event.kind {
        EventKind::InterfaceUnsupported {
            interface_kind,
            interface,
            operation,
            requester,
            artifact,
            store,
        } => {
            let requester_label = requester.as_deref().unwrap_or("unknown");
            Some(InterfaceEventManifest {
                id: event.id,
                epoch: event.epoch,
                interface_kind: interface_kind.clone(),
                interface: interface.clone(),
                operation: operation.clone(),
                requester: requester.clone(),
                artifact: *artifact,
                store: *store,
                explanation: format!(
                    "{requester_label} observed {interface_kind} {interface}::{operation} as unsupported"
                ),
            })
        }
        _ => None,
    }
}

pub(crate) fn migration_object_manifest(record: &MigrationObjectRecord) -> MigrationObjectManifest {
    MigrationObjectManifest {
        object: record.object.clone(),
        class: record.class.as_str().to_owned(),
        reason: record.reason.clone(),
    }
}

pub(crate) fn tombstone_manifest(record: &TombstoneRecord) -> TombstoneManifest {
    TombstoneManifest {
        kind: record.kind.as_str().to_owned(),
        id: record.id,
        generation: record.generation,
        died_at: record.died_at,
        reason: record.reason.clone(),
    }
}

pub(crate) fn contract_object_ref_manifest(
    reference: ContractObjectRef,
) -> ContractObjectRefManifest {
    ContractObjectRefManifest {
        kind: reference.kind.as_str().to_owned(),
        id: reference.id,
        generation: reference.generation,
    }
}

pub(crate) fn optional_generation_ref(id: Option<u64>, generation: Option<u64>) -> String {
    match (id, generation) {
        (Some(id), Some(generation)) => format!("{id}@{generation}"),
        _ => "none".to_owned(),
    }
}

pub(crate) fn authority_object_ref_manifest(
    reference: AuthorityObjectRef,
) -> AuthorityObjectRefManifest {
    match reference {
        AuthorityObjectRef::Internal { class, object } => AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
        AuthorityObjectRef::External { class, object } => AuthorityObjectRefManifest {
            scope: "external".to_owned(),
            class: class.as_str().to_owned(),
            object: contract_object_ref_manifest(object),
        },
    }
}

pub(crate) fn contract_violation_manifest(
    violation: &ContractViolation,
) -> ContractViolationManifest {
    ContractViolationManifest {
        kind: violation.kind.as_str().to_owned(),
        edge: violation.edge.clone(),
        from: contract_object_ref_manifest(violation.from),
        to: violation.to.map(contract_object_ref_manifest),
        detail: violation.detail.clone(),
    }
}

pub(crate) fn cleanup_transaction_manifest(
    cleanup: &semantic_core::target_executor::FaultCleanupTransaction,
) -> CleanupTransactionManifest {
    CleanupTransactionManifest {
        id: cleanup.id,
        store: cleanup.store,
        store_generation: cleanup.store_generation,
        target_store_generation: cleanup.store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation: cleanup.activation_generation,
        code_object: cleanup.code_object,
        code_generation: cleanup.code_generation,
        generation: cleanup.generation,
        started_at: cleanup.started_at,
        finished_at: cleanup.finished_at,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        released_dmw_leases: cleanup.released_dmw_leases,
        cancelled_waits: cleanup.cancelled_waits,
        revoked_capabilities: cleanup.revoked_capabilities.clone(),
        revoked_capability_refs: cleanup
            .revoked_capability_refs
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        dropped_resources: cleanup.dropped_resources,
        unbound_code_object: cleanup.unbound_code_object,
        state_digest: cleanup.state_digest.clone(),
        effect: cleanup.effect.summary(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| CleanupStepManifest {
                step: step.step.as_str().to_owned(),
                state: step.state.as_str().to_owned(),
                detail: step.detail.clone(),
                target: step.target.map(contract_object_ref_manifest),
                observed_generation: step.observed_generation,
                error: step.error.clone(),
                idempotency_key: step.idempotency_key.clone(),
                event_seq: step.event_seq,
            })
            .collect(),
        effects: cleanup
            .effects
            .iter()
            .map(|effect| CleanupEffectManifest {
                kind: effect.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(effect.target),
                expected_generation: effect.expected_generation,
                status: effect.status.as_str().to_owned(),
                event_seq: effect.event_seq,
            })
            .collect(),
    }
}

pub(crate) fn memory_policy_manifest(policy: &MemoryClassPolicy) -> MemoryClassPolicyManifest {
    MemoryClassPolicyManifest {
        class: policy.class.as_str().to_owned(),
        owner_kind: policy.owner_kind.as_str().to_owned(),
        permissions: policy.permissions.summary(),
        migration_policy: policy.migratable.as_str().to_owned(),
        snapshot_policy: policy.snapshot_policy.as_str().to_owned(),
        cleanup_policy: policy.cleanup_policy.as_str().to_owned(),
        can_alias_guest_memory: policy.can_alias_guest_memory,
        can_cross_pending: policy.can_cross_pending,
        can_be_executable: policy.can_be_executable,
    }
}
