use super::*;

pub(super) fn push_scheduler_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.hart_roots = semantic
        .harts()
        .iter()
        .map(|hart| {
            format!(
                "hart id={} hardware_id={} label={} state={} generation={} boot={} current={}@{}",
                hart.id,
                hart.hardware_id,
                hart.label,
                hart.state.as_str(),
                hart.generation,
                hart.boot,
                hart.current_activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                hart.current_activation_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_owned())
            )
        })
        .collect();
    roots.task_roots = semantic
        .tasks()
        .iter()
        .map(|task| {
            format!(
                "task:{}:{}:{}:gen{}",
                task.id,
                task.frontend.as_str(),
                task.state.as_str(),
                task.generation
            )
        })
        .collect();
    roots.task_record_roots = semantic
        .tasks()
        .iter()
        .map(|task| {
            format!(
                "task-record id={} state={} generation={}",
                task.id,
                task.state.as_str(),
                task.generation
            )
        })
        .collect();
    roots.runtime_activation_roots = semantic
        .runtime_activations()
        .iter()
        .map(|activation| {
            format!(
                "runtime-activation id={} task={}@{} state={} generation={} queue={}@{}",
                activation.id,
                activation.owner_task,
                activation.owner_task_generation,
                activation.state.as_str(),
                activation.generation,
                activation
                    .runnable_queue
                    .map(|queue| queue.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                activation
                    .runnable_queue_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_owned())
            )
        })
        .collect();
    roots.runnable_queue_roots = semantic
        .runnable_queues()
        .iter()
        .map(|queue| {
            format!(
                "runnable-queue id={} label={} state={} generation={} entries={}",
                queue.id,
                queue.label,
                queue.state.as_str(),
                queue.generation,
                queue.entries.len()
            )
        })
        .collect();
    roots.activation_context_roots = semantic            .activation_contexts()
            .iter()
            .map(|context| {
                format!(
                    "activation-context id={} activation={}@{} state={} generation={} saved={}@{} vector_status={} vector_state={}",
                    context.id,
                    context.activation,
                    context.activation_generation,
                    context.state.as_str(),
                    context.generation,
                    context
                        .current_saved_context
                        .map(|saved| saved.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context
                        .current_saved_context_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context.vector_status.as_str(),
                    context
                        .vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect();
    roots.saved_context_roots = semantic            .saved_contexts()
            .iter()
            .map(|saved| {
                format!(
                    "saved-context id={} context={}@{} activation={}@{} state={} reason={} pc={:#x} sp={:#x} vector_status={} vector_state={} generation={}",
                    saved.id,
                    saved.context,
                    saved.context_generation,
                    saved.activation,
                    saved.activation_generation,
                    saved.state.as_str(),
                    saved.reason.as_str(),
                    saved.pc,
                    saved.sp,
                    saved.vector_status.as_str(),
                    saved
                        .vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    saved.generation
                )
            })
            .collect();
    roots.timer_interrupt_roots = semantic
        .timer_interrupts()
        .iter()
        .map(|interrupt| {
            format!(
                "timer-interrupt id={} epoch={} hart={} target={}@{} state={} generation={}",
                interrupt.id,
                interrupt.timer_epoch,
                interrupt.hart,
                interrupt
                    .target_activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                interrupt
                    .target_activation_generation
                    .map(|generation| generation.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                interrupt.state.as_str(),
                interrupt.generation
            )
        })
        .collect();
    roots.ipi_event_roots = semantic            .ipi_events()
            .iter()
            .map(|ipi| {
                format!(
                    "ipi-event id={} kind={} source_hart={}@{} target_hart={}@{} state={} generation={}",
                    ipi.id,
                    ipi.kind.as_str(),
                    ipi.source_hart,
                    ipi.source_hart_generation,
                    ipi.target_hart,
                    ipi.target_hart_generation,
                    ipi.state.as_str(),
                    ipi.generation
                )
            })
            .collect();
    roots.remote_preempt_roots = semantic            .remote_preempts()
            .iter()
            .map(|remote| {
                format!(
                    "remote-preempt id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} activation={}@{}->{} queue={}@{} state={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.activation,
                    remote.activation_generation_before,
                    remote.activation_generation_after,
                    remote.queue,
                    remote.queue_generation,
                    remote.state.as_str(),
                    remote.generation
                )
            })
            .collect();
    roots.remote_park_roots = semantic            .remote_parks()
            .iter()
            .map(|remote| {
                format!(
                    "remote-park id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} state={} reason={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.state.as_str(),
                    remote.reason,
                    remote.generation
                )
            })
            .collect();
    roots.preemption_roots = semantic            .preemptions()
            .iter()
            .map(|preemption| {
                format!(
                    "preemption id={} activation={}@{}->{} timer={}@{} queue={}@{} state={} generation={}",
                    preemption.id,
                    preemption.activation,
                    preemption.activation_generation_before,
                    preemption.activation_generation_after,
                    preemption.timer_interrupt,
                    preemption.timer_interrupt_generation,
                    preemption.queue,
                    preemption.queue_generation,
                    preemption.state.as_str(),
                    preemption.generation
                )
            })
            .collect();
    roots.scheduler_decision_roots = semantic
        .scheduler_decisions()
        .iter()
        .map(|decision| {
            format!(
                "scheduler-decision id={} queue={}@{} activation={}@{} state={} generation={}",
                decision.id,
                decision.queue,
                decision.queue_generation,
                decision.selected_activation,
                decision.selected_activation_generation,
                decision.state.as_str(),
                decision.generation
            )
        })
        .collect();
    roots.cross_hart_scheduler_decision_roots = semantic            .cross_hart_scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "cross-hart-scheduler-decision id={} decision={}@{} deciding_hart={}@{} target_hart={}@{} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.scheduler_decision,
                    decision.scheduler_decision_generation,
                    decision.deciding_hart,
                    decision.deciding_hart_generation,
                    decision.target_hart,
                    decision.target_hart_generation,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect();
    roots.activation_migration_roots = semantic            .activation_migrations()
            .iter()
            .map(|migration| {
                format!(
                    "activation-migration id={} activation={}@{}->{} source_hart={}@{} target_hart={}@{} source_queue={}@{} target_queue={}@{} vector_status={} source_vector_state={} migrated_vector_state={} state={} generation={}",
                    migration.id,
                    migration.activation,
                    migration.activation_generation_before,
                    migration.activation_generation_after,
                    migration.source_hart,
                    migration.source_hart_generation,
                    migration.target_hart,
                    migration.target_hart_generation,
                    migration.source_queue,
                    migration.source_queue_generation,
                    migration.target_queue,
                    migration.target_queue_generation,
                    migration.vector_status.as_str(),
                    migration
                        .source_vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    migration
                        .migrated_vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    migration.state.as_str(),
                    migration.generation
                )
            })
            .collect();
    roots.smp_safe_point_roots = semantic            .smp_safe_points()
            .iter()
            .map(|safe_point| {
                format!(
                    "smp-safe-point id={} coordinator_hart={}@{} participants={} state={} generation={}",
                    safe_point.id,
                    safe_point.coordinator_hart,
                    safe_point.coordinator_hart_generation,
                    safe_point.participants.len(),
                    safe_point.state.as_str(),
                    safe_point.generation
                )
            })
            .collect();
    roots.stop_the_world_rendezvous_roots = semantic            .stop_the_world_rendezvous()
            .iter()
            .map(|rendezvous| {
                format!(
                    "stop-the-world-rendezvous id={} epoch={} safe_point={}@{} participants={} state={} generation={}",
                    rendezvous.id,
                    rendezvous.epoch,
                    rendezvous.safe_point,
                    rendezvous.safe_point_generation,
                    rendezvous.participants.len(),
                    rendezvous.state.as_str(),
                    rendezvous.generation
                )
            })
            .collect();
    roots.smp_code_publish_barrier_roots = semantic            .smp_code_publish_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-code-publish-barrier id={} rendezvous={}@{} code_publish_epoch={}->{} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.code_publish_epoch_before,
                    barrier.code_publish_epoch_after,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect();
    roots.smp_cleanup_quiescence_roots = semantic            .smp_cleanup_quiescence()
            .iter()
            .map(|quiescence| {
                format!(
                    "smp-cleanup-quiescence id={} cleanup={}@{} store={}@{}->{} rendezvous={}@{} participants={} state={} generation={}",
                    quiescence.id,
                    quiescence.cleanup,
                    quiescence.cleanup_generation,
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                    quiescence.rendezvous,
                    quiescence.rendezvous_generation,
                    quiescence.participants.len(),
                    quiescence.state.as_str(),
                    quiescence.generation
                )
            })
            .collect();
    roots.smp_snapshot_barrier_roots = semantic            .smp_snapshot_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-snapshot-barrier id={} rendezvous={}@{} cursor={} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.event_log_cursor,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect();
    roots.smp_stress_run_roots = semantic            .smp_stress_runs()
            .iter()
            .map(|run| {
                format!(
                    "smp-stress-run id={} scenario={} iterations={} invariants={} failures={} cursor={} generation={}",
                    run.id,
                    run.scenario,
                    run.iterations,
                    run.invariant_checks,
                    run.property_failures,
                    run.event_log_cursor,
                    run.generation
                )
            })
            .collect();
    roots.smp_scaling_benchmark_roots = semantic            .smp_scaling_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "smp-scaling-benchmark id={} scenario={} stress_run={}@{} harts={} workload_units={} measured_nanos={} speedup_milli={} efficiency_milli={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.stress_run,
                    benchmark.stress_run_generation,
                    benchmark.hart_count,
                    benchmark.workload_units,
                    benchmark.measured_smp_nanos,
                    benchmark.speedup_milli,
                    benchmark.efficiency_milli,
                    benchmark.generation
                )
            })
            .collect();
}
