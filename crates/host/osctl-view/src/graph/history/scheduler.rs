use super::super::*;

pub(super) fn push_scheduler_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
    for interrupt in &package.semantic.timer_interrupts {
        let from = object_ref_json("timer-interrupt", interrupt.id, interrupt.generation);
        if let Some(hart_generation) = interrupt.hart_generation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", interrupt.hart, hart_generation),
                "recorded-on-hart",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
        if let (Some(activation), Some(generation)) =
            (interrupt.target_activation, interrupt.target_activation_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, generation),
                "recorded-target",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
        if let (Some(task), Some(generation)) =
            (interrupt.target_task, interrupt.target_task_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("task", task, generation),
                "recorded-task",
                "historical",
                Some(interrupt.recorded_at_event),
            ));
        }
    }
    for ipi in &package.semantic.ipi_events {
        let from = object_ref_json("ipi-event", ipi.id, ipi.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", ipi.source_hart, ipi.source_hart_generation),
            "ipi-source-hart",
            "historical",
            Some(ipi.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("hart", ipi.target_hart, ipi.target_hart_generation),
            "ipi-target-hart",
            "historical",
            Some(ipi.recorded_at_event),
        ));
    }
    for remote in &package.semantic.remote_preempts {
        let from = object_ref_json("remote-preempt", remote.id, remote.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("ipi-event", remote.ipi, remote.ipi_generation),
            "caused-by-ipi",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.source_hart, remote.source_hart_generation),
            "source-hart",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.target_hart, remote.target_hart_generation_before),
            "target-hart-before",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.target_hart, remote.target_hart_generation_after),
            "target-hart-after",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", remote.activation, remote.activation_generation_before),
            "activation-before",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", remote.activation, remote.activation_generation_after),
            "activation-after",
            "historical",
            Some(remote.preempted_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("runnable-queue", remote.queue, remote.queue_generation),
            "target-runnable-queue",
            "historical",
            Some(remote.preempted_at_event),
        ));
    }
    for remote in &package.semantic.remote_parks {
        let from = object_ref_json("remote-park", remote.id, remote.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("ipi-event", remote.ipi, remote.ipi_generation),
            "caused-by-ipi",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.source_hart, remote.source_hart_generation),
            "source-hart",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", remote.target_hart, remote.target_hart_generation_before),
            "target-hart-before",
            "historical",
            Some(remote.parked_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("hart", remote.target_hart, remote.target_hart_generation_after),
            "target-hart-after",
            "historical",
            Some(remote.parked_at_event),
        ));
    }
    for attribution in &package.semantic.hart_event_attributions {
        let from =
            object_ref_json("hart-event-attribution", attribution.id, attribution.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", attribution.hart, attribution.hart_generation),
            "attributed-to-hart",
            "historical",
            Some(attribution.event),
        ));
        if let (Some(activation), Some(generation)) =
            (attribution.activation, attribution.activation_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, generation),
                "attributed-activation",
                "historical",
                Some(attribution.event),
            ));
        }
        if let (Some(task), Some(generation)) = (attribution.task, attribution.task_generation) {
            edges.push(graph_edge(
                from,
                object_ref_json("task", task, generation),
                "attributed-task",
                "historical",
                Some(attribution.event),
            ));
        }
    }
    for preemption in &package.semantic.preemptions {
        let from = object_ref_json("preemption", preemption.id, preemption.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                preemption.activation,
                preemption.activation_generation_before,
            ),
            "preempted-from",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                preemption.activation,
                preemption.activation_generation_after,
            ),
            "preempted-to",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "timer-interrupt",
                preemption.timer_interrupt,
                preemption.timer_interrupt_generation,
            ),
            "caused-by",
            "historical",
            Some(preemption.preempted_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("runnable-queue", preemption.queue, preemption.queue_generation),
            "queued-into",
            "historical",
            Some(preemption.preempted_at_event),
        ));
    }
    for saved in &package.semantic.saved_contexts {
        if let (Some(preemption), Some(preemption_generation)) =
            (saved.source_preemption, saved.source_preemption_generation)
        {
            edges.push(graph_edge(
                object_ref_json("saved-context", saved.id, saved.generation),
                object_ref_json("preemption", preemption, preemption_generation),
                "captured-from-preemption",
                "historical",
                Some(saved.saved_at_event),
            ));
        }
        if let Some(vector_state) = &saved.vector_state {
            edges.push(graph_edge(
                object_ref_json("saved-context", saved.id, saved.generation),
                object_ref_manifest_json(vector_state),
                "saved-vector-state",
                "historical",
                saved.vector_saved_at_event.or(Some(saved.saved_at_event)),
            ));
        }
    }
    for decision in &package.semantic.scheduler_decisions {
        let from = object_ref_json("scheduler-decision", decision.id, decision.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", decision.queue, decision.queue_generation),
            "selected-from",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                decision.selected_activation,
                decision.selected_activation_generation,
            ),
            "selected",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("task", decision.owner_task, decision.owner_task_generation),
            "owned-by-task",
            "historical",
            Some(decision.decided_at_event),
        ));
    }
    for decision in &package.semantic.cross_hart_scheduler_decisions {
        let from =
            object_ref_json("cross-hart-scheduler-decision", decision.id, decision.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                decision.scheduler_decision,
                decision.scheduler_decision_generation,
            ),
            "extends-scheduler-decision",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", decision.deciding_hart, decision.deciding_hart_generation),
            "deciding-hart",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", decision.target_hart, decision.target_hart_generation),
            "target-hart",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", decision.queue, decision.queue_generation),
            "target-runnable-queue",
            "historical",
            Some(decision.decided_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "activation",
                decision.selected_activation,
                decision.selected_activation_generation,
            ),
            "selected-activation",
            "historical",
            Some(decision.decided_at_event),
        ));
    }
    for migration in &package.semantic.activation_migrations {
        let from = object_ref_json("activation-migration", migration.id, migration.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                migration.activation,
                migration.activation_generation_before,
            ),
            "migrated-from",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                migration.activation,
                migration.activation_generation_after,
            ),
            "migrated-to",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", migration.source_hart, migration.source_hart_generation),
            "source-hart",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("hart", migration.target_hart, migration.target_hart_generation),
            "target-hart",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "runnable-queue",
                migration.source_queue,
                migration.source_queue_generation,
            ),
            "source-runnable-queue",
            "historical",
            Some(migration.migrated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "runnable-queue",
                migration.target_queue,
                migration.target_queue_generation,
            ),
            "target-runnable-queue",
            "historical",
            Some(migration.migrated_at_event),
        ));
        if let Some(source_vector_state) = &migration.source_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(source_vector_state),
                "source-vector-state",
                "historical",
                migration.vector_migrated_at_event.or(Some(migration.migrated_at_event)),
            ));
        }
        if let Some(migrated_vector_state) = &migration.migrated_vector_state {
            edges.push(graph_edge(
                from,
                object_ref_manifest_json(migrated_vector_state),
                "migrated-vector-state",
                "historical",
                migration.vector_migrated_at_event.or(Some(migration.migrated_at_event)),
            ));
        }
    }
    for safe_point in &package.semantic.smp_safe_points {
        let from = object_ref_json("smp-safe-point", safe_point.id, safe_point.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                safe_point.coordinator_hart,
                safe_point.coordinator_hart_generation,
            ),
            "coordinator-hart",
            "historical",
            Some(safe_point.recorded_at_event),
        ));
        for participant in &safe_point.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(safe_point.recorded_at_event),
            ));
        }
    }
    for rendezvous in &package.semantic.stop_the_world_rendezvous {
        let from =
            object_ref_json("stop-the-world-rendezvous", rendezvous.id, rendezvous.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "smp-safe-point",
                rendezvous.safe_point,
                rendezvous.safe_point_generation,
            ),
            "rendezvous-safe-point",
            "historical",
            Some(rendezvous.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "hart",
                rendezvous.coordinator_hart,
                rendezvous.coordinator_hart_generation,
            ),
            "coordinator-hart",
            "historical",
            Some(rendezvous.completed_at_event),
        ));
        for participant in &rendezvous.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(rendezvous.completed_at_event),
            ));
        }
    }
    for barrier in &package.semantic.smp_code_publish_barriers {
        let from = object_ref_json("smp-code-publish-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                barrier.rendezvous,
                barrier.rendezvous_generation,
            ),
            "publish-rendezvous",
            "historical",
            Some(barrier.validated_at_event),
        ));
        for participant in &barrier.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(barrier.validated_at_event),
            ));
        }
    }
    for quiescence in &package.semantic.smp_cleanup_quiescence {
        let from = object_ref_json("smp-cleanup-quiescence", quiescence.id, quiescence.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation-cleanup",
                quiescence.cleanup,
                quiescence.cleanup_generation,
            ),
            "cleanup",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", quiescence.store, quiescence.result_store_generation),
            "dead-store",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                quiescence.rendezvous,
                quiescence.rendezvous_generation,
            ),
            "cleanup-rendezvous",
            "historical",
            Some(quiescence.validated_at_event),
        ));
        for participant in &quiescence.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(quiescence.validated_at_event),
            ));
        }
    }
    for barrier in &package.semantic.smp_snapshot_barriers {
        let from = object_ref_json("smp-snapshot-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "stop-the-world-rendezvous",
                barrier.rendezvous,
                barrier.rendezvous_generation,
            ),
            "snapshot-rendezvous",
            "historical",
            Some(barrier.validated_at_event),
        ));
        for participant in &barrier.participants {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("hart", participant.hart, participant.hart_generation),
                "participant-hart",
                "historical",
                Some(barrier.validated_at_event),
            ));
        }
    }
    for run in &package.semantic.smp_stress_runs {
        let from = object_ref_json("smp-stress-run", run.id, run.generation);
        let stress_edges = [
            (
                "last-safe-point",
                "smp-safe-point",
                run.last_safe_point,
                run.last_safe_point_generation,
            ),
            (
                "last-rendezvous",
                "stop-the-world-rendezvous",
                run.last_rendezvous,
                run.last_rendezvous_generation,
            ),
            (
                "last-code-publish-barrier",
                "smp-code-publish-barrier",
                run.last_code_publish_barrier,
                run.last_code_publish_barrier_generation,
            ),
            (
                "last-cleanup-quiescence",
                "smp-cleanup-quiescence",
                run.last_cleanup_quiescence,
                run.last_cleanup_quiescence_generation,
            ),
            (
                "last-snapshot-barrier",
                "smp-snapshot-barrier",
                run.last_snapshot_barrier,
                run.last_snapshot_barrier_generation,
            ),
            (
                "last-activation-migration",
                "activation-migration",
                run.last_activation_migration,
                run.last_activation_migration_generation,
            ),
            (
                "last-remote-preempt",
                "remote-preempt",
                run.last_remote_preempt,
                run.last_remote_preempt_generation,
            ),
            (
                "last-remote-park",
                "remote-park",
                run.last_remote_park,
                run.last_remote_park_generation,
            ),
        ];
        for (label, kind, id, generation) in stress_edges {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(run.recorded_at_event),
            ));
        }
    }
    for benchmark in &package.semantic.smp_scaling_benchmarks {
        edges.push(graph_edge(
            object_ref_json("smp-scaling-benchmark", benchmark.id, benchmark.generation),
            object_ref_json(
                "smp-stress-run",
                benchmark.stress_run,
                benchmark.stress_run_generation,
            ),
            "scaling-stress-run",
            "historical",
            Some(benchmark.recorded_at_event),
        ));
    }
    for record in &package.semantic.integrated_smp_preemption_cleanups {
        let from =
            object_ref_json("integrated-smp-preemption-cleanup", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-stress-run",
                "smp-stress-run",
                record.stress_run,
                record.stress_run_generation,
            ),
            (
                "integrated-preemption",
                "preemption",
                record.preemption,
                record.preemption_generation,
            ),
            (
                "integrated-timer-interrupt",
                "timer-interrupt",
                record.timer_interrupt,
                record.timer_interrupt_generation,
            ),
            (
                "integrated-saved-context",
                "saved-context",
                record.saved_context,
                record.saved_context_generation,
            ),
            (
                "integrated-remote-preempt",
                "remote-preempt",
                record.remote_preempt,
                record.remote_preempt_generation,
            ),
            (
                "integrated-activation-cleanup",
                "activation-cleanup",
                record.activation_cleanup,
                record.activation_cleanup_generation,
            ),
            (
                "integrated-cleanup-quiescence",
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            (
                "integrated-cleanup-store",
                "store",
                record.cleanup_store,
                record.target_store_generation,
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(record.recorded_at_event),
            ));
        }
    }
    for record in &package.semantic.integrated_smp_network_faults {
        let from = object_ref_json("integrated-smp-network-fault", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-network-cleanup",
                "network-driver-cleanup",
                record.network_driver_cleanup,
                record.network_driver_cleanup_generation,
            ),
            (
                "integrated-smp-stress-run",
                "smp-stress-run",
                record.smp_stress_run,
                record.smp_stress_run_generation,
            ),
            (
                "integrated-remote-preempt",
                "remote-preempt",
                record.remote_preempt,
                record.remote_preempt_generation,
            ),
            (
                "integrated-cleanup-quiescence",
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            (
                "integrated-packet-device",
                "packet-device-object",
                record.packet_device,
                record.packet_device_generation,
            ),
            (
                "integrated-network-adapter",
                "network-stack-adapter",
                record.adapter,
                record.adapter_generation,
            ),
            (
                "integrated-io-cleanup",
                "io-cleanup",
                record.io_cleanup,
                record.io_cleanup_generation,
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(record.recorded_at_event),
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json(&record.backend.kind, record.backend.id, record.backend.generation),
            "integrated-network-backend",
            "historical",
            Some(record.recorded_at_event),
        ));
    }
    for record in &package.semantic.integrated_disk_preempt_faults {
        let from = object_ref_json("integrated-disk-preempt-fault", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-preemption",
                "preemption",
                record.preemption,
                record.preemption_generation,
            ),
            (
                "integrated-timer-interrupt",
                "timer-interrupt",
                record.timer_interrupt,
                record.timer_interrupt_generation,
            ),
            (
                "integrated-block-policy",
                "block-pending-io-policy",
                record.block_pending_io_policy,
                record.block_pending_io_policy_generation,
            ),
            (
                "integrated-block-wait",
                "block-wait",
                record.block_wait,
                record.block_wait_generation,
            ),
            ("integrated-wait-token", "wait-token", record.wait, record.wait_generation),
            (
                "integrated-block-request",
                "block-request-object",
                record.block_request,
                record.block_request_generation,
            ),
            (
                "integrated-block-device",
                "block-device-object",
                record.block_device,
                record.block_device_generation,
            ),
            (
                "integrated-block-range",
                "block-range-object",
                record.block_range,
                record.block_range_generation,
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(kind, id, generation),
                label,
                "historical",
                Some(record.recorded_at_event),
            ));
        }
        if let (Some(retry_request), Some(retry_generation)) =
            (record.retry_request, record.retry_request_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("block-request-object", retry_request, retry_generation),
                "integrated-block-retry-request",
                "historical",
                Some(record.recorded_at_event),
            ));
        }
    }
}
