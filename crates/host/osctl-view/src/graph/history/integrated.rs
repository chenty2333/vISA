use super::super::*;

pub(super) fn push_integrated_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
    for record in &package.semantic.integrated_simd_migrations {
        let from = object_ref_json("integrated-simd-migration", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-activation-migration",
                "activation-migration",
                record.activation_migration,
                record.activation_migration_generation,
            ),
            (
                "integrated-target-feature-set",
                "target-feature-set",
                record.target_feature_set,
                record.target_feature_set_generation,
            ),
            (
                "integrated-activation-before",
                "activation",
                record.activation,
                record.activation_generation_before,
            ),
            (
                "integrated-activation-after",
                "activation",
                record.activation,
                record.activation_generation_after,
            ),
            (
                "integrated-context",
                "activation-context",
                record.context,
                record.context_generation_after,
            ),
            ("integrated-source-hart", "hart", record.source_hart, record.source_hart_generation),
            ("integrated-target-hart", "hart", record.target_hart, record.target_hart_generation),
            (
                "integrated-source-queue",
                "runnable-queue",
                record.source_queue,
                record.source_queue_generation,
            ),
            (
                "integrated-target-queue",
                "runnable-queue",
                record.target_queue,
                record.target_queue_generation,
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
        for (label, reference) in [
            ("integrated-source-vector-state", &record.source_vector_state),
            ("integrated-migrated-vector-state", &record.migrated_vector_state),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(reference),
                label,
                "historical",
                Some(record.recorded_at_event),
            ));
        }
    }
    for record in &package.semantic.integrated_network_disk_ios {
        let from = object_ref_json("integrated-network-disk-io", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-network-benchmark",
                "network-benchmark",
                record.network_benchmark,
                record.network_benchmark_generation,
            ),
            (
                "integrated-block-benchmark",
                "block-benchmark",
                record.block_benchmark,
                record.block_benchmark_generation,
            ),
            (
                "integrated-network-owner-store",
                "store",
                record.network_owner_store,
                record.network_owner_store_generation,
            ),
            (
                "integrated-network-adapter",
                "network-stack-adapter",
                record.network_adapter,
                record.network_adapter_generation,
            ),
            (
                "integrated-packet-device",
                "packet-device-object",
                record.packet_device,
                record.packet_device_generation,
            ),
            ("integrated-socket", "socket-object", record.socket, record.socket_generation),
            (
                "integrated-block-device",
                "block-device-object",
                record.block_device,
                record.block_device_generation,
            ),
            (
                "integrated-block-request-queue",
                "block-request-queue",
                record.block_request_queue,
                record.block_request_queue_generation,
            ),
            (
                "integrated-block-dma-buffer",
                "block-dma-buffer",
                record.block_dma_buffer,
                record.block_dma_buffer_generation,
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
            object_ref_manifest_json(&record.block_backend),
            "integrated-block-backend",
            "historical",
            Some(record.recorded_at_event),
        ));
    }
    for record in &package.semantic.integrated_display_scheduler_loads {
        let from =
            object_ref_json("integrated-display-scheduler-load", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-framebuffer-benchmark",
                "framebuffer-benchmark",
                record.framebuffer_benchmark,
                record.framebuffer_benchmark_generation,
            ),
            (
                "integrated-scheduler-decision",
                "scheduler-decision",
                record.scheduler_decision,
                record.scheduler_decision_generation,
            ),
            ("integrated-owner-store", "store", record.owner_store, record.owner_store_generation),
            ("integrated-owner-task", "task", record.owner_task, record.owner_task_generation),
            ("integrated-runnable-queue", "runnable-queue", record.queue, record.queue_generation),
            (
                "integrated-selected-activation",
                "activation",
                record.selected_activation,
                record.selected_activation_generation,
            ),
            ("integrated-display", "display-object", record.display, record.display_generation),
            (
                "integrated-framebuffer",
                "framebuffer-object",
                record.framebuffer,
                record.framebuffer_generation,
            ),
            (
                "integrated-display-capability",
                "display-capability",
                record.display_capability,
                record.display_capability_generation,
            ),
            (
                "integrated-framebuffer-write",
                "framebuffer-write",
                record.framebuffer_write,
                record.framebuffer_write_generation,
            ),
            (
                "integrated-framebuffer-flush-region",
                "framebuffer-flush-region",
                record.framebuffer_flush_region,
                record.framebuffer_flush_region_generation,
            ),
            (
                "integrated-display-event-log",
                "display-event-log",
                record.display_event_log,
                record.display_event_log_generation,
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
    for record in &package.semantic.integrated_snapshot_io_lease_barriers {
        let from =
            object_ref_json("integrated-snapshot-io-lease-barrier", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-smp-snapshot-barrier",
                "smp-snapshot-barrier",
                record.smp_snapshot_barrier,
                record.smp_snapshot_barrier_generation,
            ),
            (
                "integrated-io-cleanup",
                "io-cleanup",
                record.io_cleanup,
                record.io_cleanup_generation,
            ),
            (
                "integrated-display-snapshot-barrier",
                "display-snapshot-barrier",
                record.display_snapshot_barrier,
                record.display_snapshot_barrier_generation,
            ),
            (
                "integrated-driver-store",
                "store",
                record.driver_store,
                record.driver_store_generation,
            ),
            ("integrated-device", "device-object", record.device, record.device_generation),
            ("integrated-display", "display-object", record.display, record.display_generation),
            (
                "integrated-framebuffer",
                "framebuffer-object",
                record.framebuffer,
                record.framebuffer_generation,
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
    for record in &package.semantic.integrated_code_publish_smp_workloads {
        let from =
            object_ref_json("integrated-code-publish-smp-workload", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-smp-stress-run",
                "smp-stress-run",
                record.smp_stress_run,
                record.smp_stress_run_generation,
            ),
            (
                "integrated-smp-code-publish-barrier",
                "smp-code-publish-barrier",
                record.smp_code_publish_barrier,
                record.smp_code_publish_barrier_generation,
            ),
            (
                "integrated-publish-rendezvous",
                "stop-the-world-rendezvous",
                record.publish_rendezvous,
                record.publish_rendezvous_generation,
            ),
            (
                "integrated-publish-safe-point",
                "smp-safe-point",
                record.publish_safe_point,
                record.publish_safe_point_generation,
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
    for record in &package.semantic.integrated_display_panics {
        let from = object_ref_json("integrated-display-panic", record.id, record.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-panic-last-frame",
                record.display_panic_last_frame,
                record.display_panic_last_frame_generation,
            ),
            "integrated-display-panic->display-panic-last-frame",
            "historical",
            Some(record.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            serde_json::json!({
                "kind": "substrate-event",
                "id": record.substrate_panic_event,
                "generation": 1,
            }),
            "integrated-display-panic->substrate-panic-event",
            "historical",
            Some(record.recorded_at_event),
        ));
    }
    for record in &package.semantic.integrated_osctl_trace_replays {
        let from = object_ref_json("integrated-osctl-trace-replay", record.id, record.generation);
        for (label, kind, id, generation) in [
            (
                "integrated-osctl-trace-replay->x0-smp-preemption-cleanup",
                "integrated-smp-preemption-cleanup",
                record.integrated_smp_preemption_cleanup,
                record.integrated_smp_preemption_cleanup_generation,
            ),
            (
                "integrated-osctl-trace-replay->x1-smp-network-fault",
                "integrated-smp-network-fault",
                record.integrated_smp_network_fault,
                record.integrated_smp_network_fault_generation,
            ),
            (
                "integrated-osctl-trace-replay->x2-disk-preempt-fault",
                "integrated-disk-preempt-fault",
                record.integrated_disk_preempt_fault,
                record.integrated_disk_preempt_fault_generation,
            ),
            (
                "integrated-osctl-trace-replay->x3-simd-migration",
                "integrated-simd-migration",
                record.integrated_simd_migration,
                record.integrated_simd_migration_generation,
            ),
            (
                "integrated-osctl-trace-replay->x4-network-disk-io",
                "integrated-network-disk-io",
                record.integrated_network_disk_io,
                record.integrated_network_disk_io_generation,
            ),
            (
                "integrated-osctl-trace-replay->x5-display-scheduler-load",
                "integrated-display-scheduler-load",
                record.integrated_display_scheduler_load,
                record.integrated_display_scheduler_load_generation,
            ),
            (
                "integrated-osctl-trace-replay->x6-snapshot-io-lease-barrier",
                "integrated-snapshot-io-lease-barrier",
                record.integrated_snapshot_io_lease_barrier,
                record.integrated_snapshot_io_lease_barrier_generation,
            ),
            (
                "integrated-osctl-trace-replay->x7-code-publish-smp-workload",
                "integrated-code-publish-smp-workload",
                record.integrated_code_publish_smp_workload,
                record.integrated_code_publish_smp_workload_generation,
            ),
            (
                "integrated-osctl-trace-replay->x8-display-panic",
                "integrated-display-panic",
                record.integrated_display_panic,
                record.integrated_display_panic_generation,
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
}
