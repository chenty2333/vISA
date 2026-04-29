use super::*;
pub(crate) fn history_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
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
    for completion in &package.semantic.block_completion_objects {
        if completion.state != "recorded" {
            continue;
        }
        let from = object_ref_json("block-completion", completion.id, completion.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
            "block-completion->block-request",
            "historical",
            Some(completion.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                completion.block_device,
                completion.block_device_generation,
            ),
            "block-completion->block-device",
            "historical",
            Some(completion.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-range",
                completion.block_range,
                completion.block_range_generation,
            ),
            "block-completion->block-range",
            "historical",
            Some(completion.recorded_at_event),
        ));
    }
    for block_wait in &package.semantic.block_waits {
        if block_wait.state == "pending" {
            continue;
        }
        let event = block_wait.completed_at_event.or(Some(block_wait.created_at_event));
        let from = object_ref_json("block-wait", block_wait.id, block_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", block_wait.wait, block_wait.wait_generation),
            "block-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                block_wait.block_request,
                block_wait.block_request_generation,
            ),
            "block-wait->block-request",
            "historical",
            event,
        ));
        if let (Some(completion), Some(generation)) =
            (block_wait.completion, block_wait.completion_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("block-completion", completion, generation),
                "block-wait->block-completion",
                "historical",
                event,
            ));
        }
    }
    for wait in &package.semantic.fs_waits {
        if wait.state == "pending" {
            continue;
        }
        let event = wait.completed_at_event.or(Some(wait.created_at_event));
        let from = object_ref_json("fs-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "fs-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "fs-wait->file-handle-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", wait.file_object, wait.file_object_generation),
            "fs-wait->file-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "fs-wait->blocker",
            "historical",
            event,
        ));
    }
    for cleanup in &package.semantic.block_driver_cleanups {
        let event = cleanup.completed_at_event.or(Some(cleanup.started_at_event));
        let from = object_ref_json("block-driver-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("io-cleanup", cleanup.io_cleanup, cleanup.io_cleanup_generation),
            "block-driver-cleanup->io-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.driver_store, cleanup.driver_store_generation),
            "block-driver-cleanup->driver-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", cleanup.device, cleanup.device_generation),
            "block-driver-cleanup->device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "block-driver-cleanup->driver-binding",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", cleanup.block_device, cleanup.block_device_generation),
            "block-driver-cleanup->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cleanup.backend),
            "block-driver-cleanup->backend",
            "historical",
            event,
        ));
        for target in &cleanup.cancelled_block_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->cancelled-block-wait",
                "historical",
                event,
            ));
        }
        for target in &cleanup.cancelled_wait_tokens {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->cancelled-wait-token",
                "historical",
                event,
            ));
        }
        for target in &cleanup.released_dma_buffers {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->released-dma-buffer",
                "historical",
                event,
            ));
        }
        for target in &cleanup.revoked_device_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                "block-driver-cleanup->revoked-device-capability",
                "historical",
                event,
            ));
        }
    }
    for policy in &package.semantic.block_pending_io_policies {
        let event = Some(policy.recorded_at_event);
        let from = object_ref_json("block-pending-io-policy", policy.id, policy.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-wait", policy.block_wait, policy.block_wait_generation),
            "block-pending-io-policy->block-wait",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", policy.wait, policy.wait_generation),
            "block-pending-io-policy->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-request", policy.block_request, policy.block_request_generation),
            "block-pending-io-policy->block-request",
            "historical",
            event,
        ));
        if let (Some(retry), Some(generation)) =
            (policy.retry_request, policy.retry_request_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("block-request", retry, generation),
                "block-pending-io-policy->retry-request",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", policy.block_device, policy.block_device_generation),
            "block-pending-io-policy->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("block-range", policy.block_range, policy.block_range_generation),
            "block-pending-io-policy->block-range",
            "historical",
            event,
        ));
    }
    for audit in &package.semantic.block_request_generation_audits {
        let event = Some(audit.recorded_at_event);
        let from = object_ref_json("block-request-generation-audit", audit.id, audit.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", audit.block_device, audit.block_device_generation),
            "block-request-generation-audit->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", audit.block_range, audit.block_range_generation),
            "block-request-generation-audit->block-range",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-request", audit.block_request, audit.block_request_generation),
            "block-request-generation-audit->block-request",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&audit.backend),
            "block-request-generation-audit->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&audit.dma_buffer),
            "block-request-generation-audit->dma-buffer",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.block_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("block-benchmark", benchmark.id, benchmark.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&benchmark.backend),
            "block-benchmark->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block-benchmark->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", benchmark.block_range, benchmark.block_range_generation),
            "block-benchmark->block-range",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-read-path", benchmark.read_path, benchmark.read_path_generation),
            "block-benchmark->read-path",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-write-path",
                benchmark.write_path,
                benchmark.write_path_generation,
            ),
            "block-benchmark->write-path",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request-queue",
                benchmark.request_queue,
                benchmark.request_queue_generation,
            ),
            "block-benchmark->request-queue",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-dma-buffer",
                benchmark.block_dma_buffer,
                benchmark.block_dma_buffer_generation,
            ),
            "block-benchmark->block-dma-buffer",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.block_recovery_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("block-recovery-benchmark", benchmark.id, benchmark.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "block-recovery-benchmark->block-driver-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("io-cleanup", benchmark.io_cleanup, benchmark.io_cleanup_generation),
            "block-recovery-benchmark->io-cleanup",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&benchmark.backend),
            "block-recovery-benchmark->backend",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block-recovery-benchmark->block-device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", benchmark.driver_store, benchmark.driver_store_generation),
            "block-recovery-benchmark->driver-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", benchmark.device, benchmark.device_generation),
            "block-recovery-benchmark->device",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "driver-store-binding",
                benchmark.driver_binding,
                benchmark.driver_binding_generation,
            ),
            "block-recovery-benchmark->driver-binding",
            "historical",
            event,
        ));
    }
    for feature in &package.semantic.target_feature_sets {
        let event = Some(feature.recorded_at_event);
        edges.push(graph_edge(
            object_ref_json("target-feature-set", feature.id, feature.generation),
            object_ref_json("event", feature.recorded_at_event, 1),
            "target-feature-set->event",
            "historical",
            event,
        ));
    }
    for vector_state in &package.semantic.vector_states {
        let event = Some(vector_state.recorded_at_event);
        let from = object_ref_json("vector-state", vector_state.id, vector_state.generation);
        for (target, label, mode) in [
            (
                &vector_state.owner_activation,
                "vector-state->activation",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.owner_store,
                "vector-state->store",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.code_object,
                "vector-state->code-object",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.target_feature_set,
                "vector-state->target-feature-set",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                mode,
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", vector_state.recorded_at_event, 1),
            "vector-state->event",
            "historical",
            event,
        ));
    }
    for injection in &package.semantic.simd_fault_injections {
        let event = Some(injection.recorded_at_event);
        let from = object_ref_json("simd-fault-injection", injection.id, injection.generation);
        for (target, label) in [
            (&injection.activation, "simd-fault-injection->activation"),
            (&injection.code_object, "simd-fault-injection->code-object"),
            (&injection.trap, "simd-fault-injection->trap"),
            (&injection.target_feature_set, "simd-fault-injection->target-feature-set"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        if let Some(vector_state) = &injection.vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(vector_state),
                "simd-fault-injection->vector-state",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", injection.recorded_at_event, 1),
            "simd-fault-injection->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("simd-benchmark", benchmark.id, benchmark.generation);
        for (target, label) in [
            (&benchmark.target_feature_set, "simd-benchmark->target-feature-set"),
            (&benchmark.scalar_code_object, "simd-benchmark->scalar-code-object"),
            (&benchmark.vector_code_object, "simd-benchmark->vector-code-object"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-benchmark->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_context_switch_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from =
            object_ref_json("simd-context-switch-benchmark", benchmark.id, benchmark.generation);
        for (target, label) in [
            (&benchmark.preemption, "simd-context-switch-benchmark->preemption"),
            (&benchmark.activation_resume, "simd-context-switch-benchmark->activation-resume"),
            (&benchmark.saved_vector_state, "simd-context-switch-benchmark->saved-vector-state"),
            (
                &benchmark.restored_vector_state,
                "simd-context-switch-benchmark->restored-vector-state",
            ),
            (&benchmark.target_feature_set, "simd-context-switch-benchmark->target-feature-set"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-context-switch-benchmark->event",
            "historical",
            event,
        ));
    }
    for framebuffer in &package.semantic.framebuffer_objects {
        let event = Some(framebuffer.recorded_at_event);
        let from = object_ref_json("framebuffer-object", framebuffer.id, framebuffer.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
            "framebuffer-object->resource",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", framebuffer.recorded_at_event, 1),
            "framebuffer-object->event",
            "historical",
            event,
        ));
    }
    for display in &package.semantic.display_objects {
        let event = Some(display.recorded_at_event);
        let from = object_ref_json("display-object", display.id, display.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "display-object->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", display.recorded_at_event, 1),
            "display-object->event",
            "historical",
            event,
        ));
    }
    for capability in &package.semantic.display_capabilities {
        let event = Some(capability.recorded_at_event);
        let from = object_ref_json("display-capability", capability.id, capability.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", capability.owner_store, capability.owner_store_generation),
            "display-capability->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", capability.display, capability.display_generation),
            "display-capability->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
            ),
            "display-capability->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("capability", capability.capability, capability.capability_generation),
            "display-capability->capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", capability.recorded_at_event, 1),
            "display-capability->event",
            "historical",
            event,
        ));
    }
    for lease in &package.semantic.framebuffer_window_leases {
        let event = Some(lease.recorded_at_event);
        let from = object_ref_json("framebuffer-window-lease", lease.id, lease.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", lease.owner_store, lease.owner_store_generation),
            "framebuffer-window-lease->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "framebuffer-window-lease->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", lease.display, lease.display_generation),
            "framebuffer-window-lease->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", lease.framebuffer, lease.framebuffer_generation),
            "framebuffer-window-lease->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", lease.recorded_at_event, 1),
            "framebuffer-window-lease->event",
            "historical",
            event,
        ));
    }
    for mapping in &package.semantic.framebuffer_mappings {
        let event = Some(mapping.recorded_at_event);
        let from = object_ref_json("framebuffer-mapping", mapping.id, mapping.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", mapping.owner_store, mapping.owner_store_generation),
            "framebuffer-mapping->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "framebuffer-mapping->framebuffer-window-lease",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "framebuffer-mapping->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", mapping.display, mapping.display_generation),
            "framebuffer-mapping->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "framebuffer-mapping->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", mapping.recorded_at_event, 1),
            "framebuffer-mapping->event",
            "historical",
            event,
        ));
    }
    for write in &package.semantic.framebuffer_writes {
        let event = Some(write.recorded_at_event);
        let from = object_ref_json("framebuffer-write", write.id, write.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", write.owner_store, write.owner_store_generation),
            "framebuffer-write->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer-write->framebuffer-mapping",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "framebuffer-write->framebuffer-window-lease",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "framebuffer-write->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", write.display, write.display_generation),
            "framebuffer-write->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", write.framebuffer, write.framebuffer_generation),
            "framebuffer-write->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", write.recorded_at_event, 1),
            "framebuffer-write->event",
            "historical",
            event,
        ));
    }
    for flush in &package.semantic.framebuffer_flush_regions {
        let event = Some(flush.recorded_at_event);
        let from = object_ref_json("framebuffer-flush-region", flush.id, flush.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", flush.owner_store, flush.owner_store_generation),
            "framebuffer-flush-region->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "framebuffer-flush-region->framebuffer-write",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "framebuffer-flush-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", flush.display, flush.display_generation),
            "framebuffer-flush-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", flush.framebuffer, flush.framebuffer_generation),
            "framebuffer-flush-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", flush.recorded_at_event, 1),
            "framebuffer-flush-region->event",
            "historical",
            event,
        ));
    }
    for dirty in &package.semantic.framebuffer_dirty_regions {
        let event = Some(dirty.recorded_at_event);
        let from = object_ref_json("framebuffer-dirty-region", dirty.id, dirty.generation);
        let owner_mode = if dirty.state == "dirty" { "live" } else { "historical" };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", dirty.owner_store, dirty.owner_store_generation),
            "framebuffer-dirty-region->owner-store",
            owner_mode,
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer-dirty-region->framebuffer-write",
            "historical",
            event,
        ));
        if let (Some(flush), Some(generation)) =
            (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("framebuffer-flush-region", flush, generation),
                "framebuffer-dirty-region->framebuffer-flush-region",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "framebuffer-dirty-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", dirty.display, dirty.display_generation),
            "framebuffer-dirty-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", dirty.framebuffer, dirty.framebuffer_generation),
            "framebuffer-dirty-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", dirty.recorded_at_event, 1),
            "framebuffer-dirty-region->event",
            "historical",
            event,
        ));
    }
    for log in &package.semantic.display_event_logs {
        let event = Some(log.recorded_at_event);
        let from = object_ref_json("display-event-log", log.id, log.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", log.owner_store, log.owner_store_generation),
            "display-event-log->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "display-event-log->framebuffer-dirty-region",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display-event-log->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", log.display, log.display_generation),
            "display-event-log->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", log.framebuffer, log.framebuffer_generation),
            "display-event-log->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", log.recorded_at_event, 1),
            "display-event-log->event",
            "historical",
            event,
        ));
    }
    for cleanup in &package.semantic.display_cleanups {
        let event = Some(cleanup.completed_at_event);
        let from = object_ref_json("display-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.owner_store, cleanup.owner_store_generation),
            "display-cleanup->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display-cleanup->display-capability",
            "cleanup-effect",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", cleanup.display, cleanup.display_generation),
            "display-cleanup->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
            "display-cleanup->framebuffer-object",
            "historical",
            event,
        ));
        for mapping in &cleanup.unmapped_framebuffer_mappings {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&mapping.kind, mapping.id, mapping.generation),
                "display-cleanup->unmapped-framebuffer-mapping",
                "cleanup-effect",
                event,
            ));
        }
        for lease in &cleanup.released_framebuffer_window_leases {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&lease.kind, lease.id, lease.generation),
                "display-cleanup->released-framebuffer-window-lease",
                "cleanup-effect",
                event,
            ));
        }
        for display_capability in &cleanup.revoked_display_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    &display_capability.kind,
                    display_capability.id,
                    display_capability.generation,
                ),
                "display-cleanup->revoked-display-capability",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&capability.kind, capability.id, capability.generation),
                "display-cleanup->revoked-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for barrier in &package.semantic.display_snapshot_barriers {
        let event = Some(barrier.validated_at_event);
        let from = object_ref_json("display-snapshot-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", barrier.owner_store, barrier.owner_store_generation),
            "display-snapshot-barrier->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", barrier.display, barrier.display_generation),
            "display-snapshot-barrier->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display-snapshot-barrier->framebuffer-object",
            "historical",
            event,
        ));
        if let (Some(cleanup), Some(cleanup_generation)) =
            (barrier.display_cleanup, barrier.display_cleanup_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("display-cleanup", cleanup, cleanup_generation),
                "display-snapshot-barrier->display-cleanup",
                "historical",
                event,
            ));
        }
    }
    for frame in &package.semantic.display_panic_last_frames {
        let event = Some(frame.recorded_at_event);
        let from = object_ref_json("display-panic-last-frame", frame.id, frame.generation);
        for (relation, to) in [
            (
                "display-panic-last-frame->owner-store",
                object_ref_json("store", frame.owner_store, frame.owner_store_generation),
            ),
            (
                "display-panic-last-frame->display-object",
                object_ref_json("display-object", frame.display, frame.display_generation),
            ),
            (
                "display-panic-last-frame->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    frame.framebuffer,
                    frame.framebuffer_generation,
                ),
            ),
            (
                "display-panic-last-frame->snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                ),
            ),
            (
                "display-panic-last-frame->display-event-log",
                object_ref_json(
                    "display-event-log",
                    frame.display_event_log,
                    frame.display_event_log_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
    for benchmark in &package.semantic.framebuffer_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("framebuffer-benchmark", benchmark.id, benchmark.generation);
        for (relation, to) in [
            (
                "framebuffer-benchmark->owner-store",
                object_ref_json("store", benchmark.owner_store, benchmark.owner_store_generation),
            ),
            (
                "framebuffer-benchmark->display-object",
                object_ref_json("display-object", benchmark.display, benchmark.display_generation),
            ),
            (
                "framebuffer-benchmark->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-capability",
                object_ref_json(
                    "display-capability",
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-event-log",
                object_ref_json(
                    "display-event-log",
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
    for operation in &package.semantic.socket_operations {
        if operation.state != "applied" {
            continue;
        }
        let from = object_ref_json("socket-operation", operation.id, operation.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", operation.endpoint, operation.endpoint_generation),
            "socket-operation->endpoint-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", operation.socket, operation.socket_generation),
            "socket-operation->socket-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                operation.adapter,
                operation.adapter_generation,
            ),
            "socket-operation->network-stack-adapter",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", operation.owner_store, operation.owner_store_generation),
            "socket-operation->owner-store",
            "historical",
            Some(operation.recorded_at_event),
        ));
    }
    for wait in &package.semantic.socket_waits {
        if wait.state == "pending" {
            continue;
        }
        let event = wait.completed_at_event.or(Some(wait.created_at_event));
        let from = object_ref_json("socket-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "socket-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", wait.endpoint, wait.endpoint_generation),
            "socket-wait->endpoint-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", wait.socket, wait.socket_generation),
            "socket-wait->socket-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("network-stack-adapter", wait.adapter, wait.adapter_generation),
            "socket-wait->network-stack-adapter",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", wait.owner_store, wait.owner_store_generation),
            "socket-wait->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "socket-wait->blocker",
            if wait.blocker.kind == "external" { "external" } else { "historical" },
            event,
        ));
    }
    for backpressure in &package.semantic.network_backpressures {
        let from =
            object_ref_json("network-backpressure", backpressure.id, backpressure.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "network-backpressure->network-stack-adapter",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "network-backpressure->packet-device",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "network-backpressure->packet-queue",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        if let (Some(endpoint), Some(endpoint_generation)) =
            (backpressure.endpoint, backpressure.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-backpressure->endpoint-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (backpressure.socket, backpressure.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-backpressure->socket-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(store), Some(store_generation)) =
            (backpressure.owner_store, backpressure.owner_store_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("store", store, store_generation),
                "network-backpressure->owner-store",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
    }
    for cleanup in &package.semantic.network_driver_cleanups {
        let from = object_ref_json("network-driver-cleanup", cleanup.id, cleanup.generation);
        let event = cleanup.completed_at_event.or(Some(cleanup.started_at_event));
        for (target, relation) in [
            (
                object_ref_json("io-cleanup", cleanup.io_cleanup, cleanup.io_cleanup_generation),
                "network-driver-cleanup->io-cleanup",
            ),
            (
                object_ref_json("store", cleanup.driver_store, cleanup.driver_store_generation),
                "network-driver-cleanup->driver-store",
            ),
            (
                object_ref_json("device", cleanup.device, cleanup.device_generation),
                "network-driver-cleanup->device",
            ),
            (
                object_ref_json(
                    "driver-store-binding",
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                ),
                "network-driver-cleanup->driver-binding",
            ),
            (
                object_ref_json(
                    "packet-device",
                    cleanup.packet_device,
                    cleanup.packet_device_generation,
                ),
                "network-driver-cleanup->packet-device",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    cleanup.adapter,
                    cleanup.adapter_generation,
                ),
                "network-driver-cleanup->network-stack-adapter",
            ),
            (object_ref_manifest_json(&cleanup.backend), "network-driver-cleanup->backend"),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        for socket_wait in &cleanup.cancelled_socket_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(socket_wait),
                "network-driver-cleanup->cancelled-socket-wait",
                "cleanup-effect",
                event,
            ));
        }
        for wait in &cleanup.cancelled_wait_tokens {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(wait),
                "network-driver-cleanup->cancelled-wait-token",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_packet_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "network-driver-cleanup->revoked-packet-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for audit in &package.semantic.network_generation_audits {
        let from = object_ref_json("network-generation-audit", audit.id, audit.generation);
        let event = Some(audit.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json("network-stack-adapter", audit.adapter, audit.adapter_generation),
                "network-generation-audit->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    audit.packet_device,
                    audit.packet_device_generation,
                ),
                "network-generation-audit->packet-device",
            ),
            (
                object_ref_json("packet-queue", audit.packet_queue, audit.packet_queue_generation),
                "network-generation-audit->packet-queue",
            ),
            (
                object_ref_json(
                    "packet-descriptor",
                    audit.packet_descriptor,
                    audit.packet_descriptor_generation,
                ),
                "network-generation-audit->packet-descriptor",
            ),
            (
                object_ref_json(
                    "packet-buffer",
                    audit.packet_buffer,
                    audit.packet_buffer_generation,
                ),
                "network-generation-audit->packet-buffer",
            ),
            (object_ref_manifest_json(&audit.dma_buffer), "network-generation-audit->dma-buffer"),
            (
                object_ref_manifest_json(&audit.device_capability),
                "network-generation-audit->device-capability",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
    }
    for injection in &package.semantic.network_fault_injections {
        let from = object_ref_json("network-fault-injection", injection.id, injection.generation);
        let event = Some(injection.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    injection.adapter,
                    injection.adapter_generation,
                ),
                "network-fault-injection->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    injection.packet_device,
                    injection.packet_device_generation,
                ),
                "network-fault-injection->packet-device",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    injection.packet_queue,
                    injection.packet_queue_generation,
                ),
                "network-fault-injection->packet-queue",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(packet_descriptor), Some(packet_descriptor_generation)) =
            (injection.packet_descriptor, injection.packet_descriptor_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "packet-descriptor",
                    packet_descriptor,
                    packet_descriptor_generation,
                ),
                "network-fault-injection->packet-descriptor",
                "historical",
                event,
            ));
        }
        if let (Some(packet_buffer), Some(packet_buffer_generation)) =
            (injection.packet_buffer, injection.packet_buffer_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("packet-buffer", packet_buffer, packet_buffer_generation),
                "network-fault-injection->packet-buffer",
                "historical",
                event,
            ));
        }
        if let (Some(endpoint), Some(endpoint_generation)) =
            (injection.endpoint, injection.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-fault-injection->endpoint-object",
                "historical",
                event,
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (injection.socket, injection.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-fault-injection->socket-object",
                "historical",
                event,
            ));
        }
        if let (Some(owner_store), Some(owner_store_generation)) =
            (injection.owner_store, injection.owner_store_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", owner_store, owner_store_generation),
                "network-fault-injection->owner-store",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_benchmarks {
        let from = object_ref_json("network-benchmark", benchmark.id, benchmark.generation);
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-benchmark->packet-device",
            ),
            (
                object_ref_json("packet-queue", benchmark.tx_queue, benchmark.tx_queue_generation),
                "network-benchmark->tx-queue",
            ),
            (
                object_ref_json("packet-queue", benchmark.rx_queue, benchmark.rx_queue_generation),
                "network-benchmark->rx-queue",
            ),
            (
                object_ref_json(
                    "network-tx-completion",
                    benchmark.tx_completion,
                    benchmark.tx_completion_generation,
                ),
                "network-benchmark->tx-completion",
            ),
            (
                object_ref_json(
                    "network-rx-wait-resolution",
                    benchmark.rx_wait_resolution,
                    benchmark.rx_wait_resolution_generation,
                ),
                "network-benchmark->rx-wait-resolution",
            ),
            (
                object_ref_json(
                    "endpoint-object",
                    benchmark.endpoint,
                    benchmark.endpoint_generation,
                ),
                "network-benchmark->endpoint-object",
            ),
            (
                object_ref_json("socket-object", benchmark.socket, benchmark.socket_generation),
                "network-benchmark->socket-object",
            ),
            (
                object_ref_json("store", benchmark.owner_store, benchmark.owner_store_generation),
                "network-benchmark->owner-store",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(backpressure), Some(backpressure_generation)) =
            (benchmark.backpressure, benchmark.backpressure_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("network-backpressure", backpressure, backpressure_generation),
                "network-benchmark->network-backpressure",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_recovery_benchmarks {
        let from =
            object_ref_json("network-recovery-benchmark", benchmark.id, benchmark.generation);
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-driver-cleanup",
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                ),
                "network-recovery-benchmark->network-driver-cleanup",
            ),
            (
                object_ref_json(
                    "io-cleanup",
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                ),
                "network-recovery-benchmark->io-cleanup",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-recovery-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-recovery-benchmark->packet-device",
            ),
            (object_ref_manifest_json(&benchmark.backend), "network-recovery-benchmark->backend"),
            (
                object_ref_json("store", benchmark.driver_store, benchmark.driver_store_generation),
                "network-recovery-benchmark->driver-store",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(fault_injection), Some(fault_injection_generation)) =
            (benchmark.fault_injection, benchmark.fault_injection_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "network-fault-injection",
                    fault_injection,
                    fault_injection_generation,
                ),
                "network-recovery-benchmark->network-fault-injection",
                "historical",
                event,
            ));
        }
    }
    for rx in &package.semantic.network_rx_interrupts {
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json("irq-event", rx.irq_event, rx.irq_event_generation),
            "network-rx-interrupt->irq-event",
            "historical",
            Some(rx.recorded_at_event),
        ));
    }
    for resolution in &package.semantic.network_rx_wait_resolutions {
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json("io-wait", resolution.io_wait, resolution.io_wait_generation),
            "network-rx-wait-resolution->io-wait",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json(
                "network-rx-interrupt",
                resolution.rx_interrupt,
                resolution.rx_interrupt_generation,
            ),
            "network-rx-wait-resolution->rx-interrupt",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json("packet-queue", resolution.rx_queue, resolution.rx_queue_generation),
            "network-rx-wait-resolution->rx-queue",
            "historical",
            Some(resolution.resolved_at_event),
        ));
    }
    for gate in &package.semantic.network_tx_capability_gates {
        let from = object_ref_json("network-tx-capability-gate", gate.id, gate.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                gate.packet_descriptor,
                gate.packet_descriptor_generation,
            ),
            "network-tx-capability-gate->packet-descriptor",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("packet-device", gate.packet_device, gate.packet_device_generation),
            "network-tx-capability-gate->packet-device",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                gate.device_capability,
                gate.device_capability_generation,
            ),
            "network-tx-capability-gate->device-capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", gate.capability, gate.capability_generation),
            "network-tx-capability-gate->capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
    }
    for completion in &package.semantic.network_tx_completions {
        let from = object_ref_json("network-tx-completion", completion.id, completion.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-tx-capability-gate",
                completion.tx_gate,
                completion.tx_gate_generation,
            ),
            "network-tx-completion->tx-gate",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
            "network-tx-completion->backend",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                completion.packet_descriptor,
                completion.packet_descriptor_generation,
            ),
            "network-tx-completion->packet-descriptor",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-buffer",
                completion.packet_buffer,
                completion.packet_buffer_generation,
            ),
            "network-tx-completion->packet-buffer",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "packet-device",
                completion.packet_device,
                completion.packet_device_generation,
            ),
            "network-tx-completion->packet-device",
            "historical",
            Some(completion.completed_at_event),
        ));
    }
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
    for device in &package.semantic.device_objects {
        edges.push(graph_edge(
            object_ref_json("device", device.id, device.generation),
            object_ref_json("resource", device.resource, device.resource_generation),
            "device-resource",
            "live",
            Some(device.recorded_at_event),
        ));
    }
    for queue in &package.semantic.queue_objects {
        edges.push(graph_edge(
            object_ref_json("queue", queue.id, queue.generation),
            object_ref_json("device", queue.device, queue.device_generation),
            "queue-device",
            "live",
            Some(queue.recorded_at_event),
        ));
    }
    for descriptor in &package.semantic.descriptor_objects {
        edges.push(graph_edge(
            object_ref_json("descriptor", descriptor.id, descriptor.generation),
            object_ref_json("queue", descriptor.queue, descriptor.queue_generation),
            "descriptor-queue",
            "live",
            Some(descriptor.recorded_at_event),
        ));
    }
    for dma_buffer in &package.semantic.dma_buffer_objects {
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json("descriptor", dma_buffer.descriptor, dma_buffer.descriptor_generation),
            "dma-buffer-descriptor",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json("resource", dma_buffer.resource, dma_buffer.resource_generation),
            "dma-buffer-resource",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
    }
    for mmio_region in &package.semantic.mmio_region_objects {
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("device", mmio_region.device, mmio_region.device_generation),
            "mmio-region-device",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("resource", mmio_region.resource, mmio_region.resource_generation),
            "mmio-region-resource",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
    }
    for irq_line in &package.semantic.irq_line_objects {
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("device", irq_line.device, irq_line.device_generation),
            "irq-line-device",
            "live",
            Some(irq_line.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("resource", irq_line.resource, irq_line.resource_generation),
            "irq-line-resource",
            "live",
            Some(irq_line.recorded_at_event),
        ));
    }
    for irq_event in &package.semantic.irq_events {
        let from = object_ref_json("irq-event", irq_event.id, irq_event.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("irq-line", irq_event.irq_line, irq_event.irq_line_generation),
            "irq-event-line",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", irq_event.device, irq_event.device_generation),
            "irq-event-device",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", irq_event.driver_store, irq_event.driver_store_generation),
            "irq-event-driver-store",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
    }
    for device_capability in &package.semantic.device_capabilities {
        let from = object_ref_json(
            "device-capability",
            device_capability.id,
            device_capability.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation,
            ),
            "device-capability-driver-store",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&device_capability.target),
            "device-capability-target",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation,
            ),
            "device-capability-ledger",
            "live",
            Some(device_capability.recorded_at_event),
        ));
    }
    for binding in &package.semantic.driver_store_bindings {
        let from = object_ref_json("driver-store-binding", binding.id, binding.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", binding.driver_store, binding.driver_store_generation),
            "driver-store-binding-store",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", binding.device, binding.device_generation),
            "driver-store-binding-device",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation,
            ),
            "driver-store-binding-device-capability",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", binding.capability, binding.capability_generation),
            "driver-store-binding-ledger",
            "live",
            Some(binding.recorded_at_event),
        ));
    }
    for io_wait in &package.semantic.io_waits {
        let from = object_ref_json("io-wait", io_wait.id, io_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", io_wait.wait, io_wait.wait_generation),
            "io-wait-token",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", io_wait.driver_store, io_wait.driver_store_generation),
            "io-wait-driver-store",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", io_wait.device, io_wait.device_generation),
            "io-wait-device",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation,
            ),
            "io-wait-driver-binding",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&io_wait.blocker),
            "io-wait-blocker",
            "historical",
            Some(io_wait.created_at_event),
        ));
        if let (Some(irq_event), Some(irq_event_generation)) =
            (io_wait.completion_irq_event, io_wait.completion_irq_event_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("irq-event", irq_event, irq_event_generation),
                "io-wait-completion-irq",
                "historical",
                io_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.io_cleanups {
        let from = object_ref_json("io-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.driver_store, cleanup.driver_store_generation),
            "io-cleanup-driver-store",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", cleanup.device, cleanup.device_generation),
            "io-cleanup-device",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "io-cleanup-driver-binding",
            "historical",
            Some(cleanup.started_at_event),
        ));
        for io_wait in &cleanup.cancelled_io_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(io_wait),
                "cancelled-io-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for device_capability in &cleanup.revoked_device_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(device_capability),
                "revoked-device-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for dma_buffer in &cleanup.released_dma_buffers {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(dma_buffer),
                "released-dma-buffer",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for mmio_region in &cleanup.released_mmio_regions {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(mmio_region),
                "released-mmio-region",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for irq_line in &cleanup.released_irq_lines {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(irq_line),
                "released-irq-line",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for fault in &package.semantic.io_fault_injections {
        let from = object_ref_json("io-fault-injection", fault.id, fault.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", fault.driver_store, fault.driver_store_generation),
            "io-fault-driver-store",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", fault.device, fault.device_generation),
            "io-fault-device",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                fault.driver_binding,
                fault.driver_binding_generation,
            ),
            "io-fault-driver-binding",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&fault.target),
            "io-fault-target",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("io-cleanup", fault.cleanup, fault.cleanup_generation),
            "triggered-cleanup",
            "cleanup-effect",
            Some(fault.injected_at_event),
        ));
    }
    for report in &package.semantic.io_validation_reports {
        let from = object_ref_json("io-validation-report", report.id, report.generation);
        for violation in &report.violations {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&violation.subject),
                &violation.relation,
                "historical",
                Some(report.validated_at_event),
            ));
        }
    }
    for resume in &package.semantic.activation_resumes {
        let from = object_ref_json("activation-resume", resume.id, resume.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                resume.scheduler_decision,
                resume.scheduler_decision_generation,
            ),
            "consumed-decision",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", resume.activation, resume.activation_generation_before),
            "resumed-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", resume.activation, resume.activation_generation_after),
            "resumed-to",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", resume.queue, resume.queue_generation),
            "dequeued-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        if let (Some(context), Some(generation)) = (resume.context, resume.context_generation_after)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation-context", context, generation),
                "restored-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let (Some(saved), Some(generation)) =
            (resume.saved_context, resume.saved_context_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("saved-context", saved, generation),
                "restored-saved-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let Some(saved_vector_state) = &resume.saved_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(saved_vector_state),
                "restores-saved-vector-state",
                "historical",
                resume.vector_restored_at_event.or(Some(resume.resumed_at_event)),
            ));
        }
        if let Some(restored_vector_state) = &resume.restored_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(restored_vector_state),
                "restored-vector-state",
                "historical",
                resume.vector_restored_at_event.or(Some(resume.resumed_at_event)),
            ));
        }
    }
    for activation_wait in &package.semantic.activation_waits {
        let from =
            object_ref_json("activation-wait", activation_wait.id, activation_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_before,
            ),
            "blocked-from",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_after_block,
            ),
            "blocked-to",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", activation_wait.wait, activation_wait.wait_generation),
            "created-wait",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        if let Some(cancel_generation) = activation_wait.activation_generation_after_cancel {
            edges.push(graph_edge(
                from,
                object_ref_json("activation", activation_wait.activation, cancel_generation),
                "cancelled-to",
                "historical",
                activation_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.activation_cleanups {
        let from = object_ref_json("activation-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.target_store_generation),
            "cleanup-target",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.result_store_generation),
            "marked-dead",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", cleanup.activation, cleanup.activation_generation_before),
            "sealed-from",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", cleanup.activation, cleanup.activation_generation_after),
            "sealed-to",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        if let (Some(wait), Some(wait_generation)) = (cleanup.wait, cleanup.wait_generation) {
            edges.push(graph_edge(
                from,
                object_ref_json("wait-token", wait, wait_generation),
                "cancelled-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for sample in &package.semantic.preemption_latency_samples {
        let from = object_ref_json("preemption-latency", sample.id, sample.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "timer-interrupt",
                sample.timer_interrupt,
                sample.timer_interrupt_generation,
            ),
            "measured-from-timer",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("preemption", sample.preemption, sample.preemption_generation),
            "measured-preemption",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                sample.scheduler_decision,
                sample.scheduler_decision_generation,
            ),
            "measured-decision",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "activation-resume",
                sample.activation_resume,
                sample.activation_resume_generation,
            ),
            "measured-resume",
            "historical",
            Some(sample.recorded_at_event),
        ));
    }
    for trap in &package.semantic.trap_records {
        let from = object_ref_json("trap", trap.id, trap.generation);
        if let Some(store) = trap.store {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", store, trap.store_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(activation) = trap.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, trap.activation_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(code_object) = trap.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("code-object", code_object, trap.code_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(artifact) = trap.artifact {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("artifact", artifact, trap.artifact_generation.unwrap_or(1)),
                "recorded",
                "historical",
                None,
            ));
        }
    }
    for hostcall in &package.semantic.hostcall_trace {
        let from = object_ref_json("hostcall", hostcall.id, hostcall.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", hostcall.activation, hostcall.activation_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", hostcall.store, hostcall.store_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("code-object", hostcall.code_object, hostcall.code_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("artifact", hostcall.artifact, hostcall.artifact_generation),
            "recorded",
            "historical",
            None,
        ));
        if let Some(trap) = hostcall.trap_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("trap", trap, hostcall.trap_generation_out.unwrap_or(0)),
                "caused",
                "historical",
                None,
            ));
        }
        if let Some(wait) = hostcall.wait_token_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "wait-token",
                    wait,
                    hostcall.wait_token_generation_out.unwrap_or(0),
                ),
                "caused",
                "historical",
                None,
            ));
        }
    }
    for cleanup in &package.semantic.cleanup_transactions {
        let from = object_ref_json("cleanup", cleanup.id, cleanup.generation);
        let target_generation = if cleanup.target_store_generation == 0 {
            cleanup.store_generation
        } else {
            cleanup.target_store_generation
        };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, target_generation),
            "killed",
            "cleanup-effect",
            Some(cleanup.started_at),
        ));
        if let Some(activation) = cleanup.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "activation",
                    activation,
                    cleanup.activation_generation.unwrap_or(0),
                ),
                "released",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        if let Some(code) = cleanup.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("code-object", code, cleanup.code_generation.unwrap_or(0)),
                "unbound",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for capability in &cleanup.revoked_capability_refs {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for effect in &cleanup.effects {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&effect.target),
                &effect.kind,
                "cleanup-effect",
                Some(effect.event_seq),
            ));
        }
    }
    edges
}
