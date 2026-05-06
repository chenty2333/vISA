use super::super::*;

pub(super) fn push_block_fs_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
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
}
