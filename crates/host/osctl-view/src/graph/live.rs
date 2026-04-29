use super::*;
pub(crate) fn live_graph_edges(package: &MigrationPackageManifest) -> Vec<serde_json::Value> {
    let mut edges = Vec::new();
    for activation in &package.semantic.runtime_activation_records {
        if matches!(activation.state.as_str(), "runnable" | "running" | "pending") {
            let task_generation = package
                .semantic
                .task_records
                .iter()
                .find(|task| {
                    task.id == activation.owner_task
                        && task.generation == activation.owner_task_generation
                })
                .map(|task| task.generation)
                .unwrap_or(activation.owner_task_generation);
            edges.push(graph_edge(
                object_ref_json("task", activation.owner_task, task_generation),
                object_ref_json("activation", activation.id, activation.generation),
                "owns",
                "live",
                activation.last_event,
            ));
            if let (Some(queue), Some(queue_generation)) =
                (activation.runnable_queue, activation.runnable_queue_generation)
            {
                edges.push(graph_edge(
                    object_ref_json("activation", activation.id, activation.generation),
                    object_ref_json("runnable-queue", queue, queue_generation),
                    "queued-in",
                    "live",
                    activation.last_event,
                ));
            }
        }
    }
    for queue in &package.semantic.runnable_queues {
        if queue.state != "active" {
            continue;
        }
        if let (Some(hart), Some(hart_generation)) = (queue.owner_hart, queue.owner_hart_generation)
        {
            edges.push(graph_edge(
                object_ref_json("hart", u64::from(hart), hart_generation),
                object_ref_json("runnable-queue", queue.id, queue.generation),
                "owns-runnable-queue",
                "historical",
                None,
            ));
        }
        for entry in &queue.entries {
            edges.push(graph_edge(
                object_ref_json("runnable-queue", queue.id, queue.generation),
                object_ref_json("activation", entry.activation, entry.activation_generation),
                "contains",
                "live",
                Some(entry.enqueued_at),
            ));
        }
    }
    for context in &package.semantic.activation_contexts {
        if context.state == "dropped" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("activation", context.activation, context.activation_generation),
            object_ref_json("activation-context", context.id, context.generation),
            "has-context",
            "live",
            context.last_event,
        ));
        if let (Some(saved), Some(saved_generation)) =
            (context.current_saved_context, context.current_saved_context_generation)
        {
            edges.push(graph_edge(
                object_ref_json("activation-context", context.id, context.generation),
                object_ref_json("saved-context", saved, saved_generation),
                "current-saved-context",
                "live",
                context.last_event,
            ));
        }
        if let Some(vector_state) = &context.vector_state {
            edges.push(graph_edge(
                object_ref_json("activation-context", context.id, context.generation),
                object_ref_manifest_json(vector_state),
                "vector-context",
                if context.vector_status == "dirty" || context.vector_status == "clean" {
                    "live"
                } else {
                    "historical"
                },
                context.vector_state_event.or(context.last_event),
            ));
        }
    }
    for saved in &package.semantic.saved_contexts {
        if saved.state != "captured" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("activation-context", saved.context, saved.context_generation),
            object_ref_json("saved-context", saved.id, saved.generation),
            "captures",
            "live",
            Some(saved.saved_at_event),
        ));
    }
    for packet_device in &package.semantic.packet_device_objects {
        if packet_device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-device", packet_device.id, packet_device.generation),
            object_ref_json("device", packet_device.device, packet_device.device_generation),
            "packet-device->device",
            "live",
            Some(packet_device.recorded_at_event),
        ));
    }
    for block_device in &package.semantic.block_device_objects {
        if block_device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-device", block_device.id, block_device.generation),
            object_ref_json("device", block_device.device, block_device.device_generation),
            "block-device->device",
            "live",
            Some(block_device.recorded_at_event),
        ));
    }
    for block_range in &package.semantic.block_range_objects {
        if block_range.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-range", block_range.id, block_range.generation),
            object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
            "block-range->block-device",
            "live",
            Some(block_range.recorded_at_event),
        ));
    }
    for request in &package.semantic.block_request_objects {
        if request.state != "submitted" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("block-request", request.id, request.generation),
            object_ref_json("block-device", request.block_device, request.block_device_generation),
            "block-request->block-device",
            "live",
            Some(request.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("block-request", request.id, request.generation),
            object_ref_json("block-range", request.block_range, request.block_range_generation),
            "block-request->block-range",
            "live",
            Some(request.recorded_at_event),
        ));
    }
    for block_wait in &package.semantic.block_waits {
        if block_wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("block-wait", block_wait.id, block_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", block_wait.wait, block_wait.wait_generation),
            "block-wait->wait-token",
            "live",
            Some(block_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                block_wait.block_request,
                block_wait.block_request_generation,
            ),
            "block-wait->block-request",
            "live",
            Some(block_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-device",
                block_wait.block_device,
                block_wait.block_device_generation,
            ),
            "block-wait->block-device",
            "live",
            Some(block_wait.created_at_event),
        ));
    }
    for backend in &package.semantic.fake_block_backends {
        if backend.state != "bound" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("fake-block-backend", backend.id, backend.generation),
            object_ref_json("block-device", backend.block_device, backend.block_device_generation),
            "fake-block-backend->block-device",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for backend in &package.semantic.virtio_blk_backends {
        if backend.state != "skeleton-ready" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("virtio-blk-backend", backend.id, backend.generation),
            object_ref_json("block-device", backend.block_device, backend.block_device_generation),
            "virtio-blk-backend->block-device",
            "live",
            Some(backend.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("virtio-blk-backend", backend.id, backend.generation),
            object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "virtio-blk-backend->driver-binding",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for read_path in &package.semantic.block_read_paths {
        if read_path.state != "completed" {
            continue;
        }
        let from = object_ref_json("block-read-path", read_path.id, read_path.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&read_path.backend_kind),
                read_path.backend,
                read_path.backend_generation,
            ),
            "block-read-path->backend",
            "historical",
            Some(read_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
            "block-read-path->block-request",
            "historical",
            Some(read_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-completion",
                read_path.block_completion,
                read_path.block_completion_generation,
            ),
            "block-read-path->block-completion",
            "historical",
            Some(read_path.recorded_at_event),
        ));
    }
    for write_path in &package.semantic.block_write_paths {
        if write_path.state != "completed" {
            continue;
        }
        let from = object_ref_json("block-write-path", write_path.id, write_path.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&write_path.backend_kind),
                write_path.backend,
                write_path.backend_generation,
            ),
            "block-write-path->backend",
            "historical",
            Some(write_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
            "block-write-path->block-request",
            "historical",
            Some(write_path.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "block-completion",
                write_path.block_completion,
                write_path.block_completion_generation,
            ),
            "block-write-path->block-completion",
            "historical",
            Some(write_path.recorded_at_event),
        ));
    }
    for queue in &package.semantic.block_request_queues {
        if queue.state != "active" {
            continue;
        }
        let from = object_ref_json("block-request-queue", queue.id, queue.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block-request-queue->backend",
            "historical",
            Some(queue.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", queue.block_device, queue.block_device_generation),
            "block-request-queue->block-device",
            "historical",
            Some(queue.recorded_at_event),
        ));
        for entry in &queue.entries {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("block-request", entry.request, entry.request_generation),
                "block-request-queue->block-request",
                "historical",
                Some(queue.recorded_at_event),
            ));
            if let (Some(completion), Some(generation)) =
                (entry.completion, entry.completion_generation)
            {
                edges.push(graph_edge(
                    from.clone(),
                    object_ref_json("block-completion", completion, generation),
                    "block-request-queue->block-completion",
                    "historical",
                    Some(queue.recorded_at_event),
                ));
            }
        }
    }
    for buffer in &package.semantic.block_dma_buffers {
        if buffer.state != "bound" {
            continue;
        }
        let from = object_ref_json("block-dma-buffer", buffer.id, buffer.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block-dma-buffer->backend",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-request", buffer.block_request, buffer.block_request_generation),
            "block-dma-buffer->block-request",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("dma-buffer", buffer.dma_buffer, buffer.dma_buffer_generation),
            "block-dma-buffer->dma-buffer",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", buffer.block_device, buffer.block_device_generation),
            "block-dma-buffer->block-device",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", buffer.block_range, buffer.block_range_generation),
            "block-dma-buffer->block-range",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("descriptor", buffer.descriptor, buffer.descriptor_generation),
            "block-dma-buffer->descriptor",
            "historical",
            Some(buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("queue", buffer.queue, buffer.queue_generation),
            "block-dma-buffer->queue",
            "historical",
            Some(buffer.recorded_at_event),
        ));
    }
    for page in &package.semantic.block_page_objects {
        if page.state != "integrated" {
            continue;
        }
        let from = object_ref_json("block-page-object", page.id, page.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
            "block-page-object->block-dma-buffer",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-request", page.block_request, page.block_request_generation),
            "block-page-object->block-request",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-completion",
                page.block_completion,
                page.block_completion_generation,
            ),
            "block-page-object->block-completion",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("dma-buffer", page.dma_buffer, page.dma_buffer_generation),
            "block-page-object->dma-buffer",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", page.block_device, page.block_device_generation),
            "block-page-object->block-device",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", page.block_range, page.block_range_generation),
            "block-page-object->block-range",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&page.aspace),
            "block-page-object->guest-address-space",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&page.vma_region),
            "block-page-object->vma-region",
            "historical",
            Some(page.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&page.page),
            "block-page-object->page-object",
            "historical",
            Some(page.recorded_at_event),
        ));
    }
    for cache in &package.semantic.buffer_cache_objects {
        if cache.state == "invalidated" {
            continue;
        }
        let from = object_ref_json("buffer-cache-object", cache.id, cache.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-page-object",
                cache.block_page_object,
                cache.block_page_object_generation,
            ),
            "buffer-cache-object->block-page-object",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "block-dma-buffer",
                cache.block_dma_buffer,
                cache.block_dma_buffer_generation,
            ),
            "buffer-cache-object->block-dma-buffer",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", cache.block_device, cache.block_device_generation),
            "buffer-cache-object->block-device",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", cache.block_range, cache.block_range_generation),
            "buffer-cache-object->block-range",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cache.aspace),
            "buffer-cache-object->guest-address-space",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&cache.vma_region),
            "buffer-cache-object->vma-region",
            "historical",
            Some(cache.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&cache.page),
            "buffer-cache-object->page-object",
            "historical",
            Some(cache.recorded_at_event),
        ));
    }
    for file in &package.semantic.file_objects {
        if file.state == "invalidated" {
            continue;
        }
        let from = object_ref_json("file-object", file.id, file.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "buffer-cache-object",
                file.buffer_cache_object,
                file.buffer_cache_object_generation,
            ),
            "file-object->buffer-cache-object",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-device", file.block_device, file.block_device_generation),
            "file-object->block-device",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("block-range", file.block_range, file.block_range_generation),
            "file-object->block-range",
            "historical",
            Some(file.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&file.page),
            "file-object->page-object",
            "historical",
            Some(file.recorded_at_event),
        ));
    }
    for directory in &package.semantic.directory_objects {
        if directory.state == "invalidated" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("directory-object", directory.id, directory.generation),
            object_ref_json("file-object", directory.file_object, directory.file_object_generation),
            "directory-object->file-object",
            "historical",
            Some(directory.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.fat_adapter_objects {
        if adapter.state != "verified" {
            continue;
        }
        let from = object_ref_json("fat-adapter-object", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "fat-adapter-object->directory-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", adapter.file_object, adapter.file_object_generation),
            "fat-adapter-object->file-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("block-device", adapter.block_device, adapter.block_device_generation),
            "fat-adapter-object->block-device",
            "historical",
            Some(adapter.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.ext4_adapter_objects {
        if adapter.state != "verified" {
            continue;
        }
        let from = object_ref_json("ext4-adapter-object", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "ext4-adapter-object->directory-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", adapter.file_object, adapter.file_object_generation),
            "ext4-adapter-object->file-object",
            "historical",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("block-device", adapter.block_device, adapter.block_device_generation),
            "ext4-adapter-object->block-device",
            "historical",
            Some(adapter.recorded_at_event),
        ));
    }
    for capability in &package.semantic.file_handle_capabilities {
        if capability.state != "allowed" {
            continue;
        }
        let from = object_ref_json("file-handle-capability", capability.id, capability.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", capability.owner_store, capability.owner_store_generation),
            "file-handle-capability->store",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-object",
                capability.file_object,
                capability.file_object_generation,
            ),
            "file-handle-capability->file-object",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "directory-object",
                capability.directory_object,
                capability.directory_object_generation,
            ),
            "file-handle-capability->directory-object",
            "historical",
            Some(capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", capability.capability, capability.capability_generation),
            "file-handle-capability->capability",
            "historical",
            Some(capability.recorded_at_event),
        ));
    }
    for wait in &package.semantic.fs_waits {
        if wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("fs-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "fs-wait->wait-token",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "fs-wait->file-handle-capability",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("file-object", wait.file_object, wait.file_object_generation),
            "fs-wait->file-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "fs-wait->blocker",
            "live",
            Some(wait.created_at_event),
        ));
    }
    for packet_buffer in &package.semantic.packet_buffer_objects {
        if packet_buffer.state != "allocated" && packet_buffer.state != "filled" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-buffer", packet_buffer.id, packet_buffer.generation),
            object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation,
            ),
            "packet-buffer->packet-device",
            "live",
            Some(packet_buffer.recorded_at_event),
        ));
    }
    for packet_queue in &package.semantic.packet_queue_objects {
        if packet_queue.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("packet-queue", packet_queue.id, packet_queue.generation),
            object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation,
            ),
            "packet-queue->packet-device",
            "live",
            Some(packet_queue.recorded_at_event),
        ));
    }
    for packet_descriptor in &package.semantic.packet_descriptors {
        if packet_descriptor.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json(
                "packet-descriptor",
                packet_descriptor.id,
                packet_descriptor.generation,
            ),
            object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation,
            ),
            "packet-descriptor->packet-queue",
            "live",
            Some(packet_descriptor.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json(
                "packet-descriptor",
                packet_descriptor.id,
                packet_descriptor.generation,
            ),
            object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation,
            ),
            "packet-descriptor->packet-buffer",
            "live",
            Some(packet_descriptor.recorded_at_event),
        ));
    }
    for backend in &package.semantic.fake_net_backends {
        if backend.state != "bound" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("fake-net-backend", backend.id, backend.generation),
            object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "fake-net-backend->packet-device",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for backend in &package.semantic.virtio_net_backends {
        if backend.state != "skeleton-ready" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("virtio-net-backend", backend.id, backend.generation),
            object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "virtio-net-backend->packet-device",
            "live",
            Some(backend.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("virtio-net-backend", backend.id, backend.generation),
            object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "virtio-net-backend->driver-binding",
            "live",
            Some(backend.recorded_at_event),
        ));
    }
    for adapter in &package.semantic.network_stack_adapters {
        if adapter.state != "bound" {
            continue;
        }
        let from = object_ref_json("network-stack-adapter", adapter.id, adapter.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "network-stack-adapter->backend",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
            "network-stack-adapter->packet-device",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("packet-queue", adapter.rx_queue, adapter.rx_queue_generation),
            "network-stack-adapter->rx-queue",
            "live",
            Some(adapter.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("packet-queue", adapter.tx_queue, adapter.tx_queue_generation),
            "network-stack-adapter->tx-queue",
            "live",
            Some(adapter.recorded_at_event),
        ));
    }
    for socket in &package.semantic.socket_objects {
        if socket.state != "created" {
            continue;
        }
        let from = object_ref_json("socket-object", socket.id, socket.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("network-stack-adapter", socket.adapter, socket.adapter_generation),
            "socket-object->network-stack-adapter",
            "live",
            Some(socket.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", socket.owner_store, socket.owner_store_generation),
            "socket-object->owner-store",
            "live",
            Some(socket.created_at_event),
        ));
    }
    for endpoint in &package.semantic.endpoint_objects {
        if endpoint.state != "allocated" {
            continue;
        }
        let from = object_ref_json("endpoint-object", endpoint.id, endpoint.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", endpoint.socket, endpoint.socket_generation),
            "endpoint-object->socket-object",
            "live",
            Some(endpoint.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("network-stack-adapter", endpoint.adapter, endpoint.adapter_generation),
            "endpoint-object->network-stack-adapter",
            "live",
            Some(endpoint.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", endpoint.owner_store, endpoint.owner_store_generation),
            "endpoint-object->owner-store",
            "live",
            Some(endpoint.created_at_event),
        ));
    }
    for wait in &package.semantic.socket_waits {
        if wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("socket-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "socket-wait->wait-token",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", wait.endpoint, wait.endpoint_generation),
            "socket-wait->endpoint-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", wait.socket, wait.socket_generation),
            "socket-wait->socket-object",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("network-stack-adapter", wait.adapter, wait.adapter_generation),
            "socket-wait->network-stack-adapter",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", wait.owner_store, wait.owner_store_generation),
            "socket-wait->owner-store",
            "live",
            Some(wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "socket-wait->blocker",
            if wait.blocker.kind == "external" { "external" } else { "live" },
            Some(wait.created_at_event),
        ));
    }
    for rx in &package.semantic.network_rx_interrupts {
        if rx.state != "recorded" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "network-rx-interrupt->virtio-net-backend",
            "live",
            Some(rx.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json("packet-queue", rx.rx_queue, rx.rx_queue_generation),
            "network-rx-interrupt->rx-queue",
            "live",
            Some(rx.recorded_at_event),
        ));
    }
    for activation in &package.semantic.activation_records {
        if activation.state == "running" {
            edges.push(graph_edge(
                object_ref_json("store", activation.store, activation.store_generation),
                object_ref_json("activation", activation.id, activation.generation),
                "owns",
                "live",
                Some(activation.start_event),
            ));
            edges.push(graph_edge(
                object_ref_json("activation", activation.id, activation.generation),
                object_ref_json("code-object", activation.code_object, activation.code_generation),
                "bound-to",
                "live",
                Some(activation.start_event),
            ));
        }
    }
    for code in &package.semantic.code_objects {
        if let Some(store) = code.bound_store {
            edges.push(graph_edge(
                object_ref_json("store", store, code.bound_store_generation.unwrap_or(0)),
                object_ref_json("code-object", code.id, code.generation),
                "bound-to",
                "live",
                None,
            ));
        }
    }
    for capability in &package.semantic.capability_records {
        if capability.revoked {
            continue;
        }
        if let Some(store) = capability.owner_store {
            edges.push(graph_edge(
                object_ref_json("store", store, capability.owner_store_generation.unwrap_or(0)),
                object_ref_json("capability", capability.id, capability.generation),
                "owns",
                "live",
                None,
            ));
        }
        if let Some(object_ref) = &capability.object_ref {
            let mode = if object_ref.scope == "external" || object_ref.object.kind == "external" {
                "external"
            } else {
                "live"
            };
            edges.push(graph_edge(
                object_ref_json("capability", capability.id, capability.generation),
                object_ref_manifest_json(&object_ref.object),
                "authorizes",
                mode,
                None,
            ));
        }
    }
    for device in &package.semantic.device_objects {
        if device.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("device", device.id, device.generation),
            object_ref_json("resource", device.resource, device.resource_generation),
            "device-resource",
            "live",
            Some(device.recorded_at_event),
        ));
    }
    for queue in &package.semantic.queue_objects {
        if queue.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("queue", queue.id, queue.generation),
            object_ref_json("device", queue.device, queue.device_generation),
            "queue-device",
            "live",
            Some(queue.recorded_at_event),
        ));
    }
    for descriptor in &package.semantic.descriptor_objects {
        if descriptor.state != "registered" {
            continue;
        }
        edges.push(graph_edge(
            object_ref_json("descriptor", descriptor.id, descriptor.generation),
            object_ref_json("queue", descriptor.queue, descriptor.queue_generation),
            "descriptor-queue",
            "live",
            Some(descriptor.recorded_at_event),
        ));
    }
    for dma_buffer in &package.semantic.dma_buffer_objects {
        if dma_buffer.state != "registered" {
            continue;
        }
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
        if mmio_region.state != "registered" {
            continue;
        }
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
        if irq_line.state != "registered" {
            continue;
        }
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
    for device_capability in &package.semantic.device_capabilities {
        if device_capability.state != "active" {
            continue;
        }
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
        if binding.state != "bound" {
            continue;
        }
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
        if io_wait.state != "pending" {
            continue;
        }
        let from = object_ref_json("io-wait", io_wait.id, io_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", io_wait.wait, io_wait.wait_generation),
            "io-wait-token",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", io_wait.driver_store, io_wait.driver_store_generation),
            "io-wait-driver-store",
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", io_wait.device, io_wait.device_generation),
            "io-wait-device",
            "live",
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
            "live",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&io_wait.blocker),
            "io-wait-blocker",
            "live",
            Some(io_wait.created_at_event),
        ));
    }
    for wait in &package.semantic.wait_records {
        if wait.state != "pending" {
            continue;
        }
        if let Some(store) = wait.owner_store {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_json("store", store, wait.owner_store_generation.unwrap_or(0)),
                "belongs-to",
                "live",
                None,
            ));
        }
        if let Some(task) = wait.owner_task {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_json("task", task, wait.owner_task_generation.unwrap_or(0)),
                "belongs-to",
                "live",
                None,
            ));
        }
        for blocker in &wait.blockers {
            edges.push(graph_edge(
                object_ref_json("wait-token", wait.id, wait.generation),
                object_ref_manifest_json(blocker),
                "blocks-on",
                if blocker.kind == "external" { "external" } else { "live" },
                None,
            ));
        }
    }
    for activation_wait in &package.semantic.activation_waits {
        if activation_wait.state != "pending" {
            continue;
        }
        let from =
            object_ref_json("activation-wait", activation_wait.id, activation_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_after_block,
            ),
            "parks",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", activation_wait.wait, activation_wait.wait_generation),
            "waits-on",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "task",
                activation_wait.owner_task,
                activation_wait.owner_task_generation,
            ),
            "blocks-task",
            "live",
            Some(activation_wait.blocked_at_event),
        ));
    }
    edges
}
