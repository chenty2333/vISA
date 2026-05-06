use super::super::super::*;

pub(crate) fn block_device_object_view_v1(
    block_device: &BlockDeviceObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-device",
        "id": block_device.id,
        "generation": block_device.generation,
        "state": block_device.state,
        "owner": {
            "device": object_ref_json("device", block_device.device, block_device.device_generation),
        },
        "references": {
            "device": object_ref_json("device", block_device.device, block_device.device_generation),
            "event": {
                "id": block_device.recorded_at_event,
            },
        },
        "identity": {
            "name": block_device.name,
        },
        "contract": {
            "sector_size": block_device.sector_size,
            "sector_count": block_device.sector_count,
            "read_only": block_device.read_only,
            "max_transfer_sectors": block_device.max_transfer_sectors,
        },
        "note": block_device.note,
        "last_transition": {
            "recorded_at_event": block_device.recorded_at_event,
            "device_generation": block_device.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_range_object_view_v1(
    block_range: &BlockRangeObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-range",
        "id": block_range.id,
        "generation": block_range.generation,
        "state": block_range.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                block_range.block_device,
                block_range.block_device_generation,
            ),
            "event": {
                "id": block_range.recorded_at_event,
            },
        },
        "sector_range": {
            "start_sector": block_range.start_sector,
            "sector_count": block_range.sector_count,
        },
        "byte_range": {
            "byte_offset": block_range.byte_offset,
            "byte_len": block_range.byte_len,
        },
        "note": block_range.note,
        "last_transition": {
            "recorded_at_event": block_range.recorded_at_event,
            "block_device_generation": block_range.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_request_object_view_v1(
    request: &BlockRequestObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request",
        "id": request.id,
        "generation": request.generation,
        "state": request.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                request.block_device,
                request.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                request.block_device,
                request.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                request.block_range,
                request.block_range_generation,
            ),
            "event": {
                "id": request.recorded_at_event,
            },
        },
        "request": {
            "operation": request.operation,
            "sequence": request.sequence,
            "byte_len": request.byte_len,
        },
        "note": request.note,
        "last_transition": {
            "recorded_at_event": request.recorded_at_event,
            "block_device_generation": request.block_device_generation,
            "block_range_generation": request.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_completion_object_view_v1(
    completion: &BlockCompletionObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-completion",
        "id": completion.id,
        "generation": completion.generation,
        "state": completion.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
        },
        "references": {
            "block_request": object_ref_json(
                "block-request",
                completion.block_request,
                completion.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                completion.block_device,
                completion.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                completion.block_range,
                completion.block_range_generation,
            ),
            "event": {
                "id": completion.recorded_at_event,
            },
        },
        "completion": {
            "sequence": completion.sequence,
            "completed_bytes": completion.completed_bytes,
            "status": completion.status,
        },
        "note": completion.note,
        "last_transition": {
            "recorded_at_event": completion.recorded_at_event,
            "block_request_generation": completion.block_request_generation,
            "block_device_generation": completion.block_device_generation,
            "block_range_generation": completion.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_wait_view_v1(wait: &BlockWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                wait.block_request,
                wait.block_request_generation,
            ),
        },
        "references": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                wait.block_request,
                wait.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                wait.block_device,
                wait.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                wait.block_range,
                wait.block_range_generation,
            ),
            "completion": optional_object_ref_json(
                "block-completion",
                wait.completion,
                wait.completion_generation,
            ),
            "created_event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|event| serde_json::json!({ "id": event })),
        },
        "wait": {
            "operation": wait.operation,
            "sequence": wait.sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "block_request_generation": wait.block_request_generation,
            "block_device_generation": wait.block_device_generation,
            "block_range_generation": wait.block_range_generation,
        },
        "last_error": wait.cancel_reason,
    })
}

pub(crate) fn fake_block_backend_object_view_v1(
    backend: &FakeBlockBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fake-block-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "deterministic_seed": backend.deterministic_seed,
        },
        "contract": {
            "sector_size": backend.sector_size,
            "sector_count": backend.sector_count,
            "read_only": backend.read_only,
            "max_transfer_sectors": backend.max_transfer_sectors,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "block_device_generation": backend.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn virtio_blk_backend_object_view_v1(
    backend: &VirtioBlkBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "virtio-blk-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                backend.block_device,
                backend.block_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "device": object_ref_json(
                "device",
                backend.device,
                backend.device_generation,
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "model": backend.model,
        },
        "contract": {
            "sector_size": backend.sector_size,
            "sector_count": backend.sector_count,
            "read_only": backend.read_only,
            "max_transfer_sectors": backend.max_transfer_sectors,
            "device_features": backend.device_features,
            "driver_features": backend.driver_features,
            "negotiated_features": backend.negotiated_features,
            "request_queue_index": backend.request_queue_index,
            "queue_size": backend.queue_size,
            "irq_vector": backend.irq_vector,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "block_device_generation": backend.block_device_generation,
            "driver_binding_generation": backend.driver_binding_generation,
            "device_generation": backend.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_read_path_view_v1(read_path: &BlockReadPathManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-read-path",
        "id": read_path.id,
        "generation": read_path.generation,
        "state": read_path.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&read_path.backend_kind),
                read_path.backend,
                read_path.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                read_path.block_request,
                read_path.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                read_path.block_completion,
                read_path.block_completion_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                read_path.block_device,
                read_path.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                read_path.block_range,
                read_path.block_range_generation,
            ),
            "event": {
                "id": read_path.recorded_at_event,
            },
        },
        "read": {
            "sequence": read_path.sequence,
            "completed_bytes": read_path.completed_bytes,
            "data_digest": read_path.data_digest,
        },
        "note": read_path.note,
        "last_transition": {
            "recorded_at_event": read_path.recorded_at_event,
            "backend_generation": read_path.backend_generation,
            "block_request_generation": read_path.block_request_generation,
            "block_completion_generation": read_path.block_completion_generation,
            "block_device_generation": read_path.block_device_generation,
            "block_range_generation": read_path.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_write_path_view_v1(write_path: &BlockWritePathManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-write-path",
        "id": write_path.id,
        "generation": write_path.generation,
        "state": write_path.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&write_path.backend_kind),
                write_path.backend,
                write_path.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                write_path.block_request,
                write_path.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                write_path.block_completion,
                write_path.block_completion_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                write_path.block_device,
                write_path.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                write_path.block_range,
                write_path.block_range_generation,
            ),
            "event": {
                "id": write_path.recorded_at_event,
            },
        },
        "write": {
            "sequence": write_path.sequence,
            "completed_bytes": write_path.completed_bytes,
            "payload_digest": write_path.payload_digest,
        },
        "note": write_path.note,
        "last_transition": {
            "recorded_at_event": write_path.recorded_at_event,
            "backend_generation": write_path.backend_generation,
            "block_request_generation": write_path.block_request_generation,
            "block_completion_generation": write_path.block_completion_generation,
            "block_device_generation": write_path.block_device_generation,
            "block_range_generation": write_path.block_range_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_request_queue_view_v1(queue: &BlockRequestQueueManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request-queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                queue.block_device,
                queue.block_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&queue.backend_kind),
                queue.backend,
                queue.backend_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                queue.block_device,
                queue.block_device_generation,
            ),
            "entries": queue
                .entries
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "request": object_ref_json(
                            "block-request",
                            entry.request,
                            entry.request_generation,
                        ),
                        "completion": optional_object_ref_json(
                            "block-completion",
                            entry.completion,
                            entry.completion_generation,
                        ),
                        "sequence": entry.sequence,
                        "operation": entry.operation,
                        "byte_len": entry.byte_len,
                        "state": entry.state,
                    })
                })
                .collect::<Vec<_>>(),
            "event": {
                "id": queue.recorded_at_event,
            },
        },
        "queue": {
            "depth": queue.depth,
            "entry_count": queue.entries.len(),
            "pending_count": queue.pending_count,
            "completed_count": queue.completed_count,
            "first_sequence": queue.first_sequence,
            "last_sequence": queue.last_sequence,
        },
        "note": queue.note,
        "last_transition": {
            "recorded_at_event": queue.recorded_at_event,
            "backend_generation": queue.backend_generation,
            "block_device_generation": queue.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_dma_buffer_view_v1(buffer: &BlockDmaBufferManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-dma-buffer",
        "id": buffer.id,
        "generation": buffer.generation,
        "state": buffer.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                buffer.block_request,
                buffer.block_request_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&buffer.backend_kind),
                buffer.backend,
                buffer.backend_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                buffer.block_request,
                buffer.block_request_generation,
            ),
            "dma_buffer": object_ref_json(
                "dma-buffer",
                buffer.dma_buffer,
                buffer.dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                buffer.block_device,
                buffer.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                buffer.block_range,
                buffer.block_range_generation,
            ),
            "descriptor": object_ref_json(
                "descriptor",
                buffer.descriptor,
                buffer.descriptor_generation,
            ),
            "queue": object_ref_json("queue", buffer.queue, buffer.queue_generation),
            "event": {
                "id": buffer.recorded_at_event,
            },
        },
        "buffer": {
            "operation": buffer.operation,
            "access": buffer.access,
            "byte_len": buffer.byte_len,
            "buffer_len": buffer.buffer_len,
            "buffer_digest": buffer.buffer_digest,
        },
        "note": buffer.note,
        "last_transition": {
            "recorded_at_event": buffer.recorded_at_event,
            "block_request_generation": buffer.block_request_generation,
            "dma_buffer_generation": buffer.dma_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_page_object_view_v1(page: &BlockPageObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-page-object",
        "id": page.id,
        "generation": page.generation,
        "state": page.state,
        "owner": {
            "page": object_ref_manifest_json(&page.page),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
        },
        "references": {
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                page.block_dma_buffer,
                page.block_dma_buffer_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                page.block_request,
                page.block_request_generation,
            ),
            "block_completion": object_ref_json(
                "block-completion",
                page.block_completion,
                page.block_completion_generation,
            ),
            "dma_buffer": object_ref_json(
                "dma-buffer",
                page.dma_buffer,
                page.dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                page.block_device,
                page.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                page.block_range,
                page.block_range_generation,
            ),
            "aspace": object_ref_manifest_json(&page.aspace),
            "vma_region": object_ref_manifest_json(&page.vma_region),
            "page": object_ref_manifest_json(&page.page),
            "event": {
                "id": page.recorded_at_event,
            },
        },
        "page": {
            "dirty_generation": page.page_dirty_generation,
            "backing": page.page_backing,
            "cow_state": page.cow_state,
            "page_state": page.page_state,
            "offset": page.page_offset,
            "byte_len": page.byte_len,
            "operation": page.operation,
        },
        "note": page.note,
        "last_transition": {
            "recorded_at_event": page.recorded_at_event,
            "block_dma_buffer_generation": page.block_dma_buffer_generation,
            "page_generation": page.page.generation,
            "page_dirty_generation": page.page_dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn buffer_cache_object_view_v1(cache: &BufferCacheObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "buffer-cache-object",
        "id": cache.id,
        "generation": cache.generation,
        "state": cache.state,
        "owner": {
            "page": object_ref_manifest_json(&cache.page),
            "block_range": object_ref_json(
                "block-range",
                cache.block_range,
                cache.block_range_generation,
            ),
        },
        "references": {
            "block_page_object": object_ref_json(
                "block-page-object",
                cache.block_page_object,
                cache.block_page_object_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                cache.block_dma_buffer,
                cache.block_dma_buffer_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cache.block_device,
                cache.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                cache.block_range,
                cache.block_range_generation,
            ),
            "aspace": object_ref_manifest_json(&cache.aspace),
            "vma_region": object_ref_manifest_json(&cache.vma_region),
            "page": object_ref_manifest_json(&cache.page),
            "event": {
                "id": cache.recorded_at_event,
            },
        },
        "cache": {
            "page_dirty_generation": cache.page_dirty_generation,
            "page_offset": cache.page_offset,
            "block_offset": cache.block_offset,
            "byte_len": cache.byte_len,
            "operation": cache.operation,
            "cache_state": cache.cache_state,
            "coherency_epoch": cache.coherency_epoch,
        },
        "note": cache.note,
        "last_transition": {
            "recorded_at_event": cache.recorded_at_event,
            "block_page_object_generation": cache.block_page_object_generation,
            "page_generation": cache.page.generation,
            "page_dirty_generation": cache.page_dirty_generation,
            "coherency_epoch": cache.coherency_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}
