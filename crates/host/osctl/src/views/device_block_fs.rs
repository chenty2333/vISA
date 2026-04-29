use super::super::*;
pub(crate) fn device_object_view_v1(device: &DeviceObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "device",
        "id": device.id,
        "generation": device.generation,
        "state": device.state,
        "owner": {
            "class": device.class,
            "backend": device.backend,
            "bus": device.bus,
        },
        "references": {
            "resource": object_ref_json("resource", device.resource, device.resource_generation),
            "event": {
                "id": device.recorded_at_event,
            },
        },
        "identity": {
            "name": device.name,
            "vendor": device.vendor,
            "model": device.model,
        },
        "note": device.note,
        "last_transition": {
            "recorded_at_event": device.recorded_at_event,
            "resource_generation": device.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn queue_object_view_v1(queue: &QueueObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "device": object_ref_json("device", queue.device, queue.device_generation),
        },
        "references": {
            "device": object_ref_json("device", queue.device, queue.device_generation),
            "event": {
                "id": queue.recorded_at_event,
            },
        },
        "identity": {
            "name": queue.name,
            "role": queue.role,
            "queue_index": queue.queue_index,
        },
        "capacity": {
            "depth": queue.depth,
        },
        "note": queue.note,
        "last_transition": {
            "recorded_at_event": queue.recorded_at_event,
            "device_generation": queue.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn descriptor_object_view_v1(
    descriptor: &DescriptorObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "descriptor",
        "id": descriptor.id,
        "generation": descriptor.generation,
        "state": descriptor.state,
        "owner": {
            "queue": object_ref_json(
                "queue",
                descriptor.queue,
                descriptor.queue_generation
            ),
        },
        "references": {
            "queue": object_ref_json(
                "queue",
                descriptor.queue,
                descriptor.queue_generation
            ),
            "event": {
                "id": descriptor.recorded_at_event,
            },
        },
        "identity": {
            "slot": descriptor.slot,
            "access": descriptor.access,
        },
        "capacity": {
            "length": descriptor.length,
        },
        "note": descriptor.note,
        "last_transition": {
            "recorded_at_event": descriptor.recorded_at_event,
            "queue_generation": descriptor.queue_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn dma_buffer_object_view_v1(dma_buffer: &DmaBufferObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "dma-buffer",
        "id": dma_buffer.id,
        "generation": dma_buffer.generation,
        "state": dma_buffer.state,
        "owner": {
            "descriptor": object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation
            ),
        },
        "references": {
            "descriptor": object_ref_json(
                "descriptor",
                dma_buffer.descriptor,
                dma_buffer.descriptor_generation
            ),
            "resource": object_ref_json(
                "resource",
                dma_buffer.resource,
                dma_buffer.resource_generation
            ),
            "event": {
                "id": dma_buffer.recorded_at_event,
            },
        },
        "identity": {
            "access": dma_buffer.access,
        },
        "capacity": {
            "length": dma_buffer.length,
        },
        "note": dma_buffer.note,
        "last_transition": {
            "recorded_at_event": dma_buffer.recorded_at_event,
            "descriptor_generation": dma_buffer.descriptor_generation,
            "resource_generation": dma_buffer.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn mmio_region_object_view_v1(
    mmio_region: &MmioRegionObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "mmio-region",
        "id": mmio_region.id,
        "generation": mmio_region.generation,
        "state": mmio_region.state,
        "owner": {
            "device": object_ref_json(
                "device",
                mmio_region.device,
                mmio_region.device_generation
            ),
        },
        "references": {
            "device": object_ref_json(
                "device",
                mmio_region.device,
                mmio_region.device_generation
            ),
            "resource": object_ref_json(
                "resource",
                mmio_region.resource,
                mmio_region.resource_generation
            ),
            "event": {
                "id": mmio_region.recorded_at_event,
            },
        },
        "identity": {
            "region_index": mmio_region.region_index,
            "offset": mmio_region.offset,
            "access": mmio_region.access,
        },
        "capacity": {
            "length": mmio_region.length,
        },
        "note": mmio_region.note,
        "last_transition": {
            "recorded_at_event": mmio_region.recorded_at_event,
            "device_generation": mmio_region.device_generation,
            "resource_generation": mmio_region.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn irq_line_object_view_v1(irq_line: &IrqLineObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "irq-line",
        "id": irq_line.id,
        "generation": irq_line.generation,
        "state": irq_line.state,
        "owner": {
            "device": object_ref_json(
                "device",
                irq_line.device,
                irq_line.device_generation
            ),
        },
        "references": {
            "device": object_ref_json(
                "device",
                irq_line.device,
                irq_line.device_generation
            ),
            "resource": object_ref_json(
                "resource",
                irq_line.resource,
                irq_line.resource_generation
            ),
            "event": {
                "id": irq_line.recorded_at_event,
            },
        },
        "identity": {
            "irq_number": irq_line.irq_number,
            "trigger": irq_line.trigger,
            "polarity": irq_line.polarity,
        },
        "note": irq_line.note,
        "last_transition": {
            "recorded_at_event": irq_line.recorded_at_event,
            "device_generation": irq_line.device_generation,
            "resource_generation": irq_line.resource_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn irq_event_view_v1(irq_event: &IrqEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "irq-event",
        "id": irq_event.id,
        "generation": irq_event.generation,
        "state": irq_event.state,
        "owner": {
            "device": object_ref_json(
                "device",
                irq_event.device,
                irq_event.device_generation
            ),
            "driver_store": object_ref_json(
                "store",
                irq_event.driver_store,
                irq_event.driver_store_generation
            ),
        },
        "references": {
            "irq_line": object_ref_json(
                "irq-line",
                irq_event.irq_line,
                irq_event.irq_line_generation
            ),
            "device": object_ref_json(
                "device",
                irq_event.device,
                irq_event.device_generation
            ),
            "driver_store": object_ref_json(
                "store",
                irq_event.driver_store,
                irq_event.driver_store_generation
            ),
            "event": {
                "id": irq_event.recorded_at_event,
            },
        },
        "identity": {
            "irq_number": irq_event.irq_number,
            "sequence": irq_event.sequence,
        },
        "note": irq_event.note,
        "last_transition": {
            "recorded_at_event": irq_event.recorded_at_event,
            "irq_line_generation": irq_event.irq_line_generation,
            "device_generation": irq_event.device_generation,
            "driver_store_generation": irq_event.driver_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn device_capability_view_v1(
    device_capability: &DeviceCapabilityManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "device-capability",
        "id": device_capability.id,
        "generation": device_capability.generation,
        "state": device_capability.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation
            ),
        },
        "references": {
            "target": object_ref_manifest_json(&device_capability.target),
            "capability": object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation
            ),
            "driver_store": object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation
            ),
            "event": {
                "id": device_capability.recorded_at_event,
            },
        },
        "authority": {
            "class": device_capability.class,
            "operation": device_capability.operation,
            "handle": {
                "slot": device_capability.handle_slot,
                "generation": device_capability.handle_generation,
                "tag": device_capability.handle_tag,
            },
        },
        "note": device_capability.note,
        "last_transition": {
            "recorded_at_event": device_capability.recorded_at_event,
            "driver_store_generation": device_capability.driver_store_generation,
            "target_generation": device_capability.target.generation,
            "capability_generation": device_capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn driver_store_binding_view_v1(
    binding: &DriverStoreBindingManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "driver-store-binding",
        "id": binding.id,
        "generation": binding.generation,
        "state": binding.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                binding.device,
                binding.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                binding.driver_store,
                binding.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                binding.device,
                binding.device_generation
            ),
            "device_capability": object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation
            ),
            "capability": object_ref_json(
                "capability",
                binding.capability,
                binding.capability_generation
            ),
            "event": {
                "id": binding.recorded_at_event,
            },
        },
        "note": binding.note,
        "last_transition": {
            "recorded_at_event": binding.recorded_at_event,
            "driver_store_generation": binding.driver_store_generation,
            "device_generation": binding.device_generation,
            "device_capability_generation": binding.device_capability_generation,
            "capability_generation": binding.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn io_wait_view_v1(io_wait: &IoWaitManifest) -> serde_json::Value {
    let completion_irq_event =
        match (io_wait.completion_irq_event, io_wait.completion_irq_event_generation) {
            (Some(irq_event), Some(irq_event_generation)) => {
                object_ref_json("irq-event", irq_event, irq_event_generation)
            }
            _ => serde_json::Value::Null,
        };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-wait",
        "id": io_wait.id,
        "generation": io_wait.generation,
        "state": io_wait.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                io_wait.device,
                io_wait.device_generation
            ),
        },
        "references": {
            "wait": object_ref_json(
                "wait-token",
                io_wait.wait,
                io_wait.wait_generation
            ),
            "driver_store": object_ref_json(
                "store",
                io_wait.driver_store,
                io_wait.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                io_wait.device,
                io_wait.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation
            ),
            "blocker": object_ref_manifest_json(&io_wait.blocker),
            "completion_irq_event": completion_irq_event,
            "created_event": {
                "id": io_wait.created_at_event,
            },
            "completed_event": io_wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "cancel_reason": io_wait.cancel_reason,
        "note": io_wait.note,
        "last_transition": {
            "created_at_event": io_wait.created_at_event,
            "completed_at_event": io_wait.completed_at_event,
            "wait_generation": io_wait.wait_generation,
            "driver_store_generation": io_wait.driver_store_generation,
            "device_generation": io_wait.device_generation,
            "driver_binding_generation": io_wait.driver_binding_generation,
        },
        "last_error": io_wait.cancel_reason,
    })
}

pub(crate) fn io_cleanup_view_v1(cleanup: &IoCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation
            ),
            "cancelled_io_waits": cleanup
                .cancelled_io_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_device_capabilities": cleanup
                .revoked_device_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_capabilities": cleanup
                .revoked_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_dma_buffers": cleanup
                .released_dma_buffers
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_mmio_regions": cleanup
                .released_mmio_regions
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_irq_lines": cleanup
                .released_irq_lines
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
        },
        "reason": cleanup.reason,
        "steps": cleanup
            .steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "kind": step.kind,
                    "target": object_ref_manifest_json(&step.target),
                    "observed_generation": step.observed_generation,
                    "status": step.status,
                    "event": step.event,
                })
            })
            .collect::<Vec<_>>(),
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "driver_store_generation": cleanup.driver_store_generation,
            "device_generation": cleanup.device_generation,
            "driver_binding_generation": cleanup.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn io_fault_injection_view_v1(fault: &IoFaultInjectionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-fault-injection",
        "id": fault.id,
        "generation": fault.generation,
        "state": fault.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                fault.driver_store,
                fault.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                fault.device,
                fault.device_generation
            ),
        },
        "references": {
            "driver_store": object_ref_json(
                "store",
                fault.driver_store,
                fault.driver_store_generation
            ),
            "device": object_ref_json(
                "device",
                fault.device,
                fault.device_generation
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                fault.driver_binding,
                fault.driver_binding_generation
            ),
            "target": object_ref_manifest_json(&fault.target),
            "cleanup": object_ref_json(
                "io-cleanup",
                fault.cleanup,
                fault.cleanup_generation
            ),
            "injected_event": {
                "id": fault.injected_at_event,
            },
        },
        "fault": {
            "kind": fault.kind,
        },
        "note": fault.note,
        "last_transition": {
            "injected_at_event": fault.injected_at_event,
            "driver_store_generation": fault.driver_store_generation,
            "device_generation": fault.device_generation,
            "driver_binding_generation": fault.driver_binding_generation,
            "cleanup_generation": fault.cleanup_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn io_validation_report_view_v1(
    report: &IoValidationReportManifest,
) -> serde_json::Value {
    let violations = report
        .violations
        .iter()
        .map(|violation| {
            serde_json::json!({
                "code": violation.code,
                "subject": object_ref_manifest_json(&violation.subject),
                "relation": violation.relation,
                "message": violation.message,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "io-validation-report",
        "id": report.id,
        "generation": report.generation,
        "state": report.state,
        "owner": serde_json::Value::Null,
        "references": {
            "validated_event": {
                "id": report.validated_at_event,
            },
            "event_log_cursor": report.event_log_cursor,
        },
        "observed": {
            "devices": report.observed_device_count,
            "queues": report.observed_queue_count,
            "descriptors": report.observed_descriptor_count,
            "dma_buffers": report.observed_dma_buffer_count,
            "mmio_regions": report.observed_mmio_region_count,
            "irq_lines": report.observed_irq_line_count,
            "irq_events": report.observed_irq_event_count,
            "device_capabilities": report.observed_device_capability_count,
            "driver_bindings": report.observed_driver_binding_count,
            "io_waits": report.observed_io_wait_count,
            "io_cleanups": report.observed_io_cleanup_count,
            "io_fault_injections": report.observed_io_fault_injection_count,
        },
        "validation": {
            "ok": report.state == "passed" && report.violation_count == 0,
            "violation_count": report.violation_count,
            "violations": violations,
        },
        "note": report.note,
        "last_transition": {
            "validated_at_event": report.validated_at_event,
            "event_log_cursor": report.event_log_cursor,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn packet_device_object_view_v1(
    packet_device: &PacketDeviceObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-device",
        "id": packet_device.id,
        "generation": packet_device.generation,
        "state": packet_device.state,
        "owner": {
            "device": object_ref_json("device", packet_device.device, packet_device.device_generation),
        },
        "references": {
            "device": object_ref_json("device", packet_device.device, packet_device.device_generation),
            "event": {
                "id": packet_device.recorded_at_event,
            },
        },
        "identity": {
            "name": packet_device.name,
            "mac": packet_device.mac,
        },
        "contract": {
            "mtu": packet_device.mtu,
            "rx_queue_depth": packet_device.rx_queue_depth,
            "tx_queue_depth": packet_device.tx_queue_depth,
            "frame_format_version": packet_device.frame_format_version,
            "max_payload_len": packet_device.max_payload_len,
        },
        "note": packet_device.note,
        "last_transition": {
            "recorded_at_event": packet_device.recorded_at_event,
            "device_generation": packet_device.device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

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

pub(crate) fn file_object_view_v1(file: &FileObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-object",
        "id": file.id,
        "generation": file.generation,
        "state": file.state,
        "owner": {
            "namespace": file.namespace,
            "file_key": file.file_key,
            "path": file.path,
        },
        "references": {
            "buffer_cache_object": object_ref_json(
                "buffer-cache-object",
                file.buffer_cache_object,
                file.buffer_cache_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                file.block_device,
                file.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                file.block_range,
                file.block_range_generation,
            ),
            "page": object_ref_manifest_json(&file.page),
            "event": {
                "id": file.recorded_at_event,
            },
        },
        "file": {
            "file_offset": file.file_offset,
            "byte_len": file.byte_len,
            "file_size": file.file_size,
            "content_digest": file.content_digest,
            "cache_state": file.cache_state,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "note": file.note,
        "last_transition": {
            "recorded_at_event": file.recorded_at_event,
            "buffer_cache_object_generation": file.buffer_cache_object_generation,
            "page_generation": file.page.generation,
            "page_dirty_generation": file.page_dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn directory_object_view_v1(directory: &DirectoryObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "directory-object",
        "id": directory.id,
        "generation": directory.generation,
        "state": directory.state,
        "owner": {
            "namespace": directory.namespace,
            "directory_key": directory.directory_key,
            "directory_path": directory.directory_path,
            "entry_name": directory.entry_name,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                directory.file_object,
                directory.file_object_generation,
            ),
            "event": {
                "id": directory.recorded_at_event,
            },
        },
        "directory": {
            "entry_kind": directory.entry_kind,
            "child_file_key": directory.child_file_key,
            "child_path": directory.child_path,
            "file_size": directory.file_size,
            "content_digest": directory.content_digest,
        },
        "note": directory.note,
        "last_transition": {
            "recorded_at_event": directory.recorded_at_event,
            "file_object_generation": directory.file_object_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn fat_adapter_object_view_v1(adapter: &FatAdapterObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fat-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "fat": {
            "image_bytes": adapter.image_bytes,
            "bytes_written": adapter.bytes_written,
            "bytes_read": adapter.bytes_read,
            "write_digest": adapter.write_digest,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn ext4_adapter_object_view_v1(
    adapter: &Ext4AdapterObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "ext4-adapter-object",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "implementation": adapter.implementation,
            "version": adapter.version,
            "profile": adapter.profile,
            "volume_label": adapter.volume_label,
            "adapter_path": adapter.adapter_path,
            "semantic_path": adapter.semantic_path,
        },
        "references": {
            "directory_object": object_ref_json(
                "directory-object",
                adapter.directory_object,
                adapter.directory_object_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                adapter.file_object,
                adapter.file_object_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                adapter.block_device,
                adapter.block_device_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "ext4": {
            "image_bytes": adapter.image_bytes,
            "bytes_read": adapter.bytes_read,
            "read_digest": adapter.read_digest,
            "file_content_digest": adapter.file_content_digest,
            "directory_entries": adapter.directory_entries,
            "read_only_enforced": adapter.read_only_enforced,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "directory_object_generation": adapter.directory_object_generation,
            "file_object_generation": adapter.file_object_generation,
            "block_device_generation": adapter.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn file_handle_capability_view_v1(
    capability: &FileHandleCapabilityManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "file-handle-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
            "operation": capability.operation,
        },
        "references": {
            "file_object": object_ref_json(
                "file-object",
                capability.file_object,
                capability.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                capability.directory_object,
                capability.directory_object_generation,
            ),
            "capability": object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "event": {
                "id": capability.recorded_at_event,
            },
        },
        "handle": {
            "slot": capability.handle_slot,
            "generation": capability.handle_generation,
            "tag": capability.handle_tag,
        },
        "file_access": {
            "operation": capability.operation,
            "file_offset": capability.file_offset,
            "byte_len": capability.byte_len,
            "content_digest": capability.content_digest,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "file_object_generation": capability.file_object_generation,
            "directory_object_generation": capability.directory_object_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn fs_wait_view_v1(wait: &FsWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fs-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "operation": wait.operation,
        },
        "references": {
            "wait": object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "owner_store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "file_object": object_ref_json(
                "file-object",
                wait.file_object,
                wait.file_object_generation,
            ),
            "directory_object": object_ref_json(
                "directory-object",
                wait.directory_object,
                wait.directory_object_generation,
            ),
            "file_handle_capability": object_ref_json(
                "file-handle-capability",
                wait.file_handle_capability,
                wait.file_handle_capability_generation,
            ),
            "blocker": object_ref_manifest_json(&wait.blocker),
            "created_event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
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
            "file_handle_capability_generation": wait.file_handle_capability_generation,
        },
        "last_error": wait.cancel_reason.as_ref().map(|reason| serde_json::json!({
            "cancel_reason": reason,
        })).unwrap_or(serde_json::Value::Null),
    })
}

pub(crate) fn block_driver_cleanup_view_v1(
    cleanup: &BlockDriverCleanupManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-driver-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
        },
        "references": {
            "io_cleanup": object_ref_json(
                "io-cleanup",
                cleanup.io_cleanup,
                cleanup.io_cleanup_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
            "backend": object_ref_manifest_json(&cleanup.backend),
            "cancelled_block_waits": cleanup
                .cancelled_block_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "cancelled_wait_tokens": cleanup
                .cancelled_wait_tokens
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_device_capabilities": cleanup
                .revoked_device_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_dma_buffers": cleanup
                .released_dma_buffers
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "started_event": {
                "id": cleanup.started_at_event,
            },
            "completed_event": cleanup.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "cancelled_block_wait_count": cleanup.cancelled_block_waits.len(),
            "released_dma_buffer_count": cleanup.released_dma_buffers.len(),
            "revoked_device_capability_count": cleanup.revoked_device_capabilities.len(),
        },
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "io_cleanup_generation": cleanup.io_cleanup_generation,
            "driver_store_generation": cleanup.driver_store_generation,
            "block_device_generation": cleanup.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_pending_io_policy_view_v1(
    policy: &BlockPendingIoPolicyManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-pending-io-policy",
        "id": policy.id,
        "generation": policy.generation,
        "state": policy.state,
        "owner": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
        },
        "references": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "wait": object_ref_json("wait-token", policy.wait, policy.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
            "retry_request": optional_object_ref_json(
                "block-request",
                policy.retry_request,
                policy.retry_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                policy.block_device,
                policy.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                policy.block_range,
                policy.block_range_generation,
            ),
            "event": {
                "id": policy.recorded_at_event,
            },
        },
        "policy": {
            "operation": policy.operation,
            "sequence": policy.sequence,
            "byte_len": policy.byte_len,
            "action": policy.action,
            "errno": policy.errno,
            "retry_attempt": policy.retry_attempt,
            "max_retries": policy.max_retries,
        },
        "note": policy.note,
        "last_transition": {
            "recorded_at_event": policy.recorded_at_event,
            "block_wait_generation": policy.block_wait_generation,
            "block_request_generation": policy.block_request_generation,
            "retry_request_generation": policy.retry_request_generation,
        },
        "last_error": if policy.action == "eio" {
            serde_json::json!({ "errno": policy.errno })
        } else {
            serde_json::Value::Null
        },
    })
}

pub(crate) fn block_request_generation_audit_view_v1(
    audit: &BlockRequestGenerationAuditManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request-generation-audit",
        "id": audit.id,
        "generation": audit.generation,
        "state": audit.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                audit.block_range,
                audit.block_range_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "backend": object_ref_manifest_json(&audit.backend),
            "dma_buffer": object_ref_manifest_json(&audit.dma_buffer),
            "event": {
                "id": audit.recorded_at_event,
            },
        },
        "audit": {
            "rejected_completion_generation_probes": audit.rejected_completion_generation_probes,
            "rejected_wait_generation_probes": audit.rejected_wait_generation_probes,
            "rejected_dma_generation_probes": audit.rejected_dma_generation_probes,
            "rejected_queue_generation_probes": audit.rejected_queue_generation_probes,
        },
        "note": audit.note,
        "last_transition": {
            "recorded_at_event": audit.recorded_at_event,
            "block_device_generation": audit.block_device_generation,
            "block_range_generation": audit.block_range_generation,
            "block_request_generation": audit.block_request_generation,
            "backend_generation": audit.backend.generation,
            "dma_buffer_generation": audit.dma_buffer.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_benchmark_view_v1(benchmark: &BlockBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                benchmark.block_range,
                benchmark.block_range_generation,
            ),
            "read_path": object_ref_json(
                "block-read-path",
                benchmark.read_path,
                benchmark.read_path_generation,
            ),
            "write_path": object_ref_json(
                "block-write-path",
                benchmark.write_path,
                benchmark.write_path_generation,
            ),
            "request_queue": object_ref_json(
                "block-request-queue",
                benchmark.request_queue,
                benchmark.request_queue_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                benchmark.block_dma_buffer,
                benchmark.block_dma_buffer_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_requests": benchmark.sample_requests,
            "sample_bytes": benchmark.sample_bytes,
            "read_completed_requests": benchmark.read_completed_requests,
            "write_completed_requests": benchmark.write_completed_requests,
            "queue_completed_requests": benchmark.queue_completed_requests,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "iops": benchmark.iops,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "block_range_generation": benchmark.block_range_generation,
            "read_path_generation": benchmark.read_path_generation,
            "write_path_generation": benchmark.write_path_generation,
            "request_queue_generation": benchmark.request_queue_generation,
            "block_dma_buffer_generation": benchmark.block_dma_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_recovery_benchmark_view_v1(
    benchmark: &BlockRecoveryBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-recovery-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
        },
        "references": {
            "cleanup": object_ref_json(
                "block-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "device": object_ref_json("device", benchmark.device, benchmark.device_generation),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                benchmark.driver_binding,
                benchmark.driver_binding_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "recovery_start_event": benchmark.recovery_start_event,
            "recovery_complete_event": benchmark.recovery_complete_event,
            "cancelled_block_waits": benchmark.cancelled_block_waits,
            "cancelled_wait_tokens": benchmark.cancelled_wait_tokens,
            "released_dma_buffers": benchmark.released_dma_buffers,
            "revoked_device_capabilities": benchmark.revoked_device_capabilities,
            "recovery_nanos": benchmark.recovery_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "cleanup_generation": benchmark.cleanup_generation,
            "io_cleanup_generation": benchmark.io_cleanup_generation,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "driver_store_generation": benchmark.driver_store_generation,
            "device_generation": benchmark.device_generation,
            "driver_binding_generation": benchmark.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn target_feature_set_view_v1(feature: &TargetFeatureSetManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "target-feature-set",
        "id": feature.id,
        "generation": feature.generation,
        "state": feature.state,
        "owner": {
            "target_profile": feature.target_profile,
            "target_arch": feature.target_arch,
        },
        "references": {
            "event": {
                "id": feature.recorded_at_event,
            },
        },
        "features": {
            "base_isa": feature.base_isa,
            "simd": {
                "abi": feature.simd_abi,
                "supported": feature.simd_supported,
                "vector_register_count": feature.vector_register_count,
                "vector_register_bits": feature.vector_register_bits,
                "scalar_fallback": feature.scalar_fallback,
                "unsupported_reason": feature.unsupported_reason,
            },
        },
        "discovery": {
            "name": feature.name,
            "source": feature.discovery_source,
        },
        "note": feature.note,
        "last_transition": {
            "recorded_at_event": feature.recorded_at_event,
            "simd_supported": feature.simd_supported,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn vector_state_view_v1(vector_state: &VectorStateManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "vector-state",
        "id": vector_state.id,
        "generation": vector_state.generation,
        "state": vector_state.state,
        "owner": {
            "activation": object_ref_manifest_json(&vector_state.owner_activation),
            "store": object_ref_manifest_json(&vector_state.owner_store),
        },
        "references": {
            "code_object": object_ref_manifest_json(&vector_state.code_object),
            "target_feature_set": object_ref_manifest_json(&vector_state.target_feature_set),
            "event": {
                "id": vector_state.recorded_at_event,
            },
        },
        "simd": {
            "abi": vector_state.simd_abi,
            "vector_register_count": vector_state.vector_register_count,
            "vector_register_bits": vector_state.vector_register_bits,
            "register_bytes": vector_state.register_bytes,
        },
        "note": vector_state.note,
        "last_transition": {
            "recorded_at_event": vector_state.recorded_at_event,
            "state": vector_state.state,
        },
        "last_error": if vector_state.state == "unavailable" {
            serde_json::json!("simd-unavailable")
        } else {
            serde_json::Value::Null
        },
    })
}

pub(crate) fn simd_fault_injection_view_v1(
    injection: &SimdFaultInjectionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-fault-injection",
        "id": injection.id,
        "generation": injection.generation,
        "state": injection.state,
        "owner": {
            "activation": object_ref_manifest_json(&injection.activation),
        },
        "references": {
            "activation": object_ref_manifest_json(&injection.activation),
            "code_object": object_ref_manifest_json(&injection.code_object),
            "trap": object_ref_manifest_json(&injection.trap),
            "target_feature_set": object_ref_manifest_json(&injection.target_feature_set),
            "vector_state": injection.vector_state.as_ref().map(object_ref_manifest_json),
            "event": {
                "id": injection.recorded_at_event,
            },
        },
        "fault": {
            "kind": injection.kind,
            "effect": injection.effect,
            "required_abi": injection.required_abi,
            "vector_register_count": injection.vector_register_count,
            "vector_register_bits": injection.vector_register_bits,
            "injected_faults": injection.injected_faults,
        },
        "note": injection.note,
        "last_transition": {
            "recorded_at_event": injection.recorded_at_event,
            "effect": injection.effect,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn simd_benchmark_view_v1(benchmark: &SimdBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
        },
        "references": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "scalar_code_object": object_ref_manifest_json(&benchmark.scalar_code_object),
            "vector_code_object": object_ref_manifest_json(&benchmark.vector_code_object),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "workload_units": benchmark.workload_units,
            "scalar_nanos": benchmark.scalar_nanos,
            "vector_nanos": benchmark.vector_nanos,
            "speedup_milli": benchmark.speedup_milli,
            "context_overhead_nanos": benchmark.context_overhead_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn simd_context_switch_benchmark_view_v1(
    benchmark: &SimdContextSwitchBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-context-switch-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
        },
        "references": {
            "preemption": object_ref_manifest_json(&benchmark.preemption),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
            "saved_vector_state": object_ref_manifest_json(&benchmark.saved_vector_state),
            "restored_vector_state": object_ref_manifest_json(&benchmark.restored_vector_state),
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "sample_count": benchmark.sample_count,
            "scalar_context_switch_nanos": benchmark.scalar_context_switch_nanos,
            "vector_context_switch_nanos": benchmark.vector_context_switch_nanos,
            "overhead_nanos": benchmark.overhead_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}
