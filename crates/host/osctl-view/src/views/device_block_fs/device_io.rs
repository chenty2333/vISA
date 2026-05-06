use super::super::super::*;

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
