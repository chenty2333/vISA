use alloc::{format, string::String};

use super::super::{super::*, kind::EventKind};

pub(super) fn summary(kind: &EventKind) -> Option<String> {
    let summary = match kind {
        EventKind::DeviceObjectRecorded {
            device,
            resource,
            resource_generation,
            class,
            backend,
            generation,
        } => format!(
            "DeviceObjectRecorded device={device} resource={resource}@{resource_generation} class={class} backend={backend} generation={generation}"
        ),
        EventKind::QueueObjectRecorded {
            queue,
            device,
            device_generation,
            role,
            queue_index,
            depth,
            generation,
        } => format!(
            "QueueObjectRecorded queue={queue} device={device}@{device_generation} role={} index={queue_index} depth={depth} generation={generation}",
            role.as_str()
        ),
        EventKind::DescriptorObjectRecorded {
            descriptor,
            queue,
            queue_generation,
            slot,
            access,
            length,
            generation,
        } => format!(
            "DescriptorObjectRecorded descriptor={descriptor} queue={queue}@{queue_generation} slot={slot} access={} length={length} generation={generation}",
            access.as_str()
        ),
        EventKind::DmaBufferObjectRecorded {
            dma_buffer,
            descriptor,
            descriptor_generation,
            resource,
            resource_generation,
            access,
            length,
            generation,
        } => format!(
            "DmaBufferObjectRecorded dma_buffer={dma_buffer} descriptor={descriptor}@{descriptor_generation} resource={resource}@{resource_generation} access={} length={length} generation={generation}",
            access.as_str()
        ),
        EventKind::MmioRegionObjectRecorded {
            mmio_region,
            device,
            device_generation,
            resource,
            resource_generation,
            region_index,
            offset,
            length,
            access,
            generation,
        } => format!(
            "MmioRegionObjectRecorded mmio_region={mmio_region} device={device}@{device_generation} resource={resource}@{resource_generation} index={region_index} offset={offset} length={length} access={} generation={generation}",
            access.as_str()
        ),
        EventKind::IrqLineObjectRecorded {
            irq_line,
            device,
            device_generation,
            resource,
            resource_generation,
            irq_number,
            trigger,
            polarity,
            generation,
        } => format!(
            "IrqLineObjectRecorded irq_line={irq_line} device={device}@{device_generation} resource={resource}@{resource_generation} irq_number={irq_number} trigger={} polarity={} generation={generation}",
            trigger.as_str(),
            polarity.as_str()
        ),
        EventKind::IrqEventRecorded {
            irq_event,
            irq_line,
            irq_line_generation,
            device,
            device_generation,
            driver_store,
            driver_store_generation,
            irq_number,
            sequence,
            generation,
        } => format!(
            "IrqEventRecorded irq_event={irq_event} irq_line={irq_line}@{irq_line_generation} device={device}@{device_generation} driver_store={driver_store}@{driver_store_generation} irq_number={irq_number} sequence={sequence} generation={generation}"
        ),
        EventKind::DeviceCapabilityRecorded {
            device_capability,
            driver_store,
            driver_store_generation,
            target,
            class,
            operation,
            capability,
            capability_generation,
            handle_slot,
            handle_generation,
            generation,
        } => format!(
            "DeviceCapabilityRecorded device_capability={device_capability} driver_store={driver_store}@{driver_store_generation} target={} class={} operation={operation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} generation={generation}",
            target.summary(),
            class.as_str()
        ),
        EventKind::DriverStoreBound {
            binding,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            device_capability,
            device_capability_generation,
            capability,
            capability_generation,
            generation,
        } => format!(
            "DriverStoreBound binding={binding} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} generation={generation}"
        ),
        EventKind::IoWaitCreated {
            io_wait,
            wait,
            wait_generation,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            blocker,
            generation,
        } => format!(
            "IoWaitCreated io_wait={io_wait} wait={wait}@{wait_generation} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} blocker={} generation={generation}",
            blocker.summary()
        ),
        EventKind::IoWaitResolved {
            io_wait,
            wait,
            wait_generation,
            irq_event,
            irq_event_generation,
            generation,
        } => format!(
            "IoWaitResolved io_wait={io_wait} wait={wait}@{wait_generation} irq_event={irq_event}@{irq_event_generation} generation={generation}"
        ),
        EventKind::IoWaitCancelled { io_wait, wait, wait_generation, reason, generation } => {
            format!(
                "IoWaitCancelled io_wait={io_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
                reason.as_str()
            )
        }
        EventKind::IoCleanupStarted {
            cleanup,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            generation,
        } => format!(
            "IoCleanupStarted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} generation={generation}"
        ),
        EventKind::IoCleanupCompleted {
            cleanup,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            cancelled_io_waits,
            revoked_device_capabilities,
            released_dma_buffers,
            released_mmio_regions,
            released_irq_lines,
            generation,
        } => format!(
            "IoCleanupCompleted cleanup={cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} cancelled_io_waits={cancelled_io_waits} revoked_device_capabilities={revoked_device_capabilities} released_dma_buffers={released_dma_buffers} released_mmio_regions={released_mmio_regions} released_irq_lines={released_irq_lines} generation={generation}"
        ),
        EventKind::IoFaultInjected {
            fault,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            target,
            cleanup,
            cleanup_generation,
            kind,
            generation,
        } => format!(
            "IoFaultInjected fault={fault} kind={} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} target={} cleanup={cleanup}@{cleanup_generation} generation={generation}",
            kind.as_str(),
            target.summary()
        ),
        EventKind::IoValidationReportRecorded {
            report,
            ok,
            violation_count,
            device_count,
            dma_buffer_count,
            irq_event_count,
            cleanup_count,
            fault_injection_count,
            generation,
        } => format!(
            "IoValidationReportRecorded report={report} ok={ok} violations={violation_count} devices={device_count} dma_buffers={dma_buffer_count} irq_events={irq_event_count} cleanups={cleanup_count} fault_injections={fault_injection_count} generation={generation}"
        ),
        EventKind::DeviceIrqDelivered { irq, device, cause } => {
            format!("DeviceIrqDelivered irq={irq} device={device} cause={cause}")
        }
        EventKind::DriverCompletion { device, operation } => {
            format!("DriverCompletion device={device} operation={operation}")
        }
        EventKind::DmaSubmitted { buffer, device, len } => {
            format!("DmaSubmitted buffer={buffer} device={device} len={len}")
        }
        EventKind::DmaCompleted { buffer, device, len } => {
            format!("DmaCompleted buffer={buffer} device={device} len={len}")
        }
        _ => return None,
    };
    Some(summary)
}
