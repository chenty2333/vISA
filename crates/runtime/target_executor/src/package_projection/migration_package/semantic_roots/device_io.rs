use super::*;

pub(super) fn push_device_io_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.device_object_roots = semantic            .device_objects()
            .iter()
            .map(|device| {
                format!(
                    "device-object id={} name={} class={} resource={}@{} backend={} state={} generation={}",
                    device.id,
                    device.name,
                    device.class,
                    device.resource,
                    device.resource_generation,
                    device.backend,
                    device.state.as_str(),
                    device.generation
                )
            })
            .collect();
    roots.queue_object_roots = semantic            .queue_objects()
            .iter()
            .map(|queue| {
                format!(
                    "queue-object id={} name={} role={} index={} depth={} device={}@{} state={} generation={}",
                    queue.id,
                    queue.name,
                    queue.role.as_str(),
                    queue.queue_index,
                    queue.depth,
                    queue.device,
                    queue.device_generation,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect();
    roots.descriptor_object_roots = semantic            .descriptor_objects()
            .iter()
            .map(|descriptor| {
                format!(
                    "descriptor-object id={} queue={}@{} slot={} access={} length={} state={} generation={}",
                    descriptor.id,
                    descriptor.queue,
                    descriptor.queue_generation,
                    descriptor.slot,
                    descriptor.access.as_str(),
                    descriptor.length,
                    descriptor.state.as_str(),
                    descriptor.generation
                )
            })
            .collect();
    roots.dma_buffer_object_roots = semantic            .dma_buffer_objects()
            .iter()
            .map(|dma_buffer| {
                format!(
                    "dma-buffer-object id={} descriptor={}@{} resource={}@{} access={} length={} state={} generation={}",
                    dma_buffer.id,
                    dma_buffer.descriptor,
                    dma_buffer.descriptor_generation,
                    dma_buffer.resource,
                    dma_buffer.resource_generation,
                    dma_buffer.access.as_str(),
                    dma_buffer.length,
                    dma_buffer.state.as_str(),
                    dma_buffer.generation
                )
            })
            .collect();
    roots.mmio_region_object_roots = semantic            .mmio_region_objects()
            .iter()
            .map(|mmio_region| {
                format!(
                    "mmio-region-object id={} device={}@{} resource={}@{} index={} offset={} length={} access={} state={} generation={}",
                    mmio_region.id,
                    mmio_region.device,
                    mmio_region.device_generation,
                    mmio_region.resource,
                    mmio_region.resource_generation,
                    mmio_region.region_index,
                    mmio_region.offset,
                    mmio_region.length,
                    mmio_region.access.as_str(),
                    mmio_region.state.as_str(),
                    mmio_region.generation
                )
            })
            .collect();
    roots.irq_line_object_roots = semantic            .irq_line_objects()
            .iter()
            .map(|irq_line| {
                format!(
                    "irq-line-object id={} device={}@{} resource={}@{} irq_number={} trigger={} polarity={} state={} generation={}",
                    irq_line.id,
                    irq_line.device,
                    irq_line.device_generation,
                    irq_line.resource,
                    irq_line.resource_generation,
                    irq_line.irq_number,
                    irq_line.trigger.as_str(),
                    irq_line.polarity.as_str(),
                    irq_line.state.as_str(),
                    irq_line.generation
                )
            })
            .collect();
    roots.irq_event_roots = semantic            .irq_events()
            .iter()
            .map(|irq_event| {
                format!(
                    "irq-event id={} irq_line={}@{} device={}@{} driver_store={}@{} irq_number={} sequence={} state={} generation={}",
                    irq_event.id,
                    irq_event.irq_line,
                    irq_event.irq_line_generation,
                    irq_event.device,
                    irq_event.device_generation,
                    irq_event.driver_store,
                    irq_event.driver_store_generation,
                    irq_event.irq_number,
                    irq_event.sequence,
                    irq_event.state.as_str(),
                    irq_event.generation
                )
            })
            .collect();
    roots.device_capability_roots = semantic            .device_capabilities()
            .iter()
            .map(|device_capability| {
                format!(
                    "device-capability id={} driver_store={}@{} target={} class={} operation={} capability={}@{} state={} generation={}",
                    device_capability.id,
                    device_capability.driver_store,
                    device_capability.driver_store_generation,
                    device_capability.target.summary(),
                    device_capability.class.as_str(),
                    device_capability.operation,
                    device_capability.capability,
                    device_capability.capability_generation,
                    device_capability.state.as_str(),
                    device_capability.generation
                )
            })
            .collect();
    roots.driver_store_binding_roots = semantic            .driver_store_bindings()
            .iter()
            .map(|binding| {
                format!(
                    "driver-store-binding id={} driver_store={}@{} device={}@{} device_capability={}@{} capability={}@{} state={} generation={}",
                    binding.id,
                    binding.driver_store,
                    binding.driver_store_generation,
                    binding.device,
                    binding.device_generation,
                    binding.device_capability,
                    binding.device_capability_generation,
                    binding.capability,
                    binding.capability_generation,
                    binding.state.as_str(),
                    binding.generation
                )
            })
            .collect();
    roots.io_wait_roots = semantic            .io_waits()
            .iter()
            .map(|io_wait| {
                format!(
                    "io-wait id={} wait={}@{} driver_store={}@{} device={}@{} binding={}@{} blocker={} state={} generation={}",
                    io_wait.id,
                    io_wait.wait,
                    io_wait.wait_generation,
                    io_wait.driver_store,
                    io_wait.driver_store_generation,
                    io_wait.device,
                    io_wait.device_generation,
                    io_wait.driver_binding,
                    io_wait.driver_binding_generation,
                    io_wait.blocker.summary(),
                    io_wait.state.as_str(),
                    io_wait.generation
                )
            })
            .collect();
    roots.io_cleanup_roots = semantic            .io_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "io-cleanup id={} driver_store={}@{} device={}@{} binding={}@{} state={} generation={} cancelled_io_waits={} revoked_device_capabilities={} released_dma_buffers={} released_mmio_regions={} released_irq_lines={}",
                    cleanup.id,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_io_waits.len(),
                    cleanup.revoked_device_capabilities.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.released_mmio_regions.len(),
                    cleanup.released_irq_lines.len()
                )
            })
            .collect();
    roots.io_fault_injection_roots = semantic            .io_fault_injections()
            .iter()
            .map(|fault| {
                format!(
                    "io-fault-injection id={} kind={} driver_store={}@{} device={}@{} binding={}@{} target={} cleanup={}@{} state={} generation={}",
                    fault.id,
                    fault.kind.as_str(),
                    fault.driver_store,
                    fault.driver_store_generation,
                    fault.device,
                    fault.device_generation,
                    fault.driver_binding,
                    fault.driver_binding_generation,
                    fault.target.summary(),
                    fault.cleanup,
                    fault.cleanup_generation,
                    fault.state.as_str(),
                    fault.generation
                )
            })
            .collect();
    roots.io_validation_report_roots = semantic            .io_validation_reports()
            .iter()
            .map(|report| {
                format!(
                    "io-validation-report id={} state={} violations={} devices={} dma_buffers={} irq_events={} cleanups={} fault_injections={} generation={}",
                    report.id,
                    report.state.as_str(),
                    report.violations.len(),
                    report.observed_device_count,
                    report.observed_dma_buffer_count,
                    report.observed_irq_event_count,
                    report.observed_io_cleanup_count,
                    report.observed_io_fault_injection_count,
                    report.generation
                )
            })
            .collect();
}
