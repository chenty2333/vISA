use super::{super::super::*, *};

pub(crate) fn queue_object_manifest(
    queue: &semantic_core::QueueObjectRecord,
) -> QueueObjectManifest {
    QueueObjectManifest {
        id: queue.id,
        name: queue.name.clone(),
        role: queue.role.as_str().to_owned(),
        queue_index: queue.queue_index,
        depth: queue.depth,
        device: queue.device,
        device_generation: queue.device_generation,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

pub(crate) fn descriptor_object_manifest(
    descriptor: &semantic_core::DescriptorObjectRecord,
) -> DescriptorObjectManifest {
    DescriptorObjectManifest {
        id: descriptor.id,
        queue: descriptor.queue,
        queue_generation: descriptor.queue_generation,
        slot: descriptor.slot,
        access: descriptor.access.as_str().to_owned(),
        length: descriptor.length,
        generation: descriptor.generation,
        state: descriptor.state.as_str().to_owned(),
        recorded_at_event: descriptor.recorded_at_event,
        note: descriptor.note.clone(),
    }
}

pub(crate) fn dma_buffer_object_manifest(
    dma_buffer: &semantic_core::DmaBufferObjectRecord,
) -> DmaBufferObjectManifest {
    DmaBufferObjectManifest {
        id: dma_buffer.id,
        descriptor: dma_buffer.descriptor,
        descriptor_generation: dma_buffer.descriptor_generation,
        resource: dma_buffer.resource,
        resource_generation: dma_buffer.resource_generation,
        access: dma_buffer.access.as_str().to_owned(),
        length: dma_buffer.length,
        generation: dma_buffer.generation,
        state: dma_buffer.state.as_str().to_owned(),
        recorded_at_event: dma_buffer.recorded_at_event,
        note: dma_buffer.note.clone(),
    }
}

pub(crate) fn mmio_region_object_manifest(
    mmio_region: &semantic_core::MmioRegionObjectRecord,
) -> MmioRegionObjectManifest {
    MmioRegionObjectManifest {
        id: mmio_region.id,
        device: mmio_region.device,
        device_generation: mmio_region.device_generation,
        resource: mmio_region.resource,
        resource_generation: mmio_region.resource_generation,
        region_index: mmio_region.region_index,
        offset: mmio_region.offset,
        length: mmio_region.length,
        access: mmio_region.access.as_str().to_owned(),
        generation: mmio_region.generation,
        state: mmio_region.state.as_str().to_owned(),
        recorded_at_event: mmio_region.recorded_at_event,
        note: mmio_region.note.clone(),
    }
}

pub(crate) fn irq_line_object_manifest(
    irq_line: &semantic_core::IrqLineObjectRecord,
) -> IrqLineObjectManifest {
    IrqLineObjectManifest {
        id: irq_line.id,
        device: irq_line.device,
        device_generation: irq_line.device_generation,
        resource: irq_line.resource,
        resource_generation: irq_line.resource_generation,
        irq_number: irq_line.irq_number,
        trigger: irq_line.trigger.as_str().to_owned(),
        polarity: irq_line.polarity.as_str().to_owned(),
        generation: irq_line.generation,
        state: irq_line.state.as_str().to_owned(),
        recorded_at_event: irq_line.recorded_at_event,
        note: irq_line.note.clone(),
    }
}

pub(crate) fn irq_event_manifest(irq_event: &semantic_core::IrqEventRecord) -> IrqEventManifest {
    IrqEventManifest {
        id: irq_event.id,
        irq_line: irq_event.irq_line,
        irq_line_generation: irq_event.irq_line_generation,
        device: irq_event.device,
        device_generation: irq_event.device_generation,
        driver_store: irq_event.driver_store,
        driver_store_generation: irq_event.driver_store_generation,
        irq_number: irq_event.irq_number,
        sequence: irq_event.sequence,
        generation: irq_event.generation,
        state: irq_event.state.as_str().to_owned(),
        recorded_at_event: irq_event.recorded_at_event,
        note: irq_event.note.clone(),
    }
}

pub(crate) fn device_capability_manifest(
    device_capability: &semantic_core::DeviceCapabilityRecord,
) -> DeviceCapabilityManifest {
    DeviceCapabilityManifest {
        id: device_capability.id,
        driver_store: device_capability.driver_store,
        driver_store_generation: device_capability.driver_store_generation,
        target: contract_object_ref_manifest(device_capability.target),
        class: device_capability.class.as_str().to_owned(),
        operation: device_capability.operation.clone(),
        capability: device_capability.capability,
        capability_generation: device_capability.capability_generation,
        handle_slot: device_capability.handle_slot,
        handle_generation: device_capability.handle_generation,
        handle_tag: device_capability.handle_tag,
        generation: device_capability.generation,
        state: device_capability.state.as_str().to_owned(),
        recorded_at_event: device_capability.recorded_at_event,
        note: device_capability.note.clone(),
    }
}

pub(crate) fn driver_store_binding_manifest(
    binding: &semantic_core::DriverStoreBindingRecord,
) -> DriverStoreBindingManifest {
    DriverStoreBindingManifest {
        id: binding.id,
        driver_store: binding.driver_store,
        driver_store_generation: binding.driver_store_generation,
        device: binding.device,
        device_generation: binding.device_generation,
        device_capability: binding.device_capability,
        device_capability_generation: binding.device_capability_generation,
        capability: binding.capability,
        capability_generation: binding.capability_generation,
        generation: binding.generation,
        state: binding.state.as_str().to_owned(),
        recorded_at_event: binding.recorded_at_event,
        note: binding.note.clone(),
    }
}

pub(crate) fn io_wait_manifest(io_wait: &semantic_core::IoWaitRecord) -> IoWaitManifest {
    IoWaitManifest {
        id: io_wait.id,
        wait: io_wait.wait,
        wait_generation: io_wait.wait_generation,
        driver_store: io_wait.driver_store,
        driver_store_generation: io_wait.driver_store_generation,
        device: io_wait.device,
        device_generation: io_wait.device_generation,
        driver_binding: io_wait.driver_binding,
        driver_binding_generation: io_wait.driver_binding_generation,
        blocker: contract_object_ref_manifest(io_wait.blocker),
        generation: io_wait.generation,
        state: io_wait.state.as_str().to_owned(),
        created_at_event: io_wait.created_at_event,
        completed_at_event: io_wait.completed_at_event,
        completion_irq_event: io_wait.completion_irq_event,
        completion_irq_event_generation: io_wait.completion_irq_event_generation,
        cancel_reason: io_wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: io_wait.note.clone(),
    }
}

pub(crate) fn io_cleanup_manifest(cleanup: &semantic_core::IoCleanupRecord) -> IoCleanupManifest {
    IoCleanupManifest {
        id: cleanup.id,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        cancelled_io_waits: cleanup
            .cancelled_io_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_device_capabilities: cleanup
            .revoked_device_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_capabilities: cleanup
            .revoked_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_dma_buffers: cleanup
            .released_dma_buffers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_mmio_regions: cleanup
            .released_mmio_regions
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_irq_lines: cleanup
            .released_irq_lines
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        steps: cleanup
            .steps
            .iter()
            .map(|step| IoCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn io_fault_injection_manifest(
    fault: &semantic_core::IoFaultInjectionRecord,
) -> IoFaultInjectionManifest {
    IoFaultInjectionManifest {
        id: fault.id,
        driver_store: fault.driver_store,
        driver_store_generation: fault.driver_store_generation,
        device: fault.device,
        device_generation: fault.device_generation,
        driver_binding: fault.driver_binding,
        driver_binding_generation: fault.driver_binding_generation,
        target: contract_object_ref_manifest(fault.target),
        cleanup: fault.cleanup,
        cleanup_generation: fault.cleanup_generation,
        generation: fault.generation,
        kind: fault.kind.as_str().to_owned(),
        state: fault.state.as_str().to_owned(),
        injected_at_event: fault.injected_at_event,
        note: fault.note.clone(),
    }
}

pub(crate) fn io_validation_report_manifest(
    report: &semantic_core::IoValidationReportRecord,
) -> IoValidationReportManifest {
    IoValidationReportManifest {
        id: report.id,
        generation: report.generation,
        state: report.state.as_str().to_owned(),
        validated_at_event: report.validated_at_event,
        event_log_cursor: report.event_log_cursor,
        observed_device_count: report.observed_device_count,
        observed_queue_count: report.observed_queue_count,
        observed_descriptor_count: report.observed_descriptor_count,
        observed_dma_buffer_count: report.observed_dma_buffer_count,
        observed_mmio_region_count: report.observed_mmio_region_count,
        observed_irq_line_count: report.observed_irq_line_count,
        observed_irq_event_count: report.observed_irq_event_count,
        observed_device_capability_count: report.observed_device_capability_count,
        observed_driver_binding_count: report.observed_driver_binding_count,
        observed_io_wait_count: report.observed_io_wait_count,
        observed_io_cleanup_count: report.observed_io_cleanup_count,
        observed_io_fault_injection_count: report.observed_io_fault_injection_count,
        violation_count: report.violations.len(),
        violations: report
            .violations
            .iter()
            .map(|violation| IoValidationViolationManifest {
                code: violation.code.as_str().to_owned(),
                subject: contract_object_ref_manifest(violation.subject),
                relation: violation.relation.clone(),
                message: violation.message.clone(),
            })
            .collect(),
        note: report.note.clone(),
    }
}

pub(crate) fn packet_device_object_manifest(
    packet_device: &semantic_core::PacketDeviceObjectRecord,
) -> PacketDeviceObjectManifest {
    PacketDeviceObjectManifest {
        id: packet_device.id,
        name: packet_device.name.clone(),
        device: packet_device.device,
        device_generation: packet_device.device_generation,
        mtu: packet_device.mtu,
        rx_queue_depth: packet_device.rx_queue_depth,
        tx_queue_depth: packet_device.tx_queue_depth,
        mac: packet_device.mac,
        frame_format_version: packet_device.frame_format_version,
        max_payload_len: packet_device.max_payload_len,
        generation: packet_device.generation,
        state: packet_device.state.as_str().to_owned(),
        recorded_at_event: packet_device.recorded_at_event,
        note: packet_device.note.clone(),
    }
}

pub(crate) fn packet_buffer_object_manifest(
    packet_buffer: &semantic_core::PacketBufferObjectRecord,
) -> PacketBufferObjectManifest {
    PacketBufferObjectManifest {
        id: packet_buffer.id,
        packet_device: packet_buffer.packet_device,
        packet_device_generation: packet_buffer.packet_device_generation,
        direction: packet_buffer.direction.as_str().to_owned(),
        frame_format_version: packet_buffer.frame_format_version,
        capacity: packet_buffer.capacity,
        payload_len: packet_buffer.payload_len,
        sequence: packet_buffer.sequence,
        generation: packet_buffer.generation,
        state: packet_buffer.state.as_str().to_owned(),
        recorded_at_event: packet_buffer.recorded_at_event,
        note: packet_buffer.note.clone(),
    }
}

pub(crate) fn packet_queue_object_manifest(
    packet_queue: &semantic_core::PacketQueueObjectRecord,
) -> PacketQueueObjectManifest {
    PacketQueueObjectManifest {
        id: packet_queue.id,
        name: packet_queue.name.clone(),
        packet_device: packet_queue.packet_device,
        packet_device_generation: packet_queue.packet_device_generation,
        role: packet_queue.role.as_str().to_owned(),
        queue_index: packet_queue.queue_index,
        depth: packet_queue.depth,
        generation: packet_queue.generation,
        state: packet_queue.state.as_str().to_owned(),
        recorded_at_event: packet_queue.recorded_at_event,
        note: packet_queue.note.clone(),
    }
}

pub(crate) fn packet_descriptor_object_manifest(
    packet_descriptor: &semantic_core::PacketDescriptorObjectRecord,
) -> PacketDescriptorObjectManifest {
    PacketDescriptorObjectManifest {
        id: packet_descriptor.id,
        packet_queue: packet_descriptor.packet_queue,
        packet_queue_generation: packet_descriptor.packet_queue_generation,
        packet_buffer: packet_descriptor.packet_buffer,
        packet_buffer_generation: packet_descriptor.packet_buffer_generation,
        slot: packet_descriptor.slot,
        length: packet_descriptor.length,
        generation: packet_descriptor.generation,
        state: packet_descriptor.state.as_str().to_owned(),
        recorded_at_event: packet_descriptor.recorded_at_event,
        note: packet_descriptor.note.clone(),
    }
}

pub(crate) fn fake_net_backend_object_manifest(
    backend: &semantic_core::FakeNetBackendObjectRecord,
) -> FakeNetBackendObjectManifest {
    FakeNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn virtio_net_backend_object_manifest(
    backend: &semantic_core::VirtioNetBackendObjectRecord,
) -> VirtioNetBackendObjectManifest {
    VirtioNetBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        packet_device: backend.packet_device,
        packet_device_generation: backend.packet_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        mtu: backend.mtu,
        rx_queue_depth: backend.rx_queue_depth,
        tx_queue_depth: backend.tx_queue_depth,
        mac: backend.mac,
        frame_format_version: backend.frame_format_version,
        max_payload_len: backend.max_payload_len,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        rx_queue_index: backend.rx_queue_index,
        tx_queue_index: backend.tx_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn network_rx_interrupt_manifest(
    rx_interrupt: &semantic_core::NetworkRxInterruptRecord,
) -> NetworkRxInterruptManifest {
    NetworkRxInterruptManifest {
        id: rx_interrupt.id,
        virtio_net_backend: rx_interrupt.virtio_net_backend,
        virtio_net_backend_generation: rx_interrupt.virtio_net_backend_generation,
        irq_event: rx_interrupt.irq_event,
        irq_event_generation: rx_interrupt.irq_event_generation,
        packet_device: rx_interrupt.packet_device,
        packet_device_generation: rx_interrupt.packet_device_generation,
        rx_queue: rx_interrupt.rx_queue,
        rx_queue_generation: rx_interrupt.rx_queue_generation,
        ready_descriptors: rx_interrupt.ready_descriptors,
        sequence: rx_interrupt.sequence,
        generation: rx_interrupt.generation,
        state: rx_interrupt.state.as_str().to_owned(),
        recorded_at_event: rx_interrupt.recorded_at_event,
        note: rx_interrupt.note.clone(),
    }
}

pub(crate) fn network_rx_wait_resolution_manifest(
    resolution: &semantic_core::NetworkRxWaitResolutionRecord,
) -> NetworkRxWaitResolutionManifest {
    NetworkRxWaitResolutionManifest {
        id: resolution.id,
        io_wait: resolution.io_wait,
        io_wait_generation: resolution.io_wait_generation,
        wait: resolution.wait,
        wait_generation: resolution.wait_generation,
        rx_interrupt: resolution.rx_interrupt,
        rx_interrupt_generation: resolution.rx_interrupt_generation,
        irq_event: resolution.irq_event,
        irq_event_generation: resolution.irq_event_generation,
        packet_device: resolution.packet_device,
        packet_device_generation: resolution.packet_device_generation,
        rx_queue: resolution.rx_queue,
        rx_queue_generation: resolution.rx_queue_generation,
        ready_descriptors: resolution.ready_descriptors,
        sequence: resolution.sequence,
        generation: resolution.generation,
        state: resolution.state.as_str().to_owned(),
        resolved_at_event: resolution.resolved_at_event,
        note: resolution.note.clone(),
    }
}

pub(crate) fn network_tx_capability_gate_manifest(
    gate: &semantic_core::NetworkTxCapabilityGateRecord,
) -> NetworkTxCapabilityGateManifest {
    NetworkTxCapabilityGateManifest {
        id: gate.id,
        driver_store: gate.driver_store,
        driver_store_generation: gate.driver_store_generation,
        packet_device: gate.packet_device,
        packet_device_generation: gate.packet_device_generation,
        tx_queue: gate.tx_queue,
        tx_queue_generation: gate.tx_queue_generation,
        packet_descriptor: gate.packet_descriptor,
        packet_descriptor_generation: gate.packet_descriptor_generation,
        packet_buffer: gate.packet_buffer,
        packet_buffer_generation: gate.packet_buffer_generation,
        device_capability: gate.device_capability,
        device_capability_generation: gate.device_capability_generation,
        capability: gate.capability,
        capability_generation: gate.capability_generation,
        handle_slot: gate.handle_slot,
        handle_generation: gate.handle_generation,
        handle_tag: gate.handle_tag,
        operation: gate.operation.clone(),
        byte_len: gate.byte_len,
        sequence: gate.sequence,
        generation: gate.generation,
        state: gate.state.as_str().to_owned(),
        recorded_at_event: gate.recorded_at_event,
        note: gate.note.clone(),
    }
}

pub(crate) fn network_tx_completion_manifest(
    completion: &semantic_core::NetworkTxCompletionRecord,
) -> NetworkTxCompletionManifest {
    NetworkTxCompletionManifest {
        id: completion.id,
        tx_gate: completion.tx_gate,
        tx_gate_generation: completion.tx_gate_generation,
        backend_kind: completion.backend.kind.as_str().to_owned(),
        backend: completion.backend.id,
        backend_generation: completion.backend.generation,
        driver_store: completion.driver_store,
        driver_store_generation: completion.driver_store_generation,
        packet_device: completion.packet_device,
        packet_device_generation: completion.packet_device_generation,
        tx_queue: completion.tx_queue,
        tx_queue_generation: completion.tx_queue_generation,
        packet_descriptor: completion.packet_descriptor,
        packet_descriptor_generation: completion.packet_descriptor_generation,
        packet_buffer: completion.packet_buffer,
        packet_buffer_generation: completion.packet_buffer_generation,
        byte_len: completion.byte_len,
        sequence: completion.sequence,
        completion_sequence: completion.completion_sequence,
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        completed_at_event: completion.completed_at_event,
        note: completion.note.clone(),
    }
}

pub(crate) fn network_stack_adapter_manifest(
    adapter: &semantic_core::NetworkStackAdapterRecord,
) -> NetworkStackAdapterManifest {
    NetworkStackAdapterManifest {
        id: adapter.id,
        implementation: adapter.implementation.clone(),
        implementation_version: adapter.implementation_version.clone(),
        profile: adapter.profile.clone(),
        medium: adapter.medium.clone(),
        backend_kind: adapter.backend.kind.as_str().to_owned(),
        backend: adapter.backend.id,
        backend_generation: adapter.backend.generation,
        packet_device: adapter.packet_device,
        packet_device_generation: adapter.packet_device_generation,
        rx_queue: adapter.rx_queue,
        rx_queue_generation: adapter.rx_queue_generation,
        tx_queue: adapter.tx_queue,
        tx_queue_generation: adapter.tx_queue_generation,
        mac: adapter.mac,
        ipv4_addr: adapter.ipv4_addr,
        ipv4_prefix_len: adapter.ipv4_prefix_len,
        mtu: adapter.mtu,
        rx_queue_depth: adapter.rx_queue_depth,
        tx_queue_depth: adapter.tx_queue_depth,
        max_payload_len: adapter.max_payload_len,
        socket_capacity: adapter.socket_capacity,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn socket_object_manifest(
    socket: &semantic_core::SocketObjectRecord,
) -> SocketObjectManifest {
    SocketObjectManifest {
        id: socket.id,
        adapter: socket.adapter,
        adapter_generation: socket.adapter_generation,
        owner_store: socket.owner_store,
        owner_store_generation: socket.owner_store_generation,
        domain: socket.domain,
        socket_type: socket.socket_type,
        protocol: socket.protocol,
        canonical_protocol: socket.canonical_protocol,
        family: socket.family.clone(),
        transport: socket.transport.clone(),
        generation: socket.generation,
        state: socket.state.as_str().to_owned(),
        created_at_event: socket.created_at_event,
        note: socket.note.clone(),
    }
}

pub(crate) fn endpoint_object_manifest(
    endpoint: &semantic_core::EndpointObjectRecord,
) -> EndpointObjectManifest {
    EndpointObjectManifest {
        id: endpoint.id,
        socket: endpoint.socket,
        socket_generation: endpoint.socket_generation,
        adapter: endpoint.adapter,
        adapter_generation: endpoint.adapter_generation,
        owner_store: endpoint.owner_store,
        owner_store_generation: endpoint.owner_store_generation,
        family: endpoint.family.clone(),
        transport: endpoint.transport.clone(),
        local_addr: endpoint.local_addr,
        local_port: endpoint.local_port,
        remote_addr: endpoint.remote_addr,
        remote_port: endpoint.remote_port,
        generation: endpoint.generation,
        state: endpoint.state.as_str().to_owned(),
        created_at_event: endpoint.created_at_event,
        note: endpoint.note.clone(),
    }
}

pub(crate) fn socket_operation_manifest(
    operation: &semantic_core::SocketOperationRecord,
) -> SocketOperationManifest {
    SocketOperationManifest {
        id: operation.id,
        endpoint: operation.endpoint,
        endpoint_generation: operation.endpoint_generation,
        socket: operation.socket,
        socket_generation: operation.socket_generation,
        adapter: operation.adapter,
        adapter_generation: operation.adapter_generation,
        owner_store: operation.owner_store,
        owner_store_generation: operation.owner_store_generation,
        operation: operation.operation.as_str().to_owned(),
        local_addr: operation.local_addr,
        local_port: operation.local_port,
        remote_addr: operation.remote_addr,
        remote_port: operation.remote_port,
        backlog: operation.backlog,
        byte_len: operation.byte_len,
        sequence: operation.sequence,
        generation: operation.generation,
        state: operation.state.as_str().to_owned(),
        recorded_at_event: operation.recorded_at_event,
        note: operation.note.clone(),
    }
}

pub(crate) fn socket_wait_manifest(wait: &semantic_core::SocketWaitRecord) -> SocketWaitManifest {
    SocketWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        endpoint: wait.endpoint,
        endpoint_generation: wait.endpoint_generation,
        socket: wait.socket,
        socket_generation: wait.socket_generation,
        adapter: wait.adapter,
        adapter_generation: wait.adapter_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        wait_kind: wait.wait_kind.as_str().to_owned(),
        blocker: contract_object_ref_manifest(wait.blocker),
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        ready_sequence: wait.ready_sequence,
        byte_len: wait.byte_len,
        note: wait.note.clone(),
    }
}

pub(crate) fn network_backpressure_manifest(
    backpressure: &semantic_core::NetworkBackpressureRecord,
) -> NetworkBackpressureManifest {
    NetworkBackpressureManifest {
        id: backpressure.id,
        adapter: backpressure.adapter,
        adapter_generation: backpressure.adapter_generation,
        packet_device: backpressure.packet_device,
        packet_device_generation: backpressure.packet_device_generation,
        packet_queue: backpressure.packet_queue,
        packet_queue_generation: backpressure.packet_queue_generation,
        endpoint: backpressure.endpoint,
        endpoint_generation: backpressure.endpoint_generation,
        socket: backpressure.socket,
        socket_generation: backpressure.socket_generation,
        owner_store: backpressure.owner_store,
        owner_store_generation: backpressure.owner_store_generation,
        direction: backpressure.direction.as_str().to_owned(),
        reason: backpressure.reason.as_str().to_owned(),
        action: backpressure.action.as_str().to_owned(),
        queue_depth: backpressure.queue_depth,
        queue_limit: backpressure.queue_limit,
        dropped_packets: backpressure.dropped_packets,
        dropped_bytes: backpressure.dropped_bytes,
        sequence: backpressure.sequence,
        generation: backpressure.generation,
        state: backpressure.state.as_str().to_owned(),
        recorded_at_event: backpressure.recorded_at_event,
        note: backpressure.note.clone(),
    }
}

pub(crate) fn network_driver_cleanup_manifest(
    cleanup: &semantic_core::NetworkDriverCleanupRecord,
) -> NetworkDriverCleanupManifest {
    NetworkDriverCleanupManifest {
        id: cleanup.id,
        io_cleanup: cleanup.io_cleanup,
        io_cleanup_generation: cleanup.io_cleanup_generation,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        packet_device: cleanup.packet_device,
        packet_device_generation: cleanup.packet_device_generation,
        adapter: cleanup.adapter,
        adapter_generation: cleanup.adapter_generation,
        backend: contract_object_ref_manifest(cleanup.backend),
        cancelled_socket_waits: cleanup
            .cancelled_socket_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        cancelled_wait_tokens: cleanup
            .cancelled_wait_tokens
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_packet_capabilities: cleanup
            .revoked_packet_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        reason: cleanup.reason.clone(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn network_generation_audit_manifest(
    audit: &semantic_core::NetworkGenerationAuditRecord,
) -> NetworkGenerationAuditManifest {
    NetworkGenerationAuditManifest {
        id: audit.id,
        adapter: audit.adapter,
        adapter_generation: audit.adapter_generation,
        packet_device: audit.packet_device,
        packet_device_generation: audit.packet_device_generation,
        packet_queue: audit.packet_queue,
        packet_queue_generation: audit.packet_queue_generation,
        packet_descriptor: audit.packet_descriptor,
        packet_descriptor_generation: audit.packet_descriptor_generation,
        packet_buffer: audit.packet_buffer,
        packet_buffer_generation: audit.packet_buffer_generation,
        dma_buffer: contract_object_ref_manifest(audit.dma_buffer),
        device_capability: contract_object_ref_manifest(audit.device_capability),
        rejected_packet_generation_probes: audit.rejected_packet_generation_probes,
        rejected_dma_generation_probes: audit.rejected_dma_generation_probes,
        generation: audit.generation,
        state: audit.state.as_str().to_owned(),
        recorded_at_event: audit.recorded_at_event,
        note: audit.note.clone(),
    }
}

pub(crate) fn network_fault_injection_manifest(
    injection: &semantic_core::NetworkFaultInjectionRecord,
) -> NetworkFaultInjectionManifest {
    NetworkFaultInjectionManifest {
        id: injection.id,
        adapter: injection.adapter,
        adapter_generation: injection.adapter_generation,
        packet_device: injection.packet_device,
        packet_device_generation: injection.packet_device_generation,
        packet_queue: injection.packet_queue,
        packet_queue_generation: injection.packet_queue_generation,
        packet_descriptor: injection.packet_descriptor,
        packet_descriptor_generation: injection.packet_descriptor_generation,
        packet_buffer: injection.packet_buffer,
        packet_buffer_generation: injection.packet_buffer_generation,
        endpoint: injection.endpoint,
        endpoint_generation: injection.endpoint_generation,
        socket: injection.socket,
        socket_generation: injection.socket_generation,
        owner_store: injection.owner_store,
        owner_store_generation: injection.owner_store_generation,
        direction: injection.direction.as_str().to_owned(),
        kind: injection.kind.as_str().to_owned(),
        effect: injection.effect.as_str().to_owned(),
        injected_packets: injection.injected_packets,
        dropped_packets: injection.dropped_packets,
        error_packets: injection.error_packets,
        error_code: injection.error_code.clone(),
        sequence: injection.sequence,
        generation: injection.generation,
        state: injection.state.as_str().to_owned(),
        recorded_at_event: injection.recorded_at_event,
        note: injection.note.clone(),
    }
}

pub(crate) fn network_benchmark_manifest(
    benchmark: &semantic_core::NetworkBenchmarkRecord,
) -> NetworkBenchmarkManifest {
    NetworkBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        tx_queue: benchmark.tx_queue,
        tx_queue_generation: benchmark.tx_queue_generation,
        rx_queue: benchmark.rx_queue,
        rx_queue_generation: benchmark.rx_queue_generation,
        tx_completion: benchmark.tx_completion,
        tx_completion_generation: benchmark.tx_completion_generation,
        rx_wait_resolution: benchmark.rx_wait_resolution,
        rx_wait_resolution_generation: benchmark.rx_wait_resolution_generation,
        endpoint: benchmark.endpoint,
        endpoint_generation: benchmark.endpoint_generation,
        socket: benchmark.socket,
        socket_generation: benchmark.socket_generation,
        owner_store: benchmark.owner_store,
        owner_store_generation: benchmark.owner_store_generation,
        backpressure: benchmark.backpressure,
        backpressure_generation: benchmark.backpressure_generation,
        sample_packets: benchmark.sample_packets,
        sample_bytes: benchmark.sample_bytes,
        tx_completed_packets: benchmark.tx_completed_packets,
        rx_resolved_packets: benchmark.rx_resolved_packets,
        dropped_packets: benchmark.dropped_packets,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn network_recovery_benchmark_manifest(
    benchmark: &semantic_core::NetworkRecoveryBenchmarkRecord,
) -> NetworkRecoveryBenchmarkManifest {
    NetworkRecoveryBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        cleanup: benchmark.cleanup,
        cleanup_generation: benchmark.cleanup_generation,
        io_cleanup: benchmark.io_cleanup,
        io_cleanup_generation: benchmark.io_cleanup_generation,
        adapter: benchmark.adapter,
        adapter_generation: benchmark.adapter_generation,
        packet_device: benchmark.packet_device,
        packet_device_generation: benchmark.packet_device_generation,
        backend: contract_object_ref_manifest(benchmark.backend),
        driver_store: benchmark.driver_store,
        driver_store_generation: benchmark.driver_store_generation,
        fault_injection: benchmark.fault_injection,
        fault_injection_generation: benchmark.fault_injection_generation,
        recovery_start_event: benchmark.recovery_start_event,
        recovery_complete_event: benchmark.recovery_complete_event,
        cancelled_socket_waits: benchmark.cancelled_socket_waits,
        revoked_packet_capabilities: benchmark.revoked_packet_capabilities,
        recovery_nanos: benchmark.recovery_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}
