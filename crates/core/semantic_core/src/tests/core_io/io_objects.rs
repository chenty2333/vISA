use super::*;

#[test]
pub(super) fn network_events_are_recorded_as_semantic_state() {
    let mut graph = SemanticGraph::new();
    let device = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let interface = graph.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
    let socket = graph.register_resource(ResourceKind::NetSocket, Some(7), "socket:tcp:1");
    let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
    let dma = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:net0-rx");

    graph.record_net_interface_state_changed(interface, true);
    graph.record_device_irq_delivered(irq, device, "rx");
    graph.record_dma_submitted(dma, device, 64);
    graph.record_dma_completed(dma, device, 64);
    graph.record_packet_received(interface, Some(socket), 0x6e6574307278, 64);

    assert!(graph.event_log_tail(8).iter().any(|event| matches!(
        event.kind,
        EventKind::PacketReceived {
            interface: recorded_interface,
            socket: Some(recorded_socket),
            len: 64,
            ..
        } if recorded_interface == interface && recorded_socket == socket
    )));
}

#[test]
pub(super) fn io_runtime_i0_device_object_records_resource_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let generation = graph.resource_handle(resource).unwrap().generation;
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 301,
            name: "fake-io0".to_string(),
            class: "fake-device".to_string(),
            resource,
            resource_generation: generation,
            backend: "fake-io-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-io-v1".to_string(),
            note: "device object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.device_objects().len(), 1);
    let device = &graph.device_objects()[0];
    assert_eq!(device.id, 301);
    assert_eq!(device.resource, resource);
    assert_eq!(device.resource_generation, generation);
    assert_eq!(device.class, "fake-device");
    assert_eq!(device.backend, "fake-io-backend");
    assert_eq!(device.state, DeviceObjectState::Registered);
    assert!(device.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DeviceObjectRecorded device=301 resource={resource}@{generation} class=fake-device backend=fake-io-backend generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i0_rejects_stale_or_non_device_resource() {
    let mut graph = SemanticGraph::new();
    let fd = graph.register_resource(ResourceKind::Fd, None, "fd:/not-a-device");
    let fd_generation = graph.resource_handle(fd).unwrap().generation;
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 301,
            name: "fake-io0".to_string(),
            class: "fake-device".to_string(),
            resource: fd,
            resource_generation: fd_generation,
            backend: "fake-io-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-io-v1".to_string(),
            note: "fd resource must reject".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["device object resource kind is not device-capable".to_string()]
    );

    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 302,
            name: "net0".to_string(),
            class: "packet-device".to_string(),
            resource,
            resource_generation: 2,
            backend: "fake-net-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-net-v1".to_string(),
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(stale.violations, vec!["device object resource generation mismatch".to_string()]);

    let generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        302,
        "net0",
        "packet-device",
        resource,
        generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "device object harness",
    ));
    graph.corrupt_device_object_resource_generation_for_test(302, generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DeviceObjectMissingResource { device: 302, resource })
    );
}

#[test]
pub(super) fn io_runtime_i1_queue_object_records_device_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 1,
            note: "queue object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.queue_objects().len(), 1);
    let queue = &graph.queue_objects()[0];
    assert_eq!(queue.id, 501);
    assert_eq!(queue.device, 401);
    assert_eq!(queue.device_generation, 1);
    assert_eq!(queue.role, QueueObjectRole::Rx);
    assert_eq!(queue.queue_index, 0);
    assert_eq!(queue.depth, 64);
    assert_eq!(queue.state, QueueObjectState::Registered);
    assert!(queue.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "QueueObjectRecorded queue=501 device=401@1 role=rx index=0 depth=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i1_rejects_stale_or_duplicate_queue() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 2,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["queue object device generation is missing or inactive".to_string()]
    );

    let zero_depth = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 0,
            device: 401,
            device_generation: 1,
            note: "zero depth must reject".to_string(),
        },
    ));
    assert_eq!(zero_depth.status, CommandStatus::Rejected);
    assert_eq!(zero_depth.violations, vec!["queue object depth is zero".to_string()]);

    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 502,
            name: "fake-io0-tx".to_string(),
            role: QueueObjectRole::Tx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 1,
            note: "duplicate index must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["queue object index already exists for device generation".to_string()]
    );

    graph.corrupt_queue_object_device_generation_for_test(501, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::QueueObjectMissingDevice { queue: 501, device: 401 })
    );
}

#[test]
pub(super) fn io_runtime_i2_descriptor_object_records_queue_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "descriptor object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.descriptor_objects().len(), 1);
    let descriptor = &graph.descriptor_objects()[0];
    assert_eq!(descriptor.id, 601);
    assert_eq!(descriptor.queue, 501);
    assert_eq!(descriptor.queue_generation, 1);
    assert_eq!(descriptor.slot, 0);
    assert_eq!(descriptor.access, DescriptorObjectAccess::ReadWrite);
    assert_eq!(descriptor.length, 2048);
    assert_eq!(descriptor.state, DescriptorObjectState::Registered);
    assert!(descriptor.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DescriptorObjectRecorded descriptor=601 queue=501@1 slot=0 access=read-write length=2048 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i2_rejects_stale_out_of_bounds_or_duplicate_descriptor() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        2,
        401,
        1,
        "queue object harness",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 2,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "stale queue generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["descriptor object queue generation is missing or inactive".to_string()]
    );

    let zero_length = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 0,
            note: "zero length must reject".to_string(),
        },
    ));
    assert_eq!(zero_length.status, CommandStatus::Rejected);
    assert_eq!(zero_length.violations, vec!["descriptor object length is zero".to_string()]);

    let out_of_bounds = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 2,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "slot outside queue depth must reject".to_string(),
        },
    ));
    assert_eq!(out_of_bounds.status, CommandStatus::Rejected);
    assert_eq!(
        out_of_bounds.violations,
        vec!["descriptor object slot is outside queue depth".to_string()]
    );

    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 602,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadOnly,
            length: 128,
            note: "duplicate slot must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["descriptor object slot already exists for queue generation".to_string()]
    );

    graph.corrupt_descriptor_object_queue_generation_for_test(601, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DescriptorObjectMissingQueue { descriptor: 601, queue: 501 })
    );
}

#[test]
pub(super) fn io_runtime_i3_dma_buffer_object_records_descriptor_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "dma buffer object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.dma_buffer_objects().len(), 1);
    let dma_buffer = &graph.dma_buffer_objects()[0];
    assert_eq!(dma_buffer.id, 701);
    assert_eq!(dma_buffer.descriptor, 601);
    assert_eq!(dma_buffer.descriptor_generation, 1);
    assert_eq!(dma_buffer.resource, dma_resource);
    assert_eq!(dma_buffer.resource_generation, dma_resource_generation);
    assert_eq!(dma_buffer.access, DmaBufferObjectAccess::ReadWrite);
    assert_eq!(dma_buffer.length, 2048);
    assert_eq!(dma_buffer.state, DmaBufferObjectState::Registered);
    assert!(dma_buffer.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DmaBufferObjectRecorded dma_buffer=701 descriptor=601@1 resource={dma_resource}@{dma_resource_generation} access=read-write length=2048 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i3_rejects_stale_wrong_resource_or_duplicate_dma_buffer() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));

    let stale_descriptor = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 2,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "stale descriptor generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_descriptor.violations,
        vec!["dma buffer object descriptor generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "non-dma resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["dma buffer object resource kind is not dma-buffer".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation + 1,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["dma buffer object resource generation mismatch".to_string()]
    );

    let length_exceeds = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 4096,
            note: "length exceeds descriptor must reject".to_string(),
        },
    ));
    assert_eq!(length_exceeds.status, CommandStatus::Rejected);
    assert_eq!(
        length_exceeds.violations,
        vec!["dma buffer object length exceeds descriptor length".to_string()]
    );

    assert!(graph.record_dma_buffer_object_with_id(
        701,
        601,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "dma buffer object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 702,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadOnly,
            length: 128,
            note: "duplicate descriptor buffer must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["dma buffer object descriptor already has a buffer".to_string()]
    );

    graph.corrupt_dma_buffer_object_resource_generation_for_test(701, dma_resource_generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DmaBufferObjectMissingResource {
            dma_buffer: 701,
            resource: dma_resource,
        })
    );
}

#[test]
pub(super) fn io_runtime_i4_mmio_region_object_records_device_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let mmio_resource =
        graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "mmio region object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.mmio_region_objects().len(), 1);
    let mmio_region = &graph.mmio_region_objects()[0];
    assert_eq!(mmio_region.id, 801);
    assert_eq!(mmio_region.device, 401);
    assert_eq!(mmio_region.device_generation, 1);
    assert_eq!(mmio_region.resource, mmio_resource);
    assert_eq!(mmio_region.resource_generation, mmio_resource_generation);
    assert_eq!(mmio_region.region_index, 0);
    assert_eq!(mmio_region.offset, 0x1000);
    assert_eq!(mmio_region.length, 0x100);
    assert_eq!(mmio_region.access, MmioRegionObjectAccess::ReadWrite);
    assert_eq!(mmio_region.state, MmioRegionObjectState::Registered);
    assert!(mmio_region.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "MmioRegionObjectRecorded mmio_region=801 device=401@1 resource={mmio_resource}@{mmio_resource_generation} index=0 offset=4096 length=256 access=read-write generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i4_rejects_stale_wrong_resource_or_duplicate_mmio_region() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let mmio_resource =
        graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 2,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["mmio region object device generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "non-mmio resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["mmio region object resource kind is not mmio-region".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation + 1,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["mmio region object resource generation mismatch".to_string()]
    );

    let range_overflows = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: u64::MAX,
            length: 1,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "overflowing range must reject".to_string(),
        },
    ));
    assert_eq!(range_overflows.status, CommandStatus::Rejected);
    assert_eq!(range_overflows.violations, vec!["mmio region object range overflows".to_string()]);

    assert!(graph.record_mmio_region_object_with_id(
        801,
        401,
        1,
        mmio_resource,
        mmio_resource_generation,
        0,
        0x1000,
        0x100,
        MmioRegionObjectAccess::ReadWrite,
        "mmio region object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 802,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x2000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadOnly,
            note: "duplicate region index must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["mmio region object index already exists for device generation".to_string()]
    );

    graph.corrupt_mmio_region_object_device_generation_for_test(801, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::MmioRegionObjectMissingDevice {
            mmio_region: 801,
            device: 401,
        })
    );
}

#[test]
pub(super) fn io_runtime_i5_irq_line_object_records_device_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "irq line object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.irq_line_objects().len(), 1);
    let irq_line = &graph.irq_line_objects()[0];
    assert_eq!(irq_line.id, 901);
    assert_eq!(irq_line.device, 401);
    assert_eq!(irq_line.device_generation, 1);
    assert_eq!(irq_line.resource, irq_resource);
    assert_eq!(irq_line.resource_generation, irq_resource_generation);
    assert_eq!(irq_line.irq_number, 5);
    assert_eq!(irq_line.trigger, IrqLineTrigger::Level);
    assert_eq!(irq_line.polarity, IrqLinePolarity::ActiveHigh);
    assert_eq!(irq_line.state, IrqLineObjectState::Registered);
    assert!(irq_line.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IrqLineObjectRecorded irq_line=901 device=401@1 resource={irq_resource}@{irq_resource_generation} irq_number=5 trigger=level polarity=active-high generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i5_rejects_stale_wrong_resource_or_duplicate_irq_line() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 2,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["irq line object device generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "non-irq resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["irq line object resource kind is not irq-line".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation + 1,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["irq line object resource generation mismatch".to_string()]
    );

    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 902,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Edge,
            polarity: IrqLinePolarity::ActiveLow,
            note: "duplicate irq number must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["irq line object number already exists for device generation".to_string()]
    );

    graph.corrupt_irq_line_object_device_generation_for_test(901, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IrqLineObjectMissingDevice { irq_line: 901, device: 401 })
    );
}

#[test]
pub(super) fn io_runtime_i6_irq_event_records_line_device_and_driver_store_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "irq event harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.irq_events().len(), 1);
    let irq_event = &graph.irq_events()[0];
    assert_eq!(irq_event.id, 1001);
    assert_eq!(irq_event.irq_line, 901);
    assert_eq!(irq_event.irq_line_generation, 1);
    assert_eq!(irq_event.device, 401);
    assert_eq!(irq_event.device_generation, 1);
    assert_eq!(irq_event.driver_store, driver_store);
    assert_eq!(irq_event.driver_store_generation, driver_store_generation);
    assert_eq!(irq_event.irq_number, 5);
    assert_eq!(irq_event.sequence, 1);
    assert_eq!(irq_event.state, IrqEventState::Recorded);
    assert!(irq_event.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IrqEventRecorded irq_event=1001 irq_line=901@1 device=401@1 driver_store={driver_store}@{driver_store_generation} irq_number=5 sequence=1 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i6_rejects_stale_wrong_store_or_duplicate_irq_event() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let service_store = graph.register_store(
        "service.fake-io0",
        "service.fake-io0.fake-aot",
        "service",
        "restartable",
    );
    graph.set_store_state(service_store, StoreState::Running);
    let service_store_generation = graph.store_handle(service_store).unwrap().generation;

    let stale_line = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 2,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "stale line generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_line.status, CommandStatus::Rejected);
    assert_eq!(
        stale_line.violations,
        vec!["irq event line generation is missing or inactive".to_string()]
    );

    let wrong_device = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 402,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "wrong device must reject".to_string(),
        },
    ));
    assert_eq!(wrong_device.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_device.violations,
        vec!["irq event device does not match irq line".to_string()]
    );

    let stale_store = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation: driver_store_generation + 1,
            sequence: 1,
            note: "stale driver store generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_store.status, CommandStatus::Rejected);
    assert_eq!(
        stale_store.violations,
        vec!["irq event driver store generation mismatch".to_string()]
    );

    let non_driver_store = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store: service_store,
            driver_store_generation: service_store_generation,
            sequence: 1,
            note: "non-driver store must reject".to_string(),
        },
    ));
    assert_eq!(non_driver_store.status, CommandStatus::Rejected);
    assert_eq!(
        non_driver_store.violations,
        vec!["irq event driver store role is not driver".to_string()]
    );

    let zero_sequence = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 0,
            note: "zero sequence must reject".to_string(),
        },
    ));
    assert_eq!(zero_sequence.status, CommandStatus::Rejected);
    assert_eq!(zero_sequence.violations, vec!["irq event sequence is zero".to_string()]);

    assert!(graph.record_irq_event_with_id(
        1001,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        1,
        "irq event harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        6,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1002,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "duplicate sequence must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["irq event sequence already exists for irq line generation".to_string()]
    );

    graph.corrupt_irq_event_driver_store_generation_for_test(1001, driver_store_generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IrqEventMissingDriverStore {
            irq_event: 1001,
            store: driver_store,
        })
    );
}
