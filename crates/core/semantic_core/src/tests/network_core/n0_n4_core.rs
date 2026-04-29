use super::*;

#[test]
pub(super) fn network_runtime_n0_packet_device_object_records_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1501,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 backing device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1502,
            name: "net0".to_string(),
            device: 1501,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 packet device object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.packet_device_object_count(), 1);
    let packet_device = &graph.packet_device_objects()[0];
    assert_eq!(
        packet_device.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1502, 1)
    );
    assert_eq!(packet_device.device, 1501);
    assert_eq!(packet_device.device_generation, 1);
    assert_eq!(packet_device.mtu, 1500);
    assert_eq!(packet_device.rx_queue_depth, 4);
    assert_eq!(packet_device.tx_queue_depth, 4);
    assert_eq!(packet_device.max_payload_len, 512);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketDeviceObjectRecorded packet_device=1502 device=1501@1 mtu=1500 rx_queue_depth=4 tx_queue_depth=4 frame_format_version=2 max_payload_len=512 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n0_rejects_stale_or_non_packet_device() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:not-packet");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1503,
        "not-net0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "n0 wrong backing device",
    ));

    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1504,
            name: "net0".to_string(),
            device: 1503,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 wrong class".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);

    let packet_resource =
        graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let packet_resource_generation = graph.resource_handle(packet_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1505,
        "virtio-net1",
        "packet-device",
        packet_resource,
        packet_resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 stale backing device",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1506,
            name: "net1".to_string(),
            device: 1505,
            device_generation: 2,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 stale generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_contract = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1509,
            name: "net1".to_string(),
            device: 1505,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
            frame_format_version: 0,
            max_payload_len: 512,
            note: "n0 bad frame format".to_string(),
        },
    ));
    assert_eq!(bad_contract.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn network_runtime_n0_invariants_reject_packet_device_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1507,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1508,
        "net0",
        1507,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n0 invariant packet device",
    ));
    graph.corrupt_packet_device_object_device_generation_for_test(1508, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketDeviceObjectMissingDevice {
            packet_device: 1508,
            device: 1507,
        })
    );
}

#[test]
pub(super) fn network_runtime_n1_packet_buffer_object_records_generation_safe_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1510,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1511,
        "net0",
        1510,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n1 packet device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1512,
            packet_device: 1511,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 64,
            sequence: 7,
            state: PacketBufferObjectState::Filled,
            note: "n1 packet buffer object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.packet_buffer_object_count(), 1);
    let packet_buffer = &graph.packet_buffer_objects()[0];
    assert_eq!(
        packet_buffer.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketBufferObject, 1512, 1)
    );
    assert_eq!(packet_buffer.packet_device, 1511);
    assert_eq!(packet_buffer.packet_device_generation, 1);
    assert_eq!(packet_buffer.direction, PacketBufferDirection::Rx);
    assert_eq!(packet_buffer.frame_format_version, 2);
    assert_eq!(packet_buffer.capacity, 512);
    assert_eq!(packet_buffer.payload_len, 64);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketBufferObjectRecorded packet_buffer=1512 packet_device=1511@1 direction=rx frame_format_version=2 capacity=512 payload_len=64 sequence=7 state=filled generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n1_rejects_stale_format_and_oversized_buffer() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1513,
        "virtio-net1",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1514,
        "net1",
        1513,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
        2,
        512,
        "n1 packet device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1515,
            packet_device: 1514,
            packet_device_generation: 2,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 64,
            sequence: 1,
            state: PacketBufferObjectState::Filled,
            note: "n1 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_format = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1516,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 3,
            capacity: 512,
            payload_len: 64,
            sequence: 2,
            state: PacketBufferObjectState::Filled,
            note: "n1 bad frame format".to_string(),
        },
    ));
    assert_eq!(bad_format.status, CommandStatus::Rejected);

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1517,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Tx,
            frame_format_version: 2,
            capacity: 513,
            payload_len: 64,
            sequence: 3,
            state: PacketBufferObjectState::Filled,
            note: "n1 oversized capacity".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);

    let empty_filled = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1518,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Tx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 0,
            sequence: 4,
            state: PacketBufferObjectState::Filled,
            note: "n1 empty filled buffer".to_string(),
        },
    ));
    assert_eq!(empty_filled.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn network_runtime_n1_invariants_reject_packet_buffer_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1519,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1520,
        "net0",
        1519,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n1 invariant packet device",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1521,
        1520,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        64,
        1,
        PacketBufferObjectState::Filled,
        "n1 invariant packet buffer",
    ));
    graph.corrupt_packet_buffer_packet_device_generation_for_test(1521, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketBufferObjectMissingDevice {
            packet_buffer: 1521,
            packet_device: 1520,
        })
    );
}

#[test]
pub(super) fn network_runtime_n2_packet_queues_record_rx_and_tx_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1522,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1523,
        "net0",
        1522,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n2 packet device",
    ));

    let rx = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1524,
            name: "net0-rx0".to_string(),
            packet_device: 1523,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 4,
            note: "n2 rx packet queue".to_string(),
        },
    ));
    let tx = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1525,
            name: "net0-tx0".to_string(),
            packet_device: 1523,
            packet_device_generation: 1,
            role: PacketQueueRole::Tx,
            queue_index: 0,
            depth: 4,
            note: "n2 tx packet queue".to_string(),
        },
    ));

    assert_eq!(rx.status, CommandStatus::Applied);
    assert_eq!(tx.status, CommandStatus::Applied);
    assert_eq!(graph.packet_queue_object_count(), 2);
    let rx_queue = &graph.packet_queue_objects()[0];
    assert_eq!(
        rx_queue.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1524, 1)
    );
    assert_eq!(rx_queue.packet_device, 1523);
    assert_eq!(rx_queue.packet_device_generation, 1);
    assert_eq!(rx_queue.role, PacketQueueRole::Rx);
    assert_eq!(rx_queue.depth, 4);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketQueueObjectRecorded packet_queue=1525 packet_device=1523@1 role=tx queue_index=0 depth=4 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n2_rejects_stale_duplicate_and_overdepth_queue() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1526,
        "virtio-net1",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1527,
        "net1",
        1526,
        1,
        1500,
        2,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
        2,
        512,
        "n2 packet device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1528,
            name: "net1-rx0".to_string(),
            packet_device: 1527,
            packet_device_generation: 2,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 2,
            note: "n2 stale queue".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    assert!(graph.record_packet_queue_object_with_id(
        1529,
        "net1-rx0",
        1527,
        1,
        PacketQueueRole::Rx,
        0,
        2,
        "n2 first rx queue",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1530,
            name: "net1-rx0-dup".to_string(),
            packet_device: 1527,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 2,
            note: "n2 duplicate rx queue".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let overdepth = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1531,
            name: "net1-rx1".to_string(),
            packet_device: 1527,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 1,
            depth: 3,
            note: "n2 overdepth rx queue".to_string(),
        },
    ));
    assert_eq!(overdepth.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn network_runtime_n2_invariants_reject_packet_queue_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1532,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1533,
        "net0",
        1532,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n2 invariant packet device",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1534,
        "net0-rx0",
        1533,
        1,
        PacketQueueRole::Rx,
        0,
        4,
        "n2 invariant packet queue",
    ));
    graph.corrupt_packet_queue_packet_device_generation_for_test(1534, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketQueueObjectMissingDevice {
            packet_queue: 1534,
            packet_device: 1533,
        })
    );
}

pub(in crate::tests) fn setup_n3_packet_descriptor_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net2");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1540,
        "virtio-net2",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n3 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1541,
        "net2",
        1540,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        "n3 packet device",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1542,
        1541,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        0,
        1,
        PacketBufferObjectState::Allocated,
        "n3 rx packet buffer",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1543,
        1541,
        1,
        PacketBufferDirection::Tx,
        2,
        512,
        64,
        2,
        PacketBufferObjectState::Filled,
        "n3 tx packet buffer",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1544,
        "net2-rx0",
        1541,
        1,
        PacketQueueRole::Rx,
        0,
        4,
        "n3 rx queue",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1545,
        "net2-tx0",
        1541,
        1,
        PacketQueueRole::Tx,
        0,
        4,
        "n3 tx queue",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n3_packet_descriptors_record_queue_and_buffer_identity() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let rx = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 rx packet descriptor".to_string(),
        },
    ));
    let tx = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1547,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            slot: 0,
            length: 64,
            note: "n3 tx packet descriptor".to_string(),
        },
    ));

    assert_eq!(rx.status, CommandStatus::Applied);
    assert_eq!(tx.status, CommandStatus::Applied);
    assert_eq!(graph.packet_descriptor_object_count(), 2);
    let rx_descriptor = &graph.packet_descriptors()[0];
    assert_eq!(
        rx_descriptor.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketDescriptorObject, 1546, 1)
    );
    assert_eq!(rx_descriptor.packet_queue, 1544);
    assert_eq!(rx_descriptor.packet_queue_generation, 1);
    assert_eq!(rx_descriptor.packet_buffer, 1542);
    assert_eq!(rx_descriptor.packet_buffer_generation, 1);
    assert_eq!(rx_descriptor.slot, 0);
    assert_eq!(rx_descriptor.length, 512);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketDescriptorObjectRecorded packet_descriptor=1547 packet_queue=1545@1 packet_buffer=1543@1 slot=0 length=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n3_rejects_stale_duplicate_mismatch_and_overlength_descriptor() {
    let mut graph = setup_n3_packet_descriptor_graph();

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1544,
            packet_queue_generation: 2,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 stale queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["packet descriptor object queue generation is missing or inactive".to_string()]
    );

    let role_mismatch = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 role mismatch".to_string(),
        },
    ));
    assert_eq!(role_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        role_mismatch.violations,
        vec!["packet descriptor object queue role and buffer direction mismatch".to_string()]
    );

    let tx_overlength = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            slot: 0,
            length: 65,
            note: "n3 tx overlength".to_string(),
        },
    ));
    assert_eq!(tx_overlength.status, CommandStatus::Rejected);
    assert_eq!(
        tx_overlength.violations,
        vec!["tx packet descriptor length exceeds packet payload".to_string()]
    );

    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 first rx descriptor",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1548,
        1541,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        0,
        3,
        PacketBufferObjectState::Allocated,
        "n3 second rx packet buffer",
    ));

    let duplicate_slot = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1549,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1548,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 duplicate slot".to_string(),
        },
    ));
    assert_eq!(duplicate_slot.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_slot.violations,
        vec![
            "packet descriptor object slot already exists for packet queue generation".to_string()
        ]
    );

    let duplicate_buffer = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1550,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 1,
            length: 512,
            note: "n3 duplicate buffer".to_string(),
        },
    ));
    assert_eq!(duplicate_buffer.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_buffer.violations,
        vec!["packet descriptor object packet buffer already has a descriptor".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n3_invariants_reject_packet_descriptor_generation_leaks() {
    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 invariant packet descriptor",
    ));
    graph.corrupt_packet_descriptor_queue_generation_for_test(1546, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketDescriptorObjectMissingQueue {
            packet_descriptor: 1546,
            packet_queue: 1544,
        })
    );

    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 invariant packet descriptor",
    ));
    graph.corrupt_packet_descriptor_buffer_generation_for_test(1546, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketDescriptorObjectMissingBuffer {
            packet_descriptor: 1546,
            packet_buffer: 1542,
        })
    );
}

#[test]
pub(super) fn network_runtime_n4_fake_net_backend_binds_exact_packet_device_contract() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 0x1234,
            note: "n4 fake backend binding".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.fake_net_backend_object_count(), 1);
    let backend = &graph.fake_net_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1551, 1)
    );
    assert_eq!(backend.packet_device, 1541);
    assert_eq!(backend.packet_device_generation, 1);
    assert_eq!(backend.provider, "service_core");
    assert_eq!(backend.profile, "fake-net-v1");
    assert_eq!(backend.deterministic_seed, 0x1234);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FakeNetBackendObjectBound fake_net_backend=1551 packet_device=1541@1 mtu=1500 rx_queue_depth=4 tx_queue_depth=4 frame_format_version=2 max_payload_len=512 deterministic_seed=4660 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n4_rejects_stale_mismatched_unsupported_and_duplicate_backend() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 2,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["fake net backend object packet device generation is missing or inactive".to_string()]
    );

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1400,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 mismatch".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        mismatch.violations,
        vec!["fake net backend object contract does not match packet device".to_string()]
    );

    let unsupported = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "virtio-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 unsupported profile".to_string(),
        },
    ));
    assert_eq!(unsupported.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported.violations,
        vec!["fake net backend object profile is unsupported".to_string()]
    );

    let unsupported_provider = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "debug-harness".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 unsupported provider".to_string(),
        },
    ));
    assert_eq!(unsupported_provider.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_provider.violations,
        vec!["fake net backend object provider is unsupported".to_string()]
    );

    assert!(graph.record_fake_net_backend_object_with_id(
        1551,
        "fake-net2",
        1541,
        1,
        "service_core",
        "fake-net-v1",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        1,
        "n4 first binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1552,
            name: "fake-net2-second".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 2,
            note: "n4 duplicate binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["fake net backend object already bound to packet device generation".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n4_invariants_reject_fake_net_backend_generation_leak() {
    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_fake_net_backend_object_with_id(
        1551,
        "fake-net2",
        1541,
        1,
        "service_core",
        "fake-net-v1",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        1,
        "n4 fake backend binding",
    ));
    graph.corrupt_fake_net_backend_packet_device_generation_for_test(1551, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FakeNetBackendObjectMissingPacketDevice {
            fake_net_backend: 1551,
            packet_device: 1541,
        })
    ));
}
